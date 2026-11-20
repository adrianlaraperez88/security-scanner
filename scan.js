import fs                                       from 'node:fs';
import { getScanners }                          from './core/registry.js';
import { fingerprint }                          from './core/fingerprint.js';
import { fetchWithRetry as baseFetch,
         createGovernedFetch }                  from './core/fetch.js';
import { generateReport, saveReport,
         saveHtmlReport, saveAutoReports,
         generateMarkdownReport, generateCsvReport,
         generateSarifReport,
         groupFindings, summarizeCveAudit,
         sanitizeApiCommunication,
         mergeApiCommunication }                from './core/report.js';
import { filterSafeSameOriginApiRoutes }        from './core/api-discovery.js';
import { generateFixSolution,
         summarizeScanForAudience,
         analyzeApiCommunication }              from './core/ai-advisor.js';
import { auditCveCoverage }                     from './core/cve-audit.js';
import { calculateRisk }                        from './core/severity.js';
import { selectScannersForStack,
         ACTIVE_FUZZING_CHECKS }                from './core/profiles.js';
import { saveHistory, loadLastHistory,
         diffScans }                            from './core/history.js';
import { sendWebhook, maskWebhookUrl }          from './core/notify.js';
import { TaskQueue }                            from './core/queue.js';
import { crawlPage,
         discoverApiRoutesFromPage }            from './core/crawler.js';
import { validateTargets }                      from './core/validator.js';
import { getCheckMeta }                         from './core/catalog.js';
import { EnrichEngine }                         from './core/enrich.js';
import { createTrackedFetch }                   from './core/reproduction.js';
import { NoiseGovernor }                        from './core/egress.js';
import { validateCustomHeaders }                from './core/headers.js';
import { evaluateAssetGate, TargetPinStore }    from './core/guard.js';
import { GraphStore }                           from './core/graph-store.js';
import { TrafficStore }                         from './core/traffic.js';
import { EvidenceStore }                        from './core/evidence.js';
import { LlmPool }                              from './core/llmpool.js';
import { SkillRegistry }                        from './core/skills.js';
import { AgentEngine }                          from './core/agent-engine.js';
import pLimit                                   from 'p-limit';

function inferScopeRuleType(pattern) {
  const pat = String(pattern || '').trim();
  if (/^https?:\/\//i.test(pat)) return 'fuzzy_url';
  if (/\/\d{1,3}$/.test(pat)) return 'cidr';
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(pat) || pat.includes(':')) return 'exact_ip';
  if (/^[\d.*]+$/.test(pat) && pat.includes('.')) return 'fuzzy_ip';
  return 'fuzzy_domain';
}

/**
 * Normalizes CLI/config `--scope` rules (strings or objects) into `evaluateAssetGate` rules.
 * Supports prefixes like `deny:`, `!`, `allow:`, `cidr:`, `ip:`, `url:`, `domain:`.
 */
export function normalizeScopeRules(scopeRules) {
  if (!scopeRules) return [];
  const rawList = Array.isArray(scopeRules)
    ? scopeRules
    : String(scopeRules).split(',').map(s => s.trim()).filter(Boolean);

  const normalized = [];
  for (const item of rawList) {
    if (!item) continue;
    if (typeof item === 'object') {
      const pattern = String(item.pattern ?? item.value ?? '').trim();
      if (!pattern) continue;
      const existingType = item.ruleType || item.rule_type || item.kind || item.type;
      const ruleType = existingType ? String(existingType).toLowerCase() : inferScopeRuleType(pattern);
      let isAllowed = true;
      if (typeof item.isAllowed === 'boolean') isAllowed = item.isAllowed;
      else if (typeof item.is_allowed === 'boolean') isAllowed = item.is_allowed;
      else if (typeof item.is_allowed === 'number') isAllowed = item.is_allowed !== 0;
      else {
        const act = String(item.action || item.effect || item.constraint_type || item.constraintType || '').toLowerCase();
        if (act === 'deny' || act === 'block') isAllowed = false;
      }
      normalized.push({
        ...item,
        ruleType,
        pattern,
        isAllowed,
        action: item.action || (isAllowed ? 'allow' : 'deny'),
      });
      continue;
    }
    let raw = String(item).trim();
    if (!raw) continue;

    let isAllowed = true;
    if (raw.startsWith('!')) {
      isAllowed = false;
      raw = raw.slice(1).trim();
    } else if (/^deny:/i.test(raw)) {
      isAllowed = false;
      raw = raw.slice(5).trim();
    } else if (/^allow:/i.test(raw)) {
      isAllowed = true;
      raw = raw.slice(6).trim();
    }

    let ruleType = null;
    const typeMatch = raw.match(/^(exact_domain|fuzzy_domain|domain|exact_ip|fuzzy_ip|ip|cidr|exact_url|fuzzy_url|url):(.+)$/i);
    if (typeMatch) {
      const prefix = typeMatch[1].toLowerCase();
      ruleType = prefix === 'url' ? 'fuzzy_url' : prefix === 'domain' ? 'fuzzy_domain' : prefix;
      raw = typeMatch[2].trim();
    } else {
      ruleType = inferScopeRuleType(raw);
    }

    if (raw) {
      normalized.push({ ruleType, pattern: raw, isAllowed, action: isAllowed ? 'allow' : 'deny' });
    }
  }
  return normalized;
}

// Status → emoji
const ICON = {
  VULNERABLE: '🚨',
  SUSPICIOUS: '⚠️ ',
  SAFE      : '✅',
  ERROR     : '❓',
};

function printDiff(diff, log = console.log) {
  const bar = '─'.repeat(60);
  log(`\n${bar}`);
  log('🔄  DIFF vs previous scan');
  log(bar);

  if (diff.newFindings.length) {
    log(`\n🆕  New findings (${diff.newFindings.length}):`);
    diff.newFindings.forEach(f =>
      log(`     + [${f.severity}] ${f.name}  →  ${f.target}`)
    );
  }

  if (diff.fixedFindings.length) {
    log(`\n✅  Fixed (${diff.fixedFindings.length}):`);
    diff.fixedFindings.forEach(({ prev }) =>
      log(`     - [${prev.severity}] ${prev.name}  →  ${prev.target}`)
    );
  }

  if (diff.changedFindings.length) {
    log(`\n↕️   Changed (${diff.changedFindings.length}):`);
    diff.changedFindings.forEach(({ prev, curr }) =>
      log(`     ~ ${curr.name}: ${prev.status}(${prev.severity}) → ${curr.status}(${curr.severity})`)
    );
  }

  if (!diff.newFindings.length && !diff.fixedFindings.length && !diff.changedFindings.length) {
    log('  No changes since last scan.');
  }

  log(bar);
}

function findHostStack(stacks, targetUrl) {
  if (!stacks || typeof stacks !== 'object') return null;
  if (targetUrl && stacks[targetUrl]) return stacks[targetUrl];
  if (targetUrl) {
    try {
      const origin = new URL(targetUrl).origin;
      for (const [k, fp] of Object.entries(stacks)) {
        if (k.startsWith(origin)) return fp;
      }
    } catch {}
  }
  return Object.values(stacks)[0] || null;
}

export async function runScanner(options) {
  const {
    targets,
    json         = false,
    html         = false,
    markdown     = false,
    csv          = false,
    sarif        = false,
    aiFix        = false,
    audience     = 'pro',
    headers      = {},
    concurrency  = 5,
    techOverride = null,
    output       = 'report',
    timeout      = 10000,
    auth         = null,
    profile      = 'smart',
    forceAll     = false,
    diff         = false,
    noHistory    = false,
    webhook      = null,
    maxDepth     = 3,
    onProgress   = null,
    silent       = false,
    setExitCode  = true,
    returnFull   = false,
    noiseProfile = null,
    governor     = null,
    scopeRules   = null,
    trafficStore = null,
    evidenceStore = null,
    graphStore   = null,
    agent        = false,
    goal         = null,
    llmPool      = null,
    skillRegistry = null,
    maxAgentRounds = 5,
    fetcher      = null,
    dnsResolver  = null,
    resolver     = null,
    checks       = null,
    allowPrivate: rawAllowPrivate = false,
  } = options;
  const allowPrivate = Boolean(rawAllowPrivate);

  const emit = (evt) => {
    if (typeof onProgress === 'function') {
      try {
        onProgress(evt);
      } catch {}
    }
  };

  const log = (...args) => {
    if (!silent) console.log(...args);
  };

  const validation = validateTargets(targets, { allowPrivate });
  if (!validation.valid) {
    throw new Error(validation.errors.join('; '));
  }
  const validatedTargets = validation.targets;

  const normalizedScopeRules = normalizeScopeRules(scopeRules);
  if (normalizedScopeRules.length > 0) {
    for (const t of validatedTargets) {
      const gate = evaluateAssetGate(t, { rules: normalizedScopeRules });
      if (!gate.allowed) {
        throw new Error(gate.reason || `Target blocked by scope rule: ${t}`);
      }
    }
  }

  const activeGovernor = governor || (noiseProfile ? new NoiseGovernor({ profile: noiseProfile }) : null);
  const targetPinStore = new TargetPinStore({ allowPrivate });
  const enrichEngine = new EnrichEngine({ allowPrivate, targetPinStore });

  emit({
    phase: 'start',
    message: 'Starting security scan...',
    percent: 5,
    targets: validatedTargets,
    profile,
  });

  // Curry fetch with timeout + optional auth/custom headers + governance/traffic/DNS-pinning wiring
  const activeDnsResolver = dnsResolver || resolver || null;
  const customHeaders  = validateCustomHeaders(headers);
  const authHeaders    = auth ? { Authorization: auth } : {};
  const governedFetch  = createGovernedFetch({
    ...(activeGovernor ? { governor: activeGovernor } : {}),
    ...(normalizedScopeRules.length ? { scopeRules: normalizedScopeRules } : {}),
    ...(trafficStore ? { trafficStore } : {}),
    ...(fetcher ? { fetcher } : {}),
    ...(activeDnsResolver ? { dnsResolver: activeDnsResolver } : {}),
    enforceDnsValidation: true,
    allowPrivate,
    targetPinStore,
    retries: 2,
    timeout,
  });
  const fetchWithRetry = (url, opts = {}) => governedFetch(url, {
    ...opts,
    headers: { ...customHeaders, ...authHeaders, ...(opts.headers || {}) }
  });
  fetchWithRetry.governance = governedFetch.governance;
  fetchWithRetry.tlsAlpnProbe = governedFetch.tlsAlpnProbe;

  const scanners      = await getScanners();

  const bar = '═'.repeat(60);
  log(bar);
  log('🔍  Security Scanner v2.2 (Discovery Mode)');
  log(bar);
  log(`📡  Targets     : ${validatedTargets.length}`);
  log(`⚙️   Scanners    : ${scanners.length}  |  Profile: ${profile}`);
  log(`🕸️   Max Depth   : ${maxDepth}`);
  log(`🔄  Concurrency : ${concurrency}  |  Timeout: ${timeout}ms`);
  if (activeGovernor) log(`🎚️   Noise Prof. : ${activeGovernor.profile}`);
  if (normalizedScopeRules.length) log(`🛡️   Scope Rules : ${normalizedScopeRules.length}`);
  if (allowPrivate) log('🏢  Private Net : enabled (metadata endpoints still blocked)');
  if (agent)   log(`🤖  Agent Mode  : enabled${goal ? ` (${goal})` : ''}`);
  if (auth)    log(`🔑  Authenticated scan`);
  if (Object.keys(customHeaders).length) log(`🧾  Custom Hdrs : ${Object.keys(customHeaders).length} header(s)`);
  if (webhook) log(`📣  Webhook: ${maskWebhookUrl(webhook)}`);
  log(bar);

  // ── Diff: load previous scan ──────────────────────────────────────────────
  let previousScan = null;
  if (diff || !noHistory) {
    previousScan = loadLastHistory(validatedTargets);
    if (diff && !previousScan) log('ℹ️  No previous scan found for diff — running fresh scan\n');
  }

  const allResults = [];
  const stacks = {};
  const limit = pLimit(concurrency);

  let totalPlannedChecks = 0;
  let completedChecks = 0;

  // ── Initial Fingerprinting & Discovery ────────────────────────────────────
  const targetTasks = validatedTargets.map(initialTarget => limit(async () => {
    log(`\n🛰️   Starting crawl: ${initialTarget}`);
    
    // 1. Initial Fingerprint
    const seenBundleUrls = new Set();
    const seenConfigUrls = new Set();
    const budgetState = { bytes: 0 };
    const fp = await fingerprint(initialTarget, fetchWithRetry, {
      seenBundleUrls,
      seenConfigUrls,
      budgetState
    });
    if (fp.apiCommunication) {
      fp.apiCommunication = sanitizeApiCommunication(fp.apiCommunication);
    }
    stacks[initialTarget] = fp;
    const stackStr = fp.stack.length
      ? fp.stack.map(s => `${s.tech}(${s.score})`).join(', ')
      : 'unknown';
    log(`    🧠  Detected Stack      : ${fp.summary || stackStr}`);
    if (fp.detectedTags?.length) log(`    🏷️   Ecosystem Tags      : ${fp.detectedTags.join(', ')}`);
    if (fp.recommendedProfile) log(`    🎯  Recommended Profile : ${fp.recommendedProfile}`);
    if (fp.apiCommunication?.usesApi) {
      const apiComm = fp.apiCommunication;
      const clients = Array.isArray(apiComm.clients) && apiComm.clients.length
        ? apiComm.clients.join(', ')
        : (Array.isArray(apiComm.protocols) && apiComm.protocols.length ? apiComm.protocols.join(', ') : 'HTTP API');
      const sameOriginCount = Array.isArray(apiComm.sameOriginEndpoints) ? apiComm.sameOriginEndpoints.length : 0;
      const externalOrigins = Array.isArray(apiComm.externalApiOrigins) ? apiComm.externalApiOrigins : [];
      log(`    🔌 API Communication : YES (${clients} → ${sameOriginCount} same-origin route(s), ${externalOrigins.length} external API origin(s))`);
      if (externalOrigins.length > 0) {
        log(`    🌐 External API Origins : ${externalOrigins.slice(0, 6).join(', ')}${externalOrigins.length > 6 ? ` (+${externalOrigins.length - 6} more)` : ''}`);
      }
    }

    const selection = selectScannersForStack(scanners, {
      profile,
      fp,
      techOverride,
      forceAll
    });
    let activeScanners = selection.activeScanners;
    let skippedScanners = selection.skippedScanners;
    if (Array.isArray(checks) && checks.length > 0) {
      const wanted = new Set(checks.map(c => String(c).trim()).filter(Boolean));
      activeScanners = scanners.filter(s => wanted.has(s.name));
      skippedScanners = scanners.filter(s => !wanted.has(s.name));
    }
    fp.activeChecksCount = activeScanners.length;
    fp.skippedChecksCount = skippedScanners.length;
    fp.skippedChecks = skippedScanners.map(s => s.name);

    log(`    🛡️   Audit Strategy      : ${activeScanners.length} relevant checks selected (${skippedScanners.length} irrelevant stack checks skipped)`);

    emit({
      phase: 'fingerprint',
      message: `Detected stack for ${initialTarget}`,
      percent: 15,
      target: initialTarget,
      stack: fp,
      apiCommunication: fp.apiCommunication || null,
      activeChecksCount: activeScanners.length,
      skippedChecksCount: skippedScanners.length,
    });

    // 2. Discover URLs via Crawler
    const queue = new TaskQueue(initialTarget);
    let depth = 0;
    const MAX_API_ROUTES_PER_TARGET = 12;
    let apiRoutesEnqueued = 0;
    const enqueueApiRoutes = (routes) => {
      if (apiRoutesEnqueued >= MAX_API_ROUTES_PER_TARGET) return;
      const safeSlice = filterSafeSameOriginApiRoutes(
        routes,
        initialTarget,
        MAX_API_ROUTES_PER_TARGET - apiRoutesEnqueued
      );
      if (safeSlice.length > 0) {
        apiRoutesEnqueued += safeSlice.length;
        queue.push(safeSlice);
      }
    };

    const normalizedInitialTarget = String(initialTarget || '').replace(/\/+$/, '');

    while (depth < maxDepth && !queue.isEmpty()) {
      emit({
        phase: 'crawl',
        message: `Crawling depth ${depth + 1}/${maxDepth}...`,
        percent: 25,
        target: initialTarget,
        pagesFound: queue.totalFound,
      });
      const topLevelPaths = queue.pending.splice(0, queue.pending.length);
      log(`    🕸️   Depth ${depth}: Scanning ${topLevelPaths.length} pages for links...`);
      
      for (const p of topLevelPaths) {
        const isSeedPage = p.replace(/\/+$/, '') === normalizedInitialTarget;
        if ((depth === 0 || isSeedPage) && fp?.apiCommunication?.sameOriginEndpoints?.length) {
          enqueueApiRoutes(fp.apiCommunication.sameOriginEndpoints);
        }
        const crawlRes = await crawlPage(p, fetchWithRetry, { includeResponse: true });
        queue.push(crawlRes.links);
        if (apiRoutesEnqueued < MAX_API_ROUTES_PER_TARGET && crawlRes.response?.status === 200) {
          const apiRoutes = await discoverApiRoutesFromPage(p, crawlRes.response.text || '', fetchWithRetry, {
            rootResponse: crawlRes.response,
            maxRoutes: MAX_API_ROUTES_PER_TARGET - apiRoutesEnqueued,
            maxBundles: isSeedPage ? 2 : 1,
            maxConfigProbes: isSeedPage && !fp?.apiCommunication ? 2 : 0,
            seenBundleUrls,
            seenConfigUrls,
            budgetState
          });
          enqueueApiRoutes(apiRoutes);
        }
      }
      depth++;
    }

    log(`    🏁  Crawl complete: ${queue.totalFound} unique pages found.`);

    // 3. Scan all discovered URLs
    const allDiscovered = Array.from(queue.seen);

    // Smart check execution:
    // Parameterized active fuzzing checks run on all discovered URLs;
    // Domain-level checks only run once on root initialTarget (unless allDiscovered.length === 1)
    const pageScannersMap = new Map();
    let targetPlanned = 0;
    for (const page of allDiscovered) {
      const isRoot = (page.replace(/\/+$/, '') === normalizedInitialTarget || allDiscovered.length === 1);
      const checksForPage = isRoot
        ? activeScanners
        : activeScanners.filter(s => ACTIVE_FUZZING_CHECKS.has(s.name));
      pageScannersMap.set(page, checksForPage);
      targetPlanned += checksForPage.length;
    }
    totalPlannedChecks += targetPlanned;

    log(`    ⚙️   Running checks on ${allDiscovered.length} pages (${targetPlanned} total executions planned)...`);

    const checkLimit = pLimit(3);

    const scannerOptions = {
      allowPrivate,
      ...(normalizedScopeRules.length ? { scopeRules: normalizedScopeRules } : {}),
      ...(activeGovernor ? { governor: activeGovernor } : {}),
      ...(activeDnsResolver ? { dnsResolver: activeDnsResolver } : {}),
      targetPinStore,
    };

    const scanResults = await Promise.all(allDiscovered.map(page => checkLimit(async () => {
      const scannersForPage = pageScannersMap.get(page) || [];
      const pageResults = await Promise.all(scannersForPage.map(async (scan) => {
        try {
          const trackedFetch = createTrackedFetch(fetchWithRetry);
          const res = await scan.run(page, trackedFetch, scannerOptions);
          const meta = scan.meta || getCheckMeta(res.name || scan.name);
          const fix = res.fix || meta?.defaultFix || undefined;

          const enriched = enrichEngine.enrichFinding({
            target: page,
            checkId: scan.name,
            ...res,
            meta,
            ...(fix ? { fix } : {}),
          }, { allowPrivate, capturedTraces: trackedFetch.getTraces() });

          if (enriched.status !== 'SAFE') {
            const icon = ICON[enriched.status] ?? '❓';
            log(`      ${icon}  [${(enriched.severity ?? 'NONE').padEnd(8)}] ${enriched.name || scan.name} → ${page}`);
            if (enriched.reproduction?.summary) log(`          🔁 Reproduce : ${enriched.reproduction.summary}`);
            if (enriched.fix) log(`          💡 Suggestion: ${enriched.fix}`);
          }

          completedChecks++;
          const percent = totalPlannedChecks > 0
            ? Math.min(95, 30 + Math.round((completedChecks / totalPlannedChecks) * 65))
            : 30;

          emit({
            phase: 'check',
            message: `Completed ${scan.name} on ${page}`,
            percent,
            checkName: scan.name,
            target: page,
            status: enriched.status,
            severity: enriched.severity,
          });

          return enriched;
        } catch (e) {
          const meta = scan.meta || getCheckMeta(scan.name);
          const fix = meta?.defaultFix || undefined;

          const errorRes = enrichEngine.enrichFinding({
            target: page,
            checkId: scan.name,
            name: scan.name,
            status: 'ERROR',
            severity: 'LOW',
            reason: e.message,
            meta,
            ...(fix ? { fix } : {}),
          }, { allowPrivate });

          completedChecks++;
          const percent = totalPlannedChecks > 0
            ? Math.min(95, 30 + Math.round((completedChecks / totalPlannedChecks) * 65))
            : 30;

          emit({
            phase: 'check',
            message: `Completed ${scan.name} on ${page}`,
            percent,
            checkName: scan.name,
            target: page,
            status: 'ERROR',
            severity: 'LOW',
          });

          return errorRes;
        }
      }));
      return pageResults;
    })));

    return scanResults.flat();
  }));

  const nested = await Promise.all(targetTasks);
  nested.forEach(r => allResults.push(...r));

  // ── Summary & CVE Coverage ───────────────────────────────────────────────
  const risk       = calculateRisk(allResults);
  const apiCommunication = mergeApiCommunication(stacks, allResults);

  for (const [targetKey, fp] of Object.entries(stacks)) {
    if (!fp || typeof fp !== 'object') continue;
    const targetFindings = allResults.filter(r => r && r.target && r.target.startsWith(targetKey));
    const mergedForTarget = mergeApiCommunication({ [targetKey]: fp }, targetFindings);
    if (mergedForTarget) {
      fp.apiCommunication = mergedForTarget;
    }
  }

  const detectedTagSet = new Set();
  for (const fp of Object.values(stacks)) {
    if (Array.isArray(fp?.detectedTags)) {
      for (const t of fp.detectedTags) {
        if (typeof t === 'string' && t.trim()) detectedTagSet.add(t.trim().toLowerCase());
      }
    }
  }
  const overrideList = Array.isArray(techOverride)
    ? techOverride
    : typeof techOverride === 'string'
      ? techOverride.split(',').map(s => s.trim()).filter(Boolean)
      : [];
  for (const t of overrideList) detectedTagSet.add(String(t).trim().toLowerCase());

  let cveCoverage = null;
  try {
    const cveAudit = await auditCveCoverage({ scanners, techTags: Array.from(detectedTagSet) });
    cveCoverage = summarizeCveAudit(cveAudit);
  } catch {}

  let aiSummary = null;
  let apiAnalysis = null;
  if (aiFix) {
    const advisorPool = llmPool || new LlmPool({ autoDiscoverEnv: true });
    const aiLimit = pLimit(4);
    await Promise.all(
      allResults
        .filter(f => f && f.status !== 'SAFE')
        .map(f => aiLimit(async () => {
          const hostStack = stacks[f.target] || findHostStack(stacks, f.target);
          f.aiSolution = await generateFixSolution(f, {
            audience,
            stack: hostStack,
            apiCommunication: f.apiCommunication || hostStack?.apiCommunication || apiCommunication,
            llmPool: advisorPool,
          });
        }))
    );
    aiSummary = await summarizeScanForAudience(
      {
        results: allResults,
        risk,
        stacks,
        cveCoverage,
        ...(apiCommunication ? { apiCommunication } : {}),
      },
      { audience, llmPool: advisorPool }
    );
    if (apiCommunication?.usesApi && typeof analyzeApiCommunication === 'function') {
      try {
        apiAnalysis = await analyzeApiCommunication(apiCommunication, {
          target: validatedTargets[0],
          audience,
          llmPool: advisorPool,
        });
      } catch {}
    }
  }

  const grouped    = groupFindings(allResults);
  const vulns      = grouped.filter(r => r.status === 'VULNERABLE');
  const suspicious = grouped.filter(r => r.status === 'SUSPICIOUS');

  log(`\n${bar}`);
  log('📊  SCAN SUMMARY');
  log(bar);
  log(`Security Grade: ${risk.grade ?? 'A+'}  |  Risk Level: ${risk.level}  (score: ${risk.score})`);
  if (risk.summary) log(`Post assessment: ${risk.summary}`);
  log(`🚨 Vulnerable  : ${vulns.length}`);
  log(`⚠️  Suspicious  : ${suspicious.length}`);
  log(`📋 Total checks: ${grouped.length} unique checks (${allResults.length} page executions)`);
  if (cveCoverage) {
    log(`🛡️  CVE Coverage: ${cveCoverage.coveredCount}/${cveCoverage.totalAdvisories} advisories (${cveCoverage.coveragePercent}%), missing=${cveCoverage.missingCount}`);
  }
  if (aiSummary) {
    const summaryMode = aiSummary.mode === 'ai' ? `AI (${aiSummary.provider}/${aiSummary.model})` : 'Playbook';
    log(`🧠  AI Advisor (${summaryMode}, ${aiSummary.audience}): ${aiSummary.headline}`);
  }
  if (apiAnalysis) {
    const apiMode = apiAnalysis.mode === 'ai' ? `AI (${apiAnalysis.provider}/${apiAnalysis.model})` : 'Playbook';
    log(`🔌  API Advisor (${apiMode}, ${apiAnalysis.audience || audience}): ${apiAnalysis.headline || apiAnalysis.explanation || ''}`);
    if (Array.isArray(apiAnalysis.recommendations) && apiAnalysis.recommendations.length > 0) {
      for (const rec of apiAnalysis.recommendations.slice(0, 3)) {
        log(`    • ${rec}`);
      }
    }
    if (Array.isArray(apiAnalysis.nextScanTargets) && apiAnalysis.nextScanTargets.length > 0) {
      log(`    🎯 Recommended API Scan Target(s): ${apiAnalysis.nextScanTargets.join(', ')}`);
    }
  }

  if (vulns.length > 0) {
    log('\n🚨  Vulnerabilities (Grouped by Check):');
    vulns.forEach(v => {
      const loc = v.path ? ` (${v.path})` : '';
      log(`  • [${v.severity}] ${v.name}${loc}:`);
      const pages = Array.isArray(v.pages) && v.pages.length ? v.pages : [v.target];
      log(`    Pages (${pages.length}):`);
      pages.forEach(p => log(`      - ${p}`));
      if (v.reproduction?.curl || v.reproduction?.steps?.[0]) {
        log(`    🔁 Reproduce : ${v.reproduction.steps?.[0] || v.reproduction.summary}`);
        if (v.reproduction.curl) log(`    📋 Command   : ${v.reproduction.curl}`);
        if (v.reproduction.verifyFix) log(`    ✅ Verify fix: ${v.reproduction.verifyFix}`);
      }
      if (v.fix) log(`    💡 How to fix: ${v.fix}`);
      if (v.aiSolution) {
        const modeTag = v.aiSolution.mode === 'ai' ? 'AI Fix' : 'Playbook Fix';
        log(`    🧠 ${modeTag}: ${v.aiSolution.plainExplanation}`);
      }
    });
  }

  if (suspicious.length > 0) {
    log('\n⚠️   Suspicious Findings (Grouped by Check):');
    suspicious.forEach(s => {
      const loc = s.path ? ` (${s.path})` : '';
      log(`  • [${s.severity}] ${s.name}${loc}:`);
      const pages = Array.isArray(s.pages) && s.pages.length ? s.pages : [s.target];
      log(`    Pages (${pages.length}):`);
      pages.forEach(p => log(`      - ${p}`));
      if (s.reproduction?.curl || s.reproduction?.steps?.[0]) {
        log(`    🔁 Reproduce : ${s.reproduction.steps?.[0] || s.reproduction.summary}`);
        if (s.reproduction.curl) log(`    📋 Command   : ${s.reproduction.curl}`);
      }
      if (s.fix) log(`    💡 How to fix: ${s.fix}`);
      if (s.aiSolution) {
        const modeTag = s.aiSolution.mode === 'ai' ? 'AI Fix' : 'Playbook Fix';
        log(`    🧠 ${modeTag}: ${s.aiSolution.plainExplanation}`);
      }
    });
  }

  // ── Save history & Auto Reports ───────────────────────────────────────────
  let historyFile = null;
  let autoReports = null;
  const reportExtra = {
    cveCoverage,
    ...(apiCommunication ? { apiCommunication } : {}),
  };
  if (!noHistory) {
    historyFile = saveHistory(validatedTargets, allResults, risk, stacks);
    autoReports = saveAutoReports(validatedTargets, allResults, risk, stacks, reportExtra);
    log(`\n📁  History saved     → ${historyFile}`);
    log(`🌐  HTML report saved → ${autoReports.htmlPath}`);
    log(`💾  JSON report saved → ${autoReports.jsonPath}`);
  }

  // ── Diff output ───────────────────────────────────────────────────────────
  if (diff && previousScan) {
    const d = diffScans(previousScan, allResults);
    printDiff(d, log);
  }

  // ── Graph Ingestion & Agentic Loop ───────────────────────────────────────
  let graphIngestion = null;
  let agentSummary = null;
  let ownedGraphStore = null;
  let ownedTrafficStore = null;
  let ownedEvidenceStore = null;

  try {
    if (graphStore && typeof graphStore.ingestStaticScanResult === 'function') {
      graphIngestion = graphStore.ingestStaticScanResult({
        targets: validatedTargets,
        results: allResults,
        risk,
        stacks,
        allow_private: allowPrivate,
        allowPrivate,
      });
    }

    if (agent) {
      emit({
        phase: 'agent',
        message: 'Running Agentic Verification loop...',
        percent: 97,
      });
      const activeGraph = graphStore || (ownedGraphStore = new GraphStore({ dbPath: ':memory:' }));
      const activeTraffic = trafficStore || (ownedTrafficStore = new TrafficStore({ dbPath: ':memory:' }));
      const activeEvidence = evidenceStore || (ownedEvidenceStore = new EvidenceStore({ dbPath: ':memory:', trafficStore: activeTraffic }));
      const activeSkills = skillRegistry || new SkillRegistry();
      const activePool = llmPool || new LlmPool({ autoDiscoverEnv: true });
      const primaryTarget = validatedTargets[0];

      const agentTask = activeGraph.createTask({
        title: `Agentic Verification: ${primaryTarget}`,
        target: primaryTarget,
        goal: goal || `Discover and verify security findings on ${primaryTarget}`,
        mode: 'auto',
        noise_profile: activeGovernor ? activeGovernor.profile : (noiseProfile || 'balanced'),
        scope: normalizedScopeRules,
        allow_private: allowPrivate,
        allowPrivate,
      });

      const engine = new AgentEngine({
        graphStore: activeGraph,
        llmPool: activePool,
        trafficStore: activeTraffic,
        evidenceStore: activeEvidence,
        skillRegistry: activeSkills,
        targetPinStore,
        allowPrivate,
        ...(activeDnsResolver ? { dnsResolver: activeDnsResolver } : {}),
        fetchImpl: (u, o = {}) => fetchWithRetry(u, o),
      });

      agentSummary = await engine.runTaskLoop(agentTask.id, {
        maxRounds: maxAgentRounds,
        debounceMs: 0,
        allowPrivate,
      });
      log(`\n🤖  Agent Engine: ${agentSummary.rounds} round(s), ${agentSummary.executed} intent(s) executed (${agentSummary.stopReason})`);
    }
  } finally {
    if (ownedEvidenceStore) { try { ownedEvidenceStore.close(); } catch {} }
    if (ownedTrafficStore) { try { ownedTrafficStore.close(); } catch {} }
    if (ownedGraphStore) { try { ownedGraphStore.close(); } catch {} }
  }

  // ── Reports ───────────────────────────────────────────────────────────────
  const stem = output.replace(/\.(json|html|md|csv|sarif)$/, '');

  if (json) {
    const report = generateReport(allResults, risk, stacks, reportExtra);
    const file   = saveReport(report, stem);
    log(`\n💾  JSON report → ${file}`);
  }

  if (html) {
    const file = saveHtmlReport(allResults, risk, stem, stacks, reportExtra);
    log(`🌐  HTML report → ${file}`);
  }

  let markdownFile = null;
  if (markdown) {
    const mdName = typeof markdown === 'string' && markdown.trim()
      ? (markdown.endsWith('.md') ? markdown : `${markdown}.md`)
      : `${stem}.md`;
    const mdContent = generateMarkdownReport({
      targets: validatedTargets,
      results: allResults,
      risk,
      stacks,
      cveCoverage,
      ...(apiCommunication ? { apiCommunication } : {}),
    });
    fs.writeFileSync(mdName, mdContent, 'utf8');
    markdownFile = mdName;
    log(`📝  Markdown report → ${mdName}`);
  }

  let csvFile = null;
  if (csv) {
    const csvName = typeof csv === 'string' && csv.trim()
      ? (csv.endsWith('.csv') ? csv : `${csv}.csv`)
      : `${stem}.csv`;
    const csvContent = generateCsvReport({
      targets: validatedTargets,
      results: allResults,
      risk,
      stacks,
    });
    fs.writeFileSync(csvName, csvContent, 'utf8');
    csvFile = csvName;
    log(`📊  CSV report → ${csvName}`);
  }

  let sarifFile = null;
  if (sarif) {
    const sarifName = typeof sarif === 'string' && sarif.trim()
      ? (sarif.endsWith('.sarif') ? sarif : `${sarif}.sarif`)
      : (output && output !== 'report' ? `${stem}.sarif` : 'secscan-report.sarif');
    const sarifObj = generateSarifReport({
      targets: validatedTargets,
      results: allResults,
      risk,
      stacks,
      cveCoverage,
      ...(apiCommunication ? { apiCommunication } : {}),
      ...(aiSummary ? { aiSummary } : {}),
    });
    fs.writeFileSync(sarifName, JSON.stringify(sarifObj, null, 2), 'utf8');
    sarifFile = sarifName;
    log(`🛡️   SARIF report → ${sarifName}`);
  }

  // ── Webhook ───────────────────────────────────────────────────────────────
  if (webhook) {
    await sendWebhook(webhook, allResults, risk, validatedTargets);
  }

  emit({
    phase: 'complete',
    message: 'Scan complete',
    percent: 100,
    risk,
    totalChecks: grouped.length,
    vulnerable: vulns.length,
    suspicious: suspicious.length,
    ...(apiCommunication ? { apiCommunication } : {}),
    ...(cveCoverage ? { cveCoverage } : {}),
  });

  log(bar);

  // ── CI/CD exit codes ──────────────────────────────────────────────────────
  // 0 = all clear | 1 = HIGH risk | 2 = VULNERABLE or CRITICAL
  if (setExitCode !== false) {
    if (vulns.length > 0 || risk.level === 'CRITICAL') {
      process.exitCode = 2;
    } else if (risk.level === 'HIGH') {
      process.exitCode = 1;
    }
  }

  if (returnFull) {
    return {
      results: allResults,
      risk,
      historyFile,
      stacks,
      ...(apiCommunication ? { apiCommunication } : {}),
      ...(apiAnalysis ? { apiAnalysis } : {}),
      ...(cveCoverage ? { cveCoverage } : {}),
      ...(markdownFile ? { markdownFile } : {}),
      ...(csvFile ? { csvFile } : {}),
      ...(sarifFile ? { sarifFile } : {}),
      ...(aiSummary ? { aiSummary } : {}),
      ...(graphIngestion ? { graphIngestion } : {}),
      ...(agentSummary ? { agentSummary } : {}),
    };
  }

  return allResults;
}
