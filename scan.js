import fs                                       from 'node:fs';
import net                                      from 'node:net';
import { getScanners, getAvailableCheckNames }  from './core/registry.js';
import { fingerprint }                          from './core/fingerprint.js';
import { createGovernedFetch }                  from './core/fetch.js';
import { generateReport, saveReport,
         saveHtmlReport, saveAutoReports,
         generateMarkdownReport, generateCsvReport,
         generateSarifReport,
         groupFindings, summarizeCveAudit,
         buildExecutiveResume,
         sanitizeApiCommunication,
         mergeApiCommunication }                from './core/report.js';
import { filterSafeSameOriginApiRoutes }        from './core/api-discovery.js';
import { sanitizeRuntimeSca,
         mergeRuntimeSca }                      from './core/runtime-sca.js';
import { calculateRisk }                        from './core/severity.js';
import { selectScannersForStack,
         getProfileChecks,
         ACTIVE_FUZZING_CHECKS }                from './core/profiles.js';
import { TaskQueue }                            from './core/queue.js';
import { crawlPage,
         discoverApiRoutesFromPage }            from './core/crawler.js';
import { normalizeTargetInput, resolveBareIpTargets, validateTargets } from './core/validator.js';
import { normalizeDeviceCategory }              from './core/device-scanner.js';
import { getCheckInfo, getCheckMeta }           from './core/catalog.js';
import { EnrichEngine }                         from './core/enrich.js';
import { createTrackedFetch }                   from './core/reproduction.js';
import { NoiseGovernor }                        from './core/egress.js';
import { validateCustomHeaders }                from './core/headers.js';
import { evaluateAssetGate, TargetPinStore }    from './core/guard.js';
import { discoverWebsiteRealIp }                from './core/real-ip-finder.js';
import { AuthSessionManager,
         parseLoginFormHtml }                   from './core/auth-session.js';
import pLimit                                   from 'p-limit';

export { discoverWebsiteRealIp, AuthSessionManager, parseLoginFormHtml };

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

export async function runScanner(options = {}) {
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
    checkConcurrency = null,
    techOverride = null,
    output       = 'report',
    timeout      = 10000,
    auth         = null,
    authSession  = null,
    loginUrl     = null,
    username     = null,
    password     = null,
    loginContentType = null,
    loginType    = null,
    usernameField = null,
    passwordField = null,
    loginPayload = null,
    recordedSession = null,
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
    resolveCache = null,
    sourceIp     : rawSourceIp = null,
    sourceIpMap  = null,
    autoRealIp   = false,
    scanRealIp   = false,
    usePinnedDialer = false,
    connectToSourceIp = true,
    baseDialer   = null,
    checks       = null,
    deviceMode   = false,
    deviceCategory = 'all',
    tcpProbe     = null,
    portProbe    = null,
    rtspProbe    = null,
    udpProbe     = null,
    tlsProbe     = null,
    tlsConnect   = null,
    portTimeoutMs = null,
    probeTimeoutMs = null,
    multiPort    = undefined,
    oast         = false,
    oastServer   = null,
    templates    = null,
    allowPrivate: rawAllowPrivate = false,
  } = options;
  const allowPrivate = Boolean(rawAllowPrivate);
  const effectiveDeviceCategory = normalizeDeviceCategory(deviceCategory);
  const isDeviceProfile = [
    'device', 'tv', 'smart-tv', 'smart_tv', 'iot',
    'camera', 'cam', 'nvr', 'ip-camera', 'ip_camera',
    'pc', 'workstation', 'server', 'pc-workstation', 'pc_workstation', 'lan'
  ].includes(String(profile || '').toLowerCase());
  const effectiveDeviceMode = Boolean(deviceMode || isDeviceProfile || effectiveDeviceCategory !== 'all');

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

  const normalizedScopeRules = normalizeScopeRules(scopeRules);
  const activeDnsResolver = dnsResolver || resolver || null;
  let bareIpProbeSummary = null;
  let resolvedInputTargets = targets;
  if (Array.isArray(targets)) {
    const bareResolved = await resolveBareIpTargets(targets, {
      allowPrivate,
      ...(normalizedScopeRules.length ? { scopeRules: normalizedScopeRules } : {}),
      ...(fetcher ? { fetcher } : {}),
      ...(typeof tcpProbe === 'function' ? { tcpProbe } : {}),
      timeoutMs: timeout,
      ...(rawSourceIp ? { sourceIp: rawSourceIp } : {}),
      ...(sourceIpMap ? { sourceIpMap } : {}),
      ...(activeDnsResolver ? { dnsResolver: activeDnsResolver } : {}),
      ...(resolveCache ? { resolveCache } : {}),
    });
    resolvedInputTargets = bareResolved.targets;
    bareIpProbeSummary = bareResolved.probeSummary;
  }
  const validation = validateTargets(resolvedInputTargets, { allowPrivate });
  if (!validation.valid) {
    throw new Error(validation.errors.join('; '));
  }
  const validatedTargets = validation.targets;

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
  let sourceIp = rawSourceIp;
  if ((autoRealIp === true || scanRealIp === true) && !sourceIp && validatedTargets.length === 1) {
    try {
      const realIpReport = await discoverWebsiteRealIp(validatedTargets[0], {
        allowPrivate,
        ...(normalizedScopeRules.length ? { rules: normalizedScopeRules } : {}),
        ...(activeDnsResolver ? { dnsResolver: activeDnsResolver } : {}),
        ...(fetcher ? { fetchFn: fetcher } : {}),
        timeoutMs: timeout || 5000,
      });
      if (realIpReport?.realIp) {
        sourceIp = realIpReport.realIp;
      }
    } catch (err) {
      if (err?.isGovernanceBlock) throw err;
    }
  }
  const customHeaders  = validateCustomHeaders(headers);
  const authHeaders    = auth ? { Authorization: auth } : {};
  const governedFetch  = createGovernedFetch({
    ...(activeGovernor ? { governor: activeGovernor } : {}),
    ...(normalizedScopeRules.length ? { scopeRules: normalizedScopeRules } : {}),
    ...(trafficStore ? { trafficStore } : {}),
    ...(fetcher ? { fetcher } : {}),
    ...(activeDnsResolver ? { dnsResolver: activeDnsResolver } : {}),
    ...(resolveCache ? { resolveCache } : {}),
    ...(sourceIp ? { sourceIp } : {}),
    ...(sourceIpMap ? { sourceIpMap } : {}),
    ...(baseDialer ? { baseDialer } : {}),
    usePinnedDialer,
    connectToSourceIp,
    enforceDnsValidation: true,
    allowPrivate,
    targetPinStore,
    retries: 2,
    timeout,
  });

  let ownedOastServer = null;
  let activeOastServer = oastServer || null;

  try {
  if (oast === true && !activeOastServer) {
    const { OastServer } = await import('./core/oast-server.js');
    ownedOastServer = new OastServer({ host: '127.0.0.1', port: 0 });
    await ownedOastServer.start();
    activeOastServer = ownedOastServer;
  }

  let loadedDeclarativeTemplates = [];
  let runDeclarativeTemplateFn = null;
  if (templates) {
    const { loadTemplatesFromPath, runDeclarativeTemplate } = await import('./core/template-loader.js');
    runDeclarativeTemplateFn = runDeclarativeTemplate;
    if (typeof templates === 'string' && templates.trim()) {
      loadedDeclarativeTemplates = loadTemplatesFromPath(templates.trim());
    } else if (Array.isArray(templates)) {
      for (const item of templates) {
        if (typeof item === 'string' && item.trim()) {
          loadedDeclarativeTemplates.push(...loadTemplatesFromPath(item.trim()));
        } else if (item && typeof item === 'object') {
          loadedDeclarativeTemplates.push(item);
        }
      }
    } else if (typeof templates === 'object') {
      loadedDeclarativeTemplates = [templates];
    }
  }

  const baseGovernedFetch = (url, opts = {}, ...rest) => governedFetch(url, {
    ...opts,
    headers: { ...customHeaders, ...authHeaders, ...(opts?.headers || {}) }
  }, ...rest);
  baseGovernedFetch.governance = governedFetch.governance;
  baseGovernedFetch.tlsAlpnProbe = governedFetch.tlsAlpnProbe;
  baseGovernedFetch.sourceIp = governedFetch.sourceIp;
  baseGovernedFetch.sourceIpMap = governedFetch.sourceIpMap;
  baseGovernedFetch.resolveCache = governedFetch.resolveCache;
  baseGovernedFetch.targetPinStore = governedFetch.targetPinStore;
  baseGovernedFetch.hasCustomFetcher = governedFetch.hasCustomFetcher;
  if (governedFetch.isDefaultFetch !== undefined) {
    baseGovernedFetch.isDefaultFetch = governedFetch.isDefaultFetch;
  }

  let authManager = null;
  const authSessionCfg = (authSession && typeof authSession === 'object' && !(authSession instanceof AuthSessionManager))
    ? authSession
    : null;
  const effectiveRecordedSession = authSessionCfg?.recordedSession || recordedSession || null;
  const effectiveLoginUrlRaw = authSessionCfg?.loginUrl ?? loginUrl ?? null;
  const effectiveLoginUrl = (() => {
    if (!effectiveLoginUrlRaw) return null;
    const trimmed = String(effectiveLoginUrlRaw).trim();
    if (trimmed.startsWith('/')) {
      try {
        return new URL(trimmed, validatedTargets[0]).toString();
      } catch {
        return trimmed;
      }
    }
    return trimmed;
  })();
  const effectiveUsername = authSessionCfg?.username ?? username ?? null;
  const effectivePassword = authSessionCfg?.password ?? password ?? null;
  const effectiveLoginContentType = authSessionCfg?.loginContentType ?? loginContentType ?? loginType ?? null;
  const effectiveUsernameField = authSessionCfg?.usernameField ?? usernameField ?? null;
  const effectivePasswordField = authSessionCfg?.passwordField ?? passwordField ?? null;
  const effectiveLoginPayload = authSessionCfg?.loginPayload ?? loginPayload ?? null;

  const hasAuthSessionConfig = Boolean(
    authSession instanceof AuthSessionManager ||
    effectiveRecordedSession ||
    effectiveLoginUrl ||
    effectiveUsername !== null ||
    effectivePassword !== null ||
    effectiveLoginPayload !== null
  );

  if (hasAuthSessionConfig) {
    if (authSession instanceof AuthSessionManager) {
      authManager = authSession;
      if (!authManager.targetUrl) {
        authManager.targetUrl = validatedTargets[0];
      }
    } else if (effectiveRecordedSession) {
      authManager = AuthSessionManager.fromRecordedSession(effectiveRecordedSession);
      if (!authManager.targetUrl) authManager.targetUrl = validatedTargets[0];
      if (effectiveLoginUrl) authManager.loginUrl = effectiveLoginUrl;
      if (effectiveUsername !== null && effectiveUsername !== undefined) authManager.username = String(effectiveUsername);
      if (effectivePassword !== null && effectivePassword !== undefined) authManager.password = String(effectivePassword);
      if (effectiveLoginContentType) authManager.loginContentType = effectiveLoginContentType;
      if (effectiveUsernameField) authManager.usernameField = effectiveUsernameField;
      if (effectivePasswordField) authManager.passwordField = effectivePasswordField;
      if (effectiveLoginPayload !== null && effectiveLoginPayload !== undefined) authManager.loginPayload = effectiveLoginPayload;
    } else {
      authManager = new AuthSessionManager({
        ...(authSessionCfg || {}),
        targetUrl: authSessionCfg?.targetUrl || validatedTargets[0],
        ...(effectiveLoginUrl ? { loginUrl: effectiveLoginUrl } : {}),
        ...(effectiveUsername !== null && effectiveUsername !== undefined ? { username: effectiveUsername } : {}),
        ...(effectivePassword !== null && effectivePassword !== undefined ? { password: effectivePassword } : {}),
        ...(effectiveLoginContentType ? { loginContentType: effectiveLoginContentType } : {}),
        ...(effectiveUsernameField ? { usernameField: effectiveUsernameField } : {}),
        ...(effectivePasswordField ? { passwordField: effectivePasswordField } : {}),
        ...(effectiveLoginPayload !== null && effectiveLoginPayload !== undefined ? { loginPayload: effectiveLoginPayload } : {}),
      });
    }

    const alreadyAuthenticated = Boolean(authManager.bearerToken || authManager.cookies.size > 0);
    const hasLoginCreds = Boolean(
      authManager.loginPayload !== null ||
      (authManager.username !== null && authManager.password !== null)
    );
    if (!alreadyAuthenticated && hasLoginCreds) {
      const loginOutcome = await authManager.executeLoginMacro(baseGovernedFetch);
      if (!loginOutcome.authenticated) {
        log(`⚠️  Auth Session warning: login macro returned HTTP ${loginOutcome.status} without a session cookie or Bearer token.`);
      }
    }
  }

  const fetchWithRetry = authManager ? authManager.wrapFetch(baseGovernedFetch) : baseGovernedFetch;
  if (authManager) {
    fetchWithRetry.governance = baseGovernedFetch.governance;
    fetchWithRetry.tlsAlpnProbe = baseGovernedFetch.tlsAlpnProbe;
    fetchWithRetry.sourceIp = baseGovernedFetch.sourceIp;
    fetchWithRetry.sourceIpMap = baseGovernedFetch.sourceIpMap;
    fetchWithRetry.resolveCache = baseGovernedFetch.resolveCache;
    fetchWithRetry.targetPinStore = baseGovernedFetch.targetPinStore;
    fetchWithRetry.hasCustomFetcher = baseGovernedFetch.hasCustomFetcher;
    if (baseGovernedFetch.isDefaultFetch !== undefined) {
      fetchWithRetry.isDefaultFetch = baseGovernedFetch.isDefaultFetch;
    }
  }

  const allCheckNames = getAvailableCheckNames();
  let scanners;
  if (Array.isArray(checks) && checks.length > 0) {
    const wantedLower = new Set(checks.map(c => String(c).trim().toLowerCase()).filter(Boolean));
    const neededNames = allCheckNames.filter(name => {
      if (wantedLower.has(name.toLowerCase())) return true;
      const info = getCheckInfo(name);
      return Array.isArray(info?.cveIds) && info.cveIds.some(cve => wantedLower.has(String(cve).toLowerCase()));
    });
    const loaded = await getScanners({ onlyChecks: neededNames });
    const loadedByName = new Map(loaded.map(s => [s.name, s]));
    scanners = allCheckNames.map(name => loadedByName.get(name) || { name, tags: [], meta: getCheckInfo(name) });
  } else if (!forceAll) {
    const profileCheckList = getProfileChecks(profile);
    if (Array.isArray(profileCheckList)) {
      const loaded = await getScanners({ onlyChecks: profileCheckList });
      const loadedByName = new Map(loaded.map(s => [s.name, s]));
      scanners = allCheckNames.map(name => loadedByName.get(name) || { name, tags: [], meta: getCheckInfo(name) });
    } else {
      scanners = await getScanners();
    }
  } else {
    scanners = await getScanners();
  }

  let notifyMod = null;
  if (webhook) {
    notifyMod = await import('./core/notify.js');
  }

  const bar = '═'.repeat(60);
  log(bar);
  log('🔍  Security Scanner v2.2 (Discovery Mode)');
  log(bar);
  log(`📡  Targets     : ${validatedTargets.length}`);
  log(`⚙️   Scanners    : ${scanners.length}  |  Profile: ${profile}`);
  log(`🕸️   Max Depth   : ${maxDepth}`);
  log(`🔄  Concurrency : ${concurrency}  |  Timeout: ${timeout}ms`);
  if (sourceIp || sourceIpMap) log(`🎯  Source IP   : ${typeof sourceIp === 'string' ? sourceIp : JSON.stringify(sourceIp || sourceIpMap)}`);
  if (activeGovernor) log(`🎚️   Noise Prof. : ${activeGovernor.profile}`);
  if (normalizedScopeRules.length) log(`🛡️   Scope Rules : ${normalizedScopeRules.length}`);
  if (allowPrivate) log('🏢  Private Net : enabled (metadata endpoints still blocked)');
  if (agent)   log(`🤖  Agent Mode  : enabled${goal ? ` (${goal})` : ''}`);
  if (auth)    log(`🔑  Authenticated scan`);
  if (authManager) {
    const sessSummary = authManager.getRecordedSession({ includeSecrets: false });
    log(`🔐  Auth Session: ${sessSummary.authenticated ? 'AUTHENTICATED' : 'UNAUTHENTICATED'} (${sessSummary.cookieCount} cookie(s)${sessSummary.hasBearerToken ? ', Bearer JWT' : ''}${sessSummary.loginUrl ? ` via ${sessSummary.loginUrl}` : ''})`);
  }
  if (Object.keys(customHeaders).length) log(`🧾  Custom Hdrs : ${Object.keys(customHeaders).length} header(s)`);
  if (webhook) log(`📣  Webhook: ${notifyMod.maskWebhookUrl(webhook)}`);
  log(bar);

  // ── Diff: load previous scan ──────────────────────────────────────────────
  let historyMod = null;
  let previousScan = null;
  if (diff || !noHistory) {
    historyMod = await import('./core/history.js');
    previousScan = historyMod.loadLastHistory(validatedTargets);
    if (diff && !previousScan) log('ℹ️  No previous scan found for diff — running fresh scan\n');
  }

  const allResults = [];
  const stacks = {};
  const limit = pLimit(concurrency);

  let totalPlannedChecks = 0;
  let completedChecks = 0;

  const schemesByHost = new Map();
  for (const vt of validatedTargets) {
    try {
      const u = new URL(vt);
      const hostKey = String(u.hostname || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
      if (!hostKey) continue;
      if (!schemesByHost.has(hostKey)) schemesByHost.set(hostKey, new Set());
      schemesByHost.get(hostKey).add(u.protocol.toLowerCase());
    } catch {}
  }

  // ── Initial Fingerprinting & Discovery ────────────────────────────────────
  const targetTasks = validatedTargets.map(initialTarget => limit(async () => {
    log(`\n🛰️   Starting crawl: ${initialTarget}`);
    let siblingSchemes = [];
    try {
      const u = new URL(initialTarget);
      const hostKey = String(u.hostname || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
      siblingSchemes = Array.from(schemesByHost.get(hostKey) || []);
    } catch {}
    
    // 1. Initial Fingerprint
    const seenBundleUrls = new Set();
    const seenConfigUrls = new Set();
    const budgetState = { bytes: 0 };
    const fp = await fingerprint(initialTarget, fetchWithRetry, {
      seenBundleUrls,
      seenConfigUrls,
      budgetState,
      allowPrivate,
      deviceMode: effectiveDeviceMode,
      deviceCategory: effectiveDeviceCategory,
      ...(typeof tcpProbe === 'function' ? { tcpProbe } : {}),
      ...(typeof portProbe === 'function' ? { portProbe } : {}),
      ...(typeof rtspProbe === 'function' ? { rtspProbe } : {}),
      ...(typeof udpProbe === 'function' ? { udpProbe } : {}),
      ...(typeof tlsProbe === 'function' ? { tlsProbe } : {}),
      ...(Number.isFinite(portTimeoutMs) ? { portTimeoutMs } : {}),
      ...(Number.isFinite(probeTimeoutMs) ? { probeTimeoutMs } : {}),
      ...(multiPort !== undefined ? { multiPort } : {}),
    });
    if (fp.apiCommunication) {
      fp.apiCommunication = sanitizeApiCommunication(fp.apiCommunication);
    }
    if (fp.runtimeSca) {
      fp.runtimeSca = sanitizeRuntimeSca(fp.runtimeSca);
    }
    stacks[initialTarget] = fp;
    const stackStr = fp.stack.length
      ? fp.stack.map(s => `${s.tech}(${s.score})`).join(', ')
      : 'unknown';
    log(`    🧠  Detected Stack      : ${fp.summary || stackStr}`);
    if (fp.detectedTags?.length) log(`    🏷️   Ecosystem Tags      : ${fp.detectedTags.join(', ')}`);
    if (fp.recommendedProfile) log(`    🎯  Recommended Profile : ${fp.recommendedProfile}`);
    if (fp.osInfo?.detected) {
      log(`    🖥️  Detected OS         : ${fp.osInfo.osName}${fp.osInfo.version ? ' ' + fp.osInfo.version : ''}${fp.osInfo.isEol ? ' [EOL ⚠️]' : ''} (${fp.osInfo.familyLabel})`);
    }
    if (fp.deviceInfo?.detected) {
      const dp = fp.deviceInfo;
      const devMeta = [
        dp.categoryLabel || dp.deviceType || 'Network Device',
        dp.vendor && dp.vendor !== 'Unknown' ? `Vendor: ${dp.vendor}` : null,
        dp.modelName ? `Model: ${dp.modelName}` : null,
        dp.os ? `OS: ${dp.os}` : null,
        dp.macAddress ? `MAC: ${dp.macAddress}` : null
      ].filter(Boolean).join(' · ');
      log(`    📺  Detected Device     : ${devMeta}`);
      if (Array.isArray(dp.openPorts) && dp.openPorts.length > 0) {
        const origins = [dp.activeHttpOrigin, dp.activeHttpsOrigin].filter(Boolean);
        const originNote = dp.basePortClosed
          ? (origins.length > 0
              ? ` (standard port 80/443 closed — routing checks to ${origins.join(', ')})`
              : ' (standard port 80/443 closed — no HTTP/HTTPS origin, skipping HTTP-only checks)')
          : '';
        log(`    🔌  Open Device Ports   : ${dp.openPorts.join(', ')}${originNote}`);
      }
    }
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

    const isDeviceBasePortClosed = Boolean(
      fp.deviceInfo?.basePortClosed &&
      (fp.deviceInfo?.detected || effectiveDeviceMode)
    );
    const effectiveProfileForSelection =
      String(profile || 'smart').toLowerCase() === 'smart' && isDeviceBasePortClosed
        ? 'device'
        : profile;

    const selection = selectScannersForStack(scanners, {
      profile: effectiveProfileForSelection,
      fp,
      techOverride,
      forceAll
    });
    let activeScanners = selection.activeScanners;
    let skippedScanners = selection.skippedScanners;
    if (Array.isArray(checks) && checks.length > 0) {
      const wantedLower = new Set(checks.map(c => String(c).trim().toLowerCase()).filter(Boolean));
      const matchesCheckOrCve = (s) => {
        if (wantedLower.has(String(s.name || '').toLowerCase())) return true;
        const cveList = Array.isArray(s.meta?.cveIds) ? s.meta.cveIds : [];
        return cveList.some(cve => wantedLower.has(String(cve).toLowerCase()));
      };
      activeScanners = scanners.filter(matchesCheckOrCve);
      skippedScanners = scanners.filter(s => !matchesCheckOrCve(s));
    }
    const noActiveHttpService = Boolean(
      isDeviceBasePortClosed &&
      !fp.deviceInfo?.activeHttpOrigin &&
      !fp.deviceInfo?.activeHttpsOrigin
    );
    if (noActiveHttpService) {
      const NON_HTTP_DEVICE_CHECKS = new Set(['device-security', 'os-security']);
      const skippedHttpChecks = activeScanners.filter(s => !NON_HTTP_DEVICE_CHECKS.has(s.name));
      if (skippedHttpChecks.length > 0) {
        activeScanners = activeScanners.filter(s => NON_HTTP_DEVICE_CHECKS.has(s.name));
        skippedScanners = [...skippedScanners, ...skippedHttpChecks];
      }
    }

    let isBareIpHttpsSniRestricted = false;
    try {
      const parsedTarget = new URL(initialTarget);
      const rawHost = String(parsedTarget.hostname || '').replace(/^\[|\]$/g, '');
      if (parsedTarget.protocol === 'https:' && net.isIP(rawHost) !== 0) {
        let probeMarkedSni = false;
        if (bareIpProbeSummary instanceof Map) {
          const normInitial = String(initialTarget).replace(/\/+$/, '');
          for (const [k, entry] of bareIpProbeSummary.entries()) {
            if (!entry?.httpsSniRequired) continue;
            if (k === rawHost) {
              probeMarkedSni = true;
              break;
            }
            if (
              Array.isArray(entry.resolvedTargets) &&
              entry.resolvedTargets.some(rt => String(rt).replace(/\/+$/, '') === normInitial)
            ) {
              probeMarkedSni = true;
              break;
            }
          }
        }
        const fpFailedNoHttp =
          siblingSchemes.includes('http:') &&
          (!fp.summary || fp.summary === 'Unreachable or Unknown') &&
          (!Array.isArray(fp.stack) || fp.stack.length === 0) &&
          !fp.deviceInfo?.detected;
        isBareIpHttpsSniRestricted = Boolean(probeMarkedSni || fpFailedNoHttp);
      }
    } catch {}

    if (isBareIpHttpsSniRestricted) {
      const BARE_IP_SNI_HTTPS_CHECKS = new Set(['ssl-tls', 'origin-source-ip', 'os-security', 'device-security']);
      const skippedSniHttpChecks = activeScanners.filter(s => !BARE_IP_SNI_HTTPS_CHECKS.has(s.name));
      if (skippedSniHttpChecks.length > 0) {
        activeScanners = activeScanners.filter(s => BARE_IP_SNI_HTTPS_CHECKS.has(s.name));
        skippedScanners = [...skippedScanners, ...skippedSniHttpChecks];
      }
      log('    🔒  Bare-IP TLS Note    : Port 443 requires SNI hostname — scoping HTTPS checks to TLS/Origin/OS (full web checks run on sibling HTTP)');
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
      runtimeSca: fp.runtimeSca || null,
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

    while (!isDeviceBasePortClosed && !isBareIpHttpsSniRestricted && depth < maxDepth && !queue.isEmpty()) {
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
    const rawCheckConcurrency = Number(checkConcurrency);
    const effectiveCheckConcurrency = Number.isFinite(rawCheckConcurrency) && rawCheckConcurrency > 0
      ? Math.max(1, Math.min(12, Math.floor(rawCheckConcurrency)))
      : 8;
    const perPageCheckLimit = pLimit(effectiveCheckConcurrency);

    const scannerOptions = {
      allowPrivate,
      deviceMode: effectiveDeviceMode,
      deviceCategory: effectiveDeviceCategory,
      siblingSchemes,
      noActiveHttpService,
      ...(typeof tcpProbe === 'function' ? { tcpProbe } : {}),
      ...(typeof portProbe === 'function' ? { portProbe } : {}),
      ...(typeof rtspProbe === 'function' ? { rtspProbe } : {}),
      ...(typeof udpProbe === 'function' ? { udpProbe } : {}),
      ...(typeof tlsProbe === 'function' ? { tlsProbe } : {}),
      ...(typeof tlsConnect === 'function' ? { tlsConnect } : {}),
      ...(Number.isFinite(portTimeoutMs) ? { portTimeoutMs } : {}),
      ...(Number.isFinite(probeTimeoutMs) ? { probeTimeoutMs } : {}),
      ...(multiPort !== undefined ? { multiPort } : {}),
      ...(fp.deviceInfo && (fp.deviceInfo.detected || isDeviceBasePortClosed) ? {
        cachedDeviceScan: {
          deviceProfile: fp.deviceInfo.detected ? fp.deviceInfo : null,
          host: fp.deviceInfo.host,
          openPorts: fp.deviceInfo.openPorts || [],
          ...(Array.isArray(fp.deviceInfo.openServices) ? { openServices: fp.deviceInfo.openServices } : {}),
          deviceCategory: effectiveDeviceCategory,
          basePortClosed: isDeviceBasePortClosed,
          noActiveHttpService,
          isQuickFingerprint: true
        }
      } : {}),
      ...(normalizedScopeRules.length ? { scopeRules: normalizedScopeRules } : {}),
      ...(activeGovernor ? { governor: activeGovernor } : {}),
      ...(activeDnsResolver ? { dnsResolver: activeDnsResolver } : {}),
      ...(activeOastServer ? { oastServer: activeOastServer } : {}),
      targetPinStore,
    };

    const scanResults = await Promise.all(allDiscovered.map(page => checkLimit(async () => {
      const scannersForPage = pageScannersMap.get(page) || [];
      const pageResults = await Promise.all(scannersForPage.map((scan) => perPageCheckLimit(async () => {
        try {
          const trackedFetch = createTrackedFetch(fetchWithRetry);
          // When scanning a Smart TV / IoT device where base port 80 is closed, route HTTP/TLS checks
          // to the discovered active device service origin while device-security audits all ports from page.
          let targetForCheck = page;
          if (isDeviceBasePortClosed && scan.name !== 'device-security') {
            if (scan.name === 'ssl-tls' && fp.deviceInfo.activeHttpsOrigin) {
              targetForCheck = fp.deviceInfo.activeHttpsOrigin;
            } else if (fp.deviceInfo.activeHttpOrigin) {
              targetForCheck = fp.deviceInfo.activeHttpOrigin;
            } else if (fp.deviceInfo.activeHttpsOrigin) {
              targetForCheck = fp.deviceInfo.activeHttpsOrigin;
            }
          }
          const res = await scan.run(targetForCheck, trackedFetch, scannerOptions);
          const meta = scan.meta || getCheckMeta(res.name || scan.name);
          const fix = res.fix || meta?.defaultFix || undefined;

          const enriched = enrichEngine.enrichFinding({
            target: targetForCheck,
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
      })));
      return pageResults;
    })));

    const flatTargetResults = scanResults.flat();

    if (loadedDeclarativeTemplates.length > 0 && typeof runDeclarativeTemplateFn === 'function') {
      for (const tpl of loadedDeclarativeTemplates) {
        try {
          const trackedFetch = createTrackedFetch(fetchWithRetry);
          const tplRes = await runDeclarativeTemplateFn(tpl, initialTarget, trackedFetch, scannerOptions);
          const enrichedTpl = enrichEngine.enrichFinding({
            target: initialTarget,
            checkId: tplRes.checkId || tpl.id || 'custom-template',
            ...tplRes,
          }, { allowPrivate, capturedTraces: trackedFetch.getTraces() });
          flatTargetResults.push(enrichedTpl);
        } catch (err) {
          const tplId = tpl?.id || 'custom-template';
          flatTargetResults.push(enrichEngine.enrichFinding({
            target: initialTarget,
            checkId: tplId,
            name: tpl?.info?.name || tplId,
            status: 'ERROR',
            severity: 'LOW',
            reason: err.message
          }, { allowPrivate }));
        }
      }
    }

    return flatTargetResults;
  }));

  const nested = await Promise.all(targetTasks);
  nested.forEach(r => allResults.push(...r));

  // ── Summary & CVE Coverage ───────────────────────────────────────────────
  const risk       = calculateRisk(allResults);
  const apiCommunication = mergeApiCommunication(stacks, allResults);
  const runtimeSca = mergeRuntimeSca(stacks, allResults);

  for (const [targetKey, fp] of Object.entries(stacks)) {
    if (!fp || typeof fp !== 'object') continue;
    const targetFindings = allResults.filter(r => r && r.target && r.target.startsWith(targetKey));
    const mergedForTarget = mergeApiCommunication({ [targetKey]: fp }, targetFindings);
    if (mergedForTarget) {
      fp.apiCommunication = mergedForTarget;
    }
    const mergedScaForTarget = mergeRuntimeSca({ [targetKey]: fp }, targetFindings);
    if (mergedScaForTarget) {
      fp.runtimeSca = mergedScaForTarget;
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
    const { auditCveCoverage } = await import('./core/cve-audit.js');
    const cveAudit = await auditCveCoverage({ scanners, techTags: Array.from(detectedTagSet) });
    cveCoverage = summarizeCveAudit(cveAudit);
  } catch {}

  let aiSummary = null;
  let apiAnalysis = null;
  if (aiFix) {
    const [
      { generateFixSolution, summarizeScanForAudience, analyzeApiCommunication },
      llmMod
    ] = await Promise.all([
      import('./core/ai-advisor.js'),
      llmPool ? Promise.resolve(null) : import('./core/llmpool.js')
    ]);
    const advisorPool = llmPool || new llmMod.LlmPool({ autoDiscoverEnv: true });
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
  for (const [tKey, fp] of Object.entries(stacks)) {
    const dp = fp?.deviceInfo;
    if (dp?.detected) {
      const devLine = [
        dp.categoryLabel || dp.category || 'Network Device',
        dp.vendor && dp.vendor !== 'Unknown' ? `Vendor: ${dp.vendor}` : null,
        dp.modelName ? `Model: ${dp.modelName}` : null,
        dp.os ? `OS: ${dp.os}` : null,
        dp.macAddress ? `MAC: ${dp.macAddress}` : null
      ].filter(Boolean).join(' · ');
      log(`📺 Device (${tKey}): ${devLine}`);
      if (Array.isArray(dp.openPorts) && dp.openPorts.length > 0) {
        log(`🔌 Open Ports  : ${dp.openPorts.join(', ')}`);
      }
    }
  }
  if (cveCoverage) {
    log(`🛡️  CVE Coverage: ${cveCoverage.coveredCount}/${cveCoverage.totalAdvisories} advisories (${cveCoverage.coveragePercent}%), missing=${cveCoverage.missingCount}`);
  }
  let scanDiff = null;
  if (previousScan) {
    if (!historyMod) historyMod = await import('./core/history.js');
    scanDiff = historyMod.diffScans(previousScan, allResults);
  }
  const executiveResume = buildExecutiveResume(allResults, stacks, {
    diff: scanDiff,
    cveCoverage,
    bareIpProbeSummary,
  });
  executiveResume.cliLines.forEach(line => log(line));
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
      if ((v.checkId === 'device-security' || v.name === 'device-security') && Array.isArray(v.files) && v.files.length > 0) {
        log(`    🔎 Device Sub-Findings (${v.files.length}):`);
        v.files.forEach(f => {
          const sevLabel = f.severity || v.severity || 'MEDIUM';
          const portLabel = f.port ? ` (port ${f.port})` : '';
          log(`      - [${sevLabel}] ${f.name || f.matchedSignal || 'Device finding'}${portLabel}`);
        });
      }
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
      if ((s.checkId === 'device-security' || s.name === 'device-security') && Array.isArray(s.files) && s.files.length > 0) {
        log(`    🔎 Device Sub-Findings (${s.files.length}):`);
        s.files.forEach(f => {
          const sevLabel = f.severity || s.severity || 'MEDIUM';
          const portLabel = f.port ? ` (port ${f.port})` : '';
          log(`      - [${sevLabel}] ${f.name || f.matchedSignal || 'Device finding'}${portLabel}`);
        });
      }
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
    executiveResume,
    ...(apiCommunication ? { apiCommunication } : {}),
    ...(runtimeSca ? { runtimeSca } : {}),
  };
  if (!noHistory) {
    if (!historyMod) historyMod = await import('./core/history.js');
    historyFile = historyMod.saveHistory(validatedTargets, allResults, risk, stacks);
    autoReports = saveAutoReports(validatedTargets, allResults, risk, stacks, reportExtra);
    log(`\n📁  History saved     → ${historyFile}`);
    log(`🌐  HTML report saved → ${autoReports.htmlPath}`);
    log(`💾  JSON report saved → ${autoReports.jsonPath}`);
  }

  // ── Diff output ───────────────────────────────────────────────────────────
  if (diff && scanDiff) {
    printDiff(scanDiff, log);
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
      const [
        graphMod,
        trafficMod,
        evidenceMod,
        skillsMod,
        llmMod,
        agentMod
      ] = await Promise.all([
        graphStore ? Promise.resolve(null) : import('./core/graph-store.js'),
        trafficStore ? Promise.resolve(null) : import('./core/traffic.js'),
        evidenceStore ? Promise.resolve(null) : import('./core/evidence.js'),
        skillRegistry ? Promise.resolve(null) : import('./core/skills.js'),
        llmPool ? Promise.resolve(null) : import('./core/llmpool.js'),
        import('./core/agent-engine.js'),
      ]);
      const activeGraph = graphStore || (ownedGraphStore = new graphMod.GraphStore({ dbPath: ':memory:' }));
      const activeTraffic = trafficStore || (ownedTrafficStore = new trafficMod.TrafficStore({ dbPath: ':memory:' }));
      const activeEvidence = evidenceStore || (ownedEvidenceStore = new evidenceMod.EvidenceStore({ dbPath: ':memory:', trafficStore: activeTraffic }));
      const activeSkills = skillRegistry || new skillsMod.SkillRegistry();
      const activePool = llmPool || new llmMod.LlmPool({ autoDiscoverEnv: true });
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

      const engine = new agentMod.AgentEngine({
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
    if (runtimeSca && !report.runtimeSca) report.runtimeSca = runtimeSca;
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
      executiveResume,
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
    if (!notifyMod) notifyMod = await import('./core/notify.js');
    await notifyMod.sendWebhook(webhook, allResults, risk, validatedTargets);
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
    ...(runtimeSca ? { runtimeSca } : {}),
    ...(cveCoverage ? { cveCoverage } : {}),
  });

  log(bar);

  const authSessionSummary = authManager ? authManager.getRecordedSession({ includeSecrets: false }) : null;

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
      executiveResume,
      ...(bareIpProbeSummary && bareIpProbeSummary.size > 0
        ? { bareIpProbeSummary: Object.fromEntries(bareIpProbeSummary) }
        : {}),
      ...(authSessionSummary ? { authSession: authSessionSummary } : {}),
      ...(apiCommunication ? { apiCommunication } : {}),
      ...(runtimeSca ? { runtimeSca } : {}),
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
  } finally {
    if (ownedOastServer) {
      try {
        await ownedOastServer.stop();
      } catch {}
    }
    try {
      governedFetch.destroyAgents?.();
    } catch {}
  }
}
