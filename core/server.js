import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { URL, fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import pLimit from 'p-limit';

import { getScanners } from './registry.js';
import { PRESETS, getCheckInfo, getCheckMeta, scaffoldCheck } from './catalog.js';
import { PROFILES, getProfileChecks, selectScannersForStack, ACTIVE_FUZZING_CHECKS } from './profiles.js';
import { validateTargets, resolveAndValidateTarget } from './validator.js';
import { listHistory, loadHistoryById, diffScans, saveHistory } from './history.js';
import { generateHtmlReport, groupFindings, sanitizeApiCommunication } from './html-report.js';
import { filterSafeSameOriginApiRoutes } from './api-discovery.js';
import { saveAutoReports, generateReport, generateMarkdownReport, generateCsvReport, generateSarifReport, summarizeCveAudit, mergeApiCommunication } from './report.js';
import { auditCveCoverage, confirmCveDatabaseCoverage, CVE_DB_PROVIDERS } from './cve-audit.js';
import { CveCatalogError } from './cve-catalog.js';
import { AiAdvisorService } from './ai-advisor.js';
import { runSystemDoctor, diagnoseTarget } from './system-doctor.js';
import { validateCustomHeadersResult } from './headers.js';
import { normalizeScopeRules } from '../scan.js';
import { calculateRisk } from './severity.js';
import { fingerprint } from './fingerprint.js';
import { TaskQueue } from './queue.js';
import { crawlPage, discoverApiRoutesFromPage } from './crawler.js';
import { fetchWithRetry as baseFetch, createGovernedFetch } from './fetch.js';
import { GraphStore } from './graph-store.js';
import { TrafficStore } from './traffic.js';
import { EvidenceStore } from './evidence.js';
import { LlmPool } from './llmpool.js';
import { LlmRecorder } from './llmrec.js';
import { SideQuestionService } from './sidequestion.js';
import { NoiseGovernor, NOISE_PROFILES } from './egress.js';
import { SkillRegistry } from './skills.js';
import { AgentEngine } from './agent-engine.js';
import { foldColdGraph } from './coldgraph.js';
import { FIELD_SPECS, AssetDslError } from './asset-dsl.js';
import { EnrichEngine, ingestScanOutput, buildFindingAssetTree } from './enrich.js';
import { createTrackedFetch } from './reproduction.js';
import { evaluateAssetGate, evaluateInterceptRules, scoreRisk, decideClosed, TargetPinStore } from './guard.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const UI_DIR = path.resolve(__dirname, '../ui');
const UI_COMPONENTS_DIR = path.resolve(UI_DIR, 'components');
const PKG_VERSION = (() => {
  try {
    const pkgPath = path.resolve(__dirname, '../package.json');
    return JSON.parse(fs.readFileSync(pkgPath, 'utf8')).version || '2.2.0';
  } catch {
    return '2.2.0';
  }
})();

const JEV_KEY_ALIASES = {
  q2_authorized: 'q2_no_destructive_side_effects',
  q3_non_destructive: 'q3_reversible',
  q4_rate_bounded: 'q4_within_rate_budget',
  q5_no_exfiltration: 'q5_no_credential_exfil',
  q6_evidence_only: 'q6_no_cross_tenant_impact',
  q7_rollback_safe: 'q7_valid_verification_intent'
};

function normalizeJevAnswers(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return raw;
  const normalized = { ...raw };
  for (const [alias, canonical] of Object.entries(JEV_KEY_ALIASES)) {
    if (!(canonical in normalized) && alias in normalized) {
      normalized[canonical] = normalized[alias];
    }
  }
  return normalized;
}

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.ico': 'image/x-icon'
};

/**
 * Apply hardened security headers on every response.
 */
function applySecurityHeaders(res) {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
  );
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
}

/**
 * Validate Origin and Host headers against DNS rebinding & CSRF attacks.
 */
function isOriginAndHostAllowed(req) {
  const origin = req.headers['origin'];
  if (origin) {
    try {
      const parsedOrigin = new URL(origin);
      const originHost = parsedOrigin.hostname.toLowerCase();
      if (
        originHost !== 'localhost' &&
        originHost !== '127.0.0.1' &&
        originHost !== '[::1]' &&
        originHost !== '::1'
      ) {
        return false;
      }
    } catch {
      return false;
    }
  }

  const host = req.headers['host'];
  if (!host || typeof host !== 'string') {
    return false;
  }

  if (!/^(\[::1\]|localhost|127\.0\.0\.1)(:\d+)?$/i.test(host.trim())) {
    return false;
  }

  return true;
}

/**
 * Shared JSON body parser enforcing a strict byte limit and Content-Type checks.
 */
function parseBodyWithLimit(req, res, { maxBytes = 65536, optional = false } = {}) {
  return new Promise(resolve => {
    let settled = false;

    const finish = (statusCode, data) => {
      if (settled || res.headersSent) return;
      settled = true;
      if (statusCode !== null) {
        sendJson(res, statusCode, data);
        resolve(null);
      } else {
        resolve(data);
      }
    };

    const contentType = String(req.headers['content-type'] || '').toLowerCase();
    const isJsonContentType = contentType.includes('application/json');

    if (!optional && !isJsonContentType) {
      finish(415, { error: 'Content-Type must be application/json' });
      return;
    }

    let size = 0;
    const chunks = [];

    req.on('data', chunk => {
      if (settled || res.headersSent) return;
      size += chunk.length;
      if (size > maxBytes) {
        res.setHeader('Connection', 'close');
        finish(413, { error: 'Payload too large (max 64KB)' });
        if (typeof res.once === 'function') {
          res.once('finish', () => {
            if (typeof req.destroy === 'function' && !req.destroyed) req.destroy();
          });
        }
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      if (settled || res.headersSent) return;
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw.trim()) {
        finish(null, {});
        return;
      }
      if (optional && contentType && !isJsonContentType) {
        finish(415, { error: 'Content-Type must be application/json' });
        return;
      }
      try {
        const parsed = JSON.parse(raw);
        finish(null, parsed);
      } catch (err) {
        finish(400, { error: `Invalid JSON body: ${err.message}` });
      }
    });

    req.on('error', () => {
      if (settled || res.headersSent) return;
      finish(400, { error: 'Stream read error' });
    });
  });
}

/**
 * Parse JSON body with strict 64KB limit.
 */
function parseJsonBody(req, res, maxBytes = 65536) {
  return parseBodyWithLimit(req, res, { maxBytes, optional: false });
}

const readJsonBody = parseJsonBody;

/**
 * Parses an optional JSON body: enforces 64KB 413 limit with or without Content-Type,
 * and rejects non-JSON Content-Type when a non-empty body is supplied.
 */
function parseOptionalJsonBody(req, res, maxBytes = 65536) {
  return parseBodyWithLimit(req, res, { maxBytes, optional: true });
}

function sendJson(res, status, data) {
  if (res.headersSent) return;
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body)
  });
  res.end(body);
}

function capApiCommunicationInput(value, depth = 0) {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return value.slice(0, 512);
  if (depth > 4) return undefined;
  if (Array.isArray(value)) {
    return value.slice(0, 50).map(item => capApiCommunicationInput(item, depth + 1));
  }
  if (typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value).slice(0, 30)) {
      out[k] = capApiCommunicationInput(v, depth + 1);
    }
    return out;
  }
  return value;
}

/**
 * Broadcast an event to all connected SSE clients and record it in job events.
 */
function broadcastJobEvent(job, evt) {
  const eventPayload = {
    ...evt,
    timestamp: new Date().toISOString(),
    progress: job.progress,
    phase: job.phase
  };
  job.events.push(eventPayload);

  const eventName = eventPayload.type || 'message';
  const sseData = `event: ${eventName}\ndata: ${JSON.stringify(eventPayload)}\n\n`;

  for (const client of job.clients) {
    try {
      client.write(sseData);
    } catch {
      job.clients.delete(client);
    }
  }
}

/**
 * Executes a security scan job asynchronously with real-time SSE progress reporting.
 */
async function executeScanJob(job, ctx = {}) {
  try {
    job.progress = 5;
    job.phase = 'starting';
    broadcastJobEvent(job, {
      type: 'start',
      message: `Starting scan for target(s): ${job.targets.join(', ')}`
    });

    const allowPrivate = Boolean(job.allowPrivate);
    const enrichEngine = ctx.enrichEngine || new EnrichEngine({ allowPrivate });
    const activeGovernor = job.noiseProfile
      ? new NoiseGovernor({ profile: job.noiseProfile })
      : (typeof ctx.getNoiseGovernor === 'function' ? ctx.getNoiseGovernor() : ctx.noiseGovernor);
    const activeScopeRules = typeof ctx.getScopeRules === 'function' ? ctx.getScopeRules() : ctx.scopeRules;
    const targetPinStore = ctx.targetPinStore || new TargetPinStore({ allowPrivate });
    const customHeaders = job.headers && typeof job.headers === 'object' ? job.headers : {};
    const authHeaders = job.auth ? { Authorization: job.auth } : {};
    const governedFetch = createGovernedFetch({
      ...(activeGovernor ? { governor: activeGovernor } : {}),
      ...(Array.isArray(activeScopeRules) && activeScopeRules.length ? { scopeRules: activeScopeRules } : {}),
      ...(ctx.trafficStore ? { trafficStore: ctx.trafficStore, taskId: `scan_${job.id}` } : {}),
      ...(ctx.dnsResolver ? { dnsResolver: ctx.dnsResolver } : {}),
      ...(ctx.fetcher ? { fetcher: ctx.fetcher } : {}),
      enforceDnsValidation: true,
      allowPrivate,
      targetPinStore,
      retries: 2,
      timeout: job.timeout
    });
    const fetchWithRetry = (url, opts = {}) =>
      governedFetch(url, {
        ...opts,
        headers: { ...customHeaders, ...authHeaders, ...(opts.headers || {}) }
      });
    fetchWithRetry.governance = governedFetch.governance;
    fetchWithRetry.tlsAlpnProbe = governedFetch.tlsAlpnProbe;

    const scanners = await getScanners();

    const allResults = [];
    const stacks = [];
    let totalPagesFound = 0;

    const targetLimit = pLimit(Math.max(1, Math.min(job.concurrency, 10)));

    const targetPromises = job.targets.map(initialTarget =>
      targetLimit(async () => {
        // 1. Tech Stack Fingerprinting
        job.phase = 'fingerprinting';
        job.progress = Math.min(job.progress + 5, 20);
        broadcastJobEvent(job, {
          type: 'fingerprinting',
          target: initialTarget,
          message: `Fingerprinting tech stack for ${initialTarget}...`
        });

        const seenBundleUrls = new Set();
        const seenConfigUrls = new Set();
        const budgetState = { bytes: 0 };
        const fp = await fingerprint(initialTarget, fetchWithRetry, {
          seenBundleUrls,
          seenConfigUrls,
          budgetState
        });
        const safeFpApiComm = fp.apiCommunication ? sanitizeApiCommunication(fp.apiCommunication) : null;
        if (safeFpApiComm) fp.apiCommunication = safeFpApiComm;
        const { activeScanners, skippedScanners } = selectScannersForStack(scanners, {
          profile: job.profile,
          fp,
          techOverride: job.techOverride,
          forceAll: job.forceAll
        });

        stacks.push({
          target: initialTarget,
          primary: fp.primary,
          confidence: fp.confidence,
          summary: fp.summary,
          stack: fp.stack,
          detectedTags: fp.detectedTags,
          recommendedProfile: fp.recommendedProfile,
          categories: fp.categories,
          apiCommunication: safeFpApiComm,
          activeChecksCount: activeScanners.length,
          skippedChecksCount: skippedScanners.length,
          skippedChecks: skippedScanners.map(s => s.name)
        });

        broadcastJobEvent(job, {
          type: 'fingerprint',
          target: initialTarget,
          primary: fp.primary,
          confidence: fp.confidence,
          summary: fp.summary,
          stack: fp.stack,
          detectedTags: fp.detectedTags,
          recommendedProfile: fp.recommendedProfile,
          categories: fp.categories,
          apiCommunication: safeFpApiComm,
          activeChecksCount: activeScanners.length,
          skippedChecksCount: skippedScanners.length,
          skippedChecks: skippedScanners.map(s => s.name),
          message: `Detected stack: ${
            fp.summary ||
            (fp.stack && fp.stack.length
              ? fp.stack.map(s => `${s.tech} (${s.score})`).join(', ')
              : 'Generic Web Application')
          } (${activeScanners.length} checks active, ${skippedScanners.length} skipped)`
        });

        // 2. Autonomous Web Crawling
        job.phase = 'crawling';
        job.progress = Math.min(job.progress + 10, 35);
        broadcastJobEvent(job, {
          type: 'crawling',
          target: initialTarget,
          message: `Discovering pages on ${initialTarget} (max depth: ${job.maxDepth})...`
        });

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

        while (depth < job.maxDepth && !queue.isEmpty()) {
          const currentBatch = queue.pending.splice(0, queue.pending.length);
          broadcastJobEvent(job, {
            type: 'crawl_depth',
            target: initialTarget,
            depth,
            pending: currentBatch.length,
            pagesFound: queue.totalFound,
            message: `Depth ${depth}: Analyzing ${currentBatch.length} pages for links...`
          });

          for (const p of currentBatch) {
            try {
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
            } catch {
              // Non-fatal crawl failure on single page
            }
          }
          depth++;
        }

        const discoveredUrls = Array.from(queue.seen);
        totalPagesFound += discoveredUrls.length;

        broadcastJobEvent(job, {
          type: 'crawl_complete',
          target: initialTarget,
          pagesFound: discoveredUrls.length,
          pages: discoveredUrls,
          message: `Crawl complete. Found ${discoveredUrls.length} unique pages on ${initialTarget}`
        });

        // 3. Run active scanners across discovered pages
        job.phase = 'scanning';

        const pageScannersMap = new Map();
        let targetPlanned = 0;
        for (const page of discoveredUrls) {
          const isRoot = (page.replace(/\/+$/, '') === normalizedInitialTarget || discoveredUrls.length === 1);
          const checksForPage = isRoot
            ? activeScanners
            : activeScanners.filter(s => ACTIVE_FUZZING_CHECKS.has(s.name));
          pageScannersMap.set(page, checksForPage);
          targetPlanned += checksForPage.length;
        }

        const totalChecks = Math.max(1, targetPlanned);
        let completedChecks = 0;

        broadcastJobEvent(job, {
          type: 'scanning',
          target: initialTarget,
          checkCount: activeScanners.length,
          pageCount: discoveredUrls.length,
          plannedChecks: totalChecks,
          message: `Running checks against ${discoveredUrls.length} discovered pages (${totalChecks} total checks planned)...`
        });

        const pageLimit = pLimit(3);
        const scannerOptions = {
          allowPrivate,
          ...(Array.isArray(activeScopeRules) && activeScopeRules.length ? { scopeRules: activeScopeRules } : {}),
          ...(activeGovernor ? { governor: activeGovernor } : {}),
          ...(ctx.dnsResolver ? { dnsResolver: ctx.dnsResolver } : {}),
          targetPinStore
        };

        const pageResultsNested = await Promise.all(
          discoveredUrls.map(page =>
            pageLimit(async () => {
              const targetPageResults = [];
              const scannersForPage = pageScannersMap.get(page) || [];

              for (const scanner of scannersForPage) {
                try {
                  const trackedFetch = createTrackedFetch(fetchWithRetry);
                  const res = await scanner.run(page, trackedFetch, scannerOptions);
                  const meta = res.meta || scanner.meta || getCheckMeta(scanner.name);
                  const finding = enrichEngine.enrichFinding({
                    target: page,
                    checkId: scanner.name,
                    ...res,
                    meta
                  }, { capturedTraces: trackedFetch.getTraces() });

                  if (
                    finding.status !== 'SAFE' &&
                    finding.status !== 'ERROR' &&
                    finding.trafficId &&
                    ctx.evidenceStore &&
                    typeof ctx.evidenceStore.captureSnapshotFromExchange === 'function' &&
                    typeof ctx.evidenceStore.bindEvidence === 'function'
                  ) {
                    try {
                      const snap = ctx.evidenceStore.captureSnapshotFromExchange(finding.trafficId, {
                        taskId: job.taskId || null
                      });
                      if (snap?.id) {
                        const firstQuote = Array.isArray(finding.evidenceQuotes) && finding.evidenceQuotes.length > 0
                          ? finding.evidenceQuotes[0]
                          : '';
                        const findingIdsToBind = new Set([
                          `${finding.checkId}::${finding.target}`,
                          `${finding.checkId}::${initialTarget}`,
                          `${finding.checkId}::${normalizedInitialTarget}`
                        ]);
                        for (const fid of findingIdsToBind) {
                          ctx.evidenceStore.bindEvidence({
                            findingId: fid,
                            snapshotId: snap.id,
                            role: 'proof',
                            quote: firstQuote
                          });
                        }
                      }
                    } catch {
                      // Non-fatal evidence binding error
                    }
                  }

                  targetPageResults.push(finding);

                  completedChecks++;
                  const progressPct = 35 + Math.round((completedChecks / totalChecks) * 55);
                  job.progress = Math.min(progressPct, 92);

                  broadcastJobEvent(job, {
                    type: 'check',
                    target: page,
                    checkId: scanner.name,
                    status: finding.status,
                    severity: finding.severity,
                    name: finding.name || scanner.name,
                    title: meta?.title || finding.name || scanner.name,
                    fix: finding.fix || meta?.defaultFix || null,
                    reason: finding.reason || null,
                    ...(finding.detail ? { detail: finding.detail } : {}),
                    ...(finding.path ? { path: finding.path } : {}),
                    ...(Array.isArray(finding.files) ? { files: finding.files } : {}),
                    ...(Array.isArray(finding.findings) ? { findings: finding.findings } : {}),
                    ...(Array.isArray(finding.missing) ? { missing: finding.missing } : {}),
                    ...(Array.isArray(finding.present) ? { present: finding.present } : {}),
                    ...(Array.isArray(finding.evidenceQuotes) ? { evidenceQuotes: finding.evidenceQuotes } : {}),
                    ...(finding.reproVerified !== undefined ? { reproVerified: finding.reproVerified } : {}),
                    ...(finding.poeLevel !== undefined ? { poeLevel: finding.poeLevel } : {}),
                    ...(finding.trafficId !== undefined ? { trafficId: finding.trafficId } : {}),
                    cwe: finding.cwe,
                    owasp: finding.owasp,
                    cvssScore: finding.cvssScore,
                    cveIds: finding.cveIds,
                    ...(finding.reproduction ? { reproduction: finding.reproduction } : {})
                  });
                } catch (err) {
                  const meta = scanner.meta || getCheckMeta(scanner.name);
                  const errorFinding = enrichEngine.enrichFinding({
                    target: page,
                    checkId: scanner.name,
                    name: scanner.name,
                    status: 'ERROR',
                    severity: 'LOW',
                    reason: err.message,
                    meta
                  });
                  targetPageResults.push(errorFinding);
                  completedChecks++;
                  const progressPct = 35 + Math.round((completedChecks / totalChecks) * 55);
                  job.progress = Math.min(progressPct, 92);

                  broadcastJobEvent(job, {
                    type: 'check',
                    target: page,
                    checkId: scanner.name,
                    status: errorFinding.status,
                    severity: errorFinding.severity,
                    name: errorFinding.name || scanner.name,
                    title: meta?.title || errorFinding.name || scanner.name,
                    fix: errorFinding.fix || meta?.defaultFix || null,
                    reason: errorFinding.reason || err.message || null,
                    cwe: errorFinding.cwe,
                    owasp: errorFinding.owasp,
                    cvssScore: errorFinding.cvssScore,
                    cveIds: errorFinding.cveIds
                  });
                }
              }
              return targetPageResults;
            })
          )
        );

        return pageResultsNested.flat();
      })
    );

    const nestedResults = await Promise.all(targetPromises);
    nestedResults.forEach(list => allResults.push(...list));

    // 5. Finalizing results and calculating risk
    job.phase = 'finalizing';
    job.progress = 96;
    broadcastJobEvent(job, {
      type: 'finalizing',
      message: 'Calculating security grade and compiling executive summary...'
    });

    const risk = calculateRisk(allResults);
    const groupedResults = groupFindings(allResults);
    const apiCommunication = mergeApiCommunication(stacks, allResults);
    for (const s of stacks) {
      if (s && typeof s === 'object') {
        const targetFindings = allResults.filter(r => r && r.target && s.target && r.target.startsWith(s.target));
        const mergedTargetApi = mergeApiCommunication([s], targetFindings);
        if (mergedTargetApi) {
          s.apiCommunication = mergedTargetApi;
        }
      }
    }

    let cveCoverage = null;
    try {
      const detectedTagSet = new Set();
      for (const s of stacks) {
        if (Array.isArray(s?.detectedTags)) {
          for (const t of s.detectedTags) {
            if (typeof t === 'string' && t.trim()) detectedTagSet.add(t.trim().toLowerCase());
          }
        }
      }
      if (Array.isArray(job.techOverride)) {
        for (const t of job.techOverride) {
          if (typeof t === 'string' && t.trim()) detectedTagSet.add(t.trim().toLowerCase());
        }
      }
      const cveAudit = await auditCveCoverage({ scanners, techTags: Array.from(detectedTagSet) });
      cveCoverage = summarizeCveAudit(cveAudit);
    } catch {}

    let historyFile = null;
    let htmlReportFile = null;
    let jsonReportFile = null;
    if (!job.noHistory) {
      historyFile = saveHistory(job.targets, allResults, risk, stacks);
      if (historyFile && (apiCommunication || cveCoverage)) {
        try {
          const histRaw = JSON.parse(fs.readFileSync(historyFile, 'utf8'));
          if (apiCommunication) histRaw.apiCommunication = apiCommunication;
          if (cveCoverage) histRaw.cveCoverage = cveCoverage;
          fs.writeFileSync(historyFile, JSON.stringify(histRaw, null, 2));
        } catch {}
      }
      try {
        const autoReports = saveAutoReports(job.targets, allResults, risk, stacks, {
          cveCoverage,
          ...(apiCommunication ? { apiCommunication } : {})
        });
        htmlReportFile = autoReports.htmlPath;
        jsonReportFile = autoReports.jsonPath;
      } catch {}
    }

    let ingestedTask = null;
    if (ctx.graphStore && typeof ctx.graphStore.ingestStaticScanResult === 'function') {
      try {
        ingestedTask = ctx.graphStore.ingestStaticScanResult({
          taskId: `scan_${job.id}`,
          title: `Scan: ${job.targets.join(', ')}`,
          targets: job.targets,
          results: allResults,
          risk,
          stacks,
          allow_private: allowPrivate,
          allowPrivate
        });
      } catch {}
    }

    let agentSummary = null;
    if (job.agent && ctx.graphStore && ctx.agentEngine) {
      try {
        job.phase = 'agent';
        broadcastJobEvent(job, {
          type: 'agent',
          message: `Running Agentic Verification loop for ${job.targets[0]}...`
        });
        const primaryTarget = job.targets[0];
        const agentTask = ctx.graphStore.createTask({
          title: `Agentic Verification: ${primaryTarget}`,
          target: primaryTarget,
          goal: job.goal || `Discover and verify security findings on ${primaryTarget}`,
          mode: 'auto',
          noise_profile: activeGovernor ? activeGovernor.profile : (job.noiseProfile || 'balanced'),
          scope: Array.isArray(activeScopeRules) ? activeScopeRules : undefined,
          allow_private: allowPrivate,
          allowPrivate,
        });
        if (typeof ctx.setTaskAllowPrivate === 'function') {
          ctx.setTaskAllowPrivate(agentTask.id, allowPrivate);
        }
        agentSummary = await ctx.agentEngine.runTaskLoop(agentTask.id, {
          maxRounds: Number(job.maxAgentRounds || 5),
          debounceMs: 0,
          allowPrivate,
          ...(typeof ctx.getScopeRules === 'function'
            ? { getScopeRules: ctx.getScopeRules }
            : Array.isArray(activeScopeRules)
              ? { scopeRules: [...activeScopeRules] }
              : {}),
        });
      } catch {}
    }

    job.status = 'completed';
    job.progress = 100;
    job.phase = 'completed';
    job.result = {
      results: allResults,
      groupedResults,
      risk,
      historyFile,
      htmlReportFile,
      jsonReportFile,
      stacks,
      apiCommunication: apiCommunication || null,
      ...(cveCoverage ? { cveCoverage } : {}),
      taskId: ingestedTask?.taskId || null,
      ...(agentSummary ? { agentSummary } : {}),
      pagesCount: totalPagesFound,
      completedAt: new Date().toISOString()
    };

    broadcastJobEvent(job, {
      type: 'complete',
      status: 'completed',
      result: job.result,
      message: `Scan complete! Grade: ${risk.grade} (${risk.level} Risk, Score ${risk.score})`
    });

    for (const client of job.clients) {
      try {
        client.end();
      } catch {}
    }
    job.clients.clear();
  } catch (err) {
    job.status = 'failed';
    job.phase = 'failed';
    job.error = err.message;

    broadcastJobEvent(job, {
      type: 'error',
      status: 'failed',
      error: err.message,
      message: `Scan failed: ${err.message}`
    });

    for (const client of job.clients) {
      try {
        client.end();
      } catch {}
    }
    job.clients.clear();
  }
}

/**
 * Serves static files strictly confined within the `ui/` folder.
 */
function serveStaticFile(req, res, pathname) {
  let decodedPath;
  try {
    decodedPath = decodeURIComponent(pathname);
  } catch {
    sendJson(res, 400, { error: 'Malformed URL path' });
    return;
  }

  if (decodedPath.includes('..') || decodedPath.includes('\0')) {
    sendJson(res, 403, { error: 'Access denied' });
    return;
  }

  let filePath;
  if (decodedPath.startsWith('/components/')) {
    const compName = decodedPath.slice('/components/'.length);
    if (!/^[a-z0-9-]+\.js$/.test(compName)) {
      sendJson(res, 403, { error: 'Access denied' });
      return;
    }
    filePath = path.resolve(UI_COMPONENTS_DIR, compName);
    if (!filePath.startsWith(UI_COMPONENTS_DIR + path.sep)) {
      sendJson(res, 403, { error: 'Access denied' });
      return;
    }
  } else {
    let cleanPath = decodedPath;
    if (cleanPath === '/' || cleanPath === '') {
      cleanPath = '/index.html';
    }

    // Sanitize path and prevent directory traversal
    const normalized = path.normalize(cleanPath).replace(/^(\.\.[/\\])+/, '');
    filePath = path.resolve(UI_DIR, '.' + normalized);

    if (!filePath.startsWith(UI_DIR + path.sep) && filePath !== path.join(UI_DIR, 'index.html')) {
      sendJson(res, 403, { error: 'Access denied' });
      return;
    }
  }

  if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
    sendJson(res, 404, { error: 'File not found' });
    return;
  }

  const ext = path.extname(filePath).toLowerCase();
  const mime = MIME_TYPES[ext] || 'application/octet-stream';
  const fileContent = fs.readFileSync(filePath);

  res.writeHead(200, {
    'Content-Type': mime,
    'Content-Length': fileContent.length,
    'Cache-Control': 'no-cache'
  });
  res.end(fileContent);
}

/**
 * Creates the HTTP Server with all security controls and API endpoints.
 */
export function createAppServer(options = {}) {
  const jobs = new Map();
  const MAX_JOBS = 100;

  const historyDir = options.historyDir || path.join(process.cwd(), '.secscan-history');
  const useInMemory = Boolean(options.inMemory);

  const ownsGraphStore = !options.graphStore;
  const graphStore = options.graphStore || new GraphStore({
    dbPath: options.graphDbPath || (useInMemory ? ':memory:' : path.join(historyDir, 'secscan-graph.sqlite'))
  });

  const ownsTrafficStore = !options.trafficStore;
  const trafficStore = options.trafficStore || new TrafficStore({
    dbPath: options.trafficDbPath || (useInMemory ? ':memory:' : path.join(historyDir, 'secscan-traffic.sqlite')),
    blobDir: options.trafficBlobDir !== undefined ? options.trafficBlobDir : (useInMemory ? null : path.join(historyDir, 'traffic-blobs'))
  });

  const ownsEvidenceStore = !options.evidenceStore;
  const evidenceStore = options.evidenceStore || new EvidenceStore({
    dbPath: options.evidenceDbPath || (useInMemory ? ':memory:' : path.join(historyDir, 'secscan-evidence.sqlite')),
    blobDir: options.evidenceBlobDir !== undefined ? options.evidenceBlobDir : (useInMemory ? null : path.join(historyDir, 'evidence-blobs')),
    trafficStore
  });

  const llmRecorder = options.llmRecorder || new LlmRecorder();
  const llmPool = options.llmPool || new LlmPool({ recorder: llmRecorder, autoDiscoverEnv: true });
  const aiAdvisor = options.aiAdvisor || new AiAdvisorService({ llmPool });
  const sideQuestionService = options.sideQuestionService || new SideQuestionService({ llmPool });
  let noiseGovernor = options.noiseGovernor || new NoiseGovernor({ profile: options.noiseProfile || 'balanced' });
  const skillRegistry = options.skillRegistry || new SkillRegistry();
  const defaultAllowPrivate = Boolean(options.allowPrivate);
  let scopeRules = Array.isArray(options.scopeRules) ? normalizeScopeRules(options.scopeRules) : [];
  let interceptRules = Array.isArray(options.interceptRules) ? [...options.interceptRules] : [];
  const agentDnsResolver = options.dnsResolver ?? options.retestOptions?.dnsResolver ?? null;
  const agentEngine = options.agentEngine || new AgentEngine({
    graphStore,
    llmPool,
    trafficStore,
    evidenceStore,
    skillRegistry,
    getScopeRules: () => scopeRules,
    ...(agentDnsResolver ? { dnsResolver: agentDnsResolver } : {}),
    ...(options.agentOptions || {})
  });
  const enrichEngine = new EnrichEngine({ allowPrivate: defaultAllowPrivate });
  const taskAllowPrivateMap = new Map();
  const withTaskAllowPrivate = (task) => {
    if (!task) return task;
    const flag = Boolean(task.allowPrivate || task.allow_private || taskAllowPrivateMap.get(task.id));
    return {
      ...task,
      allowPrivate: flag,
      allow_private: flag
    };
  };

  function pruneJobs() {
    if (jobs.size <= MAX_JOBS) return;

    // Evict oldest completed or failed jobs first
    for (const [id, job] of jobs.entries()) {
      if (job.status === 'completed' || job.status === 'failed') {
        jobs.delete(id);
        if (jobs.size <= MAX_JOBS) return;
      }
    }

    // If still over cap, evict oldest jobs
    for (const [id] of jobs.entries()) {
      jobs.delete(id);
      if (jobs.size <= MAX_JOBS) return;
    }
  }

  const server = http.createServer(async (req, res) => {
    applySecurityHeaders(res);

    // ── Host & Origin validation on ALL requests ────────────────────────────
    if (!isOriginAndHostAllowed(req)) {
      sendJson(res, 403, { error: 'Forbidden: Invalid Origin or Host header' });
      return;
    }

    const rawPathOnly = String(req.url || '').split('?')[0];
    if (/(?:^|[\\/])\.\.(?:[\\/]|$)|%2e%2e/i.test(rawPathOnly)) {
      sendJson(res, 403, { error: 'Access denied' });
      return;
    }

    let parsedUrl;
    try {
      parsedUrl = new URL(req.url, `http://${req.headers.host || '127.0.0.1'}`);
    } catch {
      sendJson(res, 400, { error: 'Malformed request URL' });
      return;
    }

    const pathname = parsedUrl.pathname;
    const method = req.method ? req.method.toUpperCase() : 'GET';

    // ── API: GET /api/meta ───────────────────────────────────────────────────
    if (method === 'GET' && pathname === '/api/meta') {
      try {
        const scanners = await getScanners();
        const checks = scanners.map(s => ({
          id: s.name,
          tags: s.tags,
          meta: s.meta || getCheckInfo(s.name)
        }));
        const categorySet = new Set();
        for (const c of checks) {
          if (c.meta?.category) categorySet.add(c.meta.category);
        }
        const categories = Array.from(categorySet).sort((a, b) => a.localeCompare(b));
        let cveCoverageSummary = null;
        try {
          const audit = await auditCveCoverage({ scanners });
          cveCoverageSummary = summarizeCveAudit(audit);
        } catch {}

        sendJson(res, 200, {
          version: PKG_VERSION,
          totalChecks: checks.length,
          categories,
          cveCoverageSummary,
          cveDbProviders: Object.values(CVE_DB_PROVIDERS),
          allowPrivate: defaultAllowPrivate,
          presets: PRESETS,
          profiles: PROFILES,
          ai: llmPool.getPoolStatus(),
          checks
        });
      } catch (err) {
        sendJson(res, 500, { error: `Failed to load metadata: ${err.message}` });
      }
      return;
    }

    // ── API: GET /api/cves/coverage, POST /api/cves/audit & POST /api/cves/confirm-db ─
    if (method === 'GET' && pathname === '/api/cves/coverage') {
      try {
        const techParam = parsedUrl.searchParams.get('tech') || '';
        const techTags = techParam
          .split(',')
          .map(s => s.trim())
          .filter(Boolean);
        const feedParam = (parsedUrl.searchParams.get('feed') || '').toLowerCase().trim();
        const providerParam = (parsedUrl.searchParams.get('provider') || parsedUrl.searchParams.get('db') || '').trim();
        const dbUrlParam = (parsedUrl.searchParams.get('dbUrl') || parsedUrl.searchParams.get('feedUrl') || '').trim();
        const packagesParam = (parsedUrl.searchParams.get('packages') || parsedUrl.searchParams.get('pkg') || '').trim();
        const includeFeed =
          feedParam === '1' ||
          feedParam === 'true' ||
          feedParam === 'yes' ||
          Boolean(providerParam || dbUrlParam);
        const audit = await auditCveCoverage({
          techTags,
          ...(packagesParam ? { packages: packagesParam } : {}),
          ...(providerParam ? { provider: providerParam } : {}),
          includeFeed,
          allowPrivate: defaultAllowPrivate,
          ...(scopeRules.length ? { scopeRules } : {}),
          ...(agentDnsResolver ? { dnsResolver: agentDnsResolver } : {}),
          ...((dbUrlParam || options.cveFeedUrl) ? { feedUrl: dbUrlParam || options.cveFeedUrl } : {}),
          ...(options.fetcher ? { fetchImpl: options.fetcher } : {})
        });
        sendJson(res, 200, audit);
      } catch (err) {
        sendJson(res, 500, { error: `Failed to audit CVE coverage: ${err.message}` });
      }
      return;
    }

    if (method === 'POST' && (pathname === '/api/cves/audit' || pathname === '/api/cves/confirm-db')) {
      const body = await parseOptionalJsonBody(req, res);
      if (!body) return;
      if (typeof body !== 'object' || Array.isArray(body)) {
        sendJson(res, 400, { error: 'Request body must be a JSON object' });
        return;
      }
      if (body.advisories !== undefined && body.advisories !== null && !Array.isArray(body.advisories)) {
        sendJson(res, 400, { error: 'advisories must be an array' });
        return;
      }
      const isConfirmRoute = pathname === '/api/cves/confirm-db';
      if (
        body.techTags !== undefined &&
        body.techTags !== null &&
        !Array.isArray(body.techTags) &&
        !(isConfirmRoute && typeof body.techTags === 'string')
      ) {
        sendJson(res, 400, { error: 'techTags must be an array' });
        return;
      }
      try {
        const provider = body.provider || body.dbProvider || null;
        const dbUrl = body.dbUrl || body.feedUrl || options.cveFeedUrl || null;
        const auditFn = isConfirmRoute ? confirmCveDatabaseCoverage : auditCveCoverage;
        const audit = await auditFn({
          advisories: body.advisories ?? null,
          externalPayload: body.externalPayload ?? null,
          techTags: body.techTags ?? [],
          packages: body.packages ?? [],
          ...(provider ? { provider } : {}),
          includeFeed: body.includeFeed !== undefined ? Boolean(body.includeFeed) : Boolean(isConfirmRoute && (provider || dbUrl)),
          allowPrivate: defaultAllowPrivate,
          ...(scopeRules.length ? { scopeRules } : {}),
          ...(agentDnsResolver ? { dnsResolver: agentDnsResolver } : {}),
          ...(dbUrl ? { feedUrl: dbUrl } : {}),
          ...(options.fetcher ? { fetchImpl: options.fetcher } : {})
        });
        sendJson(res, 200, audit);
      } catch (err) {
        const status = err instanceof CveCatalogError || err.name === 'CveCatalogError' ? 400 : 500;
        sendJson(res, status, { error: err.message });
      }
      return;
    }

    // ── API: POST /api/fingerprint ───────────────────────────────────────────
    if (method === 'POST' && pathname === '/api/fingerprint') {
      const body = await parseJsonBody(req, res);
      if (!body) return;

      const { target, auth = null, timeout = 10000 } = body;
      const allowPrivate = body.allowPrivate !== undefined ? Boolean(body.allowPrivate) : defaultAllowPrivate;
      const rawTargets = target ? [String(target).trim()] : [];
      const validation = validateTargets(rawTargets, { allowPrivate });
      if (!validation.valid) {
        sendJson(res, 400, {
          error: validation.errors.join('; '),
          errors: validation.errors
        });
        return;
      }

      const targetUrl = validation.targets[0];
      if (scopeRules.length) {
        const gate = evaluateAssetGate(targetUrl, { rules: scopeRules });
        if (!gate.allowed) {
          sendJson(res, 403, { error: gate.reason, code: gate.code || 'TARGET_RULE_BLOCKED' });
          return;
        }
      }

      const targetPinStore = new TargetPinStore({ allowPrivate });
      const dnsResolver = options.dnsResolver ?? options.retestOptions?.dnsResolver ?? null;
      const preDns = await resolveAndValidateTarget(targetUrl, {
        resolver: dnsResolver,
        targetPinStore,
        allowPrivate
      });
      if (!preDns.valid && preDns.code === 'DNS_REBIND_OR_PRIVATE_IP') {
        sendJson(res, 403, { error: preDns.reason, code: preDns.code });
        return;
      }

      const authHeaders = auth ? { Authorization: String(auth).trim() } : {};
      const fetchTimeout = Math.max(1000, Math.min(Number(timeout) || 10000, 60000));
      const governedFetch = createGovernedFetch({
        ...(scopeRules.length ? { scopeRules } : {}),
        ...(dnsResolver ? { dnsResolver } : {}),
        ...(options.fetcher ? { fetcher: options.fetcher } : {}),
        enforceDnsValidation: true,
        allowPrivate,
        targetPinStore,
        retries: 2,
        timeout: fetchTimeout
      });
      const fetchWithRetry = (url, opts = {}) =>
        governedFetch(url, {
          ...opts,
          headers: { ...authHeaders, ...(opts.headers || {}) }
        });

      try {
        const fp = await fingerprint(targetUrl, fetchWithRetry);
        const scanners = await getScanners();
        const selection = selectScannersForStack(scanners, { profile: 'smart', fp });

        sendJson(res, 200, {
          target: targetUrl,
          fingerprint: fp,
          recommendedProfile: fp.recommendedProfile || 'smart',
          activeChecksCount: selection.activeScanners.length,
          skippedChecksCount: selection.skippedScanners.length,
          activeChecks: selection.activeScanners.map(s => ({
            id: s.name,
            title: s.meta?.title || s.name,
            category: s.meta?.category || 'General'
          })),
          skippedChecks: selection.skippedScanners.map(s => ({
            id: s.name,
            title: s.meta?.title || s.name,
            tags: s.tags
          }))
        });
      } catch (err) {
        sendJson(res, 500, { error: `Fingerprint failed: ${err.message}` });
      }
      return;
    }

    // ── API: POST /api/scan ──────────────────────────────────────────────────
    if (method === 'POST' && pathname === '/api/scan') {
      const body = await parseJsonBody(req, res);
      if (!body) return;

      const {
        target,
        targets,
        profile = 'smart',
        maxDepth = 3,
        concurrency = 5,
        timeout = 10000,
        auth = null,
        headers = null,
        techOverride = null,
        forceAll = false,
        noHistory = false,
        agent = false,
        agentMode = false,
        goal = null,
      } = body;
      const allowPrivate = body.allowPrivate !== undefined ? Boolean(body.allowPrivate) : defaultAllowPrivate;

      const headerValidation = validateCustomHeadersResult(headers);
      if (!headerValidation.valid) {
        sendJson(res, 400, { error: headerValidation.error });
        return;
      }
      const validatedCustomHeaders = headerValidation.headers;

      let requestedNoiseProfile = null;
      if (body.noiseProfile !== undefined && body.noiseProfile !== null && body.noiseProfile !== '') {
        const normNoise = String(body.noiseProfile).trim().toLowerCase();
        if (!Object.hasOwn(NOISE_PROFILES, normNoise)) {
          sendJson(res, 400, {
            error: `Invalid noiseProfile "${body.noiseProfile}". Expected off, quiet, balanced, or aggressive.`
          });
          return;
        }
        requestedNoiseProfile = normNoise;
      }

      const rawDepth = maxDepth !== undefined && maxDepth !== null && maxDepth !== ''
        ? Number(maxDepth)
        : 3;
      if (!Number.isFinite(rawDepth)) {
        sendJson(res, 400, { error: 'Invalid maxDepth: must be a finite number' });
        return;
      }
      const effectiveMaxDepth = Math.max(0, Math.min(Math.floor(rawDepth), 5));

      const rawTargets = Array.isArray(targets)
        ? targets
        : typeof target === 'string' && target.trim()
        ? [target.trim()]
        : [];

      const validation = validateTargets(rawTargets, { allowPrivate });
      if (!validation.valid) {
        sendJson(res, 400, {
          error: validation.errors.join('; '),
          errors: validation.errors
        });
        return;
      }

      const dnsResolver = options.dnsResolver ?? options.retestOptions?.dnsResolver ?? null;
      for (const validatedTarget of validation.targets) {
        if (scopeRules.length) {
          const gate = evaluateAssetGate(validatedTarget, { rules: scopeRules });
          if (!gate.allowed) {
            sendJson(res, 403, { error: gate.reason, code: gate.code || 'TARGET_RULE_BLOCKED' });
            return;
          }
        }
        const preDns = await resolveAndValidateTarget(validatedTarget, {
          resolver: dnsResolver,
          allowPrivate
        });
        if (!preDns.valid && preDns.code === 'DNS_REBIND_OR_PRIVATE_IP') {
          sendJson(res, 403, { error: preDns.reason, code: preDns.code });
          return;
        }
        if (preDns.valid && Array.isArray(preDns.resolvedIps) && preDns.resolvedIps.length > 0 && scopeRules.length) {
          const postDnsGate = evaluateAssetGate(
            { url: validatedTarget, hostname: preDns.hostname, resolvedIps: preDns.resolvedIps },
            { rules: scopeRules }
          );
          if (!postDnsGate.allowed) {
            sendJson(res, 403, { error: postDnsGate.reason, code: postDnsGate.code || 'TARGET_RULE_BLOCKED' });
            return;
          }
        }
      }

      // Concurrency check (max 3 concurrent scans)
      const activeRunningJobs = Array.from(jobs.values()).filter(
        j => j.status === 'running'
      );
      if (activeRunningJobs.length >= 3) {
        sendJson(res, 429, {
          error: 'Maximum concurrent scans reached (3). Please wait for an existing scan to finish.'
        });
        return;
      }

      const scanId = crypto.randomUUID();
      const job = {
        id: scanId,
        status: 'running',
        progress: 0,
        phase: 'initializing',
        targets: validation.targets,
        profile: profile || 'smart',
        forceAll: Boolean(forceAll),
        allowPrivate,
        noiseProfile: requestedNoiseProfile,
        agent: Boolean(agent || agentMode),
        goal: typeof goal === 'string' && goal.trim() ? goal.trim() : null,
        maxDepth: effectiveMaxDepth,
        concurrency: Math.max(1, Math.min(Number(concurrency) || 5, 10)),
        timeout: Math.max(1000, Math.min(Number(timeout) || 10000, 60000)),
        auth: typeof auth === 'string' && auth.trim() ? auth.trim() : null,
        headers: validatedCustomHeaders,
        techOverride: Array.isArray(techOverride)
          ? techOverride
          : typeof techOverride === 'string' && techOverride.trim()
          ? techOverride.split(',').map(s => s.trim()).filter(Boolean)
          : null,
        noHistory: Boolean(noHistory),
        createdAt: new Date().toISOString(),
        events: [],
        clients: new Set(),
        result: null,
        error: null
      };

      pruneJobs();
      jobs.set(scanId, job);

      // Launch async scan
      executeScanJob(job, {
        graphStore,
        trafficStore,
        evidenceStore,
        agentEngine,
        setTaskAllowPrivate: (taskId, flag) => taskAllowPrivateMap.set(taskId, Boolean(flag)),
        dnsResolver: options.dnsResolver ?? null,
        fetcher: options.fetcher ?? null,
        getNoiseGovernor: () => noiseGovernor,
        getScopeRules: () => scopeRules
      });

      sendJson(res, 202, {
        scanId,
        targets: validation.targets,
        profile: job.profile,
        allowPrivate
      });
      return;
    }

    // ── API: GET /api/scan/:id/stream (SSE) ──────────────────────────────────
    const streamMatch = pathname.match(/^\/api\/scan\/([a-zA-Z0-9_-]+)\/stream$/);
    if (method === 'GET' && streamMatch) {
      const scanId = streamMatch[1];
      const job = jobs.get(scanId);

      if (!job) {
        sendJson(res, 404, { error: 'Scan job not found' });
        return;
      }

      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache, no-transform',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no'
      });

      // Stream buffered prior events
      for (const evt of job.events) {
        const eventName = evt.type || 'message';
        res.write(`event: ${eventName}\ndata: ${JSON.stringify(evt)}\n\n`);
      }

      if (job.status === 'completed' || job.status === 'failed') {
        res.end();
      } else {
        job.clients.add(res);
        req.on('close', () => {
          job.clients.delete(res);
        });
      }
      return;
    }

    // ── API: GET /api/scan/:id ───────────────────────────────────────────────
    const scanMatch = pathname.match(/^\/api\/scan\/([a-zA-Z0-9_-]+)$/);
    if (method === 'GET' && scanMatch) {
      const scanId = scanMatch[1];
      const job = jobs.get(scanId);

      if (!job) {
        sendJson(res, 404, { error: 'Scan job not found' });
        return;
      }

      sendJson(res, 200, {
        id: job.id,
        status: job.status,
        progress: job.progress,
        phase: job.phase,
        targets: job.targets,
        result: job.result,
        error: job.error
      });
      return;
    }

    // ── API: GET /api/history ────────────────────────────────────────────────
    if (method === 'GET' && pathname === '/api/history') {
      try {
        const history = listHistory();
        sendJson(res, 200, { history });
      } catch (err) {
        sendJson(res, 500, { error: `Failed to retrieve history: ${err.message}` });
      }
      return;
    }

    // ── API: GET /api/history/:id ────────────────────────────────────────────
    const historyMatch = pathname.match(/^\/api\/history\/([a-zA-Z0-9._-]+\.json)$/);
    if (method === 'GET' && historyMatch) {
      const historyId = historyMatch[1];
      const record = loadHistoryById(historyId);

      if (!record) {
        sendJson(res, 404, { error: 'History record not found' });
        return;
      }

      // Enrich results with plain-English metadata
      if (Array.isArray(record.results)) {
        record.results = record.results.map(r => ({
          ...r,
          meta: r.meta || getCheckInfo(r.checkId || r.name)
        }));
      }
      if (!record.apiCommunication) {
        const mergedApi = mergeApiCommunication(record.stacks, record.results);
        if (mergedApi) record.apiCommunication = mergedApi;
      }

      sendJson(res, 200, { record });
      return;
    }

    // ── API: POST /api/diff ──────────────────────────────────────────────────
    if (method === 'POST' && pathname === '/api/diff') {
      const body = await parseJsonBody(req, res);
      if (!body) return;

      const { previousId, currentId, currentResults } = body;
      if (!previousId) {
        sendJson(res, 400, { error: 'previousId is required' });
        return;
      }

      const prevRecord = loadHistoryById(previousId);
      if (!prevRecord) {
        sendJson(res, 404, { error: `Previous history record "${previousId}" not found` });
        return;
      }

      let currFindings = null;
      if (currentId) {
        const currRecord = loadHistoryById(currentId);
        if (!currRecord) {
          sendJson(res, 404, { error: `Current history record "${currentId}" not found` });
          return;
        }
        currFindings = currRecord.results;
      } else if (currentResults) {
        currFindings = Array.isArray(currentResults)
          ? currentResults
          : currentResults.results || [];
      } else {
        sendJson(res, 400, { error: 'Either currentId or currentResults must be provided' });
        return;
      }

      const diff = diffScans(prevRecord, currFindings);
      sendJson(res, 200, { diff });
      return;
    }

    // ── API: POST /api/report/html ───────────────────────────────────────────
    if (method === 'POST' && pathname === '/api/report/html') {
      const body = await parseJsonBody(req, res);
      if (!body) return;

      let { historyId, results, risk, stacks, cveCoverage, apiCommunication } = body;

      if (historyId) {
        const record = loadHistoryById(historyId);
        if (!record) {
          sendJson(res, 404, { error: `History record "${historyId}" not found` });
          return;
        }
        results = record.results;
        risk = record.risk;
        if (!stacks && record.stacks) {
          stacks = record.stacks;
        }
        if (!cveCoverage && record.cveCoverage) {
          cveCoverage = record.cveCoverage;
        }
        if (!apiCommunication && record.apiCommunication) {
          apiCommunication = record.apiCommunication;
        }
      }

      if (!Array.isArray(results)) {
        sendJson(res, 400, { error: 'A valid results array or historyId is required' });
        return;
      }

      try {
        const computedRisk = risk || calculateRisk(results);
        const resolvedApi = mergeApiCommunication(stacks, results, apiCommunication);
        const reportOpts = (cveCoverage || resolvedApi)
          ? {
              ...(cveCoverage ? { cveCoverage } : {}),
              ...(resolvedApi ? { apiCommunication: resolvedApi } : {})
            }
          : null;
        const html = generateHtmlReport(results, computedRisk, stacks, reportOpts);
        sendJson(res, 200, { html });
      } catch (err) {
        sendJson(res, 500, { error: 'Failed to generate HTML report: ' + err.message });
      }
      return;
    }

    // ── API: POST /api/checks/scaffold ───────────────────────────────────────
    if (method === 'POST' && pathname === '/api/checks/scaffold') {
      const body = await parseJsonBody(req, res);
      if (!body) return;

      const {
        name,
        title,
        category,
        plainExplanation,
        whyItMatters,
        defaultFix,
        tags,
        cveIds,
        cwe,
        owasp,
        cvssScore,
        dryRun
      } = body;

      if (!name || typeof name !== 'string') {
        sendJson(res, 400, { error: 'Check name string is required' });
        return;
      }

      try {
        const result = scaffoldCheck(name, {
          title,
          category,
          plainExplanation,
          whyItMatters,
          defaultFix,
          tags,
          cveIds,
          cwe,
          owasp,
          cvssScore,
          dryRun: Boolean(dryRun)
        });
        sendJson(res, 200, result);
      } catch (err) {
        sendJson(res, 400, { error: err.message });
      }
      return;
    }

    // ── API: GET /api/scan/:id/export ────────────────────────────────────────
    const scanExportMatch = pathname.match(/^\/api\/scan\/([a-zA-Z0-9._-]+)\/export$/);
    if (method === 'GET' && scanExportMatch) {
      const exportId = scanExportMatch[1];
      const format = (parsedUrl.searchParams.get('format') || 'json').toLowerCase();

      let exportData = null;
      const job = jobs.get(exportId);
      if (job && job.result) {
        exportData = {
          targets: job.targets,
          results: job.result.results || [],
          risk: job.result.risk || calculateRisk(job.result.results || []),
          stacks: job.result.stacks || null,
          apiCommunication: job.result.apiCommunication || mergeApiCommunication(job.result.stacks, job.result.results) || null,
          cveCoverage: job.result.cveCoverage || null
        };
      } else {
        const hist = loadHistoryById(exportId);
        if (hist) {
          exportData = {
            targets: hist.targets || [],
            results: hist.results || [],
            risk: hist.risk || calculateRisk(hist.results || []),
            stacks: hist.stacks || null,
            apiCommunication: hist.apiCommunication || mergeApiCommunication(hist.stacks, hist.results) || null,
            cveCoverage: hist.cveCoverage || null
          };
        } else {
          const task = graphStore.getTask(exportId);
          if (task) {
            const findingNodes = graphStore.listNodes(task.id, { node_type: 'finding' });
            const taskResults = findingNodes.map(n => ({
              ...(n.data && typeof n.data === 'object' ? n.data : {}),
              checkId: n.data?.checkId || n.title,
              name: n.title,
              status: n.status === 'verified' || n.status === 'confirmed' ? 'VULNERABLE' : 'SUSPICIOUS',
              severity: n.severity || 'MEDIUM',
              reason: n.summary || ''
            }));
            const taskAssets = graphStore.queryAssets({ taskId: task.id, limit: 1000 }).items;
            exportData = {
              targets: task.target ? [task.target] : [],
              results: taskResults,
              risk: calculateRisk(taskResults),
              stacks: null,
              cveCoverage: null,
              assets: taskAssets
            };
          }
        }
      }

      if (!exportData) {
        sendJson(res, 404, { error: 'Scan or history record not found' });
        return;
      }

      const safeFileId = exportId.replace(/[^a-zA-Z0-9._-]/g, '_');
      if (format === 'markdown' || format === 'md') {
        const md = generateMarkdownReport(exportData);
        const buf = Buffer.from(md, 'utf8');
        res.writeHead(200, {
          'Content-Type': 'text/markdown; charset=utf-8',
          'Content-Length': buf.length,
          'Content-Disposition': `attachment; filename="security-report-${safeFileId}.md"`
        });
        res.end(buf);
        return;
      }

      if (format === 'csv') {
        const csvStr = generateCsvReport(exportData);
        const buf = Buffer.from(csvStr, 'utf8');
        res.writeHead(200, {
          'Content-Type': 'text/csv; charset=utf-8',
          'Content-Length': buf.length,
          'Content-Disposition': `attachment; filename="security-report-${safeFileId}.csv"`
        });
        res.end(buf);
        return;
      }

      if (format === 'html') {
        const htmlOpts = (exportData.cveCoverage || exportData.apiCommunication)
          ? {
              ...(exportData.cveCoverage ? { cveCoverage: exportData.cveCoverage } : {}),
              ...(exportData.apiCommunication ? { apiCommunication: exportData.apiCommunication } : {})
            }
          : null;
        const htmlStr = generateHtmlReport(
          exportData.results,
          exportData.risk,
          exportData.stacks,
          htmlOpts
        );
        const buf = Buffer.from(htmlStr, 'utf8');
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Length': buf.length,
          'Content-Disposition': `attachment; filename="security-report-${safeFileId}.html"`
        });
        res.end(buf);
        return;
      }

      if (format === 'sarif') {
        const sarifObj = generateSarifReport(exportData, { version: PKG_VERSION });
        const buf = Buffer.from(JSON.stringify(sarifObj, null, 2), 'utf8');
        res.writeHead(200, {
          'Content-Type': 'application/sarif+json; charset=utf-8',
          'Content-Length': buf.length,
          'Content-Disposition': `attachment; filename="security-report-${safeFileId}.sarif"`
        });
        res.end(buf);
        return;
      }

      if (format === 'json') {
        const jsonOpts = (exportData.cveCoverage || exportData.apiCommunication)
          ? {
              ...(exportData.cveCoverage ? { cveCoverage: exportData.cveCoverage } : {}),
              ...(exportData.apiCommunication ? { apiCommunication: exportData.apiCommunication } : {})
            }
          : null;
        const report = generateReport(
          exportData.results,
          exportData.risk,
          exportData.stacks,
          jsonOpts
        );
        sendJson(res, 200, report);
        return;
      }

      sendJson(res, 400, { error: 'Unsupported export format. Expected markdown, csv, html, sarif, or json.' });
      return;
    }

    // ── API: Tasks & Agent Sessions ──────────────────────────────────────────
    if (method === 'GET' && pathname === '/api/tasks') {
      const status = parsedUrl.searchParams.get('status') || undefined;
      const mode = parsedUrl.searchParams.get('mode') || undefined;
      const tasks = graphStore.listTasks({
        ...(status ? { status } : {}),
        ...(mode ? { mode } : {})
      }).map(withTaskAllowPrivate);
      sendJson(res, 200, { tasks });
      return;
    }

    if (method === 'POST' && pathname === '/api/tasks') {
      const body = await parseJsonBody(req, res);
      if (!body) return;

      const allowPrivate =
        body.allowPrivate !== undefined || body.allow_private !== undefined
          ? Boolean(body.allowPrivate ?? body.allow_private)
          : defaultAllowPrivate;
      const rawTarget = typeof body.target === 'string' ? body.target.trim() : '';
      const rawTitle = typeof body.title === 'string' ? body.title.trim() : '';
      if (!rawTarget && !rawTitle) {
        sendJson(res, 400, { error: 'target or title is required' });
        return;
      }

      let validatedTarget = rawTarget;
      if (rawTarget) {
        const validation = validateTargets([rawTarget], { allowPrivate });
        if (!validation.valid) {
          sendJson(res, 400, {
            error: validation.errors.join('; '),
            errors: validation.errors
          });
          return;
        }
        validatedTarget = validation.targets[0];
        const gate = evaluateAssetGate(validatedTarget, { rules: scopeRules });
        if (!gate.allowed) {
          sendJson(res, 403, { error: gate.reason, code: gate.code || 'TARGET_RULE_BLOCKED' });
          return;
        }

        const dnsResolver = options.dnsResolver ?? options.retestOptions?.dnsResolver ?? null;
        const preDns = await resolveAndValidateTarget(validatedTarget, {
          resolver: dnsResolver,
          allowPrivate
        });
        if (!preDns.valid && preDns.code === 'DNS_REBIND_OR_PRIVATE_IP') {
          sendJson(res, 403, { error: preDns.reason, code: preDns.code });
          return;
        }
        if (preDns.valid && Array.isArray(preDns.resolvedIps) && preDns.resolvedIps.length > 0) {
          const postDnsGate = evaluateAssetGate(
            { url: validatedTarget, hostname: preDns.hostname, resolvedIps: preDns.resolvedIps },
            { rules: scopeRules }
          );
          if (!postDnsGate.allowed) {
            sendJson(res, 403, { error: postDnsGate.reason, code: postDnsGate.code || 'TARGET_RULE_BLOCKED' });
            return;
          }
        }
      }

      const profileIds = body.llm_profile_ids ?? body.llmProfileIds;
      const llmRotate = body.llm_rotate ?? body.llmRotate;

      try {
        const task = graphStore.createTask({
          title: rawTitle || `Task: ${validatedTarget}`,
          target: validatedTarget || null,
          goal: body.goal || '',
          mode: body.mode || 'auto',
          noise_profile: body.noise_profile || body.noiseProfile || noiseGovernor.profile || 'balanced',
          llm_profile_ids: Array.isArray(profileIds) ? profileIds : [],
          llm_rotate: Boolean(llmRotate),
          allow_private: allowPrivate,
          allowPrivate,
          scope: Array.isArray(body.scope) ? body.scope : undefined,
          constraints: Array.isArray(body.constraints) ? body.constraints : undefined
        });
        taskAllowPrivateMap.set(task.id, allowPrivate);

        if (Array.isArray(profileIds) || llmRotate !== undefined) {
          llmPool.configureTaskChain(task.id, {
            ...(Array.isArray(profileIds) ? { profileIds } : {}),
            ...(llmRotate !== undefined ? { llmRotate: Boolean(llmRotate) } : {})
          });
        }

        await agentEngine.decomposeGoals(task);

        if (body.autoRun === true || body.runLoop === true) {
          agentEngine.runTaskLoop(task.id, {
            maxRounds: Number(body.maxRounds || 5),
            allowPrivate,
            getScopeRules: () => scopeRules,
            scopeRules: [...scopeRules]
          }).catch(() => {});
        }

        const graph = graphStore.getExplorationGraph(task.id);
        sendJson(res, 201, { task: withTaskAllowPrivate(graphStore.getTask(task.id)), graph });
      } catch (err) {
        sendJson(res, 400, { error: err.message });
      }
      return;
    }

    const taskMatch = pathname.match(/^\/api\/tasks\/([^/]+)$/);
    if (method === 'GET' && taskMatch) {
      const taskId = decodeURIComponent(taskMatch[1]);
      const task = graphStore.getTask(taskId);
      if (!task) {
        sendJson(res, 404, { error: 'Task not found' });
        return;
      }
      const sinceSeq = Number(parsedUrl.searchParams.get('sinceSeq') || 0);
      sendJson(res, 200, {
        task: withTaskAllowPrivate(task),
        graph: graphStore.getExplorationGraph(taskId),
        activity: graphStore.listActivity(taskId, { sinceSeq }),
        coverage: graphStore.buildCoverageLedger(taskId),
        llmChain: llmPool.getTaskChain(taskId)
      });
      return;
    }

    const taskLlmMatch = pathname.match(/^\/api\/tasks\/([^/]+)\/llm$/);
    if (method === 'PUT' && taskLlmMatch) {
      const taskId = decodeURIComponent(taskLlmMatch[1]);
      const task = graphStore.getTask(taskId);
      if (!task) {
        sendJson(res, 404, { error: 'Task not found' });
        return;
      }
      const body = await parseJsonBody(req, res);
      if (!body) return;

      const profileIds = body.profileIds ?? body.llm_profile_ids ?? body.llmProfileIds;
      const llmRotate = body.llmRotate ?? body.llm_rotate;
      const llmChain = llmPool.configureTaskChain(taskId, {
        ...(Array.isArray(profileIds) ? { profileIds } : {}),
        ...(llmRotate !== undefined ? { llmRotate: Boolean(llmRotate) } : {})
      });
      const updatedTask = graphStore.updateTask(taskId, {
        ...(Array.isArray(profileIds) ? { llm_profile_ids: profileIds } : {}),
        ...(llmRotate !== undefined ? { llm_rotate: Boolean(llmRotate) } : {})
      });
      sendJson(res, 200, { task: updatedTask, llmChain });
      return;
    }

    const taskPlanMatch = pathname.match(/^\/api\/tasks\/([^/]+)\/plan$/);
    if (method === 'POST' && taskPlanMatch) {
      const taskId = decodeURIComponent(taskPlanMatch[1]);
      const task = graphStore.getTask(taskId);
      if (!task) {
        sendJson(res, 404, { error: 'Task not found' });
        return;
      }
      const body = await parseOptionalJsonBody(req, res);
      if (!body) return;

      try {
        const plan = await agentEngine.planNextRound(taskId, {
          force: body.force !== undefined ? Boolean(body.force) : true
        });
        sendJson(res, 200, { plan, graph: graphStore.getExplorationGraph(taskId) });
      } catch (err) {
        sendJson(res, 500, { error: `Plan round failed: ${err.message}` });
      }
      return;
    }

    const taskSideQMatch = pathname.match(/^\/api\/tasks\/([^/]+)\/sidequestion$/);
    if (method === 'POST' && taskSideQMatch) {
      const taskId = decodeURIComponent(taskSideQMatch[1]);
      const task = graphStore.getTask(taskId);
      if (!task) {
        sendJson(res, 404, { error: 'Task not found' });
        return;
      }
      const body = await parseJsonBody(req, res);
      if (!body) return;
      if (!body.question || typeof body.question !== 'string' || !body.question.trim()) {
        sendJson(res, 400, { error: 'question is required' });
        return;
      }

      const graph = graphStore.getExplorationGraph(taskId);
      const contextSnapshot = body.contextSnapshot || {
        task: { id: task.id, title: task.title, target: task.target, goal: task.goal, status: task.status },
        nodes: graph.nodes,
        edges: graph.edges,
        activity: graphStore.listActivity(taskId, { limit: 30 }),
        coverage: graphStore.buildCoverageLedger(taskId)
      };

      try {
        const result = await sideQuestionService.askSideQuestion({
          taskId,
          question: body.question,
          contextSnapshot,
          llmPool
        });
        sendJson(res, 200, result);
      } catch (err) {
        const status = /No enabled LLM profile|No healthy LLM/i.test(err.message) ? 503 : 500;
        sendJson(res, status, { error: err.message });
      }
      return;
    }

    const intentSteerMatch = pathname.match(/^\/api\/tasks\/([^/]+)\/intents\/([^/]+)\/steer$/);
    if (method === 'POST' && intentSteerMatch) {
      const taskId = decodeURIComponent(intentSteerMatch[1]);
      const nodeId = decodeURIComponent(intentSteerMatch[2]);
      const task = graphStore.getTask(taskId);
      if (!task) {
        sendJson(res, 404, { error: 'Task not found' });
        return;
      }
      const node = graphStore.getNode(nodeId);
      if (!node || node.task_id !== taskId) {
        sendJson(res, 404, { error: 'Intent node not found' });
        return;
      }
      const body = await parseJsonBody(req, res);
      if (!body) return;
      if (!body.instruction || typeof body.instruction !== 'string') {
        sendJson(res, 400, { error: 'instruction is required' });
        return;
      }
      const active = agentEngine.steerWork(nodeId, body.instruction);
      if (!active) {
        graphStore.appendActivity(taskId, {
          actor: 'operator',
          eventType: 'steer',
          nodeId,
          summary: body.instruction.slice(0, 160)
        });
      }
      sendJson(res, 200, { ok: true, active, taskId, nodeId, instruction: body.instruction });
      return;
    }

    const intentCancelMatch = pathname.match(/^\/api\/tasks\/([^/]+)\/intents\/([^/]+)\/cancel$/);
    if (method === 'POST' && intentCancelMatch) {
      const taskId = decodeURIComponent(intentCancelMatch[1]);
      const nodeId = decodeURIComponent(intentCancelMatch[2]);
      const task = graphStore.getTask(taskId);
      if (!task) {
        sendJson(res, 404, { error: 'Task not found' });
        return;
      }
      const node = graphStore.getNode(nodeId);
      if (!node || node.task_id !== taskId) {
        sendJson(res, 404, { error: 'Intent node not found' });
        return;
      }
      const result = agentEngine.killWork(taskId, nodeId);
      sendJson(res, 200, { ok: true, ...result, graph: graphStore.getExplorationGraph(taskId) });
      return;
    }

    // ── API: Dual-Graph & Asset DSL ──────────────────────────────────────────
    const explorationGraphMatch = pathname.match(/^\/api\/graph\/exploration\/([^/]+)$/);
    if (method === 'GET' && explorationGraphMatch) {
      const taskId = decodeURIComponent(explorationGraphMatch[1]);
      const task = graphStore.getTask(taskId);
      if (!task) {
        sendJson(res, 404, { error: 'Task not found' });
        return;
      }
      const graph = graphStore.getExplorationGraph(taskId);
      if (parsedUrl.searchParams.get('fold') === 'true') {
        const currentRound = Number(parsedUrl.searchParams.get('round') || 1);
        const folded = foldColdGraph(graph, { graphStore, currentRound });
        sendJson(res, 200, {
          taskId,
          nodes: folded.nodes,
          edges: folded.edges,
          digests: folded.digests,
          foldedCount: folded.foldedCount,
          folded: true
        });
        return;
      }
      sendJson(res, 200, { taskId, ...graph, folded: false });
      return;
    }

    if (method === 'GET' && pathname === '/api/graph/coverage') {
      const taskId = parsedUrl.searchParams.get('taskId') || null;
      const companyId = parsedUrl.searchParams.get('companyId') || null;
      const coverageGraph = graphStore.getCoverageGraph({ taskId, companyId });
      sendJson(res, 200, coverageGraph);
      return;
    }

    const lineageMatch = pathname.match(/^\/api\/graph\/lineage\/([^/]+)\/([^/]+)$/);
    if (method === 'GET' && lineageMatch) {
      const taskId = decodeURIComponent(lineageMatch[1]);
      const findingId = decodeURIComponent(lineageMatch[2]);
      const task = graphStore.getTask(taskId);
      if (!task) {
        sendJson(res, 404, { error: 'Task not found' });
        return;
      }
      const lineage = graphStore.getFindingLineage(taskId, findingId);
      if (!lineage || !lineage.finding) {
        sendJson(res, 404, { error: 'Finding node not found' });
        return;
      }
      sendJson(res, 200, { taskId, findingId, ...lineage });
      return;
    }

    if (method === 'GET' && pathname === '/api/assets') {
      const dsl = parsedUrl.searchParams.get('dsl') || '';
      const taskId = parsedUrl.searchParams.get('taskId') || null;
      const assetType = parsedUrl.searchParams.get('type') || null;
      const inScopeOnly = parsedUrl.searchParams.get('inScope') === 'true';
      const limit = Number(parsedUrl.searchParams.get('limit') || 200);
      const offset = Number(parsedUrl.searchParams.get('offset') || 0);

      try {
        const result = graphStore.queryAssets({ dsl, taskId, assetType, inScopeOnly, limit, offset });
        sendJson(res, 200, { ...result, fields: FIELD_SPECS });
      } catch (err) {
        const status = err instanceof AssetDslError || err.name === 'AssetDslError' ? 400 : 500;
        sendJson(res, status, { error: err.message, fields: FIELD_SPECS });
      }
      return;
    }

    if (method === 'POST' && pathname === '/api/assets/ingest') {
      const body = await parseJsonBody(req, res);
      if (!body) return;
      const format = body.format || body.tool;
      const rawInput = body.rawInput !== undefined ? body.rawInput : body.output;
      if (!format || rawInput === undefined) {
        sendJson(res, 400, { error: 'format and rawInput are required' });
        return;
      }
      try {
        const parsed = ingestScanOutput(format, rawInput);
        const taskId = body.taskId || null;
        const upsertedAssets = [];
        for (const asset of parsed.assets) {
          const saved = graphStore.upsertAsset(asset, { taskId });
          if (saved) upsertedAssets.push(saved);
        }
        sendJson(res, 200, {
          format,
          assets: upsertedAssets,
          facts: parsed.facts,
          findings: parsed.findings,
          counts: {
            assets: upsertedAssets.length,
            facts: parsed.facts.length,
            findings: parsed.findings.length
          }
        });
      } catch (err) {
        sendJson(res, 400, { error: err.message });
      }
      return;
    }

    // ── API: Findings, S1 Evidence Receipts, Retests & Asset Tree ────────────
    if (method === 'GET' && pathname === '/api/findings/asset-tree') {
      const taskId = parsedUrl.searchParams.get('taskId') || null;
      const scanId = parsedUrl.searchParams.get('scanId') || null;
      const historyId = parsedUrl.searchParams.get('historyId') || null;

      let findings = [];
      let assets = [];

      if (scanId && jobs.get(scanId)?.result?.results) {
        findings = jobs.get(scanId).result.results;
        const tId = jobs.get(scanId).result.taskId;
        assets = tId ? graphStore.queryAssets({ taskId: tId, limit: 1000 }).items : [];
      } else if (historyId) {
        const record = loadHistoryById(historyId);
        if (!record) {
          sendJson(res, 404, { error: 'History record not found' });
          return;
        }
        findings = Array.isArray(record.results) ? record.results : [];
      } else if (taskId) {
        const nodes = graphStore.listNodes(taskId, { node_type: 'finding' });
        findings = nodes.map(n => ({
          id: n.id,
          ...(n.data && typeof n.data === 'object' ? n.data : {}),
          name: n.title,
          severity: n.severity || 'MEDIUM',
          status: n.status === 'verified' || n.status === 'confirmed' ? 'VULNERABLE' : 'SUSPICIOUS'
        }));
        assets = graphStore.queryAssets({ taskId, limit: 1000 }).items;
      } else {
        const tasks = graphStore.listTasks();
        for (const t of tasks) {
          const nodes = graphStore.listNodes(t.id, { node_type: 'finding' });
          for (const n of nodes) {
            findings.push({
              id: n.id,
              ...(n.data && typeof n.data === 'object' ? n.data : {}),
              name: n.title,
              severity: n.severity || 'MEDIUM',
              status: n.status === 'verified' || n.status === 'confirmed' ? 'VULNERABLE' : 'SUSPICIOUS'
            });
          }
        }
        assets = graphStore.queryAssets({ limit: 1000 }).items;
      }

      sendJson(res, 200, buildFindingAssetTree(findings, assets));
      return;
    }

    const findingEvidenceMatch = pathname.match(/^\/api\/findings\/([^/]+)\/evidence$/);
    if (method === 'GET' && findingEvidenceMatch) {
      const findingId = decodeURIComponent(findingEvidenceMatch[1]);
      sendJson(res, 200, evidenceStore.getFindingEvidence(findingId));
      return;
    }

    if (method === 'POST' && findingEvidenceMatch) {
      const findingId = decodeURIComponent(findingEvidenceMatch[1]);
      const body = await parseJsonBody(req, res);
      if (!body) return;

      try {
        let snapshot = null;
        if (body.exchangeId) {
          snapshot = evidenceStore.captureSnapshotFromExchange(body.exchangeId, {
            taskId: body.taskId || null
          });
        } else if (body.snapshotId) {
          snapshot = evidenceStore.getSnapshot(body.snapshotId);
          if (!snapshot) {
            sendJson(res, 404, { error: `Snapshot not found: ${body.snapshotId}` });
            return;
          }
        } else {
          if (!body.url) {
            sendJson(res, 400, { error: 'exchangeId, snapshotId, or raw snapshot url is required' });
            return;
          }
          snapshot = evidenceStore.createSnapshot({
            taskId: body.taskId || null,
            method: body.method || 'GET',
            url: body.url,
            statusCode: body.statusCode ?? body.status ?? 200,
            reqHeaders: body.reqHeaders || {},
            resHeaders: body.resHeaders || {},
            reqBody: body.reqBody || '',
            resBody: body.resBody ?? body.responseBody ?? ''
          });
        }

        const binding = evidenceStore.bindEvidence({
          findingId,
          snapshotId: snapshot.id,
          role: body.role || 'proof',
          quote: body.quote || '',
          note: body.note || ''
        });

        let verification = null;
        if (body.verify !== false) {
          verification = evidenceStore.verifyFindingReceipts(findingId, {
            poeLevel: body.poeLevel ?? 3,
            evidenceQuotes: Array.isArray(body.evidenceQuotes)
              ? body.evidenceQuotes
              : (body.quote ? [body.quote] : [])
          });
        }

        sendJson(res, 200, {
          binding,
          snapshot,
          verification,
          evidence: evidenceStore.getFindingEvidence(findingId)
        });
      } catch (err) {
        sendJson(res, 400, { error: err.message });
      }
      return;
    }

    const findingVerifyMatch = pathname.match(/^\/api\/findings\/([^/]+)\/verify$/);
    if (method === 'POST' && findingVerifyMatch) {
      const findingId = decodeURIComponent(findingVerifyMatch[1]);
      const body = await parseOptionalJsonBody(req, res);
      if (!body) return;

      try {
        const assessment = evidenceStore.verifyFindingReceipts(findingId, {
          poeLevel: body.poeLevel ?? 3,
          evidenceQuotes: Array.isArray(body.evidenceQuotes) ? body.evidenceQuotes : []
        });
        sendJson(res, 200, {
          assessment,
          evidence: evidenceStore.getFindingEvidence(findingId)
        });
      } catch (err) {
        sendJson(res, 400, { error: err.message });
      }
      return;
    }

    const findingRetestMatch = pathname.match(/^\/api\/findings\/([^/]+)\/retest$/);
    if (method === 'POST' && findingRetestMatch) {
      const findingId = decodeURIComponent(findingRetestMatch[1]);
      const body = await parseOptionalJsonBody(req, res);
      if (!body) return;

      try {
        const allowPrivate = body.allowPrivate !== undefined ? Boolean(body.allowPrivate) : defaultAllowPrivate;
        const targetPinStore = new TargetPinStore({ allowPrivate });
        const dnsResolver = options.retestOptions?.dnsResolver ?? options.dnsResolver ?? null;
        const validateUrl =
          options.retestOptions?.validateUrl ||
          ((u, vOpts = {}) =>
            resolveAndValidateTarget(u, {
              resolver: vOpts.resolver ?? dnsResolver,
              targetPinStore: vOpts.targetPinStore ?? targetPinStore,
              allowPrivate: vOpts.allowPrivate ?? allowPrivate
            }));
        const retest = await evidenceStore.retestFinding(findingId, {
          ...(options.retestOptions || {}),
          dnsResolver,
          targetPinStore,
          allowPrivate,
          validateUrl,
          guard: scopeRules.length ? scopeRules : null,
          ...(Array.isArray(body.evidenceQuotes) ? { evidenceQuotes: body.evidenceQuotes } : {})
        });
        sendJson(res, 200, {
          retest,
          evidence: evidenceStore.getFindingEvidence(findingId)
        });
      } catch (err) {
        const msg = err.message || '';
        const status = /No bound proof snapshot/i.test(msg)
          ? 404
          : /blocked by/i.test(msg)
            ? 403
            : 400;
        sendJson(res, status, { error: msg });
      }
      return;
    }

    // ── API: Traffic Store, Rewrite Rules & RFC-9110 Replay ──────────────────
    if (method === 'GET' && pathname === '/api/traffic') {
      const taskId = parsedUrl.searchParams.get('taskId') || undefined;
      const host = parsedUrl.searchParams.get('host') || undefined;
      const methodFilter = parsedUrl.searchParams.get('method') || undefined;
      const statusParam = parsedUrl.searchParams.get('status');
      let status;
      if (statusParam !== null && statusParam.trim() !== '') {
        const trimmedStatus = statusParam.trim();
        if (/^[1-5]xx$/i.test(trimmedStatus)) {
          status = trimmedStatus.toLowerCase();
        } else if (/^\d+$/.test(trimmedStatus)) {
          status = Number(trimmedStatus);
        } else {
          sendJson(res, 400, { error: `Invalid status filter "${statusParam}". Expected numeric status or 1xx-5xx.` });
          return;
        }
      }
      const search = parsedUrl.searchParams.get('search') || undefined;
      const source = parsedUrl.searchParams.get('source') || undefined;
      const limit = Number(parsedUrl.searchParams.get('limit') || 100);
      const offset = Number(parsedUrl.searchParams.get('offset') || 0);

      const exchanges = trafficStore.queryExchanges({
        taskId,
        host,
        method: methodFilter,
        status,
        search,
        source,
        limit,
        offset
      });
      const total = typeof exchanges.total === 'number' ? exchanges.total : exchanges.length;
      sendJson(res, 200, { exchanges, items: exchanges, total });
      return;
    }

    if (method === 'GET' && pathname === '/api/traffic/hosts') {
      const taskId = parsedUrl.searchParams.get('taskId') || undefined;
      const hosts = trafficStore.listHosts({ taskId });
      sendJson(res, 200, { hosts });
      return;
    }

    if (method === 'GET' && pathname === '/api/traffic/rewrite-rules') {
      const rules = trafficStore.listRewriteRules();
      sendJson(res, 200, { rules });
      return;
    }

    if (method === 'POST' && pathname === '/api/traffic/rewrite-rules') {
      const body = await parseJsonBody(req, res);
      if (!body) return;
      try {
        const rule = trafficStore.addRewriteRule(body);
        sendJson(res, 201, { rule });
      } catch (err) {
        sendJson(res, 400, { error: err.message });
      }
      return;
    }

    const rewriteDeleteMatch = pathname.match(/^\/api\/traffic\/rewrite-rules\/([^/]+)$/);
    if (method === 'DELETE' && rewriteDeleteMatch) {
      const ruleId = decodeURIComponent(rewriteDeleteMatch[1]);
      const deleted = trafficStore.deleteRewriteRule(ruleId);
      if (!deleted) {
        sendJson(res, 404, { error: 'Rewrite rule not found' });
        return;
      }
      sendJson(res, 200, { deleted: true, id: ruleId });
      return;
    }

    if (method === 'POST' && pathname === '/api/traffic/ingest') {
      const body = await parseJsonBody(req, res);
      if (!body) return;
      try {
        const recorded = trafficStore.recordExternal(body);
        const count = Array.isArray(recorded) ? recorded.length : 1;
        sendJson(res, 201, { recorded, count });
      } catch (err) {
        sendJson(res, 400, { error: err.message });
      }
      return;
    }

    const trafficReplayMatch = pathname.match(/^\/api\/traffic\/([^/]+)\/replay$/);
    if (method === 'POST' && trafficReplayMatch) {
      const exchangeId = decodeURIComponent(trafficReplayMatch[1]);
      const body = await parseOptionalJsonBody(req, res);
      if (!body) return;
      try {
        let replayOverrides = { ...body };
        let rewriteInfo = { applied: false, taintedSensitive: false, appliedRules: [] };
        const original = trafficStore.getExchange(exchangeId, { includeBodies: true });
        if (original && body.applyRewrites !== false) {
          const rewritten = trafficStore.applyRewrites(
            {
              method: body.method || original.method,
              url: body.url || original.url,
              headers: { ...(original.reqHeaders || {}), ...(body.headers || body.reqHeaders || {}) },
              body: body.body ?? body.reqBody ?? original.reqBody ?? ''
            },
            'request'
          );
          if (rewritten.rewriteApplied) {
            replayOverrides = {
              ...replayOverrides,
              method: rewritten.method,
              url: rewritten.url,
              headers: rewritten.headers,
              body: rewritten.body
            };
            rewriteInfo = {
              applied: true,
              taintedSensitive: Boolean(rewritten.taintedSensitive),
              appliedRules: rewritten.appliedRules || []
            };
          }
        }
        const allowPrivate = body.allowPrivate !== undefined ? Boolean(body.allowPrivate) : defaultAllowPrivate;
        const targetPinStore = new TargetPinStore({ allowPrivate });
        const dnsResolver = options.retestOptions?.dnsResolver ?? options.dnsResolver ?? null;
        const validateUrl =
          options.retestOptions?.validateUrl ||
          ((u, vOpts = {}) =>
            resolveAndValidateTarget(u, {
              resolver: vOpts.resolver ?? dnsResolver,
              targetPinStore: vOpts.targetPinStore ?? targetPinStore,
              allowPrivate: vOpts.allowPrivate ?? allowPrivate
            }));
        const followRedirects = body.followRedirects !== undefined
          ? Boolean(body.followRedirects)
          : options.retestOptions?.followRedirects !== undefined
            ? Boolean(options.retestOptions.followRedirects)
            : Number(options.retestOptions?.maxRedirects) === 0;
        const result = await trafficStore.replayRequest(exchangeId, replayOverrides, {
          ...(options.retestOptions || {}),
          followRedirects,
          dnsResolver,
          targetPinStore,
          allowPrivate,
          validateUrl,
          guard: scopeRules.length ? scopeRules : null
        });
        sendJson(res, 200, { ...result, rewrite: rewriteInfo });
      } catch (err) {
        const msg = err.message || '';
        const status = /Exchange not found/i.test(msg)
          ? 404
          : /Maximum redirect limit/i.test(msg)
            ? 400
            : /blocked by/i.test(msg)
              ? 403
              : 400;
        sendJson(res, status, { error: msg });
      }
      return;
    }

    const trafficGetMatch = pathname.match(/^\/api\/traffic\/([^/]+)$/);
    if (method === 'GET' && trafficGetMatch) {
      const exchangeId = decodeURIComponent(trafficGetMatch[1]);
      const exchange = trafficStore.getExchange(exchangeId, { includeBodies: true });
      if (!exchange) {
        sendJson(res, 404, { error: 'Traffic exchange not found' });
        return;
      }
      sendJson(res, 200, { exchange });
      return;
    }

    // ── API: Multi-LLM Pool, Guardrails, Noise Governor & Skills ─────────────
    if (method === 'GET' && pathname === '/api/llm/pool') {
      sendJson(res, 200, {
        ...llmPool.getPoolStatus(),
        usage: llmRecorder.getUsageSummary()
      });
      return;
    }

    if (method === 'POST' && pathname === '/api/llm/profiles') {
      const body = await parseJsonBody(req, res);
      if (!body) return;
      if (!body.id && typeof body.name === 'string' && body.name.trim()) {
        body.id = body.name.trim().toLowerCase().replace(/[^a-z0-9_-]+/g, '-');
      }
      if (!body.id) {
        sendJson(res, 400, { error: 'LLM profile id is required' });
        return;
      }
      try {
        llmPool.upsertProfile(body);
        const status = llmPool.getPoolStatus();
        const profile = status.profiles.find(p => p.id === String(body.id)) || null;
        sendJson(res, 200, { ...status, profile });
      } catch (err) {
        sendJson(res, 400, { error: err.message });
      }
      return;
    }

    const llmProfileResetMatch = pathname.match(/^\/api\/llm\/profiles\/([^/]+)\/reset$/);
    if (method === 'POST' && llmProfileResetMatch) {
      const profileId = decodeURIComponent(llmProfileResetMatch[1]);
      if (!llmPool.getProfile(profileId)) {
        sendJson(res, 404, { error: 'LLM profile not found' });
        return;
      }
      llmPool.resetBreaker(profileId);
      sendJson(res, 200, { reset: true, id: profileId, ...llmPool.getPoolStatus() });
      return;
    }

    const llmProfileMatch = pathname.match(/^\/api\/llm\/profiles\/([^/]+)$/);
    if (method === 'DELETE' && llmProfileMatch) {
      const profileId = decodeURIComponent(llmProfileMatch[1]);
      if (!llmPool.getProfile(profileId)) {
        sendJson(res, 404, { error: 'LLM profile not found' });
        return;
      }
      llmPool.removeProfile(profileId);
      sendJson(res, 200, { deleted: true, id: profileId, ...llmPool.getPoolStatus() });
      return;
    }

    if (method === 'GET' && pathname === '/api/guard/settings') {
      sendJson(res, 200, {
        noise: noiseGovernor.snapshot(),
        noiseProfile: noiseGovernor.profile,
        scopeRules,
        interceptRules,
        skills: typeof skillRegistry.listSkills === 'function' ? skillRegistry.listSkills() : []
      });
      return;
    }

    if (method === 'PUT' && pathname === '/api/guard/settings') {
      const body = await parseJsonBody(req, res);
      if (!body) return;

      try {
        if (typeof body !== 'object' || Array.isArray(body)) {
          sendJson(res, 400, { error: 'Request body must be a JSON object' });
          return;
        }

        const requestedProfile = body.noiseProfile ?? body.profile ?? body.noise?.profile;
        let nextGovernor = noiseGovernor;
        if (requestedProfile !== undefined) {
          if (typeof requestedProfile !== 'string' && typeof requestedProfile !== 'number') {
            sendJson(res, 400, {
              error: `Invalid noiseProfile "${requestedProfile}". Expected off, quiet, balanced, or aggressive.`
            });
            return;
          }
          const normalizedProfile = String(requestedProfile).trim().toLowerCase();
          if (!Object.hasOwn(NOISE_PROFILES, normalizedProfile)) {
            sendJson(res, 400, {
              error: `Invalid noiseProfile "${requestedProfile}". Expected off, quiet, balanced, or aggressive.`
            });
            return;
          }
          if (
            body.noiseConfig !== undefined &&
            (typeof body.noiseConfig !== 'object' || body.noiseConfig === null || Array.isArray(body.noiseConfig))
          ) {
            sendJson(res, 400, { error: 'noiseConfig must be a JSON object' });
            return;
          }
          nextGovernor = new NoiseGovernor({
            profile: normalizedProfile,
            ...(body.noiseConfig && typeof body.noiseConfig === 'object' ? body.noiseConfig : {})
          });
        }

        let nextScopeRules = scopeRules;
        if (body.scopeRules !== undefined) {
          if (!Array.isArray(body.scopeRules)) {
            sendJson(res, 400, { error: 'scopeRules must be an array' });
            return;
          }
          nextScopeRules = normalizeScopeRules(body.scopeRules);
        }

        let nextInterceptRules = interceptRules;
        if (body.interceptRules !== undefined) {
          if (!Array.isArray(body.interceptRules)) {
            sendJson(res, 400, { error: 'interceptRules must be an array' });
            return;
          }
          nextInterceptRules = body.interceptRules;
        }

        noiseGovernor = nextGovernor;
        scopeRules = nextScopeRules;
        interceptRules = nextInterceptRules;

        sendJson(res, 200, {
          noise: noiseGovernor.snapshot(),
          noiseProfile: noiseGovernor.profile,
          scopeRules,
          interceptRules
        });
      } catch (err) {
        sendJson(res, 400, { error: err?.message || 'Invalid guard settings payload' });
      }
      return;
    }

    if (method === 'POST' && pathname === '/api/guard/evaluate') {
      const body = await parseJsonBody(req, res);
      if (!body) return;

      const mode = body.mode ? String(body.mode).trim().toLowerCase() : null;
      const hasTarget = body.target !== undefined || body.url !== undefined;
      const hasRisk = body.toolName !== undefined || body.tool !== undefined || body.method !== undefined;
      const hasJev = body.jevAnswers !== undefined || body.answers !== undefined || body.q1_in_scope !== undefined;
      const hasIntercept = body.command !== undefined;
      const applicableCount = [hasTarget, hasRisk, hasJev, hasIntercept].filter(Boolean).length;

      const evalRules = Array.isArray(body.rules) ? normalizeScopeRules(body.rules) : scopeRules;
      const includeBuiltinDeny = body.includeBuiltinDeny !== undefined ? Boolean(body.includeBuiltinDeny) : true;

      if (mode === 'all' || (!mode && applicableCount >= 2)) {
        const gateResult = hasTarget
          ? evaluateAssetGate(body.target ?? body.url, { rules: evalRules, includeBuiltinDeny })
          : { allowed: true, matchedRule: null, code: 'TARGET_SKIPPED', reason: 'No target provided' };

        const toolName = body.toolName || body.tool || body.method || 'http';
        const riskResult = scoreRisk(toolName, body.input || body);

        const rawJev = body.jevAnswers ?? body.answers ?? (body.q1_in_scope !== undefined ? body : null);
        const jevResult = hasJev || mode === 'all'
          ? decideClosed(normalizeJevAnswers(rawJev))
          : null;

        const interceptResult = hasIntercept
          ? evaluateInterceptRules(body.command ?? body, Array.isArray(body.rules) ? body.rules : interceptRules)
          : null;

        const allowed = Boolean(
          gateResult.allowed &&
          (jevResult ? jevResult.approved : true) &&
          (interceptResult ? interceptResult.allowed : true)
        );

        sendJson(res, 200, {
          mode: 'all',
          allowed,
          gate: gateResult,
          risk: riskResult,
          ...(jevResult ? { jev: jevResult } : {}),
          ...(interceptResult ? { intercept: interceptResult } : {})
        });
        return;
      }

      if (mode === 'asset' || (!mode && hasTarget)) {
        const targetInput = body.target ?? body.url;
        const result = evaluateAssetGate(targetInput, {
          rules: evalRules,
          includeBuiltinDeny
        });
        sendJson(res, 200, { mode: 'asset', result, ...result });
        return;
      }

      if (mode === 'jev' || (!mode && hasJev)) {
        const answers = normalizeJevAnswers(body.jevAnswers || body.answers || body);
        const result = decideClosed(answers);
        sendJson(res, 200, { mode: 'jev', result, ...result });
        return;
      }

      if (mode === 'intercept' || (!mode && hasIntercept)) {
        const rules = Array.isArray(body.rules) ? body.rules : interceptRules;
        const result = evaluateInterceptRules(body.command ?? body, rules);
        sendJson(res, 200, { mode: 'intercept', result, ...result });
        return;
      }

      if (mode === 'risk' || (!mode && hasRisk)) {
        const toolName = body.toolName || body.tool || body.method || 'http';
        const result = scoreRisk(toolName, body.input || body);
        sendJson(res, 200, { mode: 'risk', result, ...result });
        return;
      }

      sendJson(res, 400, {
        error: mode
          ? `Unsupported guard mode "${body.mode}". Expected asset, risk, jev, intercept, or all.`
          : 'Provide target/url (asset gate), toolName/method (risk), command (intercept), or jevAnswers (closed-world JEV).'
      });
      return;
    }

    // ── API: System Doctor & Target Connectivity Triage ──────────────────────
    if ((method === 'GET' || method === 'POST') && pathname === '/api/system/doctor') {
      try {
        const report = await runSystemDoctor({
          allowPrivate: defaultAllowPrivate,
          llmPool,
          historyDir,
          probeWrites: method === 'POST'
        });
        sendJson(res, 200, report);
      } catch (err) {
        sendJson(res, 500, { error: `System doctor failed: ${err.message}` });
      }
      return;
    }

    if (method === 'POST' && pathname === '/api/system/diagnose-target') {
      const body = await parseJsonBody(req, res);
      if (!body) return;
      if (!body.target || typeof body.target !== 'string' || !body.target.trim()) {
        sendJson(res, 400, { error: 'target URL string is required' });
        return;
      }
      try {
        const diag = await diagnoseTarget(body.target, {
          allowPrivate: body.allowPrivate ?? defaultAllowPrivate,
          dnsResolver: agentDnsResolver,
          scopeRules,
          ...(options.fetcher ? { fetcher: options.fetcher } : {})
        });
        sendJson(res, 200, diag);
      } catch (err) {
        sendJson(res, 500, { error: `Target diagnostics failed: ${err.message}` });
      }
      return;
    }

    // ── API: AI Remediation & Audience Summary ───────────────────────────────
    if (method === 'POST' && pathname === '/api/ai/remediate') {
      const body = await parseJsonBody(req, res);
      if (!body) return;
      if (!body.finding || typeof body.finding !== 'object' || Array.isArray(body.finding)) {
        sendJson(res, 400, { error: 'finding object is required' });
        return;
      }
      let resolvedStack = body.stack || null;
      let resolvedApiComm =
        (body.apiCommunication && typeof body.apiCommunication === 'object' && !Array.isArray(body.apiCommunication)
          ? body.apiCommunication
          : null) ||
        body.finding.apiCommunication ||
        (resolvedStack && typeof resolvedStack === 'object' ? resolvedStack.apiCommunication : null) ||
        null;

      if (body.scanId && typeof body.scanId === 'string' && body.scanId.trim()) {
        const sid = body.scanId.trim();
        const job = jobs.get(sid);
        if (job && job.result) {
          if (!resolvedStack && job.result.stacks) resolvedStack = job.result.stacks;
          if (!resolvedApiComm) {
            resolvedApiComm = job.result.apiCommunication || mergeApiCommunication(job.result.stacks, job.result.results);
          }
        } else {
          const hist = loadHistoryById(sid);
          if (hist) {
            if (!resolvedStack && hist.stacks) resolvedStack = hist.stacks;
            if (!resolvedApiComm) {
              resolvedApiComm = hist.apiCommunication || mergeApiCommunication(hist.stacks, hist.results);
            }
          }
        }
      }

      const findingForAdvisor = resolvedApiComm && !body.finding.apiCommunication
        ? { ...body.finding, apiCommunication: resolvedApiComm }
        : body.finding;

      try {
        const solution = await aiAdvisor.generateFixSolution(findingForAdvisor, {
          audience: body.audience !== undefined ? body.audience : 'pro',
          stack: resolvedStack,
          ...(resolvedApiComm ? { apiCommunication: resolvedApiComm } : {})
        });
        sendJson(res, 200, solution);
      } catch (err) {
        const status = err.code === 'INVALID_AUDIENCE' ? 400 : 500;
        sendJson(res, status, { error: err.message, ...(err.code ? { code: err.code } : {}) });
      }
      return;
    }

    if (method === 'POST' && pathname === '/api/ai/summary') {
      const body = await parseJsonBody(req, res);
      if (!body) return;
      let scanData = null;
      if (body.scanId !== undefined && body.scanId !== null && String(body.scanId).trim()) {
        if (typeof body.scanId !== 'string') {
          sendJson(res, 400, { error: 'scanId must be a string' });
          return;
        }
        const sid = body.scanId.trim();
        const job = jobs.get(sid);
        if (job && job.result) {
          const apiComm =
            job.result.apiCommunication ||
            mergeApiCommunication(job.result.stacks, job.result.results) ||
            (body.apiCommunication && typeof body.apiCommunication === 'object' ? body.apiCommunication : null);
          scanData = {
            targets: job.targets,
            results: job.result.results || [],
            risk: job.result.risk,
            stacks: job.result.stacks || null,
            cveCoverage: job.result.cveCoverage || null,
            ...(apiComm ? { apiCommunication: apiComm } : {})
          };
        } else {
          const hist = loadHistoryById(sid);
          if (hist) {
            const apiComm =
              hist.apiCommunication ||
              mergeApiCommunication(hist.stacks, hist.results) ||
              (body.apiCommunication && typeof body.apiCommunication === 'object' ? body.apiCommunication : null);
            scanData = {
              ...hist,
              ...(apiComm ? { apiCommunication: apiComm } : {})
            };
          } else {
            sendJson(res, 404, { error: `Scan or history record "${sid}" not found` });
            return;
          }
        }
      } else if (body.scanResult && typeof body.scanResult === 'object' && !Array.isArray(body.scanResult)) {
        const apiComm =
          body.scanResult.apiCommunication ||
          (body.apiCommunication && typeof body.apiCommunication === 'object' ? body.apiCommunication : null) ||
          mergeApiCommunication(body.scanResult.stacks, body.scanResult.results);
        scanData = {
          ...body.scanResult,
          ...(apiComm ? { apiCommunication: apiComm } : {})
        };
      } else {
        sendJson(res, 400, { error: 'scanResult object or scanId string is required' });
        return;
      }

      try {
        const summary = await aiAdvisor.summarizeScanForAudience(scanData, {
          audience: body.audience !== undefined ? body.audience : 'beginner'
        });
        sendJson(res, 200, summary);
      } catch (err) {
        const status = err.code === 'INVALID_AUDIENCE' ? 400 : 500;
        sendJson(res, status, { error: err.message, ...(err.code ? { code: err.code } : {}) });
      }
      return;
    }

    if (method === 'POST' && pathname === '/api/ai/analyze-api') {
      const body = await parseJsonBody(req, res);
      if (!body) return;
      if (typeof body !== 'object' || Array.isArray(body)) {
        sendJson(res, 400, { error: 'Request body must be a JSON object' });
        return;
      }

      let apiData = null;
      let resolvedTarget = typeof body.target === 'string' && body.target.trim()
        ? body.target.trim().slice(0, 2048)
        : null;

      if (body.scanId !== undefined && body.scanId !== null && String(body.scanId).trim()) {
        if (typeof body.scanId !== 'string') {
          sendJson(res, 400, { error: 'scanId must be a string' });
          return;
        }
        const sid = body.scanId.trim();
        const job = jobs.get(sid);
        if (job && job.result) {
          apiData =
            job.result.apiCommunication ||
            mergeApiCommunication(job.result.stacks, job.result.results) ||
            { usesApi: false };
          if (!resolvedTarget && Array.isArray(job.targets) && job.targets[0]) {
            resolvedTarget = job.targets[0];
          }
        } else {
          const hist = loadHistoryById(sid);
          if (hist) {
            apiData =
              hist.apiCommunication ||
              mergeApiCommunication(hist.stacks, hist.results) ||
              { usesApi: false };
            if (!resolvedTarget && Array.isArray(hist.targets) && hist.targets[0]) {
              resolvedTarget = hist.targets[0];
            }
          } else {
            sendJson(res, 404, { error: `Scan or history record "${sid}" not found` });
            return;
          }
        }
      } else if (body.apiCommunication !== undefined && body.apiCommunication !== null) {
        if (typeof body.apiCommunication !== 'object' || Array.isArray(body.apiCommunication)) {
          sendJson(res, 400, { error: 'apiCommunication must be a JSON object' });
          return;
        }
        apiData = capApiCommunicationInput(body.apiCommunication);
      } else if (resolvedTarget) {
        apiData = { usesApi: false };
      } else {
        sendJson(res, 400, { error: 'apiCommunication object, scanId, or target URL is required' });
        return;
      }

      try {
        const analysis = await aiAdvisor.analyzeApiCommunication(apiData, {
          target: resolvedTarget,
          audience: body.audience !== undefined ? body.audience : 'beginner'
        });
        sendJson(res, 200, analysis);
      } catch (err) {
        const status = err.code === 'INVALID_AUDIENCE' ? 400 : 500;
        sendJson(res, status, { error: err.message, ...(err.code ? { code: err.code } : {}) });
      }
      return;
    }

    // ── Static Assets (UI) ──────────────────────────────────────────────────
    if (method === 'GET') {
      serveStaticFile(req, res, pathname);
      return;
    }

    sendJson(res, 405, { error: 'Method Not Allowed' });
  });

  server.context = {
    jobs,
    graphStore,
    trafficStore,
    evidenceStore,
    llmPool,
    llmRecorder,
    aiAdvisor,
    sideQuestionService,
    getNoiseGovernor: () => noiseGovernor,
    skillRegistry,
    agentEngine,
    getScopeRules: () => scopeRules,
    getInterceptRules: () => interceptRules
  };

  server.on('close', () => {
    if (ownsEvidenceStore) evidenceStore.close();
    if (ownsTrafficStore) trafficStore.close();
    if (ownsGraphStore) graphStore.close();
  });

  return server;
}

/**
 * Starts the server and listens on the configured host & port.
 */
export function startServer(options = {}) {
  const { port = 4321, host = '127.0.0.1' } = options;
  const server = createAppServer(options);

  return new Promise((resolve, reject) => {
    server.on('error', reject);
    server.listen(port, host, () => {
      const address = server.address();
      const actualPort = typeof address === 'object' && address ? address.port : port;
      const formattedHost = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
      const url = `http://${formattedHost}:${actualPort}`;
      console.log(`🚀 Security Scanner UI Server running at ${url}`);
      resolve({ server, port: actualPort, host, url });
    });
  });
}

// Automatically start if executed directly via `node core/server.js`
if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  const port = parseInt(process.env.PORT || '4321', 10);
  const host = process.env.HOST || '127.0.0.1';
  startServer({ port, host }).catch(err => {
    console.error('Failed to start server:', err);
    process.exit(1);
  });
}
