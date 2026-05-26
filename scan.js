import { getScanners }                          from './core/registry.js';
import { fingerprint }                          from './core/fingerprint.js';
import { fetchWithRetry as baseFetch }          from './core/fetch.js';
import { generateReport, saveReport,
         saveHtmlReport }                       from './core/report.js';
import { calculateRisk }                        from './core/severity.js';
import { getProfileChecks }                     from './core/profiles.js';
import { saveHistory, loadLastHistory,
         diffScans }                            from './core/history.js';
import { sendWebhook }                          from './core/notify.js';
import { TaskQueue }                            from './core/queue.js';
import { crawlPage }                            from './core/crawler.js';
import pLimit                                   from 'p-limit';

// Status → emoji
const ICON = {
  VULNERABLE: '🚨',
  SUSPICIOUS: '⚠️ ',
  SAFE      : '✅',
  ERROR     : '❓',
};

function printDiff(diff) {
  const bar = '─'.repeat(60);
  console.log(`\n${bar}`);
  console.log('🔄  DIFF vs previous scan');
  console.log(bar);

  if (diff.newFindings.length) {
    console.log(`\n🆕  New findings (${diff.newFindings.length}):`);
    diff.newFindings.forEach(f =>
      console.log(`     + [${f.severity}] ${f.name}  →  ${f.target}`)
    );
  }

  if (diff.fixedFindings.length) {
    console.log(`\n✅  Fixed (${diff.fixedFindings.length}):`);
    diff.fixedFindings.forEach(({ prev }) =>
      console.log(`     - [${prev.severity}] ${prev.name}  →  ${prev.target}`)
    );
  }

  if (diff.changedFindings.length) {
    console.log(`\n↕️   Changed (${diff.changedFindings.length}):`);
    diff.changedFindings.forEach(({ prev, curr }) =>
      console.log(`     ~ ${curr.name}: ${prev.status}(${prev.severity}) → ${curr.status}(${curr.severity})`)
    );
  }

  if (!diff.newFindings.length && !diff.fixedFindings.length && !diff.changedFindings.length) {
    console.log('  No changes since last scan.');
  }

  console.log(bar);
}

export async function runScanner(options) {
  const {
    targets,
    json        = false,
    html        = false,
    concurrency = 5,
    techOverride= null,
    output      = 'report',
    timeout     = 10000,
    auth        = null,
    profile     = 'full',
    diff        = false,
    noHistory   = false,
    webhook     = null,
    maxDepth    = 3, // New for Scanner 2.0
  } = options;

  // Curry fetch with timeout + optional auth header
  const authHeaders    = auth ? { Authorization: auth } : {};
  const fetchWithRetry = (url, opts = {}) => baseFetch(url, {
    ...opts,
    headers: { ...authHeaders, ...(opts.headers || {}) }
  }, 2, timeout);

  const scanners     = await getScanners();
  const profileChecks = getProfileChecks(profile);  // null = all

  const bar = '═'.repeat(60);
  console.log(bar);
  console.log('🔍  Security Scanner v2.0 (Discovery Mode)');
  console.log(bar);
  console.log(`📡  Targets     : ${targets.length}`);
  console.log(`⚙️   Scanners    : ${scanners.length}  |  Profile: ${profile}`);
  console.log(`🕸️   Max Depth   : ${maxDepth}`);
  console.log(`🔄  Concurrency : ${concurrency}  |  Timeout: ${timeout}ms`);
  if (auth)    console.log(`🔑  Authenticated scan`);
  if (webhook) console.log(`📣  Webhook: ${webhook}`);
  console.log(bar);

  // ── Diff: load previous scan ──────────────────────────────────────────────
  let previousScan = null;
  if (diff || !noHistory) {
    previousScan = loadLastHistory(targets);
    if (diff && !previousScan) console.log('ℹ️  No previous scan found for diff — running fresh scan\n');
  }

  const allResults = [];
  const limit      = pLimit(concurrency);

  // ── Initial Fingerprinting & Discovery ────────────────────────────────────
  const targetTasks = targets.map(initialTarget => limit(async () => {
    console.log(`\n🛰️   Starting crawl: ${initialTarget}`);
    
    // 1. Initial Fingerprint
    const fp = await fingerprint(initialTarget, fetchWithRetry);
    const stackStr = fp.stack.length
      ? fp.stack.map(s => `${s.tech}(${s.score})`).join(', ')
      : 'unknown';
    console.log(`    🧠  Stack : ${stackStr}`);

    // 2. Discover URLs via Crawler
    const queue = new TaskQueue(initialTarget);
    let depth = 0;

    // Sequential crawl for base structure (simple for now)
    while (depth < maxDepth && !queue.isEmpty()) {
      const topLevelPaths = Array.from(queue.pending);
      console.log(`    🕸️   Depth ${depth}: Scanning ${topLevelPaths.length} pages for links...`);
      
      for (const p of topLevelPaths) {
        const discovered = await crawlPage(p, fetchWithRetry);
        queue.push(discovered);
      }
      depth++;
    }

    console.log(`    🏁  Crawl complete: ${queue.totalFound} unique pages found.`);

    // 3. Scan all discovered URLs
    const activeScanners = scanners.filter(s => {
      if (profileChecks && !profileChecks.includes(s.name)) return false;
      if (s.tags.includes('all')) return true;
      if (techOverride?.length) {
        return techOverride.includes(fp.primary) ||
               s.tags.some(t => techOverride.includes(t));
      }
      return fp.stack?.some(t => s.tags.includes(t.tech));
    });

    console.log(`    ⚙️   Running ${activeScanners.length} checks on ${queue.totalFound} pages...`);

    const checkLimit = pLimit(3);
    const allDiscovered = Array.from(queue.seen);
    
    const scanResults = await Promise.all(allDiscovered.map(page => checkLimit(async () => {
      // Run each scanner on each page
      const pageResults = await Promise.all(activeScanners.map(scan => async () => {
        try {
          const res    = await scan.run(page, fetchWithRetry);
          // Only log non-safe results for discovery mode to avoid noise
          if (res.status !== 'SAFE') {
            const icon = ICON[res.status] ?? '❓';
            console.log(`      ${icon}  [${(res.severity ?? 'NONE').padEnd(8)}] ${res.name} → ${page}`);
            if (res.fix) console.log(`          💡 Suggestion: ${res.fix}`);
          }
          return { target: page, ...res };
        } catch (e) {
          return { target: page, name: scan.name, status: 'ERROR', severity: 'LOW', reason: e.message };
        }
      }).map(fn => fn()));
      return pageResults;
    })));

    return scanResults.flat();
  }));

  const nested = await Promise.all(targetTasks);
  nested.forEach(r => allResults.push(...r));

  // ── Summary ───────────────────────────────────────────────────────────────
  const risk       = calculateRisk(allResults);
  const vulns      = allResults.filter(r => r.status === 'VULNERABLE');
  const suspicious = allResults.filter(r => r.status === 'SUSPICIOUS');

  console.log(`\n${bar}`);
  console.log('📊  SCAN SUMMARY');
  console.log(bar);
  console.log(`Risk Level  : ${risk.level}  (score: ${risk.score})`);
  console.log(`🚨 Vulnerable  : ${vulns.length}`);
  console.log(`⚠️  Suspicious  : ${suspicious.length}`);
  console.log(`📋 Total checks: ${allResults.length}`);

  if (vulns.length > 0) {
    console.log('\n🚨  Vulnerabilities:');
    vulns.forEach(v => {
      const loc = v.path ?? '';
      console.log(`     • [${v.severity}] ${v.name}${loc}  →  ${v.target}`);
      if (v.fix) console.log(`       💡 How to fix: ${v.fix}`);
    });
  }

  // ── Save history ──────────────────────────────────────────────────────────
  if (!noHistory) {
    const hFile = saveHistory(targets, allResults, risk);
    console.log(`\n📁  History saved → ${hFile}`);
  }

  // ── Diff output ───────────────────────────────────────────────────────────
  if (diff && previousScan) {
    const d = diffScans(previousScan, allResults);
    printDiff(d);
  }

  // ── Reports ───────────────────────────────────────────────────────────────
  const stem = output.replace(/\.(json|html)$/, '');

  if (json) {
    const report = generateReport(allResults, risk);
    const file   = saveReport(report, stem);
    console.log(`\n💾  JSON report → ${file}`);
  }

  if (html) {
    const file = saveHtmlReport(allResults, risk, stem);
    console.log(`🌐  HTML report → ${file}`);
  }

  // ── Webhook ───────────────────────────────────────────────────────────────
  if (webhook) {
    await sendWebhook(webhook, allResults, risk, targets);
  }

  console.log(bar);

  // ── CI/CD exit codes ──────────────────────────────────────────────────────
  // 0 = all clear | 1 = HIGH risk | 2 = VULNERABLE or CRITICAL
  if (vulns.length > 0 || risk.level === 'CRITICAL') {
    process.exitCode = 2;
  } else if (risk.level === 'HIGH') {
    process.exitCode = 1;
  }

  return allResults;
}