#!/usr/bin/env node

import fs                             from 'node:fs';
import path                           from 'node:path';
import { fileURLToPath }              from 'node:url';
import { runScanner, normalizeScopeRules } from '../scan.js';
import { loadConfig, mergeConfig }  from '../core/config.js';
import { listProfiles }             from '../core/profiles.js';
import { validateTargets, validateTargetUrl, resolveAndValidateTarget } from '../core/validator.js';
import { scaffoldCheck }              from '../core/catalog.js';
import { getScanners }               from '../core/registry.js';
import { fingerprint }               from '../core/fingerprint.js';
import { createGovernedFetch }       from '../core/fetch.js';
import { TargetPinStore }            from '../core/guard.js';
import { selectScannersForStack }    from '../core/profiles.js';
import { LlmPool }                   from '../core/llmpool.js';
import { analyzeApiCommunication }   from '../core/ai-advisor.js';
import { runSystemDoctor, diagnoseTarget } from '../core/system-doctor.js';
import { parseCustomHeaderLine, validateCustomHeaders } from '../core/headers.js';
import {
  auditCveCoverage,
  formatCveAuditText,
  formatCveAuditMarkdown,
  formatCveAuditCsv
}                                     from '../core/cve-audit.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PKG_VERSION = (() => {
  try {
    const pkgPath = path.resolve(__dirname, '../package.json');
    return JSON.parse(fs.readFileSync(pkgPath, 'utf8')).version || '2.2.0';
  } catch {
    return '2.2.0';
  }
})();

function printUsage() {
  console.log([
    'Usage: secscan <url> [options]',
    '       secscan --cve-audit [options]',
    '       secscan --doctor [url...] [options]',
    '       secscan --ui [--port 4321]',
    '       secscan --new-check <name>',
    '       secscan --list-checks',
    '',
    'General:',
    '  -h, --help                Show this help message and exit',
    '  -v, --version             Print version and exit',
    '  --doctor                  Check runtime, storage, proxy, LLM pool, and optional target connectivity',
    '',
    'Web Dashboard:',
    '  --ui                      Launch interactive Web UI Dashboard',
    '  --port <port>             Port for Web UI server          (default: 4321)',
    '',
    'CVE Coverage Audit:',
    '  --cve-audit               Audit built-in scanner checks against CVE advisories',
    '  --cve-db <provider|url>   Confirm vs external CVE DB: osv|nvd|ghsa|cisa-kev or custom JSON URL',
    '  --cve-packages <list>     Filter/match package@version list (e.g. laravel/framework@11.30.0,next@14.2.1)',
    '  --cve-catalog <file>      Load custom CVE advisory catalog or NVD/OSV/GHSA/KEV JSON export file',
    '  --cve-feed                Sync optional online advisory feed (graceful offline fallback)',
    '  --fail-on-missing-cves    Exit 1 if any evaluated CVE advisories are missing coverage',
    '',
    'Maintenance & Scaffolding:',
    '  --new-check <name>        Scaffold a new check plugin and test suite',
    '  --list-checks             List all security checks with metadata',
    '',
    'Scan Options:',
    '  --detect, --fingerprint   Detect tech stack and profile recommendation only (no scan)',
    '  --force-all               Run all security checks regardless of detected tech stack',
    '  --json                    Save JSON report (or stdout JSON in --cve-audit / --doctor mode)',
    '  --html                    Save HTML report (dark-mode, self-contained)',
    '  --markdown [file]         Save Markdown report (optional output filename)',
    '  --csv [file]              Save CSV report (optional output filename)',
    '  --sarif [file]            Save SARIF v2.1.0 report (default: secscan-report.sarif)',
    '  --ai-fix                  Generate AI / playbook fix solutions and audience summary',
    '  --audience <beginner|pro> Target audience for --ai-fix guidance (default: pro)',
    '  --output <stem>           Base name for reports            (default: report)',
    '  --profile <name>          Scan profile (18+ profiles): smart (default)|quick|modern|cms|api|laravel|wordpress|apache|nginx|spring|full',
    '  --profiles                List all 18+ available profiles',
    '  --depth <n>               Crawl depth for discovery (0..5, default: 3)',
    '  --tech <list>             Force tech tags, comma-separated (e.g. react,node,laravel)',
    '  --concurrency <n>         Parallel targets                 (default: 5)',
    '  --timeout <ms>            Request timeout in ms            (default: 10000)',
    '  --auth <token>            Authorization header value',
    '  --header "Name: Value"    Custom HTTP request header (repeatable)',
    '  --diff                    Compare with last scan and show changes',
    '  --no-history              Do not save this scan to history',
    '  --webhook <url>           Send results to Slack/webhook URL',
    '  --agent                   Run AgentEngine planner-worker verification loop',
    '  --goal <text>             Custom verification goal for --agent mode',
    '  --noise-profile <p>       NoiseGovernor profile: off|quiet|balanced|aggressive',
    '  --scope <rule>            Scope allow/deny rule (repeatable or comma-separated)',
    '  --allow-private           Allow RFC1918 & internal hosts (cloud metadata stays blocked)',
    '  --verify                  Reserved for future use',
    '',
    'Examples:',
    '  secscan --ui',
    '  secscan --cve-audit --json',
    '  secscan --cve-audit --tech nextjs,spring --fail-on-missing-cves',
    '  secscan https://example.com --detect',
    '  secscan https://example.com --profile smart --html',
    '  secscan https://example.com --force-all',
    '  secscan --new-check my-custom-check',
    '  secscan --list-checks',
    '',
    'Config file: create .secscanrc in your project root to persist options.',
  ].join('\n'));
}

// ── Parse raw CLI arguments ────────────────────────────────────────────────
const args = process.argv.slice(2);

const cli = {
  targets          : [],
  verify           : false,
  json             : false,
  html             : false,
  markdown         : false,
  csv              : false,
  sarif            : false,
  aiFix            : false,
  audience         : null,
  headers          : {},
  doctor           : false,
  diff             : false,
  noHistory        : false,
  concurrency      : null,
  techOverride     : null,
  output           : null,
  timeout          : null,
  auth             : null,
  profile          : null,
  webhook          : null,
  maxDepth         : null,
  ui               : false,
  port             : null,
  newCheck         : null,
  listChecks       : false,
  detect           : false,
  forceAll         : false,
  agent            : false,
  goal             : null,
  noiseProfile     : null,
  scopeRules       : [],
  allowPrivate     : false,
  cveAudit         : false,
  cveCatalog       : null,
  cveFeed          : false,
  cveDb            : null,
  cvePackages      : null,
  failOnMissingCves: false,
  help             : false,
  version          : false,
  profiles         : false,
};

function isOptionalFileArg(next) {
  return Boolean(next && !next.startsWith('-') && !/^https?:\/\//i.test(next));
}

function parseStrictInt(raw, flagName, { min = null, max = null } = {}) {
  const trimmed = String(raw ?? '').trim();
  if (!/^-?\d+$/.test(trimmed)) {
    console.error(`❌  Invalid ${flagName} value "${raw}". Expected an integer.`);
    process.exit(1);
  }
  const n = Number(trimmed);
  if (!Number.isSafeInteger(n) || (min !== null && n < min) || (max !== null && n > max)) {
    const rangeDesc = min !== null && max !== null
      ? `between ${min} and ${max}`
      : min !== null
        ? `>= ${min}`
        : `<= ${max}`;
    console.error(`❌  Invalid ${flagName} value "${raw}". Expected an integer ${rangeDesc}.`);
    process.exit(1);
  }
  return n;
}

for (let i = 0; i < args.length; i++) {
  const a = args[i];
  const requireArgValue = (flagName) => {
    if (i + 1 >= args.length || args[i + 1].startsWith('--') || args[i + 1].trim() === '') {
      console.error(`❌  Missing value for ${flagName}`);
      process.exit(1);
    }
    i += 1;
    return args[i];
  };

  if      (a === '--help' || a === '-h') cli.help       = true;
  else if (a === '--version' || a === '-v') cli.version = true;
  else if (a === '--profiles')    cli.profiles   = true;
  else if (a === '--verify')      cli.verify     = true;
  else if (a === '--json')        cli.json       = true;
  else if (a === '--html')        cli.html       = true;
  else if (a === '--markdown')    cli.markdown   = isOptionalFileArg(args[i + 1]) ? args[++i] : true;
  else if (a === '--csv')         cli.csv        = isOptionalFileArg(args[i + 1]) ? args[++i] : true;
  else if (a === '--sarif')       cli.sarif      = isOptionalFileArg(args[i + 1]) ? args[++i] : true;
  else if (a === '--ai-fix')      cli.aiFix      = true;
  else if (a === '--audience')    cli.audience   = requireArgValue('--audience');
  else if (a === '--doctor')      cli.doctor     = true;
  else if (a === '--header') {
    const rawHeader = requireArgValue('--header');
    const parsedHdr = parseCustomHeaderLine(rawHeader);
    if (!parsedHdr.valid) {
      console.error(`❌  Invalid --header: ${parsedHdr.error}`);
      process.exit(1);
    }
    cli.headers[parsedHdr.name] = parsedHdr.value;
    try {
      cli.headers = validateCustomHeaders(cli.headers);
    } catch (err) {
      console.error(`❌  Invalid --header: ${err.message}`);
      process.exit(1);
    }
  }
  else if (a === '--diff')        cli.diff       = true;
  else if (a === '--no-history')  cli.noHistory  = true;
  else if (a === '--ui')          cli.ui         = true;
  else if (a === '--detect' || a === '--fingerprint') cli.detect = true;
  else if (a === '--force-all')   cli.forceAll   = true;
  else if (a === '--allow-private') cli.allowPrivate = true;
  else if (a === '--agent')       cli.agent      = true;
  else if (a === '--list-checks') cli.listChecks = true;
  else if (a === '--cve-audit')   cli.cveAudit   = true;
  else if (a === '--cve-feed')    cli.cveFeed    = true;
  else if (a === '--cve-db')      cli.cveDb      = requireArgValue('--cve-db');
  else if (a === '--cve-packages') cli.cvePackages = requireArgValue('--cve-packages');
  else if (a === '--fail-on-missing-cves') cli.failOnMissingCves = true;
  else if (a === '--cve-catalog') cli.cveCatalog = requireArgValue('--cve-catalog');
  else if (a === '--goal')        cli.goal       = requireArgValue('--goal');
  else if (a === '--noise-profile') cli.noiseProfile = requireArgValue('--noise-profile');
  else if (a === '--scope') {
    const rawScope = requireArgValue('--scope');
    for (const part of rawScope.split(',')) {
      const trimmed = part.trim();
      if (trimmed) cli.scopeRules.push(trimmed);
    }
  }
  else if (a === '--port')        cli.port       = parseStrictInt(requireArgValue('--port'), '--port', { min: 1, max: 65535 });
  else if (a === '--new-check')   cli.newCheck   = requireArgValue('--new-check');
  else if (a === '--concurrency') cli.concurrency= parseStrictInt(requireArgValue('--concurrency'), '--concurrency', { min: 1 });
  else if (a === '--tech') {
    const rawTech = requireArgValue('--tech');
    cli.techOverride = rawTech.split(',').map(s => s.trim()).filter(Boolean);
  }
  else if (a === '--output')      cli.output     = requireArgValue('--output');
  else if (a === '--timeout')     cli.timeout    = parseStrictInt(requireArgValue('--timeout'), '--timeout', { min: 100 });
  else if (a === '--auth')        cli.auth       = requireArgValue('--auth');
  else if (a === '--profile')     cli.profile    = requireArgValue('--profile');
  else if (a === '--webhook')     cli.webhook    = requireArgValue('--webhook');
  else if (a === '--depth')       cli.maxDepth   = parseStrictInt(requireArgValue('--depth'), '--depth', { min: 0 });
  else if (a.startsWith('-')) {
    console.error(`❌  Unknown CLI option: ${a}. Run \`secscan --help\` for usage.`);
    process.exit(1);
  }
  else                            cli.targets.push(a);
}

if (cli.help) {
  printUsage();
  process.exit(0);
}

if (cli.version) {
  console.log(`secscan ${PKG_VERSION}`);
  process.exit(0);
}

if (cli.profiles) {
  console.log('Available profiles:\n' + listProfiles());
  process.exit(0);
}

// ── Check Scaffolding (--new-check <name>) ─────────────────────────────────
if (cli.newCheck !== null) {
  if (!cli.newCheck || typeof cli.newCheck !== 'string') {
    console.error('❌  Error: --new-check requires a check name (e.g. secscan --new-check my-vuln)');
    process.exit(1);
  }
  try {
    const result = scaffoldCheck(cli.newCheck);
    console.log('\n✅  Check scaffolded successfully!');
    console.log('\nCreated files:');
    console.log(`  📄 Check plugin : ${result.checkPath}`);
    console.log(`  🧪 Test suite   : ${result.testPath}`);
    console.log('\nNext steps:');
    console.log(`  1. Edit ${result.checkFilename} to add vulnerability detection logic`);
    console.log(`  2. Add test cases in ${result.testFilename}`);
    console.log('  3. Run `npm test` to verify\n');
    process.exit(0);
  } catch (err) {
    console.error(`❌  Failed to scaffold check: ${err.message}`);
    process.exit(1);
  }
}

// ── List Checks (--list-checks) ────────────────────────────────────────────
if (cli.listChecks) {
  try {
    const scanners = await getScanners();
    const sorted = [...scanners].sort((a, b) => a.name.localeCompare(b.name));
    console.log(`\n🔍 Available Security Checks (${sorted.length} total):\n`);
    console.log('ID'.padEnd(28) + 'Category'.padEnd(24) + 'Tags'.padEnd(20) + 'Title');
    console.log('─'.repeat(95));
    for (const s of sorted) {
      const meta = s.meta || {};
      const id = s.name.padEnd(28);
      const cat = (meta.category || 'General').padEnd(24);
      const tags = (s.tags || []).join(',').slice(0, 18).padEnd(20);
      const title = meta.title || s.name;
      console.log(`${id}${cat}${tags}${title}`);
    }
    console.log('─'.repeat(95) + '\n');
    process.exit(0);
  } catch (err) {
    console.error(`❌  Failed to list checks: ${err.message}`);
    process.exit(1);
  }
}

// ── Load .secscanrc and merge ────────────────────────────────────────────────
const config  = loadConfig();
const baseOptions = mergeConfig(cli, config);
const options = {
  ...baseOptions,
  agent: cli.agent || Boolean(config.agent),
  goal: cli.goal ?? config.goal ?? null,
  noiseProfile: cli.noiseProfile ?? config.noiseProfile ?? null,
  scopeRules: cli.scopeRules.length ? cli.scopeRules : (config.scopeRules ?? null),
  markdown: cli.markdown || config.markdown || false,
  csv: cli.csv || config.csv || false,
  sarif: cli.sarif || config.sarif || false,
  aiFix: Boolean(cli.aiFix || config.aiFix),
  audience: cli.audience ?? config.audience ?? 'pro',
  headers: Object.keys(cli.headers).length ? cli.headers : (config.headers ?? {}),
  allowPrivate: Boolean(cli.allowPrivate || config.allowPrivate),
  cveAudit: Boolean(cli.cveAudit || (cli.cveDb && cli.targets.length === 0)),
  cveCatalog: cli.cveCatalog ?? config.cveCatalog ?? null,
  cveFeed: Boolean(cli.cveFeed || config.cveFeed || cli.cveDb || config.cveDb),
  cveDb: cli.cveDb ?? config.cveDb ?? null,
  cvePackages: cli.cvePackages ?? config.cvePackages ?? null,
  failOnMissingCves: Boolean(cli.failOnMissingCves || config.failOnMissingCves),
};

const VALID_AUDIENCES = new Set(['beginner', 'pro']);
if (options.audience !== null && options.audience !== undefined) {
  const normAudience = String(options.audience).trim().toLowerCase();
  if (!VALID_AUDIENCES.has(normAudience)) {
    console.error(`❌  Invalid --audience "${options.audience}". Expected: beginner or pro`);
    process.exit(1);
  }
  options.audience = normAudience;
}

const VALID_NOISE_PROFILES = new Set(['off', 'quiet', 'balanced', 'aggressive']);
if (options.noiseProfile && !VALID_NOISE_PROFILES.has(String(options.noiseProfile).toLowerCase())) {
  console.error(`❌  Invalid --noise-profile "${options.noiseProfile}". Expected: off, quiet, balanced, aggressive`);
  process.exit(1);
}

try {
  options.headers = validateCustomHeaders(options.headers);
} catch (err) {
  console.error(`❌  Invalid headers configuration: ${err.message}`);
  process.exit(1);
}

// ── System Doctor Mode (--doctor) ──────────────────────────────────────────
if (cli.doctor) {
  try {
    const allowPrivate = Boolean(options.allowPrivate);
    const llmPool = new LlmPool({ autoDiscoverEnv: true });
    const doctor = await runSystemDoctor({ allowPrivate, llmPool, probeWrites: true });
    const normalizedScopeRules = normalizeScopeRules(options.scopeRules);
    const targetDiagnostics = [];
    for (const rawTarget of cli.targets) {
      const check = validateTargetUrl(rawTarget, { allowPrivate });
      const targetToDiagnose = check.valid ? check.normalized : rawTarget;
      const diag = await diagnoseTarget(targetToDiagnose, {
        allowPrivate,
        ...(normalizedScopeRules.length ? { scopeRules: normalizedScopeRules } : {}),
      });
      targetDiagnostics.push(diag);
    }
    const allTargetsOk = targetDiagnostics.every(d => d.ok === true);
    const overallOk = Boolean(doctor.ok) && allTargetsOk;

    if (options.json) {
      console.log(JSON.stringify({
        ok: overallOk,
        doctor,
        ...(targetDiagnostics.length ? { targets: targetDiagnostics } : {}),
      }, null, 2));
    } else {
      console.log('\n🩺 Security Scanner System Doctor');
      console.log('─'.repeat(60));
      console.log(`Status       : ${doctor.ok ? '✅ HEALTHY' : '❌ UNHEALTHY'}`);
      console.log(`Node.js      : ${doctor.environment.nodeVersion} (${doctor.environment.nodeOk ? 'OK' : 'Requires >= 22'})`);
      console.log(`SQLite       : ${doctor.environment.sqliteAvailable ? 'Available' : 'Unavailable'}`);
      console.log(`Checks       : ${doctor.checks.count} loaded`);
      console.log(`Storage      : history=${doctor.storage.historyDir.writable ? 'writable' : 'NOT writable'}, reports=${doctor.storage.reportsDir.writable ? 'writable' : 'NOT writable'}`);
      console.log(`Proxy        : ${doctor.proxy.configured ? `http=${doctor.proxy.httpProxy || 'none'}, https=${doctor.proxy.httpsProxy || 'none'}` : 'none'}`);
      console.log(`AI Pool      : ${doctor.ai.activeProfilesCount} active profile(s)${doctor.ai.providers.length ? ` (${doctor.ai.providers.join(', ')})` : ''}`);
      if (doctor.recommendations.length > 0) {
        console.log('\nRecommendations:');
        for (const rec of doctor.recommendations) {
          console.log(`  - ${rec}`);
        }
      }
      if (targetDiagnostics.length > 0) {
        console.log('\nTarget Connectivity Triage:');
        for (const d of targetDiagnostics) {
          console.log(`  ${d.ok ? '✅' : '❌'} ${d.targetUrl} [${d.stage}${d.issueOrigin ? ` / ${d.issueOrigin}` : ''}]: ${d.reason}`);
          if (d.recommendation) console.log(`     💡 ${d.recommendation}`);
        }
      }
      console.log('─'.repeat(60) + '\n');
    }

    process.exit(overallOk ? 0 : 1);
  } catch (err) {
    console.error(`❌  System doctor failed: ${err.message}`);
    process.exit(1);
  }
}

// ── CVE Coverage Audit Mode (--cve-audit) ──────────────────────────────────
if (options.cveAudit) {
  try {
    const normalizedScopeRules = normalizeScopeRules(options.scopeRules);
    const audit = await auditCveCoverage({
      customCatalogPath: options.cveCatalog || null,
      techTags: options.techOverride || [],
      ...(options.cveDb ? { provider: options.cveDb } : {}),
      ...(options.cvePackages ? { packages: options.cvePackages } : {}),
      includeFeed: Boolean(options.cveFeed || options.cveDb),
      allowPrivate: Boolean(options.allowPrivate),
      ...(normalizedScopeRules.length ? { scopeRules: normalizedScopeRules } : {}),
    });

    if (options.markdown) {
      const mdContent = formatCveAuditMarkdown(audit);
      if (typeof options.markdown === 'string' && options.markdown.trim()) {
        const mdName = options.markdown.endsWith('.md') ? options.markdown : `${options.markdown}.md`;
        fs.writeFileSync(mdName, mdContent, 'utf8');
        if (!options.json) console.log(`📝  CVE audit Markdown → ${mdName}`);
      } else if (!options.json) {
        console.log(mdContent);
      }
    }

    if (options.csv) {
      const csvContent = formatCveAuditCsv(audit);
      if (typeof options.csv === 'string' && options.csv.trim()) {
        const csvName = options.csv.endsWith('.csv') ? options.csv : `${options.csv}.csv`;
        fs.writeFileSync(csvName, csvContent, 'utf8');
        if (!options.json) console.log(`📊  CVE audit CSV → ${csvName}`);
      } else if (!options.json) {
        console.log(csvContent);
      }
    }

    if (options.json) {
      console.log(JSON.stringify(audit, null, 2));
    } else if (!options.markdown && !options.csv) {
      console.log(formatCveAuditText(audit));
    }

    if (options.failOnMissingCves && audit.summary.missingCount > 0) {
      process.exit(1);
    }
    process.exit(0);
  } catch (err) {
    console.error(`❌  CVE audit failed: ${err.message}`);
    process.exit(1);
  }
}

// ── Interactive Web UI Dashboard ───────────────────────────────────────────
if (options.ui) {
  const { startServer } = await import('../core/server.js');
  const normalizedScopeRules = normalizeScopeRules(options.scopeRules);
  await startServer({
    port: options.port || 4321,
    ...(options.noiseProfile ? { noiseProfile: options.noiseProfile } : {}),
    ...(normalizedScopeRules.length ? { scopeRules: normalizedScopeRules } : {}),
    allowPrivate: Boolean(options.allowPrivate),
  });
} else {
  // ── Show help if no targets ────────────────────────────────────────────────
  if (!options.targets.length) {
    printUsage();
    process.exit(1);
  }

  // ── Target validation & SSRF protection ────────────────────────────────────
  const allowPrivate = Boolean(options.allowPrivate);
  const validation = validateTargets(options.targets, { allowPrivate });
  if (!validation.valid) {
    for (const err of validation.errors) {
      console.error(`❌  ${err}`);
    }
    process.exit(1);
  }

  // ── Tech stack detection mode (--detect / --fingerprint) ───────────────────
  if (options.detect) {
    const scanners = await getScanners();
    const customHeaders = options.headers && typeof options.headers === 'object' ? options.headers : {};
    const authHeaders = options.auth ? { Authorization: options.auth } : {};
    const normalizedScopeRules = normalizeScopeRules(options.scopeRules);
    const targetPinStore = new TargetPinStore({ allowPrivate });
    const governedFetch = createGovernedFetch({
      ...(normalizedScopeRules.length ? { scopeRules: normalizedScopeRules } : {}),
      enforceDnsValidation: true,
      allowPrivate,
      targetPinStore,
      retries: 2,
      timeout: options.timeout || 10000
    });
    const fetchWithRetry = (url, opts = {}) => governedFetch(url, {
      ...opts,
      headers: { ...customHeaders, ...authHeaders, ...(opts.headers || {}) }
    });
    const advisorPool = options.aiFix ? new LlmPool({ autoDiscoverEnv: true }) : null;
    const detectResults = [];

    const bar = '─'.repeat(60);
    if (!options.json) {
      console.log('\n🔍 Tech Stack Detection & Profile Recommendation');
      console.log(bar);
    }

    for (const target of validation.targets) {
      if (!options.json) console.log(`\n📡 Target URL: ${target}`);
      try {
        const preDns = await resolveAndValidateTarget(target, { targetPinStore, allowPrivate });
        if (!preDns.valid) {
          const reason = preDns.reason || preDns.error || 'Target blocked by policy';
          if (options.json) {
            detectResults.push({ target, ok: false, error: reason });
          } else {
            console.error(`  ❌ Target blocked: ${reason}`);
          }
          continue;
        }
        const fp = await fingerprint(target, fetchWithRetry);
        const selection = selectScannersForStack(scanners, {
          profile: options.profile || 'smart',
          fp,
          techOverride: options.techOverride,
          forceAll: options.forceAll
        });

        let apiAnalysis = null;
        if (options.aiFix && typeof analyzeApiCommunication === 'function') {
          try {
            apiAnalysis = await analyzeApiCommunication(fp.apiCommunication || { usesApi: false }, {
              target,
              audience: options.audience || 'pro',
              llmPool: advisorPool
            });
          } catch {}
        }

        if (options.json) {
          detectResults.push({
            target,
            ok: true,
            fingerprint: fp,
            apiCommunication: fp.apiCommunication || null,
            recommendedProfile: fp.recommendedProfile || 'smart',
            activeChecksCount: selection.activeScanners.length,
            skippedChecksCount: selection.skippedScanners.length,
            ...(apiAnalysis ? { apiAnalysis } : {})
          });
          continue;
        }

        console.log(`  🧠 Detected Summary           : ${fp.summary || 'Unknown stack'}`);
        console.log(`  ⚡ Primary Tech & Confidence  : ${fp.primary || 'unknown'} (${fp.confidence ?? 0}% confidence)`);
        const ecoTags = (fp.detectedTags && fp.detectedTags.length) ? fp.detectedTags.join(', ') : 'none';
        console.log(`  🏷️  Detected Ecosystem Tags    : ${ecoTags}`);
        console.log(`  🎯 Recommended Profile        : ${fp.recommendedProfile || 'smart'}`);
        console.log(`  🛡️  Relevant Checks Activated  : ${selection.activeScanners.length} active (${selection.skippedScanners.length} skipped)`);

        const apiComm = fp.apiCommunication;
        if (apiComm && apiComm.usesApi) {
          const clientsStr = Array.isArray(apiComm.clients) && apiComm.clients.length ? apiComm.clients.join(', ') : 'HTTP API';
          const protoStr = Array.isArray(apiComm.protocols) && apiComm.protocols.length ? apiComm.protocols.join(', ') : 'HTTP/REST';
          const sameEps = Array.isArray(apiComm.sameOriginEndpoints) ? apiComm.sameOriginEndpoints : [];
          const extOrigins = Array.isArray(apiComm.externalApiOrigins) ? apiComm.externalApiOrigins : [];
          console.log(`  🔌 API Communication          : YES (${clientsStr} [${protoStr}] → ${sameEps.length} same-origin route(s), ${extOrigins.length} external origin(s))`);
          if (sameEps.length > 0) {
            console.log(`     ↳ Same-Origin Endpoints    : ${sameEps.slice(0, 8).join(', ')}${sameEps.length > 8 ? ` (+${sameEps.length - 8} more)` : ''}`);
          }
          if (extOrigins.length > 0) {
            console.log(`     ↳ External API Origins     : ${extOrigins.slice(0, 8).join(', ')}${extOrigins.length > 8 ? ` (+${extOrigins.length - 8} more)` : ''}`);
          }
        } else {
          console.log(`  🔌 API Communication          : Not detected`);
        }

        if (apiAnalysis) {
          const modeLabel = apiAnalysis.mode === 'ai' ? `AI (${apiAnalysis.provider}/${apiAnalysis.model})` : 'Playbook';
          console.log(`  🤖 API Security Advisor       : [${modeLabel}] ${apiAnalysis.headline || apiAnalysis.explanation || ''}`);
          if (apiAnalysis.explanation && apiAnalysis.headline && apiAnalysis.explanation !== apiAnalysis.headline) {
            console.log(`     ${apiAnalysis.explanation}`);
          }
          if (Array.isArray(apiAnalysis.recommendations) && apiAnalysis.recommendations.length > 0) {
            for (const rec of apiAnalysis.recommendations.slice(0, 4)) {
              console.log(`     • ${rec}`);
            }
          }
          if (Array.isArray(apiAnalysis.nextScanTargets) && apiAnalysis.nextScanTargets.length > 0) {
            console.log(`     🎯 Next API Scan Target(s) : ${apiAnalysis.nextScanTargets.join(', ')}`);
          }
        }
      } catch (err) {
        if (options.json) {
          detectResults.push({ target, ok: false, error: err.message });
        } else {
          console.error(`  ❌ Fingerprinting failed: ${err.message}`);
        }
      }
    }

    if (options.json) {
      const single = detectResults[0] || {};
      const payload = detectResults.length === 1
        ? {
            ...(single.fingerprint || {}),
            target: single.target,
            ok: Boolean(single.ok),
            fingerprint: single.fingerprint || null,
            apiCommunication: single.apiCommunication || null,
            recommendedProfile: single.recommendedProfile || 'smart',
            activeChecksCount: single.activeChecksCount ?? 0,
            skippedChecksCount: single.skippedChecksCount ?? 0,
            ...(single.apiAnalysis ? { apiAnalysis: single.apiAnalysis } : {}),
            ...(single.error ? { error: single.error } : {}),
            targets: detectResults
          }
        : { targets: detectResults };
      console.log(JSON.stringify(payload, null, 2));
    } else {
      console.log(`\n${bar}\n`);
    }
    process.exitCode = 0;
  } else {
    // ── Run ────────────────────────────────────────────────────────────────────
    runScanner({ ...options, targets: validation.targets, allowPrivate })
      .catch(e => {
        console.error('Fatal:', e.message);
        process.exitCode = 1;
      });
  }
}
