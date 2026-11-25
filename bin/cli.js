#!/usr/bin/env node

import fs                             from 'node:fs';
import path                           from 'node:path';
import { fileURLToPath }              from 'node:url';
import { loadConfig, mergeConfig }  from '../core/config.js';
import {
  normalizeTargetInput,
  resolveBareIpTargets,
  validateTargets,
  validateTargetUrl,
  resolveAndValidateTarget
} from '../core/validator.js';
import { DEVICE_CATEGORIES, DEVICE_CATEGORY_ALIASES, normalizeDeviceCategory } from '../core/device-scanner.js';
import { parseCustomHeaderLine, validateCustomHeaders } from '../core/headers.js';

async function loadNormalizeScopeRules() {
  const { normalizeScopeRules } = await import('../scan.js');
  return normalizeScopeRules;
}

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
    '  --cve-lab [all|CVE-ID,..] Run Tri-State CVE Lab Benchmark (vulnerable, patched, fp_trap) and market comparison',
    '  --cve-lab-mode <mode>     CVE lab execution mode: emulated (default) or docker',
    '  --cve-db <provider|url>   Confirm vs external CVE DB: osv|nvd|ghsa|cisa-kev or custom JSON URL',
    '  --cve-packages <list>     Filter/match package@version list (e.g. laravel/framework@11.30.0,next@14.2.1)',
    '  --cve-catalog <file>      Load custom CVE advisory catalog or NVD/OSV/GHSA/KEV JSON export file',
    '  --cve-feed                Sync optional online advisory feed (graceful offline fallback)',
    '  --fail-on-missing-cves    Exit 1 if any evaluated CVE advisories are missing coverage',
    '',
    'Maintenance & Scaffolding:',
    '  --new-check <name>        Scaffold a new check plugin and test suite',
    '  --new-cve-lab <CVE-ID>    Scaffold a new Tri-State CVE Docker Lab under cve-labs/<CVE-ID>',
    '  --list-checks             List all security checks with metadata',
    '',
    'Scan Options:',
    '  --detect, --fingerprint   Detect tech stack and profile recommendation only (no scan)',
    '  --force-all               Run all security checks regardless of detected tech stack',
    '  --pc-local                Run deep local host PC security audit (ports, firewall, AV/EDR, unquoted services)',
    '  --oast                    Start local HMAC-tokenized OAST callback server for blind SSRF/XXE verification',
    '  --templates <path>        Run declarative YAML/JSON CVE templates from file or directory',
    '  --json                    Save JSON report (or stdout JSON in --cve-audit / --doctor mode)',
    '  --html                    Save HTML report (dark-mode, self-contained)',
    '  --markdown [file]         Save Markdown report (optional output filename)',
    '  --csv [file]              Save CSV report (optional output filename)',
    '  --sarif [file]            Save SARIF v2.1.0 report (default: secscan-report.sarif)',
    '  --ai-fix                  Generate AI / playbook fix solutions and audience summary',
    '  --audience <beginner|pro> Target audience for --ai-fix guidance (default: pro)',
    '  --output <stem>           Base name for reports            (default: report)',
    '  --profile <name>          Scan profile (20+ profiles): smart (default)|device|quick|modern|cms|api|laravel|wordpress|apache|nginx|spring|full',
    '  --device, --tv, --camera, --pc, --iot',
    '                            Scan Smart TVs, IP Cameras/NVRs, PCs/Workstations/Servers, Routers, Printers, NAS or IoT devices (sets --profile device --allow-private; --tv/--camera/--pc set category)',
    '  --device-category <cat>   Filter device discovery/checks: all|smart_tv|ip_camera|pc_workstation (aliases: tv, camera, pc)',
    '  --profiles                List all 20+ available profiles',
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
    '  --source-ip <ip|host=ip>  Connect HTTP/HTTPS directly to Source/Origin IP with Host & TLS SNI',
    '  --get-real-ip, --real-ip  Discover website real/origin IP (DNS, CDN, SPF, MX, subdomains, headers)',
    '  --scan-real-ip            Discover real/origin IP first and automatically pin --source-ip for the scan',
    '  --review-report <file>    Validate report/finding file against SecScan 7-Gate VDP eligibility rules',
    '  --posture-check [model]   Run SecScan 9-Probe Fenceline LLM refusal-posture check',
    '  --scope <rule>            Scope allow/deny rule (repeatable or comma-separated)',
    '  --allow-private           Allow RFC1918 & internal hosts (cloud metadata stays blocked)',
    '  --verify                  Reserved for future use',
    '',
    'Authentication & Session Recording:',
    '  --login-url <url>         Login form or API endpoint URL (auto-detected if omitted with --username)',
    '  --username, --user <user> Username or email for authenticated website login',
    '  --password, --pass <pass> Password for authenticated website login',
    '  --login-type <type>       Login submission format: auto, form, or json (default: auto)',
    '  --save-session <file>     Record and save the authenticated session (cookies/JWT/CSRF) to a JSON file',
    '  --load-session <file>     Load a previously recorded session JSON file for authenticated scanning',
    '  --record-session          Test login with --username & --password, print recorded session, and exit',
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
  loginUrl         : null,
  username         : null,
  password         : null,
  loginType        : null,
  saveSession      : null,
  loadSession      : null,
  recordSession    : false,
  scan             : false,
  profile          : null,
  device           : false,
  deviceCategory   : null,
  webhook          : null,
  maxDepth         : null,
  ui               : false,
  port             : null,
  newCheck         : null,
  newCveLab        : null,
  listChecks       : false,
  pcLocal          : false,
  oast             : false,
  templates        : null,
  detect           : false,
  forceAll         : false,
  agent            : false,
  goal             : null,
  noiseProfile     : null,
  scopeRules       : [],
  allowPrivate     : false,
  cveLab           : null,
  cveLabMode       : 'emulated',
  cveAudit         : false,
  cveCatalog       : null,
  cveFeed          : false,
  cveDb            : null,
  cvePackages      : null,
  failOnMissingCves: false,
  sourceIp         : null,
  getRealIp        : false,
  scanRealIp       : false,
  checks           : null,
  reviewReport     : null,
  postureCheck     : null,
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
  else if (a === '--device' || a === '--iot') {
    cli.device = true;
    cli.allowPrivate = true;
    if (!cli.profile) cli.profile = 'device';
  }
  else if (a === '--tv') {
    cli.device = true;
    cli.allowPrivate = true;
    if (!cli.profile) cli.profile = 'device';
    if (!cli.deviceCategory) cli.deviceCategory = 'smart_tv';
  }
  else if (a === '--camera') {
    cli.device = true;
    cli.allowPrivate = true;
    if (!cli.profile) cli.profile = 'device';
    if (!cli.deviceCategory) cli.deviceCategory = 'ip_camera';
  }
  else if (a === '--pc') {
    cli.device = true;
    cli.allowPrivate = true;
    if (!cli.profile) cli.profile = 'device';
    if (!cli.deviceCategory) cli.deviceCategory = 'pc_workstation';
  }
  else if (a === '--device-category') {
    cli.deviceCategory = requireArgValue('--device-category');
  }
  else if (a === '--agent')       cli.agent      = true;
  else if (a === '--pc-local')    cli.pcLocal    = true;
  else if (a === '--oast')        cli.oast       = true;
  else if (a === '--templates')   cli.templates  = requireArgValue('--templates');
  else if (a === '--new-cve-lab') cli.newCveLab  = requireArgValue('--new-cve-lab');
  else if (a === '--list-checks') cli.listChecks = true;
  else if (a === '--cve-lab')     cli.cveLab     = isOptionalFileArg(args[i + 1]) ? args[++i] : 'all';
  else if (a === '--cve-lab-mode') cli.cveLabMode = requireArgValue('--cve-lab-mode');
  else if (a === '--cve-audit')   cli.cveAudit   = true;
  else if (a === '--cve-feed')    cli.cveFeed    = true;
  else if (a === '--cve-db')      cli.cveDb      = requireArgValue('--cve-db');
  else if (a === '--cve-packages') cli.cvePackages = requireArgValue('--cve-packages');
  else if (a === '--fail-on-missing-cves') cli.failOnMissingCves = true;
  else if (a === '--cve-catalog') cli.cveCatalog = requireArgValue('--cve-catalog');
  else if (a === '--goal')        cli.goal       = requireArgValue('--goal');
  else if (a === '--noise-profile') cli.noiseProfile = requireArgValue('--noise-profile');
  else if (a === '--source-ip')   cli.sourceIp   = requireArgValue('--source-ip');
  else if (a === '--get-real-ip' || a === '--real-ip' || a === '--find-origin-ip') cli.getRealIp = true;
  else if (a === '--scan-real-ip' || a === '--auto-source-ip') {
    cli.scanRealIp = true;
    cli.getRealIp = true;
  }
  else if (a === '--review-report') cli.reviewReport = requireArgValue('--review-report');
  else if (a === '--posture-check') cli.postureCheck = isOptionalFileArg(args[i + 1]) ? args[++i] : 'default';
  else if (a === '--intruder')    cli.intruderUrl = requireArgValue('--intruder');
  else if (a === '--payloads')    cli.payloads   = requireArgValue('--payloads');
  else if (a === '--attack-mode') cli.attackMode = requireArgValue('--attack-mode');
  else if (a === '--autorize')    cli.autorizeUrl = requireArgValue('--autorize');
  else if (a === '--auth-low')    cli.authLow    = requireArgValue('--auth-low');
  else if (a === '--check' || a === '--checks' || a === '--cve') {
    const rawChecks = requireArgValue(a);
    cli.checks = [
      ...(Array.isArray(cli.checks) ? cli.checks : []),
      ...rawChecks.split(',').map(s => s.trim()).filter(Boolean)
    ];
  }
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
  else if (a === '--login-url')   cli.loginUrl   = requireArgValue('--login-url');
  else if (a === '--username' || a === '--user') cli.username = requireArgValue(a);
  else if (a === '--password' || a === '--pass') {
    if (i + 1 >= args.length || args[i + 1].startsWith('--')) {
      console.error(`❌  Missing value for ${a}`);
      process.exit(1);
    }
    i += 1;
    cli.password = args[i];
  }
  else if (a === '--login-type')  cli.loginType  = requireArgValue('--login-type');
  else if (a === '--save-session') cli.saveSession = requireArgValue('--save-session');
  else if (a === '--load-session') cli.loadSession = requireArgValue('--load-session');
  else if (a === '--record-session') cli.recordSession = true;
  else if (a === '--scan')        cli.scan       = true;
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
  const { listProfiles } = await import('../core/profiles.js');
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
    const { scaffoldCheck } = await import('../core/catalog.js');
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

// ── CVE Lab Scaffolding (--new-cve-lab <CVE-ID>) ───────────────────────────
if (cli.newCveLab !== null) {
  try {
    const { scaffoldCveLab } = await import('../core/cve-lab-runner.js');
    const result = scaffoldCveLab(cli.newCveLab, {
      labsDir: path.resolve(process.cwd(), 'cve-labs')
    });
    if (cli.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log(`\n✅  Scaffolded Tri-State CVE Lab: ${result.cveId} → ${result.relativeDir}`);
      console.log(`    Files created: ${result.filesCreated.join(', ')}\n`);
    }
    process.exit(0);
  } catch (err) {
    console.error(`❌  Failed to scaffold CVE lab: ${err.message}`);
    process.exit(1);
  }
}

// ── List Checks (--list-checks) ────────────────────────────────────────────
if (cli.listChecks) {
  try {
    const { getScanners } = await import('../core/registry.js');
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
  pcLocal: Boolean(cli.pcLocal || config.pcLocal),
  oast: Boolean(cli.oast || config.oast),
  templates: cli.templates ?? config.templates ?? null,
  cveLab: cli.cveLab ?? config.cveLab ?? null,
  cveLabMode: cli.cveLabMode ?? config.cveLabMode ?? 'emulated',
  cveAudit: Boolean(cli.cveAudit || (cli.cveDb && cli.targets.length === 0)),
  cveCatalog: cli.cveCatalog ?? config.cveCatalog ?? null,
  cveFeed: Boolean(cli.cveFeed || config.cveFeed || cli.cveDb || config.cveDb),
  cveDb: cli.cveDb ?? config.cveDb ?? null,
  cvePackages: cli.cvePackages ?? config.cvePackages ?? null,
  failOnMissingCves: Boolean(cli.failOnMissingCves || config.failOnMissingCves),
  sourceIp: cli.sourceIp ?? config.sourceIp ?? null,
  getRealIp: Boolean(cli.getRealIp || config.getRealIp),
  scanRealIp: Boolean(cli.scanRealIp || config.scanRealIp),
  checks: cli.checks ?? config.checks ?? null,
  loginUrl: cli.loginUrl ?? config.loginUrl ?? null,
  username: cli.username ?? config.username ?? null,
  password: cli.password ?? config.password ?? null,
  loginType: cli.loginType ?? config.loginType ?? 'auto',
  saveSession: cli.saveSession ?? config.saveSession ?? null,
  loadSession: cli.loadSession ?? config.loadSession ?? null,
  recordSession: Boolean(cli.recordSession),
  scan: Boolean(cli.scan),
  deviceMode: Boolean(cli.device || baseOptions.deviceMode),
  deviceCategory: cli.deviceCategory ?? baseOptions.deviceCategory ?? null,
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

const VALID_LOGIN_TYPES = new Set(['auto', 'form', 'json']);
if (options.loginType !== null && options.loginType !== undefined) {
  const normLoginType = String(options.loginType).trim().toLowerCase();
  if (!VALID_LOGIN_TYPES.has(normLoginType)) {
    console.error(`❌  Invalid --login-type "${options.loginType}". Expected: auto, form, or json`);
    process.exit(1);
  }
  options.loginType = normLoginType;
}

const PROFILE_DEVICE_CATEGORY_MAP = new Map([
  ['tv', 'smart_tv'],
  ['smart-tv', 'smart_tv'],
  ['smart_tv', 'smart_tv'],
  ['camera', 'ip_camera'],
  ['cam', 'ip_camera'],
  ['nvr', 'ip_camera'],
  ['ip-camera', 'ip_camera'],
  ['ip_camera', 'ip_camera'],
  ['pc', 'pc_workstation'],
  ['workstation', 'pc_workstation'],
  ['server', 'pc_workstation'],
  ['pc-workstation', 'pc_workstation'],
  ['pc_workstation', 'pc_workstation']
]);

if (options.deviceCategory !== null && options.deviceCategory !== undefined && String(options.deviceCategory).trim() !== '') {
  const rawCat = String(options.deviceCategory).trim().toLowerCase();
  const underscoredCat = rawCat.replace(/-/g, '_');
  const validCat =
    Object.prototype.hasOwnProperty.call(DEVICE_CATEGORY_ALIASES, rawCat) ||
    Object.prototype.hasOwnProperty.call(DEVICE_CATEGORIES, underscoredCat);
  if (!validCat) {
    console.error(`❌  Invalid --device-category "${options.deviceCategory}". Expected: all, smart_tv, ip_camera, or pc_workstation (aliases: tv, camera, pc)`);
    process.exit(1);
  }
  options.deviceCategory = normalizeDeviceCategory(rawCat);
} else {
  const profileKey = String(options.profile || '').trim().toLowerCase();
  options.deviceCategory = PROFILE_DEVICE_CATEGORY_MAP.get(profileKey) || 'all';
}

try {
  options.headers = validateCustomHeaders(options.headers);
} catch (err) {
  console.error(`❌  Invalid headers configuration: ${err.message}`);
  process.exit(1);
}

const DEVICE_PROFILE_SET = new Set([
  'device', 'tv', 'smart-tv', 'smart_tv', 'iot',
  'camera', 'cam', 'nvr', 'ip-camera', 'ip_camera',
  'pc', 'workstation', 'server', 'pc-workstation', 'pc_workstation', 'lan'
]);
const isDeviceProfile = DEVICE_PROFILE_SET.has(String(options.profile || '').toLowerCase());
const deviceMode = Boolean(options.deviceMode || cli.device || isDeviceProfile || options.deviceCategory !== 'all');
const allowPrivate = Boolean(options.allowPrivate || cli.device || isDeviceProfile);
options.deviceMode = deviceMode;
options.allowPrivate = allowPrivate;

// ── Pre-Submission VDP Report Review Mode (--review-report <file>) ─────────
if (cli.reviewReport) {
  try {
    const { reviewReportSubmission } = await import('../core/submission-review.js');
    const rawReport = fs.readFileSync(path.resolve(cli.reviewReport), 'utf8');
    let parsedInput = rawReport;
    if (cli.reviewReport.endsWith('.json')) {
      try {
        parsedInput = JSON.parse(rawReport);
      } catch {}
    }
    const review = await reviewReportSubmission(parsedInput);
    if (options.json) {
      console.log(JSON.stringify(review, null, 2));
    } else {
      console.log(`\n${review.submitReady ? '✅ SUBMIT-READY' : '❌ GAPS FOUND'} (${review.passedCount}/${review.totalChecks} checks pass)`);
      for (const v of review.failedChecks) {
        console.log(`  FAIL ${v.check}: ${v.reason}`);
        if (v.fix) console.log(`       fix: ${v.fix}`);
      }
      console.log('');
    }
    process.exit(review.exitCode);
  } catch (err) {
    console.error(`❌  Report review failed: ${err.message}`);
    process.exit(err.exitCode || 1);
  }
}

// ── LLM Refusal Posture Check Mode (--posture-check [model]) ───────────────
if (cli.postureCheck) {
  try {
    const [{ LlmPool }, { runLlmPostureCheck }] = await Promise.all([
      import('../core/llmpool.js'),
      import('../core/posture-check.js'),
    ]);
    const llmPool = new LlmPool({ autoDiscoverEnv: true });
    const summary = await runLlmPostureCheck({
      model: cli.postureCheck === 'default' ? 'configured-pool' : cli.postureCheck,
      llmPool
    });
    if (options.json) {
      console.log(JSON.stringify(summary, null, 2));
    } else {
      console.log(`\n🛡️  LLM Refusal Posture Check (${summary.model})`);
      console.log(`  Refused ${summary.refusedOf[0]}/${summary.refusedOf[1]} policy-boundary | Over-refused ${summary.overRefusedOf[0]}/${summary.overRefusedOf[1]} dual-use/benign | Invalid: ${summary.invalid}`);
      console.log(`  Clean Posture: ${summary.cleanPosture ? '✅ YES' : '⚠️ NO'}\n`);
    }
    process.exit(summary.cleanPosture ? 0 : 1);
  } catch (err) {
    console.error(`❌  Posture check failed: ${err.message}`);
    process.exit(1);
  }
}

// ── System Doctor Mode (--doctor) ──────────────────────────────────────────
if (cli.doctor) {
  try {
    const [{ LlmPool }, { runSystemDoctor, diagnoseTarget }] = await Promise.all([
      import('../core/llmpool.js'),
      import('../core/system-doctor.js'),
    ]);
    const llmPool = new LlmPool({ autoDiscoverEnv: true });
    const doctor = await runSystemDoctor({ allowPrivate, llmPool, probeWrites: true });
    const normalizedScopeRules = options.scopeRules?.length
      ? (await loadNormalizeScopeRules())(options.scopeRules)
      : [];
    const doctorResolved = await resolveBareIpTargets(cli.targets, {
      allowPrivate,
      ...(normalizedScopeRules.length ? { scopeRules: normalizedScopeRules } : {}),
      timeoutMs: options.timeout,
      ...(options.sourceIp ? { sourceIp: options.sourceIp } : {}),
      ...(options.sourceIpMap ? { sourceIpMap: options.sourceIpMap } : {}),
    });
    const targetDiagnostics = [];
    for (const rawTarget of doctorResolved.targets) {
      const normalizedRaw = normalizeTargetInput(rawTarget) || String(rawTarget ?? '').trim();
      const check = validateTargetUrl(normalizedRaw, { allowPrivate });
      const targetToDiagnose = check.valid ? check.normalized : normalizedRaw;
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

// ── Local & Host PC Deep Security Audit Mode (--pc-local) ──────────────────
if (options.pcLocal) {
  try {
    const { runLocalPcAudit, formatLocalPcAuditText } = await import('../core/pc-local-auditor.js');
    const report = await runLocalPcAudit();
    if (options.json) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(formatLocalPcAuditText(report));
    }
    process.exit(0);
  } catch (err) {
    console.error(`❌  Local PC audit failed: ${err.message}`);
    process.exit(1);
  }
}

// ── Tri-State CVE Lab Benchmark Mode (--cve-lab) ───────────────────────────
if (options.cveLab) {
  try {
    const {
      runCveLabBenchmark,
      formatCveLabTextReport,
      formatCveLabMarkdownReport
    } = await import('../core/cve-lab-runner.js');

    const report = await runCveLabBenchmark({
      cveIds: options.cveLab === 'all' || options.cveLab === true ? null : options.cveLab,
      mode: options.cveLabMode || 'emulated'
    });

    if (options.markdown) {
      const mdContent = formatCveLabMarkdownReport(report);
      if (typeof options.markdown === 'string' && options.markdown.trim()) {
        const mdName = options.markdown.endsWith('.md') ? options.markdown : `${options.markdown}.md`;
        fs.writeFileSync(mdName, mdContent, 'utf8');
        if (!options.json) console.log(`📝  CVE lab Markdown → ${mdName}`);
      } else if (!options.json) {
        console.log(mdContent);
      }
    }

    if (options.json) {
      console.log(JSON.stringify(report, null, 2));
    } else if (!options.markdown) {
      console.log(formatCveLabTextReport(report));
    }

    const ok = report.summary.failedVariants === 0 && report.summary.falsePositives === 0;
    process.exit(ok ? 0 : 1);
  } catch (err) {
    console.error(`❌  CVE lab benchmark failed: ${err.message}`);
    process.exit(1);
  }
}

// ── CVE Coverage Audit Mode (--cve-audit) ──────────────────────────────────
if (options.cveAudit) {
  try {
    const {
      auditCveCoverage,
      formatCveAuditText,
      formatCveAuditMarkdown,
      formatCveAuditCsv
    } = await import('../core/cve-audit.js');
    const normalizedScopeRules = options.scopeRules?.length
      ? (await loadNormalizeScopeRules())(options.scopeRules)
      : [];
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
if (cli.intruderUrl) {
  const { runIntruderCampaign } = await import('../core/intruder.js');
  const rawPayloads = String(cli.payloads || '1,2,admin,test').split(',').map(s => s.trim()).filter(Boolean);
  try {
    const res = await runIntruderCampaign(
      {
        url: cli.intruderUrl,
        headers: options.auth ? { Authorization: options.auth } : {},
        payloadSets: [rawPayloads],
        attackMode: cli.attackMode || 'sniper'
      },
      {
        allowPrivate: Boolean(options.allowPrivate),
        sourceIp: options.sourceIp || null,
        scopeRules: options.scopeRules?.length ? (await loadNormalizeScopeRules())(options.scopeRules) : [],
        timeout: options.timeout || 10000
      }
    );
    if (options.json) {
      console.log(JSON.stringify(res, null, 2));
    } else {
      console.log(`\n🎯 Burp Intruder (${res.attackMode}) — ${res.totalPayloads} payloads, ${res.interestingCount} interesting anomalies`);
      for (const r of res.results) {
        const flag = r.isInteresting ? '🔥' : '  ';
        console.log(`${flag} [${r.step}] HTTP ${r.status} (${r.byteLength}B, Δ${r.byteDelta}B, ${r.durationMs}ms) payload=${JSON.stringify(r.payloads)} ${r.anomalyReasons.join('; ')}`);
      }
    }
    process.exit(0);
  } catch (err) {
    console.error(`❌  Intruder failed: ${err.message}`);
    process.exit(1);
  }
}

if (cli.autorizeUrl) {
  const { runAutorizeMatrix } = await import('../core/intruder.js');
  try {
    const res = await runAutorizeMatrix(
      {
        endpoints: [cli.autorizeUrl],
        primaryHeaders: options.auth ? { Authorization: options.auth } : {},
        secondaryHeaders: cli.authLow ? { Authorization: cli.authLow } : null
      },
      {
        allowPrivate: Boolean(options.allowPrivate),
        sourceIp: options.sourceIp || null,
        scopeRules: options.scopeRules?.length ? (await loadNormalizeScopeRules())(options.scopeRules) : [],
        timeout: options.timeout || 10000
      }
    );
    if (options.json) {
      console.log(JSON.stringify(res, null, 2));
    } else {
      console.log(`\n🔐 Burp Autorize Matrix — ${res.totalEndpoints} endpoint(s), ${res.vulnerableCount} bypass(es)`);
      for (const m of res.matrix) {
        console.log(`  [${m.verdict}] ${m.method} ${m.url} -> ${m.status} (${m.detail})`);
      }
    }
    process.exit(res.vulnerableCount > 0 ? 1 : 0);
  } catch (err) {
    console.error(`❌  Autorize failed: ${err.message}`);
    process.exit(1);
  }
}

if (options.ui) {
  const { startServer } = await import('../core/server.js');
  const normalizedScopeRules = options.scopeRules?.length
    ? (await loadNormalizeScopeRules())(options.scopeRules)
    : [];
  await startServer({
    port: options.port || 4321,
    ...(options.noiseProfile ? { noiseProfile: options.noiseProfile } : {}),
    ...(normalizedScopeRules.length ? { scopeRules: normalizedScopeRules } : {}),
    allowPrivate: Boolean(options.allowPrivate),
  });
} else {
  const loadRecordedSessionFile = (filePath) => {
    const resolved = path.resolve(filePath);
    if (!fs.existsSync(resolved)) {
      console.error(`❌  Session file not found: ${resolved}`);
      process.exit(1);
    }
    try {
      const parsed = JSON.parse(fs.readFileSync(resolved, 'utf8'));
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('Expected a JSON object');
      }
      return parsed;
    } catch (err) {
      console.error(`❌  Failed to load session file "${resolved}": ${err.message}`);
      process.exit(1);
    }
  };

  const saveRecordedSessionFile = (filePath, authMgr) => {
    const resolved = path.resolve(filePath);
    fs.mkdirSync(path.dirname(resolved), { recursive: true });
    fs.writeFileSync(resolved, JSON.stringify(authMgr.exportRecordedSession(), null, 2), {
      encoding: 'utf8',
      mode: 0o600
    });
    return resolved;
  };

  const buildCliAuthManager = async (targetUrl, opts, loadedSess) => {
    const resolvedLoginUrl = (() => {
      if (!opts.loginUrl) return null;
      const trimmed = String(opts.loginUrl).trim();
      if (trimmed.startsWith('/')) {
        try {
          return new URL(trimmed, targetUrl).toString();
        } catch {
          return trimmed;
        }
      }
      return trimmed;
    })();

    const hasAuthOpts = Boolean(
      loadedSess ||
      resolvedLoginUrl ||
      opts.username !== null ||
      opts.password !== null
    );
    if (!hasAuthOpts) return null;

    const { AuthSessionManager } = await import('../core/auth-session.js');
    if (loadedSess) {
      const mgr = AuthSessionManager.fromRecordedSession(loadedSess);
      if (!mgr.targetUrl) mgr.targetUrl = targetUrl;
      if (resolvedLoginUrl) mgr.loginUrl = resolvedLoginUrl;
      if (opts.username !== null) mgr.username = String(opts.username);
      if (opts.password !== null) mgr.password = String(opts.password);
      if (cli.loginType) mgr.loginContentType = opts.loginType;
      return mgr;
    }

    return new AuthSessionManager({
      targetUrl,
      ...(resolvedLoginUrl ? { loginUrl: resolvedLoginUrl } : {}),
      ...(opts.username !== null ? { username: opts.username } : {}),
      ...(opts.password !== null ? { password: opts.password } : {}),
      loginContentType: opts.loginType || 'auto'
    });
  };

  const printRecordedSessionDetails = (summary, savedPath = null) => {
    const bar = '─'.repeat(60);
    console.log('\n🔐 Recorded Auth Session');
    console.log(bar);
    console.log(`  Session ID     : ${summary.sessionId}`);
    console.log(`  Target URL     : ${summary.targetUrl || 'N/A'}`);
    console.log(`  Login URL      : ${summary.loginUrl || 'N/A'} (${summary.loginMethod}, ${summary.loginContentType})`);
    console.log(`  Authenticated  : ${summary.authenticated ? '✅ YES' : '❌ NO'}${summary.authenticatedAt ? ` (at ${summary.authenticatedAt})` : ''}`);
    console.log(`  Username       : ${summary.username || 'N/A'} | Password: ${summary.password}`);
    console.log(`  Cookies (${summary.cookieCount})   : ${summary.cookieNames?.length ? summary.cookieNames.join(', ') : 'none'}`);
    console.log(`  Bearer Token   : ${summary.hasBearerToken ? summary.bearerTokenPreview : 'none'}`);
    console.log(`  CSRF Protection: ${summary.csrfHeaderName || 'none'}${summary.csrfFormField ? ` (form field: ${summary.csrfFormField})` : ''}`);
    if (Array.isArray(summary.steps) && summary.steps.length > 0) {
      console.log('  Recorded Steps :');
      for (const s of summary.steps) {
        console.log(`    ${s.step}. [${s.action}] ${s.method || 'GET'} ${s.url} -> HTTP ${s.status}${s.contentType ? ` (${s.contentType})` : ''}`);
      }
    }
    if (savedPath) {
      console.log(`  Saved Session  : ${savedPath}`);
    }
    console.log(bar + '\n');
  };

  const loadedSession = options.loadSession ? loadRecordedSessionFile(options.loadSession) : null;

  if (!options.targets.length) {
    if (options.recordSession && options.loginUrl) {
      try {
        options.targets = [new URL(options.loginUrl).origin];
      } catch {
        options.targets = [options.loginUrl];
      }
    } else if (loadedSession?.targetUrl) {
      options.targets = [loadedSession.targetUrl];
    }
  }

  // ── Show help if no targets ────────────────────────────────────────────────
  if (!options.targets.length) {
    printUsage();
    process.exit(1);
  }

  // ── Target validation & SSRF protection ────────────────────────────────────
  // Auto-normalize quoted/trailing-backslash inputs, bare IP literals (probing both HTTPS/HTTP), and bare domain names
  const normalizedScopeRulesForResolve = options.scopeRules?.length
    ? (await loadNormalizeScopeRules())(options.scopeRules)
    : [];
  const bareIpResolved = await resolveBareIpTargets(options.targets, {
    allowPrivate,
    ...(normalizedScopeRulesForResolve.length ? { scopeRules: normalizedScopeRulesForResolve } : {}),
    timeoutMs: options.timeout,
    ...(options.sourceIp ? { sourceIp: options.sourceIp } : {}),
    ...(options.sourceIpMap ? { sourceIpMap: options.sourceIpMap } : {}),
  });
  options.targets = bareIpResolved.targets;
  const validation = validateTargets(options.targets, { allowPrivate });
  if (!validation.valid) {
    for (const err of validation.errors) {
      console.error(`❌  ${err}`);
    }
    process.exit(1);
  }

  // ── Real / Origin IP Discovery (--get-real-ip / --scan-real-ip) ───────────
  if (options.getRealIp) {
    const { discoverWebsiteRealIp } = await import('../core/real-ip-finder.js');
    const hasExplicitChecks = Boolean(options.checks && options.checks.length > 0);
    const shouldRunScan = Boolean(options.scanRealIp || hasExplicitChecks);
    const normalizedScopeRules = options.scopeRules?.length
      ? (await loadNormalizeScopeRules())(options.scopeRules)
      : [];
    const realIpHeaders = {
      ...(options.headers && typeof options.headers === 'object' ? options.headers : {}),
      ...(options.auth ? { Authorization: options.auth } : {}),
    };
    const results = [];
    const bar = '─'.repeat(60);

    for (const target of validation.targets) {
      let report;
      try {
        report = await discoverWebsiteRealIp(target, {
          allowPrivate,
          rules: normalizedScopeRules,
          ...(Object.keys(realIpHeaders).length ? { headers: realIpHeaders } : {}),
          timeoutMs: options.timeout || 6000
        });
      } catch (err) {
        if (options.json && !shouldRunScan) {
          console.error(JSON.stringify({ ok: false, target, error: err.message, code: err.code || 'REAL_IP_ERROR' }, null, 2));
        } else {
          console.error(`❌  Real IP discovery failed for ${target}: ${err.message}`);
        }
        process.exit(1);
      }
      results.push(report);

      if (!options.json) {
        console.log(`\n🌐 Real / Origin IP Discovery`);
        console.log(bar);
        console.log(`  Target           : ${report.target} (${report.hostname})`);
        console.log(`  Primary DNS IPs  : ${report.primaryIps?.length ? report.primaryIps.join(', ') : 'none'}`);
        console.log(`  CDN / Edge Status: ${report.isBehindCdn ? `Behind CDN/WAF (${report.cdnProvider || 'Detected'})` : 'Direct Origin Server (Not behind CDN)'}`);
        console.log(`  Real / Origin IP : ${report.realIp || 'N/A'} (confidence: ${report.realIpConfidence ?? 0}%, source: ${report.realIpSource || 'N/A'})`);
        if (Array.isArray(report.candidates) && report.candidates.length > 0) {
          console.log('\n  Candidates:');
          console.log(`  ${'IP'.padEnd(20)} ${'Sources'.padEnd(26)} ${'Role'.padEnd(22)} ${'Match'.padEnd(9)} ${'Conf'.padEnd(5)} Reason`);
          console.log(`  ${'─'.repeat(98)}`);
          for (const c of report.candidates) {
            const role = c.isCdnEdge ? `CDN (${c.cdnProvider || 'Edge'})` : 'Origin Candidate';
            const match = c.verifiedOriginMatch ? 'VERIFIED' : (c.blockedByPolicy ? 'BLOCKED' : '');
            const sources = Array.isArray(c.sources) ? c.sources.join(',') : '';
            console.log(
              `  ${String(c.ip).padEnd(20)} ${sources.slice(0, 25).padEnd(26)} ${role.slice(0, 21).padEnd(22)} ${match.padEnd(9)} ${`${c.confidence ?? 0}%`.padEnd(5)} ${c.reason || ''}`
            );
          }
        }
        if (report.commands && typeof report.commands === 'object') {
          console.log('\n  Ready-to-Run Commands:');
          for (const [label, cmd] of Object.entries(report.commands)) {
            if (cmd) console.log(`    ${label}: ${cmd}`);
          }
        }
        console.log(bar);
      }
    }

    if (options.json && !shouldRunScan) {
      console.log(JSON.stringify(results.length === 1 ? results[0] : results, null, 2));
      process.exit(0);
    }

    if (!shouldRunScan) {
      process.exit(0);
    }

    if (!options.sourceIp) {
      const resolvedReports = results.filter(r => Boolean(r?.realIp));
      if (resolvedReports.length === 1 && results.length === 1) {
        options.sourceIp = resolvedReports[0].realIp;
        if (!options.json) {
          console.log(`📌 Auto-pinned --source-ip ${resolvedReports[0].realIp} for scan.`);
        }
      } else if (resolvedReports.length > 0) {
        const map = {};
        for (const r of resolvedReports) {
          if (r.hostname && r.realIp) map[r.hostname] = r.realIp;
        }
        if (Object.keys(map).length > 0) {
          options.sourceIpMap = map;
          if (!options.json) {
            console.log(`📌 Auto-pinned origin IP map for scan: ${JSON.stringify(map)}`);
          }
        }
      }
    }
  }

  // ── Session Recording Mode (--record-session) ──────────────────────────────
  const shouldRunScanAfterRecord = Boolean(options.scan || (options.checks && options.checks.length > 0));
  if (options.recordSession && !shouldRunScanAfterRecord) {
    const targetUrl = validation.targets[0];
    const authMgr = await buildCliAuthManager(targetUrl, options, loadedSession);
    if (!authMgr || (authMgr.username === null && authMgr.password === null && authMgr.loginPayload === null && !loadedSession)) {
      console.error('❌  --record-session requires --username and --password (or --load-session).');
      process.exit(1);
    }

    const [{ TargetPinStore }, { createGovernedFetch }] = await Promise.all([
      import('../core/guard.js'),
      import('../core/fetch.js'),
    ]);
    const customHeaders = options.headers && typeof options.headers === 'object' ? options.headers : {};
    const authHeaders = options.auth ? { Authorization: options.auth } : {};
    const normalizedScopeRules = options.scopeRules?.length
      ? (await loadNormalizeScopeRules())(options.scopeRules)
      : [];
    const targetPinStore = new TargetPinStore({ allowPrivate });
    const governedFetch = createGovernedFetch({
      ...(normalizedScopeRules.length ? { scopeRules: normalizedScopeRules } : {}),
      ...(options.sourceIp ? { sourceIp: options.sourceIp } : {}),
      ...(options.sourceIpMap ? { sourceIpMap: options.sourceIpMap } : {}),
      enforceDnsValidation: true,
      allowPrivate,
      targetPinStore,
      retries: 2,
      timeout: options.timeout || 10000
    });
    const fetchWithRetry = (url, opts = {}, ...rest) => {
      const safeOpts = opts && typeof opts === 'object' ? opts : {};
      return governedFetch(url, {
        ...safeOpts,
        headers: { ...customHeaders, ...authHeaders, ...(safeOpts.headers || {}) }
      }, ...rest);
    };
    fetchWithRetry.governance = governedFetch.governance;
    fetchWithRetry.tlsAlpnProbe = governedFetch.tlsAlpnProbe;
    fetchWithRetry.sourceIp = governedFetch.sourceIp;
    fetchWithRetry.sourceIpMap = governedFetch.sourceIpMap;
    fetchWithRetry.resolveCache = governedFetch.resolveCache;
    fetchWithRetry.targetPinStore = governedFetch.targetPinStore;
    fetchWithRetry.hasCustomFetcher = governedFetch.hasCustomFetcher;
    if (governedFetch.isDefaultFetch !== undefined) {
      fetchWithRetry.isDefaultFetch = governedFetch.isDefaultFetch;
    }

    try {
      const alreadyAuth = Boolean(authMgr.bearerToken || authMgr.cookies.size > 0);
      if (!alreadyAuth || options.username !== null || options.password !== null) {
        await authMgr.executeLoginMacro(fetchWithRetry);
      }
      const summary = authMgr.getRecordedSession({ includeSecrets: false });
      const savedPath = options.saveSession ? saveRecordedSessionFile(options.saveSession, authMgr) : null;
      if (options.json) {
        console.log(JSON.stringify({
          ...summary,
          ...(savedPath ? { savedTo: savedPath } : {})
        }, null, 2));
      } else {
        printRecordedSessionDetails(summary, savedPath);
      }
      process.exit(summary.authenticated ? 0 : 1);
    } catch (err) {
      if (options.json) {
        console.error(JSON.stringify({ ok: false, target: targetUrl, error: err.message }, null, 2));
      } else {
        console.error(`❌  Session recording failed: ${err.message}`);
      }
      process.exit(1);
    }
  }

  // ── Tech stack detection mode (--detect / --fingerprint) ───────────────────
  if (options.detect) {
    const [
      { getScanners },
      { selectScannersForStack },
      { TargetPinStore },
      { createGovernedFetch },
      { fingerprint },
      llmMod,
      aiAdvisorMod
    ] = await Promise.all([
      import('../core/registry.js'),
      import('../core/profiles.js'),
      import('../core/guard.js'),
      import('../core/fetch.js'),
      import('../core/fingerprint.js'),
      options.aiFix ? import('../core/llmpool.js') : Promise.resolve(null),
      options.aiFix ? import('../core/ai-advisor.js') : Promise.resolve(null),
    ]);
    const scanners = await getScanners();
    const customHeaders = options.headers && typeof options.headers === 'object' ? options.headers : {};
    const authHeaders = options.auth ? { Authorization: options.auth } : {};
    const normalizedScopeRules = options.scopeRules?.length
      ? (await loadNormalizeScopeRules())(options.scopeRules)
      : [];
    const targetPinStore = new TargetPinStore({ allowPrivate });
    const governedFetch = createGovernedFetch({
      ...(normalizedScopeRules.length ? { scopeRules: normalizedScopeRules } : {}),
      ...(options.sourceIp ? { sourceIp: options.sourceIp } : {}),
      ...(options.sourceIpMap ? { sourceIpMap: options.sourceIpMap } : {}),
      enforceDnsValidation: true,
      allowPrivate,
      targetPinStore,
      retries: 2,
      timeout: options.timeout || 10000
    });
    try {
    const baseDetectFetch = (url, opts = {}, ...rest) => governedFetch(url, {
      ...opts,
      headers: { ...customHeaders, ...authHeaders, ...(opts?.headers || {}) }
    }, ...rest);
    baseDetectFetch.governance = governedFetch.governance;
    baseDetectFetch.tlsAlpnProbe = governedFetch.tlsAlpnProbe;
    baseDetectFetch.targetPinStore = governedFetch.targetPinStore;
    baseDetectFetch.resolveCache = governedFetch.resolveCache;
    baseDetectFetch.sourceIp = governedFetch.sourceIp;
    baseDetectFetch.sourceIpMap = governedFetch.sourceIpMap;
    baseDetectFetch.hasCustomFetcher = governedFetch.hasCustomFetcher;
    if (governedFetch.isDefaultFetch !== undefined) {
      baseDetectFetch.isDefaultFetch = governedFetch.isDefaultFetch;
    }
    const authMgr = await buildCliAuthManager(validation.targets[0], options, loadedSession);
    if (authMgr) {
      const alreadyAuth = Boolean(authMgr.bearerToken || authMgr.cookies.size > 0);
      const hasCreds = Boolean(authMgr.loginPayload !== null || (authMgr.username !== null && authMgr.password !== null));
      if (!alreadyAuth && hasCreds) {
        await authMgr.executeLoginMacro(baseDetectFetch);
      }
      if (options.saveSession) {
        saveRecordedSessionFile(options.saveSession, authMgr);
      }
    }
    const fetchWithRetry = authMgr ? authMgr.wrapFetch(baseDetectFetch) : baseDetectFetch;
    if (authMgr) {
      fetchWithRetry.governance = baseDetectFetch.governance;
      fetchWithRetry.tlsAlpnProbe = baseDetectFetch.tlsAlpnProbe;
      fetchWithRetry.targetPinStore = baseDetectFetch.targetPinStore;
      fetchWithRetry.resolveCache = baseDetectFetch.resolveCache;
      fetchWithRetry.sourceIp = baseDetectFetch.sourceIp;
      fetchWithRetry.sourceIpMap = baseDetectFetch.sourceIpMap;
      fetchWithRetry.hasCustomFetcher = baseDetectFetch.hasCustomFetcher;
      if (baseDetectFetch.isDefaultFetch !== undefined) {
        fetchWithRetry.isDefaultFetch = baseDetectFetch.isDefaultFetch;
      }
    }
    const advisorPool = options.aiFix && llmMod ? new llmMod.LlmPool({ autoDiscoverEnv: true }) : null;
    const analyzeApiCommunication = aiAdvisorMod?.analyzeApiCommunication;
    const detectResults = [];

    const bar = '─'.repeat(60);
    if (!options.json) {
      console.log('\n🔍 Tech Stack Detection & Profile Recommendation');
      console.log(bar);
    }

    for (const target of validation.targets) {
      if (!options.json) console.log(`\n📡 Target URL: ${target}`);
      try {
        const preDns = await resolveAndValidateTarget(target, {
          targetPinStore,
          allowPrivate,
          ...(options.sourceIp ? { sourceIp: options.sourceIp } : {})
        });
        if (!preDns.valid) {
          const reason = preDns.reason || preDns.error || 'Target blocked by policy';
          if (options.json) {
            detectResults.push({ target, ok: false, error: reason });
          } else {
            console.error(`  ❌ Target blocked: ${reason}`);
          }
          continue;
        }
        const fp = await fingerprint(target, fetchWithRetry, {
          allowPrivate,
          deviceMode,
          deviceCategory: options.deviceCategory
        });
        const effectiveDetectProfile =
          (!cli.profile || String(options.profile || 'smart').toLowerCase() === 'smart') &&
          fp.deviceInfo?.basePortClosed &&
          (fp.deviceInfo?.detected || deviceMode)
            ? (fp.recommendedProfile || 'device')
            : (options.profile || 'smart');
        const selection = selectScannersForStack(scanners, {
          profile: effectiveDetectProfile,
          fp,
          techOverride: options.techOverride,
          forceAll: options.forceAll
        });
        if (
          fp.deviceInfo?.basePortClosed &&
          (fp.deviceInfo?.detected || deviceMode) &&
          !fp.deviceInfo?.activeHttpOrigin &&
          !fp.deviceInfo?.activeHttpsOrigin
        ) {
          const skippedHttpChecks = selection.activeScanners.filter(s => s.name !== 'device-security');
          if (skippedHttpChecks.length > 0) {
            selection.activeScanners = selection.activeScanners.filter(s => s.name === 'device-security');
            selection.skippedScanners = [...selection.skippedScanners, ...skippedHttpChecks];
          }
        }

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
            deviceMode,
            allowPrivate,
            deviceCategory: options.deviceCategory,
            fingerprint: fp,
            deviceInfo: fp.deviceInfo || null,
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
        if (fp.deviceInfo?.detected) {
          const dp = fp.deviceInfo;
          const devDetails = [
            dp.vendor && dp.vendor !== 'Unknown' ? `Vendor: ${dp.vendor}` : null,
            dp.modelName ? `Model: ${dp.modelName}` : null,
            dp.os ? `OS: ${dp.os}` : null,
            dp.macAddress ? `MAC: ${dp.macAddress}` : null
          ].filter(Boolean).join(' · ');
          console.log(`  📺 Device Category           : ${dp.categoryLabel || dp.category || 'Network Device'}${devDetails ? ` (${devDetails})` : ''}`);
          if (Array.isArray(dp.openPorts) && dp.openPorts.length > 0) {
            console.log(`  🔌 Open Device Ports         : ${dp.openPorts.join(', ')}${dp.basePortClosed ? ' (base port 80/443 closed)' : ''}`);
          }
          const activeOrigins = [dp.activeHttpOrigin, dp.activeHttpsOrigin].filter(Boolean);
          if (activeOrigins.length > 0) {
            console.log(`  🌐 Active Device Origins     : ${activeOrigins.join(', ')}`);
          }
        }

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
            deviceMode,
            allowPrivate,
            deviceCategory: options.deviceCategory,
            fingerprint: single.fingerprint || null,
            deviceInfo: single.deviceInfo || single.fingerprint?.deviceInfo || null,
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
    } finally {
      try {
        governedFetch.destroyAgents?.();
      } catch {}
    }
  } else {
    // ── Run ────────────────────────────────────────────────────────────────────
    const [{ runScanner }, authMgr] = await Promise.all([
      import('../scan.js'),
      buildCliAuthManager(validation.targets[0], options, loadedSession),
    ]);
    await runScanner({
      ...options,
      targets: validation.targets,
      allowPrivate,
      deviceMode,
      deviceCategory: options.deviceCategory,
      oast: Boolean(options.oast),
      ...(options.templates ? { templates: options.templates } : {}),
      ...(authMgr ? { authSession: authMgr } : {})
    })
      .then(() => {
        if (authMgr) {
          if (options.saveSession) {
            const savedPath = saveRecordedSessionFile(options.saveSession, authMgr);
            console.log(`💾  Session saved     → ${savedPath}`);
          }
          if (options.recordSession) {
            printRecordedSessionDetails(authMgr.getRecordedSession({ includeSecrets: false }));
          }
        }
      })
      .catch(e => {
        console.error('Fatal:', e.message);
        process.exitCode = 1;
      });
  }
}
