#!/usr/bin/env node

import { runScanner }          from '../scan.js';
import { loadConfig, mergeConfig } from '../core/config.js';
import { listProfiles }        from '../core/profiles.js';
import { URL }                 from 'url';

// ── Parse raw CLI arguments ────────────────────────────────────────────────
const args = process.argv.slice(2);

const cli = {
  targets     : [],
  verify      : false,
  json        : false,
  html        : false,
  diff        : false,
  noHistory   : false,
  concurrency : null,
  techOverride: null,
  output      : null,
  timeout     : null,
  auth        : null,
  profile     : null,
  webhook     : null,
};

for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if      (a === '--verify')      cli.verify     = true;
  else if (a === '--json')        cli.json       = true;
  else if (a === '--html')        cli.html       = true;
  else if (a === '--diff')        cli.diff       = true;
  else if (a === '--no-history')  cli.noHistory  = true;
  else if (a === '--concurrency') cli.concurrency= parseInt(args[++i] || '5',     10);
  else if (a === '--tech')        cli.techOverride= args[++i]?.split(',') || [];
  else if (a === '--output')      cli.output     = args[++i] || null;
  else if (a === '--timeout')     cli.timeout    = parseInt(args[++i] || '10000', 10);
  else if (a === '--auth')        cli.auth       = args[++i] || null;
  else if (a === '--profile')     cli.profile    = args[++i] || null;
  else if (a === '--webhook')     cli.webhook    = args[++i] || null;
  else if (a === '--depth')       cli.maxDepth   = parseInt(args[++i] || '3',     10);
  else if (a === '--profiles')    { console.log('Available profiles:\n' + listProfiles()); process.exit(0); }
  else if (!a.startsWith('--'))   cli.targets.push(a);
}

// ── Load .secscanrc and merge ────────────────────────────────────────────────
const config  = loadConfig();
const options = mergeConfig(cli, config);

// ── Show help if no targets ────────────────────────────────────────────────
if (!options.targets.length) {
  console.log([
    'Usage: secscan <url> [options]',
    '',
    'Options:',
    '  --json              Save JSON report',
    '  --html              Save HTML report (dark-mode, self-contained)',
    '  --output <stem>     Base name for reports (default: report)',
    '  --profile <name>    Scan profile: quick|api|laravel|wordpress|full',
    '  --profiles          List all available profiles',
    '  --depth <n>         Crawl depth for discovery   (default: 3)',
    '  --tech <list>       Force tech tags, comma-separated (e.g. laravel,php)',
    '  --concurrency <n>   Parallel targets            (default: 5)',
    '  --timeout <ms>      Request timeout in ms       (default: 10000)',
    '  --auth <token>      Authorization header value',
    '  --diff              Compare with last scan and show changes',
    '  --no-history        Do not save this scan to history',
    '  --webhook <url>     Send results to Slack/webhook URL',
    '  --verify            Reserved for future use',
    '',
    'Examples:',
    '  secscan https://example.com --html --json',
    '  secscan https://example.com --profile laravel --html',
    '  secscan https://example.com --profile quick',
    '  secscan https://api.example.com --auth "Bearer eyJ..."',
    '  secscan https://example.com --diff',
    '  secscan https://a.com https://b.com --concurrency 3',
    '',
    'Config file: create .secscanrc in your project root to persist options.',
  ].join('\n'));
  process.exit(1);
}

// ── Input validation & SSRF protection ────────────────────────────────────
const PRIVATE_IP = /^(localhost|127\.|0\.0\.0\.0|::1|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/i;
const validated  = [];

for (const t of options.targets) {
  let url;
  try {
    url = new URL(t);
  } catch {
    console.error(`❌  Invalid URL: "${t}"`);
    process.exit(1);
  }

  if (!['http:', 'https:'].includes(url.protocol)) {
    console.error(`❌  Only http/https allowed: "${t}"`);
    process.exit(1);
  }

  if (PRIVATE_IP.test(url.hostname)) {
    console.error(`❌  Private/internal targets blocked: "${t}"`);
    process.exit(1);
  }

  validated.push(t.replace(/\/+$/, ''));   // strip trailing slash
}

// ── Run ────────────────────────────────────────────────────────────────────
runScanner({ ...options, targets: validated })
  .catch(e => {
    console.error('Fatal:', e.message);
    process.exit(1);
  });