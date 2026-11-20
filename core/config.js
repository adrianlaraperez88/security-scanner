import fs   from 'fs';
import path  from 'path';

const CONFIG_FILE = '.secscanrc';

/**
 * Loads configuration from .secscanrc in the current working directory.
 * Returns an empty object if the file doesn't exist or can't be parsed.
 *
 * Supported keys:
 *   targets      string[] — default scan targets
 *   concurrency  number   — parallel target limit (default: 5)
 *   timeout      number   — request timeout ms  (default: 10000)
 *   profile      string   — profile name        (default: 'smart')
 *   output       string   — output file stem    (default: 'report')
 *   json         boolean  — always save JSON    (default: false)
 *   html         boolean  — always save HTML    (default: false)
 *   auth         string   — Authorization header value
 *   webhook      string   — webhook URL for notifications
 *   noHistory    boolean  — disable scan history (default: false)
 *   maxDepth     number   — crawl depth for discovery (default: 3)
 *   port         number   — web UI port (default: 4321)
 *   ui           boolean  — start web UI server (default: false)
 *   forceAll     boolean  — force all checks    (default: false)
 *   techOverride string   — override technology stack (default: null)
 *   agent        boolean  — enable agentic loop (default: false)
 *   goal         string   — agent objective     (default: null)
 *   noiseProfile string   — noise governor profile (default: null)
 *   scopeRules   Array    — scope/deny rules    (default: null)
 *   markdown     boolean|string — save Markdown report (default: false)
 *   csv          boolean|string — save CSV report (default: false)
 *   allowPrivate boolean  — allow private/internal targets (default: false)
 */
export function loadConfig() {
  const configPath = path.join(process.cwd(), CONFIG_FILE);

  if (!fs.existsSync(configPath)) return {};

  try {
    const raw = fs.readFileSync(configPath, 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    console.warn(`⚠️  Failed to parse ${CONFIG_FILE}: ${e.message}`);
    return {};
  }
}

/**
 * Merges CLI flags (higher priority) over config file values.
 * CLI values that are the "default" are overridden by config.
 */
export function mergeConfig(cliOptions = {}, config = {}) {
  return {
    targets     : cliOptions.targets?.length ? cliOptions.targets : (config.targets ?? []),
    concurrency : cliOptions.concurrency ?? config.concurrency ?? 5,
    timeout     : cliOptions.timeout     ?? config.timeout     ?? 10000,
    profile     : cliOptions.profile     ?? config.profile     ?? 'smart',
    output      : cliOptions.output      ?? config.output      ?? 'report',
    json        : cliOptions.json        || config.json        || false,
    html        : cliOptions.html        || config.html        || false,
    markdown    : cliOptions.markdown    || config.markdown    || false,
    csv         : cliOptions.csv         || config.csv         || false,
    auth        : cliOptions.auth        ?? config.auth        ?? null,
    webhook     : cliOptions.webhook     ?? config.webhook     ?? null,
    noHistory   : cliOptions.noHistory   || config.noHistory   || false,
    diff        : cliOptions.diff        || false,
    techOverride: cliOptions.techOverride ?? config.techOverride ?? null,
    verify      : cliOptions.verify      || false,
    maxDepth    : cliOptions.maxDepth    ?? config.maxDepth    ?? 3,
    port        : cliOptions.port        ?? config.port        ?? 4321,
    ui          : Boolean(cliOptions.ui  || config.ui),
    detect      : cliOptions.detect      || false,
    forceAll    : cliOptions.forceAll    || config.forceAll    || false,
    agent       : Boolean(cliOptions.agent || config.agent),
    goal        : cliOptions.goal        ?? config.goal        ?? null,
    noiseProfile: cliOptions.noiseProfile ?? config.noiseProfile ?? null,
    scopeRules  : cliOptions.scopeRules?.length ? cliOptions.scopeRules : (config.scopeRules ?? null),
    allowPrivate: Boolean(cliOptions.allowPrivate || config.allowPrivate),
  };
}
