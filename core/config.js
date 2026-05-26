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
 *   profile      string   — profile name        (default: 'full')
 *   output       string   — output file stem    (default: 'report')
 *   json         boolean  — always save JSON    (default: false)
 *   html         boolean  — always save HTML    (default: false)
 *   auth         string   — Authorization header value
 *   webhook      string   — webhook URL for notifications
 *   noHistory    boolean  — disable scan history (default: false)
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
export function mergeConfig(cliOptions, config) {
  return {
    targets     : cliOptions.targets?.length ? cliOptions.targets : (config.targets ?? []),
    concurrency : cliOptions.concurrency ?? config.concurrency ?? 5,
    timeout     : cliOptions.timeout     ?? config.timeout     ?? 10000,
    profile     : cliOptions.profile     ?? config.profile     ?? 'full',
    output      : cliOptions.output      ?? config.output      ?? 'report',
    json        : cliOptions.json        || config.json        || false,
    html        : cliOptions.html        || config.html        || false,
    auth        : cliOptions.auth        ?? config.auth        ?? null,
    webhook     : cliOptions.webhook     ?? config.webhook     ?? null,
    noHistory   : cliOptions.noHistory   || config.noHistory   || false,
    diff        : cliOptions.diff        || false,
    techOverride: cliOptions.techOverride ?? null,
    verify      : cliOptions.verify      || false,
  };
}
