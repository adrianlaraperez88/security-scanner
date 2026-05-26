export const tags = ['php', 'symfony', 'all'];

/**
 * Checks for Symfony framework-specific misconfigurations.
 *
 * Symfony Web Profiler (/_profiler) in production leaks:
 *  - Every HTTP request/response body
 *  - All database queries and timing
 *  - Environment variables and config
 *  - Session data
 *
 * app_dev.php (development front controller) is CRITICAL — it bypasses
 * production config and may expose RCE via Twig template evaluation.
 */
const CHECKS = [
  {
    path    : '/app_dev.php',
    signals : ['symfony', 'debug', '_profiler', 'Environment'],
    severity: 'CRITICAL',
    detail  : 'Symfony dev front controller deployed in production — bypasses security config'
  },
  {
    path    : '/_profiler',
    signals : ['profiler', 'symfony', 'Requests', 'Timeline'],
    severity: 'HIGH',
    detail  : 'Symfony web profiler accessible — leaks all requests, DB queries, env vars, session data'
  },
  {
    path    : '/_profiler/phpinfo',
    signals : ['PHP Version', 'PHP Extension', 'php.ini'],
    severity: 'HIGH',
    detail  : 'Symfony profiler phpinfo page accessible — full PHP configuration exposed'
  },
  {
    path    : '/_wdt',
    signals : ['symfony', 'wdt', 'toolbar', '_token'],
    severity: 'MEDIUM',
    detail  : 'Symfony web debug toolbar endpoint accessible'
  },
  {
    path    : '/app/config/parameters.yml',
    signals : ['database_host', 'database_password', 'secret', 'mailer_'],
    severity: 'CRITICAL',
    detail  : 'Symfony parameters.yml exposed — contains DB credentials and app secret'
  },
];

export default async function run(target, fetchWithRetry) {
  const findings = [];

  for (const check of CHECKS) {
    try {
      const res  = await fetchWithRetry(`${target}${check.path}`);
      const body = res.text.toLowerCase();

      if (res.status === 200 && check.signals.some(s => body.includes(s.toLowerCase()))) {
        findings.push({
          path    : check.path,
          severity: check.severity,
          detail  : check.detail
        });
      }

    } catch { /* path unreachable */ }
  }

  if (!findings.length) {
    return { name: 'symfony misconfiguration', status: 'SAFE', severity: 'NONE' };
  }

  const maxSev = findings.some(f => f.severity === 'CRITICAL') ? 'CRITICAL' : 'HIGH';

  return {
    name    : 'symfony misconfiguration',
    status  : 'VULNERABLE',
    severity: maxSev,
    findings,
    detail  : `${findings.length} Symfony misconfiguration(s) found`,
    fix     : "Set 'APP_DEBUG=0' and 'APP_ENV=prod' in your .env file. Remove 'app_dev.php' from the public directory and ensure the '/_profiler' routes are disabled or restricted to localhost."
  };
}
