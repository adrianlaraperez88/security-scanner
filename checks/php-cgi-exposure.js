export const tags = ['php', 'all'];

/**
 * PHP-CGI / PHP-FPM Direct Exposure
 *
 * PHP-FPM and PHP-CGI status/ping endpoints should NEVER be publicly accessible.
 * When misconfigured (wrong Nginx `location` block), they leak:
 *   - /php-status: active workers, request rate, idle processes, memory
 *   - /fpm-ping  : confirms PHP-FPM is directly accessible
 *   - CGI paths  : PHP binary directly invokable (leads to CVE-2024-4577 class attacks)
 *
 * This is a common Nginx/Apache misconfiguration and often the first step
 * in identifying a server's attack surface.
 */

const CHECKS = [
  // ── PHP-FPM endpoints ─────────────────────────────────────────────────────
  {
    path    : '/fpm-ping',
    signals : ['pong'],
    severity: 'HIGH',
    detail  : 'PHP-FPM ping endpoint accessible — FPM exposed directly to internet'
  },
  {
    path    : '/php-fpm-ping',
    signals : ['pong'],
    severity: 'HIGH',
    detail  : 'PHP-FPM ping endpoint accessible at /php-fpm-ping'
  },
  {
    path    : '/php-status',
    signals : ['pool:', 'process manager:', 'idle processes:', 'active processes:'],
    severity: 'HIGH',
    detail  : 'PHP-FPM status page accessible — leaks worker count, request rate, memory usage'
  },
  {
    path    : '/php-fpm-status',
    signals : ['pool:', 'process manager:', 'idle processes:'],
    severity: 'HIGH',
    detail  : 'PHP-FPM status page accessible at /php-fpm-status'
  },

  // ── PHP CGI binary paths ──────────────────────────────────────────────────
  {
    path    : '/cgi-bin/php',
    signals : ['content-type: text/html', 'x-powered-by: php', 'php version'],
    severity: 'HIGH',
    detail  : 'PHP CGI binary directly accessible at /cgi-bin/php — potential CVE-2024-4577 vector'
  },
  {
    path    : '/cgi-bin/php-cgi',
    signals : ['content-type: text/html', 'php'],
    severity: 'HIGH',
    detail  : 'PHP CGI binary directly accessible at /cgi-bin/php-cgi'
  },
  {
    path    : '/php-cgi/php.cgi',
    signals : ['content-type: text/html', 'php'],
    severity: 'HIGH',
    detail  : 'PHP CGI binary accessible at /php-cgi/php.cgi (common XAMPP/Windows path)'
  },
];

export default async function run(target, fetchWithRetry) {
  const found = [];

  for (const check of CHECKS) {
    try {
      const res  = await fetchWithRetry(`${target}${check.path}`);
      const body = res.text.toLowerCase();

      if (res.status !== 200) continue;

      const hasSignal = check.signals.some(s => body.includes(s.toLowerCase()));

      // FPM ping is special — "pong" is only 4 chars but is definitive
      const isFpmPing = check.path.includes('ping') && body.trim() === 'pong';

      if (hasSignal || isFpmPing) {
        found.push({ path: check.path, severity: check.severity, detail: check.detail });
      }

    } catch { /* unreachable */ }
  }

  if (!found.length) {
    return { name: 'php-cgi/fpm exposure', status: 'SAFE', severity: 'NONE' };
  }

  return {
    name    : 'php-cgi/fpm exposure',
    status  : 'VULNERABLE',
    severity: 'HIGH',
    findings: found,
    detail  : `${found.length} PHP-FPM/CGI endpoint(s) publicly accessible`,
    fix     : "Restrict access to '/php-status' and '/fpm-ping' to local or trusted IP addresses in your Nginx/Apache configuration. Remove or strictly protect any CGI binaries in '/cgi-bin/'."
  };
}
