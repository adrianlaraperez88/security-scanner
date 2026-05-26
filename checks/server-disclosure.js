export const tags = ['all'];

/**
 * Flags HTTP response headers that disclose server software versions.
 * Version numbers give attackers a precise CVE lookup target.
 *
 * Safe   → Software name only (e.g. "nginx", "Apache")
 * MEDIUM → Software + version (e.g. "nginx/1.18.0", "PHP/8.1.2")
 */
const VERSION_RE = /\d+\.\d+/;

export default async function run(target, fetchWithRetry) {
  try {
    const res     = await fetchWithRetry(target);
    const headers = res.headers || {};
    const issues  = [];

    // Server: nginx/1.18.0  vs  Server: nginx
    const server = headers['server'] || '';
    if (server) {
      if (VERSION_RE.test(server)) {
        issues.push({ header: 'Server', value: server, severity: 'MEDIUM', detail: 'Version number exposed' });
      }
      // Even without version, server header should ideally be removed
    }

    // X-Powered-By: PHP/8.1.2  →  exposes both technology AND version
    const powered = headers['x-powered-by'] || '';
    if (powered) {
      const severity = VERSION_RE.test(powered) ? 'HIGH' : 'MEDIUM';
      issues.push({ header: 'X-Powered-By', value: powered, severity, detail: 'Technology/version disclosed — remove this header' });
    }

    // X-AspNet-Version: 4.0.30319
    const aspnet = headers['x-aspnetmvc-version'] || headers['x-aspnet-version'] || '';
    if (aspnet) {
      issues.push({ header: 'X-AspNet-Version', value: aspnet, severity: 'MEDIUM', detail: 'ASP.NET version exposed' });
    }

    if (issues.length === 0) {
      return { name: 'server version disclosure', status: 'SAFE', severity: 'NONE' };
    }

    const maxSev = issues.some(i => i.severity === 'HIGH') ? 'HIGH' : 'MEDIUM';

    return {
      name    : 'server version disclosure',
      status  : 'SUSPICIOUS',
      severity: maxSev,
      issues,
      fix     : "Disable server signatures (e.g., 'ServerTokens Prod' in Apache, 'server_tokens off' in Nginx) and remove headers like 'X-Powered-By' to prevent version disclosure."
    };

  } catch (e) {
    return { name: 'server version disclosure', status: 'ERROR', severity: 'LOW', reason: e.message };
  }
}
