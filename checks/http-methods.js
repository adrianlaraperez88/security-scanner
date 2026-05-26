export const tags = ['all'];

/**
 * Tests whether the server accepts dangerous HTTP methods.
 *
 * TRACE  → enables Cross-Site Tracing (XST) attacks — should always be disabled
 * PUT    → allows file uploads if misconfigured
 * DELETE → allows file removal if misconfigured
 *
 * Also checks OPTIONS response for an Allow header listing dangerous methods.
 */
const DANGEROUS = ['TRACE', 'PUT', 'DELETE'];

export default async function run(target, fetchWithRetry) {
  const findings = [];

  // ── Test each dangerous method directly ──────────────────────────────────
  for (const method of DANGEROUS) {
    try {
      const res = await fetchWithRetry(target, { method });

      if (method === 'TRACE') {
        // TRACE is dangerous if server returns 200 and echoes the request back
        if (res.status === 200 && res.text.toUpperCase().includes('TRACE')) {
          findings.push({ method, severity: 'MEDIUM', issue: 'TRACE enabled — Cross-Site Tracing (XST) vector' });
        }
      }

      if (['PUT', 'DELETE'].includes(method) && res.status < 400) {
        findings.push({
          method,
          severity: 'HIGH',
          issue   : `${method} accepted (HTTP ${res.status}) — possible unauthorized file manipulation`
        });
      }

    } catch { /* connection reset for method — good */ }
  }

  // ── Check OPTIONS for Allow header ────────────────────────────────────────
  try {
    const res   = await fetchWithRetry(target, { method: 'OPTIONS' });
    const allow = (res.headers?.['allow'] || res.headers?.['access-control-allow-methods'] || '').toUpperCase();

    if (allow) {
      const listed = DANGEROUS.filter(m => allow.includes(m));
      if (listed.length > 0) {
        findings.push({
          method  : 'OPTIONS',
          severity: 'LOW',
          issue   : `OPTIONS Allow header lists: ${listed.join(', ')}`,
          allow
        });
      }
    }
  } catch { /* unreachable */ }

  if (findings.length === 0) {
    return { name: 'http methods', status: 'SAFE', severity: 'NONE' };
  }

  const maxSev = findings.some(f => f.severity === 'HIGH')   ? 'HIGH'
               : findings.some(f => f.severity === 'MEDIUM') ? 'MEDIUM'
               : 'LOW';

  return {
    name    : 'http methods',
    status  : 'VULNERABLE',
    severity: maxSev,
    findings,
    fix     : "Disable 'TRACE' and 'TRACK' methods in your web server configuration (e.g., 'TraceEnable off' in Apache). Restrict 'PUT' and 'DELETE' to authorized users or specific API endpoints."
  };
}
