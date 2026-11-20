import { URL } from 'node:url';

export const tags = ['all'];

const GOVERNANCE_ERROR_CODES = new Set([
  'SSRF_POLICY_BLOCKED',
  'TARGET_RULE_BLOCKED',
  'TARGET_OUT_OF_SCOPE',
  'DNS_REBIND_OR_PRIVATE_IP'
]);

function isGovernanceBlockError(err) {
  if (!err) return false;
  if (err.isGovernanceBlock === true) return true;
  if (GOVERNANCE_ERROR_CODES.has(err.code)) return true;
  const msg = typeof err.message === 'string' ? err.message : '';
  return (
    msg.startsWith('Redirect blocked by SSRF policy') ||
    msg.startsWith('Request blocked by SSRF policy') ||
    msg.startsWith('[SECSCAN platform control')
  );
}

function getHeader(headers, name) {
  if (!headers || typeof headers !== 'object') return '';
  const targetLower = String(name).toLowerCase();
  if (typeof headers.get === 'function') {
    return String(headers.get(name) ?? headers.get(targetLower) ?? '');
  }
  for (const [k, v] of Object.entries(headers)) {
    if (String(k).toLowerCase() === targetLower && v !== undefined && v !== null) {
      return Array.isArray(v) ? v.join(', ') : String(v);
    }
  }
  return '';
}

function isHtmlResponse(res, text) {
  const ct = getHeader(res?.headers, 'content-type').toLowerCase();
  if (ct.includes('text/html') || ct.includes('application/xhtml+xml')) return true;
  return /^\s*(?:<!doctype\s+html|<html\b)/i.test(text);
}

/**
 * Tests whether the server accepts dangerous HTTP methods.
 */
const DANGEROUS = ['TRACE', 'PUT', 'DELETE'];

export default async function run(target, fetchWithRetry) {
  let baseUrl;
  try {
    baseUrl = new URL(String(target ?? '').trim());
  } catch {
    return { name: 'http methods', status: 'ERROR', severity: 'NONE', reason: 'Invalid URL' };
  }

  const findings = [];
  let networkSuccess = false;
  let lastError = null;

  // ── Test each dangerous method directly ──────────────────────────────────
  for (const method of DANGEROUS) {
    try {
      const res = await fetchWithRetry(baseUrl.href, { method });
      if (res?.isGovernanceBlock) {
        return {
          name: 'http methods',
          status: 'ERROR',
          severity: 'NONE',
          reason: res.reason || res.error || 'Blocked by governance policy'
        };
      }
      networkSuccess = true;
      const text = typeof res?.text === 'string' ? res.text : '';

      if (method === 'TRACE') {
        if (res?.status === 200 && !isHtmlResponse(res, text) && /\bTRACE\b/i.test(text)) {
          findings.push({
            method,
            path: baseUrl.pathname || '/',
            url: baseUrl.href,
            status: res.status,
            severity: 'MEDIUM',
            issue: 'TRACE enabled — Cross-Site Tracing (XST) vector',
            ...(res?.trafficId !== undefined ? { trafficId: res.trafficId } : {})
          });
        }
      }

      if (['PUT', 'DELETE'].includes(method) && res?.status >= 200 && res?.status < 300 && !isHtmlResponse(res, text)) {
        findings.push({
          method,
          path: baseUrl.pathname || '/',
          url: baseUrl.href,
          status: res.status,
          severity: 'HIGH',
          issue   : `${method} accepted (HTTP ${res.status}) — possible unauthorized file manipulation`,
          ...(res?.trafficId !== undefined ? { trafficId: res.trafficId } : {})
        });
      }
    } catch (err) {
      if (isGovernanceBlockError(err)) {
        return { name: 'http methods', status: 'ERROR', severity: 'NONE', reason: err.message };
      }
      lastError = err;
    }
  }

  // ── Check OPTIONS for Allow header ────────────────────────────────────────
  try {
    const res = await fetchWithRetry(baseUrl.href, { method: 'OPTIONS' });
    if (res?.isGovernanceBlock) {
      return {
        name: 'http methods',
        status: 'ERROR',
        severity: 'NONE',
        reason: res.reason || res.error || 'Blocked by governance policy'
      };
    }
    networkSuccess = true;
    const allow = (
      getHeader(res?.headers, 'allow') ||
      getHeader(res?.headers, 'access-control-allow-methods')
    ).toUpperCase();

    if (allow) {
      const tokens = allow.split(/[^A-Z]+/).filter(Boolean);
      const listed = DANGEROUS.filter(m => tokens.includes(m));
      if (listed.length > 0) {
        findings.push({
          method  : 'OPTIONS',
          path    : baseUrl.pathname || '/',
          url     : baseUrl.href,
          status  : res?.status ?? 200,
          severity: 'LOW',
          issue   : `OPTIONS Allow header lists: ${listed.join(', ')}`,
          allow,
          ...(res?.trafficId !== undefined ? { trafficId: res.trafficId } : {})
        });
      }
    }
  } catch (err) {
    if (isGovernanceBlockError(err)) {
      return { name: 'http methods', status: 'ERROR', severity: 'NONE', reason: err.message };
    }
    lastError = err;
  }

  if (findings.length === 0) {
    if (!networkSuccess) {
      return {
        name: 'http methods',
        status: 'ERROR',
        severity: 'NONE',
        reason: lastError?.message || 'Target unreachable'
      };
    }
    return { name: 'http methods', status: 'SAFE', severity: 'NONE' };
  }

  const maxSev = findings.some(f => f.severity === 'HIGH')   ? 'HIGH'
               : findings.some(f => f.severity === 'MEDIUM') ? 'MEDIUM'
               : 'LOW';
  const primary = findings[0];

  return {
    name    : 'http methods',
    status  : 'VULNERABLE',
    severity: maxSev,
    path    : baseUrl.pathname || '/',
    detail  : findings.map(f => f.issue).join('; '),
    findings,
    ...(primary?.trafficId !== undefined ? { trafficId: primary.trafficId } : {}),
    fix     : "Disable 'TRACE' and 'TRACK' methods in your web server configuration (e.g., 'TraceEnable off' in Apache). Restrict 'PUT' and 'DELETE' to authorized users or specific API endpoints."
  };
}
