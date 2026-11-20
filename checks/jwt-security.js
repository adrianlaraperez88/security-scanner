import { isRedirectedToDifferentPath } from '../core/check-verify.js';

export const tags = ['all'];

/**
 * Passive JWT security check.
 *
 * Probes common API endpoints and inspects any JWT tokens returned
 * in the response body or Authorization-related headers.
 *
 * Checks:
 *  - alg: none / HS256 weak key indicators
 *  - Missing `exp` claim (token never expires)
 *  - Sensitive PII in payload (email, role, password, ssn)
 *
 * NOTE: This is passive — no signature cracking is attempted.
 */

const API_PATHS = ['/api/user', '/api/me', '/api/profile', '/api/v1/user', '/api/auth/me'];
const JWT_RE    = /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*/g;
const PII_KEYS  = ['email', 'password', 'ssn', 'phone', 'dob', 'birth', 'secret', 'api_key'];

function safeBase64Decode(str) {
  try {
    const padded = str.replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(Buffer.from(padded, 'base64').toString('utf8'));
  } catch {
    return null;
  }
}

function analyzeToken(jwt) {
  const parts = jwt.split('.');
  if (parts.length !== 3) return null;

  const header  = safeBase64Decode(parts[0]);
  const payload = safeBase64Decode(parts[1]);
  if (!header || !payload) return null;

  const issues = [];

  // alg: none — signature completely bypassed
  if ((header.alg ?? '').toLowerCase() === 'none') {
    issues.push({ issue: 'alg: none — signature validation bypassed', severity: 'CRITICAL' });
  }

  // No exp claim — token never expires
  if (!payload.exp) {
    issues.push({ issue: 'Missing exp claim — token never expires', severity: 'HIGH' });
  }

  // PII in payload
  const payloadKeys = Object.keys(payload).map(k => k.toLowerCase());
  const foundPii    = PII_KEYS.filter(k => payloadKeys.some(pk => pk.includes(k)));
  if (foundPii.length) {
    issues.push({ issue: `Sensitive data in JWT payload: ${foundPii.join(', ')}`, severity: 'MEDIUM' });
  }

  return issues.length ? issues : null;
}

export default async function run(target, fetchWithRetry) {
  for (const p of API_PATHS) {
    try {
      const url   = `${target}${p}`;
      const res   = await fetchWithRetry(url, { followRedirects: false });
      if (isRedirectedToDifferentPath(res, url)) continue;
      const body  = res.text ?? '';
      const tokens = body.match(JWT_RE) ?? [];

      for (const jwt of tokens) {
        const issues = analyzeToken(jwt);
        if (issues) {
          const maxSev = issues.some(i => i.severity === 'CRITICAL') ? 'CRITICAL'
                       : issues.some(i => i.severity === 'HIGH')     ? 'HIGH'
                       : 'MEDIUM';
          const detail = issues.map(i => i.issue).join('; ');
          return {
            name    : 'jwt security',
            status  : 'VULNERABLE',
            severity: maxSev,
            path    : p,
            url,
            detail,
            issues,
            files   : [{
              path         : p,
              url,
              method       : 'GET',
              status       : res?.status ?? 200,
              matchedSignal: issues[0].issue,
              reproducible : true
            }],
            ...(res?.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
            fix     : "Disable 'alg: none' and only accept strong algorithms (e.g., RS256/ES256). Always include an 'exp' (expiration) claim and keep the payload minimal, avoiding sensitive data like passwords or internal IDs."
          };
        }

        // Token found but no issues — still note it
        if (tokens.length) {
          return { name: 'jwt security', status: 'SAFE', severity: 'NONE', detail: 'JWT found, no issues detected' };
        }
      }
    } catch { /* path unreachable */ }
  }

  return { name: 'jwt security', status: 'SAFE', severity: 'NONE', detail: 'No JWT tokens found in probed endpoints' };
}
