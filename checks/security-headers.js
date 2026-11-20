import { URL } from 'node:url';
import { getHeader, confirmReproducible } from '../core/check-verify.js';

export const tags = ['all'];

/**
 * Checks for missing security-related HTTP response headers.
 * Confirms reproducibility on the target URL and includes missing/present header details.
 */
const REQUIRED_HEADERS = {
  'strict-transport-security' : 'HSTS (Strict-Transport-Security)',
  'x-content-type-options'    : 'X-Content-Type-Options',
  'x-frame-options'           : 'X-Frame-Options',
  'content-security-policy'   : 'Content-Security-Policy',
  'referrer-policy'           : 'Referrer-Policy',
  'permissions-policy'        : 'Permissions-Policy',
};

function evaluateMissing(headers) {
  const missingKeys = [];
  const missing = [];
  const present = [];

  for (const [key, label] of Object.entries(REQUIRED_HEADERS)) {
    const val = getHeader(headers, key);
    if (!val) {
      missingKeys.push(key);
      missing.push(label);
    } else {
      present.push(`${key}: ${val.slice(0, 80)}`);
    }
  }
  return { missingKeys, missing, present };
}

export default async function run(target, fetchWithRetry) {
  try {
    const res = await fetchWithRetry(target);
    const headers = res?.headers || {};
    const { missingKeys, missing, present } = evaluateMissing(headers);

    if (missing.length === 0) {
      return { name: 'security headers', status: 'SAFE', severity: 'NONE' };
    }

    // Confirm missing headers persist on a verification request
    const { confirmed, res: confirmRes } = await confirmReproducible(
      target,
      fetchWithRetry,
      {},
      (r) => {
        const cHeaders = r?.headers || {};
        return missingKeys.some(k => !getHeader(cHeaders, k));
      }
    );

    if (!confirmed) {
      return { name: 'security headers', status: 'SAFE', severity: 'NONE' };
    }

    const severity = missing.length >= 4 ? 'HIGH' : missing.length >= 2 ? 'MEDIUM' : 'LOW';
    let reqPath = '/';
    try {
      const u = new URL(target);
      reqPath = `${u.pathname || '/'}${u.search || ''}`;
    } catch { /* keep '/' */ }

    const status = confirmRes?.status ?? res?.status ?? 200;
    const trafficId = confirmRes?.trafficId ?? res?.trafficId;
    const summaryQuote = `HTTP ${status} missing headers: ${missing.join(', ')}`.slice(0, 180);
    const evidenceQuotes = [summaryQuote, ...present.slice(0, 3)].filter(q => q.length >= 8);

    return {
      name          : 'security headers',
      status        : 'SUSPICIOUS',
      severity,
      path          : reqPath,
      observedStatus: status,
      missing,
      present,
      detail        : `Confirmed on ${reqPath} (HTTP ${status}): missing ${missing.length} security header(s): ${missing.join(', ')}`,
      files         : [{
        path         : reqPath,
        url          : target,
        method       : 'GET',
        status,
        matchedSignal: `Missing: ${missing.join(', ')}`,
        reproducible : true,
        preview      : summaryQuote
      }],
      reproVerified : true,
      poeLevel      : evidenceQuotes.length > 0 ? 3 : 2,
      ...(evidenceQuotes.length > 0 ? { evidenceQuotes } : {}),
      ...(trafficId !== undefined ? { trafficId } : {}),
      fix           : "Implement the missing security headers in your web server configuration (e.g., in Nginx 'add_header' or Apache 'Header set') to protect against XSS, clickjacking, and mime-type sniffing."
    };

  } catch (e) {
    return { name: 'security headers', status: 'ERROR', severity: 'LOW', reason: e.message };
  }
}
