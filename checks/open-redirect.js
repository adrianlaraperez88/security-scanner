import { URL } from 'node:url';
import { fetchWithRetry as defaultFetch } from '../core/fetch.js';

export const tags = ['all'];

/**
 * Tests for open redirect vulnerabilities by injecting a hostile URL into
 * common redirect parameters and checking if the server blindly follows it.
 *
 * Uses governed fetchWithRetry with followRedirects: false so we inspect the raw Location header.
 */
const REDIRECT_PARAMS = [
  'redirect', 'url', 'next', 'return', 'return_url',
  'returnUrl', 'callback', 'continue', 'dest', 'destination',
  'go', 'goto', 'target', 'redir', 'redirect_to',
];

const EVIL_HOST = 'evil.attacker.example.com';
const EVIL_URL  = `https://${EVIL_HOST}`;

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

export default async function run(target, fetchWithRetry = defaultFetch) {
  let parsed;
  try {
    parsed = new URL(String(target ?? '').trim());
  } catch {
    return { name: 'open redirect', status: 'ERROR', severity: 'NONE', reason: 'Invalid URL' };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { name: 'open redirect', status: 'ERROR', severity: 'NONE', reason: `Unsupported protocol: ${parsed.protocol}` };
  }

  const fetchFn = typeof fetchWithRetry === 'function' ? fetchWithRetry : defaultFetch;
  let networkSuccess = false;
  let lastError = null;

  for (const param of REDIRECT_PARAMS) {
    const testUrlObj = new URL(parsed.toString());
    testUrlObj.searchParams.set(param, EVIL_URL);
    const testUrl = testUrlObj.toString();

    try {
      const res = await fetchFn(testUrl, { followRedirects: false });
      if (res?.isGovernanceBlock) {
        return {
          name: 'open redirect',
          status: 'ERROR',
          severity: 'NONE',
          reason: res.reason || res.error || 'Blocked by governance policy'
        };
      }

      networkSuccess = true;
      const location   = getHeader(res?.headers, 'location').trim();
      const isRedirect = [301, 302, 303, 307, 308].includes(res?.status);

      if (isRedirect && location) {
        let redirectsToEvil = false;
        try {
          const dest = new URL(location, testUrl);
          const destHost = dest.hostname.toLowerCase();
          redirectsToEvil = destHost === EVIL_HOST || destHost.endsWith(`.${EVIL_HOST}`);
        } catch {
          redirectsToEvil = false;
        }

        if (redirectsToEvil) {
          const path = `${testUrlObj.pathname || '/'}${testUrlObj.search}`;
          const quote = `Location: ${location}`;
          return {
            name          : 'open redirect',
            status        : 'VULNERABLE',
            severity      : 'MEDIUM',
            path,
            url           : testUrl,
            detail        : `?${param}= parameter redirects to arbitrary external URLs (${location})`,
            fix           : "Validate all redirect destinations against a strict whitelist of allowed domains or use a fixed mapping for internal paths only.",
            location,
            files         : [{
              path,
              url          : testUrl,
              method       : 'GET',
              status       : res?.status ?? 302,
              matchedSignal: quote,
              reproducible : true,
              preview      : quote
            }],
            reproVerified : true,
            poeLevel      : quote.length >= 8 ? 3 : 2,
            ...(quote.length >= 8 ? { evidenceQuotes: [quote] } : {}),
            ...(res?.trafficId !== undefined ? { trafficId: res.trafficId } : {})
          };
        }
      }
    } catch (err) {
      if (isGovernanceBlockError(err)) {
        return {
          name    : 'open redirect',
          status  : 'ERROR',
          severity: 'NONE',
          reason  : err.message
        };
      }
      lastError = err;
    }
  }

  if (!networkSuccess) {
    return {
      name    : 'open redirect',
      status  : 'ERROR',
      severity: 'NONE',
      reason  : lastError?.message || 'All requests failed'
    };
  }

  return { name: 'open redirect', status: 'SAFE', severity: 'NONE' };
}
