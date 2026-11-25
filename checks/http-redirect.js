import { URL } from 'node:url';
import { fetchWithRetry as defaultFetch } from '../core/fetch.js';

export const tags = ['all'];

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

function hasErrorCode(err, targetCode) {
  const seen = new Set();
  const queue = [err];
  while (queue.length > 0 && seen.size < 12) {
    const node = queue.shift();
    if (!node || typeof node !== 'object' || seen.has(node)) continue;
    seen.add(node);
    if (String(node.code || '').toUpperCase() === targetCode) return true;
    if (node.cause && typeof node.cause === 'object') queue.push(node.cause);
    if (Array.isArray(node.errors)) {
      for (const child of node.errors) {
        if (child && typeof child === 'object') queue.push(child);
      }
    }
  }
  return false;
}

/**
 * Checks whether plain HTTP requests are properly redirected to HTTPS.
 *
 * Uses governed fetchWithRetry with followRedirects: false so we see the raw 3xx
 * response while enforcing SSRF, DNS pinning, scope rules, NoiseGovernor, and TrafficStore.
 */
export default async function run(target, fetchWithRetry = defaultFetch, options = {}) {
  let parsed;
  try {
    parsed = new URL(String(target ?? '').trim());
  } catch {
    return { name: 'https redirect', status: 'ERROR', severity: 'NONE', reason: 'Invalid URL' };
  }

  const siblingSchemes = options?.siblingSchemes instanceof Set
    ? Array.from(options.siblingSchemes)
    : (Array.isArray(options?.siblingSchemes) ? options.siblingSchemes : null);
  const hasSiblingContext = Array.isArray(siblingSchemes) && siblingSchemes.length > 0;
  const hasHttpsSibling = hasSiblingContext && siblingSchemes.some(s => String(s).toLowerCase() === 'https:');
  const hasHttpSibling = hasSiblingContext && siblingSchemes.some(s => String(s).toLowerCase() === 'http:');

  if (parsed.protocol === 'http:') {
    if (!hasHttpsSibling) {
      return { name: 'https redirect', status: 'SAFE', severity: 'NONE', detail: 'Target is already HTTP — HTTPS check skipped' };
    }
  } else if (parsed.protocol !== 'https:') {
    return { name: 'https redirect', status: 'ERROR', severity: 'NONE', reason: `Unsupported protocol: ${parsed.protocol}` };
  }

  const httpTarget = new URL(parsed.toString());
  httpTarget.protocol = 'http:';
  if (parsed.protocol === 'https:' || httpTarget.port === '80') {
    httpTarget.port = '';
  }
  httpTarget.hash = '';
  const httpUrl = httpTarget.toString();

  const fetchFn = typeof fetchWithRetry === 'function' ? fetchWithRetry : defaultFetch;

  try {
    const res = await fetchFn(httpUrl, { followRedirects: false });
    if (res?.isGovernanceBlock) {
      return {
        name: 'https redirect',
        status: 'ERROR',
        severity: 'NONE',
        reason: res.reason || res.error || 'Blocked by governance policy'
      };
    }

    const location = getHeader(res?.headers, 'location').trim();
    const isRedirect = [301, 302, 307, 308].includes(res?.status);
    const trafficField = res?.trafficId !== undefined ? { trafficId: res.trafficId } : {};

    if (isRedirect && location.toLowerCase().startsWith('https://')) {
      const permanent = [301, 308].includes(res.status);
      return {
        name    : 'https redirect',
        status  : 'SAFE',
        severity: 'NONE',
        detail  : `HTTP → HTTPS redirect in place (${res.status}${permanent ? ' permanent' : ' temporary'})`,
        ...trafficField
      };
    }

    if (res?.status === 200) {
      const reqPath = `${httpTarget.pathname || '/'}${httpTarget.search || ''}`;
      return {
        name    : 'https redirect',
        status  : 'VULNERABLE',
        severity: 'MEDIUM',
        path    : reqPath,
        url     : httpUrl,
        detail  : 'HTTP returns 200 (no HTTPS redirect) — plain-text traffic is possible',
        files   : [{
          path         : reqPath,
          url          : httpUrl,
          method       : 'GET',
          status       : 200,
          matchedSignal: 'HTTP 200 without HTTPS redirect',
          reproducible : true
        }],
        fix     : "Implement a permanent (301) redirect from HTTP to HTTPS in your web server configuration to force secure connections.",
        ...trafficField
      };
    }

    if (isRedirect && !location.toLowerCase().startsWith('https://')) {
      const reqPath = `${httpTarget.pathname || '/'}${httpTarget.search || ''}`;
      return {
        name    : 'https redirect',
        status  : 'SUSPICIOUS',
        severity: 'LOW',
        path    : reqPath,
        url     : httpUrl,
        detail  : location
          ? `Redirect destination is not HTTPS: ${location}`
          : 'Redirect response is missing Location header',
        files   : [{
          path         : reqPath,
          url          : httpUrl,
          method       : 'GET',
          status       : res.status,
          matchedSignal: location ? `Location: ${location}` : 'Missing Location header',
          reproducible : true
        }],
        fix     : "Ensure that all HTTP redirects point to the HTTPS version of your site.",
        ...trafficField
      };
    }

    return { name: 'https redirect', status: 'SAFE', severity: 'NONE', ...trafficField };

  } catch (err) {
    if (
      parsed.protocol === 'https:' &&
      (
        hasErrorCode(err, 'ECONNREFUSED') ||
        (hasSiblingContext && !hasHttpSibling && /ECONNREFUSED/i.test(String(err?.message || '')))
      )
    ) {
      return {
        name: 'https redirect',
        status: 'SAFE',
        severity: 'NONE',
        detail: 'Plaintext HTTP port 80 is closed/unreachable; HTTPS-only'
      };
    }
    return {
      name    : 'https redirect',
      status  : 'ERROR',
      severity: 'NONE',
      reason  : err?.message || 'Request failed'
    };
  }
}
