/**
 * Shared non-destructive verification helpers for security checks:
 *  - HTML / SPA / JS / CSS catch-all filtering
 *  - Safe JSON parsing for API / manifest checks
 *  - Repeat confirmation probing so non-reproducible hits are not reported
 *  - Verbatim single-line evidence snippet extraction (>= 8 chars for S1 receipts)
 */

/**
 * Case-insensitive header lookup supporting both Fetch Headers and plain objects.
 *
 * @param {object} headers
 * @param {string} name
 * @returns {string}
 */
export function getHeader(headers, name) {
  if (!headers || typeof headers !== 'object') return '';
  const targetLower = String(name || '').toLowerCase();
  if (typeof headers.get === 'function') {
    return String(headers.get(name) ?? headers.get(targetLower) ?? '');
  }
  for (const [k, v] of Object.entries(headers)) {
    if (String(k).toLowerCase() === targetLower && v !== undefined && v !== null) {
      return Array.isArray(v) ? v.join('; ') : String(v);
    }
  }
  return '';
}

/**
 * Returns true if the response is HTML, XHTML, JavaScript, CSS, or an SPA shell.
 * Prevents catch-all 200 HTML fallbacks from triggering file/JSON/API checks.
 *
 * @param {object} res
 * @param {string} [text]
 * @returns {boolean}
 */
export function isHtmlOrScript(res, text) {
  const ct = getHeader(res?.headers, 'content-type').toLowerCase();
  if (
    ct.includes('text/html') ||
    ct.includes('application/xhtml+xml') ||
    ct.includes('javascript') ||
    ct.includes('text/css')
  ) {
    return true;
  }
  const body = typeof text === 'string' ? text : (typeof res?.text === 'string' ? res.text : '');
  const trimmed = body.trimStart();
  if (!trimmed) return false;
  return /^(?:<!doctype\s+html|<html\b|<head\b|<body\b|<app-root\b|<div\s+id=["'](?:root|app|__next)["'])/i.test(trimmed);
}

/**
 * Parses a JSON object or array strictly; returns null on failure or primitive values.
 *
 * @param {string} text
 * @returns {object|Array|null}
 */
export function parseJsonObject(text) {
  if (typeof text !== 'string') return null;
  const trimmed = text.trim();
  if (!trimmed || (trimmed[0] !== '{' && trimmed[0] !== '[')) return null;
  try {
    const parsed = JSON.parse(trimmed);
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}

/**
 * Extracts a short single-line verbatim quote around a matched substring or RegExp.
 * Ensures quotes meet the >= 8 char S1 evidence floor when present in the text.
 *
 * @param {string} text
 * @param {string|RegExp} matcher
 * @param {number} [maxLen=120]
 * @returns {string|null}
 */
export function extractVerbatimSnippet(text, matcher, maxLen = 120) {
  if (typeof text !== 'string' || !text) return null;
  let idx = -1;
  let len = 0;

  if (matcher instanceof RegExp) {
    const m = matcher.exec(text);
    if (!m) return null;
    idx = m.index;
    len = m[0].length;
  } else if (typeof matcher === 'string' && matcher) {
    idx = text.toLowerCase().indexOf(matcher.toLowerCase());
    len = matcher.length;
  }

  if (idx === -1) return null;

  const start = Math.max(0, idx - 24);
  const end = Math.min(text.length, idx + Math.max(len, 16) + 48);
  let slice = text.slice(start, end).replace(/[\r\n\t]+/g, ' ').replace(/\s{2,}/g, ' ').trim();
  if (slice.length > maxLen) {
    slice = slice.slice(0, maxLen).trim();
  }
  return slice || null;
}

/**
 * Returns true if the HTTP response was redirected to a different path or origin than requested
 * (for example, a 302 redirect from /api/user or /.env to /login or /).
 *
 * @param {object} res
 * @param {string} [requestedUrl]
 * @returns {boolean}
 */
export function isRedirectedToDifferentPath(res, requestedUrl) {
  if (!res || typeof res !== 'object') return false;
  const finalUrl = res.finalUrl || res.url;
  if (!finalUrl || typeof finalUrl !== 'string' || !requestedUrl || typeof requestedUrl !== 'string') {
    return Boolean(res.redirected);
  }
  try {
    const reqParsed = new URL(requestedUrl);
    const finParsed = new URL(finalUrl, requestedUrl);
    if (reqParsed.origin !== finParsed.origin) return true;
    const normReq = reqParsed.pathname.replace(/\/+$/, '') || '/';
    const normFin = finParsed.pathname.replace(/\/+$/, '') || '/';
    return normReq !== normFin;
  } catch {
    return Boolean(res.redirected);
  }
}

/**
 * Repeats a check request to verify that the finding is consistently reproducible
 * rather than a transient response, then validates the confirmation response.
 *
 * @param {string} url
 * @param {Function} fetchWithRetry
 * @param {object} [fetchOpts={}]
 * @param {(res: object) => boolean} validator
 * @returns {Promise<{ confirmed: boolean, res: object|null }>}
 */
export async function confirmReproducible(url, fetchWithRetry, fetchOpts, validator) {
  if (typeof fetchWithRetry !== 'function' || typeof validator !== 'function') {
    return { confirmed: false, res: null };
  }
  try {
    const confirmRes = await fetchWithRetry(url, fetchOpts);
    const ok = Boolean(confirmRes && validator(confirmRes));
    return { confirmed: ok, res: confirmRes };
  } catch {
    return { confirmed: false, res: null };
  }
}

const ROUTE_NOT_FOUND_TEXT_RE = /\b(?:the route\s+[^\r\n"']{1,160}\s+could not be found|no route found for\s+["']?(?:get|post|put|delete|patch|head|options)|notfoundhttpexception|methodnotallowedhttpexception|the\s+(?:get|post|put|delete|patch)\s+method is not supported for route|cannot\s+(?:get|post|put|delete)\s+\/[^\s<"{]{1,160})\b/i;

/**
 * Returns true if a response body snippet is a framework routing error
 * (e.g., Laravel "The route _ignition/execute-solution could not be found.",
 * Symfony "No route found for...", Express "Cannot POST /...").
 *
 * @param {string} text
 * @returns {boolean}
 */
export function isFrameworkRouteErrorText(text) {
  if (typeof text !== 'string' || !text) return false;
  const sample = text.slice(0, 4096);
  if (ROUTE_NOT_FOUND_TEXT_RE.test(sample)) return true;
  const json = parseJsonObject(sample);
  if (json && !Array.isArray(json)) {
    const statusField = Number(json.status ?? json.statusCode ?? json.code);
    if (statusField === 404 || statusField === 405 || statusField === 410) return true;
    const msg = String(json.message || json.error || json.detail || '');
    const exc = String(json.exception || '');
    if (ROUTE_NOT_FOUND_TEXT_RE.test(msg) || ROUTE_NOT_FOUND_TEXT_RE.test(exc)) return true;
    if (/^(?:404\s+)?not\s+found\.?$/i.test(msg.trim())) return true;
  }
  return false;
}

/**
 * Returns true if the HTTP response status or body indicates a missing route (404/405/410)
 * or framework route-not-found error payload.
 *
 * @param {object} res
 * @param {string} [text]
 * @returns {boolean}
 */
export function isFrameworkRouteErrorResponse(res, text) {
  if (!res || typeof res !== 'object') return false;
  const st = Number(res.status);
  if (st === 404 || st === 405 || st === 410) return true;
  const body = typeof text === 'string' ? text : (typeof res.text === 'string' ? res.text : '');
  return isFrameworkRouteErrorText(body);
}

const REDIRECT_TESTING_CHECK_IDS = new Set([
  'open-redirect',
  'open redirect',
  'http-redirect',
  'https redirect',
  'cve-spring-framework',
  'cve-nextjs-react',
  'nextjs-checks',
  'nextjs security'
]);

const PASSIVE_ROOT_HEADER_CHECK_IDS = new Set([
  'security-headers',
  'security headers',
  'clickjacking',
  'clickjacking protection',
  'cookie-security',
  'cookie security',
  'cors',
  'cors misconfiguration',
  'ssl-tls',
  'ssl/tls check',
  'server-disclosure',
  'server disclosure',
  'php-version',
  'php version disclosure',
  'rate-limit',
  'rate limiting',
  'sri-supply-chain',
  'sri & supply chain',
  'http-methods',
  'http methods',
  'jwt-security',
  'jwt security',
  'cve-2026-123007',
  'cve-2026-123633',
  'cve-2026-123634',
  'nginx resolver & upstream proxy uaf advisory (cve-2026-123634)',
  'cve-nginx-http3',
  'nginx http/3 security advisories (cve-2026-121810, cve-2026-95101, cve-2026-90439)',
  'cve-nginx-tls',
  'nginx tls 1.3 security advisories (cve-2026-118899, cve-2026-97629, cve-2025-23419)',
  'cve-apache-httpd',
  'cve-tomcat',
  'cve-php-ecosystem',
  'cve-2026-114938',
  'cve-jdk-advisories',
  'jdk & java security advisories (cve-2026-91403, cve-2026-114820, cve-2026-114939, cve-2026-114940, cve-2026-22016, cve-2026-34282, cve-2026-47063, cve-2026-91398, cve-2026-91453)'
]);

function isDjangoDebug404Finding(finding) {
  const hay = `${finding?.name || ''} ${finding?.detail || ''} ${(finding?.evidenceQuotes || []).join(' ')}`.toLowerCase();
  return hay.includes('using the urlconf defined in') || hay.includes('django debug mode');
}

function sameEndpointPathname(urlA, urlB) {
  try {
    const a = new URL(urlA);
    const b = new URL(urlB);
    const pa = a.pathname.replace(/\/+$/, '') || '/';
    const pb = b.pathname.replace(/\/+$/, '') || '/';
    return a.origin === b.origin && pa === pb;
  } catch {
    return false;
  }
}

/**
 * Pre-Report Verification Gate:
 * Validates a VULNERABLE or SUSPICIOUS finding against its captured HTTP traces,
 * sub-file entries, and reproduction metadata before it is emitted to any report.
 * Automatically downgrades false positives caused by HTTP 404/405/410 responses,
 * echoed route-not-found messages, or soft redirects to login/home pages.
 *
 * @param {object} finding
 * @param {{ capturedTraces?: Array<object> }} [options={}]
 * @returns {object}
 */
export function verifyFindingBeforeReport(finding, options = {}) {
  if (!finding || typeof finding !== 'object') return finding;
  const status = String(finding.status || 'SAFE').toUpperCase();
  if (status !== 'VULNERABLE' && status !== 'SUSPICIOUS') return finding;

  if (isDjangoDebug404Finding(finding)) {
    return finding;
  }

  const checkId = String(finding.checkId || finding.meta?.id || finding.name || '').toLowerCase();
  const isRedirectCheck = REDIRECT_TESTING_CHECK_IDS.has(checkId);
  const isPassiveRootCheck = PASSIVE_ROOT_HEADER_CHECK_IDS.has(checkId);
  const traces = Array.isArray(options.capturedTraces) ? options.capturedTraces : [];

  const downgradeToSafe = (reason) => ({
    ...finding,
    status: 'SAFE',
    severity: 'NONE',
    reproVerified: false,
    poeLevel: 0,
    verificationStatus: 'not_assessed',
    detail: reason,
    files: undefined,
    panels: undefined,
    findings: undefined,
    evidenceQuotes: undefined,
    reproduction: undefined
  });

  // 1. Check finding.observedStatus or reproduction.responseStatus
  const reproStatus = Number(finding.reproduction?.responseStatus ?? finding.observedStatus);
  if (reproStatus === 404 || reproStatus === 405 || reproStatus === 410) {
    return downgradeToSafe(`Endpoint returned HTTP ${reproStatus} (not exposed)`);
  }

  // 2. Check evidenceQuotes / observedSignal for framework route-not-found messages
  const quotes = Array.isArray(finding.evidenceQuotes) ? finding.evidenceQuotes : [];
  if (
    quotes.length > 0 &&
    quotes.every(q => isFrameworkRouteErrorText(String(q || '')))
  ) {
    return downgradeToSafe('Response body matched framework route-not-found error message');
  }
  if (
    finding.reproduction?.observedSignal &&
    isFrameworkRouteErrorText(finding.reproduction.observedSignal) &&
    !quotes.length
  ) {
    return downgradeToSafe('Observed signal matched framework route-not-found error message');
  }

  // 3. Validate sub-items in finding.files / finding.panels
  for (const listKey of ['files', 'panels']) {
    if (Array.isArray(finding[listKey]) && finding[listKey].length > 0) {
      const validItems = finding[listKey].filter(item => {
        if (!item || typeof item !== 'object') return false;
        if (isDjangoDebug404Finding(item)) return true;
        const st = Number(item.status);
        if (st === 404 || st === 405 || st === 410) return false;
        if (isFrameworkRouteErrorText(String(item.preview || ''))) return false;
        return true;
      });
      if (validItems.length === 0) {
        return downgradeToSafe(`All probed ${listKey} returned 404/405 or route-not-found error payloads`);
      }
    }
  }

  // 4. Validate against captured HTTP traces for the triggering endpoint
  if (traces.length > 0 && !isPassiveRootCheck) {
    let triggerTrace = null;
    if (finding.trafficId) {
      triggerTrace = traces.find(t => t.trafficId === finding.trafficId) || null;
    }

    const reproUrl = finding.reproduction?.url || finding.url || null;
    const endpointTraces = reproUrl
      ? traces.filter(t => t.url === reproUrl || sameEndpointPathname(t.url, reproUrl))
      : [];

    if (triggerTrace) {
      const st = Number(triggerTrace.status);
      if (st === 404 || st === 405 || st === 410) {
        return downgradeToSafe(`Triggering request returned HTTP ${st}`);
      }
      if (isFrameworkRouteErrorText(triggerTrace.responseSnippet || '')) {
        return downgradeToSafe('Triggering request returned framework route-not-found payload');
      }
      if (
        !isRedirectCheck &&
        triggerTrace.redirected &&
        triggerTrace.url &&
        triggerTrace.finalUrl &&
        !sameEndpointPathname(triggerTrace.url, triggerTrace.finalUrl)
      ) {
        return downgradeToSafe(`Triggering request redirected to a different path (${triggerTrace.finalUrl})`);
      }
    } else if (endpointTraces.length > 0) {
      const allDeadOrNotFound = endpointTraces.every(t => {
        const st = Number(t.status);
        if (st === 404 || st === 405 || st === 410) return true;
        if (isFrameworkRouteErrorText(t.responseSnippet || '')) return true;
        if (
          !isRedirectCheck &&
          t.redirected &&
          t.url &&
          t.finalUrl &&
          !sameEndpointPathname(t.url, t.finalUrl)
        ) {
          return true;
        }
        return false;
      });
      if (allDeadOrNotFound) {
        return downgradeToSafe('Probed endpoint returned HTTP 404/405/route-not-found or redirected on all attempts');
      }
    }
  }

  return finding;
}
