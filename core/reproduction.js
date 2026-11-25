import { URL } from 'node:url';
import net from 'node:net';

const SENSITIVE_HEADER_RE = /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-access-token|x-csrf-token)$/i;
const DEFAULT_NOISE_HEADERS = new Set(['user-agent', 'accept-encoding', 'connection', 'host', 'content-length']);
const DEFAULT_SCANNER_ACCEPT_VALUES = new Set(['*/*', 'text/html,application/json,*/*', 'text/html,application/xhtml+xml,*/*;q=0.8']);
const CONTROL_CHAR_RE = /[\u0000-\u001f\u007f]/g;
const MAX_TRACES_PER_CHECK = 200;
const MAX_SNIPPET_LEN = 240;
const MAX_BODY_PREVIEW = 512;
const NON_HTTP_PROTOCOLS = new Set(['rtsp:', 'rtsps:', 'tcp:', 'udp:', 'ssh:', 'rdp:', 'smb:', 'vnc:', 'telnet:', 'ftp:', 'mqtt:']);

function stripControlChars(value) {
  return String(value ?? '').replace(CONTROL_CHAR_RE, ' ').trim();
}

function normalizeHttpUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') return null;
  const cleaned = stripControlChars(rawUrl);
  if (!cleaned) return null;
  try {
    const parsed = new URL(cleaned);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
    if (parsed.username || parsed.password) {
      parsed.username = '';
      parsed.password = '';
    }
    return parsed.href;
  } catch {
    return null;
  }
}

function normalizeNonHttpUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') return null;
  const cleaned = stripControlChars(rawUrl);
  if (!cleaned) return null;
  try {
    const parsed = new URL(cleaned);
    if (!NON_HTTP_PROTOCOLS.has(parsed.protocol)) return null;
    if (!parsed.hostname) return null;
    if (parsed.username || parsed.password) {
      parsed.username = '';
      parsed.password = '';
    }
    return parsed.href;
  } catch {
    return null;
  }
}

function isValidShellHost(rawHost) {
  if (typeof rawHost !== 'string') return false;
  const cleaned = stripControlChars(rawHost).replace(/^\[|\]$/g, '').trim();
  if (!cleaned || cleaned.length > 253) return false;
  if (net.isIP(cleaned) !== 0) return true;
  return /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(cleaned);
}

function parseValidPort(rawPort) {
  if (rawPort === undefined || rawPort === null || typeof rawPort === 'boolean') return null;
  if (typeof rawPort === 'string' && !/^\s*\d+\s*$/.test(rawPort)) return null;
  const n = Number(rawPort);
  return Number.isInteger(n) && n >= 1 && n <= 65535 ? n : null;
}

function parsedUrlHostname(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') return '';
  try {
    const u = new URL(stripControlChars(rawUrl));
    return String(u.hostname || '').replace(/^\[|\]$/g, '');
  } catch {
    return '';
  }
}

function parsedUrlPort(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') return '';
  try {
    const u = new URL(stripControlChars(rawUrl));
    return u.port || '';
  } catch {
    return '';
  }
}

function resolveEndpointUrl(baseTarget, pathOrUrl) {
  const explicit = normalizeHttpUrl(pathOrUrl);
  if (explicit) return explicit;
  const normalizedBase = normalizeHttpUrl(baseTarget);
  if (!normalizedBase) return null;
  if (!pathOrUrl || typeof pathOrUrl !== 'string') return normalizedBase;
  let cleanedPath = stripControlChars(pathOrUrl);
  if (!cleanedPath) return normalizedBase;
  // If pathOrUrl is a comma-joined list of paths (e.g. "/api/user, /api/v1/users"), use the first path token
  if (cleanedPath.includes(',') && /^\s*\/[^,\s]*\s*,/.test(cleanedPath)) {
    cleanedPath = cleanedPath.split(',')[0].trim();
  }
  const explicitFirst = normalizeHttpUrl(cleanedPath);
  if (explicitFirst) return explicitFirst;
  try {
    const resolved = new URL(cleanedPath.startsWith('/') || cleanedPath.startsWith('?') ? cleanedPath : `/${cleanedPath}`, normalizedBase);
    if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') return normalizedBase;
    return resolved.href;
  } catch {
    return normalizedBase;
  }
}

/**
 * Sanitizes HTTP headers for reproduction storage/display by removing control characters,
 * dropping default transport noise headers, and redacting credentials/session tokens.
 *
 * @param {Headers|Map|Array|object|null} headers
 * @param {{ keepDefaults?: boolean }} [opts]
 * @returns {Record<string, string>}
 */
export function sanitizeHeadersForRepro(headers, { keepDefaults = false } = {}) {
  const out = {};
  if (!headers || typeof headers !== 'object') return out;

  const entries = typeof headers.entries === 'function'
    ? Array.from(headers.entries())
    : Array.isArray(headers)
      ? headers
      : Object.entries(headers);

  for (const pair of entries) {
    if (!Array.isArray(pair) || pair.length < 2) continue;
    const rawKey = stripControlChars(pair[0]);
    if (!rawKey) continue;
    const lowerKey = rawKey.toLowerCase();
    if (!keepDefaults && DEFAULT_NOISE_HEADERS.has(lowerKey)) continue;

    const rawVal = Array.isArray(pair[1]) ? pair[1].join(', ') : String(pair[1] ?? '');
    const cleanVal = stripControlChars(rawVal);
    if (!cleanVal) continue;
    if (!keepDefaults && lowerKey === 'accept' && DEFAULT_SCANNER_ACCEPT_VALUES.has(cleanVal.toLowerCase())) {
      continue;
    }

    out[rawKey] = SENSITIVE_HEADER_RE.test(lowerKey) ? '<REDACTED>' : cleanVal;
  }

  return out;
}

/**
 * Safely quotes a string for POSIX/sh single-quoted shell arguments after stripping control chars.
 *
 * @param {string} value
 * @returns {string}
 */
export function shellQuoteSingle(value) {
  const cleaned = stripControlChars(value);
  return `'${cleaned.replace(/'/g, "'\\''")}'`;
}

/**
 * Builds a copy-pasteable, shell-safe `curl` reproduction command from sanitized request parts.
 * Returns `null` when URL is not a valid HTTP/HTTPS URL.
 *
 * @param {object} [params]
 * @returns {string|null}
 */
export function buildCurlCommand({
  method = 'GET',
  url = '',
  headers = {},
  body = null,
  http2 = false,
  http3 = false,
  tlsv13 = false,
  sourceIp = null,
  resolvedIp = null,
  includeResolveFlag = false
} = {}) {
  const safeUrl = normalizeHttpUrl(url);
  if (!safeUrl) return null;

  const cleanMethod = String(method || 'GET').toUpperCase().replace(/[^A-Z]/g, '') || 'GET';
  const parts = ['curl', '-i', '-sS'];
  if (http3) {
    parts.push('--http3');
  } else if (http2) {
    parts.push('--http2');
  }
  if (tlsv13 && safeUrl.startsWith('https://')) {
    parts.push('--tlsv1.3');
  }

  const effectivePinIp = stripControlChars(sourceIp || (includeResolveFlag ? resolvedIp : '') || '')
    .replace(/^\[|\]$/g, '');
  if (effectivePinIp && /^[0-9a-fA-F:.]+$/.test(effectivePinIp)) {
    try {
      const parsed = new URL(safeUrl);
      const cleanHost = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
      const isLiteralIpHost = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(cleanHost) || cleanHost.includes(':');
      if (cleanHost && !isLiteralIpHost) {
        const port = parsed.port || (parsed.protocol === 'https:' ? '443' : '80');
        parts.push('--resolve', shellQuoteSingle(`${cleanHost}:${port}:${effectivePinIp}`));
      }
    } catch {
      // ignore invalid URL parse
    }
  }

  if (cleanMethod !== 'GET') {
    parts.push('-X', cleanMethod);
  }

  const sanitizedHeaders = sanitizeHeadersForRepro(headers);
  for (const [k, v] of Object.entries(sanitizedHeaders)) {
    parts.push('-H', shellQuoteSingle(`${k}: ${v}`));
  }

  if (body !== null && body !== undefined && cleanMethod !== 'GET' && cleanMethod !== 'HEAD') {
    const bodyStr = stripControlChars(typeof body === 'string' ? body : JSON.stringify(body)).slice(0, MAX_BODY_PREVIEW);
    if (bodyStr) {
      parts.push('--data-raw', shellQuoteSingle(bodyStr));
    }
  }

  parts.push(shellQuoteSingle(safeUrl));
  return parts.join(' ');
}

function summarizeObservedSignal(finding, trace) {
  const parts = [];
  if (Number.isFinite(trace?.status) && trace.status > 0) {
    parts.push(`HTTP ${trace.status}`);
  }
  if (finding?.evidence?.quote) {
    parts.push(`matched ${JSON.stringify(stripControlChars(finding.evidence.quote).slice(0, 140))}`);
  } else if (finding?.detail) {
    parts.push(stripControlChars(finding.detail).slice(0, 200));
  } else if (Array.isArray(finding?.findings) && finding.findings.length > 0) {
    const first = finding.findings[0];
    const msg = first?.issue || first?.reason || first?.detail || first?.matchedSignal || first?.name || first?.parameter || '';
    if (msg) parts.push(stripControlChars(msg).slice(0, 200));
  } else if (Array.isArray(finding?.files) && finding.files.length > 0) {
    const first = finding.files[0];
    const msg = first?.matchedSignal || first?.detail || first?.reason || first?.issue || first?.preview || first?.path || '';
    if (msg) parts.push(stripControlChars(msg).slice(0, 200));
  } else if (Array.isArray(finding?.panels) && finding.panels.length > 0) {
    const first = finding.panels[0];
    const msg = first?.matchedSignal || first?.detail || first?.preview || first?.path || '';
    if (msg) parts.push(stripControlChars(msg).slice(0, 200));
  } else if (Array.isArray(finding?.issues) && finding.issues.length > 0) {
    const issueStrings = finding.issues
      .map(i => (typeof i === 'string' ? i : (i?.issue || i?.detail || i?.reason || i?.name || '')))
      .filter(Boolean);
    if (issueStrings.length > 0) {
      parts.push(stripControlChars(issueStrings.slice(0, 3).join('; ')).slice(0, 200));
    }
  } else if (Array.isArray(finding?.missing) && finding.missing.length > 0) {
    const missingNames = finding.missing
      .map(m => (typeof m === 'string' ? m : (m?.header || m?.name || '')))
      .filter(Boolean);
    if (missingNames.length > 0) {
      parts.push(stripControlChars(`Missing security header(s): ${missingNames.join(', ')}`).slice(0, 200));
    }
  } else if (Array.isArray(finding?.evidenceQuotes) && finding.evidenceQuotes.length > 0) {
    parts.push(`matched ${JSON.stringify(stripControlChars(finding.evidenceQuotes[0]).slice(0, 140))}`);
  } else if (finding?.reason) {
    parts.push(stripControlChars(finding.reason).slice(0, 200));
  } else if (trace?.responseSnippet) {
    parts.push(trace.responseSnippet.slice(0, 160));
  }
  return parts.join(' — ') || 'Check condition matched target response';
}

function inferPayloadHint(finding, trace, url) {
  if (finding?.evidence?.payload) return stripControlChars(finding.evidence.payload).slice(0, 200);
  if (Array.isArray(finding?.findings) && finding.findings.length > 0) {
    const first = finding.findings[0];
    if (first?.payload) return stripControlChars(first.payload).slice(0, 200);
    if (first?.parameter) return `parameter=${stripControlChars(first.parameter)}`;
  }
  if (trace?.bodyPreview) return trace.bodyPreview.slice(0, 200);
  const headers = trace?.headers || {};
  for (const [k, v] of Object.entries(headers)) {
    if (!DEFAULT_NOISE_HEADERS.has(k.toLowerCase()) && v !== '<REDACTED>') {
      return `Header ${k}: ${v}`.slice(0, 200);
    }
  }
  try {
    const u = new URL(url);
    if (u.search && u.search.length > 1) return `Query ${u.search.slice(0, 200)}`;
  } catch {
    // ignore
  }
  return null;
}

/**
 * Wraps `fetchWithRetry` during a single check execution to capture sanitized HTTP traces
 * while preserving `.governance`, `.tlsAlpnProbe`, `.governor`, and `.trafficStore`.
 *
 * @param {Function} baseFetch
 * @returns {Function & { getTraces: () => Array<object> }}
 */
export function createTrackedFetch(baseFetch) {
  const traces = [];

  const trackedFetch = async function trackedFetch(url, opts = {}, ...rest) {
    const safeOpts = opts && typeof opts === 'object' ? opts : {};
    const reqMethod = String(safeOpts.method || 'GET').toUpperCase();
    const reqHeaders = sanitizeHeadersForRepro(safeOpts.headers);
    const bodyPreview = (safeOpts.body !== undefined && safeOpts.body !== null)
      ? stripControlChars(typeof safeOpts.body === 'string' ? safeOpts.body : JSON.stringify(safeOpts.body)).slice(0, MAX_BODY_PREVIEW)
      : null;

    let res;
    try {
      res = await baseFetch(url, opts, ...rest);
    } catch (err) {
      if (traces.length < MAX_TRACES_PER_CHECK) {
        traces.push({
          method: reqMethod,
          url: normalizeHttpUrl(url) || stripControlChars(url),
          headers: reqHeaders,
          bodyPreview,
          status: null,
          error: stripControlChars(err?.message || 'Request failed').slice(0, 160),
          responseSnippet: '',
          trafficId: null
        });
      }
      throw err;
    }

    if (traces.length < MAX_TRACES_PER_CHECK) {
      const text = typeof res?.text === 'string' ? res.text : '';
      const reqUrl = normalizeHttpUrl(url) || stripControlChars(url);
      const finalUrl = normalizeHttpUrl(res?.finalUrl || res?.url) || reqUrl;
      traces.push({
        method: reqMethod,
        url: reqUrl,
        finalUrl,
        redirected: Boolean(res?.redirected || (finalUrl && reqUrl && finalUrl !== reqUrl)),
        headers: reqHeaders,
        bodyPreview,
        status: Number.isFinite(Number(res?.status)) ? Number(res.status) : null,
        responseSnippet: stripControlChars(text).slice(0, MAX_SNIPPET_LEN),
        trafficId: res?.trafficId || null,
        ...(res?.resolvedIp ? { resolvedIp: stripControlChars(res.resolvedIp) } : {}),
        ...(res?.sourceIp ? { sourceIp: stripControlChars(res.sourceIp) } : {}),
        ...(res?.dialedAddress ? { dialedAddress: stripControlChars(res.dialedAddress) } : {})
      });
    }

    return res;
  };

  for (const prop of [
    'governance',
    'tlsAlpnProbe',
    'governor',
    'guard',
    'trafficStore',
    'targetPinStore',
    'resolveCache',
    'sourceIp',
    'sourceIpMap',
    'hasCustomFetcher',
    'isDefaultFetch'
  ]) {
    if (baseFetch && baseFetch[prop] !== undefined) {
      trackedFetch[prop] = baseFetch[prop];
    }
  }
  trackedFetch.getTraces = () => traces.slice();

  return trackedFetch;
}

/**
 * Selects the most likely triggering HTTP trace from a check's captured requests.
 *
 * @param {Array<object>} traces
 * @param {object} [finding={}]
 * @returns {object|null}
 */
export function selectTriggerTrace(traces = [], finding = {}) {
  if (!Array.isArray(traces) || traces.length === 0) return null;

  if (finding?.trafficId) {
    const byTrafficId = traces.find(t => t.trafficId === finding.trafficId);
    if (byTrafficId) return byTrafficId;
  }

  const preferredTargets = [];
  const baseForResolve = finding?.target || (Array.isArray(finding?.pages) ? finding.pages[0] : '') || '';
  const explicitFindingUrl = finding?.url ? normalizeHttpUrl(finding.url) : null;
  if (explicitFindingUrl && explicitFindingUrl !== normalizeHttpUrl(baseForResolve)) {
    preferredTargets.push(explicitFindingUrl);
  }
  const baseForPathResolve = explicitFindingUrl || baseForResolve;
  if (finding?.evidence?.requestUrl) preferredTargets.push(String(finding.evidence.requestUrl));
  for (const listKey of ['files', 'findings', 'panels']) {
    if (Array.isArray(finding?.[listKey])) {
      for (const item of finding[listKey]) {
        const itemPath = item?.path || item?.endpoint;
        const itemTarget = item?.url || (baseForPathResolve && itemPath ? resolveEndpointUrl(baseForPathResolve, itemPath) : null);
        if (itemTarget) preferredTargets.push(itemTarget);
      }
    }
  }
  if (Array.isArray(finding?.issues)) {
    for (const iss of finding.issues) {
      if (iss && typeof iss === 'object') {
        const issPath = iss.path || iss.endpoint;
        const issTarget = iss.url || (baseForPathResolve && issPath ? resolveEndpointUrl(baseForPathResolve, issPath) : null);
        if (issTarget) preferredTargets.push(issTarget);
      }
    }
  }
  if (Array.isArray(finding?.paths) && baseForPathResolve) {
    for (const p of finding.paths) {
      if (typeof p === 'string' && p) {
        const resolved = resolveEndpointUrl(baseForPathResolve, p);
        if (resolved) preferredTargets.push(resolved);
      }
    }
  }
  if (finding?.path && baseForPathResolve) {
    const resolved = resolveEndpointUrl(baseForPathResolve, finding.path);
    if (resolved) preferredTargets.push(resolved);
  }

  const checkId = String(finding?.checkId || finding?.meta?.id || finding?.name || '').toLowerCase();
  const subItems = [
    ...(Array.isArray(finding?.files) ? finding.files : []),
    ...(Array.isArray(finding?.findings) ? finding.findings : []),
    ...(Array.isArray(finding?.issues) ? finding.issues : [])
  ].filter(item => item && typeof item === 'object');
  const hasAny404SubItem = subItems.some(item => Number(item.status) === 404);
  const findingExpects404 =
    Number(finding?.observedStatus) === 404 ||
    (checkId === 'device-security' && hasAny404SubItem);

  const preferredOrigins = new Set();
  for (const pref of preferredTargets) {
    let prefParsed = null;
    try {
      prefParsed = new URL(pref);
      preferredOrigins.add(prefParsed.origin);
    } catch {
      prefParsed = null;
    }

    const prefSubItem = subItems.find(
      item =>
        (item.url && item.url === pref) ||
        (item.path && pref.endsWith(String(item.path)))
    );
    const allow404ForPref =
      Number(finding?.observedStatus) === 404 ||
      Number(prefSubItem?.status) === 404 ||
      (checkId === 'device-security' && hasAny404SubItem);

    const findMatchingTrace = (allow404) => {
      const statusOk = (t) => allow404 || t.status !== 404;
      const exact = traces.find(t => t.url === pref && statusOk(t));
      if (exact) return exact;
      if (!prefParsed) return null;

      const prefOrigin = prefParsed.origin;
      const prefPath = prefParsed.pathname;
      const prefSearch = prefParsed.search;
      if (prefSearch) {
        const byPathAndSearch = traces.find(t => {
          try {
            const tu = new URL(t.url);
            return tu.origin === prefOrigin && tu.pathname === prefPath && tu.search === prefSearch && statusOk(t);
          } catch {
            return false;
          }
        });
        if (byPathAndSearch) return byPathAndSearch;
      }
      const byPath = traces.find(t => {
        try {
          const tu = new URL(t.url);
          return tu.origin === prefOrigin && tu.pathname === prefPath && statusOk(t);
        } catch {
          return false;
        }
      });
      return byPath || null;
    };

    const matched = findMatchingTrace(false) || (allow404ForPref ? findMatchingTrace(true) : null);
    if (matched) return matched;
  }

  const fallbackTraces = preferredOrigins.size > 0
    ? traces.filter(t => {
        try {
          return preferredOrigins.has(new URL(t.url).origin);
        } catch {
          return false;
        }
      })
    : traces;
  if (fallbackTraces.length === 0) return null;

  const isTriggerCandidate = (t) => {
    const hasProbeHeaders = t.headers && Object.keys(t.headers).some(k => !DEFAULT_NOISE_HEADERS.has(k.toLowerCase()));
    const nonGet = t.method && t.method !== 'GET' && t.method !== 'HEAD';
    const goodStatus = Number.isFinite(t.status) && t.status !== 404;
    return goodStatus && (hasProbeHeaders || nonGet || Boolean(t.bodyPreview));
  };

  const probeHit = fallbackTraces.find(isTriggerCandidate);
  if (probeHit) return probeHit;

  const status2xx3xx = fallbackTraces.find(t => Number.isFinite(t.status) && t.status >= 200 && t.status < 400);
  if (status2xx3xx) return status2xx3xx;

  if (findingExpects404) {
    const exact404 = fallbackTraces.find(t => Number.isFinite(t.status) && t.status === 404);
    if (exact404) return exact404;
  }

  const non404 = fallbackTraces.find(t => Number.isFinite(t.status) && t.status !== 404);
  return non404 || fallbackTraces[fallbackTraces.length - 1] || null;
}

/**
 * Builds structured, secret-safe reproduction & post-fix verification context for a finding.
 * Returns `null` for `SAFE` findings (or non-object inputs).
 *
 * @param {object} finding
 * @param {{ capturedTraces?: Array<object> }} [options={}]
 * @returns {object|null}
 */
export function buildReproductionContext(finding, options = {}) {
  if (!finding || typeof finding !== 'object') return null;

  const status = String(finding.status || 'SAFE').toUpperCase();
  if (status === 'SAFE') return null;

  const custom = finding.reproduction && typeof finding.reproduction === 'object'
    ? finding.reproduction
    : null;

  const checkId = String(finding.checkId || finding.meta?.id || finding.name || 'security-check').toLowerCase();
  const capturedTraces = Array.isArray(options.capturedTraces) ? options.capturedTraces : [];

  const subItems = [
    ...(Array.isArray(finding.files) ? finding.files : []),
    ...(Array.isArray(finding.findings) ? finding.findings : []),
    ...(Array.isArray(finding.issues) ? finding.issues : [])
  ].filter(item => item && typeof item === 'object');

  const matchingSubItem =
    subItems.find(item => (finding.url && item.url === finding.url) || (finding.path && item.path === finding.path)) ||
    subItems[0] ||
    null;

  const rawExplicitMethod = String(
    custom?.method ||
    finding.method ||
    finding.evidence?.requestMethod ||
    matchingSubItem?.method ||
    ''
  ).toUpperCase().replace(/[^A-Z]/g, '');

  const explicitNonHttpUrl =
    normalizeNonHttpUrl(custom?.url) ||
    normalizeNonHttpUrl(finding.url) ||
    normalizeNonHttpUrl(matchingSubItem?.url) ||
    normalizeNonHttpUrl(finding.target);

  const isRtsp = rawExplicitMethod === 'RTSP' || /^rtsps?:\/\//i.test(explicitNonHttpUrl || '');
  const isPortExposedItem = Boolean(
    checkId === 'device-security' &&
    matchingSubItem &&
    String(matchingSubItem.method || '').toUpperCase() === 'TCP'
  );
  const isTcp = !isRtsp && (
    rawExplicitMethod === 'TCP' ||
    rawExplicitMethod === 'UDP' ||
    /^(?:tcp|udp):\/\//i.test(explicitNonHttpUrl || '') ||
    /^:\d{1,5}$/.test(String(finding.path || '').trim()) ||
    (matchingSubItem && /^:\d{1,5}$/.test(String(matchingSubItem.path || '').trim())) ||
    isPortExposedItem
  );
  const isOtherNonHttp = !isRtsp && !isTcp && Boolean(explicitNonHttpUrl);
  const isNonHttpMode = isRtsp || isTcp || isOtherNonHttp;

  const triggerTrace = isNonHttpMode
    ? (finding?.trafficId ? capturedTraces.find(t => t.trafficId === finding.trafficId) || null : null)
    : selectTriggerTrace(capturedTraces, finding);

  let defaultMethod = 'GET';
  const defaultHeaders = {};
  let useHttp2 = false;
  let useHttp3 = false;
  let useTls13 = false;

  if (checkId === 'cors' || checkId.includes('cors')) {
    defaultHeaders.Origin = 'https://evil.attacker.example.com';
  } else if (checkId === 'http-methods' || checkId === 'http methods') {
    const firstMethod = Array.isArray(finding.findings) && finding.findings[0]?.method;
    if (firstMethod && firstMethod !== 'OPTIONS') {
      defaultMethod = String(firstMethod).toUpperCase();
    } else if (firstMethod === 'OPTIONS') {
      defaultMethod = 'OPTIONS';
    } else if (/TRACE/i.test(String(finding.detail || ''))) {
      defaultMethod = 'TRACE';
    } else if (/PUT/i.test(String(finding.detail || ''))) {
      defaultMethod = 'PUT';
    } else if (/DELETE/i.test(String(finding.detail || ''))) {
      defaultMethod = 'DELETE';
    }
  } else if (checkId === 'cve-2026-123007' || checkId === 'cve-2026-123633') {
    useHttp2 = true;
  } else if (checkId === 'cve-nginx-http3' || checkId.includes('nginx http/3')) {
    useHttp3 = true;
  } else if (checkId === 'cve-nginx-tls' || checkId.includes('nginx tls')) {
    useTls13 = true;
  }

  const subFindingUrl = Array.isArray(finding.findings)
    ? (finding.findings.find(f => typeof f?.url === 'string' && f.url)?.url ||
       finding.findings.find(f => typeof f?.path === 'string' && f.path)?.path ||
       finding.findings.find(f => typeof f?.endpoint === 'string' && f.endpoint)?.endpoint)
    : null;
  const subFileUrl = Array.isArray(finding.files)
    ? (finding.files.find(f => typeof f?.url === 'string' && f.url)?.url ||
       finding.files.find(f => typeof f?.path === 'string' && f.path)?.path)
    : null;
  const subPanelUrl = Array.isArray(finding.panels)
    ? (finding.panels.find(f => typeof f?.url === 'string' && f.url)?.url ||
       finding.panels.find(f => typeof f?.path === 'string' && f.path)?.path)
    : null;
  const subIssueUrl = Array.isArray(finding.issues)
    ? (finding.issues.find(i => typeof i?.url === 'string' && i.url)?.url ||
       finding.issues.find(i => typeof i?.path === 'string' && i.path)?.path ||
       finding.issues.find(i => typeof i?.endpoint === 'string' && i.endpoint)?.endpoint)
    : null;
  const subPathEntry = Array.isArray(finding.paths) && typeof finding.paths[0] === 'string'
    ? finding.paths[0]
    : null;
  const pageFallback = Array.isArray(finding.pages) && finding.pages[0] ? finding.pages[0] : finding.target;
  const fallbackUrl = resolveEndpointUrl(
    pageFallback || finding.url || '',
    subFindingUrl || subFileUrl || subPanelUrl || subIssueUrl || subPathEntry || finding.evidence?.requestUrl || finding.path || ''
  );

  let method = String(
    custom?.method ||
    triggerTrace?.method ||
    finding.evidence?.requestMethod ||
    (isTcp ? (rawExplicitMethod === 'UDP' ? 'UDP' : 'TCP') : isRtsp ? (rawExplicitMethod === 'DESCRIBE' ? 'DESCRIBE' : 'OPTIONS') : defaultMethod)
  ).toUpperCase().replace(/[^A-Z]/g, '') || 'GET';

  let url =
    normalizeHttpUrl(custom?.url) ||
    normalizeHttpUrl(triggerTrace?.url) ||
    fallbackUrl;

  const requestHeaders = sanitizeHeadersForRepro({
    ...defaultHeaders,
    ...(triggerTrace?.headers || {}),
    ...(custom?.requestHeaders || custom?.headers || {})
  });

  const body = custom?.body ?? triggerTrace?.bodyPreview ?? null;
  const responseStatus = isNonHttpMode
    ? (Number.isFinite(Number(custom?.responseStatus ?? triggerTrace?.status))
        ? Number(custom?.responseStatus ?? triggerTrace?.status)
        : null)
    : (Number.isFinite(Number(custom?.responseStatus ?? triggerTrace?.status))
        ? Number(custom?.responseStatus ?? triggerTrace?.status)
        : null);

  const observedSignal = stripControlChars(
    custom?.observedSignal || summarizeObservedSignal(finding, triggerTrace)
  );
  const payload = custom?.payload !== undefined
    ? (custom.payload ? stripControlChars(custom.payload) : null)
    : inferPayloadHint(finding, { headers: requestHeaders, bodyPreview: body }, url);

  const sourceIp = stripControlChars(
    custom?.sourceIp ||
    finding.sourceIp ||
    triggerTrace?.sourceIp ||
    ''
  ) || null;
  const resolvedIp = stripControlChars(
    custom?.resolvedIp ||
    finding.resolvedIp ||
    triggerTrace?.resolvedIp ||
    ''
  ) || null;
  const dialedAddress = stripControlChars(
    custom?.dialedAddress ||
    finding.dialedAddress ||
    triggerTrace?.dialedAddress ||
    ''
  ) || null;
  const includeResolveFlag = Boolean(
    sourceIp ||
    custom?.includeResolveFlag ||
    finding.includeResolveFlag ||
    checkId === 'origin-source-ip'
  );

  let nonHttpHost = '';
  let nonHttpPort = null;
  let curl = null;
  let rtspRequestMethod = 'OPTIONS';

  if (isRtsp) {
    method = rawExplicitMethod === 'RTSP' ? 'RTSP' : (rawExplicitMethod === 'DESCRIBE' ? 'DESCRIBE' : 'OPTIONS');
    rtspRequestMethod = method === 'DESCRIBE' ? 'DESCRIBE' : 'OPTIONS';
    const rawHostSource = (finding.host !== undefined && finding.host !== null && String(finding.host).trim() !== '')
      ? String(finding.host)
      : (parsedUrlHostname(explicitNonHttpUrl) || finding.device?.host || parsedUrlHostname(finding.url) || parsedUrlHostname(finding.target) || '');
    const cleanHost = stripControlChars(rawHostSource).replace(/^\[|\]$/g, '').trim();
    const hostOk = isValidShellHost(cleanHost);
    const pathPortMatch = String(finding.path || matchingSubItem?.path || '').trim().match(/^:(\d{1,5})$/);
    const portCandidate =
      finding.port ??
      matchingSubItem?.port ??
      (explicitNonHttpUrl ? (parsedUrlPort(explicitNonHttpUrl) || (/^rtsps:\/\//i.test(explicitNonHttpUrl) ? 322 : 554)) : null) ??
      (parsedUrlPort(finding.url) || (pathPortMatch ? pathPortMatch[1] : null) || 554);
    const portOk = parseValidPort(portCandidate);
    nonHttpHost = cleanHost;
    nonHttpPort = portOk;

    let rtspUrl = explicitNonHttpUrl;
    if (!rtspUrl && hostOk && portOk) {
      const formattedHost = cleanHost.includes(':') ? `[${cleanHost}]` : cleanHost;
      rtspUrl = `rtsp://${formattedHost}:${portOk}/`;
    }
    url = rtspUrl || null;
    curl = (rtspUrl && hostOk)
      ? (custom?.curl && typeof custom.curl === 'string'
          ? stripControlChars(custom.curl)
          : `curl -i -sS --request ${rtspRequestMethod} ${shellQuoteSingle(rtspUrl)}`)
      : null;
  } else if (isTcp || isOtherNonHttp) {
    if (isTcp) {
      method = rawExplicitMethod === 'UDP' ? 'UDP' : 'TCP';
    } else {
      method = rawExplicitMethod || 'TCP';
    }
    const rawHostSource = (finding.host !== undefined && finding.host !== null && String(finding.host).trim() !== '')
      ? String(finding.host)
      : (finding.device?.host
          ? String(finding.device.host)
          : (parsedUrlHostname(explicitNonHttpUrl) ||
             parsedUrlHostname(finding.url) ||
             parsedUrlHostname(matchingSubItem?.url) ||
             parsedUrlHostname(finding.target) ||
             ''));
    const cleanHost = stripControlChars(rawHostSource).replace(/^\[|\]$/g, '').trim();
    const hostOk = isValidShellHost(cleanHost);
    const pathPortMatch = String(finding.path || matchingSubItem?.path || '').trim().match(/^:(\d{1,5})$/);
    const rawPortSource =
      finding.port !== undefined && finding.port !== null && finding.port !== ''
        ? finding.port
        : (matchingSubItem?.port !== undefined && matchingSubItem?.port !== null && matchingSubItem?.port !== ''
            ? matchingSubItem.port
            : ((explicitNonHttpUrl && parsedUrlPort(explicitNonHttpUrl)) ||
               parsedUrlPort(finding.url) ||
               parsedUrlPort(matchingSubItem?.url) ||
               (pathPortMatch ? pathPortMatch[1] : null)));
    const portOk = parseValidPort(rawPortSource);
    nonHttpHost = cleanHost;
    nonHttpPort = portOk;

    const protoScheme = method === 'UDP' ? 'udp' : 'tcp';
    const formattedHost = cleanHost.includes(':') ? `[${cleanHost}]` : cleanHost;
    url = explicitNonHttpUrl || (hostOk && portOk ? `${protoScheme}://${formattedHost}:${portOk}` : null);
    curl = (hostOk && portOk)
      ? (custom?.curl && typeof custom.curl === 'string'
          ? stripControlChars(custom.curl)
          : `nc -vz ${shellQuoteSingle(cleanHost)} ${portOk}`)
      : null;
  } else {
    curl = normalizeHttpUrl(url)
      ? (custom?.curl && typeof custom.curl === 'string'
          ? stripControlChars(custom.curl)
          : buildCurlCommand({
              method,
              url,
              headers: requestHeaders,
              body,
              http2: useHttp2,
              http3: useHttp3,
              tlsv13: useTls13,
              sourceIp,
              resolvedIp,
              includeResolveFlag
            }))
      : null;

    if (curl && checkId === 'ssl-tls' && url) {
      try {
        const u = new URL(url);
        if (u.protocol === 'https:') {
          const port = u.port || '443';
          curl = `openssl s_client -connect ${shellQuoteSingle(`${u.hostname}:${port}`)} -servername ${shellQuoteSingle(u.hostname)} </dev/null`;
        }
      } catch {
        // keep curl
      }
    }
  }

  const verifyFix = stripControlChars(
    custom?.verifyFix ||
    ((isTcp || isOtherNonHttp) && isValidShellHost(nonHttpHost) && nonHttpPort
      ? `Apply the remediation, then re-test ${method} port ${nonHttpPort} on ${nonHttpHost} (nc -vz ${shellQuoteSingle(nonHttpHost)} ${nonHttpPort} or PowerShell Test-NetConnection -ComputerName ${nonHttpHost} -Port ${nonHttpPort}) and re-run check "${finding.checkId || finding.name || checkId}" to confirm status transitions to SAFE.`
      : isRtsp && url
        ? `Apply the remediation, then replay RTSP ${rtspRequestMethod} against ${url} and re-run check "${finding.checkId || finding.name || checkId}" to confirm status transitions to SAFE.`
        : (finding.fix || finding.remediation || finding.meta?.defaultFix
            ? `Apply the remediation, then replay ${method} ${url || 'the endpoint'} and re-run check "${finding.checkId || finding.name || checkId}" to confirm status transitions to SAFE and the triggering indicator no longer appears.`
            : `Apply the recommended fix and re-run "${finding.checkId || finding.name || checkId}" (or click 1-Click Retest) until status returns SAFE.`))
  );

  const steps = Array.isArray(custom?.steps) && custom.steps.length > 0
    ? custom.steps.map(s => stripControlChars(s)).filter(Boolean)
    : (isTcp || isOtherNonHttp) && isValidShellHost(nonHttpHost) && nonHttpPort
      ? [
          `Run ${method} connectivity probe against ${nonHttpHost}:${nonHttpPort}: nc -vz ${shellQuoteSingle(nonHttpHost)} ${nonHttpPort} (or PowerShell: Test-NetConnection -ComputerName ${nonHttpHost} -Port ${nonHttpPort}).`,
          `Observe that ${method} port ${nonHttpPort} is reachable (${observedSignal}).`,
          verifyFix
        ]
      : isRtsp && url
        ? [
            `Send RTSP ${rtspRequestMethod} probe to ${url}: curl -i -sS --request ${rtspRequestMethod} ${shellQuoteSingle(url)}.`,
            `Observe the RTSP response (${observedSignal})${responseStatus ? ` (status ${responseStatus})` : ''}.`,
            verifyFix
          ]
        : [
            url
              ? `Send ${method} request to ${url}${Object.keys(requestHeaders).length ? ` with header(s) ${Object.entries(requestHeaders).map(([k, v]) => `${k}: ${v}`).join('; ')}` : ''}${payload && !url.includes(payload) ? ` (probe: ${payload})` : ''}.`
              : `Run the "${finding.checkId || finding.name || checkId}" verification check against ${stripControlChars(pageFallback || 'the target')}.`,
            `Observe the indicator (${observedSignal})${responseStatus ? ` on HTTP ${responseStatus}` : ''}.`,
            verifyFix
          ];

  const summary = stripControlChars(
    custom?.summary ||
    ((isTcp || isOtherNonHttp) && isValidShellHost(nonHttpHost) && nonHttpPort
      ? `${method} ${nonHttpHost}:${nonHttpPort} (${observedSignal})`
      : isRtsp && url
        ? `RTSP ${rtspRequestMethod} ${url} (${observedSignal})`
        : (url ? `${method} ${url}${responseStatus ? ` -> HTTP ${responseStatus}` : ''} (${observedSignal})` : observedSignal))
  );

  const trafficId = finding.trafficId || triggerTrace?.trafficId || null;
  const reproducible = (finding.reproVerified === false || custom?.reproducible === false)
    ? false
    : Boolean(
        finding.reproVerified === true ||
        custom?.reproducible === true ||
        ((isTcp || isOtherNonHttp) && isValidShellHost(nonHttpHost) && Boolean(nonHttpPort)) ||
        (isRtsp && Boolean(url) && isValidShellHost(nonHttpHost)) ||
        (responseStatus !== null && responseStatus >= 200 && responseStatus < 400 && Boolean(url))
      );
  const matchedEvidence = [];
  const rawEvidenceList = Array.isArray(finding.files) && finding.files.length > 0
    ? finding.files
    : Array.isArray(finding.findings) && finding.findings.length > 0
      ? finding.findings
      : Array.isArray(finding.panels) && finding.panels.length > 0
        ? finding.panels
        : (Array.isArray(finding.issues) ? finding.issues.filter(i => i && typeof i === 'object') : []);
  for (const f of rawEvidenceList.slice(0, 10)) {
    if (!f || typeof f !== 'object') continue;
    const itemPath = f.path || f.endpoint;
    matchedEvidence.push({
      ...(itemPath ? { path: stripControlChars(itemPath).slice(0, 200) } : {}),
      ...(f.url ? { url: normalizeHttpUrl(f.url) || normalizeNonHttpUrl(f.url) || stripControlChars(f.url).slice(0, 300) } : {}),
      ...(f.method ? { method: stripControlChars(f.method).slice(0, 16) } : {}),
      ...(f.status !== undefined && Number.isFinite(Number(f.status)) ? { status: Number(f.status) } : {}),
      ...(f.matchedSignal || f.signal ? { matchedSignal: stripControlChars(f.matchedSignal || f.signal).slice(0, 140) } : {}),
      ...(f.preview ? { preview: stripControlChars(f.preview).slice(0, 200) } : {}),
      ...(f.detail || f.reason || f.issue ? { detail: stripControlChars(f.detail || f.reason || f.issue).slice(0, 220) } : {})
    });
  }
  const evidenceQuotes = Array.isArray(finding.evidenceQuotes)
    ? finding.evidenceQuotes.map(q => stripControlChars(q).slice(0, 200)).filter(Boolean).slice(0, 5)
    : [];

  return {
    summary,
    method,
    url,
    requestHeaders,
    reproducible,
    ...(payload ? { payload } : {}),
    ...(responseStatus !== null ? { responseStatus } : {}),
    observedSignal,
    ...(curl ? { curl } : (isNonHttpMode ? { curl: null } : {})),
    steps,
    verifyFix,
    ...(matchedEvidence.length ? { matchedEvidence } : {}),
    ...(evidenceQuotes.length ? { evidenceQuotes } : {}),
    ...(sourceIp ? { sourceIp } : {}),
    ...(resolvedIp ? { resolvedIp } : {}),
    ...(dialedAddress ? { dialedAddress } : {}),
    ...(trafficId ? { trafficId } : {})
  };
}
