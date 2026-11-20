import { URL } from 'node:url';

const SENSITIVE_HEADER_RE = /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-access-token|x-csrf-token)$/i;
const DEFAULT_NOISE_HEADERS = new Set(['user-agent', 'accept-encoding', 'connection', 'host', 'content-length']);
const DEFAULT_SCANNER_ACCEPT_VALUES = new Set(['*/*', 'text/html,application/json,*/*', 'text/html,application/xhtml+xml,*/*;q=0.8']);
const CONTROL_CHAR_RE = /[\u0000-\u001f\u007f]/g;
const MAX_TRACES_PER_CHECK = 200;
const MAX_SNIPPET_LEN = 240;
const MAX_BODY_PREVIEW = 512;

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
  tlsv13 = false
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

  const trackedFetch = async function trackedFetch(url, opts = {}) {
    const reqMethod = String(opts?.method || 'GET').toUpperCase();
    const reqHeaders = sanitizeHeadersForRepro(opts?.headers);
    const bodyPreview = (opts?.body !== undefined && opts?.body !== null)
      ? stripControlChars(typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body)).slice(0, MAX_BODY_PREVIEW)
      : null;

    let res;
    try {
      res = await baseFetch(url, opts);
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
        trafficId: res?.trafficId || null
      });
    }

    return res;
  };

  for (const prop of ['governance', 'tlsAlpnProbe', 'governor', 'trafficStore']) {
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
  if (finding?.url) {
    const explicitUrl = normalizeHttpUrl(finding.url);
    if (explicitUrl && explicitUrl !== normalizeHttpUrl(baseForResolve)) {
      preferredTargets.push(explicitUrl);
    }
  }
  if (finding?.evidence?.requestUrl) preferredTargets.push(String(finding.evidence.requestUrl));
  for (const listKey of ['files', 'findings', 'panels']) {
    if (Array.isArray(finding?.[listKey])) {
      for (const item of finding[listKey]) {
        const itemPath = item?.path || item?.endpoint;
        const itemTarget = item?.url || (baseForResolve && itemPath ? resolveEndpointUrl(baseForResolve, itemPath) : null);
        if (itemTarget) preferredTargets.push(itemTarget);
      }
    }
  }
  if (Array.isArray(finding?.issues)) {
    for (const iss of finding.issues) {
      if (iss && typeof iss === 'object') {
        const issPath = iss.path || iss.endpoint;
        const issTarget = iss.url || (baseForResolve && issPath ? resolveEndpointUrl(baseForResolve, issPath) : null);
        if (issTarget) preferredTargets.push(issTarget);
      }
    }
  }
  if (Array.isArray(finding?.paths) && baseForResolve) {
    for (const p of finding.paths) {
      if (typeof p === 'string' && p) {
        const resolved = resolveEndpointUrl(baseForResolve, p);
        if (resolved) preferredTargets.push(resolved);
      }
    }
  }
  if (finding?.path && baseForResolve) {
    const resolved = resolveEndpointUrl(baseForResolve, finding.path);
    if (resolved) preferredTargets.push(resolved);
  }

  for (const pref of preferredTargets) {
    const exact = traces.find(t => t.url === pref && t.status !== 404);
    if (exact) return exact;
    try {
      const prefParsed = new URL(pref);
      const prefPath = prefParsed.pathname;
      const prefSearch = prefParsed.search;
      if (prefSearch) {
        const byPathAndSearch = traces.find(t => {
          try {
            const tu = new URL(t.url);
            return tu.pathname === prefPath && tu.search === prefSearch && t.status !== 404;
          } catch {
            return false;
          }
        });
        if (byPathAndSearch) return byPathAndSearch;
      }
      const byPath = traces.find(t => {
        try {
          return new URL(t.url).pathname === prefPath && t.status !== 404;
        } catch {
          return false;
        }
      });
      if (byPath) return byPath;
    } catch {
      // ignore
    }
  }

  const isTriggerCandidate = (t) => {
    const hasProbeHeaders = t.headers && Object.keys(t.headers).some(k => !DEFAULT_NOISE_HEADERS.has(k.toLowerCase()));
    const nonGet = t.method && t.method !== 'GET' && t.method !== 'HEAD';
    const goodStatus = Number.isFinite(t.status) && t.status !== 404;
    return goodStatus && (hasProbeHeaders || nonGet || Boolean(t.bodyPreview));
  };

  const probeHit = traces.find(isTriggerCandidate);
  if (probeHit) return probeHit;

  const status2xx3xx = traces.find(t => Number.isFinite(t.status) && t.status >= 200 && t.status < 400);
  if (status2xx3xx) return status2xx3xx;

  const non404 = traces.find(t => Number.isFinite(t.status) && t.status !== 404);
  return non404 || traces[traces.length - 1] || null;
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
  const triggerTrace = selectTriggerTrace(capturedTraces, finding);

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

  const method = String(
    custom?.method ||
    triggerTrace?.method ||
    finding.evidence?.requestMethod ||
    defaultMethod
  ).toUpperCase().replace(/[^A-Z]/g, '') || 'GET';

  const url =
    normalizeHttpUrl(custom?.url) ||
    normalizeHttpUrl(triggerTrace?.url) ||
    fallbackUrl;

  const requestHeaders = sanitizeHeadersForRepro({
    ...defaultHeaders,
    ...(triggerTrace?.headers || {}),
    ...(custom?.requestHeaders || custom?.headers || {})
  });

  const body = custom?.body ?? triggerTrace?.bodyPreview ?? null;
  const responseStatus = Number.isFinite(Number(custom?.responseStatus ?? triggerTrace?.status))
    ? Number(custom?.responseStatus ?? triggerTrace?.status)
    : null;

  const observedSignal = stripControlChars(
    custom?.observedSignal || summarizeObservedSignal(finding, triggerTrace)
  );
  const payload = custom?.payload !== undefined
    ? (custom.payload ? stripControlChars(custom.payload) : null)
    : inferPayloadHint(finding, { headers: requestHeaders, bodyPreview: body }, url);

  let curl = normalizeHttpUrl(url)
    ? (custom?.curl && typeof custom.curl === 'string'
        ? stripControlChars(custom.curl)
        : buildCurlCommand({
            method,
            url,
            headers: requestHeaders,
            body,
            http2: useHttp2,
            http3: useHttp3,
            tlsv13: useTls13
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

  const verifyFix = stripControlChars(
    custom?.verifyFix ||
    (finding.fix || finding.remediation || finding.meta?.defaultFix
      ? `Apply the remediation, then replay ${method} ${url || 'the endpoint'} and re-run check "${finding.checkId || finding.name || checkId}" to confirm status transitions to SAFE and the triggering indicator no longer appears.`
      : `Apply the recommended fix and re-run "${finding.checkId || finding.name || checkId}" (or click 1-Click Retest) until status returns SAFE.`)
  );

  const steps = Array.isArray(custom?.steps) && custom.steps.length > 0
    ? custom.steps.map(s => stripControlChars(s)).filter(Boolean)
    : [
        url
          ? `Send ${method} request to ${url}${Object.keys(requestHeaders).length ? ` with header(s) ${Object.entries(requestHeaders).map(([k, v]) => `${k}: ${v}`).join('; ')}` : ''}${payload && !url.includes(payload) ? ` (probe: ${payload})` : ''}.`
          : `Run the "${finding.checkId || finding.name || checkId}" verification check against ${stripControlChars(pageFallback || 'the target')}.`,
        `Observe the indicator (${observedSignal})${responseStatus ? ` on HTTP ${responseStatus}` : ''}.`,
        verifyFix
      ];

  const summary = stripControlChars(
    custom?.summary ||
    (url ? `${method} ${url}${responseStatus ? ` -> HTTP ${responseStatus}` : ''} (${observedSignal})` : observedSignal)
  );

  const trafficId = finding.trafficId || triggerTrace?.trafficId || null;
  const reproducible = (finding.reproVerified === false || custom?.reproducible === false)
    ? false
    : Boolean(
        finding.reproVerified === true ||
        custom?.reproducible === true ||
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
      ...(f.url ? { url: normalizeHttpUrl(f.url) || stripControlChars(f.url).slice(0, 300) } : {}),
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
    ...(curl ? { curl } : {}),
    steps,
    verifyFix,
    ...(matchedEvidence.length ? { matchedEvidence } : {}),
    ...(evidenceQuotes.length ? { evidenceQuotes } : {}),
    ...(trafficId ? { trafficId } : {})
  };
}
