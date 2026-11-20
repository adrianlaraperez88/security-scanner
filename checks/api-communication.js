import { URL } from 'node:url';
import {
  inspectApiCommunication,
  redactEndpointQuery,
  stripSensitiveQueryParamsForProbe,
  isDestructiveApiRoute
} from '../core/api-discovery.js';
import { redactSecretsInText } from '../core/ai-advisor.js';

export const tags = ['all', 'frontend', 'angular', 'react', 'vue', 'nextjs', 'api'];

export const name = 'api-communication';
export const cwe = 'CWE-200';
export const owasp = 'A05:2021-Security Misconfiguration';
export const cvssScore = 5.3;

export const meta = {
  id: 'api-communication',
  title: 'Client-Side API Communication & Endpoint Discovery',
  category: 'API Security',
  plainExplanation:
    'Inspects Single Page Application (SPA) HTML, JavaScript bundles (Angular, React, Vue, Next.js), runtime configuration files (/assets/config.json, /config.json, /env.js), and CSP connect-src directives to map client-to-API communication, discover backend REST/GraphQL/WebSocket endpoints, and detect unauthenticated API data exposure or insecure API configurations.',
  whyItMatters:
    'Modern SPAs communicate directly with same-origin or external backend APIs via Angular HttpClient, Fetch, Axios, or GraphQL. Hardcoded development/localhost API URLs, plaintext HTTP API endpoints on HTTPS pages, exposed runtime config files, or unauthenticated JSON API endpoints can leak sensitive customer data, credentials, and internal service topology.',
  defaultFix:
    'Use environment-specific production builds (e.g., Angular environment.prod.ts without dev proxy.conf.json localhost URLs), enforce HTTPS for all API origins, require authentication on sensitive REST/GraphQL endpoints, remove secrets from public /assets/config.json files, and restrict allowed API origins via Content-Security-Policy connect-src and strict CORS policies.',
  cwe: 'CWE-200',
  owasp: 'A05:2021-Security Misconfiguration',
  cvssScore: 5.3,
  cveIds: [],
  references: [
    'https://cwe.mitre.org/data/definitions/200.html',
    'https://owasp.org/API-Security/',
    'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
  ]
};

const CONFIG_PROBE_PATHS = new Set([
  '/assets/config.json',
  '/config.json',
  '/app-config.json',
  '/runtime-config.json',
  '/env.js'
]);

const CREDENTIAL_FIELD_RE = /^(?:password|passwd|pwd|secret|client_?secret|api_?key|access_?token|refresh_?token|private_?key|auth_?token|session_?token|jwt|bearer|connection_?string|database_?url|db_?password|signing_?key|encryption_?key|master_?key|token)$/i;

const SENSITIVE_DATA_FIELD_RE = /^(?:email|e_?mail|users|user_?list|accounts|customers|members|admins|private|internal_?data|phone|phone_?number|ssn|social_?security|credit_?card|billing|salary|permissions|roles|api_?keys|secrets|tokens|credentials)$/i;

const TRIVIAL_STATUS_KEYS = new Set([
  'ok',
  'status',
  'healthy',
  'alive',
  'up',
  'ping',
  'pong',
  'version',
  'message',
  'timestamp',
  'time'
]);

const RAW_SECRET_VALUE_RE = /(?<![A-Za-z0-9_-])(?:sk-ant-[A-Za-z0-9_-]{12,256}|sk-[A-Za-z0-9_-]{12,256}|sk_(?:live|test)_[0-9A-Za-z]{12,256}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,256}|AIza[0-9A-Za-z_-]{35}|eyJ[A-Za-z0-9_-]{10,2048}\.[A-Za-z0-9_-]{10,2048}\.[A-Za-z0-9_-]{5,2048})/;

function getHeader(headers, headerName) {
  if (!headers || typeof headers !== 'object') return '';
  const lower = String(headerName).toLowerCase();
  if (typeof headers.get === 'function') {
    return String(headers.get(headerName) ?? headers.get(lower) ?? '');
  }
  for (const [k, v] of Object.entries(headers)) {
    if (String(k).toLowerCase() === lower && v !== undefined && v !== null) {
      return Array.isArray(v) ? v.join(', ') : String(v);
    }
  }
  return '';
}

function isLocalOrInternalHost(hostname) {
  const h = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
  if (!h) return false;
  if (h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '0.0.0.0') return true;
  if (h.startsWith('127.')) return true;
  if (
    h.endsWith('.localhost') ||
    h.endsWith('.local') ||
    h.endsWith('.internal') ||
    h.endsWith('.test') ||
    h.endsWith('.localdomain')
  ) {
    return true;
  }
  return false;
}

function referencesLocalHost(textOrUrl) {
  const s = String(textOrUrl || '');
  if (!s) return false;
  try {
    const u = new URL(s);
    return isLocalOrInternalHost(u.hostname);
  } catch {
    return /(?:https?|wss?):\/\/(?:localhost|127\.\d+\.\d+\.\d+|\[::1\]|0\.0\.0\.0|[a-z0-9.-]+\.(?:local|internal|localhost|test))(?::\d+)?(?:\/|$)/i.test(s);
  }
}

/**
 * Inspects parsed JSON payload for unauthenticated sensitive fields or credential leaks.
 */
function analyzeJsonExposure(parsed) {
  if (!parsed || typeof parsed !== 'object') {
    return { exposed: false };
  }

  // Check if trivial status object like {} or {"ok":true}
  if (!Array.isArray(parsed)) {
    const topKeys = Object.keys(parsed);
    if (topKeys.length === 0) return { exposed: false };
    const allTrivial = topKeys.every(k => {
      if (!TRIVIAL_STATUS_KEYS.has(k.toLowerCase())) return false;
      const val = parsed[k];
      return val === null || typeof val !== 'object';
    });
    if (allTrivial) return { exposed: false };
  } else if (parsed.length === 0) {
    return { exposed: false };
  }

  const credentialFields = new Set();
  const sensitiveFields = new Set();

  function walk(node, depth = 0) {
    if (!node || typeof node !== 'object' || depth > 4) return;
    if (Array.isArray(node)) {
      for (const item of node.slice(0, 15)) {
        walk(item, depth + 1);
      }
      return;
    }

    for (const [key, val] of Object.entries(node).slice(0, 40)) {
      const cleanKey = String(key).trim();
      if (!cleanKey) continue;

      const isNonEmptyScalar =
        (typeof val === 'string' && val.trim().length > 0 && val.trim().toLowerCase() !== 'false' && val.trim().toLowerCase() !== 'null') ||
        (typeof val === 'number' && Number.isFinite(val));
      const isNonEmptyContainer =
        (Array.isArray(val) && val.length > 0) ||
        (val && typeof val === 'object' && !Array.isArray(val) && Object.keys(val).length > 0);

      if (CREDENTIAL_FIELD_RE.test(cleanKey) && isNonEmptyScalar) {
        credentialFields.add(cleanKey);
      } else if (typeof val === 'string' && RAW_SECRET_VALUE_RE.test(val)) {
        credentialFields.add(cleanKey);
      } else if (SENSITIVE_DATA_FIELD_RE.test(cleanKey) && (isNonEmptyScalar || isNonEmptyContainer)) {
        sensitiveFields.add(cleanKey);
      }

      if (val && typeof val === 'object') {
        walk(val, depth + 1);
      }
    }
  }

  walk(parsed, 0);

  if (credentialFields.size > 0) {
    return {
      exposed: true,
      hasCredentials: true,
      severity: 'HIGH',
      status: 'VULNERABLE',
      fields: [...credentialFields, ...sensitiveFields].slice(0, 8)
    };
  }

  if (sensitiveFields.size > 0) {
    return {
      exposed: true,
      hasCredentials: false,
      severity: 'MEDIUM',
      status: 'SUSPICIOUS',
      fields: [...sensitiveFields].slice(0, 8)
    };
  }

  return { exposed: false };
}

function buildSafeQuote(text, maxLen = 140) {
  const preSliced = String(text || '').slice(0, Math.max(maxLen * 4, 512)).replace(/\s+/g, ' ').trim();
  const redacted = redactSecretsInText(preSliced);
  if (!redacted) return '';
  return redacted.length > maxLen ? `${redacted.slice(0, maxLen - 1)}…` : redacted;
}

function buildSafeJsonPreviewQuote(endpoint, parsedJson, exposedFields = []) {
  const safeEp = redactEndpointQuery(String(endpoint || '/'));
  const keys = [];
  const seenKeys = new Set();
  const addKey = (k) => {
    const clean = redactSecretsInText(String(k ?? '').replace(/\s+/g, ' ').trim()).slice(0, 40);
    if (clean && !seenKeys.has(clean)) {
      seenKeys.add(clean);
      keys.push(clean);
    }
  };
  if (Array.isArray(parsedJson)) {
    const first = parsedJson[0];
    if (first && typeof first === 'object' && !Array.isArray(first)) {
      for (const k of Object.keys(first).slice(0, 10)) addKey(k);
    }
  } else if (parsedJson && typeof parsedJson === 'object') {
    for (const k of Object.keys(parsedJson).slice(0, 10)) addKey(k);
  }
  const safeFields = Array.isArray(exposedFields)
    ? exposedFields.slice(0, 8).map(f => redactSecretsInText(String(f ?? '').trim()).slice(0, 40)).filter(Boolean)
    : [];
  const keyText = keys.length > 0 ? keys.join(', ') : safeFields.join(', ');
  const prefix = Array.isArray(parsedJson) ? `${safeEp} -> JSON array keys` : `${safeEp} -> JSON keys`;
  const baseQuote = safeFields.length > 0
    ? `${prefix}: [${keyText}] (exposed: ${safeFields.join(', ')})`
    : `${prefix}: [${keyText}]`;
  return buildSafeQuote(baseQuote, 140);
}

/**
 * Client-Side API Communication & Endpoint Discovery scanner.
 */
export default async function run(target, fetchWithRetry, options = {}) {
  const base = String(target ?? '').trim().replace(/\/+$/, '');
  let parsedBase;
  try {
    parsedBase = new URL(base);
  } catch {
    return {
      name: 'api communication',
      status: 'ERROR',
      severity: 'LOW',
      reason: 'Invalid target URL'
    };
  }

  let rootRes = options?.rootResponse || null;
  if (!rootRes) {
    try {
      rootRes = await fetchWithRetry(base, {
        sameOriginRedirects: true,
        maxBytes: 2_097_152
      });
    } catch (err) {
      return {
        name: 'api communication',
        status: 'ERROR',
        severity: 'LOW',
        reason: err?.message || 'Target unreachable'
      };
    }
  }

  if (!rootRes || typeof rootRes !== 'object' || typeof rootRes.status !== 'number') {
    return {
      name: 'api communication',
      status: 'ERROR',
      severity: 'LOW',
      reason: 'Target unreachable'
    };
  }
  if (rootRes.url) {
    try {
      if (new URL(rootRes.url, `${base}/`).origin !== parsedBase.origin) {
        return {
          name: 'api communication',
          status: 'ERROR',
          severity: 'LOW',
          reason: 'Cross-origin redirect ignored'
        };
      }
    } catch {
      return {
        name: 'api communication',
        status: 'ERROR',
        severity: 'LOW',
        reason: 'Invalid root redirect URL'
      };
    }
  }
  if (rootRes.status >= 300 && rootRes.status < 400) {
    const loc = getHeader(rootRes.headers, 'location');
    if (loc) {
      try {
        if (new URL(loc, `${base}/`).origin !== parsedBase.origin) {
          return {
            name: 'api communication',
            status: 'ERROR',
            severity: 'LOW',
            reason: 'Cross-origin redirect ignored'
          };
        }
      } catch {}
    }
  }

  let apiInfo;
  try {
    apiInfo = await inspectApiCommunication(base, fetchWithRetry, {
      maxBundles: 5,
      maxConfigProbes: 4,
      ...options,
      rootResponse: rootRes
    });
  } catch (err) {
    return {
      name: 'api communication',
      status: 'ERROR',
      severity: 'LOW',
      reason: err?.message || 'Failed to inspect API communication'
    };
  }

  if (!apiInfo || typeof apiInfo !== 'object') {
    return {
      name: 'api communication',
      status: 'ERROR',
      severity: 'LOW',
      reason: 'Target unreachable'
    };
  }

  const isHttpsTarget = parsedBase.protocol === 'https:';
  const isBaseLocal = isLocalOrInternalHost(parsedBase.hostname);

  const sanitizeConfigItem = (cf) => {
    if (typeof cf === 'string') return redactEndpointQuery(cf);
    if (!cf || typeof cf !== 'object') return cf;
    return {
      ...cf,
      ...(typeof cf.path === 'string' ? { path: redactEndpointQuery(cf.path) } : {}),
      ...(Array.isArray(cf.endpoints)
        ? { endpoints: cf.endpoints.filter(e => typeof e === 'string').map(e => redactEndpointQuery(e)) }
        : {}),
      ...(Array.isArray(cf.externalOrigins)
        ? { externalOrigins: cf.externalOrigins.filter(o => typeof o === 'string').map(o => redactEndpointQuery(o)) }
        : {})
    };
  };

  const apiCommunication = {
    usesApi: Boolean(apiInfo.usesApi),
    architecture: apiInfo.architecture || 'traditional_web',
    clients: Array.isArray(apiInfo.clients) ? apiInfo.clients : [],
    protocols: Array.isArray(apiInfo.protocols) ? apiInfo.protocols : [],
    sameOriginEndpoints: Array.isArray(apiInfo.sameOriginEndpoints)
      ? apiInfo.sameOriginEndpoints.filter(e => typeof e === 'string').map(e => redactEndpointQuery(e))
      : [],
    externalApiOrigins: Array.isArray(apiInfo.externalApiOrigins)
      ? apiInfo.externalApiOrigins.filter(o => typeof o === 'string').map(o => redactEndpointQuery(o))
      : [],
    configFiles: Array.isArray(apiInfo.configFiles) ? apiInfo.configFiles.map(sanitizeConfigItem) : [],
    cspConnectSrc: Array.isArray(apiInfo.cspConnectSrc)
      ? apiInfo.cspConnectSrc.filter(c => typeof c === 'string').map(c => redactEndpointQuery(c))
      : [],
    bundlesInspected: Number(apiInfo.bundlesInspected) || 0,
    summary: redactSecretsInText(apiInfo.summary || '')
  };

  const findings = [];
  const evidenceQuotes = [];
  const seenFindingKeys = new Set();

  const addFinding = ({ name: fName, type, status, severity, detail, endpoint, quote }) => {
    const sanitizeTextWithEndpoints = (str) =>
      redactSecretsInText(
        String(str || '').replace(/(?:https?:\/\/[^\s"'<>)]+|\/[^\s"'<>)]+)\?[^\s"'<>)]+/g, m => redactEndpointQuery(m))
      );
    const safeDetail = sanitizeTextWithEndpoints(detail);
    const safeName = sanitizeTextWithEndpoints(fName);
    const safeEndpoint = endpoint ? redactEndpointQuery(String(endpoint)) : undefined;
    const key = `${type || safeName}|${safeEndpoint || ''}|${severity}`;
    if (seenFindingKeys.has(key)) return;
    seenFindingKeys.add(key);

    findings.push({
      name: safeName,
      type: type || safeName,
      status,
      severity,
      endpoint: safeEndpoint,
      reason: safeDetail,
      detail: safeDetail
    });

    const safeQuote = buildSafeQuote(quote || safeDetail);
    if (safeQuote && safeQuote.length >= 8 && !evidenceQuotes.includes(safeQuote)) {
      evidenceQuotes.push(safeQuote);
    }
  };

  // 1. Incorporate issues reported by inspectApiCommunication
  const rawIssues = Array.isArray(apiInfo.issues) ? apiInfo.issues : [];
  for (const issue of rawIssues) {
    if (!issue || typeof issue !== 'object') continue;
    const rawType = String(issue.type || 'api-config-issue').toLowerCase();
    const rawEndpoint = issue.endpoint ? String(issue.endpoint) : '';
    const rawDetail = String(issue.detail || issue.reason || '');
    const combined = `${rawType} ${rawEndpoint} ${rawDetail}`;

    const isLocalRef = referencesLocalHost(rawEndpoint) || referencesLocalHost(rawDetail);
    const isPlainHttpIssue =
      rawType.includes('insecure') ||
      rawType.includes('plaintext') ||
      rawType.includes('mixed') ||
      rawType.includes('http-api') ||
      /plaintext\s+http|insecure\s+http:\/\//i.test(rawDetail);
    const isLocalIssue =
      rawType.includes('localhost') ||
      rawType.includes('dev-api') ||
      rawType.includes('internal-api') ||
      rawType.includes('dev_url') ||
      /localhost|127\.0\.0\.1|development\s+api/i.test(rawDetail);

    // If a non-local target references http://localhost:..., classify it as localhost/dev API leak (SUSPICIOUS / MEDIUM)
    if (!isBaseLocal && (isLocalIssue || (isPlainHttpIssue && isLocalRef))) {
      addFinding({
        name: 'development or localhost api url in production bundle',
        type: 'localhost-api-url',
        status: 'SUSPICIOUS',
        severity: 'MEDIUM',
        endpoint: rawEndpoint || undefined,
        detail: rawDetail || `Production client bundle references development/localhost API endpoint (${rawEndpoint || 'localhost'}).`,
        quote: rawEndpoint ? `${rawEndpoint} (${rawDetail})` : rawDetail
      });
      continue;
    }

    if (isPlainHttpIssue && isHttpsTarget && !isLocalRef) {
      addFinding({
        name: 'plaintext http api origin on https frontend',
        type: 'insecure-http-api',
        status: 'VULNERABLE',
        severity: 'HIGH',
        endpoint: rawEndpoint || undefined,
        detail: rawDetail || `HTTPS frontend communicates with plaintext HTTP API origin (${rawEndpoint}).`,
        quote: rawEndpoint ? `${rawEndpoint} (${rawDetail})` : rawDetail
      });
      continue;
    }

    const hasSecretSignal =
      rawType.includes('secret') ||
      rawType.includes('token') ||
      rawType.includes('credential') ||
      rawType.includes('key') ||
      /secret|token|password|api[-_]?key|credential|private[-_]?key/i.test(rawDetail);

    const sev = String(issue.severity || (hasSecretSignal ? 'HIGH' : 'MEDIUM')).toUpperCase();
    const isHighOrCritical = sev === 'CRITICAL' || sev === 'HIGH' || hasSecretSignal;

    addFinding({
      name: rawType.replace(/[_-]+/g, ' '),
      type: rawType,
      status: isHighOrCritical ? 'VULNERABLE' : 'SUSPICIOUS',
      severity: sev === 'CRITICAL' ? 'CRITICAL' : isHighOrCritical ? 'HIGH' : sev === 'LOW' ? 'LOW' : 'MEDIUM',
      endpoint: rawEndpoint || undefined,
      detail: rawDetail || `Client-side API configuration issue detected${rawEndpoint ? ` at ${rawEndpoint}` : ''}.`,
      quote: rawDetail
    });
  }

  // 2. Ensure externalApiOrigins are checked for plaintext HTTP on HTTPS and localhost/dev leaks
  for (const extOrigin of apiCommunication.externalApiOrigins) {
    let parsedExt;
    try {
      parsedExt = new URL(extOrigin);
    } catch {
      continue;
    }

    const extIsLocal = isLocalOrInternalHost(parsedExt.hostname);
    if (!isBaseLocal && extIsLocal) {
      addFinding({
        name: 'development or localhost api url in production bundle',
        type: 'localhost-api-url',
        status: 'SUSPICIOUS',
        severity: 'MEDIUM',
        endpoint: extOrigin,
        detail: `Production client bundle references development/internal API origin ${extOrigin}.`,
        quote: `API origin: ${extOrigin}`
      });
    } else if (isHttpsTarget && (parsedExt.protocol === 'http:' || parsedExt.protocol === 'ws:') && !extIsLocal) {
      addFinding({
        name: 'plaintext http api origin on https frontend',
        type: 'insecure-http-api',
        status: 'VULNERABLE',
        severity: 'HIGH',
        endpoint: extOrigin,
        detail: `HTTPS frontend references unencrypted ${parsedExt.protocol}// API origin ${extOrigin}, exposing API traffic to interception or active tampering.`,
        quote: `Plaintext API origin: ${extOrigin}`
      });
    }
  }

  // 3. Probe up to 6 discovered same-origin API endpoints via read-only GET
  const candidateEndpoints = [];
  const seenCandidateDisplay = new Set();
  for (const ep of apiCommunication.sameOriginEndpoints) {
    if (typeof ep !== 'string' || !ep.trim()) continue;
    const cleanEp = ep.trim();
    const pathOnly = cleanEp.split('?')[0];
    if (CONFIG_PROBE_PATHS.has(pathOnly.toLowerCase())) continue;
    if (isDestructiveApiRoute(cleanEp)) continue;
    if (/[{}$]/.test(cleanEp) || /\/:[a-zA-Z0-9_]+/.test(cleanEp)) continue;
    const displayEp = redactEndpointQuery(cleanEp);
    const probeEp = stripSensitiveQueryParamsForProbe(displayEp);
    if (!probeEp) continue;
    if (!seenCandidateDisplay.has(displayEp)) {
      seenCandidateDisplay.add(displayEp);
      candidateEndpoints.push({ displayEp, probeEp });
    }
    if (candidateEndpoints.length >= 6) break;
  }

  for (const { displayEp, probeEp } of candidateEndpoints) {
    let probeUrl;
    try {
      const resolved = new URL(probeEp.startsWith('/') ? probeEp : `/${probeEp}`, `${base}/`);
      if (resolved.origin !== parsedBase.origin) continue;
      probeUrl = resolved.href;
    } catch {
      continue;
    }

    try {
      const res = await fetchWithRetry(probeUrl, {
        followRedirects: false,
        redirect: 'manual',
        maxBytes: 262_144
      });
      if (!res || res.status !== 200 || typeof res.text !== 'string') continue;
      if (res.url) {
        try {
          if (new URL(res.url, `${base}/`).origin !== parsedBase.origin) continue;
        } catch {
          continue;
        }
      }

      const ct = getHeader(res.headers, 'content-type').toLowerCase();
      if (ct.includes('text/html') || ct.includes('javascript') || ct.includes('text/css')) continue;

      const boundedBody = res.text.slice(0, 262_144);
      const trimmedBody = boundedBody.trim();
      const looksLikeJson = ct.includes('json') || (!ct && /^[\[{]/.test(trimmedBody));
      if (!looksLikeJson || !/^[\[{]/.test(trimmedBody)) continue;

      let parsedJson;
      try {
        parsedJson = JSON.parse(trimmedBody);
      } catch {
        continue;
      }

      const exposure = analyzeJsonExposure(parsedJson);
      if (exposure.exposed) {
        const fieldList = exposure.fields.join(', ');
        const previewQuote = buildSafeJsonPreviewQuote(displayEp, parsedJson, exposure.fields);
        if (exposure.hasCredentials) {
          addFinding({
            name: `unauthenticated api credential exposure (${displayEp})`,
            type: 'unauthenticated-api-credentials',
            status: 'VULNERABLE',
            severity: 'HIGH',
            endpoint: displayEp,
            detail: `Unauthenticated GET ${displayEp} returned HTTP 200 JSON exposing credential/token field(s): ${fieldList}.`,
            quote: previewQuote
          });
        } else {
          addFinding({
            name: `unauthenticated sensitive api data exposure (${displayEp})`,
            type: 'unauthenticated-api-data',
            status: 'SUSPICIOUS',
            severity: 'MEDIUM',
            endpoint: displayEp,
            detail: `Unauthenticated GET ${displayEp} returned HTTP 200 JSON exposing sensitive field(s): ${fieldList}.`,
            quote: previewQuote
          });
        }
      }
    } catch {
      // Ignore individual endpoint probe error
    }
  }

  const defaultSummary =
    apiCommunication.summary ||
    (apiCommunication.usesApi
      ? `Detected ${apiCommunication.architecture} (${apiCommunication.clients.join(', ') || 'HTTP API'}) with ${apiCommunication.sameOriginEndpoints.length} same-origin endpoint(s) and ${apiCommunication.externalApiOrigins.length} external API origin(s).`
      : 'No client-side SPA API communication patterns or exposed API endpoints detected.');

  if (findings.length === 0) {
    return {
      name: 'api communication',
      status: 'SAFE',
      severity: 'NONE',
      cwe: meta.cwe,
      owasp: meta.owasp,
      cvssScore: meta.cvssScore,
      detail: defaultSummary,
      fix: meta.defaultFix,
      findings: [],
      evidenceQuotes: [],
      apiCommunication
    };
  }

  const overallStatus = findings.some(f => f.status === 'VULNERABLE') ? 'VULNERABLE' : 'SUSPICIOUS';
  const overallSeverity = findings.some(f => f.severity === 'CRITICAL')
    ? 'CRITICAL'
    : findings.some(f => f.severity === 'HIGH')
    ? 'HIGH'
    : findings.some(f => f.severity === 'MEDIUM')
    ? 'MEDIUM'
    : 'LOW';

  const primaryDetails = findings.map(f => f.detail).join(' ');

  return {
    name: 'api communication',
    status: overallStatus,
    severity: overallSeverity,
    cwe: meta.cwe,
    owasp: meta.owasp,
    cvssScore: meta.cvssScore,
    detail: `${primaryDetails} (${defaultSummary})`,
    fix: meta.defaultFix,
    findings,
    evidenceQuotes,
    apiCommunication
  };
}
