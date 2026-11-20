import {
  redactSecretsInText,
  redactEndpointQuery,
  stripSensitiveQueryParamsForProbe
} from './ai-advisor.js';

export { redactEndpointQuery, stripSensitiveQueryParamsForProbe };

export const DEFAULT_MAX_SCRIPT_BYTES = 1_572_864; // 1.5 MiB
export const DEFAULT_MAX_TOTAL_SCRIPT_BYTES = 4_194_304; // 4 MiB
export const DEFAULT_MAX_HTML_BYTES = 2_097_152; // 2 MiB
export const DEFAULT_MAX_JSON_BYTES = 524_288; // 512 KiB

export const RUNTIME_CONFIG_PATHS = [
  '/assets/config.json',
  '/config.json',
  '/app-config.json',
  '/runtime-config.json',
  '/env.js'
];

const NOISY_EXTERNAL_HOSTS = new Set([
  'w3.org',
  'schemas.microsoft.com',
  'schema.org',
  'fonts.googleapis.com',
  'fonts.gstatic.com',
  'cdn.jsdelivr.net',
  'unpkg.com',
  'cdnjs.cloudflare.com',
  'angular.io',
  'angular.dev',
  'reactjs.org',
  'vuejs.org',
  'react.dev',
  'nextjs.org',
  'json-schema.org',
  'xmlns.com',
  'purl.org',
  'creativecommons.org',
  'opensource.org',
  'mozilla.org',
  'developer.mozilla.org'
]);

const STATIC_EXT_RE = /\.(?:png|jpe?g|gif|svg|webp|css|scss|sass|less|woff2?|ttf|eot|ico|map|html?)(?:[?#].*)?$/i;
const IGNORED_PATH_PREFIX_RE = /(?:^|\/)(?:node_modules|_next\/static|static)(?:\/|$)/i;
const API_PATH_PREFIX_RE = /^\/(?:api|v[1-3]|graphql|rest|auth|oauth|trpc)(?:\/|$|\?)/i;
const CONFIG_FILE_PATH_RE = /^\/?(?:assets\/config\.json|config\.json|app-config\.json|runtime-config\.json|env\.js)(?:\?.*)?$/i;

// Linear, non-backtracking matchers with bounded lengths
const SAME_ORIGIN_PATH_RE = /(?:["'`])(\/(?:api|v[1-3]|graphql|rest|auth|oauth|trpc)(?:\/[A-Za-z0-9._~!&*+=:@%/-]{0,180})?(?:\?[A-Za-z0-9._~!&*+=:@%?/-]{0,120})?|\/?(?:assets\/config\.json|config\.json|app-config\.json|runtime-config\.json|env\.js)(?:\?[A-Za-z0-9._~!&*+=:@%?/-]{0,120})?)(?=["'`$])/gi;
const EXTERNAL_URL_RE = /(https?|wss?):\/\/(?:[A-Za-z0-9.-]{1,253}|\[[0-9A-Fa-f:]{2,45}\])(?::\d{1,5})?(?:\/[A-Za-z0-9._~!&*+=:@%?/-]{0,200})?/gi;
const API_CONTEXT_HINT_RE = /\b(?:fetch|axios|HttpClient|httpClient|baseURL|apiUrl|apiBase|apiEndpoint|backendUrl|endpoint|graphql|WebSocket|EventSource|apollo|trpc|serverUrl|proxy|wsUrl|wssUrl|socketUrl|api_url|api_base|backend_url|server_url|authUrl|oauthUrl|restUrl|uri|http\.get|http\.post|http\.put|http\.delete|http\.patch|http\.request)\b/i;
const API_HOST_HINT_RE = /^(?:api|graphql|gql|backend|rpc|trpc|ws|wss|gateway|auth|oauth)[.-]/i;
const API_URL_PATH_HINT_RE = /^\/(?:api|v[1-3]|graphql|rest|auth|oauth|trpc|ws|socket\.io|sse|events)(?:\/|$)/i;

const SCRIPT_TAG_RE = /<script\b([^>]{0,2048})>/gi;
const SCRIPT_SRC_ATTR_RE = /\bsrc\s*=\s*(?:"([^"]{1,1024})"|'([^']{1,1024})'|([^\s"'=<>`]{1,1024}))/i;
const SCRIPT_TYPE_ATTR_RE = /\btype\s*=\s*(?:"([^"]{1,128})"|'([^']{1,128})'|([^\s"'=<>`]{1,128}))/i;
const META_CSP_RE = /<meta\b[^>]{0,512}\bhttp-equiv\s*=\s*["']?content-security-policy["']?[^>]{0,1024}>/gi;
const META_CONTENT_ATTR_RE = /\bcontent\s*=\s*(?:"([^"]{1,4096})"|'([^']{1,4096})')/i;

const PRIVATE_KEY_RE = /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----[\s\S]{0,1024}/gi;
const EXTRA_VENDOR_TOKEN_RE = /(?<![A-Za-z0-9_-])(rk_(?:live|test)_[0-9A-Za-z]{12,256}|whsec_[0-9A-Za-z]{12,256}|gh[ousr]_[A-Za-z0-9]{16,256}|ASIA[0-9A-Z]{16}|SG\.[A-Za-z0-9_-]{12,256}\.[A-Za-z0-9_-]{12,256})/g;
const EXTRA_SECRET_PROP_RE = /(?<![A-Za-z0-9_-])(apikey|clientsecret|authtoken|accesstoken|secretkey|privatekey|refreshsecret|jwtsecret|dbpassword)\b(\s*["']?\s*[:=]\s*["']?)([^\r\n"',;]*)/gi;

const SCRIPT_SECRET_PATTERNS = [
  { kind: 'Private Key', regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g },
  { kind: 'Provider API Token', regex: /(?<![A-Za-z0-9_-])(?:sk-ant-[A-Za-z0-9_-]{12,256}|sk-[A-Za-z0-9_-]{16,256}|sk_(?:live|test)_[0-9A-Za-z]{12,256}|rk_(?:live|test)_[0-9A-Za-z]{12,256}|whsec_[0-9A-Za-z]{12,256}|(?:AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,256}|glpat-[A-Za-z0-9_-]{16,256}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[0-9A-Za-z-]{10,256})/g },
  { kind: 'Hardcoded JWT', regex: /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,2048}\.[A-Za-z0-9_-]{10,2048}\.[A-Za-z0-9_-]{5,2048}/g },
  { kind: 'Hardcoded Auth Header', regex: /\b(?:Bearer|Basic)\s+[A-Za-z0-9\-._~+/=]{16,2048}/g },
  { kind: 'Embedded URL Credential', regex: /\bhttps?:\/\/[^\s/@:'"`<>]{1,64}:[^\s/@'"`<>]{4,64}@[A-Za-z0-9.-]+/gi },
  { kind: 'Hardcoded Secret Property', regex: /(?<![A-Za-z0-9_-])["']?(?:api[-_]?key|secret[-_]?key|private[-_]?key|access[-_]?key|client[-_]?secret|auth[-_]?token|access[-_]?token|refresh[-_]?token|jwt[-_]?secret|db[-_]?password|password|passwd)["']?\s*[:=]\s*["']([^\s"'`$\\]{12,160})["']/gi }
];

const PLACEHOLDER_VALUE_RE = /^(?:undefined|null|true|false|example|placeholder|your[_-]?|change[_-]?me|replace[_-]?me|<[^>]+>|application\/|text\/|https?:\/\/)/i;
const DESTRUCTIVE_OR_SESSION_ROUTE_RE = /(?:^|\/)(?:logout|log-out|signout|sign-out|delete|remove|destroy|reset|purge|drop|revoke|unsubscribe|deactivate|cancel|kill|shutdown|restart)(?:\/|$|\?)/i;

function normalizeHeadersMap(headers) {
  const out = {};
  if (!headers) return out;
  if (typeof headers.entries === 'function') {
    for (const [k, v] of headers.entries()) {
      out[String(k).toLowerCase()] = String(v);
    }
    return out;
  }
  if (typeof headers === 'object') {
    for (const [k, v] of Object.entries(headers)) {
      out[String(k).toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v ?? '');
    }
  }
  return out;
}

function safeParseUrl(raw, base) {
  try {
    return base ? new URL(raw, base) : new URL(raw);
  } catch {
    return null;
  }
}

function isLocalOrInternalHost(hostname) {
  const h = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
  if (!h) return false;
  if (
    h === 'localhost' ||
    h === '127.0.0.1' ||
    h === '::1' ||
    h === '0.0.0.0' ||
    h.endsWith('.localhost') ||
    h.endsWith('.local') ||
    h.endsWith('.internal')
  ) {
    return true;
  }
  if (/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
  if (/^192\.168\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
  if (/^169\.254\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
  const m172 = h.match(/^172\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/);
  if (m172 && Number(m172[1]) >= 16 && Number(m172[1]) <= 31) return true;
  return false;
}

function isNoisyExternalHost(hostname) {
  const h = String(hostname || '').toLowerCase().replace(/\.+$/, '');
  if (!h) return true;
  for (const noisy of NOISY_EXTERNAL_HOSTS) {
    if (h === noisy || h.endsWith(`.${noisy}`)) return true;
  }
  return false;
}

function isHtmlResponse(res) {
  if (!res) return false;
  const headers = normalizeHeadersMap(res.headers);
  const ct = (headers['content-type'] || '').toLowerCase();
  if (ct.includes('text/html') || ct.includes('application/xhtml+xml')) return true;
  const trimmed = typeof res.text === 'string' ? res.text.trimStart().slice(0, 64).toLowerCase() : '';
  return trimmed.startsWith('<!doctype') || trimmed.startsWith('<html') || trimmed.startsWith('<head') || trimmed.startsWith('<body');
}

function isJsonApiResponse(res) {
  if (!res || typeof res.text !== 'string') return false;
  const headers = normalizeHeadersMap(res.headers);
  const ct = (headers['content-type'] || '').toLowerCase();
  if (ct.includes('application/json') || ct.includes('application/problem+json') || ct.includes('application/vnd.api+json')) {
    return true;
  }
  if (isHtmlResponse(res)) return false;
  const bounded = res.text.slice(0, DEFAULT_MAX_JSON_BYTES);
  const trimmed = bounded.trim();
  if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) return false;
  try {
    const parsed = JSON.parse(trimmed);
    return parsed !== null && typeof parsed === 'object';
  } catch {
    return false;
  }
}

function isIgnoredStaticPath(pathname) {
  const pathOnly = String(pathname || '').split('?')[0];
  if (!pathOnly) return true;
  if (IGNORED_PATH_PREFIX_RE.test(pathOnly)) return true;
  if (CONFIG_FILE_PATH_RE.test(pathOnly)) return false;
  return STATIC_EXT_RE.test(pathOnly);
}

function scriptPriorityScore(urlStr) {
  const pathLower = (() => {
    try {
      return new URL(urlStr).pathname.toLowerCase();
    } catch {
      return String(urlStr || '').toLowerCase();
    }
  })();
  const fileName = pathLower.split('/').pop() || '';
  if (/^(?:polyfills|runtime|vendors?|framework|webpack|manifest|core-js)(?:[.-]|$)/i.test(fileName)) {
    return 3;
  }
  if (/^(?:main|app|index|bundle|client|entry|env|config)(?:[.-]|$)/i.test(fileName) || /\/(?:pages|app)\//.test(pathLower)) {
    return 1;
  }
  return 2;
}

function parseCspConnectSrc(cspHeaderValue) {
  if (!cspHeaderValue) return [];
  const ignored = new Set([
    "'self'",
    "'none'",
    "'strict-dynamic'",
    "'report-sample'",
    "'wasm-unsafe-eval'",
    'data:',
    'blob:',
    'mediastream:',
    'filesystem:'
  ]);
  const origins = [];
  const seen = new Set();

  for (const directive of String(cspHeaderValue).split(';')) {
    const trimmed = directive.trim();
    if (!trimmed) continue;
    const parts = trimmed.split(/\s+/);
    if (parts[0].toLowerCase() !== 'connect-src') continue;
    for (const token of parts.slice(1)) {
      const clean = token.trim();
      const lower = clean.toLowerCase();
      if (!clean) continue;
      if (ignored.has(lower)) continue;
      if (lower.startsWith("'unsafe-") || lower.startsWith("'nonce-") || lower.startsWith("'sha")) continue;
      if (clean === '*') continue;
      const parsed = safeParseUrl(clean);
      const value = (parsed && ['http:', 'https:', 'ws:', 'wss:'].includes(parsed.protocol))
        ? parsed.origin
        : clean;
      if (!seen.has(value)) {
        seen.add(value);
        origins.push(value);
      }
    }
  }
  return origins;
}

function parseLinkHeader(linkHeaderValue, baseUrl) {
  if (!linkHeaderValue) return [];
  const links = [];
  const entries = String(linkHeaderValue).split(',');
  for (const entry of entries.slice(0, 30)) {
    const urlMatch = entry.match(/<([^>\s]{1,512})>/);
    if (!urlMatch) continue;
    const relMatch = entry.match(/\brel\s*=\s*(?:"([^"]{1,64})"|([^\s;]{1,64}))/i);
    const rawHref = urlMatch[1].trim();
    const resolved = baseUrl ? safeParseUrl(rawHref, baseUrl)?.href || rawHref : rawHref;
    links.push({
      url: resolved,
      rel: (relMatch?.[1] || relMatch?.[2] || '').toLowerCase()
    });
  }
  return links;
}

function extractInlineScriptsFromHtml(html) {
  if (typeof html !== 'string' || !html) return '';
  const bounded = html.slice(0, DEFAULT_MAX_HTML_BYTES);
  const lower = bounded.toLowerCase();
  const chunks = [];
  let total = 0;

  SCRIPT_TAG_RE.lastIndex = 0;
  let match;
  while ((match = SCRIPT_TAG_RE.exec(bounded)) !== null) {
    const attrs = match[1] || '';
    if (SCRIPT_SRC_ATTR_RE.test(attrs)) continue;
    const typeMatch = attrs.match(SCRIPT_TYPE_ATTR_RE);
    const scriptType = (typeMatch?.[1] || typeMatch?.[2] || typeMatch?.[3] || '').toLowerCase();
    if (scriptType && !/^(?:text\/javascript|application\/javascript|module)$/.test(scriptType)) {
      continue;
    }
    const contentStart = match.index + match[0].length;
    const closeIdx = lower.indexOf('</script', contentStart);
    if (closeIdx === -1) continue;
    const body = bounded.slice(contentStart, closeIdx).trim();
    if (!body) continue;
    chunks.push(body);
    total += body.length;
    if (total >= DEFAULT_MAX_SCRIPT_BYTES) break;
  }
  return chunks.join('\n');
}

function detectClientsAndProtocols(text, { sameOriginEndpoints = [], externalApiOrigins = [], isHtml = false } = {}) {
  const clients = new Set();
  const protocols = new Set();

  if (/@angular\/common\/http|\bprovideHttpClient\b|\bHttpClient\b|\bHttpXhrBackend\b|\bHttpBackend\b/.test(text)) {
    clients.add('Angular HttpClient');
    protocols.add('HTTP/REST');
  }
  if (/\bfetch\s*\(|window\.fetch\b/.test(text)) {
    clients.add('Fetch API');
    protocols.add('HTTP/REST');
  }
  if (/\baxios\b(?:\s*[.(]|\.(?:create|get|post|put|delete|patch|request)\b)/i.test(text)) {
    clients.add('Axios');
    protocols.add('HTTP/REST');
  }
  if (/\bApolloClient\b|@apollo\/client|\b__APOLLO_STATE__\b|\bapolloClient\b/i.test(text)) {
    clients.add('Apollo GraphQL');
    clients.add('GraphQL');
    protocols.add('GraphQL');
  }
  if (/\/graphql\b|\bgraphql\b|\burql\b|\bcreateClient\s*\(/i.test(text) && /\bgraphql\b|\burql\b|\/graphql/i.test(text)) {
    clients.add('GraphQL');
    protocols.add('GraphQL');
  }
  if (/@trpc\/|\bcreateTRPC|\btrpcClient\b|\/trpc\b/i.test(text)) {
    clients.add('tRPC');
    protocols.add('tRPC');
  }
  if (/\bnew\s+WebSocket\b|\bWebSocket\b|\bsocket\.io\b|\bwss?:\/\//i.test(text)) {
    clients.add('WebSocket');
    protocols.add('WebSocket');
  }
  if (/\bnew\s+EventSource\b|\bEventSource\b|text\/event-stream/i.test(text)) {
    clients.add('Server-Sent Events');
    protocols.add('SSE');
  }
  if (/\$fetch\s*\(|\buseFetch\s*\(/.test(text) && (/\b__nuxt\b|\/_nuxt\/|\$fetch\s*\(/i.test(text) || !isHtml)) {
    clients.add('Nuxt $fetch');
    protocols.add('HTTP/REST');
  }

  if (
    sameOriginEndpoints.some(ep => /^\/(?:api|v[1-3]|rest|auth|oauth)\b/i.test(ep)) ||
    externalApiOrigins.some(o => /^https?:\/\//i.test(o))
  ) {
    protocols.add('HTTP/REST');
  }
  if (sameOriginEndpoints.some(ep => /^\/graphql\b/i.test(ep))) {
    clients.add('GraphQL');
    protocols.add('GraphQL');
  }
  if (sameOriginEndpoints.some(ep => /^\/trpc\b/i.test(ep))) {
    clients.add('tRPC');
    protocols.add('tRPC');
  }
  if (externalApiOrigins.some(o => /^wss?:\/\//i.test(o))) {
    clients.add('WebSocket');
    protocols.add('WebSocket');
  }

  return {
    clients: Array.from(clients),
    protocols: Array.from(protocols)
  };
}

function addUniqueIssue(issues, seenKeys, issue) {
  if (!issue || !issue.type) return;
  const key = `${issue.type}|${issue.endpoint || ''}|${issue.detail || ''}`;
  if (seenKeys.has(key)) return;
  seenKeys.add(key);
  issues.push(issue);
}

/**
 * Redacts credentials, tokens, and secret assignments before creating an API discovery preview.
 *
 * @param {string} text
 * @param {number} [maxLen=240]
 * @returns {string}
 */
export function redactApiSecretPreview(text, maxLen = 240) {
  const limit = Number.isFinite(Number(maxLen)) && Number(maxLen) > 0 ? Math.floor(Number(maxLen)) : 240;
  let value = String(text ?? '').slice(0, 4096);
  value = value
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/\s{2,}/g, ' ')
    .replace(PRIVATE_KEY_RE, '<REDACTED_PRIVATE_KEY>')
    .replace(EXTRA_VENDOR_TOKEN_RE, '<REDACTED>')
    .replace(EXTRA_SECRET_PROP_RE, '$1$2<REDACTED>');
  value = redactSecretsInText(value).trim();
  if (value.length > limit) {
    return `${value.slice(0, Math.max(0, limit - 3))}...`;
  }
  return value;
}

/**
 * Extracts SPA framework signals, API client hints, CSP connect-src origins, Link headers,
 * and prioritized same-origin script URLs from an HTML document and response headers.
 *
 * @param {string} html
 * @param {Record<string, string|string[]>|Headers} headers
 * @param {string} baseUrl
 */
export function extractApiSignalsFromHtml(html, headers, baseUrl) {
  const boundedHtml = typeof html === 'string' ? html.slice(0, DEFAULT_MAX_HTML_BYTES) : '';
  const lower = boundedHtml.toLowerCase();
  const h = normalizeHeadersMap(headers);
  const baseObj = safeParseUrl(baseUrl);
  const baseOrigin = baseObj ? baseObj.origin : '';

  const frameworks = new Set();
  const signals = new Set();

  // Script tags extraction (same-origin only)
  const rawScripts = [];
  const seenScriptUrls = new Set();
  const skippedExternalScripts = [];

  SCRIPT_TAG_RE.lastIndex = 0;
  let scriptMatch;
  while ((scriptMatch = SCRIPT_TAG_RE.exec(boundedHtml)) !== null) {
    const attrs = scriptMatch[1] || '';
    const srcMatch = attrs.match(SCRIPT_SRC_ATTR_RE);
    const src = (srcMatch?.[1] || srcMatch?.[2] || srcMatch?.[3] || '').trim();
    if (!src) continue;
    const resolved = baseObj ? safeParseUrl(src, baseObj.href) : safeParseUrl(src);
    if (!resolved || !['http:', 'https:'].includes(resolved.protocol)) continue;
    if (baseOrigin && resolved.origin !== baseOrigin) {
      skippedExternalScripts.push(resolved.href);
      continue;
    }
    if (!seenScriptUrls.has(resolved.href)) {
      seenScriptUrls.add(resolved.href);
      rawScripts.push(resolved.href);
    }
  }

  // Prioritize app/main bundles ahead of polyfills/runtime/vendor bundles (stable sort)
  const scriptUrls = rawScripts
    .map((url, idx) => ({ url, idx, priority: scriptPriorityScore(url) }))
    .sort((a, b) => (a.priority - b.priority) || (a.idx - b.idx))
    .map(item => item.url);

  const scriptFileNames = scriptUrls.map(u => {
    try {
      return new URL(u).pathname.split('/').pop()?.toLowerCase() || '';
    } catch {
      return '';
    }
  });
  const hasMainBundle = scriptFileNames.some(f => /^main(?:[.-][a-z0-9]+)?\.m?js$/i.test(f))
    || /main(?:[.-][a-z0-9]+)?\.m?js\b/i.test(lower);
  const hasPolyfillsBundle = scriptFileNames.some(f => /^polyfills(?:[.-][a-z0-9]+)?\.m?js$/i.test(f))
    || /polyfills(?:[.-][a-z0-9]+)?\.m?js\b/i.test(lower);

  // Angular signals
  if (lower.includes('ng-version')) { frameworks.add('angular'); signals.add('ng-version'); }
  if (lower.includes('ng-server-context')) { frameworks.add('angular'); signals.add('ng-server-context'); }
  if (lower.includes('ng-component') || lower.includes('_nghost-') || lower.includes('_ngcontent-')) {
    frameworks.add('angular');
    signals.add('ng-component');
  }
  if (lower.includes('<app-root')) { frameworks.add('angular'); signals.add('<app-root>'); }
  if (/\bng-app\b/.test(lower)) { frameworks.add('angular'); signals.add('ng-app'); }
  if (/@angular\/common\/http|\bprovideHttpClient\b|\bHttpClient\b/.test(boundedHtml)) {
    frameworks.add('angular');
    signals.add('angular-http');
  }
  if (hasMainBundle && hasPolyfillsBundle) {
    frameworks.add('angular');
    signals.add('main+polyfills');
  }

  // React / Next.js signals
  if (lower.includes('__next_data__') || lower.includes('/_next/') || lower.includes('next-router') || lower.includes('__next_f') || h['x-nextjs-page']) {
    frameworks.add('nextjs');
    frameworks.add('react');
    signals.add('nextjs');
  }
  if (lower.includes('react-dom') || lower.includes('data-reactroot')) {
    frameworks.add('react');
    signals.add('react');
  }

  // Vue / Nuxt signals
  if (lower.includes('__nuxt') || lower.includes('/_nuxt/') || /\$fetch|\buseFetch\b/.test(boundedHtml)) {
    frameworks.add('nuxt');
    frameworks.add('vue');
    signals.add('nuxt');
  }
  if (lower.includes('__vue_app__') || lower.includes('data-v-')) {
    frameworks.add('vue');
    signals.add('vue');
  }

  // SvelteKit signals
  if (lower.includes('__sveltekit') || lower.includes('data-sveltekit') || lower.includes('/_app/immutable/')) {
    frameworks.add('sveltekit');
    signals.add('sveltekit');
  }

  // CSP connect-src extraction (header + <meta http-equiv>)
  const cspValues = [];
  if (h['content-security-policy']) cspValues.push(h['content-security-policy']);
  META_CSP_RE.lastIndex = 0;
  let metaMatch;
  while ((metaMatch = META_CSP_RE.exec(boundedHtml)) !== null) {
    const contentMatch = metaMatch[0].match(META_CONTENT_ATTR_RE);
    const val = contentMatch?.[1] || contentMatch?.[2];
    if (val) cspValues.push(val);
  }
  const cspConnectSrc = Array.from(new Set(cspValues.flatMap(parseCspConnectSrc)));

  // Link headers extraction
  const linkHeaders = parseLinkHeader(h['link'], baseObj?.href);

  // Client HTTP/API libraries & protocols detected in HTML
  const { clients, protocols } = detectClientsAndProtocols(boundedHtml, { isHtml: true });

  return {
    frameworks: Array.from(frameworks),
    signals: Array.from(signals),
    clients,
    protocols,
    cspConnectSrc,
    linkHeaders,
    scriptUrls,
    skippedExternalScripts
  };
}

/**
 * Safely scans client-side JavaScript or runtime configuration text for same-origin API paths,
 * external API origins, HTTP client libraries/protocols, insecure HTTP references, localhost URLs,
 * and client-side secret exposures (strictly redacted).
 *
 * @param {string} jsText
 * @param {string} baseUrl
 * @param {object} [options={}]
 */
export function extractApiEndpointsFromScript(jsText, baseUrl, options = {}) {
  const maxBytes = Number.isFinite(Number(options.maxBytes)) && Number(options.maxBytes) > 0
    ? Math.floor(Number(options.maxBytes))
    : DEFAULT_MAX_SCRIPT_BYTES;
  const rawText = typeof jsText === 'string' ? jsText : '';
  const text = rawText.slice(0, maxBytes);
  const truncated = rawText.length > text.length;

  const baseObj = safeParseUrl(baseUrl);
  const baseOrigin = baseObj ? baseObj.origin : '';
  const isBaseHttps = baseObj?.protocol === 'https:';
  const isBaseLocal = baseObj ? isLocalOrInternalHost(baseObj.hostname) : false;
  const sourceUrl = redactEndpointQuery(options.sourceUrl || baseUrl || '');

  const sameOriginSet = new Set();
  const externalOriginsSet = new Set();
  const externalEndpointsSet = new Set();
  const issues = [];
  const seenIssueKeys = new Set();

  // 1. Same-origin API paths & runtime config paths
  SAME_ORIGIN_PATH_RE.lastIndex = 0;
  let pathMatch;
  while ((pathMatch = SAME_ORIGIN_PATH_RE.exec(text)) !== null) {
    let candidate = (pathMatch[1] || '').trim();
    if (!candidate) continue;
    if (!candidate.startsWith('/')) candidate = `/${candidate}`;
    if (candidate.length > 1 && candidate.endsWith('/')) {
      candidate = candidate.slice(0, -1);
    }
    if (isIgnoredStaticPath(candidate)) continue;
    if (!API_PATH_PREFIX_RE.test(candidate) && !CONFIG_FILE_PATH_RE.test(candidate)) continue;
    sameOriginSet.add(redactEndpointQuery(candidate));
    if (sameOriginSet.size >= 50) break;
  }

  // 2. External URLs (https/http/wss/ws) near API/HTTP hints or config contexts
  EXTERNAL_URL_RE.lastIndex = 0;
  let urlMatch;
  while ((urlMatch = EXTERNAL_URL_RE.exec(text)) !== null) {
    const rawMatched = urlMatch[0].replace(/[.,;:]+$/, '');
    const parsed = safeParseUrl(rawMatched);
    if (!parsed || !['http:', 'https:', 'ws:', 'wss:'].includes(parsed.protocol)) continue;
    if (!parsed.hostname || /^\.+$/.test(parsed.hostname)) continue;

    if (isNoisyExternalHost(parsed.hostname)) continue;
    if (isIgnoredStaticPath(parsed.pathname)) continue;

    if (baseOrigin && parsed.origin === baseOrigin) {
      let pathWithQuery = `${parsed.pathname}${parsed.search}`;
      if (pathWithQuery.length > 1 && pathWithQuery.endsWith('/') && !parsed.search) {
        pathWithQuery = pathWithQuery.slice(0, -1);
      }
      if (!isIgnoredStaticPath(pathWithQuery) && (API_PATH_PREFIX_RE.test(pathWithQuery) || CONFIG_FILE_PATH_RE.test(pathWithQuery))) {
        sameOriginSet.add(redactEndpointQuery(pathWithQuery));
      }
      continue;
    }

    const ctxStart = Math.max(0, urlMatch.index - 180);
    const ctxEnd = Math.min(text.length, urlMatch.index + rawMatched.length + 80);
    const ctx = text.slice(ctxStart, ctxEnd);

    const hasApiHint = Boolean(
      options.isConfigFile ||
      API_CONTEXT_HINT_RE.test(ctx) ||
      parsed.protocol === 'ws:' ||
      parsed.protocol === 'wss:' ||
      API_URL_PATH_HINT_RE.test(parsed.pathname) ||
      API_HOST_HINT_RE.test(parsed.hostname)
    );

    if (!hasApiHint) continue;

    externalOriginsSet.add(parsed.origin);
    externalEndpointsSet.add(redactEndpointQuery(parsed.href));

    if (isBaseHttps && (parsed.protocol === 'http:' || parsed.protocol === 'ws:')) {
      addUniqueIssue(issues, seenIssueKeys, {
        type: 'insecure_http_api',
        severity: 'HIGH',
        detail: `Plaintext ${parsed.protocol.replace(':', '').toUpperCase()} API endpoint referenced by HTTPS frontend: ${parsed.origin}`,
        endpoint: parsed.origin
      });
    }

    if (!isBaseLocal && isLocalOrInternalHost(parsed.hostname)) {
      addUniqueIssue(issues, seenIssueKeys, {
        type: 'localhost_api_leak',
        severity: 'MEDIUM',
        detail: `Local/internal development API URL baked into non-local frontend asset: ${parsed.origin}`,
        endpoint: parsed.origin
      });
    }
  }

  // 3. Client HTTP libraries, frameworks & protocols
  const sameOriginEndpoints = Array.from(sameOriginSet);
  const externalApiOrigins = Array.from(externalOriginsSet);
  const { clients, protocols } = detectClientsAndProtocols(text, {
    sameOriginEndpoints,
    externalApiOrigins,
    isHtml: false
  });

  const frameworks = [];
  if (/@angular\/common\/http|\bprovideHttpClient\b|\bngDevMode\b/.test(text)) {
    frameworks.push('angular');
  }

  // 4. Potential hardcoded client-side secrets / tokens (strictly redacted)
  for (const pattern of SCRIPT_SECRET_PATTERNS) {
    pattern.regex.lastIndex = 0;
    let secMatch;
    while ((secMatch = pattern.regex.exec(text)) !== null) {
      const capturedVal = secMatch[1];
      if (capturedVal) {
        if (PLACEHOLDER_VALUE_RE.test(capturedVal)) continue;
        if (API_PATH_PREFIX_RE.test(capturedVal)) continue;
      }
      const winStart = Math.max(0, secMatch.index - 24);
      const winEnd = Math.min(text.length, secMatch.index + secMatch[0].length + 48);
      const snippet = redactApiSecretPreview(text.slice(winStart, winEnd), 160);
      addUniqueIssue(issues, seenIssueKeys, {
        type: 'client_secret_exposure',
        severity: 'HIGH',
        detail: `Potential client-side ${pattern.kind} exposure in ${sourceUrl || 'script'}: ${snippet}`,
        endpoint: sourceUrl || baseOrigin || '/'
      });
      if (issues.length >= 25) break;
    }
  }

  return {
    sameOriginEndpoints,
    externalApiOrigins,
    externalEndpoints: Array.from(externalEndpointsSet),
    clients,
    protocols,
    frameworks,
    issues,
    truncated
  };
}

/**
 * Bounded, SSRF-safe analyzer that inspects a target page, its same-origin JS bundles,
 * and common runtime configuration files for client-side API communication and security issues.
 *
 * @param {string} targetUrl
 * @param {Function} fetchWithRetry
 * @param {object} [options={}]
 */
export async function inspectApiCommunication(targetUrl, fetchWithRetry, options = {}) {
  const emptyResult = (summary, reachable = true) => ({
    reachable,
    usesApi: false,
    architecture: 'traditional_web',
    frameworks: [],
    clients: [],
    protocols: [],
    sameOriginEndpoints: [],
    externalApiOrigins: [],
    configFiles: [],
    issues: [],
    cspConnectSrc: [],
    bundlesInspected: 0,
    summary
  });

  const baseObj = safeParseUrl(targetUrl);
  if (!baseObj || !['http:', 'https:'].includes(baseObj.protocol)) {
    return emptyResult('Invalid target URL', false);
  }
  const baseOrigin = baseObj.origin;
  const isBaseHttps = baseObj.protocol === 'https:';
  const isBaseLocal = isLocalOrInternalHost(baseObj.hostname);

  let rootRes = options.rootResponse ?? null;
  if (!rootRes) {
    try {
      rootRes = await fetchWithRetry(baseObj.href, {
        sameOriginRedirects: true,
        maxBytes: DEFAULT_MAX_HTML_BYTES
      });
    } catch {
      return emptyResult('Target unreachable', false);
    }
  }
  if (!rootRes) {
    return emptyResult('Target unreachable', false);
  }
  if (rootRes.url) {
    const rootFinalObj = safeParseUrl(rootRes.url, baseObj.href);
    if (!rootFinalObj || rootFinalObj.origin !== baseOrigin) {
      return emptyResult('Cross-origin redirect ignored', false);
    }
  }

  const rootHeaders = normalizeHeadersMap(rootRes.headers);
  if (rootRes.status >= 300 && rootRes.status < 400 && rootHeaders.location) {
    const redirObj = safeParseUrl(rootHeaders.location, baseObj.href);
    if (!redirObj || redirObj.origin !== baseOrigin) {
      return emptyResult('Cross-origin redirect ignored', false);
    }
  }
  const rootText = typeof rootRes.text === 'string' ? rootRes.text : '';
  const isJsonRoot = isJsonApiResponse(rootRes);

  const htmlSignals = extractApiSignalsFromHtml(rootText, rootHeaders, baseObj.href);

  const frameworksSet = new Set(htmlSignals.frameworks);
  const clientsSet = new Set(htmlSignals.clients);
  const protocolsSet = new Set(htmlSignals.protocols);
  const sameOriginSet = new Set();
  const externalOriginsSet = new Set();
  const configFiles = [];
  const issues = [];
  const seenIssueKeys = new Set();

  const mergeScriptScan = (scan) => {
    for (const ep of scan.sameOriginEndpoints) sameOriginSet.add(redactEndpointQuery(ep));
    for (const origin of scan.externalApiOrigins) externalOriginsSet.add(origin);
    for (const c of scan.clients) clientsSet.add(c);
    for (const p of scan.protocols) protocolsSet.add(p);
    for (const fw of scan.frameworks || []) frameworksSet.add(fw);
    for (const iss of scan.issues) addUniqueIssue(issues, seenIssueKeys, iss);
  };

  // Incorporate CSP connect-src external origins (never fetched, only reported/audited)
  for (const cspEntry of htmlSignals.cspConnectSrc) {
    const parsed = safeParseUrl(cspEntry);
    if (!parsed || !['http:', 'https:', 'ws:', 'wss:'].includes(parsed.protocol)) continue;
    if (isNoisyExternalHost(parsed.hostname)) continue;
    if (parsed.origin !== baseOrigin) {
      externalOriginsSet.add(parsed.origin);
      if (isBaseHttps && (parsed.protocol === 'http:' || parsed.protocol === 'ws:')) {
        addUniqueIssue(issues, seenIssueKeys, {
          type: 'insecure_http_api',
          severity: 'HIGH',
          detail: `CSP connect-src allows plaintext ${parsed.protocol.replace(':', '').toUpperCase()} origin on HTTPS page: ${parsed.origin}`,
          endpoint: parsed.origin
        });
      }
      if (!isBaseLocal && isLocalOrInternalHost(parsed.hostname)) {
        addUniqueIssue(issues, seenIssueKeys, {
          type: 'localhost_api_leak',
          severity: 'MEDIUM',
          detail: `CSP connect-src exposes local/internal development origin: ${parsed.origin}`,
          endpoint: parsed.origin
        });
      }
    }
  }

  // Incorporate API-related Link header targets (service-desc, api/graphql/backend hosts)
  for (const link of htmlSignals.linkHeaders) {
    const parsed = safeParseUrl(link.url, baseObj.href);
    if (!parsed || !['http:', 'https:', 'ws:', 'wss:'].includes(parsed.protocol)) continue;
    if (isNoisyExternalHost(parsed.hostname)) continue;
    const isServiceLink = link.rel === 'service-desc' || link.rel === 'service-doc' || link.rel === 'api';
    if (parsed.origin === baseOrigin) {
      if (isServiceLink || API_PATH_PREFIX_RE.test(parsed.pathname)) {
        sameOriginSet.add(redactEndpointQuery(`${parsed.pathname}${parsed.search}`));
      }
    } else if (isServiceLink || API_HOST_HINT_RE.test(parsed.hostname) || API_URL_PATH_HINT_RE.test(parsed.pathname)) {
      externalOriginsSet.add(parsed.origin);
    }
  }

  // Shared budget across inline scripts / JSON root, external bundles, and config probes
  const maxBundles = Math.max(0, Number.isFinite(Number(options.maxBundles)) ? Math.floor(Number(options.maxBundles)) : 5);
  const maxSingleBundleBytes = Math.max(1024, Number(options.maxSingleBundleBytes) || DEFAULT_MAX_SCRIPT_BYTES);
  const maxTotalScriptBytes = Math.max(maxSingleBundleBytes, Number(options.maxTotalScriptBytes) || DEFAULT_MAX_TOTAL_SCRIPT_BYTES);
  const budgetState = (options.budgetState && typeof options.budgetState === 'object' && Number.isFinite(Number(options.budgetState.bytes)))
    ? options.budgetState
    : { bytes: 0 };
  const seenBundleUrls = options.seenBundleUrls instanceof Set ? options.seenBundleUrls : null;
  const seenConfigUrls = options.seenConfigUrls instanceof Set ? options.seenConfigUrls : seenBundleUrls;

  // Scan inline scripts (or JSON root body) without making extra requests
  const rawInlineJs = isJsonRoot ? rootText : extractInlineScriptsFromHtml(rootText);
  if (rawInlineJs && budgetState.bytes < maxTotalScriptBytes) {
    const inlineRemaining = maxTotalScriptBytes - budgetState.bytes;
    const inlineCap = Math.min(
      isJsonRoot ? Math.min(maxSingleBundleBytes, DEFAULT_MAX_JSON_BYTES) : maxSingleBundleBytes,
      inlineRemaining
    );
    const boundedInline = rawInlineJs.slice(0, inlineCap);
    budgetState.bytes += boundedInline.length;
    mergeScriptScan(
      extractApiEndpointsFromScript(boundedInline, baseObj.href, {
        isConfigFile: isJsonRoot,
        maxBytes: inlineCap,
        sourceUrl: redactEndpointQuery(baseObj.href)
      })
    );
  }

  // Bounded same-origin bundle inspection
  let bundlesInspected = 0;

  for (const scriptUrl of htmlSignals.scriptUrls.slice(0, maxBundles)) {
    if (budgetState.bytes >= maxTotalScriptBytes) break;
    const parsedScript = safeParseUrl(scriptUrl, baseObj.href);
    if (!parsedScript || parsedScript.origin !== baseOrigin) continue;
    if (seenBundleUrls) {
      if (seenBundleUrls.has(parsedScript.href)) continue;
      seenBundleUrls.add(parsedScript.href);
    }

    const remaining = maxTotalScriptBytes - budgetState.bytes;
    const sliceLimit = Math.min(maxSingleBundleBytes, remaining);
    if (sliceLimit <= 0) break;

    try {
      const scriptRes = await fetchWithRetry(parsedScript.href, {
        followRedirects: false,
        redirect: 'manual',
        maxBytes: sliceLimit
      });
      if (!scriptRes || scriptRes.status !== 200 || typeof scriptRes.text !== 'string' || !scriptRes.text) {
        continue;
      }
      if (scriptRes.url) {
        const finalScriptObj = safeParseUrl(scriptRes.url, baseObj.href);
        if (!finalScriptObj || finalScriptObj.origin !== baseOrigin) continue;
      }
      if (isHtmlResponse(scriptRes)) continue;

      const boundedChunk = scriptRes.text.slice(0, sliceLimit);
      budgetState.bytes += boundedChunk.length;
      bundlesInspected += 1;

      mergeScriptScan(
        extractApiEndpointsFromScript(boundedChunk, baseObj.href, {
          maxBytes: sliceLimit,
          sourceUrl: redactEndpointQuery(parsedScript.pathname)
        })
      );
    } catch {
      // Non-fatal bundle fetch failure
    }
  }

  // Bounded same-origin runtime config probes
  const maxConfigProbes = Math.max(0, Number.isFinite(Number(options.maxConfigProbes)) ? Math.floor(Number(options.maxConfigProbes)) : 4);
  for (const cfgPath of RUNTIME_CONFIG_PATHS.slice(0, maxConfigProbes)) {
    if (budgetState.bytes >= maxTotalScriptBytes) break;
    const cfgUrl = safeParseUrl(cfgPath, baseOrigin);
    if (!cfgUrl || cfgUrl.origin !== baseOrigin) continue;
    if (seenConfigUrls) {
      if (seenConfigUrls.has(cfgUrl.href)) continue;
      seenConfigUrls.add(cfgUrl.href);
    }

    const cfgRemaining = maxTotalScriptBytes - budgetState.bytes;
    const isJsonCfg = cfgPath.endsWith('.json');
    const cfgCap = Math.min(
      maxSingleBundleBytes,
      isJsonCfg ? DEFAULT_MAX_JSON_BYTES : maxSingleBundleBytes,
      cfgRemaining
    );
    if (cfgCap <= 0) break;

    try {
      const cfgRes = await fetchWithRetry(cfgUrl.href, {
        followRedirects: false,
        redirect: 'manual',
        maxBytes: cfgCap
      });
      if (!cfgRes || cfgRes.status !== 200 || typeof cfgRes.text !== 'string' || !cfgRes.text) {
        continue;
      }
      if (cfgRes.url) {
        const finalCfgObj = safeParseUrl(cfgRes.url, baseObj.href);
        if (!finalCfgObj || finalCfgObj.origin !== baseOrigin) continue;
      }
      if (isHtmlResponse(cfgRes)) continue;

      const boundedCfg = cfgRes.text.slice(0, cfgCap);
      const trimmed = boundedCfg.trim();
      if (!trimmed) continue;

      const cfgHeaders = normalizeHeadersMap(cfgRes.headers);
      const ct = (cfgHeaders['content-type'] || '').toLowerCase();

      if (isJsonCfg) {
        let parsedJson = null;
        try {
          parsedJson = JSON.parse(trimmed);
        } catch {
          continue;
        }
        if (!parsedJson || typeof parsedJson !== 'object') continue;
      } else if (trimmed.startsWith('<')) {
        continue;
      }

      budgetState.bytes += boundedCfg.length;

      const cfgScan = extractApiEndpointsFromScript(boundedCfg, baseObj.href, {
        isConfigFile: true,
        maxBytes: cfgCap,
        sourceUrl: cfgPath
      });
      mergeScriptScan(cfgScan);
      sameOriginSet.add(cfgPath);
      configFiles.push({
        path: cfgPath,
        status: cfgRes.status,
        contentType: ct || (isJsonCfg ? 'application/json' : 'application/javascript'),
        endpoints: cfgScan.sameOriginEndpoints.slice(0, 15),
        externalOrigins: cfgScan.externalApiOrigins.slice(0, 10)
      });
    } catch {
      // Non-fatal config probe failure
    }
  }

  const sameOriginEndpoints = Array.from(sameOriginSet).slice(0, 25);
  const externalApiOrigins = Array.from(externalOriginsSet).slice(0, 15);
  const clients = Array.from(clientsSet);
  const protocols = Array.from(protocolsSet);
  const frameworks = Array.from(frameworksSet);

  if (isJsonRoot) protocols.push('HTTP/REST');
  const finalProtocols = Array.from(new Set(protocols));

  const usesApi = Boolean(
    isJsonRoot ||
    clients.length > 0 ||
    sameOriginEndpoints.length > 0 ||
    externalApiOrigins.length > 0 ||
    configFiles.length > 0 ||
    htmlSignals.cspConnectSrc.length > 0
  );

  const isSsrHybrid = Boolean(
    frameworks.includes('nextjs') ||
    frameworks.includes('nuxt') ||
    frameworks.includes('sveltekit') ||
    htmlSignals.signals.includes('ng-server-context')
  );
  const isSpaFramework = Boolean(
    frameworks.includes('angular') ||
    frameworks.includes('react') ||
    frameworks.includes('vue')
  );

  let architecture = 'traditional_web';
  if (isJsonRoot) {
    architecture = 'api_service';
  } else if (usesApi && isSsrHybrid) {
    architecture = 'ssr_hybrid_api';
  } else if (usesApi || isSpaFramework) {
    architecture = 'spa_api_client';
  }

  const summary = !usesApi
    ? `No client-side API communication detected (${architecture})`
    : `${architecture} — ${clients.length ? `Clients: ${clients.join(', ')}` : 'API references detected'} | ${sameOriginEndpoints.length} same-origin route(s), ${externalApiOrigins.length} external origin(s)`;

  return {
    reachable: true,
    usesApi,
    architecture,
    frameworks,
    clients,
    protocols: finalProtocols,
    sameOriginEndpoints,
    externalApiOrigins,
    configFiles,
    issues: issues.slice(0, 30),
    cspConnectSrc: htmlSignals.cspConnectSrc,
    bundlesInspected,
    summary
  };
}

function safeDecodePathRecursive(pathname, maxDepth = 3) {
  let current = String(pathname || '');
  for (let i = 0; i < maxDepth; i++) {
    if (!current.includes('%')) break;
    let decoded;
    try {
      decoded = decodeURIComponent(current);
    } catch {
      return { ok: false, decoded: current };
    }
    if (decoded === current) break;
    current = decoded;
  }
  if (/%[0-9A-Fa-f]{2}/.test(current) || current.includes('%')) {
    return { ok: false, decoded: current };
  }
  return { ok: true, decoded: current };
}

/**
 * Checks whether an endpoint path/URL targets a destructive or session-terminating route,
 * recursively decoding valid percent-escapes and rejecting malformed/multi-encoded evasions.
 *
 * @param {string} urlOrPath
 * @returns {boolean}
 */
export function isDestructiveApiRoute(urlOrPath) {
  const raw = String(urlOrPath || '').trim();
  if (!raw) return true;
  let pathOnly = raw.split(/[?#]/)[0];
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) || raw.startsWith('//')) {
    try {
      pathOnly = new URL(raw, 'https://example.invalid').pathname;
    } catch {
      return true;
    }
  }
  const normalizedRawPath = pathOnly.replace(/\\/g, '/');
  if (DESTRUCTIVE_OR_SESSION_ROUTE_RE.test(normalizedRawPath)) return true;

  const decodedRes = safeDecodePathRecursive(normalizedRawPath, 3);
  if (!decodedRes.ok) return true;
  const decodedNorm = decodedRes.decoded.replace(/\\/g, '/');
  if (DESTRUCTIVE_OR_SESSION_ROUTE_RE.test(decodedNorm)) return true;

  try {
    const resolvedNorm = new URL(decodedNorm.startsWith('/') ? decodedNorm : `/${decodedNorm}`, 'https://example.invalid').pathname;
    if (DESTRUCTIVE_OR_SESSION_ROUTE_RE.test(resolvedNorm)) return true;
  } catch {
    return true;
  }
  return false;
}

export function isSafeReadOnlyApiRoute(route) {
  const s = String(route || '').trim();
  if (!s) return false;
  if (isDestructiveApiRoute(s)) return false;
  const pathOnly = s.split(/[?#]/)[0];
  const decoded = safeDecodePathRecursive(pathOnly, 3);
  if (!decoded.ok) return false;
  if (/\.(?:js|mjs|json|map|css|png|jpe?g|gif|svg|ico|woff2?)(?:\?.*)?$/i.test(decoded.decoded)) return false;
  return true;
}

/**
 * Filters a list of discovered routes down to unique, safe, read-only same-origin API paths
 * suitable for enqueuing into TaskQueue (stripping sensitive query parameters).
 *
 * @param {string[]} routes
 * @param {string} targetUrl
 * @param {number} [maxCount=12]
 * @returns {string[]}
 */
export function filterSafeSameOriginApiRoutes(routes, targetUrl, maxCount = 12) {
  if (!Array.isArray(routes) || maxCount <= 0) return [];
  let targetOrigin;
  try {
    targetOrigin = new URL(targetUrl).origin;
  } catch {
    return [];
  }
  const safe = [];
  const seen = new Set();
  for (const raw of routes) {
    if (typeof raw !== 'string') continue;
    const trimmed = raw.trim();
    if (!trimmed || /[{}$]/.test(trimmed) || /\/:[a-zA-Z0-9_]+/.test(trimmed)) continue;
    if (isDestructiveApiRoute(trimmed)) continue;
    const cleanRoute = stripSensitiveQueryParamsForProbe(trimmed);
    if (!cleanRoute) continue;
    try {
      const resolved = new URL(cleanRoute, targetUrl);
      if (resolved.origin !== targetOrigin) continue;
      if (!['http:', 'https:'].includes(resolved.protocol)) continue;
      if (!isSafeReadOnlyApiRoute(`${resolved.pathname}${resolved.search}`)) continue;
      const route = `${resolved.pathname}${resolved.search}`;
      if (!seen.has(route)) {
        seen.add(route);
        safe.push(route);
        if (safe.length >= maxCount) break;
      }
    } catch {}
  }
  return safe;
}
