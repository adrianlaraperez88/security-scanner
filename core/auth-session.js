/**
 * Invicti / Burp Suite Stateful Authenticated Session, Cookie Jar, CSRF Extractor
 * & Login Macro Manager (`AuthSessionManager`).
 *
 * Capabilities:
 *  - Extracts hidden HTML form CSRF tokens (`_token`, `csrf_token`, `authenticity_token`, `__RequestVerificationToken`)
 *    and `<meta name="csrf-token">` tags.
 *  - Maintains a scoped `Set-Cookie` Cookie Jar and automatically promotes `XSRF-TOKEN` / `csrftoken`
 *    cookies into `X-XSRF-TOKEN` / `X-CSRFToken` request headers.
 *  - Executes form or JSON Login Macros (`POST /login` or `POST /api/auth/login`), extracting
 *    session cookies and JSON Bearer JWT tokens (`access_token`, `token`, `jwt`, `id_token`).
 *  - Blocks in-scan `/logout`, `/signout`, `/logoff` URLs to prevent self-termination of authenticated scans.
 *  - Detects session expiration (`401 Unauthorized`) and automatically re-runs the login macro.
 */

import crypto from 'node:crypto';

const LOGOUT_PATH_RE = /(?:^|\/)(?:log[-_]?out|sign[-_]?out|log[-_]?off|kill[-_]?session|destroy[-_]?session)(?:\/|$|\?)/i;

const COMMON_LOGIN_PATHS = [
  '/login',
  '/signin',
  '/user/login',
  '/admin/login',
  '/wp-login.php',
  '/api/auth/login',
  '/api/login',
  '/auth/login'
];

const USERNAME_FIELD_EXACT = new Set([
  'email',
  'username',
  'user',
  'user_login',
  'log',
  'login',
  'userid',
  'user_id',
  'account'
]);

const PASSWORD_FIELD_EXACT = new Set([
  'password',
  'pass',
  'pwd',
  'user_pass',
  'passwd'
]);

const NON_TEXT_INPUT_TYPES = new Set([
  'hidden',
  'password',
  'submit',
  'button',
  'reset',
  'image',
  'file',
  'checkbox',
  'radio'
]);

const CSRF_INPUT_NAMES = [
  '_token',
  'csrf_token',
  'csrftoken',
  'authenticity_token',
  '__requestverificationtoken',
  '_csrf',
  'csrf'
];

const CSRF_COOKIE_TO_HEADER = {
  'xsrf-token': 'X-XSRF-TOKEN',
  'csrftoken': 'X-CSRFToken',
  'csrf-token': 'X-CSRF-Token',
  '_csrf': 'X-CSRF-Token'
};

export const MAX_SEQUENCE_STEPS = 25;
export const MAX_SYSTEM_VARIABLES = 100;

const MAX_RESTRICTIONS = 50;
const MAX_RESTRICTION_LEN = 256;
const MAX_SECRETS = 50;
const MAX_INSPECT_HTML_BYTES = 262144;
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const SYSTEM_VARIABLE_CATEGORIES = new Set(['username', 'password', 'otp_seed', 'url', 'token', 'custom']);
const SECRET_VARIABLE_CATEGORIES = new Set(['password', 'otp_seed', 'token']);
const SECRET_VARIABLE_NAME_RE = /pass|pwd|secret|token|key|otp|seed/i;
const OTP_NON_CANDIDATE_TYPES = new Set([
  'hidden',
  'submit',
  'button',
  'reset',
  'image',
  'file',
  'checkbox',
  'radio'
]);
const OTP_FIELD_TOKEN_RE = /(?:^|[^a-zA-Z0-9])(otp|totp|mfa|2fa|two[-_]?factor|verification[-_]?code|auth[-_]?code|passcode|token|pin)(?:$|[^a-zA-Z0-9])/i;
const SUPPORTED_SEQUENCE_ACTIONS = new Set([
  'navigate',
  'change_input',
  'fill_otp',
  'click_button',
  'extract_token',
  'custom_request'
]);
const TOTP_ALGORITHM_MAP = {
  SHA1: { label: 'SHA1', nodeAlg: 'sha1' },
  'SHA-1': { label: 'SHA1', nodeAlg: 'sha1' },
  SHA256: { label: 'SHA256', nodeAlg: 'sha256' },
  'SHA-256': { label: 'SHA256', nodeAlg: 'sha256' },
  SHA512: { label: 'SHA512', nodeAlg: 'sha512' },
  'SHA-512': { label: 'SHA512', nodeAlg: 'sha512' }
};

/**
 * Returns `true` if a URL path matches a logout or session-termination endpoint
 * that must be skipped during an authenticated scan.
 *
 * @param {string} rawUrlOrPath
 * @returns {boolean}
 */
export function isLogoutOrDestructiveUrl(rawUrlOrPath) {
  const str = String(rawUrlOrPath || '').trim();
  if (!str) return false;
  try {
    const decoded = decodeURIComponent(str);
    return LOGOUT_PATH_RE.test(decoded);
  } catch {
    return LOGOUT_PATH_RE.test(str);
  }
}

/**
 * Extracts CSRF tokens from HTML forms (`<input type="hidden" name="_token" value="...">`),
 * `<meta name="csrf-token" content="...">` tags, and response headers.
 *
 * @param {string} htmlText
 * @param {Record<string, string>} [headers={}]
 * @returns {{
 *   formField: string | null,
 *   tokenValue: string | null,
 *   headerName: string | null,
 *   headerValue: string | null
 * }}
 */
export function extractCsrfTokens(htmlText = '', headers = {}) {
  const html = String(htmlText || '').slice(0, 262144);
  let formField = null;
  let tokenValue = null;
  let headerName = null;
  let headerValue = null;

  // 1. Check response headers (x-csrf-token, x-xsrf-token)
  if (headers && typeof headers === 'object') {
    for (const [k, v] of Object.entries(headers)) {
      const lower = k.toLowerCase();
      if (lower === 'x-csrf-token' || lower === 'x-xsrf-token') {
        headerName = k;
        headerValue = String(v ?? '').trim();
        tokenValue = headerValue;
      }
    }
  }

  // 2. Check <meta name="csrf-token" content="...">
  const metaMatch =
    html.match(/<meta[^>]+name=["']csrf-token["'][^>]+content=["']([^"']{6,256})["']/i) ||
    html.match(/<meta[^>]+content=["']([^"']{6,256})["'][^>]+name=["']csrf-token["']/i);
  if (metaMatch) {
    tokenValue = metaMatch[1];
    headerName = headerName || 'X-CSRF-TOKEN';
    headerValue = headerValue || metaMatch[1];
  }

  // 3. Check hidden <input> fields
  const inputRegex = /<input\b[^>]{1,300}>/gi;
  let m;
  while ((m = inputRegex.exec(html)) !== null) {
    const tag = m[0];
    const nameMatch = tag.match(/\bname=["']([^"']{1,64})["']/i);
    const valMatch = tag.match(/\bvalue=["']([^"']{4,256})["']/i);
    if (!nameMatch || !valMatch) continue;
    const fieldName = nameMatch[1];
    if (CSRF_INPUT_NAMES.includes(fieldName.toLowerCase())) {
      formField = fieldName;
      tokenValue = valMatch[1];
      headerName = headerName || 'X-CSRF-TOKEN';
      headerValue = headerValue || valMatch[1];
      break;
    }
  }

  return {
    formField,
    tokenValue,
    headerName,
    headerValue
  };
}

function decodeBasicHtmlEntities(str = '') {
  return String(str)
    .replace(/&amp;/gi, '&')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&#x27;/gi, "'")
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>');
}

function parseTagAttributes(attrText = '') {
  const attrs = {};
  const attrRegex = /([a-zA-Z_:][a-zA-Z0-9_.:-]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  let m;
  while ((m = attrRegex.exec(attrText)) !== null) {
    const key = m[1].toLowerCase();
    if (FORBIDDEN_KEYS.has(key)) continue;
    const rawVal = m[2] ?? m[3] ?? m[4] ?? '';
    if (!Object.hasOwn(attrs, key)) {
      attrs[key] = decodeBasicHtmlEntities(rawVal);
    }
  }
  return attrs;
}

function parseInputsFromHtmlSnippet(snippet = '') {
  const inputs = [];
  const inputRegex = /<input\b([^>]{0,1024})>/gi;
  let m;
  while ((m = inputRegex.exec(snippet)) !== null) {
    const cleanAttrText = String(m[1] || '').replace(/\/\s*$/, '');
    const attrs = parseTagAttributes(cleanAttrText);
    inputs.push({
      type: String(attrs.type || 'text').trim().toLowerCase(),
      name: String(attrs.name || '').trim(),
      value: attrs.value !== undefined ? String(attrs.value) : ''
    });
  }
  return inputs;
}

function extractFormBlocks(html = '') {
  const forms = [];
  const lowerHtml = html.toLowerCase();
  const formOpenRe = /<form\b([^>]{0,2048})>/gi;
  let m;
  while ((m = formOpenRe.exec(html)) !== null) {
    const cleanAttrText = String(m[1] || '').replace(/\/\s*$/, '');
    const attrs = parseTagAttributes(cleanAttrText);
    const bodyStart = m.index + m[0].length;
    const closeIdx = lowerHtml.indexOf('</form>', bodyStart);
    const nextFormIdx = lowerHtml.indexOf('<form', bodyStart);
    let bodyEnd = html.length;
    if (closeIdx !== -1 && (nextFormIdx === -1 || closeIdx < nextFormIdx)) {
      bodyEnd = bodyStart + closeIdx;
    } else if (nextFormIdx !== -1) {
      bodyEnd = bodyStart + nextFormIdx;
    }
    forms.push({
      attrs,
      inputs: parseInputsFromHtmlSnippet(html.slice(bodyStart, bodyEnd))
    });
  }
  return forms;
}

function resolveSameOriginActionUrl(rawAction = '', pageUrl = '') {
  const action = String(rawAction || '').trim();
  const baseStr = String(pageUrl || '').trim();

  if (!baseStr) {
    if (!action || action === '#') return '';
    try {
      const parsed = new URL(action);
      if ((parsed.protocol === 'http:' || parsed.protocol === 'https:') && !parsed.username && !parsed.password) {
        return parsed.toString();
      }
    } catch {}
    return /^(?:javascript|data|vbscript):/i.test(action) ? '' : action;
  }

  let baseUrl;
  try {
    baseUrl = new URL(baseStr);
  } catch {
    return baseStr;
  }

  if (!action || action === '#') {
    return baseUrl.toString();
  }

  try {
    const resolved = new URL(action, baseUrl);
    if (
      (resolved.protocol === 'http:' || resolved.protocol === 'https:') &&
      resolved.origin === baseUrl.origin &&
      !resolved.username &&
      !resolved.password
    ) {
      return resolved.toString();
    }
  } catch {}

  return baseUrl.toString();
}

function pickUsernameField(inputs) {
  const candidates = inputs.filter(i => i.name && !NON_TEXT_INPUT_TYPES.has(i.type));
  for (const inp of candidates) {
    if (USERNAME_FIELD_EXACT.has(inp.name.toLowerCase())) {
      return inp.name;
    }
  }
  const tokenRe = /(?:^|[_\-\[\].$])(email|username|user_login|user|login|userid|user_id|account)(?:$|[_\-\[\].$])/i;
  for (const inp of candidates) {
    if (tokenRe.test(inp.name) || /email|username|user_login|userid|account/i.test(inp.name)) {
      return inp.name;
    }
  }
  for (const inp of candidates) {
    if (inp.type === 'email') {
      return inp.name;
    }
  }
  return 'username';
}

function pickPasswordField(inputs) {
  for (const inp of inputs) {
    if (inp.type === 'password' && inp.name) {
      return inp.name;
    }
  }
  const candidates = inputs.filter(i => i.name && i.type !== 'hidden' && !NON_TEXT_INPUT_TYPES.has(i.type));
  for (const inp of candidates) {
    if (PASSWORD_FIELD_EXACT.has(inp.name.toLowerCase())) {
      return inp.name;
    }
  }
  const passRe = /(?:^|[_\-\[\].$])(password|pass|pwd|user_pass)(?:$|[_\-\[\].$])/i;
  for (const inp of candidates) {
    if (passRe.test(inp.name)) {
      return inp.name;
    }
  }
  return 'password';
}

function resolveJsonPath(obj, dotPath) {
  if (!obj || typeof obj !== 'object' || !dotPath) return null;
  const parts = String(dotPath).split('.').filter(Boolean);
  let cur = obj;
  for (const key of parts) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') return null;
    if (!cur || typeof cur !== 'object' || !Object.hasOwn(cur, key)) return null;
    cur = cur[key];
  }
  return cur;
}

/**
 * Parses HTML for a `<form>` containing `<input type="password">` (or falls back
 * to `<input>` elements in the page) and extracts login form metadata safely.
 *
 * @param {string} [htmlText='']
 * @param {string} [pageUrl='']
 * @returns {{
 *   actionUrl: string,
 *   method: string,
 *   usernameField: string,
 *   passwordField: string,
 *   hiddenFields: Record<string, string>,
 *   hasPasswordInput: boolean
 * }}
 */
export function parseLoginFormHtml(htmlText = '', pageUrl = '') {
  const html = String(htmlText || '').slice(0, 262144);
  const forms = extractFormBlocks(html);
  const loginForm = forms.find(f => f.inputs.some(i => i.type === 'password')) || null;

  const inspectedInputs = loginForm ? loginForm.inputs : parseInputsFromHtmlSnippet(html);
  const hasPasswordInput = inspectedInputs.some(i => i.type === 'password');

  const rawMethod = String(loginForm?.attrs?.method || 'POST').trim().toUpperCase();
  const method = rawMethod === 'GET' || rawMethod === 'POST' ? rawMethod : 'POST';
  const actionUrl = resolveSameOriginActionUrl(loginForm?.attrs?.action || '', pageUrl);
  const usernameField = pickUsernameField(inspectedInputs);
  const passwordField = pickPasswordField(inspectedInputs);

  const hiddenFields = {};
  for (const inp of inspectedInputs) {
    if (
      inp.type === 'hidden' &&
      inp.name &&
      inp.name !== '__proto__' &&
      inp.name !== 'constructor' &&
      inp.name !== 'prototype'
    ) {
      hiddenFields[inp.name] = inp.value ?? '';
    }
  }

  return {
    actionUrl,
    method,
    usernameField,
    passwordField,
    hiddenFields,
    hasPasswordInput
  };
}

/**
 * Auto-discovers the login endpoint on `targetUrl` and performs login using
 * `AuthSessionManager`.
 *
 * @param {string} targetUrl
 * @param {Function} fetchWithRetry
 * @param {object} [options={}]
 * @returns {Promise<object>}
 */
export async function discoverAndLogin(targetUrl, fetchWithRetry, options = {}) {
  const mgr = new AuthSessionManager({ ...options, targetUrl });
  const outcome = await mgr.executeLoginMacro(fetchWithRetry);
  return {
    ...outcome,
    manager: mgr,
    session: mgr.getRecordedSession({ includeSecrets: false })
  };
}

/**
 * Decodes an RFC 4648 Base32-encoded string (case-insensitive, ignoring spaces,
 * hyphens, and trailing `=` padding) into a `Buffer`.
 *
 * @param {string} input
 * @returns {Buffer}
 */
export function decodeBase32(input) {
  if (input === null || input === undefined) {
    throw new Error('Base32 secret is empty');
  }
  const normalized = String(input)
    .toUpperCase()
    .replace(/[\s-]+/g, '')
    .replace(/=+$/g, '');

  if (!normalized) {
    throw new Error('Base32 secret is empty');
  }

  const invalidMatch = normalized.match(/[^A-Z2-7]/);
  if (invalidMatch) {
    throw new Error(`Invalid Base32 character '${invalidMatch[0]}' in secret`);
  }

  let bits = 0;
  let value = 0;
  const bytes = [];

  for (let i = 0; i < normalized.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(normalized[i]);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
      value &= (1 << bits) - 1;
    }
  }

  if (bytes.length === 0) {
    throw new Error('Base32 secret is too short to decode');
  }

  return Buffer.from(bytes);
}

function resolveTotpAlgorithm(rawAlgorithm = 'SHA1') {
  const key = String(rawAlgorithm ?? 'SHA1').trim().toUpperCase();
  const entry = TOTP_ALGORITHM_MAP[key];
  if (!entry) {
    throw new Error(`Unsupported TOTP algorithm '${rawAlgorithm}'; expected SHA1, SHA256, or SHA512`);
  }
  return entry;
}

/**
 * Computes an RFC 6238 TOTP (via RFC 4226 HOTP dynamic truncation) one-time code
 * using pure Node `crypto.createHmac`.
 *
 * @param {string | { secret: string, digits?: number, period?: number, algorithm?: string, timestamp?: number }} secretOrConfig
 * @param {{ secret?: string, digits?: number, period?: number, algorithm?: string, timestamp?: number }} [options={}]
 * @returns {{ code: string, digits: number, period: number, algorithm: string, counter: number, remainingSeconds: number }}
 */
export function generateTotpCode(secretOrConfig, options = {}) {
  const isConfigObj = secretOrConfig !== null && typeof secretOrConfig === 'object' && !Array.isArray(secretOrConfig);
  const opts = options && typeof options === 'object' && !Array.isArray(options) ? options : {};

  const secret = isConfigObj ? (opts.secret ?? secretOrConfig.secret) : secretOrConfig;
  const rawDigits = opts.digits ?? (isConfigObj ? secretOrConfig.digits : undefined) ?? 6;
  const rawPeriod = opts.period ?? (isConfigObj ? secretOrConfig.period : undefined) ?? 30;
  const rawAlgorithm = opts.algorithm ?? (isConfigObj ? secretOrConfig.algorithm : undefined) ?? 'SHA1';
  const rawTimestamp = opts.timestamp ?? (isConfigObj ? secretOrConfig.timestamp : undefined) ?? Date.now();

  const digits = Number(rawDigits);
  if (digits !== 6 && digits !== 8) {
    throw new Error(`Invalid TOTP digits '${rawDigits}'; expected 6 or 8`);
  }

  const period = Number(rawPeriod);
  if (!Number.isInteger(period) || period < 15 || period > 120) {
    throw new Error(`Invalid TOTP period '${rawPeriod}'; expected an integer between 15 and 120 seconds`);
  }

  const { label: algorithm, nodeAlg } = resolveTotpAlgorithm(rawAlgorithm);

  const timestamp = Number(rawTimestamp);
  if (!Number.isFinite(timestamp) || timestamp < 0) {
    throw new Error(`Invalid TOTP timestamp '${rawTimestamp}'`);
  }

  const keyBuffer = decodeBase32(secret);
  const epochSeconds = Math.floor(timestamp / 1000);
  const counter = Math.floor(epochSeconds / period);
  const remainingSeconds = period - (epochSeconds % period);

  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));

  const hmac = crypto.createHmac(nodeAlg, keyBuffer).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const code = String(binary % (10 ** digits)).padStart(digits, '0');

  return {
    code,
    digits,
    period,
    algorithm,
    counter,
    remainingSeconds
  };
}

function stripNonDomBlocks(html = '') {
  const lower = html.toLowerCase();
  const chunks = [];
  let i = 0;

  while (i < html.length) {
    const lt = html.indexOf('<', i);
    if (lt === -1) {
      chunks.push(html.slice(i));
      break;
    }
    if (lt > i) {
      chunks.push(html.slice(i, lt));
    }

    if (html.startsWith('<!--', lt)) {
      const end = html.indexOf('-->', lt + 4);
      if (end === -1) break;
      i = end + 3;
      continue;
    }

    if (lower.startsWith('<script', lt) && (lt + 7 === html.length || /[\s>/]/.test(html[lt + 7]))) {
      const openEnd = html.indexOf('>', lt + 7);
      if (openEnd === -1) break;
      const closeIdx = lower.indexOf('</script', openEnd + 1);
      if (closeIdx === -1) break;
      const closeEnd = html.indexOf('>', closeIdx + 8);
      i = closeEnd === -1 ? html.length : closeEnd + 1;
      continue;
    }

    if (lower.startsWith('<style', lt) && (lt + 6 === html.length || /[\s>/]/.test(html[lt + 6]))) {
      const openEnd = html.indexOf('>', lt + 6);
      if (openEnd === -1) break;
      const closeIdx = lower.indexOf('</style', openEnd + 1);
      if (closeIdx === -1) break;
      const closeEnd = html.indexOf('>', closeIdx + 7);
      i = closeEnd === -1 ? html.length : closeEnd + 1;
      continue;
    }

    chunks.push('<');
    i = lt + 1;
  }

  return chunks.join('');
}

function stripHtmlTags(snippet = '') {
  const clean = String(snippet || '').replace(/<[^>]{0,1024}>/g, ' ');
  return decodeBasicHtmlEntities(clean).replace(/\s+/g, ' ').trim();
}

function extractHtmlTitle(cleanHtml = '') {
  const lower = cleanHtml.toLowerCase();
  let searchFrom = 0;
  while (searchFrom < lower.length) {
    const startIdx = lower.indexOf('<title', searchFrom);
    if (startIdx === -1) return '';
    const nextChar = lower[startIdx + 6];
    if (nextChar && !/[\s>]/.test(nextChar)) {
      searchFrom = startIdx + 6;
      continue;
    }
    const openEnd = cleanHtml.indexOf('>', startIdx + 6);
    if (openEnd === -1) return '';
    const closeIdx = lower.indexOf('</title>', openEnd + 1);
    if (closeIdx === -1) return '';
    return stripHtmlTags(cleanHtml.slice(openEnd + 1, closeIdx));
  }
  return '';
}

function parseSelectedOptionValue(selectInnerHtml = '') {
  const optRegex = /<option\b([^>]{0,1024})>([\s\S]{0,1024}?)(?=<\/option>|<option\b|$)/gi;
  let firstVal = null;
  let m;
  while ((m = optRegex.exec(selectInnerHtml)) !== null) {
    const attrs = parseTagAttributes(m[1] || '');
    const optVal = attrs.value !== undefined ? String(attrs.value) : stripHtmlTags(m[2] || '');
    if (firstVal === null) firstVal = optVal;
    if (Object.hasOwn(attrs, 'selected')) {
      return optVal;
    }
  }
  return firstVal ?? '';
}

function isOtpInputCandidate(attrs, labelText, inputType) {
  if (OTP_NON_CANDIDATE_TYPES.has(inputType)) return false;
  const autocomplete = String(attrs.autocomplete || '').trim().toLowerCase();
  if (autocomplete === 'one-time-code') return true;
  const candidates = [
    attrs.id || '',
    attrs.name || '',
    attrs.placeholder || '',
    labelText || ''
  ];
  for (const raw of candidates) {
    if (!raw) continue;
    const camelSplit = String(raw).replace(/([a-z0-9])([A-Z])/g, '$1 $2');
    if (OTP_FIELD_TOKEN_RE.test(raw) || OTP_FIELD_TOKEN_RE.test(camelSplit)) {
      return true;
    }
  }
  return false;
}

function escapeCssAttrVal(val = '') {
  return String(val).replace(/["\\]/g, '');
}

function buildInputDescriptor({ tagName, attrs, label, value, formIndex }) {
  const id = String(attrs.id || '').trim();
  const name = String(attrs.name || '').trim();
  const placeholder = String(attrs.placeholder || '').trim();
  const type = tagName === 'input'
    ? String(attrs.type || 'text').trim().toLowerCase()
    : tagName;
  const isPassword = type === 'password';
  const isOtpCandidate = isOtpInputCandidate(attrs, label, type);

  let selectorType;
  let selectorValue;
  if (id) {
    selectorType = 'id';
    selectorValue = id;
  } else if (name) {
    selectorType = 'name';
    selectorValue = name;
  } else {
    selectorType = 'css';
    if (tagName === 'select' || tagName === 'textarea') {
      selectorValue = placeholder ? `${tagName}[placeholder="${escapeCssAttrVal(placeholder)}"]` : tagName;
    } else {
      selectorValue = placeholder
        ? `input[type="${escapeCssAttrVal(type)}"][placeholder="${escapeCssAttrVal(placeholder)}"]`
        : `input[type="${escapeCssAttrVal(type)}"]`;
    }
  }

  const primary = label || placeholder || name || id || type;
  const hint = id ? `#${id}` : (name ? `[name=${name}]` : type);
  const displayLabel = primary === id || primary === name
    ? `${primary} (${type})`
    : `${primary} (${hint})`;

  return {
    id,
    name,
    type,
    placeholder,
    label,
    value,
    formIndex,
    isPassword,
    isOtpCandidate,
    selectorType,
    selectorValue,
    displayLabel
  };
}

function buildButtonDescriptor({ tagName, attrs, text, formIndex }) {
  const id = String(attrs.id || '').trim();
  const name = String(attrs.name || '').trim();
  const type = tagName === 'button'
    ? String(attrs.type || 'submit').trim().toLowerCase()
    : String(attrs.type || 'submit').trim().toLowerCase();
  const cleanText = String(text || '').trim();

  let selectorType;
  let selectorValue;
  if (id) {
    selectorType = 'id';
    selectorValue = id;
  } else if (name) {
    selectorType = 'name';
    selectorValue = name;
  } else if (cleanText) {
    selectorType = 'text';
    selectorValue = cleanText;
  } else {
    selectorType = 'css';
    selectorValue = `${tagName}[type="${escapeCssAttrVal(type)}"]`;
  }

  const displayLabel = cleanText
    ? `${cleanText}${id ? ` (#${id})` : (name ? ` ([name=${name}])` : '')}`
    : (id ? `#${id} (${type})` : (name ? `[name=${name}] (${type})` : `${type} button`));

  return {
    id,
    name,
    type,
    text: cleanText,
    formIndex,
    selectorType,
    selectorValue,
    displayLabel
  };
}

/**
 * Safely parses up to 256 KB of HTML without executing scripts and inspects
 * title, CSRF tokens, forms, inputs (`<input>`, `<select>`, `<textarea>`),
 * and clickable buttons (`<button>`, `<input type="submit|button">`).
 *
 * @param {string} [htmlText='']
 * @param {string} [pageUrl='']
 * @returns {{
 *   pageUrl: string,
 *   title: string,
 *   csrf: object,
 *   forms: Array<object>,
 *   inputs: Array<object>,
 *   buttons: Array<object>,
 *   hasPasswordInput: boolean,
 *   hasMfaOrOtpField: boolean
 * }}
 */
export function inspectLoginPageDom(htmlText = '', pageUrl = '') {
  const rawHtml = String(htmlText || '').slice(0, MAX_INSPECT_HTML_BYTES);
  const cleanHtml = stripNonDomBlocks(rawHtml);
  const lowerClean = cleanHtml.toLowerCase();

  const title = extractHtmlTitle(cleanHtml);
  const csrf = extractCsrfTokens(cleanHtml);

  const labelByFor = new Map();
  const labelRegex = /<label\b([^>]{0,2048})>/gi;
  let lm;
  while ((lm = labelRegex.exec(cleanHtml)) !== null) {
    const attrs = parseTagAttributes(String(lm[1] || '').replace(/\/\s*$/, ''));
    if (!attrs.for) continue;
    const innerStart = lm.index + lm[0].length;
    const closeIdx = lowerClean.indexOf('</label>', innerStart);
    if (closeIdx === -1) continue;
    const nextLabelIdx = lowerClean.indexOf('<label', innerStart);
    if (nextLabelIdx !== -1 && nextLabelIdx < closeIdx) continue;
    const text = stripHtmlTags(cleanHtml.slice(innerStart, closeIdx));
    if (text && !labelByFor.has(attrs.for)) {
      labelByFor.set(attrs.for, text);
    }
  }

  const forms = [];
  const formIdToIndex = new Map();
  const inputs = [];
  const buttons = [];

  let activeFormIndex = -1;
  let activeLabelEnd = -1;
  let activeLabelText = '';
  let activeLabelFor = '';

  const tagRegex = /<(\/?)([a-zA-Z][a-zA-Z0-9-]*)\b([^>]{0,2048})>/g;
  let tm;
  while ((tm = tagRegex.exec(cleanHtml)) !== null) {
    const isClosing = tm[1] === '/';
    const tagName = tm[2].toLowerCase();
    const tagEnd = tm.index + tm[0].length;

    if (tm.index >= activeLabelEnd) {
      activeLabelEnd = -1;
      activeLabelText = '';
      activeLabelFor = '';
    }

    if (tagName === 'form') {
      if (isClosing) {
        activeFormIndex = -1;
      } else {
        const cleanAttrs = String(tm[3] || '').replace(/\/\s*$/, '');
        const attrs = parseTagAttributes(cleanAttrs);
        const rawMethod = String(attrs.method || 'POST').trim().toUpperCase();
        const method = rawMethod === 'GET' || rawMethod === 'POST' ? rawMethod : 'POST';
        const formIndex = forms.length;
        const formObj = {
          formIndex,
          id: String(attrs.id || '').trim(),
          name: String(attrs.name || '').trim(),
          action: String(attrs.action || '').trim(),
          actionUrl: resolveSameOriginActionUrl(attrs.action || '', pageUrl),
          method,
          enctype: String(attrs.enctype || 'application/x-www-form-urlencoded').trim().toLowerCase(),
          inputCount: 0,
          hasPasswordInput: false,
          hiddenFields: {}
        };
        forms.push(formObj);
        activeFormIndex = formIndex;
        if (formObj.id && !formIdToIndex.has(formObj.id)) {
          formIdToIndex.set(formObj.id, formIndex);
        }
      }
      continue;
    }

    if (tagName === 'label') {
      if (isClosing) {
        activeLabelEnd = -1;
        activeLabelText = '';
        activeLabelFor = '';
      } else {
        const cleanAttrs = String(tm[3] || '').replace(/\/\s*$/, '');
        const attrs = parseTagAttributes(cleanAttrs);
        const closeIdx = lowerClean.indexOf('</label>', tagEnd);
        const nextLabelIdx = lowerClean.indexOf('<label', tagEnd);
        if (closeIdx !== -1 && (nextLabelIdx === -1 || closeIdx < nextLabelIdx)) {
          activeLabelEnd = closeIdx;
          activeLabelText = stripHtmlTags(cleanHtml.slice(tagEnd, closeIdx));
          activeLabelFor = String(attrs.for || '').trim();
        }
      }
      continue;
    }

    if (isClosing) continue;

    if (tagName === 'input') {
      const cleanAttrs = String(tm[3] || '').replace(/\/\s*$/, '');
      const attrs = parseTagAttributes(cleanAttrs);
      const rawType = String(attrs.type || 'text').trim().toLowerCase();
      const formIndex = (attrs.form && formIdToIndex.has(attrs.form))
        ? formIdToIndex.get(attrs.form)
        : activeFormIndex;

      if (rawType === 'submit' || rawType === 'button') {
        const btnText = attrs.value !== undefined
          ? String(attrs.value).trim()
          : String(attrs['aria-label'] || '').trim();
        buttons.push(buildButtonDescriptor({ tagName: 'input', attrs, text: btnText, formIndex }));
        continue;
      }

      const id = String(attrs.id || '').trim();
      const label = (id && labelByFor.get(id)) ||
        (tm.index < activeLabelEnd && (!activeLabelFor || activeLabelFor === id) ? activeLabelText : '') ||
        String(attrs['aria-label'] || '').trim();
      const value = attrs.value !== undefined ? String(attrs.value) : '';
      const desc = buildInputDescriptor({ tagName: 'input', attrs, label, value, formIndex });
      inputs.push(desc);

      if (formIndex >= 0 && forms[formIndex]) {
        forms[formIndex].inputCount += 1;
        if (desc.isPassword) forms[formIndex].hasPasswordInput = true;
        if (desc.type === 'hidden' && desc.name && !FORBIDDEN_KEYS.has(desc.name)) {
          forms[formIndex].hiddenFields[desc.name] = value;
        }
      }
      continue;
    }

    if (tagName === 'select') {
      const cleanAttrs = String(tm[3] || '').replace(/\/\s*$/, '');
      const attrs = parseTagAttributes(cleanAttrs);
      const formIndex = (attrs.form && formIdToIndex.has(attrs.form))
        ? formIdToIndex.get(attrs.form)
        : activeFormIndex;
      const closeIdx = lowerClean.indexOf('</select>', tagEnd);
      const inner = closeIdx !== -1 ? cleanHtml.slice(tagEnd, closeIdx) : '';
      const id = String(attrs.id || '').trim();
      const label = (id && labelByFor.get(id)) ||
        (tm.index < activeLabelEnd && (!activeLabelFor || activeLabelFor === id) ? activeLabelText : '') ||
        String(attrs['aria-label'] || '').trim();
      const value = parseSelectedOptionValue(inner);
      inputs.push(buildInputDescriptor({ tagName: 'select', attrs, label, value, formIndex }));
      if (formIndex >= 0 && forms[formIndex]) {
        forms[formIndex].inputCount += 1;
      }
      if (closeIdx !== -1) {
        tagRegex.lastIndex = closeIdx + 9;
      }
      continue;
    }

    if (tagName === 'textarea') {
      const cleanAttrs = String(tm[3] || '').replace(/\/\s*$/, '');
      const attrs = parseTagAttributes(cleanAttrs);
      const formIndex = (attrs.form && formIdToIndex.has(attrs.form))
        ? formIdToIndex.get(attrs.form)
        : activeFormIndex;
      const closeIdx = lowerClean.indexOf('</textarea>', tagEnd);
      const value = closeIdx !== -1 ? decodeBasicHtmlEntities(cleanHtml.slice(tagEnd, closeIdx)) : '';
      const id = String(attrs.id || '').trim();
      const label = (id && labelByFor.get(id)) ||
        (tm.index < activeLabelEnd && (!activeLabelFor || activeLabelFor === id) ? activeLabelText : '') ||
        String(attrs['aria-label'] || '').trim();
      inputs.push(buildInputDescriptor({ tagName: 'textarea', attrs, label, value, formIndex }));
      if (formIndex >= 0 && forms[formIndex]) {
        forms[formIndex].inputCount += 1;
      }
      if (closeIdx !== -1) {
        tagRegex.lastIndex = closeIdx + 11;
      }
      continue;
    }

    if (tagName === 'button') {
      const cleanAttrs = String(tm[3] || '').replace(/\/\s*$/, '');
      const attrs = parseTagAttributes(cleanAttrs);
      const formIndex = (attrs.form && formIdToIndex.has(attrs.form))
        ? formIdToIndex.get(attrs.form)
        : activeFormIndex;
      const closeIdx = lowerClean.indexOf('</button>', tagEnd);
      const text = closeIdx !== -1
        ? stripHtmlTags(cleanHtml.slice(tagEnd, closeIdx))
        : String(attrs.value || attrs['aria-label'] || '').trim();
      buttons.push(buildButtonDescriptor({ tagName: 'button', attrs, text, formIndex }));
      if (closeIdx !== -1) {
        tagRegex.lastIndex = closeIdx + 9;
      }
    }
  }

  return {
    pageUrl: String(pageUrl || ''),
    title,
    csrf,
    forms,
    inputs,
    buttons,
    hasPasswordInput: inputs.some(i => i.isPassword),
    hasMfaOrOtpField: inputs.some(i => i.isOtpCandidate)
  };
}

const LOGIN_ERROR_BANNER_CLASS_RE = /(?:^|\s)(?!no-error\b)(?:[a-z0-9_-]*error[a-z0-9_-]*|alert-danger|invalid-feedback)(?:$|\s)/i;
const LOGIN_ERROR_VISIBLE_TEXT_RE = /(?:invalid|incorrect|wrong)\s+(?:username|user|email|password|credentials|otp|totp|verification\s+code|login)|authentication\s+failed|login\s+failed|account\s+locked/i;

function findBalancedClosingTagIndex(cleanHtml, lowerClean, tagName, innerStart, maxScanBytes = 4096) {
  const openToken = `<${tagName}`;
  const closeToken = `</${tagName}>`;
  const limit = Math.min(cleanHtml.length, innerStart + maxScanBytes);
  let depth = 1;
  let pos = innerStart;

  while (pos < limit) {
    const nextOpen = lowerClean.indexOf(openToken, pos);
    const nextClose = lowerClean.indexOf(closeToken, pos);
    if (nextClose === -1 || nextClose >= limit) return -1;
    if (nextOpen !== -1 && nextOpen < nextClose) {
      const charAfter = lowerClean[nextOpen + openToken.length];
      if (!charAfter || /[\s>/]/.test(charAfter)) {
        depth += 1;
      }
      pos = nextOpen + openToken.length;
    } else {
      depth -= 1;
      if (depth === 0) return nextClose;
      pos = nextClose + closeToken.length;
    }
  }
  return -1;
}

/**
 * Inspects JSON or HTML responses for common authentication failure messages,
 * returning a cleaned concise error string (<= 200 chars) or `null`.
 *
 * @param {string} [text='']
 * @param {number} [status=200]
 * @returns {string | null}
 */
export function extractLoginErrorFromResponse(text = '', status = 200) {
  const raw = String(text ?? '');
  const trimmed = raw.trim();
  if (!trimmed) return null;
  const httpStatus = Number(status || 0);

  if (trimmed.startsWith('{')) {
    try {
      const json = JSON.parse(trimmed.slice(0, MAX_INSPECT_HTML_BYTES));
      if (json && typeof json === 'object' && !Array.isArray(json)) {
        let candidate = null;
        if (typeof json.error === 'string' && json.error.trim()) {
          candidate = json.error;
        } else if (
          typeof json.message === 'string' &&
          json.message.trim() &&
          (httpStatus >= 400 || json.ok === false || json.authenticated === false)
        ) {
          candidate = json.message;
        }
        if (candidate) {
          const cleaned = candidate.replace(/\s+/g, ' ').trim().slice(0, 200);
          return cleaned || null;
        }
      }
    } catch {
      // Non-JSON or malformed JSON
    }
    return null;
  }

  const cleanHtml = stripNonDomBlocks(raw.slice(0, MAX_INSPECT_HTML_BYTES));
  const lowerClean = cleanHtml.toLowerCase();

  const errorTagRegex = /<(div|p|span|li|section|aside|strong|small|em|b|h[1-6]|label)\b([^>]{0,2048})>/gi;
  let m;
  while ((m = errorTagRegex.exec(cleanHtml)) !== null) {
    const tagName = m[1].toLowerCase();
    const attrs = parseTagAttributes(String(m[2] || '').replace(/\/\s*$/, ''));
    const cls = String(attrs.class || '');
    const role = String(attrs.role || '').trim().toLowerCase();
    const style = String(attrs.style || '');

    const isAlertRole = role === 'alert';
    const isErrorClass = Boolean(cls && LOGIN_ERROR_BANNER_CLASS_RE.test(cls));
    if (!isAlertRole && !isErrorClass) continue;

    if (
      Object.hasOwn(attrs, 'hidden') ||
      /(?:^|\s)(?:hidden|d-none|is-hidden)(?:$|\s)/i.test(cls) ||
      /display\s*:\s*none|visibility\s*:\s*hidden/i.test(style)
    ) {
      continue;
    }

    const innerStart = m.index + m[0].length;
    const closeIdx = findBalancedClosingTagIndex(cleanHtml, lowerClean, tagName, innerStart);
    if (closeIdx === -1) continue;

    const innerHtml = cleanHtml.slice(innerStart, closeIdx);
    if (/<(?:form|input|select|textarea)\b/i.test(innerHtml)) continue;

    const cleanText = stripHtmlTags(innerHtml);
    if (cleanText && cleanText.length >= 2) {
      return cleanText.slice(0, 200);
    }
  }

  const blockText = cleanHtml
    .replace(/<\/?(?:div|p|li|td|th|tr|h[1-6]|br|hr|form|fieldset|section|article|header|footer|nav|main|aside|ul|ol|table|blockquote|pre)\b[^>]*>/gi, '\n');
  for (const line of blockText.split(/\r?\n/)) {
    const cleanLine = stripHtmlTags(line);
    if (!cleanLine) continue;
    const match = cleanLine.match(LOGIN_ERROR_VISIBLE_TEXT_RE);
    if (match) {
      if (cleanLine.length <= 200) return cleanLine;
      const idx = Math.max(0, (match.index || 0) - 40);
      return cleanLine.slice(idx, idx + 200).trim();
    }
  }

  return null;
}

function sanitizePlainObject(obj, depth = 0) {
  if (depth > 8 || obj === null || typeof obj !== 'object') return null;
  if (Array.isArray(obj)) {
    return obj.slice(0, 100).map(item =>
      (item !== null && typeof item === 'object') ? sanitizePlainObject(item, depth + 1) : item
    );
  }
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (FORBIDDEN_KEYS.has(k)) continue;
    if (v !== null && typeof v === 'object') {
      out[k] = sanitizePlainObject(v, depth + 1);
    } else {
      out[k] = v;
    }
  }
  return out;
}

function sanitizeStringHeaders(headers = {}) {
  const out = {};
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) return out;
  for (const [k, v] of Object.entries(headers)) {
    if (FORBIDDEN_KEYS.has(k)) continue;
    const key = String(k || '').trim();
    if (!key || /[\r\n]/.test(key)) continue;
    const val = String(v ?? '').replace(/[\r\n]+/g, ' ');
    out[key] = val;
  }
  return out;
}

function normalizeSequenceName(rawName) {
  const trimmed = typeof rawName === 'string' ? rawName.replace(/[\r\n]+/g, '').trim() : '';
  if (!trimmed) return 'LoginSequence.lsr';
  if (/\.[a-zA-Z][a-zA-Z0-9]{0,7}$/.test(trimmed)) return trimmed;
  return `${trimmed}.lsr`;
}

function normalizeSecretsList(rawSecrets) {
  const map = new Map();
  if (Array.isArray(rawSecrets)) {
    for (const entry of rawSecrets) {
      if (!entry || typeof entry !== 'object') continue;
      const name = String(entry.name || '').trim();
      if (!name || FORBIDDEN_KEYS.has(name)) continue;
      const value = entry.value !== undefined && entry.value !== null ? String(entry.value) : '';
      const description = typeof entry.description === 'string' ? entry.description.trim() : '';
      if (map.has(name) && (value === '[SECRET]' || value === '[REDACTED]') && map.get(name).value) {
        continue;
      }
      map.set(name, { name, value, description });
      if (map.size >= MAX_SECRETS) break;
    }
  } else if (rawSecrets && typeof rawSecrets === 'object') {
    for (const [k, v] of Object.entries(rawSecrets)) {
      const name = String(k || '').trim();
      if (!name || FORBIDDEN_KEYS.has(name)) continue;
      const value = v !== undefined && v !== null ? String(v) : '';
      map.set(name, { name, value, description: '' });
      if (map.size >= MAX_SECRETS) break;
    }
  }
  return Array.from(map.values());
}

function normalizeSingleSystemVariable(rawName, rawEntry, existingMap) {
  const name = String(rawName || '').trim();
  if (!name || FORBIDDEN_KEYS.has(name)) return;

  const isObj = rawEntry !== null && typeof rawEntry === 'object' && !Array.isArray(rawEntry);
  const entry = isObj ? rawEntry : { value: rawEntry };

  const rawValue = entry.value !== undefined && entry.value !== null ? String(entry.value) : '';
  const prev = existingMap.get(name);
  const value = ((rawValue === '[SECRET]' || rawValue === '[REDACTED]') && prev && prev.value)
    ? prev.value
    : rawValue;

  const rawCat = typeof entry.category === 'string' ? entry.category.trim().toLowerCase() : '';
  const category = SYSTEM_VARIABLE_CATEGORIES.has(rawCat)
    ? rawCat
    : (prev?.category || 'custom');

  let isSecret;
  if (entry.isSecret === false) {
    isSecret = false;
  } else if (
    entry.isSecret === true ||
    SECRET_VARIABLE_CATEGORIES.has(category) ||
    SECRET_VARIABLE_NAME_RE.test(name)
  ) {
    isSecret = true;
  } else {
    isSecret = false;
  }

  const description = typeof entry.description === 'string'
    ? entry.description.trim()
    : (prev?.description || '');

  let updatedAt;
  if (typeof entry.updatedAt === 'string' && entry.updatedAt.trim() && !Number.isNaN(Date.parse(entry.updatedAt))) {
    updatedAt = new Date(entry.updatedAt).toISOString();
  } else {
    updatedAt = new Date().toISOString();
  }

  existingMap.set(name, {
    name,
    value,
    isSecret,
    category,
    description,
    updatedAt
  });
}

/**
 * Normalizes a System Variables collection (array, `Map`, or plain object) into a
 * canonical array of `{ name, value, isSecret, category, description, updatedAt }`.
 *
 * @param {Array<object> | Map<string, any> | Record<string, any>} [rawVars=[]]
 * @returns {Array<{
 *   name: string,
 *   value: string,
 *   isSecret: boolean,
 *   category: 'username' | 'password' | 'otp_seed' | 'url' | 'token' | 'custom',
 *   description: string,
 *   updatedAt: string
 * }>}
 */
export function normalizeSystemVariables(rawVars = []) {
  const map = new Map();
  if (rawVars instanceof Map) {
    for (const [k, v] of rawVars.entries()) {
      const varName = (v !== null && typeof v === 'object' && !Array.isArray(v) && v.name) ? v.name : k;
      normalizeSingleSystemVariable(varName, v, map);
      if (map.size >= MAX_SYSTEM_VARIABLES) break;
    }
  } else if (Array.isArray(rawVars)) {
    for (const entry of rawVars) {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
      normalizeSingleSystemVariable(entry.name, entry, map);
      if (map.size >= MAX_SYSTEM_VARIABLES) break;
    }
  } else if (rawVars && typeof rawVars === 'object') {
    for (const [k, v] of Object.entries(rawVars)) {
      if (FORBIDDEN_KEYS.has(k)) continue;
      const varName = (v !== null && typeof v === 'object' && !Array.isArray(v) && v.name) ? v.name : k;
      normalizeSingleSystemVariable(varName, v, map);
      if (map.size >= MAX_SYSTEM_VARIABLES) break;
    }
  }
  return Array.from(map.values());
}

/**
 * Exports normalized System Variables, masking secret values (`'[SECRET]'`) and
 * computing `hasValue` unless `includeSecrets: true`.
 *
 * @param {Array<object> | Map<string, any> | Record<string, any>} [vars=[]]
 * @param {{ includeSecrets?: boolean }} [options={}]
 * @returns {Array<object>}
 */
export function exportSystemVariables(vars = [], { includeSecrets = false } = {}) {
  return normalizeSystemVariables(vars).map(v => {
    const hasValue = Boolean(v.value && v.value !== '[SECRET]' && v.value !== '[REDACTED]');
    return {
      name: v.name,
      value: (!includeSecrets && v.isSecret) ? '[SECRET]' : v.value,
      isSecret: Boolean(v.isSecret),
      category: v.category,
      description: v.description,
      updatedAt: v.updatedAt,
      hasValue
    };
  });
}

function normalizeOtpConfig(rawOtp = {}) {
  const src = rawOtp && typeof rawOtp === 'object' && !Array.isArray(rawOtp) ? rawOtp : {};
  const secret = typeof src.secret === 'string' ? src.secret.trim() : '';
  const secretNameRaw = typeof src.secretName === 'string' ? src.secretName.trim() : '';
  const secretName = FORBIDDEN_KEYS.has(secretNameRaw) ? '' : secretNameRaw;
  const variableNameRaw = typeof src.variableName === 'string' ? src.variableName.trim() : '';
  const variableName = FORBIDDEN_KEYS.has(variableNameRaw) ? '' : variableNameRaw;
  const digits = Number(src.digits) === 8 ? 8 : 6;
  const rawPeriod = Number(src.period);
  const period = Number.isInteger(rawPeriod) && rawPeriod >= 15 && rawPeriod <= 120 ? rawPeriod : 30;

  let algorithm = 'SHA1';
  if (src.algorithm) {
    const algKey = String(src.algorithm).trim().toUpperCase();
    if (Object.hasOwn(TOTP_ALGORITHM_MAP, algKey)) {
      algorithm = TOTP_ALGORITHM_MAP[algKey].label;
    }
  }

  const enabled = src.enabled !== undefined
    ? Boolean(src.enabled)
    : Boolean(secret || secretName || variableName);

  return {
    enabled,
    secret,
    secretName,
    ...(variableName ? { variableName } : {}),
    digits,
    period,
    algorithm,
    issuer: typeof src.issuer === 'string' ? src.issuer.trim() : '',
    label: typeof src.label === 'string' ? src.label.trim() : '',
    inputSelector: typeof src.inputSelector === 'string' ? src.inputSelector.trim() : ''
  };
}

function normalizeRestrictionsList(rawRestrictions) {
  if (!Array.isArray(rawRestrictions)) return [];
  const seen = new Set();
  const out = [];
  for (const item of rawRestrictions) {
    if (typeof item !== 'string') continue;
    const cleaned = item.replace(/[\r\n]+/g, '').trim().slice(0, MAX_RESTRICTION_LEN);
    if (!cleaned || seen.has(cleaned)) continue;
    seen.add(cleaned);
    out.push(cleaned);
    if (out.length >= MAX_RESTRICTIONS) break;
  }
  return out;
}

function normalizeSessionDetection(rawSd = {}, defaults = { statusCodes: [401, 403], redirectPattern: '/login' }) {
  const src = rawSd && typeof rawSd === 'object' && !Array.isArray(rawSd) ? rawSd : {};
  const statusCodes = Array.isArray(src.statusCodes)
    ? Array.from(new Set(src.statusCodes.map(Number).filter(n => Number.isInteger(n) && n >= 100 && n <= 599)))
    : [...(defaults.statusCodes || [401])];

  return {
    statusCodes,
    redirectPattern: src.redirectPattern !== undefined
      ? String(src.redirectPattern || '').trim().slice(0, MAX_RESTRICTION_LEN)
      : String(defaults.redirectPattern ?? ''),
    loggedOutPattern: src.loggedOutPattern !== undefined
      ? String(src.loggedOutPattern || '').trim().slice(0, MAX_RESTRICTION_LEN)
      : '',
    loggedInPattern: src.loggedInPattern !== undefined
      ? String(src.loggedInPattern || '').trim().slice(0, MAX_RESTRICTION_LEN)
      : ''
  };
}

function buildActionLabel(action) {
  switch (action.type) {
    case 'navigate':
      return `Navigate to ${action.url || '(target)'}`;
    case 'change_input': {
      const target = action.selector || action.fieldName || 'field';
      const displayVal = action.isSecret
        ? '***'
        : (action.value ||
            (action.secretName ? `{{SECRET:${action.secretName}}}` : '') ||
            (action.variableName ? `{{VAR:${action.variableName}}}` : ''));
      if (action.selectorType === 'id') {
        return `Change INPUT with id ${target.replace(/^#/, '')} to ${displayVal}`;
      }
      if (action.selectorType === 'name') {
        return `Change INPUT named ${action.fieldName || target} to ${displayVal}`;
      }
      return `Change INPUT matching ${target} to ${displayVal}`;
    }
    case 'fill_otp': {
      const target = action.selector || action.fieldName || 'auto';
      if (!target || target === 'auto') {
        return 'Fill OTP code into auto-detected MFA INPUT';
      }
      if (action.selectorType === 'id') {
        return `Fill OTP code into INPUT with id ${target.replace(/^#/, '')}`;
      }
      if (action.selectorType === 'name') {
        return `Fill OTP code into INPUT named ${action.fieldName || target}`;
      }
      return `Fill OTP code into INPUT matching ${target}`;
    }
    case 'click_button': {
      const target = action.selector || '';
      if (action.selectorType === 'id') {
        return `Click on BUTTON with id ${target.replace(/^#/, '')}`;
      }
      if (action.selectorType === 'name') {
        return `Click on BUTTON named ${target}`;
      }
      if (action.selectorType === 'text') {
        return `Click on BUTTON with text ${target || 'Submit'}`;
      }
      return `Click on BUTTON matching ${target || 'button[type=submit]'}`;
    }
    case 'extract_token': {
      const detail = action.tokenJsonPath || action.key;
      return `Extract ${action.source.toUpperCase()} token${detail ? ` (${detail})` : ''}`;
    }
    case 'custom_request':
      return `${action.method} ${action.url || '(custom request)'}`;
    default:
      return String(action.type || 'step');
  }
}

function normalizeSequenceAction(raw = {}, index = 0) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error(`Invalid login sequence action at step ${index + 1}`);
  }
  const type = String(raw.type || raw.action || '').trim().toLowerCase();
  if (!SUPPORTED_SEQUENCE_ACTIONS.has(type)) {
    throw new Error(`Unsupported login sequence action type: '${type || '(empty)'}'`);
  }

  const id = typeof raw.id === 'string' && raw.id.trim() ? raw.id.trim() : crypto.randomUUID();
  const step = index + 1;
  const description = typeof raw.description === 'string' ? raw.description.trim() : '';

  let normalized;
  if (type === 'navigate') {
    normalized = {
      id,
      step,
      type: 'navigate',
      url: String(raw.url || '').replace(/[\r\n]+/g, '').trim(),
      description
    };
  } else if (type === 'change_input') {
    const rawSelType = String(raw.selectorType || '').trim().toLowerCase();
    const selectorType = (rawSelType === 'id' || rawSelType === 'name' || rawSelType === 'css')
      ? rawSelType
      : (raw.fieldName && !raw.selector ? 'name' : 'id');
    const selector = String(raw.selector || raw.fieldName || '').trim();
    const rawFieldName = String(raw.fieldName || (selectorType === 'name' ? selector : selector.replace(/^#/, '')) || '').trim();
    const fieldName = FORBIDDEN_KEYS.has(rawFieldName) ? '' : rawFieldName;
    const value = raw.value !== undefined && raw.value !== null ? String(raw.value) : '';
    const rawSecretName = String(raw.secretName || '').trim();
    const secretName = FORBIDDEN_KEYS.has(rawSecretName) ? '' : rawSecretName;
    const rawVariableName = String(raw.variableName || '').trim();
    const variableName = FORBIDDEN_KEYS.has(rawVariableName) ? '' : rawVariableName;
    const varTemplateMatch = value.match(/^\{\{VAR:([^}]+)\}\}$/i);
    const inferredSecret = Boolean(secretName) ||
      Boolean(variableName && SECRET_VARIABLE_NAME_RE.test(variableName)) ||
      Boolean(varTemplateMatch && SECRET_VARIABLE_NAME_RE.test(varTemplateMatch[1])) ||
      /pass|pwd|secret/i.test(`${fieldName} ${selector}`) ||
      /^\{\{SECRET:[^}]+\}\}$/i.test(value);
    const isSecret = raw.isSecret !== undefined ? Boolean(raw.isSecret) : inferredSecret;
    normalized = {
      id,
      step,
      type: 'change_input',
      selectorType,
      selector,
      fieldName,
      value,
      secretName,
      ...(variableName ? { variableName } : {}),
      isSecret,
      description
    };
  } else if (type === 'fill_otp') {
    const rawSelType = String(raw.selectorType || '').trim().toLowerCase();
    const selectorType = (rawSelType === 'id' || rawSelType === 'name' || rawSelType === 'css')
      ? rawSelType
      : 'id';
    const selector = String(raw.selector || raw.fieldName || 'auto').trim() || 'auto';
    const rawFieldName = String(raw.fieldName || (selector !== 'auto' ? selector.replace(/^#/, '') : '') || '').trim();
    const fieldName = FORBIDDEN_KEYS.has(rawFieldName) ? '' : rawFieldName;
    const rawSecretName = String(raw.secretName || '').trim();
    const secretName = FORBIDDEN_KEYS.has(rawSecretName) ? '' : rawSecretName;
    const rawVariableName = String(raw.variableName || '').trim();
    const variableName = FORBIDDEN_KEYS.has(rawVariableName) ? '' : rawVariableName;
    normalized = {
      id,
      step,
      type: 'fill_otp',
      selectorType,
      selector,
      fieldName,
      secretName,
      ...(variableName ? { variableName } : {}),
      description
    };
  } else if (type === 'click_button') {
    const rawSelType = String(raw.selectorType || '').trim().toLowerCase();
    const selectorType = (rawSelType === 'id' || rawSelType === 'name' || rawSelType === 'text' || rawSelType === 'css')
      ? rawSelType
      : 'text';
    const selector = String(raw.selector || '').trim();
    const submitUrl = String(raw.submitUrl || '').replace(/[\r\n]+/g, '').trim();
    const rawMethod = String(raw.method || '').trim().toUpperCase();
    const method = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(rawMethod) ? rawMethod : '';
    const rawCt = String(raw.contentType || '').trim().toLowerCase();
    const contentType = (rawCt === 'form' || rawCt === 'json') ? rawCt : '';
    normalized = {
      id,
      step,
      type: 'click_button',
      selectorType,
      selector,
      submitUrl,
      method,
      contentType,
      description
    };
  } else if (type === 'extract_token') {
    const rawSource = String(raw.source || 'json').trim().toLowerCase();
    const source = ['json', 'header', 'cookie', 'csrf'].includes(rawSource) ? rawSource : 'json';
    const key = String(raw.key || '').trim();
    const tokenJsonPath = String(raw.tokenJsonPath || (source === 'json' ? key : '') || '').trim();
    normalized = {
      id,
      step,
      type: 'extract_token',
      source,
      key,
      tokenJsonPath,
      description
    };
  } else {
    const rawMethod = String(raw.method || 'POST').trim().toUpperCase();
    const method = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].includes(rawMethod) ? rawMethod : 'POST';
    const rawCt = String(raw.contentType || 'json').trim().toLowerCase();
    const contentType = (rawCt === 'form' || rawCt === 'raw' || rawCt === 'json') ? rawCt : 'json';
    let payload = null;
    if (typeof raw.payload === 'string') {
      payload = raw.payload;
    } else if (raw.payload !== null && typeof raw.payload === 'object') {
      payload = sanitizePlainObject(raw.payload);
    }
    normalized = {
      id,
      step,
      type: 'custom_request',
      method,
      url: String(raw.url || '').replace(/[\r\n]+/g, '').trim(),
      contentType,
      payload,
      headers: sanitizeStringHeaders(raw.headers),
      description
    };
  }

  normalized.label = buildActionLabel(normalized);
  return normalized;
}

/**
 * Normalizes a Login Sequence Recorder (`.lsr`) configuration object.
 *
 * @param {object} [rawSeq={}]
 * @param {string} [baseTargetUrl='']
 * @returns {object}
 */
export function normalizeLoginSequence(rawSeq = {}, baseTargetUrl = '') {
  const src = rawSeq && typeof rawSeq === 'object' && !Array.isArray(rawSeq) ? rawSeq : {};
  const sequenceId = typeof src.sequenceId === 'string' && src.sequenceId.trim()
    ? src.sequenceId.trim()
    : crypto.randomUUID();
  const name = normalizeSequenceName(src.name);

  let updatedAt;
  if (typeof src.updatedAt === 'string' && src.updatedAt.trim() && !Number.isNaN(Date.parse(src.updatedAt))) {
    updatedAt = new Date(src.updatedAt).toISOString();
  } else {
    updatedAt = new Date().toISOString();
  }

  const rawTarget = src.targetUrl || baseTargetUrl || null;
  const targetUrl = typeof rawTarget === 'string' && rawTarget.trim()
    ? rawTarget.replace(/[\r\n]+/g, '').trim()
    : null;

  const secrets = normalizeSecretsList(src.secrets);
  const otpConfig = normalizeOtpConfig(src.otpConfig);
  const rawActions = Array.isArray(src.actions) ? src.actions.slice(0, MAX_SEQUENCE_STEPS) : [];
  const actions = rawActions.map((act, idx) => normalizeSequenceAction(act, idx));
  const restrictions = normalizeRestrictionsList(src.restrictions);
  const sessionDetection = normalizeSessionDetection(src.sessionDetection, {
    statusCodes: [401, 403],
    redirectPattern: '/login'
  });

  return {
    sequenceId,
    name,
    updatedAt,
    targetUrl,
    secrets,
    otpConfig,
    actions,
    restrictions,
    sessionDetection
  };
}

/**
 * Parses and normalizes a `.lsr` JSON string or object into a canonical `.lsr` structure.
 *
 * @param {string | object} input
 * @returns {object}
 */
export function parseLsrSequence(input) {
  let parsed = input;
  if (typeof input === 'string') {
    const trimmed = input.trim();
    if (!trimmed) {
      throw new Error('Empty .lsr login sequence input');
    }
    try {
      parsed = JSON.parse(trimmed);
    } catch (err) {
      throw new Error(`Invalid .lsr JSON syntax: ${err.message}`);
    }
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Invalid .lsr login sequence: expected a JSON object');
  }
  return normalizeLoginSequence(parsed);
}

/**
 * Exports a normalized `.lsr` login sequence, masking vault secrets, TOTP secrets,
 * and secret step values unless `includeSecrets: true`.
 *
 * @param {object} seq
 * @param {{ includeSecrets?: boolean }} [options={}]
 * @returns {object}
 */
export function exportLsrSequence(seq, { includeSecrets = false } = {}) {
  const normalized = normalizeLoginSequence(seq || {});
  const secrets = normalized.secrets.map(s => ({
    name: s.name,
    value: includeSecrets ? s.value : '[SECRET]',
    description: s.description
  }));

  const otpSecretIsRef = /^\{\{(?:SECRET:[^}]+|VAR:[^}]+)\}\}$/i.test(normalized.otpConfig.secret || '');
  const otpConfig = {
    ...normalized.otpConfig,
    secret: normalized.otpConfig.secret
      ? (includeSecrets || otpSecretIsRef ? normalized.otpConfig.secret : '[REDACTED]')
      : ''
  };

  const actions = normalized.actions.map(act => {
    if (act.type === 'change_input') {
      const isTemplateRef = /^\{\{(?:SECRET:[^}]+|VAR:[^}]+|OTP|TOTP)\}\}$/i.test(act.value || '');
      return {
        ...act,
        value: (!includeSecrets && act.isSecret && act.value && !isTemplateRef)
          ? '[REDACTED]'
          : act.value
      };
    }
    if (act.type === 'custom_request') {
      const headers = { ...act.headers };
      if (!includeSecrets) {
        for (const k of Object.keys(headers)) {
          const kl = k.toLowerCase();
          if ((kl === 'authorization' || kl === 'cookie' || kl === 'x-api-key' || kl.includes('secret') || kl.includes('token')) &&
              !/^\{\{(?:SECRET:[^}]+|VAR:[^}]+|OTP|TOTP)\}\}$/i.test(headers[k])) {
            headers[k] = '[REDACTED]';
          }
        }
      }
      return {
        ...act,
        headers,
        payload: typeof act.payload === 'object' && act.payload !== null
          ? sanitizePlainObject(act.payload)
          : act.payload
      };
    }
    return { ...act };
  });

  return {
    ...normalized,
    secrets,
    otpConfig,
    actions
  };
}

function matchWildcardPattern(text, pattern) {
  let ti = 0;
  let pi = 0;
  let starIdx = -1;
  let matchIdx = 0;

  while (ti < text.length) {
    if (pi < pattern.length && (pattern[pi] === '?' || pattern[pi] === text[ti])) {
      ti++;
      pi++;
    } else if (pi < pattern.length && pattern[pi] === '*') {
      starIdx = pi;
      matchIdx = ti;
      pi++;
    } else if (starIdx !== -1) {
      pi = starIdx + 1;
      matchIdx++;
      ti = matchIdx;
    } else {
      return false;
    }
  }

  while (pi < pattern.length && pattern[pi] === '*') {
    pi++;
  }
  return pi === pattern.length;
}

function iterateHeaders(headers) {
  if (!headers || typeof headers !== 'object') return [];
  if (typeof headers.entries === 'function') {
    const pairs = [];
    if (typeof headers.getSetCookie === 'function') {
      for (const sc of headers.getSetCookie()) {
        pairs.push(['set-cookie', sc]);
      }
    }
    for (const [k, v] of headers.entries()) {
      if (k.toLowerCase() === 'set-cookie' && typeof headers.getSetCookie === 'function') continue;
      pairs.push([k, v]);
    }
    return pairs;
  }
  return Object.entries(headers);
}

function getHeaderCaseInsensitive(headers, targetName) {
  const lowerTarget = String(targetName || '').toLowerCase();
  for (const [k, v] of iterateHeaders(headers)) {
    if (String(k).toLowerCase() === lowerTarget) {
      return Array.isArray(v) ? v.join(', ') : String(v ?? '');
    }
  }
  return '';
}

/**
 * Stateful Authenticated Session, Cookie Jar & Login Macro Manager.
 */
export class AuthSessionManager {
  /**
   * @param {{
   *   targetUrl?: string,
   *   loginUrl?: string,
   *   loginMethod?: string,
   *   loginPayload?: object | string,
   *   loginContentType?: 'auto' | 'json' | 'form',
   *   username?: string,
   *   password?: string,
   *   usernameField?: string,
   *   passwordField?: string,
   *   tokenJsonPath?: string,
   *   staticHeaders?: Record<string, string>,
   *   maxReauthAttempts?: number,
   *   sessionId?: string,
   *   recordedSteps?: Array<object>,
   *   authenticatedAt?: string | null,
   *   loginSequence?: object | string | null,
   *   secrets?: Array<object> | Record<string, string> | Map<string, string> | null,
   *   systemVariables?: Array<object> | Record<string, any> | Map<string, any> | null,
   *   diagnostics?: Array<object>,
   *   otpConfig?: object | null,
   *   restrictions?: Array<string> | null,
   *   sessionDetection?: object | null
   * }} [config={}]
   */
  constructor(config = {}) {
    this.targetUrl = config.targetUrl ? String(config.targetUrl).trim() : null;
    this.loginUrl = config.loginUrl ? String(config.loginUrl).trim() : null;
    this._hasExplicitLoginUrl = Boolean(this.loginUrl);
    this.loginMethod = String(config.loginMethod || 'POST').toUpperCase();
    this.loginPayload = config.loginPayload ?? null;
    this.username = config.username !== undefined && config.username !== null ? String(config.username) : null;
    this.password = config.password !== undefined && config.password !== null ? String(config.password) : null;
    this.usernameField = config.usernameField ? String(config.usernameField).trim() : null;
    this.passwordField = config.passwordField ? String(config.passwordField).trim() : null;
    this.tokenJsonPath = config.tokenJsonPath ? String(config.tokenJsonPath).trim() : null;

    const rawContentType = config.loginContentType ? String(config.loginContentType).trim().toLowerCase() : '';
    this._hasExplicitContentType = (rawContentType === 'auto' || rawContentType === 'json' || rawContentType === 'form');
    if (this._hasExplicitContentType) {
      this.loginContentType = rawContentType;
    } else if (this.loginPayload !== null && this.loginPayload !== undefined) {
      this.loginContentType = 'json';
    } else if (this.username !== null || this.password !== null) {
      this.loginContentType = 'auto';
    } else {
      this.loginContentType = 'json';
    }

    this.staticHeaders = sanitizeStringHeaders(config.staticHeaders);
    this.maxReauthAttempts = Math.min(5, Math.max(1, Number(config.maxReauthAttempts) || 2));

    this.sessionId = config.sessionId ? String(config.sessionId) : crypto.randomUUID();
    this.recordedSteps = Array.isArray(config.recordedSteps)
      ? config.recordedSteps.map(s => ({ ...s }))
      : [];
    this.authenticatedAt = config.authenticatedAt || null;

    if (config.loginSequence && (typeof config.loginSequence === 'string' || typeof config.loginSequence === 'object')) {
      this.loginSequence = typeof config.loginSequence === 'string'
        ? parseLsrSequence(config.loginSequence)
        : normalizeLoginSequence(config.loginSequence, this.targetUrl || this.loginUrl || '');
      if (!this.targetUrl && this.loginSequence.targetUrl) {
        this.targetUrl = this.loginSequence.targetUrl;
      }
      if (!this.loginUrl && this.loginSequence.actions.length > 0) {
        const firstUrlStep = this.loginSequence.actions.find(
          a => (a.type === 'navigate' || a.type === 'custom_request') && a.url
        );
        if (firstUrlStep) {
          try {
            const candidate = new URL(firstUrlStep.url, this.targetUrl || undefined);
            let sameOriginAsTarget = true;
            if (this.targetUrl) {
              try {
                sameOriginAsTarget = candidate.origin === new URL(this.targetUrl).origin;
              } catch {
                sameOriginAsTarget = false;
              }
            }
            if (
              sameOriginAsTarget &&
              (candidate.protocol === 'http:' || candidate.protocol === 'https:') &&
              !candidate.username &&
              !candidate.password
            ) {
              this.loginUrl = candidate.toString();
            }
          } catch {}
        }
      }
    } else {
      this.loginSequence = null;
    }

    // Secrets vault (Map<string, string>) + descriptions
    this.secrets = new Map();
    this._secretMeta = new Map();
    const absorbSecret = (name, value, description = '') => {
      const key = String(name || '').trim();
      if (!key || FORBIDDEN_KEYS.has(key)) return;
      const valStr = value !== undefined && value !== null ? String(value) : '';
      if (this.secrets.has(key) && (valStr === '[SECRET]' || valStr === '[REDACTED]') && this.secrets.get(key)) {
        return;
      }
      this.secrets.set(key, valStr);
      if (description) {
        this._secretMeta.set(key, String(description).trim());
      } else if (!this._secretMeta.has(key)) {
        this._secretMeta.set(key, '');
      }
    };
    if (this.loginSequence?.secrets) {
      for (const entry of this.loginSequence.secrets) {
        absorbSecret(entry.name, entry.value, entry.description);
      }
    }
    if (config.secrets instanceof Map) {
      for (const [k, v] of config.secrets.entries()) {
        absorbSecret(k, v);
      }
    } else if (Array.isArray(config.secrets)) {
      for (const entry of config.secrets) {
        if (entry && typeof entry === 'object') {
          absorbSecret(entry.name, entry.value, entry.description);
        }
      }
    } else if (config.secrets && typeof config.secrets === 'object') {
      for (const [k, v] of Object.entries(config.secrets)) {
        absorbSecret(k, v);
      }
    }
    if (this.loginSequence && this.secrets.size > 0) {
      this.loginSequence.secrets = Array.from(this.secrets.entries())
        .slice(0, MAX_SECRETS)
        .map(([name, value]) => ({
          name,
          value,
          description: this._secretMeta.get(name) || ''
        }));
    }

    // System Variables store (Map<string, normalizedVarObj>)
    this.systemVariables = new Map();
    const absorbSystemVars = (rawVars) => {
      if (!rawVars) return;
      for (const item of normalizeSystemVariables(rawVars)) {
        const prev = this.systemVariables.get(item.name);
        if (prev && prev.value && (item.value === '[SECRET]' || item.value === '[REDACTED]')) {
          this.systemVariables.set(item.name, { ...item, value: prev.value });
        } else if (this.systemVariables.has(item.name) || this.systemVariables.size < MAX_SYSTEM_VARIABLES) {
          this.systemVariables.set(item.name, item);
        }
      }
    };
    if (config.loginSequence && typeof config.loginSequence === 'object' && config.loginSequence.systemVariables) {
      absorbSystemVars(config.loginSequence.systemVariables);
    }
    if (config.systemVariables) {
      absorbSystemVars(config.systemVariables);
    }

    this.lastDiagnostics = Array.isArray(config.diagnostics)
      ? config.diagnostics.map(d => ({ ...d }))
      : [];

    // OTP config
    const seqOtp = this.loginSequence?.otpConfig || {};
    const cfgOtp = config.otpConfig && typeof config.otpConfig === 'object' && !Array.isArray(config.otpConfig)
      ? config.otpConfig
      : {};
    const mergedOtp = { ...seqOtp, ...cfgOtp };
    if (
      seqOtp.secret &&
      seqOtp.secret !== '[REDACTED]' &&
      (cfgOtp.secret === '[REDACTED]' || cfgOtp.secret === undefined)
    ) {
      mergedOtp.secret = seqOtp.secret;
    }
    this.otpConfig = normalizeOtpConfig(mergedOtp);
    if (this.loginSequence) {
      this.loginSequence.otpConfig = { ...this.otpConfig };
    }

    // Restrictions
    const combinedRestrictions = [
      ...(this.loginSequence?.restrictions || []),
      ...(Array.isArray(config.restrictions) ? config.restrictions : [])
    ];
    this.restrictions = normalizeRestrictionsList(combinedRestrictions);
    if (this.loginSequence) {
      this.loginSequence.restrictions = [...this.restrictions];
    }

    // Session expiration detection rules
    if (config.sessionDetection && typeof config.sessionDetection === 'object' && !Array.isArray(config.sessionDetection)) {
      const baseDefaults = this.loginSequence?.sessionDetection || { statusCodes: [401], redirectPattern: '' };
      this.sessionDetection = normalizeSessionDetection(config.sessionDetection, baseDefaults);
      if (this.loginSequence) {
        this.loginSequence.sessionDetection = {
          ...this.sessionDetection,
          statusCodes: [...this.sessionDetection.statusCodes]
        };
      }
    } else if (this.loginSequence?.sessionDetection) {
      this.sessionDetection = {
        ...this.loginSequence.sessionDetection,
        statusCodes: [...this.loginSequence.sessionDetection.statusCodes]
      };
    } else {
      this.sessionDetection = {
        statusCodes: [401],
        redirectPattern: '',
        loggedOutPattern: '',
        loggedInPattern: ''
      };
    }

    this.cookies = new Map(); // cookieName -> cookieValue
    this.bearerToken = null;
    this.csrfHeaderName = null;
    this.csrfHeaderValue = null;
    this.csrfFormField = null;
    this.csrfFormValue = null;
    this.reauthCount = 0;

    this._discoveredPreflight = null;
    this._reauthPromise = null;
    this._lastLoginRejected = false;
  }

  /**
   * Restores an `AuthSessionManager` instance from a previously exported/recorded session object.
   *
   * @param {object} [saved={}]
   * @returns {AuthSessionManager}
   */
  static fromRecordedSession(saved = {}) {
    const data = saved && typeof saved === 'object' && !Array.isArray(saved) ? saved : {};
    const mgr = new AuthSessionManager({
      sessionId: data.sessionId || crypto.randomUUID(),
      targetUrl: data.targetUrl || null,
      loginUrl: data.loginUrl || null,
      loginMethod: data.loginMethod || 'POST',
      loginContentType: data.loginContentType || 'auto',
      username: data.username ?? null,
      recordedSteps: Array.isArray(data.steps)
        ? data.steps
        : (Array.isArray(data.recordedSteps) ? data.recordedSteps : []),
      authenticatedAt: data.authenticatedAt || null,
      loginSequence: data.loginSequence || null,
      secrets: data.secrets || data.loginSequence?.secrets || null,
      systemVariables: data.systemVariables || data.loginSequence?.systemVariables || null,
      diagnostics: Array.isArray(data.diagnostics) ? data.diagnostics : [],
      otpConfig: data.otpConfig || data.loginSequence?.otpConfig || null,
      restrictions: data.restrictions || data.loginSequence?.restrictions || null,
      sessionDetection: data.sessionDetection || data.loginSequence?.sessionDetection || null
    });

    if (data.cookies instanceof Map) {
      for (const [k, v] of data.cookies.entries()) {
        if (typeof k === 'string' && k && typeof v === 'string' && v !== '[CAPTURED]' && !/[\r\n]/.test(k) && !/[\r\n]/.test(v)) {
          mgr.cookies.set(k, v);
        }
      }
    } else if (data.cookies && typeof data.cookies === 'object') {
      for (const [k, v] of Object.entries(data.cookies)) {
        if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
        if (k && typeof v === 'string' && v !== '[CAPTURED]' && !/[\r\n]/.test(k) && !/[\r\n]/.test(v)) {
          mgr.cookies.set(k, v);
        }
      }
    }

    if (typeof data.bearerToken === 'string' && data.bearerToken.trim() && !/[\r\n]/.test(data.bearerToken)) {
      mgr.bearerToken = data.bearerToken.trim();
    }
    if (typeof data.csrfHeaderName === 'string' && data.csrfHeaderName.trim() && !/[\r\n]/.test(data.csrfHeaderName)) {
      mgr.csrfHeaderName = data.csrfHeaderName.trim();
    }
    if (typeof data.csrfHeaderValue === 'string' && data.csrfHeaderValue && !/[\r\n]/.test(data.csrfHeaderValue)) {
      mgr.csrfHeaderValue = data.csrfHeaderValue;
    }
    if (typeof data.csrfFormField === 'string' && data.csrfFormField.trim()) {
      mgr.csrfFormField = data.csrfFormField.trim();
    }
    if (Number.isFinite(Number(data.reauthCount)) && Number(data.reauthCount) >= 0) {
      mgr.reauthCount = Number(data.reauthCount);
    }

    if (!mgr.csrfHeaderValue) {
      for (const [cookieName, cookieVal] of mgr.cookies.entries()) {
        const lowerName = cookieName.toLowerCase();
        if (Object.hasOwn(CSRF_COOKIE_TO_HEADER, lowerName)) {
          mgr.csrfHeaderName = mgr.csrfHeaderName || CSRF_COOKIE_TO_HEADER[lowerName];
          try {
            mgr.csrfHeaderValue = decodeURIComponent(cookieVal);
          } catch {
            mgr.csrfHeaderValue = cookieVal;
          }
          break;
        }
      }
    }

    return mgr;
  }

  /**
   * Ingests `Set-Cookie` header(s) into the session cookie jar and promotes
   * known CSRF cookies (`XSRF-TOKEN`, `csrftoken`) into CSRF request headers.
   *
   * @param {Record<string, string | string[]>} [headers={}]
   * @returns {string[]} Cookie names harvested from this response
   */
  ingestResponseHeaders(headers = {}) {
    const harvested = [];
    if (!headers || typeof headers !== 'object') return harvested;
    const setCookieChunks = [];
    for (const [k, v] of iterateHeaders(headers)) {
      if (String(k).toLowerCase() === 'set-cookie') {
        if (Array.isArray(v)) {
          for (const item of v) setCookieChunks.push(String(item ?? ''));
        } else {
          setCookieChunks.push(String(v ?? ''));
        }
      }
    }
    const rawSetCookie = setCookieChunks.filter(Boolean).join('\n');
    if (!rawSetCookie) return harvested;

    // Split multiple Set-Cookie entries (newline or comma not followed by expires date)
    const parts = rawSetCookie.split(/\r?\n|,(?=\s*[A-Za-z0-9_.-]+=)/);
    for (const part of parts) {
      const firstPair = part.split(';')[0]?.trim();
      if (!firstPair) continue;
      const eqIdx = firstPair.indexOf('=');
      if (eqIdx <= 0) continue;
      const name = firstPair.slice(0, eqIdx).trim();
      const val = firstPair.slice(eqIdx + 1).trim();
      if (!name || /[\r\n]/.test(name) || /[\r\n]/.test(val)) continue;
      this.cookies.set(name, val);
      harvested.push(name);

      const lowerName = name.toLowerCase();
      if (Object.hasOwn(CSRF_COOKIE_TO_HEADER, lowerName)) {
        this.csrfHeaderName = CSRF_COOKIE_TO_HEADER[lowerName];
        try {
          this.csrfHeaderValue = decodeURIComponent(val);
        } catch {
          this.csrfHeaderValue = val;
        }
      }
    }
    return harvested;
  }

  /**
   * Builds the merged authentication headers (`Cookie`, `Authorization`, `X-CSRF-TOKEN` / `X-XSRF-TOKEN`)
   * for an outgoing scan request.
   */
  getAuthHeaders(extraHeaders = {}) {
    const out = { ...this.staticHeaders };
    if (this.cookies.size > 0) {
      const cookieStr = Array.from(this.cookies.entries())
        .map(([k, v]) => `${k}=${v}`)
        .join('; ');
      out.Cookie = cookieStr;
    }
    if (this.bearerToken) {
      out.Authorization = this.bearerToken.startsWith('Bearer ')
        ? this.bearerToken
        : `Bearer ${this.bearerToken}`;
    }
    if (this.csrfHeaderName && this.csrfHeaderValue) {
      out[this.csrfHeaderName] = this.csrfHeaderValue;
    }
    return { ...out, ...(extraHeaders || {}) };
  }

  /**
   * Looks up a named variable in `this.secrets` first, then `this.systemVariables`.
   * Ignores empty or redacted placeholder values (`'[SECRET]'`, `'[REDACTED]'`).
   * @private
   */
  _lookupNamedValue(rawName) {
    const key = String(rawName || '').trim();
    if (!key || FORBIDDEN_KEYS.has(key)) {
      return { found: false, value: '', isSecret: false, source: null };
    }
    if (this.secrets.has(key)) {
      const val = this.secrets.get(key);
      if (val !== undefined && val !== null && val !== '' && val !== '[SECRET]' && val !== '[REDACTED]') {
        return { found: true, value: String(val), isSecret: true, source: 'secrets' };
      }
    }
    if (this.systemVariables.has(key)) {
      const varObj = this.systemVariables.get(key);
      const val = varObj?.value;
      if (val !== undefined && val !== null && val !== '' && val !== '[SECRET]' && val !== '[REDACTED]') {
        return { found: true, value: String(val), isSecret: Boolean(varObj.isSecret), source: 'systemVariables' };
      }
    }
    return { found: false, value: '', isSecret: false, source: null };
  }

  /**
   * Resolves `{{VAR:name}}`, `{{SECRET:name}}`, explicit secret/variable names from
   * `this.secrets` / `this.systemVariables`, and `{{OTP}}` / `{{TOTP}}` via `this.generateCurrentOtp()`.
   *
   * @param {string} rawValOrSecretName
   * @returns {string}
   */
  resolveSecretValue(rawValOrSecretName) {
    if (rawValOrSecretName === null || rawValOrSecretName === undefined) return '';
    const str = String(rawValOrSecretName);
    if (!str) return '';

    if (/\{\{(?:(?:VAR|SECRET):[^}]{0,128}|OTP|TOTP)\}\}/i.test(str)) {
      return this._resolveTemplatePlaceholders(str);
    }

    const trimmed = str.trim();
    if (trimmed && !FORBIDDEN_KEYS.has(trimmed) && (this.secrets.has(trimmed) || this.systemVariables.has(trimmed))) {
      return this._lookupNamedValue(trimmed).value;
    }

    return str;
  }

  /**
   * Generates a fresh RFC 6238 TOTP code from `this.otpConfig` (or a secret/System Variable
   * referenced by `otpConfig.secretName`, `otpConfig.variableName`, `{{VAR:name}}`/`{{SECRET:name}}`
   * in `otpConfig.secret`, or `overrideSecretName`).
   *
   * @param {string} [overrideSecretName='']
   * @returns {{ code: string, digits: number, period: number, algorithm: string, counter: number, remainingSeconds: number }}
   */
  generateCurrentOtp(overrideSecretName = '') {
    let secret = '';
    let missingVarName = '';
    const overrideKey = String(overrideSecretName || '').trim();

    if (overrideKey && !FORBIDDEN_KEYS.has(overrideKey)) {
      const lookup = this._lookupNamedValue(overrideKey);
      if (lookup.found) {
        secret = lookup.value;
      } else {
        missingVarName = overrideKey;
      }
    }

    if (!secret && !missingVarName && this.otpConfig?.secret && this.otpConfig.secret !== '[REDACTED]' && this.otpConfig.secret !== '[SECRET]') {
      const rawCfgSecret = String(this.otpConfig.secret).trim();
      const varPattern = /\{\{(?:VAR|SECRET):([^}]{0,128})\}\}/gi;
      if (varPattern.test(rawCfgSecret)) {
        varPattern.lastIndex = 0;
        let unresolvedInCfg = '';
        const resolvedCfg = rawCfgSecret.replace(varPattern, (_m, rawKey) => {
          const key = String(rawKey || '').trim();
          const lookup = this._lookupNamedValue(key);
          if (!lookup.found) {
            if (!unresolvedInCfg) unresolvedInCfg = key || '(empty)';
            return '';
          }
          return lookup.value;
        });
        if (!unresolvedInCfg && resolvedCfg) {
          secret = resolvedCfg;
        } else if (unresolvedInCfg) {
          missingVarName = unresolvedInCfg;
        }
      } else {
        secret = rawCfgSecret;
      }
    }

    if (!secret && !missingVarName) {
      const cfgKey = String(this.otpConfig?.secretName || this.otpConfig?.variableName || '').trim();
      if (cfgKey && !FORBIDDEN_KEYS.has(cfgKey)) {
        const lookup = this._lookupNamedValue(cfgKey);
        if (lookup.found) {
          secret = lookup.value;
        } else {
          missingVarName = cfgKey;
        }
      }
    }

    if (!secret) {
      if (missingVarName) {
        throw new Error(`TOTP secret variable '${missingVarName}' is missing or empty in System Variables / Secrets vault`);
      }
      throw new Error('No TOTP secret configured in otpConfig, secrets vault, or System Variables');
    }

    return generateTotpCode({
      secret,
      digits: this.otpConfig?.digits ?? 6,
      period: this.otpConfig?.period ?? 30,
      algorithm: this.otpConfig?.algorithm ?? 'SHA1'
    });
  }

  /**
   * Returns `true` if `rawUrlOrPath` matches a logout/destructive endpoint OR
   * any configured rule in `this.restrictions` (prefix/substring/wildcard without RegExp compilation).
   *
   * @param {string} rawUrlOrPath
   * @returns {boolean}
   */
  isRestrictedUrl(rawUrlOrPath) {
    if (isLogoutOrDestructiveUrl(rawUrlOrPath)) return true;
    if (!Array.isArray(this.restrictions) || this.restrictions.length === 0) return false;

    const rawStr = String(rawUrlOrPath || '').trim().slice(0, 4096);
    if (!rawStr) return false;

    let decodedStr = rawStr;
    try {
      decodedStr = decodeURIComponent(rawStr);
    } catch {}

    const candidates = new Set([rawStr.toLowerCase(), decodedStr.toLowerCase()]);
    try {
      const base = this.targetUrl || this.loginUrl || 'http://localhost';
      const parsed = new URL(rawStr, base);
      const pathnameLower = parsed.pathname.toLowerCase();
      const pathQueryLower = `${parsed.pathname}${parsed.search}`.toLowerCase();
      const hrefLower = parsed.href.toLowerCase();
      candidates.add(pathnameLower);
      candidates.add(pathQueryLower);
      candidates.add(hrefLower);
      try {
        candidates.add(decodeURIComponent(pathnameLower));
        candidates.add(decodeURIComponent(pathQueryLower));
      } catch {}
    } catch {}

    for (const rule of this.restrictions) {
      const pat = String(rule || '').trim().toLowerCase().slice(0, MAX_RESTRICTION_LEN);
      if (!pat) continue;
      const hasWildcard = pat.includes('*') || pat.includes('?');
      for (const candidate of candidates) {
        if (hasWildcard) {
          if (matchWildcardPattern(candidate, pat)) return true;
        } else {
          if (candidate.startsWith(pat) || candidate.includes(pat)) return true;
        }
      }
    }

    return false;
  }

  /**
   * Checks whether an HTTP response indicates session expiration based on `this.sessionDetection`.
   *
   * @param {object} res
   * @returns {boolean}
   */
  isSessionExpiredResponse(res) {
    if (!res || typeof res !== 'object') return false;
    const sd = this.sessionDetection || { statusCodes: [401], redirectPattern: '', loggedOutPattern: '', loggedInPattern: '' };
    const status = Number(res.status ?? 0);

    if (Array.isArray(sd.statusCodes) && sd.statusCodes.includes(status)) {
      return true;
    }

    if (sd.redirectPattern && status >= 300 && status < 400) {
      const location = getHeaderCaseInsensitive(res.headers, 'location').toLowerCase();
      const pat = sd.redirectPattern.toLowerCase();
      if (location) {
        if ((pat.includes('*') || pat.includes('?')) ? matchWildcardPattern(location, pat) : location.includes(pat)) {
          return true;
        }
      }
    }

    const body = typeof res.text === 'string' ? res.text.slice(0, MAX_INSPECT_HTML_BYTES) : '';
    const bodyLower = body ? body.toLowerCase() : '';

    if (sd.loggedOutPattern && bodyLower) {
      const pat = sd.loggedOutPattern.toLowerCase();
      if (bodyLower.includes(pat)) {
        return true;
      }
    }

    if (sd.loggedInPattern && status >= 200 && status < 300 && body.trim()) {
      const contentType = getHeaderCaseInsensitive(res.headers, 'content-type').toLowerCase();
      const isHtml = contentType
        ? (contentType.includes('text/html') || contentType.includes('application/xhtml+xml'))
        : /<(?:!doctype|html|head|body|form)\b/i.test(body.slice(0, 4096));
      if (isHtml && !bodyLower.includes(sd.loggedInPattern.toLowerCase())) {
        return true;
      }
    }

    return false;
  }

  /**
   * Extracts CSRF tokens/cookies from a preflight GET response and updates session state.
   * @private
   */
  _ingestPreflightResponse(res, pageUrl) {
    const cookiesHarvested = this.ingestResponseHeaders(res?.headers);
    const csrf = extractCsrfTokens(res?.text || '', res?.headers);
    if (csrf.headerName && csrf.headerValue && !/[\r\n]/.test(csrf.headerValue)) {
      this.csrfHeaderName = csrf.headerName;
      this.csrfHeaderValue = csrf.headerValue;
    }
    if (csrf.formField && csrf.tokenValue) {
      this.csrfFormField = csrf.formField;
      this.csrfFormValue = csrf.tokenValue;
    }
    const csrfDetected = Boolean(
      csrf.tokenValue ||
      csrf.headerValue ||
      cookiesHarvested.some(name => Object.hasOwn(CSRF_COOKIE_TO_HEADER, name.toLowerCase()))
    );
    const parsedForm = parseLoginFormHtml(res?.text || '', pageUrl);
    return { cookiesHarvested, csrfDetected, parsedForm };
  }

  /**
   * Extracts `Set-Cookie` and JSON Bearer JWT tokens from a login submission response.
   * @private
   */
  _ingestLoginResponse(loginRes) {
    const cookiesHarvested = this.ingestResponseHeaders(loginRes?.headers || {});
    let tokenExtracted = false;

    const hdrs = loginRes?.headers;
    if (hdrs && typeof hdrs === 'object') {
      for (const [k, v] of iterateHeaders(hdrs)) {
        if (String(k).toLowerCase() === 'authorization' && typeof v === 'string' && /^Bearer\s+\S+/i.test(v)) {
          const tok = v.replace(/^Bearer\s+/i, '').trim();
          if (tok && !/[\r\n]/.test(tok)) {
            this.bearerToken = tok;
            tokenExtracted = true;
          }
        }
      }
    }

    const text = String(loginRes?.text || '').trim();
    if (text.startsWith('{')) {
      try {
        const json = JSON.parse(text);
        const tokenCandidate =
          (this.tokenJsonPath ? resolveJsonPath(json, this.tokenJsonPath) : null) ||
          json.access_token ||
          json.accessToken ||
          json.token ||
          json.jwt ||
          json.id_token ||
          json.data?.access_token ||
          json.data?.accessToken ||
          json.data?.token ||
          json.data?.jwt ||
          json.authentication?.token ||
          json.result?.token ||
          json.result?.access_token ||
          null;
        if (typeof tokenCandidate === 'string' && tokenCandidate.trim() && !/[\r\n]/.test(tokenCandidate)) {
          this.bearerToken = tokenCandidate.trim();
          tokenExtracted = true;
        }
      } catch {
        // non-JSON response
      }
    }

    return { cookiesHarvested, tokenExtracted };
  }

  /**
   * Probes common login paths on `this.targetUrl` origin until one returns HTTP 200
   * containing an HTML `<input type="password">` form or HTTP 405 (POST-only JSON API login).
   *
   * @param {Function} fetchWithRetry
   * @returns {Promise<{ discovered: boolean, loginUrl: string | null, status: number | null, form: object | null }>}
   */
  async discoverLoginUrl(fetchWithRetry) {
    if (!this.targetUrl) {
      throw new Error('AuthSessionManager requires targetUrl to auto-discover loginUrl');
    }
    let parsedTarget;
    try {
      parsedTarget = new URL(this.targetUrl);
    } catch {
      throw new Error(`Invalid targetUrl for login discovery: ${this.targetUrl}`);
    }
    if (parsedTarget.protocol !== 'http:' && parsedTarget.protocol !== 'https:') {
      throw new Error(`Unsupported targetUrl protocol for login discovery: ${parsedTarget.protocol}`);
    }

    const candidates = COMMON_LOGIN_PATHS.map(p => new URL(p, parsedTarget.origin).toString());
    const targetHref = parsedTarget.toString();
    if (!candidates.includes(targetHref)) {
      candidates.push(targetHref);
    }

    for (const candidateUrl of candidates) {
      let res;
      try {
        res = await fetchWithRetry(candidateUrl, {
          method: 'GET',
          headers: this.getAuthHeaders(),
          sameOriginRedirects: true
        });
      } catch (err) {
        if (err?.isGovernanceBlock) throw err;
        continue;
      }

      const status = Number(res?.status ?? 0);
      const effectiveUrl = (typeof res?.url === 'string' && res.url) ? res.url : candidateUrl;

      if (status === 200) {
        const form = parseLoginFormHtml(res?.text || '', effectiveUrl);
        if (form.hasPasswordInput) {
          this.loginUrl = effectiveUrl;
          const pre = this._ingestPreflightResponse(res, effectiveUrl);
          this._discoveredPreflight = {
            url: effectiveUrl,
            res,
            ...pre
          };
          return { discovered: true, loginUrl: this.loginUrl, status, form };
        }
      } else if (status === 405) {
        this.loginUrl = effectiveUrl;
        const cookiesHarvested = this.ingestResponseHeaders(res?.headers);
        this._discoveredPreflight = {
          url: effectiveUrl,
          res,
          cookiesHarvested,
          csrfDetected: false,
          parsedForm: null
        };
        return { discovered: true, loginUrl: this.loginUrl, status, form: null };
      }
    }

    return { discovered: false, loginUrl: null, status: null, form: null };
  }

  /**
   * Auto-discovers the login endpoint for `targetUrl` (when needed) and executes the login macro.
   *
   * @param {string} targetUrl
   * @param {Function} fetchWithRetry
   */
  async discoverAndLogin(targetUrl, fetchWithRetry) {
    if (targetUrl) {
      this.targetUrl = String(targetUrl).trim();
    }
    return await this.executeLoginMacro(fetchWithRetry);
  }

  /**
   * Resolves and verifies a login sequence URL against `baseUrl` and `allowedOrigins`
   * to prevent cross-host SSRF and dangerous schemes (`javascript:`, `data:`, etc.).
   * @private
   */
  _resolveAndVerifySequenceUrl(rawUrl, baseUrl, allowedOrigins) {
    const candidate = String(rawUrl || '').trim();
    if (!candidate) {
      throw new Error('Login sequence step is missing a target URL');
    }
    if (/^(?:javascript|data|vbscript|file):/i.test(candidate)) {
      throw new Error(`Unsafe protocol in login sequence URL: ${candidate}`);
    }

    let parsed;
    try {
      const effectiveBase = baseUrl || this.targetUrl || this.loginUrl || undefined;
      parsed = new URL(candidate, effectiveBase);
    } catch {
      throw new Error(`Invalid login sequence URL: ${candidate}`);
    }

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new Error(`Unsupported login sequence URL protocol: ${parsed.protocol}`);
    }
    if (parsed.username || parsed.password) {
      throw new Error('Embedded credentials are not allowed in login sequence URLs');
    }

    if (allowedOrigins.size === 0) {
      allowedOrigins.add(parsed.origin);
    } else if (!allowedOrigins.has(parsed.origin)) {
      throw new Error(`Blocked cross-origin login sequence URL: ${parsed.origin}`);
    }

    return parsed.toString();
  }

  /**
   * Inspects and resolves `{{VAR:name}}`, `{{SECRET:name}}`, `{{OTP}}`, and `{{TOTP}}`
   * placeholders inside a string, tracking unresolved variable names and OTP errors.
   * @private
   */
  _inspectAndResolvePlaceholders(str, { catchOtpError = false } = {}) {
    const s = String(str ?? '');
    const unresolvedVars = [];
    const resolvedVars = [];
    const pattern = /\{\{(?:(VAR|SECRET):([^}]{0,128})|(OTP|TOTP))\}\}/gi;

    if (!pattern.test(s)) {
      return {
        resolved: s,
        unresolvedVars,
        resolvedVars,
        usedOtp: false,
        isSecret: false,
        otpError: null
      };
    }
    pattern.lastIndex = 0;

    let cachedOtp = null;
    let usedOtp = false;
    let inferredSecret = false;
    let otpError = null;
    const getOtp = () => {
      usedOtp = true;
      inferredSecret = true;
      if (cachedOtp === null) {
        if (catchOtpError) {
          try {
            cachedOtp = this.generateCurrentOtp().code;
          } catch (err) {
            otpError = err?.message || String(err);
            cachedOtp = '';
          }
        } else {
          cachedOtp = this.generateCurrentOtp().code;
        }
      }
      return cachedOtp;
    };

    const resolved = s.replace(pattern, (_m, kind, rawKey, otpKind) => {
      if (otpKind) {
        return getOtp();
      }
      const key = String(rawKey || '').trim();
      if (!key || FORBIDDEN_KEYS.has(key)) {
        const missingLabel = key || '(empty)';
        if (!unresolvedVars.includes(missingLabel)) unresolvedVars.push(missingLabel);
        return '';
      }
      const lookup = this._lookupNamedValue(key);
      if (!lookup.found) {
        if (!unresolvedVars.includes(key)) unresolvedVars.push(key);
        return '';
      }
      if (!resolvedVars.includes(key)) resolvedVars.push(key);
      if (String(kind).toUpperCase() === 'SECRET' || lookup.isSecret) {
        inferredSecret = true;
      }
      return lookup.value;
    });

    return {
      resolved,
      unresolvedVars,
      resolvedVars,
      usedOtp,
      isSecret: inferredSecret,
      otpError
    };
  }

  /**
   * Resolves explicit `{{VAR:name}}`, `{{SECRET:name}}`, `{{OTP}}`, and `{{TOTP}}` placeholders inside a string.
   * @private
   */
  _resolveTemplatePlaceholders(str) {
    return this._inspectAndResolvePlaceholders(str).resolved;
  }

  /**
   * Recursively resolves template placeholders in plain objects/arrays for custom requests.
   * @private
   */
  _resolvePayloadTemplates(payload, depth = 0, tracker = null) {
    if (depth > 8 || payload === null || payload === undefined) return payload;
    if (typeof payload === 'string') {
      if (tracker) {
        const info = this._inspectAndResolvePlaceholders(payload, { catchOtpError: Boolean(tracker.catchOtpError) });
        for (const u of info.unresolvedVars) {
          if (!tracker.unresolvedVars.includes(u)) tracker.unresolvedVars.push(u);
        }
        if (info.otpError && !tracker.otpError) {
          tracker.otpError = info.otpError;
        }
        return info.resolved;
      }
      return this._resolveTemplatePlaceholders(payload);
    }
    if (Array.isArray(payload)) {
      return payload.map(item => this._resolvePayloadTemplates(item, depth + 1, tracker));
    }
    if (typeof payload === 'object') {
      const out = {};
      for (const [k, v] of Object.entries(payload)) {
        if (FORBIDDEN_KEYS.has(k)) continue;
        out[k] = this._resolvePayloadTemplates(v, depth + 1, tracker);
      }
      return out;
    }
    return payload;
  }

  /** @private */
  _findMatchingInputInDom(dom, selectorType, selector, fieldName = '') {
    const inputs = dom?.inputs;
    if (!Array.isArray(inputs) || inputs.length === 0) return null;
    const sel = String(selector || '').trim();
    const cleanId = sel.replace(/^#/, '');

    if (selectorType === 'id') {
      return inputs.find(i => i.id && i.id === cleanId) || null;
    }
    if (selectorType === 'name') {
      return inputs.find(i => i.name && (i.name === sel || (fieldName && i.name === fieldName))) || null;
    }
    if (sel.startsWith('#')) {
      return inputs.find(i => i.id && i.id === sel.slice(1)) || null;
    }
    const nameAttrMatch = sel.match(/\[name=["']?([^"'\]]+)["']?\]/i);
    if (nameAttrMatch) {
      return inputs.find(i => i.name === nameAttrMatch[1]) || null;
    }
    return inputs.find(i => i.selectorValue === sel || (i.id && i.id === cleanId) || (i.name && i.name === sel)) || null;
  }

  /** @private */
  _findMatchingButtonInDom(dom, selectorType, selector) {
    const buttons = dom?.buttons;
    if (!Array.isArray(buttons) || buttons.length === 0) return null;
    const sel = String(selector || '').trim();
    const cleanId = sel.replace(/^#/, '');

    if (selectorType === 'id') {
      return buttons.find(b => b.id && b.id === cleanId) || null;
    }
    if (selectorType === 'name') {
      return buttons.find(b => b.name && b.name === sel) || null;
    }
    if (selectorType === 'text') {
      const targetLower = sel.toLowerCase();
      return buttons.find(b => b.text && b.text.toLowerCase() === targetLower) ||
        buttons.find(b => b.text && targetLower && b.text.toLowerCase().includes(targetLower)) ||
        null;
    }
    if (sel.startsWith('#')) {
      return buttons.find(b => b.id && b.id === sel.slice(1)) || null;
    }
    return buttons.find(b => b.selectorValue === sel || (b.id && b.id === cleanId) || (b.name && b.name === sel)) || null;
  }

  /** @private */
  _pickDefaultFormAndPopulateHidden(dom, targetMap) {
    const forms = dom?.forms || [];
    if (forms.length > 0) {
      const preferred =
        forms.find(f => f.hasPasswordInput) ||
        forms.find(f => Object.keys(f.hiddenFields || {}).length > 0) ||
        forms[0];
      for (const [k, v] of Object.entries(preferred.hiddenFields || {})) {
        if (!FORBIDDEN_KEYS.has(k)) {
          targetMap[k] = v;
        }
      }
      return preferred.formIndex;
    }
    for (const inp of (dom?.inputs || [])) {
      if (inp.type === 'hidden' && inp.name && !FORBIDDEN_KEYS.has(inp.name)) {
        targetMap[inp.name] = inp.value ?? '';
      }
    }
    return -1;
  }

  /**
   * Executes the configured Multi-Step Login Sequence (`.lsr`) step by step:
   *  - `navigate`: Same-origin GET, harvests cookies/CSRF, parses DOM, seeds hidden form inputs.
   *  - `change_input`: Resolves field name from DOM + secret/placeholder value into `pendingInputs`.
   *  - `fill_otp`: Generates fresh TOTP code and populates target/auto-detected OTP field.
   *  - `click_button`: Submits form/JSON payload with CSRF token, ingests auth artifacts, follows 1 same-origin redirect, refreshes DOM.
   *  - `extract_token`: Extracts token from JSON/header/cookie/CSRF of last response.
   *  - `custom_request`: Sends governed same-origin HTTP request with template resolution.
   *
   * @param {Function} fetchWithRetry
   */
  async executeLoginSequence(fetchWithRetry) {
    if (!this.loginSequence || !Array.isArray(this.loginSequence.actions) || this.loginSequence.actions.length === 0) {
      throw new Error('AuthSessionManager has no loginSequence actions configured');
    }

    if (this.reauthCount === 0) {
      this.recordedSteps = [];
    }

    const allowedOrigins = new Set();
    const originSources = [];
    if (this.targetUrl) {
      originSources.push(this.targetUrl);
    } else if (this.loginSequence.targetUrl) {
      originSources.push(this.loginSequence.targetUrl);
    }
    if (this._hasExplicitLoginUrl && this.loginUrl) {
      originSources.push(this.loginUrl);
    } else if (!this.targetUrl && !this.loginSequence.targetUrl && this.loginUrl) {
      originSources.push(this.loginUrl);
    }
    for (const u of originSources) {
      if (!u) continue;
      try {
        const parsed = new URL(u);
        if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
          allowedOrigins.add(parsed.origin);
        }
      } catch {}
    }

    let currentPageUrl = this.targetUrl || this.loginUrl || '';
    let currentDom = null;
    let pendingInputs = Object.create(null);
    let activeFormIndex = -1;
    let lastResponse = null;
    let lastStatus = 0;
    let gotSubmitAuthArtifact = false;
    let hasSubmitStep = false;
    const sequenceStepResults = [];
    const diagnostics = [];
    this.lastDiagnostics = diagnostics;
    const filledFields = new Map();

    const buildFallbackDomFromSequence = () => {
      const synthInputs = [];
      const synthButtons = [];
      const seenInputKeys = new Set();
      const seenBtnKeys = new Set();
      for (const act of (this.loginSequence?.actions || [])) {
        if (!act) continue;
        if (act.type === 'change_input' || act.type === 'fill_otp') {
          const cleanSel = String(act.selector || act.fieldName || 'input').replace(/^#/, '').trim() || 'input';
          const key = cleanSel.toLowerCase();
          if (seenInputKeys.has(key)) continue;
          seenInputKeys.add(key);
          const isPass = Boolean(act.isSecret || /pass|pwd|secret/i.test(cleanSel));
          synthInputs.push({
            id: act.selectorType === 'id' ? cleanSel : '',
            name: act.fieldName || cleanSel,
            type: act.type === 'fill_otp' ? 'text' : (isPass ? 'password' : 'text'),
            label: cleanSel,
            placeholder: cleanSel,
            selectorType: act.selectorType || 'id',
            selectorValue: act.selector || cleanSel,
            isPassword: isPass,
            isOtpCandidate: act.type === 'fill_otp'
          });
        } else if (act.type === 'click_button') {
          const cleanBtn = String(act.selector || 'Submit').replace(/^#/, '').trim() || 'Submit';
          const key = cleanBtn.toLowerCase();
          if (seenBtnKeys.has(key)) continue;
          seenBtnKeys.add(key);
          synthButtons.push({
            id: act.selectorType === 'id' ? cleanBtn : '',
            name: act.selectorType === 'name' ? cleanBtn : '',
            type: 'submit',
            text: cleanBtn,
            displayLabel: cleanBtn,
            selectorType: act.selectorType || 'text',
            selectorValue: act.selector || cleanBtn
          });
        }
      }
      return {
        title: `${this.loginSequence?.name || 'Login Sequence'} (Blueprint Preview)`,
        csrf: {},
        inputs: synthInputs,
        buttons: synthButtons,
        hasPasswordInput: synthInputs.some(i => i.isPassword),
        hasMfaOrOtpField: synthInputs.some(i => i.isOtpCandidate)
      };
    };

    const isGovernanceOrSsrfError = (err) => Boolean(
      err?.isGovernanceBlock ||
      err?.code === 'SSRF_POLICY_BLOCKED' ||
      err?.code === 'TARGET_RULE_BLOCKED' ||
      err?.code === 'DNS_REBIND_OR_PRIVATE_IP' ||
      /^Request blocked by SSRF policy|^Redirect blocked by SSRF policy|^\[SECSCAN platform control/i.test(String(err?.message || ''))
    );

    const buildDomSnapshot = (
      rawDom,
      pageUrl,
      httpStatus,
      { activeInput = null, clickedButton = null, pageErrorBanner = null, UnmatchedSelector = null, unmatchedSelector = null } = {}
    ) => {
      const dom = (rawDom && ((Array.isArray(rawDom.inputs) && rawDom.inputs.length > 0) || (Array.isArray(rawDom.buttons) && rawDom.buttons.length > 0) || rawDom.title))
        ? rawDom
        : buildFallbackDomFromSequence();
      const resolvedUnmatched = unmatchedSelector || UnmatchedSelector || null;
      return {
        pageUrl: pageUrl || '',
        title: dom?.title || '',
        httpStatus: Number(httpStatus || 0),
        csrfDetected: Boolean(this.csrfFormField || this.csrfHeaderName || dom?.csrf?.tokenValue),
        csrfField: this.csrfFormField || dom?.csrf?.formField || null,
        pageErrorBanner: pageErrorBanner || null,
        unmatchedSelector: resolvedUnmatched,
        inputs: (dom?.inputs || []).slice(0, 30).map(inp => {
          const key = inp.name || inp.id || inp.selectorValue;
          const filled =
            (key ? filledFields.get(key) : null) ||
            (inp.id ? filledFields.get(inp.id) : null) ||
            (inp.name ? filledFields.get(inp.name) : null) ||
            null;
          return {
            id: inp.id || '',
            name: inp.name || '',
            type: inp.type || 'text',
            label: inp.label || inp.placeholder || inp.name || inp.id || 'input',
            selectorType: inp.selectorType || 'id',
            selectorValue: inp.selectorValue || inp.id || inp.name || '',
            isPassword: Boolean(inp.isPassword),
            isOtpCandidate: Boolean(inp.isOtpCandidate),
            isFilled: Boolean(filled),
            filledValueMasked: filled ? filled.maskedValue : '',
            boundVariable: filled ? filled.boundVariable : '',
            isCurrentStepTarget: Boolean(
              activeInput &&
              (
                activeInput === inp ||
                (inp.id && activeInput.id === inp.id) ||
                (inp.name && activeInput.name === inp.name)
              )
            )
          };
        }),
        buttons: (() => {
          const mapped = (dom?.buttons || []).slice(0, 20).map(btn => ({
            id: btn.id || '',
            name: btn.name || '',
            type: btn.type || 'submit',
            text: btn.text || btn.displayLabel || 'Submit',
            selectorType: btn.selectorType || 'text',
            selectorValue: btn.selectorValue || btn.text || btn.id || '',
            wasClicked: Boolean(
              clickedButton &&
              (
                clickedButton === btn ||
                (btn.id && clickedButton.id === btn.id) ||
                (btn.text && clickedButton.text === btn.text)
              )
            )
          }));
          if (clickedButton && !mapped.some(b => b.wasClicked)) {
            mapped.push({
              id: clickedButton.id || '',
              name: clickedButton.name || '',
              type: clickedButton.type || 'submit',
              text: clickedButton.text || clickedButton.displayLabel || 'Submit',
              selectorType: clickedButton.selectorType || 'text',
              selectorValue: clickedButton.selectorValue || clickedButton.text || clickedButton.id || '',
              wasClicked: true
            });
          }
          return mapped;
        })()
      };
    };

    const pushUnresolvedVarIssues = (stepIssues, stepNum, seqStep, actionDesc, missingVars) => {
      for (const varName of missingVars) {
        stepIssues.push({
          step: stepNum,
          sequenceStep: seqStep,
          severity: 'error',
          code: 'UNRESOLVED_VARIABLE',
          title: `Step ${seqStep} (${actionDesc}): Missing or empty variable '${varName}'`,
          detail: `Variable '${varName}' was not found in Secrets/System Variables or has an empty value.`,
          fixSuggestion: `Add or update '${varName}' in System Variables with a non-empty value.`
        });
      }
    };

    const pushOtpConfigIssue = (stepIssues, stepNum, seqStep, actionDesc, message) => {
      stepIssues.push({
        step: stepNum,
        sequenceStep: seqStep,
        severity: 'error',
        code: 'OTP_CONFIG_ERROR',
        title: `Step ${seqStep} (${actionDesc}): ${message}`,
        detail: message,
        fixSuggestion: 'Configure a valid Base32 TOTP secret in Configure OTP or bind a System Variable.'
      });
    };

    const finalizeStepRecord = (stepRecord, stepIssues, domSnapshot) => {
      stepRecord.stepStatus = stepIssues.some(i => i.severity === 'error')
        ? 'error'
        : (stepIssues.length > 0 ? 'warning' : 'ok');
      stepRecord.issues = stepIssues;
      stepRecord.domSnapshot = domSnapshot;
      for (const issue of stepIssues) {
        diagnostics.push(issue);
      }
      this.recordedSteps.push(stepRecord);
      sequenceStepResults.push(stepRecord);
    };

    const ingestHtmlDomAndCsrf = (res, pageUrl) => {
      const text = typeof res?.text === 'string' ? res.text : '';
      const preInfo = this._ingestPreflightResponse(res, pageUrl);
      if (text.includes('<')) {
        currentDom = inspectLoginPageDom(text, pageUrl);
        if (currentDom.csrf?.formField && currentDom.csrf?.tokenValue) {
          this.csrfFormField = currentDom.csrf.formField;
          this.csrfFormValue = currentDom.csrf.tokenValue;
        }
        if (currentDom.csrf?.headerName && currentDom.csrf?.headerValue && !/[\r\n]/.test(currentDom.csrf.headerValue)) {
          this.csrfHeaderName = currentDom.csrf.headerName;
          this.csrfHeaderValue = currentDom.csrf.headerValue;
        }
      } else {
        currentDom = null;
      }
      return preInfo;
    };

    for (const step of this.loginSequence.actions) {
      const stepNum = this.recordedSteps.length + 1;
      const stepIssues = [];

      if (step.type === 'navigate') {
        const rawNavUrl = step.url || '';
        const urlInspection = rawNavUrl
          ? this._inspectAndResolvePlaceholders(rawNavUrl, { catchOtpError: true })
          : { resolved: '', unresolvedVars: [], resolvedVars: [], otpError: null };
        if (urlInspection.otpError) {
          pushOtpConfigIssue(stepIssues, stepNum, step.step, 'Navigate', urlInspection.otpError);
        }
        if (urlInspection.unresolvedVars.length > 0) {
          pushUnresolvedVarIssues(stepIssues, stepNum, step.step, 'Navigate', urlInspection.unresolvedVars);
        }

        if (rawNavUrl && !urlInspection.resolved.trim() && urlInspection.unresolvedVars.length > 0) {
          const stepRecord = {
            step: stepNum,
            sequenceStep: step.step,
            action: 'navigate',
            type: 'navigate',
            label: step.label,
            url: rawNavUrl,
            status: 0,
            csrfDetected: false,
            cookiesHarvested: [],
            inputsFound: currentDom ? currentDom.inputs.length : 0,
            buttonsFound: currentDom ? currentDom.buttons.length : 0,
            hasPasswordInput: Boolean(currentDom?.hasPasswordInput),
            hasMfaOrOtpField: Boolean(currentDom?.hasMfaOrOtpField)
          };
          finalizeStepRecord(stepRecord, stepIssues, buildDomSnapshot(currentDom, currentPageUrl, lastStatus));
          continue;
        }

        const stepUrl = this._resolveAndVerifySequenceUrl(
          urlInspection.resolved || currentPageUrl || this.targetUrl || this.loginUrl,
          currentPageUrl || this.targetUrl || this.loginUrl,
          allowedOrigins
        );

        let res = null;
        let navFetchErr = null;
        try {
          res = await fetchWithRetry(stepUrl, {
            method: 'GET',
            headers: this.getAuthHeaders(),
            followRedirects: false
          });
        } catch (err) {
          if (isGovernanceOrSsrfError(err)) throw err;
          navFetchErr = err;
        }

        if (navFetchErr) {
          currentPageUrl = stepUrl;
          if (!this.loginUrl) this.loginUrl = stepUrl;
          lastResponse = null;
          lastStatus = 0;
          const errMsg = navFetchErr?.message || String(navFetchErr);
          const isAbort = /aborted|timed?\s*out|ETIMEDOUT/i.test(errMsg);
          stepIssues.push({
            step: stepNum,
            sequenceStep: step.step,
            severity: 'error',
            code: isAbort ? 'NETWORK_TIMEOUT_OR_ABORT' : 'NAVIGATION_HTTP_ERROR',
            title: isAbort
              ? `Step ${step.step} (Navigate): Connection to ${stepUrl} timed out or was aborted`
              : `Step ${step.step} (Navigate): Could not connect to ${stepUrl}`,
            detail: `${errMsg}. The login page at ${stepUrl} could not be loaded.`,
            fixSuggestion: 'Verify the Login URL in Step 1 is reachable from this machine, check "Allow Authorized Internal / Private Targets" for internal servers, or click "⚡ Load Working Example" to test with the built-in demo login portal.'
          });
          const stepRecord = {
            step: stepNum,
            sequenceStep: step.step,
            action: 'navigate',
            type: 'navigate',
            label: step.label,
            url: stepUrl,
            status: 0,
            error: errMsg,
            csrfDetected: false,
            cookiesHarvested: [],
            inputsFound: 0,
            buttonsFound: 0,
            hasPasswordInput: false,
            hasMfaOrOtpField: false
          };
          finalizeStepRecord(
            stepRecord,
            stepIssues,
            buildDomSnapshot(currentDom, stepUrl, 0, { pageErrorBanner: errMsg })
          );
          continue;
        }

        let effectiveUrl = stepUrl;
        if (typeof res?.url === 'string' && res.url) {
          try {
            effectiveUrl = this._resolveAndVerifySequenceUrl(res.url, stepUrl, allowedOrigins);
          } catch {}
        }

        const firstCookies = this.ingestResponseHeaders(res?.headers);
        const navCookies = [...firstCookies];
        const navStatus = Number(res?.status ?? 0);
        if (navStatus >= 300 && navStatus < 400) {
          const loc = getHeaderCaseInsensitive(res?.headers, 'location');
          if (loc) {
            const redirUrl = this._resolveAndVerifySequenceUrl(loc, effectiveUrl, allowedOrigins);
            try {
              res = await fetchWithRetry(redirUrl, {
                method: 'GET',
                headers: this.getAuthHeaders(),
                followRedirects: false
              });
              effectiveUrl = redirUrl;
              if (typeof res?.url === 'string' && res.url) {
                try {
                  effectiveUrl = this._resolveAndVerifySequenceUrl(res.url, redirUrl, allowedOrigins);
                } catch {}
              }
              navCookies.push(...this.ingestResponseHeaders(res?.headers));
            } catch (redirErr) {
              if (isGovernanceOrSsrfError(redirErr)) throw redirErr;
            }
          }
        }

        currentPageUrl = effectiveUrl;
        if (!this.loginUrl) {
          this.loginUrl = effectiveUrl;
        }
        const preInfo = ingestHtmlDomAndCsrf(res, currentPageUrl);
        pendingInputs = Object.create(null);
        filledFields.clear();
        activeFormIndex = this._pickDefaultFormAndPopulateHidden(currentDom, pendingInputs);
        lastResponse = res;
        lastStatus = Number(res?.status ?? 0);

        const pageErr = extractLoginErrorFromResponse(res?.text || '', lastStatus);
        if (lastStatus >= 400 || lastStatus === 0) {
          stepIssues.push({
            step: stepNum,
            sequenceStep: step.step,
            severity: 'error',
            code: 'NAVIGATION_HTTP_ERROR',
            title: `Step ${step.step} (Navigate): Target returned HTTP ${lastStatus || 'network error'}`,
            detail: `GET ${currentPageUrl} returned HTTP ${lastStatus}${pageErr ? ` ("${pageErr}")` : ''}.`,
            fixSuggestion: 'Verify the target login URL is correct and reachable.'
          });
        }

        const stepRecord = {
          step: stepNum,
          sequenceStep: step.step,
          action: 'navigate',
          type: 'navigate',
          label: step.label,
          url: currentPageUrl,
          status: lastStatus,
          csrfDetected: Boolean(preInfo.csrfDetected),
          cookiesHarvested: Array.from(new Set([...navCookies, ...(preInfo.cookiesHarvested || [])])),
          inputsFound: currentDom ? currentDom.inputs.length : 0,
          buttonsFound: currentDom ? currentDom.buttons.length : 0,
          hasPasswordInput: Boolean(currentDom?.hasPasswordInput),
          hasMfaOrOtpField: Boolean(currentDom?.hasMfaOrOtpField)
        };
        finalizeStepRecord(
          stepRecord,
          stepIssues,
          buildDomSnapshot(currentDom, currentPageUrl, lastStatus, { pageErrorBanner: pageErr })
        );
        continue;
      }

      if (step.type === 'change_input') {
        const matchedInput = this._findMatchingInputInDom(currentDom, step.selectorType, step.selector, step.fieldName);
        if (matchedInput && matchedInput.formIndex >= 0) {
          activeFormIndex = matchedInput.formIndex;
          const matchedForm = (currentDom?.forms || []).find(f => f.formIndex === activeFormIndex);
          if (matchedForm) {
            for (const [hk, hv] of Object.entries(matchedForm.hiddenFields || {})) {
              if (!FORBIDDEN_KEYS.has(hk) && !(hk in pendingInputs)) {
                pendingInputs[hk] = hv;
              }
            }
          }
        }

        if (currentDom && Array.isArray(currentDom.inputs) && currentDom.inputs.length > 0 && !matchedInput) {
          const availableInputs = currentDom.inputs
            .filter(i => i.type !== 'hidden')
            .map(i => (i.id ? `#${i.id}` : (i.name || i.selectorValue)))
            .filter(Boolean)
            .join(', ');
          stepIssues.push({
            step: stepNum,
            sequenceStep: step.step,
            severity: 'error',
            code: 'SELECTOR_NOT_FOUND',
            title: `Step ${step.step} (Change Input): Selector '${step.selector || step.fieldName}' not found on page`,
            detail: `No input matched ${step.selectorType}='${step.selector || step.fieldName}' on ${currentPageUrl || 'current page'}. Available inputs: ${availableInputs || '(none)'}.`,
            fixSuggestion: availableInputs
              ? `Update the input selector to one of the detected inputs: ${availableInputs}.`
              : 'Verify the preceding navigate/submit step landed on the login form page.'
          });
        }

        const rawFieldName = (step.selectorType === 'id' && matchedInput?.name)
          ? matchedInput.name
          : (matchedInput?.name || matchedInput?.id || step.fieldName || step.selector.replace(/^#/, ''));
        const resolvedFieldName = String(rawFieldName || '').trim();
        if (!resolvedFieldName || FORBIDDEN_KEYS.has(resolvedFieldName)) {
          throw new Error(`Cannot resolve a safe field name for change_input step ${step.step}`);
        }

        let resolvedValue = '';
        let unresolvedVars = [];
        let resolvedVars = [];
        let inferredSecretFromVar = false;
        let inspectionIsSecret = false;
        let otpError = null;

        const explicitVarName = step.secretName || step.variableName || '';
        if (explicitVarName) {
          const lookup = this._lookupNamedValue(explicitVarName);
          if (lookup.found) {
            resolvedValue = lookup.value;
            resolvedVars.push(explicitVarName);
            inferredSecretFromVar = lookup.isSecret;
          } else {
            if (step.value && step.value !== '[REDACTED]' && step.value !== '[SECRET]') {
              const info = this._inspectAndResolvePlaceholders(step.value, { catchOtpError: true });
              resolvedValue = info.resolved;
              unresolvedVars = [...info.unresolvedVars];
              resolvedVars = [...info.resolvedVars];
              inspectionIsSecret = info.isSecret;
              otpError = info.otpError;
            }
            if (!unresolvedVars.includes(explicitVarName) && resolvedVars.length === 0 && !resolvedValue) {
              unresolvedVars.push(explicitVarName);
            } else if (!unresolvedVars.includes(explicitVarName) && !lookup.found && !resolvedVars.length) {
              // Explicit secretName/variableName was missing even if literal fallback was absent/template
              if (/^\{\{(?:VAR|SECRET):/i.test(step.value || '') || !step.value) {
                unresolvedVars.push(explicitVarName);
              }
            }
          }
        } else {
          const info = this._inspectAndResolvePlaceholders(step.value, { catchOtpError: true });
          resolvedValue = info.resolved;
          unresolvedVars = info.unresolvedVars;
          resolvedVars = info.resolvedVars;
          inspectionIsSecret = info.isSecret;
          otpError = info.otpError;
        }

        if (otpError) {
          pushOtpConfigIssue(stepIssues, stepNum, step.step, 'Change Input', otpError);
        }
        if (unresolvedVars.length > 0) {
          pushUnresolvedVarIssues(stepIssues, stepNum, step.step, 'Change Input', unresolvedVars);
        }

        pendingInputs[resolvedFieldName] = resolvedValue;
        const isSecret = Boolean(
          step.isSecret ||
          step.secretName ||
          inferredSecretFromVar ||
          inspectionIsSecret ||
          matchedInput?.isPassword ||
          /pass|pwd|secret/i.test(resolvedFieldName)
        );

        const boundVariable = explicitVarName || resolvedVars[0] || unresolvedVars[0] || '';
        if (unresolvedVars.length === 0 && !otpError) {
          const fillEntry = {
            maskedValue: isSecret ? (resolvedValue ? '••••••••' : '') : String(resolvedValue ?? '').slice(0, 128),
            isSecret,
            boundVariable,
            selectorMatched: Boolean(matchedInput)
          };
          if (matchedInput) {
            if (matchedInput.name) filledFields.set(matchedInput.name, fillEntry);
            if (matchedInput.id) filledFields.set(matchedInput.id, fillEntry);
            if (matchedInput.selectorValue) filledFields.set(matchedInput.selectorValue, fillEntry);
          }
          filledFields.set(resolvedFieldName, fillEntry);
        }

        const stepRecord = {
          step: stepNum,
          sequenceStep: step.step,
          action: 'change_input',
          type: 'change_input',
          label: step.label,
          selectorType: step.selectorType,
          selector: step.selector,
          fieldName: resolvedFieldName,
          value: isSecret ? '[REDACTED]' : resolvedValue,
          isSecret,
          ...(boundVariable ? { boundVariable } : {})
        };
        const unmatchedInputSel = (currentDom && Array.isArray(currentDom.inputs) && currentDom.inputs.length > 0 && !matchedInput)
          ? (step.selector || step.fieldName || null)
          : null;
        finalizeStepRecord(
          stepRecord,
          stepIssues,
          buildDomSnapshot(currentDom, currentPageUrl, lastStatus, {
            activeInput: matchedInput,
            unmatchedSelector: unmatchedInputSel
          })
        );
        continue;
      }

      if (step.type === 'fill_otp') {
        const otpVarName = step.secretName || step.variableName || '';
        let otp;
        try {
          otp = this.generateCurrentOtp(otpVarName);
        } catch (err) {
          const errMsg = err?.message || String(err);
          otp = {
            code: '',
            digits: 6,
            period: 30,
            algorithm: 'SHA1',
            remainingSeconds: 0,
            error: errMsg
          };
          pushOtpConfigIssue(stepIssues, stepNum, step.step, 'Fill OTP', errMsg);
        }

        let matchedInput = null;
        if (!step.selector || step.selector === 'auto') {
          matchedInput = (currentDom?.inputs || []).find(i => i.isOtpCandidate) || null;
          if (!matchedInput && this.otpConfig?.inputSelector) {
            matchedInput = this._findMatchingInputInDom(
              currentDom,
              this.otpConfig.inputSelector.startsWith('#') ? 'id' : 'name',
              this.otpConfig.inputSelector
            );
          }
        } else {
          matchedInput = this._findMatchingInputInDom(currentDom, step.selectorType, step.selector, step.fieldName);
        }

        if (currentDom && Array.isArray(currentDom.inputs) && currentDom.inputs.length > 0 && !matchedInput) {
          const availableInputs = currentDom.inputs
            .filter(i => i.type !== 'hidden')
            .map(i => (i.id ? `#${i.id}` : (i.name || i.selectorValue)))
            .filter(Boolean)
            .join(', ');
          stepIssues.push({
            step: stepNum,
            sequenceStep: step.step,
            severity: 'error',
            code: 'SELECTOR_NOT_FOUND',
            title: `Step ${step.step} (Fill OTP): Selector '${step.selector || 'auto'}' not found on page`,
            detail: `No OTP input matched ${step.selectorType}='${step.selector || 'auto'}' on ${currentPageUrl || 'current page'}. Available inputs: ${availableInputs || '(none)'}.`,
            fixSuggestion: availableInputs
              ? `Update the fill_otp selector to one of the detected inputs: ${availableInputs}.`
              : 'Verify the preceding navigate/submit step reached the MFA/OTP page.'
          });
        }

        if (matchedInput && matchedInput.formIndex >= 0) {
          activeFormIndex = matchedInput.formIndex;
          const matchedForm = (currentDom?.forms || []).find(f => f.formIndex === activeFormIndex);
          if (matchedForm) {
            for (const [hk, hv] of Object.entries(matchedForm.hiddenFields || {})) {
              if (!FORBIDDEN_KEYS.has(hk) && !(hk in pendingInputs)) {
                pendingInputs[hk] = hv;
              }
            }
          }
        }

        const rawFieldName = matchedInput?.name ||
          matchedInput?.id ||
          step.fieldName ||
          (step.selector && step.selector !== 'auto' ? step.selector.replace(/^#/, '') : '') ||
          (this.otpConfig?.inputSelector ? this.otpConfig.inputSelector.replace(/^#/, '') : '') ||
          'otp';
        const resolvedFieldName = String(rawFieldName || 'otp').trim();
        if (!resolvedFieldName || FORBIDDEN_KEYS.has(resolvedFieldName)) {
          throw new Error(`Cannot resolve a safe field name for fill_otp step ${step.step}`);
        }

        pendingInputs[resolvedFieldName] = otp.code;

        const boundOtpVar = otpVarName || this.otpConfig?.secretName || this.otpConfig?.variableName || 'TOTP';
        if (!otp.error && otp.code) {
          const fillEntry = {
            maskedValue: '•'.repeat(otp.digits || 6),
            isSecret: true,
            boundVariable: boundOtpVar,
            selectorMatched: Boolean(matchedInput)
          };
          if (matchedInput) {
            if (matchedInput.name) filledFields.set(matchedInput.name, fillEntry);
            if (matchedInput.id) filledFields.set(matchedInput.id, fillEntry);
            if (matchedInput.selectorValue) filledFields.set(matchedInput.selectorValue, fillEntry);
          }
          filledFields.set(resolvedFieldName, fillEntry);
        }

        const stepRecord = {
          step: stepNum,
          sequenceStep: step.step,
          action: 'fill_otp',
          type: 'fill_otp',
          label: step.label,
          selectorType: step.selectorType,
          selector: step.selector,
          fieldName: resolvedFieldName,
          otpGenerated: Boolean(!otp.error && otp.code),
          digits: otp.digits,
          period: otp.period,
          algorithm: otp.algorithm,
          remainingSeconds: otp.remainingSeconds,
          value: '[OTP-REDACTED]',
          ...(otp.error ? { error: otp.error } : {})
        };
        const unmatchedOtpSel = (currentDom && Array.isArray(currentDom.inputs) && currentDom.inputs.length > 0 && !matchedInput)
          ? (step.selector || step.fieldName || 'auto')
          : null;
        finalizeStepRecord(
          stepRecord,
          stepIssues,
          buildDomSnapshot(currentDom, currentPageUrl, lastStatus, {
            activeInput: matchedInput,
            unmatchedSelector: unmatchedOtpSel
          })
        );
        continue;
      }

      if (step.type === 'click_button') {
        hasSubmitStep = true;
        const preSubmitDom = currentDom;
        const matchedButton = this._findMatchingButtonInDom(preSubmitDom, step.selectorType, step.selector);
        if (matchedButton && matchedButton.formIndex >= 0) {
          activeFormIndex = matchedButton.formIndex;
        }

        const buttonUnmatchedSel = (
          preSubmitDom &&
          Array.isArray(preSubmitDom.buttons) &&
          preSubmitDom.buttons.length > 0 &&
          !matchedButton
        ) ? (step.selector || '(empty)') : null;

        if (buttonUnmatchedSel) {
          const availableButtons = preSubmitDom.buttons
            .map(b => (b.id ? `#${b.id}` : (b.text || b.name || b.selectorValue)))
            .filter(Boolean)
            .join(', ');
          stepIssues.push({
            step: stepNum,
            sequenceStep: step.step,
            severity: 'warning',
            code: 'BUTTON_SELECTOR_NOT_FOUND',
            title: `Step ${step.step} (Click Button): Button '${step.selector || '(empty)'}' not found on page`,
            detail: `No button matched ${step.selectorType}='${step.selector}' on ${currentPageUrl || 'current page'}. Falling back to form action submit. Available buttons: ${availableButtons || '(none)'}.`,
            fixSuggestion: availableButtons
              ? `Update the click_button selector to match one of the available buttons: ${availableButtons}.`
              : 'Verify the page contains the expected submit button.'
          });
        }

        const activeForm = (preSubmitDom?.forms || []).find(f => f.formIndex === activeFormIndex) ||
          (preSubmitDom?.forms || []).find(f => f.hasPasswordInput) ||
          (preSubmitDom?.forms || [])[0] ||
          null;

        let resolvedSubmitUrl = step.submitUrl || '';
        if (resolvedSubmitUrl) {
          const submitUrlInfo = this._inspectAndResolvePlaceholders(resolvedSubmitUrl, { catchOtpError: true });
          if (submitUrlInfo.otpError) {
            pushOtpConfigIssue(stepIssues, stepNum, step.step, 'Submit', submitUrlInfo.otpError);
          }
          if (submitUrlInfo.unresolvedVars.length > 0) {
            pushUnresolvedVarIssues(stepIssues, stepNum, step.step, 'Submit', submitUrlInfo.unresolvedVars);
          }
          resolvedSubmitUrl = submitUrlInfo.resolved;
        }

        const rawSubmitTarget = resolvedSubmitUrl || activeForm?.actionUrl || currentPageUrl || this.loginUrl || this.targetUrl;
        const submitUrl = this._resolveAndVerifySequenceUrl(
          rawSubmitTarget,
          currentPageUrl || this.targetUrl || this.loginUrl,
          allowedOrigins
        );

        const method = step.method || activeForm?.method || this.loginMethod || 'POST';
        let contentType = step.contentType;
        if (!contentType) {
          if (this._hasExplicitContentType && this.loginContentType !== 'auto') {
            contentType = this.loginContentType;
          } else if (activeForm || preSubmitDom?.forms?.length || preSubmitDom?.inputs?.length) {
            contentType = 'form';
          } else {
            contentType = this.loginContentType === 'json' ? 'json' : 'form';
          }
        }

        const submitPayload = {
          ...(activeForm?.hiddenFields || {}),
          ...pendingInputs
        };
        if (this.csrfFormField && (this.csrfFormValue || this.csrfHeaderValue) && !Object.hasOwn(submitPayload, this.csrfFormField)) {
          submitPayload[this.csrfFormField] = this.csrfFormValue || this.csrfHeaderValue;
        }

        const reqHeaders = this.getAuthHeaders();
        let requestUrl = submitUrl;
        let requestBody;

        if (contentType === 'form') {
          if (method === 'GET') {
            const urlObj = new URL(submitUrl);
            for (const [k, v] of Object.entries(submitPayload)) {
              urlObj.searchParams.set(k, String(v ?? ''));
            }
            requestUrl = urlObj.toString();
          } else {
            reqHeaders['Content-Type'] = 'application/x-www-form-urlencoded';
            requestBody = new URLSearchParams(
              Object.entries(submitPayload).map(([k, v]) => [k, String(v ?? '')])
            ).toString();
          }
        } else {
          reqHeaders['Content-Type'] = 'application/json';
          requestBody = JSON.stringify(submitPayload);
        }

        let res = null;
        let submitFetchErr = null;
        try {
          res = await fetchWithRetry(requestUrl, {
            method,
            headers: reqHeaders,
            ...(requestBody !== undefined ? { body: requestBody } : {}),
            followRedirects: false
          });
        } catch (err) {
          if (isGovernanceOrSsrfError(err)) throw err;
          submitFetchErr = err;
        }

        if (submitFetchErr) {
          lastResponse = null;
          lastStatus = 0;
          const errMsg = submitFetchErr?.message || String(submitFetchErr);
          const isAbort = /aborted|timed?\s*out|ETIMEDOUT/i.test(errMsg);
          stepIssues.push({
            step: stepNum,
            sequenceStep: step.step,
            severity: 'error',
            code: isAbort ? 'NETWORK_TIMEOUT_OR_ABORT' : 'HTTP_AUTH_ERROR',
            title: isAbort
              ? `Step ${step.step} (Submit): Login request to ${requestUrl} timed out or was aborted`
              : `Step ${step.step} (Submit): Could not send login request to ${requestUrl}`,
            detail: `${errMsg} during ${method} ${requestUrl}.`,
            fixSuggestion: 'Check that the form Submit URL is reachable and matches the target login endpoint, or increase Request Timeout.'
          });
          const stepRecord = {
            step: stepNum,
            sequenceStep: step.step,
            action: 'click_button',
            type: 'click_button',
            label: step.label,
            selectorType: step.selectorType,
            selector: step.selector,
            url: requestUrl,
            finalUrl: requestUrl,
            method,
            contentType,
            redirected: false,
            status: 0,
            error: errMsg,
            cookiesHarvested: [],
            tokenExtracted: false
          };
          finalizeStepRecord(
            stepRecord,
            stepIssues,
            buildDomSnapshot(preSubmitDom || currentDom, requestUrl, 0, {
              clickedButton: matchedButton,
              pageErrorBanner: errMsg,
              unmatchedSelector: buttonUnmatchedSel
            })
          );
          continue;
        }

        const ingested = this._ingestLoginResponse(res);
        const harvestedCookies = [...ingested.cookiesHarvested];
        let tokenExtracted = ingested.tokenExtracted;

        let finalRes = res;
        let finalUrl = requestUrl;
        if (typeof res?.url === 'string' && res.url) {
          try {
            finalUrl = this._resolveAndVerifySequenceUrl(res.url, requestUrl, allowedOrigins);
          } catch {}
        }

        let redirectedTo = '';
        const submitStatus = Number(res?.status ?? 0);
        if (submitStatus >= 300 && submitStatus < 400) {
          const loc = getHeaderCaseInsensitive(res?.headers, 'location');
          if (loc) {
            const redirUrl = this._resolveAndVerifySequenceUrl(loc, submitUrl, allowedOrigins);
            redirectedTo = redirUrl;
            try {
              const redirRes = await fetchWithRetry(redirUrl, {
                method: 'GET',
                headers: this.getAuthHeaders(),
                followRedirects: false
              });
              const redirIngested = this._ingestLoginResponse(redirRes);
              harvestedCookies.push(...redirIngested.cookiesHarvested);
              tokenExtracted = tokenExtracted || redirIngested.tokenExtracted;
              finalRes = redirRes;
              finalUrl = redirUrl;
              if (typeof redirRes?.url === 'string' && redirRes.url) {
                try {
                  finalUrl = this._resolveAndVerifySequenceUrl(redirRes.url, redirUrl, allowedOrigins);
                } catch {}
              }
            } catch (redirErr) {
              if (isGovernanceOrSsrfError(redirErr)) throw redirErr;
            }
          }
        }

        if (tokenExtracted || harvestedCookies.length > 0) {
          gotSubmitAuthArtifact = true;
        }

        currentPageUrl = finalUrl;
        lastResponse = finalRes;
        lastStatus = Number(finalRes?.status ?? 0);
        ingestHtmlDomAndCsrf(finalRes, currentPageUrl);

        const pageErr = extractLoginErrorFromResponse(finalRes?.text || '', lastStatus);
        const snapshotDomForClick = (currentDom && (currentDom.inputs.length > 0 || currentDom.buttons.length > 0))
          ? currentDom
          : (preSubmitDom || currentDom);
        const clickDomSnapshot = buildDomSnapshot(snapshotDomForClick, currentPageUrl, lastStatus, {
          clickedButton: matchedButton,
          pageErrorBanner: pageErr,
          unmatchedSelector: buttonUnmatchedSel
        });

        pendingInputs = Object.create(null);
        filledFields.clear();
        activeFormIndex = this._pickDefaultFormAndPopulateHidden(currentDom, pendingInputs);

        if (lastStatus >= 400) {
          stepIssues.push({
            step: stepNum,
            sequenceStep: step.step,
            severity: 'error',
            code: 'HTTP_AUTH_ERROR',
            title: `Step ${step.step} (Submit): Authentication request failed with HTTP ${lastStatus}`,
            detail: pageErr
              ? `Server returned HTTP ${lastStatus}: "${pageErr}"`
              : `Server returned HTTP ${lastStatus} from ${requestUrl}.`,
            fixSuggestion: 'Check the credentials, OTP code, CSRF token, and target login endpoint.'
          });
        } else if (pageErr) {
          stepIssues.push({
            step: stepNum,
            sequenceStep: step.step,
            severity: 'error',
            code: 'LOGIN_ERROR_BANNER_DETECTED',
            title: `Step ${step.step} (Submit): Target page reported a login error`,
            detail: `Server message: "${pageErr}"`,
            fixSuggestion: 'Check the username/password values in System Variables and verify the form fields.'
          });
        }

        const stepRecord = {
          step: stepNum,
          sequenceStep: step.step,
          action: 'click_button',
          type: 'click_button',
          label: step.label,
          selectorType: step.selectorType,
          selector: step.selector,
          url: requestUrl,
          finalUrl: currentPageUrl,
          method,
          contentType,
          redirected: Boolean(redirectedTo),
          ...(redirectedTo ? { redirectUrl: redirectedTo } : {}),
          status: lastStatus,
          cookiesHarvested: Array.from(new Set(harvestedCookies)),
          tokenExtracted
        };
        finalizeStepRecord(stepRecord, stepIssues, clickDomSnapshot);
        continue;
      }

      if (step.type === 'extract_token') {
        let extracted = false;
        if (step.source === 'json') {
          const rawText = String(lastResponse?.text || '').trim();
          if (rawText.startsWith('{') || rawText.startsWith('[')) {
            try {
              const json = JSON.parse(rawText);
              const pathStr = step.tokenJsonPath || step.key;
              const candidate = pathStr ? resolveJsonPath(json, pathStr) : null;
              if (typeof candidate === 'string' && candidate.trim() && !/[\r\n]/.test(candidate)) {
                this.bearerToken = candidate.trim();
                extracted = true;
                gotSubmitAuthArtifact = true;
              }
            } catch {}
          }
        } else if (step.source === 'header') {
          const headerVal = getHeaderCaseInsensitive(lastResponse?.headers, step.key || 'authorization').trim();
          if (headerVal && !/[\r\n]/.test(headerVal)) {
            this.bearerToken = headerVal.replace(/^Bearer\s+/i, '').trim();
            extracted = Boolean(this.bearerToken);
            if (extracted) gotSubmitAuthArtifact = true;
          }
        } else if (step.source === 'cookie') {
          const cookieName = step.key;
          if (cookieName && this.cookies.has(cookieName)) {
            const cookieVal = this.cookies.get(cookieName);
            if (cookieVal && !/[\r\n]/.test(cookieVal)) {
              const lowerName = cookieName.toLowerCase();
              if (Object.hasOwn(CSRF_COOKIE_TO_HEADER, lowerName)) {
                this.csrfHeaderName = CSRF_COOKIE_TO_HEADER[lowerName];
                this.csrfHeaderValue = cookieVal;
              } else {
                this.bearerToken = cookieVal;
              }
              extracted = true;
              gotSubmitAuthArtifact = true;
            }
          }
        } else if (step.source === 'csrf') {
          const csrf = extractCsrfTokens(lastResponse?.text || '', lastResponse?.headers);
          if (csrf.formField && csrf.tokenValue) {
            this.csrfFormField = csrf.formField;
            this.csrfFormValue = csrf.tokenValue;
            extracted = true;
          }
          if (csrf.headerName && csrf.headerValue && !/[\r\n]/.test(csrf.headerValue)) {
            this.csrfHeaderName = csrf.headerName;
            this.csrfHeaderValue = csrf.headerValue;
            extracted = true;
          }
          if (!extracted && step.key && currentDom?.inputs) {
            const match = currentDom.inputs.find(i => i.name === step.key || i.id === step.key);
            if (match && match.value) {
              this.csrfFormField = match.name || step.key;
              this.csrfFormValue = match.value;
              extracted = true;
            }
          }
        }

        const stepRecord = {
          step: stepNum,
          sequenceStep: step.step,
          action: 'extract_token',
          type: 'extract_token',
          label: step.label,
          source: step.source,
          key: step.key || step.tokenJsonPath || null,
          extracted
        };
        const pageErr = extractLoginErrorFromResponse(lastResponse?.text || '', lastStatus);
        finalizeStepRecord(
          stepRecord,
          stepIssues,
          buildDomSnapshot(currentDom, currentPageUrl, lastStatus, { pageErrorBanner: pageErr })
        );
        continue;
      }

      if (step.type === 'custom_request') {
        hasSubmitStep = true;
        const unresolvedVars = [];
        let otpError = null;
        const collectInspection = (info) => {
          for (const u of info.unresolvedVars) {
            if (!unresolvedVars.includes(u)) unresolvedVars.push(u);
          }
          if (info.otpError && !otpError) otpError = info.otpError;
        };

        const rawReqUrl = step.url || '';
        const urlInspection = rawReqUrl
          ? this._inspectAndResolvePlaceholders(rawReqUrl, { catchOtpError: true })
          : { resolved: '', unresolvedVars: [], otpError: null };
        collectInspection(urlInspection);

        const resolvedExtraHeaders = {};
        for (const [hk, hv] of Object.entries(step.headers || {})) {
          if (FORBIDDEN_KEYS.has(hk) || /[\r\n]/.test(hk)) continue;
          const hdrInspection = this._inspectAndResolvePlaceholders(hv, { catchOtpError: true });
          collectInspection(hdrInspection);
          resolvedExtraHeaders[hk] = hdrInspection.resolved.replace(/[\r\n]+/g, ' ');
        }

        let resolvedPayload = null;
        if (step.payload !== null && step.payload !== undefined) {
          const tracker = { unresolvedVars, otpError: null, catchOtpError: true };
          resolvedPayload = this._resolvePayloadTemplates(step.payload, 0, tracker);
          if (tracker.otpError && !otpError) otpError = tracker.otpError;
        }

        if (otpError) {
          pushOtpConfigIssue(stepIssues, stepNum, step.step, 'Custom Request', otpError);
        }
        if (unresolvedVars.length > 0) {
          pushUnresolvedVarIssues(stepIssues, stepNum, step.step, 'Custom Request', unresolvedVars);
        }

        if (rawReqUrl && !urlInspection.resolved.trim() && urlInspection.unresolvedVars.length > 0) {
          const stepRecord = {
            step: stepNum,
            sequenceStep: step.step,
            action: 'custom_request',
            type: 'custom_request',
            label: step.label,
            method: step.method,
            url: rawReqUrl,
            contentType: step.contentType,
            status: 0,
            cookiesHarvested: [],
            tokenExtracted: false
          };
          finalizeStepRecord(stepRecord, stepIssues, buildDomSnapshot(currentDom, currentPageUrl, lastStatus));
          continue;
        }

        const reqUrl = this._resolveAndVerifySequenceUrl(
          urlInspection.resolved || currentPageUrl || this.loginUrl || this.targetUrl,
          currentPageUrl || this.targetUrl || this.loginUrl,
          allowedOrigins
        );

        const reqHeaders = this.getAuthHeaders(resolvedExtraHeaders);
        let finalReqUrl = reqUrl;
        let reqBody;

        if (step.payload !== null && step.payload !== undefined) {
          if (step.method === 'GET' || step.method === 'HEAD') {
            if (resolvedPayload && typeof resolvedPayload === 'object' && !Array.isArray(resolvedPayload)) {
              const urlObj = new URL(reqUrl);
              for (const [pk, pv] of Object.entries(resolvedPayload)) {
                urlObj.searchParams.set(pk, String(pv ?? ''));
              }
              finalReqUrl = urlObj.toString();
            }
          } else if (typeof resolvedPayload === 'string') {
            reqBody = resolvedPayload;
          } else if (step.contentType === 'form') {
            if (!getHeaderCaseInsensitive(reqHeaders, 'content-type')) {
              reqHeaders['Content-Type'] = 'application/x-www-form-urlencoded';
            }
            reqBody = new URLSearchParams(
              Object.entries(resolvedPayload).map(([k, v]) => [k, String(v ?? '')])
            ).toString();
          } else {
            if (!getHeaderCaseInsensitive(reqHeaders, 'content-type')) {
              reqHeaders['Content-Type'] = 'application/json';
            }
            reqBody = JSON.stringify(resolvedPayload);
          }
        }

        let res = null;
        let customFetchErr = null;
        try {
          res = await fetchWithRetry(finalReqUrl, {
            method: step.method,
            headers: reqHeaders,
            ...(reqBody !== undefined ? { body: reqBody } : {}),
            followRedirects: false
          });
        } catch (err) {
          if (isGovernanceOrSsrfError(err)) throw err;
          customFetchErr = err;
        }

        if (customFetchErr) {
          lastResponse = null;
          lastStatus = 0;
          const errMsg = customFetchErr?.message || String(customFetchErr);
          const isAbort = /aborted|timed?\s*out|ETIMEDOUT/i.test(errMsg);
          stepIssues.push({
            step: stepNum,
            sequenceStep: step.step,
            severity: 'error',
            code: isAbort ? 'NETWORK_TIMEOUT_OR_ABORT' : 'HTTP_AUTH_ERROR',
            title: isAbort
              ? `Step ${step.step} (${step.method}): Request to ${finalReqUrl} timed out or was aborted`
              : `Step ${step.step} (${step.method}): Could not connect to ${finalReqUrl}`,
            detail: `${errMsg} during ${step.method} ${finalReqUrl}.`,
            fixSuggestion: 'Verify the custom request URL is reachable and check "Allow Authorized Internal / Private Targets" if needed.'
          });
          const stepRecord = {
            step: stepNum,
            sequenceStep: step.step,
            action: 'custom_request',
            type: 'custom_request',
            label: step.label,
            method: step.method,
            url: finalReqUrl,
            contentType: step.contentType,
            status: 0,
            error: errMsg,
            cookiesHarvested: [],
            tokenExtracted: false
          };
          finalizeStepRecord(
            stepRecord,
            stepIssues,
            buildDomSnapshot(currentDom, finalReqUrl, 0, { pageErrorBanner: errMsg })
          );
          continue;
        }

        const ingested = this._ingestLoginResponse(res);
        if (ingested.tokenExtracted || ingested.cookiesHarvested.length > 0) {
          gotSubmitAuthArtifact = true;
        }

        lastResponse = res;
        lastStatus = Number(res?.status ?? 0);
        if (typeof res?.text === 'string' && res.text.includes('<')) {
          currentPageUrl = finalReqUrl;
          ingestHtmlDomAndCsrf(res, currentPageUrl);
          pendingInputs = Object.create(null);
          filledFields.clear();
          activeFormIndex = this._pickDefaultFormAndPopulateHidden(currentDom, pendingInputs);
        }

        const pageErr = extractLoginErrorFromResponse(res?.text || '', lastStatus);
        if (lastStatus >= 400) {
          stepIssues.push({
            step: stepNum,
            sequenceStep: step.step,
            severity: 'error',
            code: 'HTTP_AUTH_ERROR',
            title: `Step ${step.step} (${step.method}): Authentication request failed with HTTP ${lastStatus}`,
            detail: pageErr
              ? `Server returned HTTP ${lastStatus}: "${pageErr}"`
              : `Server returned HTTP ${lastStatus} from ${finalReqUrl}.`,
            fixSuggestion: 'Verify the request payload, System Variables, headers, and endpoint URL.'
          });
        } else if (pageErr) {
          stepIssues.push({
            step: stepNum,
            sequenceStep: step.step,
            severity: 'error',
            code: 'LOGIN_ERROR_BANNER_DETECTED',
            title: `Step ${step.step} (Submit): Target page reported a login error`,
            detail: `Server message: "${pageErr}"`,
            fixSuggestion: 'Check the username/password values in System Variables and verify the form fields.'
          });
        }

        const stepRecord = {
          step: stepNum,
          sequenceStep: step.step,
          action: 'custom_request',
          type: 'custom_request',
          label: step.label,
          method: step.method,
          url: finalReqUrl,
          contentType: step.contentType,
          status: lastStatus,
          cookiesHarvested: ingested.cookiesHarvested,
          tokenExtracted: ingested.tokenExtracted
        };
        finalizeStepRecord(
          stepRecord,
          stepIssues,
          buildDomSnapshot(currentDom, currentPageUrl, lastStatus, { pageErrorBanner: pageErr })
        );
      }
    }

    const hasFatalAuthDiagnostic = diagnostics.some(d =>
      d.severity === 'error' &&
      (
        d.code === 'HTTP_AUTH_ERROR' ||
        d.code === 'LOGIN_ERROR_BANNER_DETECTED' ||
        d.code === 'OTP_CONFIG_ERROR' ||
        d.code === 'NETWORK_TIMEOUT_OR_ABORT'
      )
    );
    const hasStepSetupErrorWithoutArtifact = Boolean(
      !gotSubmitAuthArtifact &&
      !this.bearerToken &&
      diagnostics.some(d =>
        d.severity === 'error' &&
        (
          d.code === 'SELECTOR_NOT_FOUND' ||
          d.code === 'UNRESOLVED_VARIABLE' ||
          d.code === 'NAVIGATION_HTTP_ERROR' ||
          d.code === 'NETWORK_TIMEOUT_OR_ABORT'
        )
      )
    );
    const remainedOnPasswordLoginWithoutArtifact = Boolean(
      hasSubmitStep &&
      !gotSubmitAuthArtifact &&
      !this.bearerToken &&
      currentDom?.hasPasswordInput
    );
    const lastSubmitRejected = Boolean(lastStatus >= 400 && !gotSubmitAuthArtifact);

    this._lastLoginRejected = Boolean(
      lastSubmitRejected ||
      hasFatalAuthDiagnostic ||
      hasStepSetupErrorWithoutArtifact ||
      remainedOnPasswordLoginWithoutArtifact
    );
    const authenticated = this._lastLoginRejected
      ? false
      : Boolean(this.bearerToken || this.cookies.size > 0);
    if (!authenticated && diagnostics.length === 0) {
      diagnostics.push({
        step: this.recordedSteps.length || 1,
        sequenceStep: this.loginSequence.actions[this.loginSequence.actions.length - 1]?.step || 1,
        severity: 'error',
        code: 'NO_POST_SUBMIT_SESSION_ARTIFACT',
        title: 'Login Incomplete: No session cookie or auth token was issued after submitting credentials',
        detail: 'The target did not issue a session cookie or Bearer token (or remained on the login form).',
        fixSuggestion: 'Check the Visual Replay Preview for each step to verify all input selectors and System Variables matched the login form.'
      });
    }
    if (authenticated) {
      this.authenticatedAt = new Date().toISOString();
    }

    this.reauthCount += 1;
    return {
      authenticated,
      authMethod: 'login_sequence',
      status: lastStatus,
      loginUrl: this.loginUrl || currentPageUrl || null,
      sessionId: this.sessionId,
      authenticatedAt: this.authenticatedAt,
      cookieCount: this.cookies.size,
      cookieNames: Array.from(this.cookies.keys()),
      hasBearerToken: Boolean(this.bearerToken),
      csrfHeaderName: this.csrfHeaderName,
      reauthCount: this.reauthCount,
      stepsExecuted: sequenceStepResults.length,
      sequenceSteps: sequenceStepResults,
      diagnostics: this.lastDiagnostics || []
    };
  }

  /**
   * Executes the configured Login Macro against `this.loginUrl`:
   *  0. If `this.loginSequence?.actions?.length > 0`, delegates to `executeLoginSequence()`.
   *  1. Auto-discovers `loginUrl` from common paths if omitted and `targetUrl` + `username` are set.
   *  2. Performs a pre-flight GET to `loginUrl` to harvest cookies, CSRF tokens, and HTML form structure.
   *  3. Submits credentials as form-urlencoded or JSON (with automatic JSON -> form fallback on 400/415/422 in `auto` mode).
   *  4. Extracts `Set-Cookie` session cookies and JSON Bearer JWT tokens.
   *
   * @param {Function} fetchWithRetry
   */
  async executeLoginMacro(fetchWithRetry) {
    if (this.loginSequence && Array.isArray(this.loginSequence.actions) && this.loginSequence.actions.length > 0) {
      return await this.executeLoginSequence(fetchWithRetry);
    }

    if (!this.loginUrl) {
      if (this.targetUrl && (this.username !== null || this.loginPayload !== null)) {
        const discovery = await this.discoverLoginUrl(fetchWithRetry);
        if (!discovery.discovered || !this.loginUrl) {
          throw new Error(`Could not auto-discover a login endpoint on ${this.targetUrl}`);
        }
      } else {
        throw new Error('AuthSessionManager has no loginUrl configured');
      }
    }

    if (this.reauthCount === 0) {
      this.recordedSteps = [];
    }

    // Step 1: Preflight GET to harvest initial CSRF token, cookies, and login form
    let preRes = null;
    let parsedForm = null;
    let preCookiesHarvested = [];
    let preCsrfDetected = false;
    let preError = null;

    const cached = this._discoveredPreflight;
    this._discoveredPreflight = null;

    if (cached && cached.url === this.loginUrl) {
      preRes = cached.res;
      parsedForm = cached.parsedForm;
      preCookiesHarvested = cached.cookiesHarvested || [];
      preCsrfDetected = Boolean(cached.csrfDetected);
    } else {
      try {
        preRes = await fetchWithRetry(this.loginUrl, {
          method: 'GET',
          headers: this.getAuthHeaders(),
          followRedirects: false
        });
        if (preRes) {
          const preInfo = this._ingestPreflightResponse(preRes, this.loginUrl);
          preCookiesHarvested = preInfo.cookiesHarvested;
          preCsrfDetected = preInfo.csrfDetected;
          parsedForm = preInfo.parsedForm;
        }
      } catch (err) {
        if (err?.isGovernanceBlock) throw err;
        preError = err?.message || String(err);
      }
    }

    this.recordedSteps.push({
      step: this.recordedSteps.length + 1,
      action: 'preflight_get',
      url: this.loginUrl,
      status: Number(preRes?.status ?? 0),
      csrfDetected: Boolean(preCsrfDetected),
      cookiesHarvested: preCookiesHarvested,
      ...(preError ? { error: preError } : {})
    });

    // Step 2: Build login request target, method, content-type, and payload
    let submitUrl = this.loginUrl;
    let submitMethod = this.loginMethod;
    let usedContentType = this.loginContentType === 'form' ? 'form' : 'json';
    let usedUsernameField = this.usernameField || null;
    let bodyStr = '';
    let payloadObj = {};

    const hasExplicitPayload = this.loginPayload !== null && this.loginPayload !== undefined;
    const useCredentialAutoMode = !hasExplicitPayload && (this.username !== null || this.password !== null);

    if (hasExplicitPayload) {
      if (typeof this.loginPayload === 'string') {
        bodyStr = this.loginPayload;
      } else if (typeof this.loginPayload === 'object') {
        payloadObj = { ...this.loginPayload };
        if (this.csrfFormField && (this.csrfFormValue || this.csrfHeaderValue) && !Object.hasOwn(payloadObj, this.csrfFormField)) {
          payloadObj[this.csrfFormField] = this.csrfFormValue || this.csrfHeaderValue;
        }
      }
      usedContentType = this.loginContentType === 'form' ? 'form' : 'json';
    } else if (useCredentialAutoMode) {
      const userStr = String(this.username ?? '');
      const passStr = String(this.password ?? '');
      const htmlFormDetected = Boolean(parsedForm?.hasPasswordInput);

      if (htmlFormDetected && (this.loginContentType === 'auto' || this.loginContentType === 'form')) {
        usedContentType = 'form';
        if (parsedForm.actionUrl) {
          try {
            if (new URL(parsedForm.actionUrl).origin === new URL(this.loginUrl).origin) {
              submitUrl = parsedForm.actionUrl;
            }
          } catch {}
        }
        submitMethod = parsedForm.method === 'GET' ? 'GET' : (this.loginMethod || 'POST');
        usedUsernameField = this.usernameField || parsedForm.usernameField || 'username';
        const usedPasswordField = this.passwordField || parsedForm.passwordField || 'password';
        payloadObj = {
          ...(parsedForm.hiddenFields || {}),
          [usedUsernameField]: userStr,
          [usedPasswordField]: passStr
        };
      } else if (this.loginContentType === 'form') {
        usedContentType = 'form';
        usedUsernameField = this.usernameField || 'username';
        const usedPasswordField = this.passwordField || 'password';
        payloadObj = {
          [usedUsernameField]: userStr,
          [usedPasswordField]: passStr
        };
      } else {
        usedContentType = 'json';
        usedUsernameField = this.usernameField || 'username';
        const usedPasswordField = this.passwordField || 'password';
        payloadObj = {
          [usedUsernameField]: userStr,
          ...(userStr.includes('@') && !this.usernameField ? { email: userStr } : {}),
          [usedPasswordField]: passStr
        };
      }

      if (this.csrfFormField && (this.csrfFormValue || this.csrfHeaderValue) && !Object.hasOwn(payloadObj, this.csrfFormField)) {
        payloadObj[this.csrfFormField] = this.csrfFormValue || this.csrfHeaderValue;
      }
    } else {
      if (this.csrfFormField && (this.csrfFormValue || this.csrfHeaderValue)) {
        payloadObj[this.csrfFormField] = this.csrfFormValue || this.csrfHeaderValue;
      }
    }

    const sendLoginRequest = async (target, method, contentType, payload, rawStringBody = null) => {
      const reqHeaders = this.getAuthHeaders();
      let requestUrl = target;
      let requestBody;

      if (rawStringBody !== null) {
        requestBody = rawStringBody;
      } else if (contentType === 'form') {
        const encoded = new URLSearchParams(
          Object.entries(payload).map(([k, v]) => [k, String(v ?? '')])
        ).toString();
        if (method === 'GET') {
          const urlObj = new URL(target);
          for (const [k, v] of Object.entries(payload)) {
            urlObj.searchParams.set(k, String(v ?? ''));
          }
          requestUrl = urlObj.toString();
        } else {
          reqHeaders['Content-Type'] = 'application/x-www-form-urlencoded';
          requestBody = encoded;
        }
      } else {
        reqHeaders['Content-Type'] = 'application/json';
        requestBody = JSON.stringify(payload);
      }

      const res = await fetchWithRetry(requestUrl, {
        method,
        headers: reqHeaders,
        ...(requestBody !== undefined ? { body: requestBody } : {}),
        followRedirects: false
      });
      const ingested = this._ingestLoginResponse(res);
      return { res, requestUrl, ingested };
    };

    const rawStringBody = typeof this.loginPayload === 'string' ? bodyStr : null;
    let attempt = await sendLoginRequest(submitUrl, submitMethod, usedContentType, payloadObj, rawStringBody);
    let loginRes = attempt.res;
    let loginStatus = Number(loginRes?.status ?? 0);
    let hasSessionArtifact = Boolean(this.bearerToken || this.cookies.size > 0);
    let loginSucceeded = hasSessionArtifact && loginStatus > 0 && loginStatus < 400;

    this.recordedSteps.push({
      step: this.recordedSteps.length + 1,
      action: 'submit_credentials',
      url: attempt.requestUrl,
      method: submitMethod,
      contentType: usedContentType,
      usernameField: usedUsernameField,
      username: this.username || null,
      password: '[REDACTED]',
      status: loginStatus,
      authenticated: loginSucceeded
    });

    // Auto fallback from JSON -> form-urlencoded on 400/415/422 in auto mode
    if (
      useCredentialAutoMode &&
      this.loginContentType === 'auto' &&
      usedContentType === 'json' &&
      (loginStatus === 400 || loginStatus === 415 || loginStatus === 422)
    ) {
      const userStr = String(this.username ?? '');
      const passStr = String(this.password ?? '');
      const uField = this.usernameField || parsedForm?.usernameField || 'username';
      const pField = this.passwordField || parsedForm?.passwordField || 'password';
      const formPayload = {
        ...(parsedForm?.hiddenFields || {}),
        [uField]: userStr,
        [pField]: passStr
      };
      if (this.csrfFormField && (this.csrfFormValue || this.csrfHeaderValue) && !Object.hasOwn(formPayload, this.csrfFormField)) {
        formPayload[this.csrfFormField] = this.csrfFormValue || this.csrfHeaderValue;
      }

      usedContentType = 'form';
      usedUsernameField = uField;
      attempt = await sendLoginRequest(submitUrl, submitMethod, 'form', formPayload, null);
      loginRes = attempt.res;
      loginStatus = Number(loginRes?.status ?? 0);
      hasSessionArtifact = Boolean(this.bearerToken || this.cookies.size > 0);
      loginSucceeded = hasSessionArtifact && loginStatus > 0 && loginStatus < 400;

      this.recordedSteps.push({
        step: this.recordedSteps.length + 1,
        action: 'submit_credentials',
        fallbackFrom: 'json',
        url: attempt.requestUrl,
        method: submitMethod,
        contentType: 'form',
        usernameField: usedUsernameField,
        username: this.username || null,
        password: '[REDACTED]',
        status: loginStatus,
        authenticated: loginSucceeded
      });
    }

    const gotNewAuthArtifact = Boolean(attempt.ingested.tokenExtracted || attempt.ingested.cookiesHarvested.length > 0);
    this._lastLoginRejected = Boolean(loginStatus >= 400 && !gotNewAuthArtifact);
    const authenticated = this._lastLoginRejected ? false : Boolean(this.bearerToken || this.cookies.size > 0);
    if (authenticated) {
      this.authenticatedAt = new Date().toISOString();
    }

    this.reauthCount += 1;
    return {
      authenticated,
      status: loginStatus,
      loginUrl: this.loginUrl,
      sessionId: this.sessionId,
      authenticatedAt: this.authenticatedAt,
      cookieCount: this.cookies.size,
      cookieNames: Array.from(this.cookies.keys()),
      hasBearerToken: Boolean(this.bearerToken),
      csrfHeaderName: this.csrfHeaderName,
      reauthCount: this.reauthCount
    };
  }

  /**
   * Returns a structured summary of the recorded session.
   * Masks sensitive cookie values, bearer token, and password unless `includeSecrets: true`.
   *
   * @param {{ includeSecrets?: boolean }} [options={}]
   * @returns {object}
   */
  getRecordedSession({ includeSecrets = false } = {}) {
    const authenticated = this._lastLoginRejected
      ? false
      : Boolean(this.bearerToken || this.cookies.size > 0);
    const bearerTokenPreview = this.bearerToken
      ? (this.bearerToken.length > 12
          ? `${this.bearerToken.slice(0, 12)}...`
          : `${this.bearerToken.slice(0, Math.max(2, Math.floor(this.bearerToken.length / 2)))}...`)
      : null;

    const hasSequence = Boolean(this.loginSequence && Array.isArray(this.loginSequence.actions) && this.loginSequence.actions.length > 0);

    return {
      sessionId: this.sessionId,
      targetUrl: this.targetUrl || this.loginUrl || null,
      loginUrl: this.loginUrl,
      loginMethod: this.loginMethod,
      loginContentType: this.loginContentType,
      username: this.username || null,
      password: '[REDACTED]',
      authenticated,
      authenticatedAt: this.authenticatedAt,
      cookieCount: this.cookies.size,
      cookieNames: Array.from(this.cookies.keys()),
      cookies: includeSecrets
        ? Object.fromEntries(this.cookies.entries())
        : Object.fromEntries(Array.from(this.cookies.keys()).map(k => [k, '[CAPTURED]'])),
      hasBearerToken: Boolean(this.bearerToken),
      bearerTokenPreview,
      ...(includeSecrets && this.bearerToken ? { bearerToken: this.bearerToken } : {}),
      csrfHeaderName: this.csrfHeaderName,
      ...(includeSecrets && this.csrfHeaderValue ? { csrfHeaderValue: this.csrfHeaderValue } : {}),
      csrfFormField: this.csrfFormField,
      reauthCount: this.reauthCount,
      authMethod: hasSequence ? 'login_sequence' : 'macro',
      loginSequence: this.loginSequence ? exportLsrSequence(this.loginSequence, { includeSecrets }) : null,
      systemVariables: exportSystemVariables(Array.from(this.systemVariables.values()), { includeSecrets }),
      otpConfigured: Boolean(this.otpConfig?.enabled || this.otpConfig?.secret || this.otpConfig?.secretName || this.otpConfig?.variableName),
      restrictions: [...this.restrictions],
      sessionDetection: {
        ...this.sessionDetection,
        statusCodes: [...(this.sessionDetection?.statusCodes || [])]
      },
      ...(includeSecrets && !this.loginSequence && this.secrets.size > 0
        ? {
            secrets: Array.from(this.secrets.entries()).map(([name, value]) => ({
              name,
              value,
              description: this._secretMeta.get(name) || ''
            }))
          }
        : {}),
      ...(includeSecrets && !this.loginSequence && (this.otpConfig?.secret || this.otpConfig?.secretName || this.otpConfig?.variableName)
        ? { otpConfig: { ...this.otpConfig } }
        : {}),
      diagnostics: (this.lastDiagnostics || []).map(d => ({ ...d })),
      steps: this.recordedSteps.map(s => ({ ...s }))
    };
  }

  /**
   * Exports the full recorded session including cookies, Bearer token, and CSRF token
   * for saving to disk and reloading with `AuthSessionManager.fromRecordedSession()`.
   *
   * @returns {object}
   */
  exportRecordedSession() {
    return this.getRecordedSession({ includeSecrets: true });
  }

  /**
   * Wraps a governed `fetchWithRetry` function so that:
   *  - Logout/signout and restricted URLs are blocked automatically,
   *  - Session cookies, Bearer tokens, and CSRF headers are attached to every request,
   *  - `Set-Cookie` headers from responses update the Cookie Jar, and
   *  - Session expiration responses trigger an automatic login macro/sequence refresh (up to `maxReauthAttempts`).
   */
  wrapFetch(baseFetch) {
    const wrapped = async (url, options = {}, ...rest) => {
      if (this.isRestrictedUrl(url)) {
        return {
          status: 204,
          headers: {},
          text: '',
          skippedLogoutGuard: true,
          restrictedUrl: true
        };
      }

      const safeOpts = options && typeof options === 'object' ? options : {};
      const mergedHeaders = this.getAuthHeaders(safeOpts.headers || {});
      let res = await baseFetch(url, { ...safeOpts, headers: mergedHeaders }, ...rest);
      if (res?.headers) {
        this.ingestResponseHeaders(res.headers);
      }

      const hasSequence = Boolean(this.loginSequence && Array.isArray(this.loginSequence.actions) && this.loginSequence.actions.length > 0);
      const hasMacroCreds = Boolean(
        this.loginUrl &&
        (this.loginPayload !== null || (this.username !== null && this.password !== null))
      );
      const canReauth = Boolean(
        this.reauthCount < this.maxReauthAttempts &&
        (hasSequence || hasMacroCreds)
      );

      if (res && this.isSessionExpiredResponse(res) && canReauth) {
        if (!this._reauthPromise) {
          this._reauthPromise = this.executeLoginMacro(baseFetch).finally(() => {
            this._reauthPromise = null;
          });
        }
        await this._reauthPromise;
        const retryHeaders = this.getAuthHeaders(safeOpts.headers || {});
        res = await baseFetch(url, { ...safeOpts, headers: retryHeaders }, ...rest);
        if (res?.headers) {
          this.ingestResponseHeaders(res.headers);
        }
      }

      return res;
    };

    for (const key of [
      'governance',
      'tlsAlpnProbe',
      'governor',
      'guard',
      'trafficStore',
      'sourceIp',
      'sourceIpMap',
      'resolveCache',
      'targetPinStore',
      'hasCustomFetcher',
      'isDefaultFetch'
    ]) {
      if (baseFetch && baseFetch[key] !== undefined) {
        wrapped[key] = baseFetch[key];
      }
    }
    return wrapped;
  }
}
