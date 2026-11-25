/**
 * Burp Suite Decoder, Smart Inspector (JWT / Nested Encoding Unwrapper) & Response Comparer Engine.
 *
 * Provides:
 *  - `runDecoderStep(input, operation)` & `runDecoderPipeline(input, steps)`
 *  - `inspectJwtToken(token)` & `smartInspectValue(input, options)`
 *  - `compareResponses(left, right, options)`
 */

import crypto from 'node:crypto';
import zlib from 'node:zlib';

export const MAX_DECODER_INPUT_BYTES = 512 * 1024; // 512 KiB
export const MAX_DECOMPRESS_BYTES = 4 * 1024 * 1024; // 4 MiB

export const SUPPORTED_DECODER_OPERATIONS = new Set([
  'url_decode',
  'url_encode',
  'url_encode_all',
  'base64_decode',
  'base64_encode',
  'base64url_decode',
  'base64url_encode',
  'hex_decode',
  'hex_encode',
  'html_decode',
  'html_encode',
  'unicode_unescape',
  'unicode_escape',
  'gzip_decompress',
  'gzip_compress',
  'deflate_decompress',
  'sha256',
  'sha1',
  'md5',
  'jwt_inspect'
]);

const HTML_NAMED_ENTITIES = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  nbsp: ' '
};

function enforceInputBound(raw) {
  const str = typeof raw === 'string' ? raw : String(raw ?? '');
  if (Buffer.byteLength(str, 'utf8') > MAX_DECODER_INPUT_BYTES) {
    throw new Error(`Input exceeds maximum allowed size (${MAX_DECODER_INPUT_BYTES} bytes)`);
  }
  return str;
}

function decodeHtmlEntities(str) {
  return str.replace(/&(?:#(\d{1,7})|#x([0-9a-fA-F]{1,6})|([a-zA-Z]{2,8}));/g, (full, dec, hex, named) => {
    if (dec !== undefined) {
      const code = Number.parseInt(dec, 10);
      return Number.isFinite(code) && code >= 0 && code <= 0x10ffff ? String.fromCodePoint(code) : full;
    }
    if (hex !== undefined) {
      const code = Number.parseInt(hex, 16);
      return Number.isFinite(code) && code >= 0 && code <= 0x10ffff ? String.fromCodePoint(code) : full;
    }
    const lower = String(named || '').toLowerCase();
    return Object.hasOwn(HTML_NAMED_ENTITIES, lower) ? HTML_NAMED_ENTITIES[lower] : full;
  });
}

function encodeHtmlEntities(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function base64UrlToBuffer(str) {
  const cleaned = str.trim().replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (cleaned.length % 4)) % 4;
  const padded = cleaned + '='.repeat(padLen);
  return Buffer.from(padded, 'base64');
}

function isLikelyPrintableUtf8(buf) {
  if (!Buffer.isBuffer(buf) || buf.length === 0) return false;
  const text = buf.toString('utf8');
  if (text.includes('\ufffd')) return false;
  let printable = 0;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code === 9 || code === 10 || code === 13 || (code >= 32 && code <= 126) || code >= 160) {
      printable++;
    }
  }
  return printable / text.length >= 0.85;
}

/**
 * Inspects a JWT token (`header.payload.signature`) for structural and security issues.
 *
 * @param {string} rawToken
 * @returns {{
 *   valid: boolean,
 *   header?: object,
 *   payload?: object,
 *   signaturePresent?: boolean,
 *   signatureHexPreview?: string,
 *   securityNotes: string[],
 *   riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE'
 * }}
 */
export function inspectJwtToken(rawToken) {
  const token = String(rawToken || '').trim().replace(/^Bearer\s+/i, '').trim();
  const parts = token.split('.');
  if (parts.length !== 3 || !parts[0] || !parts[1]) {
    return {
      valid: false,
      securityNotes: ['Input is not a 3-part JWS/JWT token (header.payload.signature).'],
      riskLevel: 'NONE'
    };
  }

  let header;
  let payload;
  try {
    header = JSON.parse(base64UrlToBuffer(parts[0]).toString('utf8'));
    payload = JSON.parse(base64UrlToBuffer(parts[1]).toString('utf8'));
  } catch (err) {
    return {
      valid: false,
      securityNotes: [`Failed to decode JWT JSON segments: ${err.message}`],
      riskLevel: 'NONE'
    };
  }

  if (!header || typeof header !== 'object' || !payload || typeof payload !== 'object') {
    return {
      valid: false,
      securityNotes: ['Decoded JWT header or payload is not a JSON object.'],
      riskLevel: 'NONE'
    };
  }

  const securityNotes = [];
  let riskLevel = 'NONE';
  const elevate = (level) => {
    const order = ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    if (order.indexOf(level) > order.indexOf(riskLevel)) {
      riskLevel = level;
    }
  };

  const alg = String(header.alg ?? '').trim();
  if (!alg || /^none$/i.test(alg)) {
    securityNotes.push(`CRITICAL: JWT uses unsigned algorithm "${alg || 'none'}" (CWE-347 signature bypass).`);
    elevate('CRITICAL');
  } else if (/^HS(?:256|384|512)$/i.test(alg)) {
    securityNotes.push(`INFO: JWT uses symmetric HMAC algorithm "${alg}" — verify secret entropy and ensure RS256/HS256 key-confusion is blocked.`);
    elevate('LOW');
  }

  if (!parts[2] && !/^none$/i.test(alg)) {
    securityNotes.push('HIGH: JWT signature segment is empty despite non-none algorithm.');
    elevate('HIGH');
  }

  if (typeof header.kid === 'string') {
    if (/(\.\.[/\\]|[/\\]etc[/\\]|['";|&$]|union\s+select)/i.test(header.kid)) {
      securityNotes.push(`HIGH: JWT "kid" header contains path traversal, SQLi, or shell metacharacters: ${JSON.stringify(header.kid)}.`);
      elevate('HIGH');
    }
  }

  for (const urlHeader of ['jku', 'x5u']) {
    if (typeof header[urlHeader] === 'string' && header[urlHeader].trim()) {
      securityNotes.push(`HIGH: JWT "${urlHeader}" header specifies external key URL (${header[urlHeader]}) — risk of SSRF / rogue key injection.`);
      elevate('HIGH');
    }
  }

  if (header.jwk && typeof header.jwk === 'object') {
    securityNotes.push('HIGH: JWT embeds inline "jwk" public key in header — verify server does not trust self-signed embedded keys.');
    elevate('HIGH');
  }

  if (payload.exp === undefined || payload.exp === null) {
    securityNotes.push('MEDIUM: JWT payload has no "exp" (expiration) claim.');
    elevate('MEDIUM');
  } else if (Number.isFinite(Number(payload.exp))) {
    const expMs = Number(payload.exp) * 1000;
    if (expMs < Date.now()) {
      securityNotes.push(`LOW: JWT token is expired (exp=${new Date(expMs).toISOString()}).`);
      elevate('LOW');
    }
  }

  for (const privKey of ['role', 'roles', 'is_admin', 'isAdmin', 'admin', 'permissions', 'scope', 'groups']) {
    if (Object.hasOwn(payload, privKey)) {
      securityNotes.push(`INFO: Authorization claim "${privKey}" present in payload: ${JSON.stringify(payload[privKey])}.`);
    }
  }

  const sigBuf = parts[2] ? base64UrlToBuffer(parts[2]) : Buffer.alloc(0);
  return {
    valid: true,
    header,
    payload,
    signaturePresent: Boolean(parts[2]),
    signatureHexPreview: sigBuf.subarray(0, 16).toString('hex'),
    securityNotes,
    riskLevel
  };
}

/**
 * Executes a single Burp Decoder transformation step.
 *
 * @param {string} rawInput
 * @param {string} operation
 * @returns {string}
 */
export function runDecoderStep(rawInput, operation) {
  const input = enforceInputBound(rawInput);
  const op = String(operation || '').trim().toLowerCase();
  if (!SUPPORTED_DECODER_OPERATIONS.has(op)) {
    throw new Error(`Unsupported decoder operation: "${operation}"`);
  }

  switch (op) {
    case 'url_decode': {
      try {
        return decodeURIComponent(input.replace(/\+/g, '%20'));
      } catch {
        return unescape(input);
      }
    }
    case 'url_encode':
      return encodeURIComponent(input);
    case 'url_encode_all':
      return Array.from(Buffer.from(input, 'utf8'))
        .map(b => `%${b.toString(16).padStart(2, '0').toUpperCase()}`)
        .join('');
    case 'base64_decode':
      return Buffer.from(input.trim(), 'base64').toString('utf8');
    case 'base64_encode':
      return Buffer.from(input, 'utf8').toString('base64');
    case 'base64url_decode':
      return base64UrlToBuffer(input).toString('utf8');
    case 'base64url_encode':
      return Buffer.from(input, 'utf8')
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
    case 'hex_decode': {
      const cleanHex = input.replace(/[^0-9a-fA-F]/g, '');
      if (cleanHex.length % 2 !== 0) {
        throw new Error('Hex string must have an even number of hexadecimal digits');
      }
      return Buffer.from(cleanHex, 'hex').toString('utf8');
    }
    case 'hex_encode':
      return Buffer.from(input, 'utf8').toString('hex');
    case 'html_decode':
      return decodeHtmlEntities(input);
    case 'html_encode':
      return encodeHtmlEntities(input);
    case 'unicode_unescape':
      return input
        .replace(/\\u\{([0-9a-fA-F]{1,6})\}/g, (_, hex) => String.fromCodePoint(Number.parseInt(hex, 16)))
        .replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16)))
        .replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16)));
    case 'unicode_escape':
      return Array.from(input)
        .map(ch => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`)
        .join('');
    case 'gzip_decompress': {
      const buf = Buffer.from(input.trim(), 'base64');
      return zlib.gunzipSync(buf, { maxOutputLength: MAX_DECOMPRESS_BYTES }).toString('utf8');
    }
    case 'gzip_compress':
      return zlib.gzipSync(Buffer.from(input, 'utf8')).toString('base64');
    case 'deflate_decompress': {
      const buf = Buffer.from(input.trim(), 'base64');
      try {
        return zlib.inflateSync(buf, { maxOutputLength: MAX_DECOMPRESS_BYTES }).toString('utf8');
      } catch {
        return zlib.inflateRawSync(buf, { maxOutputLength: MAX_DECOMPRESS_BYTES }).toString('utf8');
      }
    }
    case 'sha256':
      return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
    case 'sha1':
      return crypto.createHash('sha1').update(input, 'utf8').digest('hex');
    case 'md5':
      return crypto.createHash('md5').update(input, 'utf8').digest('hex');
    case 'jwt_inspect':
      return JSON.stringify(inspectJwtToken(input), null, 2);
    default:
      throw new Error(`Unsupported operation: ${op}`);
  }
}

/**
 * Executes a multi-stage Burp Decoder pipeline (`steps: ['url_decode', 'base64_decode', ...]`).
 *
 * @param {string} rawInput
 * @param {string[]} [steps=[]]
 * @returns {{
 *   input: string,
 *   output: string,
 *   history: Array<{ step: number, operation: string, output: string }>
 * }}
 */
export function runDecoderPipeline(rawInput, steps = []) {
  const initial = enforceInputBound(rawInput);
  if (!Array.isArray(steps) || steps.length === 0) {
    return { input: initial, output: initial, history: [] };
  }
  if (steps.length > 16) {
    throw new Error('Decoder pipeline cannot exceed 16 steps');
  }

  let current = initial;
  const history = [];
  for (let i = 0; i < steps.length; i++) {
    const op = String(steps[i] || '').trim().toLowerCase();
    current = runDecoderStep(current, op);
    history.push({
      step: i + 1,
      operation: op,
      output: current
    });
  }

  return {
    input: initial,
    output: current,
    history
  };
}

/**
 * Burp Inspector-style Recursive Smart Auto-Decoder.
 * Automatically detects and unwraps nested URL-encoding, Base64/Base64URL, Hex, HTML entities,
 * Unicode escapes, JSON structures, and JWT tokens up to `maxDepth` (default 5).
 *
 * @param {string} rawInput
 * @param {{ maxDepth?: number }} [options={}]
 */
export function smartInspectValue(rawInput, options = {}) {
  const initial = enforceInputBound(rawInput).trim();
  const maxDepth = Math.min(8, Math.max(1, Number(options.maxDepth) || 5));

  const layers = [];
  const detectedTypes = [];
  let current = initial;
  let jwtAnalysis = null;
  let parsedJson = null;

  for (let depth = 0; depth < maxDepth; depth++) {
    const trimmed = current.trim();
    if (!trimmed) break;

    // 1. Check if current layer is a JWT token
    const cleanJwtCandidate = trimmed.replace(/^Bearer\s+/i, '').trim();
    if (/^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*$/.test(cleanJwtCandidate)) {
      const jwtRes = inspectJwtToken(cleanJwtCandidate);
      if (jwtRes.valid) {
        jwtAnalysis = jwtRes;
        detectedTypes.push('jwt');
        layers.push({
          depth: depth + 1,
          encoding: 'jwt',
          output: JSON.stringify({ header: jwtRes.header, payload: jwtRes.payload }, null, 2)
        });
        current = JSON.stringify(jwtRes.payload);
        break;
      }
    }

    // 2. Check for URL-encoding (%XX)
    if (/%[0-9a-fA-F]{2}/.test(trimmed)) {
      try {
        const decoded = decodeURIComponent(trimmed.replace(/\+/g, '%20'));
        if (decoded !== trimmed) {
          detectedTypes.push('url');
          layers.push({ depth: depth + 1, encoding: 'url_decode', output: decoded });
          current = decoded;
          continue;
        }
      } catch {
        // continue
      }
    }

    // 3. Check for HTML entities
    if (/&(?:#\d{1,7}|#x[0-9a-fA-F]{1,6}|amp|lt|gt|quot|apos);/i.test(trimmed)) {
      const decoded = decodeHtmlEntities(trimmed);
      if (decoded !== trimmed) {
        detectedTypes.push('html');
        layers.push({ depth: depth + 1, encoding: 'html_decode', output: decoded });
        current = decoded;
        continue;
      }
    }

    // 4. Check for Unicode escapes (\uXXXX)
    if (/\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}/.test(trimmed)) {
      const decoded = runDecoderStep(trimmed, 'unicode_unescape');
      if (decoded !== trimmed) {
        detectedTypes.push('unicode');
        layers.push({ depth: depth + 1, encoding: 'unicode_unescape', output: decoded });
        current = decoded;
        continue;
      }
    }

    // 5. Check for JSON object or array
    if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
      try {
        parsedJson = JSON.parse(trimmed);
        detectedTypes.push('json');
        layers.push({
          depth: depth + 1,
          encoding: 'json',
          output: JSON.stringify(parsedJson, null, 2)
        });
        current = JSON.stringify(parsedJson, null, 2);
        break;
      } catch {
        // continue
      }
    }

    // 6. Check for Hex string (at least 8 hex chars, even length)
    if (/^(?:0x)?[0-9a-fA-F]{8,}$/.test(trimmed) && trimmed.replace(/^0x/i, '').length % 2 === 0) {
      const rawHex = trimmed.replace(/^0x/i, '');
      const buf = Buffer.from(rawHex, 'hex');
      if (isLikelyPrintableUtf8(buf)) {
        const decoded = buf.toString('utf8');
        if (decoded !== trimmed) {
          detectedTypes.push('hex');
          layers.push({ depth: depth + 1, encoding: 'hex_decode', output: decoded });
          current = decoded;
          continue;
        }
      }
    }

    // 7. Check for Base64 / Base64URL (at least 8 chars)
    if (
      /^[A-Za-z0-9+/_-]{8,}={0,2}$/.test(trimmed) &&
      !/^[0-9]+$/.test(trimmed) &&
      !/^[a-zA-Z]+$/.test(trimmed)
    ) {
      try {
        const buf = base64UrlToBuffer(trimmed);
        if (isLikelyPrintableUtf8(buf)) {
          const decoded = buf.toString('utf8');
          if (decoded && decoded !== trimmed) {
            detectedTypes.push('base64');
            layers.push({ depth: depth + 1, encoding: 'base64_decode', output: decoded });
            current = decoded;
            continue;
          }
        }
      } catch {
        // continue
      }
    }

    break;
  }

  // Final JSON check if last decoded layer produced JSON
  if (!parsedJson) {
    const finTrim = current.trim();
    if ((finTrim.startsWith('{') && finTrim.endsWith('}')) || (finTrim.startsWith('[') && finTrim.endsWith(']'))) {
      try {
        parsedJson = JSON.parse(finTrim);
        if (!detectedTypes.includes('json')) detectedTypes.push('json');
      } catch {
        parsedJson = null;
      }
    }
  }

  return {
    input: initial,
    finalValue: current,
    layers,
    detectedTypes,
    parsedJson,
    jwtAnalysis,
    securityNotes: jwtAnalysis ? jwtAnalysis.securityNotes : []
  };
}

function flattenJsonKeys(obj, prefix = '', out = new Map(), depth = 0) {
  if (depth > 8 || obj === null || obj === undefined) return out;
  if (Array.isArray(obj)) {
    out.set(prefix || '[]', `Array(${obj.length})`);
    if (obj.length > 0 && typeof obj[0] === 'object' && obj[0] !== null) {
      flattenJsonKeys(obj[0], `${prefix}[0]`, out, depth + 1);
    }
    return out;
  }
  if (typeof obj === 'object') {
    for (const [k, v] of Object.entries(obj)) {
      const nextKey = prefix ? `${prefix}.${k}` : k;
      if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
        flattenJsonKeys(v, nextKey, out, depth + 1);
      } else {
        out.set(nextKey, Array.isArray(v) ? `Array(${v.length})` : String(v ?? 'null'));
      }
    }
  }
  return out;
}

function countWords(text) {
  const trimmed = String(text || '').trim();
  if (!trimmed) return 0;
  return trimmed.split(/\s+/).length;
}

function countLines(text) {
  const str = String(text || '');
  if (!str) return 0;
  return str.split(/\r?\n/).length;
}

/**
 * Burp Comparer Engine: Computes word-level, line-level, byte-level, header-level,
 * and JSON-structural diffs between two HTTP responses or payloads.
 *
 * @param {{ status?: number, headers?: Record<string, string>, body?: string, text?: string } | string} leftInput
 * @param {{ status?: number, headers?: Record<string, string>, body?: string, text?: string } | string} rightInput
 * @param {{ maxDiffLines?: number }} [options={}]
 */
export function compareResponses(leftInput, rightInput, options = {}) {
  const normalizeSide = (side) => {
    if (typeof side === 'string') {
      return {
        status: null,
        headers: {},
        body: enforceInputBound(side)
      };
    }
    const obj = side && typeof side === 'object' ? side : {};
    return {
      status: obj.status !== undefined && obj.status !== null ? Number(obj.status) : null,
      headers: obj.headers && typeof obj.headers === 'object' ? obj.headers : {},
      body: enforceInputBound(obj.body ?? obj.text ?? '')
    };
  };

  const left = normalizeSide(leftInput);
  const right = normalizeSide(rightInput);
  const maxDiffLines = Math.min(200, Math.max(10, Number(options.maxDiffLines) || 60));

  const leftBytes = Buffer.byteLength(left.body, 'utf8');
  const rightBytes = Buffer.byteLength(right.body, 'utf8');
  const leftWords = countWords(left.body);
  const rightWords = countWords(right.body);
  const leftLinesArr = left.body ? left.body.split(/\r?\n/) : [];
  const rightLinesArr = right.body ? right.body.split(/\r?\n/) : [];

  // Token/line Jaccard + multiset similarity ratio (0.0000 .. 1.0000)
  let similarityRatio = 1;
  if (left.body === right.body) {
    similarityRatio = 1;
  } else if (!left.body || !right.body) {
    similarityRatio = 0;
  } else {
    const tokenizeForSimilarity = (str) =>
      (str.slice(0, 32768).match(/[A-Za-z0-9_@.-]+|[^\sA-Za-z0-9_@.-]/g) || []).slice(0, 4000);
    const leftTokens = tokenizeForSimilarity(left.body);
    const rightTokens = tokenizeForSimilarity(right.body);
    const freqLeft = new Map();
    for (const t of leftTokens) freqLeft.set(t, (freqLeft.get(t) || 0) + 1);
    let intersection = 0;
    for (const t of rightTokens) {
      const c = freqLeft.get(t) || 0;
      if (c > 0) {
        intersection++;
        freqLeft.set(t, c - 1);
      }
    }
    const total = leftTokens.length + rightTokens.length;
    similarityRatio = total > 0 ? Number(((2 * intersection) / total).toFixed(4)) : 1;
  }

  // Header diff
  const leftH = {};
  const rightH = {};
  for (const [k, v] of Object.entries(left.headers)) leftH[k.toLowerCase()] = String(v ?? '');
  for (const [k, v] of Object.entries(right.headers)) rightH[k.toLowerCase()] = String(v ?? '');
  const allHeaderKeys = new Set([...Object.keys(leftH), ...Object.keys(rightH)]);
  const addedHeaders = [];
  const removedHeaders = [];
  const changedHeaders = [];
  for (const k of allHeaderKeys) {
    if (!Object.hasOwn(leftH, k)) addedHeaders.push(k);
    else if (!Object.hasOwn(rightH, k)) removedHeaders.push(k);
    else if (leftH[k] !== rightH[k]) changedHeaders.push({ header: k, left: leftH[k], right: rightH[k] });
  }

  // JSON structural diff (when both bodies are valid JSON)
  let jsonDiff = null;
  const trimL = left.body.trim();
  const trimR = right.body.trim();
  if (
    ((trimL.startsWith('{') && trimL.endsWith('}')) || (trimL.startsWith('[') && trimL.endsWith(']'))) &&
    ((trimR.startsWith('{') && trimR.endsWith('}')) || (trimR.startsWith('[') && trimR.endsWith(']')))
  ) {
    try {
      const parsedL = JSON.parse(trimL);
      const parsedR = JSON.parse(trimR);
      const mapL = flattenJsonKeys(parsedL);
      const mapR = flattenJsonKeys(parsedR);
      const allKeys = new Set([...mapL.keys(), ...mapR.keys()]);
      const addedKeys = [];
      const removedKeys = [];
      const changedKeys = [];
      let sameKeyCount = 0;

      for (const k of allKeys) {
        if (!mapL.has(k)) addedKeys.push(k);
        else if (!mapR.has(k)) removedKeys.push(k);
        else {
          sameKeyCount++;
          if (mapL.get(k) !== mapR.get(k)) {
            changedKeys.push({ key: k, left: mapL.get(k), right: mapR.get(k) });
          }
        }
      }

      const keyOverlapRatio = allKeys.size > 0
        ? Number((sameKeyCount / allKeys.size).toFixed(4))
        : 1;

      jsonDiff = {
        isJson: true,
        leftKeyCount: mapL.size,
        rightKeyCount: mapR.size,
        keyOverlapRatio,
        addedKeys,
        removedKeys,
        changedKeys: changedKeys.slice(0, 50)
      };
    } catch {
      jsonDiff = null;
    }
  }

  // Line diff preview
  const lineDiffPreview = [];
  const maxLines = Math.max(leftLinesArr.length, rightLinesArr.length);
  for (let i = 0; i < maxLines && lineDiffPreview.length < maxDiffLines; i++) {
    const lLine = leftLinesArr[i];
    const rLine = rightLinesArr[i];
    if (lLine === rLine) continue;
    if (lLine !== undefined && rLine === undefined) {
      lineDiffPreview.push({ line: i + 1, type: 'removed', text: lLine.slice(0, 300) });
    } else if (lLine === undefined && rLine !== undefined) {
      lineDiffPreview.push({ line: i + 1, type: 'added', text: rLine.slice(0, 300) });
    } else {
      lineDiffPreview.push({
        line: i + 1,
        type: 'changed',
        left: lLine.slice(0, 300),
        right: rLine.slice(0, 300)
      });
    }
  }

  return {
    identical: left.body === right.body && left.status === right.status,
    similarityRatio,
    statusLeft: left.status,
    statusRight: right.status,
    statusChanged: left.status !== null && right.status !== null && left.status !== right.status,
    bytesLeft: leftBytes,
    bytesRight: rightBytes,
    byteDelta: rightBytes - leftBytes,
    wordsLeft: leftWords,
    wordsRight: rightWords,
    wordDelta: rightWords - leftWords,
    linesLeft: countLines(left.body),
    linesRight: countLines(right.body),
    lineDelta: countLines(right.body) - countLines(left.body),
    headerDiff: {
      addedHeaders,
      removedHeaders,
      changedHeaders
    },
    jsonDiff,
    lineDiffPreview
  };
}
