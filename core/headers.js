/**
 * Shared RFC 7230 HTTP custom header parser & validator.
 * Rejects invalid tokens, CR/LF/NUL/control characters, prototype-pollution keys,
 * hop-by-hop / smuggling / host-override headers, and enforces count/byte bounds.
 */

export const RFC7230_TOKEN_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

export const FORBIDDEN_CUSTOM_HEADERS = new Set([
  'host',
  'content-length',
  'transfer-encoding',
  'connection',
  'keep-alive',
  'upgrade',
  'expect',
  'te',
  'trailer',
  'proxy-connection',
]);

export const FORBIDDEN_HEADER_KEYS = new Set([
  '__proto__',
  'constructor',
  'prototype',
]);

export const MAX_CUSTOM_HEADERS = 32;
export const MAX_CUSTOM_HEADER_BYTES = 8192;

// Rejects CR, LF, NUL and all other ASCII control characters except horizontal tab (\t)
const HEADER_CTL_RE = /[\x00-\x08\x0A-\x1F\x7F]/;
const UTF8_ENCODER = new TextEncoder();

/**
 * Validates a custom headers object map and returns `{ valid, headers?, error? }`.
 *
 * @param {unknown} rawHeaders
 * @returns {{ valid: boolean, headers?: Record<string, string>, error?: string }}
 */
export function validateCustomHeadersResult(rawHeaders) {
  if (rawHeaders === undefined || rawHeaders === null) {
    return { valid: true, headers: {} };
  }
  if (typeof rawHeaders !== 'object' || Array.isArray(rawHeaders)) {
    return {
      valid: false,
      error: 'Invalid headers: expected a key-value object map',
    };
  }

  const clean = {};
  const seenLower = new Set();
  let totalBytes = 0;

  for (const rawKey of Object.getOwnPropertyNames(rawHeaders)) {
    const rawVal = rawHeaders[rawKey];

    if (HEADER_CTL_RE.test(String(rawKey))) {
      return {
        valid: false,
        error: 'Invalid header name: control characters (CR/LF/NUL) are not allowed',
      };
    }

    const hdrName = String(rawKey).trim();
    if (!hdrName || !RFC7230_TOKEN_RE.test(hdrName)) {
      return {
        valid: false,
        error: `Invalid header name "${hdrName}": must be a non-empty RFC 7230 HTTP header token`,
      };
    }

    const lower = hdrName.toLowerCase();
    if (FORBIDDEN_HEADER_KEYS.has(lower)) {
      return {
        valid: false,
        error: `Forbidden header name "${hdrName}"`,
      };
    }

    if (FORBIDDEN_CUSTOM_HEADERS.has(lower)) {
      return {
        valid: false,
        error: `Forbidden header "${hdrName}": hop-by-hop, framing, and Host headers cannot be set`,
      };
    }

    if (rawVal === undefined || rawVal === null) {
      continue;
    }

    if (typeof rawVal === 'object' || typeof rawVal === 'function' || typeof rawVal === 'symbol') {
      return {
        valid: false,
        error: `Invalid header value for "${hdrName}": expected scalar string`,
      };
    }

    const hdrVal = String(rawVal);
    if (HEADER_CTL_RE.test(hdrVal)) {
      return {
        valid: false,
        error: `Invalid header value for "${hdrName}": control characters (CR/LF/NUL) are not allowed`,
      };
    }

    if (!seenLower.has(lower)) {
      seenLower.add(lower);
      if (seenLower.size > MAX_CUSTOM_HEADERS) {
        return {
          valid: false,
          error: `Too many custom headers: maximum ${MAX_CUSTOM_HEADERS} headers allowed`,
        };
      }
    } else {
      // Remove earlier casing duplicate so clean object has deterministic single entry
      for (const existingKey of Object.keys(clean)) {
        if (existingKey.toLowerCase() === lower) {
          totalBytes -= UTF8_ENCODER.encode(`${existingKey}: ${clean[existingKey]}\r\n`).length;
          delete clean[existingKey];
          break;
        }
      }
    }

    totalBytes += UTF8_ENCODER.encode(`${hdrName}: ${hdrVal}\r\n`).length;
    if (totalBytes > MAX_CUSTOM_HEADER_BYTES) {
      return {
        valid: false,
        error: `Custom headers exceed maximum total size of ${MAX_CUSTOM_HEADER_BYTES} bytes`,
      };
    }

    clean[hdrName] = hdrVal;
  }

  return { valid: true, headers: clean };
}

/**
 * Validates a custom headers object map, throwing an Error on failure.
 *
 * @param {unknown} rawHeaders
 * @returns {Record<string, string>}
 */
export function validateCustomHeaders(rawHeaders) {
  const res = validateCustomHeadersResult(rawHeaders);
  if (!res.valid) {
    throw new Error(res.error);
  }
  return res.headers;
}

/**
 * Parses and validates a single `"Name: Value"` header line.
 *
 * @param {string} rawLine
 * @returns {{ valid: boolean, name?: string, value?: string, error?: string }}
 */
export function parseCustomHeaderLine(rawLine) {
  if (typeof rawLine !== 'string') {
    return { valid: false, error: 'Header must be a string in "Name: Value" format' };
  }
  if (HEADER_CTL_RE.test(rawLine)) {
    return { valid: false, error: 'Control characters (CR/LF/NUL) are not allowed in headers' };
  }
  const colonIdx = rawLine.indexOf(':');
  if (colonIdx <= 0) {
    return { valid: false, error: 'Expected "Name: Value" with a non-empty header name' };
  }
  const name = rawLine.slice(0, colonIdx).trim();
  const value = rawLine.slice(colonIdx + 1).trim();
  const res = validateCustomHeadersResult({ [name]: value });
  if (!res.valid) {
    return { valid: false, error: res.error };
  }
  return { valid: true, name, value };
}
