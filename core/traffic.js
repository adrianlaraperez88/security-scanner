import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { validateTargetUrl, resolveAndValidateTarget } from './validator.js';
import { TargetPinStore, evaluateAssetGate } from './guard.js';
import { inspectJwtToken } from './decoder-comparer.js';

/**
 * SecScan URL Path Template Normalizer (`db.TemplatePath`).
 * Normalizes dynamic path segments (UUIDs, Mongo ObjectIds, integers, and opaque tokens)
 * into `{uuid}`, `{oid}`, `{id}`, and `{token}` so thousands of requests collapse into
 * canonical route templates for the Target Site Map, Intruder, and Autorize.
 *
 * @param {string} rawPathOrUrl
 * @returns {string}
 */
export function templateUrlPath(rawPathOrUrl) {
  let pathname = String(rawPathOrUrl || '/').trim();
  try {
    if (/^https?:\/\//i.test(pathname)) {
      pathname = new URL(pathname).pathname || '/';
    } else {
      const qIdx = pathname.indexOf('?');
      if (qIdx !== -1) pathname = pathname.slice(0, qIdx);
    }
  } catch {
    const qIdx = pathname.indexOf('?');
    if (qIdx !== -1) pathname = pathname.slice(0, qIdx);
  }

  const segments = pathname.split('/').filter(Boolean);
  if (segments.length === 0) return '/';

  const normalized = segments.map(seg => {
    // 1. Standard UUID
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg)) {
      return '{uuid}';
    }
    // 2. 24-hex Mongo ObjectId
    if (/^[0-9a-f]{24}$/i.test(seg)) {
      return '{oid}';
    }
    // 3. Pure numeric ID
    if (/^\d+$/.test(seg)) {
      return '{id}';
    }
    // 4. Long hex / base64url token (>= 20 chars with digits and letters)
    if (seg.length >= 20 && /^[A-Za-z0-9_-]+$/.test(seg) && /\d/.test(seg) && /[A-Za-z]/.test(seg)) {
      return '{token}';
    }
    return seg;
  });

  return `/${normalized.join('/')}`;
}

/**
 * Passively analyzes a captured HTTP exchange (from browser extension, HAR, or proxy)
 * for security issues without sending any active network requests.
 *
 * @param {object} exchange
 * @returns {Array<{
 *   ruleId: string,
 *   title: string,
 *   severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW',
 *   cwe: string,
 *   detail: string,
 *   evidenceQuote: string
 * }>}
 */
export function analyzePassiveExchange(exchange = {}) {
  const findings = [];
  const url = String(exchange.url || '');
  const reqHeaders = normalizeHeaders(exchange.reqHeaders || exchange.requestHeaders || {});
  const resHeaders = normalizeHeaders(exchange.resHeaders || exchange.responseHeaders || {});
  const resBody = typeof exchange.resBody === 'string'
    ? exchange.resBody
    : Buffer.isBuffer(exchange.resBody)
      ? exchange.resBody.toString('utf8')
      : String(exchange.responseBody || '');

  // 1. Secret / token in URL query string
  const urlSecretMatch = url.match(/[?&](api[_-]?key|access[_-]?token|auth[_-]?token|jwt|secret|password|client_secret)=([^&#\s]{6,})/i);
  if (urlSecretMatch) {
    findings.push({
      ruleId: 'passive-url-secret',
      title: 'Sensitive Credential / Token Exposed in URL Query String',
      severity: 'HIGH',
      cwe: 'CWE-598',
      detail: `URL query parameter "${urlSecretMatch[1]}" carries a credential or token in cleartext URL history/logs.`,
      evidenceQuote: `${urlSecretMatch[1]}=${urlSecretMatch[2].slice(0, 8)}...`
    });
  }

  // 2. Cookie security flags on Set-Cookie
  const setCookie = getHeaderCaseInsensitive(resHeaders, 'set-cookie');
  if (setCookie && /(?:session|sess|token|auth|jwt|sid)[a-z0-9_.-]*=/i.test(setCookie)) {
    if (!/\bhttponly\b/i.test(setCookie)) {
      findings.push({
        ruleId: 'passive-cookie-httponly',
        title: 'Session Cookie Missing HttpOnly Flag',
        severity: 'MEDIUM',
        cwe: 'CWE-1004',
        detail: 'Session/authentication cookie is set without HttpOnly, exposing it to document.cookie access on XSS.',
        evidenceQuote: `Set-Cookie: ${setCookie.slice(0, 120)}`
      });
    }
    if (url.startsWith('https://') && !/\bsecure\b/i.test(setCookie)) {
      findings.push({
        ruleId: 'passive-cookie-secure',
        title: 'HTTPS Session Cookie Missing Secure Flag',
        severity: 'MEDIUM',
        cwe: 'CWE-614',
        detail: 'Session cookie on HTTPS response is missing the Secure attribute.',
        evidenceQuote: `Set-Cookie: ${setCookie.slice(0, 120)}`
      });
    }
  }

  // 3. Permissive CORS with credentials
  const acao = getHeaderCaseInsensitive(resHeaders, 'access-control-allow-origin').trim();
  const acac = getHeaderCaseInsensitive(resHeaders, 'access-control-allow-credentials').trim().toLowerCase();
  if (acao && acac === 'true') {
    findings.push({
      ruleId: 'passive-cors-credentials',
      title: 'Cross-Origin Resource Sharing (CORS) Allows Credentials',
      severity: acao === '*' || acao === 'null' ? 'CRITICAL' : 'MEDIUM',
      cwe: 'CWE-942',
      detail: `Response sets Access-Control-Allow-Origin: ${acao} with Access-Control-Allow-Credentials: true.`,
      evidenceQuote: `Access-Control-Allow-Origin: ${acao}`
    });
  }

  // 4. JWT token security inspection (Authorization header)
  const authHeader = getHeaderCaseInsensitive(reqHeaders, 'authorization');
  if (/^Bearer\s+[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/i.test(authHeader.trim())) {
    const jwtRes = inspectJwtToken(authHeader);
    if (jwtRes.valid && (jwtRes.riskLevel === 'CRITICAL' || jwtRes.riskLevel === 'HIGH')) {
      findings.push({
        ruleId: 'passive-jwt-weakness',
        title: 'Vulnerable JWT Header / Algorithm Configuration',
        severity: jwtRes.riskLevel,
        cwe: 'CWE-347',
        detail: jwtRes.securityNotes.join(' '),
        evidenceQuote: authHeader.slice(0, 80)
      });
    }
  }

  // 5. Origin IP disclosure headers
  for (const hName of ['x-origin-ip', 'x-backend-ip', 'x-real-server-ip', 'x-upstream-addr']) {
    const val = getHeaderCaseInsensitive(resHeaders, hName);
    if (val && /\d{1,3}(?:\.\d{1,3}){3}/.test(val)) {
      findings.push({
        ruleId: 'passive-origin-ip-leak',
        title: 'Backend Origin IP Disclosed in Response Header',
        severity: 'MEDIUM',
        cwe: 'CWE-200',
        detail: `Header "${hName}: ${val}" leaks internal or origin server IP address.`,
        evidenceQuote: `${hName}: ${val}`
      });
    }
  }

  // 6. Verbose SQL / framework error disclosure in response body
  const errMatch = resBody.match(/(SQLSTATE\[[0-9A-Z]+\]|You have an error in your SQL syntax|Traceback \(most recent call last\):|ReferenceError:\s+[^\r\n]{5,80}|Fatal error:\s+Uncaught\s+[^\r\n]{5,100})/i);
  if (errMatch) {
    findings.push({
      ruleId: 'passive-error-disclosure',
      title: 'Verbose Database / Application Stack Trace Disclosure',
      severity: 'HIGH',
      cwe: 'CWE-209',
      detail: `Response body discloses raw exception/SQL error signature: "${errMatch[1].slice(0, 100)}".`,
      evidenceQuote: errMatch[1].slice(0, 120)
    });
  }

  return findings;
}

export const INLINE_BODY_LIMIT = 256 * 1024; // 256 KiB

export const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'transfer-encoding',
  'content-length',
  'upgrade',
  'proxy-connection',
  'te',
  'trailer',
  'proxy-authenticate',
  'proxy-authorization'
]);

const SHA256_REGEX = /^[a-f0-9]{64}$/;
const VALID_PHASES = new Set(['request', 'response']);
const VALID_TARGETS = new Set(['header', 'body', 'query']);
const VALID_EXTERNAL_SOURCES = new Set(['extension', 'har', 'external']);
const MAX_REWRITE_REGEX_LEN = 512;
const NESTED_QUANTIFIER_RE = /\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*{]/;

function validateSafeRegex(pattern, label = 'Invalid regular expression') {
  const str = String(pattern ?? '');
  if (str.length > MAX_REWRITE_REGEX_LEN) {
    throw new Error(`${label}: pattern length (${str.length}) exceeds max ${MAX_REWRITE_REGEX_LEN}`);
  }
  if (NESTED_QUANTIFIER_RE.test(str)) {
    throw new Error(`${label}: nested quantifier pattern rejected to prevent ReDoS`);
  }
  try {
    return new RegExp(str);
  } catch (err) {
    throw new Error(`${label}: ${err.message}`);
  }
}

/**
 * Validates that a string is a lowercase 64-character hex SHA-256 digest.
 *
 * @param {string} sha256
 * @returns {boolean}
 */
export function isValidSha256(sha256) {
  return typeof sha256 === 'string' && SHA256_REGEX.test(sha256);
}

function toBuffer(input) {
  if (input === null || input === undefined) {
    return Buffer.alloc(0);
  }
  if (Buffer.isBuffer(input)) {
    return input;
  }
  if (input instanceof Uint8Array) {
    return Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  }
  if (typeof input === 'string') {
    return Buffer.from(input, 'utf8');
  }
  if (typeof input === 'object') {
    return Buffer.from(JSON.stringify(input), 'utf8');
  }
  return Buffer.from(String(input), 'utf8');
}

function normalizeHeaders(headers) {
  if (!headers) return {};
  if (typeof headers === 'string') {
    try {
      const parsed = JSON.parse(headers);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return parsed;
      }
    } catch {
      return {};
    }
  }
  if (typeof headers.entries === 'function') {
    const out = {};
    for (const [k, v] of headers.entries()) {
      out[k] = v;
    }
    return out;
  }
  if (Array.isArray(headers)) {
    const out = {};
    for (const entry of headers) {
      if (Array.isArray(entry) && entry.length >= 2) {
        out[String(entry[0])] = String(entry[1]);
      } else if (entry && typeof entry === 'object' && entry.name) {
        out[String(entry.name)] = String(entry.value ?? '');
      }
    }
    return out;
  }
  if (typeof headers === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(headers)) {
      if (v !== undefined && v !== null) {
        out[k] = Array.isArray(v) ? v.join(', ') : String(v);
      }
    }
    return out;
  }
  return {};
}

function getHeaderCaseInsensitive(headers, targetName) {
  if (!headers || typeof headers !== 'object') return '';
  const lower = targetName.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lower) {
      return String(v ?? '');
    }
  }
  return '';
}

function parseUrlParts(rawUrl, fallbackHost = '', fallbackPath = '/') {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return {
      host: fallbackHost || 'unknown',
      path: fallbackPath || '/'
    };
  }
  try {
    const parsed = new URL(rawUrl);
    return {
      host: parsed.hostname.toLowerCase(),
      path: (parsed.pathname || '/') + (parsed.search || '')
    };
  } catch {
    return {
      host: fallbackHost || 'unknown',
      path: fallbackPath || rawUrl
    };
  }
}

function headersToSearchText(headers) {
  if (!headers || typeof headers !== 'object') return '';
  return Object.entries(headers)
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n');
}

function buildSafeFtsQuery(rawSearch) {
  if (typeof rawSearch !== 'string' || !rawSearch.trim()) {
    return '';
  }
  const tokens = rawSearch
    .trim()
    .split(/\s+/)
    .map(t => t.replace(/"/g, '""').trim())
    .filter(Boolean);
  if (tokens.length === 0) return '';
  return tokens.map(t => `"${t}"`).join(' AND ');
}

function escapeLike(str) {
  return String(str).replace(/[\\%_]/g, ch => `\\${ch}`);
}

function hostMatchesScope(scopeHost, actualHost) {
  if (!scopeHost || scopeHost === '*') return true;
  if (!actualHost) return false;
  const normScope = scopeHost.toLowerCase().trim();
  const normHost = actualHost.toLowerCase().trim().replace(/:\d+$/, '');
  if (normScope === normHost) return true;
  if (normScope.startsWith('*.')) {
    const suffix = normScope.slice(2);
    return normHost === suffix || normHost.endsWith(`.${suffix}`);
  }
  return false;
}

/**
 * Strip RFC-9110 hop-by-hop headers and any header names listed in the Connection header.
 *
 * @param {Record<string, string>} headers
 * @returns {Record<string, string>}
 */
export function stripHopByHopHeaders(headers) {
  const normalized = normalizeHeaders(headers);
  const dynamicHopHeaders = new Set();

  for (const [k, v] of Object.entries(normalized)) {
    if (k.toLowerCase() === 'connection' && typeof v === 'string') {
      for (const token of v.split(',')) {
        const trimmed = token.trim().toLowerCase();
        if (trimmed) dynamicHopHeaders.add(trimmed);
      }
    }
  }

  const cleaned = {};
  for (const [k, v] of Object.entries(normalized)) {
    const lower = k.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(lower) || dynamicHopHeaders.has(lower)) {
      continue;
    }
    cleaned[k] = v;
  }
  return cleaned;
}

export class TrafficStore {
  /**
   * @param {object} [options]
   * @param {DatabaseSync} [options.db]
   * @param {string} [options.dbPath=':memory:']
   * @param {string|null} [options.blobDir=null]
   * @param {string|null} [options.hmacSecret=null]
   */
  constructor({
    db = null,
    dbPath = ':memory:',
    blobDir = null,
    hmacSecret = null,
    maxMemoryBlobs = 256,
    maxMemoryBlobBytes = 64 * 1024 * 1024
  } = {}) {
    if (db) {
      this.db = db;
      this.ownsDb = false;
    } else {
      if (dbPath !== ':memory:') {
        fs.mkdirSync(path.dirname(path.resolve(dbPath)), { recursive: true });
      }
      this.db = new DatabaseSync(dbPath);
      this.ownsDb = true;
    }

    this.dbPath = dbPath;
    this.blobDir = blobDir ? path.resolve(blobDir) : null;
    if (this.blobDir) {
      fs.mkdirSync(path.join(this.blobDir, 'sha256'), { recursive: true });
    }
    this.hmacSecret = hmacSecret || crypto.randomBytes(32).toString('hex');
    this._memoryBlobs = new Map();
    this._memoryBlobBytes = 0;
    this.maxMemoryBlobs = Number.isFinite(Number(maxMemoryBlobs)) && Number(maxMemoryBlobs) > 0
      ? Math.floor(Number(maxMemoryBlobs))
      : 256;
    this.maxMemoryBlobBytes = Number.isFinite(Number(maxMemoryBlobBytes)) && Number(maxMemoryBlobBytes) > 0
      ? Math.floor(Number(maxMemoryBlobBytes))
      : 64 * 1024 * 1024;
    this._closed = false;
    this._txDepth = 0;

    this._initSchema();
  }

  _initSchema() {
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA busy_timeout = 5000;
      PRAGMA foreign_keys = ON;

      CREATE TABLE IF NOT EXISTS exchanges (
        id TEXT PRIMARY KEY,
        task_id TEXT,
        source TEXT NOT NULL DEFAULT 'scanner',
        method TEXT NOT NULL,
        url TEXT NOT NULL,
        host TEXT NOT NULL,
        path TEXT NOT NULL,
        status_code INTEGER,
        req_headers_json TEXT NOT NULL DEFAULT '{}',
        res_headers_json TEXT NOT NULL DEFAULT '{}',
        req_size INTEGER NOT NULL DEFAULT 0,
        res_size INTEGER NOT NULL DEFAULT 0,
        duration_ms REAL NOT NULL DEFAULT 0,
        mime_type TEXT NOT NULL DEFAULT '',
        tainted_sensitive INTEGER NOT NULL DEFAULT 0,
        rewrite_applied INTEGER NOT NULL DEFAULT 0,
        original_req_json TEXT,
        created_at TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_exchanges_task_id ON exchanges(task_id);
      CREATE INDEX IF NOT EXISTS idx_exchanges_host ON exchanges(host);
      CREATE INDEX IF NOT EXISTS idx_exchanges_status ON exchanges(status_code);

      CREATE TABLE IF NOT EXISTS exchange_bodies (
        exchange_id TEXT PRIMARY KEY,
        req_body_inline BLOB,
        req_blob_sha256 TEXT,
        res_body_inline BLOB,
        res_blob_sha256 TEXT,
        res_encoding TEXT NOT NULL DEFAULT ''
      );

      CREATE TABLE IF NOT EXISTS blob_refs (
        sha256 TEXT PRIMARY KEY,
        size INTEGER NOT NULL,
        ref_count INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS stream_messages (
        id TEXT PRIMARY KEY,
        exchange_id TEXT NOT NULL,
        direction TEXT NOT NULL,
        seq INTEGER NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_stream_messages_exchange ON stream_messages(exchange_id, seq);

      CREATE TABLE IF NOT EXISTS exchange_rewrites (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        scope_host TEXT NOT NULL DEFAULT '*',
        phase TEXT NOT NULL DEFAULT 'request',
        target TEXT NOT NULL DEFAULT 'header',
        match_pattern TEXT NOT NULL,
        replace_value TEXT NOT NULL DEFAULT '',
        is_regex INTEGER NOT NULL DEFAULT 0,
        is_sensitive INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
      );

      CREATE VIRTUAL TABLE IF NOT EXISTS ex_fts USING fts5(
        exchange_id UNINDEXED,
        host,
        path,
        method,
        status_code,
        req_text,
        res_text
      );
    `);
  }

  _inTransaction(fn) {
    if (this._txDepth > 0) {
      this._txDepth++;
      try {
        return fn();
      } finally {
        this._txDepth--;
      }
    }
    this._txDepth = 1;
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const result = fn();
      this.db.exec('COMMIT');
      return result;
    } catch (err) {
      try {
        this.db.exec('ROLLBACK');
      } catch {}
      throw err;
    } finally {
      this._txDepth = 0;
    }
  }

  _setMemoryBlob(sha256, buf) {
    const existing = this._memoryBlobs.get(sha256);
    if (existing) {
      this._memoryBlobBytes = Math.max(0, this._memoryBlobBytes - existing.byteLength);
      this._memoryBlobs.delete(sha256);
    }
    if (buf.byteLength > this.maxMemoryBlobBytes) {
      this._memoryBlobs.clear();
      this._memoryBlobBytes = 0;
    }
    while (
      this._memoryBlobs.size >= this.maxMemoryBlobs ||
      (this._memoryBlobs.size > 0 && this._memoryBlobBytes + buf.byteLength > this.maxMemoryBlobBytes)
    ) {
      const oldestKey = this._memoryBlobs.keys().next().value;
      if (oldestKey === undefined) break;
      const oldestBuf = this._memoryBlobs.get(oldestKey);
      this._memoryBlobs.delete(oldestKey);
      if (oldestBuf) {
        this._memoryBlobBytes = Math.max(0, this._memoryBlobBytes - oldestBuf.byteLength);
      }
    }
    this._memoryBlobs.set(sha256, buf);
    this._memoryBlobBytes += buf.byteLength;
  }

  /**
   * Validates SHA-256 and resolves the confined blob file path under `<blobDir>/sha256/<first2>/<sha256>.bin`.
   *
   * @param {string} sha256
   * @returns {string}
   */
  _resolveBlobPath(sha256) {
    if (!isValidSha256(sha256)) {
      throw new Error(`Invalid SHA-256 hash: "${sha256}"`);
    }
    if (!this.blobDir) {
      throw new Error('Blob directory is not configured on TrafficStore');
    }
    const prefix = sha256.slice(0, 2);
    const targetPath = path.resolve(this.blobDir, 'sha256', prefix, `${sha256}.bin`);
    const relative = path.relative(this.blobDir, targetPath);
    if (relative.startsWith('..') || path.isAbsolute(relative)) {
      throw new Error(`Blob path traversal blocked for hash: "${sha256}"`);
    }
    return targetPath;
  }

  /**
   * Writes a buffer to the content-addressed blob directory and updates `blob_refs`.
   *
   * @param {Buffer} buffer
   * @returns {string} sha256 hex digest
   */
  _writeBlob(buffer) {
    const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
    if (!isValidSha256(sha256)) {
      throw new Error('Computed SHA-256 failed validation');
    }

    if (this.blobDir) {
      const targetPath = this._resolveBlobPath(sha256);
      const dir = path.dirname(targetPath);
      fs.mkdirSync(dir, { recursive: true });
      if (!fs.existsSync(targetPath)) {
        const tmpPath = `${targetPath}.${crypto.randomBytes(6).toString('hex')}.tmp`;
        fs.writeFileSync(tmpPath, buffer);
        fs.renameSync(tmpPath, targetPath);
      }
    } else {
      this._setMemoryBlob(sha256, Buffer.from(buffer));
    }

    const now = new Date().toISOString();
    const existing = this.db
      .prepare('SELECT sha256 FROM blob_refs WHERE sha256 = ?')
      .get(sha256);
    if (existing) {
      this.db
        .prepare('UPDATE blob_refs SET ref_count = ref_count + 1 WHERE sha256 = ?')
        .run(sha256);
    } else {
      this.db
        .prepare(
          'INSERT INTO blob_refs (sha256, size, ref_count, created_at) VALUES (?, ?, 1, ?)'
        )
        .run(sha256, buffer.byteLength, now);
    }

    return sha256;
  }

  /**
   * Validates `/^[a-f0-9]{64}$/` and reads a content-addressed blob from `blobDir`.
   *
   * @param {string} sha256
   * @returns {Buffer|null}
   */
  getBlob(sha256) {
    if (!isValidSha256(sha256)) {
      throw new Error(`Invalid SHA-256 hash: "${sha256}"`);
    }
    if (this.blobDir) {
      const targetPath = this._resolveBlobPath(sha256);
      if (!fs.existsSync(targetPath)) {
        return null;
      }
      return fs.readFileSync(targetPath);
    }
    const mem = this._memoryBlobs.get(sha256) || null;
    if (mem) {
      this._memoryBlobs.delete(sha256);
      this._memoryBlobs.set(sha256, mem);
    }
    return mem;
  }

  _decrementBlobRef(sha256) {
    if (!sha256 || !isValidSha256(sha256)) return;
    this.db
      .prepare('UPDATE blob_refs SET ref_count = MAX(0, ref_count - 1) WHERE sha256 = ?')
      .run(sha256);
    const row = this.db
      .prepare('SELECT ref_count FROM blob_refs WHERE sha256 = ?')
      .get(sha256);
    if (row && row.ref_count <= 0) {
      this.db.prepare('DELETE FROM blob_refs WHERE sha256 = ? AND ref_count <= 0').run(sha256);
      if (!this.blobDir) {
        const mem = this._memoryBlobs.get(sha256);
        if (mem) {
          this._memoryBlobBytes = Math.max(0, this._memoryBlobBytes - mem.byteLength);
          this._memoryBlobs.delete(sha256);
        }
      }
    }
  }

  gcOrphanBlobs({ graceMs = 24 * 3600 * 1000, now = Date.now() } = {}) {
    const referencedRows = this.db
      .prepare(
        `SELECT req_blob_sha256 AS sha FROM exchange_bodies WHERE req_blob_sha256 IS NOT NULL
         UNION
         SELECT res_blob_sha256 AS sha FROM exchange_bodies WHERE res_blob_sha256 IS NOT NULL`
      )
      .all();
    const referenced = new Set(referencedRows.map(r => r.sha));

    const staleRefs = this.db.prepare('SELECT sha256, ref_count FROM blob_refs').all();
    for (const ref of staleRefs) {
      if (!referenced.has(ref.sha256) && ref.ref_count <= 0) {
        this.db.prepare('DELETE FROM blob_refs WHERE sha256 = ?').run(ref.sha256);
      }
    }

    const deletedBlobs = [];
    const deletedTempFiles = [];
    if (!this.blobDir) {
      return { deletedCount: 0, deletedBlobs, deletedTempFiles };
    }

    const blobRoot = path.join(this.blobDir, 'sha256');
    if (!fs.existsSync(blobRoot)) {
      return { deletedCount: 0, deletedBlobs, deletedTempFiles };
    }

    const prefixEntries = fs.readdirSync(blobRoot, { withFileTypes: true });
    for (const dirEntry of prefixEntries) {
      if (!dirEntry.isDirectory()) continue;
      const prefixDir = path.join(blobRoot, dirEntry.name);
      const files = fs.readdirSync(prefixDir, { withFileTypes: true });
      for (const file of files) {
        if (!file.isFile()) continue;
        const fullPath = path.join(prefixDir, file.name);
        let stat;
        try {
          stat = fs.statSync(fullPath);
        } catch {
          continue;
        }
        const ageMs = now - stat.mtimeMs;
        if (file.name.endsWith('.tmp')) {
          if (ageMs >= graceMs) {
            try {
              fs.unlinkSync(fullPath);
              deletedTempFiles.push(file.name);
            } catch {}
          }
          continue;
        }
        if (!file.name.endsWith('.bin')) continue;
        const sha = file.name.slice(0, -4);
        if (!isValidSha256(sha)) continue;
        if (!referenced.has(sha) && ageMs >= graceMs) {
          try {
            fs.unlinkSync(fullPath);
            this.db.prepare('DELETE FROM blob_refs WHERE sha256 = ?').run(sha);
            deletedBlobs.push(sha);
          } catch {}
        }
      }
    }

    return {
      deletedCount: deletedBlobs.length,
      deletedBlobs,
      deletedTempFiles
    };
  }

  /**
   * Records an HTTP exchange, spilling bodies >256 KiB to content-addressed storage and indexing in `ex_fts`.
   *
   * @param {object} exchange
   * @returns {object}
   */
  recordExchange(exchange = {}) {
    let working = { ...exchange };

    if (working.applyRewrites) {
      const rewrittenReq = this.applyRewrites(
        {
          method: working.method || 'GET',
          url: working.url || '',
          host: working.host,
          headers: working.reqHeaders ?? working.requestHeaders ?? working.req_headers ?? working.headers ?? {},
          body: working.reqBody ?? working.requestBody ?? working.req_body ?? working.body ?? ''
        },
        'request'
      );
      working.method = rewrittenReq.method;
      working.url = rewrittenReq.url;
      working.host = rewrittenReq.host;
      working.path = rewrittenReq.path;
      working.reqHeaders = rewrittenReq.headers;
      working.reqBody = rewrittenReq.body;
      if (rewrittenReq.rewriteApplied) {
        working.rewriteApplied = true;
        working.taintedSensitive = working.taintedSensitive || rewrittenReq.taintedSensitive;
        working.originalReq = working.originalReq || rewrittenReq.originalReq;
      }
    }

    const id = working.id || crypto.randomUUID();
    const taskId = working.taskId ?? working.task_id ?? null;
    const source = working.source || 'scanner';
    const method = String(working.method || 'GET').toUpperCase();
    const url = String(working.url || '');
    const parsedUrl = parseUrlParts(url, working.host, working.path);
    const host = (working.host || parsedUrl.host).toLowerCase();
    const urlPath = working.path || parsedUrl.path;
    const statusCode =
      working.statusCode !== undefined
        ? Number(working.statusCode)
        : working.status_code !== undefined
          ? Number(working.status_code)
          : working.status !== undefined
            ? Number(working.status)
            : 0;

    const reqHeaders = normalizeHeaders(
      working.reqHeaders ?? working.requestHeaders ?? working.req_headers ?? working.headers ?? {}
    );
    const resHeaders = normalizeHeaders(
      working.resHeaders ?? working.responseHeaders ?? working.res_headers ?? {}
    );

    const reqBuf = toBuffer(
      working.reqBody ?? working.requestBody ?? working.req_body ?? working.body ?? ''
    );
    const resBuf = toBuffer(
      working.resBody ??
        working.responseBody ??
        working.res_body ??
        working.responseText ??
        working.text ??
        ''
    );

    const reqSize = working.reqSize ?? working.req_size ?? reqBuf.byteLength;
    const resSize = working.resSize ?? working.res_size ?? resBuf.byteLength;
    const durationMs = Number(working.durationMs ?? working.duration_ms ?? working.duration ?? 0);

    const mimeType =
      working.mimeType ??
      working.mime_type ??
      working.contentType ??
      getHeaderCaseInsensitive(resHeaders, 'content-type') ??
      '';
    const resEncoding =
      working.resEncoding ??
      working.res_encoding ??
      getHeaderCaseInsensitive(resHeaders, 'content-encoding') ??
      '';

    const taintedSensitive = Boolean(working.taintedSensitive ?? working.tainted_sensitive ?? false);
    const rewriteApplied = Boolean(working.rewriteApplied ?? working.rewrite_applied ?? false);
    const originalReqRaw =
      working.originalReq ??
      working.original_req ??
      working.originalReqJson ??
      working.original_req_json ??
      null;
    const originalReqJson =
      originalReqRaw === null
        ? null
        : typeof originalReqRaw === 'string'
          ? originalReqRaw
          : JSON.stringify(originalReqRaw);

    const createdAt = working.createdAt ?? working.created_at ?? new Date().toISOString();

    const reqHeadersJson = JSON.stringify(reqHeaders);
    const resHeadersJson = JSON.stringify(resHeaders);
    const reqPreview = reqBuf.subarray(0, INLINE_BODY_LIMIT).toString('utf8');
    const resPreview = resBuf.subarray(0, INLINE_BODY_LIMIT).toString('utf8');
    const reqText = `${url}\n${headersToSearchText(reqHeaders)}\n${reqPreview}`;
    const resText = `${headersToSearchText(resHeaders)}\n${resPreview}`;

    this._inTransaction(() => {
      const existingBody = this.db
        .prepare('SELECT req_blob_sha256, res_blob_sha256 FROM exchange_bodies WHERE exchange_id = ?')
        .get(id);

      let reqBodyInline = null;
      let reqBlobSha256 = null;
      if (reqBuf.byteLength > INLINE_BODY_LIMIT) {
        reqBlobSha256 = this._writeBlob(reqBuf);
      } else {
        reqBodyInline = reqBuf;
      }

      let resBodyInline = null;
      let resBlobSha256 = null;
      if (resBuf.byteLength > INLINE_BODY_LIMIT) {
        resBlobSha256 = this._writeBlob(resBuf);
      } else {
        resBodyInline = resBuf;
      }

      this.db
        .prepare(
          `INSERT OR REPLACE INTO exchanges (
            id, task_id, source, method, url, host, path, status_code,
            req_headers_json, res_headers_json, req_size, res_size,
            duration_ms, mime_type, tainted_sensitive, rewrite_applied,
            original_req_json, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          id,
          taskId,
          source,
          method,
          url,
          host,
          urlPath,
          statusCode,
          reqHeadersJson,
          resHeadersJson,
          reqSize,
          resSize,
          durationMs,
          mimeType,
          taintedSensitive ? 1 : 0,
          rewriteApplied ? 1 : 0,
          originalReqJson,
          createdAt
        );

      this.db
        .prepare(
          `INSERT OR REPLACE INTO exchange_bodies (
            exchange_id, req_body_inline, req_blob_sha256, res_body_inline, res_blob_sha256, res_encoding
          ) VALUES (?, ?, ?, ?, ?, ?)`
        )
        .run(id, reqBodyInline, reqBlobSha256, resBodyInline, resBlobSha256, resEncoding);

      if (existingBody) {
        this._decrementBlobRef(existingBody.req_blob_sha256);
        this._decrementBlobRef(existingBody.res_blob_sha256);
      }

      this.db.prepare('DELETE FROM ex_fts WHERE exchange_id = ?').run(id);
      this.db
        .prepare(
          `INSERT INTO ex_fts (exchange_id, host, path, method, status_code, req_text, res_text)
           VALUES (?, ?, ?, ?, ?, ?, ?)`
        )
        .run(id, host, urlPath, method, String(statusCode), reqText, resText);
    });

    return this.getExchange(id, { includeBodies: true });
  }

  /**
   * Ingests browser extension, HAR, or external proxy traffic (`source = 'extension' | 'har' | 'external'`).
   *
   * @param {object|Array} entry
   * @returns {object|Array}
   */
  recordExternal(entry) {
    if (Array.isArray(entry)) {
      return entry.map(item => this.recordExternal(item));
    }
    if (entry && typeof entry === 'object') {
      if (Array.isArray(entry.log?.entries)) {
        return entry.log.entries.map(item =>
          this.recordExternal({ ...item, source: entry.source || 'har', taskId: entry.taskId })
        );
      }
      if (Array.isArray(entry.entries)) {
        return entry.entries.map(item =>
          this.recordExternal({ ...item, source: entry.source || 'har', taskId: entry.taskId })
        );
      }

      // Check if it's a HAR entry object with { request, response }
      if (entry.request && typeof entry.request === 'object') {
        const req = entry.request;
        const res = entry.response || {};
        const rawSource = entry.source || 'har';
        const source = VALID_EXTERNAL_SOURCES.has(rawSource) ? rawSource : 'external';
        return this.recordExchange({
          id: entry.id,
          taskId: entry.taskId ?? entry.task_id ?? null,
          source,
          method: req.method || 'GET',
          url: req.url || '',
          statusCode: res.status ?? res.statusCode ?? 0,
          reqHeaders: req.headers || {},
          resHeaders: res.headers || {},
          reqBody: req.postData?.text ?? req.body ?? '',
          resBody: res.content?.text ?? res.body ?? '',
          mimeType: res.content?.mimeType ?? '',
          durationMs: entry.time ?? entry.durationMs ?? 0
        });
      }
    }

    const rawSource = entry?.source || 'external';
    const source = VALID_EXTERNAL_SOURCES.has(rawSource) ? rawSource : 'external';
    return this.recordExchange({
      ...entry,
      source
    });
  }

  /**
   * Retrieves exchange metadata, headers, and full request/response bodies (reading from blob store if spilled).
   *
   * @param {string} exchangeId
   * @param {object} [options]
   * @param {boolean} [options.includeBodies=true]
   * @returns {object|null}
   */
  getExchange(exchangeId, { includeBodies = true } = {}) {
    const row = this.db.prepare('SELECT * FROM exchanges WHERE id = ?').get(exchangeId);
    if (!row) return null;

    const bodyRow = this.db
      .prepare('SELECT * FROM exchange_bodies WHERE exchange_id = ?')
      .get(exchangeId);

    const reqHeaders = normalizeHeaders(row.req_headers_json);
    const resHeaders = normalizeHeaders(row.res_headers_json);
    let originalReq = null;
    if (row.original_req_json) {
      try {
        originalReq = JSON.parse(row.original_req_json);
      } catch {
        originalReq = null;
      }
    }

    let reqBodyBuffer = Buffer.alloc(0);
    let resBodyBuffer = Buffer.alloc(0);
    let reqBody = '';
    let resBody = '';

    if (includeBodies && bodyRow) {
      if (bodyRow.req_blob_sha256) {
        reqBodyBuffer = this.getBlob(bodyRow.req_blob_sha256) || Buffer.alloc(0);
      } else if (bodyRow.req_body_inline !== null && bodyRow.req_body_inline !== undefined) {
        reqBodyBuffer = toBuffer(bodyRow.req_body_inline);
      }
      reqBody = reqBodyBuffer.toString('utf8');

      if (bodyRow.res_blob_sha256) {
        resBodyBuffer = this.getBlob(bodyRow.res_blob_sha256) || Buffer.alloc(0);
      } else if (bodyRow.res_body_inline !== null && bodyRow.res_body_inline !== undefined) {
        resBodyBuffer = toBuffer(bodyRow.res_body_inline);
      }
      resBody = resBodyBuffer.toString('utf8');
    }

    const result = {
      id: row.id,
      taskId: row.task_id,
      task_id: row.task_id,
      source: row.source,
      method: row.method,
      url: row.url,
      host: row.host,
      path: row.path,
      statusCode: row.status_code,
      status_code: row.status_code,
      status: row.status_code,
      reqHeaders,
      resHeaders,
      req_headers_json: row.req_headers_json,
      res_headers_json: row.res_headers_json,
      reqSize: row.req_size,
      req_size: row.req_size,
      resSize: row.res_size,
      res_size: row.res_size,
      durationMs: row.duration_ms,
      duration_ms: row.duration_ms,
      mimeType: row.mime_type,
      mime_type: row.mime_type,
      taintedSensitive: Boolean(row.tainted_sensitive),
      tainted_sensitive: Boolean(row.tainted_sensitive),
      rewriteApplied: Boolean(row.rewrite_applied),
      rewrite_applied: Boolean(row.rewrite_applied),
      originalReq,
      original_req_json: row.original_req_json,
      createdAt: row.created_at,
      created_at: row.created_at,
      reqBlobSha256: bodyRow?.req_blob_sha256 || null,
      req_blob_sha256: bodyRow?.req_blob_sha256 || null,
      resBlobSha256: bodyRow?.res_blob_sha256 || null,
      res_blob_sha256: bodyRow?.res_blob_sha256 || null,
      resEncoding: bodyRow?.res_encoding || '',
      res_encoding: bodyRow?.res_encoding || ''
    };

    if (includeBodies) {
      result.reqBody = reqBody;
      result.reqBodyBuffer = reqBodyBuffer;
      result.resBody = resBody;
      result.resBodyBuffer = resBodyBuffer;
    }

    return result;
  }

  /**
   * Searches and filters exchanges using FTS5 (`ex_fts MATCH ?`) + `LIKE` substring fallback.
   *
   * @param {object} [filters]
   * @returns {Array}
   */
  queryExchanges({
    taskId,
    host,
    method,
    status,
    search,
    source,
    includeBodies = false,
    limit = 100,
    offset = 0
  } = {}) {
    const whereClauses = [];
    const params = [];

    if (taskId !== undefined && taskId !== null && taskId !== '') {
      whereClauses.push('e.task_id = ?');
      params.push(String(taskId));
    }

    if (host !== undefined && host !== null && host !== '') {
      whereClauses.push('LOWER(e.host) = LOWER(?)');
      params.push(String(host));
    }

    if (method !== undefined && method !== null && method !== '') {
      whereClauses.push('UPPER(e.method) = UPPER(?)');
      params.push(String(method));
    }

    if (source !== undefined && source !== null && source !== '') {
      whereClauses.push('e.source = ?');
      params.push(String(source));
    }

    if (status !== undefined && status !== null && status !== '') {
      const statusStr = String(status).toLowerCase().trim();
      if (/^[1-5]xx$/.test(statusStr)) {
        const base = Number(statusStr[0]) * 100;
        whereClauses.push('(e.status_code >= ? AND e.status_code < ?)');
        params.push(base, base + 100);
      } else {
        whereClauses.push('e.status_code = ?');
        params.push(Number(status));
      }
    }

    if (typeof search === 'string' && search.trim()) {
      const ftsQuery = buildSafeFtsQuery(search);
      const likePattern = `%${escapeLike(search.trim())}%`;

      if (ftsQuery) {
        whereClauses.push(`e.id IN (
          SELECT exchange_id FROM ex_fts WHERE ex_fts MATCH ?
          UNION
          SELECT exchange_id FROM ex_fts
          WHERE host LIKE ? ESCAPE '\\'
             OR path LIKE ? ESCAPE '\\'
             OR method LIKE ? ESCAPE '\\'
             OR status_code LIKE ? ESCAPE '\\'
             OR req_text LIKE ? ESCAPE '\\'
             OR res_text LIKE ? ESCAPE '\\'
        )`);
        params.push(
          ftsQuery,
          likePattern,
          likePattern,
          likePattern,
          likePattern,
          likePattern,
          likePattern
        );
      } else {
        whereClauses.push(`e.id IN (
          SELECT exchange_id FROM ex_fts
          WHERE host LIKE ? ESCAPE '\\'
             OR path LIKE ? ESCAPE '\\'
             OR method LIKE ? ESCAPE '\\'
             OR status_code LIKE ? ESCAPE '\\'
             OR req_text LIKE ? ESCAPE '\\'
             OR res_text LIKE ? ESCAPE '\\'
        )`);
        params.push(
          likePattern,
          likePattern,
          likePattern,
          likePattern,
          likePattern,
          likePattern
        );
      }
    }

    const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';
    const countRow = this.db
      .prepare(`SELECT COUNT(*) AS cnt FROM exchanges e ${whereSql}`)
      .get(...params);
    const total = Number(countRow?.cnt ?? 0);

    const rows = this.db
      .prepare(
        `SELECT e.id FROM exchanges e ${whereSql}
         ORDER BY e.created_at DESC, e.rowid DESC
         LIMIT ? OFFSET ?`
      )
      .all(...params, Number(limit), Number(offset));

    const items = rows
      .map(r => this.getExchange(r.id, { includeBodies }))
      .filter(Boolean);

    Object.defineProperties(items, {
      items: { value: items, enumerable: false },
      exchanges: { value: items, enumerable: false },
      total: { value: total, enumerable: false }
    });

    return items;
  }

  /**
   * Returns aggregated traffic count and status breakdown per host.
   *
   * @param {object} [options]
   * @param {string} [options.taskId]
   * @returns {Array}
   */
  listHosts({ taskId } = {}) {
    const whereSql = taskId ? 'WHERE task_id = ?' : '';
    const params = taskId ? [String(taskId)] : [];

    const rows = this.db
      .prepare(
        `SELECT
          host,
          COUNT(*) AS total,
          SUM(CASE WHEN status_code >= 200 AND status_code < 300 THEN 1 ELSE 0 END) AS s2xx,
          SUM(CASE WHEN status_code >= 300 AND status_code < 400 THEN 1 ELSE 0 END) AS s3xx,
          SUM(CASE WHEN status_code >= 400 AND status_code < 500 THEN 1 ELSE 0 END) AS s4xx,
          SUM(CASE WHEN status_code >= 500 AND status_code < 600 THEN 1 ELSE 0 END) AS s5xx,
          SUM(CASE WHEN status_code < 200 OR status_code >= 600 OR status_code IS NULL THEN 1 ELSE 0 END) AS s_other,
          MAX(created_at) AS last_seen_at
         FROM exchanges
         ${whereSql}
         GROUP BY host
         ORDER BY total DESC, host ASC`
      )
      .all(...params);

    return rows.map(row => ({
      host: row.host,
      count: Number(row.total),
      total: Number(row.total),
      status2xx: Number(row.s2xx || 0),
      status3xx: Number(row.s3xx || 0),
      status4xx: Number(row.s4xx || 0),
      status5xx: Number(row.s5xx || 0),
      statusOther: Number(row.s_other || 0),
      statusBreakdown: {
        '2xx': Number(row.s2xx || 0),
        '3xx': Number(row.s3xx || 0),
        '4xx': Number(row.s4xx || 0),
        '5xx': Number(row.s5xx || 0),
        other: Number(row.s_other || 0)
      },
      lastSeenAt: row.last_seen_at
    }));
  }

  /**
   * Records a WebSocket or SSE stream frame associated with an exchange.
   */
  recordStreamMessage({ id = crypto.randomUUID(), exchangeId, direction = 's2c', seq = 0, payload = '' }) {
    const createdAt = new Date().toISOString();
    this.db
      .prepare(
        `INSERT INTO stream_messages (id, exchange_id, direction, seq, payload, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`
      )
      .run(id, exchangeId, direction, Number(seq), String(payload), createdAt);
    return { id, exchangeId, direction, seq: Number(seq), payload: String(payload), createdAt };
  }

  /**
   * Lists stream messages for an exchange ordered by sequence number.
   */
  listStreamMessages(exchangeId) {
    return this.db
      .prepare('SELECT * FROM stream_messages WHERE exchange_id = ? ORDER BY seq ASC, rowid ASC')
      .all(exchangeId);
  }

  /**
   * Adds a request/response rewrite rule.
   *
   * @param {object} rule
   * @returns {object}
   */
  addRewriteRule(rule = {}) {
    const id = rule.id || crypto.randomUUID();
    const name = String(rule.name || 'Rewrite Rule');
    const enabled = rule.enabled !== undefined ? Boolean(rule.enabled) : true;
    const scopeHost = String(rule.scopeHost ?? rule.scope_host ?? '*');
    const phase = String(rule.phase || 'request').toLowerCase();
    const target = String(rule.target || 'header').toLowerCase();
    const matchPattern = String(rule.matchPattern ?? rule.match_pattern ?? '');
    const replaceValue = String(rule.replaceValue ?? rule.replace_value ?? '');
    const isRegex = Boolean(rule.isRegex ?? rule.is_regex ?? false);
    const isSensitive = Boolean(rule.isSensitive ?? rule.is_sensitive ?? false);
    const createdAt = rule.createdAt ?? rule.created_at ?? new Date().toISOString();

    if (!VALID_PHASES.has(phase)) {
      throw new Error(`Invalid rewrite phase "${phase}"; expected "request" or "response"`);
    }
    if (!VALID_TARGETS.has(target)) {
      throw new Error(`Invalid rewrite target "${target}"; expected "header", "body", or "query"`);
    }
    if (!matchPattern) {
      throw new Error('Rewrite rule matchPattern must be a non-empty string');
    }
    if (isRegex) {
      validateSafeRegex(matchPattern, 'Invalid rewrite rule matchPattern regex');
    }
    if (target === 'header' && matchPattern.includes(':')) {
      const colonIdx = matchPattern.indexOf(':');
      const namePart = matchPattern.slice(0, colonIdx).trim();
      const valPart = matchPattern.slice(colonIdx + 1).trim();
      if (!namePart) {
        throw new Error('Invalid rewrite rule header pattern: header name before ":" must be non-empty');
      }
      if (isRegex && valPart) {
        validateSafeRegex(valPart, 'Invalid rewrite rule header value regex');
      }
    }

    this.db
      .prepare(
        `INSERT OR REPLACE INTO exchange_rewrites (
          id, name, enabled, scope_host, phase, target,
          match_pattern, replace_value, is_regex, is_sensitive, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        id,
        name,
        enabled ? 1 : 0,
        scopeHost,
        phase,
        target,
        matchPattern,
        replaceValue,
        isRegex ? 1 : 0,
        isSensitive ? 1 : 0,
        createdAt
      );

    return {
      id,
      name,
      enabled,
      scopeHost,
      scope_host: scopeHost,
      phase,
      target,
      matchPattern,
      match_pattern: matchPattern,
      replaceValue,
      replace_value: replaceValue,
      isRegex,
      is_regex: isRegex,
      isSensitive,
      is_sensitive: isSensitive,
      createdAt,
      created_at: createdAt
    };
  }

  /**
   * Lists all configured rewrite rules.
   *
   * @returns {Array}
   */
  listRewriteRules() {
    const rows = this.db
      .prepare('SELECT * FROM exchange_rewrites ORDER BY created_at ASC, rowid ASC')
      .all();
    return rows.map(row => ({
      id: row.id,
      name: row.name,
      enabled: Boolean(row.enabled),
      scopeHost: row.scope_host,
      scope_host: row.scope_host,
      phase: row.phase,
      target: row.target,
      matchPattern: row.match_pattern,
      match_pattern: row.match_pattern,
      replaceValue: row.replace_value,
      replace_value: row.replace_value,
      isRegex: Boolean(row.is_regex),
      is_regex: Boolean(row.is_regex),
      isSensitive: Boolean(row.is_sensitive),
      is_sensitive: Boolean(row.is_sensitive),
      createdAt: row.created_at,
      created_at: row.created_at
    }));
  }

  /**
   * Deletes a rewrite rule by ID.
   *
   * @param {string} id
   * @returns {boolean}
   */
  deleteRewriteRule(id) {
    const res = this.db.prepare('DELETE FROM exchange_rewrites WHERE id = ?').run(id);
    return Number(res.changes) > 0;
  }

  /**
   * Applies enabled rewrite rules matching the host and phase (`request` | `response`).
   * If any applied rule has `is_sensitive: true`, sets `tainted_sensitive: true`, computes an
   * HMAC-SHA256 taint tag, and preserves the pre-rewrite snapshot in `original_req_json`.
   *
   * @param {object} requestOrResponse
   * @param {'request'|'response'} [phase='request']
   * @returns {object}
   */
  applyRewrites(requestOrResponse = {}, phase = 'request') {
    const normPhase = String(phase || 'request').toLowerCase();
    const method = String(requestOrResponse.method || 'GET').toUpperCase();
    let url = String(requestOrResponse.url || '');
    const parsedInitial = parseUrlParts(url, requestOrResponse.host, requestOrResponse.path);
    const host = (
      requestOrResponse.host ||
      parsedInitial.host ||
      getHeaderCaseInsensitive(requestOrResponse.headers || requestOrResponse.reqHeaders, 'host')
    ).toLowerCase();
    let urlPath = requestOrResponse.path || parsedInitial.path;

    const rawHeaders =
      normPhase === 'response'
        ? requestOrResponse.headers ?? requestOrResponse.resHeaders ?? requestOrResponse.responseHeaders ?? {}
        : requestOrResponse.headers ?? requestOrResponse.reqHeaders ?? requestOrResponse.requestHeaders ?? {};
    const headers = { ...normalizeHeaders(rawHeaders) };

    const rawBody =
      normPhase === 'response'
        ? requestOrResponse.body ?? requestOrResponse.resBody ?? requestOrResponse.responseBody ?? ''
        : requestOrResponse.body ?? requestOrResponse.reqBody ?? requestOrResponse.requestBody ?? '';
    let body = Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : String(rawBody ?? '');

    const preRewriteSnapshot = {
      method,
      url,
      host,
      path: urlPath,
      headers: { ...headers },
      body
    };

    const rules = this.listRewriteRules().filter(
      r => r.enabled && r.phase === normPhase && hostMatchesScope(r.scopeHost, host)
    );

    const appliedRules = [];
    let taintedSensitive = false;

    for (const rule of rules) {
      let ruleApplied = false;

      if (rule.target === 'header') {
        const pattern = rule.matchPattern;
        const replacement = rule.replaceValue;

        if (pattern.includes(':')) {
          const colonIdx = pattern.indexOf(':');
          const namePart = pattern.slice(0, colonIdx).trim();
          const valPart = pattern.slice(colonIdx + 1).trim();

          let matchedExisting = false;
          for (const [hKey, hVal] of Object.entries(headers)) {
            if (hKey.toLowerCase() === namePart.toLowerCase()) {
              matchedExisting = true;
              if (rule.isRegex) {
                let re;
                try {
                  re = new RegExp(valPart || '.*', 'g');
                } catch {
                  continue;
                }
                if (re.test(hVal)) {
                  re.lastIndex = 0;
                  headers[hKey] = hVal.replace(re, replacement);
                  ruleApplied = true;
                }
              } else if (!valPart || hVal.includes(valPart)) {
                headers[hKey] = valPart ? hVal.replaceAll(valPart, replacement) : replacement;
                ruleApplied = true;
              }
            }
          }
          if (!matchedExisting && (!valPart || valPart === '.*')) {
            headers[namePart] = replacement;
            ruleApplied = true;
          }
        } else {
          // Check if pattern matches a header key first
          let keyMatched = false;
          for (const hKey of Object.keys(headers)) {
            const isMatch = rule.isRegex
              ? new RegExp(pattern, 'i').test(hKey)
              : hKey.toLowerCase() === pattern.toLowerCase();
            if (isMatch) {
              keyMatched = true;
              let newVal = replacement;
              const prefix = `${hKey.toLowerCase()}:`;
              if (newVal.toLowerCase().startsWith(prefix)) {
                newVal = newVal.slice(prefix.length).trim();
              }
              headers[hKey] = newVal;
              ruleApplied = true;
            }
          }

          // Check if pattern matches inside any header value
          if (!keyMatched) {
            for (const [hKey, hVal] of Object.entries(headers)) {
              if (rule.isRegex) {
                const re = new RegExp(pattern, 'g');
                if (re.test(hVal)) {
                  headers[hKey] = hVal.replace(new RegExp(pattern, 'g'), replacement);
                  ruleApplied = true;
                }
              } else if (hVal.includes(pattern)) {
                headers[hKey] = hVal.replaceAll(pattern, replacement);
                ruleApplied = true;
              }
            }
          }

          // If not matched on existing keys/values and pattern is a literal header token, add header
          if (!ruleApplied && !rule.isRegex && /^[a-zA-Z0-9-]+$/.test(pattern)) {
            headers[pattern] = replacement;
            ruleApplied = true;
          }
        }
      } else if (rule.target === 'body') {
        if (rule.isRegex) {
          const re = new RegExp(rule.matchPattern, 'g');
          if (re.test(body)) {
            body = body.replace(new RegExp(rule.matchPattern, 'g'), rule.replaceValue);
            ruleApplied = true;
          }
        } else if (rule.matchPattern === '*') {
          body = rule.replaceValue;
          ruleApplied = true;
        } else if (body.includes(rule.matchPattern)) {
          body = body.replaceAll(rule.matchPattern, rule.replaceValue);
          ruleApplied = true;
        }
      } else if (rule.target === 'query') {
        try {
          const parsedUrl = new URL(url);
          const rawSearch = parsedUrl.search.startsWith('?')
            ? parsedUrl.search.slice(1)
            : parsedUrl.search;

          if (rule.isRegex) {
            const re = new RegExp(rule.matchPattern, 'g');
            if (re.test(rawSearch)) {
              const updatedSearch = rawSearch.replace(
                new RegExp(rule.matchPattern, 'g'),
                rule.replaceValue
              );
              parsedUrl.search = updatedSearch ? `?${updatedSearch}` : '';
              url = parsedUrl.toString();
              urlPath = (parsedUrl.pathname || '/') + (parsedUrl.search || '');
              ruleApplied = true;
            }
          } else if (parsedUrl.searchParams.has(rule.matchPattern)) {
            parsedUrl.searchParams.set(rule.matchPattern, rule.replaceValue);
            url = parsedUrl.toString();
            urlPath = (parsedUrl.pathname || '/') + (parsedUrl.search || '');
            ruleApplied = true;
          } else if (rawSearch.includes(rule.matchPattern)) {
            const updatedSearch = rawSearch.replaceAll(rule.matchPattern, rule.replaceValue);
            parsedUrl.search = updatedSearch ? `?${updatedSearch}` : '';
            url = parsedUrl.toString();
            urlPath = (parsedUrl.pathname || '/') + (parsedUrl.search || '');
            ruleApplied = true;
          } else if (/^[a-zA-Z0-9_.-]+$/.test(rule.matchPattern)) {
            parsedUrl.searchParams.set(rule.matchPattern, rule.replaceValue);
            url = parsedUrl.toString();
            urlPath = (parsedUrl.pathname || '/') + (parsedUrl.search || '');
            ruleApplied = true;
          }
        } catch {
          // Fallback if URL is relative path
          if (urlPath.includes(rule.matchPattern)) {
            urlPath = urlPath.replaceAll(rule.matchPattern, rule.replaceValue);
            url = urlPath;
            ruleApplied = true;
          }
        }
      }

      if (ruleApplied) {
        appliedRules.push(rule.id);
        if (rule.isSensitive) {
          taintedSensitive = true;
        }
      }
    }

    const rewriteApplied = appliedRules.length > 0;
    const originalReqJson = rewriteApplied ? JSON.stringify(preRewriteSnapshot) : null;
    let taintHmac = null;

    if (taintedSensitive) {
      taintHmac = crypto
        .createHmac('sha256', this.hmacSecret)
        .update(JSON.stringify({ method, url, headers, body }))
        .digest('hex');
    }

    return {
      ...requestOrResponse,
      method,
      url,
      host,
      path: urlPath,
      headers,
      reqHeaders: normPhase === 'request' ? headers : requestOrResponse.reqHeaders,
      resHeaders: normPhase === 'response' ? headers : requestOrResponse.resHeaders,
      body,
      reqBody: normPhase === 'request' ? body : requestOrResponse.reqBody,
      resBody: normPhase === 'response' ? body : requestOrResponse.resBody,
      rewriteApplied,
      rewrite_applied: rewriteApplied,
      taintedSensitive,
      tainted_sensitive: taintedSensitive,
      taintHmac,
      taint_hmac: taintHmac,
      originalReq: rewriteApplied ? preRewriteSnapshot : null,
      original_req_json: originalReqJson,
      appliedRules
    };
  }

  /**
   * RFC-9110 Request Replay: loads original exchange, merges method/URL/header/body overrides,
   * strips hop-by-hop headers, validates target URL against `validateUrl` (defaulting to
   * `resolveAndValidateTarget` with DNS/pinning protection) and optional `guard` (SSRF protection),
   * enforces `redirect: 'manual'` (and re-validates hops up to `maxRedirects` if `followRedirects` is enabled),
   * records the new exchange (`source: 'replay'`), and returns `{ replayExchange, response }`.
   *
   * @param {string} exchangeId
   * @param {object} [overrides={}]
   * @param {object} [options={}]
   * @returns {Promise<{ replayExchange: object, response: object }>}
   */
  async replayRequest(
    exchangeId,
    overrides = {},
    {
      fetcher = globalThis.fetch,
      validateUrl = resolveAndValidateTarget,
      dnsResolver = null,
      resolver = null,
      targetPinStore = null,
      guard = null,
      allowPrivate = false,
      followRedirects = false,
      maxRedirects = 5,
      timeout = 15000,
      timeoutMs = undefined
    } = {}
  ) {
    const original = this.getExchange(exchangeId, { includeBodies: true });
    if (!original) {
      throw new Error(`Exchange not found: "${exchangeId}"`);
    }

    const method = String(overrides.method || original.method || 'GET').toUpperCase();
    const initialUrl = String(overrides.url || original.url || '');
    const allowPrivateFlag = Boolean(allowPrivate);
    const activeDnsResolver = dnsResolver ?? resolver ?? null;
    const activePinStore = targetPinStore || new TargetPinStore({ allowPrivate: allowPrivateFlag });

    const evalGuard = async (input) => {
      if (!guard) return null;
      if (typeof guard === 'function') return guard(input);
      if (typeof guard.evaluateAssetGate === 'function') return guard.evaluateAssetGate(input);
      if (typeof guard.check === 'function') return guard.check(input);
      if (typeof guard.validate === 'function') return guard.validate(input);
      if (Array.isArray(guard)) return evaluateAssetGate(input, { rules: guard });
      return null;
    };

    const checkTarget = async (targetUrl, { isRedirect = false } = {}) => {
      const validatorPrefix = isRedirect ? 'Replay redirect blocked by URL validator' : 'Replay blocked by URL validator';
      const guardPrefix = isRedirect ? 'Replay redirect blocked by guard' : 'Replay blocked by guard';

      if (validateUrl === resolveAndValidateTarget) {
        const preCheck = validateTargetUrl(targetUrl, { allowPrivate: allowPrivateFlag });
        if (!preCheck.valid) {
          throw new Error(`${validatorPrefix}: ${preCheck.error || `Blocked target URL: ${targetUrl}`}`);
        }
      }

      if (guard) {
        const guardRes = await evalGuard(targetUrl);
        if (guardRes && (guardRes.allowed === false || guardRes.valid === false)) {
          throw new Error(`${guardPrefix}: ${guardRes.reason || guardRes.error || 'Target denied'}`);
        }
      }

      let resolvedIps = null;
      let resolvedHostname = null;
      if (typeof validateUrl === 'function') {
        const validation = await validateUrl(targetUrl, {
          resolver: activeDnsResolver,
          targetPinStore: activePinStore,
          allowPrivate: allowPrivateFlag
        });
        if (!validation || validation.valid === false) {
          const errReason = validation?.error || validation?.reason || `Blocked target URL: ${targetUrl}`;
          throw new Error(`${validatorPrefix}: ${errReason}`);
        }
        if (Array.isArray(validation.resolvedIps)) {
          resolvedIps = validation.resolvedIps;
        }
        if (validation.hostname) {
          resolvedHostname = validation.hostname;
        }
      }

      if (guard && resolvedIps && resolvedIps.length > 0 && (Array.isArray(guard) || typeof guard.evaluateAssetGate === 'function')) {
        const postDnsGuard = await evalGuard({
          url: targetUrl,
          hostname: resolvedHostname,
          resolvedIps
        });
        if (postDnsGuard && (postDnsGuard.allowed === false || postDnsGuard.valid === false)) {
          throw new Error(`${guardPrefix}: ${postDnsGuard.reason || postDnsGuard.error || 'Target denied'}`);
        }
      }
    };

    await checkTarget(initialUrl, { isRedirect: false });

    // Merge headers (case-insensitively applying overrides) and strip hop-by-hop headers
    const mergedHeaders = { ...normalizeHeaders(original.reqHeaders) };
    const overrideHeaders = normalizeHeaders(overrides.headers ?? overrides.reqHeaders ?? {});
    for (const [oKey, oVal] of Object.entries(overrideHeaders)) {
      for (const existingKey of Object.keys(mergedHeaders)) {
        if (existingKey.toLowerCase() === oKey.toLowerCase() && existingKey !== oKey) {
          delete mergedHeaders[existingKey];
        }
      }
      mergedHeaders[oKey] = oVal;
    }

    const cleanedHeaders = stripHopByHopHeaders(mergedHeaders);

    const rawBody =
      overrides.body !== undefined
        ? overrides.body
        : overrides.reqBody !== undefined
          ? overrides.reqBody
          : original.reqBody;

    const hasBody =
      rawBody !== undefined &&
      rawBody !== null &&
      rawBody !== '' &&
      method !== 'GET' &&
      method !== 'HEAD';

    const parsedMaxRedirects = Number(maxRedirects);
    const hopLimit = Number.isFinite(parsedMaxRedirects)
      ? Math.max(0, Math.min(Math.trunc(parsedMaxRedirects), 5))
      : 5;
    const effectiveTimeoutMs = Number.isFinite(Number(timeoutMs ?? timeout)) && Number(timeoutMs ?? timeout) > 0
      ? Number(timeoutMs ?? timeout)
      : 15000;
    let currentUrl = initialUrl;
    let hops = 0;
    let statusCode = 200;
    let resHeaders = {};
    let fetchResponse = null;

    const startTime = performance.now();
    while (true) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(new Error(`Replay request timed out after ${effectiveTimeoutMs}ms`)), effectiveTimeoutMs);
      try {
        fetchResponse = await fetcher(currentUrl, {
          method,
          headers: cleanedHeaders,
          body: hasBody ? rawBody : undefined,
          redirect: 'manual',
          signal: controller.signal
        });
      } finally {
        clearTimeout(timer);
      }

      statusCode = Number(fetchResponse.status ?? fetchResponse.statusCode ?? 200);
      resHeaders = normalizeHeaders(fetchResponse.headers || {});
      const location = getHeaderCaseInsensitive(resHeaders, 'location');
      const isRedirect = statusCode >= 300 && statusCode < 400;

      if (followRedirects && isRedirect && location) {
        if (hops >= hopLimit) {
          throw new Error(`Replay blocked by URL validator: Maximum redirect limit (${hopLimit}) exceeded`);
        }
        let nextUrl;
        try {
          nextUrl = new URL(location, currentUrl).href;
        } catch {
          throw new Error(`Replay redirect blocked by URL validator: Invalid redirect URL "${location}"`);
        }
        await checkTarget(nextUrl, { isRedirect: true });
        currentUrl = nextUrl;
        hops += 1;
        continue;
      }

      break;
    }
    const durationMs = Math.max(0, performance.now() - startTime);

    let resBodyBuf = Buffer.alloc(0);
    if (typeof fetchResponse.arrayBuffer === 'function') {
      resBodyBuf = Buffer.from(await fetchResponse.arrayBuffer());
    } else if (typeof fetchResponse.text === 'function') {
      resBodyBuf = Buffer.from(await fetchResponse.text(), 'utf8');
    } else if (Buffer.isBuffer(fetchResponse.body)) {
      resBodyBuf = fetchResponse.body;
    } else if (typeof fetchResponse.body === 'string') {
      resBodyBuf = Buffer.from(fetchResponse.body, 'utf8');
    } else if (typeof fetchResponse.text === 'string') {
      resBodyBuf = Buffer.from(fetchResponse.text, 'utf8');
    }

    const replayExchange = this.recordExchange({
      taskId: overrides.taskId ?? original.taskId,
      source: 'replay',
      method,
      url: currentUrl,
      statusCode,
      reqHeaders: cleanedHeaders,
      resHeaders,
      reqBody: hasBody ? rawBody : '',
      resBody: resBodyBuf,
      durationMs
    });

    return {
      replayExchange,
      response: {
        status: statusCode,
        statusCode,
        headers: resHeaders,
        body: resBodyBuf.toString('utf8'),
        bodyBuffer: resBodyBuf
      }
    };
  }

  /**
   * Clusters captured exchanges by `(host, method, templateUrlPath(path))`
   * (SecScan `idx_ex_tmpl` route template aggregation).
   *
   * @param {{ host?: string, taskId?: string, limit?: number }} [options={}]
   */
  listUrlTemplates({ host = '', taskId = '', limit = 100 } = {}) {
    const clauses = [];
    const params = [];
    if (host) {
      clauses.push('host = ?');
      params.push(String(host).toLowerCase());
    }
    if (taskId) {
      clauses.push('task_id = ?');
      params.push(String(taskId));
    }
    const whereSql = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    const rows = this.db
      .prepare(`SELECT id, host, method, url, path, status_code, created_at FROM exchanges ${whereSql} ORDER BY created_at DESC LIMIT 2000`)
      .all(...params);

    const groups = new Map();
    for (const r of rows) {
      const urlTemplate = templateUrlPath(r.path || r.url);
      const key = `${r.host}||${r.method}||${urlTemplate}`;
      let g = groups.get(key);
      if (!g) {
        g = {
          host: r.host,
          method: r.method,
          urlTemplate,
          intruderTemplateUrl: r.url.replace(/\/\d+(?=\/|$|\?)/g, '/§1§'),
          count: 0,
          sampleUrl: r.url,
          sampleExchangeId: r.id,
          statuses: {},
          lastSeenAt: r.created_at
        };
        groups.set(key, g);
      }
      g.count += 1;
      const sc = String(r.status_code ?? 0);
      g.statuses[sc] = (g.statuses[sc] || 0) + 1;
    }

    const maxItems = Math.min(500, Math.max(1, Number(limit) || 100));
    return Array.from(groups.values())
      .sort((a, b) => b.count - a.count || a.urlTemplate.localeCompare(b.urlTemplate))
      .slice(0, maxItems);
  }

  /**
   * Exports captured HTTP exchanges in standard HAR 1.2 format for interoperability
   * with Burp Suite, Caido, OWASP ZAP, and browser DevTools.
   *
   * @param {{ host?: string, taskId?: string, limit?: number }} [options={}]
   */
  exportHar({ host = '', taskId = '', limit = 200 } = {}) {
    const cap = Math.min(500, Math.max(1, Number(limit) || 200));
    const exchanges = this.queryExchanges({
      host: host || undefined,
      taskId: taskId || undefined,
      limit: cap,
      includeBodies: true
    });

    const entries = exchanges.map(ex => {
      const reqHeadersArr = Object.entries(ex.reqHeaders || {}).map(([name, value]) => ({
        name,
        value: String(value ?? '')
      }));
      const resHeadersArr = Object.entries(ex.resHeaders || {}).map(([name, value]) => ({
        name,
        value: String(value ?? '')
      }));
      const reqBodyStr = typeof ex.reqBody === 'string' ? ex.reqBody : '';
      const resBodyStr = typeof ex.resBody === 'string' ? ex.resBody : '';
      const reqContentType = getHeaderCaseInsensitive(ex.reqHeaders, 'content-type') || 'text/plain';
      const resContentType = ex.mimeType || getHeaderCaseInsensitive(ex.resHeaders, 'content-type') || 'text/plain';

      let queryString = [];
      try {
        const u = new URL(ex.url);
        queryString = Array.from(u.searchParams.entries()).map(([name, value]) => ({ name, value }));
      } catch {
        queryString = [];
      }

      return {
        _exchangeId: ex.id,
        _urlTemplate: templateUrlPath(ex.path || ex.url),
        startedDateTime: ex.createdAt || new Date().toISOString(),
        time: Number(ex.durationMs || 0),
        request: {
          method: ex.method || 'GET',
          url: ex.url,
          httpVersion: 'HTTP/1.1',
          cookies: [],
          headers: reqHeadersArr,
          queryString,
          headersSize: -1,
          bodySize: Number(ex.reqSize || Buffer.byteLength(reqBodyStr, 'utf8')),
          ...(reqBodyStr
            ? {
                postData: {
                  mimeType: reqContentType,
                  text: reqBodyStr
                }
              }
            : {})
        },
        response: {
          status: Number(ex.statusCode ?? 200),
          statusText: '',
          httpVersion: 'HTTP/1.1',
          cookies: [],
          headers: resHeadersArr,
          content: {
            size: Number(ex.resSize || Buffer.byteLength(resBodyStr, 'utf8')),
            mimeType: resContentType,
            text: resBodyStr
          },
          redirectURL: getHeaderCaseInsensitive(ex.resHeaders, 'location') || '',
          headersSize: -1,
          bodySize: Number(ex.resSize || Buffer.byteLength(resBodyStr, 'utf8'))
        },
        cache: {},
        timings: {
          send: 0,
          wait: Number(ex.durationMs || 0),
          receive: 0
        }
      };
    });

    return {
      log: {
        version: '1.2',
        creator: {
          name: 'Security Scanner',
          version: '2.5.0'
        },
        entries
      }
    };
  }

  /**
   * Runs passive vulnerability analysis against a stored exchange by ID.
   */
  analyzeExchangePassive(exchangeId) {
    const ex = this.getExchange(exchangeId, { includeBodies: true });
    if (!ex) return [];
    return analyzePassiveExchange(ex);
  }

  close() {
    if (this._closed) return;
    this._closed = true;
    this._memoryBlobs.clear();
    this._memoryBlobBytes = 0;
    if (this.ownsDb && this.db) {
      try {
        this.db.close();
      } catch {
        // ignore double-close errors
      }
    }
  }
}
