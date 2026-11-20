import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {
  gunzipSync,
  inflateSync,
  inflateRawSync,
  brotliDecompressSync
} from 'node:zlib';
import { validateTargetUrl, resolveAndValidateTarget } from './validator.js';
import { TargetPinStore, evaluateAssetGate } from './guard.js';
import { isValidSha256, stripHopByHopHeaders } from './traffic.js';

export const MAX_DECOMPRESS_BYTES = 16 * 1024 * 1024; // 16 MiB cap against decompression bombs
export const MIN_EVIDENCE_QUOTE_LEN = 8;
export const MIN_VERIFIED_POE_LEVEL = 3;

const VALID_BINDING_ROLES = new Set(['baseline', 'proof', 'verification', 'supporting']);
const PROOF_ROLES = new Set(['proof', 'verification']);
const VALID_RETEST_VERDICTS = new Set(['reproduced', 'fixed', 'inconclusive']);

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
  if (typeof headers === 'object' && !Array.isArray(headers)) {
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

function headersToText(headers) {
  const norm = normalizeHeaders(headers);
  return Object.entries(norm)
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n');
}

/**
 * Safely decompresses an HTTP body buffer according to `Content-Encoding`
 * (`gzip`, `x-gzip`, `deflate`, `br`) with a strict 16 MiB output cap (`MAX_DECOMPRESS_BYTES`).
 *
 * @param {Buffer|Uint8Array|string} buffer
 * @param {string} [contentEncoding='']
 * @returns {Buffer}
 */
export function decompressBodyBuffer(buffer, contentEncoding = '') {
  const buf = toBuffer(buffer);
  if (buf.byteLength === 0) {
    return buf;
  }

  const encoding = String(contentEncoding || '')
    .toLowerCase()
    .trim();

  if (!encoding || encoding === 'identity' || encoding === 'none') {
    if (buf.byteLength > MAX_DECOMPRESS_BYTES) {
      const err = new RangeError(
        `Decompressed body exceeds MAX_DECOMPRESS_BYTES (${MAX_DECOMPRESS_BYTES})`
      );
      err.code = 'ERR_BUFFER_TOO_LARGE';
      throw err;
    }
    return buf;
  }

  if (encoding === 'gzip' || encoding === 'x-gzip') {
    return gunzipSync(buf, { maxOutputLength: MAX_DECOMPRESS_BYTES });
  }

  if (encoding === 'deflate') {
    try {
      return inflateSync(buf, { maxOutputLength: MAX_DECOMPRESS_BYTES });
    } catch (err) {
      if (err && err.code === 'ERR_BUFFER_TOO_LARGE') {
        throw err;
      }
      return inflateRawSync(buf, { maxOutputLength: MAX_DECOMPRESS_BYTES });
    }
  }

  if (encoding === 'br' || encoding === 'brotli') {
    return brotliDecompressSync(buf, { maxOutputLength: MAX_DECOMPRESS_BYTES });
  }

  if (buf.byteLength > MAX_DECOMPRESS_BYTES) {
    const err = new RangeError(
      `Body exceeds MAX_DECOMPRESS_BYTES (${MAX_DECOMPRESS_BYTES})`
    );
    err.code = 'ERR_BUFFER_TOO_LARGE';
    throw err;
  }
  return buf;
}

/**
 * Collapses all contiguous whitespace (`\s+`) to a single space and trims.
 *
 * @param {string|Buffer} str
 * @returns {string}
 */
export function normalizeEvidenceWhitespace(str) {
  if (str === null || str === undefined) return '';
  const text = Buffer.isBuffer(str) ? str.toString('utf8') : String(str);
  return text.replace(/\s+/g, ' ').trim();
}

function isLikelyGzipBuffer(buf) {
  return Buffer.isBuffer(buf) && buf.byteLength >= 2 && buf[0] === 0x1f && buf[1] === 0x8b;
}

/**
 * Extracts and whitespace-normalizes all searchable HTTP request & response headers + decompressed body text
 * from a snapshot object.
 *
 * @param {object} rawSnap
 * @returns {string}
 */
function buildNormalizedSnapshotCorpus(rawSnap) {
  const snap = rawSnap?.snapshot && typeof rawSnap.snapshot === 'object'
    ? { ...rawSnap.snapshot, role: rawSnap.role || rawSnap.snapshot.role }
    : rawSnap || {};

  const method = String(snap.method || '');
  const url = String(snap.url || '');
  const statusCode = snap.statusCode ?? snap.status_code ?? snap.status ?? '';

  const reqHeaders = normalizeHeaders(
    snap.reqHeaders ?? snap.req_headers_json ?? snap.requestHeaders ?? {}
  );
  const resHeaders = normalizeHeaders(
    snap.resHeaders ?? snap.res_headers_json ?? snap.responseHeaders ?? {}
  );

  const rawEncoding =
    snap.resEncoding ??
    snap.res_encoding ??
    snap.contentEncoding ??
    getHeaderCaseInsensitive(resHeaders, 'content-encoding') ??
    '';
  const encoding = snap.resBodyAlreadyDecompressed === true ? 'identity' : rawEncoding;

  let reqBodyText = '';
  const rawReqBody =
    snap.reqBodyBuffer ??
    snap.reqBody ??
    snap.req_body_text ??
    snap.req_body ??
    snap.requestBody ??
    '';
  if (Buffer.isBuffer(rawReqBody) || rawReqBody instanceof Uint8Array) {
    reqBodyText = toBuffer(rawReqBody).toString('utf8');
  } else {
    reqBodyText = String(rawReqBody ?? '');
  }

  let resBodyText = '';
  const rawResBufferCandidate =
    snap.resBodyBuffer ??
    (Buffer.isBuffer(snap.resBody) || snap.resBody instanceof Uint8Array ? snap.resBody : null) ??
    (Buffer.isBuffer(snap.body) || snap.body instanceof Uint8Array ? snap.body : null) ??
    (Buffer.isBuffer(snap.res_body_text) ? snap.res_body_text : null);

  if (rawResBufferCandidate) {
    const decompressed = decompressBodyBuffer(rawResBufferCandidate, encoding);
    resBodyText = decompressed.toString('utf8');
  } else {
    const strBody =
      snap.resBody ?? snap.res_body_text ?? snap.res_body ?? snap.responseBody ?? snap.body ?? '';
    if (Buffer.byteLength(String(strBody), 'utf8') > MAX_DECOMPRESS_BYTES) {
      const err = new RangeError(
        `Response body exceeds MAX_DECOMPRESS_BYTES (${MAX_DECOMPRESS_BYTES})`
      );
      err.code = 'ERR_BUFFER_TOO_LARGE';
      throw err;
    }
    resBodyText = String(strBody);
  }

  const combined = [
    `${method} ${url} ${statusCode}`,
    headersToText(reqHeaders),
    reqBodyText,
    headersToText(resHeaders),
    resBodyText
  ].join('\n');

  return normalizeEvidenceWhitespace(combined);
}

/**
 * ARTEX S1 Machine-Checked Receipt Verifier.
 *
 * Rules:
 * 1. Must have at least one bound snapshot with `role` in `'proof'` or `'verification'`.
 * 2. `finding.poeLevel >= 3`.
 * 3. `finding.evidenceQuotes` must contain at least one quote with whitespace-normalized length >= 8
 *    that appears verbatim inside the decompressed, whitespace-normalized request/response headers or body
 *    of a bound `proof`/`verification` snapshot (and no invalid/missing quotes).
 *
 * @param {object} finding
 * @param {Array<object>} [snapshots=[]]
 * @returns {{
 *   verified: boolean,
 *   status: 'verified' | 'unverified' | 'rejected',
 *   poeLevel: number,
 *   matchedQuotes: string[],
 *   missingQuotes: string[],
 *   reason: string
 * }}
 */
export function assessFindingVerification(finding = {}, snapshots = []) {
  const poeLevel = Number(finding?.poeLevel ?? finding?.poe_level ?? finding?.poe ?? 0);
  const rawQuotes = Array.isArray(finding?.evidenceQuotes)
    ? finding.evidenceQuotes
    : Array.isArray(finding?.evidence_quotes)
      ? finding.evidence_quotes
      : Array.isArray(finding?.quotes)
        ? finding.quotes
        : [];

  const candidateSnapshots =
    Array.isArray(snapshots) && snapshots.length > 0
      ? snapshots
      : Array.isArray(finding?.snapshots)
        ? finding.snapshots
        : Array.isArray(finding?.bindings)
          ? finding.bindings
          : [];

  const proofSnapshots = candidateSnapshots.filter(s => {
    const role = String(s?.role ?? s?.snapshot?.role ?? '').toLowerCase();
    return PROOF_ROLES.has(role);
  });

  if (proofSnapshots.length === 0) {
    return {
      verified: false,
      status: 'unverified',
      poeLevel,
      matchedQuotes: [],
      missingQuotes: [...rawQuotes],
      reason: 'No proof or verification snapshot bound to finding'
    };
  }

  if (!Number.isFinite(poeLevel) || poeLevel < MIN_VERIFIED_POE_LEVEL) {
    return {
      verified: false,
      status: 'unverified',
      poeLevel,
      matchedQuotes: [],
      missingQuotes: [...rawQuotes],
      reason: `PoE level ${poeLevel} is below required minimum L${MIN_VERIFIED_POE_LEVEL}`
    };
  }

  if (rawQuotes.length === 0) {
    return {
      verified: false,
      status: 'rejected',
      poeLevel,
      matchedQuotes: [],
      missingQuotes: [],
      reason: 'No evidence quotes provided for S1 receipt verification'
    };
  }

  const corpora = [];
  for (const snap of proofSnapshots) {
    try {
      corpora.push(buildNormalizedSnapshotCorpus(snap));
    } catch (err) {
      return {
        verified: false,
        status: 'rejected',
        poeLevel,
        matchedQuotes: [],
        missingQuotes: [...rawQuotes],
        reason: `Failed to decompress or read snapshot body: ${err.message}`
      };
    }
  }

  const matchedQuotes = [];
  const missingQuotes = [];
  const tooShortQuotes = [];

  for (const rawQuote of rawQuotes) {
    const normQuote = normalizeEvidenceWhitespace(rawQuote);
    if (normQuote.length < MIN_EVIDENCE_QUOTE_LEN) {
      tooShortQuotes.push(String(rawQuote));
      missingQuotes.push(String(rawQuote));
      continue;
    }

    const found = corpora.some(corpus => corpus.includes(normQuote));
    if (found) {
      matchedQuotes.push(String(rawQuote));
    } else {
      missingQuotes.push(String(rawQuote));
    }
  }

  if (tooShortQuotes.length > 0) {
    return {
      verified: false,
      status: 'rejected',
      poeLevel,
      matchedQuotes,
      missingQuotes,
      reason: `Evidence quote shorter than minimum ${MIN_EVIDENCE_QUOTE_LEN} characters after whitespace normalization`
    };
  }

  if (missingQuotes.length > 0 || matchedQuotes.length === 0) {
    return {
      verified: false,
      status: 'rejected',
      poeLevel,
      matchedQuotes,
      missingQuotes,
      reason: `Verbatim evidence quote not found in bound proof/verification snapshots`
    };
  }

  return {
    verified: true,
    status: 'verified',
    poeLevel,
    matchedQuotes,
    missingQuotes: [],
    reason: `Verified ${matchedQuotes.length} verbatim quote(s) at PoE L${poeLevel}`
  };
}

export class EvidenceStore {
  /**
   * @param {object} [options]
   * @param {DatabaseSync|null} [options.db=null]
   * @param {string} [options.dbPath=':memory:']
   * @param {string|null} [options.blobDir=null]
   * @param {object|null} [options.trafficStore=null]
   */
  constructor({
    db = null,
    dbPath = ':memory:',
    blobDir = null,
    trafficStore = null,
    maxMemoryBlobs = 512,
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
      fs.mkdirSync(this.blobDir, { recursive: true });
    }
    this.trafficStore = trafficStore || null;
    this._memoryBlobs = new Map();
    this._memoryBlobBytes = 0;
    this.maxMemoryBlobs = Number.isFinite(Number(maxMemoryBlobs)) && Number(maxMemoryBlobs) > 0
      ? Math.floor(Number(maxMemoryBlobs))
      : 512;
    this.maxMemoryBlobBytes = Number.isFinite(Number(maxMemoryBlobBytes)) && Number(maxMemoryBlobBytes) > 0
      ? Math.floor(Number(maxMemoryBlobBytes))
      : 64 * 1024 * 1024;
    this._closed = false;

    this._initSchema();
  }

  _initSchema() {
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA busy_timeout = 5000;
      PRAGMA foreign_keys = ON;

      CREATE TABLE IF NOT EXISTS evidence_snapshots (
        id TEXT PRIMARY KEY,
        task_id TEXT,
        exchange_id TEXT,
        req_sha256 TEXT NOT NULL,
        res_sha256 TEXT NOT NULL,
        method TEXT NOT NULL,
        url TEXT NOT NULL,
        status_code INTEGER,
        req_headers_json TEXT NOT NULL DEFAULT '{}',
        res_headers_json TEXT NOT NULL DEFAULT '{}',
        req_body_text TEXT,
        res_body_text TEXT,
        res_encoding TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_evidence_snapshots_exchange ON evidence_snapshots(exchange_id);

      CREATE TABLE IF NOT EXISTS finding_evidence_bindings (
        id TEXT PRIMARY KEY,
        finding_id TEXT NOT NULL,
        snapshot_id TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'proof',
        quote TEXT NOT NULL DEFAULT '',
        note TEXT NOT NULL DEFAULT '',
        evidence_version INTEGER NOT NULL,
        created_at TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_finding_bindings_finding ON finding_evidence_bindings(finding_id);
      CREATE INDEX IF NOT EXISTS idx_finding_bindings_snapshot ON finding_evidence_bindings(snapshot_id);

      CREATE TABLE IF NOT EXISTS finding_evidence_state (
        finding_id TEXT PRIMARY KEY,
        evidence_version INTEGER NOT NULL DEFAULT 0,
        report_evidence_version INTEGER NOT NULL DEFAULT 0,
        verification_status TEXT NOT NULL DEFAULT 'unverified',
        verification_note TEXT NOT NULL DEFAULT '',
        poe_level INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS finding_retests (
        id TEXT PRIMARY KEY,
        finding_id TEXT NOT NULL,
        snapshot_id TEXT,
        verdict TEXT NOT NULL,
        status_code INTEGER,
        matched_quotes_json TEXT NOT NULL DEFAULT '[]',
        notes TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_finding_retests_finding ON finding_retests(finding_id);
    `);
  }

  /**
   * Resolves `<blobDir>/<aa>/<sha256>.bin` after strictly validating `sha256` against `/^[a-f0-9]{64}$/`
   * and confining the path under `this.blobDir`.
   *
   * @param {string} sha256
   * @returns {string}
   */
  _resolveBlobPath(sha256) {
    if (!isValidSha256(sha256)) {
      throw new Error(`Invalid SHA-256 hash: "${sha256}"`);
    }
    if (!this.blobDir) {
      throw new Error('Blob directory is not configured on EvidenceStore');
    }
    const prefix = sha256.slice(0, 2);
    const targetPath = path.resolve(this.blobDir, prefix, `${sha256}.bin`);
    const relative = path.relative(this.blobDir, targetPath);
    if (relative.startsWith('..') || path.isAbsolute(relative)) {
      throw new Error(`Evidence blob path traversal blocked for hash: "${sha256}"`);
    }
    return targetPath;
  }

  _setMemoryBlob(sha256, buf) {
    const existing = this._memoryBlobs.get(sha256);
    if (existing) {
      this._memoryBlobBytes = Math.max(0, this._memoryBlobBytes - existing.byteLength);
      this._memoryBlobs.delete(sha256);
    }
    if (buf.byteLength > this.maxMemoryBlobBytes) {
      // Single blob exceeds total memory budget; store only if single item fits after clearing
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
   * Writes a buffer to `<blobDir>/<aa>/<sha256>.bin` atomically via a `.tmp` file + rename.
   *
   * @param {Buffer|Uint8Array|string} data
   * @returns {string} sha256 hex digest
   */
  writeBlob(data) {
    const buf = toBuffer(data);
    const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
    if (!isValidSha256(sha256)) {
      throw new Error('Computed SHA-256 failed validation');
    }

    if (this.blobDir) {
      const finalPath = this._resolveBlobPath(sha256);
      const dir = path.dirname(finalPath);
      fs.mkdirSync(dir, { recursive: true });
      if (!fs.existsSync(finalPath)) {
        const tmpPath = `${finalPath}.${crypto.randomBytes(6).toString('hex')}.tmp`;
        fs.writeFileSync(tmpPath, buf);
        fs.renameSync(tmpPath, finalPath);
      }
    } else {
      this._setMemoryBlob(sha256, buf);
    }

    return sha256;
  }

  /**
   * Reads a content-addressed blob by SHA-256 hash.
   *
   * @param {string} sha256
   * @returns {Buffer|null}
   */
  readBlob(sha256) {
    if (!isValidSha256(sha256)) {
      throw new Error(`Invalid SHA-256 hash: "${sha256}"`);
    }
    if (this.blobDir) {
      const targetPath = this._resolveBlobPath(sha256);
      if (fs.existsSync(targetPath)) {
        return fs.readFileSync(targetPath);
      }
    }
    const mem = this._memoryBlobs.get(sha256) || null;
    if (mem) {
      // Refresh LRU order
      this._memoryBlobs.delete(sha256);
      this._memoryBlobs.set(sha256, mem);
    }
    return mem;
  }

  /**
   * Alias for `readBlob(sha256)`.
   *
   * @param {string} sha256
   * @returns {Buffer|null}
   */
  getBlob(sha256) {
    return this.readBlob(sha256);
  }

  /**
   * Garbage-collects orphan `.bin` blobs in `blobDir` not referenced by any bound evidence snapshot
   * and older than `graceMs`.
   *
   * @param {object} [options]
   * @param {number} [options.graceMs=86400000] 24 hours default grace period
   * @param {number} [options.now=Date.now()]
   * @returns {{ deletedBlobs: string[], deletedCount: number, keptCount: number }}
   */
  gcOrphanBlobs({ graceMs = 24 * 3600 * 1000, now = Date.now() } = {}) {
    if (!this.blobDir || !fs.existsSync(this.blobDir)) {
      return { deletedBlobs: [], deletedCount: 0, keptCount: 0 };
    }

    // Collect all SHA-256 hashes actively bound to findings
    const boundRows = this.db
      .prepare(
        `SELECT DISTINCT s.req_sha256, s.res_sha256
         FROM evidence_snapshots s
         INNER JOIN finding_evidence_bindings b ON b.snapshot_id = s.id`
      )
      .all();

    const referencedHashes = new Set();
    for (const r of boundRows) {
      if (r.req_sha256) referencedHashes.add(r.req_sha256);
      if (r.res_sha256) referencedHashes.add(r.res_sha256);
    }

    const deletedBlobs = [];
    let keptCount = 0;

    const entries = fs.readdirSync(this.blobDir, { withFileTypes: true });
    for (const sub of entries) {
      if (!sub.isDirectory() || !/^[a-f0-9]{2}$/.test(sub.name)) {
        continue;
      }
      const subDir = path.join(this.blobDir, sub.name);
      const files = fs.readdirSync(subDir, { withFileTypes: true });
      for (const file of files) {
        if (!file.isFile()) continue;
        const fullPath = path.join(subDir, file.name);

        if (file.name.endsWith('.tmp')) {
          const stat = fs.statSync(fullPath);
          if (now - stat.mtimeMs >= graceMs) {
            fs.unlinkSync(fullPath);
          }
          continue;
        }

        if (!file.name.endsWith('.bin')) continue;
        const sha256 = file.name.slice(0, -4);
        if (!isValidSha256(sha256)) continue;

        if (referencedHashes.has(sha256)) {
          keptCount++;
          continue;
        }

        const stat = fs.statSync(fullPath);
        if (now - stat.mtimeMs >= graceMs) {
          fs.unlinkSync(fullPath);
          this._memoryBlobs.delete(sha256);
          deletedBlobs.push(sha256);
        } else {
          keptCount++;
        }
      }
    }

    return {
      deletedBlobs,
      deletedCount: deletedBlobs.length,
      keptCount
    };
  }

  /**
   * Creates an immutable evidence snapshot from a raw HTTP exchange object.
   *
   * @param {object} rawExchange
   * @returns {object}
   */
  createSnapshot(rawExchange = {}) {
    const id = rawExchange.id || rawExchange.snapshotId || crypto.randomUUID();
    const taskId = rawExchange.taskId ?? rawExchange.task_id ?? null;
    const exchangeId = rawExchange.exchangeId ?? rawExchange.exchange_id ?? null;
    const method = String(rawExchange.method || 'GET').toUpperCase();
    const url = String(rawExchange.url || '');
    const statusCode =
      rawExchange.statusCode !== undefined
        ? Number(rawExchange.statusCode)
        : rawExchange.status_code !== undefined
          ? Number(rawExchange.status_code)
          : rawExchange.status !== undefined
            ? Number(rawExchange.status)
            : 0;

    const reqHeaders = normalizeHeaders(
      rawExchange.reqHeaders ??
        rawExchange.requestHeaders ??
        rawExchange.req_headers_json ??
        rawExchange.headers ??
        {}
    );
    const resHeaders = normalizeHeaders(
      rawExchange.resHeaders ??
        rawExchange.responseHeaders ??
        rawExchange.res_headers_json ??
        {}
    );

    const rawEncoding = String(
      rawExchange.resEncoding ??
        rawExchange.res_encoding ??
        getHeaderCaseInsensitive(resHeaders, 'content-encoding') ??
        ''
    ).trim();
    const normEnc = rawEncoding.toLowerCase();
    const hasBinaryResBuffer =
      Buffer.isBuffer(rawExchange.resBodyBuffer) ||
      rawExchange.resBodyBuffer instanceof Uint8Array ||
      Buffer.isBuffer(rawExchange.resBody) ||
      rawExchange.resBody instanceof Uint8Array ||
      Buffer.isBuffer(rawExchange.responseBody) ||
      rawExchange.responseBody instanceof Uint8Array;
    const explicitDecompressed = Boolean(rawExchange.resBodyAlreadyDecompressed);

    const reqBuf = toBuffer(
      rawExchange.reqBodyBuffer ??
        rawExchange.reqBody ??
        rawExchange.req_body_text ??
        rawExchange.requestBody ??
        rawExchange.body ??
        ''
    );
    const resBuf = toBuffer(
      rawExchange.resBodyBuffer ??
        rawExchange.resBody ??
        rawExchange.res_body_text ??
        rawExchange.responseBody ??
        ''
    );

    const reqSha256 = this.writeBlob(reqBuf);
    const resSha256 = this.writeBlob(resBuf);

    const reqBodyText = reqBuf.toString('utf8');
    let effectiveResEncoding = rawEncoding;
    let resBodyText = '';

    const assertWithinMaxBytes = (buf) => {
      if (buf.byteLength > MAX_DECOMPRESS_BYTES) {
        const err = new RangeError(
          `Response body exceeds MAX_DECOMPRESS_BYTES (${MAX_DECOMPRESS_BYTES})`
        );
        err.code = 'ERR_BUFFER_TOO_LARGE';
        throw err;
      }
    };

    if (!normEnc || normEnc === 'identity' || normEnc === 'none') {
      resBodyText = decompressBodyBuffer(resBuf, rawEncoding).toString('utf8');
    } else if (explicitDecompressed || !hasBinaryResBuffer) {
      assertWithinMaxBytes(resBuf);
      effectiveResEncoding = 'identity';
      resBodyText = resBuf.toString('utf8');
    } else if (
      (normEnc === 'gzip' || normEnc === 'x-gzip') &&
      resBuf.byteLength > 0 &&
      !isLikelyGzipBuffer(resBuf)
    ) {
      assertWithinMaxBytes(resBuf);
      effectiveResEncoding = 'identity';
      resBodyText = resBuf.toString('utf8');
    } else {
      try {
        resBodyText = decompressBodyBuffer(resBuf, rawEncoding).toString('utf8');
        effectiveResEncoding = rawEncoding;
      } catch (err) {
        if (err && err.code === 'ERR_BUFFER_TOO_LARGE') {
          throw err;
        }
        assertWithinMaxBytes(resBuf);
        effectiveResEncoding = 'identity';
        resBodyText = resBuf.toString('utf8');
      }
    }

    const reqHeadersJson = JSON.stringify(reqHeaders);
    const resHeadersJson = JSON.stringify(resHeaders);
    const createdAt = rawExchange.createdAt ?? rawExchange.created_at ?? new Date().toISOString();

    this.db
      .prepare(
        `INSERT OR REPLACE INTO evidence_snapshots (
          id, task_id, exchange_id, req_sha256, res_sha256,
          method, url, status_code, req_headers_json, res_headers_json,
          req_body_text, res_body_text, res_encoding, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        id,
        taskId,
        exchangeId,
        reqSha256,
        resSha256,
        method,
        url,
        statusCode,
        reqHeadersJson,
        resHeadersJson,
        reqBodyText,
        resBodyText,
        effectiveResEncoding,
        createdAt
      );

    return this.getSnapshot(id);
  }

  /**
   * Captures an evidence snapshot from an exchange stored in `this.trafficStore`.
   *
   * @param {string} exchangeId
   * @param {object} [options]
   * @param {string} [options.taskId]
   * @returns {object}
   */
  captureSnapshotFromExchange(exchangeId, { taskId } = {}) {
    if (!this.trafficStore) {
      throw new Error('TrafficStore is not configured on EvidenceStore');
    }
    const ex = this.trafficStore.getExchange(exchangeId, { includeBodies: true });
    if (!ex) {
      throw new Error(`Exchange not found in TrafficStore: "${exchangeId}"`);
    }

    return this.createSnapshot({
      taskId: taskId ?? ex.taskId,
      exchangeId: ex.id,
      method: ex.method,
      url: ex.url,
      statusCode: ex.statusCode,
      reqHeaders: ex.reqHeaders,
      resHeaders: ex.resHeaders,
      reqBodyBuffer: ex.reqBodyBuffer,
      resBodyBuffer: ex.resBodyBuffer,
      resEncoding: ex.resEncoding
    });
  }

  /**
   * Retrieves a snapshot by ID, including raw blob buffers if available.
   *
   * @param {string} snapshotId
   * @returns {object|null}
   */
  getSnapshot(snapshotId) {
    const row = this.db
      .prepare('SELECT * FROM evidence_snapshots WHERE id = ?')
      .get(snapshotId);
    if (!row) return null;

    const reqHeaders = normalizeHeaders(row.req_headers_json);
    const resHeaders = normalizeHeaders(row.res_headers_json);
    const reqBodyBuffer = isValidSha256(row.req_sha256) ? this.readBlob(row.req_sha256) : null;
    const resBodyBuffer = isValidSha256(row.res_sha256) ? this.readBlob(row.res_sha256) : null;

    return {
      id: row.id,
      taskId: row.task_id,
      task_id: row.task_id,
      exchangeId: row.exchange_id,
      exchange_id: row.exchange_id,
      reqSha256: row.req_sha256,
      req_sha256: row.req_sha256,
      resSha256: row.res_sha256,
      res_sha256: row.res_sha256,
      method: row.method,
      url: row.url,
      statusCode: row.status_code,
      status_code: row.status_code,
      reqHeaders,
      resHeaders,
      req_headers_json: row.req_headers_json,
      res_headers_json: row.res_headers_json,
      reqBodyText: row.req_body_text,
      req_body_text: row.req_body_text,
      reqBody: row.req_body_text,
      resBodyText: row.res_body_text,
      res_body_text: row.res_body_text,
      resBody: row.res_body_text,
      reqBodyBuffer,
      resBodyBuffer,
      resEncoding: row.res_encoding,
      res_encoding: row.res_encoding,
      createdAt: row.created_at,
      created_at: row.created_at
    };
  }

  /**
   * Binds an evidence snapshot to a finding and increments `evidence_version`
   * (flagging `reportStale: evidence_version > report_evidence_version`).
   *
   * @param {object} params
   * @param {string} params.findingId
   * @param {string} params.snapshotId
   * @param {'baseline'|'proof'|'verification'|'supporting'} [params.role='proof']
   * @param {string} [params.quote='']
   * @param {string} [params.note='']
   * @returns {object}
   */
  bindEvidence({ findingId, snapshotId, role = 'proof', quote = '', note = '' } = {}) {
    if (!findingId) {
      throw new Error('findingId is required to bind evidence');
    }
    if (!snapshotId) {
      throw new Error('snapshotId is required to bind evidence');
    }
    const normRole = String(role || 'proof').toLowerCase();
    if (!VALID_BINDING_ROLES.has(normRole)) {
      throw new Error(
        `Invalid evidence binding role "${role}"; expected baseline, proof, verification, or supporting`
      );
    }

    const now = new Date().toISOString();
    const existingState = this.db
      .prepare('SELECT * FROM finding_evidence_state WHERE finding_id = ?')
      .get(findingId);

    let nextVersion = 1;
    let reportVersion = 0;

    if (!existingState) {
      this.db
        .prepare(
          `INSERT INTO finding_evidence_state (
            finding_id, evidence_version, report_evidence_version,
            verification_status, verification_note, poe_level, updated_at
          ) VALUES (?, 1, 0, 'unverified', '', 0, ?)`
        )
        .run(findingId, now);
    } else {
      nextVersion = Number(existingState.evidence_version) + 1;
      reportVersion = Number(existingState.report_evidence_version);
      this.db
        .prepare(
          `UPDATE finding_evidence_state
           SET evidence_version = ?, updated_at = ?
           WHERE finding_id = ?`
        )
        .run(nextVersion, now, findingId);
    }

    const id = crypto.randomUUID();
    this.db
      .prepare(
        `INSERT INTO finding_evidence_bindings (
          id, finding_id, snapshot_id, role, quote, note, evidence_version, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(id, findingId, snapshotId, normRole, String(quote || ''), String(note || ''), nextVersion, now);

    const reportStale = nextVersion > reportVersion;

    return {
      id,
      findingId,
      finding_id: findingId,
      snapshotId,
      snapshot_id: snapshotId,
      role: normRole,
      quote: String(quote || ''),
      note: String(note || ''),
      evidenceVersion: nextVersion,
      evidence_version: nextVersion,
      reportEvidenceVersion: reportVersion,
      report_evidence_version: reportVersion,
      reportStale,
      createdAt: now,
      created_at: now
    };
  }

  /**
   * Synchronizes `report_evidence_version = evidence_version` after the finding's report is regenerated.
   *
   * @param {string} findingId
   * @returns {object}
   */
  markReportSynchronized(findingId) {
    const now = new Date().toISOString();
    const state = this.db
      .prepare('SELECT * FROM finding_evidence_state WHERE finding_id = ?')
      .get(findingId);

    if (!state) {
      this.db
        .prepare(
          `INSERT INTO finding_evidence_state (
            finding_id, evidence_version, report_evidence_version,
            verification_status, verification_note, poe_level, updated_at
          ) VALUES (?, 0, 0, 'unverified', '', 0, ?)`
        )
        .run(findingId, now);
    } else {
      this.db
        .prepare(
          `UPDATE finding_evidence_state
           SET report_evidence_version = evidence_version, updated_at = ?
           WHERE finding_id = ?`
        )
        .run(now, findingId);
    }

    return this.getFindingEvidence(findingId);
  }

  /**
   * Runs `assessFindingVerification` against the finding's bound snapshots, persists
   * `verification_status` and `verification_note`, and returns the assessment.
   *
   * @param {string} findingId
   * @param {object} [options]
   * @param {number} [options.poeLevel=3]
   * @param {string[]} [options.evidenceQuotes=[]]
   * @returns {object}
   */
  verifyFindingReceipts(findingId, { poeLevel = 3, evidenceQuotes = [] } = {}) {
    const { bindings } = this.getFindingEvidence(findingId);

    const boundSnapshots = bindings
      .map(b => {
        const snap = this.getSnapshot(b.snapshotId);
        if (!snap) return null;
        return {
          ...snap,
          role: b.role,
          quote: b.quote
        };
      })
      .filter(Boolean);

    const quotesToVerify =
      Array.isArray(evidenceQuotes) && evidenceQuotes.length > 0
        ? evidenceQuotes
        : bindings.map(b => b.quote).filter(Boolean);

    const assessment = assessFindingVerification(
      {
        id: findingId,
        poeLevel,
        evidenceQuotes: quotesToVerify
      },
      boundSnapshots
    );

    const now = new Date().toISOString();
    const existing = this.db
      .prepare('SELECT * FROM finding_evidence_state WHERE finding_id = ?')
      .get(findingId);

    if (!existing) {
      this.db
        .prepare(
          `INSERT INTO finding_evidence_state (
            finding_id, evidence_version, report_evidence_version,
            verification_status, verification_note, poe_level, updated_at
          ) VALUES (?, 0, 0, ?, ?, ?, ?)`
        )
        .run(findingId, assessment.status, assessment.reason, Number(poeLevel), now);
    } else {
      this.db
        .prepare(
          `UPDATE finding_evidence_state
           SET verification_status = ?, verification_note = ?, poe_level = ?, updated_at = ?
           WHERE finding_id = ?`
        )
        .run(assessment.status, assessment.reason, Number(poeLevel), now, findingId);
    }

    return assessment;
  }

  /**
   * Retrieves the complete evidence state, staleness flag, bindings, snapshots, and retest history for a finding.
   *
   * @param {string} findingId
   * @returns {{
   *   state: object,
   *   reportStale: boolean,
   *   bindings: Array<object>,
   *   snapshots: Array<object>,
   *   retests: Array<object>
   * }}
   */
  getFindingEvidence(findingId) {
    const stateRow = this.db
      .prepare('SELECT * FROM finding_evidence_state WHERE finding_id = ?')
      .get(findingId);

    const evidenceVersion = Number(stateRow?.evidence_version ?? 0);
    const reportEvidenceVersion = Number(stateRow?.report_evidence_version ?? 0);
    const reportStale = evidenceVersion > reportEvidenceVersion;

    const state = {
      findingId,
      finding_id: findingId,
      evidenceVersion,
      evidence_version: evidenceVersion,
      reportEvidenceVersion,
      report_evidence_version: reportEvidenceVersion,
      verificationStatus: stateRow?.verification_status || 'unverified',
      verification_status: stateRow?.verification_status || 'unverified',
      verificationNote: stateRow?.verification_note || '',
      verification_note: stateRow?.verification_note || '',
      poeLevel: Number(stateRow?.poe_level ?? 0),
      poe_level: Number(stateRow?.poe_level ?? 0),
      reportStale,
      updatedAt: stateRow?.updated_at || null,
      updated_at: stateRow?.updated_at || null
    };

    const bindingRows = this.db
      .prepare(
        'SELECT * FROM finding_evidence_bindings WHERE finding_id = ? ORDER BY created_at ASC, rowid ASC'
      )
      .all(findingId);

    const bindings = [];
    const snapshotsMap = new Map();

    for (const b of bindingRows) {
      let snap = snapshotsMap.get(b.snapshot_id);
      if (!snap) {
        snap = this.getSnapshot(b.snapshot_id);
        if (snap) snapshotsMap.set(b.snapshot_id, snap);
      }
      bindings.push({
        id: b.id,
        findingId: b.finding_id,
        finding_id: b.finding_id,
        snapshotId: b.snapshot_id,
        snapshot_id: b.snapshot_id,
        role: b.role,
        quote: b.quote,
        note: b.note,
        evidenceVersion: Number(b.evidence_version),
        evidence_version: Number(b.evidence_version),
        createdAt: b.created_at,
        created_at: b.created_at,
        snapshot: snap || null
      });
    }

    const retestRows = this.db
      .prepare(
        'SELECT * FROM finding_retests WHERE finding_id = ? ORDER BY created_at ASC, rowid ASC'
      )
      .all(findingId);

    const retests = retestRows.map(r => {
      let matchedQuotes = [];
      try {
        matchedQuotes = JSON.parse(r.matched_quotes_json || '[]');
      } catch {
        matchedQuotes = [];
      }
      return {
        id: r.id,
        findingId: r.finding_id,
        finding_id: r.finding_id,
        snapshotId: r.snapshot_id,
        snapshot_id: r.snapshot_id,
        verdict: r.verdict,
        statusCode: r.status_code,
        status_code: r.status_code,
        matchedQuotes,
        matched_quotes_json: r.matched_quotes_json,
        notes: r.notes,
        createdAt: r.created_at,
        created_at: r.created_at
      };
    });

    return {
      state,
      reportStale,
      bindings,
      snapshots: Array.from(snapshotsMap.values()),
      retests
    };
  }

  /**
   * Replays the bound `proof` snapshot via `trafficStore.replayRequest` (or direct validated fetch),
   * validating target URLs via `validateUrl` (defaulting to `resolveAndValidateTarget` with DNS/pinning),
   * enforcing `redirect: 'manual'` (and re-validating hops up to `maxRedirects` if `followRedirects` is enabled),
   * checks whether original `evidenceQuotes` still match in the new response, records a `finding_retests`
   * row (`reproduced` | `fixed` | `inconclusive`), binds the new snapshot as `role: 'verification'`,
   * and returns the retest result.
   *
   * @param {string} findingId
   * @param {object} [options]
   * @returns {Promise<object>}
   */
  async retestFinding(
    findingId,
    {
      fetcher = globalThis.fetch,
      validateUrl = resolveAndValidateTarget,
      dnsResolver = null,
      resolver = null,
      targetPinStore = null,
      guard = null,
      evidenceQuotes = null,
      allowPrivate = false,
      followRedirects = false,
      maxRedirects = 5,
      timeout = 15000,
      timeoutMs = undefined
    } = {}
  ) {
    const { bindings } = this.getFindingEvidence(findingId);
    const proofBindings = bindings.filter(b => b.role === 'proof' && b.snapshot);
    const targetBinding =
      proofBindings[proofBindings.length - 1] ||
      bindings.find(b => PROOF_ROLES.has(b.role) && b.snapshot);

    if (!targetBinding || !targetBinding.snapshot) {
      throw new Error(`No bound proof snapshot found for finding: "${findingId}"`);
    }

    const proofSnap = targetBinding.snapshot;
    const quotesToCheck =
      Array.isArray(evidenceQuotes) && evidenceQuotes.length > 0
        ? evidenceQuotes
        : bindings
            .filter(b => PROOF_ROLES.has(b.role) && b.quote)
            .map(b => b.quote);

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
      const validatorPrefix = isRedirect ? 'Retest redirect blocked by URL validator' : 'Retest blocked by URL validator';
      const guardPrefix = isRedirect ? 'Retest redirect blocked by guard' : 'Retest blocked by guard';

      if (validateUrl === resolveAndValidateTarget) {
        const preCheck = validateTargetUrl(targetUrl, { allowPrivate: allowPrivateFlag });
        if (!preCheck.valid) {
          throw new Error(`${validatorPrefix}: ${preCheck.error || targetUrl}`);
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
          throw new Error(
            `${validatorPrefix}: ${validation?.error || validation?.reason || targetUrl}`
          );
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

    let newSnapshot = null;
    let statusCode = 0;
    let networkError = null;

    const effectiveTimeoutMs = Number.isFinite(Number(timeoutMs ?? timeout)) && Number(timeoutMs ?? timeout) > 0
      ? Number(timeoutMs ?? timeout)
      : 15000;

    try {
      if (this.trafficStore && proofSnap.exchangeId && this.trafficStore.getExchange(proofSnap.exchangeId)) {
        const { replayExchange } = await this.trafficStore.replayRequest(
          proofSnap.exchangeId,
          {},
          {
            fetcher,
            validateUrl,
            dnsResolver: activeDnsResolver,
            targetPinStore: activePinStore,
            guard,
            allowPrivate: allowPrivateFlag,
            followRedirects,
            maxRedirects,
            timeout: effectiveTimeoutMs
          }
        );
        statusCode = replayExchange.statusCode;
        newSnapshot = this.captureSnapshotFromExchange(replayExchange.id, {
          taskId: proofSnap.taskId
        });
      } else {
        // Direct validated fetch when exchange is not in trafficStore
        await checkTarget(proofSnap.url, { isRedirect: false });

        const cleanedHeaders = stripHopByHopHeaders(proofSnap.reqHeaders || {});
        const hasBody =
          proofSnap.reqBody &&
          proofSnap.method !== 'GET' &&
          proofSnap.method !== 'HEAD';

        const parsedMaxRedirects = Number(maxRedirects);
        const hopLimit = Number.isFinite(parsedMaxRedirects)
          ? Math.max(0, Math.min(Math.trunc(parsedMaxRedirects), 5))
          : 5;
        let currentUrl = proofSnap.url;
        let hops = 0;
        let res = null;
        let resHeaders = {};

        while (true) {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(new Error(`Retest request timed out after ${effectiveTimeoutMs}ms`)), effectiveTimeoutMs);
          try {
            res = await fetcher(currentUrl, {
              method: proofSnap.method,
              headers: cleanedHeaders,
              body: hasBody ? proofSnap.reqBody : undefined,
              redirect: 'manual',
              signal: controller.signal
            });
          } finally {
            clearTimeout(timer);
          }

          statusCode = Number(res.status ?? res.statusCode ?? 200);
          resHeaders = normalizeHeaders(res.headers || {});
          const location = getHeaderCaseInsensitive(resHeaders, 'location');
          const isRedirect = statusCode >= 300 && statusCode < 400;

          if (followRedirects && isRedirect && location) {
            if (hops >= hopLimit) {
              throw new Error(`Retest blocked by URL validator: Maximum redirect limit (${hopLimit}) exceeded`);
            }
            let nextUrl;
            try {
              nextUrl = new URL(location, currentUrl).href;
            } catch {
              throw new Error(`Retest redirect blocked by URL validator: Invalid redirect URL "${location}"`);
            }
            await checkTarget(nextUrl, { isRedirect: true });
            currentUrl = nextUrl;
            hops += 1;
            continue;
          }

          break;
        }

        let resBodyBuf = Buffer.alloc(0);
        let resBodyAlreadyDecompressed = false;
        if (typeof res.arrayBuffer === 'function') {
          resBodyBuf = Buffer.from(await res.arrayBuffer());
        } else if (typeof res.text === 'function') {
          resBodyBuf = Buffer.from(await res.text(), 'utf8');
          resBodyAlreadyDecompressed = true;
        } else if (Buffer.isBuffer(res.body) || typeof res.body === 'string') {
          resBodyBuf = toBuffer(res.body);
          if (typeof res.body === 'string') resBodyAlreadyDecompressed = true;
        } else if (typeof res.text === 'string') {
          resBodyBuf = Buffer.from(res.text, 'utf8');
          resBodyAlreadyDecompressed = true;
        }

        newSnapshot = this.createSnapshot({
          taskId: proofSnap.taskId,
          method: proofSnap.method,
          url: currentUrl,
          statusCode,
          reqHeaders: cleanedHeaders,
          resHeaders,
          reqBodyBuffer: proofSnap.reqBodyBuffer || toBuffer(proofSnap.reqBody),
          resBodyBuffer: resBodyBuf,
          resBodyAlreadyDecompressed
        });
      }
    } catch (err) {
      if (
        err.message.includes('blocked by URL validator') ||
        err.message.includes('blocked by guard')
      ) {
        throw err;
      }
      networkError = err;
    }

    let verdict = 'inconclusive';
    const matchedQuotes = [];
    let notes = '';

    if (networkError || !newSnapshot) {
      verdict = 'inconclusive';
      notes = `Network or transport error during retest: ${networkError?.message || 'unknown error'}`;
    } else {
      const firstMatchQuote = quotesToCheck[0] || '';
      this.bindEvidence({
        findingId,
        snapshotId: newSnapshot.id,
        role: 'verification',
        quote: firstMatchQuote,
        note: 'Retest verification snapshot'
      });

      let corpus = '';
      let corpusErr = null;
      try {
        corpus = buildNormalizedSnapshotCorpus(newSnapshot);
      } catch (err) {
        corpusErr = err;
      }

      const validQuotes = quotesToCheck.filter(
        q => normalizeEvidenceWhitespace(q).length >= MIN_EVIDENCE_QUOTE_LEN
      );

      if (corpusErr) {
        verdict = 'inconclusive';
        notes = `Failed to read or decompress retest snapshot body: ${corpusErr?.message || corpusErr}`;
      } else if (validQuotes.length === 0) {
        verdict = 'inconclusive';
        notes = 'No valid evidence quotes (>= 8 chars) available to verify fix';
      } else {
        for (const q of validQuotes) {
          const normQ = normalizeEvidenceWhitespace(q);
          if (corpus.includes(normQ)) {
            matchedQuotes.push(q);
          }
        }

        if (statusCode >= 500 || statusCode < 200) {
          if (matchedQuotes.length === validQuotes.length) {
            verdict = 'reproduced';
            notes = `Finding reproduced on HTTP ${statusCode} (${matchedQuotes.length}/${validQuotes.length} quotes matched)`;
          } else {
            verdict = 'inconclusive';
            notes = `Target returned HTTP ${statusCode} without matching proof quotes`;
          }
        } else if (matchedQuotes.length === validQuotes.length) {
          verdict = 'reproduced';
          notes = `Finding reproduced on HTTP ${statusCode} (${matchedQuotes.length}/${validQuotes.length} quotes matched)`;
        } else if (statusCode >= 200 && statusCode < 500) {
          verdict = 'fixed';
          notes = `Target responded HTTP ${statusCode} and proof quotes are no longer present`;
        } else {
          verdict = 'inconclusive';
          notes = `Inconclusive response status ${statusCode}`;
        }
      }
    }

    if (!VALID_RETEST_VERDICTS.has(verdict)) {
      verdict = 'inconclusive';
    }

    const retestId = crypto.randomUUID();
    const createdAt = new Date().toISOString();
    const matchedQuotesJson = JSON.stringify(matchedQuotes);

    this.db
      .prepare(
        `INSERT INTO finding_retests (
          id, finding_id, snapshot_id, verdict, status_code, matched_quotes_json, notes, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        retestId,
        findingId,
        newSnapshot ? newSnapshot.id : null,
        verdict,
        statusCode,
        matchedQuotesJson,
        notes,
        createdAt
      );

    if (verdict === 'reproduced' || verdict === 'fixed') {
      this.db
        .prepare(
          `UPDATE finding_evidence_state
           SET verification_status = 'verified', verification_note = ?, updated_at = ?
           WHERE finding_id = ?`
        )
        .run(`retest #${retestId}: ${verdict} — ${notes}`, createdAt, findingId);
    }

    return {
      id: retestId,
      findingId,
      finding_id: findingId,
      snapshotId: newSnapshot ? newSnapshot.id : null,
      snapshot_id: newSnapshot ? newSnapshot.id : null,
      verdict,
      statusCode,
      status_code: statusCode,
      matchedQuotes,
      notes,
      createdAt,
      created_at: createdAt
    };
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
