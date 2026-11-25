import crypto from 'node:crypto';
import http from 'node:http';

const MAX_CALLBACK_BODY_BYTES = 8192;
const MAX_SOCKET_DRAIN_BYTES = 65536;
const DEFAULT_MAX_INTERACTIONS = 500;
const DEFAULT_WAIT_TIMEOUT_MS = 800;
const OAST_PATH_RE = /^\/oast\/([^/]+)\/([^/]+)(?:\/.*)?$/;

function sanitizeControl(str, maxLen = 256) {
  return String(str ?? '')
    .replace(/[\x00-\x1F\x7F]+/g, ' ')
    .replace(/\s{2,}/g, ' ')
    .trim()
    .slice(0, maxLen);
}

function sanitizeHeaders(rawHeaders = {}) {
  const out = {};
  if (!rawHeaders || typeof rawHeaders !== 'object') return out;
  const entries = Object.entries(rawHeaders).slice(0, 40);
  for (const [rawKey, rawVal] of entries) {
    const key = sanitizeControl(rawKey, 80).toLowerCase();
    if (!key) continue;
    const valStr = Array.isArray(rawVal) ? rawVal.join(', ') : String(rawVal ?? '');
    out[key] = sanitizeControl(valStr, 512);
  }
  return out;
}

function formatHostForUrl(host) {
  const clean = String(host || '127.0.0.1').trim();
  if (clean.includes(':') && !clean.startsWith('[')) {
    return `[${clean}]`;
  }
  return clean;
}

/**
 * Cryptographic HMAC-Tokenized Out-of-Band Application Security Testing (OAST)
 * Blind Callback Receiver for SSRF & Blind XXE verification.
 */
export class OastServer {
  /**
   * @param {object} [options={}]
   * @param {string} [options.host='127.0.0.1']
   * @param {number} [options.port=0]
   * @param {Buffer|Uint8Array|string} [options.secret]
   * @param {number} [options.maxInteractions=500]
   */
  constructor(options = {}) {
    this.host = typeof options.host === 'string' && options.host.trim()
      ? options.host.trim()
      : '127.0.0.1';
    const rawPort = Number(options.port ?? 0);
    this.port = Number.isInteger(rawPort) && rawPort >= 0 && rawPort <= 65535 ? rawPort : 0;

    if (Buffer.isBuffer(options.secret) && options.secret.length > 0) {
      this.secret = Buffer.from(options.secret);
    } else if (options.secret instanceof Uint8Array && options.secret.byteLength > 0) {
      this.secret = Buffer.from(options.secret.buffer, options.secret.byteOffset, options.secret.byteLength);
    } else if (typeof options.secret === 'string' && options.secret.length > 0) {
      this.secret = Buffer.from(options.secret, 'utf8');
    } else {
      this.secret = crypto.randomBytes(32);
    }

    const maxInt = Number(options.maxInteractions ?? DEFAULT_MAX_INTERACTIONS);
    this.maxInteractions = Number.isInteger(maxInt) && maxInt > 0
      ? Math.min(maxInt, 10000)
      : DEFAULT_MAX_INTERACTIONS;
    this.maxInteractionsPerToken = Math.min(
      Number.isFinite(Number(options.maxInteractionsPerToken)) && Number(options.maxInteractionsPerToken) > 0
        ? Math.floor(Number(options.maxInteractionsPerToken))
        : 10,
      50
    );
    this.tokenTtlMs = Number.isFinite(Number(options.tokenTtlMs)) && Number(options.tokenTtlMs) > 0
      ? Number(options.tokenTtlMs)
      : 300_000;
    this.maxTokens = Math.max(this.maxInteractions * 2, 1000);

    this.running = false;
    this.server = null;
    this.actualPort = null;
    this.baseUrl = null;
    this.tokens = new Map();
    this.interactions = [];
    this.waiters = new Map();
    this._verifiedCount = 0;
  }

  /**
   * Starts the local OAST callback HTTP server bound to `this.host:this.port`.
   *
   * @returns {Promise<{ running: boolean, baseUrl: string, host: string, port: number, issuedTokensCount: number, verifiedInteractionsCount: number }>}
   */
  async start() {
    if (this.running && this.server) {
      return this.getStatus();
    }

    const server = http.createServer((req, res) => {
      this._handleRequest(req, res);
    });

    await new Promise((resolve, reject) => {
      const onError = err => {
        server.removeListener('listening', onListening);
        reject(err);
      };
      const onListening = () => {
        server.removeListener('error', onError);
        resolve();
      };
      server.once('error', onError);
      server.once('listening', onListening);
      server.listen(this.port, this.host);
    });

    const address = server.address();
    this.server = server;
    this.actualPort = typeof address === 'object' && address ? address.port : this.port;
    this.running = true;
    this.baseUrl = `http://${formatHostForUrl(this.host)}:${this.actualPort}`;
    return this.getStatus();
  }

  /**
   * Stops the OAST server, closes active sockets, and cancels pending waiters.
   *
   * @returns {Promise<void>}
   */
  async stop() {
    this.running = false;

    for (const [, waiterSet] of this.waiters.entries()) {
      for (const waiter of waiterSet) {
        clearTimeout(waiter.timer);
        waiter.resolve(null);
      }
    }
    this.waiters.clear();

    if (this.server) {
      const srv = this.server;
      this.server = null;
      this.baseUrl = null;
      this.actualPort = null;
      try {
        srv.closeAllConnections?.();
      } catch {}
      await new Promise(resolve => {
        srv.close(() => resolve());
      });
    }
  }

  _deleteTokenRecord(tokenId) {
    this.tokens.delete(tokenId);
    if (this.interactions.length > 0) {
      this.interactions = this.interactions.filter(item => item.tokenId !== tokenId);
    }
  }

  _pruneExpiredTokens(now = Date.now()) {
    for (const [tid, rec] of this.tokens.entries()) {
      if (now - rec.createdAt > this.tokenTtlMs) {
        this._deleteTokenRecord(tid);
      }
    }
  }

  /**
   * Issues a cryptographically signed HMAC probe token and callback URL.
   *
   * @param {{ checkId?: string, target?: string, parameter?: string }} [params={}]
   * @returns {{ tokenId: string, hmacSig: string, callbackPath: string, callbackUrl: string }}
   */
  issueProbe({ checkId = 'unknown', target = '', parameter = '' } = {}) {
    const now = Date.now();
    this._pruneExpiredTokens(now);

    const tokenId = crypto.randomBytes(12).toString('hex');
    const normCheckId = String(checkId ?? 'unknown');
    const normTarget = String(target ?? '');
    const normParam = String(parameter ?? '');

    const hmacSig = crypto
      .createHmac('sha256', this.secret)
      .update(`${tokenId}:${normCheckId}:${normTarget}`)
      .digest('hex')
      .slice(0, 20);

    while (this.tokens.size >= this.maxTokens) {
      const oldestKey = this.tokens.keys().next().value;
      if (oldestKey === undefined) break;
      this._deleteTokenRecord(oldestKey);
    }

    this.tokens.set(tokenId, {
      tokenId,
      hmacSig,
      checkId: normCheckId,
      target: normTarget,
      parameter: normParam,
      createdAt: now,
      interactions: []
    });

    const callbackPath = `/oast/${tokenId}/${hmacSig}`;
    return {
      tokenId,
      hmacSig,
      callbackPath,
      callbackUrl: this.baseUrl ? `${this.baseUrl}${callbackPath}` : callbackPath
    };
  }

  /**
   * Constant-time verification of a callback `(tokenId, suppliedSig)` pair.
   *
   * @param {string} tokenId
   * @param {string} suppliedSig
   * @returns {boolean}
   */
  verifyToken(tokenId, suppliedSig) {
    if (typeof tokenId !== 'string' || !tokenId || typeof suppliedSig !== 'string') {
      return false;
    }
    const record = this.tokens.get(tokenId);
    if (!record) return false;
    if (Date.now() - record.createdAt > this.tokenTtlMs) {
      this._deleteTokenRecord(tokenId);
      return false;
    }

    const suppliedBuf = Buffer.from(suppliedSig, 'utf8');
    const expectedBuf = Buffer.from(record.hmacSig, 'utf8');
    if (suppliedBuf.length !== expectedBuf.length) {
      return false;
    }

    return crypto.timingSafeEqual(suppliedBuf, expectedBuf);
  }

  _sendResponse(res, statusCode, contentType, bodyText) {
    if (res.writableEnded || res.destroyed) return;
    const buf = Buffer.from(String(bodyText), 'utf8');
    res.writeHead(statusCode, {
      'Content-Type': contentType,
      'Content-Length': buf.length,
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'no-store'
    });
    res.end(buf);
  }

  _handleRequest(req, res) {
    const rawUrl = String(req.url || '/').slice(0, 2048);
    let pathname = '/';
    try {
      pathname = new URL(rawUrl, 'http://127.0.0.1').pathname;
    } catch {
      pathname = rawUrl.split('?')[0] || '/';
    }

    const match = OAST_PATH_RE.exec(pathname);
    const tokenId = match ? match[1] : '';
    const suppliedSig = match ? match[2] : '';

    const chunks = [];
    let bufferedBytes = 0;
    let totalReceived = 0;
    let settled = false;

    const finalize = () => {
      if (settled) return;
      settled = true;

      if (!match || !this.verifyToken(tokenId, suppliedSig)) {
        this._sendResponse(res, 403, 'application/json; charset=utf-8', '{"verified":false}');
        return;
      }

      const record = this.tokens.get(tokenId);
      if (!record) {
        this._sendResponse(res, 403, 'application/json; charset=utf-8', '{"verified":false}');
        return;
      }

      const rawBody = Buffer.concat(chunks).toString('utf8');
      const interaction = {
        id: `oast_${crypto.randomBytes(8).toString('hex')}`,
        tokenId: record.tokenId,
        hmacSig: record.hmacSig,
        method: sanitizeControl(req.method || 'GET', 16).toUpperCase(),
        path: sanitizeControl(pathname, 256),
        remoteAddress: sanitizeControl(req.socket?.remoteAddress || '', 64),
        userAgent: sanitizeControl(req.headers?.['user-agent'] || '', 256),
        headers: sanitizeHeaders(req.headers),
        bodyPreview: sanitizeControl(rawBody, MAX_CALLBACK_BODY_BYTES),
        timestamp: Date.now(),
        verified: true
      };

      while (record.interactions.length >= this.maxInteractionsPerToken) {
        const evictedPerToken = record.interactions.shift();
        if (evictedPerToken) {
          const gIdx = this.interactions.indexOf(evictedPerToken);
          if (gIdx !== -1) this.interactions.splice(gIdx, 1);
        }
      }
      while (this.interactions.length >= this.maxInteractions) {
        const evictedGlobal = this.interactions.shift();
        if (evictedGlobal) {
          const owner = this.tokens.get(evictedGlobal.tokenId);
          if (owner) {
            const oIdx = owner.interactions.indexOf(evictedGlobal);
            if (oIdx !== -1) owner.interactions.splice(oIdx, 1);
          }
        }
      }
      record.interactions.push(interaction);
      this.interactions.push(interaction);
      this._verifiedCount++;

      const waiterSet = this.waiters.get(record.tokenId);
      if (waiterSet && waiterSet.size > 0) {
        this.waiters.delete(record.tokenId);
        for (const waiter of waiterSet) {
          clearTimeout(waiter.timer);
          waiter.resolve(interaction);
        }
      }

      this._sendResponse(res, 200, 'text/plain; charset=utf-8', `oast_ack_${record.tokenId}`);
    };

    req.setTimeout(2000, () => {
      try {
        req.destroy();
      } catch {}
      finalize();
    });

    req.on('data', chunk => {
      totalReceived += chunk.length;
      if (bufferedBytes < MAX_CALLBACK_BODY_BYTES) {
        const remaining = MAX_CALLBACK_BODY_BYTES - bufferedBytes;
        const slice = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;
        chunks.push(slice);
        bufferedBytes += slice.length;
      }
      if (totalReceived > MAX_SOCKET_DRAIN_BYTES) {
        try {
          req.destroy();
        } catch {}
        finalize();
      }
    });

    req.once('end', finalize);
    req.once('error', () => {
      if (!settled && !res.writableEnded && !res.destroyed) {
        settled = true;
        this._sendResponse(res, 403, 'application/json; charset=utf-8', '{"verified":false}');
      }
    });
  }

  /**
   * Returns verified callback interactions for a specific `tokenId` or all tokens.
   *
   * @param {string|null} [tokenId=null]
   * @returns {Array<object>}
   */
  getInteractions(tokenId = null) {
    if (tokenId !== null && tokenId !== undefined) {
      const record = this.tokens.get(String(tokenId));
      return record ? record.interactions.slice() : [];
    }
    return this.interactions.slice();
  }

  /**
   * Waits for the first verified interaction matching `tokenId` up to `timeoutMs`.
   *
   * @param {string} tokenId
   * @param {number} [timeoutMs=800]
   * @returns {Promise<object|null>}
   */
  async waitForInteraction(tokenId, timeoutMs = DEFAULT_WAIT_TIMEOUT_MS) {
    const key = String(tokenId || '');
    const record = this.tokens.get(key);
    if (!record) return null;
    if (record.interactions.length > 0) {
      return record.interactions[0];
    }
    if (!this.running) return null;

    const rawTimeout = Number(timeoutMs);
    const boundedMs = Number.isFinite(rawTimeout)
      ? Math.max(1, Math.min(rawTimeout, 30000))
      : DEFAULT_WAIT_TIMEOUT_MS;

    return new Promise(resolve => {
      const waiterSet = this.waiters.get(key) || new Set();
      this.waiters.set(key, waiterSet);

      const waiter = {
        resolve,
        timer: null
      };

      waiter.timer = setTimeout(() => {
        const set = this.waiters.get(key);
        if (set) {
          set.delete(waiter);
          if (set.size === 0) this.waiters.delete(key);
        }
        resolve(null);
      }, boundedMs);

      waiterSet.add(waiter);
    });
  }

  /**
   * Returns current OAST server status and metrics.
   *
   * @returns {{ running: boolean, baseUrl: string|null, host: string, port: number, issuedTokensCount: number, verifiedInteractionsCount: number }}
   */
  getStatus() {
    return {
      running: this.running,
      baseUrl: this.baseUrl,
      host: this.host,
      port: this.actualPort ?? this.port,
      issuedTokensCount: this.tokens.size,
      verifiedInteractionsCount: this._verifiedCount
    };
  }
}

/**
 * Starts an ephemeral `OastServer`, invokes `fn(oastServer)`, and guarantees shutdown in `finally`.
 *
 * @param {object|Function} options
 * @param {Function} [fn]
 * @returns {Promise<any>}
 */
export async function withOastServer(options = {}, fn) {
  let opts = options;
  let callback = fn;
  if (typeof options === 'function') {
    callback = options;
    opts = {};
  }
  const server = new OastServer(opts || {});
  await server.start();
  try {
    return await callback(server);
  } finally {
    await server.stop();
  }
}
