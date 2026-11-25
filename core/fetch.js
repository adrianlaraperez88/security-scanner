import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import net from 'node:net';
import zlib from 'node:zlib';
import {
  validateTargetUrl,
  resolveAndValidateTarget,
  canonicalizeResolvedIps,
  canonicalizeIpAddress
} from './validator.js';
import { evaluateAssetGate, TargetPinStore } from './guard.js';

const NATIVE_GLOBAL_FETCH = globalThis.fetch;

/**
 * Evaluates a target URL or resolved IP object against the configured guard or scope rules.
 */
export function runAssetGateCheck(inputTarget, { guard = null, scopeRules = null, alwaysBuiltin = false } = {}) {
  if (!guard && !scopeRules) {
    return alwaysBuiltin
      ? evaluateAssetGate(inputTarget, { rules: [], includeBuiltinDeny: true })
      : { allowed: true };
  }
  if (typeof guard === 'function') {
    return guard(inputTarget);
  }
  if (guard && typeof guard.evaluateAssetGate === 'function') {
    return guard.evaluateAssetGate(inputTarget);
  }
  if (guard && typeof guard.evaluate === 'function') {
    return guard.evaluate(inputTarget);
  }
  const rules = Array.isArray(guard)
    ? guard
    : Array.isArray(guard?.rules)
      ? guard.rules
      : Array.isArray(scopeRules)
        ? scopeRules
        : [];
  const includeBuiltinDeny = guard?.includeBuiltinDeny ?? true;
  return evaluateAssetGate(inputTarget, { rules, includeBuiltinDeny });
}

/**
 * Evaluates Scope/Deny guardrails and DNS-pinned SSRF checks for an initial or redirect target URL.
 * Returns the resolved IP and governance context so HTTP/HTTPS transports dial the pinned/source IP directly.
 */
export async function enforceTargetGovernance(
  targetUrl,
  {
    isRedirect = false,
    guard = null,
    scopeRules = null,
    enforceDnsValidation = false,
    dnsResolver = null,
    resolveCache = null,
    fresh = false,
    targetPinStore = null,
    allowPrivate = false,
    sourceIp = null,
    sourceIpMap = null
  } = {}
) {
  // 1. Standard URL SSRF validation on initial and redirect hops (forwarding allowPrivate)
  const urlCheck = validateTargetUrl(targetUrl, { allowPrivate });
  if (!urlCheck.valid) {
    const prefix = isRedirect ? 'Redirect blocked by SSRF policy' : 'Request blocked by SSRF policy';
    const err = new Error(`${prefix}: ${urlCheck.error}`);
    err.code = 'SSRF_POLICY_BLOCKED';
    err.isGovernanceBlock = true;
    throw err;
  }

  // 2. Pre-DNS Scope & Deny Asset Gate evaluation (always enforce built-in TLD deny rules on redirects)
  if (guard || scopeRules || isRedirect) {
    const gateRes = runAssetGateCheck(targetUrl, { guard, scopeRules, alwaysBuiltin: isRedirect });
    if (gateRes && gateRes.allowed === false) {
      const msg = isRedirect
        ? `Redirect blocked by SSRF policy: ${gateRes.reason}`
        : gateRes.reason;
      const err = new Error(msg);
      err.code = gateRes.code || 'TARGET_RULE_BLOCKED';
      err.matchedRule = gateRes.matchedRule || null;
      err.isGovernanceBlock = true;
      throw err;
    }
  }

  // 3. DNS Resolution / Explicit Source-IP & Target Pinning validation
  if (enforceDnsValidation || dnsResolver || resolveCache || targetPinStore || sourceIp || sourceIpMap) {
    const dnsRes = await resolveAndValidateTarget(targetUrl, {
      resolver: dnsResolver,
      resolveCache,
      fresh,
      targetPinStore,
      allowPrivate,
      sourceIp,
      sourceIpMap
    });

    if (!dnsRes.valid) {
      const msg = isRedirect
        ? `Redirect blocked by SSRF policy: ${dnsRes.reason}`
        : dnsRes.reason.startsWith('[SECSCAN platform control')
          ? dnsRes.reason
          : `[SECSCAN platform control, not target defense] ${dnsRes.reason}`;
      const err = new Error(msg);
      err.code = dnsRes.code || 'DNS_REBIND_OR_PRIVATE_IP';
      err.isGovernanceBlock = true;
      throw err;
    }

    // Re-evaluate Scope & Deny Asset Gate with resolved IPs so IP/CIDR rules catch DNS-resolved hosts
    if ((guard || scopeRules) && Array.isArray(dnsRes.resolvedIps) && dnsRes.resolvedIps.length > 0) {
      const postDnsGate = runAssetGateCheck(
        {
          url: targetUrl,
          hostname: dnsRes.hostname,
          resolvedIps: dnsRes.resolvedIps
        },
        { guard, scopeRules }
      );
      if (postDnsGate && postDnsGate.allowed === false) {
        const msg = isRedirect
          ? `Redirect blocked by SSRF policy: ${postDnsGate.reason}`
          : postDnsGate.reason;
        const err = new Error(msg);
        err.code = postDnsGate.code || 'TARGET_RULE_BLOCKED';
        err.matchedRule = postDnsGate.matchedRule || null;
        err.isGovernanceBlock = true;
        throw err;
      }
    }

    return {
      urlCheck,
      dnsRes,
      hostname: dnsRes.hostname,
      resolvedIps: dnsRes.resolvedIps || [],
      primaryIp: dnsRes.primaryIp || (dnsRes.resolvedIps && dnsRes.resolvedIps[0]) || null,
      sourceIp: dnsRes.sourceIp || null,
      sourceIpUsed: Boolean(dnsRes.sourceIpUsed)
    };
  }

  const cleanHost = String(urlCheck.hostname || '')
    .toLowerCase()
    .replace(/\.+$/, '')
    .replace(/^\[|\]$/g, '');
  const literalIp = canonicalizeIpAddress(cleanHost);
  return {
    urlCheck,
    dnsRes: null,
    hostname: cleanHost,
    resolvedIps: literalIp ? [literalIp] : [],
    primaryIp: literalIp || null,
    sourceIp: null,
    sourceIpUsed: false
  };
}

/**
 * Formats an IP and port into `ip:port` or `[ipv6]:port`.
 */
export function formatIpPort(ip, port) {
  const cleanIp = String(ip || '').replace(/^\[|\]$/g, '');
  if (cleanIp.includes(':')) {
    return `[${cleanIp}]:${port}`;
  }
  return `${cleanIp}:${port}`;
}

function decompressResponseBuffer(rawBuffer, contentEncoding = '', maxBytes = null) {
  if (!rawBuffer || rawBuffer.byteLength === 0) return Buffer.alloc(0);
  const enc = String(contentEncoding || '').trim().toLowerCase();
  const limit = maxBytes && maxBytes > 0 ? Math.max(maxBytes * 4, 16 * 1024 * 1024) : 16 * 1024 * 1024;
  try {
    if (enc === 'gzip' || enc === 'x-gzip') {
      return zlib.gunzipSync(rawBuffer, { maxOutputLength: limit });
    }
    if (enc === 'deflate') {
      try {
        return zlib.inflateSync(rawBuffer, { maxOutputLength: limit });
      } catch {
        return zlib.inflateRawSync(rawBuffer, { maxOutputLength: limit });
      }
    }
    if (enc === 'br' || enc === 'brotli') {
      return zlib.brotliDecompressSync(rawBuffer, { maxOutputLength: limit });
    }
  } catch {
    return rawBuffer;
  }
  return rawBuffer;
}

/**
 * SecScan Pinned Source-IP HTTP/HTTPS Dialer (`intercept/target_dial.go` `PinnedDialer` + `dialAddrs`).
 * Connects directly to the validated/pinned Source IP(s) in canonical order — never resolving or dialing
 * the domain name via the OS DNS stack — while preserving the HTTP `Host` header and TLS SNI (`servername`).
 *
 * @param {string} targetUrl
 * @param {{
 *   method?: string,
 *   headers?: Record<string, string>,
 *   body?: string | Buffer | Uint8Array,
 *   signal?: AbortSignal,
 *   timeout?: number,
 *   maxBytes?: number | null,
 *   followRedirects?: boolean,
 *   resolvedIps: string[],
 *   sourceIp?: string | null,
 *   family?: 0 | 4 | 6 | 'tcp' | 'tcp4' | 'tcp6',
 *   tlsRejectUnauthorized?: boolean,
 *   ca?: string | Buffer | Array<string | Buffer>,
 *   baseDialer?: Function
 * }} options
 * @returns {Promise<{
 *   status: number,
 *   headers: Record<string, string>,
 *   text: string,
 *   location: string | null,
 *   url: string,
 *   resolvedIp: string,
 *   resolvedIps: string[],
 *   sourceIp: string | null,
 *   dialedAddress: string
 * }>}
 */
export async function dialPinnedSourceIpRequest(targetUrl, options = {}) {
  const parsed = new URL(targetUrl);
  const isHttps = parsed.protocol === 'https:';
  const defaultPort = isHttps ? 443 : 80;
  const port = Number(parsed.port || defaultPort);
  const cleanHostname = parsed.hostname.toLowerCase().replace(/\.+$/, '').replace(/^\[|\]$/g, '');
  const isIpHost = net.isIP(cleanHostname) !== 0;
  const sniServername = !isIpHost ? cleanHostname : undefined;

  const rawFamily = options.family;
  const wantedFamily =
    rawFamily === 4 || rawFamily === 'tcp4'
      ? 4
      : rawFamily === 6 || rawFamily === 'tcp6'
        ? 6
        : 0;

  const allIps = canonicalizeResolvedIps(options.resolvedIps || []);
  const candidateIps = allIps.filter(ip => {
    const fam = net.isIP(ip);
    if (fam === 0) return false;
    if (wantedFamily === 4 && fam !== 4) return false;
    if (wantedFamily === 6 && fam !== 6) return false;
    return true;
  });

  if (candidateIps.length === 0) {
    const err = new Error(`no suitable address found for ${cleanHostname} (${allIps.join(', ') || 'none'})`);
    err.code = 'ENOTFOUND';
    throw err;
  }

  const reqHeaders = { ...(options.headers || {}) };
  const hasExplicitHost = Object.keys(reqHeaders).some(k => k.toLowerCase() === 'host');
  if (!hasExplicitHost) {
    reqHeaders.Host = parsed.host;
  }

  const method = String(options.method || 'GET').toUpperCase();
  const pathWithQuery = `${parsed.pathname || '/'}${parsed.search || ''}`;
  const maxBytes = options.maxBytes && Number(options.maxBytes) > 0 ? Math.floor(Number(options.maxBytes)) : null;
  const reqTimeout = Number.isFinite(Number(options.timeout)) && Number(options.timeout) > 0
    ? Number(options.timeout)
    : 10000;
  const tlsRejectUnauthorized = options.tlsRejectUnauthorized !== undefined
    ? Boolean(options.tlsRejectUnauthorized)
    : false;
  const bodyBuf = (options.body !== undefined && options.body !== null && method !== 'GET' && method !== 'HEAD')
    ? (Buffer.isBuffer(options.body)
        ? options.body
        : options.body instanceof Uint8Array
          ? Buffer.from(options.body)
          : Buffer.from(typeof options.body === 'string' ? options.body : JSON.stringify(options.body), 'utf8'))
    : null;
  if (bodyBuf !== null) {
    const hasContentLen = Object.keys(reqHeaders).some(k => {
      const lower = k.toLowerCase();
      return lower === 'content-length' || lower === 'transfer-encoding';
    });
    if (!hasContentLen) {
      reqHeaders['Content-Length'] = String(bodyBuf.byteLength);
    }
  }

  const attemptSingleIp = (ip, forceFreshSocket = false) => new Promise((resolve, reject) => {
    let settled = false;
    let req = null;
    const dialedAddress = formatIpPort(ip, port);

    const cleanupSignal = () => {
      if (options.signal) {
        try { options.signal.removeEventListener('abort', onAbort); } catch {}
      }
    };

    const finishErr = (err) => {
      if (settled) return;
      settled = true;
      cleanupSignal();
      reject(err instanceof Error ? err : new Error(String(err)));
    };

    const onAbort = () => {
      try { req?.destroy(); } catch {}
      const abortErr = new Error('The operation was aborted');
      abortErr.name = 'AbortError';
      finishErr(abortErr);
    };

    if (options.signal?.aborted) {
      const abortErr = new Error('The operation was aborted');
      abortErr.name = 'AbortError';
      return finishErr(abortErr);
    }

    if (options.signal) {
      options.signal.addEventListener('abort', onAbort, { once: true });
    }

    const transportMod = isHttps ? https : http;
    const pooledAgent = forceFreshSocket
      ? false
      : isHttps
        ? (!options.ca && !tlsRejectUnauthorized && options.httpsAgent ? options.httpsAgent : false)
        : (options.httpAgent || false);
    const reqOpts = {
      protocol: parsed.protocol,
      host: ip,
      hostname: ip,
      port,
      family: net.isIP(ip) || undefined,
      method,
      path: pathWithQuery,
      headers: reqHeaders,
      agent: pooledAgent,
      timeout: reqTimeout,
      // Explicitly pin lookup to the already-validated IP literal so Node never queries DNS
      lookup: (_hostname, lookupOpts, cb) => {
        const callback = typeof lookupOpts === 'function' ? lookupOpts : cb;
        const fam = net.isIP(ip) || 4;
        if (lookupOpts && typeof lookupOpts === 'object' && lookupOpts.all) {
          return callback(null, [{ address: ip, family: fam }]);
        }
        return callback(null, ip, fam);
      }
    };

    if (isHttps) {
      if (sniServername) {
        reqOpts.servername = sniServername;
      }
      reqOpts.rejectUnauthorized = tlsRejectUnauthorized;
      if (options.ca) {
        reqOpts.ca = options.ca;
      }
      if (tlsRejectUnauthorized && sniServername) {
        reqOpts.checkServerIdentity = (servername, cert) => tls.checkServerIdentity(sniServername, cert);
      }
    }

    if (typeof options.baseDialer === 'function') {
      const customCreateConnection = (connOpts, oncreate) => {
        let handled = false;
        const handleResult = (err, sock) => {
          if (handled) return;
          handled = true;
          if (err) {
            if (typeof oncreate === 'function') oncreate(err);
            else finishErr(err);
            return;
          }
          if (isHttps && !(sock instanceof tls.TLSSocket)) {
            const tlsSock = tls.connect({
              socket: sock,
              ...(sniServername ? { servername: sniServername } : {}),
              rejectUnauthorized: tlsRejectUnauthorized,
              ...(options.ca ? { ca: options.ca } : {}),
              ...(tlsRejectUnauthorized && sniServername
                ? { checkServerIdentity: (_sn, cert) => tls.checkServerIdentity(sniServername, cert) }
                : {})
            });
            if (typeof oncreate === 'function') oncreate(null, tlsSock);
            return tlsSock;
          }
          if (typeof oncreate === 'function') oncreate(null, sock);
          return sock;
        };

        try {
          const maybePromise = options.baseDialer({
            ip,
            port,
            address: dialedAddress,
            family: net.isIP(ip) || 4,
            network: wantedFamily === 4 ? 'tcp4' : wantedFamily === 6 ? 'tcp6' : 'tcp',
            hostname: cleanHostname,
            isHttps,
            servername: sniServername,
            timeout: reqTimeout
          }, handleResult);

          if (maybePromise && typeof maybePromise.then === 'function') {
            maybePromise.then(sock => handleResult(null, sock), err => handleResult(err));
            return undefined;
          }
          if (maybePromise && typeof maybePromise.on === 'function') {
            return handleResult(null, maybePromise);
          }
        } catch (err) {
          handleResult(err);
        }
        return undefined;
      };
      const oneOffAgent = new transportMod.Agent({ keepAlive: false });
      oneOffAgent.createConnection = customCreateConnection;
      reqOpts.agent = oneOffAgent;
      reqOpts.createConnection = customCreateConnection;
    }

    req = transportMod.request(reqOpts, (res) => {
      const status = res.statusCode ?? 200;
      const headersObj = {};
      for (const [k, v] of Object.entries(res.headers || {})) {
        if (v === undefined) continue;
        headersObj[String(k).toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
      }
      const location = headersObj.location ?? null;
      const isRedirect = status >= 300 && status < 400;

      if (isRedirect && location && options.followRedirects !== false) {
        res.resume();
        cleanupSignal();
        settled = true;
        return resolve({
          status,
          headers: headersObj,
          text: '',
          location,
          url: targetUrl,
          resolvedIp: ip,
          resolvedIps: candidateIps,
          sourceIp: options.sourceIp || ip,
          dialedAddress
        });
      }

      const chunks = [];
      let totalBytes = 0;
      const readCap = maxBytes ? Math.max(maxBytes * 2, 65536) : 8 * 1024 * 1024;

      res.on('data', (chunk) => {
        if (settled) return;
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        const remaining = readCap - totalBytes;
        if (remaining <= 0) {
          try { res.destroy(); } catch {}
          return;
        }
        if (buf.byteLength > remaining) {
          chunks.push(buf.subarray(0, remaining));
          totalBytes += remaining;
          try { res.destroy(); } catch {}
        } else {
          chunks.push(buf);
          totalBytes += buf.byteLength;
        }
      });

      const finalizeBody = () => {
        if (settled) return;
        settled = true;
        cleanupSignal();
        const rawBuf = Buffer.concat(chunks);
        const decompressed = decompressResponseBuffer(rawBuf, headersObj['content-encoding'], maxBytes);
        const rawText = decompressed.toString('utf8');
        const text = maxBytes ? sliceToMaxBytes(rawText, maxBytes) : rawText;
        resolve({
          status,
          headers: headersObj,
          text,
          location,
          url: targetUrl,
          resolvedIp: ip,
          resolvedIps: candidateIps,
          sourceIp: options.sourceIp || ip,
          dialedAddress
        });
      };

      res.on('end', finalizeBody);
      res.on('close', finalizeBody);
      res.on('error', (err) => {
        if (chunks.length > 0) {
          finalizeBody();
        } else {
          cleanupSignal();
          finishErr(err);
        }
      });
    });

    req.on('timeout', () => {
      const timeoutErr = new Error(`Request timed out after ${reqTimeout}ms`);
      timeoutErr.code = 'ETIMEDOUT';
      timeoutErr.name = 'TimeoutError';
      try { req.destroy(timeoutErr); } catch {}
    });

    req.on('error', (err) => {
      if (req?.reusedSocket && err?.code === 'ECONNRESET') {
        err._reusedSocketReset = true;
      }
      cleanupSignal();
      finishErr(err);
    });

    if (bodyBuf !== null) {
      req.write(bodyBuf);
    }

    req.end();
  });

  let lastError = null;
  for (const ip of candidateIps) {
    try {
      return await attemptSingleIp(ip, false);
    } catch (err) {
      if (err?._reusedSocketReset) {
        try {
          return await attemptSingleIp(ip, true);
        } catch (retryErr) {
          err = retryErr;
        }
      }
      lastError = err;
      // Do not failover to next IP on AbortError or TLS certificate verification error
      if (
        err?.name === 'AbortError' ||
        /certificate|Hostname\/IP does not match|ERR_TLS_CERT_ALTNAME_INVALID/i.test(err?.message || '') ||
        err?.code === 'ERR_TLS_CERT_ALTNAME_INVALID'
      ) {
        throw err;
      }
    }
  }

  throw lastError || new Error(`Failed to connect to any resolved IP (${candidateIps.join(', ')})`);
}

function sliceToMaxBytes(text, maxBytes) {
  if (!maxBytes || !text) return String(text || '');
  const s = String(text);
  if (s.length <= Math.floor(maxBytes / 3)) return s;
  const rough = s.length > maxBytes ? s.slice(0, maxBytes) : s;
  if (Buffer.byteLength(rough, 'utf8') <= maxBytes) return rough;
  const buf = Buffer.from(rough, 'utf8').subarray(0, maxBytes);
  return new TextDecoder('utf-8', { fatal: false }).decode(buf);
}

async function readResponseTextBounded(res, maxBytes) {
  if (maxBytes && res?.body && typeof res.body.getReader === 'function') {
    const reader = res.body.getReader();
    const decoder = new TextDecoder('utf-8', { fatal: false });
    const encoder = new TextEncoder();
    let decoded = '';
    let totalBytes = 0;
    try {
      while (totalBytes < maxBytes) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!value) continue;
        const chunk = typeof value === 'string'
          ? encoder.encode(value)
          : (value instanceof Uint8Array ? value : new Uint8Array(value));
        const remaining = maxBytes - totalBytes;
        if (chunk.byteLength > remaining) {
          decoded += decoder.decode(chunk.subarray(0, remaining), { stream: true });
          totalBytes += remaining;
          try { await reader.cancel(); } catch {}
          break;
        }
        decoded += decoder.decode(chunk, { stream: true });
        totalBytes += chunk.byteLength;
      }
      decoded += decoder.decode();
      return decoded;
    } finally {
      try { reader.releaseLock?.(); } catch {}
    }
  }

  let raw = '';
  if (typeof res?.text === 'function') {
    raw = (await res.text()) || '';
  } else if (typeof res?.text === 'string') {
    raw = res.text;
  } else if (typeof res?.body === 'string') {
    raw = res.body;
  }
  return maxBytes ? sliceToMaxBytes(raw, maxBytes) : raw;
}

const FAIL_FAST_NETWORK_CODES = new Set([
  'ECONNREFUSED',
  'ETIMEDOUT',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'UND_ERR_CONNECT_TIMEOUT'
]);

const FAIL_FAST_NETWORK_RE = /\b(?:ECONNREFUSED|ETIMEDOUT|EHOSTUNREACH|ENETUNREACH|UND_ERR_CONNECT_TIMEOUT)\b/i;
const FAIL_FAST_TIMEOUT_RE = /\b(?:operation was aborted|timed?\s*out)\b/i;
const MAX_ERROR_TRAVERSAL_DEPTH = 10;

function resolveNonNegativeInt(val) {
  if (typeof val !== 'number' && typeof val !== 'string') return null;
  if (typeof val === 'string' && val.trim() === '') return null;
  const num = Number(val);
  return Number.isFinite(num) && num >= 0 ? Math.floor(num) : null;
}

function resolvePositiveNumber(val) {
  if (typeof val !== 'number' && typeof val !== 'string') return null;
  if (typeof val === 'string' && val.trim() === '') return null;
  const num = Number(val);
  return Number.isFinite(num) && num > 0 ? num : null;
}

function traverseErrorNodes(err, visitor, maxDepth = MAX_ERROR_TRAVERSAL_DEPTH) {
  if (!err || typeof err !== 'object') return false;
  const seen = new Set();
  const queue = [{ node: err, depth: 0 }];
  let head = 0;

  while (head < queue.length) {
    const { node, depth } = queue[head++];
    if (!node || typeof node !== 'object' || seen.has(node)) continue;
    seen.add(node);

    if (visitor(node)) return true;
    if (depth >= maxDepth) continue;

    if (Array.isArray(node.errors)) {
      for (const sub of node.errors) {
        if (sub && typeof sub === 'object' && !seen.has(sub)) {
          queue.push({ node: sub, depth: depth + 1 });
        }
      }
    }
    if (node.cause && typeof node.cause === 'object' && !seen.has(node.cause)) {
      queue.push({ node: node.cause, depth: depth + 1 });
    }
  }
  return false;
}

function extractNetworkErrorCode(err) {
  let foundCode = undefined;
  traverseErrorNodes(err, (node) => {
    if (node.code !== undefined) {
      foundCode = node.code;
      return true;
    }
    return false;
  });
  return foundCode;
}

function isFailFastError(err) {
  return traverseErrorNodes(err, (node) => {
    if (node.name === 'AbortError' || node.name === 'TimeoutError') {
      return true;
    }
    if (node.code && FAIL_FAST_NETWORK_CODES.has(node.code)) {
      return true;
    }
    if (
      typeof node.message === 'string' &&
      (FAIL_FAST_NETWORK_RE.test(node.message) || FAIL_FAST_TIMEOUT_RE.test(node.message))
    ) {
      return true;
    }
    return false;
  });
}

/**
 * Fetches a URL with timeout, retries, manual redirect following (max 5 hops) with SSRF validation,
 * and optional Scope Gate (`guard`), DNS rebinding validator (`enforceDnsValidation` / `dnsResolver` / `targetPinStore`),
 * Pinned Source-IP Dialing (`sourceIp` / `sourceIpMap` / `usePinnedDialer` / `baseDialer`),
 * Target Noise Governor (`governor`), and Traffic Store recording (`trafficStore`).
 *
 * @param {string} url
 * @param {object} [options={}]
 * @param {number} [retries=2]
 * @param {number} [timeout=10000]
 * @returns {Promise<{ status: number, headers: Record<string, string>, text: string, url: string, resolvedIp?: string, resolvedIps?: string[], sourceIp?: string | null, dialedAddress?: string, trafficId?: string }>}
 */
export async function fetchWithRetry(url, options = {}, retries = 2, timeout = 10000) {
  const opts = options && typeof options === 'object' ? options : {};
  const effectiveRetries = resolveNonNegativeInt(opts.retries) ?? resolveNonNegativeInt(retries) ?? 2;
  const effectiveTimeout = resolvePositiveNumber(opts.timeout) ?? resolvePositiveNumber(timeout) ?? 10000;
  const failFast = Boolean(opts.failFast);

  const {
    guard = null,
    scopeRules = null,
    governor = null,
    trafficStore = null,
    taskId = null,
    dnsResolver = opts.resolver ?? null,
    resolveCache = null,
    freshDns = false,
    targetPinStore = null,
    enforceDnsValidation = false,
    allowPrivate = false,
    sourceIp = null,
    sourceIpMap = null,
    usePinnedDialer = false,
    connectToSourceIp = true,
    baseDialer = null,
    family = 0,
    tlsRejectUnauthorized = false,
    ca = null,
    httpAgent = null,
    httpsAgent = null,
    _pinVersionTracker = null,
    fetcher = null
  } = opts;

  const maxBytes = Number.isFinite(Number(opts.maxBytes)) && Number(opts.maxBytes) > 0
    ? Math.floor(Number(opts.maxBytes))
    : null;
  const hasCustomFetcher =
    typeof fetcher === 'function' ||
    (typeof globalThis.fetch === 'function' && globalThis.fetch !== NATIVE_GLOBAL_FETCH);
  const activeFetcher = typeof fetcher === 'function' ? fetcher : globalThis.fetch;

  for (let i = 0; i <= effectiveRetries; i++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), effectiveTimeout);
    timer.unref?.();

    const externalSignal = opts.signal && typeof opts.signal === 'object' ? opts.signal : null;
    const onExternalAbort = () => {
      try {
        controller.abort(externalSignal?.reason);
      } catch {
        controller.abort();
      }
    };
    if (externalSignal) {
      if (externalSignal.aborted) {
        onExternalAbort();
      } else if (typeof externalSignal.addEventListener === 'function') {
        externalSignal.addEventListener('abort', onExternalAbort, { once: true });
      }
    }

    try {
      if (externalSignal?.aborted) {
        const abortErr = new Error('The operation was aborted');
        abortErr.name = 'AbortError';
        throw abortErr;
      }

      let currentUrl = url;
      let hops = 0;
      const maxRedirects = 5;
      let currentGovernance = null;

      while (true) {
        // Validate initial URL against SSRF policy, Scope Gate & DNS/Source-IP validator before hop 0
        if (hops === 0) {
          currentGovernance = await enforceTargetGovernance(currentUrl, {
            isRedirect: false,
            guard,
            scopeRules,
            enforceDnsValidation,
            dnsResolver,
            resolveCache,
            fresh: Boolean(freshDns || targetPinStore),
            targetPinStore,
            allowPrivate,
            sourceIp,
            sourceIpMap
          });
        }

        const resolvedIps = currentGovernance?.resolvedIps || [];
        const primaryIp = currentGovernance?.primaryIp || resolvedIps[0] || null;
        const activeSourceIp = currentGovernance?.sourceIp || (currentGovernance?.sourceIpUsed ? primaryIp : null);
        const parsedCurrent = new URL(currentUrl);
        const effectivePort = Number(parsedCurrent.port || (parsedCurrent.protocol === 'https:' ? 443 : 80));
        const expectedDialedAddress = primaryIp ? formatIpPort(primaryIp, effectivePort) : null;

        const reqMethod = opts.method || 'GET';
        const reqBody = opts.body || undefined;
        const reqHeaders = {
          'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/2.2)',
          'Accept': 'text/html,application/json,*/*',
          ...(opts.headers || {})
        };

        // Ensure logical Host header is preserved when routing via Source IP
        if (activeSourceIp && !Object.keys(reqHeaders).some(k => k.toLowerCase() === 'host')) {
          reqHeaders.Host = parsedCurrent.host;
        }

        const hopStartMs = Date.now();
        const shouldUsePinnedSocketDialer =
          Boolean(usePinnedDialer || typeof baseDialer === 'function') ||
          (!hasCustomFetcher && connectToSourceIp !== false && resolvedIps.length > 0);

        const executeSingleHop = async () => {
          if (shouldUsePinnedSocketDialer) {
            if (targetPinStore && _pinVersionTracker && currentGovernance?.hostname) {
              const hostKey = currentGovernance.hostname;
              const curPin = typeof targetPinStore.getPin === 'function' ? targetPinStore.getPin(hostKey) : null;
              const curVer = curPin?.version ?? 0;
              const prevVer = _pinVersionTracker.get(hostKey);
              if (prevVer !== undefined && prevVer !== curVer) {
                try { httpAgent?.destroy(); } catch {}
                try { httpsAgent?.destroy(); } catch {}
              }
              _pinVersionTracker.set(hostKey, curVer);
            }
            return await dialPinnedSourceIpRequest(currentUrl, {
              method: reqMethod,
              headers: reqHeaders,
              body: reqBody,
              signal: controller.signal,
              timeout: effectiveTimeout,
              maxBytes,
              followRedirects: opts.followRedirects,
              resolvedIps,
              sourceIp: activeSourceIp,
              family,
              tlsRejectUnauthorized,
              ca,
              httpAgent,
              httpsAgent,
              baseDialer
            });
          }

          const res = await activeFetcher(currentUrl, {
            method: reqMethod,
            body: reqBody,
            redirect: 'manual',
            signal: controller.signal,
            headers: reqHeaders,
            ...(primaryIp ? { resolvedIp: primaryIp, resolvedIps } : {}),
            ...(activeSourceIp ? { sourceIp: activeSourceIp } : {}),
            ...(expectedDialedAddress ? { dialedAddress: expectedDialedAddress } : {})
          });

          const status = res.status ?? 200;
          let headersObj = {};
          let location = null;

          if (res.headers && typeof res.headers.entries === 'function') {
            headersObj = Object.fromEntries(res.headers.entries());
            location = typeof res.headers.get === 'function'
              ? res.headers.get('location')
              : (headersObj.location ?? null);
          } else if (res.headers && typeof res.headers === 'object') {
            for (const [k, v] of Object.entries(res.headers)) {
              headersObj[String(k).toLowerCase()] = String(v);
            }
            location = headersObj.location ?? null;
          }

          const isRedirect = status >= 300 && status < 400;
          let text = '';
          if (!isRedirect || !location || opts.followRedirects === false) {
            text = await readResponseTextBounded(res, maxBytes);
          } else {
            try { await res?.body?.cancel?.(); } catch {}
          }

          return {
            status,
            headers: headersObj,
            text,
            location,
            url: (typeof res.url === 'string' && res.url) ? res.url : currentUrl,
            ...(primaryIp ? { resolvedIp: res.resolvedIp || primaryIp, resolvedIps } : {}),
            ...(activeSourceIp ? { sourceIp: res.sourceIp || activeSourceIp } : {}),
            ...(expectedDialedAddress ? { dialedAddress: res.dialedAddress || expectedDialedAddress } : {})
          };
        };

        const hopResult = (governor && typeof governor.execute === 'function')
          ? await governor.execute(
              currentUrl,
              { method: reqMethod, headers: reqHeaders, body: reqBody },
              executeSingleHop
            )
          : await executeSingleHop();

        const durationMs = Math.max(0, Date.now() - hopStartMs);
        let recordedTrafficId = null;

        if (trafficStore && typeof trafficStore.recordExchange === 'function') {
          try {
            const rec = trafficStore.recordExchange({
              taskId: taskId || null,
              source: opts.trafficSource || 'scanner',
              method: reqMethod,
              url: currentUrl,
              status: hopResult.status,
              statusCode: hopResult.status,
              reqHeaders,
              requestHeaders: reqHeaders,
              reqBody: reqBody || '',
              requestBody: reqBody || '',
              resHeaders: hopResult.headers,
              responseHeaders: hopResult.headers,
              resBody: hopResult.text || '',
              responseBody: hopResult.text || '',
              durationMs
            });
            if (rec && rec.id) {
              recordedTrafficId = rec.id;
            }
          } catch (err) {
            console.warn(`⚠️  TrafficStore.recordExchange failed: ${err?.message || err}`);
          }
        }

        const isRedirect = hopResult.status >= 300 && hopResult.status < 400;
        const location = hopResult.location ?? hopResult.headers?.location ?? null;

        if (isRedirect && location && opts.followRedirects !== false) {
          if (hops >= maxRedirects) {
            throw new Error(`Maximum redirect limit (${maxRedirects}) exceeded`);
          }

          let resolvedUrl;
          try {
            resolvedUrl = new URL(location, currentUrl).href;
          } catch {
            throw new Error(`Invalid redirect URL: "${location}"`);
          }

          if (opts.sameOriginRedirects && new URL(resolvedUrl).origin !== new URL(currentUrl).origin) {
            const finalResolvedUrl = hopResult.url || currentUrl;
            const output = {
              status: hopResult.status,
              headers: hopResult.headers || {},
              text: hopResult.text || '',
              url: finalResolvedUrl,
              initialUrl: url,
              finalUrl: finalResolvedUrl,
              redirected: hops > 0,
              redirectHops: hops,
              ...(hopResult.resolvedIp ? { resolvedIp: hopResult.resolvedIp } : {}),
              ...(hopResult.resolvedIps ? { resolvedIps: hopResult.resolvedIps } : {}),
              ...(hopResult.sourceIp ? { sourceIp: hopResult.sourceIp } : {}),
              ...(hopResult.dialedAddress ? { dialedAddress: hopResult.dialedAddress } : {})
            };
            if (recordedTrafficId) {
              output.trafficId = recordedTrafficId;
            }
            return output;
          }

          currentGovernance = await enforceTargetGovernance(resolvedUrl, {
            isRedirect: true,
            guard,
            scopeRules,
            enforceDnsValidation,
            dnsResolver,
            resolveCache,
            fresh: true,
            targetPinStore,
            allowPrivate,
            sourceIp,
            sourceIpMap
          });

          currentUrl = resolvedUrl;
          hops++;
          continue;
        }

        const finalResolvedUrl = hopResult.url || currentUrl;
        const output = {
          status: hopResult.status,
          headers: hopResult.headers || {},
          text: hopResult.text || '',
          url: finalResolvedUrl,
          initialUrl: url,
          finalUrl: finalResolvedUrl,
          redirected: hops > 0,
          redirectHops: hops,
          ...(hopResult.resolvedIp ? { resolvedIp: hopResult.resolvedIp } : {}),
          ...(hopResult.resolvedIps ? { resolvedIps: hopResult.resolvedIps } : {}),
          ...(hopResult.sourceIp ? { sourceIp: hopResult.sourceIp } : {}),
          ...(hopResult.dialedAddress ? { dialedAddress: hopResult.dialedAddress } : {})
        };
        if (recordedTrafficId) {
          output.trafficId = recordedTrafficId;
        }
        return output;
      }
    } catch (e) {
      const errMsg = String(e?.message || '');
      if (
        e?.isGovernanceBlock ||
        errMsg.startsWith('Redirect blocked by SSRF policy') ||
        errMsg.startsWith('Request blocked by SSRF policy') ||
        errMsg.startsWith('[SECSCAN platform control')
      ) {
        throw e;
      }
      if (i === effectiveRetries || externalSignal?.aborted || (failFast && isFailFastError(e))) {
        const wrapped = new Error(`Fetch failed: ${e?.message || e}`);
        const resolvedCode = extractNetworkErrorCode(e);
        if (resolvedCode !== undefined) wrapped.code = resolvedCode;
        if (e?.name && e.name !== 'Error') wrapped.name = e.name;
        if (e?.cause !== undefined) wrapped.cause = e.cause;
        throw wrapped;
      }
      // Short pause before retry
      await new Promise(r => setTimeout(r, 500 * (i + 1)));
    } finally {
      clearTimeout(timer);
      if (externalSignal && typeof externalSignal.removeEventListener === 'function') {
        try { externalSignal.removeEventListener('abort', onExternalAbort); } catch {}
      }
    }
  }
}

fetchWithRetry.isDefaultFetch = true;

/**
 * Performs a governed TLS ALPN probe (e.g. checking HTTP/2 negotiation) against an `https:` target.
 * Enforces `validateTargetUrl`, pre-DNS `evaluateAssetGate`, `resolveAndValidateTarget` (with optional
 * `TargetPinStore`), and post-DNS `evaluateAssetGate` before opening a pinned `tls.connect` socket.
 *
 * @param {string} targetUrl
 * @param {{
 *   guard?: object | Array<object> | Function,
 *   scopeRules?: Array<object>,
 *   dnsResolver?: Function | object,
 *   resolver?: Function | object,
 *   targetPinStore?: TargetPinStore,
 *   allowPrivate?: boolean,
 *   timeout?: number,
 *   alpnProtocols?: string[],
 *   tlsProbe?: Function,
 *   alpnProbe?: Function
 * }} [options={}]
 * @returns {Promise<{ probed: boolean, alpnProtocol: string | null, tlsProtocol: string | null, resolvedIp?: string, reason?: string }>}
 */
export async function governedTlsAlpnProbe(targetUrl, options = {}) {
  const {
    guard = null,
    scopeRules = null,
    governor = null,
    dnsResolver = options?.resolver ?? null,
    resolveCache = null,
    targetPinStore = null,
    allowPrivate = false,
    sourceIp = null,
    sourceIpMap = null,
    timeout = 10000,
    alpnProtocols = ['h2', 'http/1.1'],
    tlsProbe = null,
    alpnProbe = null
  } = options || {};

  const urlCheck = validateTargetUrl(targetUrl, { allowPrivate });
  if (!urlCheck.valid) {
    const err = new Error(`Request blocked by SSRF policy: ${urlCheck.error}`);
    err.code = 'SSRF_POLICY_BLOCKED';
    err.isGovernanceBlock = true;
    throw err;
  }

  let parsed;
  try {
    parsed = new URL(String(targetUrl ?? '').trim());
  } catch {
    const err = new Error(`Request blocked by SSRF policy: Invalid URL format: "${targetUrl}"`);
    err.code = 'SSRF_POLICY_BLOCKED';
    err.isGovernanceBlock = true;
    throw err;
  }

  if (parsed.protocol === 'http:') {
    return { probed: false, alpnProtocol: null, tlsProtocol: null, reason: 'Non-HTTPS target' };
  }

  if (parsed.protocol !== 'https:') {
    const err = new Error(`Request blocked by SSRF policy: Protocol "${parsed.protocol}" is not supported`);
    err.code = 'SSRF_POLICY_BLOCKED';
    err.isGovernanceBlock = true;
    throw err;
  }

  if (parsed.username || parsed.password) {
    const err = new Error('Request blocked by SSRF policy: URLs containing credentials are not allowed');
    err.code = 'SSRF_POLICY_BLOCKED';
    err.isGovernanceBlock = true;
    throw err;
  }

  const preDnsGate = runAssetGateCheck(targetUrl, { guard, scopeRules, alwaysBuiltin: true });
  if (preDnsGate && preDnsGate.allowed === false) {
    const err = new Error(preDnsGate.reason);
    err.code = preDnsGate.code || 'TARGET_RULE_BLOCKED';
    err.matchedRule = preDnsGate.matchedRule || null;
    err.isGovernanceBlock = true;
    throw err;
  }

  const dnsRes = await resolveAndValidateTarget(targetUrl, {
    resolver: dnsResolver,
    resolveCache,
    targetPinStore,
    allowPrivate,
    sourceIp,
    sourceIpMap
  });

  if (!dnsRes.valid) {
    const msg = dnsRes.reason.startsWith('[SECSCAN platform control')
      ? dnsRes.reason
      : `[SECSCAN platform control, not target defense] ${dnsRes.reason}`;
    const err = new Error(msg);
    err.code = dnsRes.code || 'DNS_REBIND_OR_PRIVATE_IP';
    err.isGovernanceBlock = true;
    throw err;
  }

  if (Array.isArray(dnsRes.resolvedIps) && dnsRes.resolvedIps.length > 0) {
    const postDnsGate = runAssetGateCheck(
      {
        url: targetUrl,
        hostname: dnsRes.hostname,
        resolvedIps: dnsRes.resolvedIps
      },
      { guard, scopeRules, alwaysBuiltin: true }
    );
    if (postDnsGate && postDnsGate.allowed === false) {
      const err = new Error(postDnsGate.reason);
      err.code = postDnsGate.code || 'TARGET_RULE_BLOCKED';
      err.matchedRule = postDnsGate.matchedRule || null;
      err.isGovernanceBlock = true;
      throw err;
    }
  }

  const resolvedIp = dnsRes.resolvedIps[0];
  const cleanHostname = String(dnsRes.hostname || parsed.hostname || '')
    .toLowerCase()
    .replace(/^\[|\]$/g, '');
  const port = Number(parsed.port || 443);
  const servername = net.isIP(cleanHostname) === 0 ? cleanHostname : undefined;
  const protocols = Array.isArray(alpnProtocols) && alpnProtocols.length > 0
    ? alpnProtocols
    : ['h2', 'http/1.1'];
  const probeTimeout = Number.isFinite(Number(timeout)) && Number(timeout) > 0
    ? Number(timeout)
    : 10000;

  const customProbe = typeof tlsProbe === 'function'
    ? tlsProbe
    : typeof alpnProbe === 'function'
      ? alpnProbe
      : null;

  if (customProbe) {
    const runCustom = async () => {
      const probeResult = await customProbe({
        url: parsed.toString(),
        host: resolvedIp,
        resolvedIp,
        resolvedIps: dnsRes.resolvedIps,
        hostname: cleanHostname,
        port,
        servername,
        ALPNProtocols: protocols,
        alpnProtocols: protocols,
        timeout: probeTimeout
      });
      if (typeof probeResult === 'string') {
        return {
          probed: true,
          alpnProtocol: probeResult || null,
          tlsProtocol: null,
          resolvedIp
        };
      }
      return {
        probed: probeResult?.probed ?? true,
        alpnProtocol: probeResult?.alpnProtocol || null,
        tlsProtocol: probeResult?.tlsProtocol || null,
        resolvedIp: probeResult?.resolvedIp || resolvedIp,
        ...(probeResult?.cert !== undefined ? { cert: probeResult.cert } : {}),
        ...(probeResult?.daysRemaining !== undefined ? { daysRemaining: probeResult.daysRemaining } : {})
      };
    };
    if (governor && typeof governor.execute === 'function') {
      return await governor.execute(parsed.toString(), { method: 'TLS', cache: false }, runCustom);
    }
    return await runCustom();
  }

  const runSocketProbe = () => new Promise((resolve, reject) => {
    let settled = false;
    let socket = null;
    let timer = null;

    const cleanup = () => {
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
      if (socket) {
        try {
          socket.setTimeout(0);
        } catch {}
        if (!socket.destroyed) {
          socket.destroy();
        }
      }
    };

    const fail = (err) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(err);
    };

    const succeed = (alpnProtocol, cert = null, tlsProtocol = null) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve({
        probed: true,
        alpnProtocol: alpnProtocol || null,
        tlsProtocol: tlsProtocol || null,
        resolvedIp,
        cert
      });
    };

    try {
      socket = tls.connect(
        {
          host: resolvedIp,
          port,
          ...(servername ? { servername } : {}),
          ALPNProtocols: protocols,
          rejectUnauthorized: false
        },
        () => {
          let cert = null;
          let tlsProtocol = null;
          try {
            cert = typeof socket.getPeerCertificate === 'function' ? socket.getPeerCertificate(true) : null;
          } catch {}
          try {
            tlsProtocol = typeof socket.getProtocol === 'function' ? (socket.getProtocol() || null) : null;
          } catch {}
          succeed(socket.alpnProtocol || null, cert, tlsProtocol);
        }
      );

      timer = setTimeout(() => {
        fail(new Error('TLS ALPN probe timed out'));
      }, probeTimeout);
      if (typeof timer.unref === 'function') {
        timer.unref();
      }

      socket.setTimeout(probeTimeout, () => {
        fail(new Error('TLS ALPN probe timed out'));
      });

      socket.on('error', (err) => {
        fail(err instanceof Error ? err : new Error(String(err)));
      });
    } catch (err) {
      fail(err instanceof Error ? err : new Error(String(err)));
    }
  });

  if (governor && typeof governor.execute === 'function') {
    return await governor.execute(parsed.toString(), { method: 'TLS', cache: false }, runSocketProbe);
  }
  return await runSocketProbe();
}

const PROBE_SPECIFIC_OPTION_KEYS = ['alpnProbe', 'tlsProbe', 'timeout', 'alpnProtocols'];
const PROBE_GOVERNANCE_KEYS = [
  'guard',
  'scopeRules',
  'governor',
  'dnsResolver',
  'resolveCache',
  'targetPinStore',
  'allowPrivate',
  'sourceIp',
  'sourceIpMap'
];

/**
 * Merges caller probe options with bound governance so caller options cannot override
 * or weaken bound governance fields (`guard`, `scopeRules`, `governor`, `dnsResolver`,
 * `targetPinStore`, `allowPrivate`, `sourceIp`, `sourceIpMap`).
 *
 * @param {object | null} boundGovernance
 * @param {object} [callerOpts={}]
 * @returns {object}
 */
export function mergeGovernedProbeOptions(boundGovernance, callerOpts = {}) {
  const src = callerOpts && typeof callerOpts === 'object' ? callerOpts : {};
  const probe = {};
  for (const key of PROBE_SPECIFIC_OPTION_KEYS) {
    if (src[key] !== undefined) {
      probe[key] = src[key];
    }
  }

  if (!boundGovernance || typeof boundGovernance !== 'object') {
    const ungoverned = { ...probe };
    for (const key of [...PROBE_GOVERNANCE_KEYS, 'resolver']) {
      if (src[key] !== undefined) {
        ungoverned[key] = src[key];
      }
    }
    return ungoverned;
  }

  const gov = {};
  for (const key of PROBE_GOVERNANCE_KEYS) {
    if (boundGovernance[key] !== undefined) {
      gov[key] = boundGovernance[key];
    } else if (key === 'dnsResolver') {
      if (boundGovernance.resolver !== undefined) {
        gov.dnsResolver = boundGovernance.resolver;
      } else if (src.dnsResolver !== undefined || src.resolver !== undefined) {
        gov.dnsResolver = src.dnsResolver ?? src.resolver;
      }
    } else if (key === 'guard') {
      gov.guard = null;
    } else if (key === 'allowPrivate') {
      gov.allowPrivate = false;
    } else if (src[key] !== undefined) {
      gov[key] = src[key];
    }
  }

  if (boundGovernance.timeout !== undefined && probe.timeout === undefined) {
    probe.timeout = boundGovernance.timeout;
  }

  return { ...probe, ...gov };
}

const PROTECTED_FETCH_OPTION_KEYS = [
  'guard',
  'scopeRules',
  'governor',
  'trafficStore',
  'dnsResolver',
  'resolver',
  'resolveCache',
  'targetPinStore',
  'enforceDnsValidation',
  'allowPrivate',
  'sourceIp',
  'sourceIpMap',
  'baseDialer',
  'httpAgent',
  'httpsAgent',
  '_pinVersionTracker',
  'fetcher'
];

/**
 * Merges caller fetch options with bound governance options so callers cannot weaken
 * or override bound security/governance/transport fields while preserving request-level
 * options (`method`, `headers`, `body`, `followRedirects`, `trafficSource`) and
 * allowing `taskId` fallback when unbound.
 *
 * @param {object | null} boundGovernance
 * @param {object} [callOptions={}]
 * @returns {object}
 */
export function mergeGovernedFetchOptions(boundGovernance, callOptions = {}) {
  const safeOpts = callOptions && typeof callOptions === 'object' ? { ...callOptions } : {};
  for (const key of PROTECTED_FETCH_OPTION_KEYS) {
    delete safeOpts[key];
  }

  const bound = boundGovernance && typeof boundGovernance === 'object' ? boundGovernance : {};
  const activeDnsResolver = bound.dnsResolver ?? bound.resolver ?? null;
  const activeResolveCache = bound.resolveCache ?? null;
  const activePinStore = bound.targetPinStore ?? null;
  const activeSourceIp = bound.sourceIp ?? null;
  const activeSourceIpMap = bound.sourceIpMap ?? null;

  return {
    ...safeOpts,
    guard: bound.guard ?? null,
    scopeRules: bound.scopeRules ?? null,
    governor: bound.governor ?? null,
    trafficStore: bound.trafficStore ?? null,
    taskId: bound.taskId ?? safeOpts.taskId ?? null,
    dnsResolver: activeDnsResolver,
    resolveCache: activeResolveCache,
    targetPinStore: activePinStore,
    sourceIp: activeSourceIp,
    sourceIpMap: activeSourceIpMap,
    usePinnedDialer: bound.usePinnedDialer ?? safeOpts.usePinnedDialer ?? false,
    connectToSourceIp: bound.connectToSourceIp ?? safeOpts.connectToSourceIp ?? true,
    baseDialer: bound.baseDialer ?? null,
    enforceDnsValidation: Boolean(
      bound.enforceDnsValidation ||
      activeDnsResolver ||
      activeResolveCache ||
      activePinStore ||
      activeSourceIp ||
      activeSourceIpMap
    ),
    allowPrivate: Boolean(bound.allowPrivate),
    httpAgent: bound.httpAgent ?? null,
    httpsAgent: bound.httpsAgent ?? null,
    _pinVersionTracker: bound._pinVersionTracker ?? null,
    fetcher: bound.fetcher ?? null
  };
}

/**
 * Factory creating a curried `fetchWithRetry` bound to a Scope Gate (`guard`),
 * Target Noise Governor (`governor`), Traffic Store (`trafficStore`), DNS-Pinned SSRF validator,
 * and SecScan Pinned Source-IP Dialer.
 */
export function createGovernedFetch({
  guard = null,
  scopeRules = null,
  governor = null,
  trafficStore = null,
  taskId = null,
  dnsResolver = null,
  resolver = null,
  resolveCache = null,
  targetPinStore = null,
  sourceIp = null,
  sourceIpMap = null,
  usePinnedDialer = false,
  connectToSourceIp = true,
  baseDialer = null,
  enforceDnsValidation = false,
  allowPrivate = false,
  retries = 2,
  timeout = 10000,
  fetcher = null
} = {}) {
  const activeDnsResolver = dnsResolver || resolver || null;
  const activePinStore =
    targetPinStore ||
    (enforceDnsValidation || activeDnsResolver || resolveCache || sourceIp || sourceIpMap
      ? new TargetPinStore({ allowPrivate })
      : null);

  const httpAgent = new http.Agent({ keepAlive: true, keepAliveMsecs: 1000, maxSockets: 8, maxFreeSockets: 4 });
  const httpsAgent = new https.Agent({ keepAlive: true, keepAliveMsecs: 1000, maxSockets: 8, maxFreeSockets: 4 });
  const pinVersionTracker = new Map();

  const boundFetchConfig = {
    guard,
    scopeRules,
    governor,
    trafficStore,
    taskId,
    dnsResolver: activeDnsResolver,
    resolveCache,
    targetPinStore: activePinStore,
    sourceIp,
    sourceIpMap,
    usePinnedDialer,
    connectToSourceIp,
    baseDialer,
    httpAgent,
    httpsAgent,
    _pinVersionTracker: pinVersionTracker,
    enforceDnsValidation: Boolean(
      enforceDnsValidation || activeDnsResolver || resolveCache || activePinStore || sourceIp || sourceIpMap
    ),
    allowPrivate: Boolean(allowPrivate),
    fetcher
  };

  const governedFetch = async function governedFetch(
    url,
    callOptions = {},
    callRetries = retries,
    callTimeout = timeout
  ) {
    return fetchWithRetry(
      url,
      mergeGovernedFetchOptions(boundFetchConfig, callOptions),
      callRetries,
      callTimeout
    );
  };

  governedFetch.targetPinStore = activePinStore;
  governedFetch.destroyAgents = () => {
    try { httpAgent.destroy(); } catch {}
    try { httpsAgent.destroy(); } catch {}
  };
  governedFetch.resolveCache = resolveCache;
  governedFetch.sourceIp = sourceIp;
  governedFetch.sourceIpMap = sourceIpMap;
  governedFetch.governor = governor;
  governedFetch.guard = guard;
  governedFetch.trafficStore = trafficStore;
  governedFetch.hasCustomFetcher = Boolean(fetcher || baseDialer);
  governedFetch.governance = Object.freeze({
    guard,
    scopeRules,
    governor,
    dnsResolver: activeDnsResolver,
    resolveCache,
    targetPinStore: activePinStore,
    sourceIp,
    sourceIpMap,
    allowPrivate: Boolean(allowPrivate),
    timeout
  });
  governedFetch.tlsAlpnProbe = (url, probeOpts = {}) =>
    governedTlsAlpnProbe(url, mergeGovernedProbeOptions(governedFetch.governance, probeOpts));

  return governedFetch;
}
