import tls from 'node:tls';
import net from 'node:net';
import { validateTargetUrl, resolveAndValidateTarget } from './validator.js';
import { evaluateAssetGate, TargetPinStore } from './guard.js';

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
 */
export async function enforceTargetGovernance(
  targetUrl,
  {
    isRedirect = false,
    guard = null,
    scopeRules = null,
    enforceDnsValidation = false,
    dnsResolver = null,
    targetPinStore = null,
    allowPrivate = false
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

  // 3. DNS Resolution & Target Pinning validation
  if (enforceDnsValidation || dnsResolver || targetPinStore) {
    const dnsRes = await resolveAndValidateTarget(targetUrl, {
      resolver: dnsResolver,
      targetPinStore,
      allowPrivate
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
  }
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

/**
 * Fetches a URL with timeout, retries, manual redirect following (max 5 hops) with SSRF validation,
 * and optional Scope Gate (`guard`), DNS rebinding validator (`enforceDnsValidation` / `dnsResolver` / `targetPinStore`),
 * Target Noise Governor (`governor`), and Traffic Store recording (`trafficStore`).
 *
 * @param {string} url
 * @param {object} [options={}]
 * @param {number} [retries=2]
 * @param {number} [timeout=10000]
 * @returns {Promise<{ status: number, headers: Record<string, string>, text: string, url: string, trafficId?: string }>}
 */
export async function fetchWithRetry(url, options = {}, retries = 2, timeout = 10000) {
  const {
    guard = null,
    scopeRules = null,
    governor = null,
    trafficStore = null,
    taskId = null,
    dnsResolver = options.resolver ?? null,
    targetPinStore = null,
    enforceDnsValidation = false,
    allowPrivate = false,
    fetcher = null
  } = options || {};

  const maxBytes = Number.isFinite(Number(options?.maxBytes)) && Number(options.maxBytes) > 0
    ? Math.floor(Number(options.maxBytes))
    : null;
  const activeFetcher = typeof fetcher === 'function' ? fetcher : globalThis.fetch;

  for (let i = 0; i <= retries; i++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    try {
      let currentUrl = url;
      let hops = 0;
      const maxRedirects = 5;

      while (true) {
        // Validate initial URL against SSRF policy, Scope Gate & DNS validator before hop 0
        if (hops === 0) {
          await enforceTargetGovernance(currentUrl, {
            isRedirect: false,
            guard,
            scopeRules,
            enforceDnsValidation,
            dnsResolver,
            targetPinStore,
            allowPrivate
          });
        }

        const reqMethod = options.method || 'GET';
        const reqBody = options.body || undefined;
        const reqHeaders = {
          'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/2.2)',
          'Accept': 'text/html,application/json,*/*',
          ...(options.headers || {})
        };

        const hopStartMs = Date.now();

        const executeSingleHop = async () => {
          const res = await activeFetcher(currentUrl, {
            method: reqMethod,
            body: reqBody,
            redirect: 'manual',
            signal: controller.signal,
            headers: reqHeaders
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
          if (!isRedirect || !location || options.followRedirects === false) {
            text = await readResponseTextBounded(res, maxBytes);
          } else {
            try { await res?.body?.cancel?.(); } catch {}
          }

          return {
            status,
            headers: headersObj,
            text,
            location,
            url: (typeof res.url === 'string' && res.url) ? res.url : currentUrl
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
              source: options.trafficSource || 'scanner',
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

        if (isRedirect && location && options.followRedirects !== false) {
          if (hops >= maxRedirects) {
            throw new Error(`Maximum redirect limit (${maxRedirects}) exceeded`);
          }

          let resolvedUrl;
          try {
            resolvedUrl = new URL(location, currentUrl).href;
          } catch {
            throw new Error(`Invalid redirect URL: "${location}"`);
          }

          if (options.sameOriginRedirects && new URL(resolvedUrl).origin !== new URL(currentUrl).origin) {
            clearTimeout(timer);
            const finalResolvedUrl = hopResult.url || currentUrl;
            const output = {
              status: hopResult.status,
              headers: hopResult.headers || {},
              text: hopResult.text || '',
              url: finalResolvedUrl,
              initialUrl: url,
              finalUrl: finalResolvedUrl,
              redirected: hops > 0,
              redirectHops: hops
            };
            if (recordedTrafficId) {
              output.trafficId = recordedTrafficId;
            }
            return output;
          }

          await enforceTargetGovernance(resolvedUrl, {
            isRedirect: true,
            guard,
            scopeRules,
            enforceDnsValidation,
            dnsResolver,
            targetPinStore,
            allowPrivate
          });

          currentUrl = resolvedUrl;
          hops++;
          continue;
        }

        clearTimeout(timer);

        const finalResolvedUrl = hopResult.url || currentUrl;
        const output = {
          status: hopResult.status,
          headers: hopResult.headers || {},
          text: hopResult.text || '',
          url: finalResolvedUrl,
          initialUrl: url,
          finalUrl: finalResolvedUrl,
          redirected: hops > 0,
          redirectHops: hops
        };
        if (recordedTrafficId) {
          output.trafficId = recordedTrafficId;
        }
        return output;
      }
    } catch (e) {
      clearTimeout(timer);
      if (
        e.isGovernanceBlock ||
        e.message.startsWith('Redirect blocked by SSRF policy') ||
        e.message.startsWith('Request blocked by SSRF policy') ||
        e.message.startsWith('[SECSCAN platform control')
      ) {
        throw e;
      }
      if (i === retries) {
        const wrapped = new Error(`Fetch failed: ${e?.message || e}`);
        if (e?.code !== undefined) wrapped.code = e.code;
        if (e?.name && e.name !== 'Error') wrapped.name = e.name;
        if (e?.cause !== undefined) wrapped.cause = e.cause;
        throw wrapped;
      }
      // Short pause before retry
      await new Promise(r => setTimeout(r, 500 * (i + 1)));
    }
  }
}

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
    targetPinStore = null,
    allowPrivate = false,
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
    targetPinStore,
    allowPrivate
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
const PROBE_GOVERNANCE_KEYS = ['guard', 'scopeRules', 'governor', 'dnsResolver', 'targetPinStore', 'allowPrivate'];

/**
 * Merges caller probe options with bound governance so caller options cannot override
 * or weaken bound governance fields (`guard`, `scopeRules`, `governor`, `dnsResolver`,
 * `targetPinStore`, `allowPrivate`).
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
  'targetPinStore',
  'enforceDnsValidation',
  'allowPrivate',
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
  const activePinStore = bound.targetPinStore ?? null;

  return {
    ...safeOpts,
    guard: bound.guard ?? null,
    scopeRules: bound.scopeRules ?? null,
    governor: bound.governor ?? null,
    trafficStore: bound.trafficStore ?? null,
    taskId: bound.taskId ?? safeOpts.taskId ?? null,
    dnsResolver: activeDnsResolver,
    targetPinStore: activePinStore,
    enforceDnsValidation: Boolean(bound.enforceDnsValidation || activeDnsResolver || activePinStore),
    allowPrivate: Boolean(bound.allowPrivate),
    fetcher: bound.fetcher ?? null
  };
}

/**
 * Factory creating a curried `fetchWithRetry` bound to a Scope Gate (`guard`),
 * Target Noise Governor (`governor`), Traffic Store (`trafficStore`), and DNS-Pinned SSRF validator.
 *
 * @param {{
 *   guard?: object | Array<object> | Function,
 *   scopeRules?: Array<object>,
 *   governor?: object,
 *   trafficStore?: object,
 *   taskId?: string,
 *   dnsResolver?: Function | object,
 *   resolver?: Function | object,
 *   targetPinStore?: TargetPinStore,
 *   enforceDnsValidation?: boolean,
 *   allowPrivate?: boolean,
 *   retries?: number,
 *   timeout?: number,
 *   fetcher?: Function
 * }} [config={}]
 */
export function createGovernedFetch({
  guard = null,
  scopeRules = null,
  governor = null,
  trafficStore = null,
  taskId = null,
  dnsResolver = null,
  resolver = null,
  targetPinStore = null,
  enforceDnsValidation = false,
  allowPrivate = false,
  retries = 2,
  timeout = 10000,
  fetcher = null
} = {}) {
  const activeDnsResolver = dnsResolver || resolver || null;
  const activePinStore =
    targetPinStore ||
    (enforceDnsValidation || activeDnsResolver ? new TargetPinStore({ allowPrivate }) : null);

  const boundFetchConfig = {
    guard,
    scopeRules,
    governor,
    trafficStore,
    taskId,
    dnsResolver: activeDnsResolver,
    targetPinStore: activePinStore,
    enforceDnsValidation: Boolean(enforceDnsValidation || activeDnsResolver || activePinStore),
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
  governedFetch.governor = governor;
  governedFetch.guard = guard;
  governedFetch.trafficStore = trafficStore;
  governedFetch.governance = Object.freeze({
    guard,
    scopeRules,
    governor,
    dnsResolver: activeDnsResolver,
    targetPinStore: activePinStore,
    allowPrivate: Boolean(allowPrivate),
    timeout
  });
  governedFetch.tlsAlpnProbe = (url, probeOpts = {}) =>
    governedTlsAlpnProbe(url, mergeGovernedProbeOptions(governedFetch.governance, probeOpts));

  return governedFetch;
}
