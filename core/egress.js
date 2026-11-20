import { URL } from 'node:url';

/**
 * Built-in Target Noise Governor profiles.
 */
export const NOISE_PROFILES = Object.freeze({
  off: Object.freeze({
    rpsPerHost: Infinity,
    maxInFlightPerHost: Infinity,
    maxGlobalInFlight: Infinity,
    cacheTtlMs: 0,
    jitterMs: Object.freeze([0, 0])
  }),
  quiet: Object.freeze({
    rpsPerHost: 2,
    maxInFlightPerHost: 1,
    maxGlobalInFlight: 8,
    cacheTtlMs: 60000,
    jitterMs: Object.freeze([50, 200])
  }),
  balanced: Object.freeze({
    rpsPerHost: 5,
    maxInFlightPerHost: 2,
    maxGlobalInFlight: 16,
    cacheTtlMs: 30000,
    jitterMs: Object.freeze([20, 80])
  }),
  aggressive: Object.freeze({
    rpsPerHost: 20,
    maxInFlightPerHost: 4,
    maxGlobalInFlight: 32,
    cacheTtlMs: 10000,
    jitterMs: Object.freeze([0, 20])
  })
});

/**
 * Simple async semaphore for bounding per-host and global concurrency.
 */
class Semaphore {
  constructor(max) {
    this.max = Number.isFinite(max) && max > 0 ? max : Infinity;
    this.current = 0;
    this.peak = 0;
    this.queue = [];
  }

  async acquire() {
    if (this.current < this.max) {
      this.current += 1;
      if (this.current > this.peak) this.peak = this.current;
      return;
    }
    await new Promise(resolve => this.queue.push(resolve));
    this.current += 1;
    if (this.current > this.peak) this.peak = this.current;
  }

  release() {
    this.current = Math.max(0, this.current - 1);
    if (this.queue.length > 0 && this.current < this.max) {
      const next = this.queue.shift();
      next();
    }
  }
}

/**
 * Extracts a normalized lowercase hostname (or authority) from a URL or hostname string.
 */
function extractHostname(urlOrHost) {
  if (typeof urlOrHost !== 'string' || !urlOrHost.trim()) return 'unknown';
  const trimmed = urlOrHost.trim();
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) {
    try {
      return new URL(trimmed).hostname.toLowerCase();
    } catch {
      return trimmed.toLowerCase();
    }
  }
  return trimmed.split('/')[0].replace(/:\d+$/, '').toLowerCase();
}

/**
 * Extracts a header value case-insensitively from a Fetch `Headers` object or a plain object.
 */
function getHeaderCaseInsensitive(headers, name) {
  if (!headers) return null;
  const target = name.toLowerCase();
  if (typeof headers.get === 'function') {
    return headers.get(name) ?? headers.get(target) ?? null;
  }
  if (typeof headers === 'object') {
    for (const [k, v] of Object.entries(headers)) {
      if (String(k).toLowerCase() === target) {
        return v;
      }
    }
  }
  return null;
}

/**
 * Clones a response safely so singleflight and TTL-cached responses can be consumed
 * independently by multiple callers.
 */
function cloneResponseForCaller(res) {
  if (!res || typeof res !== 'object') return res;
  if (typeof res.clone === 'function') {
    try {
      return res.clone();
    } catch {
      return res;
    }
  }
  return {
    ...res,
    headers: res.headers && typeof res.headers === 'object' && typeof res.headers.get !== 'function'
      ? { ...res.headers }
      : res.headers
  };
}

/**
 * Target Noise Governor:
 * - Per-host token bucket rate limiter
 * - Per-host & global concurrency semaphores
 * - Uniform random jitter delay
 * - `Retry-After` / `429` / `503` exponential host backoff window (`recordResponse`)
 * - Per-scan `GET` singleflight coalescing + TTL response cache (`execute`)
 * - Live telemetry (`snapshot`)
 */
export class NoiseGovernor {
  /**
   * @param {string | object} [profileOrOptions='balanced']
   * @param {object} [overrides={}]
   */
  constructor(profileOrOptions = 'balanced', overrides = {}) {
    let profileName = 'balanced';
    let customOpts = { ...overrides };

    if (typeof profileOrOptions === 'string') {
      profileName = Object.hasOwn(NOISE_PROFILES, profileOrOptions) ? profileOrOptions : 'balanced';
    } else if (profileOrOptions && typeof profileOrOptions === 'object') {
      const candidate = typeof profileOrOptions.profile === 'string' ? profileOrOptions.profile : '';
      profileName = Object.hasOwn(NOISE_PROFILES, candidate) ? candidate : 'balanced';
      customOpts = { ...profileOrOptions, ...overrides };
    }

    const baseProfile = Object.hasOwn(NOISE_PROFILES, profileName)
      ? NOISE_PROFILES[profileName]
      : NOISE_PROFILES.balanced;

    this.profile = profileName;
    this.config = {
      rpsPerHost: customOpts.rpsPerHost ?? baseProfile.rpsPerHost,
      maxInFlightPerHost: customOpts.maxInFlightPerHost ?? baseProfile.maxInFlightPerHost,
      maxGlobalInFlight: customOpts.maxGlobalInFlight ?? baseProfile.maxGlobalInFlight,
      cacheTtlMs: customOpts.cacheTtlMs ?? baseProfile.cacheTtlMs,
      jitterMs: Array.isArray(customOpts.jitterMs) ? customOpts.jitterMs : [...baseProfile.jitterMs],
      burst: customOpts.burst ?? 1,
      baseBackoffMs: customOpts.baseBackoffMs ?? 1000,
      maxBackoffMs: customOpts.maxBackoffMs ?? 60000,
      maxHosts: customOpts.maxHosts ?? 500,
      maxCacheEntries: customOpts.maxCacheEntries ?? 1000
    };

    this.nowFn = typeof customOpts.nowFn === 'function' ? customOpts.nowFn : () => Date.now();
    this.sleepFn = typeof customOpts.sleepFn === 'function'
      ? customOpts.sleepFn
      : (ms) => new Promise(resolve => setTimeout(resolve, ms));

    this.globalSemaphore = new Semaphore(this.config.maxGlobalInFlight);
    this.hosts = new Map();
    this.inFlightGets = new Map();
    this.cache = new Map();

    this.totals = {
      requests: 0,
      throttled: 0,
      backoffHits: 0,
      duplicatesAvoided: 0,
      cacheHits: 0
    };
  }

  _evictIdleHostsIfNeeded() {
    const maxHosts = this.config.maxHosts;
    if (!Number.isFinite(maxHosts) || maxHosts <= 0 || this.hosts.size < maxHosts) {
      return;
    }
    const now = this.nowFn();
    for (const [k, s] of this.hosts.entries()) {
      if (this.hosts.size < maxHosts) return;
      if (s.semaphore.current === 0 && s.semaphore.queue.length === 0 && s.backoffUntil <= now) {
        this.hosts.delete(k);
      }
    }
    for (const [k, s] of this.hosts.entries()) {
      if (this.hosts.size < maxHosts) return;
      if (s.semaphore.current === 0 && s.semaphore.queue.length === 0) {
        this.hosts.delete(k);
      }
    }
  }

  _getHostState(host) {
    const key = extractHostname(host);
    let state = this.hosts.get(key);
    const now = this.nowFn();
    if (state) {
      // Refresh LRU order
      this.hosts.delete(key);
      state.lastUsedAt = now;
      this.hosts.set(key, state);
      return state;
    }

    this._evictIdleHostsIfNeeded();
    const capacity = Math.max(1, Number(this.config.burst ?? 1));
    state = {
      host: key,
      semaphore: new Semaphore(this.config.maxInFlightPerHost),
      tokens: capacity,
      capacity,
      lastRefillAt: now,
      lastUsedAt: now,
      backoffUntil: 0,
      backoffAttempts: 0,
      requests: 0,
      throttled: 0,
      backoffHits: 0,
      duplicatesAvoided: 0,
      cacheHits: 0
    };
    this.hosts.set(key, state);
    return state;
  }

  /**
   * Computes a uniform random jitter delay in `[min, max]` milliseconds.
   */
  _computeJitterMs() {
    if (this.profile === 'off') return 0;
    const [min, max] = this.config.jitterMs || [0, 0];
    if (!Number.isFinite(min) || !Number.isFinite(max) || max <= 0) return 0;
    if (max <= min) return Math.max(0, min);
    return Math.floor(min + Math.random() * (max - min + 1));
  }

  /**
   * Acquires a token from the host's token bucket, returning the required wait time in ms.
   */
  _reserveTokenWaitMs(hostState) {
    if (this.profile === 'off' || !Number.isFinite(this.config.rpsPerHost) || this.config.rpsPerHost <= 0) {
      return 0;
    }

    const now = this.nowFn();
    const intervalMs = 1000 / this.config.rpsPerHost;

    if (now > hostState.lastRefillAt) {
      const gained = (now - hostState.lastRefillAt) / intervalMs;
      hostState.tokens = Math.min(hostState.capacity, hostState.tokens + gained);
      hostState.lastRefillAt = now;
    }

    if (hostState.tokens >= 1) {
      hostState.tokens -= 1;
      return 0;
    }

    const deficit = 1 - hostState.tokens;
    const waitMs = Math.ceil(deficit * intervalMs);
    hostState.tokens -= 1;
    this.totals.throttled += 1;
    hostState.throttled += 1;
    return waitMs;
  }

  /**
   * Records an HTTP response for a host and updates the exponential / Retry-After backoff window
   * on HTTP 429 or 503 responses.
   *
   * @param {string} urlOrHost
   * @param {number} status
   * @param {object} [headers={}]
   * @returns {{ backedOff: boolean, delayMs: number, backoffUntil: number, attempts: number }}
   */
  recordResponse(urlOrHost, status, headers = {}) {
    const hostState = this._getHostState(urlOrHost);
    const now = this.nowFn();

    if (status === 429 || status === 503) {
      hostState.backoffAttempts += 1;
      hostState.backoffHits += 1;
      this.totals.backoffHits += 1;

      let delayMs = null;
      const retryAfterRaw = getHeaderCaseInsensitive(headers, 'retry-after');

      if (retryAfterRaw !== null && retryAfterRaw !== undefined && String(retryAfterRaw).trim() !== '') {
        const retryStr = String(retryAfterRaw).trim();
        if (/^\d+(\.\d+)?$/.test(retryStr)) {
          delayMs = Math.max(0, Math.round(parseFloat(retryStr) * 1000));
        } else {
          const parsedDate = Date.parse(retryStr);
          if (!Number.isNaN(parsedDate)) {
            delayMs = Math.max(0, parsedDate - now);
          }
        }
      }

      if (delayMs === null) {
        const expDelay = this.config.baseBackoffMs * Math.pow(2, hostState.backoffAttempts - 1);
        delayMs = Math.min(this.config.maxBackoffMs, expDelay);
      }

      hostState.backoffUntil = Math.max(hostState.backoffUntil, now + delayMs);

      return {
        backedOff: true,
        delayMs,
        backoffUntil: hostState.backoffUntil,
        attempts: hostState.backoffAttempts
      };
    }

    if (status >= 200 && status < 400) {
      hostState.backoffAttempts = 0;
    }

    return {
      backedOff: false,
      delayMs: 0,
      backoffUntil: hostState.backoffUntil,
      attempts: hostState.backoffAttempts
    };
  }

  _buildCacheKey(url, options = {}) {
    const method = String(options.method || 'GET').toUpperCase();
    let normUrl = String(url).trim();
    try {
      normUrl = new URL(normUrl).toString();
    } catch {
      // keep raw
    }
    const hdrs = options.headers && typeof options.headers === 'object' ? options.headers : {};
    const rawEntries = Array.isArray(hdrs)
      ? hdrs.filter(pair => Array.isArray(pair) && pair.length >= 2)
      : typeof hdrs.entries === 'function'
        ? Array.from(hdrs.entries())
        : Object.entries(hdrs);
    const headerEntries = rawEntries
      .filter(([, v]) => v !== undefined && v !== null && v !== '')
      .map(([k, v]) => [String(k).toLowerCase().trim(), Array.isArray(v) ? v.join(',') : String(v)])
      .sort(([a, av], [b, bv]) => (a < b ? -1 : a > b ? 1 : av < bv ? -1 : av > bv ? 1 : 0));
    const headerKey = headerEntries
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
      .join('&');
    return `${method}::${normUrl}::${headerKey}`;
  }

  _setCacheEntry(cacheKey, response) {
    const maxEntries = this.config.maxCacheEntries;
    if (Number.isFinite(maxEntries) && maxEntries <= 0) {
      return;
    }
    if (this.cache.has(cacheKey)) {
      this.cache.delete(cacheKey);
    }
    const now = this.nowFn();
    if (Number.isFinite(maxEntries) && this.cache.size >= maxEntries) {
      for (const [k, entry] of this.cache.entries()) {
        if (now >= entry.expiresAt) {
          this.cache.delete(k);
        }
      }
      while (this.cache.size >= maxEntries) {
        const oldestKey = this.cache.keys().next().value;
        if (oldestKey === undefined) break;
        this.cache.delete(oldestKey);
      }
    }
    this.cache.set(cacheKey, {
      response: cloneResponseForCaller(response),
      expiresAt: now + this.config.cacheTtlMs
    });
  }

  /**
   * Executes an outbound HTTP request through the Noise Governor:
   * 1. Returns cached response if `GET` is in TTL cache (`cacheHits++`, `duplicatesAvoided++`).
   * 2. Coalesces concurrent identical `GET` requests via singleflight (`duplicatesAvoided++`).
   * 3. Enforces per-host & global concurrency semaphores, `429`/`503` backoff windows,
   *    per-host token bucket rate limiting, and uniform jitter.
   *
   * @param {string} url
   * @param {object | Function} [options={}]
   * @param {Function} [fetcher=globalThis.fetch]
   */
  async execute(url, options = {}, fetcher = globalThis.fetch) {
    if (typeof options === 'function') {
      fetcher = options;
      options = {};
    }
    const opts = options || {};
    const hostState = this._getHostState(url);

    this.totals.requests += 1;
    hostState.requests += 1;

    const method = String(opts.method || 'GET').toUpperCase();
    const isCoalesceableGet =
      this.profile !== 'off' &&
      method === 'GET' &&
      !opts.body &&
      opts.cache !== false;

    const cacheKey = isCoalesceableGet ? this._buildCacheKey(url, opts) : null;

    if (isCoalesceableGet) {
      // 1. Check TTL response cache
      if (this.config.cacheTtlMs > 0 && this.cache.has(cacheKey)) {
        const entry = this.cache.get(cacheKey);
        if (this.nowFn() < entry.expiresAt) {
          // Refresh LRU order
          this.cache.delete(cacheKey);
          this.cache.set(cacheKey, entry);
          this.totals.cacheHits += 1;
          this.totals.duplicatesAvoided += 1;
          hostState.cacheHits += 1;
          hostState.duplicatesAvoided += 1;
          return cloneResponseForCaller(entry.response);
        }
        this.cache.delete(cacheKey);
      }

      // 2. Check in-flight singleflight coalescing map
      if (this.inFlightGets.has(cacheKey)) {
        this.totals.duplicatesAvoided += 1;
        hostState.duplicatesAvoided += 1;
        const sharedResponse = await this.inFlightGets.get(cacheKey);
        return cloneResponseForCaller(sharedResponse);
      }
    }

    const runRequest = async () => {
      await hostState.semaphore.acquire();
      let globalAcquired = false;
      try {
        // Wait out any active host backoff window from earlier 429/503 responses
        const nowBeforeBackoff = this.nowFn();
        if (hostState.backoffUntil > nowBeforeBackoff) {
          const backoffWaitMs = hostState.backoffUntil - nowBeforeBackoff;
          await this.sleepFn(backoffWaitMs);
        }

        // Reserve token from per-host token bucket + jitter
        const tokenWaitMs = this._reserveTokenWaitMs(hostState);
        const jitterWaitMs = this._computeJitterMs();
        const totalWaitMs = tokenWaitMs + jitterWaitMs;
        if (totalWaitMs > 0) {
          await this.sleepFn(totalWaitMs);
        }

        await this.globalSemaphore.acquire();
        globalAcquired = true;

        const response = await fetcher(url, opts);

        const status = response?.status ?? 200;
        const headers = response?.headers ?? {};
        this.recordResponse(url, status, headers);

        // Cache successful GET responses in TTL cache
        if (
          isCoalesceableGet &&
          this.config.cacheTtlMs > 0 &&
          status >= 200 &&
          status < 400
        ) {
          this._setCacheEntry(cacheKey, response);
        }

        return response;
      } finally {
        if (globalAcquired) {
          this.globalSemaphore.release();
        }
        hostState.semaphore.release();
      }
    };

    if (!isCoalesceableGet) {
      return runRequest();
    }

    const flightPromise = runRequest();
    this.inFlightGets.set(cacheKey, flightPromise);

    try {
      const result = await flightPromise;
      return cloneResponseForCaller(result);
    } finally {
      this.inFlightGets.delete(cacheKey);
    }
  }

  /**
   * Returns a live telemetry snapshot of the Noise Governor.
   *
   * @returns {{
   *   profile: string,
   *   totals: { requests: number, throttled: number, backoffHits: number, duplicatesAvoided: number, cacheHits: number },
   *   hosts: Record<string, object>
   * }}
   */
  snapshot() {
    const hostsSnapshot = {};
    for (const [host, state] of this.hosts.entries()) {
      hostsSnapshot[host] = {
        host,
        requests: state.requests,
        inFlight: state.semaphore.current,
        peakInFlight: state.semaphore.peak,
        throttled: state.throttled,
        backoffHits: state.backoffHits,
        duplicatesAvoided: state.duplicatesAvoided,
        cacheHits: state.cacheHits,
        backoffUntil: state.backoffUntil,
        backoffAttempts: state.backoffAttempts
      };
    }

    return {
      profile: this.profile,
      totals: { ...this.totals },
      hosts: hostsSnapshot
    };
  }
}
