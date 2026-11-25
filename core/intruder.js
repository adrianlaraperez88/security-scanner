/**
 * Burp Suite Intruder (`§marker§` Sniper / Battering Ram / Pitchfork / Cluster Bomb)
 * and Autorize 3-Context BOLA / IDOR / BFLA Differential Matrix Engine.
 *
 * All network requests execute strictly through governed fetch (`createGovernedFetch`),
 * enforcing SSRF guards, cloud metadata blocking, SecScan ResolveCache + Pinned Source-IP
 * transport, TargetPinStore, Scope/Deny rules, and NoiseGovernor pacing.
 */

import { createGovernedFetch } from './fetch.js';
import { compareResponses } from './decoder-comparer.js';

export const MAX_INTRUDER_POSITIONS = 16;
export const MAX_INTRUDER_REQUESTS = 250;
export const MAX_INTRUDER_CONCURRENCY = 10;
export const VALID_ATTACK_MODES = new Set([
  'sniper',
  'battering_ram',
  'pitchfork',
  'cluster_bomb'
]);

const AUTH_HEADER_NAMES = new Set([
  'authorization',
  'cookie',
  'x-api-key',
  'x-auth-token',
  'x-access-token',
  'x-session-token',
  'x-csrf-token',
  'x-xsrf-token'
]);

const NESTED_QUANTIFIER_RE = /\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*{]/;

function compileSafeGrepRegex(pattern) {
  const str = String(pattern ?? '').trim();
  if (!str || str.length > 256) return null;
  if (NESTED_QUANTIFIER_RE.test(str)) return null;
  try {
    return new RegExp(str, 'i');
  } catch {
    return null;
  }
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
 * Parses `§baseline§` position markers across `url`, `headers`, and `body`.
 *
 * @param {{
 *   url: string,
 *   method?: string,
 *   headers?: Record<string, string>,
 *   body?: string
 * }} template
 */
export function parseIntruderTemplate(template = {}) {
  const rawUrl = String(template.url || '').trim();
  if (!rawUrl) {
    throw new Error('Intruder template requires a non-empty target URL');
  }
  const method = String(template.method || 'GET').trim().toUpperCase();
  const rawHeaders = template.headers && typeof template.headers === 'object' ? { ...template.headers } : {};
  const rawBody = template.body !== undefined && template.body !== null ? String(template.body) : '';

  const positions = [];
  const markerRe = /§([^§]*)§/g;

  const tokenizeString = (str, location, headerName = null) => {
    const segments = [];
    let lastIdx = 0;
    let match;
    markerRe.lastIndex = 0;
    while ((match = markerRe.exec(str)) !== null) {
      if (positions.length >= MAX_INTRUDER_POSITIONS) {
        throw new Error(`Intruder template exceeds maximum allowed positions (${MAX_INTRUDER_POSITIONS})`);
      }
      if (match.index > lastIdx) {
        segments.push({ type: 'literal', value: str.slice(lastIdx, match.index) });
      }
      const posIndex = positions.length;
      const baselineValue = match[1] || '';
      positions.push({
        index: posIndex,
        location,
        ...(headerName ? { headerName } : {}),
        baselineValue
      });
      segments.push({ type: 'position', index: posIndex, baselineValue });
      lastIdx = match.index + match[0].length;
    }
    if (lastIdx < str.length) {
      segments.push({ type: 'literal', value: str.slice(lastIdx) });
    }
    if (segments.length === 0) {
      segments.push({ type: 'literal', value: str });
    }
    return segments;
  };

  const urlSegments = tokenizeString(rawUrl, 'url');
  const headerSegmentsMap = {};
  for (const [k, v] of Object.entries(rawHeaders)) {
    headerSegmentsMap[k] = tokenizeString(String(v ?? ''), 'header', k);
  }
  const bodySegments = tokenizeString(rawBody, 'body');

  const renderSegments = (segments, values, encodeForUrl = false) =>
    segments
      .map(seg => {
        if (seg.type === 'literal') return seg.value;
        const val = values[seg.index] !== undefined ? String(values[seg.index]) : seg.baselineValue;
        return encodeForUrl ? encodeURIComponent(val) : val;
      })
      .join('');

  const renderRequest = (positionValues = [], options = {}) => {
    const encodeUrlPayloads = options.encodeUrlPayloads !== false;
    const url = renderSegments(urlSegments, positionValues, encodeUrlPayloads);
    const headers = {};
    for (const [k, segs] of Object.entries(headerSegmentsMap)) {
      headers[k] = renderSegments(segs, positionValues, false);
    }
    const body = renderSegments(bodySegments, positionValues, false);
    return {
      url,
      method,
      headers,
      ...(body ? { body } : {})
    };
  };

  return {
    method,
    positions,
    baselineValues: positions.map(p => p.baselineValue),
    renderRequest
  };
}

/**
 * Generates payload tuples according to the selected Burp Intruder attack mode:
 *  - `sniper`: One payload list applied to one position at a time while others hold baseline values.
 *  - `battering_ram`: One payload list placed into all positions simultaneously.
 *  - `pitchfork`: Multiple payload lists stepped in parallel lockstep (`list_k[i]`).
 *  - `cluster_bomb`: Cartesian product across multiple payload lists (`list_1[i] × list_2[j]`).
 *
 * @param {{
 *   positions: Array<{ index: number, baselineValue: string }>,
 *   payloadSets: string[][] | string[],
 *   attackMode?: 'sniper' | 'battering_ram' | 'pitchfork' | 'cluster_bomb',
 *   maxRequests?: number
 * }} params
 */
export function buildIntruderPayloads(params = {}) {
  const positions = Array.isArray(params.positions) ? params.positions : [];
  const mode = String(params.attackMode || 'sniper').trim().toLowerCase();
  if (!VALID_ATTACK_MODES.has(mode)) {
    throw new Error(`Invalid Intruder attackMode "${params.attackMode}". Must be one of: ${Array.from(VALID_ATTACK_MODES).join(', ')}`);
  }
  if (positions.length === 0) {
    throw new Error('Intruder template contains 0 §marker§ positions');
  }

  const maxRequests = Math.min(
    MAX_INTRUDER_REQUESTS,
    Math.max(1, Number(params.maxRequests) || MAX_INTRUDER_REQUESTS)
  );

  // Normalize payloadSets into Array<Array<string>>
  let sets = [];
  if (Array.isArray(params.payloadSets)) {
    if (params.payloadSets.length > 0 && Array.isArray(params.payloadSets[0])) {
      sets = params.payloadSets.map(arr => (Array.isArray(arr) ? arr.map(v => String(v ?? '')) : []));
    } else {
      sets = [params.payloadSets.map(v => String(v ?? ''))];
    }
  }
  if (sets.length === 0 || sets[0].length === 0) {
    throw new Error('Intruder requires at least one non-empty payload list');
  }

  const baselineValues = positions.map(p => String(p.baselineValue ?? ''));
  const plan = [];

  if (mode === 'sniper') {
    const primaryList = sets[0];
    for (let posIdx = 0; posIdx < positions.length; posIdx++) {
      for (const payload of primaryList) {
        if (plan.length >= maxRequests) break;
        const values = [...baselineValues];
        values[posIdx] = payload;
        plan.push({
          step: plan.length + 1,
          attackMode: mode,
          activePosition: posIdx,
          payloads: [payload],
          positionValues: values
        });
      }
      if (plan.length >= maxRequests) break;
    }
  } else if (mode === 'battering_ram') {
    const primaryList = sets[0];
    for (const payload of primaryList) {
      if (plan.length >= maxRequests) break;
      const values = positions.map(() => payload);
      plan.push({
        step: plan.length + 1,
        attackMode: mode,
        activePosition: 'all',
        payloads: [payload],
        positionValues: values
      });
    }
  } else if (mode === 'pitchfork') {
    const minLen = Math.min(...positions.map((_, idx) => (sets[idx] || sets[0]).length));
    for (let i = 0; i < minLen && plan.length < maxRequests; i++) {
      const values = positions.map((_, idx) => {
        const list = sets[idx] || sets[0];
        return list[i];
      });
      plan.push({
        step: plan.length + 1,
        attackMode: mode,
        activePosition: 'lockstep',
        payloads: values,
        positionValues: values
      });
    }
  } else if (mode === 'cluster_bomb') {
    const lists = positions.map((_, idx) => sets[idx] || sets[0]);
    const walk = (depth, currentValues) => {
      if (plan.length >= maxRequests) return;
      if (depth === positions.length) {
        plan.push({
          step: plan.length + 1,
          attackMode: mode,
          activePosition: 'cartesian',
          payloads: [...currentValues],
          positionValues: [...currentValues]
        });
        return;
      }
      for (const item of lists[depth]) {
        if (plan.length >= maxRequests) return;
        currentValues.push(item);
        walk(depth + 1, currentValues);
        currentValues.pop();
      }
    };
    walk(0, []);
  }

  return plan;
}

/**
 * Executes a governed Burp Intruder campaign and computes status, length, word,
 * line, latency, grep-match, and grep-extract anomalies against the baseline response.
 *
 * @param {{
 *   url: string,
 *   method?: string,
 *   headers?: Record<string, string>,
 *   body?: string,
 *   payloadSets: string[][] | string[],
 *   attackMode?: 'sniper' | 'battering_ram' | 'pitchfork' | 'cluster_bomb',
 *   grepMatch?: string[],
 *   grepExtract?: string[],
 *   encodeUrlPayloads?: boolean,
 *   maxRequests?: number,
 *   concurrency?: number
 * }} config
 * @param {{
 *   fetchWithRetry?: Function,
 *   allowPrivate?: boolean,
 *   sourceIp?: string,
 *   sourceIpMap?: object,
 *   scopeRules?: Array,
 *   trafficStore?: object,
 *   timeout?: number
 * }} [options={}]
 */
export async function runIntruderCampaign(config = {}, options = {}) {
  const parsedTemplate = parseIntruderTemplate(config);
  const plan = buildIntruderPayloads({
    positions: parsedTemplate.positions,
    payloadSets: config.payloadSets,
    attackMode: config.attackMode || 'sniper',
    maxRequests: config.maxRequests
  });

  const fetcher = typeof options.fetchWithRetry === 'function'
    ? options.fetchWithRetry
    : createGovernedFetch({
        allowPrivate: Boolean(options.allowPrivate),
        sourceIp: options.sourceIp || null,
        sourceIpMap: options.sourceIpMap || null,
        scopeRules: options.scopeRules || [],
        trafficStore: options.trafficStore || null,
        enforceDnsValidation: true,
        ...(options.dnsResolver ? { dnsResolver: options.dnsResolver } : {}),
        timeout: Number(options.timeout) || 10000,
        retries: 0
      });

  const grepMatches = Array.isArray(config.grepMatch)
    ? config.grepMatch.map(s => String(s || '').trim()).filter(Boolean).slice(0, 20)
    : [];
  const grepExtracts = Array.isArray(config.grepExtract)
    ? config.grepExtract.map(compileSafeGrepRegex).filter(Boolean).slice(0, 10)
    : [];

  const executeSingle = async (rendered) => {
    const startMs = Date.now();
    try {
      const res = await fetcher(rendered.url, {
        method: rendered.method,
        headers: rendered.headers,
        ...(rendered.body ? { body: rendered.body } : {}),
        followRedirects: false
      });
      const durationMs = Math.max(0, Date.now() - startMs);
      const text = String(res?.text || '');
      return {
        ok: true,
        status: Number(res?.status ?? 0),
        headers: res?.headers || {},
        text,
        byteLength: Buffer.byteLength(text, 'utf8'),
        wordCount: countWords(text),
        lineCount: countLines(text),
        durationMs,
        trafficId: res?.trafficId || null,
        resolvedIp: res?.resolvedIp || null
      };
    } catch (err) {
      if (err?.isGovernanceBlock) throw err;
      return {
        ok: false,
        status: 0,
        headers: {},
        text: '',
        byteLength: 0,
        wordCount: 0,
        lineCount: 0,
        durationMs: Math.max(0, Date.now() - startMs),
        error: err?.message || String(err),
        trafficId: null
      };
    }
  };

  // 1. Baseline request using baseline position values
  const baselineReq = parsedTemplate.renderRequest(parsedTemplate.baselineValues, {
    encodeUrlPayloads: config.encodeUrlPayloads
  });
  const baselineRes = await executeSingle(baselineReq);

  // 2. Execute payload plan with bounded concurrency
  const concurrency = Math.min(
    MAX_INTRUDER_CONCURRENCY,
    Math.max(1, Number(config.concurrency) || 4)
  );
  const results = new Array(plan.length);
  let cursor = 0;

  const worker = async () => {
    while (cursor < plan.length) {
      const idx = cursor++;
      const item = plan[idx];
      const rendered = parsedTemplate.renderRequest(item.positionValues, {
        encodeUrlPayloads: config.encodeUrlPayloads
      });
      const res = await executeSingle(rendered);

      const matchedGrep = grepMatches.filter(needle => res.text.toLowerCase().includes(needle.toLowerCase()));
      const extracted = {};
      for (const rx of grepExtracts) {
        const m = rx.exec(res.text);
        if (m) {
          extracted[rx.source] = (m[1] !== undefined ? m[1] : m[0]).slice(0, 200);
        }
      }

      const statusChanged = baselineRes.ok && res.ok && res.status !== baselineRes.status;
      const byteDelta = res.byteLength - baselineRes.byteLength;
      const wordDelta = res.wordCount - baselineRes.wordCount;
      const lineDelta = res.lineCount - baselineRes.lineCount;
      const durationDeltaMs = res.durationMs - baselineRes.durationMs;

      const anomalyReasons = [];
      let anomalyScore = 0;

      if (statusChanged) {
        anomalyScore += 40;
        anomalyReasons.push(`HTTP status changed (${baselineRes.status} -> ${res.status})`);
      }
      if (matchedGrep.length > 0) {
        anomalyScore += 45;
        anomalyReasons.push(`Grep match: ${matchedGrep.join(', ')}`);
      }
      const relByteDiff = baselineRes.byteLength > 0
        ? Math.abs(byteDelta) / baselineRes.byteLength
        : Math.abs(byteDelta);
      if (Math.abs(byteDelta) >= 32 && relByteDiff >= 0.25) {
        anomalyScore += 25;
        anomalyReasons.push(`Byte length delta (${byteDelta > 0 ? `+${byteDelta}` : byteDelta} bytes)`);
      }
      if (durationDeltaMs >= 2500) {
        anomalyScore += 30;
        anomalyReasons.push(`Response time spike (+${durationDeltaMs}ms)`);
      }
      // Check if payload itself was reflected unescaped
      const reflectedPayloads = item.payloads.filter(p => p.length >= 4 && res.text.includes(p));
      if (reflectedPayloads.length > 0) {
        anomalyScore += 20;
        anomalyReasons.push(`Payload reflected verbatim (${reflectedPayloads[0].slice(0, 48)})`);
      }

      results[idx] = {
        step: item.step,
        activePosition: item.activePosition,
        payloads: item.payloads,
        positionValues: item.positionValues,
        url: rendered.url,
        method: rendered.method,
        status: res.status,
        byteLength: res.byteLength,
        byteDelta,
        wordCount: res.wordCount,
        wordDelta,
        lineCount: res.lineCount,
        lineDelta,
        durationMs: res.durationMs,
        durationDeltaMs,
        matchedGrep,
        extracted,
        reflectedPayloads,
        anomalyScore: Math.min(100, anomalyScore),
        isInteresting: anomalyScore >= 25,
        anomalyReasons,
        trafficId: res.trafficId,
        error: res.error || null
      };
    }
  };

  await Promise.all(Array.from({ length: Math.min(concurrency, plan.length) }, () => worker()));

  const interestingResults = results.filter(r => r && r.isInteresting);

  return {
    attackMode: String(config.attackMode || 'sniper').toLowerCase(),
    positions: parsedTemplate.positions,
    totalPayloads: results.length,
    interestingCount: interestingResults.length,
    baseline: {
      url: baselineReq.url,
      method: baselineReq.method,
      status: baselineRes.status,
      byteLength: baselineRes.byteLength,
      wordCount: baselineRes.wordCount,
      lineCount: baselineRes.lineCount,
      durationMs: baselineRes.durationMs,
      trafficId: baselineRes.trafficId
    },
    results,
    interestingResults
  };
}

function stripAuthHeaders(headers = {}) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    if (!AUTH_HEADER_NAMES.has(String(k).toLowerCase())) {
      out[k] = v;
    }
  }
  return out;
}

/**
 * Burp Autorize 3-Context BOLA / IDOR / BFLA Differential Matrix Engine.
 * Replays target endpoints across:
 *   1. `primary` (Owner / Admin authenticated session)
 *   2. `secondary` (Low-Privilege / Cross-Tenant User B session, optional)
 *   3. `unauthenticated` (All auth/cookie headers stripped)
 *
 * Compares responses against each other and a 404 canary to accurately detect
 * Broken Object Level Authorization (BOLA/IDOR) and Broken Function Level Authorization (BFLA).
 *
 * @param {{
 *   endpoints: Array<{ url: string, method?: string, headers?: Record<string, string>, body?: string }> | string[],
 *   primaryHeaders?: Record<string, string>,
 *   secondaryHeaders?: Record<string, string> | null
 * }} config
 * @param {{
 *   fetchWithRetry?: Function,
 *   allowPrivate?: boolean,
 *   sourceIp?: string,
 *   sourceIpMap?: object,
 *   scopeRules?: Array,
 *   trafficStore?: object,
 *   timeout?: number
 * }} [options={}]
 */
export async function runAutorizeMatrix(config = {}, options = {}) {
  const rawEndpoints = Array.isArray(config.endpoints) ? config.endpoints : [];
  if (rawEndpoints.length === 0) {
    throw new Error('Autorize matrix requires at least one endpoint in endpoints[]');
  }
  if (rawEndpoints.length > 50) {
    throw new Error('Autorize matrix is bounded to at most 50 endpoints per run');
  }

  const primaryExtra = config.primaryHeaders && typeof config.primaryHeaders === 'object'
    ? config.primaryHeaders
    : {};
  const secondaryExtra = config.secondaryHeaders && typeof config.secondaryHeaders === 'object'
    ? config.secondaryHeaders
    : null;
  const hasSecondaryContext = Boolean(secondaryExtra && Object.keys(secondaryExtra).length > 0);

  const fetcher = typeof options.fetchWithRetry === 'function'
    ? options.fetchWithRetry
    : createGovernedFetch({
        allowPrivate: Boolean(options.allowPrivate),
        sourceIp: options.sourceIp || null,
        sourceIpMap: options.sourceIpMap || null,
        scopeRules: options.scopeRules || [],
        trafficStore: options.trafficStore || null,
        enforceDnsValidation: true,
        ...(options.dnsResolver ? { dnsResolver: options.dnsResolver } : {}),
        timeout: Number(options.timeout) || 10000,
        retries: 0
      });

  const canaryByOrigin = new Map();
  const getOriginCanary = async (targetUrl) => {
    const parsed = new URL(targetUrl);
    if (canaryByOrigin.has(parsed.origin)) {
      return canaryByOrigin.get(parsed.origin);
    }
    const canaryUrl = new URL('/.secscan-autorize-canary-404', parsed.origin).href;
    try {
      const res = await fetcher(canaryUrl, { method: 'GET', followRedirects: false });
      const info = { status: Number(res?.status ?? 404), text: String(res?.text || '') };
      canaryByOrigin.set(parsed.origin, info);
      return info;
    } catch (err) {
      if (err?.isGovernanceBlock) throw err;
      const info = { status: 404, text: '' };
      canaryByOrigin.set(parsed.origin, info);
      return info;
    }
  };

  const matrix = [];

  for (const item of rawEndpoints) {
    const ep = typeof item === 'string' ? { url: item, method: 'GET' } : item;
    const url = String(ep?.url || '').trim();
    if (!url) continue;
    const method = String(ep?.method || 'GET').trim().toUpperCase();
    const baseHeaders = ep?.headers && typeof ep.headers === 'object' ? { ...ep.headers } : {};
    const body = ep?.body !== undefined && ep?.body !== null ? String(ep.body) : undefined;

    const canary = await getOriginCanary(url);

    // 1. Primary (Owner / Admin) request
    const primaryHeaders = { ...baseHeaders, ...primaryExtra };
    const primaryRes = await fetcher(url, {
      method,
      headers: primaryHeaders,
      ...(body ? { body } : {}),
      followRedirects: false
    });
    const primaryBody = String(primaryRes?.text || '');
    const primaryStatus = Number(primaryRes?.status ?? 0);

    // 2. Unauthenticated request (all auth/cookie headers removed)
    const unauthHeaders = stripAuthHeaders(primaryHeaders);
    const unauthRes = await fetcher(url, {
      method,
      headers: unauthHeaders,
      ...(body ? { body } : {}),
      followRedirects: false
    });
    const unauthBody = String(unauthRes?.text || '');
    const unauthStatus = Number(unauthRes?.status ?? 0);

    // 3. Secondary (Low-Privilege / User B) request if provided
    let secondaryRes = null;
    let secondaryBody = '';
    let secondaryStatus = null;
    if (hasSecondaryContext) {
      const secHeaders = { ...stripAuthHeaders(primaryHeaders), ...secondaryExtra };
      secondaryRes = await fetcher(url, {
        method,
        headers: secHeaders,
        ...(body ? { body } : {}),
        followRedirects: false
      });
      secondaryBody = String(secondaryRes?.text || '');
      secondaryStatus = Number(secondaryRes?.status ?? 0);
    }

    const unauthVsPrimary = compareResponses(
      { status: primaryStatus, headers: primaryRes?.headers, body: primaryBody },
      { status: unauthStatus, headers: unauthRes?.headers, body: unauthBody }
    );
    const unauthVsCanary = compareResponses(
      { status: canary.status, body: canary.text },
      { status: unauthStatus, body: unauthBody }
    );

    const secondaryVsPrimary = hasSecondaryContext
      ? compareResponses(
          { status: primaryStatus, headers: primaryRes?.headers, body: primaryBody },
          { status: secondaryStatus, headers: secondaryRes?.headers, body: secondaryBody }
        )
      : null;

    const primarySucceeded = primaryStatus >= 200 && primaryStatus < 300 && primaryBody.length >= 16;
    const isErrorPayload = (text) =>
      /"(?:error|message)"\s*:\s*"(?:unauthorized|unauthenticated|forbidden|access denied|not logged in|invalid token)"/i.test(text);

    const unauthDenied =
      unauthStatus === 401 ||
      unauthStatus === 403 ||
      unauthStatus === 404 ||
      (unauthStatus >= 300 && unauthStatus < 400) ||
      isErrorPayload(unauthBody) ||
      (canary.text.length > 0 && unauthVsCanary.similarityRatio >= 0.90);

    const secondaryDenied = !hasSecondaryContext
      ? true
      : secondaryStatus === 401 ||
        secondaryStatus === 403 ||
        secondaryStatus === 404 ||
        (secondaryStatus >= 300 && secondaryStatus < 400) ||
        isErrorPayload(secondaryBody);

    let verdict = 'ENFORCED';
    let status = 'SAFE';
    let severity = 'NONE';
    let detail = 'Authorization enforced properly across contexts.';

    const unauthHighSimilarity =
      unauthVsPrimary.similarityRatio >= 0.75 ||
      Boolean(unauthVsPrimary.jsonDiff && unauthVsPrimary.jsonDiff.keyOverlapRatio >= 0.80 && unauthVsPrimary.jsonDiff.rightKeyCount >= 2);

    const secondaryHighSimilarity =
      secondaryVsPrimary &&
      (secondaryVsPrimary.similarityRatio >= 0.75 ||
        Boolean(secondaryVsPrimary.jsonDiff && secondaryVsPrimary.jsonDiff.keyOverlapRatio >= 0.80 && secondaryVsPrimary.jsonDiff.rightKeyCount >= 2));

    if (primarySucceeded && hasSecondaryContext && unauthDenied && !secondaryDenied && secondaryStatus === primaryStatus && secondaryHighSimilarity) {
      verdict = 'BYPASSED_LOW_PRIV';
      status = 'VULNERABLE';
      severity = 'HIGH';
      detail = `Cross-user / low-privilege BOLA/IDOR/BFLA bypass on ${method} ${url}: unauthenticated access was denied (HTTP ${unauthStatus}), but secondary low-privilege context received HTTP ${secondaryStatus} matching primary data (similarity=${secondaryVsPrimary.similarityRatio}).`;
    } else if (primarySucceeded && !unauthDenied && unauthStatus === primaryStatus && unauthHighSimilarity) {
      // Distinguish sensitive authenticated API/data endpoints from public pages
      const looksSensitiveData =
        /"(?:id|user_id|userId|email|token|api_key|apiKey|role|permissions|balance|account|ssn|phone|address|secret|orders|invoices)"\s*:/i.test(unauthBody) ||
        /\/(?:api|admin|internal|v[1-9]|graphql|account|profile|users|orders|billing)\b/i.test(url);
      if (looksSensitiveData) {
        verdict = 'BYPASSED_UNAUTH';
        status = 'VULNERABLE';
        severity = 'CRITICAL';
        detail = `Unauthenticated authorization bypass on ${method} ${url}: stripping auth headers still returned HTTP ${unauthStatus} with private/API resource payload matching authenticated primary response (similarity=${unauthVsPrimary.similarityRatio}).`;
      } else {
        verdict = 'PUBLIC_ENDPOINT';
        status = 'SAFE';
        severity = 'NONE';
        detail = `Endpoint ${method} ${url} returned identical public content across authenticated and unauthenticated contexts.`;
      }
    }

    matrix.push({
      url,
      method,
      verdict,
      status,
      severity,
      detail,
      primary: {
        status: primaryStatus,
        byteLength: Buffer.byteLength(primaryBody, 'utf8'),
        trafficId: primaryRes?.trafficId || null
      },
      secondary: hasSecondaryContext
        ? {
            status: secondaryStatus,
            byteLength: Buffer.byteLength(secondaryBody, 'utf8'),
            similarityToPrimary: secondaryVsPrimary.similarityRatio,
            jsonKeyOverlap: secondaryVsPrimary.jsonDiff?.keyOverlapRatio ?? null,
            trafficId: secondaryRes?.trafficId || null
          }
        : null,
      unauthenticated: {
        status: unauthStatus,
        byteLength: Buffer.byteLength(unauthBody, 'utf8'),
        similarityToPrimary: unauthVsPrimary.similarityRatio,
        jsonKeyOverlap: unauthVsPrimary.jsonDiff?.keyOverlapRatio ?? null,
        trafficId: unauthRes?.trafficId || null
      }
    });
  }

  const vulnerableCount = matrix.filter(m => m.status === 'VULNERABLE').length;
  return {
    totalEndpoints: matrix.length,
    vulnerableCount,
    hasSecondaryContext,
    matrix
  };
}
