/**
 * False-Positive Reduction & Confidence Classification Engine (`core/fp-engine.js`).
 *
 * Provides bounded, ReDoS-safe, O(n) linear-time helpers for:
 *  - Framework soft-404 marker & structural template detection
 *  - HTML/text structural Jaccard similarity (3-gram word/tag shingles + HTML tag skeleton)
 *  - Differential probe verification (attack vs baseline-404 vs negative-control)
 *  - Verbatim S1 evidence quote augmentation from captured HTTP traces
 *  - Non-mutating finding confidence tier & score classification
 */

const MAX_BODY_CHARS = 65536;
const MAX_SIMILARITY_CHARS = 32768;
const MAX_DETAIL_CHARS = 8192;
const MIN_EVIDENCE_QUOTE_LEN = 8;

const WORD_TAG_TOKEN_RE = /<\/?[a-z][a-z0-9:-]{0,31}|[a-z0-9_-]{1,64}/g;
const HTML_TAG_TOKEN_RE = /<\/?([a-z][a-z0-9:-]{0,31})(?=[\s/>]|$)/g;
const TITLE_SOFT_404_RE = /<title>\s*404\s*:\s*this page could not be found/i;
const JSON_STATUS_404_RE = /"statuscode"\s*:\s*404/i;
const SYNTHETIC_PROSE_QUOTE_RE = /^(?:HTTP\s+\d{3}\s+non-HTML\s+response|x-middleware-subrequest\s+bypassed|Protected\s+path\s+\S+\s+returned\s+HTTP\s+\d{3}|Endpoint\s+returned\s+HTTP\s+\d{3})\b/i;
const HEURISTIC_DETAIL_RE = /\b(?:backport[a-z]{0,8}|ranges?|wildcards?|constraints?|without\s+version)\b/i;

const PASSIVE_VERSION_CHECK_IDS = new Set([
  'cve-apache-httpd',
  'cve-tomcat',
  'cve-php-ecosystem',
  'cve-nginx-http3',
  'cve-nginx-tls',
  'cve-2026-123007',
  'cve-2026-123633',
  'cve-2026-123634',
  'cve-2026-114938',
  'cve-jdk-advisories',
  'cve-node-express',
  'cve-python-web',
  'cve-wordpress-ecosystem',
  'php-version',
  'server-disclosure',
  'os-security'
]);

const ACTIVE_EXPLOIT_DETAIL_RE = /\b(?:rce\s+confirmed|executed|command\s+execution|bypassed|traversal\s+confirmed|open\s+redirect|reflected|ssti|ssrf|sqli|xss|injection\s+confirmed|flight\s+post|server\s+action\s+post)\b/i;
const PASSIVE_VERSION_DETAIL_RE = /\b(?:passive\s+version|version\s+match|banner\s+version|header\s+version|version\s+disclosure|discloses?\s+(?:vulnerable\s+)?version|package\.json|package-lock\.json|requirements\.txt|reached\s+eol|is\s+within\s+range|is\s+below\s+patched|ships\s+vulnerable|x-nextjs-version|x-powered-by)\b/i;

const DEFAULT_NOISE_HEADER_KEYS = new Set([
  'user-agent',
  'accept-encoding',
  'connection',
  'host',
  'content-length'
]);

/**
 * Common framework soft-404 body markers.
 */
export const SOFT_404_MARKERS = Object.freeze([
  'next-error-h1',
  'This page could not be found',
  '<title>404:',
  '"statusCode":404',
  'Page Not Found',
  'Whitelabel Error Page'
]);

function getResponseText(res) {
  if (typeof res === 'string') return res;
  if (!res || typeof res !== 'object') return '';
  if (typeof res.text === 'string') return res.text;
  if (typeof res.body === 'string') return res.body;
  if (typeof res.responseSnippet === 'string') return res.responseSnippet;
  return '';
}

function normalizeTextForSimilarity(raw) {
  if (raw === null || raw === undefined) return '';
  const str = (typeof raw === 'string' ? raw : String(raw)).slice(0, MAX_SIMILARITY_CHARS);
  return str.toLowerCase().replace(/\s+/g, ' ').trim();
}

function extractShingleSet(normText) {
  const shingles = new Set();
  if (!normText) return shingles;

  const wordTagTokens = normText.match(WORD_TAG_TOKEN_RE) || [];
  if (wordTagTokens.length >= 3) {
    for (let i = 0; i <= wordTagTokens.length - 3; i++) {
      shingles.add(`w:${wordTagTokens[i]} ${wordTagTokens[i + 1]} ${wordTagTokens[i + 2]}`);
    }
  } else if (wordTagTokens.length > 0) {
    for (const tok of wordTagTokens) {
      shingles.add(`w1:${tok}`);
    }
    if (wordTagTokens.length === 2) {
      shingles.add(`w2:${wordTagTokens[0]} ${wordTagTokens[1]}`);
    }
  }

  const tagTokens = [];
  HTML_TAG_TOKEN_RE.lastIndex = 0;
  let match;
  while ((match = HTML_TAG_TOKEN_RE.exec(normText)) !== null) {
    const isClosing = match[0].startsWith('</');
    tagTokens.push(isClosing ? `/${match[1]}` : match[1]);
  }
  if (tagTokens.length >= 3) {
    for (let i = 0; i <= tagTokens.length - 3; i++) {
      shingles.add(`s:${tagTokens[i]}>${tagTokens[i + 1]}>${tagTokens[i + 2]}`);
    }
  } else if (tagTokens.length > 0) {
    shingles.add(`s1:${tagTokens.join('>')}`);
  }

  if (shingles.size === 0) {
    if (normText.length >= 3) {
      for (let i = 0; i <= normText.length - 3; i++) {
        shingles.add(`c:${normText.slice(i, i + 3)}`);
      }
    } else {
      shingles.add(`c:${normText}`);
    }
  }

  return shingles;
}

/**
 * Computes structural Jaccard similarity in `[0, 1]` using lowercase word/tag 3-gram
 * shingles and HTML tag-skeleton tokens, bounded to 32,768 chars.
 *
 * @param {string} textA
 * @param {string} textB
 * @returns {number}
 */
export function computeStructuralSimilarity(textA, textB) {
  const normA = normalizeTextForSimilarity(textA);
  const normB = normalizeTextForSimilarity(textB);

  if (!normA && !normB) return 1;
  if (!normA || !normB) return 0;
  if (normA === normB) return 1;

  const setA = extractShingleSet(normA);
  const setB = extractShingleSet(normB);

  if (setA.size === 0 && setB.size === 0) return 1;
  if (setA.size === 0 || setB.size === 0) return 0;

  let smaller = setA;
  let larger = setB;
  if (setB.size < setA.size) {
    smaller = setB;
    larger = setA;
  }

  let intersection = 0;
  for (const token of smaller) {
    if (larger.has(token)) intersection++;
  }

  const union = setA.size + setB.size - intersection;
  if (union <= 0) return 0;
  const score = intersection / union;
  return score < 0 ? 0 : (score > 1 ? 1 : score);
}

/**
 * Returns `true` if `res` is a soft-404 response:
 *  a) status is 200 and body contains explicit Next.js/SPA soft-404 markers
 *     (`next-error-h1`, `<title>404: This page could not be found`, `"statusCode":404` with `"not found"`), OR
 *  b) `baseline404Res` is provided with a non-empty body and structural similarity >= threshold (default 0.82).
 *
 * @param {object} res
 * @param {object|null} [baseline404Res=null]
 * @param {{ similarityThreshold?: number }} [options={}]
 * @returns {boolean}
 */
export function isSoft404Response(res, baseline404Res = null, options = {}) {
  if (!res || typeof res !== 'object') return false;

  const status = Number(res.status);
  const body = getResponseText(res).slice(0, MAX_BODY_CHARS);

  if (status === 200 && body) {
    const lower = body.toLowerCase();
    if (lower.includes('next-error-h1')) return true;
    if (TITLE_SOFT_404_RE.test(body)) return true;
    if (JSON_STATUS_404_RE.test(body) && lower.includes('not found')) return true;
  }

  if (baseline404Res && typeof baseline404Res === 'object') {
    const baseBody = getResponseText(baseline404Res).slice(0, MAX_BODY_CHARS);
    if (baseBody.trim().length > 0 && body.trim().length > 0) {
      const threshold = Number.isFinite(options?.similarityThreshold)
        ? options.similarityThreshold
        : 0.82;
      if (computeStructuralSimilarity(body, baseBody) >= threshold) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Verifies an active probe response against an optional baseline soft-404 response and
 * optional negative control probe response.
 *
 * @param {{
 *   baselineRes?: object|null,
 *   attackRes: object,
 *   controlRes?: object|null,
 *   validator: (res: object) => boolean
 * }} params
 * @returns {{ confirmed: boolean, reason: string }}
 */
export function verifyDifferentialProbe({
  baselineRes = null,
  attackRes,
  controlRes = null,
  validator
} = {}) {
  if (typeof validator !== 'function' || !attackRes || !validator(attackRes)) {
    return {
      confirmed: false,
      reason: 'Attack probe did not match validator'
    };
  }

  if (controlRes && typeof controlRes === 'object' && validator(controlRes)) {
    const attackText = getResponseText(attackRes);
    const controlText = getResponseText(controlRes);
    if (computeStructuralSimilarity(attackText, controlText) >= 0.85) {
      return {
        confirmed: false,
        reason: 'Negative control probe produced identical positive signal (false positive)'
      };
    }
  }

  if (baselineRes && isSoft404Response(attackRes, baselineRes)) {
    return {
      confirmed: false,
      reason: 'Attack probe matched soft-404 baseline'
    };
  }

  return {
    confirmed: true,
    reason: 'Differential verification passed'
  };
}

function sameEndpointPathname(urlA, urlB) {
  try {
    const a = new URL(urlA);
    const b = new URL(urlB);
    const pa = a.pathname.replace(/\/+$/, '') || '/';
    const pb = b.pathname.replace(/\/+$/, '') || '/';
    return a.origin === b.origin && pa === pb;
  } catch {
    return false;
  }
}

function extractHeaderLines(trace) {
  if (!trace || typeof trace !== 'object') return [];
  const lines = [];
  const seen = new Set();

  for (const field of ['responseHeaders', 'resHeaders', 'headers', 'reqHeaders', 'requestHeaders']) {
    const hdrs = trace[field];
    if (!hdrs || typeof hdrs !== 'object') continue;
    const entries = typeof hdrs.entries === 'function'
      ? Array.from(hdrs.entries())
      : Array.isArray(hdrs)
        ? hdrs
        : Object.entries(hdrs);

    for (const entry of entries) {
      if (!Array.isArray(entry) || entry.length < 2) continue;
      const key = String(entry[0] ?? '').replace(/[\r\n\t]+/g, ' ').trim();
      const val = (Array.isArray(entry[1]) ? entry[1].join(', ') : String(entry[1] ?? ''))
        .replace(/[\r\n\t]+/g, ' ')
        .replace(/\s{2,}/g, ' ')
        .trim();
      if (!key || !val) continue;
      const line = `${key}: ${val}`.slice(0, 240);
      if (!seen.has(line)) {
        seen.add(line);
        lines.push({ keyLower: key.toLowerCase(), val, line });
      }
    }
  }

  return lines;
}

function buildTraceCorpus(trace) {
  const headerLines = extractHeaderLines(trace);
  const rawBody = String(
    trace.responseSnippet || trace.responseBody || trace.resBody || trace.text || ''
  ).slice(0, MAX_BODY_CHARS);
  const rawCorpus = `${headerLines.map(h => h.line).join('\n')}\n${rawBody}`.slice(0, MAX_BODY_CHARS);
  return {
    headerLines,
    rawCorpus,
    normCorpus: normalizeQuoteWhitespace(rawCorpus)
  };
}

function findMatchingTraces(finding, capturedTraces) {
  if (finding?.trafficId) {
    const byId = capturedTraces.find(t => t && t.trafficId === finding.trafficId);
    return byId ? [byId] : [];
  }

  const candidateUrls = [
    finding?.reproduction?.url,
    finding?.url,
    finding?.target
  ].filter(u => typeof u === 'string' && u.length > 0);

  if (candidateUrls.length > 0) {
    const matched = [];
    for (const candidate of candidateUrls) {
      for (const t of capturedTraces) {
        if (t && t.url && (t.url === candidate || sameEndpointPathname(t.url, candidate))) {
          if (!matched.includes(t)) matched.push(t);
        }
      }
    }
    const non404 = matched.filter(t => Number(t.status) !== 404);
    return non404.length > 0 ? non404 : matched;
  }

  return capturedTraces.filter(t => t && typeof t === 'object');
}

function normalizeQuoteWhitespace(str) {
  return String(str ?? '').slice(0, MAX_BODY_CHARS).replace(/\s+/g, ' ').trim();
}

function pickVerbatimTraceSnippet(trace, headerLines, existingQuotes) {
  const existingNorm = new Set(existingQuotes.map(q => normalizeQuoteWhitespace(q)));

  const rawBody = String(
    trace.responseSnippet || trace.responseBody || trace.resBody || trace.text || ''
  ).slice(0, MAX_BODY_CHARS);
  const cleanBody = rawBody.replace(/[\r\n\t]+/g, ' ').replace(/\s{2,}/g, ' ').trim();
  if (cleanBody.length >= MIN_EVIDENCE_QUOTE_LEN) {
    const bodyQuote = cleanBody.slice(0, 160).trim();
    if (bodyQuote.length >= MIN_EVIDENCE_QUOTE_LEN && !existingNorm.has(normalizeQuoteWhitespace(bodyQuote))) {
      return bodyQuote;
    }
  }

  const nonNoiseHeaders = headerLines.filter(
    h => !DEFAULT_NOISE_HEADER_KEYS.has(h.keyLower) && h.val !== '<REDACTED>' && h.line.length >= MIN_EVIDENCE_QUOTE_LEN
  );
  for (const h of [...nonNoiseHeaders, ...headerLines]) {
    if (h.val === '<REDACTED>' || h.line.length < MIN_EVIDENCE_QUOTE_LEN) continue;
    if (!existingNorm.has(normalizeQuoteWhitespace(h.line))) {
      return h.line;
    }
  }

  return null;
}

/**
 * Checks whether `finding.evidenceQuotes` contains synthetic prose quotes missing from
 * its matched HTTP trace and, if so, appends a real verbatim >= 8-char snippet from
 * the trace's `responseSnippet` or `Key: Value` headers while preserving existing valid quotes.
 *
 * @param {object} finding
 * @param {Array<object>} [capturedTraces=[]]
 * @returns {object}
 */
export function ensureVerbatimEvidenceQuotes(finding, capturedTraces = []) {
  if (!finding || typeof finding !== 'object') return finding;
  if (!Array.isArray(finding.evidenceQuotes) || finding.evidenceQuotes.length === 0) return finding;
  if (!Array.isArray(capturedTraces) || capturedTraces.length === 0) return finding;

  const trace = findMatchingTraces(finding, capturedTraces)[0] || null;
  if (!trace) return finding;

  const { headerLines, rawCorpus, normCorpus } = buildTraceCorpus(trace);

  const hasMissingSyntheticQuote = finding.evidenceQuotes.some(rawQ => {
    const q = String(rawQ ?? '').slice(0, 512).trim();
    if (!q || !SYNTHETIC_PROSE_QUOTE_RE.test(q)) return false;
    const normQ = normalizeQuoteWhitespace(q);
    if (!normQ) return false;
    return !rawCorpus.includes(q) && !normCorpus.includes(normQ);
  });

  if (!hasMissingSyntheticQuote) return finding;

  const realSnippet = pickVerbatimTraceSnippet(trace, headerLines, finding.evidenceQuotes);
  if (!realSnippet) return finding;

  return {
    ...finding,
    evidenceQuotes: [...finding.evidenceQuotes, realSnippet]
  };
}

function isPassiveVersionMatch(finding, options = {}) {
  if (options?.passiveVersionMatch === false || finding?.passiveVersionMatch === false) {
    return false;
  }
  if (
    options?.passiveVersionMatch === true ||
    finding?.passiveVersionMatch === true ||
    finding?.attribution === 'passive_version'
  ) {
    return true;
  }

  const checkId = String(finding?.checkId || finding?.meta?.id || finding?.name || '')
    .trim()
    .toLowerCase();
  if (PASSIVE_VERSION_CHECK_IDS.has(checkId)) {
    return true;
  }

  const text = `${finding?.name || ''} ${finding?.detail || ''} ${finding?.reason || ''}`
    .slice(0, MAX_DETAIL_CHARS);
  if (ACTIVE_EXPLOIT_DETAIL_RE.test(text)) {
    return false;
  }
  if (PASSIVE_VERSION_DETAIL_RE.test(text)) {
    return true;
  }

  if (
    (checkId === 'cve-nextjs-react' || checkId === 'cve-spring-framework') &&
    /\b(?:affected\s+by\s+cve-|release\s+track|version\s+\d+\.\d+)/i.test(text)
  ) {
    return true;
  }

  return false;
}

/**
 * Computes `{ confidenceTier, confidenceScore }` for a finding without mutating it.
 *
 * @param {object} finding
 * @param {{ passiveVersionMatch?: boolean }} [options={}]
 * @returns {{ confidenceTier: string, confidenceScore: number }}
 */
export function classifyFindingConfidence(finding, options = {}) {
  const status = String(finding?.status || 'SAFE').toUpperCase();
  if (status !== 'VULNERABLE' && status !== 'SUSPICIOUS') {
    return { confidenceTier: 'INFORMATIONAL', confidenceScore: 100 };
  }

  if (status === 'VULNERABLE') {
    const poeLevel = Number(finding?.poeLevel ?? finding?.poe_level ?? 0);
    const verificationStatus = String(finding?.verificationStatus ?? finding?.verification_status ?? '').toLowerCase();
    const isRejected = verificationStatus === 'rejected';
    const hasTraces = Array.isArray(options?.capturedTraces) && options.capturedTraces.length > 0;
    const traceCorpora = hasTraces
      ? findMatchingTraces(finding, options.capturedTraces).map(t => buildTraceCorpus(t))
      : [];

    const hasEvidenceQuotes =
      !isRejected &&
      Array.isArray(finding?.evidenceQuotes) &&
      finding.evidenceQuotes.some(rawQ => {
        if (typeof rawQ !== 'string') return false;
        const trimmedQ = rawQ.trim().slice(0, 512);
        const normQ = normalizeQuoteWhitespace(rawQ);
        if (normQ.length < MIN_EVIDENCE_QUOTE_LEN) return false;
        if (SYNTHETIC_PROSE_QUOTE_RE.test(trimmedQ) || SYNTHETIC_PROSE_QUOTE_RE.test(normQ)) {
          return false;
        }
        if (hasTraces) {
          return traceCorpora.some(
            c => c.rawCorpus.includes(rawQ) || c.rawCorpus.includes(trimmedQ) || c.normCorpus.includes(normQ)
          );
        }
        return true;
      });

    const isVerifiedSignal =
      finding?.reproVerified === true ||
      verificationStatus === 'verified' ||
      hasEvidenceQuotes;

    if (poeLevel >= 3 && isVerifiedSignal) {
      return {
        confidenceTier: 'CONFIRMED_EXPLOITABLE',
        confidenceScore: isPassiveVersionMatch(finding, options) ? 90 : 95
      };
    }

    return {
      confidenceTier: 'VERSION_ATTRIBUTED',
      confidenceScore: 82
    };
  }

  const detailText = `${finding?.detail || ''} ${finding?.reason || ''}`.slice(0, MAX_DETAIL_CHARS);
  if (HEURISTIC_DETAIL_RE.test(detailText)) {
    return {
      confidenceTier: 'HEURISTIC_ADVISORY',
      confidenceScore: 55
    };
  }

  return {
    confidenceTier: 'VERSION_ATTRIBUTED',
    confidenceScore: 70
  };
}
