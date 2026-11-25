import dns from 'node:dns/promises';
import net from 'node:net';
import { URL } from 'node:url';
import { ipMatchesCidr, evaluateAssetGate } from './guard.js';
import { createGovernedFetch } from './fetch.js';
import {
  validateTargetUrl,
  isMetadataOrForbiddenIP,
  isForbiddenMetadataHost,
  voidsExemption,
  canonicalizeIpAddress
} from './validator.js';

const DEFAULT_SUBDOMAINS = Object.freeze([
  'direct',
  'origin',
  'origin-www',
  'cpanel',
  'mail',
  'webmail',
  'ftp',
  'dev',
  'staging',
  'api',
  'backend',
  'server'
]);

const THIRD_PARTY_MAIL_HOSTS = Object.freeze([
  'google.com',
  'googlemail.com',
  'outlook.com',
  'protection.outlook.com',
  'pphosted.com',
  'mimecast.com',
  'protonmail.ch',
  'zoho.com',
  'amazonses.com',
  'sendgrid.net',
  'mailgun.org',
  'yahoodns.net'
]);

const ORIGIN_DISCLOSURE_HEADERS = Object.freeze([
  'x-origin-ip',
  'x-backend-ip',
  'x-real-server-ip',
  'x-server-ip',
  'x-upstream-addr',
  'x-forwarded-server',
  'x-host-ip'
]);

const MULTI_PART_PUBLIC_SUFFIXES = new Set([
  'co.uk',
  'org.uk',
  'ac.uk',
  'gov.uk',
  'com.au',
  'net.au',
  'org.au',
  'co.nz',
  'co.jp',
  'ne.jp',
  'or.jp',
  'com.br',
  'com.mx',
  'co.in',
  'co.za',
  'com.sg',
  'com.hk',
  'com.tw',
  'com.tr',
  'com.ar',
  'com.cn',
  'net.cn',
  'org.cn'
]);

const DEFAULT_SERVER_PAGE_RE = /(?:Welcome to nginx!|Apache2 Ubuntu Default Page|Apache2 Debian Default Page|It works!.*Apache|IIS Windows Server|CentOS.*Test Page|Test Page for the Apache HTTP Server|Direct IP access not allowed|cPanel.*Default Web Site Page|Server Status for\b)/i;

const ACCEPTABLE_PROBE_STATUSES = new Set([200, 301, 302, 401, 403]);

/**
 * Known CDN / WAF edge providers with IPv4/IPv6 CIDR blocks and HTTP/DNS fingerprints.
 */
export const CDN_CIDR_PROVIDERS = Object.freeze([
  Object.freeze({
    provider: 'Cloudflare',
    ipv4Cidrs: Object.freeze([
      '173.245.48.0/20',
      '103.21.244.0/22',
      '103.22.200.0/22',
      '103.31.4.0/22',
      '141.101.64.0/18',
      '108.162.192.0/18',
      '190.93.240.0/20',
      '188.114.96.0/20',
      '197.234.240.0/22',
      '198.41.128.0/17',
      '162.158.0.0/15',
      '104.16.0.0/13',
      '104.24.0.0/14',
      '172.64.0.0/13',
      '131.0.72.0/22'
    ]),
    ipv6Cidrs: Object.freeze([
      '2400:cb00::/32',
      '2606:4700::/32',
      '2803:f800::/32',
      '2405:b500::/32',
      '2405:8100::/32',
      '2a06:98c0::/29',
      '2c0f:f248::/32'
    ]),
    headers: Object.freeze(['cf-ray']),
    cnamePatterns: Object.freeze(['cloudflare']),
    serverPatterns: Object.freeze(['cloudflare'])
  }),
  Object.freeze({
    provider: 'AWS CloudFront',
    ipv4Cidrs: Object.freeze([
      '13.32.0.0/15',
      '13.35.0.0/16',
      '13.224.0.0/14',
      '18.64.0.0/14',
      '18.160.0.0/15',
      '52.84.0.0/15',
      '54.182.0.0/16',
      '54.192.0.0/16',
      '54.230.0.0/16',
      '65.8.0.0/16',
      '65.9.0.0/17',
      '99.84.0.0/16',
      '99.86.0.0/16',
      '108.156.0.0/14',
      '143.204.0.0/16',
      '205.251.192.0/19'
    ]),
    ipv6Cidrs: Object.freeze([]),
    headers: Object.freeze(['x-amz-cf-id']),
    cnamePatterns: Object.freeze(['cloudfront.net']),
    serverPatterns: Object.freeze(['cloudfront'])
  }),
  Object.freeze({
    provider: 'Fastly',
    ipv4Cidrs: Object.freeze([
      '23.235.32.0/20',
      '43.249.72.0/22',
      '103.244.50.0/24',
      '103.245.222.0/23',
      '104.156.80.0/20',
      '140.248.64.0/18',
      '140.248.128.0/17',
      '146.75.0.0/17',
      '151.101.0.0/16',
      '157.52.64.0/18',
      '167.82.0.0/17',
      '172.111.64.0/18',
      '185.31.16.0/22',
      '199.27.72.0/21',
      '199.232.0.0/16'
    ]),
    ipv6Cidrs: Object.freeze([]),
    headers: Object.freeze(['x-fastly-request-id']),
    cnamePatterns: Object.freeze(['fastly.net']),
    serverPatterns: Object.freeze(['fastly'])
  }),
  Object.freeze({
    provider: 'Akamai',
    ipv4Cidrs: Object.freeze([
      '23.32.0.0/11',
      '23.64.0.0/14',
      '23.72.0.0/13',
      '23.192.0.0/11',
      '104.64.0.0/10',
      '184.24.0.0/13',
      '184.50.0.0/15',
      '184.84.0.0/14'
    ]),
    ipv6Cidrs: Object.freeze([]),
    headers: Object.freeze(['x-akamai-transformed']),
    cnamePatterns: Object.freeze(['akamai', 'edgekey.net', 'edgesuite.net']),
    serverPatterns: Object.freeze(['akamai'])
  }),
  Object.freeze({
    provider: 'Imperva / Incapsula',
    ipv4Cidrs: Object.freeze([
      '199.83.128.0/21',
      '198.143.32.0/19',
      '149.126.72.0/21',
      '103.28.248.0/22',
      '185.11.124.0/22',
      '192.230.64.0/18',
      '45.64.64.0/22',
      '107.154.0.0/16'
    ]),
    ipv6Cidrs: Object.freeze([]),
    headers: Object.freeze(['x-iinfo']),
    cnamePatterns: Object.freeze(['incapdns.net', 'imperva']),
    serverPatterns: Object.freeze(['incapsula', 'imperva'])
  }),
  Object.freeze({
    provider: 'Sucuri',
    ipv4Cidrs: Object.freeze([
      '192.88.134.0/23',
      '185.93.228.0/22',
      '66.248.200.0/22',
      '208.109.0.0/22'
    ]),
    ipv6Cidrs: Object.freeze([]),
    headers: Object.freeze(['x-sucuri-id']),
    cnamePatterns: Object.freeze(['sucuri.net']),
    serverPatterns: Object.freeze(['sucuri'])
  })
]);

/**
 * Checks whether an IP address is disallowed by SSRF policy (metadata/reserved always blocked;
 * private/loopback/CGNAT blocked unless `allowPrivate` is true).
 *
 * @param {string} ip
 * @param {{ allowPrivate?: boolean }} [options]
 * @returns {boolean}
 */
export function isDisallowedIp(ip, { allowPrivate = false } = {}) {
  const canon = canonicalizeIpAddress(ip);
  if (!canon) return true;
  if (isMetadataOrForbiddenIP(canon)) return true;
  if (!allowPrivate && voidsExemption(canon)) return true;
  return false;
}

/**
 * Validates a normalized target URL against SSRF and Scope/Deny asset gate rules.
 *
 * @param {string} targetUrl
 * @param {{ allowPrivate?: boolean, rules?: Array<object> }} [options]
 * @returns {{ allowed: boolean, normalized?: string, hostname?: string, code?: string, reason?: string }}
 */
export function validateTarget(targetUrl, { allowPrivate = false, rules = [] } = {}) {
  const urlCheck = validateTargetUrl(targetUrl, { allowPrivate: Boolean(allowPrivate) });
  if (!urlCheck.valid) {
    return {
      allowed: false,
      code: 'SSRF_POLICY_BLOCKED',
      reason: urlCheck.error
    };
  }

  const gateCheck = evaluateAssetGate(urlCheck.normalized, {
    rules: Array.isArray(rules) ? rules : [],
    includeBuiltinDeny: true
  });
  if (!gateCheck.allowed) {
    return {
      allowed: false,
      code: gateCheck.code || 'TARGET_RULE_BLOCKED',
      reason: gateCheck.reason
    };
  }

  return {
    allowed: true,
    normalized: urlCheck.normalized,
    hostname: urlCheck.hostname
  };
}

/**
 * Normalizes HTTP response headers from a Fetch Headers instance or plain object into lowercase keys.
 */
function normalizeHeaders(rawHeaders) {
  const out = {};
  if (!rawHeaders) return out;
  if (typeof rawHeaders.entries === 'function') {
    for (const [k, v] of rawHeaders.entries()) {
      out[String(k).toLowerCase()] = String(v ?? '');
    }
    return out;
  }
  if (typeof rawHeaders === 'object') {
    for (const [k, v] of Object.entries(rawHeaders)) {
      out[String(k).toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v ?? '');
    }
  }
  return out;
}

/**
 * Classifies an IPv4 or IPv6 address against known CDN / edge proxy CIDR ranges.
 *
 * @param {string} ip
 * @returns {{ isCdn: boolean, provider: string | null }}
 */
export function classifyCdnIp(ip) {
  const canon = canonicalizeIpAddress(ip);
  if (!canon) return { isCdn: false, provider: null };

  const ipVersion = net.isIP(canon);
  if (ipVersion === 0) return { isCdn: false, provider: null };

  for (const entry of CDN_CIDR_PROVIDERS) {
    const cidrs = ipVersion === 4 ? entry.ipv4Cidrs : entry.ipv6Cidrs;
    for (const cidr of cidrs) {
      if (ipMatchesCidr(canon, cidr)) {
        return { isCdn: true, provider: entry.provider };
      }
    }
  }

  return { isCdn: false, provider: null };
}

/**
 * Detects whether an HTTP response or DNS CNAME chain indicates a CDN / edge proxy.
 *
 * @param {Record<string, string> | Headers} [headers={}]
 * @param {string[] | string} [cnames=[]]
 * @returns {{ isCdn: boolean, provider: string | null }}
 */
export function detectCdnFromHttp(headers = {}, cnames = []) {
  const normHeaders = normalizeHeaders(headers);
  const cnameList = (Array.isArray(cnames) ? cnames : [cnames])
    .map(c => String(c || '').trim().toLowerCase().replace(/\.+$/, ''))
    .filter(Boolean);

  const serverHeader = String(normHeaders['server'] || '').toLowerCase();
  const viaHeader = String(normHeaders['via'] || '').toLowerCase();
  const xCdnHeader = String(normHeaders['x-cdn'] || '').toLowerCase();

  for (const entry of CDN_CIDR_PROVIDERS) {
    for (const hdr of entry.headers) {
      if (normHeaders[hdr] && normHeaders[hdr].trim()) {
        return { isCdn: true, provider: entry.provider };
      }
    }

    for (const pat of entry.serverPatterns) {
      if (serverHeader.includes(pat) || viaHeader.includes(pat) || xCdnHeader.includes(pat)) {
        return { isCdn: true, provider: entry.provider };
      }
    }

    for (const cname of cnameList) {
      for (const pat of entry.cnamePatterns) {
        if (cname.includes(pat)) {
          return { isCdn: true, provider: entry.provider };
        }
      }
    }
  }

  return { isCdn: false, provider: null };
}

/**
 * Extracts IPv4/IPv6 addresses and `a:` hostnames from DNS TXT SPF (`v=spf1`) records.
 *
 * @param {Array<string | string[]>} [txtRecords=[]]
 * @returns {{ ips: Array<{ ip: string, cidr?: string, mechanism: string }>, hostnames: string[] }}
 */
export function extractSpfIps(txtRecords = []) {
  if (!Array.isArray(txtRecords)) {
    return { ips: [], hostnames: [] };
  }

  const ips = [];
  const seenIps = new Set();
  const hostnames = [];
  const seenHosts = new Set();

  const addIpEntry = (ip, mechanism, cidr) => {
    if (!ip || seenIps.has(ip)) return;
    seenIps.add(ip);
    const entry = { ip, mechanism };
    if (cidr) entry.cidr = cidr;
    ips.push(entry);
  };

  for (const rawRecord of txtRecords) {
    const flattened = (Array.isArray(rawRecord) ? rawRecord.map(String).join('') : String(rawRecord ?? ''))
      .trim()
      .replace(/^"+|"+$/g, '');

    if (!/v=spf1/i.test(flattened)) continue;

    const tokens = flattened.split(/\s+/).filter(Boolean);
    for (const rawToken of tokens) {
      // Skip explicit fail (`-`) qualifiers
      if (rawToken.startsWith('-')) continue;
      const token = rawToken.replace(/^[+~?]/, '');

      const aMatch = token.match(/^a:([^/\s]+)(?:\/\d+)?$/i);
      if (aMatch) {
        const host = aMatch[1].trim().toLowerCase().replace(/\.+$/, '');
        if (host && isValidDnsHostname(host) && !seenHosts.has(host)) {
          seenHosts.add(host);
          hostnames.push(host);
        }
        continue;
      }

      const ip4Match = token.match(/^ip4:(.+)$/i);
      if (ip4Match) {
        const spec = ip4Match[1].trim();
        const slashIdx = spec.indexOf('/');
        if (slashIdx === -1) {
          const canon = canonicalizeIpAddress(spec);
          if (canon && net.isIP(canon) === 4) {
            addIpEntry(canon, 'ip4');
          }
        } else {
          const addrPart = spec.slice(0, slashIdx).trim();
          const prefixStr = spec.slice(slashIdx + 1).trim();
          if (!/^\d+$/.test(prefixStr)) continue;
          const prefix = Number(prefixStr);
          const canon = canonicalizeIpAddress(addrPart);
          if (!canon || net.isIP(canon) !== 4) continue;

          if (prefix === 32) {
            addIpEntry(canon, 'ip4', spec);
          } else if (prefix >= 24 && prefix <= 31 && !canon.endsWith('.0')) {
            addIpEntry(canon, 'ip4', spec);
          }
        }
        continue;
      }

      const ip6Match = token.match(/^ip6:(.+)$/i);
      if (ip6Match) {
        const spec = ip6Match[1].trim();
        const slashIdx = spec.indexOf('/');
        if (slashIdx === -1) {
          const canon = canonicalizeIpAddress(spec);
          if (canon && net.isIP(canon) === 6) {
            addIpEntry(canon, 'ip6');
          }
        } else {
          const addrPart = spec.slice(0, slashIdx).trim();
          const prefixStr = spec.slice(slashIdx + 1).trim();
          if (!/^\d+$/.test(prefixStr)) continue;
          const prefix = Number(prefixStr);
          const canon = canonicalizeIpAddress(addrPart);
          if (!canon || net.isIP(canon) !== 6) continue;

          if (prefix === 128) {
            addIpEntry(canon, 'ip6', spec);
          }
        }
      }
    }
  }

  return { ips, hostnames };
}

/**
 * Parses a single IP token (optionally with `:port` or `[ipv6]:port`) into a canonical IP string, or `''`.
 */
function parseIpLiteralToken(rawToken) {
  const token = String(rawToken || '').trim().replace(/^['"]+|['"]+$/g, '');
  if (!token) return '';

  // [ipv6] or [ipv6]:port
  if (token.startsWith('[')) {
    const closeIdx = token.indexOf(']');
    if (closeIdx !== -1) {
      const inner = token.slice(1, closeIdx);
      const canon = canonicalizeIpAddress(inner);
      return canon && net.isIP(canon) !== 0 ? canon : '';
    }
  }

  // ipv4:port
  const v4PortMatch = token.match(/^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/);
  if (v4PortMatch) {
    const canon = canonicalizeIpAddress(v4PortMatch[1]);
    return canon && net.isIP(canon) === 4 ? canon : '';
  }

  const canon = canonicalizeIpAddress(token);
  return canon && net.isIP(canon) !== 0 ? canon : '';
}

/**
 * Extracts disclosed origin IPv4/IPv6 literals from HTTP headers and response body (`SERVER_ADDR`).
 *
 * @param {Record<string, string> | Headers} [headers={}]
 * @param {string} [bodyText='']
 * @returns {string[]}
 */
export function extractHeaderOriginIps(headers = {}, bodyText = '') {
  const normHeaders = normalizeHeaders(headers);
  const found = new Set();

  for (const hdrName of ORIGIN_DISCLOSURE_HEADERS) {
    const rawVal = normHeaders[hdrName];
    if (!rawVal) continue;
    const tokens = rawVal.split(/[\s,;]+/).filter(Boolean);
    for (const tok of tokens) {
      const ip = parseIpLiteralToken(tok);
      if (ip) found.add(ip);
    }
  }

  const body = typeof bodyText === 'string' ? bodyText : String(bodyText ?? '');
  if (body) {
    const tableRe = /SERVER_ADDR\s*(?:<\/t[dh]>\s*<td[^>]*>)\s*\[?([0-9a-fA-F.:]+)\]?/gi;
    for (const match of body.matchAll(tableRe)) {
      const ip = parseIpLiteralToken(match[1]);
      if (ip) found.add(ip);
    }

    const kvRe = /["']?SERVER_ADDR["']?\s*[:=]\s*["']?\[?([0-9a-fA-F.:]+)\]?["']?/gi;
    for (const match of body.matchAll(kvRe)) {
      const ip = parseIpLiteralToken(match[1]);
      if (ip) found.add(ip);
    }
  }

  return Array.from(found);
}

/**
 * Extracts and sanitizes `<title>` text from an HTML response body.
 */
function extractHtmlTitle(bodyText) {
  if (typeof bodyText !== 'string' || !bodyText) return '';
  const match = bodyText.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  if (!match) return '';
  return match[1]
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/[\x00-\x1f\x7f]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 200);
}

/**
 * Computes normalized token-overlap / length similarity in `[0, 1]` between two bodies.
 */
function computeBodySimilarity(probeResult, baseline) {
  if (typeof probeResult?.bodySimilarity === 'number') {
    return probeResult.bodySimilarity;
  }

  const probeText = typeof probeResult?.body === 'string'
    ? probeResult.body
    : typeof probeResult?.text === 'string'
      ? probeResult.text
      : '';
  const baseText = typeof baseline?.body === 'string'
    ? baseline.body
    : typeof baseline?.text === 'string'
      ? baseline.text
      : '';

  const probeLen = Number.isFinite(Number(probeResult?.bodyLength))
    ? Number(probeResult.bodyLength)
    : probeText.length;
  const baseLen = Number.isFinite(Number(baseline?.bodyLength))
    ? Number(baseline.bodyLength)
    : baseText.length;

  if (probeLen < 20 || baseLen < 20) return 0;

  const lengthRatio = Math.min(probeLen, baseLen) / Math.max(probeLen, baseLen);
  if (probeText && baseText) {
    if (probeText === baseText) return 1;
    const probeTokens = new Set(probeText.toLowerCase().split(/\W+/).filter(t => t.length >= 3).slice(0, 200));
    const baseTokens = new Set(baseText.toLowerCase().split(/\W+/).filter(t => t.length >= 3).slice(0, 200));
    if (probeTokens.size === 0 || baseTokens.size === 0) {
      return lengthRatio;
    }
    let intersection = 0;
    for (const tok of probeTokens) {
      if (baseTokens.has(tok)) intersection += 1;
    }
    const union = probeTokens.size + baseTokens.size - intersection;
    const jaccard = union > 0 ? intersection / union : 0;
    return (jaccard + lengthRatio) / 2;
  }

  return lengthRatio;
}

function getBaseConfidenceForSource(source) {
  const src = String(source || '').toLowerCase();
  if (src === 'http-header') return { confidence: 70, reason: 'Origin IP disclosed in HTTP header/body' };
  if (src === 'spf-ip4' || src === 'spf-ip6' || src === 'spf-txt' || src.startsWith('spf-')) {
    return { confidence: 65, reason: 'Origin IP candidate extracted from SPF TXT record' };
  }
  if (src === 'subdomain:direct' || src === 'subdomain:origin') {
    return { confidence: 65, reason: `Direct origin subdomain (${src.split(':')[1]})` };
  }
  if (src.startsWith('subdomain:')) {
    return { confidence: 55, reason: `Unproxied subdomain DNS record (${src.split(':')[1]})` };
  }
  if (src === 'mx-record' || src.startsWith('mx-record:')) {
    return { confidence: 50, reason: 'Unproxied MX mail server IP' };
  }
  if (src === 'dns-a' || src === 'dns-aaaa') {
    return { confidence: 60, reason: 'Non-CDN DNS A/AAAA record' };
  }
  return { confidence: 40, reason: `Discovered candidate (${src || 'unknown'})` };
}

/**
 * Scores a candidate IP against the baseline target response.
 *
 * @param {object} candidate
 * @param {object} [baseline={}]
 * @returns {{ confidence: number, verifiedOriginMatch: boolean, reason: string }}
 */
export function scoreOriginCandidate(candidate, baseline = {}) {
  if (!candidate || candidate.blockedByPolicy) {
    return {
      confidence: 0,
      verifiedOriginMatch: false,
      reason: 'Blocked by SSRF / IP policy'
    };
  }

  if (candidate.isCdnEdge) {
    return {
      confidence: 10,
      verifiedOriginMatch: false,
      reason: candidate.cdnProvider
        ? `Known CDN edge IP (${candidate.cdnProvider})`
        : 'Known CDN edge IP'
    };
  }

  const sources = Array.isArray(candidate.sources)
    ? candidate.sources
    : candidate.source
      ? [candidate.source]
      : [];

  const isPrimaryDns = sources.includes('dns-a') || sources.includes('dns-aaaa');
  if (isPrimaryDns && !baseline?.isBehindCdn) {
    return {
      confidence: 100,
      verifiedOriginMatch: true,
      reason: 'Direct DNS A/AAAA record (not behind CDN)'
    };
  }

  const probe = candidate.probeResult;
  if (probe && probe.ok !== false && typeof probe.status === 'number' && probe.status > 0) {
    const probeCdn = detectCdnFromHttp(probe.headers || {}, []);
    if (!probeCdn.isCdn) {
      const probeStatus = probe.status;
      const probeTitle = typeof probe.title === 'string'
        ? probe.title.trim()
        : extractHtmlTitle(probe.body || probe.text || '');
      const baseTitle = typeof baseline?.title === 'string' ? baseline.title.trim() : '';
      const probeBodyText = typeof probe.body === 'string'
        ? probe.body
        : typeof probe.text === 'string'
          ? probe.text
          : '';

      const is3xx = probeStatus >= 300 && probeStatus < 400;
      const isAcceptableForHigh = probeStatus === 200 || is3xx || probeStatus === 401 || probeStatus === 403;
      const titleMatches = Boolean(
        baseTitle.length >= 3 &&
        probeTitle.length >= 3 &&
        probeTitle.toLowerCase() === baseTitle.toLowerCase()
      );
      const similarity = computeBodySimilarity(probe, baseline);
      const highBodyMatch = Boolean(
        isAcceptableForHigh &&
        probeStatus === baseline?.status &&
        similarity >= 0.8
      );

      if (isAcceptableForHigh && (titleMatches || highBodyMatch)) {
        return {
          confidence: 95,
          verifiedOriginMatch: true,
          reason: titleMatches
            ? `Direct probe matched baseline title "${probeTitle}" (HTTP ${probeStatus})`
            : `Direct probe matched baseline response body and status (HTTP ${probeStatus})`
        };
      }

      if (ACCEPTABLE_PROBE_STATUSES.has(probeStatus) && !DEFAULT_SERVER_PAGE_RE.test(`${probeTitle}\n${probeBodyText}`)) {
        return {
          confidence: 75,
          verifiedOriginMatch: true,
          reason: `Direct probe with Host header returned non-default HTTP ${probeStatus} origin response`
        };
      }
    }
  }

  let bestBase = { confidence: 40, reason: 'Unverified candidate IP' };
  for (const src of sources) {
    const scored = getBaseConfidenceForSource(src);
    if (scored.confidence >= bestBase.confidence) {
      bestBase = scored;
    }
  }

  return {
    confidence: bestBase.confidence,
    verifiedOriginMatch: false,
    reason: bestBase.reason
  };
}

/**
 * Normalizes raw user target input into an `http://` or `https://` URL string.
 */
function normalizeTargetInput(targetInput) {
  if (typeof targetInput !== 'string' || !targetInput.trim()) {
    return '';
  }
  const trimmed = targetInput.trim();
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) {
    return trimmed;
  }

  // Bare IPv6 literal without brackets
  if (net.isIP(trimmed) === 6) {
    return `http://[${trimmed}]`;
  }

  // Bracketed IPv6 with optional :port and path: [2001:db8::1]:8443/path
  const v6Match = trimmed.match(/^\[([^\]]+)\](?::(\d+))?(?:[/?#].*)?$/);
  if (v6Match && net.isIP(v6Match[1]) === 6) {
    const port = v6Match[2] || '';
    const scheme = port === '443' || port === '8443' ? 'https://' : 'http://';
    return `${scheme}${trimmed}`;
  }

  // Bare IPv4 with optional :port and path: 203.0.113.10:8080/path
  const v4Match = trimmed.match(/^(\d{1,3}(?:\.\d{1,3}){3})(?::(\d+))?(?:[/?#].*)?$/);
  if (v4Match && net.isIP(v4Match[1]) === 4) {
    const port = v4Match[2] || '';
    const scheme = port === '443' || port === '8443' ? 'https://' : 'http://';
    return `${scheme}${trimmed}`;
  }

  return `https://${trimmed}`;
}

/**
 * Validates that a hostname extracted from untrusted DNS/TXT/MX records is syntactically safe.
 */
function isValidDnsHostname(host) {
  if (typeof host !== 'string') return false;
  const clean = host.trim().toLowerCase().replace(/\.+$/, '');
  if (!clean || clean.length > 253) return false;
  if (isForbiddenMetadataHost(clean)) return false;
  if (net.isIP(clean) !== 0) return false;
  if (/[\x00-\x1f\x7f\s/\\@]/.test(clean)) return false;
  const labels = clean.split('.');
  return labels.every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label));
}

function deriveApexDomain(hostname) {
  if (!hostname || net.isIP(hostname) !== 0) return hostname;
  const labels = hostname.split('.').filter(Boolean);
  if (labels.length <= 2) return hostname;

  const lastTwo = labels.slice(-2).join('.');
  if (MULTI_PART_PUBLIC_SUFFIXES.has(lastTwo)) {
    return labels.length >= 3 ? labels.slice(-3).join('.') : hostname;
  }
  return lastTwo;
}

function isThirdPartyMailHost(exchange) {
  const clean = String(exchange || '').trim().toLowerCase().replace(/\.+$/, '');
  if (!clean) return true;
  return THIRD_PARTY_MAIL_HOSTS.some(host => clean === host || clean.endsWith(`.${host}`));
}

/**
 * Builds an adapter over `options.dnsResolver` (or Node `dns/promises` + OS `dns.lookup` used by `ping`).
 */
function buildDnsClient(customResolver, queryTimeoutMs = 1500) {
  const withTimeout = (promise, ms = queryTimeoutMs) => {
    let timer = null;
    const timeoutPromise = new Promise((resolve) => {
      timer = setTimeout(() => resolve([]), ms);
      if (typeof timer?.unref === 'function') timer.unref();
    });
    return Promise.race([
      Promise.resolve(promise).catch(() => []),
      timeoutPromise
    ]).finally(() => {
      if (timer) clearTimeout(timer);
    });
  };

  const safeCall = async (fn, ...args) => {
    if (typeof fn !== 'function') return [];
    try {
      const res = await withTimeout(fn(...args));
      return Array.isArray(res) ? res : [];
    } catch {
      return [];
    }
  };

  const extractIpsByVersion = (items, version) => {
    const out = [];
    const seen = new Set();
    for (const item of Array.isArray(items) ? items : []) {
      const raw = typeof item === 'string'
        ? item
        : item && typeof item === 'object' && typeof item.address === 'string'
          ? item.address
          : '';
      const canon = canonicalizeIpAddress(raw);
      if (canon && net.isIP(canon) === version && !seen.has(canon)) {
        seen.add(canon);
        out.push(canon);
      }
    }
    return out;
  };

  if (!customResolver) {
    const osLookupAll = async (host) => {
      try {
        const res = await withTimeout(dns.lookup(host, { all: true }));
        return Array.isArray(res) ? res : res ? [res] : [];
      } catch {
        return [];
      }
    };

    return {
      resolve4: async (host) => {
        const osItems = await osLookupAll(host);
        const osV4 = extractIpsByVersion(osItems, 4);
        const aresV4 = await withTimeout(
          dns.resolve4(host).catch(() => []),
          osV4.length > 0 ? 350 : queryTimeoutMs
        );
        return extractIpsByVersion([...osV4, ...(Array.isArray(aresV4) ? aresV4 : [])], 4);
      },
      resolve6: async (host) => {
        const osItems = await osLookupAll(host);
        const osV6 = extractIpsByVersion(osItems, 6);
        const aresV6 = await withTimeout(
          dns.resolve6(host).catch(() => []),
          osV6.length > 0 ? 350 : queryTimeoutMs
        );
        return extractIpsByVersion([...osV6, ...(Array.isArray(aresV6) ? aresV6 : [])], 6);
      },
      resolveCname: (host) => safeCall(dns.resolveCname.bind(dns), host),
      resolveTxt: (host) => safeCall(dns.resolveTxt.bind(dns), host),
      resolveMx: (host) => safeCall(dns.resolveMx.bind(dns), host)
    };
  }

  if (typeof customResolver === 'function') {
    return {
      resolve4: async (host) => extractIpsByVersion(await safeCall(customResolver, host, 'A'), 4),
      resolve6: async (host) => extractIpsByVersion(await safeCall(customResolver, host, 'AAAA'), 6),
      resolveCname: async (host) => (await safeCall(customResolver, host, 'CNAME'))
        .filter(x => typeof x === 'string' && net.isIP(x) === 0),
      resolveTxt: (host) => safeCall(customResolver, host, 'TXT'),
      resolveMx: async (host) => (await safeCall(customResolver, host, 'MX'))
        .filter(x => x && typeof x === 'object' && x.exchange)
    };
  }

  return {
    resolve4: async (host) => {
      const v4 = await safeCall(customResolver.resolve4?.bind(customResolver), host);
      if (v4.length > 0) return extractIpsByVersion(v4, 4);
      if (typeof customResolver.lookup === 'function') {
        return extractIpsByVersion(await safeCall(customResolver.lookup.bind(customResolver), host, { all: true }), 4);
      }
      return [];
    },
    resolve6: async (host) => {
      const v6 = await safeCall(customResolver.resolve6?.bind(customResolver), host);
      if (v6.length > 0) return extractIpsByVersion(v6, 6);
      if (typeof customResolver.lookup === 'function') {
        return extractIpsByVersion(await safeCall(customResolver.lookup.bind(customResolver), host, { all: true }), 6);
      }
      return [];
    },
    resolveCname: (host) => safeCall(customResolver.resolveCname?.bind(customResolver), host),
    resolveTxt: (host) => safeCall(customResolver.resolveTxt?.bind(customResolver), host),
    resolveMx: (host) => safeCall(customResolver.resolveMx?.bind(customResolver), host)
  };
}

/**
 * Runs `worker` over `items` with a fixed concurrency cap.
 */
async function mapWithConcurrency(items, limit, worker) {
  const results = new Array(items.length);
  let cursor = 0;

  const runner = async () => {
    while (true) {
      const idx = cursor;
      cursor += 1;
      if (idx >= items.length) return;
      results[idx] = await worker(items[idx], idx);
    }
  };

  const workers = Array.from({ length: Math.min(limit, items.length) }, () => runner());
  await Promise.all(workers);
  return results;
}

async function normalizeHttpResponse(res) {
  if (!res || typeof res !== 'object') return null;
  const status = typeof res.status === 'number' ? res.status : 0;
  const headers = normalizeHeaders(res.headers);
  let body = '';
  if (typeof res.text === 'string') {
    body = res.text;
  } else if (typeof res.text === 'function') {
    body = await res.text();
  } else if (typeof res.body === 'string') {
    body = res.body;
  }
  const title = extractHtmlTitle(body);
  return {
    ok: status > 0,
    status,
    headers,
    body,
    bodyLength: body.length,
    title,
    serverHeader: headers['server'] || null
  };
}

function buildRecommendedCommands(normalizedUrl, realIp) {
  if (!realIp) return null;
  const cliTarget = realIp.includes(':') ? `[${realIp}]` : realIp;
  return {
    directIpScan: `node bin/cli.js ${cliTarget}`,
    pinnedHostScan: `node bin/cli.js ${normalizedUrl} --source-ip ${realIp}`,
    cveDirectScan: `node bin/cli.js ${cliTarget} --cve CVE-2026-123007`
  };
}

/**
 * Discovers the likely origin / real IP behind a CDN or edge proxy for a website target,
 * combining DNS A/AAAA/CNAME, baseline HTTP inspection, SPF TXT/A records, MX records,
 * common origin subdomains, and direct origin-IP probing under strict SSRF/asset governance.
 *
 * @param {string} targetInput
 * @param {{
 *   allowPrivate?: boolean,
 *   rules?: Array<object>,
 *   dnsResolver?: object | Function,
 *   fetchFn?: Function,
 *   probeFn?: Function,
 *   skipHttp?: boolean,
 *   deepSearch?: boolean,
 *   verifyCandidates?: boolean,
 *   maxVerifyCandidates?: number,
 *   timeoutMs?: number,
 *   headers?: Record<string, string>
 * }} [options={}]
 * @returns {Promise<object>}
 */
export async function discoverWebsiteRealIp(targetInput, options = {}) {
  const allowPrivate = Boolean(options.allowPrivate);
  const rules = Array.isArray(options.rules) ? options.rules : [];
  const timeoutMs = Number.isFinite(Number(options.timeoutMs)) && Number(options.timeoutMs) > 0
    ? Number(options.timeoutMs)
    : 5000;
  const maxVerifyCandidates = Number.isFinite(Number(options.maxVerifyCandidates)) && Number(options.maxVerifyCandidates) >= 0
    ? Math.floor(Number(options.maxVerifyCandidates))
    : 8;

  const rawNormalized = normalizeTargetInput(targetInput);
  const validation = validateTarget(rawNormalized, { allowPrivate, rules });
  if (!validation.allowed) {
    const err = new Error(validation.reason || 'Target blocked by SSRF or asset policy');
    err.code = validation.code || 'SSRF_POLICY_BLOCKED';
    err.isGovernanceBlock = true;
    throw err;
  }

  const normalizedUrl = validation.normalized;
  const parsed = new URL(normalizedUrl);
  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
  const apexDomain = deriveApexDomain(hostname);

  // Immediate return for bare IP literal targets
  if (net.isIP(hostname) !== 0) {
    const canonIp = canonicalizeIpAddress(hostname) || hostname;
    const cdn = classifyCdnIp(canonIp);
    const candidate = {
      ip: canonIp,
      sources: ['ip-literal'],
      isCdnEdge: cdn.isCdn,
      cdnProvider: cdn.provider,
      blockedByPolicy: false,
      verifiedOriginMatch: !cdn.isCdn,
      confidence: 100,
      reason: cdn.isCdn
        ? `Direct CDN edge IP literal (${cdn.provider})`
        : 'Direct IP literal target',
      httpStatus: null,
      serverHeader: null,
      title: null
    };

    return {
      target: normalizedUrl,
      hostname: canonIp,
      apexDomain: canonIp,
      isBehindCdn: cdn.isCdn,
      cdnProvider: cdn.provider,
      primaryIps: [canonIp],
      cnames: [],
      realIp: canonIp,
      realIpConfidence: 100,
      confidence: 100,
      realIpSource: 'ip-literal',
      verifiedOrigin: !cdn.isCdn,
      candidates: [candidate],
      commands: buildRecommendedCommands(normalizedUrl, canonIp)
    };
  }

  const dnsClient = buildDnsClient(options.dnsResolver);
  const candidateMap = new Map();

  const addCandidate = (rawIp, source) => {
    const canon = canonicalizeIpAddress(rawIp);
    if (!canon || net.isIP(canon) === 0) return;

    let blocked = isDisallowedIp(canon, { allowPrivate });
    if (!blocked && rules.length > 0) {
      const ipGate = evaluateAssetGate(
        { url: normalizedUrl, hostname, resolvedIps: [canon] },
        { rules, includeBuiltinDeny: true }
      );
      if (!ipGate.allowed) {
        blocked = true;
      }
    }

    const cdn = classifyCdnIp(canon);
    if (!candidateMap.has(canon)) {
      candidateMap.set(canon, {
        ip: canon,
        sources: [source],
        isCdnEdge: cdn.isCdn,
        cdnProvider: cdn.provider,
        blockedByPolicy: blocked,
        probeResult: null,
        httpStatus: null,
        serverHeader: null,
        title: null,
        verifiedOriginMatch: false,
        confidence: 0,
        reason: ''
      });
    } else {
      const existing = candidateMap.get(canon);
      if (!existing.sources.includes(source)) {
        existing.sources.push(source);
      }
      if (blocked) existing.blockedByPolicy = true;
    }
  };

  // Step A: Resolve primary A, AAAA, and CNAME records for hostname
  const [rawA, rawAaaa, rawCnames] = await Promise.all([
    dnsClient.resolve4(hostname),
    dnsClient.resolve6(hostname),
    dnsClient.resolveCname(hostname)
  ]);

  const primaryIps = [];
  const seenPrimary = new Set();
  for (const ip of rawA) {
    const canon = canonicalizeIpAddress(ip);
    if (canon && net.isIP(canon) !== 0) {
      if (!seenPrimary.has(canon)) {
        seenPrimary.add(canon);
        primaryIps.push(canon);
      }
      addCandidate(canon, 'dns-a');
    }
  }
  for (const ip of rawAaaa) {
    const canon = canonicalizeIpAddress(ip);
    if (canon && net.isIP(canon) !== 0) {
      if (!seenPrimary.has(canon)) {
        seenPrimary.add(canon);
        primaryIps.push(canon);
      }
      addCandidate(canon, 'dns-aaaa');
    }
  }

  // Fallback to www.<hostname> if bare domain has no direct A/AAAA record
  if (primaryIps.length === 0 && !hostname.startsWith('www.') && isValidDnsHostname(`www.${hostname}`)) {
    const [wwwA, wwwAaaa] = await Promise.all([
      dnsClient.resolve4(`www.${hostname}`),
      dnsClient.resolve6(`www.${hostname}`)
    ]);
    for (const ip of wwwA) {
      const canon = canonicalizeIpAddress(ip);
      if (canon && net.isIP(canon) !== 0) {
        if (!seenPrimary.has(canon)) {
          seenPrimary.add(canon);
          primaryIps.push(canon);
        }
        addCandidate(canon, 'dns-a');
      }
    }
    for (const ip of wwwAaaa) {
      const canon = canonicalizeIpAddress(ip);
      if (canon && net.isIP(canon) !== 0) {
        if (!seenPrimary.has(canon)) {
          seenPrimary.add(canon);
          primaryIps.push(canon);
        }
        addCandidate(canon, 'dns-aaaa');
      }
    }
  }

  const cnames = rawCnames
    .map(c => String(c || '').trim().toLowerCase().replace(/\.+$/, ''))
    .filter(c => c && isValidDnsHostname(c));

  // Step B: Fetch baseline target response (unless skipHttp === true)
  const safePrimaryIps = primaryIps.filter(ip => !isDisallowedIp(ip, { allowPrivate }));
  let baseline = {
    status: null,
    headers: {},
    body: '',
    bodyLength: 0,
    title: '',
    serverHeader: null,
    isBehindCdn: false
  };

  if (options.skipHttp !== true && !(primaryIps.length > 0 && safePrimaryIps.length === 0)) {
    try {
      let rawBaselineRes;
      if (typeof options.fetchFn === 'function') {
        rawBaselineRes = await options.fetchFn(normalizedUrl, {
          headers: options.headers || {},
          timeoutMs
        });
      } else {
        const baselineGovernanceDns = options.dnsResolver
          ? async (lookupHost) => {
              const cleanLookup = String(lookupHost || '').trim().toLowerCase().replace(/\.+$/, '');
              if (cleanLookup === hostname) return primaryIps;
              const [v4, v6] = await Promise.all([
                dnsClient.resolve4(cleanLookup),
                dnsClient.resolve6(cleanLookup)
              ]);
              return [...v4, ...v6].map(ip => canonicalizeIpAddress(ip)).filter(Boolean);
            }
          : null;
        const governedFetch = createGovernedFetch({
          allowPrivate,
          scopeRules: rules,
          enforceDnsValidation: true,
          ...(baselineGovernanceDns ? { dnsResolver: baselineGovernanceDns } : {}),
          retries: 0,
          timeout: timeoutMs
        });
        rawBaselineRes = await governedFetch(normalizedUrl, {
          ...(options.headers ? { headers: options.headers } : {})
        });
      }
      const parsedBaseline = await normalizeHttpResponse(rawBaselineRes);
      if (parsedBaseline) {
        baseline = { ...baseline, ...parsedBaseline };
      }
    } catch {
      // Baseline HTTP failure is non-fatal; DNS/SPF/MX/subdomain discovery continues
    }
  }

  // Determine CDN status from primary IPs, CNAMEs, and baseline HTTP headers
  let isBehindCdn = false;
  let cdnProvider = null;

  for (const ip of primaryIps) {
    const ipCdn = classifyCdnIp(ip);
    if (ipCdn.isCdn) {
      isBehindCdn = true;
      cdnProvider = ipCdn.provider;
      break;
    }
  }

  const httpOrCnameCdn = detectCdnFromHttp(baseline.headers, cnames);
  if (httpOrCnameCdn.isCdn) {
    isBehindCdn = true;
    cdnProvider = cdnProvider || httpOrCnameCdn.provider;
  }

  baseline.isBehindCdn = isBehindCdn;

  // Always extract HTTP header/body origin IP leaks from baseline response
  const leakedHeaderIps = extractHeaderOriginIps(baseline.headers, baseline.body);
  for (const ip of leakedHeaderIps) {
    addCandidate(ip, 'http-header');
  }

  // Step C: Deep candidate gathering (SPF TXT/A, MX, common origin subdomains)
  // Run automatically when behind a CDN, when primary DNS returned no IPs, or when deepSearch === true
  if ((isBehindCdn || primaryIps.length === 0 || options.deepSearch === true) && options.deepSearch !== false) {
    const resolveHostIntoCandidates = async (fqdn, source) => {
      const [v4, v6] = await Promise.all([
        dnsClient.resolve4(fqdn),
        dnsClient.resolve6(fqdn)
      ]);
      for (const ip of [...v4, ...v6]) {
        addCandidate(ip, source);
      }
    };

    // 1. TXT / SPF records
    const txtDomains = apexDomain !== hostname ? [apexDomain, hostname] : [apexDomain];
    const txtResults = await Promise.all(txtDomains.map(d => dnsClient.resolveTxt(d)));
    const spfHostnames = new Set();

    for (const records of txtResults) {
      const spf = extractSpfIps(records);
      for (const entry of spf.ips) {
        addCandidate(entry.ip, 'spf-txt');
      }
      for (const h of spf.hostnames) {
        if (isValidDnsHostname(h)) {
          spfHostnames.add(h);
        }
      }
    }

    if (spfHostnames.size > 0) {
      await mapWithConcurrency(Array.from(spfHostnames), 4, (spfHost) =>
        resolveHostIntoCandidates(spfHost, 'spf-txt')
      );
    }

    // 2. MX records on apexDomain (filtering out known 3rd-party mail providers)
    const mxRecords = await dnsClient.resolveMx(apexDomain);
    const customMxHosts = [];
    const seenMx = new Set();
    for (const rec of mxRecords) {
      const exchange = String(rec?.exchange || '').trim().toLowerCase().replace(/\.+$/, '');
      if (!exchange || !isValidDnsHostname(exchange) || isThirdPartyMailHost(exchange)) continue;
      if (!seenMx.has(exchange)) {
        seenMx.add(exchange);
        customMxHosts.push(exchange);
      }
    }

    if (customMxHosts.length > 0) {
      await mapWithConcurrency(customMxHosts, 4, (exchange) =>
        resolveHostIntoCandidates(exchange, `mx-record:${exchange}`)
      );
    }

    // 3. Common origin subdomains on apexDomain (max 4 concurrent)
    const subdomainTargets = DEFAULT_SUBDOMAINS
      .map(sub => ({ sub, fqdn: `${sub}.${apexDomain}` }))
      .filter(item => item.fqdn !== hostname && isValidDnsHostname(item.fqdn));

    await mapWithConcurrency(subdomainTargets, 4, ({ sub, fqdn }) =>
      resolveHostIntoCandidates(fqdn, `subdomain:${sub}`)
    );
  }

  // Step D: Direct candidate probing when behind CDN (never probe CDN-edge or policy-blocked IPs)
  if (isBehindCdn && options.verifyCandidates !== false && maxVerifyCandidates > 0) {
    const preProbeCandidates = Array.from(candidateMap.values())
      .filter(c => !c.isCdnEdge && !c.blockedByPolicy)
      .sort((a, b) => scoreOriginCandidate(b, baseline).confidence - scoreOriginCandidate(a, baseline).confidence)
      .slice(0, maxVerifyCandidates);

    await mapWithConcurrency(preProbeCandidates, 4, async (candidate) => {
      // Defensive guardrail re-check right before issuing any probe
      if (candidate.blockedByPolicy || isDisallowedIp(candidate.ip, { allowPrivate })) {
        candidate.blockedByPolicy = true;
        return;
      }

      try {
        let rawProbeRes;
        if (typeof options.probeFn === 'function') {
          rawProbeRes = await options.probeFn(normalizedUrl, candidate.ip, {
            hostname,
            sourceIp: candidate.ip,
            timeoutMs
          });
        } else {
          const probeFetch = createGovernedFetch({
            allowPrivate,
            scopeRules: rules,
            sourceIp: `${hostname}=${candidate.ip}`,
            timeout: timeoutMs,
            retries: 0,
            ...(typeof options.fetchFn === 'function' ? { fetcher: options.fetchFn } : {})
          });
          rawProbeRes = await probeFetch(normalizedUrl, {
            followRedirects: false,
            ...(options.headers ? { headers: options.headers } : {})
          });
        }

        const normalizedProbe = await normalizeHttpResponse(rawProbeRes);
        if (normalizedProbe) {
          candidate.probeResult = normalizedProbe;
          candidate.httpStatus = normalizedProbe.status;
          candidate.serverHeader = normalizedProbe.serverHeader;
          candidate.title = normalizedProbe.title || null;
        }
      } catch (err) {
        candidate.probeResult = {
          ok: false,
          error: err?.message || String(err)
        };
      }
    });
  }

  // Step E: Score, sort, and select best realIp
  const candidates = Array.from(candidateMap.values()).map((candidate) => {
    const scored = scoreOriginCandidate(candidate, baseline);
    return {
      ip: candidate.ip,
      sources: candidate.sources,
      isCdnEdge: candidate.isCdnEdge,
      cdnProvider: candidate.cdnProvider,
      blockedByPolicy: candidate.blockedByPolicy,
      verifiedOriginMatch: scored.verifiedOriginMatch,
      confidence: scored.confidence,
      reason: scored.reason,
      httpStatus: candidate.httpStatus,
      serverHeader: candidate.serverHeader,
      title: candidate.title
    };
  });

  candidates.sort((a, b) => {
    if (a.blockedByPolicy !== b.blockedByPolicy) return a.blockedByPolicy ? 1 : -1;
    if (b.confidence !== a.confidence) return b.confidence - a.confidence;
    if (a.isCdnEdge !== b.isCdnEdge) return a.isCdnEdge ? 1 : -1;
    return 0;
  });

  const eligibleCandidates = candidates.filter(c => !c.blockedByPolicy);
  const nonCdnCandidates = eligibleCandidates.filter(c => !c.isCdnEdge);

  let selectedCandidate = null;
  if (!isBehindCdn && safePrimaryIps.length > 0) {
    selectedCandidate = eligibleCandidates.find(c => c.ip === safePrimaryIps[0]) || eligibleCandidates[0] || null;
  } else if (nonCdnCandidates.length > 0) {
    selectedCandidate = nonCdnCandidates[0];
  } else if (safePrimaryIps.length > 0) {
    selectedCandidate = eligibleCandidates.find(c => c.ip === safePrimaryIps[0]) || eligibleCandidates[0] || null;
  }

  const realIp = selectedCandidate ? selectedCandidate.ip : null;
  const realIpConfidence = selectedCandidate ? selectedCandidate.confidence : 0;
  const realIpSource = selectedCandidate && selectedCandidate.sources.length > 0
    ? selectedCandidate.sources[0]
    : null;
  const verifiedOrigin = Boolean(selectedCandidate && selectedCandidate.verifiedOriginMatch);

  return {
    target: normalizedUrl,
    hostname,
    apexDomain,
    isBehindCdn,
    cdnProvider,
    primaryIps,
    cnames,
    realIp,
    realIpConfidence,
    realIpSource,
    verifiedOrigin,
    candidates,
    commands: buildRecommendedCommands(normalizedUrl, realIp)
  };
}
