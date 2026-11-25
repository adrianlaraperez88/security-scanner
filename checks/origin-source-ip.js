import net from 'node:net';
import { URL } from 'node:url';
import { classifyCdnIp } from '../core/real-ip-finder.js';

export const tags = ['all'];

export const meta = {
  id: 'origin-source-ip',
  title: 'Direct Source-IP / Origin-IP HTTP Exposure & CDN/WAF Bypass',
  category: 'Infrastructure & Network',
  plainExplanation:
    'Verifies whether the target connects via a resolved or configured Source/Origin IP and checks if direct Source-IP HTTP/HTTPS requests bypass CDN/WAF edge protections or leak internal default virtual-host / origin server metadata.',
  whyItMatters:
    'When an origin server accepts direct HTTP/HTTPS connections on its Source IP outside the CDN/WAF IP allowlist, attackers can bypass edge WAF rules, rate limits, and bot protections by connecting directly to the Source IP with a Host header (--resolve) or accessing the raw IP virtual host.',
  defaultFix:
    'Restrict origin firewall / security-group ingress on ports 80 and 443 to trusted CDN/WAF IP ranges only, configure a strict default-deny catch-all virtual host that rejects unknown Host headers or direct-IP TLS handshakes (nginx ssl_reject_handshake on; return 444;), and enforce Authenticated Origin Pulls (mTLS).',
  cwe: 'CWE-284',
  owasp: 'A05:2021-Security Misconfiguration',
  cvssScore: 7.5,
  references: [
    'https://cwe.mitre.org/data/definitions/284.html',
    'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
  ]
};

const CDN_EDGE_PATTERNS = [
  { provider: 'Cloudflare', header: 'cf-ray', serverRe: /\bcloudflare\b/i },
  { provider: 'AWS CloudFront', header: 'x-amz-cf-id', serverRe: /\bcloudfront\b/i },
  { provider: 'Akamai', header: 'x-akamai-transformed', serverRe: /\bakamai/i },
  { provider: 'Fastly', header: 'x-fastly-request-id', serverRe: /\bfastly\b/i },
  { provider: 'Sucuri', header: 'x-sucuri-id', serverRe: /\bsucuri\b/i },
  { provider: 'Imperva / Incapsula', header: 'x-iinfo', serverRe: /\bincapsula|imperva\b/i }
];

const INTERNAL_ORIGIN_LEAK_RE = /(?:Welcome to nginx!|Apache2 Ubuntu Default Page|Apache2 Debian Default Page|It works!.*Apache|IIS Windows Server|CentOS.*Test Page|Test Page for the Apache HTTP Server|cPanel.*Default Web Site Page|Server Status for\b)/i;
const CDN_DIRECT_IP_BLOCK_RE = /(?:Direct IP access not allowed|Error\s*1003\b)/i;

const ORIGIN_LEAK_HEADERS = Object.freeze([
  'x-origin-ip',
  'x-backend-ip',
  'x-real-server-ip',
  'x-server-ip',
  'x-upstream-addr',
  'x-forwarded-server',
  'x-host-ip'
]);

const GOVERNANCE_ERROR_CODES = new Set([
  'SSRF_POLICY_BLOCKED',
  'TARGET_RULE_BLOCKED',
  'TARGET_OUT_OF_SCOPE',
  'DNS_REBIND_OR_PRIVATE_IP'
]);

function isGovernanceBlock(err) {
  if (!err) return false;
  if (err.isGovernanceBlock === true || GOVERNANCE_ERROR_CODES.has(err.code)) return true;
  const msg = String(err.message || '');
  return (
    msg.startsWith('Redirect blocked by SSRF policy') ||
    msg.startsWith('Request blocked by SSRF policy') ||
    msg.startsWith('[SECSCAN platform control')
  );
}

function getHeader(headers, key) {
  if (!headers || typeof headers !== 'object') return '';
  const lower = key.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (String(k).toLowerCase() === lower) {
      return String(v ?? '');
    }
  }
  return '';
}

function detectEdgeProvider(headers = {}) {
  const server = getHeader(headers, 'server');
  const via = getHeader(headers, 'via');
  for (const rule of CDN_EDGE_PATTERNS) {
    if (getHeader(headers, rule.header)) return rule.provider;
    if (rule.serverRe.test(server) || rule.serverRe.test(via)) return rule.provider;
  }
  return null;
}

export async function run(targetInput, fetchWithRetry) {
  const target = Array.isArray(targetInput) ? targetInput[0] : targetInput;
  if (!target || typeof target !== 'string') {
    return {
      name: meta.title,
      checkId: meta.id,
      target: String(target || ''),
      status: 'SAFE',
      detail: 'No valid target URL provided for Source-IP inspection.'
    };
  }

  let parsed;
  try {
    parsed = new URL(target);
  } catch {
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      status: 'SAFE',
      detail: 'Target URL could not be parsed.'
    };
  }

  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
  const isLiteralIp = net.isIP(hostname) !== 0;

  let baselineRes;
  try {
    baselineRes = await fetchWithRetry(target, { followRedirects: false });
  } catch (err) {
    if (isGovernanceBlock(err)) throw err;
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      status: 'ERROR',
      detail: `Baseline request failed: ${err.message}`
    };
  }

  const resolvedIp = baselineRes?.sourceIp || baselineRes?.resolvedIp || (isLiteralIp ? hostname : null);
  const dialedAddress = baselineRes?.dialedAddress || null;
  const edgeProvider = detectEdgeProvider(baselineRes?.headers || {});
  const baselineServer = getHeader(baselineRes?.headers || {}, 'server');

  const findings = [];
  const evidenceQuotes = [];
  const trafficIds = [];
  if (baselineRes?.trafficId) trafficIds.push(baselineRes.trafficId);

  // 1. Check if response headers leak an internal/origin IP behind a CDN/reverse proxy
  for (const headerName of ORIGIN_LEAK_HEADERS) {
    const rawHeaderVal = getHeader(baselineRes?.headers || {}, headerName);
    const cleanLeak = rawHeaderVal.trim();
    if (cleanLeak.length >= 7) {
      findings.push({
        type: 'origin_ip_header_disclosure',
        severity: 'MEDIUM',
        url: target,
        header: headerName,
        status: baselineRes.status,
        issue: `Response header (${headerName}) discloses upstream/origin server address: "${cleanLeak}"`,
        matchedSignal: cleanLeak
      });
      evidenceQuotes.push(cleanLeak.length >= 8 ? cleanLeak : `${headerName}: ${cleanLeak}`);
    }
  }

  let directIpMeta = null;
  let directReproduction = null;

  // 2. Direct literal IP branch: classify CDN/WAF edge vs exposed origin default vhost vs standalone origin
  if (isLiteralIp) {
    const ipCdn = classifyCdnIp(hostname);
    const cdnProvider = edgeProvider || (ipCdn.isCdn ? ipCdn.provider : null);
    const isCdnEdge = Boolean(cdnProvider);
    const baselineBody = String(baselineRes?.text || '');
    const directIpBlocked = isCdnEdge && (
      CDN_DIRECT_IP_BLOCK_RE.test(baselineBody) ||
      baselineRes.status === 403 ||
      baselineRes.status === 400 ||
      baselineRes.status === 421
    );

    directIpMeta = {
      isCdnEdge,
      ...(cdnProvider ? { cdnProvider } : {}),
      ...(isCdnEdge ? { directIpBlocked } : {})
    };

    if (!isCdnEdge && baselineRes.status !== 404 && baselineRes.status !== 405 && baselineRes.status !== 410) {
      const leakMatch = baselineBody.match(INTERNAL_ORIGIN_LEAK_RE);
      if (leakMatch) {
        const quote = leakMatch[0].length >= 8 ? leakMatch[0] : baselineBody.trim().slice(0, 80);
        findings.push({
          type: 'direct_ip_default_vhost_exposure',
          severity: 'MEDIUM',
          url: target,
          sourceIp: resolvedIp || hostname,
          status: baselineRes.status,
          issue: `Direct IP (${hostname}) serves an exposed default web server virtual-host page ("${leakMatch[0]}") without CDN/WAF masking.`,
          matchedSignal: quote
        });
        if (quote && quote.length >= 8) evidenceQuotes.push(quote);
        directReproduction = {
          method: 'GET',
          url: target,
          responseStatus: baselineRes.status,
          observedSignal: quote
        };
      }
    }

    if (findings.length === 0) {
      return {
        name: meta.title,
        checkId: meta.id,
        target,
        status: 'SAFE',
        ...directIpMeta,
        ...(resolvedIp ? { resolvedIp } : {}),
        ...(dialedAddress ? { dialedAddress } : {}),
        detail: isCdnEdge
          ? `Direct IP ${hostname} is a ${cdnProvider} CDN/WAF edge endpoint (HTTP ${baselineRes.status}${directIpBlocked ? ' — direct IP access blocked by edge' : ''}); origin server is masked.`
          : `Direct IP ${hostname} responds directly as an origin/standalone server (HTTP ${baselineRes.status}${baselineServer ? `, Server: ${baselineServer}` : ''}); no CDN/WAF edge detected and no default vhost or origin-header leakage found.`
      };
    }
  }

  // 3. If target is a domain name and we have a resolved/configured Source IP, probe with bare-IP Host header
  //    to check if the source IP exposes an unhardened default virtual host or bypasses edge CDN/WAF
  if (!isLiteralIp && resolvedIp && baselineRes.status !== 404) {
    try {
      const directVhostRes = await fetchWithRetry(target, {
        followRedirects: false,
        headers: {
          'X-SecScan-Probe': 'source-ip-vhost'
        }
      });
      if (directVhostRes?.trafficId) trafficIds.push(directVhostRes.trafficId);

      const directBody = String(directVhostRes?.text || '');
      const directServer = getHeader(directVhostRes?.headers || {}, 'server');
      const directEdge = detectEdgeProvider(directVhostRes?.headers || {});

      // Case A: baseline was blocked by CDN/WAF (403/406/429) or showed CDN edge, while direct source-IP probe
      // bypassed the edge (no edge headers) and returned 200 OK with application or default vhost content
      if (
        edgeProvider &&
        !directEdge &&
        directVhostRes.status === 200 &&
        (baselineRes.status === 403 || baselineRes.status === 429 || (directServer && directServer !== baselineServer))
      ) {
        const quote = directServer
          ? `Server: ${directServer}`
          : directBody.trim().slice(0, 120);
        findings.push({
          type: 'cdn_waf_source_ip_bypass',
          severity: 'HIGH',
          url: target,
          sourceIp: resolvedIp,
          status: directVhostRes.status,
          issue: `Direct Source-IP HTTP access (${resolvedIp}) bypassed ${edgeProvider} edge protection (edge status ${baselineRes.status} -> direct status ${directVhostRes.status}${directServer ? `, origin Server: ${directServer}` : ''}).`,
          matchedSignal: quote
        });
        if (quote && quote.length >= 8) evidenceQuotes.push(quote);
      }

      // Case B: direct source IP response exposes unconfigured default web server installation page
      const leakMatch = directBody.match(INTERNAL_ORIGIN_LEAK_RE);
      if (
        directVhostRes.status === 200 &&
        leakMatch &&
        !INTERNAL_ORIGIN_LEAK_RE.test(String(baselineRes?.text || ''))
      ) {
        const quote = leakMatch[0].length >= 8 ? leakMatch[0] : directBody.trim().slice(0, 80);
        findings.push({
          type: 'source_ip_default_vhost_exposure',
          severity: 'MEDIUM',
          url: target,
          sourceIp: resolvedIp,
          status: directVhostRes.status,
          issue: `Source IP (${resolvedIp}) exposes default web server virtual-host page ("${leakMatch[0]}") not visible on the primary domain response.`,
          matchedSignal: quote
        });
        if (quote && quote.length >= 8) evidenceQuotes.push(quote);
      }
    } catch (err) {
      if (isGovernanceBlock(err)) throw err;
    }
  }

  if (findings.length === 0) {
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      status: 'SAFE',
      ...(resolvedIp ? { resolvedIp } : {}),
      ...(dialedAddress ? { dialedAddress } : {}),
      detail: resolvedIp
        ? `Target HTTP transport routed via Source IP ${resolvedIp}${dialedAddress ? ` (${dialedAddress})` : ''}; no origin WAF bypass or default vhost leakage detected.`
        : 'No origin/source-IP bypass or upstream IP disclosure detected.'
    };
  }

  const hasHigh = findings.some(f => f.severity === 'HIGH');
  return {
    name: meta.title,
    checkId: meta.id,
    target,
    url: target,
    status: hasHigh ? 'VULNERABLE' : 'SUSPICIOUS',
    severity: hasHigh ? 'HIGH' : 'MEDIUM',
    ...(directIpMeta || {}),
    ...(resolvedIp ? { sourceIp: resolvedIp, resolvedIp, includeResolveFlag: true } : {}),
    ...(dialedAddress ? { dialedAddress } : {}),
    findings,
    evidenceQuotes: Array.from(new Set(evidenceQuotes)).slice(0, 5),
    poeLevel: 3,
    ...(directReproduction ? { reproduction: directReproduction } : {}),
    ...(trafficIds.length > 0 ? { trafficId: trafficIds[trafficIds.length - 1], trafficIds } : {}),
    detail: findings.map(f => f.issue).join(' ')
  };
}
