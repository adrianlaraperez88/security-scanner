import dns from 'node:dns/promises';
import pLimit from 'p-limit';
import { URL } from 'node:url';
import { validateTargetUrl, resolveAndValidateTarget } from './validator.js';
import { getCheckMeta, CWE_OWASP_MAP } from './catalog.js';
import { buildReproductionContext } from './reproduction.js';
import { verifyFindingBeforeReport } from './check-verify.js';

/**
 * Strips embedded credentials (user:pass@) from raw URL strings.
 *
 * @param {string} rawUrl
 * @returns {string}
 */
export function stripUserinfo(rawUrl) {
  if (typeof rawUrl !== 'string' || !rawUrl.trim()) return '';
  try {
    const u = new URL(rawUrl.trim());
    u.username = '';
    u.password = '';
    return u.toString().replace(/\/+$/, '');
  } catch {
    return rawUrl.trim().replace(/^([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)[^/@\s]+@/, '$1');
  }
}

/**
 * Strips control characters and escapes quotes, backticks, and prompt-injection
 * data envelopes so ingested external banners cannot inject instructions.
 *
 * @param {unknown} str
 * @param {number} [maxLen=300]
 * @returns {string}
 */
export function sanitizeExternalBanner(str, maxLen = 300) {
  if (str === null || str === undefined) return '';
  const limit = Number.isFinite(maxLen) && maxLen > 0 ? Math.floor(maxLen) : 300;

  let cleaned = String(str)
    // Remove ANSI escape sequences (e.g., \x1b[31m)
    .replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '')
    // Convert CR/LF/TAB into single spaces
    .replace(/[\r\n\t]+/g, ' ')
    // Strip remaining C0/C1 control characters and DEL
    .replace(/[\x00-\x1F\x7F-\x9F]/g, '')
    // Neutralize data envelope markers (ARTEX_DATA / SECSCAN_DATA) and ChatML tags
    .replace(/\[\[\s*(?:END_)?(?:ARTEX|SECSCAN)_DATA[^\]]*\]\]/gi, '[data-marker-removed]')
    .replace(/<\|(?:im_start|im_end|system|user|assistant)\|>/gi, '[role-marker-removed]')
    // Collapse consecutive spaces
    .replace(/\s{2,}/g, ' ')
    .trim();

  // Escape backticks and quotes so banner text cannot break out of markdown fences or quoted strings
  cleaned = cleaned
    .replace(/\\/g, '\\\\')
    .replace(/`/g, '\\`')
    .replace(/"/g, '\\"')
    .replace(/'/g, "\\'");

  if (cleaned.length > limit) {
    cleaned = cleaned.slice(0, limit);
  }

  return cleaned;
}

const HTML_ENTITIES = {
  '&amp;': '&',
  '&lt;': '<',
  '&gt;': '>',
  '&quot;': '"',
  '&#39;': "'",
  '&apos;': "'"
};

/**
 * Unescapes common HTML/XML entities in a single pass before sanitization.
 */
function decodeHtmlEntities(str) {
  return String(str || '').replace(
    /&(?:amp|lt|gt|quot|apos|#39|#(\d+)|#x([0-9a-fA-F]+));/gi,
    (match, dec, hex) => {
      if (dec !== undefined) {
        const code = Number(dec);
        return Number.isFinite(code) && code >= 32 && code <= 126 ? String.fromCharCode(code) : ' ';
      }
      if (hex !== undefined) {
        const code = Number.parseInt(hex, 16);
        return Number.isFinite(code) && code >= 32 && code <= 126 ? String.fromCharCode(code) : ' ';
      }
      return HTML_ENTITIES[match.toLowerCase()] ?? match;
    }
  );
}

/**
 * Extracts root domain from a hostname (or returns the IP if literal IPv4/IPv6).
 *
 * @param {string} host
 * @returns {{ isIp: boolean, rootDomain: string, subdomain: string }}
 */
export function classifyHost(host) {
  const clean = String(host || '')
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '')
    .replace(/:\d+$/, '')
    .replace(/\.+$/, '');

  if (!clean) {
    return { isIp: false, rootDomain: 'unknown', subdomain: 'unknown' };
  }

  const isIpv4 = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(clean);
  const isIpv6 = clean.includes(':');
  if (isIpv4 || isIpv6) {
    return { isIp: true, rootDomain: clean, subdomain: clean };
  }

  const parts = clean.split('.').filter(Boolean);
  if (parts.length <= 2) {
    return { isIp: false, rootDomain: clean, subdomain: clean };
  }

  // Handle common two-level public suffixes like .co.uk, .com.au, .gov.uk, .org.uk
  const twoPartTlds = new Set(['co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'com.au', 'co.jp', 'com.br', 'co.nz']);
  const lastTwo = parts.slice(-2).join('.');
  const rootDomain = twoPartTlds.has(lastTwo) && parts.length >= 3
    ? parts.slice(-3).join('.')
    : lastTwo;

  return {
    isIp: false,
    rootDomain,
    subdomain: clean
  };
}

/**
 * Parses JSON or JSONL string/array into an array of objects.
 */
function parseJsonOrJsonl(rawInput) {
  if (Array.isArray(rawInput)) return rawInput.filter(x => x && typeof x === 'object');
  if (rawInput && typeof rawInput === 'object') return [rawInput];
  if (typeof rawInput !== 'string') return [];

  const trimmed = rawInput.trim();
  if (!trimmed) return [];

  try {
    const parsed = JSON.parse(trimmed);
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch {
    const items = [];
    for (const line of trimmed.split(/\r?\n/)) {
      const l = line.trim();
      if (!l) continue;
      try {
        const obj = JSON.parse(l);
        if (obj && typeof obj === 'object') items.push(obj);
      } catch {
        // Ignore malformed JSONL line
      }
    }
    return items;
  }
}

/**
 * Parses Nmap output (XML, grepable, plain table, or JSON) into normalized assets, facts, findings.
 */
function parseNmapOutput(rawInput) {
  const assets = [];
  const facts = [];
  const findings = [];

  if (rawInput && typeof rawInput === 'object') {
    const items = parseJsonOrJsonl(rawInput);
    for (const item of items) {
      const host = sanitizeExternalBanner(item.host || item.ip || item.address || '', 120);
      if (!host) continue;
      assets.push({ kind: /^\d+\.\d+\.\d+\.\d+$/.test(host) ? 'ip' : 'subdomain', value: host, host });
      const ports = Array.isArray(item.ports) ? item.ports : [];
      for (const p of ports) {
        const port = Number(p.port || p.portid);
        if (!Number.isFinite(port)) continue;
        const proto = sanitizeExternalBanner(p.protocol || 'tcp', 16);
        const service = sanitizeExternalBanner(p.service || p.name || 'unknown', 64);
        const banner = sanitizeExternalBanner(p.banner || p.product || p.version || '', 200);
        assets.push({ kind: 'service', value: `${host}:${port}/${proto}`, host, port, protocol: proto, service, banner });
        facts.push({
          kind: 'open_port',
          host,
          port,
          protocol: proto,
          service,
          banner,
          detail: `Open port ${port}/${proto} (${service})${banner ? ` banner="${banner}"` : ''}`
        });
      }
    }
    return { assets, facts, findings };
  }

  const text = String(rawInput || '');

  // 1. Check for Nmap XML (<host ...>...</host>)
  if (text.includes('<nmaprun') || text.includes('<host')) {
    const hostBlocks = text.match(/<host[\s>][\s\S]*?<\/host>/gi) || [];
    for (const block of hostBlocks) {
      const addrMatch = block.match(/<address\s+[^>]*addr="([^"]+)"/i);
      const hostnameMatch = block.match(/<hostname\s+[^>]*name="([^"]+)"/i);
      const ip = addrMatch ? sanitizeExternalBanner(decodeHtmlEntities(addrMatch[1]), 100) : '';
      const hostname = hostnameMatch ? sanitizeExternalBanner(decodeHtmlEntities(hostnameMatch[1]), 150) : '';
      const primaryHost = hostname || ip;
      if (!primaryHost) continue;

      if (ip) assets.push({ kind: 'ip', value: ip, host: primaryHost });
      if (hostname) assets.push({ kind: 'subdomain', value: hostname, host: hostname, ip });

      const portMatches = block.matchAll(/<port\s+protocol="([^"]+)"\s+portid="(\d+)"[\s\S]*?<\/port>/gi);
      for (const pm of portMatches) {
        const portXml = pm[0];
        const protocol = sanitizeExternalBanner(decodeHtmlEntities(pm[1]), 16);
        const port = Number(pm[2]);
        const stateMatch = portXml.match(/<state\s+[^>]*state="([^"]+)"/i);
        const state = stateMatch ? stateMatch[1].toLowerCase() : 'open';
        if (state !== 'open') continue;

        const svcMatch = portXml.match(/<service\s+([^>]+)\/?>/i);
        let serviceName = 'unknown';
        let product = '';
        let version = '';
        if (svcMatch) {
          const attrs = svcMatch[1];
          serviceName = (attrs.match(/name="([^"]+)"/i) || [])[1] || 'unknown';
          product = (attrs.match(/product="([^"]+)"/i) || [])[1] || '';
          version = (attrs.match(/version="([^"]+)"/i) || [])[1] || '';
        }

        const safeService = sanitizeExternalBanner(decodeHtmlEntities(serviceName), 64);
        const safeBanner = sanitizeExternalBanner(
          decodeHtmlEntities([product, version].filter(Boolean).join(' ')),
          250
        );

        assets.push({
          kind: 'service',
          value: `${primaryHost}:${port}/${protocol}`,
          host: primaryHost,
          port,
          protocol,
          service: safeService,
          banner: safeBanner
        });

        facts.push({
          kind: 'open_port',
          host: primaryHost,
          port,
          protocol,
          service: safeService,
          banner: safeBanner,
          detail: `Open port ${port}/${protocol} (${safeService})${safeBanner ? ` banner="${safeBanner}"` : ''}`
        });
      }
    }
    return { assets, facts, findings };
  }

  // 2. Grepable Nmap format: Host: 93.184.216.34 (example.com) Ports: 80/open/tcp//http//Apache httpd 2.4.41/
  let currentHost = '';
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;

    const grepMatch = line.match(/^Host:\s+(\S+)\s*(?:\(([^)]*)\))?\s+Ports:\s+(.+)$/i);
    if (grepMatch) {
      const ip = sanitizeExternalBanner(grepMatch[1], 100);
      const hostname = sanitizeExternalBanner(grepMatch[2] || '', 150);
      const primaryHost = hostname || ip;
      if (ip) assets.push({ kind: 'ip', value: ip, host: primaryHost });
      if (hostname) assets.push({ kind: 'subdomain', value: hostname, host: hostname, ip });

      const portEntries = grepMatch[3].split(',').map(s => s.trim());
      for (const entry of portEntries) {
        const parts = entry.split('/');
        if (parts.length < 3) continue;
        const port = Number(parts[0]);
        const state = (parts[1] || '').toLowerCase();
        const protocol = sanitizeExternalBanner(parts[2] || 'tcp', 16);
        const service = sanitizeExternalBanner(parts[4] || 'unknown', 64);
        const banner = sanitizeExternalBanner(parts[6] || '', 250);
        if (!Number.isFinite(port) || state !== 'open') continue;

        assets.push({
          kind: 'service',
          value: `${primaryHost}:${port}/${protocol}`,
          host: primaryHost,
          port,
          protocol,
          service,
          banner
        });
        facts.push({
          kind: 'open_port',
          host: primaryHost,
          port,
          protocol,
          service,
          banner,
          detail: `Open port ${port}/${protocol} (${service})${banner ? ` banner="${banner}"` : ''}`
        });
      }
      continue;
    }

    // 3. Standard Nmap text output
    const reportHeader = line.match(/^Nmap scan report for\s+([^\s(]+)(?:\s+\(([^)]+)\))?/i);
    if (reportHeader) {
      const h1 = sanitizeExternalBanner(reportHeader[1], 150);
      const h2 = sanitizeExternalBanner(reportHeader[2] || '', 100);
      currentHost = h1;
      if (h2) {
        assets.push({ kind: 'subdomain', value: h1, host: h1, ip: h2 });
        assets.push({ kind: 'ip', value: h2, host: h1 });
      } else {
        assets.push({ kind: /^\d+\.\d+\.\d+\.\d+$/.test(h1) ? 'ip' : 'subdomain', value: h1, host: h1 });
      }
      continue;
    }

    const portLine = line.match(/^(\d+)\/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$/i);
    if (portLine) {
      const host = currentHost || 'unknown';
      const port = Number(portLine[1]);
      const protocol = sanitizeExternalBanner(portLine[2].toLowerCase(), 16);
      const service = sanitizeExternalBanner(portLine[3], 64);
      const banner = sanitizeExternalBanner(portLine[4] || '', 250);

      assets.push({
        kind: 'service',
        value: `${host}:${port}/${protocol}`,
        host,
        port,
        protocol,
        service,
        banner
      });
      facts.push({
        kind: 'open_port',
        host,
        port,
        protocol,
        service,
        banner,
        detail: `Open port ${port}/${protocol} (${service})${banner ? ` banner="${banner}"` : ''}`
      });
    }
  }

  return { assets, facts, findings };
}

/**
 * Parses structured external scanner output (nmap, nuclei, httpx, ffuf, bbot)
 * into normalized { assets, facts, findings } with prompt-injection sanitization.
 *
 * @param {'nmap'|'nuclei'|'httpx'|'ffuf'|'bbot'|string} format
 * @param {string|object|Array} rawInput
 * @returns {{ assets: Array<object>, facts: Array<object>, findings: Array<object> }}
 */
export function ingestScanOutput(format, rawInput) {
  const fmt = String(format || '').trim().toLowerCase();

  if (fmt === 'nmap') {
    return parseNmapOutput(rawInput);
  }

  const assets = [];
  const facts = [];
  const findings = [];

  if (fmt === 'nuclei') {
    const records = parseJsonOrJsonl(rawInput);
    for (const rec of records) {
      const templateId = sanitizeExternalBanner(rec['template-id'] || rec.templateId || rec.id || 'nuclei-finding', 100);
      const info = rec.info && typeof rec.info === 'object' ? rec.info : {};
      const title = sanitizeExternalBanner(info.name || rec.name || templateId, 200);
      const rawSev = String(info.severity || rec.severity || 'medium').toUpperCase();
      const severity = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'].includes(rawSev)
        ? rawSev
        : (rawSev === 'INFO' ? 'LOW' : 'MEDIUM');
      const rawMatchedUrl = stripUserinfo(rec['matched-at'] || rec.matched || rec.host || rec.url || '');
      const ip = sanitizeExternalBanner(rec.ip || '', 100);
      const extracted = Array.isArray(rec['extracted-results'])
        ? rec['extracted-results'].map(x => sanitizeExternalBanner(x, 200)).join(', ')
        : sanitizeExternalBanner(rec.matcher_name || rec['matcher-name'] || info.description || '', 250);

      let parsedHost = '';
      let parsedPath = '/';
      try {
        const u = new URL(rawMatchedUrl);
        parsedHost = u.hostname;
        parsedPath = u.pathname + u.search;
      } catch {
        // Not a full URL
      }
      const matchedUrl = sanitizeExternalBanner(rawMatchedUrl, 1000);
      const host = sanitizeExternalBanner(parsedHost || rec.host || '', 150);
      const pathName = sanitizeExternalBanner(parsedPath, 500);

      if (host) {
        assets.push({ kind: 'subdomain', value: host, host, ip: ip || undefined });
      }
      if (matchedUrl) {
        assets.push({ kind: 'endpoint', value: matchedUrl, url: matchedUrl, host, path: pathName });
      }

      const cweList = info.classification?.['cwe-id'] || info.classification?.cweId || [];
      const cwe = Array.isArray(cweList) && cweList.length > 0
        ? String(cweList[0]).toUpperCase()
        : 'CWE-16';
      const cvssScore = Number(info.classification?.['cvss-score'] ?? info.classification?.cvssScore) ||
        (severity === 'CRITICAL' ? 9.1 : severity === 'HIGH' ? 7.5 : severity === 'MEDIUM' ? 5.3 : 3.1);

      findings.push({
        name: templateId,
        checkId: templateId,
        title,
        status: severity === 'NONE' ? 'SAFE' : 'VULNERABLE',
        severity,
        target: matchedUrl || host,
        path: pathName,
        detail: extracted,
        cwe,
        cvssScore,
        source: 'nuclei'
      });

      facts.push({
        kind: 'nuclei_match',
        host,
        url: matchedUrl,
        templateId,
        severity,
        detail: `Nuclei matched ${templateId} (${severity}) on ${matchedUrl || host}${extracted ? `: "${extracted}"` : ''}`
      });
    }
    return { assets, facts, findings };
  }

  if (fmt === 'httpx') {
    const records = parseJsonOrJsonl(rawInput);
    for (const rec of records) {
      const rawUrl = stripUserinfo(rec.url || rec.input || '');
      const status = Number(rec.status_code ?? rec['status-code'] ?? rec.status) || 0;
      const title = sanitizeExternalBanner(decodeHtmlEntities(rec.title || ''), 200);
      const server = sanitizeExternalBanner(rec.webserver || rec.server || '', 150);
      const techList = Array.isArray(rec.tech || rec.technologies)
        ? (rec.tech || rec.technologies).map(t => sanitizeExternalBanner(t, 80))
        : [];
      let parsedHost = '';
      try {
        if (rawUrl) parsedHost = new URL(rawUrl).hostname;
      } catch {
        // ignore
      }
      const url = sanitizeExternalBanner(rawUrl, 1000);
      const host = sanitizeExternalBanner(parsedHost || rec.host || rec.input || '', 150);

      if (host) {
        assets.push({ kind: 'subdomain', value: host, host });
      }
      if (url) {
        assets.push({
          kind: 'service',
          value: url,
          url,
          host,
          status,
          title,
          server,
          technologies: techList
        });
      }
      facts.push({
        kind: 'http_service',
        host,
        url,
        status,
        title,
        server,
        technologies: techList,
        detail: `HTTP ${status} on ${url || host}${title ? ` title="${title}"` : ''}${server ? ` server="${server}"` : ''}`
      });
    }
    return { assets, facts, findings };
  }

  if (fmt === 'ffuf') {
    let results = [];
    if (rawInput && typeof rawInput === 'object' && Array.isArray(rawInput.results)) {
      results = rawInput.results;
    } else if (typeof rawInput === 'string') {
      try {
        const parsed = JSON.parse(rawInput);
        results = Array.isArray(parsed?.results) ? parsed.results : (Array.isArray(parsed) ? parsed : []);
      } catch {
        results = parseJsonOrJsonl(rawInput);
      }
    } else if (Array.isArray(rawInput)) {
      results = rawInput;
    }

    for (const item of results) {
      const rawUrl = stripUserinfo(item.url || '');
      const status = Number(item.status) || 0;
      const length = Number(item.length) || 0;
      const fuzzWord = sanitizeExternalBanner(item.input?.FUZZ || item.path || '', 150);
      const redirectLocation = sanitizeExternalBanner(item.redirectlocation || '', 200);

      let parsedHost = '';
      let parsedPath = fuzzWord ? `/${fuzzWord.replace(/^\/+/, '')}` : '/';
      try {
        if (rawUrl) {
          const u = new URL(rawUrl);
          parsedHost = u.hostname;
          parsedPath = u.pathname + u.search;
        }
      } catch {
        // ignore
      }
      const url = sanitizeExternalBanner(rawUrl, 1000);
      const host = sanitizeExternalBanner(parsedHost || item.host || '', 150);
      const pathName = sanitizeExternalBanner(parsedPath, 500);

      assets.push({
        kind: 'endpoint',
        value: url || pathName,
        url,
        host,
        path: pathName,
        status,
        length
      });

      facts.push({
        kind: 'ffuf_endpoint',
        host,
        url,
        path: pathName,
        status,
        length,
        redirectLocation,
        detail: `Discovered endpoint ${pathName} (HTTP ${status}, ${length}B)`
      });

      if (status === 200 && /\.(env|git|bak|sql|old|config|zip)$/i.test(pathName)) {
        findings.push({
          name: 'sensitive-files',
          checkId: 'sensitive-files',
          status: 'VULNERABLE',
          severity: 'HIGH',
          target: url || host,
          path: pathName,
          detail: `Exposed sensitive endpoint discovered via ffuf: ${pathName} (HTTP ${status})`,
          source: 'ffuf'
        });
      }
    }
    return { assets, facts, findings };
  }

  if (fmt === 'bbot') {
    const events = parseJsonOrJsonl(rawInput);
    for (const ev of events) {
      const type = String(ev.type || '').toUpperCase();
      const scopeDistance = Number(ev.scope_distance ?? ev.scopeDistance ?? 0);
      const host = sanitizeExternalBanner(ev.host || '', 150);
      const rawData = typeof ev.data === 'string'
        ? sanitizeExternalBanner(ev.data, 250)
        : sanitizeExternalBanner(JSON.stringify(ev.data || {}), 250);

      if (scopeDistance > 0) {
        facts.push({
          kind: 'third_party_intel',
          type,
          host,
          scopeDistance,
          detail: `Third-party intel (${type}, distance=${scopeDistance}): "${rawData}"`
        });
        continue;
      }

      if (type === 'DNS_NAME') {
        assets.push({ kind: 'subdomain', value: rawData || host, host: rawData || host });
      } else if (type === 'IP_ADDRESS') {
        assets.push({ kind: 'ip', value: rawData || host, host: rawData || host });
      } else if (type === 'OPEN_TCP_PORT') {
        assets.push({ kind: 'service', value: rawData, host });
      } else if (type === 'URL') {
        const cleanUrl = sanitizeExternalBanner(
          stripUserinfo(typeof ev.data === 'string' ? ev.data : (ev.data?.url || '')),
          1000
        );
        assets.push({ kind: 'endpoint', value: cleanUrl, url: cleanUrl, host });
      } else if (type === 'VULNERABILITY' || type === 'FINDING') {
        const desc = typeof ev.data === 'object' && ev.data !== null
          ? sanitizeExternalBanner(ev.data.description || ev.data.name || rawData, 250)
          : rawData;
        const sevRaw = typeof ev.data === 'object' && ev.data?.severity
          ? String(ev.data.severity).toUpperCase()
          : 'MEDIUM';
        const severity = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'].includes(sevRaw) ? sevRaw : 'MEDIUM';
        findings.push({
          name: 'bbot-finding',
          checkId: 'bbot-finding',
          status: 'VULNERABLE',
          severity,
          target: host,
          detail: desc,
          source: 'bbot'
        });
      }

      facts.push({
        kind: 'bbot_event',
        type,
        host,
        scopeDistance: 0,
        detail: `BBOT ${type} on ${host || rawData}: "${rawData}"`
      });
    }
    return { assets, facts, findings };
  }

  throw new Error(`Unsupported scan ingestion format: "${format}". Expected nmap, nuclei, httpx, ffuf, or bbot.`);
}

/**
 * Builds ARTEX's hierarchical asset-to-finding tree:
 *   root_domain / ip -> subdomain -> service / app -> endpoint -> findings[]
 * with deduplicated severity rollup counts across ancestor chains.
 *
 * @param {Array<object>} [findings=[]]
 * @param {Array<object>} [assets=[]]
 * @returns {{
 *   roots: Array<object>,
 *   nodes: Array<object>,
 *   unlinked: Array<object>,
 *   totalFindings: number,
 *   totalAssets: number,
 *   summary: { total: number, CRITICAL: number, HIGH: number, MEDIUM: number, LOW: number, NONE: number, vulnerable: number, suspicious: number }
 * }}
 */
export function buildFindingAssetTree(findings = [], assets = []) {
  const safeFindings = Array.isArray(findings) ? findings.filter(f => f && typeof f === 'object') : [];
  const safeAssets = Array.isArray(assets) ? assets.filter(a => a && typeof a === 'object') : [];

  const rootMap = new Map();
  const unlinked = [];

  function createCounts() {
    return {
      total: 0,
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      NONE: 0,
      vulnerable: 0,
      suspicious: 0
    };
  }

  function ensureRoot(hostStr) {
    const { isIp, rootDomain } = classifyHost(hostStr);
    const rootKey = `${isIp ? 'ip' : 'root_domain'}:${rootDomain}`;
    if (!rootMap.has(rootKey)) {
      rootMap.set(rootKey, {
        id: rootKey,
        kind: isIp ? 'ip' : 'root_domain',
        name: rootDomain,
        value: rootDomain,
        counts: createCounts(),
        _findingIds: new Set(),
        subdomains: new Map(),
        children: []
      });
    }
    return rootMap.get(rootKey);
  }

  function ensureSubdomain(rootNode, hostStr) {
    const { subdomain } = classifyHost(hostStr);
    const subKey = subdomain || rootNode.value;
    if (!rootNode.subdomains.has(subKey)) {
      const subNode = {
        id: `subdomain:${subKey}`,
        kind: 'subdomain',
        name: subKey,
        value: subKey,
        counts: createCounts(),
        _findingIds: new Set(),
        services: new Map(),
        children: []
      };
      rootNode.subdomains.set(subKey, subNode);
      rootNode.children.push(subNode);
    }
    return rootNode.subdomains.get(subKey);
  }

  function ensureService(subNode, serviceName) {
    const svcKey = serviceName || `https://${subNode.value}:443`;
    if (!subNode.services.has(svcKey)) {
      const svcNode = {
        id: `service:${svcKey}`,
        kind: 'service',
        name: svcKey,
        value: svcKey,
        counts: createCounts(),
        _findingIds: new Set(),
        endpoints: new Map(),
        children: []
      };
      subNode.services.set(svcKey, svcNode);
      subNode.children.push(svcNode);
    }
    return subNode.services.get(svcKey);
  }

  function ensureEndpoint(svcNode, endpointPath) {
    const epKey = endpointPath || '/';
    if (!svcNode.endpoints.has(epKey)) {
      const epNode = {
        id: `endpoint:${svcNode.value}${epKey}`,
        kind: 'endpoint',
        name: epKey,
        value: epKey,
        counts: createCounts(),
        _findingIds: new Set(),
        findings: [],
        children: []
      };
      svcNode.endpoints.set(epKey, epNode);
      svcNode.children.push(epNode);
    }
    return svcNode.endpoints.get(epKey);
  }

  function parseTargetLocation(rawUrlOrHost, explicitPath) {
    const raw = String(rawUrlOrHost || '').trim();
    if (!raw) return null;
    try {
      const u = new URL(raw.includes('://') ? raw : `https://${raw}`);
      const host = u.hostname.toLowerCase();
      const proto = u.protocol.replace(':', '') || 'https';
      const port = u.port || (proto === 'http' ? '80' : '443');
      const service = `${proto}://${host}:${port}`;
      const endpoint = explicitPath || (u.pathname + u.search) || '/';
      return { host, service, endpoint };
    } catch {
      return {
        host: raw.split('/')[0].toLowerCase(),
        service: `https://${raw.split('/')[0].toLowerCase()}:443`,
        endpoint: explicitPath || '/'
      };
    }
  }

  // 1. Seed hierarchy from explicit assets
  for (const asset of safeAssets) {
    const rawTarget = asset.url || asset.host || asset.value || '';
    if (!rawTarget) continue;
    const loc = parseTargetLocation(rawTarget, asset.path);
    if (!loc || !loc.host) continue;
    const rootNode = ensureRoot(loc.host);
    const subNode = ensureSubdomain(rootNode, loc.host);
    if (asset.kind === 'service' || asset.kind === 'app' || asset.kind === 'endpoint' || asset.url || asset.port) {
      let svcLabel = loc.service;
      if (asset.url) {
        svcLabel = loc.service;
      } else if (asset.service) {
        const svcLower = String(asset.service).trim().toLowerCase();
        if (svcLower === 'http' || svcLower === 'https') {
          svcLabel = `${svcLower}://${loc.host}:${asset.port || (svcLower === 'http' ? 80 : 443)}`;
        } else {
          svcLabel = `${loc.host}:${asset.port || 80}/${asset.service}`;
        }
      }
      const svcNode = ensureService(subNode, svcLabel);
      if (asset.kind === 'endpoint' || asset.path) {
        ensureEndpoint(svcNode, loc.endpoint);
      }
    }
  }

  // 2. Attach findings and roll up deduplicated severity counts
  const summary = createCounts();

  safeFindings.forEach((finding, idx) => {
    const findingUid = finding.id || `${finding.checkId || finding.name || 'finding'}#${idx}`;
    const sev = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'].includes(String(finding.severity).toUpperCase())
      ? String(finding.severity).toUpperCase()
      : 'NONE';
    const status = String(finding.status || 'SAFE').toUpperCase();

    summary.total++;
    summary[sev] = (summary[sev] || 0) + 1;
    if (status === 'VULNERABLE') summary.vulnerable++;
    if (status === 'SUSPICIOUS') summary.suspicious++;

    const rawTargets = Array.isArray(finding.pages) && finding.pages.length > 0
      ? finding.pages
      : [finding.target || finding.url || finding.host || ''].filter(Boolean);

    if (rawTargets.length === 0) {
      unlinked.push(finding);
      return;
    }

    let linkedCount = 0;
    for (const t of rawTargets) {
      const loc = parseTargetLocation(t, finding.path);
      if (!loc || !loc.host) {
        continue;
      }

      const rootNode = ensureRoot(loc.host);
      const subNode = ensureSubdomain(rootNode, loc.host);
      const svcNode = ensureService(subNode, loc.service);
      const epNode = ensureEndpoint(svcNode, loc.endpoint);

      epNode.findings.push(finding);
      linkedCount += 1;

      for (const ancestor of [rootNode, subNode, svcNode, epNode]) {
        if (!ancestor._findingIds.has(findingUid)) {
          ancestor._findingIds.add(findingUid);
          ancestor.counts.total++;
          ancestor.counts[sev] = (ancestor.counts[sev] || 0) + 1;
          if (status === 'VULNERABLE') ancestor.counts.vulnerable++;
          if (status === 'SUSPICIOUS') ancestor.counts.suspicious++;
        }
      }
    }
    if (linkedCount === 0) {
      unlinked.push(finding);
    }
  });

  // Clean internal sets/maps for clean JSON serialization while keeping children arrays
  const roots = Array.from(rootMap.values()).map(root => {
    delete root._findingIds;
    delete root.subdomains;
    for (const sub of root.children) {
      delete sub._findingIds;
      delete sub.services;
      for (const svc of sub.children) {
        delete svc._findingIds;
        delete svc.endpoints;
        for (const ep of svc.children) {
          delete ep._findingIds;
        }
      }
    }
    return root;
  });

  return {
    roots,
    nodes: roots,
    unlinked,
    totalFindings: safeFindings.length,
    totalAssets: roots.length,
    summary
  };
}

/**
 * Async 4-worker DNS (A, AAAA, CNAME) and HTTP <title>/banner enrichment engine
 * with a 5-minute per-host cooldown cache and SSRF validation.
 */
export class EnrichEngine {
  /**
   * @param {object} [options={}]
   * @param {number} [options.concurrency=4]
   * @param {number} [options.cooldownMs=300000]
   * @param {number} [options.timeoutMs=12000]
   * @param {object} [options.dns]
   * @param {Function} [options.fetch]
   */
  constructor(options = {}) {
    this.concurrency = Number(options.concurrency) > 0 ? Number(options.concurrency) : 4;
    this.cooldownMs = Number.isFinite(options.cooldownMs) && options.cooldownMs >= 0
      ? Number(options.cooldownMs)
      : 300_000;
    this.timeoutMs = Number(options.timeoutMs) > 0 ? Number(options.timeoutMs) : 12_000;
    this.limit = pLimit(this.concurrency);
    this.dnsResolver = options.dns || dns;
    this.fetchImpl = options.fetch || ((...args) => globalThis.fetch(...args));
    this.allowPrivate = Boolean(options.allowPrivate);
    this.targetPinStore = options.targetPinStore || null;
    this.maxCacheSize = Number(options.maxCacheSize) > 0 ? Math.floor(Number(options.maxCacheSize)) : 1000;
    this.maxBodyBytes = Number(options.maxBodyBytes) > 0 ? Math.floor(Number(options.maxBodyBytes)) : 1024 * 1024;
    this.cooldownCache = new Map();
  }

  _setCooldown(cacheKey, entry, now = Date.now()) {
    if (this.cooldownCache.has(cacheKey)) {
      this.cooldownCache.delete(cacheKey);
    }
    if (this.cooldownCache.size >= this.maxCacheSize) {
      for (const [k, v] of this.cooldownCache.entries()) {
        if (now >= v.timestamp && now - v.timestamp >= this.cooldownMs) {
          this.cooldownCache.delete(k);
        }
      }
      while (this.cooldownCache.size >= this.maxCacheSize) {
        const oldestKey = this.cooldownCache.keys().next().value;
        if (oldestKey === undefined) break;
        this.cooldownCache.delete(oldestKey);
      }
    }
    this.cooldownCache.set(cacheKey, entry);
  }

  async _readBoundedBody(res, maxBytes = this.maxBodyBytes) {
    const limit = Number(maxBytes) > 0 ? Math.floor(Number(maxBytes)) : 1024 * 1024;
    if (res?.body && typeof res.body.getReader === 'function' && !res.bodyUsed) {
      const reader = res.body.getReader();
      const decoder = new TextDecoder('utf-8', { fatal: false });
      const chunks = [];
      let totalBytes = 0;
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (!value || value.byteLength === 0) continue;
          const remaining = limit - totalBytes;
          if (remaining <= 0) {
            await reader.cancel().catch(() => {});
            break;
          }
          if (value.byteLength >= remaining) {
            chunks.push(decoder.decode(value.subarray(0, remaining), { stream: false }));
            totalBytes += remaining;
            await reader.cancel().catch(() => {});
            break;
          }
          chunks.push(decoder.decode(value, { stream: true }));
          totalBytes += value.byteLength;
        }
        if (totalBytes < limit) {
          const tail = decoder.decode();
          if (tail) chunks.push(tail);
        }
      } catch {
        await reader.cancel().catch(() => {});
      }
      const text = chunks.join('');
      return { text, byteLength: Buffer.byteLength(text, 'utf8') };
    }

    const rawText = typeof res?.text === 'function'
      ? await res.text()
      : (typeof res?.text === 'string' ? res.text : String(res?.body ?? ''));
    const buf = Buffer.from(String(rawText || ''), 'utf8');
    if (buf.byteLength > limit) {
      const text = buf.subarray(0, limit).toString('utf8');
      return { text, byteLength: Buffer.byteLength(text, 'utf8') };
    }
    return { text: String(rawText || ''), byteLength: buf.byteLength };
  }

  /**
   * Checks whether a given (kind, key) pair is currently within its cooldown window.
   */
  isOnCooldown(kind, key, now = Date.now()) {
    const cacheKey = `${kind}:${String(key || '').toLowerCase()}`;
    const entry = this.cooldownCache.get(cacheKey);
    if (!entry) return false;
    if (now - entry.timestamp < this.cooldownMs) {
      return true;
    }
    this.cooldownCache.delete(cacheKey);
    return false;
  }

  /**
   * Clears all cooldown entries.
   */
  clearCooldowns() {
    this.cooldownCache.clear();
  }

  /**
   * Resolves DNS A, AAAA, and CNAME records for a public hostname using the 4-worker pool
   * and 5-minute per-host cooldown cache.
   *
   * @param {string} host
   * @param {object} [options={}]
   */
  async resolveDomain(host, options = {}) {
    const rawHost = String(host || '').trim().toLowerCase().replace(/\.+$/, '');
    if (!rawHost) {
      throw new Error('Hostname must be a non-empty string');
    }

    const allowPrivate = options.allowPrivate !== undefined ? Boolean(options.allowPrivate) : this.allowPrivate;
    const targetPinStore = options.targetPinStore ?? this.targetPinStore;

    // Validate host against SSRF rules via synthetic https URL
    const validation = validateTargetUrl(`https://${rawHost}`, { allowPrivate });
    if (!validation.valid) {
      throw new Error(`DNS enrichment blocked by SSRF policy: ${validation.error}`);
    }

    const normalizedHost = validation.hostname;
    const cacheKey = `dns:${normalizedHost}`;
    const now = typeof options.now === 'number' ? options.now : Date.now();

    if (!options.force && this.cooldownCache.has(cacheKey)) {
      const prev = this.cooldownCache.get(cacheKey);
      if (now - prev.timestamp < this.cooldownMs) {
        if (!prev.allowPrivate || allowPrivate) {
          this.cooldownCache.delete(cacheKey);
          this.cooldownCache.set(cacheKey, prev);
          return {
            ...prev.result,
            cached: true,
            skippedCooldown: true
          };
        }
      } else {
        this.cooldownCache.delete(cacheKey);
      }
    }

    return this.limit(async () => {
      const resolve4Fn = typeof this.dnsResolver.resolve4 === 'function'
        ? this.dnsResolver.resolve4.bind(this.dnsResolver)
        : async () => [];
      const resolve6Fn = typeof this.dnsResolver.resolve6 === 'function'
        ? this.dnsResolver.resolve6.bind(this.dnsResolver)
        : async () => [];
      const resolveCnameFn = typeof this.dnsResolver.resolveCname === 'function'
        ? this.dnsResolver.resolveCname.bind(this.dnsResolver)
        : async () => [];

      const [v4Res, v6Res, cnameRes] = await Promise.allSettled([
        resolve4Fn(normalizedHost),
        resolve6Fn(normalizedHost),
        resolveCnameFn(normalizedHost)
      ]);

      const rawIpv4 = v4Res.status === 'fulfilled' && Array.isArray(v4Res.value) ? v4Res.value : [];
      const rawIpv6 = v6Res.status === 'fulfilled' && Array.isArray(v6Res.value) ? v6Res.value : [];
      const rawCnames = cnameRes.status === 'fulfilled' && Array.isArray(cnameRes.value) ? cnameRes.value : [];

      // Filter out any private/loopback IPs (unless allowPrivate) & always block metadata/forbidden IPs
      const ipv4 = rawIpv4.filter(ip => validateTargetUrl(`http://${ip}`, { allowPrivate }).valid);
      const ipv6 = rawIpv6.filter(ip => validateTargetUrl(`http://[${ip}]`, { allowPrivate }).valid);
      const allIps = [...ipv4, ...ipv6];
      if (targetPinStore && typeof targetPinStore.verifyOrPin === 'function' && allIps.length > 0) {
        const pinRes = targetPinStore.verifyOrPin(normalizedHost, allIps, { allowPrivate });
        if (pinRes && pinRes.valid === false) {
          throw new Error(`DNS enrichment blocked by SSRF policy: ${pinRes.reason || pinRes.error || 'Target pinning rejected'}`);
        }
      }
      const cnames = rawCnames.map(c => sanitizeExternalBanner(c, 150)).filter(Boolean);

      const assets = [
        { kind: 'subdomain', value: normalizedHost, host: normalizedHost },
        ...ipv4.map(ip => ({ kind: 'ip', value: ip, host: normalizedHost, family: 'IPv4' })),
        ...ipv6.map(ip => ({ kind: 'ip', value: ip, host: normalizedHost, family: 'IPv6' }))
      ];

      const result = {
        host: normalizedHost,
        ipv4,
        ipv6,
        cnames,
        assets,
        cached: false,
        skippedCooldown: false,
        timestamp: now
      };

      this._setCooldown(cacheKey, { timestamp: now, allowPrivate, result }, now);
      return result;
    });
  }

  /**
   * Alias of resolveDomain.
   */
  async probeDns(host, options = {}) {
    return this.resolveDomain(host, options);
  }

  /**
   * Builds a resolver function for resolveAndValidateTarget from this.dnsResolver.
   */
  _buildValidationResolver() {
    if (typeof this.dnsResolver === 'function') {
      return this.dnsResolver;
    }
    return async (host, opts) => {
      if (this.dnsResolver && typeof this.dnsResolver.lookup === 'function') {
        return this.dnsResolver.lookup(host, opts);
      }
      if (
        this.dnsResolver &&
        (typeof this.dnsResolver.resolve4 === 'function' || typeof this.dnsResolver.resolve6 === 'function')
      ) {
        const [v4, v6] = await Promise.allSettled([
          typeof this.dnsResolver.resolve4 === 'function' ? this.dnsResolver.resolve4(host) : Promise.resolve([]),
          typeof this.dnsResolver.resolve6 === 'function' ? this.dnsResolver.resolve6(host) : Promise.resolve([])
        ]);
        const ips = [
          ...(v4.status === 'fulfilled' && Array.isArray(v4.value) ? v4.value : []),
          ...(v6.status === 'fulfilled' && Array.isArray(v6.value) ? v6.value : [])
        ];
        if (ips.length > 0) return ips;
        if (v4.status === 'rejected' && v6.status === 'rejected') {
          throw v4.reason || v6.reason;
        }
        return [];
      }
      if (this.dnsResolver && typeof this.dnsResolver.resolve === 'function') {
        return this.dnsResolver.resolve(host);
      }
      return dns.lookup(host, opts);
    };
  }

  /**
   * Probes an HTTP/HTTPS URL to extract status code, <title>, and Server/X-Powered-By banners.
   * Enforces resolveAndValidateTarget (DNS + SSRF) before probing and applies a 5-minute per-host cooldown.
   *
   * @param {string} rawUrl
   * @param {object} [options={}]
   */
  async probeHttp(rawUrl, options = {}) {
    const allowPrivate = options.allowPrivate !== undefined ? Boolean(options.allowPrivate) : this.allowPrivate;
    const targetPinStore = options.targetPinStore ?? this.targetPinStore;

    const validation = await resolveAndValidateTarget(rawUrl, {
      resolver: this._buildValidationResolver(),
      allowPrivate,
      ...(targetPinStore ? { targetPinStore } : {})
    });
    if (!validation.valid) {
      throw new Error(`HTTP probe blocked by SSRF policy: ${validation.reason || validation.error}`);
    }

    const normalizedUrl = validation.normalized;
    const hostname = validation.hostname;
    const cacheKey = `http:${hostname}`;
    const now = typeof options.now === 'number' ? options.now : Date.now();

    if (!options.force && this.cooldownCache.has(cacheKey)) {
      const prev = this.cooldownCache.get(cacheKey);
      if (now - prev.timestamp < this.cooldownMs) {
        if (!prev.allowPrivate || allowPrivate) {
          this.cooldownCache.delete(cacheKey);
          this.cooldownCache.set(cacheKey, prev);
          return {
            ...prev.result,
            cached: true,
            skippedCooldown: true
          };
        }
      } else {
        this.cooldownCache.delete(cacheKey);
      }
    }

    return this.limit(async () => {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);

      try {
        const res = await this.fetchImpl(normalizedUrl, {
          method: 'GET',
          redirect: 'manual',
          signal: controller.signal,
          headers: {
            'User-Agent': 'SecurityScanner-Enrich/2.2',
            Accept: 'text/html,application/xhtml+xml,*/*;q=0.8'
          }
        });

        const { text: bodySlice, byteLength } = await this._readBoundedBody(res, this.maxBodyBytes);

        const titleMatch = bodySlice.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
        const rawTitle = titleMatch ? decodeHtmlEntities(titleMatch[1]) : '';
        const title = sanitizeExternalBanner(rawTitle, 200);

        const getHeader = (name) => {
          if (!res.headers) return '';
          if (typeof res.headers.get === 'function') return res.headers.get(name) || '';
          return res.headers[name] || res.headers[name.toLowerCase()] || '';
        };

        const server = sanitizeExternalBanner(getHeader('server'), 150);
        const poweredBy = sanitizeExternalBanner(getHeader('x-powered-by'), 150);
        const contentLengthHeader = getHeader('content-length');
        const contentLength = contentLengthHeader ? Number(contentLengthHeader) : byteLength;

        const result = {
          url: normalizedUrl,
          host: hostname,
          status: Number(res.status) || 0,
          contentLength,
          title,
          server,
          poweredBy,
          cached: false,
          skippedCooldown: false,
          timestamp: now
        };

        this._setCooldown(cacheKey, { timestamp: now, allowPrivate, result }, now);
        return result;
      } finally {
        clearTimeout(timer);
      }
    });
  }

  /**
   * Alias of probeHttp.
   */
  async probeSite(rawUrl, options = {}) {
    return this.probeHttp(rawUrl, options);
  }

  /**
   * Enriches a single finding with CWE, OWASP, CVSS score, remediation, references,
   * and proof-strength quality descriptors from getCheckMeta.
   *
   * @param {object} finding
   * @returns {object}
   */
  enrichFinding(finding, options = {}) {
    if (!finding || typeof finding !== 'object') {
      return finding;
    }

    const checkKey = finding.checkId || finding.name || finding.id || 'custom-check';
    const meta = getCheckMeta(checkKey);
    const fallbackCwe = CWE_OWASP_MAP[meta.id] || CWE_OWASP_MAP.default;

    const status = String(finding.status || 'SAFE').toUpperCase();
    const trafficBindings = Array.isArray(finding.trafficBindings)
      ? finding.trafficBindings
      : (Array.isArray(finding.evidenceBindings) ? finding.evidenceBindings : []);
    const trafficCount = Number.isFinite(finding.trafficCount)
      ? Number(finding.trafficCount)
      : trafficBindings.length;

    const poeLevel = Number.isFinite(finding.poeLevel ?? finding.poe_level)
      ? Number(finding.poeLevel ?? finding.poe_level)
      : (status === 'VULNERABLE' ? (trafficCount > 0 ? 3 : 2) : status === 'SUSPICIOUS' ? 1 : 0);

    const verificationStatus = finding.verificationStatus ||
      finding.verification_status ||
      (poeLevel >= 3 && trafficCount > 0 ? 'verified' : status === 'VULNERABLE' || status === 'SUSPICIOUS' ? 'unverified' : 'not_assessed');

    const baseEnriched = {
      ...finding,
      checkId: finding.checkId || meta.id,
      title: finding.title || meta.title,
      category: finding.category || meta.category,
      cwe: finding.cwe || meta.cwe || fallbackCwe.cwe,
      owasp: finding.owasp || meta.owasp || fallbackCwe.owasp,
      cvssScore: Number.isFinite(finding.cvssScore) ? finding.cvssScore : (meta.cvssScore ?? fallbackCwe.cvssScore),
      cveIds: Array.isArray(finding.cveIds) ? finding.cveIds : [...(meta.cveIds || [])],
      remediation: finding.remediation || finding.fix || meta.remediation || meta.defaultFix,
      references: Array.isArray(finding.references) && finding.references.length > 0
        ? finding.references
        : [...(meta.references || fallbackCwe.references)],
      poeLevel,
      verificationStatus,
      trafficCount,
      meta
    };

    const capturedTraces = options.capturedTraces || finding._capturedTraces || [];
    const reproduction = status !== 'SAFE'
      ? buildReproductionContext(baseEnriched, { capturedTraces })
      : null;
    if (Object.hasOwn(baseEnriched, '_capturedTraces')) {
      delete baseEnriched._capturedTraces;
    }
    if (reproduction) {
      baseEnriched.reproduction = reproduction;
      if (!baseEnriched.trafficId && reproduction.trafficId) {
        baseEnriched.trafficId = reproduction.trafficId;
      }
    }

    return verifyFindingBeforeReport(baseEnriched, { capturedTraces });
  }

  /**
   * Batch enriches an array of findings.
   *
   * @param {Array<object>} [findings=[]]
   * @returns {Array<object>}
   */
  enrichFindings(findings = []) {
    if (!Array.isArray(findings)) return [];
    return findings.map(f => this.enrichFinding(f));
  }
}
