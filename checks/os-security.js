import {
  detectOperatingSystemFromSignals,
  parseOpenSshBanner
} from '../core/os-scanner.js';
import {
  isVersionAffected,
  resolveTargetUrl
} from '../core/cve-utils.js';

export const tags = ['all', 'os', 'windows', 'linux', 'macos', 'bsd', 'device', 'iot', 'server'];

const MIN_QUOTE_LEN = 8;

const GOVERNANCE_ERROR_CODES = new Set([
  'SSRF_POLICY_BLOCKED',
  'TARGET_RULE_BLOCKED',
  'TARGET_OUT_OF_SCOPE',
  'DNS_REBIND_OR_PRIVATE_IP'
]);

export const meta = {
  id: 'os-security',
  title: 'Universal Operating System, Edge Appliance & Market CVE Security Audit',
  category: 'Known Vulnerabilities',
  plainExplanation:
    'Passively inspects HTTP headers, service banners, and open OS/appliance/runtime ports across Windows Server & Workstation, Linux distributions (Ubuntu, Debian, CentOS, RHEL, AlmaLinux, Rocky, Alpine), macOS / Apple Darwin / AirPlay, BSD / Firewall OS (FreeBSD, OpenBSD, pfSense, OPNsense), Edge VPN/Firewall/Router/NAS appliances (Palo Alto PAN-OS, Fortinet FortiOS, Ivanti Connect Secure, Citrix NetScaler, Cisco IOS XE, MikroTik RouterOS, QNAP QTS), and AI/Cloud runtimes (Ollama, Anyscale Ray) for End-of-Life OS releases and high-impact CVEs.',
  whyItMatters:
    'End-of-Life operating systems and unpatched OS daemons or edge appliances (OpenSSH regreSSHion CVE-2024-6387, CUPS CVE-2024-47176, Apple AirPlay AirBorne CVE-2025-24252, Windows HTTP.sys/TCP-IP/RDP/SMBGhost, PAN-OS GlobalProtect, FortiOS SSL VPN, Ivanti Connect Secure, CitrixBleed, Cisco IOS XE, MikroTik RouterOS, QNAP QTS, Ollama Probllama, and Anyscale Ray ShadowRay) allow unauthenticated remote attackers to achieve root/SYSTEM remote code execution, session hijacking, or full network compromise.',
  defaultFix:
    'Upgrade End-of-Life operating systems to actively supported LTS releases, upgrade OpenSSH to 9.9p2+ (or apply vendor backport security updates), restrict or disable CUPS (631), AirPlay (5000/7000), SMB (445), and RDP (3389) on untrusted networks, apply emergency patches for PAN-OS, FortiOS, Ivanti, Citrix NetScaler, Cisco IOS XE, MikroTik RouterOS, and QNAP QTS appliances, and upgrade Ollama to 0.1.34+ and Ray to 2.8.1+ while binding AI runtimes to localhost.',
  cwe: 'CWE-1104',
  owasp: 'A06:2021-Vulnerable and Outdated Components',
  cvssScore: 9.8,
  cveIds: [
    'CVE-2024-6387',
    'CVE-2025-26465',
    'CVE-2025-26466',
    'CVE-2024-7589',
    'CVE-2024-47176',
    'CVE-2024-38063',
    'CVE-2024-38077',
    'CVE-2022-21907',
    'CVE-2020-0796',
    'CVE-2025-24252',
    'CVE-2024-3400',
    'CVE-2024-0012',
    'CVE-2024-21762',
    'CVE-2024-55591',
    'CVE-2024-21887',
    'CVE-2025-0282',
    'CVE-2023-4966',
    'CVE-2023-20198',
    'CVE-2023-30799',
    'CVE-2024-27130',
    'CVE-2024-37032',
    'CVE-2023-48022'
  ],
  references: [
    'https://cwe.mitre.org/data/definitions/1104.html',
    'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
    'https://nvd.nist.gov/vuln/detail/CVE-2024-6387',
    'https://nvd.nist.gov/vuln/detail/CVE-2025-26465',
    'https://nvd.nist.gov/vuln/detail/CVE-2025-26466',
    'https://nvd.nist.gov/vuln/detail/CVE-2024-7589',
    'https://nvd.nist.gov/vuln/detail/CVE-2024-47176',
    'https://nvd.nist.gov/vuln/detail/CVE-2024-38063',
    'https://nvd.nist.gov/vuln/detail/CVE-2024-38077',
    'https://nvd.nist.gov/vuln/detail/CVE-2022-21907',
    'https://nvd.nist.gov/vuln/detail/CVE-2020-0796',
    'https://nvd.nist.gov/vuln/detail/CVE-2025-24252',
    'https://nvd.nist.gov/vuln/detail/CVE-2024-3400',
    'https://nvd.nist.gov/vuln/detail/CVE-2024-0012',
    'https://nvd.nist.gov/vuln/detail/CVE-2024-21762',
    'https://nvd.nist.gov/vuln/detail/CVE-2024-55591',
    'https://nvd.nist.gov/vuln/detail/CVE-2024-21887',
    'https://nvd.nist.gov/vuln/detail/CVE-2025-0282',
    'https://nvd.nist.gov/vuln/detail/CVE-2023-4966',
    'https://nvd.nist.gov/vuln/detail/CVE-2023-20198',
    'https://nvd.nist.gov/vuln/detail/CVE-2023-30799',
    'https://nvd.nist.gov/vuln/detail/CVE-2024-27130',
    'https://nvd.nist.gov/vuln/detail/CVE-2024-37032',
    'https://nvd.nist.gov/vuln/detail/CVE-2023-48022'
  ]
};

function isGovernanceBlockError(err) {
  if (!err) return false;
  if (err.isGovernanceBlock === true) return true;
  if (GOVERNANCE_ERROR_CODES.has(err.code)) return true;
  const msg = typeof err.message === 'string' ? err.message : '';
  return (
    msg.startsWith('Redirect blocked by SSRF policy') ||
    msg.startsWith('Request blocked by SSRF policy') ||
    msg.startsWith('[SECSCAN platform control')
  );
}

function normalizeQuote(raw) {
  return String(raw ?? '').replace(/\s+/g, ' ').trim();
}

function getHeaderEntry(headers, targetLower) {
  if (!headers || typeof headers !== 'object') return null;
  if (typeof headers.entries === 'function') {
    for (const [k, v] of headers.entries()) {
      if (String(k).toLowerCase() === targetLower && v !== undefined && v !== null) {
        return { key: String(k), value: String(v) };
      }
    }
    return null;
  }
  for (const [k, v] of Object.entries(headers)) {
    if (String(k).toLowerCase() === targetLower && v !== undefined && v !== null) {
      const str = Array.isArray(v) ? v.join('; ') : String(v);
      return { key: String(k), value: str };
    }
  }
  return null;
}

function extractBodySnippet(text, regex) {
  if (typeof text !== 'string' || !text) return null;
  const m = regex.exec(text);
  if (!m) return null;
  const matched = normalizeQuote(m[0]);
  if (matched.length >= MIN_QUOTE_LEN) return matched.slice(0, 140);
  const start = Math.max(0, m.index - 20);
  const end = Math.min(text.length, m.index + m[0].length + 40);
  const ctx = normalizeQuote(text.slice(start, end));
  return ctx.length >= MIN_QUOTE_LEN ? ctx.slice(0, 140) : null;
}

function severityRank(sev) {
  switch (String(sev || '').toUpperCase()) {
    case 'CRITICAL': return 4;
    case 'HIGH': return 3;
    case 'MEDIUM': return 2;
    case 'LOW': return 1;
    default: return 0;
  }
}

function addFinding(findings, item) {
  const quotes = Array.isArray(item.evidenceQuotes)
    ? Array.from(new Set(item.evidenceQuotes.filter(q => normalizeQuote(q).length >= MIN_QUOTE_LEN)))
    : [];
  findings.push({
    ...item,
    cwe: item.cwe || meta.cwe,
    owasp: item.owasp || meta.owasp,
    evidenceQuotes: quotes,
    poeLevel: item.status === 'VULNERABLE' ? (quotes.length > 0 ? 3 : 2) : 2
  });
}

function selectPrimaryEvidence(findings) {
  const sorted = [...findings].sort((a, b) => {
    const statusDiff = (b.status === 'VULNERABLE' ? 1 : 0) - (a.status === 'VULNERABLE' ? 1 : 0);
    if (statusDiff !== 0) return statusDiff;
    const sevDiff = severityRank(b.severity) - severityRank(a.severity);
    if (sevDiff !== 0) return sevDiff;
    const cveDiff = (b.cve ? 1 : 0) - (a.cve ? 1 : 0);
    if (cveDiff !== 0) return cveDiff;
    return (b.evidenceQuotes?.length || 0) - (a.evidenceQuotes?.length || 0);
  });
  const chosen = sorted.find(f => f.evidenceQuotes && f.evidenceQuotes.length > 0) || sorted[0];
  return {
    primaryCve: chosen?.cve || sorted.find(f => f.cve)?.cve || null,
    primaryCwe: chosen?.cwe || meta.cwe,
    primaryOwasp: chosen?.owasp || meta.owasp,
    primaryPath: chosen?.path || '/',
    primaryDetail: chosen?.detail || '',
    method: chosen?.method,
    port: chosen?.port,
    trafficId: chosen?.trafficId,
    evidenceQuotes: chosen?.evidenceQuotes || []
  };
}

function buildErrorResult(reason) {
  const msg = reason || 'Target unreachable';
  return {
    name: meta.title,
    status: 'ERROR',
    severity: 'NONE',
    reason: msg,
    detail: msg
  };
}

function normalizeVendorVersion(rawVer) {
  if (typeof rawVer !== 'string' || !rawVer.trim()) return null;
  let v = rawVer.trim().replace(/^[vV]/, '');
  // Ivanti: 22.7R2.3 -> 22.7.2.3
  v = v.replace(/(\d)[rR](\d)/g, '$1.$2');
  // PAN-OS hotfix: 11.1.2-h3 -> 11.1.2.3
  v = v.replace(/-h(\d+)\b/i, '.$1');
  // Citrix NetScaler: 14.1-8.42 -> 14.1.8.42
  v = v.replace(/(\d)-(\d)/g, '$1.$2');
  // Cisco IOS XE letter suffix: 17.9.4a -> 17.9.4.1
  v = v.replace(/(\d)([a-zA-Z])$/, (_m, d, ch) => `${d}.${ch.toLowerCase().charCodeAt(0) - 96}`);
  return v;
}

/**
 * Executes passive, non-intrusive Operating System, Edge Appliance & AI Runtime CVE auditing.
 */
export default async function run(target, fetchWithRetry, options = {}) {
  const rootUrl = resolveTargetUrl(target, '/');
  if (!rootUrl) {
    return buildErrorResult('Invalid target URL');
  }

  const cachedDeviceScan = options?.cachedDeviceScan && typeof options.cachedDeviceScan === 'object'
    ? options.cachedDeviceScan
    : null;
  const deviceProfile =
    cachedDeviceScan?.deviceProfile ||
    options?.deviceProfile ||
    options?.deviceInfo ||
    null;

  const openPortSet = new Set();
  const addPort = (p) => {
    const n = Number(p);
    if (Number.isInteger(n) && n > 0 && n <= 65535) openPortSet.add(n);
  };
  for (const list of [options?.openPorts, cachedDeviceScan?.openPorts, deviceProfile?.openPorts]) {
    if (Array.isArray(list)) {
      for (const p of list) addPort(p);
    }
  }

  const openServices = [
    ...(Array.isArray(options?.openServices) ? options.openServices : []),
    ...(Array.isArray(cachedDeviceScan?.openServices) ? cachedDeviceScan.openServices : []),
    ...(Array.isArray(deviceProfile?.openServices) ? deviceProfile.openServices : [])
  ];
  for (const svc of openServices) {
    addPort(svc?.port);
  }
  const openPorts = Array.from(openPortSet);

  const serviceBanners = [
    ...(Array.isArray(options?.serviceBanners) ? options.serviceBanners : []),
    ...(Array.isArray(cachedDeviceScan?.serviceBanners) ? cachedDeviceScan.serviceBanners : []),
    ...(Array.isArray(deviceProfile?.serviceBanners) ? deviceProfile.serviceBanners : [])
  ];

  const hasDeviceTelemetry = Boolean(
    openPorts.length > 0 ||
    openServices.length > 0 ||
    serviceBanners.length > 0 ||
    (typeof options?.sshBanner === 'string' && options.sshBanner.trim()) ||
    deviceProfile
  );

  const basePortClosedWithoutHttp = Boolean(
    (deviceProfile?.basePortClosed === true || cachedDeviceScan?.basePortClosed === true) &&
    !deviceProfile?.activeHttpOrigin &&
    !deviceProfile?.activeHttpsOrigin &&
    !cachedDeviceScan?.activeHttpOrigin &&
    !cachedDeviceScan?.activeHttpsOrigin
  );

  const skipHttpRoot = Boolean(
    (options?.noActiveHttpService === true ||
      cachedDeviceScan?.noActiveHttpService === true ||
      deviceProfile?.noActiveHttpService === true ||
      basePortClosedWithoutHttp) &&
    hasDeviceTelemetry
  );

  let networkSuccess = false;
  let lastError = null;

  async function safeFetch(url) {
    if (!url || typeof fetchWithRetry !== 'function') return null;
    try {
      const res = await fetchWithRetry(url);
      if (res?.isGovernanceBlock) {
        const err = new Error(res.reason || res.error || 'Target blocked by governance policy');
        err.isGovernanceBlock = true;
        throw err;
      }
      if (res && typeof res === 'object') {
        networkSuccess = true;
      }
      return res;
    } catch (err) {
      if (isGovernanceBlockError(err)) throw err;
      lastError = err;
      return null;
    }
  }

  let rootRes = null;
  if (!skipHttpRoot) {
    try {
      rootRes = await safeFetch(target);
    } catch (err) {
      return buildErrorResult(err?.message || 'Target blocked by governance policy');
    }
  }

  if (!networkSuccess && !hasDeviceTelemetry) {
    return buildErrorResult(lastError?.message || 'Target unreachable');
  }

  const rootText = typeof rootRes?.text === 'string' ? rootRes.text.slice(0, 131072) : '';
  const serverHdr = getHeaderEntry(rootRes?.headers, 'server');
  const poweredByHdr = getHeaderEntry(rootRes?.headers, 'x-powered-by');
  const setCookieHdr = getHeaderEntry(rootRes?.headers, 'set-cookie');
  const xSshBannerHdr = getHeaderEntry(rootRes?.headers, 'x-ssh-banner');
  const xWinBuildHdr =
    getHeaderEntry(rootRes?.headers, 'x-windows-build') ||
    getHeaderEntry(rootRes?.headers, 'x-os-build') ||
    getHeaderEntry(rootRes?.headers, 'x-os-version');

  const port22Service = openServices.find(s => Number(s?.port) === 22 && typeof s?.banner === 'string' && s.banner.trim());
  const effectiveSshBanner =
    (typeof options?.sshBanner === 'string' && options.sshBanner.trim()) ||
    port22Service?.banner?.trim() ||
    xSshBannerHdr?.value?.trim() ||
    null;

  const osInfo = detectOperatingSystemFromSignals({
    headers: rootRes?.headers,
    html: rootText,
    sshBanner: effectiveSshBanner,
    serviceBanners,
    openPorts,
    openServices,
    deviceInfo: deviceProfile
  });

  const findings = [];

  const getHttpHeaderQuote = (...hdrEntries) => {
    for (const h of hdrEntries) {
      if (h && typeof h.value === 'string' && h.value.trim()) {
        const formatted = `${h.key}: ${h.value.trim()}`;
        if (normalizeQuote(formatted).length >= MIN_QUOTE_LEN) {
          return formatted;
        }
      }
    }
    return null;
  };

  // ── Check 1: End-of-Life (EOL) Operating System Posture ───────────────────
  if (osInfo.isEol) {
    const httpQuote = getHttpHeaderQuote(serverHdr, poweredByHdr, xSshBannerHdr);
    const bannerQuote = !httpQuote
      ? (osInfo.sshInfo?.raw || osInfo.signals.find(s => normalizeQuote(s).length >= MIN_QUOTE_LEN) || null)
      : null;
    const isFromHttp = Boolean(httpQuote && rootRes);

    addFinding(findings, {
      cve: null,
      name: `End-of-Life (EOL) Operating System Detected (${osInfo.osName || 'OS'}${osInfo.version ? ` ${osInfo.version}` : ''})`,
      status: 'VULNERABLE',
      severity: 'HIGH',
      cvssScore: 7.5,
      cwe: 'CWE-1104',
      owasp: 'A06:2021-Vulnerable and Outdated Components',
      path: isFromHttp ? '/' : (osInfo.sshInfo ? ':22' : '/'),
      ...(isFromHttp ? {} : { method: 'TCP' }),
      detail: osInfo.eolReason || `${osInfo.osName || 'Operating System'}${osInfo.version ? ` ${osInfo.version}` : ''} has reached End-of-Life and no longer receives standard security updates`,
      ...(isFromHttp && rootRes?.trafficId !== undefined ? { trafficId: rootRes.trafficId } : {}),
      evidenceQuotes: httpQuote ? [httpQuote] : (bannerQuote ? [bannerQuote] : [])
    });
  }

  // ── Check 2: OpenSSH Vulnerability Auditing (CVE-2024-6387, CVE-2024-7589, CVE-2025-26465, CVE-2025-26466) ──
  let sshInfo = osInfo.sshInfo;
  if (!sshInfo && effectiveSshBanner) {
    sshInfo = parseOpenSshBanner(effectiveSshBanner);
  }
  if (!sshInfo && serverHdr?.value) {
    sshInfo = parseOpenSshBanner(serverHdr.value);
  }

  if (sshInfo && sshInfo.baseVersion) {
    const sshSemVer = `${sshInfo.baseVersion}.${sshInfo.patchNum ?? 0}`;
    const sshFromHttpHdr =
      (xSshBannerHdr && /OpenSSH/i.test(xSshBannerHdr.value) ? xSshBannerHdr : null) ||
      (serverHdr && /OpenSSH/i.test(serverHdr.value) ? serverHdr : null) ||
      (poweredByHdr && /OpenSSH/i.test(poweredByHdr.value) ? poweredByHdr : null);
    const sshQuote = sshFromHttpHdr
      ? `${sshFromHttpHdr.key}: ${sshFromHttpHdr.value.trim()}`
      : sshInfo.raw;
    const sshIsHttp = Boolean(sshFromHttpHdr && rootRes);

    // CVE-2024-6387 (regreSSHion: >=8.5p1 <9.8p1, not backport-patched)
    if (
      isVersionAffected(sshInfo.baseVersion, ['>=8.5.0 <9.8.0']) &&
      !sshInfo.isBackportPatchedFor6387
    ) {
      addFinding(findings, {
        cve: 'CVE-2024-6387',
        name: 'OpenSSH regreSSHion Unauthenticated Root RCE (CVE-2024-6387)',
        status: 'VULNERABLE',
        severity: 'CRITICAL',
        cvssScore: 8.1,
        cwe: 'CWE-362',
        owasp: 'A06:2021-Vulnerable and Outdated Components',
        path: sshIsHttp ? '/' : ':22',
        ...(sshIsHttp ? {} : { method: 'TCP', port: 22 }),
        detail: `OpenSSH ${sshInfo.version} (${sshInfo.raw}) is within the regreSSHion affected range (>= 8.5p1 < 9.8p1) without distro backport patch confirmation`,
        ...(sshIsHttp && rootRes?.trafficId !== undefined ? { trafficId: rootRes.trafficId } : {}),
        evidenceQuotes: sshQuote ? [sshQuote] : []
      });
    }

    // CVE-2024-7589 (FreeBSD OpenSSH blacklistd RCE: FreeBSD <9.8p1, not backport-patched)
    if (
      sshInfo.isFreeBsd &&
      isVersionAffected(sshInfo.baseVersion, ['<9.8.0']) &&
      !sshInfo.isBackportPatchedFor6387
    ) {
      addFinding(findings, {
        cve: 'CVE-2024-7589',
        name: 'FreeBSD OpenSSH blacklistd Pre-Authentication Root RCE (CVE-2024-7589)',
        status: 'VULNERABLE',
        severity: 'CRITICAL',
        cvssScore: 8.1,
        cwe: 'CWE-362',
        owasp: 'A06:2021-Vulnerable and Outdated Components',
        path: sshIsHttp ? '/' : ':22',
        ...(sshIsHttp ? {} : { method: 'TCP', port: 22 }),
        detail: `FreeBSD OpenSSH ${sshInfo.version} (${sshInfo.raw}) is prior to 9.8p1 / SA-24:08.openssh and vulnerable to CVE-2024-7589`,
        ...(sshIsHttp && rootRes?.trafficId !== undefined ? { trafficId: rootRes.trafficId } : {}),
        evidenceQuotes: sshQuote ? [sshQuote] : []
      });
    }

    // CVE-2025-26465 (OpenSSH VerifyHostKeyDNS MitM: >=6.8p1 <9.9p2)
    if (isVersionAffected(sshSemVer, ['>=6.8.0 <9.9.2'])) {
      addFinding(findings, {
        cve: 'CVE-2025-26465',
        name: 'OpenSSH VerifyHostKeyDNS Man-in-the-Middle Attack (CVE-2025-26465)',
        status: 'VULNERABLE',
        severity: 'HIGH',
        cvssScore: 6.8,
        cwe: 'CWE-295',
        owasp: 'A07:2021-Identification and Authentication Failures',
        path: sshIsHttp ? '/' : ':22',
        ...(sshIsHttp ? {} : { method: 'TCP', port: 22 }),
        detail: `OpenSSH ${sshInfo.version} (${sshInfo.raw}) is within affected range >= 6.8p1 < 9.9p2 for CVE-2025-26465`,
        ...(sshIsHttp && rootRes?.trafficId !== undefined ? { trafficId: rootRes.trafficId } : {}),
        evidenceQuotes: sshQuote ? [sshQuote] : []
      });
    }

    // CVE-2025-26466 (OpenSSH Pre-Authentication Ping DoS: >=9.5p1 <9.9p2)
    if (isVersionAffected(sshSemVer, ['>=9.5.0 <9.9.2'])) {
      addFinding(findings, {
        cve: 'CVE-2025-26466',
        name: 'OpenSSH Pre-Authentication SSH2_MSG_PING Memory/CPU DoS (CVE-2025-26466)',
        status: 'VULNERABLE',
        severity: 'MEDIUM',
        cvssScore: 5.9,
        cwe: 'CWE-400',
        owasp: 'A06:2021-Vulnerable and Outdated Components',
        path: sshIsHttp ? '/' : ':22',
        ...(sshIsHttp ? {} : { method: 'TCP', port: 22 }),
        detail: `OpenSSH ${sshInfo.version} (${sshInfo.raw}) is within affected range >= 9.5p1 < 9.9p2 for CVE-2025-26466`,
        ...(sshIsHttp && rootRes?.trafficId !== undefined ? { trafficId: rootRes.trafficId } : {}),
        evidenceQuotes: sshQuote ? [sshQuote] : []
      });
    }
  }

  // ── Check 3: Linux/Unix CUPS (CVE-2024-47176) & Apple AirPlay AirBorne (CVE-2025-24252) ──
  const allBannersText = [
    serverHdr?.value || '',
    poweredByHdr?.value || '',
    ...serviceBanners,
    ...openServices.map(s => s?.banner || '')
  ].filter(Boolean).join(' ');

  const cupsBrowsedMatch = /\bcups-browsed\/(\d+\.\d+(?:\.\d+)?)\b/i.exec(`${allBannersText} ${rootText}`);
  const cupsMatch = /\bCUPS\/(\d+\.\d+(?:\.\d+)?)\b/i.exec(allBannersText);
  const hasCupsPort = openPortSet.has(631) || /\bCUPS\b/i.test(serverHdr?.value || '');

  if (cupsBrowsedMatch || cupsMatch || hasCupsPort) {
    const cupsBrowsedVer = cupsBrowsedMatch ? cupsBrowsedMatch[1] : null;
    const cupsVer = cupsMatch ? cupsMatch[1] : null;
    const isCupsVuln =
      (cupsBrowsedVer && isVersionAffected(cupsBrowsedVer, ['<=2.0.1'])) ||
      (cupsVer && isVersionAffected(cupsVer, ['<=2.4.10']));
    const isCupsPatched =
      (cupsBrowsedVer && !isVersionAffected(cupsBrowsedVer, ['<=2.0.1'])) ||
      (!cupsBrowsedVer && cupsVer && !isVersionAffected(cupsVer, ['<=2.4.10']));

    if (isCupsVuln || (!isCupsPatched && hasCupsPort)) {
      const cupsHttpQuote = serverHdr && /cups/i.test(serverHdr.value)
        ? `${serverHdr.key}: ${serverHdr.value.trim()}`
        : extractBodySnippet(rootText, /\b(?:cups-browsed\/\d+\.\d+(?:\.\d+)?|CUPS\/\d+\.\d+(?:\.\d+)?)/i);
      const cupsSvc = openServices.find(s => Number(s?.port) === 631);
      const cupsBannerQuote = cupsHttpQuote || cupsSvc?.banner || 'CUPS Print Server Daemon (631/TCP)';
      const cupsIsHttp = Boolean(cupsHttpQuote && rootRes);
      const dispVer = cupsBrowsedVer ? `cups-browsed/${cupsBrowsedVer}` : (cupsVer ? `CUPS/${cupsVer}` : 'CUPS (port 631)');

      addFinding(findings, {
        cve: 'CVE-2024-47176',
        name: 'Linux/Unix CUPS & cups-browsed Unauthenticated IPP RCE Chain (CVE-2024-47176)',
        status: isCupsVuln ? 'VULNERABLE' : 'SUSPICIOUS',
        severity: 'HIGH',
        cvssScore: isCupsVuln ? 8.6 : 7.5,
        cwe: 'CWE-749',
        owasp: 'A05:2021-Security Misconfiguration',
        path: cupsIsHttp ? '/' : ':631',
        ...(cupsIsHttp ? {} : { method: 'TCP', port: 631 }),
        detail: isCupsVuln
          ? `Disclosed ${dispVer} is affected by the OpenPrinting CUPS / cups-browsed unauthenticated IPP RCE chain (CVE-2024-47176)`
          : `Exposed CUPS print server daemon on port 631 without confirmed patch level for CVE-2024-47176`,
        ...(cupsIsHttp && rootRes?.trafficId !== undefined ? { trafficId: rootRes.trafficId } : {}),
        evidenceQuotes: [cupsBannerQuote]
      });
    }
  }

  const airTunesMatch = /\bAirTunes\/(\d+(?:\.\d+)*)\b/i.exec(`${allBannersText} ${rootText}`);
  const airPlayVerMatch = /\bAirPlay\/(\d+(?:\.\d+)*)\b/i.exec(`${allBannersText} ${rootText}`);
  const hasAirPlayService =
    Boolean(airTunesMatch || airPlayVerMatch) ||
    /\bAirPlay\b/i.test(serverHdr?.value || '') ||
    (osInfo.family === 'macos' && (openPortSet.has(5000) || openPortSet.has(7000))) ||
    osInfo.exposedOsServices.some(s => s.service === 'airplay');

  if (hasAirPlayService) {
    const airTunesVer = airTunesMatch ? airTunesMatch[1] : null;
    const airPlayVer = airPlayVerMatch ? airPlayVerMatch[1] : null;
    const isAirPlayVuln =
      (airTunesVer && isVersionAffected(airTunesVer, ['<800.0'])) ||
      (airPlayVer && isVersionAffected(airPlayVer, ['<15.4'])) ||
      (osInfo.family === 'macos' && osInfo.isEol && (openPortSet.has(5000) || openPortSet.has(7000)));
    const isAirPlayPatched =
      (airTunesVer && !isVersionAffected(airTunesVer, ['<800.0'])) ||
      (!airTunesVer && airPlayVer && !isVersionAffected(airPlayVer, ['<15.4']));

    if (isAirPlayVuln || !isAirPlayPatched) {
      const airHttpQuote = serverHdr && /AirTunes|AirPlay/i.test(serverHdr.value)
        ? `${serverHdr.key}: ${serverHdr.value.trim()}`
        : extractBodySnippet(rootText, /\b(?:AirTunes|AirPlay)\/\d+(?:\.\d+)*/i);
      const airPort = openPortSet.has(7000) ? 7000 : 5000;
      const airSvc = openServices.find(s => Number(s?.port) === 7000 || Number(s?.port) === 5000);
      const airQuote = airHttpQuote || airSvc?.banner || `Apple AirPlay Receiver (${airPort}/TCP)`;
      const airIsHttp = Boolean(airHttpQuote && rootRes);

      addFinding(findings, {
        cve: 'CVE-2025-24252',
        name: 'Apple AirPlay / AirTunes AirBorne Zero-Click Unauthenticated RCE (CVE-2025-24252)',
        status: isAirPlayVuln ? 'VULNERABLE' : 'SUSPICIOUS',
        severity: isAirPlayVuln ? 'CRITICAL' : 'HIGH',
        cvssScore: isAirPlayVuln ? 9.8 : 8.1,
        cwe: 'CWE-416',
        owasp: 'A06:2021-Vulnerable and Outdated Components',
        path: airIsHttp ? '/' : `:${airPort}`,
        ...(airIsHttp ? {} : { method: 'TCP', port: airPort }),
        detail: isAirPlayVuln
          ? `Disclosed Apple AirPlay / AirTunes service (${airTunesVer ? `AirTunes/${airTunesVer}` : (airPlayVer ? `AirPlay/${airPlayVer}` : osInfo.version)}) is vulnerable to AirBorne zero-click RCE (CVE-2025-24252)`
          : `Unauthenticated Apple AirPlay receiver surface exposed on port ${airPort} without confirmed AirBorne patch (CVE-2025-24252)`,
        ...(airIsHttp && rootRes?.trafficId !== undefined ? { trafficId: rootRes.trafficId } : {}),
        evidenceQuotes: [airQuote]
      });
    }
  }

  // ── Check 4: Windows OS Service & HTTP.sys / IIS / SMB / RDP CVEs ─────────
  const winBuildMatch =
    /(\d+\.\d+\.\d{4,5}(?:\.\d+)?)/.exec(xWinBuildHdr?.value || '') ||
    /\bWindows(?:\s+NT|\s+Server|\s+Build)?[\s/:-]+(\d+\.\d+\.\d{4,5}(?:\.\d+)?)\b/i.exec(`${allBannersText} ${rootText}`) ||
    /(\d+\.\d+\.\d{4,5}(?:\.\d+)?)/.exec(String(deviceProfile?.osVersion || ''));
  const winBuild = winBuildMatch ? winBuildMatch[1] : null;
  const iisVerMatch = /\bMicrosoft-IIS\/(\d+\.\d+)\b/i.exec(serverHdr?.value || allBannersText);
  const iisVer = iisVerMatch ? iisVerMatch[1] : null;
  const hasHttpApi = /\bMicrosoft-HTTPAPI\/2\.0\b/i.test(serverHdr?.value || allBannersText);
  const isEolIis75To85 = iisVer === '7.5' || iisVer === '8.0' || iisVer === '8.5';

  // CVE-2022-21907 (Windows HTTP.sys / IIS HTTP Protocol Stack RCE: <10.0.20348.469 or EOL IIS 7.5/8.0/8.5)
  const is21907BuildVuln = Boolean(winBuild && isVersionAffected(winBuild, ['<10.0.20348.469']));
  const is21907BuildPatched = Boolean(winBuild && !isVersionAffected(winBuild, ['<10.0.20348.469']));

  if (!is21907BuildPatched && (is21907BuildVuln || isEolIis75To85 || (hasHttpApi && osInfo.isEol))) {
    const winQuote = getHttpHeaderQuote(xWinBuildHdr, serverHdr) || `Microsoft-IIS/${iisVer || 'HTTP.sys'}`;
    const isConfirmed21907 = is21907BuildVuln || isEolIis75To85;
    addFinding(findings, {
      cve: 'CVE-2022-21907',
      name: 'Windows HTTP.sys / IIS HTTP Protocol Stack RCE (CVE-2022-21907)',
      status: isConfirmed21907 ? 'VULNERABLE' : 'SUSPICIOUS',
      severity: isConfirmed21907 ? 'CRITICAL' : 'HIGH',
      cvssScore: 9.8,
      cwe: 'CWE-400',
      owasp: 'A06:2021-Vulnerable and Outdated Components',
      path: '/',
      detail: is21907BuildVuln
        ? `Windows HTTP.sys build ${winBuild} (< 10.0.20348.469) is vulnerable to unauthenticated HTTP trailer kernel RCE (CVE-2022-21907)`
        : `End-of-Life Microsoft-IIS/${iisVer || 'HTTPAPI'} Windows HTTP.sys stack exposed without CVE-2022-21907 patch baseline`,
      ...(rootRes?.trafficId !== undefined ? { trafficId: rootRes.trafficId } : {}),
      evidenceQuotes: [winQuote]
    });
  }

  // CVE-2020-0796 (SMBGhost) & CVE-2024-38063 (Windows TCP/IP IPv6 RCE)
  const hasSmbPort445 = openPortSet.has(445) || openServices.some(s => Number(s?.port) === 445 || s?.service === 'smb');
  const smbSvc = openServices.find(s => Number(s?.port) === 445 || s?.service === 'smb');
  const is38063BuildVuln = Boolean(winBuild && isVersionAffected(winBuild, ['<10.0.22621.4037']));
  const is38063BuildPatched = Boolean(winBuild && !isVersionAffected(winBuild, ['<10.0.22621.4037']));
  const is0796BuildVuln = Boolean(
    (winBuild && isVersionAffected(winBuild, ['>=10.0.18362.0 <10.0.18363.720'])) ||
    (smbSvc?.banner && /SMBv3\.1\.1.*(?:unpatched|18362|18363)/i.test(smbSvc.banner))
  );
  const is0796BuildPatched = Boolean(winBuild && !isVersionAffected(winBuild, ['<10.0.18363.720']));

  if (!is38063BuildPatched && (is38063BuildVuln || hasSmbPort445)) {
    const quote38063 = getHttpHeaderQuote(xWinBuildHdr, serverHdr) || smbSvc?.banner || 'Windows SMB / TCP-IP Service (445/TCP)';
    const isHttp38063 = Boolean(is38063BuildVuln && getHttpHeaderQuote(xWinBuildHdr, serverHdr) && rootRes && !hasSmbPort445);
    addFinding(findings, {
      cve: 'CVE-2024-38063',
      name: 'Windows TCP/IP IPv6 Unauthenticated Kernel RCE (CVE-2024-38063)',
      status: is38063BuildVuln ? 'VULNERABLE' : 'SUSPICIOUS',
      severity: is38063BuildVuln ? 'CRITICAL' : 'HIGH',
      cvssScore: 9.8,
      cwe: 'CWE-191',
      owasp: 'A06:2021-Vulnerable and Outdated Components',
      path: isHttp38063 ? '/' : ':445',
      ...(isHttp38063 ? {} : { method: 'TCP', port: 445 }),
      detail: is38063BuildVuln
        ? `Windows build ${winBuild} (< 10.0.22621.4037) is vulnerable to tcpip.sys IPv6 unauthenticated kernel RCE (CVE-2024-38063)`
        : 'Windows network daemon surface (445/TCP) exposed without confirmed CVE-2024-38063 patch baseline',
      ...(isHttp38063 && rootRes?.trafficId !== undefined ? { trafficId: rootRes.trafficId } : {}),
      evidenceQuotes: [quote38063]
    });
  }

  if ((!is0796BuildPatched && hasSmbPort445) || is0796BuildVuln) {
    const quote0796 = smbSvc?.banner || getHttpHeaderQuote(xWinBuildHdr, serverHdr) || 'Windows SMBv3 File Sharing Service (445/TCP)';
    const isHttp0796 = Boolean(!hasSmbPort445 && getHttpHeaderQuote(xWinBuildHdr, serverHdr) && rootRes);
    addFinding(findings, {
      cve: 'CVE-2020-0796',
      name: 'Windows SMBv3 Compression RCE — SMBGhost (CVE-2020-0796)',
      status: is0796BuildVuln ? 'VULNERABLE' : 'SUSPICIOUS',
      severity: is0796BuildVuln ? 'CRITICAL' : 'HIGH',
      cvssScore: 10.0,
      cwe: 'CWE-119',
      owasp: 'A06:2021-Vulnerable and Outdated Components',
      path: isHttp0796 ? '/' : ':445',
      ...(isHttp0796 ? {} : { method: 'TCP', port: 445 }),
      detail: is0796BuildVuln
        ? `Disclosed Windows SMBv3 build ${winBuild || smbSvc?.banner} is vulnerable to SMBGhost compression RCE (CVE-2020-0796)`
        : 'Windows SMB port 445/TCP is directly exposed without confirmed SMBv3 compression patch (CVE-2020-0796)',
      ...(isHttp0796 && rootRes?.trafficId !== undefined ? { trafficId: rootRes.trafficId } : {}),
      evidenceQuotes: [quote0796]
    });
  }

  // CVE-2024-38077 (Windows Remote Desktop Licensing Service RCE — MadLicense)
  const hasRdpPort3389 = openPortSet.has(3389) || openServices.some(s => Number(s?.port) === 3389 || s?.service === 'rdp');
  const rdpSvc = openServices.find(s => Number(s?.port) === 3389 || s?.service === 'rdp');
  const is38077BuildVuln = Boolean(winBuild && isVersionAffected(winBuild, ['<10.0.22621.3880']));
  const is38077BuildPatched = Boolean(winBuild && !isVersionAffected(winBuild, ['<10.0.22621.3880']));

  if (!is38077BuildPatched && (hasRdpPort3389 || (is38077BuildVuln && hasRdpPort3389))) {
    const quote38077 = rdpSvc?.banner || getHttpHeaderQuote(xWinBuildHdr, serverHdr) || 'Windows Remote Desktop Protocol (RDP 3389/TCP)';
    addFinding(findings, {
      cve: 'CVE-2024-38077',
      name: 'Windows Remote Desktop Licensing Service RCE — MadLicense (CVE-2024-38077)',
      status: is38077BuildVuln ? 'VULNERABLE' : 'SUSPICIOUS',
      severity: is38077BuildVuln ? 'CRITICAL' : 'HIGH',
      cvssScore: 9.8,
      cwe: 'CWE-122',
      owasp: 'A06:2021-Vulnerable and Outdated Components',
      path: ':3389',
      method: 'TCP',
      port: 3389,
      detail: is38077BuildVuln
        ? `Windows RDP / Licensing service on build ${winBuild} (< 10.0.22621.3880) is vulnerable to MadLicense RCE (CVE-2024-38077)`
        : 'Windows Remote Desktop service (3389/TCP) exposed without confirmed CVE-2024-38077 patch level',
      evidenceQuotes: [quote38077]
    });
  }

  // ── Check 5: Network, Firewall, VPN & NAS Appliance CVEs ──────────────────
  const combinedApplianceText = `${allBannersText} ${setCookieHdr?.value || ''} ${rootText}`;

  // 5a. Palo Alto PAN-OS (CVE-2024-3400, CVE-2024-0012)
  if (osInfo.osName === 'Palo Alto PAN-OS' || osInfo.distro === 'PAN-OS') {
    const panVerMatch = /(?:PAN-OS|GlobalProtect)[\s/v:-]*(\d+\.\d+(?:\.\d+)?(?:-h\d+)?)/i.exec(combinedApplianceText);
    const rawPanVer = panVerMatch ? panVerMatch[1] : osInfo.version;
    const normPanVer = normalizeVendorVersion(rawPanVer);
    const panQuote =
      getHttpHeaderQuote(serverHdr, setCookieHdr) ||
      extractBodySnippet(rootText, /(?:\/global-protect\/login\.esp|GlobalProtect|PAN-OS[^\r\n<]{0,40})/i) ||
      'Palo Alto PAN-OS GlobalProtect Portal';

    const hasHotfix = rawPanVer && /-h\d+/i.test(rawPanVer);
    const vuln3400 = normPanVer
      ? isVersionAffected(normPanVer, [hasHotfix ? '<11.1.2.3' : '<11.1.2'])
      : false;
    const patched3400 = normPanVer
      ? !isVersionAffected(normPanVer, [hasHotfix ? '<11.1.2.3' : '<11.1.2'])
      : false;

    if (vuln3400 || !patched3400) {
      addFinding(findings, {
        cve: 'CVE-2024-3400',
        name: 'Palo Alto PAN-OS GlobalProtect Command Injection RCE (CVE-2024-3400)',
        status: vuln3400 ? 'VULNERABLE' : 'SUSPICIOUS',
        severity: vuln3400 ? 'CRITICAL' : 'HIGH',
        cvssScore: 10.0,
        cwe: 'CWE-77',
        owasp: 'A03:2021-Injection',
        path: '/',
        detail: vuln3400
          ? `Palo Alto PAN-OS ${rawPanVer} (< 11.1.2-h3) GlobalProtect portal is vulnerable to unauthenticated command injection RCE (CVE-2024-3400)`
          : 'Palo Alto PAN-OS GlobalProtect portal is publicly exposed without confirmed CVE-2024-3400 patch level',
        ...(rootRes?.trafficId !== undefined ? { trafficId: rootRes.trafficId } : {}),
        evidenceQuotes: [panQuote]
      });
    }

    const vuln0012 = normPanVer
      ? isVersionAffected(normPanVer, [hasHotfix ? '<11.2.4.1' : '<11.2.4'])
      : false;
    const patched0012 = normPanVer
      ? !isVersionAffected(normPanVer, [hasHotfix ? '<11.2.4.1' : '<11.2.4'])
      : false;

    if (vuln0012 || !patched0012) {
      addFinding(findings, {
        cve: 'CVE-2024-0012',
        name: 'Palo Alto PAN-OS Management Interface Authentication Bypass (CVE-2024-0012)',
        status: vuln0012 ? 'VULNERABLE' : 'SUSPICIOUS',
        severity: vuln0012 ? 'CRITICAL' : 'HIGH',
        cvssScore: 9.8,
        cwe: 'CWE-306',
        owasp: 'A07:2021-Identification and Authentication Failures',
        path: '/',
        detail: vuln0012
          ? `Palo Alto PAN-OS ${rawPanVer} (< 11.2.4-h1) web interface is vulnerable to authentication bypass (CVE-2024-0012)`
          : 'Palo Alto PAN-OS web interface is publicly exposed without confirmed CVE-2024-0012 patch level',
        ...(rootRes?.trafficId !== undefined ? { trafficId: rootRes.trafficId } : {}),
        evidenceQuotes: [panQuote]
      });
    }
  }

  // 5b. Fortinet FortiOS / FortiGate (CVE-2024-21762, CVE-2024-55591)
  if (osInfo.osName === 'Fortinet FortiOS' || osInfo.distro === 'FortiOS') {
    const fortiVerMatch = /Forti(?:OS|Gate|Proxy)[\s/v:-]*(\d+\.\d+(?:\.\d+)?)/i.exec(combinedApplianceText);
    const fortiVer = fortiVerMatch ? fortiVerMatch[1] : osInfo.version;
    const fortiQuote =
      getHttpHeaderQuote(setCookieHdr, serverHdr) ||
      extractBodySnippet(rootText, /(?:\/remote\/login|fgt_lang|FortiOS[^\r\n<]{0,40}|FortiGate[^\r\n<]{0,40})/i) ||
      'Fortinet FortiOS SSL VPN Portal';

    const vuln21762 = Boolean(fortiVer && isVersionAffected(fortiVer, ['<7.4.3']));
    const patched21762 = Boolean(fortiVer && !isVersionAffected(fortiVer, ['<7.4.3']));

    if (vuln21762 || !patched21762) {
      addFinding(findings, {
        cve: 'CVE-2024-21762',
        name: 'Fortinet FortiOS SSL VPN Out-of-Bounds Write RCE (CVE-2024-21762)',
        status: vuln21762 ? 'VULNERABLE' : 'SUSPICIOUS',
        severity: vuln21762 ? 'CRITICAL' : 'HIGH',
        cvssScore: 9.8,
        cwe: 'CWE-787',
        owasp: 'A06:2021-Vulnerable and Outdated Components',
        path: '/',
        detail: vuln21762
          ? `Fortinet FortiOS ${fortiVer} (< 7.4.3) SSL VPN is vulnerable to out-of-bounds write RCE (CVE-2024-21762)`
          : 'Fortinet FortiOS SSL VPN portal is publicly exposed without confirmed CVE-2024-21762 patch level',
        ...(rootRes?.trafficId !== undefined ? { trafficId: rootRes.trafficId } : {}),
        evidenceQuotes: [fortiQuote]
      });
    }

    const vuln55591 = Boolean(fortiVer && isVersionAffected(fortiVer, ['<7.2.11']));
    const patched55591 = Boolean(fortiVer && !isVersionAffected(fortiVer, ['<7.2.11']));

    if (vuln55591 || !patched55591) {
      addFinding(findings, {
        cve: 'CVE-2024-55591',
        name: 'Fortinet FortiOS Node.js WebSocket Authentication Bypass (CVE-2024-55591)',
        status: vuln55591 ? 'VULNERABLE' : 'SUSPICIOUS',
        severity: vuln55591 ? 'CRITICAL' : 'HIGH',
        cvssScore: 9.8,
        cwe: 'CWE-288',
        owasp: 'A07:2021-Identification and Authentication Failures',
        path: '/',
        detail: vuln55591
          ? `Fortinet FortiOS ${fortiVer} (< 7.2.11) is vulnerable to WebSocket CLI authentication bypass (CVE-2024-55591)`
          : 'Fortinet FortiOS management/VPN interface is publicly exposed without confirmed CVE-2024-55591 patch level',
        ...(rootRes?.trafficId !== undefined ? { trafficId: rootRes.trafficId } : {}),
        evidenceQuotes: [fortiQuote]
      });
    }
  }

  // 5c. Ivanti Connect Secure (CVE-2024-21887, CVE-2025-0282)
  if (osInfo.osName === 'Ivanti Connect Secure' || osInfo.distro === 'Ivanti Connect Secure') {
    const ivantiVerMatch = /(?:Ivanti(?:\s+Connect\s+Secure|\s+Policy\s+Secure)?|Pulse\s+Connect\s+Secure)[\s/v:-]*(\d+\.\d+(?:[rR]\d+(?:\.\d+)?|\.\d+(?:\.\d+)?)?)/i.exec(combinedApplianceText);
    const rawIvantiVer = ivantiVerMatch ? ivantiVerMatch[1] : osInfo.version;
    const normIvantiVer = normalizeVendorVersion(rawIvantiVer);
    const ivantiQuote =
      getHttpHeaderQuote(setCookieHdr, serverHdr) ||
      extractBodySnippet(rootText, /(?:\/dana-na\/[^\s"'<>]{0,60}|Ivanti Connect Secure[^\r\n<]{0,40})/i) ||
      'Ivanti Connect Secure Portal (/dana-na/)';

    const vuln21887 = Boolean(normIvantiVer && isVersionAffected(normIvantiVer, ['<22.7.2.4']));
    const patched21887 = Boolean(normIvantiVer && !isVersionAffected(normIvantiVer, ['<22.7.2.4']));

    if (vuln21887 || !patched21887) {
      addFinding(findings, {
        cve: 'CVE-2024-21887',
        name: 'Ivanti Connect Secure Web Component Command Injection RCE (CVE-2024-21887)',
        status: vuln21887 ? 'VULNERABLE' : 'SUSPICIOUS',
        severity: vuln21887 ? 'CRITICAL' : 'HIGH',
        cvssScore: 9.1,
        cwe: 'CWE-77',
        owasp: 'A03:2021-Injection',
        path: '/',
        detail: vuln21887
          ? `Ivanti Connect Secure ${rawIvantiVer} (< 22.7R2.4) is vulnerable to web component command injection RCE (CVE-2024-21887)`
          : 'Ivanti Connect Secure (/dana-na/) portal is publicly exposed without confirmed CVE-2024-21887 patch level',
        ...(rootRes?.trafficId !== undefined ? { trafficId: rootRes.trafficId } : {}),
        evidenceQuotes: [ivantiQuote]
      });
    }

    const vuln0282 = Boolean(normIvantiVer && isVersionAffected(normIvantiVer, ['<22.7.2.5']));
    const patched0282 = Boolean(normIvantiVer && !isVersionAffected(normIvantiVer, ['<22.7.2.5']));

    if (vuln0282 || !patched0282) {
      addFinding(findings, {
        cve: 'CVE-2025-0282',
        name: 'Ivanti Connect Secure IF-T/TLS Stack Buffer Overflow RCE (CVE-2025-0282)',
        status: vuln0282 ? 'VULNERABLE' : 'SUSPICIOUS',
        severity: vuln0282 ? 'CRITICAL' : 'HIGH',
        cvssScore: 9.0,
        cwe: 'CWE-121',
        owasp: 'A06:2021-Vulnerable and Outdated Components',
        path: '/',
        detail: vuln0282
          ? `Ivanti Connect Secure ${rawIvantiVer} (< 22.7R2.5) is vulnerable to stack-based buffer overflow RCE (CVE-2025-0282)`
          : 'Ivanti Connect Secure (/dana-na/) portal is publicly exposed without confirmed CVE-2025-0282 patch level',
        ...(rootRes?.trafficId !== undefined ? { trafficId: rootRes.trafficId } : {}),
        evidenceQuotes: [ivantiQuote]
      });
    }
  }

  // 5d. Citrix NetScaler ADC / Gateway (CVE-2023-4966 — CitrixBleed)
  if (osInfo.osName === 'Citrix NetScaler ADC' || osInfo.distro === 'NetScaler') {
    const citrixVerMatch = /(?:NetScaler|Citrix(?:\s+ADC|\s+Gateway)?)[\s/v:-]*(?:NS)?(\d+\.\d+(?:-\d+\.\d+|\.\d+(?:\.\d+)?))/i.exec(combinedApplianceText);
    const rawCitrixVer = citrixVerMatch ? citrixVerMatch[1] : osInfo.version;
    const normCitrixVer = normalizeVendorVersion(rawCitrixVer);
    const citrixQuote =
      getHttpHeaderQuote(setCookieHdr, serverHdr) ||
      extractBodySnippet(rootText, /(?:\/logon\/LogonPoint\/[^\s"'<>]{0,50}|Citrix Gateway[^\r\n<]{0,40}|NetScaler[^\r\n<]{0,40})/i) ||
      'Citrix NetScaler Gateway (/logon/LogonPoint/)';

    const vuln4966 = Boolean(normCitrixVer && isVersionAffected(normCitrixVer, ['<14.1.8.50']));
    const patched4966 = Boolean(normCitrixVer && !isVersionAffected(normCitrixVer, ['<14.1.8.50']));

    if (vuln4966 || !patched4966) {
      addFinding(findings, {
        cve: 'CVE-2023-4966',
        name: 'Citrix NetScaler ADC & Gateway CitrixBleed Session Token Disclosure (CVE-2023-4966)',
        status: vuln4966 ? 'VULNERABLE' : 'SUSPICIOUS',
        severity: vuln4966 ? 'CRITICAL' : 'HIGH',
        cvssScore: 9.4,
        cwe: 'CWE-119',
        owasp: 'A07:2021-Identification and Authentication Failures',
        path: '/',
        detail: vuln4966
          ? `Citrix NetScaler ADC / Gateway ${rawCitrixVer} (< 14.1-8.50) is vulnerable to CitrixBleed session token memory disclosure (CVE-2023-4966)`
          : 'Citrix NetScaler Gateway login portal exposed without confirmed CitrixBleed patch level (CVE-2023-4966)',
        ...(rootRes?.trafficId !== undefined ? { trafficId: rootRes.trafficId } : {}),
        evidenceQuotes: [citrixQuote]
      });
    }
  }

  // 5e. Cisco IOS XE (CVE-2023-20198)
  if (osInfo.osName === 'Cisco IOS XE' || osInfo.distro === 'IOS XE') {
    const ciscoVerMatch = /(?:Cisco\s+IOS(?:\s+XE)?|cisco-IOS|IOS[\s-]*XE)[\s/v,:-]*(\d+\.\d+(?:\.\d+[a-zA-Z]?)?)/i.exec(combinedApplianceText);
    const rawCiscoVer = ciscoVerMatch ? ciscoVerMatch[1] : osInfo.version;
    const normCiscoVer = normalizeVendorVersion(rawCiscoVer);
    const ciscoQuote =
      getHttpHeaderQuote(serverHdr) ||
      extractBodySnippet(rootText, /(?:\/webui\/[^\s"'<>]{0,40}|Cisco IOS XE[^\r\n<]{0,40})/i) ||
      'Server: cisco-IOS (Cisco IOS XE Web UI)';

    const vuln20198 = Boolean(normCiscoVer && isVersionAffected(normCiscoVer, ['<17.9.4']));
    const patched20198 = Boolean(normCiscoVer && !isVersionAffected(normCiscoVer, ['<17.9.4']));

    if (vuln20198 || !patched20198) {
      addFinding(findings, {
        cve: 'CVE-2023-20198',
        name: 'Cisco IOS XE Web UI Unauthenticated Privilege Escalation (CVE-2023-20198)',
        status: vuln20198 ? 'VULNERABLE' : 'SUSPICIOUS',
        severity: vuln20198 ? 'CRITICAL' : 'HIGH',
        cvssScore: 10.0,
        cwe: 'CWE-284',
        owasp: 'A01:2021-Broken Access Control',
        path: '/',
        detail: vuln20198
          ? `Cisco IOS XE Web UI ${rawCiscoVer} (< 17.9.4a) is vulnerable to unauthenticated privilege 15 account creation (CVE-2023-20198)`
          : 'Cisco IOS XE Web UI (cisco-IOS / /webui/) is publicly exposed without confirmed CVE-2023-20198 patch level',
        ...(rootRes?.trafficId !== undefined ? { trafficId: rootRes.trafficId } : {}),
        evidenceQuotes: [ciscoQuote]
      });
    }
  }

  // 5f. MikroTik RouterOS (CVE-2023-30799)
  if (osInfo.osName === 'MikroTik RouterOS' || osInfo.distro === 'RouterOS') {
    const mikrotikVerMatch = /(?:RouterOS|MikroTik|WebFig)[\s/v:-]*(\d+\.\d+(?:\.\d+)?)/i.exec(combinedApplianceText);
    const mikrotikVer = mikrotikVerMatch ? mikrotikVerMatch[1] : osInfo.version;
    const mikrotikQuote =
      getHttpHeaderQuote(serverHdr) ||
      extractBodySnippet(rootText, /(?:RouterOS[^\r\n<]{0,50}|WebFig[^\r\n<]{0,40}|MikroTik[^\r\n<]{0,40})/i) ||
      'MikroTik RouterOS WebFig / Winbox Service';
    const hasHttpMikrotik = Boolean((getHttpHeaderQuote(serverHdr) || /RouterOS|WebFig|MikroTik/i.test(rootText)) && rootRes);
    const mtPort = openPortSet.has(8291) ? 8291 : (openPortSet.has(8728) ? 8728 : null);

    const vuln30799 = Boolean(mikrotikVer && isVersionAffected(mikrotikVer, ['<6.49.8']));
    const patched30799 = Boolean(mikrotikVer && !isVersionAffected(mikrotikVer, ['<6.49.8']));

    if (vuln30799 || !patched30799) {
      addFinding(findings, {
        cve: 'CVE-2023-30799',
        name: 'MikroTik RouterOS WebFig/Winbox Superadmin Privilege Escalation (CVE-2023-30799)',
        status: vuln30799 ? 'VULNERABLE' : 'SUSPICIOUS',
        severity: vuln30799 ? 'HIGH' : 'MEDIUM',
        cvssScore: vuln30799 ? 9.1 : 7.5,
        cwe: 'CWE-269',
        owasp: 'A01:2021-Broken Access Control',
        path: hasHttpMikrotik ? '/' : `:${mtPort || 8291}`,
        ...(hasHttpMikrotik ? {} : { method: 'TCP', port: mtPort || 8291 }),
        detail: vuln30799
          ? `MikroTik RouterOS ${mikrotikVer} (< 6.49.8) is vulnerable to super-admin privilege escalation (CVE-2023-30799)`
          : 'MikroTik RouterOS management interface (WebFig / Winbox) is exposed without confirmed CVE-2023-30799 patch level',
        ...(hasHttpMikrotik && rootRes?.trafficId !== undefined ? { trafficId: rootRes.trafficId } : {}),
        evidenceQuotes: [mikrotikQuote]
      });
    }
  }

  // 5g. QNAP QTS / QuTS hero (CVE-2024-27130)
  if (osInfo.osName === 'QNAP QTS' || osInfo.distro === 'QTS') {
    const qnapVerMatch = /(?:QNAP\s+QTS|QuTS\s+hero|QTS)[\s/v:-]*(\d+\.\d+(?:\.\d+(?:\.\d+)?)?)/i.exec(combinedApplianceText);
    const qnapVer = qnapVerMatch ? qnapVerMatch[1] : osInfo.version;
    const qnapQuote =
      getHttpHeaderQuote(serverHdr) ||
      extractBodySnippet(rootText, /(?:\/cgi-bin\/authLogin\.cgi|\/cgi-bin\/share\.cgi|QNAP[^\r\n<]{0,40}|QTS[^\r\n<]{0,40})/i) ||
      'QNAP QTS NAS Portal (/cgi-bin/authLogin.cgi)';

    const qnapRange = qnapVer && qnapVer.split('.').length >= 4 ? ['<5.1.7.2770'] : ['<5.1.7'];
    const vuln27130 = Boolean(qnapVer && isVersionAffected(qnapVer, qnapRange));
    const patched27130 = Boolean(qnapVer && !isVersionAffected(qnapVer, qnapRange));

    if (vuln27130 || !patched27130) {
      addFinding(findings, {
        cve: 'CVE-2024-27130',
        name: 'QNAP QTS / QuTS hero share.cgi Stack Buffer Overflow RCE (CVE-2024-27130)',
        status: vuln27130 ? 'VULNERABLE' : 'SUSPICIOUS',
        severity: vuln27130 ? 'CRITICAL' : 'HIGH',
        cvssScore: 8.8,
        cwe: 'CWE-121',
        owasp: 'A06:2021-Vulnerable and Outdated Components',
        path: '/',
        detail: vuln27130
          ? `QNAP QTS ${qnapVer} (< 5.1.7.2770) is vulnerable to share.cgi stack-based buffer overflow RCE (CVE-2024-27130)`
          : 'QNAP QTS management interface (/cgi-bin/authLogin.cgi) is exposed without confirmed CVE-2024-27130 patch level',
        ...(rootRes?.trafficId !== undefined ? { trafficId: rootRes.trafficId } : {}),
        evidenceQuotes: [qnapQuote]
      });
    }
  }

  // ── Check 6: AI & Cloud Runtime OS Daemons (CVE-2024-37032 Ollama, CVE-2023-48022 Ray) ──
  const isOllamaIndicated =
    osInfo.osName === 'Ollama AI Runtime' ||
    /Ollama is running/i.test(rootText) ||
    /\bollama\/\d+\.\d+/i.test(serverHdr?.value || '') ||
    openPortSet.has(11434);

  const isRayIndicated =
    osInfo.osName === 'Ray Cluster Runtime' ||
    /\bRay Dashboard\b|"ray_version"\s*:/i.test(rootText) ||
    /\bray\/\d+\.\d+/i.test(serverHdr?.value || '') ||
    openPortSet.has(8265);

  if (isOllamaIndicated || isRayIndicated) {
    let ollamaVer = isOllamaIndicated
      ? (osInfo.osName === 'Ollama AI Runtime' && osInfo.version
          ? osInfo.version
          : (/ollama\/(\d+\.\d+\.\d+)/i.exec(serverHdr?.value || '')?.[1] ||
             /"version"\s*:\s*"(\d+\.\d+\.\d+)"/i.exec(rootText)?.[1] ||
             null))
      : null;

    let rayVer = isRayIndicated
      ? (osInfo.osName === 'Ray Cluster Runtime' && osInfo.version
          ? osInfo.version
          : (/ray\/(\d+\.\d+\.\d+)/i.exec(serverHdr?.value || '')?.[1] ||
             /"ray_version"\s*:\s*"(\d+\.\d+\.\d+)"/i.exec(rootText)?.[1] ||
             null))
      : null;

    let verRes = null;
    let verText = '';
    if ((isOllamaIndicated && !ollamaVer) || (isRayIndicated && !rayVer)) {
      const apiVerUrl = resolveTargetUrl(target, '/api/version');
      if (apiVerUrl) {
        try {
          verRes = await safeFetch(apiVerUrl);
          verText = typeof verRes?.text === 'string' ? verRes.text.slice(0, 16384) : '';
          if (verRes && verRes.status === 200 && verText) {
            if (isOllamaIndicated && !ollamaVer) {
              const m = /"version"\s*:\s*"(\d+\.\d+\.\d+)"/i.exec(verText);
              if (m) ollamaVer = m[1];
            }
            if (isRayIndicated && !rayVer) {
              const m = /"(?:ray_version|version)"\s*:\s*"(\d+\.\d+\.\d+)"/i.exec(verText);
              if (m) rayVer = m[1];
            }
          }
        } catch (err) {
          if (isGovernanceBlockError(err)) {
            return buildErrorResult(err?.message || 'Target blocked by governance policy');
          }
        }
      }
    }

    if (isOllamaIndicated && ollamaVer && isVersionAffected(ollamaVer, ['<0.1.34'])) {
      const fromVerEndpoint = Boolean(verRes && verText.includes(ollamaVer));
      const quoteOllama = fromVerEndpoint
        ? (extractBodySnippet(verText, /"version"\s*:\s*"[^"]+"/i) || `"version":"${ollamaVer}"`)
        : (getHttpHeaderQuote(serverHdr) ||
           extractBodySnippet(rootText, /(?:Ollama is running|"version"\s*:\s*"[^"]+")/i) ||
           `Ollama/${ollamaVer} (11434/TCP)`);
      const targetRes = fromVerEndpoint ? verRes : rootRes;

      addFinding(findings, {
        cve: 'CVE-2024-37032',
        name: 'Ollama Probllama Unauthenticated Model Pull Path Traversal & RCE (CVE-2024-37032)',
        status: 'VULNERABLE',
        severity: 'CRITICAL',
        cvssScore: 9.1,
        cwe: 'CWE-22',
        owasp: 'A01:2021-Broken Access Control',
        path: fromVerEndpoint ? '/api/version' : '/',
        detail: `Ollama ${ollamaVer} (< 0.1.34) is vulnerable to Probllama unauthenticated digest path traversal and RCE (CVE-2024-37032)`,
        ...(targetRes?.trafficId !== undefined ? { trafficId: targetRes.trafficId } : {}),
        evidenceQuotes: [quoteOllama]
      });
    }

    if (isRayIndicated && rayVer && isVersionAffected(rayVer, ['<2.8.1'])) {
      const fromVerEndpoint = Boolean(verRes && verText.includes(rayVer));
      const quoteRay = fromVerEndpoint
        ? (extractBodySnippet(verText, /"(?:ray_version|version)"\s*:\s*"[^"]+"/i) || `"ray_version":"${rayVer}"`)
        : (getHttpHeaderQuote(serverHdr) ||
           extractBodySnippet(rootText, /(?:Ray Dashboard|"ray_version"\s*:\s*"[^"]+")/i) ||
           `Ray/${rayVer} (8265/TCP)`);
      const targetRes = fromVerEndpoint ? verRes : rootRes;

      addFinding(findings, {
        cve: 'CVE-2023-48022',
        name: 'Anyscale Ray ShadowRay Jobs API Unauthenticated Cluster RCE (CVE-2023-48022)',
        status: 'VULNERABLE',
        severity: 'CRITICAL',
        cvssScore: 9.8,
        cwe: 'CWE-306',
        owasp: 'A07:2021-Identification and Authentication Failures',
        path: fromVerEndpoint ? '/api/version' : '/',
        detail: `Anyscale Ray ${rayVer} (< 2.8.1) is vulnerable to ShadowRay unauthenticated Jobs API remote code execution (CVE-2023-48022)`,
        ...(targetRes?.trafficId !== undefined ? { trafficId: targetRes.trafficId } : {}),
        evidenceQuotes: [quoteRay]
      });
    }
  }

  if (findings.length === 0) {
    return {
      name: meta.title,
      status: 'SAFE',
      severity: 'NONE',
      cveIds: [],
      detail: 'No vulnerable OS banners, EOL OS versions, or exposed appliance/daemon CVEs detected',
      osInfo
    };
  }

  const overallStatus = findings.some(f => f.status === 'VULNERABLE') ? 'VULNERABLE' : 'SUSPICIOUS';
  const maxSeverity = findings.reduce(
    (best, f) => (severityRank(f.severity) > severityRank(best) ? f.severity : best),
    'LOW'
  );
  const maxCvss = findings.reduce(
    (best, f) => (typeof f.cvssScore === 'number' && f.cvssScore > best ? f.cvssScore : best),
    0
  ) || meta.cvssScore;
  const detectedCves = Array.from(new Set(findings.map(f => f.cve).filter(Boolean)));
  const primary = selectPrimaryEvidence(findings);

  const matchingQuotes = [];
  for (const f of findings) {
    if (primary.trafficId !== undefined && f.trafficId !== primary.trafficId) continue;
    for (const q of f.evidenceQuotes || []) {
      if (!matchingQuotes.includes(q)) {
        matchingQuotes.push(q);
      }
    }
  }
  const finalQuotes = matchingQuotes.length > 0 ? matchingQuotes : primary.evidenceQuotes;
  const detailSummary = findings.map(f => `${f.cve ? `${f.cve}: ` : ''}${f.detail}`).join(' | ');

  return {
    name: meta.title,
    status: overallStatus,
    severity: maxSeverity,
    poeLevel: overallStatus === 'VULNERABLE' && finalQuotes.length > 0 ? 3 : 2,
    cve: primary.primaryCve,
    cveIds: detectedCves,
    cwe: findings.length === 1 && findings[0].cwe ? findings[0].cwe : primary.primaryCwe,
    owasp: findings.length === 1 && findings[0].owasp ? findings[0].owasp : primary.primaryOwasp,
    cvssScore: maxCvss,
    path: primary.primaryPath,
    ...(primary.method ? { method: primary.method } : {}),
    ...(primary.port ? { port: primary.port } : {}),
    reason: primary.primaryDetail || detailSummary,
    detail: detailSummary,
    fix: meta.defaultFix,
    evidence: {
      osFamily: osInfo.family,
      osName: osInfo.osName,
      distro: osInfo.distro,
      version: osInfo.version,
      isEol: osInfo.isEol,
      signals: osInfo.signals,
      exposedOsServices: osInfo.exposedOsServices
    },
    osInfo,
    ...(primary.trafficId !== undefined ? { trafficId: primary.trafficId } : {}),
    ...(finalQuotes.length > 0 ? { evidenceQuotes: finalQuotes } : {}),
    findings,
    subFindings: findings
  };
}
