/**
 * Universal Multi-OS Fingerprinting & Analysis Engine
 *
 * Passively identifies Operating System families, distributions, versions,
 * End-of-Life (EOL) status, OpenSSH distro backport patch levels, and exposed
 * OS/appliance/runtime network services from HTTP headers, response bodies,
 * service banners, and open port telemetry.
 */

export const OS_FAMILIES = Object.freeze({
  windows: 'Windows Server & Workstation',
  linux: 'Linux Distribution',
  macos: 'macOS / Apple Darwin / iOS / tvOS',
  bsd: 'BSD & Firewall OS (FreeBSD / OpenBSD / pfSense / OPNsense)',
  mobile_tv_os: 'Smart TV, Mobile & Embedded OS (Android / Tizen / webOS / Roku)',
  network_appliance_os: 'Network, Firewall, VPN & NAS Appliance OS',
  container_ai_os: 'Container, Cloud & AI Runtime OS Surface'
});

const OS_PORT_SERVICE_CATALOG = Object.freeze({
  // Windows OS Services
  135: { service: 'msrpc', family: 'windows', risk: 'MEDIUM', detail: 'Microsoft RPC Endpoint Mapper (135/TCP)' },
  139: { service: 'netbios-ssn', family: 'windows', risk: 'MEDIUM', detail: 'Windows NetBIOS Session Service (139/TCP)' },
  445: { service: 'smb', family: 'windows', risk: 'HIGH', detail: 'Windows SMB / CIFS File Sharing Service (445/TCP)' },
  3389: { service: 'rdp', family: 'windows', risk: 'HIGH', detail: 'Windows Remote Desktop Protocol (RDP 3389/TCP)' },
  5357: { service: 'wsdapi', family: 'windows', risk: 'LOW', detail: 'Windows WSDAPI Network Discovery HTTP Service (5357/TCP)' },
  5985: { service: 'winrm-http', family: 'windows', risk: 'HIGH', detail: 'Windows Remote Management Cleartext HTTP (WinRM 5985/TCP)' },
  5986: { service: 'winrm-https', family: 'windows', risk: 'MEDIUM', detail: 'Windows Remote Management HTTPS (WinRM 5986/TCP)' },

  // Linux & Unix OS Services
  22: { service: 'ssh', family: 'linux', risk: 'LOW', detail: 'OpenSSH / SSH Remote Shell Service (22/TCP)' },
  111: { service: 'rpcbind', family: 'linux', risk: 'MEDIUM', detail: 'ONC RPC / rpcbind Portmapper (111/TCP)' },
  631: { service: 'cups-ipp', family: 'linux', risk: 'HIGH', detail: 'CUPS / IPP Print Server Daemon (631/TCP)' },
  873: { service: 'rsync', family: 'linux', risk: 'MEDIUM', detail: 'rsync File Synchronization Daemon (873/TCP)' },
  2049: { service: 'nfs', family: 'linux', risk: 'HIGH', detail: 'NFS Network File System Service (2049/TCP)' },
  9090: { service: 'cockpit', family: 'linux', risk: 'MEDIUM', detail: 'Linux Cockpit Web Administration Console (9090/TCP)' },
  10000: { service: 'webmin', family: 'linux', risk: 'HIGH', detail: 'Webmin Linux System Administration Portal (10000/TCP)' },

  // macOS / Apple Darwin Services
  548: { service: 'afp', family: 'macos', risk: 'MEDIUM', detail: 'Apple Filing Protocol (AFP 548/TCP)' },
  5000: { service: 'airplay', family: 'macos', risk: 'MEDIUM', detail: 'Apple AirPlay Receiver / Companion Service (5000/TCP)' },
  5900: { service: 'vnc-ard', family: 'macos', risk: 'HIGH', detail: 'Apple Remote Desktop / VNC Remote Framebuffer (5900/TCP)' },
  7000: { service: 'airplay', family: 'macos', risk: 'MEDIUM', detail: 'Apple AirPlay / AirTunes Media Receiver (7000/TCP)' },

  // Smart TV & Mobile OS Services
  3000: { service: 'lg-webos-ssap', family: 'mobile_tv_os', risk: 'MEDIUM', detail: 'LG webOS SSAP Control Service (3000/TCP)' },
  3001: { service: 'lg-webos-ssap-tls', family: 'mobile_tv_os', risk: 'LOW', detail: 'LG webOS SSAP TLS Control Service (3001/TCP)' },
  5555: { service: 'adb', family: 'mobile_tv_os', risk: 'CRITICAL', detail: 'Android Debug Bridge (ADB) Unauthenticated Shell Daemon (5555/TCP)' },
  8001: { service: 'samsung-tizen-api', family: 'mobile_tv_os', risk: 'MEDIUM', detail: 'Samsung Tizen Smart TV REST/WebSocket API (8001/TCP)' },
  8002: { service: 'samsung-tizen-tls', family: 'mobile_tv_os', risk: 'LOW', detail: 'Samsung Tizen Smart TV TLS API (8002/TCP)' },
  8008: { service: 'google-cast', family: 'mobile_tv_os', risk: 'MEDIUM', detail: 'Google Cast / Android TV Eureka HTTP API (8008/TCP)' },
  8009: { service: 'google-cast-tls', family: 'mobile_tv_os', risk: 'LOW', detail: 'Google Cast / Android TV TLS Control Channel (8009/TCP)' },
  8060: { service: 'roku-ecp', family: 'mobile_tv_os', risk: 'HIGH', detail: 'Roku OS External Control Protocol (ECP 8060/TCP)' },
  9998: { service: 'lg-webos-debug', family: 'mobile_tv_os', risk: 'HIGH', detail: 'LG webOS Developer Mode / Debug Service (9998/TCP)' },

  // Network Appliance / Router / NAS Services
  23: { service: 'telnet', family: 'network_appliance_os', risk: 'CRITICAL', detail: 'Cleartext Telnet Remote Shell Service (23/TCP)' },
  5001: { service: 'synology-dsm-https', family: 'network_appliance_os', risk: 'LOW', detail: 'Synology DSM HTTPS Management Portal (5001/TCP)' },
  7547: { service: 'tr069-cwmp', family: 'network_appliance_os', risk: 'HIGH', detail: 'TR-069 / CWMP Router WAN Management Service (7547/TCP)' },
  8291: { service: 'mikrotik-winbox', family: 'network_appliance_os', risk: 'HIGH', detail: 'MikroTik RouterOS Winbox Management Service (8291/TCP)' },
  8728: { service: 'mikrotik-api', family: 'network_appliance_os', risk: 'HIGH', detail: 'MikroTik RouterOS Cleartext API Service (8728/TCP)' },

  // Container, Cloud & AI Runtime Services
  2375: { service: 'docker-api', family: 'container_ai_os', risk: 'CRITICAL', detail: 'Unauthenticated Docker Engine TCP Daemon API (2375/TCP)' },
  2376: { service: 'docker-tls-api', family: 'container_ai_os', risk: 'MEDIUM', detail: 'Docker Engine TLS TCP API (2376/TCP)' },
  2379: { service: 'etcd', family: 'container_ai_os', risk: 'CRITICAL', detail: 'Kubernetes / CoreOS etcd Key-Value Store API (2379/TCP)' },
  6379: { service: 'redis', family: 'container_ai_os', risk: 'CRITICAL', detail: 'Redis In-Memory Data Store Service (6379/TCP)' },
  6443: { service: 'kubernetes-api', family: 'container_ai_os', risk: 'MEDIUM', detail: 'Kubernetes API Server (6443/TCP)' },
  8265: { service: 'ray-dashboard', family: 'container_ai_os', risk: 'CRITICAL', detail: 'Anyscale Ray Cluster Dashboard & Job Submission API (8265/TCP)' },
  9200: { service: 'elasticsearch', family: 'container_ai_os', risk: 'HIGH', detail: 'Elasticsearch REST API Service (9200/TCP)' },
  10250: { service: 'kubelet-api', family: 'container_ai_os', risk: 'CRITICAL', detail: 'Kubernetes Kubelet Daemon API (10250/TCP)' },
  11211: { service: 'memcached', family: 'container_ai_os', risk: 'HIGH', detail: 'Memcached Cache Daemon Service (11211/TCP)' },
  11434: { service: 'ollama-api', family: 'container_ai_os', risk: 'HIGH', detail: 'Ollama Local LLM Runtime HTTP API (11434/TCP)' }
});

/**
 * Parses an OpenSSH version banner or token such as:
 *   `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10`
 *   `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3`
 *   `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.3`
 *   `SSH-2.0-OpenSSH_9.3p2 FreeBSD-20230719`
 *   `OpenSSH_9.7p1`
 *
 * Includes distro backport awareness for CVE-2024-6387 (regreSSHion affects
 * OpenSSH >=8.5p1 <9.8p1, except patched Ubuntu packages 1:8.9p1-3ubuntu0.10+,
 * 1:9.2p1-2+deb12u3+ on Debian 12, and 1:9.6p1-3ubuntu13.3+ on Ubuntu 24.04).
 *
 * @param {string | null | undefined} rawBanner
 * @returns {{
 *   raw: string,
 *   version: string,
 *   baseVersion: string,
 *   patchNum: number,
 *   osFamily: string | null,
 *   distro: string | null,
 *   distroRelease: string | null,
 *   distroPackage: string | null,
 *   isBackportPatchedFor6387: boolean,
 *   isFreeBsd: boolean
 * } | null}
 */
export function parseOpenSshBanner(rawBanner) {
  if (typeof rawBanner !== 'string') return null;
  const trimmed = rawBanner.trim();
  if (!trimmed) return null;

  const match = /(?:SSH-\d+\.\d+-)?OpenSSH[/_-](?:(for_Windows)[/_-])?(\d+\.\d+)(?:p(\d+))?(?:[\s\-/]+([^\r\n;,"')>]+))?/i.exec(trimmed);
  if (!match) return null;

  const isForWindowsToken = Boolean(match[1]);
  const baseVersion = match[2];
  const hasPatch = match[3] !== undefined && match[3] !== '';
  const patchNum = hasPatch ? Number(match[3]) : 0;
  const version = hasPatch ? `${baseVersion}p${patchNum}` : baseVersion;
  const trailingComment = (match[4] || '').trim().replace(/^[()]+|[()]+$/g, '');

  const isFreeBsd = /freebsd/i.test(trimmed);
  let osFamily = null;
  let distro = null;
  let distroRelease = null;
  let distroPackage = trailingComment || null;

  if (isForWindowsToken || /windows|win32|win64/i.test(trimmed)) {
    osFamily = 'windows';
    distro = 'Windows';
  } else if (isFreeBsd) {
    osFamily = 'bsd';
    distro = 'FreeBSD';
    const relMatch = /FreeBSD[\s/-]+(\d{1,2}(?:\.\d+)?)\b/i.exec(trimmed);
    const dateMatch = /FreeBSD-(\d{8})\b/i.exec(trimmed);
    if (relMatch) {
      distroRelease = relMatch[1];
    } else if (dateMatch) {
      distroRelease = dateMatch[1];
    }
  } else if (/openbsd/i.test(trimmed)) {
    osFamily = 'bsd';
    distro = 'OpenBSD';
  } else if (/netbsd/i.test(trimmed)) {
    osFamily = 'bsd';
    distro = 'NetBSD';
  } else if (/pfsense/i.test(trimmed)) {
    osFamily = 'bsd';
    distro = 'pfSense';
  } else if (/opnsense/i.test(trimmed)) {
    osFamily = 'bsd';
    distro = 'OPNsense';
  } else if (/ubuntu/i.test(trimmed)) {
    osFamily = 'linux';
    distro = 'Ubuntu';
    const explicitRel = /\b(14\.04|16\.04|18\.04|20\.04|22\.04|24\.04)\b/.exec(trimmed);
    if (explicitRel) {
      distroRelease = explicitRel[1];
    } else if (baseVersion === '9.6' || baseVersion === '9.7' || /3ubuntu13/i.test(trimmed)) {
      distroRelease = '24.04';
    } else if (baseVersion === '9.3') {
      distroRelease = '23.10';
    } else if (baseVersion === '8.9' || /3ubuntu0/i.test(trimmed) || /Ubuntu-3ubuntu/i.test(trimmed)) {
      distroRelease = '22.04';
    } else if (baseVersion === '8.2') {
      distroRelease = '20.04';
    } else if (baseVersion === '7.6') {
      distroRelease = '18.04';
    } else if (baseVersion === '7.2') {
      distroRelease = '16.04';
    } else if (baseVersion === '6.6') {
      distroRelease = '14.04';
    } else if (/Ubuntu-4ubuntu/i.test(trimmed)) {
      distroRelease = '24.04';
    } else if (/1ubuntu/i.test(trimmed)) {
      distroRelease = '18.04';
    }
  } else if (/debian|\+deb\d+/i.test(trimmed)) {
    osFamily = 'linux';
    distro = 'Debian';
    const debRel = /\+deb(\d+)/i.exec(trimmed) || /Debian[\s/-]+(\d{1,2})\b/i.exec(trimmed);
    if (debRel && (!/\+deb\d+/i.test(trimmed) ? Number(debRel[1]) >= 7 : true)) {
      distroRelease = debRel[1];
    } else if (baseVersion === '9.2') {
      distroRelease = '12';
    } else if (baseVersion === '8.4') {
      distroRelease = '11';
    } else if (baseVersion === '7.9') {
      distroRelease = '10';
    } else if (baseVersion === '7.4') {
      distroRelease = '9';
    }
  } else if (/centos/i.test(trimmed)) {
    osFamily = 'linux';
    distro = 'CentOS';
    const elMatch = /(?:centos[\s/-]*|\.el)(\d+)/i.exec(trimmed);
    if (elMatch) distroRelease = elMatch[1];
  } else if (/red\s*hat|rhel|\.el\d+/i.test(trimmed)) {
    osFamily = 'linux';
    distro = 'Red Hat Enterprise Linux';
    const elMatch = /(?:rhel[\s/-]*|\.el)(\d+)/i.exec(trimmed);
    if (elMatch) distroRelease = elMatch[1];
  } else if (/almalinux/i.test(trimmed)) {
    osFamily = 'linux';
    distro = 'AlmaLinux';
  } else if (/rocky/i.test(trimmed)) {
    osFamily = 'linux';
    distro = 'Rocky Linux';
  } else if (/alpine/i.test(trimmed)) {
    osFamily = 'linux';
    distro = 'Alpine';
  } else if (/suse/i.test(trimmed)) {
    osFamily = 'linux';
    distro = 'SUSE';
  } else if (/arch/i.test(trimmed)) {
    osFamily = 'linux';
    distro = 'Arch';
  } else if (/darwin|macos|mac\s*os\s*x/i.test(trimmed)) {
    osFamily = 'macos';
    distro = 'macOS';
  }

  // Distro backport awareness for CVE-2024-6387 (regreSSHion: >=8.5p1 <9.8p1)
  let isBackportPatchedFor6387 = false;

  // 1. Ubuntu 22.04 Jammy: 1:8.9p1-3ubuntu0.10+ (or Ubuntu-3ubuntu0.10+)
  if (baseVersion === '8.9') {
    const u22 = /(\d+)ubuntu(\d+)\.(\d+)/i.exec(trimmed);
    if (u22) {
      const maj = Number(u22[1]);
      const mid = Number(u22[2]);
      const rev = Number(u22[3]);
      if (maj > 3 || (maj === 3 && (mid > 0 || rev >= 10))) {
        isBackportPatchedFor6387 = true;
      }
    }
  }

  // 2. Debian 12 Bookworm: 1:9.2p1-2+deb12u3+ (or Debian-2+deb12u3+)
  if (baseVersion === '9.2' || /\+deb12u/i.test(trimmed)) {
    const deb12 = /(?:(\d+)\+)?deb12u(\d+)/i.exec(trimmed);
    if (deb12) {
      const pkgRev = deb12[1] ? Number(deb12[1]) : 2;
      const debUpdate = Number(deb12[2]);
      if (pkgRev > 2 || (pkgRev === 2 && debUpdate >= 3)) {
        isBackportPatchedFor6387 = true;
      }
    }
  }

  // 3. Ubuntu 24.04 Noble: 1:9.6p1-3ubuntu13.3+ (or Ubuntu-3ubuntu13.3+)
  if (baseVersion === '9.6') {
    const u24 = /(\d+)ubuntu(\d+)(?:\.(\d+))?/i.exec(trimmed);
    if (u24) {
      const maj = Number(u24[1]);
      const mid = Number(u24[2]);
      const rev = u24[3] !== undefined ? Number(u24[3]) : 0;
      if (maj > 3 || (maj === 3 && (mid > 13 || (mid === 13 && rev >= 3)))) {
        isBackportPatchedFor6387 = true;
      }
    }
  }

  // 4. FreeBSD SA-24:04.openssh patch date >= 20240701
  if (isFreeBsd) {
    const fbsdDate = /FreeBSD-(\d{8})\b/i.exec(trimmed);
    if (fbsdDate && Number(fbsdDate[1]) >= 20240701) {
      isBackportPatchedFor6387 = true;
    }
  }

  return {
    raw: trimmed,
    version,
    baseVersion,
    patchNum,
    osFamily,
    distro,
    distroRelease,
    distroPackage,
    isBackportPatchedFor6387,
    isFreeBsd
  };
}

/**
 * Normalizes headers object into lowercase keys with string values.
 */
function normalizeHeadersMap(headers) {
  const map = {};
  if (!headers || typeof headers !== 'object') return map;
  for (const [k, v] of Object.entries(headers)) {
    if (v === undefined || v === null) continue;
    map[k.toLowerCase()] = Array.isArray(v) ? v.join('; ') : String(v);
  }
  return map;
}

/**
 * Collects all raw service banner strings from signals.
 */
function collectServiceBanners(signals = {}) {
  signals = signals && typeof signals === 'object' ? signals : {};
  const list = [];
  if (typeof signals.sshBanner === 'string' && signals.sshBanner.trim()) {
    list.push(signals.sshBanner.trim());
  }
  if (Array.isArray(signals.serviceBanners)) {
    for (const item of signals.serviceBanners) {
      if (typeof item === 'string' && item.trim()) {
        list.push(item.trim());
      } else if (item && typeof item === 'object' && typeof item.banner === 'string' && item.banner.trim()) {
        list.push(item.banner.trim());
      }
    }
  } else if (signals.serviceBanners && typeof signals.serviceBanners === 'object') {
    for (const val of Object.values(signals.serviceBanners)) {
      if (typeof val === 'string' && val.trim()) {
        list.push(val.trim());
      }
    }
  }
  const servicesList = [
    ...(Array.isArray(signals.openServices) ? signals.openServices : []),
    ...(Array.isArray(signals.deviceInfo?.openServices) ? signals.deviceInfo.openServices : [])
  ];
  for (const svc of servicesList) {
    if (svc && typeof svc.banner === 'string' && svc.banner.trim()) {
      list.push(svc.banner.trim());
    }
  }
  return Array.from(new Set(list));
}

/**
 * Collects unique numeric open ports from signals.
 */
function collectOpenPorts(signals = {}) {
  signals = signals && typeof signals === 'object' ? signals : {};
  const portSet = new Set();
  const addPort = (p) => {
    const n = Number(p);
    if (Number.isInteger(n) && n > 0 && n <= 65535) {
      portSet.add(n);
    }
  };

  if (Array.isArray(signals.openPorts)) {
    for (const p of signals.openPorts) addPort(p);
  }
  if (Array.isArray(signals.deviceInfo?.openPorts)) {
    for (const p of signals.deviceInfo.openPorts) addPort(p);
  }
  if (Array.isArray(signals.openServices)) {
    for (const s of signals.openServices) addPort(s?.port);
  }
  if (Array.isArray(signals.deviceInfo?.openServices)) {
    for (const s of signals.deviceInfo.openServices) addPort(s?.port);
  }
  return Array.from(portSet);
}

/**
 * Universal Operating System detection & EOL analysis engine.
 *
 * @param {object} [signals={}]
 * @returns {{
 *   detected: boolean,
 *   family: 'windows' | 'linux' | 'macos' | 'bsd' | 'mobile_tv_os' | 'network_appliance_os' | 'container_ai_os' | null,
 *   familyLabel: string,
 *   osName: string | null,
 *   distro: string | null,
 *   version: string | null,
 *   isEol: boolean,
 *   eolReason: string | null,
 *   confidence: 'high' | 'medium' | 'low' | 'none',
 *   signals: string[],
 *   sshInfo: ReturnType<typeof parseOpenSshBanner>,
 *   applianceType: string | null,
 *   exposedOsServices: Array<{ port: number, service: string, family: string, risk: string, detail: string }>
 * }}
 */
export function detectOperatingSystemFromSignals(signals = {}) {
  signals = signals && typeof signals === 'object' ? signals : {};
  const h = normalizeHeadersMap(signals.headers);
  const server = (typeof signals.serverHeader === 'string' ? signals.serverHeader : (h['server'] || '')).trim();
  const poweredBy = (h['x-powered-by'] || '').trim();
  const setCookie = (h['set-cookie'] || '').trim();
  const wwwAuth = (h['www-authenticate'] || '').trim();
  const aspnetVer = (h['x-aspnet-version'] || '').trim();
  const generator = (h['x-generator'] || '').trim();
  const via = (h['via'] || '').trim();
  const headerCombined = [server, poweredBy, wwwAuth, aspnetVer, generator, via].filter(Boolean).join(' ');

  const html = typeof signals.html === 'string'
    ? signals.html
    : (typeof signals.body === 'string' ? signals.body : '');
  const deviceInfo = signals.deviceInfo && typeof signals.deviceInfo === 'object' ? signals.deviceInfo : null;

  const banners = collectServiceBanners(signals);
  const openPorts = collectOpenPorts(signals);
  const openPortSet = new Set(openPorts);

  const evidenceSignals = [];
  const addSignal = (sig) => {
    if (typeof sig === 'string' && sig.trim() && !evidenceSignals.includes(sig.trim())) {
      evidenceSignals.push(sig.trim());
    }
  };

  // Parse OpenSSH banner from explicit sshBanner, serviceBanners, or Server header
  let sshInfo = null;
  for (const candidate of [...banners, server, poweredBy]) {
    if (candidate && /OpenSSH[/_-]/i.test(candidate)) {
      sshInfo = parseOpenSshBanner(candidate);
      if (sshInfo) {
        addSignal(sshInfo.raw);
        break;
      }
    }
  }

  let family = null;
  let osName = null;
  let distro = null;
  let version = null;
  let isEol = false;
  let eolReason = null;
  let confidence = 'none';
  let applianceType = null;

  const setDetection = (opts) => {
    family = opts.family;
    osName = opts.osName;
    distro = opts.distro ?? opts.osName ?? null;
    version = opts.version ?? version;
    isEol = Boolean(opts.isEol);
    eolReason = opts.eolReason ?? null;
    confidence = opts.confidence || 'high';
    if (opts.applianceType !== undefined) {
      applianceType = opts.applianceType;
    }
  };

  // ── 1. Network Appliance, Firewall, VPN, Router & NAS OS Detection ────────
  const isFortiOs =
    /\bFortiGate\b|\bFortiOS\b|\bSVPNCOOKIE\b|\bAPSCOOKIE_/i.test(`${headerCombined} ${setCookie} ${html}`) ||
    /\/remote\/login\b|\/remote\/fgt_lang\b|\bfgt_lang\b/i.test(html) ||
    (/^xxxxxxxx-xxxxx$/i.test(server) && (/SVPNCOOKIE|APSCOOKIE|\/remote\/login|forti|top\.location/i.test(`${setCookie} ${html}`) || Boolean(server)));

  const isPanOs =
    /\bPAN-OS\b|\bGlobalProtect\b/i.test(`${headerCombined} ${setCookie} ${html}`) ||
    /\/global-protect\/login\.esp\b|\/global-protect\/portal\b/i.test(html) ||
    (/\/php\/login\.php\b/i.test(html) && /palo\s*alto|pan-os|globalprotect/i.test(`${headerCombined} ${html}`));

  const isIvanti =
    /\/dana-na\/|\/dana-cached\/|\bIvanti Connect Secure\b|\bIvanti Policy Secure\b|\bPulse Connect Secure\b/i.test(`${headerCombined} ${html}`) ||
    /\bDSID=|\bDSIVS=|\bDSFirstAccess=/i.test(setCookie);

  const isCitrixNetScaler =
    /\bNSC_AAAC\b|\bNSC_TMAA\b|\bNSC_TMAS\b|\bns_af\b/i.test(`${setCookie} ${html}`) ||
    /\/logon\/LogonPoint\/|\bCitrix Gateway\b|\bCitrix ADC\b|\bNetScaler Gateway\b/i.test(`${headerCombined} ${html}`);

  const isCiscoIosXe =
    /\bcisco-IOS\b|\bIOS-XE\b|\bCisco IOS XE\b/i.test(`${headerCombined} ${html} ${banners.join(' ')}`) ||
    (/\/webui\//i.test(html) && /\bcisco\b|\bios\b/i.test(`${headerCombined} ${html}`));

  const isMikroTik =
    /\bRouterOS\b|\bMikroTik\b|\bWebFig\b/i.test(`${headerCombined} ${html} ${banners.join(' ')} ${deviceInfo?.vendor || ''}`) ||
    openPortSet.has(8291) ||
    openPortSet.has(8728);

  const isSynologyDsm =
    /\bSynology\b|\bSYNO\.API\.Info\b|webapi\/query\.cgi\b|\bDiskStation\b/i.test(`${headerCombined} ${html} ${deviceInfo?.vendor || ''} ${deviceInfo?.deviceType || ''}`) ||
    ((openPortSet.has(5000) || openPortSet.has(5001)) && /synology|dsm|webapi/i.test(`${headerCombined} ${html} ${deviceInfo?.vendor || ''}`)) ||
    (openPortSet.has(5000) && openPortSet.has(5001) && !openPortSet.has(548) && !openPortSet.has(7000));

  const isQnapQts =
    /\bQNAP\b|\/cgi-bin\/authLogin\.cgi\b|\/cgi-bin\/share\.cgi\b|\bQuTS hero\b/i.test(`${headerCombined} ${html} ${deviceInfo?.vendor || ''}`) ||
    (/\bQTS\b/.test(`${headerCombined} ${html}`) && /qnap|authLogin\.cgi|nas/i.test(`${headerCombined} ${html}`));

  const isOpenWrt =
    /\bOpenWrt\b|LuCI - Lua Configuration Interface|\/cgi-bin\/luci\b/i.test(`${headerCombined} ${html} ${banners.join(' ')}`);

  const isUbiquitiUniFi =
    /\bUniFi OS\b|\bUniFi Network\b|\bUniFi Protect\b/i.test(`${headerCombined} ${html} ${deviceInfo?.deviceType || ''}`) ||
    /^Ubiquiti$/i.test(String(deviceInfo?.vendor || ''));

  if (isFortiOs) {
    const verMatch = /Forti(?:OS|Gate)[\s/v-]*(\d+\.\d+(?:\.\d+)?)/i.exec(`${headerCombined} ${html} ${banners.join(' ')}`);
    if (server) addSignal(`Server: ${server}`);
    if (/SVPNCOOKIE/i.test(setCookie)) addSignal('Set-Cookie: SVPNCOOKIE');
    if (/\/remote\/login/i.test(html)) addSignal('FortiOS SSL VPN Portal (/remote/login)');
    if (evidenceSignals.length === 0) addSignal('Fortinet FortiOS signature');
    setDetection({
      family: 'network_appliance_os',
      osName: 'Fortinet FortiOS',
      distro: 'FortiOS',
      version: verMatch ? verMatch[1] : null,
      confidence: 'high',
      applianceType: 'firewall_vpn'
    });
  } else if (isPanOs) {
    const verMatch = /PAN-OS[\s/v-]*(\d+\.\d+(?:\.\d+)?)/i.exec(`${headerCombined} ${html}`);
    if (/\/global-protect\/login\.esp/i.test(html)) addSignal('PAN-OS GlobalProtect Portal (/global-protect/login.esp)');
    else if (/GlobalProtect/i.test(`${headerCombined} ${html}`)) addSignal('Palo Alto PAN-OS GlobalProtect');
    else addSignal('Palo Alto PAN-OS Web Interface');
    setDetection({
      family: 'network_appliance_os',
      osName: 'Palo Alto PAN-OS',
      distro: 'PAN-OS',
      version: verMatch ? verMatch[1] : null,
      confidence: 'high',
      applianceType: 'firewall_vpn'
    });
  } else if (isIvanti) {
    const verMatch = /(?:Ivanti Connect Secure|Pulse Connect Secure)[\s/v-]*(\d+\.\d+(?:\.\d+)?)/i.exec(`${headerCombined} ${html}`);
    if (/DSID/i.test(setCookie)) addSignal('Set-Cookie: DSID (Ivanti Connect Secure)');
    if (/\/dana-na\//i.test(html)) addSignal('Ivanti Connect Secure Portal (/dana-na/)');
    if (evidenceSignals.length === 0) addSignal('Ivanti Connect Secure signature');
    setDetection({
      family: 'network_appliance_os',
      osName: 'Ivanti Connect Secure',
      distro: 'Ivanti Connect Secure',
      version: verMatch ? verMatch[1] : null,
      confidence: 'high',
      applianceType: 'vpn_gateway'
    });
  } else if (isCitrixNetScaler) {
    if (/NSC_AAAC/i.test(setCookie)) addSignal('Set-Cookie: NSC_AAAC (Citrix NetScaler)');
    if (/\/logon\/LogonPoint\//i.test(html)) addSignal('Citrix NetScaler Gateway (/logon/LogonPoint/)');
    if (evidenceSignals.length === 0) addSignal('Citrix NetScaler ADC / Gateway signature');
    setDetection({
      family: 'network_appliance_os',
      osName: 'Citrix NetScaler ADC',
      distro: 'NetScaler',
      version: null,
      confidence: 'high',
      applianceType: 'adc_vpn_gateway'
    });
  } else if (isCiscoIosXe) {
    const verMatch = /IOS[\s-]*(?:XE)?[\s/v,]*(\d+\.\d+(?:\.\d+[a-zA-Z0-9]*)?)/i.exec(`${headerCombined} ${html} ${banners.join(' ')}`);
    if (/cisco-IOS/i.test(server)) addSignal(`Server: ${server}`);
    else addSignal('Cisco IOS XE Web UI (/webui/)');
    setDetection({
      family: 'network_appliance_os',
      osName: 'Cisco IOS XE',
      distro: 'IOS XE',
      version: verMatch ? verMatch[1] : null,
      confidence: 'high',
      applianceType: 'router_switch'
    });
  } else if (isMikroTik) {
    const verMatch = /RouterOS[\s/v-]*(\d+\.\d+(?:\.\d+)?)/i.exec(`${headerCombined} ${html} ${banners.join(' ')}`);
    if (server && /mikrotik|routeros/i.test(server)) addSignal(`Server: ${server}`);
    else addSignal('MikroTik RouterOS / WebFig');
    setDetection({
      family: 'network_appliance_os',
      osName: 'MikroTik RouterOS',
      distro: 'RouterOS',
      version: verMatch ? verMatch[1] : null,
      confidence: 'high',
      applianceType: 'router_gateway'
    });
  } else if (isSynologyDsm) {
    const verMatch = /DSM[\s/v-]*(\d+\.\d+(?:-\d+)?)/i.exec(`${headerCombined} ${html}`);
    addSignal('Synology DSM (webapi/query.cgi / DiskStation)');
    setDetection({
      family: 'network_appliance_os',
      osName: 'Synology DSM',
      distro: 'DSM',
      version: verMatch ? verMatch[1] : null,
      confidence: 'high',
      applianceType: 'nas'
    });
  } else if (isQnapQts) {
    const verMatch = /QTS[\s/v-]*(\d+\.\d+(?:\.\d+)?)/i.exec(`${headerCombined} ${html}`);
    addSignal('QNAP QTS (/cgi-bin/authLogin.cgi)');
    setDetection({
      family: 'network_appliance_os',
      osName: 'QNAP QTS',
      distro: 'QTS',
      version: verMatch ? verMatch[1] : null,
      confidence: 'high',
      applianceType: 'nas'
    });
  } else if (isOpenWrt) {
    const verMatch = /OpenWrt[\s/v-]*(\d+\.\d+(?:\.\d+)?)/i.exec(`${headerCombined} ${html} ${banners.join(' ')}`);
    addSignal('OpenWrt LuCI Configuration Interface');
    setDetection({
      family: 'network_appliance_os',
      osName: 'OpenWrt',
      distro: 'OpenWrt',
      version: verMatch ? verMatch[1] : null,
      confidence: 'high',
      applianceType: 'router_gateway'
    });
  } else if (isUbiquitiUniFi) {
    const verMatch = /UniFi(?:\s+OS)?[\s/v-]*(\d+\.\d+(?:\.\d+)?)/i.exec(`${headerCombined} ${html}`);
    addSignal('Ubiquiti UniFi OS');
    setDetection({
      family: 'network_appliance_os',
      osName: 'Ubiquiti UniFi',
      distro: 'UniFi OS',
      version: verMatch ? verMatch[1] : null,
      confidence: 'high',
      applianceType: 'network_controller'
    });
  }

  // ── 2. Smart TV, Mobile & Embedded OS Detection ───────────────────────────
  if (!family) {
    const isTizen =
      /\bTizen\b/i.test(`${headerCombined} ${banners.join(' ')} ${deviceInfo?.os || ''} ${deviceInfo?.deviceType || ''}`) ||
      /"Samsung SmartTV"|"OS"\s*:\s*"Tizen"|"tokenAuthSupport"/i.test(html) ||
      openPortSet.has(8001) ||
      openPortSet.has(8002);

    const isWebOs =
      /\bwebOS\b|\bWeb0S\b|\bwebOSTV\b/i.test(`${headerCombined} ${html} ${banners.join(' ')} ${deviceInfo?.os || ''} ${deviceInfo?.deviceType || ''}`) ||
      openPortSet.has(9998) ||
      ((openPortSet.has(3000) || openPortSet.has(3001)) && !openPortSet.has(22) && !openPortSet.has(445) && !openPortSet.has(3389));

    const isAndroid =
      /\bAndroid(?:\s+TV)?\b|\bFire\s+OS\b/i.test(`${headerCombined} ${banners.join(' ')} ${deviceInfo?.os || ''} ${deviceInfo?.deviceType || ''}`) ||
      /"cast_build_revision"|"eureka_info"/i.test(html) ||
      openPortSet.has(5555) ||
      openPortSet.has(8008) ||
      openPortSet.has(8009);

    const isRoku =
      /\bRoku\b/i.test(`${headerCombined} ${banners.join(' ')} ${deviceInfo?.vendor || ''} ${deviceInfo?.os || ''}`) ||
      /<vendor-name>Roku<\/vendor-name>|<model-name>Roku/i.test(html) ||
      openPortSet.has(8060);

    if (isTizen) {
      const verMatch = /Tizen[\s/v":]+(\d+(?:\.\d+)?)/i.exec(`${headerCombined} ${html}`);
      addSignal(openPortSet.has(8001) || openPortSet.has(8002) ? 'Samsung Tizen OS SmartView API (8001/8002)' : 'Samsung Tizen OS signature');
      setDetection({
        family: 'mobile_tv_os',
        osName: 'Samsung Tizen OS',
        distro: 'Tizen',
        version: verMatch ? verMatch[1] : null,
        confidence: 'high',
        applianceType: 'smart_tv'
      });
    } else if (isWebOs) {
      const verMatch = /webOS[\s/v":]+(\d+(?:\.\d+)?)/i.exec(`${headerCombined} ${html}`);
      addSignal(openPortSet.has(3000) || openPortSet.has(3001) ? 'LG webOS SSAP Service (3000/3001)' : 'LG webOS signature');
      setDetection({
        family: 'mobile_tv_os',
        osName: 'LG webOS',
        distro: 'webOS',
        version: verMatch ? verMatch[1] : null,
        confidence: 'high',
        applianceType: 'smart_tv'
      });
    } else if (isAndroid) {
      const verMatch = /Android[\s/v":]+(\d+(?:\.\d+)?)/i.exec(`${headerCombined} ${html}`);
      addSignal(openPortSet.has(5555) ? 'Android Debug Bridge (5555/TCP)' : (openPortSet.has(8008) ? 'Google Cast / Android TV (8008/TCP)' : 'Android / Android TV signature'));
      setDetection({
        family: 'mobile_tv_os',
        osName: 'Android / Android TV',
        distro: 'Android',
        version: verMatch ? verMatch[1] : null,
        confidence: 'high',
        applianceType: 'smart_tv_mobile'
      });
    } else if (isRoku) {
      const verMatch = /Roku\/DVP-(\d+\.\d+)/i.exec(headerCombined) || /<software-version>([^<]+)<\/software-version>/i.exec(html);
      addSignal(openPortSet.has(8060) ? 'Roku OS External Control Protocol (8060/TCP)' : 'Roku OS signature');
      setDetection({
        family: 'mobile_tv_os',
        osName: 'Roku OS',
        distro: 'Roku OS',
        version: verMatch ? verMatch[1].trim() : null,
        confidence: 'high',
        applianceType: 'smart_tv'
      });
    }
  }

  // ── 3. BSD & Firewall OS Detection (pfSense / OPNsense / FreeBSD / OpenBSD / NetBSD) ──
  if (!family) {
    const bsdContext = `${headerCombined} ${banners.join(' ')} ${html}`;
    if (/\bpfSense\b/i.test(bsdContext)) {
      const verMatch = /pfSense[\s/v-]*(\d+\.\d+(?:\.\d+)?)/i.exec(bsdContext);
      addSignal('pfSense Firewall OS');
      setDetection({
        family: 'bsd',
        osName: 'pfSense',
        distro: 'pfSense',
        version: verMatch ? verMatch[1] : null,
        confidence: 'high',
        applianceType: 'firewall'
      });
    } else if (/\bOPNsense\b/i.test(bsdContext)) {
      const verMatch = /OPNsense[\s/v-]*(\d+\.\d+(?:\.\d+)?)/i.exec(bsdContext);
      addSignal('OPNsense Firewall OS');
      setDetection({
        family: 'bsd',
        osName: 'OPNsense',
        distro: 'OPNsense',
        version: verMatch ? verMatch[1] : null,
        confidence: 'high',
        applianceType: 'firewall'
      });
    } else if (sshInfo?.isFreeBsd || /\bFreeBSD\b/i.test(`${headerCombined} ${banners.join(' ')}`)) {
      const relMatch = /FreeBSD[\s/-]+(\d{1,2}(?:\.\d+)?)\b/i.exec(`${headerCombined} ${banners.join(' ')}`);
      const fbsdVer = relMatch ? relMatch[1] : (sshInfo?.distroRelease || null);
      const majorNum = fbsdVer && /^\d{1,2}(?:\.\d+)?$/.test(fbsdVer) ? parseInt(fbsdVer, 10) : null;
      const fbsdEol = majorNum !== null && majorNum <= 12;
      if (server && /freebsd/i.test(server)) addSignal(`Server: ${server}`);
      else if (!sshInfo) addSignal(`FreeBSD${fbsdVer ? ` ${fbsdVer}` : ''}`);
      setDetection({
        family: 'bsd',
        osName: 'FreeBSD',
        distro: 'FreeBSD',
        version: fbsdVer,
        isEol: fbsdEol,
        eolReason: fbsdEol ? `FreeBSD ${majorNum} has reached End-of-Life (FreeBSD 11 EOL 2021-09-30, FreeBSD 12 EOL 2023-12-31)` : null,
        confidence: 'high'
      });
    } else if (sshInfo?.distro === 'OpenBSD' || /\bOpenBSD\b/i.test(`${headerCombined} ${banners.join(' ')}`)) {
      const relMatch = /OpenBSD[\s/-]+(\d+\.\d+)/i.exec(`${headerCombined} ${banners.join(' ')}`);
      addSignal(server && /openbsd/i.test(server) ? `Server: ${server}` : 'OpenBSD');
      setDetection({
        family: 'bsd',
        osName: 'OpenBSD',
        distro: 'OpenBSD',
        version: relMatch ? relMatch[1] : null,
        confidence: 'high'
      });
    } else if (sshInfo?.distro === 'NetBSD' || /\bNetBSD\b/i.test(`${headerCombined} ${banners.join(' ')}`)) {
      const relMatch = /NetBSD[\s/-]+(\d+\.\d+)/i.exec(`${headerCombined} ${banners.join(' ')}`);
      addSignal(server && /netbsd/i.test(server) ? `Server: ${server}` : 'NetBSD');
      setDetection({
        family: 'bsd',
        osName: 'NetBSD',
        distro: 'NetBSD',
        version: relMatch ? relMatch[1] : null,
        confidence: 'high'
      });
    }
  }

  // ── 4. Container, Cloud & AI Runtime OS Surfaces ──────────────────────────
  if (!family) {
    const isOllama =
      /Ollama is running/i.test(html) ||
      /\bollama\/(\d+\.\d+\.\d+)/i.test(headerCombined) ||
      /^Ollama$/i.test(String(deviceInfo?.vendor || '')) ||
      (openPortSet.has(11434) && !sshInfo);

    const isRay =
      /\bRay Dashboard\b|"ray_version"\s*:\s*"[^"]+"|"ray_commit"\s*:\s*"/i.test(`${headerCombined} ${html}`) ||
      (openPortSet.has(8265) && !sshInfo);

    const hasExplicitLinuxHostSignal =
      Boolean(sshInfo && sshInfo.osFamily === 'linux') ||
      /\b(?:Ubuntu|Debian|CentOS|Red Hat|AlmaLinux|Rocky|Alpine|SUSE|Arch)\b|\+deb\d+|\.el[6789]\b/i.test(headerCombined) ||
      openPortSet.has(631) ||
      openPortSet.has(9090);

    const isDockerEngine =
      (!hasExplicitLinuxHostSignal || /\bDocker\/\d+\.\d+/i.test(server)) &&
      (/\bDocker\/(\d+\.\d+(?:\.\d+)?)/i.test(server) ||
        (/"ApiVersion"\s*:\s*"[^"]+"/.test(html) && /"KernelVersion"\s*:\s*"[^"]+"/.test(html)) ||
        /^Docker$/i.test(String(deviceInfo?.vendor || '')) ||
        (openPortSet.has(2375) && !hasExplicitLinuxHostSignal));

    const isKubernetes =
      (/\bKubernetes\b/i.test(`${headerCombined} ${banners.join(' ')}`) ||
        (/"gitVersion"\s*:\s*"v\d+\.\d+/.test(html) && /"platform"\s*:\s*"/.test(html)) ||
        openPortSet.has(6443) ||
        openPortSet.has(10250)) &&
      !hasExplicitLinuxHostSignal;

    if (isOllama) {
      const verMatch = /ollama\/(\d+\.\d+\.\d+)/i.exec(headerCombined) || /"version"\s*:\s*"(\d+\.\d+\.\d+)"/i.exec(html);
      addSignal(/Ollama is running/i.test(html) ? 'Ollama is running (11434/TCP)' : 'Ollama AI Runtime API (11434/TCP)');
      setDetection({
        family: 'container_ai_os',
        osName: 'Ollama AI Runtime',
        distro: 'Ollama',
        version: verMatch ? verMatch[1] : null,
        confidence: 'high',
        applianceType: 'ai_runtime'
      });
    } else if (isRay) {
      const verMatch = /"ray_version"\s*:\s*"(\d+\.\d+\.\d+)"/i.exec(html) || /Ray[\s/v-]+(\d+\.\d+\.\d+)/i.exec(`${headerCombined} ${html}`);
      addSignal(/Ray Dashboard/i.test(html) ? 'Ray Dashboard (8265/TCP)' : 'Ray Cluster Runtime API (8265/TCP)');
      setDetection({
        family: 'container_ai_os',
        osName: 'Ray Cluster Runtime',
        distro: 'Anyscale Ray',
        version: verMatch ? verMatch[1] : null,
        confidence: 'high',
        applianceType: 'ai_runtime'
      });
    } else if (isDockerEngine) {
      const verMatch = /Docker\/(\d+\.\d+(?:\.\d+)?)/i.exec(server) || /"Version"\s*:\s*"(\d+\.\d+(?:\.\d+)?)"/i.exec(html);
      addSignal(server && /Docker\//i.test(server) ? `Server: ${server}` : 'Docker Engine API (2375/TCP)');
      setDetection({
        family: 'container_ai_os',
        osName: 'Docker Engine',
        distro: 'Docker',
        version: verMatch ? verMatch[1] : null,
        confidence: 'high',
        applianceType: 'container_runtime'
      });
    } else if (isKubernetes) {
      const verMatch = /"gitVersion"\s*:\s*"v?(\d+\.\d+(?:\.\d+)?)"/i.exec(html) || /Kubernetes[\s/v-]+(\d+\.\d+(?:\.\d+)?)/i.exec(headerCombined);
      addSignal(openPortSet.has(10250) ? 'Kubernetes Kubelet API (10250/TCP)' : 'Kubernetes Cluster API (6443/TCP)');
      setDetection({
        family: 'container_ai_os',
        osName: 'Kubernetes Cluster Runtime',
        distro: 'Kubernetes',
        version: verMatch ? verMatch[1] : null,
        confidence: 'high',
        applianceType: 'container_orchestrator'
      });
    }
  }

  // ── 5. Windows Server & Workstation Detection & EOL Rules ─────────────────
  if (!family) {
    const iisMatch = /Microsoft-IIS\/(\d+\.\d+)/i.exec(headerCombined);
    const hasHttpApi = /Microsoft-HTTPAPI\/(\d+\.\d+)/i.test(headerCombined);
    const hasWinToken = /\((?:Win32|Win64)\)/i.test(headerCombined) || sshInfo?.osFamily === 'windows' || /^Windows$/i.test(String(deviceInfo?.osFamily || ''));
    const winPorts = [135, 139, 445, 3389, 5985, 5986, 5357].filter(p => openPortSet.has(p));

    if (iisMatch) {
      const iisVer = iisMatch[1];
      addSignal(`Server: Microsoft-IIS/${iisVer}`);
      if (iisVer === '6.0') {
        setDetection({
          family: 'windows',
          osName: 'Windows Server 2003',
          distro: 'Windows Server',
          version: '2003',
          isEol: true,
          eolReason: 'Windows Server 2003 (Microsoft-IIS/6.0) reached End-of-Life on 2015-07-14',
          confidence: 'high'
        });
      } else if (iisVer === '7.0') {
        setDetection({
          family: 'windows',
          osName: 'Windows Server 2008',
          distro: 'Windows Server',
          version: '2008',
          isEol: true,
          eolReason: 'Windows Server 2008 (Microsoft-IIS/7.0) reached End-of-Life on 2020-01-14',
          confidence: 'high'
        });
      } else if (iisVer === '7.5') {
        setDetection({
          family: 'windows',
          osName: 'Windows Server 2008 R2 / Windows 7',
          distro: 'Windows Server',
          version: '2008 R2',
          isEol: true,
          eolReason: 'Windows Server 2008 R2 / Windows 7 (Microsoft-IIS/7.5) reached End-of-Life on 2020-01-14',
          confidence: 'high'
        });
      } else if (iisVer === '8.0') {
        setDetection({
          family: 'windows',
          osName: 'Windows Server 2012',
          distro: 'Windows Server',
          version: '2012',
          isEol: true,
          eolReason: 'Windows Server 2012 (Microsoft-IIS/8.0) reached End-of-Life on 2023-10-10',
          confidence: 'high'
        });
      } else if (iisVer === '8.5') {
        setDetection({
          family: 'windows',
          osName: 'Windows Server 2012 R2',
          distro: 'Windows Server',
          version: '2012 R2',
          isEol: true,
          eolReason: 'Windows Server 2012 R2 (Microsoft-IIS/8.5) reached End-of-Life on 2023-10-10',
          confidence: 'high'
        });
      } else if (iisVer === '10.0') {
        setDetection({
          family: 'windows',
          osName: 'Windows Server 2016/2019/2022/2025 or Windows 10/11',
          distro: 'Windows Server',
          version: '2016+',
          isEol: false,
          eolReason: null,
          confidence: 'high'
        });
      } else {
        const isOldIis = parseFloat(iisVer) < 10.0;
        setDetection({
          family: 'windows',
          osName: `Windows Server (IIS ${iisVer})`,
          distro: 'Windows Server',
          version: iisVer,
          isEol: isOldIis,
          eolReason: isOldIis ? `Microsoft-IIS/${iisVer} indicates an End-of-Life Windows Server release` : null,
          confidence: 'high'
        });
      }
    } else if (hasHttpApi || hasWinToken || winPorts.length > 0) {
      if (hasHttpApi) addSignal('Server: Microsoft-HTTPAPI/2.0');
      if (/\((?:Win32|Win64)\)/i.test(headerCombined)) addSignal(server || poweredBy);
      if (winPorts.length > 0) addSignal(`Windows OS Ports Open: ${winPorts.join(', ')}`);
      setDetection({
        family: 'windows',
        osName: 'Windows Server / Workstation',
        distro: 'Windows',
        version: null,
        isEol: false,
        eolReason: null,
        confidence: hasHttpApi || hasWinToken || winPorts.length >= 2 ? 'high' : 'medium'
      });
    }
  }

  // ── 6. macOS / Apple Darwin Detection & EOL Rules ─────────────────────────
  if (!family) {
    const darwinMatch = /\bDarwin\/(\d+)(?:\.(\d+)(?:\.(\d+))?)?/i.exec(`${headerCombined} ${banners.join(' ')}`);
    const hasAirTunes = /\bAirTunes\/(\d+(?:\.\d+)*)|\bAirPlay\b/i.test(`${headerCombined} ${banners.join(' ')}`);
    const hasMacHeader = /\(macOS\)|\(Mac OS X\)|\(Unix\)\s+DAV\/2\b/i.test(headerCombined);
    const hasApplePorts = openPortSet.has(548) || openPortSet.has(7000) || (openPortSet.has(5000) && !isSynologyDsm);

    if (darwinMatch) {
      const darwinMajor = Number(darwinMatch[1]);
      const fullDarwin = darwinMatch[0].replace(/^Darwin\//i, '');
      addSignal(server && /Darwin\//i.test(server) ? `Server: ${server}` : `Darwin/${fullDarwin}`);

      let macVersion = `Darwin ${fullDarwin}`;
      let macEol = false;
      let macEolReason = null;

      if (darwinMajor === 18) {
        macVersion = '10.14 Mojave';
        macEol = true;
        macEolReason = `macOS 10.14 Mojave (Darwin/${fullDarwin}) reached End-of-Life in October 2021`;
      } else if (darwinMajor === 19) {
        macVersion = '10.15 Catalina';
        macEol = true;
        macEolReason = `macOS 10.15 Catalina (Darwin/${fullDarwin}) reached End-of-Life in November 2022`;
      } else if (darwinMajor === 20) {
        macVersion = '11 Big Sur';
        macEol = true;
        macEolReason = `macOS 11 Big Sur (Darwin/${fullDarwin}) reached End-of-Life in September 2023`;
      } else if (darwinMajor === 21) {
        macVersion = '12 Monterey';
        macEol = true;
        macEolReason = `macOS 12 Monterey (Darwin/${fullDarwin}) reached End-of-Life in September 2024`;
      } else if (darwinMajor < 18) {
        macEol = true;
        macEolReason = `Apple Darwin/${fullDarwin} (pre-Mojave macOS) has reached End-of-Life`;
      } else if (darwinMajor === 22) {
        macVersion = '13 Ventura';
      } else if (darwinMajor === 23) {
        macVersion = '14 Sonoma';
      } else if (darwinMajor >= 24) {
        macVersion = '15 Sequoia';
      }

      setDetection({
        family: 'macos',
        osName: 'macOS / Apple Darwin',
        distro: 'macOS',
        version: macVersion,
        isEol: macEol,
        eolReason: macEolReason,
        confidence: 'high'
      });
    } else if (hasAirTunes || hasMacHeader || hasApplePorts || sshInfo?.osFamily === 'macos') {
      if (hasAirTunes) addSignal(server ? `Server: ${server}` : 'Apple AirTunes / AirPlay Service');
      if (hasMacHeader) addSignal(`Server: ${server}`);
      if (hasApplePorts) {
        const ap = [548, 5000, 7000].filter(p => openPortSet.has(p));
        addSignal(`Apple macOS / AirPlay Ports Open: ${ap.join(', ')}`);
      }
      setDetection({
        family: 'macos',
        osName: 'macOS / Apple Darwin',
        distro: 'macOS',
        version: null,
        isEol: false,
        eolReason: null,
        confidence: hasAirTunes || hasMacHeader || openPortSet.has(548) ? 'high' : 'medium'
      });
    }
  }

  // ── 7. Linux Distributions Detection & EOL Rules ──────────────────────────
  if (!family) {
    const linuxContext = `${headerCombined} ${banners.join(' ')}`;

    // 7a. Ubuntu
    if (sshInfo?.distro === 'Ubuntu' || /\(Ubuntu\)|\bUbuntu[-/]\d*ubuntu|\b[0134]ubuntu\d/i.test(linuxContext)) {
      if (server && /ubuntu/i.test(server)) addSignal(`Server: ${server}`);
      else if (poweredBy && /ubuntu/i.test(poweredBy)) addSignal(`X-Powered-By: ${poweredBy}`);
      else if (!sshInfo) addSignal('Ubuntu Linux package banner');

      let uVer = sshInfo?.distroRelease || null;
      if (!uVer) {
        const exp = /\b(14\.04|16\.04|18\.04|20\.04|22\.04|24\.04)\b/.exec(linuxContext);
        if (exp) {
          uVer = exp[1];
        } else if (/Ubuntu-3ubuntu|\b3ubuntu0\b|Apache\/2\.4\.52\s+\(Ubuntu\)/i.test(linuxContext)) {
          uVer = '22.04';
        } else if (/Ubuntu-4ubuntu|\b3ubuntu13\b|Apache\/2\.4\.58\s+\(Ubuntu\)/i.test(linuxContext)) {
          uVer = '24.04';
        } else if (/Apache\/2\.4\.41\s+\(Ubuntu\)/i.test(linuxContext)) {
          uVer = '20.04';
        } else if (/Apache\/2\.4\.29\s+\(Ubuntu\)|nginx\/1\.14\.0\s+\(Ubuntu\)/i.test(linuxContext)) {
          uVer = '18.04';
        } else if (/Apache\/2\.4\.18\s+\(Ubuntu\)/i.test(linuxContext)) {
          uVer = '16.04';
        } else if (/\b1ubuntu/i.test(linuxContext)) {
          uVer = '18.04';
        }
      }

      const isUbuntuEol = uVer === '14.04' || uVer === '16.04' || uVer === '18.04';
      setDetection({
        family: 'linux',
        osName: 'Ubuntu Linux',
        distro: 'Ubuntu',
        version: uVer,
        isEol: isUbuntuEol,
        eolReason: isUbuntuEol ? `Ubuntu ${uVer} LTS has reached End-of-Standard-Support` : null,
        confidence: 'high'
      });
    }
    // 7b. Debian
    else if (sshInfo?.distro === 'Debian' || /\(Debian\)|\+deb\d+/i.test(linuxContext)) {
      if (server && /debian|\+deb/i.test(server)) addSignal(`Server: ${server}`);
      else if (poweredBy && /debian|\+deb/i.test(poweredBy)) addSignal(`X-Powered-By: ${poweredBy}`);
      else if (!sshInfo) addSignal('Debian Linux package banner');

      let dVer = sshInfo?.distroRelease || null;
      if (!dVer) {
        const debM = /\+deb(\d+)/i.exec(linuxContext);
        if (debM) dVer = debM[1];
      }
      const debNum = dVer ? parseInt(dVer, 10) : null;
      const isDebEol = debNum !== null && debNum <= 10;
      const debCodename = debNum === 9 ? 'Stretch' : (debNum === 10 ? 'Buster' : (debNum === 8 ? 'Jessie' : null));

      setDetection({
        family: 'linux',
        osName: 'Debian Linux',
        distro: 'Debian',
        version: dVer,
        isEol: isDebEol,
        eolReason: isDebEol ? `Debian ${dVer}${debCodename ? ` (${debCodename})` : ''} has reached End-of-Life` : null,
        confidence: 'high'
      });
    }
    // 7c. CentOS
    else if (sshInfo?.distro === 'CentOS' || /\(CentOS\)|\bCentOS(?:\s+Linux)?\s+[678]\b|\b(?:el6|el7)\b/i.test(linuxContext) && !/\(Red Hat/i.test(linuxContext)) {
      if (server) addSignal(`Server: ${server}`);
      else if (poweredBy) addSignal(`X-Powered-By: ${poweredBy}`);
      else addSignal('CentOS Linux banner');

      let cVer = sshInfo?.distroRelease || null;
      if (!cVer) {
        const m = /(?:CentOS(?:\s+Linux)?\s+|\.?el)([6789])\b/i.exec(linuxContext);
        if (m) {
          cVer = m[1];
        } else if (/Apache\/2\.4\.6\s+\(CentOS\)/i.test(linuxContext)) {
          cVer = '7';
        } else if (/Apache\/2\.2\.15\s+\(CentOS\)/i.test(linuxContext)) {
          cVer = '6';
        } else if (/Apache\/2\.4\.37\s+\(CentOS\)/i.test(linuxContext)) {
          cVer = '8';
        }
      }
      const isCentosEol = !cVer || ['6', '7', '8'].includes(cVer);
      setDetection({
        family: 'linux',
        osName: 'CentOS Linux',
        distro: 'CentOS',
        version: cVer,
        isEol: isCentosEol,
        eolReason: isCentosEol ? `CentOS Linux${cVer ? ` ${cVer}` : ''} has reached End-of-Life (CentOS 7 EOL 2024-06-30, CentOS 8 EOL 2021-12-31)` : null,
        confidence: 'high'
      });
    }
    // 7d. Red Hat Enterprise Linux (RHEL)
    else if (sshInfo?.distro === 'Red Hat Enterprise Linux' || /\(Red Hat[^)]*\)|\bRHEL\b/i.test(linuxContext)) {
      if (server) addSignal(`Server: ${server}`);
      else addSignal('Red Hat Enterprise Linux banner');
      const rVer = sshInfo?.distroRelease || (/(?:RHEL[\s/-]*|\.?el)([6789])\b/i.exec(linuxContext) || [])[1] || null;
      const isRhelEol = rVer === '6' || rVer === '7';
      setDetection({
        family: 'linux',
        osName: 'Red Hat Enterprise Linux',
        distro: 'RHEL',
        version: rVer,
        isEol: isRhelEol,
        eolReason: isRhelEol ? `Red Hat Enterprise Linux ${rVer} (el${rVer}) has reached End-of-Maintenance-Support` : null,
        confidence: 'high'
      });
    }
    // 7e. AlmaLinux
    else if (sshInfo?.distro === 'AlmaLinux' || /\(AlmaLinux\)|\bAlmaLinux\b/i.test(linuxContext)) {
      if (server) addSignal(`Server: ${server}`);
      else addSignal('AlmaLinux banner');
      const aVer = (/AlmaLinux[\s/-]*(\d+(?:\.\d+)?)/i.exec(linuxContext) || [])[1] || null;
      setDetection({
        family: 'linux',
        osName: 'AlmaLinux',
        distro: 'AlmaLinux',
        version: aVer,
        confidence: 'high'
      });
    }
    // 7f. Rocky Linux
    else if (sshInfo?.distro === 'Rocky Linux' || /\(Rocky[^)]*\)|\bRocky Linux\b/i.test(linuxContext)) {
      if (server) addSignal(`Server: ${server}`);
      else addSignal('Rocky Linux banner');
      const rkVer = (/Rocky(?:\s+Linux)?[\s/-]*(\d+(?:\.\d+)?)/i.exec(linuxContext) || [])[1] || null;
      setDetection({
        family: 'linux',
        osName: 'Rocky Linux',
        distro: 'Rocky Linux',
        version: rkVer,
        confidence: 'high'
      });
    }
    // 7g. Alpine Linux
    else if (sshInfo?.distro === 'Alpine' || /\(Alpine\)|\bAlpine Linux\b/i.test(linuxContext)) {
      if (server) addSignal(`Server: ${server}`);
      else if (poweredBy) addSignal(`X-Powered-By: ${poweredBy}`);
      else addSignal('Alpine Linux banner');
      const alVer = (/Alpine[\s/-]*(\d+\.\d+(?:\.\d+)?)/i.exec(linuxContext) || [])[1] || null;
      setDetection({
        family: 'linux',
        osName: 'Alpine Linux',
        distro: 'Alpine',
        version: alVer,
        confidence: 'high'
      });
    }
    // 7h. SUSE Linux
    else if (sshInfo?.distro === 'SUSE' || /\(SUSE\)|\bopenSUSE\b|\bSLES\b/i.test(linuxContext)) {
      if (server) addSignal(`Server: ${server}`);
      else addSignal('SUSE Linux banner');
      setDetection({
        family: 'linux',
        osName: 'SUSE Linux',
        distro: 'SUSE',
        version: null,
        confidence: 'high'
      });
    }
    // 7i. Arch Linux
    else if (sshInfo?.distro === 'Arch' || /\(Arch(?:\s+Linux)?\)|\bArch Linux\b/i.test(linuxContext)) {
      if (server) addSignal(`Server: ${server}`);
      else addSignal('Arch Linux banner');
      setDetection({
        family: 'linux',
        osName: 'Arch Linux',
        distro: 'Arch',
        version: null,
        confidence: 'high'
      });
    }
    // 7j. Generic Linux / Unix via ports (631 CUPS, 9090 Cockpit, 2375 Docker, 2049 NFS, 111 rpcbind), SSH banner, or Server: (Linux)/(Unix)
    else {
      const linuxPorts = [631, 9090, 2375, 2049, 111, 873, 10000].filter(p => openPortSet.has(p));
      const hasLinuxToken = /\(Linux\)|\(Unix\)|\bCUPS\/\d+\.\d+/i.test(headerCombined) || /^Linux$/i.test(String(deviceInfo?.osFamily || ''));
      if (hasLinuxToken || linuxPorts.length > 0 || Boolean(sshInfo)) {
        if (server && /\(Linux\)|\(Unix\)|\bCUPS\//i.test(server)) addSignal(`Server: ${server}`);
        if (linuxPorts.length > 0) addSignal(`Linux OS Ports Open: ${linuxPorts.join(', ')}`);
        setDetection({
          family: 'linux',
          osName: 'Linux',
          distro: 'Linux',
          version: null,
          isEol: false,
          eolReason: null,
          confidence: hasLinuxToken || linuxPorts.length >= 2 ? 'medium' : 'low'
        });
      }
    }
  }

  // ── 8. Build Exposed OS Services Inventory ────────────────────────────────
  const exposedOsServices = [];
  const seenServicePorts = new Set();

  for (const port of openPorts) {
    const catEntry = OS_PORT_SERVICE_CATALOG[port];
    if (catEntry && !seenServicePorts.has(port)) {
      seenServicePorts.add(port);
      let svcFamily = catEntry.family;
      let svcName = catEntry.service;
      let svcDetail = catEntry.detail;

      if (port === 5000 && family === 'network_appliance_os') {
        svcFamily = 'network_appliance_os';
        svcName = 'synology-dsm-http';
        svcDetail = 'Synology DSM Cleartext HTTP Management Portal (5000/TCP)';
      } else if (port === 22 && family) {
        svcFamily = family;
      }

      exposedOsServices.push({
        port,
        service: svcName,
        family: svcFamily,
        risk: catEntry.risk,
        detail: svcDetail
      });
    }
  }

  if (sshInfo && !seenServicePorts.has(22)) {
    exposedOsServices.push({
      port: 22,
      service: 'ssh',
      family: family || sshInfo.osFamily || 'linux',
      risk: 'LOW',
      detail: `OpenSSH ${sshInfo.version} Remote Shell Service (22/TCP)`
    });
  }

  const detected = Boolean(family);
  const familyLabel = family && OS_FAMILIES[family] ? OS_FAMILIES[family] : 'Unknown / Unclassified OS';

  return {
    detected,
    family,
    familyLabel,
    osName,
    distro,
    version,
    isEol,
    eolReason,
    confidence: detected ? confidence : 'none',
    signals: evidenceSignals,
    sshInfo,
    applianceType,
    exposedOsServices
  };
}
