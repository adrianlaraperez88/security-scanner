import net from 'node:net';
import { fetchWithRetry as defaultFetch } from '../core/fetch.js';
import { scanDeviceTarget, normalizeDeviceCategory } from '../core/device-scanner.js';
import { normalizeTargetInput, isPrivateOrReservedIP } from '../core/validator.js';

function isPrivateOrLanHost(hostname) {
  if (typeof hostname !== 'string') return false;
  const clean = hostname.trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
  if (!clean) return false;
  if (clean === 'localhost' || clean.endsWith('.local') || clean.endsWith('.localhost')) {
    return true;
  }
  if (net.isIP(clean) !== 0) {
    return isPrivateOrReservedIP(clean);
  }
  return false;
}

export const tags = ['all', 'device', 'tv', 'smart-tv', 'camera', 'ip-camera', 'pc', 'workstation', 'server', 'iot', 'ops'];

export const name = 'device-security';
export const cwe = 'CWE-200';
export const owasp = 'A05:2021-Security Misconfiguration';
export const cvssScore = 7.5;

export const meta = {
  id: 'device-security',
  title: 'Smart TV, IP Camera, PC/Workstation & Network Device Security Exposure',
  category: 'Infrastructure & Network',
  plainExplanation:
    'Performs strictly non-intrusive discovery and security exposure auditing across Smart TVs (Samsung Tizen, LG webOS, Roku ECP, Google TV / Android TV / Chromecast, Sony Bravia, Vizio SmartCast, Philips JointSpace, Apple AirPlay, DIAL), IP Cameras / NVRs (RTSP 554/8554, ONVIF SOAP, Hikvision ISAPI, Dahua, Axis, Xiongmai, UniFi Protect, unauthenticated snapshots), PCs / Workstations / Local Servers (Windows SMB/NetBIOS/MSRPC/RDP/WinRM/WSDAPI, macOS/Linux SSH/VNC/CUPS/NFS/AFP/rsync/mDNS, Docker TCP 2375, Ollama 11434, local dev servers, open directory shares), routers, printers, NAS, and IoT appliances.',
  whyItMatters:
    'Local network devices and workstations often expose unauthenticated REST/WebSocket control APIs, live RTSP/MJPEG camera feeds, cleartext admin UIs, unauthenticated Docker/Ollama/dev servers, or remote file-sharing and shell services (SMB 445, RDP 3389, WinRM 5985, ADB 5555, Telnet 23) that allow LAN attackers or compromised hosts to hijack screens, view surveillance feeds, access files, or execute arbitrary commands.',
  defaultFix:
    'Segment Smart TVs, IP cameras/NVRs, and IoT appliances onto isolated VLANs with client isolation enabled. Require authentication and HTTPS/TLS on camera and appliance admin interfaces, enforce RTSP Digest auth, disable unused UPnP/DLNA/ADB/Telnet services, bind local dev servers, Docker, and Ollama to 127.0.0.1, and restrict SMB/RDP/WinRM/SSH/VNC/NFS via host firewalls.',
  cwe: 'CWE-200',
  owasp: 'A05:2021-Security Misconfiguration',
  cvssScore: 7.5,
  cveIds: [],
  references: [
    'https://cwe.mitre.org/data/definitions/200.html',
    'https://owasp.org/www-project-internet-of-things/',
    'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
  ]
};

function buildDeviceFixGuidance(deviceProfile, findings) {
  const hints = [];
  const vendor = String(deviceProfile?.vendor || '').toLowerCase();
  const category = String(deviceProfile?.category || '').toLowerCase();
  const openPorts = Array.isArray(deviceProfile?.openPorts) ? deviceProfile.openPorts : [];
  const findingText = findings.map(f => `${f.name || ''} ${f.matchedSignal || ''}`).join(' ').toLowerCase();

  // Smart TVs
  if (vendor.includes('samsung') || openPorts.includes(8001) || openPorts.includes(8002) || openPorts.includes(9197)) {
    hints.push(
      'Samsung Smart TV (Tizen): Open Settings > General (or Connection) > External Device Manager > Device Connect Manager, set Access Notification to "Always On" or "First Time Only" (enforcing tokenAuthSupport on wss://:8002), review the Device List to revoke unknown paired controllers, and disable Wi-Fi Direct / DLNA DMR (port 9197) if unused.'
    );
  }
  if (vendor.includes('roku') || openPorts.includes(8060)) {
    hints.push(
      'Roku TV: Navigate to Settings > System > Advanced System Settings > Control by Mobile Apps and set Network Access to "Disabled" (or "Limited") to restrict unauthenticated ECP commands on port 8060.'
    );
  }
  if (vendor.includes('google') || vendor.includes('android') || openPorts.includes(8008) || openPorts.includes(8009)) {
    hints.push(
      'Google TV / Android TV / Cast: In Settings > System > Cast (or Google Cast), restrict "Let others control your cast media" to "Never", and disable Developer Options > USB/Network ADB Debugging.'
    );
  }
  if (openPorts.includes(5555) || findings.some(f => f.port === 5555)) {
    hints.push(
      'CRITICAL — Android ADB (5555/TCP): Immediately disable ADB over Network/Wi-Fi in Settings > Device Preferences > Developer Options to prevent unauthenticated remote shell compromise.'
    );
  }
  if (vendor.includes('lg') || openPorts.includes(9998) || (category === 'smart_tv' && (openPorts.includes(3000) || openPorts.includes(3001)))) {
    hints.push(
      'LG webOS TV: In Settings > General > External Devices > TV On With Mobile / LG Connect Apps, disable remote app control when not required and turn off Developer Mode (port 9998).'
    );
  }
  if (vendor.includes('sony') || openPorts.includes(52323)) {
    hints.push(
      'Sony Bravia TV: Enable Pre-Shared Key (PSK) authentication under Settings > Network > Home Network > IP Control and disable Simple IP Control if unused.'
    );
  }
  if (vendor.includes('vizio') || openPorts.includes(7345)) {
    hints.push(
      'Vizio SmartCast TV: Require pairing PIN verification for SmartCast mobile control and isolate the TV on a media VLAN.'
    );
  }
  if (vendor.includes('philips') || openPorts.includes(1925) || openPorts.includes(1926)) {
    hints.push(
      'Philips JointSpace TV: Restrict JointSpace API access on ports 1925/1926 to trusted LAN controllers or disable network control when unused.'
    );
  }
  if ((category === 'smart_tv' && (vendor.includes('apple') || vendor.includes('airplay'))) || openPorts.includes(7100)) {
    hints.push(
      'Apple AirPlay: Set AirPlay access to "Only People Sharing This Home" or require a passcode/PIN in AirPlay & HomeKit settings.'
    );
  }

  // IP Cameras / NVRs
  if (
    category === 'ip_camera' ||
    openPorts.includes(554) ||
    openPorts.includes(8554) ||
    openPorts.includes(37777) ||
    openPorts.includes(34567) ||
    findings.some(f => f.method === 'RTSP' || f.port === 554 || f.port === 8554)
  ) {
    hints.push(
      'IP Camera / NVR: Enable RTSP Digest authentication (never leave streams unauthenticated or on HTTP/RTSP Basic auth), disable unauthenticated ONVIF/ISAPI/magicBox/axis-cgi device-info endpoints or restrict them to the NVR IP, switch web administration from HTTP to HTTPS, apply latest vendor firmware, and isolate cameras on a dedicated surveillance VLAN.'
    );
  }

  // PCs / Workstations / Local Servers
  if (category === 'pc_workstation' || openPorts.some(p => [22, 135, 139, 445, 548, 873, 2049, 2375, 3389, 5173, 5357, 5900, 5901, 5985, 5986, 8888, 11434].includes(p))) {
    if (openPorts.some(p => [445, 139, 135].includes(p))) {
      hints.push(
        'Windows SMB / NetBIOS / MSRPC (445/139/135): Block inbound SMB/RPC on untrusted or public network profiles via Windows Defender Firewall, disable SMBv1, and require SMB signing and encryption.'
      );
    }
    if (openPorts.includes(3389)) {
      hints.push(
        'RDP (3389/TCP): Enforce Network Level Authentication (NLA), limit RDP access to VPN or jump-host subnets via firewall rules, and require strong MFA.'
      );
    }
    if (openPorts.includes(5985) || openPorts.includes(5986)) {
      hints.push(
        'WinRM (5985/5986): Disable unencrypted WinRM HTTP (5985) if not required, enforce HTTPS (5986) with Kerberos/certificate auth, and restrict to management subnets.'
      );
    }
    if (openPorts.includes(22)) {
      hints.push(
        'SSH (22/TCP): Disable SSHv1, enforce public-key authentication (PasswordAuthentication no), disable root login, and restrict SSH access with host firewall rules.'
      );
    }
    if (openPorts.includes(5900) || openPorts.includes(5901)) {
      hints.push(
        'VNC (5900/5901): Never expose unencrypted VNC directly to the LAN; require strong VNC authentication and tunnel RFB traffic over SSH or VPN.'
      );
    }
    if (openPorts.includes(2375) || findingText.includes('docker')) {
      hints.push(
        'CRITICAL — Docker Engine TCP API (2375/TCP): Immediately disable the unauthenticated TCP Docker socket (port 2375) or enforce mutual TLS on port 2376.'
      );
    }
    if (openPorts.includes(11434) || findingText.includes('ollama')) {
      hints.push(
        'Ollama API (11434/TCP): Bind Ollama to localhost (OLLAMA_HOST=127.0.0.1) or place it behind an authenticated reverse proxy.'
      );
    }
    if (openPorts.some(p => [631, 2049, 111, 548, 873].includes(p))) {
      hints.push(
        'Host File/Print Services (CUPS/NFS/AFP/rsync): Bind CUPS to localhost if remote printing is unused, restrict NFS/AFP/rsync exports to specific trusted hosts, and require authentication.'
      );
    }
    if (
      openPorts.some(p => [3000, 3001, 4200, 5000, 5173, 8000, 8080, 8081, 8888, 9000, 9090].includes(p)) ||
      findingText.includes('index of /') ||
      findingText.includes('simplehttp') ||
      findingText.includes('werkzeug') ||
      findingText.includes('jupyter')
    ) {
      hints.push(
        'Local Dev Servers & Open Shares: Bind development servers (Vite, Next.js, Flask/Werkzeug, Django, FastAPI, Jupyter) to 127.0.0.1 instead of 0.0.0.0, disable interactive debuggers and HTTP directory listings, and require token auth on notebooks.'
      );
    }
  }

  // Routers, Printers, NAS, IoT
  if (category === 'router_gateway' || openPorts.includes(7547) || openPorts.includes(23)) {
    hints.push(
      'Router / Gateway: Disable UPnP IGD WAN port-forwarding, disable TR-069/CWMP (port 7547) and Telnet (port 23), and restrict admin management to HTTPS with strong credentials.'
    );
  }
  if (category === 'printer' || openPorts.includes(9100)) {
    hints.push(
      'Network Printer: Restrict RAW JetDirect port 9100 and CUPS/IPP web management to authorized print servers or trusted workstations.'
    );
  }
  if (category === 'nas_media_server' || openPorts.includes(21)) {
    hints.push(
      'NAS / Media Server: Disable cleartext FTP (port 21) in favor of SFTP/HTTPS, and restrict media/admin interfaces to authenticated LAN users.'
    );
  }
  if (category === 'smart_home_iot' || openPorts.includes(1883) || openPorts.includes(1880)) {
    hints.push(
      'Smart Home / IoT Hub: Require TLS + authentication on MQTT (8883 instead of 1883) and lock down Node-RED / Tasmota / Shelly control APIs.'
    );
  }

  hints.push(
    'Network Segmentation: Isolate Smart TVs, IP cameras, and IoT appliances on dedicated VLANs or Wi-Fi SSIDs separated from workstations and sensitive servers.'
  );

  return hints.join(' ');
}

/**
 * Smart TV, IP Camera/NVR, PC/Workstation & Network Device Security Exposure scanner
 */
export default async function run(target, fetchWithRetry = defaultFetch, options = {}) {
  const fetchFn = typeof fetchWithRetry === 'function' ? fetchWithRetry : defaultFetch;
  const normalizedTarget = typeof target === 'string' ? (normalizeTargetInput(target) || target) : target;

  let parsedHostname = '';
  try {
    parsedHostname = new URL(normalizedTarget).hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
  } catch {
    parsedHostname = '';
  }

  const hasExplicitPorts = Array.isArray(options.ports) && options.ports.length > 0;
  const requestedCategory = normalizeDeviceCategory(options.deviceCategory);
  if (
    parsedHostname &&
    !isPrivateOrLanHost(parsedHostname) &&
    options.deviceMode !== true &&
    options.multiPort !== true &&
    !hasExplicitPorts &&
    requestedCategory === 'all'
  ) {
    return {
      name: 'device-security',
      status: 'SAFE',
      severity: 'NONE',
      cwe: 'CWE-200',
      owasp: 'A05:2021-Security Misconfiguration',
      cvssScore: 7.5,
      reason: 'Target is a public host without device scan mode enabled; multi-port LAN device discovery skipped.',
      detail: 'Target is a public host without device scan mode enabled; multi-port LAN device discovery skipped.'
    };
  }

  const scanRes = await scanDeviceTarget(normalizedTarget, fetchFn, options);
  if (!scanRes.ok) {
    return {
      name: 'device-security',
      status: 'ERROR',
      severity: 'NONE',
      reason: scanRes.error || 'Target unreachable'
    };
  }

  const findings = Array.isArray(scanRes.findings) ? scanRes.findings : [];
  const deviceProfile = scanRes.deviceProfile || null;

  if (findings.length === 0) {
    return {
      name: 'device-security',
      status: 'SAFE',
      severity: 'NONE',
      cwe: 'CWE-200',
      owasp: 'A05:2021-Security Misconfiguration',
      cvssScore: 7.5,
      ...(deviceProfile
        ? {
            device: deviceProfile,
            deviceCategory: deviceProfile.category || null,
            openPorts: deviceProfile.openPorts || []
          }
        : {})
    };
  }

  const hasVulnerable = findings.some(f => f.statusTag === 'VULNERABLE' || f.status === 'VULNERABLE');
  const overallStatus = hasVulnerable ? 'VULNERABLE' : 'SUSPICIOUS';

  const maxSev = findings.some(f => f.severity === 'CRITICAL')
    ? 'CRITICAL'
    : findings.some(f => f.severity === 'HIGH')
      ? 'HIGH'
      : findings.some(f => f.severity === 'MEDIUM')
        ? 'MEDIUM'
        : 'LOW';

  // Pick a primary finding that has an HTTP 200 trace first so reproduction curl commands point directly to the verified HTTP endpoint
  const NON_HTTP_METHODS = new Set(['TCP', 'UDP', 'RTSP']);
  const primary =
    findings.find(f => f.statusTag === 'VULNERABLE' && !NON_HTTP_METHODS.has(String(f.method || '').toUpperCase()) && f.status === 200) ||
    findings.find(f => f.statusTag === 'VULNERABLE') ||
    findings[0];

  const evidenceQuotes = [];
  for (const f of findings) {
    const q = f.evidenceQuote || f.preview;
    if (typeof q === 'string' && q.trim().length >= 8 && !evidenceQuotes.includes(q.trim())) {
      evidenceQuotes.push(q.trim());
    }
  }

  const files = findings.map(f => ({
    name: f.name,
    path: f.path || '/',
    url: f.url,
    port: f.port,
    method: f.method || 'GET',
    status: f.status ?? 200,
    severity: f.severity,
    statusTag: f.statusTag || 'VULNERABLE',
    matchedSignal: f.matchedSignal,
    reproducible: true,
    preview: f.preview,
    detail: f.reason,
    reason: f.reason,
    ...(f.evidenceQuote ? { evidenceQuote: f.evidenceQuote } : {}),
    ...(f.service ? { service: f.service } : {}),
    ...(f.scheme ? { scheme: f.scheme } : {}),
    ...(f.category ? { category: f.category } : {}),
    ...(f.vendor ? { vendor: f.vendor } : {}),
    ...(f.trafficId !== undefined ? { trafficId: f.trafficId } : {})
  }));

  const devicePrefix = deviceProfile?.summary ? `[${deviceProfile.summary}] ` : '';
  const detailSummary = `${devicePrefix}${findings.map(f => `${f.name} (port ${f.port}): ${f.reason}`).join(' | ')}`;

  return {
    name: 'device-security',
    status: overallStatus,
    severity: maxSev,
    path: primary.path || '/',
    url: primary.url,
    observedStatus: primary.status ?? 200,
    ...(primary.method ? { method: primary.method } : {}),
    ...(primary.port ? { port: primary.port } : {}),
    ...(deviceProfile?.host ? { host: deviceProfile.host } : {}),
    reproVerified: true,
    cwe: 'CWE-200',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 7.5,
    detail: detailSummary,
    reason: primary.reason,
    ...(deviceProfile
      ? {
          device: deviceProfile,
          deviceCategory: deviceProfile.category || null,
          openPorts: deviceProfile.openPorts || []
        }
      : {}),
    files,
    issues: files,
    evidenceQuotes: evidenceQuotes.slice(0, 6),
    ...(primary.trafficId !== undefined ? { trafficId: primary.trafficId } : {}),
    fix: buildDeviceFixGuidance(deviceProfile, findings)
  };
}
