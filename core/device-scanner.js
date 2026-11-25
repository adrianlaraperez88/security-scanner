import net from 'node:net';
import tls from 'node:tls';
import dgram from 'node:dgram';
import { URL } from 'node:url';
import pLimit from 'p-limit';
import {
  getHeader,
  isHtmlOrScript,
  parseJsonObject,
  extractVerbatimSnippet
} from './check-verify.js';
import { validateTargetUrl, normalizeTargetInput, resolveAndValidateTarget, isPrivateOrReservedIP } from './validator.js';
import { runAssetGateCheck, fetchWithRetry as defaultCoreFetch } from './fetch.js';

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

const DEVICE_WEB_PATH_CATEGORIES = new Map([
  ['/', null],
  ['/api/v2/', ['smart_tv']],
  ['/ws/app/', ['smart_tv']],
  ['/ws/apps/', ['smart_tv']],
  ['/setup/eureka_info', ['smart_tv']],
  ['/query/device-info', ['smart_tv']],
  ['/query/apps', ['smart_tv']],
  ['/sony/system', ['smart_tv']],
  ['/apps', ['smart_tv']],
  ['/dmr', ['smart_tv']],
  ['/smp_2_', ['smart_tv']],
  ['/dd.xml', ['smart_tv']],
  ['/info', ['smart_tv']],
  ['/server-info', ['smart_tv']],
  ['/1/system', ['smart_tv']],
  ['/6/system', ['smart_tv']],
  ['/description.xml', ['smart_tv', 'upnp_dlna', 'router_gateway', 'nas_media_server']],
  ['/rootDesc.xml', ['smart_tv', 'upnp_dlna', 'router_gateway', 'nas_media_server']],
  ['/ssdp/device-desc.xml', ['smart_tv', 'upnp_dlna', 'router_gateway']],
  ['/cm?cmnd=Status%200', ['smart_home_iot']],
  ['/shelly', ['smart_home_iot']],
  ['/identity', ['nas_media_server']],
  ['/System/Info/Public', ['nas_media_server']],
  ['/ISAPI/System/deviceInfo', ['ip_camera']],
  ['/SDK/activateStatus', ['ip_camera']],
  ['/onvif/device_service', ['ip_camera']],
  ['/cgi-bin/magicBox.cgi?action=getSystemInfo', ['ip_camera']],
  ['/axis-cgi/param.cgi?action=list&group=Brand', ['ip_camera']],
  ['/axis-cgi/basicdeviceinfo.cgi', ['ip_camera']],
  ['/view/viewer_index.shtml', ['ip_camera']],
  ['/snapshot.jpg', ['ip_camera']]
]);

function filterDeviceWebPathsForCategory(paths, requestedCategory) {
  if (!Array.isArray(paths) || paths.length === 0) return ['/'];
  if (!requestedCategory || requestedCategory === 'all') return paths;
  const filtered = paths.filter(p => {
    if (!DEVICE_WEB_PATH_CATEGORIES.has(p)) return true;
    const allowed = DEVICE_WEB_PATH_CATEGORIES.get(p);
    return allowed === null || allowed.includes(requestedCategory);
  });
  return filtered.length > 0 ? filtered : ['/'];
}

/**
 * Human-readable labels for device categories.
 */
export const DEVICE_CATEGORIES = Object.freeze({
  smart_tv: 'Smart TV & Streaming Media Device',
  ip_camera: 'IP Camera / NVR / Video Surveillance',
  pc_workstation: 'PC, Workstation & Local Server',
  upnp_dlna: 'UPnP / DLNA Media Renderer & Control Device',
  router_gateway: 'Router, Mesh Wi-Fi & Network Gateway',
  printer: 'Network Printer & Print Server',
  nas_media_server: 'NAS & Home Media Server',
  smart_home_iot: 'Smart Home & IoT Hub / Appliance',
  device_web: 'Network Device Web & Companion Interface'
});

/**
 * Alias map for normalizing user-facing device category inputs.
 */
export const DEVICE_CATEGORY_ALIASES = Object.freeze({
  all: 'all',
  any: 'all',
  '*': 'all',
  tv: 'smart_tv',
  'smart-tv': 'smart_tv',
  smart_tv: 'smart_tv',
  smarttv: 'smart_tv',
  television: 'smart_tv',
  camera: 'ip_camera',
  cameras: 'ip_camera',
  cam: 'ip_camera',
  nvr: 'ip_camera',
  dvr: 'ip_camera',
  cctv: 'ip_camera',
  surveillance: 'ip_camera',
  'ip-camera': 'ip_camera',
  ip_camera: 'ip_camera',
  ipcamera: 'ip_camera',
  pc: 'pc_workstation',
  workstation: 'pc_workstation',
  server: 'pc_workstation',
  desktop: 'pc_workstation',
  laptop: 'pc_workstation',
  'pc-workstation': 'pc_workstation',
  pc_workstation: 'pc_workstation',
  'local-server': 'pc_workstation',
  local_server: 'pc_workstation',
  'dev-server': 'pc_workstation',
  host: 'pc_workstation',
  upnp: 'upnp_dlna',
  dlna: 'upnp_dlna',
  upnp_dlna: 'upnp_dlna',
  router: 'router_gateway',
  gateway: 'router_gateway',
  'router-gateway': 'router_gateway',
  router_gateway: 'router_gateway',
  printer: 'printer',
  nas: 'nas_media_server',
  'nas-media-server': 'nas_media_server',
  nas_media_server: 'nas_media_server',
  iot: 'smart_home_iot',
  'smart-home': 'smart_home_iot',
  smart_home_iot: 'smart_home_iot',
  device_web: 'device_web'
});

/**
 * Normalizes a device category filter string to a canonical category key or `'all'`.
 *
 * @param {string | null | undefined} input
 * @returns {string}
 */
export function normalizeDeviceCategory(input) {
  if (input === null || input === undefined) return 'all';
  const raw = String(input).trim().toLowerCase();
  if (!raw) return 'all';
  if (Object.prototype.hasOwnProperty.call(DEVICE_CATEGORY_ALIASES, raw)) {
    return DEVICE_CATEGORY_ALIASES[raw];
  }
  const underscored = raw.replace(/-/g, '_');
  if (Object.prototype.hasOwnProperty.call(DEVICE_CATEGORIES, underscored)) {
    return underscored;
  }
  return 'all';
}

/**
 * Catalog of common Smart TV, Streaming, IP Camera/NVR, PC/Workstation/Server, IoT, Router, Printer, and NAS ports.
 */
export const DEVICE_PORT_CATALOG = Object.freeze([
  // Smart TVs & Streaming Media Devices
  {
    port: 8001,
    scheme: 'http',
    category: 'smart_tv',
    vendor: 'Samsung',
    service: 'samsung-tizen-api',
    label: 'Samsung Smart TV (Tizen) SmartView HTTP REST/WS API',
    paths: ['/api/v2/', '/ms/1.0/', '/ws/apps/'],
    risk: 'MEDIUM'
  },
  {
    port: 8002,
    scheme: 'https',
    category: 'smart_tv',
    vendor: 'Samsung',
    service: 'samsung-tizen-tls-api',
    label: 'Samsung Smart TV (Tizen) SmartView HTTPS/WSS API',
    paths: ['/api/v2/'],
    risk: 'LOW'
  },
  {
    port: 9197,
    scheme: 'http',
    category: 'smart_tv',
    vendor: 'Samsung',
    service: 'samsung-dlna-dmr',
    label: 'Samsung Smart TV DLNA / UPnP Digital Media Renderer (DMR)',
    paths: ['/dmr', '/smp_2_', '/rcr', '/description.xml', '/'],
    risk: 'MEDIUM'
  },
  {
    port: 7676,
    scheme: 'http',
    category: 'smart_tv',
    vendor: 'Samsung',
    service: 'samsung-upnp-smp',
    label: 'Samsung Smart TV AllShare / UPnP SMP Service',
    paths: ['/smp_2_', '/smp_4_', '/description.xml'],
    risk: 'MEDIUM'
  },
  {
    port: 8008,
    scheme: 'http',
    category: 'smart_tv',
    vendor: 'Google',
    service: 'google-cast-eureka',
    label: 'Google Cast / Android TV / Chromecast Eureka HTTP API',
    paths: ['/setup/eureka_info', '/ssdp/device-desc.xml', '/apps'],
    risk: 'MEDIUM'
  },
  {
    port: 8443,
    scheme: 'https',
    category: 'smart_tv',
    categories: ['smart_tv', 'pc_workstation', 'router_gateway'],
    sharedPort: true,
    ambiguous: true,
    vendor: null,
    service: 'device-https-alt',
    label: 'Device / Cast / App HTTPS Control Interface',
    paths: ['/setup/eureka_info', '/api/v2/', '/'],
    risk: 'LOW'
  },
  {
    port: 8009,
    scheme: 'tcp',
    category: 'smart_tv',
    vendor: 'Google',
    service: 'google-cast-tls',
    label: 'Google Cast / Android TV TLS Control Channel',
    paths: [],
    risk: 'LOW'
  },
  {
    port: 8060,
    scheme: 'http',
    category: 'smart_tv',
    vendor: 'Roku',
    service: 'roku-ecp',
    label: 'Roku TV / Roku External Control Protocol (ECP)',
    paths: ['/query/device-info', '/query/apps', '/query/active-app', '/'],
    risk: 'HIGH'
  },
  {
    port: 3000,
    scheme: 'http',
    category: 'smart_tv',
    categories: ['smart_tv', 'pc_workstation'],
    sharedPort: true,
    ambiguous: true,
    vendor: null,
    service: 'http-3000-ssap-dev',
    label: 'LG webOS SSAP / Local Dev HTTP Service (3000/TCP)',
    paths: ['/'],
    risk: 'MEDIUM'
  },
  {
    port: 3001,
    scheme: 'https',
    category: 'smart_tv',
    categories: ['smart_tv', 'pc_workstation'],
    sharedPort: true,
    ambiguous: true,
    vendor: null,
    service: 'https-3001-ssap-dev',
    label: 'LG webOS SSAP / Local Dev HTTPS Service (3001/TCP)',
    paths: ['/'],
    risk: 'LOW'
  },
  {
    port: 9998,
    scheme: 'http',
    category: 'smart_tv',
    vendor: 'LG',
    service: 'lg-webos-debug',
    label: 'LG webOS Smart TV Developer Mode / Debug Service',
    paths: ['/'],
    risk: 'HIGH'
  },
  {
    port: 7000,
    scheme: 'http',
    category: 'smart_tv',
    categories: ['smart_tv', 'pc_workstation'],
    sharedPort: true,
    ambiguous: true,
    vendor: null,
    service: 'apple-airplay',
    label: 'Apple AirPlay / AirTunes Media Receiver (7000/TCP)',
    paths: ['/info', '/server-info'],
    risk: 'MEDIUM'
  },
  {
    port: 5000,
    scheme: 'http',
    category: 'smart_tv',
    categories: ['smart_tv', 'nas_media_server', 'pc_workstation'],
    sharedPort: true,
    ambiguous: true,
    vendor: null,
    service: 'upnp-airplay-dsm',
    label: 'AirPlay / NAS / Local App HTTP Service (5000/TCP)',
    paths: ['/info', '/server-info', '/rootDesc.xml', '/description.xml', '/'],
    risk: 'MEDIUM'
  },
  {
    port: 7100,
    scheme: 'http',
    category: 'smart_tv',
    categories: ['smart_tv', 'pc_workstation'],
    sharedPort: true,
    ambiguous: true,
    vendor: null,
    service: 'apple-airplay-mirror',
    label: 'Apple AirPlay Screen Mirroring Service',
    paths: ['/info'],
    risk: 'LOW'
  },
  {
    port: 52323,
    scheme: 'http',
    category: 'smart_tv',
    vendor: 'Sony',
    service: 'sony-bravia-upnp',
    label: 'Sony Bravia Smart TV UPnP & ScalarWebAPI',
    paths: ['/dd.xml', '/sony/system'],
    risk: 'MEDIUM'
  },
  {
    port: 7345,
    scheme: 'https',
    category: 'smart_tv',
    vendor: 'Vizio',
    service: 'vizio-smartcast',
    label: 'Vizio SmartCast TV Local Control HTTPS API',
    paths: ['/state/device/power_mode'],
    risk: 'MEDIUM'
  },
  {
    port: 9000,
    scheme: 'https',
    alternateSchemes: ['http'],
    category: 'smart_tv',
    categories: ['smart_tv', 'pc_workstation'],
    sharedPort: true,
    ambiguous: true,
    vendor: null,
    service: 'https-9000-smartcast-app',
    label: 'Vizio SmartCast / Local App Service (9000/TCP)',
    paths: ['/state/device/power_mode', '/'],
    risk: 'LOW'
  },
  {
    port: 1925,
    scheme: 'http',
    category: 'smart_tv',
    vendor: 'Philips',
    service: 'philips-jointspace',
    label: 'Philips JointSpace Smart TV HTTP Control API',
    paths: ['/1/system', '/6/system'],
    risk: 'MEDIUM'
  },
  {
    port: 1926,
    scheme: 'https',
    category: 'smart_tv',
    vendor: 'Philips',
    service: 'philips-jointspace-tls',
    label: 'Philips JointSpace Smart TV HTTPS Control API',
    paths: ['/6/system', '/1/system'],
    risk: 'LOW'
  },
  {
    port: 5555,
    scheme: 'tcp',
    category: 'smart_tv',
    vendor: 'Android',
    service: 'android-adb-tcp',
    label: 'Android Debug Bridge (ADB over Wi-Fi / TCP)',
    paths: [],
    risk: 'CRITICAL'
  },

  // Device Web / Companion / DIAL Ports (shared across categories)
  {
    port: 80,
    scheme: 'http',
    category: 'device_web',
    categories: ['device_web', 'smart_tv', 'ip_camera', 'pc_workstation', 'router_gateway', 'printer', 'nas_media_server', 'smart_home_iot'],
    sharedPort: true,
    ambiguous: true,
    vendor: null,
    service: 'http-device-web',
    label: 'Device HTTP Web Admin / Control Interface',
    paths: [
      '/',
      '/api/v2/',
      '/setup/eureka_info',
      '/query/device-info',
      '/sony/system',
      '/description.xml',
      '/rootDesc.xml',
      '/ssdp/device-desc.xml',
      '/apps',
      '/info',
      '/cm?cmnd=Status%200',
      '/shelly',
      '/ISAPI/System/deviceInfo',
      '/SDK/activateStatus',
      '/onvif/device_service',
      '/cgi-bin/magicBox.cgi?action=getSystemInfo',
      '/axis-cgi/param.cgi?action=list&group=Brand',
      '/axis-cgi/basicdeviceinfo.cgi',
      '/view/viewer_index.shtml',
      '/snapshot.jpg'
    ],
    risk: 'LOW'
  },
  {
    port: 443,
    scheme: 'https',
    category: 'device_web',
    categories: ['device_web', 'smart_tv', 'ip_camera', 'pc_workstation', 'router_gateway', 'printer', 'nas_media_server', 'smart_home_iot'],
    sharedPort: true,
    ambiguous: true,
    vendor: null,
    service: 'https-device-web',
    label: 'Device HTTPS Web Admin / Control Interface',
    paths: [
      '/',
      '/api/v2/',
      '/setup/eureka_info',
      '/query/device-info',
      '/sony/system',
      '/description.xml',
      '/rootDesc.xml',
      '/ssdp/device-desc.xml',
      '/apps',
      '/info',
      '/System/Info/Public',
      '/ISAPI/System/deviceInfo',
      '/SDK/activateStatus',
      '/onvif/device_service',
      '/cgi-bin/magicBox.cgi?action=getSystemInfo',
      '/axis-cgi/param.cgi?action=list&group=Brand',
      '/axis-cgi/basicdeviceinfo.cgi',
      '/view/viewer_index.shtml',
      '/snapshot.jpg'
    ],
    risk: 'NONE'
  },
  {
    port: 8080,
    scheme: 'http',
    category: 'device_web',
    categories: ['device_web', 'smart_tv', 'ip_camera', 'pc_workstation'],
    sharedPort: true,
    ambiguous: true,
    vendor: null,
    service: 'http-companion-dial',
    label: 'Device Companion Web / DIAL / Proxy HTTP Service',
    paths: [
      '/',
      '/ws/app/',
      '/ws/apps/',
      '/apps',
      '/api/v2/',
      '/description.xml',
      '/ssdp/device-desc.xml',
      '/ISAPI/System/deviceInfo',
      '/onvif/device_service'
    ],
    risk: 'MEDIUM'
  },

  // UPnP / DLNA / Speakers / Smart Home / IoT
  {
    port: 1400,
    scheme: 'http',
    category: 'smart_home_iot',
    vendor: 'Sonos',
    service: 'sonos-upnp',
    label: 'Sonos Smart Speaker UPnP & Diagnostics Service',
    paths: ['/xml/device_description.xml', '/status/info'],
    risk: 'MEDIUM'
  },
  {
    port: 2869,
    scheme: 'http',
    category: 'upnp_dlna',
    vendor: null,
    service: 'upnp-event-control',
    label: 'Universal UPnP / DLNA Event & Control Service',
    paths: ['/description.xml', '/rootDesc.xml'],
    risk: 'MEDIUM'
  },
  {
    port: 49152,
    scheme: 'http',
    category: 'upnp_dlna',
    vendor: null,
    service: 'libupnp-device',
    label: 'Portable SDK for UPnP Devices (libupnp) Service',
    paths: ['/description.xml', '/rootDesc.xml', '/tvdevicedesc.xml'],
    risk: 'MEDIUM'
  },
  {
    port: 8123,
    scheme: 'http',
    category: 'smart_home_iot',
    vendor: 'Home Assistant',
    service: 'home-assistant',
    label: 'Home Assistant Smart Home Hub',
    paths: ['/manifest.json', '/api/'],
    risk: 'LOW'
  },
  {
    port: 1883,
    scheme: 'tcp',
    category: 'smart_home_iot',
    vendor: null,
    service: 'mqtt-broker',
    label: 'MQTT Cleartext IoT Telemetry & Command Broker',
    paths: [],
    risk: 'HIGH'
  },
  {
    port: 1880,
    scheme: 'http',
    category: 'smart_home_iot',
    vendor: 'Node-RED',
    service: 'node-red',
    label: 'Node-RED IoT Automation Flow Editor',
    paths: ['/settings', '/'],
    risk: 'HIGH'
  },

  // NAS & Media Servers
  {
    port: 32400,
    scheme: 'http',
    category: 'nas_media_server',
    vendor: 'Plex',
    service: 'plex-media-server',
    label: 'Plex Media Server',
    paths: ['/identity'],
    risk: 'LOW'
  },
  {
    port: 8096,
    scheme: 'http',
    category: 'nas_media_server',
    vendor: 'Jellyfin',
    service: 'jellyfin-emby',
    label: 'Jellyfin / Emby Home Media Server',
    paths: ['/System/Info/Public'],
    risk: 'LOW'
  },
  {
    port: 8200,
    scheme: 'http',
    category: 'nas_media_server',
    vendor: 'ReadyMedia',
    service: 'minidlna',
    label: 'MiniDLNA / ReadyMedia DLNA Media Server',
    paths: ['/', '/rootDesc.xml'],
    risk: 'LOW'
  },
  {
    port: 21,
    scheme: 'tcp',
    category: 'nas_media_server',
    vendor: null,
    service: 'ftp-cleartext',
    label: 'FTP Cleartext File Transfer Service',
    paths: [],
    risk: 'HIGH'
  },

  // Network Printers
  {
    port: 9100,
    scheme: 'tcp',
    category: 'printer',
    vendor: 'HP/JetDirect',
    service: 'jetdirect-raw-print',
    label: 'HP JetDirect / RAW Network Printing Port (9100/TCP)',
    paths: [],
    risk: 'HIGH'
  },
  {
    port: 631,
    scheme: 'http',
    category: 'printer',
    categories: ['printer', 'pc_workstation'],
    sharedPort: true,
    ambiguous: true,
    vendor: null,
    service: 'ipp-cups',
    label: 'IPP / CUPS Print Server Service (631/TCP)',
    paths: ['/printers', '/'],
    risk: 'MEDIUM'
  },

  // IP Cameras / NVRs & Video Surveillance
  {
    port: 554,
    scheme: 'tcp',
    category: 'ip_camera',
    vendor: null,
    service: 'rtsp-stream',
    label: 'RTSP Real-Time Video Streaming Port (554/TCP)',
    paths: [],
    risk: 'MEDIUM'
  },
  {
    port: 8554,
    scheme: 'tcp',
    category: 'ip_camera',
    vendor: null,
    service: 'rtsp-alt-stream',
    label: 'RTSP Alternate Video Streaming Port (8554/TCP)',
    paths: [],
    risk: 'MEDIUM'
  },
  {
    port: 8000,
    scheme: 'http',
    category: 'ip_camera',
    categories: ['ip_camera', 'pc_workstation'],
    sharedPort: true,
    ambiguous: true,
    vendor: null,
    service: 'ip-camera-or-dev-http',
    label: 'IP Camera / ONVIF / Local HTTP Service (8000/TCP)',
    paths: ['/ISAPI/System/deviceInfo', '/SDK/activateStatus', '/onvif/device_service', '/'],
    risk: 'MEDIUM'
  },
  {
    port: 8899,
    scheme: 'http',
    category: 'ip_camera',
    vendor: null,
    service: 'onvif-soap-alt',
    label: 'ONVIF IP Camera SOAP Service (8899/TCP)',
    paths: ['/onvif/device_service', '/'],
    risk: 'MEDIUM'
  },
  {
    port: 2020,
    scheme: 'http',
    category: 'ip_camera',
    vendor: null,
    service: 'onvif-camera-alt',
    label: 'IP Camera ONVIF / Control Service (2020/TCP)',
    paths: ['/onvif/device_service', '/'],
    risk: 'MEDIUM'
  },
  {
    port: 37777,
    scheme: 'tcp',
    category: 'ip_camera',
    vendor: 'Dahua',
    service: 'dahua-private-protocol',
    label: 'Dahua NVR / DVR Private Control Protocol (37777/TCP)',
    paths: [],
    risk: 'MEDIUM'
  },
  {
    port: 34567,
    scheme: 'tcp',
    category: 'ip_camera',
    vendor: 'Xiongmai',
    service: 'xiongmai-dvrip',
    label: 'Xiongmai / DVRIP Surveillance Control Port (34567/TCP)',
    paths: [],
    risk: 'HIGH'
  },
  {
    port: 7080,
    scheme: 'http',
    category: 'ip_camera',
    vendor: 'Ubiquiti',
    service: 'unifi-protect-http',
    label: 'UniFi Protect / NVR HTTP Interface (7080/TCP)',
    paths: ['/api/2.0/bootstrap', '/'],
    risk: 'MEDIUM'
  },
  {
    port: 7443,
    scheme: 'https',
    category: 'ip_camera',
    vendor: 'Ubiquiti',
    service: 'unifi-protect-https',
    label: 'UniFi Protect / NVR HTTPS Interface (7443/TCP)',
    paths: ['/api/2.0/bootstrap', '/'],
    risk: 'LOW'
  },

  // Routers & Gateways
  {
    port: 7547,
    scheme: 'http',
    category: 'router_gateway',
    vendor: null,
    service: 'tr069-cwmp',
    label: 'TR-069 / CWMP Router WAN Remote Management Port',
    paths: ['/'],
    risk: 'HIGH'
  },
  {
    port: 23,
    scheme: 'tcp',
    category: 'router_gateway',
    vendor: null,
    service: 'telnet-cleartext',
    label: 'Telnet Cleartext Remote Shell Service (23/TCP)',
    paths: [],
    risk: 'CRITICAL'
  },

  // PCs, Workstations & Local Servers
  {
    port: 445,
    scheme: 'tcp',
    category: 'pc_workstation',
    vendor: 'Microsoft',
    service: 'smb-cifs',
    label: 'Windows SMB / CIFS File Sharing Service (445/TCP)',
    paths: [],
    risk: 'HIGH'
  },
  {
    port: 139,
    scheme: 'tcp',
    category: 'pc_workstation',
    vendor: 'Microsoft',
    service: 'netbios-ssn',
    label: 'NetBIOS Session Service (139/TCP)',
    paths: [],
    risk: 'MEDIUM'
  },
  {
    port: 135,
    scheme: 'tcp',
    category: 'pc_workstation',
    vendor: 'Microsoft',
    service: 'msrpc-epmap',
    label: 'Microsoft RPC Endpoint Mapper (135/TCP)',
    paths: [],
    risk: 'MEDIUM'
  },
  {
    port: 3389,
    scheme: 'tcp',
    category: 'pc_workstation',
    vendor: 'Microsoft',
    service: 'rdp-remote-desktop',
    label: 'Remote Desktop Protocol (RDP 3389/TCP)',
    paths: [],
    risk: 'HIGH'
  },
  {
    port: 5985,
    scheme: 'http',
    category: 'pc_workstation',
    vendor: 'Microsoft',
    service: 'winrm-http',
    label: 'Windows Remote Management (WinRM HTTP 5985/TCP)',
    paths: ['/wsman'],
    risk: 'HIGH'
  },
  {
    port: 5986,
    scheme: 'https',
    category: 'pc_workstation',
    vendor: 'Microsoft',
    service: 'winrm-https',
    label: 'Windows Remote Management (WinRM HTTPS 5986/TCP)',
    paths: ['/wsman'],
    risk: 'MEDIUM'
  },
  {
    port: 5357,
    scheme: 'http',
    category: 'pc_workstation',
    vendor: 'Microsoft',
    service: 'wsdapi-http',
    label: 'Windows WSDAPI / Network Discovery HTTP Service (5357/TCP)',
    paths: ['/'],
    risk: 'LOW'
  },
  {
    port: 22,
    scheme: 'tcp',
    category: 'pc_workstation',
    vendor: null,
    service: 'ssh-remote',
    label: 'SSH Remote Shell Service (22/TCP)',
    paths: [],
    risk: 'LOW'
  },
  {
    port: 5900,
    scheme: 'tcp',
    category: 'pc_workstation',
    vendor: null,
    service: 'vnc-rfb',
    label: 'VNC Remote Framebuffer Desktop Service (5900/TCP)',
    paths: [],
    risk: 'HIGH'
  },
  {
    port: 5901,
    scheme: 'tcp',
    category: 'pc_workstation',
    vendor: null,
    service: 'vnc-rfb-1',
    label: 'VNC Remote Framebuffer Desktop Service (5901/TCP)',
    paths: [],
    risk: 'HIGH'
  },
  {
    port: 2049,
    scheme: 'tcp',
    category: 'pc_workstation',
    vendor: null,
    service: 'nfs-share',
    label: 'NFS Network File System Export Port (2049/TCP)',
    paths: [],
    risk: 'HIGH'
  },
  {
    port: 111,
    scheme: 'tcp',
    category: 'pc_workstation',
    vendor: null,
    service: 'rpcbind-portmapper',
    label: 'ONC RPC / rpcbind Portmapper (111/TCP)',
    paths: [],
    risk: 'MEDIUM'
  },
  {
    port: 548,
    scheme: 'tcp',
    category: 'pc_workstation',
    vendor: 'Apple',
    service: 'afp-file-sharing',
    label: 'Apple Filing Protocol (AFP 548/TCP)',
    paths: [],
    risk: 'MEDIUM'
  },
  {
    port: 873,
    scheme: 'tcp',
    category: 'pc_workstation',
    vendor: null,
    service: 'rsync-daemon',
    label: 'rsync File Synchronization Daemon (873/TCP)',
    paths: [],
    risk: 'MEDIUM'
  },
  {
    port: 4200,
    scheme: 'http',
    category: 'pc_workstation',
    sharedPort: true,
    ambiguous: true,
    vendor: null,
    service: 'dev-angular-http',
    label: 'Local Dev Server / Angular CLI HTTP Port (4200/TCP)',
    paths: ['/'],
    risk: 'LOW'
  },
  {
    port: 5173,
    scheme: 'http',
    category: 'pc_workstation',
    sharedPort: true,
    ambiguous: true,
    vendor: null,
    service: 'dev-vite-http',
    label: 'Vite Local Dev Server HTTP Port (5173/TCP)',
    paths: ['/', '/@vite/client'],
    risk: 'LOW'
  },
  {
    port: 8081,
    scheme: 'http',
    category: 'pc_workstation',
    categories: ['pc_workstation', 'ip_camera'],
    sharedPort: true,
    ambiguous: true,
    vendor: null,
    service: 'dev-http-alt',
    label: 'Local Web / App / Camera Alt HTTP Port (8081/TCP)',
    paths: ['/', '/ISAPI/System/deviceInfo', '/onvif/device_service', '/snapshot.jpg'],
    risk: 'LOW'
  },
  {
    port: 8888,
    scheme: 'http',
    category: 'pc_workstation',
    sharedPort: true,
    ambiguous: true,
    vendor: null,
    service: 'jupyter-http',
    label: 'Jupyter Notebook / Local Dev HTTP Service (8888/TCP)',
    paths: ['/', '/api/status'],
    risk: 'MEDIUM'
  },
  {
    port: 9090,
    scheme: 'http',
    category: 'pc_workstation',
    sharedPort: true,
    ambiguous: true,
    vendor: null,
    service: 'dev-console-http',
    label: 'Local Web Console / Dev Server HTTP Port (9090/TCP)',
    paths: ['/'],
    risk: 'LOW'
  },
  {
    port: 2375,
    scheme: 'http',
    category: 'pc_workstation',
    vendor: 'Docker',
    service: 'docker-daemon-tcp',
    label: 'Unauthenticated Docker Engine TCP API (2375/TCP)',
    paths: ['/version'],
    risk: 'CRITICAL'
  },
  {
    port: 11434,
    scheme: 'http',
    category: 'pc_workstation',
    vendor: 'Ollama',
    service: 'ollama-api',
    label: 'Ollama Local LLM API Service (11434/TCP)',
    paths: ['/api/tags', '/'],
    risk: 'MEDIUM'
  }
]);

const PORT_MAP = new Map(DEVICE_PORT_CATALOG.map(entry => [entry.port, entry]));
export const PORT_ENTRIES_MAP = new Map(
  DEVICE_PORT_CATALOG.map(entry => [entry.port, [entry]])
);

/**
 * Extracts a XML tag value case-insensitively.
 */
function extractXmlTag(xml, tagName) {
  if (typeof xml !== 'string' || !xml) return null;
  const re = new RegExp(`<${tagName}(?:\\s[^>]*)?>([^<]{1,240})<\\/${tagName}>`, 'i');
  const m = re.exec(xml);
  return m && m[1] ? m[1].trim() : null;
}

/**
 * Probes a single TCP port on `host` and resolves `{ port, open, banner, latencyMs }`.
 */
export function probeSingleTcpPort(host, port, { timeoutMs = 700, bannerTimeoutMs = 80 } = {}) {
  return new Promise(resolve => {
    const start = Date.now();
    let settled = false;
    let connected = false;
    let banner = '';
    let bannerTimer = null;
    let hardTimer = null;

    const socket = new net.Socket();
    const finish = (open, errCode = null) => {
      if (settled) return;
      settled = true;
      if (bannerTimer) {
        clearTimeout(bannerTimer);
        bannerTimer = null;
      }
      if (hardTimer) {
        clearTimeout(hardTimer);
        hardTimer = null;
      }
      try {
        socket.setTimeout(0);
      } catch {}
      try {
        socket.destroy();
      } catch {}
      resolve({
        port,
        open,
        latencyMs: Date.now() - start,
        ...(banner ? { banner: banner.slice(0, 180).replace(/[\r\n\t]+/g, ' ').trim() } : {}),
        ...(errCode ? { error: errCode } : {})
      });
    };

    const effectiveTimeout = Number.isFinite(Number(timeoutMs)) && Number(timeoutMs) > 0
      ? Number(timeoutMs)
      : 700;
    const effectiveBannerMs = Number.isFinite(Number(bannerTimeoutMs)) && Number(bannerTimeoutMs) > 0
      ? Number(bannerTimeoutMs)
      : 80;

    socket.setTimeout(effectiveTimeout);
    hardTimer = setTimeout(() => finish(false, 'ETIMEDOUT'), effectiveTimeout + 50);
    if (typeof hardTimer.unref === 'function') hardTimer.unref();

    socket.on('connect', () => {
      connected = true;
      // Wait briefly in case the service sends a greeting banner (SSH, FTP, Telnet, VNC), then resolve open
      bannerTimer = setTimeout(() => finish(true), effectiveBannerMs);
      if (typeof bannerTimer.unref === 'function') bannerTimer.unref();
    });

    socket.on('data', chunk => {
      try {
        banner += chunk.toString('utf8', 0, 180);
      } catch {}
      if (banner.length > 0) {
        finish(true);
      }
    });

    socket.on('close', hadError => {
      finish(connected && !hadError, hadError ? 'ECONNRESET' : null);
    });

    socket.on('timeout', () => finish(false, 'ETIMEDOUT'));
    socket.on('error', err => {
      const code = err?.code || (Array.isArray(err?.errors) ? err.errors[0]?.code : null) || 'ECONNREFUSED';
      finish(false, code);
    });

    try {
      socket.connect({ host, port });
    } catch (err) {
      finish(false, err?.code || 'ECONNREFUSED');
    }
  });
}

/**
 * Probes multiple device TCP ports in parallel on `host`.
 */
export async function probeDevicePorts(host, options = {}) {
  const requestedCategory = normalizeDeviceCategory(options.deviceCategory);
  let catalogEntries;
  if (Array.isArray(options.ports) && options.ports.length > 0) {
    catalogEntries = options.ports.map(p => (
      typeof p === 'number'
        ? PORT_MAP.get(p) || {
            port: p,
            scheme: p === 443 || p === 8443 || p === 8002 || p === 7443 ? 'https' : 'http',
            category: 'device_web',
            label: `Port ${p}`,
            paths: ['/', '/api/v2/']
          }
        : p
    ));
  } else if (requestedCategory && requestedCategory !== 'all') {
    const filtered = DEVICE_PORT_CATALOG.filter(entry =>
      entry.category === requestedCategory ||
      (Array.isArray(entry.categories) && entry.categories.includes(requestedCategory)) ||
      entry.category === 'device_web'
    );
    const seenPorts = new Set(filtered.map(e => e.port));
    const basePort = Number(options.basePort);
    if (Number.isInteger(basePort) && basePort > 0 && !seenPorts.has(basePort)) {
      const baseEntry = PORT_MAP.get(basePort) || {
        port: basePort,
        scheme: basePort === 443 || basePort === 8443 ? 'https' : 'http',
        category: 'device_web',
        vendor: null,
        service: `port-${basePort}`,
        label: `Target Base Port (${basePort}/TCP)`,
        paths: ['/'],
        risk: 'LOW'
      };
      filtered.push(baseEntry);
      seenPorts.add(basePort);
    }
    catalogEntries = filtered;
  } else {
    catalogEntries = DEVICE_PORT_CATALOG;
  }

  const timeoutMs = Number(options.portTimeoutMs || options.timeoutMs) || 700;
  const rawConcurrency = Number(options.portConcurrency ?? options.concurrency);
  const concurrency = Math.max(1, Math.min(Number.isFinite(rawConcurrency) && rawConcurrency > 0 ? rawConcurrency : 32, 64));
  const limit = pLimit(concurrency);
  const customProbe = typeof options.tcpProbe === 'function'
    ? options.tcpProbe
    : (typeof options.portProbe === 'function' ? options.portProbe : null);

  const probeResults = await Promise.all(
    catalogEntries.map(entry =>
      limit(async () => {
        let res;
        if (customProbe) {
          const raw = await customProbe(host, entry.port, { timeoutMs, entry });
          if (typeof raw === 'boolean') {
            res = { port: entry.port, open: raw };
          } else if (raw && typeof raw === 'object') {
            res = { port: entry.port, open: Boolean(raw.open), banner: raw.banner || '', latencyMs: raw.latencyMs ?? null };
          } else {
            res = { port: entry.port, open: false };
          }
        } else {
          res = await probeSingleTcpPort(host, entry.port, { timeoutMs });
        }

        return {
          ...entry,
          open: Boolean(res?.open),
          banner: res?.banner || null,
          latencyMs: res?.latencyMs ?? null
        };
      })
    )
  );

  const openServices = probeResults.filter(r => r.open);
  const openPorts = openServices.map(r => r.port);
  const closedPorts = probeResults.filter(r => !r.open).map(r => r.port);

  return {
    host,
    openPorts,
    closedPorts,
    openServices,
    allProbed: probeResults
  };
}

/**
 * Non-intrusive TLS handshake & peer certificate metadata probe (for Cast 8009, TV HTTPS, NVR HTTPS).
 */
export async function probeTlsMetadata(host, port, options = {}) {
  const timeoutMs = Number(options.tlsTimeoutMs || options.portTimeoutMs || options.timeoutMs) || 1200;
  if (typeof options.tlsProbe === 'function') {
    try {
      const raw = await options.tlsProbe(host, port, { timeoutMs });
      if (!raw || typeof raw !== 'object') return { ok: false, port };
      const protocol = raw.protocol || null;
      return {
        ok: raw.ok !== false,
        port,
        protocol,
        alpnProtocol: raw.alpnProtocol || null,
        subjectCN: raw.subjectCN || raw.subject?.CN || null,
        issuerCN: raw.issuerCN || raw.issuer?.CN || null,
        san: raw.san || raw.subjectaltname || null,
        selfSigned: Boolean(raw.selfSigned ?? (raw.subjectCN && raw.issuerCN && raw.subjectCN === raw.issuerCN)),
        legacyTls: Boolean(raw.legacyTls || protocol === 'TLSv1' || protocol === 'TLSv1.1')
      };
    } catch (err) {
      return { ok: false, port, error: err?.message || 'tlsProbe failed' };
    }
  }

  return new Promise(resolve => {
    let settled = false;
    let timer = null;
    let socket = null;

    const finish = (payload) => {
      if (settled) return;
      settled = true;
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
      if (socket) {
        try { socket.setTimeout(0); } catch {}
        try { socket.destroy(); } catch {}
      }
      resolve(payload);
    };

    timer = setTimeout(() => finish({ ok: false, port, error: 'ETIMEDOUT' }), timeoutMs + 50);
    if (typeof timer.unref === 'function') timer.unref();

    try {
      socket = tls.connect({
        host,
        port,
        rejectUnauthorized: false,
        ...(options.servername ? { servername: options.servername } : (net.isIP(host) === 0 ? { servername: host } : {}))
      }, () => {
        try {
          const protocol = typeof socket.getProtocol === 'function' ? socket.getProtocol() : null;
          const cert = typeof socket.getPeerCertificate === 'function' ? socket.getPeerCertificate(false) : null;
          const subjectCN = cert?.subject?.CN || null;
          const issuerCN = cert?.issuer?.CN || null;
          const san = cert?.subjectaltname || null;
          finish({
            ok: true,
            port,
            protocol,
            alpnProtocol: socket.alpnProtocol || null,
            subjectCN,
            issuerCN,
            san,
            selfSigned: Boolean(subjectCN && issuerCN && subjectCN === issuerCN),
            legacyTls: protocol === 'TLSv1' || protocol === 'TLSv1.1'
          });
        } catch (err) {
          finish({ ok: false, port, error: err?.message || 'TLS inspection failed' });
        }
      });

      socket.setTimeout(timeoutMs);
      socket.on('timeout', () => finish({ ok: false, port, error: 'ETIMEDOUT' }));
      socket.on('close', hadError => finish({ ok: false, port, error: hadError ? 'ECONNRESET' : 'CLOSED' }));
      socket.on('error', err => finish({ ok: false, port, error: err?.code || err?.message || 'TLS_ERROR' }));
    } catch (err) {
      finish({ ok: false, port, error: err?.code || err?.message || 'TLS_CONNECT_ERROR' });
    }
  });
}

/**
 * Parses a raw RTSP response string into status, headers, and body.
 */
function parseRtspResponse(raw) {
  const text = String(raw || '');
  const sepIdx = text.indexOf('\r\n\r\n');
  const headerBlock = sepIdx >= 0 ? text.slice(0, sepIdx) : text;
  const body = sepIdx >= 0 ? text.slice(sepIdx + 4) : '';
  const lines = headerBlock.split(/\r?\n/);
  const statusLine = lines[0] || '';
  const statusMatch = /^RTSP\/\d+\.\d+\s+(\d{3})/i.exec(statusLine);
  const status = statusMatch ? Number(statusMatch[1]) : null;
  const headers = {};
  for (let i = 1; i < lines.length; i++) {
    const colon = lines[i].indexOf(':');
    if (colon > 0) {
      const key = lines[i].slice(0, colon).trim().toLowerCase();
      const val = lines[i].slice(colon + 1).trim();
      headers[key] = headers[key] ? `${headers[key]}, ${val}` : val;
    }
  }
  return {
    status,
    statusLine: statusLine.trim(),
    headers,
    server: headers.server || null,
    publicMethods: headers.public || null,
    wwwAuth: headers['www-authenticate'] || null,
    body
  };
}

/**
 * Strictly non-intrusive RTSP service probe: sends unauthenticated `OPTIONS` and (if 200 OK) unauthenticated `DESCRIBE`.
 * Never sends credentials or performs authentication brute-forcing.
 */
export async function probeRtspService(host, port = 554, options = {}) {
  const timeoutMs = Number(options.rtspTimeoutMs || options.portTimeoutMs || options.timeoutMs) || 1200;
  if (typeof options.rtspProbe === 'function') {
    try {
      const raw = await options.rtspProbe(host, port, { timeoutMs });
      if (!raw || typeof raw !== 'object') return { ok: false, port };
      const status = Number.isFinite(Number(raw.status)) ? Number(raw.status) : null;
      const describeStatus = Number.isFinite(Number(raw.describeStatus)) ? Number(raw.describeStatus) : null;
      const sdpBody = String(raw.sdp || raw.sdpSnippet || raw.describeBody || '');
      const hasSdp = Boolean(raw.hasSdp || /(?:^|\r?\n)v=0\b|\bm=video\b/i.test(sdpBody));
      return {
        ok: raw.ok !== false,
        port,
        status,
        server: raw.server || null,
        publicMethods: raw.publicMethods || raw.public || null,
        wwwAuth: raw.wwwAuth || raw.wwwAuthenticate || null,
        describeStatus,
        hasSdp,
        sdpSnippet: sdpBody ? sdpBody.slice(0, 240).trim() : null,
        unauthenticatedStream: Boolean(raw.unauthenticatedStream ?? (describeStatus === 200 && hasSdp))
      };
    } catch (err) {
      return { ok: false, port, error: err?.message || 'rtspProbe failed' };
    }
  }

  const hostBracketed = host.includes(':') ? `[${host}]` : host;
  const sendRtspRequest = (reqText) => new Promise(resolve => {
    let settled = false;
    let buf = '';
    let timer = null;
    let bodyTimer = null;
    const socket = new net.Socket();

    const finish = (result) => {
      if (settled) return;
      settled = true;
      if (timer) { clearTimeout(timer); timer = null; }
      if (bodyTimer) { clearTimeout(bodyTimer); bodyTimer = null; }
      try { socket.setTimeout(0); } catch {}
      try { socket.destroy(); } catch {}
      resolve(result);
    };

    timer = setTimeout(() => finish(buf ? { ok: true, raw: buf } : { ok: false, error: 'ETIMEDOUT' }), timeoutMs + 50);
    if (typeof timer.unref === 'function') timer.unref();
    socket.setTimeout(timeoutMs);

    socket.on('connect', () => {
      try { socket.write(reqText); } catch (err) { finish({ ok: false, error: err?.code || 'WRITE_ERR' }); }
    });
    socket.on('data', chunk => {
      buf += chunk.toString('utf8', 0, 4096);
      if (buf.length >= 4096) {
        finish({ ok: true, raw: buf });
        return;
      }
      const sep = buf.indexOf('\r\n\r\n');
      if (sep >= 0 && !bodyTimer) {
        // Wait briefly for any trailing SDP body, then finish
        bodyTimer = setTimeout(() => finish({ ok: true, raw: buf }), 80);
        if (typeof bodyTimer.unref === 'function') bodyTimer.unref();
      }
    });
    socket.on('end', () => finish(buf ? { ok: true, raw: buf } : { ok: false, error: 'EOF' }));
    socket.on('close', () => finish(buf ? { ok: true, raw: buf } : { ok: false, error: 'CLOSED' }));
    socket.on('timeout', () => finish(buf ? { ok: true, raw: buf } : { ok: false, error: 'ETIMEDOUT' }));
    socket.on('error', err => finish({ ok: false, error: err?.code || 'ECONNREFUSED' }));

    try {
      socket.connect({ host, port });
    } catch (err) {
      finish({ ok: false, error: err?.code || 'ECONNREFUSED' });
    }
  });

  const optReq = `OPTIONS rtsp://${hostBracketed}:${port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: SecurityScanner/2.2\r\n\r\n`;
  const optRes = await sendRtspRequest(optReq);
  if (!optRes.ok || !optRes.raw) {
    return { ok: false, port, error: optRes.error || 'RTSP no response' };
  }

  const parsedOpt = parseRtspResponse(optRes.raw);
  if (!parsedOpt.status) {
    return { ok: false, port, error: 'Non-RTSP response' };
  }

  let describeStatus = null;
  let hasSdp = false;
  let sdpSnippet = null;
  let wwwAuth = parsedOpt.wwwAuth;
  let server = parsedOpt.server;

  if (parsedOpt.status === 200 && options.probeDescribe !== false) {
    const descReq = `DESCRIBE rtsp://${hostBracketed}:${port}/ RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\nUser-Agent: SecurityScanner/2.2\r\n\r\n`;
    const descRes = await sendRtspRequest(descReq);
    if (descRes.ok && descRes.raw) {
      const parsedDesc = parseRtspResponse(descRes.raw);
      describeStatus = parsedDesc.status;
      if (!wwwAuth && parsedDesc.wwwAuth) wwwAuth = parsedDesc.wwwAuth;
      if (!server && parsedDesc.server) server = parsedDesc.server;
      if (parsedDesc.body && /(?:^|\r?\n)v=0\b|\bm=video\b|\bm=audio\b/i.test(parsedDesc.body)) {
        hasSdp = true;
        sdpSnippet = parsedDesc.body.slice(0, 240).replace(/\r+/g, '').trim();
      }
    }
  }

  return {
    ok: true,
    port,
    status: parsedOpt.status,
    server,
    publicMethods: parsedOpt.publicMethods,
    wwwAuth,
    describeStatus,
    hasSdp,
    sdpSnippet,
    unauthenticatedStream: Boolean(describeStatus === 200 && hasSdp)
  };
}

/**
 * Non-intrusive unicast mDNS / DNS-SD PTR query on 5353/UDP (`_services._dns-sd._udp.local`).
 */
export async function probeMdnsService(host, options = {}) {
  const timeoutMs = Number(options.mdnsTimeoutMs || options.timeoutMs) || 450;
  if (typeof options.udpProbe === 'function') {
    try {
      const raw = await options.udpProbe(host, 5353, { timeoutMs });
      if (!raw || typeof raw !== 'object') return { ok: false, services: [], deviceNames: [] };
      return {
        ok: raw.ok !== false,
        services: Array.isArray(raw.services) ? raw.services : [],
        deviceNames: Array.isArray(raw.deviceNames) ? raw.deviceNames : [],
        rawBanner: raw.rawBanner || null
      };
    } catch {
      return { ok: false, services: [], deviceNames: [] };
    }
  }

  // Minimal read-only DNS-SD PTR query packet for _services._dns-sd._udp.local
  const queryPacket = Buffer.from([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x09, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73,
    0x07, 0x5f, 0x64, 0x6e, 0x73, 0x2d, 0x73, 0x64,
    0x04, 0x5f, 0x75, 0x64, 0x70,
    0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c,
    0x00,
    0x00, 0x0c, 0x00, 0x01
  ]);

  return new Promise(resolve => {
    let settled = false;
    let timer = null;
    let socket = null;
    const finish = (res) => {
      if (settled) return;
      settled = true;
      if (timer) { clearTimeout(timer); timer = null; }
      if (socket) {
        try { socket.close(); } catch {}
      }
      resolve(res);
    };

    try {
      socket = dgram.createSocket(net.isIPv6(host) ? 'udp6' : 'udp4');
      timer = setTimeout(() => finish({ ok: false, services: [], deviceNames: [] }), timeoutMs);
      if (typeof timer.unref === 'function') timer.unref();

      socket.on('message', msg => {
        const printable = msg.toString('latin1').replace(/[^\x20-\x7e]+/g, ' ').trim();
        const matches = printable.match(/_[a-z0-9-]+(?:\._(?:tcp|udp))?/gi) || [];
        const services = Array.from(new Set(matches.map(s => s.toLowerCase())));
        finish({
          ok: services.length > 0 || printable.length > 0,
          services,
          deviceNames: [],
          rawBanner: printable.slice(0, 180) || null
        });
      });

      socket.on('error', () => finish({ ok: false, services: [], deviceNames: [] }));
      socket.send(queryPacket, 5353, host, err => {
        if (err) finish({ ok: false, services: [], deviceNames: [] });
      });
    } catch {
      finish({ ok: false, services: [], deviceNames: [] });
    }
  });
}

/**
 * Extracts a safe realm/vendor string from a WWW-Authenticate header.
 */
function extractAuthRealm(wwwAuth) {
  if (!wwwAuth) return null;
  const m = /realm="([^"]{1,120})"/i.exec(String(wwwAuth));
  return m && m[1] ? m[1].trim() : null;
}

const DEV_SERVER_PORTS = new Set([3000, 3001, 4200, 5000, 5173, 8000, 8080, 8081, 8888, 9000, 9090]);

const ONVIF_TIME_SOAP_BODY =
  '<?xml version="1.0" encoding="utf-8"?>' +
  '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl">' +
  '<s:Body><tds:GetSystemDateAndTime/></s:Body></s:Envelope>';

const SONY_SYS_INFO_BODY = JSON.stringify({
  method: 'getSystemInformation',
  id: 1,
  params: [],
  version: '1.0'
});

/**
 * Analyzes an HTTP response from a device endpoint and returns any device identity metadata and security findings.
 */
export function analyzeDeviceHttpResponse({ url, port, path: reqPath, res, openPorts = [] }) {
  if (!res || typeof res !== 'object') return null;
  const status = Number(res.status);
  const text = typeof res.text === 'string' ? res.text : '';
  const serverHdr = getHeader(res.headers, 'server');
  const poweredHdr = getHeader(res.headers, 'x-powered-by');
  const contentType = getHeader(res.headers, 'content-type').toLowerCase();
  const wwwAuth = getHeader(res.headers, 'www-authenticate');
  const appUrlHdr = getHeader(res.headers, 'application-url');
  const xAuthPsk = getHeader(res.headers, 'x-auth-psk');
  const upgradeHdr = getHeader(res.headers, 'upgrade');

  const findings = [];
  let deviceMeta = null;

  // ── 1. Samsung Smart TV (Tizen) SmartView REST API (/api/v2/) ──────────────
  if (status === 200 && (reqPath === '/api/v2/' || reqPath === '/api/v2' || text.includes('"Samsung SmartTV"') || text.includes('"FrameTVSupport"') || text.includes('"tokenAuthSupport"'))) {
    const json = parseJsonObject(text);
    const dev = json && !Array.isArray(json) ? (json.device || json) : null;
    if (
      dev &&
      typeof dev === 'object' &&
      (dev.type === 'Samsung SmartTV' ||
        dev.OS === 'Tizen' ||
        dev.tokenAuthSupport !== undefined ||
        dev.FrameTVSupport !== undefined ||
        /samsung/i.test(String(dev.modelName || dev.name || '')))
    ) {
      const modelName = dev.modelName || 'Samsung Smart TV';
      const friendlyName = dev.name || json.name || modelName;
      const os = dev.OS || 'Tizen';
      const wifiMac = dev.wifiMac || null;
      const deviceId = dev.id || json.id || dev.duid || null;
      const firmwareVersion = dev.firmwareVersion || json.version || null;
      const tokenAuth = String(dev.tokenAuthSupport ?? '').toLowerCase();
      const tokenAuthDisabled = tokenAuth === 'false' || dev.tokenAuthSupport === false;
      const networkType = dev.networkType || null;
      const resolution = dev.resolution || null;
      const countryCode = dev.countryCode || null;

      deviceMeta = {
        category: 'smart_tv',
        vendor: 'Samsung',
        deviceType: 'Samsung Smart TV (Tizen)',
        deviceName: friendlyName,
        modelName,
        os,
        firmwareVersion,
        macAddress: wifiMac,
        udn: deviceId,
        networkType,
        resolution,
        countryCode,
        tokenAuthSupport: dev.tokenAuthSupport
      };

      const quote =
        extractVerbatimSnippet(text, /"modelName"\s*:\s*"[^"]+"|"type"\s*:\s*"Samsung SmartTV"|"wifiMac"\s*:\s*"[^"]+"|"OS"\s*:\s*"Tizen"/) ||
        text.slice(0, 120).trim();

      const schemeLabel = url.startsWith('https://') ? 'HTTPS' : 'HTTP';
      findings.push({
        name: `Samsung Smart TV (Tizen) SmartView ${schemeLabel} API & Hardware Metadata Exposure`,
        path: reqPath,
        url,
        port,
        method: 'GET',
        status: 200,
        severity: tokenAuthDisabled ? 'HIGH' : 'MEDIUM',
        statusTag: 'VULNERABLE',
        matchedSignal: `Samsung Tizen SmartView API (${modelName}, OS: ${os}${wifiMac ? `, MAC: ${wifiMac}` : ''})`,
        preview: quote,
        evidenceQuote: quote,
        ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
        reason: `Unauthenticated Samsung SmartView API on port ${port} (${url}) discloses hardware & network metadata: model="${modelName}", name="${friendlyName}", OS="${os}"${wifiMac ? `, wifiMac="${wifiMac}"` : ''}${deviceId ? `, id="${deviceId}"` : ''}, tokenAuthSupport=${String(dev.tokenAuthSupport)}.`
      });

      if (tokenAuthDisabled) {
        findings.push({
          name: 'Samsung Smart TV Remote Control Token Authentication Disabled',
          path: reqPath,
          url,
          port,
          method: 'GET',
          status: 200,
          severity: 'HIGH',
          statusTag: 'VULNERABLE',
          matchedSignal: '"tokenAuthSupport": "false"',
          preview: quote,
          evidenceQuote: quote,
          ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
          reason: `Samsung Smart TV reports tokenAuthSupport="false" on ${url}, allowing unauthenticated LAN clients to connect to the WebSocket remote control channel (/api/v2/channels/samsung.remote.control) without pairing token enforcement.`
        });
      }

      if (port === 8001 || url.startsWith('http://')) {
        findings.push({
          name: 'Samsung Smart TV Cleartext HTTP SmartView Control Port (8001/TCP)',
          path: reqPath,
          url,
          port,
          method: 'GET',
          status: 200,
          severity: 'MEDIUM',
          statusTag: 'SUSPICIOUS',
          matchedSignal: `Cleartext HTTP SmartView API on port ${port}`,
          preview: quote,
          evidenceQuote: quote,
          ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
          reason: `Port ${port} serves the Samsung SmartView REST and WebSocket control interface over unencrypted HTTP/WS, allowing local network interception of TV metadata and app launch commands.`
        });
      }

      return { deviceMeta, findings };
    }
  }

  // ── 2. Google Cast / Android TV / Chromecast Eureka Info (/setup/eureka_info) ──
  if (status === 200 && (reqPath.includes('eureka_info') || text.includes('"cast_build_revision"') || text.includes('"ssdp_udn"') || text.includes('"hotspot_bssid"'))) {
    const json = parseJsonObject(text);
    if (
      json &&
      !Array.isArray(json) &&
      (json.ssdp_udn || json.cast_build_revision || json.build_info || json.hotspot_bssid || json.mac_address || json.uma_client_id)
    ) {
      const friendlyName = json.name || 'Google Cast / Android TV';
      const castBuild = json.build_info?.cast_build_revision || json.cast_build_revision || json.version || null;
      const mac = json.mac_address || null;
      const ssid = json.ssid || null;
      const bssid = json.hotspot_bssid || null;

      deviceMeta = {
        category: 'smart_tv',
        vendor: 'Google / Android TV',
        deviceType: 'Google TV / Android TV / Chromecast',
        deviceName: friendlyName,
        modelName: json.model_name || 'Google Cast Receiver',
        os: 'Android TV / Cast OS',
        firmwareVersion: castBuild ? String(castBuild) : null,
        macAddress: mac,
        ssid,
        udn: json.ssdp_udn || null
      };

      const quote =
        extractVerbatimSnippet(text, /"ssdp_udn"\s*:\s*"[^"]+"|"mac_address"\s*:\s*"[^"]+"|"hotspot_bssid"\s*:\s*"[^"]+"|"cast_build_revision"\s*:\s*"[^"]+"/) ||
        text.slice(0, 120).trim();

      findings.push({
        name: 'Google Cast / Android TV Unauthenticated Eureka Info Disclosure',
        path: reqPath,
        url,
        port,
        method: 'GET',
        status: 200,
        severity: 'MEDIUM',
        statusTag: 'VULNERABLE',
        matchedSignal: `Google Cast eureka_info (${friendlyName}${mac ? `, MAC: ${mac}` : ''}${ssid ? `, SSID: ${ssid}` : ''})`,
        preview: quote,
        evidenceQuote: quote,
        ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
        reason: `Unauthenticated Google Cast /setup/eureka_info endpoint on port ${port} leaks device name ("${friendlyName}")${mac ? `, MAC address (${mac})` : ''}${ssid ? `, Wi-Fi SSID ("${ssid}")` : ''}${bssid ? `, router BSSID (${bssid})` : ''}, and firmware build details.`
      });

      return { deviceMeta, findings };
    }
  }

  // ── 3. Roku TV / Roku Streaming Device External Control Protocol (ECP :8060) ──
  if (
    status === 200 &&
    !isHtmlOrScript(res, text) &&
    (text.includes('<device-info>') ||
      (text.includes('<apps>') && text.includes('<app id=')) ||
      (text.includes('<active-app>') && text.includes('<app')))
  ) {
    const vendorName = extractXmlTag(text, 'vendor-name') || 'Roku';
    const modelName = extractXmlTag(text, 'model-name') || 'Roku TV';
    const friendlyName = extractXmlTag(text, 'user-device-name') || extractXmlTag(text, 'friendly-device-name') || `${vendorName} ${modelName}`;
    const serialNumber = extractXmlTag(text, 'serial-number');
    const wifiMac = extractXmlTag(text, 'wifi-mac');
    const ssid = extractXmlTag(text, 'network-name');
    const softwareVersion = extractXmlTag(text, 'software-version');
    const devEnabled = extractXmlTag(text, 'developer-enabled');

    deviceMeta = {
      category: 'smart_tv',
      vendor: vendorName,
      deviceType: 'Roku TV / Roku Streaming Device',
      deviceName: friendlyName,
      modelName,
      os: 'Roku OS',
      firmwareVersion: softwareVersion,
      serialNumber,
      macAddress: wifiMac,
      ssid
    };

    const quote =
      extractVerbatimSnippet(text, /<(?:model-name|serial-number|wifi-mac|vendor-name|app\s+id=)[^>]*>[^<]+/) ||
      text.slice(0, 120).trim();

    if (text.includes('<device-info>')) {
      findings.push({
        name: 'Roku TV Unauthenticated External Control Protocol (ECP) & Device Info Exposure',
        path: reqPath,
        url,
        port,
        method: 'GET',
        status: 200,
        severity: 'HIGH',
        statusTag: 'VULNERABLE',
        matchedSignal: `Roku ECP /query/device-info (${modelName}${serialNumber ? `, SN: ${serialNumber}` : ''})`,
        preview: quote,
        evidenceQuote: quote,
        ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
        reason: `Unauthenticated Roku External Control Protocol (ECP) on port ${port} exposes hardware serial number${serialNumber ? ` (${serialNumber})` : ''}, Wi-Fi MAC${wifiMac ? ` (${wifiMac})` : ''}, Wi-Fi SSID${ssid ? ` ("${ssid}")` : ''}, and allows unauthenticated remote control keystrokes (/keypress/*) and app launching.`
      });

      if (String(devEnabled).toLowerCase() === 'true') {
        findings.push({
          name: 'Roku TV Developer Mode Enabled',
          path: reqPath,
          url,
          port,
          method: 'GET',
          status: 200,
          severity: 'MEDIUM',
          statusTag: 'SUSPICIOUS',
          matchedSignal: '<developer-enabled>true</developer-enabled>',
          preview: '<developer-enabled>true</developer-enabled>',
          evidenceQuote: '<developer-enabled>true</developer-enabled>',
          ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
          reason: 'Roku Developer Mode is enabled (<developer-enabled>true</developer-enabled>), allowing channel sideloading over the local network.'
        });
      }
    } else {
      findings.push({
        name: 'Roku TV Installed Channels & Active Viewing Activity Disclosure',
        path: reqPath,
        url,
        port,
        method: 'GET',
        status: 200,
        severity: 'MEDIUM',
        statusTag: 'VULNERABLE',
        matchedSignal: `Roku ECP ${reqPath} enumeration`,
        preview: quote,
        evidenceQuote: quote,
        ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
        reason: `Roku ECP endpoint ${url} allows unauthenticated enumeration of installed streaming applications and real-time active viewing state.`
      });
    }

    return { deviceMeta, findings };
  }

  // ── 4. UPnP / DLNA / SSDP / DIAL Device Description & Application-URL ───────
  if (
    status === 200 &&
    !isHtmlOrScript(res, text) &&
    (text.includes('urn:schemas-upnp-org:device:') ||
      text.includes('urn:schemas-upnp-org:service:') ||
      text.includes('urn:samsung.com:device:') ||
      text.includes('urn:dial-multiscreen-org:') ||
      (text.includes('<root') && text.includes('<device>') && text.includes('<friendlyName>')))
  ) {
    const friendlyName = extractXmlTag(text, 'friendlyName') || 'UPnP / DLNA Device';
    const manufacturer = extractXmlTag(text, 'manufacturer') || 'Unknown Vendor';
    const modelName = extractXmlTag(text, 'modelName') || friendlyName;
    const serialNumber = extractXmlTag(text, 'serialNumber');
    const udn = extractXmlTag(text, 'UDN');
    const deviceTypeXml = extractXmlTag(text, 'deviceType') || '';

    const isRouterIgd = /WANIPConnection|WANPPPConnection|InternetGatewayDevice/i.test(text);
    const isDial = text.includes('urn:dial-multiscreen-org:') || Boolean(appUrlHdr);
    const isMediaRenderer = /MediaRenderer|AVTransport|RenderingControl|samsung\.com:device|bravia|sonos/i.test(text);
    const isTv = isDial || /tv|tizen|webos|bravia|roku|vizio|samsung|lg electronics|sony/i.test(`${friendlyName} ${manufacturer} ${modelName} ${deviceTypeXml}`);
    const isSonos = /sonos/i.test(`${manufacturer} ${modelName} ${friendlyName}`);

    deviceMeta = {
      category: isRouterIgd ? 'router_gateway' : isSonos ? 'smart_home_iot' : isTv ? 'smart_tv' : 'upnp_dlna',
      vendor: manufacturer,
      deviceType: isRouterIgd
        ? 'UPnP Internet Gateway Router'
        : isTv
          ? `${manufacturer} Smart TV (${isDial ? 'DIAL/UPnP' : 'DLNA/UPnP'})`
          : 'UPnP / DLNA Media Device',
      deviceName: friendlyName,
      modelName,
      serialNumber,
      udn
    };

    const quote =
      extractVerbatimSnippet(text, /<(?:friendlyName|modelName|manufacturer|deviceType|serviceType)>[^<]+<\/(?:friendlyName|modelName|manufacturer|deviceType|serviceType)>/) ||
      (appUrlHdr ? `Application-URL: ${appUrlHdr}` : text.slice(0, 120).trim());

    if (isRouterIgd) {
      findings.push({
        name: 'UPnP IGD Router WAN Port-Forwarding Control Surface Exposed',
        path: reqPath,
        url,
        port,
        method: 'GET',
        status: 200,
        severity: 'HIGH',
        statusTag: 'VULNERABLE',
        matchedSignal: `UPnP InternetGatewayDevice / WANIPConnection (${friendlyName})`,
        preview: quote,
        evidenceQuote: quote,
        ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
        reason: `Router UPnP Internet Gateway Device (IGD) descriptor at ${url} exposes WANIPConnection/WANPPPConnection SOAP services, allowing LAN devices or malware to open external firewall port forwards.`
      });
    } else if (isDial && !isMediaRenderer) {
      findings.push({
        name: `DIAL Multi-Screen App Launch & Discovery Service Exposed (${port}/TCP)`,
        path: reqPath,
        url,
        port,
        method: 'GET',
        status: 200,
        severity: 'MEDIUM',
        statusTag: 'VULNERABLE',
        matchedSignal: `DIAL service (${friendlyName}${appUrlHdr ? `, Application-URL: ${appUrlHdr}` : ''})`,
        preview: quote,
        evidenceQuote: quote,
        ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
        reason: `Smart TV DIAL service at ${url} exposes device metadata ("${friendlyName}", "${manufacturer}")${appUrlHdr ? ` and Application-URL (${appUrlHdr})` : ''}, permitting unauthenticated LAN app status queries and launches.`
      });
    } else if (isMediaRenderer) {
      findings.push({
        name: 'UPnP / DLNA MediaRenderer Unauthenticated Control & Metadata Exposure',
        path: reqPath,
        url,
        port,
        method: 'GET',
        status: 200,
        severity: 'MEDIUM',
        statusTag: 'VULNERABLE',
        matchedSignal: `UPnP MediaRenderer (${friendlyName}, ${manufacturer}, ${modelName})`,
        preview: quote,
        evidenceQuote: quote,
        ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
        reason: `UPnP/DLNA descriptor on port ${port} (${url}) exposes device metadata (friendlyName="${friendlyName}", manufacturer="${manufacturer}", model="${modelName}"${serialNumber ? `, serial="${serialNumber}"` : ''}) and unauthenticated SOAP media control services (AVTransport / RenderingControl).`
      });
    } else {
      findings.push({
        name: 'UPnP / SSDP Device Description XML Metadata Exposure',
        path: reqPath,
        url,
        port,
        method: 'GET',
        status: 200,
        severity: 'MEDIUM',
        statusTag: 'VULNERABLE',
        matchedSignal: `UPnP descriptor (${friendlyName}, ${manufacturer})`,
        preview: quote,
        evidenceQuote: quote,
        ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
        reason: `Unauthenticated UPnP device descriptor at ${url} discloses hardware manufacturer ("${manufacturer}"), model ("${modelName}"), friendly name ("${friendlyName}"), and UDN.`
      });
    }

    return { deviceMeta, findings };
  }

  // DIAL Application-URL header or /apps XML on Smart TV ports
  if ((appUrlHdr && /\/apps/i.test(appUrlHdr)) || (status === 200 && (reqPath === '/apps' || reqPath === '/ws/apps/') && /urn:dial-multiscreen-org|<service\b/i.test(text))) {
    const appName = extractXmlTag(text, 'name');
    deviceMeta = {
      category: 'smart_tv',
      vendor: 'DIAL / Smart TV',
      deviceType: 'DIAL-Enabled Smart TV / Streaming Device',
      deviceName: appName ? `DIAL Receiver (${appName})` : 'DIAL Smart TV',
      modelName: 'DIAL Multi-Screen Receiver'
    };
    const quote = appUrlHdr ? `Application-URL: ${appUrlHdr}` : text.slice(0, 120).trim();
    findings.push({
      name: `DIAL Multi-Screen App Control Endpoint Exposed (${port}/TCP)`,
      path: reqPath,
      url,
      port,
      method: 'GET',
      status: status || 200,
      severity: 'MEDIUM',
      statusTag: status === 200 ? 'VULNERABLE' : 'SUSPICIOUS',
      matchedSignal: `DIAL Application-URL (${appUrlHdr || reqPath})`,
      preview: quote,
      evidenceQuote: quote,
      ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
      reason: `DIAL endpoint at ${url} advertises remote application control${appUrlHdr ? ` via Application-URL: ${appUrlHdr}` : ''} without authentication.`
    });
    return { deviceMeta, findings };
  }

  // ── 5. Apple AirPlay / AirTunes Receiver (/info, /server-info on :7000 / :5000 / :7100) ──
  if (
    status === 200 &&
    (reqPath === '/info' || reqPath === '/server-info') &&
    (/airtunes|airplay/i.test(serverHdr) ||
      text.startsWith('bplist00') ||
      contentType.includes('x-apple-binary-plist') ||
      (text.includes('deviceid') && (text.includes('srcvers') || text.includes('features') || text.includes('model'))))
  ) {
    const isBinaryPlist = text.startsWith('bplist00') || contentType.includes('x-apple-binary-plist');
    const modelMatch = text.match(/<key>model<\/key>\s*<string>([^<]+)<\/string>/i) || text.match(/"model"\s*:\s*"([^"]+)"/i);
    const macMatch = text.match(/<key>deviceid<\/key>\s*<string>([^<]+)<\/string>/i) || text.match(/"deviceid"\s*:\s*"([^"]+)"/i);
    const verMatch = text.match(/<key>srcvers<\/key>\s*<string>([^<]+)<\/string>/i) || text.match(/"srcvers"\s*:\s*"([^"]+)"/i);
    const modelName = modelMatch ? modelMatch[1].trim() : 'AirPlay Receiver';
    const macAddress = macMatch ? macMatch[1].trim() : null;
    const firmwareVersion = verMatch ? verMatch[1].trim() : (serverHdr || null);

    deviceMeta = {
      category: 'smart_tv',
      vendor: 'Apple / AirPlay',
      deviceType: 'AirPlay / AirTunes Media Receiver',
      deviceName: modelName,
      modelName,
      firmwareVersion,
      macAddress
    };

    const quote =
      extractVerbatimSnippet(text, /deviceid|srcvers|<string>[^<]+<\/string>/) ||
      (serverHdr.length >= 8 ? `Server: ${serverHdr}` : (isBinaryPlist ? 'bplist00 binary plist AirPlay /info metadata' : 'AirPlay /info metadata'));

    findings.push({
      name: 'Apple AirPlay / AirTunes Receiver Metadata Exposure',
      path: reqPath,
      url,
      port,
      method: 'GET',
      status: 200,
      severity: 'MEDIUM',
      statusTag: 'VULNERABLE',
      matchedSignal: `AirPlay receiver (${modelName}${macAddress ? `, deviceid: ${macAddress}` : ''})`,
      preview: quote,
      evidenceQuote: quote,
      ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
      reason: `Unauthenticated AirPlay endpoint ${url} exposes hardware deviceid/MAC${macAddress ? ` (${macAddress})` : ''}, model ("${modelName}"), and AirTunes version${firmwareVersion ? ` (${firmwareVersion})` : ''}.`
    });

    return { deviceMeta, findings };
  }

  // ── 6. Philips JointSpace Smart TV API (/1/system, /6/system on :1925 / :1926) ──
  if (reqPath === '/1/system' || reqPath === '/6/system') {
    if (status === 200) {
      const json = parseJsonObject(text);
      if (json && !Array.isArray(json) && (json.menulanguage || json.serialnumber || json.softwareversion || json.model)) {
        deviceMeta = {
          category: 'smart_tv',
          vendor: 'Philips',
          deviceType: 'Philips Smart TV (JointSpace)',
          deviceName: json.name || 'Philips Smart TV',
          modelName: json.model || 'Philips TV',
          firmwareVersion: json.softwareversion || null,
          serialNumber: json.serialnumber || null
        };

        const quote =
          extractVerbatimSnippet(text, /"serialnumber"\s*:\s*"[^"]+"|"softwareversion"\s*:\s*"[^"]+"|"model"\s*:\s*"[^"]+"/) ||
          text.slice(0, 120).trim();

        findings.push({
          name: 'Philips JointSpace Smart TV Unauthenticated System API Exposure',
          path: reqPath,
          url,
          port,
          method: 'GET',
          status: 200,
          severity: 'MEDIUM',
          statusTag: 'VULNERABLE',
          matchedSignal: `Philips JointSpace ${reqPath} (${deviceMeta.modelName})`,
          preview: quote,
          evidenceQuote: quote,
          ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
          reason: `Philips JointSpace API at ${url} leaks TV model, software version, and serial number without authentication.`
        });

        return { deviceMeta, findings };
      }
    } else if (status === 401 && (port === 1925 || port === 1926 || /philips|jointspace/i.test(`${wwwAuth} ${serverHdr}`))) {
      deviceMeta = {
        category: 'smart_tv',
        vendor: 'Philips',
        deviceType: 'Philips Smart TV (JointSpace)',
        deviceName: 'Philips Smart TV',
        modelName: 'Philips JointSpace TV'
      };
      const quote = wwwAuth ? `WWW-Authenticate: ${wwwAuth}` : `HTTP 401 on Philips JointSpace ${reqPath} (${port}/TCP)`;
      findings.push({
        name: `Philips JointSpace Smart TV Control Port Exposed (${port}/TCP)`,
        path: reqPath,
        url,
        port,
        method: 'GET',
        status: 401,
        severity: 'LOW',
        statusTag: 'SUSPICIOUS',
        matchedSignal: `Philips JointSpace auth challenge on port ${port}`,
        preview: quote,
        evidenceQuote: quote,
        ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
        reason: `Philips JointSpace API endpoint ${url} is active on port ${port} (Digest authentication enabled).`
      });
      return { deviceMeta, findings };
    }
  }

  // ── 7. LG webOS Smart TV SSAP Service (:3000 / :3001 / :9998) ──────────────
  const hasExplicitLgWebOsSignal = /webos|lg\s*electronics|lg\s*tv|ssap|webostv/i.test(`${serverHdr} ${text}`);
  const hasCompanion9998 = Array.isArray(openPorts) && openPorts.includes(9998);
  const isLgWebOsConfirmed =
    hasExplicitLgWebOsSignal ||
    (status === 426 && /websocket/i.test(`${upgradeHdr} ${text}`) && (hasCompanion9998 || hasExplicitLgWebOsSignal)) ||
    ((port === 3000 || port === 3001) && /^\s*hello\s*$/i.test(text) && (hasCompanion9998 || /webos|lg\s*electronics|lg\s*tv|ssap|webostv/i.test(serverHdr))) ||
    (port === 9998 && !isHtmlOrScript(res, text));

  if (
    (port === 3000 || port === 3001 || port === 9998) &&
    (status === 200 || status === 400 || status === 404 || status === 426) &&
    isLgWebOsConfirmed
  ) {
    deviceMeta = {
      category: 'smart_tv',
      vendor: 'LG',
      deviceType: 'LG webOS Smart TV',
      deviceName: 'LG webOS Smart TV',
      modelName: 'LG webOS TV',
      os: 'webOS'
    };

    const quote = serverHdr.length >= 8
      ? `Server: ${serverHdr}`
      : (text.trim().length >= 8 ? text.trim().slice(0, 100) : `LG webOS SSAP HTTP ${status} on port ${port}`);

    findings.push({
      name: port === 9998
        ? 'LG webOS Smart TV Developer Mode / Debug Port Exposed (9998/TCP)'
        : `LG webOS Smart TV SSAP Control Service Exposed (${port}/TCP)`,
      path: reqPath,
      url,
      port,
      method: 'GET',
      status,
      severity: port === 9998 ? 'HIGH' : 'MEDIUM',
      statusTag: port === 9998 ? 'VULNERABLE' : 'SUSPICIOUS',
      matchedSignal: `LG webOS service on port ${port} (HTTP ${status})`,
      preview: quote,
      evidenceQuote: quote,
      ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
      reason: port === 9998
        ? `LG webOS Developer Mode debug port ${port} is open at ${url} (HTTP ${status}), permitting remote app inspection and debugging.`
        : `LG webOS SSAP WebSocket/HTTP control service is accessible at ${url} (HTTP ${status}), allowing LAN clients to initiate pairing prompts and control sessions.`
    });

    return { deviceMeta, findings };
  }

  // ── 7b. Sony Bravia Smart TV (/sony/system) ────────────────────────────────
  if (reqPath === '/sony/system') {
    const json = parseJsonObject(text);
    const sysInfo = json && Array.isArray(json.result) ? json.result[0] : null;
    if (status === 200 && sysInfo && typeof sysInfo === 'object' && (sysInfo.product || sysInfo.model || sysInfo.macAddr || sysInfo.serial)) {
      const modelName = sysInfo.model || sysInfo.product || 'Sony Bravia TV';
      const friendlyName = sysInfo.name || modelName;
      deviceMeta = {
        category: 'smart_tv',
        vendor: 'Sony',
        deviceType: 'Sony Bravia Smart TV',
        deviceName: friendlyName,
        modelName,
        os: 'Sony Bravia / Android TV',
        firmwareVersion: sysInfo.generation || null,
        macAddress: sysInfo.macAddr || null,
        serialNumber: sysInfo.serial || null
      };
      const quote = extractVerbatimSnippet(text, /"model"\s*:\s*"[^"]+"|"macAddr"\s*:\s*"[^"]+"|"serial"\s*:\s*"[^"]+"/) || text.slice(0, 120).trim();
      findings.push({
        name: `Sony Bravia Smart TV Unauthenticated System API Exposure (${port}/TCP)`,
        path: reqPath,
        url,
        port,
        method: 'POST',
        status: 200,
        severity: 'MEDIUM',
        statusTag: 'VULNERABLE',
        matchedSignal: `Sony Bravia /sony/system (${modelName})`,
        preview: quote,
        evidenceQuote: quote,
        ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
        reason: `Sony Bravia ScalarWebAPI at ${url} discloses TV model ("${modelName}")${sysInfo.macAddr ? `, MAC (${sysInfo.macAddr})` : ''}${sysInfo.serial ? `, and serial (${sysInfo.serial})` : ''} without authentication.`
      });
      return { deviceMeta, findings };
    }
    if ((status === 401 || status === 403) && (xAuthPsk || /x-auth-psk|bravia|sony/i.test(`${wwwAuth} ${text} ${serverHdr}`) || (json && Array.isArray(json.error)))) {
      deviceMeta = {
        category: 'smart_tv',
        vendor: 'Sony',
        deviceType: 'Sony Bravia Smart TV',
        deviceName: 'Sony Bravia Smart TV',
        modelName: 'Sony Bravia TV'
      };
      const quote = xAuthPsk ? `X-Auth-PSK: ${xAuthPsk}` : (text.slice(0, 120).trim() || `Sony Bravia /sony/system HTTP ${status}`);
      findings.push({
        name: `Sony Bravia Smart TV Control API Exposed (${port}/TCP)`,
        path: reqPath,
        url,
        port,
        method: 'POST',
        status,
        severity: 'LOW',
        statusTag: 'SUSPICIOUS',
        matchedSignal: `Sony Bravia /sony/system auth response (HTTP ${status})`,
        preview: quote,
        evidenceQuote: quote,
        ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
        reason: `Sony Bravia control endpoint ${url} is reachable on the local network (HTTP ${status}, PSK authentication enforced).`
      });
      return { deviceMeta, findings };
    }
  }

  // ── 7c. Vizio SmartCast TV (/state/device/power_mode) ──────────────────────
  if (reqPath === '/state/device/power_mode') {
    const json = parseJsonObject(text);
    const statusRes = json?.STATUS?.RESULT;
    if (status === 200 && json && (statusRes === 'SUCCESS' || Array.isArray(json.ITEMS))) {
      deviceMeta = {
        category: 'smart_tv',
        vendor: 'Vizio',
        deviceType: 'Vizio SmartCast TV',
        deviceName: 'Vizio SmartCast TV',
        modelName: 'Vizio SmartCast TV',
        os: 'SmartCast'
      };
      const quote = extractVerbatimSnippet(text, /"RESULT"\s*:\s*"SUCCESS"|"ITEMS"\s*:/) || text.slice(0, 120).trim();
      findings.push({
        name: `Vizio SmartCast TV Unauthenticated State API Exposure (${port}/TCP)`,
        path: reqPath,
        url,
        port,
        method: 'GET',
        status: 200,
        severity: 'MEDIUM',
        statusTag: 'VULNERABLE',
        matchedSignal: `Vizio SmartCast ${reqPath} (RESULT=${statusRes || 'OK'})`,
        preview: quote,
        evidenceQuote: quote,
        ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
        reason: `Vizio SmartCast API at ${url} returns TV device power state without authentication.`
      });
      return { deviceMeta, findings };
    }
    if ((status === 401 || status === 403) && (statusRes || /vizio|smartcast/i.test(`${text} ${serverHdr}`))) {
      deviceMeta = {
        category: 'smart_tv',
        vendor: 'Vizio',
        deviceType: 'Vizio SmartCast TV',
        deviceName: 'Vizio SmartCast TV',
        modelName: 'Vizio SmartCast TV',
        os: 'SmartCast'
      };
      const quote = text.slice(0, 120).trim() || `Vizio SmartCast HTTP ${status}`;
      findings.push({
        name: `Vizio SmartCast TV Control Port Exposed (${port}/TCP)`,
        path: reqPath,
        url,
        port,
        method: 'GET',
        status,
        severity: 'LOW',
        statusTag: 'SUSPICIOUS',
        matchedSignal: `Vizio SmartCast endpoint on port ${port} (HTTP ${status})`,
        preview: quote,
        evidenceQuote: quote,
        ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
        reason: `Vizio SmartCast control interface at ${url} is reachable on port ${port} (pairing auth required).`
      });
      return { deviceMeta, findings };
    }
  }

  // ── 8. Tasmota / Shelly Smart Home IoT Relay (/cm?cmnd=Status%200, /shelly) ──
  if (status === 200 && (reqPath.startsWith('/cm') || reqPath === '/shelly')) {
    const json = parseJsonObject(text);
    if (json && !Array.isArray(json)) {
      if (json.Status || json.StatusPRM || json.StatusNET || json.StatusFWR) {
        const devName = json.Status?.FriendlyName?.[0] || json.Status?.DeviceName || 'Tasmota IoT Device';
        const mac = json.StatusNET?.Mac || null;
        const fw = json.StatusFWR?.Version || null;
        deviceMeta = {
          category: 'smart_home_iot',
          vendor: 'Tasmota',
          deviceType: 'Tasmota Smart Plug / Relay',
          deviceName: devName,
          modelName: 'Tasmota ESP Device',
          firmwareVersion: fw,
          macAddress: mac
        };
        const quote = extractVerbatimSnippet(text, /"StatusNET"|"StatusFWR"|"FriendlyName"/) || text.slice(0, 120).trim();
        findings.push({
          name: 'Unauthenticated Tasmota IoT Control & Status API Exposure',
          path: reqPath,
          url,
          port,
          method: 'GET',
          status: 200,
          severity: 'CRITICAL',
          statusTag: 'VULNERABLE',
          matchedSignal: `Tasmota unauthenticated /cm command API (${devName})`,
          preview: quote,
          evidenceQuote: quote,
          ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
          reason: `Tasmota IoT device at ${url} executes unauthenticated /cm commands, allowing anyone on the network to toggle physical power relays, read network configuration, or flash firmware.`
        });
        return { deviceMeta, findings };
      }

      if (reqPath === '/shelly' && (json.mac || json.fw_id || json.type || json.gen)) {
        const model = json.type || json.app || 'Shelly Relay';
        deviceMeta = {
          category: 'smart_home_iot',
          vendor: 'Shelly',
          deviceType: 'Shelly Smart Home Relay',
          deviceName: json.name || model,
          modelName: model,
          firmwareVersion: json.fw_id || json.ver || null,
          macAddress: json.mac || null
        };
        const quote = extractVerbatimSnippet(text, /"mac"\s*:\s*"[^"]+"|"fw_id"\s*:\s*"[^"]+"|"type"\s*:\s*"[^"]+"/) || text.slice(0, 120).trim();
        findings.push({
          name: 'Shelly Smart Home IoT Device Info Exposure',
          path: reqPath,
          url,
          port,
          method: 'GET',
          status: 200,
          severity: json.auth === false ? 'HIGH' : 'LOW',
          statusTag: json.auth === false ? 'VULNERABLE' : 'SUSPICIOUS',
          matchedSignal: `Shelly /shelly descriptor (${model}, auth=${String(json.auth)})`,
          preview: quote,
          evidenceQuote: quote,
          ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
          reason: `Shelly IoT endpoint ${url} exposes hardware MAC (${json.mac || 'unknown'}), firmware (${json.fw_id || 'unknown'}), and authentication state (auth=${String(json.auth)}).`
        });
        return { deviceMeta, findings };
      }
    }
  }

  // ── 9. Plex (/identity :32400) & Jellyfin/Emby (/System/Info/Public :8096) ──
  if (status === 200 && reqPath === '/identity' && text.includes('machineIdentifier')) {
    const ver = (text.match(/version="([^"]+)"/i) || [])[1] || null;
    const machineId = (text.match(/machineIdentifier="([^"]+)"/i) || [])[1] || null;
    deviceMeta = {
      category: 'nas_media_server',
      vendor: 'Plex',
      deviceType: 'Plex Media Server',
      deviceName: 'Plex Media Server',
      modelName: 'Plex Media Server',
      firmwareVersion: ver,
      udn: machineId
    };
    const quote = extractVerbatimSnippet(text, /machineIdentifier="[^"]+"/) || text.slice(0, 120).trim();
    findings.push({
      name: 'Plex Media Server Identity & Version Metadata Exposure',
      path: reqPath,
      url,
      port,
      method: 'GET',
      status: 200,
      severity: 'LOW',
      statusTag: 'SUSPICIOUS',
      matchedSignal: `Plex /identity (version=${ver || 'unknown'})`,
      preview: quote,
      evidenceQuote: quote,
      ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
      reason: `Plex Media Server endpoint ${url} discloses machineIdentifier and exact server version (${ver || 'unknown'}) without authentication.`
    });
    return { deviceMeta, findings };
  }

  if (status === 200 && reqPath === '/System/Info/Public') {
    const json = parseJsonObject(text);
    if (json && !Array.isArray(json) && (json.ServerName || json.ProductName) && json.Version) {
      deviceMeta = {
        category: 'nas_media_server',
        vendor: json.ProductName || 'Jellyfin',
        deviceType: 'Jellyfin / Emby Media Server',
        deviceName: json.ServerName || 'Jellyfin Media Server',
        modelName: json.ProductName || 'Jellyfin',
        firmwareVersion: json.Version,
        udn: json.Id || null
      };
      const quote = extractVerbatimSnippet(text, /"Version"\s*:\s*"[^"]+"|"ServerName"\s*:\s*"[^"]+"/) || text.slice(0, 120).trim();
      findings.push({
        name: 'Jellyfin / Emby Media Server Public Info & Version Disclosure',
        path: reqPath,
        url,
        port,
        method: 'GET',
        status: 200,
        severity: 'LOW',
        statusTag: 'SUSPICIOUS',
        matchedSignal: `Jellyfin /System/Info/Public (${json.ServerName}, v${json.Version})`,
        preview: quote,
        evidenceQuote: quote,
        ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
        reason: `Media server endpoint ${url} discloses server name ("${json.ServerName}"), version (${json.Version}), and unique server ID without authentication.`
      });
      return { deviceMeta, findings };
    }
  }

  // ── 10. IP Cameras / NVRs (Hikvision, ONVIF SOAP, Dahua, Axis, UniFi Protect, Snapshots) ──
  // 10a. Hikvision /SDK/activateStatus
  if (status === 200 && !isHtmlOrScript(res, text) && reqPath.includes('SDK/activateStatus') && (text.includes('<ActivateStatus') || text.includes('<Activated>'))) {
    const activated = extractXmlTag(text, 'Activated');
    const isUnactivated = String(activated || '').toLowerCase() === 'false';
    deviceMeta = {
      category: 'ip_camera',
      vendor: 'Hikvision',
      deviceType: 'Hikvision IP Camera / NVR',
      deviceName: 'Hikvision IP Camera / NVR',
      modelName: 'Hikvision Device'
    };
    const quote = extractVerbatimSnippet(text, /<Activated>[^<]+<\/Activated>|<ActivateStatus[^>]*>/) || text.slice(0, 120).trim();
    findings.push({
      name: isUnactivated
        ? `Unactivated Hikvision IP Camera / NVR Exposed (${port}/TCP)`
        : `Hikvision IP Camera Activation Status Endpoint Exposed (${port}/TCP)`,
      path: reqPath,
      url,
      port,
      method: 'GET',
      status: 200,
      severity: isUnactivated ? 'CRITICAL' : 'LOW',
      statusTag: isUnactivated ? 'VULNERABLE' : 'SUSPICIOUS',
      matchedSignal: `Hikvision /SDK/activateStatus (Activated=${activated || 'unknown'})`,
      preview: quote,
      evidenceQuote: quote,
      ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
      reason: isUnactivated
        ? `Hikvision camera/NVR at ${url} reports <Activated>false</Activated>, indicating an uninitialized device awaiting initial admin password setup.`
        : `Hikvision camera/NVR activation status endpoint ${url} responds unauthenticated (Activated=${activated || 'true'}).`
    });
    return { deviceMeta, findings };
  }

  // 10b. Hikvision ISAPI / ONVIF SOAP device_service
  if (
    status === 200 &&
    !isHtmlOrScript(res, text) &&
    (reqPath.includes('ISAPI/System/deviceInfo') || reqPath.includes('onvif/device_service')) &&
    (text.includes('<DeviceInfo') || text.includes('onvif.org') || text.includes('<deviceName>') || text.includes('GetSystemDateAndTimeResponse') || text.includes('UTCDateTime'))
  ) {
    const isHik = reqPath.includes('ISAPI') || text.includes('<DeviceInfo');
    const isOnvif = reqPath.includes('onvif') || text.includes('onvif.org') || text.includes('GetSystemDateAndTimeResponse');
    const model = extractXmlTag(text, 'model') || extractXmlTag(text, 'tt:Model') || (isOnvif ? 'ONVIF IP Camera' : 'IP Camera');
    const serial = extractXmlTag(text, 'serialNumber');
    const fw = extractXmlTag(text, 'firmwareVersion');
    const mac = extractXmlTag(text, 'macAddress');
    deviceMeta = {
      category: 'ip_camera',
      vendor: isHik ? 'Hikvision' : 'ONVIF',
      deviceType: 'IP Camera / NVR',
      deviceName: extractXmlTag(text, 'deviceName') || model,
      modelName: model,
      firmwareVersion: fw,
      serialNumber: serial,
      macAddress: mac
    };
    const quote = extractVerbatimSnippet(text, /<(?:model|serialNumber|firmwareVersion|DeviceInfo|GetSystemDateAndTimeResponse|UTCDateTime)[^>]*>[^<]*/) || text.slice(0, 120).trim();
    findings.push({
      name: isOnvif && !isHik
        ? `ONVIF IP Camera Unauthenticated Device Service Exposure (${port}/TCP)`
        : 'IP Camera Unauthenticated Device Info / ONVIF Service Exposure',
      path: reqPath,
      url,
      port,
      method: isOnvif && text.includes('GetSystemDateAndTimeResponse') ? 'POST' : 'GET',
      status: 200,
      severity: 'HIGH',
      statusTag: 'VULNERABLE',
      matchedSignal: `IP Camera ${reqPath} (${model})`,
      preview: quote,
      evidenceQuote: quote,
      ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
      reason: `IP camera endpoint ${url} exposes device metadata${model ? ` (model="${model}")` : ''} and unauthenticated ONVIF/ISAPI control surface.`
    });
    return { deviceMeta, findings };
  }

  // ONVIF SOAP 400/405/500 recognition
  if (
    reqPath.includes('onvif/device_service') &&
    (status === 400 || status === 405 || status === 500) &&
    (/onvif|gsoap|soap:Envelope|s:Envelope|SOAP-ENV|wsdl/i.test(`${serverHdr} ${text}`))
  ) {
    deviceMeta = {
      category: 'ip_camera',
      vendor: 'ONVIF',
      deviceType: 'ONVIF IP Camera / NVR',
      deviceName: 'ONVIF IP Camera',
      modelName: serverHdr || 'ONVIF Device'
    };
    const quote = serverHdr.length >= 4 ? `Server: ${serverHdr}` : (text.slice(0, 120).trim() || `ONVIF SOAP HTTP ${status}`);
    findings.push({
      name: `ONVIF IP Camera SOAP Service Endpoint Exposed (${port}/TCP)`,
      path: reqPath,
      url,
      port,
      method: 'GET',
      status,
      severity: 'LOW',
      statusTag: 'SUSPICIOUS',
      matchedSignal: `ONVIF SOAP endpoint on port ${port} (HTTP ${status})`,
      preview: quote,
      evidenceQuote: quote,
      ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
      reason: `ONVIF device_service endpoint at ${url} responded with SOAP/gSOAP metadata (HTTP ${status}).`
    });
    return { deviceMeta, findings };
  }

  // 10c. Dahua magicBox.cgi / WEB SERVICE / RPC2_Login
  if (status === 200 && reqPath.includes('magicBox.cgi') && /(?:deviceType|serialNumber|hardwareVersion|updateSerial)=/i.test(text)) {
    const devType = (text.match(/deviceType=([^\r\n]+)/i) || [])[1]?.trim() || 'Dahua IP Camera / NVR';
    const serial = (text.match(/serialNumber=([^\r\n]+)/i) || [])[1]?.trim() || null;
    deviceMeta = {
      category: 'ip_camera',
      vendor: 'Dahua',
      deviceType: 'Dahua IP Camera / NVR',
      deviceName: devType,
      modelName: devType,
      serialNumber: serial
    };
    const quote = extractVerbatimSnippet(text, /(?:deviceType|serialNumber|hardwareVersion)=[^\r\n]+/i) || text.slice(0, 120).trim();
    findings.push({
      name: `Dahua IP Camera / NVR Unauthenticated Device Info Exposure (${port}/TCP)`,
      path: reqPath,
      url,
      port,
      method: 'GET',
      status: 200,
      severity: 'HIGH',
      statusTag: 'VULNERABLE',
      matchedSignal: `Dahua magicBox.cgi (${devType}${serial ? `, SN: ${serial}` : ''})`,
      preview: quote,
      evidenceQuote: quote,
      ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
      reason: `Dahua camera/NVR endpoint ${url} exposes hardware type ("${devType}")${serial ? ` and serial number (${serial})` : ''} without authentication.`
    });
    return { deviceMeta, findings };
  }

  // 10d. Axis Network Camera (/axis-cgi/param.cgi, /axis-cgi/basicdeviceinfo.cgi, /view/viewer_index.shtml)
  if (
    status === 200 &&
    ((reqPath.includes('/axis-cgi/') && /Brand=AXIS|ProdNbr=|ProdShortName=|SerialNumber|Architecture/i.test(text)) ||
      (reqPath.includes('/view/viewer_index.shtml') && /axis/i.test(text)))
  ) {
    const prod = (text.match(/ProdShortName=([^\r\n]+)/i) || text.match(/"ProdShortName"\s*:\s*"([^"]+)"/i) || [])[1]?.trim() || 'Axis Network Camera';
    const serial = (text.match(/SerialNumber=([^\r\n]+)/i) || text.match(/"SerialNumber"\s*:\s*"([^"]+)"/i) || [])[1]?.trim() || null;
    deviceMeta = {
      category: 'ip_camera',
      vendor: 'Axis',
      deviceType: 'Axis Network Camera',
      deviceName: prod,
      modelName: prod,
      serialNumber: serial
    };
    const quote = extractVerbatimSnippet(text, /(?:Brand|ProdShortName|ProdNbr|SerialNumber)=[^\r\n]+/i) || text.slice(0, 120).trim();
    findings.push({
      name: `Axis Network Camera Unauthenticated Device Info Exposure (${port}/TCP)`,
      path: reqPath,
      url,
      port,
      method: 'GET',
      status: 200,
      severity: reqPath.includes('axis-cgi') ? 'HIGH' : 'MEDIUM',
      statusTag: 'VULNERABLE',
      matchedSignal: `Axis ${reqPath} (${prod})`,
      preview: quote,
      evidenceQuote: quote,
      ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
      reason: `Axis camera endpoint ${url} exposes camera model ("${prod}")${serial ? ` and serial (${serial})` : ''} or live viewer UI without authentication.`
    });
    return { deviceMeta, findings };
  }

  // 10e. Ubiquiti UniFi Protect (7080 / 7443 / /api/2.0/bootstrap)
  if (
    (port === 7080 || port === 7443 || reqPath.includes('/api/2.0/bootstrap')) &&
    (/unifi\s*protect|ubiquiti|ubnt/i.test(`${serverHdr} ${text}`) || (status === 200 && reqPath.includes('/api/2.0/bootstrap') && text.includes('"cameras"')))
  ) {
    deviceMeta = {
      category: 'ip_camera',
      vendor: 'Ubiquiti',
      deviceType: 'UniFi Protect NVR / Camera Controller',
      deviceName: 'UniFi Protect NVR',
      modelName: 'UniFi Protect'
    };
    const quote = extractVerbatimSnippet(text, /UniFi Protect|"cameras"|Ubiquiti/i) || `UniFi Protect on port ${port}`;
    findings.push({
      name: `UniFi Protect NVR Interface Exposed (${port}/TCP)`,
      path: reqPath,
      url,
      port,
      method: 'GET',
      status,
      severity: status === 200 && reqPath.includes('bootstrap') ? 'HIGH' : 'MEDIUM',
      statusTag: status === 200 && reqPath.includes('bootstrap') ? 'VULNERABLE' : 'SUSPICIOUS',
      matchedSignal: `UniFi Protect on port ${port} (HTTP ${status})`,
      preview: quote,
      evidenceQuote: quote,
      ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
      reason: `Ubiquiti UniFi Protect NVR interface is reachable at ${url} (HTTP ${status}).`
    });
    return { deviceMeta, findings };
  }

  // 10f. Passive Unauthenticated Live Camera Snapshot / MJPEG Stream
  if (
    status === 200 &&
    (reqPath.includes('snapshot.jpg') || reqPath.includes('image.jpg') || reqPath.includes('video.mjpg')) &&
    (contentType.includes('image/jpeg') || contentType.includes('multipart/x-mixed-replace'))
  ) {
    deviceMeta = {
      category: 'ip_camera',
      vendor: 'IP Camera',
      deviceType: 'IP Camera Live Feed',
      deviceName: 'IP Camera Feed',
      modelName: 'IP Camera'
    };
    const quote = `Content-Type: ${contentType} on ${reqPath}`;
    findings.push({
      name: `Unauthenticated Live Camera Snapshot / MJPEG Stream Exposure (${port}/TCP)`,
      path: reqPath,
      url,
      port,
      method: 'GET',
      status: 200,
      severity: 'CRITICAL',
      statusTag: 'VULNERABLE',
      matchedSignal: `Unauthenticated camera media stream (${contentType})`,
      preview: quote,
      evidenceQuote: quote,
      ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
      reason: `IP camera endpoint ${url} serves live JPEG snapshot or MJPEG video (${contentType}) without authentication.`
    });
    return { deviceMeta, findings };
  }

  // ── 11. CUPS / IPP Print Server (/printers on :631) ────────────────────────
  if (status === 200 && port === 631 && (/cups/i.test(serverHdr) || /<title>[^<]*CUPS/i.test(text))) {
    deviceMeta = {
      category: 'printer',
      vendor: 'CUPS / IPP',
      deviceType: 'IPP / CUPS Network Print Server',
      deviceName: 'CUPS Print Server',
      modelName: serverHdr || 'CUPS'
    };
    const quote = serverHdr.length >= 8 ? `Server: ${serverHdr}` : extractVerbatimSnippet(text, /CUPS[^<\r\n]{0,60}/i) || 'CUPS Print Server :631';
    findings.push({
      name: 'IPP / CUPS Network Print Server Management & Queue Exposure (631/TCP)',
      path: reqPath,
      url,
      port,
      method: 'GET',
      status: 200,
      severity: 'MEDIUM',
      statusTag: 'VULNERABLE',
      matchedSignal: `CUPS Print Server on port 631 (${serverHdr || 'HTTP 200'})`,
      preview: quote,
      evidenceQuote: quote,
      ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
      reason: `IPP/CUPS print server interface is accessible without authentication at ${url}, disclosing printer queues and version metadata.`
    });
    return { deviceMeta, findings };
  }

  // ── 11b. PCs, Workstations & Local Dev / AI / Container Servers ────────────
  // WinRM (:5985 / :5986 /wsman)
  if ((port === 5985 || port === 5986 || reqPath === '/wsman') && (/microsoft-httpapi/i.test(serverHdr) || /negotiate|kerberos/i.test(wwwAuth) || status === 401 || status === 405)) {
    if (/microsoft-httpapi|negotiate|kerberos/i.test(`${serverHdr} ${wwwAuth}`) || port === 5985 || port === 5986) {
      deviceMeta = {
        category: 'pc_workstation',
        vendor: 'Microsoft',
        deviceType: 'Windows Workstation / Server (WinRM)',
        deviceName: 'Windows Host (WinRM)',
        modelName: serverHdr || 'WinRM',
        os: 'Windows',
        osFamily: 'Windows'
      };
      const quote = serverHdr ? `Server: ${serverHdr}` : (wwwAuth ? `WWW-Authenticate: ${wwwAuth}` : `WinRM HTTP ${status} on port ${port}`);
      findings.push({
        name: `Windows Remote Management (WinRM) Service Exposed (${port}/TCP)`,
        path: reqPath,
        url,
        port,
        method: 'GET',
        status,
        severity: port === 5985 ? 'HIGH' : 'MEDIUM',
        statusTag: port === 5985 ? 'VULNERABLE' : 'SUSPICIOUS',
        matchedSignal: `WinRM endpoint on port ${port} (${serverHdr || `HTTP ${status}`})`,
        preview: quote,
        evidenceQuote: quote,
        ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
        reason: `Windows Remote Management (WinRM) endpoint ${url} is exposed on port ${port}/TCP${port === 5985 ? ' over cleartext HTTP' : ''}.`
      });
      return { deviceMeta, findings };
    }
  }

  // Windows WSDAPI (:5357)
  if (port === 5357 && (/microsoft-httpapi/i.test(serverHdr) || status > 0)) {
    deviceMeta = {
      category: 'pc_workstation',
      vendor: 'Microsoft',
      deviceType: 'Windows Workstation / Server (WSDAPI)',
      deviceName: 'Windows Host',
      modelName: serverHdr || 'Windows WSDAPI',
      os: 'Windows',
      osFamily: 'Windows'
    };
    const quote = serverHdr ? `Server: ${serverHdr}` : `Windows WSDAPI HTTP ${status} on port 5357`;
    findings.push({
      name: 'Windows WSDAPI Network Discovery HTTP Port Exposed (5357/TCP)',
      path: reqPath,
      url,
      port: 5357,
      method: 'GET',
      status,
      severity: 'LOW',
      statusTag: 'SUSPICIOUS',
      matchedSignal: `Windows WSDAPI on port 5357 (${serverHdr || `HTTP ${status}`})`,
      preview: quote,
      evidenceQuote: quote,
      ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
      reason: `Windows Web Services for Devices (WSDAPI) HTTP listener on port 5357/TCP is reachable at ${url}.`
    });
    return { deviceMeta, findings };
  }

  // Unauthenticated Docker Engine TCP API (:2375 /version)
  if (status === 200 && (port === 2375 || reqPath === '/version')) {
    const json = parseJsonObject(text);
    if (json && !Array.isArray(json) && json.Version && (json.ApiVersion || json.KernelVersion || json.Components)) {
      const osName = json.Os ? String(json.Os) : 'Linux';
      deviceMeta = {
        category: 'pc_workstation',
        vendor: 'Docker',
        deviceType: 'Docker Host / Workstation Server',
        deviceName: `Docker Engine ${json.Version}`,
        modelName: `Docker ${json.Version} (API ${json.ApiVersion || 'unknown'})`,
        os: `${osName}${json.KernelVersion ? ` ${json.KernelVersion}` : ''}`,
        osFamily: /windows/i.test(osName) ? 'Windows' : 'Linux',
        firmwareVersion: String(json.Version)
      };
      const quote = extractVerbatimSnippet(text, /"Version"\s*:\s*"[^"]+"|"ApiVersion"\s*:\s*"[^"]+"/) || text.slice(0, 120).trim();
      findings.push({
        name: `Unauthenticated Docker Engine TCP API Exposure (${port}/TCP)`,
        path: reqPath,
        url,
        port,
        method: 'GET',
        status: 200,
        severity: 'CRITICAL',
        statusTag: 'VULNERABLE',
        matchedSignal: `Docker Engine API ${reqPath} (v${json.Version})`,
        preview: quote,
        evidenceQuote: quote,
        ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
        reason: `Unauthenticated Docker Engine TCP API at ${url} exposes full container and host control (Docker ${json.Version}, OS=${osName}), allowing trivial host root compromise.`
      });
      return { deviceMeta, findings };
    }
  }

  // Ollama Local LLM API (:11434 /api/tags or /)
  if (status === 200 && (port === 11434 || reqPath === '/api/tags' || /ollama is running/i.test(text))) {
    const json = reqPath === '/api/tags' ? parseJsonObject(text) : null;
    const isOllamaJson = Boolean(json && Array.isArray(json.models));
    const isOllamaBanner = /ollama is running/i.test(text);
    if (isOllamaJson || isOllamaBanner) {
      const modelCount = isOllamaJson ? json.models.length : null;
      deviceMeta = {
        category: 'pc_workstation',
        vendor: 'Ollama',
        deviceType: 'Workstation / Local AI Server (Ollama)',
        deviceName: 'Ollama Local LLM Server',
        modelName: modelCount !== null ? `Ollama (${modelCount} models)` : 'Ollama'
      };
      const quote = isOllamaBanner ? 'Ollama is running' : (extractVerbatimSnippet(text, /"models"\s*:\s*\[/) || text.slice(0, 120).trim());
      findings.push({
        name: `Unauthenticated Ollama Local LLM API Exposure (${port}/TCP)`,
        path: reqPath,
        url,
        port,
        method: 'GET',
        status: 200,
        severity: 'MEDIUM',
        statusTag: 'VULNERABLE',
        matchedSignal: `Ollama API on port ${port}${modelCount !== null ? ` (${modelCount} models)` : ''}`,
        preview: quote,
        evidenceQuote: quote,
        ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
        reason: `Ollama local LLM server at ${url} is exposed without authentication${modelCount !== null ? `, listing ${modelCount} local model(s)` : ''}.`
      });
      return { deviceMeta, findings };
    }
  }

  // Werkzeug / Flask Debugger (always critical if interactive debugger exposed; suspicious on dev port)
  if (/werkzeug/i.test(serverHdr) || /werkzeug debugger|__debugger__|console\.log\("werkzeug"\)/i.test(text)) {
    const hasDebugger = /werkzeug debugger|__debugger__|evalex|pin-prompt/i.test(text);
    deviceMeta = {
      category: 'pc_workstation',
      vendor: 'Python / Flask',
      deviceType: 'Local Development Server (Flask / Werkzeug)',
      deviceName: 'Flask / Werkzeug Dev Server',
      modelName: serverHdr || 'Werkzeug'
    };
    const quote = hasDebugger
      ? (extractVerbatimSnippet(text, /Werkzeug Debugger|__debugger__/i) || 'Werkzeug Debugger')
      : (`Server: ${serverHdr}`);
    findings.push({
      name: hasDebugger
        ? `Werkzeug / Flask Interactive Debugger Exposed (${port}/TCP)`
        : `Flask / Werkzeug Local Development Server Exposed (${port}/TCP)`,
      path: reqPath,
      url,
      port,
      method: 'GET',
      status,
      severity: hasDebugger ? 'CRITICAL' : 'MEDIUM',
      statusTag: hasDebugger ? 'VULNERABLE' : 'SUSPICIOUS',
      matchedSignal: `Werkzeug server on port ${port}`,
      preview: quote,
      evidenceQuote: quote,
      ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
      reason: hasDebugger
        ? `Flask/Werkzeug interactive debugger is exposed at ${url}, risking arbitrary Python code execution.`
        : `Flask/Werkzeug development server (${serverHdr || 'Werkzeug'}) is listening on ${url}.`
    });
    return { deviceMeta, findings };
  }

  // Jupyter Notebook / Lab (:8888 or /api/status)
  if ((port === 8888 || /jupyter/i.test(`${serverHdr} ${text}`)) && status === 200 && (/jupyter|ipython|notebookapp|jupyterlab/i.test(text) || (reqPath === '/api/status' && parseJsonObject(text)?.connections !== undefined))) {
    const isUnauthApi = reqPath === '/api/status' || /"tree"|jp-Notebook|JupyterLab/i.test(text);
    const hasLogin = /type="password"|name="password"|Login to Jupyter/i.test(text);
    deviceMeta = {
      category: 'pc_workstation',
      vendor: 'Jupyter',
      deviceType: 'Workstation / Jupyter Notebook Server',
      deviceName: 'Jupyter Notebook Server',
      modelName: 'Jupyter'
    };
    const quote = extractVerbatimSnippet(text, /Jupyter[^\n<]{0,60}|"connections"\s*:\s*\d+/i) || 'Jupyter Server';
    findings.push({
      name: !hasLogin && isUnauthApi
        ? `Unauthenticated Jupyter Notebook Server Exposed (${port}/TCP)`
        : `Jupyter Notebook Server Exposed (${port}/TCP)`,
      path: reqPath,
      url,
      port,
      method: 'GET',
      status: 200,
      severity: !hasLogin && isUnauthApi ? 'HIGH' : 'MEDIUM',
      statusTag: !hasLogin && isUnauthApi ? 'VULNERABLE' : 'SUSPICIOUS',
      matchedSignal: `Jupyter server on port ${port}`,
      preview: quote,
      evidenceQuote: quote,
      ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
      reason: `Jupyter Notebook/Lab server is reachable at ${url}${!hasLogin && isUnauthApi ? ' without visible authentication challenge' : ''}.`
    });
    return { deviceMeta, findings };
  }

  // Django Dev Server (WSGIServer or Django DEBUG page)
  if (
    status > 0 &&
    status < 500 &&
    (DEV_SERVER_PORTS.has(port) || /WSGIServer/i.test(serverHdr)) &&
    (/WSGIServer/i.test(serverHdr) || /DisallowedHost|You're seeing this error because you have DEBUG = True/i.test(text))
  ) {
    const debugExposed = /DEBUG = True|DisallowedHost/i.test(text);
    deviceMeta = {
      category: 'pc_workstation',
      vendor: 'Python / Django',
      deviceType: 'Local Development Server (Django)',
      deviceName: 'Django Dev Server',
      modelName: serverHdr || 'Django'
    };
    findings.push({
      name: `Django Local Development Server Exposed (${port}/TCP)`,
      path: reqPath,
      url,
      port,
      method: 'GET',
      status,
      severity: debugExposed ? 'HIGH' : 'MEDIUM',
      statusTag: debugExposed ? 'VULNERABLE' : 'SUSPICIOUS',
      matchedSignal: `Django dev server on port ${port}`,
      preview: serverHdr ? `Server: ${serverHdr}` : 'Django DEBUG page',
      evidenceQuote: serverHdr ? `Server: ${serverHdr}` : 'Django DEBUG page',
      ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
      reason: `Django development server is exposed at ${url}${debugExposed ? ' with DEBUG details visible' : ''}.`
    });
    return { deviceMeta, findings };
  }

  // FastAPI / Uvicorn Dev Server
  if (
    status > 0 &&
    status < 500 &&
    DEV_SERVER_PORTS.has(port) &&
    (/uvicorn|hypercorn|starlette/i.test(serverHdr) || (text.includes('swagger-ui') && text.includes('openapi.json')))
  ) {
    deviceMeta = {
      category: 'pc_workstation',
      vendor: 'Python / FastAPI',
      deviceType: 'Local API Server (FastAPI / Uvicorn)',
      deviceName: 'FastAPI / Uvicorn Server',
      modelName: serverHdr || 'Uvicorn'
    };
    findings.push({
      name: `FastAPI / Uvicorn Local API Server Exposed (${port}/TCP)`,
      path: reqPath,
      url,
      port,
      method: 'GET',
      status,
      severity: 'LOW',
      statusTag: 'SUSPICIOUS',
      matchedSignal: `FastAPI / Uvicorn on port ${port}`,
      preview: serverHdr ? `Server: ${serverHdr}` : 'FastAPI / OpenAPI',
      evidenceQuote: serverHdr ? `Server: ${serverHdr}` : 'FastAPI / OpenAPI',
      ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
      reason: `FastAPI/Uvicorn local API server is exposed on port ${port} at ${url}.`
    });
    return { deviceMeta, findings };
  }

  // Python SimpleHTTP / Open Directory Listing Share (never trigger on bare Python/\d without SimpleHTTP or directory listing HTML)
  if (
    status === 200 &&
    (/SimpleHTTP/i.test(serverHdr) || /<title>\s*Directory listing for \//i.test(text) || /<h1>\s*(?:Index of \/|Directory listing for \/)/i.test(text))
  ) {
    deviceMeta = {
      category: 'pc_workstation',
      vendor: 'Python / HTTP Share',
      deviceType: 'Workstation / Open HTTP File Share',
      deviceName: 'Open HTTP File Share',
      modelName: serverHdr || 'HTTP Directory Listing'
    };
    const quote = extractVerbatimSnippet(text, /<(?:title|h1)>\s*(?:Index of \/|Directory listing for \/)[^<]*/i) || (serverHdr ? `Server: ${serverHdr}` : 'Index of /');
    findings.push({
      name: `Unauthenticated HTTP Directory Listing / Open File Share (${port}/TCP)`,
      path: reqPath,
      url,
      port,
      method: 'GET',
      status: 200,
      severity: 'HIGH',
      statusTag: 'VULNERABLE',
      matchedSignal: `Open directory listing on port ${port} (${serverHdr || 'Index of /'})`,
      preview: quote,
      evidenceQuote: quote,
      ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
      reason: `Unauthenticated HTTP directory listing (${serverHdr || 'Index of /'}) at ${url} exposes local workstation files over the network.`
    });
    return { deviceMeta, findings };
  }

  // Vite Dev Server (/@vite/client)
  if (status === 200 && (reqPath === '/@vite/client' || text.includes('/@vite/client') || text.includes('__vite_plugin_react_preamble_installed__'))) {
    deviceMeta = {
      category: 'pc_workstation',
      vendor: 'Vite',
      deviceType: 'Local Development Server (Vite)',
      deviceName: 'Vite Dev Server',
      modelName: 'Vite'
    };
    const quote = extractVerbatimSnippet(text, /\/@vite\/client|__vite_/) || 'Vite dev server (/@vite/client)';
    findings.push({
      name: `Vite Local Development Server Exposed (${port}/TCP)`,
      path: reqPath,
      url,
      port,
      method: 'GET',
      status: 200,
      severity: 'MEDIUM',
      statusTag: 'SUSPICIOUS',
      matchedSignal: `Vite dev server on port ${port}`,
      preview: quote,
      evidenceQuote: quote,
      ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
      reason: `Vite local development server is bound to a network interface at ${url}, exposing HMR client and source modules.`
    });
    return { deviceMeta, findings };
  }

  // Dev servers on known local dev ports (Webpack Dev Server, Next.js, Express)
  if (DEV_SERVER_PORTS.has(port) && status > 0 && status < 500) {
    if (/webpack-dev-server|webpackHotUpdate/i.test(text)) {
      deviceMeta = {
        category: 'pc_workstation',
        vendor: 'Webpack',
        deviceType: 'Local Development Server (Webpack)',
        deviceName: 'Webpack Dev Server',
        modelName: 'Webpack Dev Server'
      };
      findings.push({
        name: `Webpack Local Development Server Exposed (${port}/TCP)`,
        path: reqPath,
        url,
        port,
        method: 'GET',
        status,
        severity: 'MEDIUM',
        statusTag: 'SUSPICIOUS',
        matchedSignal: `Webpack dev server on port ${port}`,
        preview: 'webpack-dev-server',
        evidenceQuote: 'webpack-dev-server',
        ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
        reason: `Webpack development server is exposed on network port ${port} at ${url}.`
      });
      return { deviceMeta, findings };
    }
    if (/next\.js/i.test(poweredHdr) || text.includes('__NEXT_DATA__') || text.includes('/_next/static')) {
      deviceMeta = {
        category: 'pc_workstation',
        vendor: 'Next.js',
        deviceType: 'Local Node.js / Next.js Server',
        deviceName: 'Next.js App Server',
        modelName: 'Next.js'
      };
      findings.push({
        name: `Next.js Local Development / App Server Exposed (${port}/TCP)`,
        path: reqPath,
        url,
        port,
        method: 'GET',
        status,
        severity: 'LOW',
        statusTag: 'SUSPICIOUS',
        matchedSignal: `Next.js server on port ${port}`,
        preview: poweredHdr ? `X-Powered-By: ${poweredHdr}` : '__NEXT_DATA__',
        evidenceQuote: poweredHdr ? `X-Powered-By: ${poweredHdr}` : '__NEXT_DATA__',
        ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
        reason: `Next.js local server is exposed on network port ${port} at ${url}.`
      });
      return { deviceMeta, findings };
    }
    if (/express/i.test(poweredHdr)) {
      deviceMeta = {
        category: 'pc_workstation',
        vendor: 'Node.js / Express',
        deviceType: 'Local Node.js / Express Server',
        deviceName: 'Express Server',
        modelName: 'Express'
      };
      findings.push({
        name: `Node.js / Express Local Server Exposed (${port}/TCP)`,
        path: reqPath,
        url,
        port,
        method: 'GET',
        status,
        severity: 'LOW',
        statusTag: 'SUSPICIOUS',
        matchedSignal: `Express server on port ${port}`,
        preview: `X-Powered-By: ${poweredHdr}`,
        evidenceQuote: `X-Powered-By: ${poweredHdr}`,
        ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
        reason: `Node.js/Express server is listening on network port ${port} at ${url}.`
      });
      return { deviceMeta, findings };
    }
  }

  // ── 12. Passive Header & 401 WWW-Authenticate Fingerprinting ───────────────
  if (/airtunes|airplay/i.test(serverHdr) && !deviceMeta) {
    deviceMeta = {
      category: 'smart_tv',
      vendor: 'Apple / AirPlay',
      deviceType: 'AirPlay-Enabled Smart TV / Receiver',
      deviceName: serverHdr,
      modelName: serverHdr
    };
    if (status === 401 || status === 403 || status === 404) {
      findings.push({
        name: `Apple AirPlay / AirTunes Receiver Service Exposed (${port}/TCP)`,
        path: reqPath,
        url,
        port,
        method: 'GET',
        status,
        severity: 'LOW',
        statusTag: 'SUSPICIOUS',
        matchedSignal: `Server: ${serverHdr} on port ${port}`,
        preview: `Server: ${serverHdr}`,
        evidenceQuote: `Server: ${serverHdr}`,
        ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
        reason: `AirPlay/AirTunes receiver (${serverHdr}) is listening on port ${port} at ${url}.`
      });
    }
  } else if (/roku/i.test(serverHdr) && !deviceMeta) {
    deviceMeta = {
      category: 'smart_tv',
      vendor: 'Roku',
      deviceType: 'Roku TV / Roku Streaming Device',
      deviceName: serverHdr,
      modelName: serverHdr,
      os: 'Roku OS'
    };
  } else if (/tizen|samsung/i.test(serverHdr) && !deviceMeta) {
    deviceMeta = {
      category: 'smart_tv',
      vendor: 'Samsung',
      deviceType: 'Samsung Smart TV (Tizen)',
      deviceName: serverHdr,
      modelName: serverHdr,
      os: 'Tizen'
    };
  } else if (/webos/i.test(serverHdr) && !deviceMeta) {
    deviceMeta = {
      category: 'smart_tv',
      vendor: 'LG',
      deviceType: 'LG webOS Smart TV',
      deviceName: serverHdr,
      modelName: serverHdr,
      os: 'webOS'
    };
  } else if (/app-webs|dnvrs-webs|dvrdvs-webs|hikvision-webs/i.test(serverHdr) && !deviceMeta) {
    deviceMeta = {
      category: 'ip_camera',
      vendor: 'Hikvision',
      deviceType: 'Hikvision IP Camera / NVR',
      deviceName: 'Hikvision Camera / NVR',
      modelName: serverHdr
    };
  } else if (/web service/i.test(serverHdr) && /RPC2_Login|dahua/i.test(text) && !deviceMeta) {
    deviceMeta = {
      category: 'ip_camera',
      vendor: 'Dahua',
      deviceType: 'Dahua IP Camera / NVR',
      deviceName: 'Dahua Camera / NVR',
      modelName: serverHdr
    };
  }

  if (status === 401 && wwwAuth) {
    const realm = extractAuthRealm(wwwAuth);
    const authTarget = `${wwwAuth} ${serverHdr}`;
    const isCleartextBasic = url.startsWith('http://') && /\bbasic\b/i.test(wwwAuth);

    if (!deviceMeta) {
      if (/hikvision|dahua|axis|onvif|ipcam|ip\s*camera|camera|nvr|dvr|reolink|amcrest|foscam|unifi\s*protect|app-webs|dnvrs-webs|dvrdvs-webs|netcam|surveillance|vivotek|hanwha|uniview/i.test(authTarget)) {
        const camVendor = /hikvision|app-webs|dnvrs|dvrdvs/i.test(authTarget)
          ? 'Hikvision'
          : /dahua/i.test(authTarget)
            ? 'Dahua'
            : /axis/i.test(authTarget)
              ? 'Axis'
              : /reolink/i.test(authTarget)
                ? 'Reolink'
                : /amcrest/i.test(authTarget)
                  ? 'Amcrest'
                  : /unifi/i.test(authTarget)
                    ? 'Ubiquiti'
                    : (realm || 'IP Camera');
        deviceMeta = {
          category: 'ip_camera',
          vendor: camVendor,
          deviceType: `${camVendor} IP Camera / NVR`,
          deviceName: realm || `${camVendor} Camera`,
          modelName: realm || camVendor
        };
      } else if (/synology|qnap|asustor|diskstation|truenas|openmediavault|terramaster|readynas/i.test(authTarget)) {
        const nasVendor = /synology|diskstation/i.test(authTarget)
          ? 'Synology'
          : /qnap/i.test(authTarget)
            ? 'QNAP'
            : /asustor/i.test(authTarget)
              ? 'Asustor'
              : /truenas/i.test(authTarget)
                ? 'TrueNAS'
                : (realm || 'NAS');
        deviceMeta = {
          category: 'nas_media_server',
          vendor: nasVendor,
          deviceType: `${nasVendor} NAS / Media Server`,
          deviceName: realm || `${nasVendor} NAS`,
          modelName: realm || nasVendor
        };
      } else if (/hp|epson|brother|canon|cups|xerox|lexmark|kyocera|ricoh|konica|printer/i.test(authTarget)) {
        deviceMeta = {
          category: 'printer',
          vendor: realm || 'Network Printer',
          deviceType: 'Network Printer Web Admin',
          deviceName: realm || 'Network Printer',
          modelName: realm || 'Printer'
        };
      } else if (/router|mikrotik|tp-link|netgear|asus|linksys|d-link|zyxel|openwrt|ubiquiti|gateway|modem|fritz/i.test(authTarget)) {
        deviceMeta = {
          category: 'router_gateway',
          vendor: realm || wwwAuth,
          deviceType: 'Network Appliance / Router',
          deviceName: realm || wwwAuth,
          modelName: realm || wwwAuth
        };
      }
    }

    if (deviceMeta && isCleartextBasic) {
      findings.push({
        name: `Cleartext HTTP Basic Authentication on Device Admin UI (${port}/TCP)`,
        path: reqPath,
        url,
        port,
        method: 'GET',
        status: 401,
        severity: 'MEDIUM',
        statusTag: 'VULNERABLE',
        matchedSignal: `HTTP 401 Basic Auth on cleartext port ${port} (${wwwAuth})`,
        preview: `WWW-Authenticate: ${wwwAuth}`,
        evidenceQuote: `WWW-Authenticate: ${wwwAuth}`,
        ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
        reason: `Device admin interface at ${url} requests HTTP Basic authentication (${wwwAuth}) over unencrypted HTTP, exposing admin credentials to LAN sniffing.`
      });
    }
  }

  return deviceMeta || findings.length > 0 ? { deviceMeta, findings } : null;
}

/**
 * Infers OS family from an SSH greeting banner.
 */
function inferOsFromSshBanner(banner) {
  const b = String(banner || '');
  if (/ubuntu|debian|raspbian|fedora|centos|rhel|alpine|arch|linux/i.test(b)) {
    return { osFamily: 'Linux', os: b };
  }
  if (/windows|openssh_for_windows/i.test(b)) {
    return { osFamily: 'Windows', os: b };
  }
  if (/darwin|macos|apple/i.test(b)) {
    return { osFamily: 'macOS', os: b };
  }
  if (/freebsd|openbsd|netbsd/i.test(b)) {
    return { osFamily: 'BSD', os: b };
  }
  return { osFamily: 'Unix/Linux', os: b || null };
}

/**
 * Evaluates dangerous raw TCP ports discovered open on the device.
 */
function evaluateRawTcpPortFinding(host, serviceEntry, baseTargetUrl) {
  const { port, banner } = serviceEntry;
  const hostBracketed = host.includes(':') ? `[${host}]` : host;
  const fallbackUrl = (() => {
    try {
      const u = new URL(baseTargetUrl);
      return `${u.protocol}//${u.hostname}:${port}/`;
    } catch {
      return `http://${hostBracketed}:${port}/`;
    }
  })();

  if (port === 5555) {
    const quote = banner && banner.length >= 8 ? banner : 'Android Debug Bridge (ADB) TCP 5555 OPEN';
    return {
      finding: {
        name: 'Exposed Android Debug Bridge (ADB over Wi-Fi / TCP 5555)',
        path: ':5555',
        url: fallbackUrl,
        port: 5555,
        method: 'TCP',
        status: 200,
        severity: 'CRITICAL',
        statusTag: 'VULNERABLE',
        matchedSignal: 'TCP port 5555 (Android ADB daemon) open',
        preview: quote,
        evidenceQuote: quote,
        reason: `TCP port 5555 (Android Debug Bridge) is open on ${host}:5555. Unauthenticated LAN attackers or malware can connect via "adb connect ${host}:5555" to gain shell access, sideload malicious APKs, or capture the TV/device screen.`
      },
      deviceMeta: {
        category: 'smart_tv',
        vendor: 'Android',
        deviceType: 'Android TV / Fire TV / Android Device',
        deviceName: `Android Device (${host})`,
        modelName: 'Android TV / ADB Device',
        os: 'Android'
      }
    };
  }

  if (port === 23) {
    const quote = banner && banner.length >= 8 ? banner : 'Telnet Cleartext Remote Shell TCP 23 OPEN';
    return {
      finding: {
        name: 'Exposed Telnet Cleartext Remote Shell Service (23/TCP)',
        path: ':23',
        url: fallbackUrl,
        port: 23,
        method: 'TCP',
        status: 200,
        severity: 'CRITICAL',
        statusTag: 'VULNERABLE',
        matchedSignal: 'TCP port 23 (Telnet) open',
        preview: quote,
        evidenceQuote: quote,
        reason: `Telnet port 23/TCP is open on ${host}:23, exposing the device to cleartext credential interception and automated IoT botnet brute-force attacks (e.g., Mirai).`
      },
      deviceMeta: null
    };
  }

  if (port === 9100) {
    const quote = banner && banner.length >= 8 ? banner : 'HP JetDirect RAW Printing TCP 9100 OPEN';
    return {
      finding: {
        name: 'Exposed HP JetDirect / RAW Network Printer Port (9100/TCP)',
        path: ':9100',
        url: fallbackUrl,
        port: 9100,
        method: 'TCP',
        status: 200,
        severity: 'HIGH',
        statusTag: 'VULNERABLE',
        matchedSignal: 'TCP port 9100 (JetDirect RAW print) open',
        preview: quote,
        evidenceQuote: quote,
        reason: `Network printer RAW port 9100/TCP is open on ${host}:9100 without authentication, permitting arbitrary print jobs, PJL command execution, or printer filesystem manipulation.`
      },
      deviceMeta: {
        category: 'printer',
        vendor: 'Network Printer',
        deviceType: 'JetDirect Network Printer',
        deviceName: `Network Printer (${host})`,
        modelName: 'JetDirect Printer'
      }
    };
  }

  if (port === 1883) {
    const quote = banner && banner.length >= 8 ? banner : 'MQTT Cleartext IoT Broker TCP 1883 OPEN';
    return {
      finding: {
        name: 'Exposed Cleartext MQTT IoT Message Broker Port (1883/TCP)',
        path: ':1883',
        url: fallbackUrl,
        port: 1883,
        method: 'TCP',
        status: 200,
        severity: 'HIGH',
        statusTag: 'VULNERABLE',
        matchedSignal: 'TCP port 1883 (MQTT broker) open',
        preview: quote,
        evidenceQuote: quote,
        reason: `Cleartext MQTT broker port 1883/TCP is open on ${host}:1883, risking unauthorized subscription to smart home telemetry topics or injection of IoT device commands.`
      },
      deviceMeta: {
        category: 'smart_home_iot',
        vendor: 'MQTT',
        deviceType: 'Smart Home MQTT Broker',
        deviceName: `MQTT Broker (${host})`,
        modelName: 'MQTT Broker'
      }
    };
  }

  if (port === 7547) {
    const quote = banner && banner.length >= 8 ? banner : 'TR-069 CWMP Router Management TCP 7547 OPEN';
    return {
      finding: {
        name: 'Exposed TR-069 / CWMP Router WAN Management Port (7547/TCP)',
        path: ':7547',
        url: fallbackUrl,
        port: 7547,
        method: 'TCP',
        status: 200,
        severity: 'HIGH',
        statusTag: 'VULNERABLE',
        matchedSignal: 'TCP port 7547 (TR-069 CWMP) open',
        preview: quote,
        evidenceQuote: quote,
        reason: `TR-069 / CWMP ISP remote management port 7547/TCP is open on ${host}:7547, a frequent vector for router remote code execution and DNS hijacking exploits.`
      },
      deviceMeta: {
        category: 'router_gateway',
        vendor: 'Router / CPE',
        deviceType: 'TR-069 Managed Router / Gateway',
        deviceName: `Router (${host})`,
        modelName: 'CPE Router'
      }
    };
  }

  if (port === 21) {
    const quote = banner && banner.length >= 8 ? banner : 'FTP Cleartext File Transfer TCP 21 OPEN';
    return {
      finding: {
        name: 'Exposed FTP Cleartext File Transfer Port (21/TCP)',
        path: ':21',
        url: `ftp://${hostBracketed}:21/`,
        port: 21,
        method: 'TCP',
        status: 200,
        severity: 'HIGH',
        statusTag: 'VULNERABLE',
        matchedSignal: 'TCP port 21 (FTP) open',
        preview: quote,
        evidenceQuote: quote,
        reason: `Cleartext FTP port 21/TCP is open on ${host}:21${banner ? ` (banner: "${banner}")` : ''}, exposing credentials and file transfers in plaintext.`
      },
      deviceMeta: null
    };
  }

  if (port === 554 || port === 8554) {
    const quote = banner && banner.length >= 8 ? banner : `RTSP Video Stream TCP ${port} OPEN`;
    return {
      finding: {
        name: `Exposed RTSP Camera / Media Video Stream Port (${port}/TCP)`,
        path: `:${port}`,
        url: `rtsp://${hostBracketed}:${port}/`,
        port,
        method: 'RTSP',
        status: 200,
        severity: 'MEDIUM',
        statusTag: 'SUSPICIOUS',
        matchedSignal: `TCP port ${port} (RTSP streaming) open`,
        preview: quote,
        evidenceQuote: quote,
        reason: `RTSP streaming port ${port}/TCP is open on ${host}:${port}. Verify that RTSP video streams require strong digest authentication.`
      },
      deviceMeta: {
        category: 'ip_camera',
        vendor: 'RTSP Camera',
        deviceType: 'RTSP IP Camera / Streamer',
        deviceName: `RTSP Device (${host})`,
        modelName: 'RTSP Camera'
      }
    };
  }

  if (port === 37777) {
    const quote = banner && banner.length >= 8 ? banner : 'Dahua NVR / DVR Private Protocol TCP 37777 OPEN';
    return {
      finding: {
        name: 'Dahua NVR / DVR Private Control Protocol Exposed (37777/TCP)',
        path: ':37777',
        url: `tcp://${hostBracketed}:37777/`,
        port: 37777,
        method: 'TCP',
        status: 200,
        severity: 'MEDIUM',
        statusTag: 'SUSPICIOUS',
        matchedSignal: 'TCP port 37777 (Dahua DVR/NVR protocol) open',
        preview: quote,
        evidenceQuote: quote,
        reason: `Dahua proprietary NVR/DVR control port 37777/TCP is reachable on ${host}:37777. Restrict access to an isolated surveillance VLAN.`
      },
      deviceMeta: {
        category: 'ip_camera',
        vendor: 'Dahua',
        deviceType: 'Dahua IP Camera / NVR',
        deviceName: `Dahua NVR (${host})`,
        modelName: 'Dahua NVR / DVR'
      }
    };
  }

  if (port === 34567) {
    const quote = banner && banner.length >= 8 ? banner : 'Xiongmai DVRIP Surveillance Protocol TCP 34567 OPEN';
    return {
      finding: {
        name: 'Xiongmai / DVRIP Surveillance Protocol Exposed (34567/TCP)',
        path: ':34567',
        url: `tcp://${hostBracketed}:34567/`,
        port: 34567,
        method: 'TCP',
        status: 200,
        severity: 'HIGH',
        statusTag: 'VULNERABLE',
        matchedSignal: 'TCP port 34567 (Xiongmai DVRIP) open',
        preview: quote,
        evidenceQuote: quote,
        reason: `Xiongmai/DVRIP surveillance port 34567/TCP is open on ${host}:34567; devices using Sofia/DVRIP firmware often suffer from critical unauthenticated RCE and hardcoded credential vulnerabilities.`
      },
      deviceMeta: {
        category: 'ip_camera',
        vendor: 'Xiongmai',
        deviceType: 'Xiongmai / DVRIP IP Camera / NVR',
        deviceName: `Xiongmai NVR (${host})`,
        modelName: 'Xiongmai DVRIP'
      }
    };
  }

  // PC / Workstation / Local Server TCP services
  if (port === 445) {
    const quote = banner && banner.length >= 8 ? banner : 'SMB / CIFS File Sharing TCP 445 OPEN';
    return {
      finding: {
        name: 'Exposed Windows SMB / CIFS File Sharing Service (445/TCP)',
        path: ':445',
        url: `smb://${hostBracketed}:445/`,
        port: 445,
        method: 'TCP',
        status: 200,
        severity: 'HIGH',
        statusTag: 'VULNERABLE',
        matchedSignal: 'TCP port 445 (SMB/CIFS) open',
        preview: quote,
        evidenceQuote: quote,
        reason: `SMB/CIFS port 445/TCP is open on ${host}:445, exposing Windows file shares, IPC$ pipes, and potential lateral-movement or SMB relay vectors.`
      },
      deviceMeta: {
        category: 'pc_workstation',
        vendor: 'Microsoft',
        deviceType: 'Windows Workstation / SMB Server',
        deviceName: `Windows Host (${host})`,
        modelName: 'SMB / Windows Host',
        os: 'Windows',
        osFamily: 'Windows'
      }
    };
  }

  if (port === 139) {
    const quote = banner && banner.length >= 8 ? banner : 'NetBIOS Session Service TCP 139 OPEN';
    return {
      finding: {
        name: 'Exposed NetBIOS Session Service (139/TCP)',
        path: ':139',
        url: `tcp://${hostBracketed}:139/`,
        port: 139,
        method: 'TCP',
        status: 200,
        severity: 'MEDIUM',
        statusTag: 'SUSPICIOUS',
        matchedSignal: 'TCP port 139 (NetBIOS-SSN) open',
        preview: quote,
        evidenceQuote: quote,
        reason: `Legacy NetBIOS Session Service port 139/TCP is open on ${host}:139, permitting SMBv1/NetBIOS enumeration.`
      },
      deviceMeta: {
        category: 'pc_workstation',
        vendor: 'Microsoft',
        deviceType: 'Windows Workstation / NetBIOS Host',
        deviceName: `Windows Host (${host})`,
        os: 'Windows',
        osFamily: 'Windows'
      }
    };
  }

  if (port === 135) {
    const quote = banner && banner.length >= 8 ? banner : 'Microsoft RPC Endpoint Mapper TCP 135 OPEN';
    return {
      finding: {
        name: 'Exposed Microsoft RPC Endpoint Mapper (135/TCP)',
        path: ':135',
        url: `tcp://${hostBracketed}:135/`,
        port: 135,
        method: 'TCP',
        status: 200,
        severity: 'MEDIUM',
        statusTag: 'SUSPICIOUS',
        matchedSignal: 'TCP port 135 (MSRPC) open',
        preview: quote,
        evidenceQuote: quote,
        reason: `Microsoft RPC Endpoint Mapper port 135/TCP is exposed on ${host}:135, revealing DCOM/RPC interfaces to LAN clients.`
      },
      deviceMeta: {
        category: 'pc_workstation',
        vendor: 'Microsoft',
        deviceType: 'Windows Workstation / Server',
        deviceName: `Windows Host (${host})`,
        os: 'Windows',
        osFamily: 'Windows'
      }
    };
  }

  if (port === 3389) {
    const quote = banner && banner.length >= 8 ? banner : 'Remote Desktop Protocol RDP TCP 3389 OPEN';
    return {
      finding: {
        name: 'Exposed Remote Desktop Protocol Service (RDP 3389/TCP)',
        path: ':3389',
        url: `rdp://${hostBracketed}:3389/`,
        port: 3389,
        method: 'TCP',
        status: 200,
        severity: 'HIGH',
        statusTag: 'VULNERABLE',
        matchedSignal: 'TCP port 3389 (RDP) open',
        preview: quote,
        evidenceQuote: quote,
        reason: `Remote Desktop Protocol (RDP) port 3389/TCP is open on ${host}:3389, exposing graphical remote login to LAN or VPN credential stuffing and RDP vulnerabilities.`
      },
      deviceMeta: {
        category: 'pc_workstation',
        vendor: 'Microsoft',
        deviceType: 'Windows Workstation / RDP Server',
        deviceName: `Windows RDP Host (${host})`,
        os: 'Windows',
        osFamily: 'Windows'
      }
    };
  }

  if (port === 22) {
    const isSsh1 = /^SSH-1\./i.test(String(banner || ''));
    const osMeta = inferOsFromSshBanner(banner);
    const quote = banner && banner.length >= 6 ? banner : 'SSH Remote Shell TCP 22 OPEN';
    return {
      finding: {
        name: isSsh1 ? 'Exposed Legacy SSHv1 Service (22/TCP)' : 'Exposed SSH Remote Shell Service (22/TCP)',
        path: ':22',
        url: `ssh://${hostBracketed}:22/`,
        port: 22,
        method: 'TCP',
        status: 200,
        severity: isSsh1 ? 'HIGH' : 'LOW',
        statusTag: isSsh1 ? 'VULNERABLE' : 'SUSPICIOUS',
        matchedSignal: banner ? `TCP port 22 (${banner})` : 'TCP port 22 (SSH) open',
        preview: quote,
        evidenceQuote: quote,
        reason: isSsh1
          ? `Legacy SSHv1 protocol (${banner}) is exposed on ${host}:22, which has known cryptographic weaknesses.`
          : `SSH service port 22/TCP is open on ${host}:22${banner ? ` (banner: "${banner}")` : ''}. Ensure key-based authentication is enforced and password login is disabled.`
      },
      deviceMeta: {
        category: 'pc_workstation',
        vendor: osMeta.osFamily === 'macOS' ? 'Apple' : osMeta.osFamily === 'Windows' ? 'Microsoft' : 'OpenSSH',
        deviceType: `${osMeta.osFamily} Workstation / Server`,
        deviceName: `SSH Host (${host})`,
        modelName: banner || 'OpenSSH',
        os: osMeta.os,
        osFamily: osMeta.osFamily
      }
    };
  }

  if (port === 5900 || port === 5901) {
    const rfbMatch = /RFB\s+\d+\.\d+/i.exec(String(banner || ''));
    const quote = banner && banner.length >= 6 ? banner : `VNC Remote Framebuffer TCP ${port} OPEN`;
    return {
      finding: {
        name: `Exposed VNC Remote Desktop Service (${port}/TCP)`,
        path: `:${port}`,
        url: `vnc://${hostBracketed}:${port}/`,
        port,
        method: 'TCP',
        status: 200,
        severity: 'HIGH',
        statusTag: 'VULNERABLE',
        matchedSignal: rfbMatch ? `VNC ${rfbMatch[0]} on port ${port}` : `TCP port ${port} (VNC) open`,
        preview: quote,
        evidenceQuote: quote,
        reason: `VNC Remote Framebuffer port ${port}/TCP is open on ${host}:${port}${rfbMatch ? ` (${rfbMatch[0]})` : ''}, often lacking TLS encryption or strong authentication.`
      },
      deviceMeta: {
        category: 'pc_workstation',
        vendor: 'VNC',
        deviceType: 'Workstation / VNC Remote Desktop',
        deviceName: `VNC Host (${host})`,
        modelName: rfbMatch ? rfbMatch[0] : 'VNC Server'
      }
    };
  }

  if (port === 2049) {
    const quote = banner && banner.length >= 8 ? banner : 'NFS Network File System TCP 2049 OPEN';
    return {
      finding: {
        name: 'Exposed NFS File System Export Service (2049/TCP)',
        path: ':2049',
        url: `tcp://${hostBracketed}:2049/`,
        port: 2049,
        method: 'TCP',
        status: 200,
        severity: 'HIGH',
        statusTag: 'VULNERABLE',
        matchedSignal: 'TCP port 2049 (NFS) open',
        preview: quote,
        evidenceQuote: quote,
        reason: `NFS export port 2049/TCP is open on ${host}:2049; unauthenticated or wildcard NFS exports can allow full filesystem read/write access.`
      },
      deviceMeta: {
        category: 'pc_workstation',
        vendor: 'NFS',
        deviceType: 'Linux / Unix Workstation or File Server',
        deviceName: `NFS Host (${host})`,
        osFamily: 'Linux'
      }
    };
  }

  if (port === 111) {
    const quote = banner && banner.length >= 8 ? banner : 'ONC RPC / rpcbind Portmapper TCP 111 OPEN';
    return {
      finding: {
        name: 'Exposed ONC RPC / rpcbind Portmapper Service (111/TCP)',
        path: ':111',
        url: `tcp://${hostBracketed}:111/`,
        port: 111,
        method: 'TCP',
        status: 200,
        severity: 'MEDIUM',
        statusTag: 'SUSPICIOUS',
        matchedSignal: 'TCP port 111 (rpcbind) open',
        preview: quote,
        evidenceQuote: quote,
        reason: `RPC portmapper (rpcbind) port 111/TCP is open on ${host}:111, enumerating registered RPC/NFS services.`
      },
      deviceMeta: {
        category: 'pc_workstation',
        vendor: 'RPC',
        deviceType: 'Linux / Unix Workstation or Server',
        deviceName: `RPC Host (${host})`,
        osFamily: 'Linux'
      }
    };
  }

  if (port === 548) {
    const quote = banner && banner.length >= 8 ? banner : 'Apple Filing Protocol AFP TCP 548 OPEN';
    return {
      finding: {
        name: 'Exposed Apple Filing Protocol File Sharing Service (548/TCP)',
        path: ':548',
        url: `tcp://${hostBracketed}:548/`,
        port: 548,
        method: 'TCP',
        status: 200,
        severity: 'MEDIUM',
        statusTag: 'SUSPICIOUS',
        matchedSignal: 'TCP port 548 (AFP) open',
        preview: quote,
        evidenceQuote: quote,
        reason: `Apple Filing Protocol (AFP) port 548/TCP is open on ${host}:548, exposing macOS file sharing over the local network.`
      },
      deviceMeta: {
        category: 'pc_workstation',
        vendor: 'Apple',
        deviceType: 'macOS Workstation / File Server',
        deviceName: `macOS Host (${host})`,
        os: 'macOS',
        osFamily: 'macOS'
      }
    };
  }

  if (port === 873) {
    const quote = banner && banner.length >= 8 ? banner : 'rsync Daemon TCP 873 OPEN';
    return {
      finding: {
        name: 'Exposed rsync File Synchronization Daemon (873/TCP)',
        path: ':873',
        url: `tcp://${hostBracketed}:873/`,
        port: 873,
        method: 'TCP',
        status: 200,
        severity: 'MEDIUM',
        statusTag: 'SUSPICIOUS',
        matchedSignal: banner ? `TCP port 873 (${banner})` : 'TCP port 873 (rsync) open',
        preview: quote,
        evidenceQuote: quote,
        reason: `rsync daemon port 873/TCP is open on ${host}:873; unauthenticated rsync modules can expose sensitive local directories.`
      },
      deviceMeta: {
        category: 'pc_workstation',
        vendor: 'rsync',
        deviceType: 'Linux / Unix Workstation or Server',
        deviceName: `rsync Host (${host})`,
        osFamily: 'Linux'
      }
    };
  }

  return null;
}

const CATEGORY_PRIORITY_LIST = [
  'smart_tv',
  'ip_camera',
  'pc_workstation',
  'router_gateway',
  'nas_media_server',
  'printer',
  'smart_home_iot',
  'upnp_dlna',
  'device_web'
];

/**
 * Performs comprehensive Smart TV, IP Camera/NVR, PC/Workstation/Server, and IoT Device discovery and security auditing.
 *
 * @param {string} targetUrl
 * @param {Function} fetchWithRetry
 * @param {object} [options={}]
 */
export async function scanDeviceTarget(targetUrl, fetchWithRetry, options = {}) {
  const boundGovernance = fetchWithRetry?.governance || null;
  const allowPrivate = Boolean(boundGovernance?.allowPrivate ?? options.allowPrivate);
  const guard = boundGovernance?.guard ?? options.guard ?? null;
  const scopeRules = boundGovernance && boundGovernance.scopeRules === undefined
    ? null
    : (boundGovernance?.scopeRules ?? options.scopeRules ?? null);

  const normalizedInput = normalizeTargetInput(targetUrl);
  if (!normalizedInput) {
    return { ok: false, error: 'Invalid URL', findings: [], deviceProfile: null };
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(normalizedInput);
  } catch {
    return { ok: false, error: 'Invalid URL', findings: [], deviceProfile: null };
  }

  const urlCheck = validateTargetUrl(normalizedInput, { allowPrivate });
  if (!urlCheck.valid) {
    return {
      ok: false,
      isGovernanceBlock: true,
      error: `Request blocked by SSRF policy: ${urlCheck.error}`,
      findings: [],
      deviceProfile: null
    };
  }

  const effectiveTargetUrl = urlCheck.normalized || normalizedInput;
  try {
    parsedUrl = new URL(effectiveTargetUrl);
  } catch {
    return { ok: false, error: 'Invalid URL', findings: [], deviceProfile: null };
  }

  const preDnsGate = runAssetGateCheck(effectiveTargetUrl, { guard, scopeRules, alwaysBuiltin: true });
  if (preDnsGate && preDnsGate.allowed === false) {
    return {
      ok: false,
      isGovernanceBlock: true,
      error: preDnsGate.reason || 'Blocked by governance policy',
      findings: [],
      deviceProfile: null
    };
  }

  const hostname = parsedUrl.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
  const isLiteralIp = net.isIP(hostname) !== 0;
  const explicitPort = parsedUrl.port ? Number(parsedUrl.port) : null;
  const defaultPort = parsedUrl.protocol === 'https:' ? 443 : 80;
  const basePort = explicitPort || defaultPort;
  const baseOrigin = parsedUrl.origin;
  const requestedCategory = normalizeDeviceCategory(options.deviceCategory);

  // Check cachedDeviceScan reuse before launching network probes
  const cached = options.cachedDeviceScan && typeof options.cachedDeviceScan === 'object' ? options.cachedDeviceScan : null;
  let reusedCachedPorts = false;
  let portScanResult = null;
  let openPorts = [];
  let openServices = [];
  let basePortClosed = false;

  if (cached) {
    const cachedHost = String(cached.deviceProfile?.host || cached.host || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
    const cachedCat = normalizeDeviceCategory(cached.deviceCategory || cached.requestedCategory || 'all');
    const hostMatches = !cachedHost || cachedHost === hostname;
    const catCompatible = cachedCat === 'all' || cachedCat === requestedCategory;

    if (hostMatches && catCompatible) {
      if (
        cached.ok === true &&
        cached.isQuickFingerprint !== true &&
        !options.quickFingerprint &&
        Array.isArray(cached.findings) &&
        cached.deviceProfile
      ) {
        return {
          ok: true,
          findings: cached.findings,
          deviceProfile: cached.deviceProfile,
          primaryResponse: cached.primaryResponse ?? null,
          fromCache: true
        };
      }

      const cachedOpenPorts = Array.isArray(cached.openPorts)
        ? cached.openPorts
        : (Array.isArray(cached.deviceProfile?.openPorts) ? cached.deviceProfile.openPorts : null);
      if (cachedOpenPorts) {
        reusedCachedPorts = true;
        openPorts = cachedOpenPorts.slice();
        if (Array.isArray(cached.allProbed) && cached.allProbed.length > 0) {
          portScanResult = cached;
          openServices = cached.allProbed.filter(p => p.open);
          const baseEntry = cached.allProbed.find(p => p.port === basePort);
          if (baseEntry && !baseEntry.open) basePortClosed = true;
        } else {
          const cachedServices = Array.isArray(cached.openServices)
            ? cached.openServices
            : (Array.isArray(cached.deviceProfile?.openServices) ? cached.deviceProfile.openServices : []);
          openServices = openPorts.map(p => {
            const baseEntry = PORT_MAP.get(p) || {
              port: p,
              scheme: p === 443 || p === 8443 || p === 8002 || p === 7443 ? 'https' : 'http',
              category: 'device_web',
              vendor: null,
              service: `port-${p}`,
              label: `Open Service (${p}/TCP)`,
              paths: ['/']
            };
            const entryScheme = String(baseEntry.scheme || 'tcp').toLowerCase();
            const cachedSvc =
              cachedServices.find(cs => Number(cs?.port) === p && String(cs?.scheme || 'tcp').toLowerCase() === entryScheme) ||
              cachedServices.find(cs => Number(cs?.port) === p);
            return cachedSvc?.banner
              ? { ...baseEntry, banner: cachedSvc.banner }
              : baseEntry;
          });
          basePortClosed = Boolean(cached.deviceProfile?.basePortClosed ?? !openPorts.includes(basePort));
        }
      }
    }
  }

  // Determine whether multi-port TCP discovery should run:
  // Never open real OS sockets when caller passes a custom test mock fetcher without tcpProbe/portProbe and without multiPort: true.
  const hasCustomProbe = typeof options.tcpProbe === 'function' || typeof options.portProbe === 'function';
  const isLiveFetcher =
    fetchWithRetry === defaultCoreFetch ||
    Boolean(fetchWithRetry?.isDefaultFetch) ||
    (Boolean(boundGovernance) && !fetchWithRetry?.hasCustomFetcher);
  const isPrivateLanHost = isPrivateOrLanHost(hostname);
  const hasExplicitPorts = Array.isArray(options.ports) && options.ports.length > 0;
  const shouldRunMultiPort =
    reusedCachedPorts ||
    options.multiPort === true ||
    hasCustomProbe ||
    (options.multiPort !== false && hasExplicitPorts && (isLiveFetcher || hasCustomProbe)) ||
    (options.multiPort !== false && isLiveFetcher && (isPrivateLanHost || options.deviceMode === true) && !explicitPort) ||
    (options.multiPort !== false && isLiveFetcher && options.deviceMode === true);

  // Enforce DNS SSRF validation for non-literal hostnames BEFORE any live/raw TCP/TLS/RTSP/mDNS socket probe.
  let probeHost = hostname;
  if (!isLiteralIp && (isLiveFetcher || Boolean(boundGovernance?.dnsResolver) || (shouldRunMultiPort && !hasCustomProbe))) {
    const activeDnsResolver = boundGovernance ? boundGovernance.dnsResolver : (options.dnsResolver ?? null);
    const dnsCheck = await resolveAndValidateTarget(effectiveTargetUrl, {
      allowPrivate,
      resolver: activeDnsResolver,
      resolveCache: boundGovernance?.resolveCache ?? null,
      targetPinStore: boundGovernance?.targetPinStore ?? null,
      sourceIp: boundGovernance?.sourceIp ?? null,
      sourceIpMap: boundGovernance?.sourceIpMap ?? null
    });
    if (!dnsCheck.valid) {
      return {
        ok: false,
        isGovernanceBlock: true,
        error: dnsCheck.reason || 'Blocked by DNS SSRF policy',
        findings: [],
        deviceProfile: null
      };
    }
    if (dnsCheck.primaryIp) {
      probeHost = dnsCheck.primaryIp;
    }
  }

  if (shouldRunMultiPort && !reusedCachedPorts) {
    portScanResult = await probeDevicePorts(probeHost, { ...options, basePort, deviceCategory: requestedCategory });
    openPorts = portScanResult.openPorts;
    openServices = portScanResult.openServices;
    const baseEntry = portScanResult.allProbed.find(p => p.port === basePort);
    if (baseEntry && !baseEntry.open) {
      basePortClosed = true;
    }
  }

  const findings = [];
  const discoveredMetas = [];
  const categoryScores = Object.create(null);
  const httpPortCategoryScores = new Map();
  const categorySignals = [];
  const responsiveHttpOrigins = [];
  const responsiveHttpsOrigins = [];
  let anyNetworkSuccess = openPorts.length > 0;

  const recordDeviceMeta = (meta, { weight = 8, signal = null, port = null } = {}) => {
    if (!meta || typeof meta !== 'object') return;
    const cat = meta.category || 'device_web';
    discoveredMetas.push({ ...meta, weight, signal });
    if (port !== null && port !== undefined) {
      const portCatKey = `${port}:${cat}`;
      const prevWeight = httpPortCategoryScores.get(portCatKey) || 0;
      if (weight > prevWeight) {
        categoryScores[cat] = (categoryScores[cat] || 0) + (weight - prevWeight);
        httpPortCategoryScores.set(portCatKey, weight);
      }
    } else {
      categoryScores[cat] = (categoryScores[cat] || 0) + weight;
    }
    if (signal && !categorySignals.includes(signal)) {
      categorySignals.push(signal);
    }
  };

  // Build list of HTTP/HTTPS endpoints to probe via fetchWithRetry
  const httpProbes = [];
  const seenProbeKeys = new Set();
  const addHttpProbe = (origin, port, pathStr, reqOpts = {}) => {
    const cleanOrigin = origin.replace(/\/+$/, '');
    const method = String(reqOpts.method || 'GET').toUpperCase();
    const fullUrl = `${cleanOrigin}${pathStr}`;
    const key = `${method} ${fullUrl}`;
    if (seenProbeKeys.has(key)) return;
    seenProbeKeys.add(key);
    httpProbes.push({
      url: fullUrl,
      origin: cleanOrigin,
      port,
      path: pathStr,
      method,
      headers: reqOpts.headers || undefined,
      body: reqOpts.body || undefined
    });
  };

  // 1. If basePort is NOT known to be closed, probe same-origin paths on baseOrigin
  if (!basePortClosed) {
    const baseCatalogEntry = PORT_MAP.get(basePort);
    const defaultSameOriginPaths = [
      '/',
      '/api/v2/',
      '/setup/eureka_info',
      '/query/device-info',
      '/query/apps',
      '/sony/system',
      '/description.xml',
      '/rootDesc.xml',
      '/ssdp/device-desc.xml',
      '/apps',
      '/dmr',
      '/smp_2_',
      '/dd.xml',
      '/info',
      '/server-info',
      '/1/system',
      '/6/system',
      '/cm?cmnd=Status%200',
      '/shelly',
      '/identity',
      '/System/Info/Public',
      '/ISAPI/System/deviceInfo',
      '/SDK/activateStatus',
      '/onvif/device_service',
      '/cgi-bin/magicBox.cgi?action=getSystemInfo',
      '/axis-cgi/param.cgi?action=list&group=Brand',
      '/axis-cgi/basicdeviceinfo.cgi',
      '/view/viewer_index.shtml',
      '/snapshot.jpg'
    ];
    const rawSameOriginPaths = options.quickFingerprint
      ? ['/', '/api/v2/', '/setup/eureka_info', '/query/device-info', '/description.xml', '/dmr', '/info', '/ISAPI/System/deviceInfo']
      : (baseCatalogEntry?.paths?.length ? baseCatalogEntry.paths : defaultSameOriginPaths);
    const sameOriginPaths = (!baseCatalogEntry || baseCatalogEntry.category === 'device_web' || baseCatalogEntry.sharedPort)
      ? filterDeviceWebPathsForCategory(rawSameOriginPaths, requestedCategory)
      : rawSameOriginPaths;

    for (const p of sameOriginPaths) {
      addHttpProbe(baseOrigin, basePort, p);
    }

    if (!options.quickFingerprint && (basePort === 80 || basePort === 443 || basePort === 8080 || basePort === 8081 || basePort === 8000 || basePort === 8899 || basePort === 2020) && (requestedCategory === 'all' || requestedCategory === 'ip_camera')) {
      addHttpProbe(baseOrigin, basePort, '/onvif/device_service', {
        method: 'POST',
        headers: { 'Content-Type': 'application/soap+xml; charset=utf-8' },
        body: ONVIF_TIME_SOAP_BODY
      });
    }
    if (!options.quickFingerprint && (basePort === 52323 || basePort === 80) && (requestedCategory === 'all' || requestedCategory === 'smart_tv')) {
      addHttpProbe(baseOrigin, basePort, '/sony/system', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: SONY_SYS_INFO_BODY
      });
    }
  }

  // 2. For every discovered open port from multi-port scan, enqueue its protocol-specific paths
  const hostBracketed = hostname.includes(':') ? `[${hostname}]` : hostname;
  const tcpHttpOrigins = [];
  const tcpHttpsOrigins = [];

  if (shouldRunMultiPort && openServices.length > 0) {
    for (const svc of openServices) {
      if (svc.scheme === 'http' || svc.scheme === 'https') {
        const schemesToProbe = Array.isArray(svc.alternateSchemes) && svc.alternateSchemes.length > 0
          ? [svc.scheme, ...svc.alternateSchemes.filter(s => s !== svc.scheme)]
          : [svc.scheme];
        for (const activeScheme of schemesToProbe) {
          const isDefaultSchemePort = (activeScheme === 'http' && svc.port === 80) || (activeScheme === 'https' && svc.port === 443);
          const origin = isDefaultSchemePort
            ? `${activeScheme}://${hostBracketed}`
            : `${activeScheme}://${hostBracketed}:${svc.port}`;
          if (activeScheme === 'https') {
            if (!tcpHttpsOrigins.includes(origin)) tcpHttpsOrigins.push(origin);
          } else {
            if (!tcpHttpOrigins.includes(origin)) tcpHttpOrigins.push(origin);
          }
          const rawPaths = activeScheme === svc.scheme
            ? (svc.paths && svc.paths.length > 0 ? svc.paths : ['/'])
            : ['/'];
          const categoryScopedPaths = (svc.category === 'device_web' || svc.sharedPort)
            ? filterDeviceWebPathsForCategory(rawPaths, requestedCategory)
            : rawPaths;
          const pathsToProbe = options.quickFingerprint ? categoryScopedPaths.slice(0, 2) : categoryScopedPaths;
          for (const p of pathsToProbe) {
            addHttpProbe(origin, svc.port, p);
          }

          if (!options.quickFingerprint && activeScheme === svc.scheme) {
            if ((svc.port === 8899 || svc.port === 2020 || svc.port === 8000 || svc.port === 80 || svc.port === 443 || svc.port === 8080 || svc.port === 8081) && (requestedCategory === 'all' || requestedCategory === 'ip_camera')) {
              addHttpProbe(origin, svc.port, '/onvif/device_service', {
                method: 'POST',
                headers: { 'Content-Type': 'application/soap+xml; charset=utf-8' },
                body: ONVIF_TIME_SOAP_BODY
              });
            }
            if (svc.port === 52323 && (requestedCategory === 'all' || requestedCategory === 'smart_tv')) {
              addHttpProbe(origin, svc.port, '/sony/system', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: SONY_SYS_INFO_BODY
              });
            }
          }
        }
      } else if (svc.scheme === 'tcp') {
        if ((svc.port === 554 || svc.port === 8554) && (typeof options.rtspProbe === 'function' || isLiveFetcher)) {
          const rtspRes = await probeRtspService(probeHost, svc.port, options);
          if (rtspRes && rtspRes.ok) {
            const rtspUrl = `rtsp://${hostBracketed}:${svc.port}/`;
            const srvText = String(rtspRes.server || '');
            const vendorHint = /hikvision/i.test(srvText)
              ? 'Hikvision'
              : /dahua/i.test(srvText)
                ? 'Dahua'
                : /axis/i.test(srvText)
                  ? 'Axis'
                  : 'RTSP Camera';
            recordDeviceMeta({
              category: 'ip_camera',
              vendor: vendorHint,
              deviceType: 'RTSP IP Camera / NVR',
              deviceName: `${vendorHint} (${hostname})`,
              modelName: srvText || 'RTSP Camera'
            }, { weight: 12, signal: `rtsp:${svc.port}` });

            if (rtspRes.unauthenticatedStream) {
              findings.push({
                name: `Unauthenticated RTSP Live Video Stream Exposure (${svc.port}/TCP)`,
                path: `:${svc.port}`,
                url: rtspUrl,
                port: svc.port,
                method: 'RTSP',
                status: 200,
                severity: 'HIGH',
                statusTag: 'VULNERABLE',
                matchedSignal: `RTSP DESCRIBE 200 OK with SDP (${svc.port}/TCP)`,
                preview: rtspRes.sdpSnippet || 'RTSP/1.0 200 OK (v=0 SDP)',
                evidenceQuote: rtspRes.sdpSnippet || 'RTSP/1.0 200 OK (v=0 SDP)',
                reason: `Unauthenticated RTSP DESCRIBE on ${rtspUrl} returned live SDP stream metadata without credentials, allowing LAN clients to view the video stream.`
              });
            } else if (rtspRes.wwwAuth && /\bbasic\b/i.test(rtspRes.wwwAuth)) {
              findings.push({
                name: `RTSP Stream Uses Cleartext Basic Authentication (${svc.port}/TCP)`,
                path: `:${svc.port}`,
                url: rtspUrl,
                port: svc.port,
                method: 'RTSP',
                status: rtspRes.describeStatus || rtspRes.status || 401,
                severity: 'MEDIUM',
                statusTag: 'VULNERABLE',
                matchedSignal: `RTSP WWW-Authenticate: ${rtspRes.wwwAuth}`,
                preview: `WWW-Authenticate: ${rtspRes.wwwAuth}`,
                evidenceQuote: `WWW-Authenticate: ${rtspRes.wwwAuth}`,
                reason: `RTSP endpoint ${rtspUrl} uses cleartext Basic authentication (${rtspRes.wwwAuth}) rather than Digest auth.`
              });
            } else {
              findings.push({
                name: `Exposed RTSP Camera / Media Video Stream Port (${svc.port}/TCP)`,
                path: `:${svc.port}`,
                url: rtspUrl,
                port: svc.port,
                method: 'RTSP',
                status: rtspRes.status || 200,
                severity: 'MEDIUM',
                statusTag: 'SUSPICIOUS',
                matchedSignal: `RTSP OPTIONS HTTP-like status ${rtspRes.status}${srvText ? ` (${srvText})` : ''}`,
                preview: srvText ? `Server: ${srvText}` : `RTSP/1.0 ${rtspRes.status}`,
                evidenceQuote: srvText ? `Server: ${srvText}` : `RTSP/1.0 ${rtspRes.status}`,
                reason: `RTSP streaming service is active on ${rtspUrl}${srvText ? ` (${srvText})` : ''}.`
              });
            }
            continue;
          }
        }

        if (svc.port === 8009 && (typeof options.tlsProbe === 'function' || isLiveFetcher)) {
          const tlsInfo = await probeTlsMetadata(probeHost, 8009, { ...options, ...(!isLiteralIp ? { servername: hostname } : {}) });
          if (tlsInfo && tlsInfo.ok) {
            const cn = tlsInfo.subjectCN || '';
            const san = tlsInfo.san || '';
            const certLabel = cn || san || 'Google Cast TLS';
            const isCastCert = svc.port === 8009 || /chromecast|google|cast|eureka|android|shield|nvidia|tv/i.test(`${cn} ${san}`);
            if (isCastCert) {
              recordDeviceMeta({
                category: 'smart_tv',
                vendor: 'Google / Android TV',
                deviceType: 'Google Cast / Android TV Receiver',
                deviceName: cn || `Google Cast (${hostname})`,
                modelName: cn || 'Google Cast TLS Receiver'
              }, { weight: 10, signal: 'cast_tls:8009' });
              findings.push({
                name: 'Google Cast / Android TV TLS Control Channel Exposed (8009/TCP)',
                path: ':8009',
                url: `tcp://${hostBracketed}:8009/`,
                port: 8009,
                method: 'TCP',
                status: 200,
                severity: tlsInfo.legacyTls ? 'MEDIUM' : 'LOW',
                statusTag: 'SUSPICIOUS',
                matchedSignal: `TLS 8009/TCP (${tlsInfo.protocol || 'TLS'}, CN=${certLabel})`,
                preview: `CN=${certLabel} (${tlsInfo.protocol || 'TLS'})`,
                evidenceQuote: `CN=${certLabel} (${tlsInfo.protocol || 'TLS'})`,
                reason: `Google Cast TLS control channel (8009/TCP) is open on ${hostname}:8009 (protocol=${tlsInfo.protocol || 'TLS'}, cert CN="${certLabel}").`
              });
              continue;
            }
          }
        }

        const rawEval = evaluateRawTcpPortFinding(hostname, svc, effectiveTargetUrl);
        if (rawEval) {
          if (rawEval.deviceMeta) {
            recordDeviceMeta(rawEval.deviceMeta, { weight: 7, signal: `tcp:${svc.port}` });
          }
          if (rawEval.finding) findings.push(rawEval.finding);
        }
      }
    }
  }

  // Optional non-intrusive mDNS (5353/UDP) discovery when udpProbe hook is provided or explicitly enabled on live scans
  if (typeof options.udpProbe === 'function' || (isLiveFetcher && options.udpProbe === true)) {
    const mdnsRes = await probeMdnsService(probeHost, options);
    if (mdnsRes && mdnsRes.ok && Array.isArray(mdnsRes.services) && mdnsRes.services.length > 0) {
      const joined = mdnsRes.services.join(' ');
      if (/_smb|_rfb|_ssh|_workstation|_afpovertcp/i.test(joined)) {
        recordDeviceMeta({
          category: 'pc_workstation',
          vendor: /_afpovertcp/i.test(joined) ? 'Apple' : null,
          deviceType: 'PC / Workstation (mDNS)',
          deviceName: mdnsRes.deviceNames?.[0] || hostname,
          osFamily: /_afpovertcp/i.test(joined) ? 'macOS' : undefined
        }, { weight: 6, signal: 'mdns:pc_workstation' });
      }
      if (/_googlecast|_airplay|_raop/i.test(joined)) {
        const isGoogleCastMdns = /_googlecast/i.test(joined);
        recordDeviceMeta({
          category: 'smart_tv',
          vendor: isGoogleCastMdns ? 'Google / Android TV' : 'Apple / AirPlay',
          deviceType: isGoogleCastMdns ? 'Google Cast / Android TV (mDNS)' : 'AirPlay Receiver (mDNS)',
          deviceName: mdnsRes.deviceNames?.[0] || hostname
        }, { weight: 5, signal: 'mdns:smart_tv' });
      }
    }
  }

  // Execute HTTP probes with bounded concurrency (default 6) and a per-origin circuit breaker
  const probeTimeoutMs = Number(options.probeTimeoutMs) > 0 ? Number(options.probeTimeoutMs) : 2000;
  const httpLimit = pLimit(Math.max(1, Math.min(Number(options.httpConcurrency) || 6, 12)));
  const trippedOrigins = new Set();
  const originFailureCount = new Map();
  const probeOutputs = new Array(httpProbes.length).fill(null);
  let governanceFailure = null;

  const runSingleHttpProbe = async (probe, idx) => {
    if (governanceFailure || trippedOrigins.has(probe.origin)) return;
    try {
      const reqOpts = {
        followRedirects: false,
        allowPrivate,
        retries: 0,
        failFast: true,
        timeout: probeTimeoutMs,
        ...(probe.method !== 'GET' ? { method: probe.method } : {}),
        ...(probe.headers ? { headers: probe.headers } : {}),
        ...(probe.body !== undefined ? { body: probe.body } : {})
      };
      const res = await fetchWithRetry(probe.url, reqOpts, 0, probeTimeoutMs);
      probeOutputs[idx] = { ok: true, res };
    } catch (err) {
      if (err?.isGovernanceBlock || err?.code === 'SSRF_POLICY_BLOCKED' || err?.code === 'TARGET_RULE_BLOCKED' || err?.code === 'DNS_REBIND_OR_PRIVATE_IP') {
        governanceFailure = {
          ok: false,
          isGovernanceBlock: true,
          error: err.message || 'Blocked by governance policy',
          findings: [],
          deviceProfile: null
        };
        return;
      }
      const nextCount = (originFailureCount.get(probe.origin) || 0) + 1;
      originFailureCount.set(probe.origin, nextCount);
      // Circuit breaker: in multiPort mode trip immediately on first transport/timeout failure per origin;
      // on single-origin fallback allow up to 1 retry probe if needed, or trip on timeout/abort/network failure immediately.
      if (shouldRunMultiPort || nextCount >= 1) {
        trippedOrigins.add(probe.origin);
      }
    }
  };

  // Phase A: first probe per unique origin (proves origin responsiveness / trips dead origins before flooding queue)
  const seenPhaseAOrigins = new Set();
  const phaseATasks = [];
  const phaseBIndices = [];
  for (let i = 0; i < httpProbes.length; i++) {
    const p = httpProbes[i];
    if (!seenPhaseAOrigins.has(p.origin)) {
      seenPhaseAOrigins.add(p.origin);
      phaseATasks.push(httpLimit(() => runSingleHttpProbe(p, i)));
    } else {
      phaseBIndices.push(i);
    }
  }
  await Promise.all(phaseATasks);

  if (governanceFailure) {
    return governanceFailure;
  }

  // Phase B: remaining probes for origins that did NOT trip circuit breaker
  if (phaseBIndices.length > 0) {
    await Promise.all(
      phaseBIndices
        .filter(i => !trippedOrigins.has(httpProbes[i].origin))
        .map(i => httpLimit(() => runSingleHttpProbe(httpProbes[i], i)))
    );
  }

  if (governanceFailure) {
    return governanceFailure;
  }

  // Process HTTP responses deterministically in probe order
  let primaryResponse = null;
  for (let i = 0; i < httpProbes.length; i++) {
    const out = probeOutputs[i];
    if (!out || !out.ok) continue;
    const probe = httpProbes[i];
    const res = out.res;
    anyNetworkSuccess = true;

    if (!primaryResponse && res && typeof res.status === 'number' && res.status > 0) {
      primaryResponse = { ...res, probeUrl: probe.url, probePort: probe.port };
    }

    if (res && typeof res.status === 'number' && res.status > 0 && res.status < 500) {
      if (probe.origin.startsWith('https://')) {
        if (!responsiveHttpsOrigins.includes(probe.origin)) responsiveHttpsOrigins.push(probe.origin);
      } else {
        if (!responsiveHttpOrigins.includes(probe.origin)) responsiveHttpOrigins.push(probe.origin);
      }
    }

    const analysis = analyzeDeviceHttpResponse({
      url: probe.url,
      port: probe.port,
      path: probe.path,
      res,
      openPorts
    });

    if (analysis) {
      if (analysis.deviceMeta) {
        const isHighConfidenceHttp = Boolean(analysis.findings?.some(f => f.status === 200)) || analysis.findings?.length > 0;
        recordDeviceMeta(analysis.deviceMeta, {
          weight: isHighConfidenceHttp ? 12 : 9,
          signal: `http:${probe.port}:${probe.path}`,
          port: probe.port
        });
      }
      if (Array.isArray(analysis.findings) && analysis.findings.length > 0) {
        for (const f of analysis.findings) {
          if (!findings.some(existing => existing.name === f.name && existing.port === f.port)) {
            findings.push(f);
          }
        }
      }
    }
  }

  // Check TLS metadata on open HTTPS device ports if no HTTP metadata was found on them or tlsProbe hook is provided
  if (shouldRunMultiPort && openServices.length > 0 && (typeof options.tlsProbe === 'function' || (isLiveFetcher && !options.quickFingerprint))) {
    for (const svc of openServices) {
      if (svc.scheme === 'https' && (svc.port === 8002 || svc.port === 8443 || svc.port === 7443 || svc.port === 7345)) {
        const tlsInfo = await probeTlsMetadata(probeHost, svc.port, { ...options, ...(!isLiteralIp ? { servername: hostname } : {}) });
        if (tlsInfo?.ok && (tlsInfo.subjectCN || tlsInfo.san)) {
          const certText = `${tlsInfo.subjectCN || ''} ${tlsInfo.san || ''}`;
          if (/samsung|tizen/i.test(certText) && !discoveredMetas.some(m => m.vendor === 'Samsung')) {
            recordDeviceMeta({
              category: 'smart_tv',
              vendor: 'Samsung',
              deviceType: 'Samsung Smart TV (Tizen)',
              deviceName: tlsInfo.subjectCN || `Samsung Smart TV (${hostname})`,
              modelName: tlsInfo.subjectCN || 'Samsung Smart TV',
              os: 'Tizen'
            }, { weight: 10, signal: `tls:${svc.port}:samsung` });
          } else if (/chromecast|google|cast/i.test(certText) && !discoveredMetas.some(m => /google/i.test(m.vendor || ''))) {
            recordDeviceMeta({
              category: 'smart_tv',
              vendor: 'Google / Android TV',
              deviceType: 'Google Cast / Android TV',
              deviceName: tlsInfo.subjectCN || `Google Cast (${hostname})`,
              modelName: tlsInfo.subjectCN || 'Google Cast'
            }, { weight: 10, signal: `tls:${svc.port}:google` });
          } else if (/ubiquiti|unifi/i.test(certText)) {
            recordDeviceMeta({
              category: 'ip_camera',
              vendor: 'Ubiquiti',
              deviceType: 'UniFi Protect NVR / Camera Controller',
              deviceName: tlsInfo.subjectCN || 'UniFi Protect'
            }, { weight: 10, signal: `tls:${svc.port}:unifi` });
          }
        }
      }
    }
  }

  // Dedicated single-vendor port metadata fallback (NEVER on shared/ambiguous ports!)
  if (shouldRunMultiPort && openServices.length > 0) {
    for (const svc of openServices) {
      if (svc.vendor && !svc.sharedPort && !svc.ambiguous && !discoveredMetas.some(m => m.vendor === svc.vendor)) {
        recordDeviceMeta({
          category: svc.category || 'device_web',
          vendor: svc.vendor,
          deviceType: svc.label,
          deviceName: `${svc.vendor} Device (${hostname})`,
          modelName: svc.label
        }, { weight: 5, signal: `port:${svc.port}` });
      }

      // If Samsung DLNA DMR port 9197 is open and no specific HTTP XML path matched on 9197, still report the open DLNA DMR port
      if (svc.port === 9197 && !findings.some(f => f.port === 9197)) {
        const primaryHttpFind = findings.find(f => f.status === 200 && f.url);
        const quote = primaryHttpFind?.evidenceQuote || `Samsung DLNA/UPnP DMR TCP port 9197 open on ${hostname}:9197`;
        findings.push({
          name: 'Samsung Smart TV DLNA / UPnP MediaRenderer Port Exposed (9197/TCP)',
          path: primaryHttpFind?.path || '/api/v2/',
          url: primaryHttpFind?.url || `http://${hostBracketed}:9197/dmr`,
          port: 9197,
          method: 'GET',
          status: 200,
          severity: 'MEDIUM',
          statusTag: 'SUSPICIOUS',
          matchedSignal: 'Samsung DLNA/UPnP MediaRenderer TCP port 9197 open',
          preview: quote,
          evidenceQuote: quote,
          ...(primaryHttpFind?.trafficId !== undefined ? { trafficId: primaryHttpFind.trafficId } : {}),
          reason: `Samsung DLNA / UPnP Digital Media Renderer (DMR) service port 9197/TCP is open on ${hostname}:9197, allowing local network media casting and UPnP control connections.`
        });
      }

      // If companion port 8080 is open on a detected Smart TV and not already reported
      if (svc.port === 8080 && discoveredMetas.some(m => m.category === 'smart_tv') && !findings.some(f => f.port === 8080)) {
        const primaryHttpFind = findings.find(f => f.status === 200 && f.url);
        const quote = primaryHttpFind?.evidenceQuote || `Smart TV companion HTTP service TCP port 8080 open on ${hostname}:8080`;
        findings.push({
          name: 'Smart TV Companion Web / DIAL Service Port Exposed (8080/TCP)',
          path: primaryHttpFind?.path || '/api/v2/',
          url: primaryHttpFind?.url || `http://${hostBracketed}:8080/`,
          port: 8080,
          method: 'GET',
          status: 200,
          severity: 'LOW',
          statusTag: 'SUSPICIOUS',
          matchedSignal: 'Smart TV companion HTTP port 8080 open',
          preview: quote,
          evidenceQuote: quote,
          ...(primaryHttpFind?.trafficId !== undefined ? { trafficId: primaryHttpFind.trafficId } : {}),
          reason: `Smart TV companion HTTP / DIAL service port 8080/TCP is open on ${hostname}:8080 alongside primary TV control ports.`
        });
      }
    }
  }

  if (!anyNetworkSuccess) {
    return {
      ok: false,
      error: 'Target unreachable across standard and device ports',
      findings: [],
      deviceProfile: null
    };
  }

  // Workstation Disambiguation:
  // A macOS/Linux workstation running CUPS (631) or AirPlay Receiver (5000/7000) alongside workstation ports
  // (22, 445, 3389, 135, 139, 5985, 5986, 5900, 5901, 548, 2049, 2375, 11434, dev servers) should classify as pc_workstation.
  const hasWorkstationSignal = (categoryScores.pc_workstation || 0) > 0;
  const hasDedicatedTvSignal = openPorts.some(p => [8001, 8002, 9197, 7676, 8008, 8009, 8060, 9998, 52323, 7345, 1925, 1926, 5555].includes(p)) ||
    discoveredMetas.some(m =>
      m.category === 'smart_tv' &&
      !/airplay|airtunes/i.test(`${m.vendor || ''} ${m.deviceType || ''}`) &&
      !/^port:(?:7000|7100)$/.test(String(m.signal || ''))
    );
  if (hasWorkstationSignal) {
    if ((categoryScores.printer || 0) > 0 && !openPorts.includes(9100)) {
      categoryScores.pc_workstation = Math.max(categoryScores.pc_workstation + 12, (categoryScores.printer || 0) + 8);
      categorySignals.push('disambig:cups_on_workstation');
    }
    if ((categoryScores.smart_tv || 0) > 0 && !hasDedicatedTvSignal) {
      categoryScores.pc_workstation = Math.max(categoryScores.pc_workstation + 12, (categoryScores.smart_tv || 0) + 8);
      categorySignals.push('disambig:airplay_on_workstation');
    }
  }

  // Determine winning category via weighted scoring
  let winningCategory = null;
  let bestScore = -1;
  for (const cat of CATEGORY_PRIORITY_LIST) {
    const sc = categoryScores[cat] || 0;
    if (sc > bestScore && sc > 0) {
      bestScore = sc;
      winningCategory = cat;
    }
  }
  for (const [cat, sc] of Object.entries(categoryScores)) {
    if (sc > bestScore) {
      bestScore = sc;
      winningCategory = cat;
    }
  }

  // Emit cleartext HTTP admin UI warning if confirmed IP camera is served over http:// without prior cleartext finding
  if (winningCategory === 'ip_camera' && responsiveHttpOrigins.length > 0 && !findings.some(f => /cleartext http/i.test(f.name))) {
    const httpUrl = responsiveHttpOrigins[0];
    let httpPort = 80;
    try { httpPort = Number(new URL(httpUrl).port) || 80; } catch {}
    if (!findings.some(f => f.port === httpPort && /cleartext/i.test(f.name))) {
      findings.push({
        name: `IP Camera / NVR Cleartext HTTP Admin Interface (${httpPort}/TCP)`,
        path: '/',
        url: `${httpUrl}/`,
        port: httpPort,
        method: 'GET',
        status: 200,
        severity: 'MEDIUM',
        statusTag: 'SUSPICIOUS',
        matchedSignal: `Cleartext HTTP IP camera web interface on ${httpUrl}`,
        preview: `Cleartext HTTP admin service on ${httpUrl}`,
        evidenceQuote: `Cleartext HTTP admin service on ${httpUrl}`,
        reason: `IP camera/NVR web management interface is accessible over unencrypted HTTP at ${httpUrl}, exposing video streams and administrative credentials on the local network.`
      });
    }
  }

  // Sort discoveredMetas so the winning category + highest weight metadata fills primary fields
  const rankedMetas = discoveredMetas.slice().sort((a, b) => {
    const aMatch = a.category === winningCategory ? 1 : 0;
    const bMatch = b.category === winningCategory ? 1 : 0;
    if (aMatch !== bMatch) return bMatch - aMatch;
    return (b.weight || 0) - (a.weight || 0);
  });

  const primaryMeta = rankedMetas[0] || null;
  const mergedMeta = rankedMetas.reduce(
    (acc, cur) => ({
      category: acc.category || cur.category,
      vendor: acc.vendor || cur.vendor,
      deviceType: acc.deviceType || cur.deviceType,
      deviceName: acc.deviceName || cur.deviceName,
      modelName: acc.modelName || cur.modelName,
      os: acc.os || cur.os,
      osFamily: acc.osFamily || cur.osFamily,
      firmwareVersion: acc.firmwareVersion || cur.firmwareVersion,
      macAddress: acc.macAddress || cur.macAddress,
      serialNumber: acc.serialNumber || cur.serialNumber,
      udn: acc.udn || cur.udn,
      ssid: acc.ssid || cur.ssid,
      networkType: acc.networkType || cur.networkType,
      resolution: acc.resolution || cur.resolution,
      countryCode: acc.countryCode || cur.countryCode,
      tokenAuthSupport: acc.tokenAuthSupport !== undefined ? acc.tokenAuthSupport : cur.tokenAuthSupport
    }),
    {}
  );

  // Infer osFamily if pc_workstation
  let osFamily = mergedMeta.osFamily || null;
  if (!osFamily && winningCategory === 'pc_workstation') {
    if (openPorts.some(p => [445, 139, 135, 3389, 5985, 5986, 5357].includes(p))) {
      osFamily = 'Windows';
    } else if (openPorts.includes(548) || (openPorts.includes(7000) && openPorts.includes(631))) {
      osFamily = 'macOS';
    } else if (openPorts.some(p => [22, 2049, 111, 873, 2375].includes(p))) {
      osFamily = 'Linux';
    }
  }

  const detected = Boolean(primaryMeta || findings.length > 0 || openPorts.some(p => p !== 80 && p !== 443));
  const category = winningCategory || mergedMeta.category || (detected ? 'device_web' : null);
  const categoryLabel = category ? (DEVICE_CATEGORIES[category] || 'Network Device') : null;

  const activeHttpOrigin =
    responsiveHttpOrigins[0] ||
    tcpHttpOrigins.find(o => !trippedOrigins.has(o)) ||
    (!basePortClosed && parsedUrl.protocol === 'http:' && !trippedOrigins.has(baseOrigin) ? baseOrigin : null);
  const activeHttpsOrigin =
    responsiveHttpsOrigins[0] ||
    tcpHttpsOrigins.find(o => !trippedOrigins.has(o)) ||
    (!basePortClosed && parsedUrl.protocol === 'https:' && !trippedOrigins.has(baseOrigin) ? baseOrigin : null);

  const summaryParts = [];
  if (mergedMeta.deviceType) {
    summaryParts.push(mergedMeta.deviceType);
  } else if (mergedMeta.vendor) {
    summaryParts.push(`${mergedMeta.vendor} Device`);
  } else if (detected) {
    summaryParts.push(categoryLabel || 'Network Device');
  }
  if (mergedMeta.modelName && !summaryParts.join(' ').includes(mergedMeta.modelName)) {
    summaryParts.push(`(${mergedMeta.modelName})`);
  }
  if (mergedMeta.deviceName && mergedMeta.deviceName !== mergedMeta.modelName && !summaryParts.join(' ').includes(mergedMeta.deviceName)) {
    summaryParts.push(`"${mergedMeta.deviceName}"`);
  }
  if (openPorts.length > 0) {
    summaryParts.push(`[Open Ports: ${openPorts.join(', ')}]`);
  }

  const deviceProfile = detected
    ? {
        detected: true,
        host: hostname,
        category,
        categoryLabel,
        vendor: mergedMeta.vendor || 'Unknown',
        deviceType: mergedMeta.deviceType || categoryLabel || 'Network Device',
        deviceName: mergedMeta.deviceName || mergedMeta.modelName || hostname,
        modelName: mergedMeta.modelName || null,
        os: mergedMeta.os || osFamily || null,
        osFamily,
        firmwareVersion: mergedMeta.firmwareVersion || null,
        macAddress: mergedMeta.macAddress || null,
        serialNumber: mergedMeta.serialNumber || null,
        udn: mergedMeta.udn || null,
        ssid: mergedMeta.ssid || null,
        networkType: mergedMeta.networkType || null,
        resolution: mergedMeta.resolution || null,
        countryCode: mergedMeta.countryCode || null,
        tokenAuthSupport: mergedMeta.tokenAuthSupport ?? null,
        openPorts,
        openServices: openServices.map(s => ({
          port: s.port,
          scheme: s.scheme,
          service: s.service,
          label: s.label,
          category: s.category,
          vendor: s.vendor || null,
          ...(s.banner ? { banner: s.banner } : {})
        })),
        basePortClosed,
        activeHttpOrigin,
        activeHttpsOrigin,
        categorySignals,
        summary: summaryParts.join(' ') || 'Network / IoT Device'
      }
    : null;

  return {
    ok: true,
    findings,
    deviceProfile,
    primaryResponse,
    ...(options.quickFingerprint ? { isQuickFingerprint: true } : {})
  };
}
