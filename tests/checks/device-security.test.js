import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { mockFetch, mockFetchMap, mockFetchError } from '../helpers/mock-fetch.js';
import runDeviceCheck, { meta, tags } from '../../checks/device-security.js';
import {
  scanDeviceTarget,
  probeDevicePorts,
  probeTlsMetadata,
  analyzeDeviceHttpResponse,
  normalizeDeviceCategory,
  DEVICE_PORT_CATALOG,
  DEVICE_CATEGORIES,
  DEVICE_CATEGORY_ALIASES
} from '../../core/device-scanner.js';
import { fingerprint } from '../../core/fingerprint.js';
import { selectScannersForStack, getProfileChecks } from '../../core/profiles.js';
import { getScanners } from '../../core/registry.js';
import { fetchWithRetry, createGovernedFetch } from '../../core/fetch.js';
import { createTrackedFetch } from '../../core/reproduction.js';
import { verifyFindingBeforeReport } from '../../core/check-verify.js';

const BASE = 'https://example.com';

test('device-security: exports valid metadata and tags', () => {
  assert.equal(meta.id, 'device-security');
  assert.ok(tags.includes('device'));
  assert.ok(tags.includes('tv'));
  assert.ok(tags.includes('iot'));
  assert.ok(DEVICE_PORT_CATALOG.length >= 30);
  assert.ok(DEVICE_CATEGORIES.smart_tv);
});

test('device-security: returns SAFE on normal website and SPA HTML 200 catch-all', async () => {
  const normalRes = await runDeviceCheck(BASE, mockFetch({
    status: 200,
    headers: { 'content-type': 'text/html' },
    text: '<!DOCTYPE html><html><head><title>Corporate Site</title></head><body>Welcome</body></html>'
  }));
  assert.equal(normalRes.status, 'SAFE');
  assert.equal(normalRes.severity, 'NONE');
});

test('device-security: returns ERROR when target is completely unreachable or blocked by SSRF policy', async () => {
  const errRes = await runDeviceCheck(BASE, mockFetchError('connect ECONNREFUSED'), { deviceMode: true });
  assert.equal(errRes.status, 'ERROR');

  const lanErrRes = await runDeviceCheck('http://192.168.68.53', mockFetchError('connect ECONNREFUSED'), {
    allowPrivate: true
  });
  assert.equal(lanErrRes.status, 'ERROR');

  const ssrfRes = await runDeviceCheck('http://192.168.68.53', mockFetch({ status: 200, text: 'OK' }), {
    allowPrivate: false
  });
  assert.equal(ssrfRes.status, 'ERROR');
  assert.ok(ssrfRes.reason.includes('SSRF policy'));
});

test('device-security: skips multi-port LAN sweep and returns SAFE on public hosts without deviceMode', async () => {
  let fetchCalled = 0;
  let tcpCalled = 0;
  const publicIpRes = await runDeviceCheck('http://104.21.43.139', async () => {
    fetchCalled++;
    return { status: 403, headers: { server: 'cloudflare' }, text: 'Direct IP access not allowed' };
  }, {
    allowPrivate: true,
    tcpProbe: async () => {
      tcpCalled++;
      return { open: true };
    }
  });
  assert.equal(publicIpRes.status, 'SAFE');
  assert.equal(publicIpRes.severity, 'NONE');
  assert.equal(publicIpRes.reason, 'Target is a public host without device scan mode enabled; multi-port LAN device discovery skipped.');
  assert.equal(fetchCalled, 0);
  assert.equal(tcpCalled, 0);

  const publicDomainRes = await runDeviceCheck(BASE, mockFetchError('connect ECONNREFUSED'));
  assert.equal(publicDomainRes.status, 'SAFE');
  assert.equal(publicDomainRes.reason, 'Target is a public host without device scan mode enabled; multi-port LAN device discovery skipped.');

  // Explicit deviceMode: true on a public IP DOES execute device discovery
  const explicitDeviceRes = await runDeviceCheck('http://104.21.43.139', async (url) => {
    if (url === 'http://104.21.43.139/ISAPI/System/deviceInfo') {
      return {
        status: 200,
        headers: { 'content-type': 'application/xml' },
        text: '<DeviceInfo><model>DS-2CD2143</model></DeviceInfo>'
      };
    }
    return { status: 404, headers: {}, text: '' };
  }, {
    deviceMode: true,
    deviceCategory: 'ip_camera',
    tcpProbe: async (_h, p) => ({ port: p, open: p === 80 || p === 554 })
  });
  assert.equal(explicitDeviceRes.status, 'VULNERABLE');
  assert.equal(explicitDeviceRes.deviceCategory, 'ip_camera');
});

test('device-security: detects Samsung Smart TV (Tizen) multi-port exposure when port 80 is closed (192.168.68.53 scenario)', async () => {
  const tvIp = '192.168.68.53';
  const targetUrl = `http://${tvIp}`;
  const openSet = new Set([8001, 8002, 8080, 9197]);

  const tcpProbe = async (_host, port) => ({
    port,
    open: openSet.has(port)
  });

  const samsungApiPayload = JSON.stringify({
    device: {
      FrameTVSupport: 'false',
      GamePadSupport: 'true',
      ImeSyncedSupport: 'true',
      OS: 'Tizen',
      TokenAuthSupport: 'true',
      VoiceSupport: 'true',
      countryCode: 'US',
      description: 'Samsung DTV RCR',
      developerIP: '0.0.0.0',
      developerMode: '0',
      duid: 'uuid:12345678-90ab-cdef-1234-567890abcdef',
      firmwareVersion: 'Unknown',
      id: 'uuid:12345678-90ab-cdef-1234-567890abcdef',
      ip: tvIp,
      model: '23_EXHIBITION',
      modelName: 'UN55TU7000FXZA',
      name: '[TV] Samsung 7 Series (55)',
      networkType: 'wireless',
      resolution: '3840x2160',
      smartHubAgreement: 'true',
      tokenAuthSupport: 'false',
      type: 'Samsung SmartTV',
      udn: 'uuid:12345678-90ab-cdef-1234-567890abcdef',
      wifiMac: 'AA:BB:CC:DD:EE:FF'
    },
    id: 'uuid:12345678-90ab-cdef-1234-567890abcdef',
    isSupport: '{"DMP_DRM_PLAYREADY":"false","DMP_DRM_WIDEVINE":"false","DMP_available":"true","EDEN_available":"true","FrameTVSupport":"false","ImeSyncedSupport":"true","TokenAuthSupport":"true","remote_available":"true","remote_fourDirections":"true","remote_touchPad":"true","remote_voiceControl":"true"}',
    name: '[TV] Samsung 7 Series (55)',
    remote: '1.0',
    type: 'Samsung SmartTV',
    uri: `http://${tvIp}:8001/api/v2/`,
    version: '2.0.25'
  });

  const dmrXml = `<?xml version="1.0"?>
  <root xmlns="urn:schemas-upnp-org:device-1-0">
    <device>
      <deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
      <friendlyName>[TV] Samsung 7 Series (55)</friendlyName>
      <manufacturer>Samsung Electronics</manufacturer>
      <modelName>UN55TU7000FXZA</modelName>
      <UDN>uuid:12345678-90ab-cdef-1234-567890abcdef</UDN>
      <serviceList>
        <service>
          <serviceType>urn:schemas-upnp-org:service:AVTransport:1</serviceType>
        </service>
        <service>
          <serviceType>urn:schemas-upnp-org:service:RenderingControl:1</serviceType>
        </service>
      </serviceList>
    </device>
  </root>`;

  const customFetch = async (url) => {
    if (url === `http://${tvIp}:8001/api/v2/` || url === `https://${tvIp}:8002/api/v2/`) {
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        text: samsungApiPayload,
        trafficId: 'tx-samsung-8001'
      };
    }
    if (url === `http://${tvIp}:9197/dmr`) {
      return {
        status: 200,
        headers: { 'content-type': 'text/xml' },
        text: dmrXml,
        trafficId: 'tx-samsung-9197'
      };
    }
    if (url.startsWith(`http://${tvIp}:8080`)) {
      return {
        status: 404,
        headers: { server: 'Tizen' },
        text: 'Not Found'
      };
    }
    throw new Error('connect ECONNREFUSED');
  };

  const res = await runDeviceCheck(targetUrl, customFetch, {
    allowPrivate: true,
    tcpProbe
  });

  assert.equal(res.status, 'VULNERABLE');
  assert.equal(res.severity, 'HIGH');
  assert.ok(res.device);
  assert.equal(res.device.vendor, 'Samsung');
  assert.equal(res.device.modelName, 'UN55TU7000FXZA');
  assert.equal(res.device.os, 'Tizen');
  assert.equal(res.device.macAddress, 'AA:BB:CC:DD:EE:FF');
  assert.equal(res.device.basePortClosed, true);
  assert.deepEqual(res.openPorts, [8001, 8002, 9197, 8080]);
  assert.ok(res.files.some(f => f.name.includes('Samsung Smart TV (Tizen) SmartView HTTP API')));
  assert.ok(res.files.some(f => f.name.includes('Token Authentication Disabled')));
  assert.ok(res.files.some(f => f.name.includes('UPnP / DLNA MediaRenderer')));
  assert.ok(res.files.some(f => f.port === 8080));
  assert.ok(res.evidenceQuotes.length >= 2);
  assert.ok(res.fix.includes('Samsung Smart TV'));

  // Also test fingerprint fallback when port 80 is closed on 192.168.68.53
  const fp = await fingerprint(targetUrl, customFetch, {
    allowPrivate: true,
    tcpProbe
  });
  assert.equal(fp.primary, 'device');
  assert.equal(fp.recommendedProfile, 'device');
  assert.ok(fp.detectedTags.includes('device'));
  assert.ok(fp.detectedTags.includes('tv'));
  assert.ok(fp.deviceInfo);
  assert.equal(fp.deviceInfo.modelName, 'UN55TU7000FXZA');
  assert.equal(fp.deviceInfo.activeHttpOrigin, `http://${tvIp}:8001`);
  assert.equal(fp.deviceInfo.activeHttpsOrigin, `https://${tvIp}:8002`);
});

test('device-security: detects Roku TV ECP (/query/device-info, /query/apps) and developer mode', async () => {
  const rokuFetch = mockFetchMap({
    '/query/device-info': {
      status: 200,
      headers: { 'content-type': 'text/xml' },
      text: `<device-info>
        <udn>29a00000-0000-1000-8000-000000000001</udn>
        <serial-number>YN00AA123456</serial-number>
        <vendor-name>TCL</vendor-name>
        <model-name>55S425</model-name>
        <user-device-name>Living Room Roku TV</user-device-name>
        <software-version>12.5.0</software-version>
        <wifi-mac>11:22:33:44:55:66</wifi-mac>
        <network-name>HomeWiFi_5G</network-name>
        <developer-enabled>true</developer-enabled>
      </device-info>`
    },
    '/query/apps': {
      status: 200,
      headers: { 'content-type': 'text/xml' },
      text: `<apps><app id="12" type="appl" version="5.1">Netflix</app><app id="837" type="appl" version="2.2">YouTube</app></apps>`
    }
  });

  const res = await runDeviceCheck('http://192.168.1.50:8060', rokuFetch, { allowPrivate: true });
  assert.equal(res.status, 'VULNERABLE');
  assert.equal(res.severity, 'HIGH');
  assert.equal(res.device.vendor, 'TCL');
  assert.equal(res.device.modelName, '55S425');
  assert.equal(res.device.serialNumber, 'YN00AA123456');
  assert.equal(res.device.ssid, 'HomeWiFi_5G');
  assert.ok(res.files.some(f => f.name.includes('Roku TV Unauthenticated External Control Protocol')));
  assert.ok(res.files.some(f => f.name.includes('Roku TV Developer Mode Enabled')));
  assert.ok(res.files.some(f => f.name.includes('Roku TV Installed Channels')));
});

test('device-security: detects Google Cast / Android TV eureka_info and critical ADB port 5555', async () => {
  const castFetch = mockFetchMap({
    '/setup/eureka_info': {
      status: 200,
      headers: { 'content-type': 'application/json' },
      text: JSON.stringify({
        name: 'Bedroom Google TV',
        model_name: 'Chromecast Google TV',
        ssdp_udn: '11112222-3333-4444-5555-666677778888',
        mac_address: 'AA:11:BB:22:CC:33',
        hotspot_bssid: 'FF:EE:DD:CC:BB:AA',
        ssid: 'MyHomeNet',
        build_info: { cast_build_revision: '1.68.374976' }
      })
    }
  });

  const tcpProbe = async (_host, port) => ({
    port,
    open: port === 8008 || port === 5555
  });

  const res = await runDeviceCheck('http://192.168.1.60', castFetch, {
    allowPrivate: true,
    tcpProbe
  });
  assert.equal(res.status, 'VULNERABLE');
  assert.equal(res.severity, 'CRITICAL');
  assert.ok(res.files.some(f => f.name.includes('Google Cast / Android TV Unauthenticated Eureka Info')));
  assert.ok(res.files.some(f => f.name.includes('Exposed Android Debug Bridge (ADB over Wi-Fi / TCP 5555)')));
  assert.ok(res.fix.includes('ADB (5555/TCP)'));
});

test('device-security: detects Tasmota IoT relay, UPnP IGD router, JetDirect printer 9100, and Telnet 23', async () => {
  const iotFetch = mockFetchMap({
    '/cm?cmnd=Status%200': {
      status: 200,
      headers: { 'content-type': 'application/json' },
      text: JSON.stringify({
        Status: { DeviceName: 'Tasmota', FriendlyName: ['SmartPlug1'] },
        StatusFWR: { Version: '13.4.0(tasmota)' },
        StatusNET: { Mac: 'DC:4F:22:11:22:33', IPAddress: '192.168.1.70' }
      })
    },
    '/rootDesc.xml': {
      status: 200,
      headers: { 'content-type': 'text/xml' },
      text: `<root xmlns="urn:schemas-upnp-org:device-1-0">
        <device>
          <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
          <friendlyName>TP-Link Deco Router</friendlyName>
          <manufacturer>TP-Link</manufacturer>
          <modelName>Deco X60</modelName>
          <serviceList>
            <service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType></service>
          </serviceList>
        </device>
      </root>`
    }
  });

  const tcpProbe = async (_host, port) => ({
    port,
    open: port === 80 || port === 23 || port === 9100 || port === 1883
  });

  const res = await runDeviceCheck('http://192.168.1.70', iotFetch, {
    allowPrivate: true,
    tcpProbe
  });
  assert.equal(res.status, 'VULNERABLE');
  assert.equal(res.severity, 'CRITICAL');
  assert.ok(res.files.some(f => f.name.includes('Unauthenticated Tasmota IoT Control')));
  assert.ok(res.files.some(f => f.name.includes('UPnP IGD Router WAN Port-Forwarding')));
  assert.ok(res.files.some(f => f.name.includes('Telnet Cleartext Remote Shell')));
  assert.ok(res.files.some(f => f.name.includes('HP JetDirect / RAW Network Printer')));
  assert.ok(res.files.some(f => f.name.includes('MQTT IoT Message Broker')));
});

test('device-security: selectScannersForStack selects device-security under device, tv, iot, and smart profiles', async () => {
  const scanners = await getScanners();
  for (const prof of ['device', 'tv', 'iot', 'camera', 'ip-camera', 'pc', 'workstation', 'lan']) {
    const sel = selectScannersForStack(scanners, { profile: prof });
    const names = sel.activeScanners.map(s => s.name);
    assert.ok(names.includes('device-security'), `Expected ${prof} profile to include device-security`);
    assert.ok(names.includes('ssl-tls'));
    assert.ok(!names.includes('wp-checks'));
  }
  assert.deepEqual(getProfileChecks('camera'), getProfileChecks('device'));
  assert.deepEqual(getProfileChecks('pc_workstation'), getProfileChecks('device'));
});

test('device-security: normalizes category aliases and filters probeDevicePorts by deviceCategory', async () => {
  assert.equal(DEVICE_CATEGORIES.pc_workstation, 'PC, Workstation & Local Server');
  assert.equal(DEVICE_CATEGORY_ALIASES.camera, 'ip_camera');
  assert.equal(normalizeDeviceCategory('smart-tv'), 'smart_tv');
  assert.equal(normalizeDeviceCategory('NVR'), 'ip_camera');
  assert.equal(normalizeDeviceCategory('workstation'), 'pc_workstation');
  assert.equal(normalizeDeviceCategory('unknown-cat'), 'all');

  const camPorts = [];
  await probeDevicePorts('192.168.1.10', {
    deviceCategory: 'ip_camera',
    tcpProbe: async (_h, p) => { camPorts.push(p); return false; }
  });
  assert.ok(camPorts.includes(554));
  assert.ok(camPorts.includes(8554));
  assert.ok(camPorts.includes(37777));
  assert.ok(camPorts.includes(8081));
  assert.ok(!camPorts.includes(8060));
  assert.ok(!camPorts.includes(3389));

  const pcPorts = [];
  await probeDevicePorts('192.168.1.20', {
    deviceCategory: 'pc_workstation',
    tcpProbe: async (_h, p) => { pcPorts.push(p); return false; }
  });
  assert.ok(pcPorts.includes(445));
  assert.ok(pcPorts.includes(3389));
  assert.ok(pcPorts.includes(22));
  assert.ok(pcPorts.includes(2375));
  assert.ok(pcPorts.includes(11434));
  assert.ok(pcPorts.includes(8081));
  assert.ok(!pcPorts.includes(8060));
  assert.ok(!pcPorts.includes(37777));
});

test('device-security: filters device_web HTTP probe paths by requested deviceCategory', async () => {
  const tvRequestedPaths = [];
  await scanDeviceTarget('http://192.168.1.40', async (url) => {
    tvRequestedPaths.push(new URL(url).pathname + new URL(url).search);
    return { status: 404, headers: {}, text: '' };
  }, {
    allowPrivate: true,
    deviceMode: true,
    deviceCategory: 'smart_tv',
    tcpProbe: async (_h, p) => ({ port: p, open: p === 80 || p === 8080 })
  });
  assert.ok(tvRequestedPaths.includes('/api/v2/'));
  assert.ok(tvRequestedPaths.includes('/setup/eureka_info'));
  assert.ok(!tvRequestedPaths.includes('/ISAPI/System/deviceInfo'));
  assert.ok(!tvRequestedPaths.includes('/onvif/device_service'));
  assert.ok(!tvRequestedPaths.includes('/snapshot.jpg'));

  const camRequestedPaths = [];
  await scanDeviceTarget('http://192.168.1.41', async (url) => {
    camRequestedPaths.push(new URL(url).pathname + new URL(url).search);
    return { status: 404, headers: {}, text: '' };
  }, {
    allowPrivate: true,
    deviceMode: true,
    deviceCategory: 'ip_camera',
    tcpProbe: async (_h, p) => ({ port: p, open: p === 80 || p === 8080 || p === 8081 })
  });
  assert.ok(camRequestedPaths.includes('/ISAPI/System/deviceInfo'));
  assert.ok(camRequestedPaths.includes('/onvif/device_service'));
  assert.ok(!camRequestedPaths.includes('/api/v2/'));
  assert.ok(!camRequestedPaths.includes('/setup/eureka_info'));
  assert.ok(!camRequestedPaths.includes('/dmr'));

  const pcRequestedPaths = [];
  await scanDeviceTarget('http://192.168.1.42', async (url) => {
    pcRequestedPaths.push(new URL(url).pathname + new URL(url).search);
    return { status: 404, headers: {}, text: '' };
  }, {
    allowPrivate: true,
    deviceMode: true,
    deviceCategory: 'pc_workstation',
    tcpProbe: async (_h, p) => ({ port: p, open: p === 80 || p === 8080 || p === 8081 })
  });
  assert.ok(pcRequestedPaths.includes('/'));
  assert.ok(!pcRequestedPaths.includes('/api/v2/'));
  assert.ok(!pcRequestedPaths.includes('/ISAPI/System/deviceInfo'));
  assert.ok(!pcRequestedPaths.includes('/onvif/device_service'));
});

test('device-security: M1 Caveat 2 + quoted/backslash input + loopback createTrackedFetch(fetchWithRetry) with allowPrivate: true', async () => {
  const server = http.createServer((req, res) => {
    if (req.url === '/api/v2/') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        device: {
          type: 'Samsung SmartTV',
          OS: 'Tizen',
          modelName: 'QN65S90C',
          name: 'Den Samsung TV',
          tokenAuthSupport: 'false',
          wifiMac: 'AA:BB:CC:11:22:33'
        }
      }));
      return;
    }
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();

  try {
    const trackedFetch = createTrackedFetch(fetchWithRetry);
    const res = await runDeviceCheck(`"http://127.0.0.1:${port}\\"`, trackedFetch, {
      allowPrivate: true,
      ports: [port],
      multiPort: true,
      probeTimeoutMs: 800
    });
    assert.equal(res.status, 'VULNERABLE');
    assert.equal(res.deviceCategory, 'smart_tv');
    assert.equal(res.device.vendor, 'Samsung');
    assert.equal(res.device.modelName, 'QN65S90C');
    assert.ok(trackedFetch.getTraces().length >= 1);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('device-security: fast completion (<1.5s) on quoted/backslash input with blackholed ports and per-origin circuit breaker + cachedDeviceScan', async () => {
  const ip = '192.168.68.53';
  const openSet = new Set([8001, 8002, 8080, 9197]);
  let probes8080 = 0;

  const slowBlackholeFetch = async (url, opts = {}) => {
    if (url.startsWith(`http://${ip}:8001/api/v2/`)) {
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        text: JSON.stringify({
          device: { type: 'Samsung SmartTV', OS: 'Tizen', modelName: 'UN55TU7000', name: 'TV', tokenAuthSupport: 'false' }
        })
      };
    }
    if (url.startsWith(`http://${ip}:8080`)) {
      probes8080++;
      throw new Error('connect ETIMEDOUT');
    }
    if (url.startsWith(`https://${ip}:8002`)) {
      throw new Error('ECONNREFUSED');
    }
    throw new Error('ECONNREFUSED');
  };

  const t0 = Date.now();
  const res = await runDeviceCheck(`"${ip}\\"`, slowBlackholeFetch, {
    allowPrivate: true,
    probeTimeoutMs: 250,
    portTimeoutMs: 150,
    tcpProbe: async (_h, port) => ({ port, open: openSet.has(port) })
  });
  const elapsed = Date.now() - t0;

  assert.ok(elapsed < 1500, `Expected scan to complete under 1500ms, took ${elapsed}ms`);
  assert.equal(res.status, 'VULNERABLE');
  assert.equal(res.deviceCategory, 'smart_tv');
  assert.equal(res.device.host, ip);
  // Circuit breaker must trip after the first failure on :8080 and skip remaining :8080 paths
  assert.equal(probes8080, 1);

  // cachedDeviceScan full reuse must not re-run tcpProbe or fetch
  let probeCalled = false;
  const rawScan = await scanDeviceTarget(ip, slowBlackholeFetch, {
    allowPrivate: true,
    tcpProbe: async (_h, port) => ({ port, open: openSet.has(port) })
  });
  const cachedRes = await scanDeviceTarget(ip, async () => { throw new Error('Should not fetch'); }, {
    allowPrivate: true,
    cachedDeviceScan: rawScan,
    tcpProbe: async () => { probeCalled = true; return false; }
  });
  assert.equal(cachedRes.fromCache, true);
  assert.equal(probeCalled, false);
  assert.equal(cachedRes.deviceProfile.category, 'smart_tv');
});

test('device-security: detects LG webOS (404/426 WS), Google Cast TLS 8009, Sony Bravia, Vizio, Philips, AirPlay & DIAL Smart TVs', async () => {
  // 1. LG webOS returning 404 on 3000 with WebOS Server header + 9998 dev mode
  const lgFetch = async (url) => {
    if (url === 'http://192.168.1.80:3000/') {
      return { status: 404, headers: { server: 'WebOS/4.0' }, text: '404 Not Found' };
    }
    if (url === 'http://192.168.1.80:9998/') {
      return { status: 400, headers: {}, text: 'Bad Request' };
    }
    throw new Error('ECONNREFUSED');
  };
  const lgRes = await runDeviceCheck('http://192.168.1.80', lgFetch, {
    allowPrivate: true,
    tcpProbe: async (_h, p) => ({ port: p, open: p === 3000 || p === 9998 })
  });
  assert.equal(lgRes.status, 'VULNERABLE');
  assert.equal(lgRes.deviceCategory, 'smart_tv');
  assert.equal(lgRes.device.vendor, 'LG');
  assert.ok(lgRes.files.some(f => f.port === 3000));
  assert.ok(lgRes.files.some(f => f.port === 9998));
  const verifiedLg = verifyFindingBeforeReport(lgRes, { capturedTraces: [] });
  assert.equal(verifiedLg.status, 'VULNERABLE');

  // 2. Google Cast TLS 8009 + DIAL Application-URL
  const castRes = await runDeviceCheck('http://192.168.1.81', async (url) => {
    if (url === 'http://192.168.1.81:8008/apps') {
      return {
        status: 200,
        headers: { 'application-url': 'http://192.168.1.81:8008/apps/' },
        text: '<service xmlns="urn:dial-multiscreen-org:schemas:dial"><name>YouTube</name></service>'
      };
    }
    return { status: 404, headers: {}, text: '' };
  }, {
    allowPrivate: true,
    tcpProbe: async (_h, p) => ({ port: p, open: p === 8008 || p === 8009 }),
    tlsProbe: async (_h, port) => ({ ok: true, port, protocol: 'TLSv1.2', subjectCN: 'Chromecast Living Room', issuerCN: 'Chromecast' })
  });
  assert.equal(castRes.deviceCategory, 'smart_tv');
  assert.ok(castRes.files.some(f => f.port === 8009 && f.method === 'TCP'));
  assert.ok(castRes.files.some(f => f.name.includes('DIAL')));

  // 3. Sony Bravia POST /sony/system + Vizio SmartCast + Philips 401 + AirPlay bplist00
  const sonyRes = await runDeviceCheck('http://192.168.1.82', async (url, opts) => {
    if (url === 'http://192.168.1.82:52323/sony/system' && opts?.method === 'POST') {
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        text: JSON.stringify({ id: 1, result: [{ product: 'BRAVIA', name: 'BRAVIA XR', model: 'XR-65A80L', macAddr: '00:11:22:33:44:55', serial: 'SN-SONY-1' }] })
      };
    }
    return { status: 404, headers: {}, text: '' };
  }, {
    allowPrivate: true,
    tcpProbe: async (_h, p) => ({ port: p, open: p === 52323 })
  });
  assert.equal(sonyRes.status, 'VULNERABLE');
  assert.equal(sonyRes.device.vendor, 'Sony');
  assert.equal(sonyRes.device.modelName, 'XR-65A80L');

  const vizioRes = await runDeviceCheck('http://192.168.1.83', async (url) => {
    if (url === 'https://192.168.1.83:7345/state/device/power_mode') {
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        text: JSON.stringify({ STATUS: { RESULT: 'SUCCESS' }, ITEMS: [{ VALUE: 1 }] })
      };
    }
    return { status: 404, headers: {}, text: '' };
  }, {
    allowPrivate: true,
    tcpProbe: async (_h, p) => ({ port: p, open: p === 7345 })
  });
  assert.equal(vizioRes.status, 'VULNERABLE');
  assert.equal(vizioRes.device.vendor, 'Vizio');

  const philipsRes = await runDeviceCheck('http://192.168.1.84', async (url) => {
    if (url === 'http://192.168.1.84:1925/6/system') {
      return { status: 401, headers: { 'www-authenticate': 'Digest realm="Philips TV"' }, text: '' };
    }
    return { status: 404, headers: {}, text: '' };
  }, {
    allowPrivate: true,
    tcpProbe: async (_h, p) => ({ port: p, open: p === 1925 })
  });
  assert.equal(philipsRes.deviceCategory, 'smart_tv');
  assert.equal(philipsRes.device.vendor, 'Philips');

  const airplayRes = await runDeviceCheck('http://192.168.1.85', async (url) => {
    if (url === 'http://192.168.1.85:7000/info') {
      return { status: 200, headers: { server: 'AirTunes/715.8.1', 'content-type': 'application/x-apple-binary-plist' }, text: 'bplist00\u0001\u0002' };
    }
    return { status: 404, headers: {}, text: '' };
  }, {
    allowPrivate: true,
    tcpProbe: async (_h, p) => ({ port: p, open: p === 7000 })
  });
  assert.equal(airplayRes.deviceCategory, 'smart_tv');
  assert.ok(airplayRes.device.vendor.includes('Apple'));
});

test('device-security: detects IP Cameras / NVRs (RTSP, ONVIF SOAP, Hikvision 401/ISAPI, Dahua, Axis, Xiongmai, UniFi, Snapshot) with zero credentials', async () => {
  const capturedRequests = [];
  const camFetch = async (url, opts = {}) => {
    capturedRequests.push({ url, opts });
    if (url === 'http://192.168.1.90/ISAPI/System/deviceInfo') {
      return {
        status: 200,
        headers: { server: 'App-webs/', 'content-type': 'application/xml' },
        text: '<DeviceInfo><deviceName>Front Door Cam</deviceName><model>DS-2CD2143G2-I</model><serialNumber>DS2CD001</serialNumber><firmwareVersion>V5.7.1</firmwareVersion></DeviceInfo>'
      };
    }
    if (url === 'http://192.168.1.90/SDK/activateStatus') {
      return { status: 200, headers: { 'content-type': 'application/xml' }, text: '<ActivateStatus><Activated>false</Activated></ActivateStatus>' };
    }
    if (url === 'http://192.168.1.90/onvif/device_service' && opts.method === 'POST') {
      return {
        status: 200,
        headers: { 'content-type': 'application/soap+xml' },
        text: '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><tds:GetSystemDateAndTimeResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><tds:SystemDateAndTime><tt:UTCDateTime/></tds:SystemDateAndTime></tds:GetSystemDateAndTimeResponse></s:Body></s:Envelope>'
      };
    }
    if (url === 'http://192.168.1.90/snapshot.jpg') {
      return { status: 200, headers: { 'content-type': 'image/jpeg' }, text: '\xff\xd8\xff\xe0JPEG' };
    }
    if (url === 'http://192.168.1.90/') {
      return { status: 401, headers: { server: 'App-webs/', 'www-authenticate': 'Basic realm="Hikvision Camera"' }, text: 'Unauthorized' };
    }
    return { status: 404, headers: { server: 'App-webs/' }, text: 'Not Found' };
  };

  const res = await runDeviceCheck('http://192.168.1.90', camFetch, {
    allowPrivate: true,
    tcpProbe: async (_h, p) => ({ port: p, open: p === 80 || p === 554 || p === 8000 }),
    rtspProbe: async (_h, port) => ({
      ok: true,
      port,
      status: 200,
      server: 'Hikvision RTSP',
      describeStatus: 200,
      hasSdp: true,
      sdpSnippet: 'v=0\nm=video 0 RTP/AVP 96',
      unauthenticatedStream: true
    })
  });

  assert.equal(res.status, 'VULNERABLE');
  assert.equal(res.severity, 'CRITICAL');
  assert.equal(res.deviceCategory, 'ip_camera');
  assert.equal(res.device.category, 'ip_camera');
  assert.equal(res.device.vendor, 'Hikvision');
  assert.ok(res.files.some(f => f.name.includes('Unactivated Hikvision')));
  assert.ok(res.files.some(f => f.name.includes('Unauthenticated RTSP Live Video Stream') && f.method === 'RTSP'));
  assert.ok(res.files.some(f => f.name.includes('ONVIF IP Camera Unauthenticated')));
  assert.ok(res.files.some(f => f.name.includes('Live Camera Snapshot')));
  assert.ok(res.files.some(f => f.name.includes('Cleartext HTTP Basic Authentication')));
  assert.ok(res.fix.includes('IP Camera / NVR'));

  // Assert strictly zero credentials or brute-force headers/bodies were sent
  for (const req of capturedRequests) {
    const hdrKeys = Object.keys(req.opts?.headers || {}).map(k => k.toLowerCase());
    assert.ok(!hdrKeys.includes('authorization'), 'Must NEVER send Authorization header');
    const bodyStr = String(req.opts?.body || '');
    assert.ok(!/password|passwd|UsernameToken|GetUsers|SetUser|keypress/i.test(bodyStr), 'Must NEVER send credential or mutation payloads');
  }

  // Also test Dahua (37777 + magicBox), Axis (axis-cgi), Xiongmai (34567), UniFi Protect (7443)
  const dahuaAxisRes = await runDeviceCheck('http://192.168.1.91', async (url) => {
    if (url.includes('magicBox.cgi')) {
      return { status: 200, headers: { server: 'WEB SERVICE' }, text: 'deviceType=NVR4108HS-4KS2\nserialNumber=DH12345' };
    }
    if (url.includes('/axis-cgi/param.cgi')) {
      return { status: 200, headers: {}, text: 'root.Brand.Brand=AXIS\nroot.Brand.ProdShortName=AXIS M3065-V' };
    }
    if (url.includes(':7443/api/2.0/bootstrap')) {
      return { status: 200, headers: { 'content-type': 'application/json' }, text: '{"nvr":{"name":"UniFi Protect"},"cameras":[]}' };
    }
    return { status: 404, headers: {}, text: '' };
  }, {
    allowPrivate: true,
    tcpProbe: async (_h, p) => ({ port: p, open: p === 80 || p === 37777 || p === 34567 || p === 7443 })
  });
  assert.equal(dahuaAxisRes.deviceCategory, 'ip_camera');
  assert.ok(dahuaAxisRes.files.some(f => f.port === 37777));
  assert.ok(dahuaAxisRes.files.some(f => f.port === 34567 && f.severity === 'HIGH'));
  assert.ok(dahuaAxisRes.files.some(f => f.name.includes('Dahua IP Camera')));
  assert.ok(dahuaAxisRes.files.some(f => f.name.includes('Axis Network Camera')));
  assert.ok(dahuaAxisRes.files.some(f => f.name.includes('UniFi Protect')));
});

test('device-security: detects PCs / Workstations / Local Servers (Windows, macOS/Linux, Docker/Ollama/Dev) and disambiguates shared ports', async () => {
  // 1. Windows Workstation (SMB 445, NetBIOS 139, MSRPC 135, RDP 3389, WinRM 5985, WSDAPI 5357)
  const winRes = await runDeviceCheck('http://192.168.1.100', async (url) => {
    if (url === 'http://192.168.1.100:5985/wsman') {
      return { status: 401, headers: { server: 'Microsoft-HTTPAPI/2.0', 'www-authenticate': 'Negotiate' }, text: '' };
    }
    if (url === 'http://192.168.1.100:5357/') {
      return { status: 404, headers: { server: 'Microsoft-HTTPAPI/2.0' }, text: '' };
    }
    return { status: 404, headers: {}, text: '' };
  }, {
    allowPrivate: true,
    tcpProbe: async (_h, p) => ({ port: p, open: [135, 139, 445, 3389, 5357, 5985].includes(p) })
  });
  assert.equal(winRes.status, 'VULNERABLE');
  assert.equal(winRes.deviceCategory, 'pc_workstation');
  assert.equal(winRes.device.osFamily, 'Windows');
  assert.ok(winRes.files.some(f => f.port === 445 && f.url.startsWith('smb://')));
  assert.ok(winRes.files.some(f => f.port === 3389 && f.url.startsWith('rdp://')));
  assert.ok(winRes.files.some(f => f.port === 5985));
  assert.ok(winRes.fix.includes('Windows SMB'));
  assert.ok(winRes.fix.includes('RDP (3389/TCP)'));

  // 2. macOS / Linux Workstation with CUPS 631 + AirPlay 7000 + SSH 22 + VNC 5900 + mDNS (MUST NOT misclassify as printer or smart_tv!)
  const macLinuxRes = await runDeviceCheck('http://192.168.1.101', async (url) => {
    if (url === 'http://192.168.1.101:631/printers') {
      return { status: 200, headers: { server: 'CUPS/2.4 IPP/2.1' }, text: '<html><title>Printers - CUPS</title></html>' };
    }
    if (url === 'http://192.168.1.101:7000/info') {
      return { status: 403, headers: { server: 'AirTunes/740.15' }, text: 'Forbidden' };
    }
    return { status: 404, headers: {}, text: '' };
  }, {
    allowPrivate: true,
    tcpProbe: async (_h, p) => {
      if (p === 22) return { port: 22, open: true, banner: 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13' };
      if (p === 5900) return { port: 5900, open: true, banner: 'RFB 003.008' };
      return { port: p, open: [22, 548, 631, 5900, 7000, 2049].includes(p) };
    },
    udpProbe: async () => ({ ok: true, services: ['_ssh._tcp', '_rfb._tcp', '_smb._tcp'], deviceNames: ['dev-macbook'] })
  });
  assert.equal(macLinuxRes.deviceCategory, 'pc_workstation');
  assert.ok(macLinuxRes.files.some(f => f.port === 22 && f.url.startsWith('ssh://')));
  assert.ok(macLinuxRes.files.some(f => f.port === 5900 && f.url.startsWith('vnc://')));
  assert.ok(macLinuxRes.files.some(f => f.port === 2049));

  // 3. Shared ports 3000 (Next.js/Vite), 5000 (Werkzeug), 8000 (SimpleHTTP), 9000 (no blind Vizio), 2375 (Docker), 11434 (Ollama)
  const devRes = await runDeviceCheck('http://192.168.1.102', async (url) => {
    if (url === 'http://192.168.1.102:3000/') {
      return { status: 200, headers: { 'x-powered-by': 'Next.js' }, text: '<script id="__NEXT_DATA__">{}</script>' };
    }
    if (url === 'http://192.168.1.102:5173/') {
      return { status: 200, headers: {}, text: '<script type="module" src="/@vite/client"></script>' };
    }
    if (url === 'http://192.168.1.102:5000/') {
      return { status: 500, headers: { server: 'Werkzeug/3.0.1 Python/3.11' }, text: '<title>Werkzeug Debugger</title>' };
    }
    if (url === 'http://192.168.1.102:8000/') {
      return { status: 200, headers: { server: 'SimpleHTTP/0.6 Python/3.11.4' }, text: '<title>Directory listing for /</title><h1>Directory listing for /</h1>' };
    }
    if (url === 'http://192.168.1.102:2375/version') {
      return { status: 200, headers: { 'content-type': 'application/json' }, text: JSON.stringify({ Version: '26.1.0', ApiVersion: '1.45', Os: 'linux', KernelVersion: '6.8.0' }) };
    }
    if (url === 'http://192.168.1.102:11434/api/tags') {
      return { status: 200, headers: { 'content-type': 'application/json' }, text: JSON.stringify({ models: [{ name: 'llama3:latest' }] }) };
    }
    return { status: 404, headers: {}, text: '' };
  }, {
    allowPrivate: true,
    tcpProbe: async (_h, p) => ({ port: p, open: [3000, 5000, 5173, 8000, 9000, 2375, 11434].includes(p) })
  });
  assert.equal(devRes.status, 'VULNERABLE');
  assert.equal(devRes.severity, 'CRITICAL');
  assert.equal(devRes.deviceCategory, 'pc_workstation');
  assert.ok(!/LG|Vizio|Hikvision/i.test(devRes.device.vendor), `Must not blindly assign LG/Vizio/Hikvision on shared dev ports, got ${devRes.device.vendor}`);
  assert.ok(devRes.files.some(f => f.port === 2375 && f.severity === 'CRITICAL'));
  assert.ok(devRes.files.some(f => f.port === 11434));
  assert.ok(devRes.files.some(f => f.port === 8000 && f.name.includes('Directory Listing')));
  assert.ok(devRes.files.some(f => f.port === 5000 && f.name.includes('Werkzeug')));
  assert.ok(devRes.files.some(f => f.port === 5173 && f.name.includes('Vite')));
  assert.ok(devRes.files.some(f => f.port === 3000 && f.name.includes('Next.js')));

  // 4. 401 realm disambiguation: Synology NAS -> nas_media_server (NOT router_gateway)
  const nasRes = await scanDeviceTarget('http://192.168.1.103', async () => ({
    status: 401,
    headers: { 'www-authenticate': 'Basic realm="Synology DiskStation"' },
    text: 'Unauthorized'
  }), { allowPrivate: true, multiPort: false });
  assert.equal(nasRes.deviceProfile.category, 'nas_media_server');
  assert.equal(nasRes.deviceProfile.vendor, 'Synology');
});

test('device-security regression (Bug 1): HTTP 200 Werkzeug/Flask and Django WSGIServer are NOT shadowed by SimpleHTTP', async () => {
  const werkzeugDbg = analyzeDeviceHttpResponse({
    url: 'http://192.168.1.110:5000/',
    port: 5000,
    path: '/',
    res: {
      status: 200,
      headers: { server: 'Werkzeug/3.0.1 Python/3.11' },
      text: '<title>Werkzeug Debugger</title>'
    }
  });
  assert.equal(werkzeugDbg.deviceMeta.vendor, 'Python / Flask');
  assert.equal(werkzeugDbg.findings[0].severity, 'CRITICAL');
  assert.ok(werkzeugDbg.findings[0].name.includes('Interactive Debugger'));

  const flaskApp = analyzeDeviceHttpResponse({
    url: 'http://192.168.1.110:5000/',
    port: 5000,
    path: '/',
    res: {
      status: 200,
      headers: { server: 'Werkzeug/3.0.1 Python/3.12.0' },
      text: '<h1>Hello Flask</h1>'
    }
  });
  assert.equal(flaskApp.deviceMeta.vendor, 'Python / Flask');
  assert.ok(flaskApp.findings[0].name.includes('Werkzeug'));
  assert.ok(!flaskApp.findings[0].name.includes('Directory Listing'));

  const djangoApp = analyzeDeviceHttpResponse({
    url: 'http://192.168.1.110:8000/',
    port: 8000,
    path: '/',
    res: {
      status: 200,
      headers: { server: 'WSGIServer/0.2 CPython/3.11.6' },
      text: '<html><body>Django App</body></html>'
    }
  });
  assert.equal(djangoApp.deviceMeta.vendor, 'Python / Django');
  assert.ok(djangoApp.findings[0].name.includes('Django'));
  assert.ok(!djangoApp.findings[0].name.includes('Directory Listing'));
});

test('device-security regression (Bug 3): workstation disambiguation wins over multi-path CUPS 631 and AirPlay 5000/7000 with SSH 22', async () => {
  // 1. SSH (22) + CUPS (631 returning 200 on BOTH /printers and /)
  const sshCupsRes = await runDeviceCheck('http://192.168.1.111', async (url) => {
    if (url === 'http://192.168.1.111:631/printers' || url === 'http://192.168.1.111:631/') {
      return { status: 200, headers: { server: 'CUPS/2.4 IPP/2.1' }, text: '<html><title>Home - CUPS 2.4.7</title></html>' };
    }
    return { status: 404, headers: {}, text: '' };
  }, {
    allowPrivate: true,
    tcpProbe: async (_h, p) => {
      if (p === 22) return { port: 22, open: true, banner: 'SSH-2.0-OpenSSH_9.2p1 Ubuntu-2ubuntu0.1' };
      return { port: p, open: p === 631 };
    }
  });
  assert.equal(sshCupsRes.deviceCategory, 'pc_workstation');
  assert.ok(sshCupsRes.device.categorySignals.includes('disambig:cups_on_workstation'));

  // 2. SSH (22) + AirPlay (5000 /info + 7000 /info + 7000 /server-info)
  const sshAirplayRes = await runDeviceCheck('http://192.168.1.112', async (url) => {
    if (url.startsWith('http://192.168.1.112:5000/') || url.startsWith('http://192.168.1.112:7000/')) {
      return { status: 403, headers: { server: 'AirTunes/740.15' }, text: 'Forbidden' };
    }
    return { status: 404, headers: {}, text: '' };
  }, {
    allowPrivate: true,
    tcpProbe: async (_h, p) => {
      if (p === 22) return { port: 22, open: true, banner: 'SSH-2.0-OpenSSH_9.6' };
      return { port: p, open: p === 5000 || p === 7000 };
    }
  });
  assert.equal(sshAirplayRes.deviceCategory, 'pc_workstation');
  assert.ok(sshAirplayRes.device.categorySignals.includes('disambig:airplay_on_workstation'));
});

test('device-security regression (Bug 4): pre-DNS SSRF blocks raw TCP/TLS/RTSP/mDNS probes when DNS resolves to private/metadata IPs', async () => {
  let tcpCount = 0;
  let tlsCount = 0;
  let rtspCount = 0;
  let udpCount = 0;

  const governedPrivateBlocked = createGovernedFetch({
    allowPrivate: false,
    dnsResolver: async () => ['127.0.0.1']
  });
  const blockedLoopback = await scanDeviceTarget('http://rebind-loopback.example', governedPrivateBlocked, {
    deviceMode: true,
    tcpProbe: async () => { tcpCount++; return { open: true }; },
    tlsProbe: async () => { tlsCount++; return { ok: true }; },
    rtspProbe: async () => { rtspCount++; return { ok: true }; },
    udpProbe: async () => { udpCount++; return { ok: true, services: ['_ssh._tcp'] }; }
  });
  assert.equal(blockedLoopback.ok, false);
  assert.equal(blockedLoopback.isGovernanceBlock, true);
  assert.equal(tcpCount, 0);
  assert.equal(tlsCount, 0);
  assert.equal(rtspCount, 0);
  assert.equal(udpCount, 0);

  const governedMetadataBlocked = createGovernedFetch({
    allowPrivate: true,
    dnsResolver: async () => ['169.254.169.254']
  });
  const blockedMetadata = await scanDeviceTarget('http://rebind-meta.example', governedMetadataBlocked, {
    allowPrivate: true,
    deviceMode: true,
    tcpProbe: async () => { tcpCount++; return { open: true }; }
  });
  assert.equal(blockedMetadata.ok, false);
  assert.equal(blockedMetadata.isGovernanceBlock, true);
  assert.equal(tcpCount, 0);

  // Real socket guard: verify OS TCP socket is never dialed when DNS resolves to 127.0.0.1 under allowPrivate: false
  let serverConns = 0;
  const tcpServer = net.createServer(sock => { serverConns++; sock.destroy(); });
  await new Promise(resolve => tcpServer.listen(0, '127.0.0.1', resolve));
  const { port } = tcpServer.address();
  try {
    const res = await scanDeviceTarget(`http://rebind-live.example:${port}`, governedPrivateBlocked, {
      deviceMode: true,
      ports: [port],
      portTimeoutMs: 250
    });
    assert.equal(res.ok, false);
    assert.equal(res.isGovernanceBlock, true);
    assert.equal(serverConns, 0);
  } finally {
    await new Promise(resolve => tcpServer.close(resolve));
  }
});

test('device-security regression (Bugs 5, 6, 7, 9): generic 426 WebSocket, port 9000 HTTP, port 443 HTTPS camera, createTrackedFetch(fetchWithRetry), and quickFingerprint/TLS close', async () => {
  // Bug 5: Generic RFC 6455 426 Upgrade Required on port 3000 must NOT classify as LG webOS
  const wsRes = await scanDeviceTarget('http://192.168.1.115', async (url) => {
    if (url === 'http://192.168.1.115:3000/') {
      return { status: 426, headers: { upgrade: 'websocket', connection: 'Upgrade' }, text: 'Upgrade Required' };
    }
    return { status: 404, headers: {}, text: '' };
  }, {
    allowPrivate: true,
    tcpProbe: async (_h, p) => ({ port: p, open: p === 3000 })
  });
  assert.notEqual(wsRes.deviceProfile?.vendor, 'LG');
  assert.notEqual(wsRes.deviceProfile?.category, 'smart_tv');

  // Bug 6a: Plain HTTP service on port 9000 populates activeHttpOrigin even when HTTPS fails TLS
  const http9000Res = await scanDeviceTarget('http://192.168.1.120', async (url) => {
    if (url === 'https://192.168.1.120:9000/state/device/power_mode' || url === 'https://192.168.1.120:9000/') {
      throw new Error('TLS handshake failed');
    }
    if (url === 'http://192.168.1.120:9000/') {
      return { status: 200, headers: { 'content-type': 'text/html' }, text: '<title>Portainer</title>' };
    }
    return { status: 404, headers: {}, text: '' };
  }, {
    allowPrivate: true,
    tcpProbe: async (_h, p) => ({ port: p, open: p === 9000 })
  });
  assert.equal(http9000Res.ok, true);
  assert.equal(http9000Res.deviceProfile.activeHttpOrigin, 'http://192.168.1.120:9000');

  // Bug 6b: HTTPS-only IP camera on port 443 discovers ISAPI and ONVIF
  const cam443Res = await scanDeviceTarget('https://192.168.1.121', async (url, opts = {}) => {
    if (url === 'https://192.168.1.121/ISAPI/System/deviceInfo') {
      return { status: 200, headers: { 'content-type': 'application/xml' }, text: '<DeviceInfo><model>DS-2CD2143</model></DeviceInfo>' };
    }
    if (url === 'https://192.168.1.121/onvif/device_service' && opts.method === 'POST') {
      return { status: 200, headers: { 'content-type': 'application/soap+xml' }, text: '<tds:GetSystemDateAndTimeResponse/>' };
    }
    return { status: 404, headers: {}, text: '' };
  }, {
    allowPrivate: true,
    tcpProbe: async (_h, p) => ({ port: p, open: p === 443 })
  });
  assert.equal(cam443Res.deviceProfile.category, 'ip_camera');
  assert.equal(cam443Res.deviceProfile.vendor, 'Hikvision');

  // Bug 9a: quickFingerprint sets isQuickFingerprint: true
  const qfRes = await scanDeviceTarget('http://192.168.1.120', async () => ({ status: 404, headers: {}, text: '' }), {
    allowPrivate: true,
    quickFingerprint: true,
    tcpProbe: async (_h, p) => ({ port: p, open: p === 8001 })
  });
  assert.equal(qfRes.isQuickFingerprint, true);

  // Bug 9b: probeTlsMetadata resolves quickly on clean TCP FIN without waiting for timeout
  const finSockets = new Set();
  const finServer = net.createServer(sock => {
    finSockets.add(sock);
    sock.on('close', () => finSockets.delete(sock));
    sock.end();
    sock.destroy();
  });
  await new Promise(resolve => finServer.listen(0, '127.0.0.1', resolve));
  const finPort = finServer.address().port;
  try {
    const t0 = Date.now();
    const tlsRes = await probeTlsMetadata('127.0.0.1', finPort, { tlsTimeoutMs: 1200 });
    const elapsed = Date.now() - t0;
    assert.equal(tlsRes.ok, false);
    assert.ok(elapsed < 500, `Expected fast FIN resolution <500ms, got ${elapsed}ms`);
  } finally {
    for (const s of finSockets) s.destroy();
    await new Promise(resolve => finServer.close(resolve));
  }

  // Bug 7: createTrackedFetch(fetchWithRetry) + explicit options.ports WITHOUT multiPort: true against real loopback server
  const tvServer = http.createServer((req, res) => {
    if (req.url === '/api/v2/') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ device: { type: 'Samsung SmartTV', OS: 'Tizen', modelName: 'UN55TU7000', tokenAuthSupport: 'false' } }));
      return;
    }
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
  });
  await new Promise(resolve => tvServer.listen(0, '127.0.0.1', resolve));
  const tvPort = tvServer.address().port;

  // Deterministic closed port to simulate closed port 80
  const closedSrv = net.createServer();
  await new Promise(resolve => closedSrv.listen(0, '127.0.0.1', resolve));
  const closedPort = closedSrv.address().port;
  await new Promise(resolve => closedSrv.close(resolve));

  try {
    const tracked = createTrackedFetch(fetchWithRetry);
    const liveRes = await runDeviceCheck(`"http://127.0.0.1:${closedPort}\\"`, tracked, {
      allowPrivate: true,
      deviceMode: true,
      ports: [closedPort, tvPort],
      portTimeoutMs: 250,
      probeTimeoutMs: 500
    });
    assert.equal(liveRes.status, 'VULNERABLE');
    assert.equal(liveRes.deviceCategory, 'smart_tv');
    assert.equal(liveRes.device.vendor, 'Samsung');
  } finally {
    tvServer.closeAllConnections?.();
    await new Promise(resolve => tvServer.close(resolve));
  }
});

test('device-security regression (M2 R3): AirPlay 7000+7100 workstation disambiguation and custom fetcher multiPort pre-DNS SSRF guard', async () => {
  // 1. SSH (22) + AirPlay (7000 + 7100) -> pc_workstation (NOT smart_tv)
  const sshAirplay7100 = await runDeviceCheck('http://192.168.1.130', async (url) => {
    if (url.startsWith('http://192.168.1.130:7000/') || url.startsWith('http://192.168.1.130:7100/')) {
      return {
        status: 200,
        headers: { server: 'AirTunes/740.15', 'content-type': 'application/x-apple-binary-plist' },
        text: 'bplist00\u0001\u0002'
      };
    }
    return { status: 404, headers: {}, text: '' };
  }, {
    allowPrivate: true,
    tcpProbe: async (_h, p) => {
      if (p === 22) return { port: 22, open: true, banner: 'SSH-2.0-OpenSSH_9.6' };
      return { port: p, open: p === 7000 || p === 7100 };
    }
  });
  assert.equal(sshAirplay7100.deviceCategory, 'pc_workstation');
  assert.notEqual(sshAirplay7100.deviceCategory, 'smart_tv');
  assert.ok(sshAirplay7100.device.categorySignals.includes('disambig:airplay_on_workstation'));

  // 2. SSH (22) + CUPS (631) + AirPlay (7000 + 7100) -> pc_workstation (NOT smart_tv or printer)
  const sshCupsAirplay7100 = await runDeviceCheck('http://192.168.1.131', async (url) => {
    if (url.startsWith('http://192.168.1.131:7000/') || url.startsWith('http://192.168.1.131:7100/')) {
      return { status: 403, headers: { server: 'AirTunes/740.15' }, text: 'Forbidden' };
    }
    if (url === 'http://192.168.1.131:631/printers' || url === 'http://192.168.1.131:631/') {
      return { status: 200, headers: { server: 'CUPS/2.4 IPP/2.1' }, text: '<html><title>Printers - CUPS</title></html>' };
    }
    return { status: 404, headers: {}, text: '' };
  }, {
    allowPrivate: true,
    tcpProbe: async (_h, p) => {
      if (p === 22) return { port: 22, open: true, banner: 'SSH-2.0-OpenSSH_9.6' };
      return { port: p, open: p === 631 || p === 7000 || p === 7100 };
    }
  });
  assert.equal(sshCupsAirplay7100.deviceCategory, 'pc_workstation');
  assert.notEqual(sshCupsAirplay7100.deviceCategory, 'smart_tv');
  assert.notEqual(sshCupsAirplay7100.deviceCategory, 'printer');
  assert.ok(sshCupsAirplay7100.device.categorySignals.includes('disambig:cups_on_workstation'));
  assert.ok(sshCupsAirplay7100.device.categorySignals.includes('disambig:airplay_on_workstation'));

  // 3. Contrast: standalone AirPlay (7000 + 7100, NO workstation ports) -> still smart_tv
  const standaloneAirplay = await runDeviceCheck('http://192.168.1.132', async (url) => {
    if (url === 'http://192.168.1.132:7000/info' || url === 'http://192.168.1.132:7100/info') {
      return {
        status: 200,
        headers: { server: 'AirTunes/740.15', 'content-type': 'application/x-apple-binary-plist' },
        text: 'bplist00\u0001\u0002'
      };
    }
    return { status: 404, headers: {}, text: '' };
  }, {
    allowPrivate: true,
    tcpProbe: async (_h, p) => ({ port: p, open: p === 7000 || p === 7100 })
  });
  assert.equal(standaloneAirplay.deviceCategory, 'smart_tv');
  assert.ok(standaloneAirplay.device.vendor.includes('Apple'));

  // 4. Pre-DNS SSRF guard when custom fetcher is passed to createGovernedFetch({ allowPrivate: false }) + multiPort: true without dnsResolver/tcpProbe
  let customFetcherCalled = 0;
  let dialerServerConns = 0;
  const dialerServer = net.createServer(sock => { dialerServerConns++; sock.destroy(); });
  await new Promise(resolve => dialerServer.listen(0, '127.0.0.1', resolve));
  const dialerPort = dialerServer.address().port;
  try {
    const governedCustomFetcher = createGovernedFetch({
      allowPrivate: false,
      fetcher: async () => {
        customFetcherCalled++;
        return { status: 200, headers: {}, text: '' };
      }
    });
    const blockedCustomRes = await scanDeviceTarget(`http://airplay-rebind.local:${dialerPort}`, governedCustomFetcher, {
      multiPort: true,
      ports: [dialerPort],
      portTimeoutMs: 250
    });
    assert.equal(blockedCustomRes.ok, false);
    assert.equal(blockedCustomRes.isGovernanceBlock, true);
    assert.equal(dialerServerConns, 0);
    assert.equal(customFetcherCalled, 0);
  } finally {
    await new Promise(resolve => dialerServer.close(resolve));
  }
});
