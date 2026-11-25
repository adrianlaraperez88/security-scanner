import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { runCli, withTempDir } from './helpers/cli-runner.mjs';
import { startAppHarness, withAppHarness } from './helpers/app-server-harness.mjs';
import { startMockTarget, withMockTarget } from './helpers/mock-target-server.mjs';
import { probeRtspService, probeSingleTcpPort } from '../core/device-scanner.js';

/**
 * Asserts that zero brute-force, default-login, or Authorization credential requests
 * were sent to a loopback HTTP mock target during any device scan.
 */
function assertNonIntrusiveHttpRequests(requests, contextLabel) {
  for (const r of requests) {
    assert.equal(
      Boolean(r.headers?.authorization),
      false,
      `[${contextLabel}] Unexpected Authorization header on ${r.method} ${r.url}`
    );
    const isLoginPost =
      r.method === 'POST' &&
      /(?:login|signin|sign_in|auth|usercheck|rpc2_login|session|dologin)/i.test(r.pathname || '');
    assert.equal(
      isLoginPost,
      false,
      `[${contextLabel}] Unexpected login POST on ${r.method} ${r.url}`
    );
    const wirePayload = `${r.url || ''} ${r.body || ''}`;
    assert.equal(
      /(?:admin:admin|root:root|12345|password=|passwd=)/i.test(wirePayload),
      false,
      `[${contextLabel}] Unexpected default-credential payload in ${r.method} ${r.url}`
    );
  }
}

/**
 * Starts a real loopback RTSP TCP server speaking RTSP/1.0 wire protocol
 * (`OPTIONS` and `DESCRIBE`) and recording every raw inbound request.
 */
async function startLoopbackRtspServer(mode = 'unauthenticated') {
  const wireLogs = [];
  const server = net.createServer(socket => {
    let buffer = '';
    socket.on('data', chunk => {
      buffer += chunk.toString('utf8');
      let sepIdx;
      while ((sepIdx = buffer.indexOf('\r\n\r\n')) !== -1) {
        const rawMsg = buffer.slice(0, sepIdx + 4);
        buffer = buffer.slice(sepIdx + 4);
        wireLogs.push(rawMsg);

        const cseqMatch = /CSeq:\s*(\d+)/i.exec(rawMsg);
        const cseq = cseqMatch ? cseqMatch[1] : '1';
        const methodLine = rawMsg.split(/\r?\n/)[0] || '';

        if (/^OPTIONS\b/i.test(methodLine)) {
          socket.write(
            `RTSP/1.0 200 OK\r\nCSeq: ${cseq}\r\nServer: Hikvision-RTSP/1.0\r\nPublic: OPTIONS, DESCRIBE, SETUP, PLAY\r\n\r\n`
          );
        } else if (/^DESCRIBE\b/i.test(methodLine)) {
          if (mode === 'basic_auth') {
            socket.write(
              `RTSP/1.0 401 Unauthorized\r\nCSeq: ${cseq}\r\nServer: IPCamera-RTSP/1.0\r\nWWW-Authenticate: Basic realm="IPCamera"\r\n\r\n`
            );
          } else {
            const sdp = 'v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=Live Camera Stream\r\nm=video 0 RTP/AVP 96\r\n';
            socket.write(
              `RTSP/1.0 200 OK\r\nCSeq: ${cseq}\r\nServer: Hikvision-RTSP/1.0\r\nContent-Type: application/sdp\r\nContent-Length: ${Buffer.byteLength(sdp)}\r\n\r\n${sdp}`
            );
          }
        } else {
          socket.write(`RTSP/1.0 405 Method Not Allowed\r\nCSeq: ${cseq}\r\n\r\n`);
        }
      }
    });
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });

  const addr = server.address();
  return {
    port: typeof addr === 'object' && addr ? addr.port : 0,
    wireLogs,
    async close() {
      await new Promise(resolve => server.close(() => resolve()));
    }
  };
}

/**
 * Starts a real loopback TCP greeting banner server (SSH-2.0 / RFB VNC) and
 * records any bytes sent by clients so we can assert zero brute-force payloads.
 */
async function startBannerTcpServer(bannerText) {
  const inboundLogs = [];
  const server = net.createServer(socket => {
    socket.write(bannerText);
    socket.on('data', chunk => {
      inboundLogs.push(chunk.toString('utf8'));
    });
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });

  const addr = server.address();
  return {
    port: typeof addr === 'object' && addr ? addr.port : 0,
    inboundLogs,
    async close() {
      await new Promise(resolve => server.close(() => resolve()));
    }
  };
}

/**
 * Starts a real loopback TCP blackhole server that accepts connections and never responds.
 */
async function startBlackholeTcpServer() {
  const sockets = new Set();
  const server = net.createServer(socket => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });

  const addr = server.address();
  return {
    port: typeof addr === 'object' && addr ? addr.port : 0,
    async close() {
      for (const s of sockets) {
        try { s.destroy(); } catch {}
      }
      sockets.clear();
      await new Promise(resolve => server.close(() => resolve()));
    }
  };
}

function buildSamsungPayload(hostLabel) {
  return {
    device: {
      FrameTVSupport: 'false',
      OS: 'Tizen',
      countryCode: 'US',
      firmwareVersion: 'T-NKMDEUC-1402.5',
      id: 'uuid:e2e-samsung-tv-001',
      ip: hostLabel,
      model: '23_EXHIBITION',
      modelName: 'UN55TU7000FXZA',
      name: '[TV] Living Room Samsung',
      networkType: 'wireless',
      resolution: '3840x2160',
      tokenAuthSupport: 'false',
      type: 'Samsung SmartTV',
      udn: 'uuid:e2e-samsung-tv-001',
      wifiMac: 'AA:BB:CC:DD:EE:FF'
    },
    id: 'uuid:e2e-samsung-tv-001',
    name: '[TV] Living Room Samsung',
    type: 'Samsung SmartTV',
    version: '2.0.25'
  };
}

const SAMSUNG_DMR_XML = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
    <friendlyName>[TV] Living Room Samsung</friendlyName>
    <manufacturer>Samsung Electronics</manufacturer>
    <modelName>UN55TU7000FXZA</modelName>
    <UDN>uuid:e2e-samsung-tv-001</UDN>
    <serviceList>
      <service><serviceType>urn:schemas-upnp-org:service:AVTransport:1</serviceType></service>
    </serviceList>
  </device>
</root>`;

describe('E2E Device Categories: Smart TV, IP Camera/NVR & PC/Workstation/Server', () => {
  describe('Tier 1 — Smart TV E2E, Target Normalization & Hang-Free Completion', () => {
    test('T1.1 CLI --detect & scan normalize quoted/backslash targets and classify Samsung Smart TV', async () => {
      const target = await startMockTarget({
        routes: {
          '/api/v2/': {
            status: 200,
            headers: { 'Content-Type': 'application/json', Server: 'Tizen/5.5 Samsung' },
            body: buildSamsungPayload('127.0.0.1')
          },
          '/dmr': {
            status: 200,
            headers: { 'Content-Type': 'text/xml; charset=utf-8' },
            body: SAMSUNG_DMR_XML
          }
        }
      });

      try {
        const malformedInputs = [
          `"127.0.0.1:${target.port}\\"`,
          `127.0.0.1:${target.port}"`,
          `http://127.0.0.1:${target.port}\\`
        ];

        for (const rawInput of malformedInputs) {
          const detectRes = await runCli([
            '--detect',
            '--device',
            '--device-category',
            'tv',
            '--json',
            rawInput
          ]);
          assert.equal(detectRes.code, 0, `Detect failed for ${rawInput}: ${detectRes.stderr}`);
          const parsed = JSON.parse(detectRes.stdout);
          assert.equal(parsed.ok, true);
          assert.equal(parsed.target, `http://127.0.0.1:${target.port}`);
          assert.equal(parsed.deviceInfo?.detected, true);
          assert.equal(parsed.deviceInfo?.category, 'smart_tv');
          assert.equal(parsed.deviceInfo?.vendor, 'Samsung');
          assert.equal(parsed.deviceInfo?.modelName, 'UN55TU7000FXZA');
        }

        await withTempDir(async tmpDir => {
          const t0 = Date.now();
          const scanRes = await runCli(
            [
              `"127.0.0.1:${target.port}\\"`,
              '--device',
              '--device-category',
              'smart_tv',
              '--depth',
              '0',
              '--no-history',
              '--json',
              '--html',
              '--markdown',
              'tv-scan.md',
              '--output',
              'tv-scan'
            ],
            { cwd: tmpDir }
          );
          const elapsedMs = Date.now() - t0;

          assert.equal(scanRes.timedOut, false);
          assert.equal(scanRes.code, 2, `Expected exit 2 for HIGH/VULNERABLE Samsung TV, got ${scanRes.code}\n${scanRes.stderr}`);
          assert.ok(elapsedMs < 20000, `Expected hang-free completion <20s, took ${elapsedMs}ms`);

          const jsonReport = JSON.parse(fs.readFileSync(path.join(tmpDir, 'tv-scan.json'), 'utf8'));
          const stack = jsonReport.stacks[`http://127.0.0.1:${target.port}`];
          assert.ok(stack?.deviceInfo?.detected);
          assert.equal(stack.deviceInfo.category, 'smart_tv');
          assert.equal(stack.deviceInfo.vendor, 'Samsung');
          assert.equal(stack.deviceInfo.modelName, 'UN55TU7000FXZA');

          const devFinding = jsonReport.findings.find(f => f.checkId === 'device-security');
          assert.ok(devFinding, 'Expected device-security finding');
          assert.equal(devFinding.status, 'VULNERABLE');

          const htmlReport = fs.readFileSync(path.join(tmpDir, 'tv-scan.html'), 'utf8');
          const mdReport = fs.readFileSync(path.join(tmpDir, 'tv-scan.md'), 'utf8');
          assert.match(htmlReport, /Samsung/i);
          assert.match(htmlReport, /UN55TU7000FXZA/);
          assert.match(mdReport, /Samsung/i);
          assert.match(mdReport, /UN55TU7000FXZA/);

          assertNonIntrusiveHttpRequests(target.requests, 'T1.1 Samsung Smart TV');
        });
      } finally {
        await target.close();
      }
    });

    test('T1.2 CLI --device --device-category smart-tv scans Roku ECP loopback mock cleanly', async () => {
      await withMockTarget(
        {
          routes: {
            '/query/device-info': {
              status: 200,
              headers: { 'Content-Type': 'text/xml; charset=utf-8' },
              body: `<device-info>
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
              headers: { 'Content-Type': 'text/xml; charset=utf-8' },
              body: '<apps><app id="12" type="appl" version="5.1">Netflix</app></apps>'
            }
          }
        },
        async target => {
          await withTempDir(async tmpDir => {
            const res = await runCli(
              [
                `http://127.0.0.1:${target.port}\\`,
                '--device',
                '--device-category',
                'smart-tv',
                '--depth',
                '0',
                '--no-history',
                '--json',
                '--output',
                'roku'
              ],
              { cwd: tmpDir }
            );
            assert.equal(res.code, 2, `stderr: ${res.stderr}`);
            const report = JSON.parse(fs.readFileSync(path.join(tmpDir, 'roku.json'), 'utf8'));
            const stack = report.stacks[target.baseUrl];
            assert.equal(stack.deviceInfo.category, 'smart_tv');
            assert.equal(stack.deviceInfo.vendor, 'TCL');
            assert.equal(stack.deviceInfo.modelName, '55S425');

            const devFinding = report.findings.find(f => f.checkId === 'device-security');
            assert.ok(devFinding);
            assert.ok(devFinding.files.some(f => /Roku TV Unauthenticated External Control Protocol/i.test(f.name)));
            assert.ok(devFinding.files.some(f => /Developer Mode Enabled/i.test(f.name)));
            assertNonIntrusiveHttpRequests(target.requests, 'T1.2 Roku ECP');
          });
        }
      );
    });

    test('T1.3 Closed port 80/443 + multi-port Smart TV (192.168.68.53 scenario) completes fast via Server API', async () => {
      const tvHttpMock = await startMockTarget({
        routes: {
          '/api/v2/': {
            status: 200,
            headers: { 'Content-Type': 'application/json', Server: 'Tizen/6.0' },
            body: buildSamsungPayload('192.168.68.53')
          },
          '/dmr': {
            status: 200,
            headers: { 'Content-Type': 'text/xml; charset=utf-8' },
            body: SAMSUNG_DMR_XML
          }
        }
      });

      const openSet = new Set([8001, 8002, 8080, 9197]);
      const realLoopbackFetcher = async (url, opts = {}) => {
        const parsed = new URL(url);
        const port = parsed.port ? Number(parsed.port) : (parsed.protocol === 'https:' ? 443 : 80);
        if (port === 80 || port === 443) {
          const err = new Error(`connect ECONNREFUSED ${parsed.hostname}:${port}`);
          err.code = 'ECONNREFUSED';
          throw err;
        }
        const mapped = `${tvHttpMock.baseUrl}${parsed.pathname}${parsed.search}`;
        return fetch(mapped, { method: opts.method || 'GET', headers: opts.headers });
      };

      try {
        await withAppHarness(
          {
            inMemory: true,
            fetcher: realLoopbackFetcher,
            tcpProbe: async (_host, port) => ({ open: openSet.has(port), banner: '' })
          },
          async app => {
            const t0 = Date.now();
            const startRes = await app.jsonFetch('/api/scan', {
              method: 'POST',
              body: {
                target: '"192.168.68.53\\"',
                profile: 'smart',
                deviceMode: true,
                deviceCategory: 'tv',
                allowPrivate: true,
                maxDepth: 2,
                noHistory: true
              }
            });
            assert.equal(startRes.status, 202, startRes.text);
            assert.equal(startRes.data.targets[0], 'http://192.168.68.53');
            assert.equal(startRes.data.deviceCategory, 'smart_tv');

            const events = await app.readSse(`/api/scan/${startRes.data.scanId}/stream`, { timeoutMs: 25000 });
            const elapsedMs = Date.now() - t0;
            assert.ok(elapsedMs < 20000, `Multi-port closed-80 scan took ${elapsedMs}ms`);

            const fpEvt = events.find(e => e.event === 'fingerprint');
            assert.ok(fpEvt?.data?.deviceInfo?.detected);
            assert.equal(fpEvt.data.deviceInfo.category, 'smart_tv');
            assert.equal(fpEvt.data.deviceInfo.vendor, 'Samsung');
            assert.equal(fpEvt.data.deviceInfo.basePortClosed, true);

            const crawlEvt = events.find(e => e.event === 'crawl_complete');
            assert.equal(crawlEvt?.data?.pagesFound, 1, 'Closed port 80 must skip web crawl');

            const completeEvt = events.find(e => e.event === 'complete');
            assert.equal(completeEvt?.data?.status, 'completed');

            assertNonIntrusiveHttpRequests(tvHttpMock.requests, 'T1.3 Multi-port Smart TV');
          }
        );
      } finally {
        await tvHttpMock.close();
      }
    });

    test('T1.4 Live blackhole/hanging loopback socket completes promptly without stalling on retries', async () => {
      const blackhole = await startBlackholeTcpServer();
      try {
        const t0 = Date.now();
        const res = await runCli(
          [`http://127.0.0.1:${blackhole.port}`, '--detect', '--device', '--device-category', 'smart_tv', '--timeout', '1000'],
          { timeoutMs: 15000 }
        );
        const elapsedMs = Date.now() - t0;
        assert.equal(res.timedOut, false, 'CLI must not hang on silent blackhole TCP port');
        assert.equal(res.code, 0, `Expected graceful exit 0 from --detect, got ${res.code}\n${res.stderr}`);
        assert.ok(elapsedMs < 12000, `Blackhole target took ${elapsedMs}ms`);
      } finally {
        await blackhole.close();
      }
    });
  });

  describe('Tier 2 — IP Camera / NVR E2E (Real RTSP Wire + ONVIF / Hikvision / Dahua / Axis)', () => {
    test('T2.1 Real loopback RTSP OPTIONS & DESCRIBE send zero Authorization headers or login POSTs', async () => {
      const openRtsp = await startLoopbackRtspServer('unauthenticated');
      const authRtsp = await startLoopbackRtspServer('basic_auth');

      try {
        const res1 = await probeRtspService('127.0.0.1', openRtsp.port, { rtspTimeoutMs: 1000 });
        assert.equal(res1.ok, true);
        assert.equal(res1.status, 200);
        assert.equal(res1.describeStatus, 200);
        assert.equal(res1.hasSdp, true);
        assert.equal(res1.unauthenticatedStream, true);
        assert.equal(res1.server, 'Hikvision-RTSP/1.0');

        assert.equal(openRtsp.wireLogs.length, 2, 'Expected strictly OPTIONS + DESCRIBE');
        assert.match(openRtsp.wireLogs[0], /^OPTIONS rtsp:\/\/127\.0\.0\.1:/);
        assert.match(openRtsp.wireLogs[1], /^DESCRIBE rtsp:\/\/127\.0\.0\.1:/);
        for (const msg of openRtsp.wireLogs) {
          assert.equal(/Authorization:/i.test(msg), false, 'RTSP probe must never send Authorization');
          assert.equal(/^POST\b/i.test(msg), false, 'RTSP probe must never send POST');
        }

        const res2 = await probeRtspService('127.0.0.1', authRtsp.port, { rtspTimeoutMs: 1000 });
        assert.equal(res2.ok, true);
        assert.equal(res2.describeStatus, 401);
        assert.equal(res2.unauthenticatedStream, false);
        assert.match(res2.wwwAuth || '', /Basic realm="IPCamera"/i);
        assert.equal(authRtsp.wireLogs.length, 2, 'Must stop after 401 DESCRIBE without credential brute-force');
        for (const msg of authRtsp.wireLogs) {
          assert.equal(/Authorization:/i.test(msg), false, 'Must never send Authorization on 401 RTSP challenge');
        }
      } finally {
        await openRtsp.close();
        await authRtsp.close();
      }
    });

    test('T2.2 CLI --device --device-category ip_camera scans Hikvision ISAPI, activateStatus & ONVIF SOAP mock', async () => {
      await withMockTarget(
        {
          routes: {
            '/ISAPI/System/deviceInfo': {
              status: 200,
              headers: { 'Content-Type': 'application/xml; charset=utf-8', Server: 'App-webs/' },
              body: `<?xml version="1.0" encoding="UTF-8"?>
              <DeviceInfo xmlns="http://www.hikvision.com/ver20/XMLSchema">
                <deviceName>Front Gate Camera</deviceName>
                <model>DS-2CD2043G2-I</model>
                <serialNumber>DS2CD-E2E-001</serialNumber>
                <macAddress>C4:2F:90:11:22:33</macAddress>
                <firmwareVersion>V5.7.13</firmwareVersion>
              </DeviceInfo>`
            },
            '/SDK/activateStatus': {
              status: 200,
              headers: { 'Content-Type': 'application/xml; charset=utf-8' },
              body: '<ActivateStatus version="2.0"><Activated>false</Activated></ActivateStatus>'
            },
            '/onvif/device_service': {
              status: 200,
              headers: { 'Content-Type': 'application/soap+xml; charset=utf-8' },
              body: `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
                <s:Body><tds:GetSystemDateAndTimeResponse><tds:SystemDateAndTime><tds:UTCDateTime/></tds:SystemDateAndTime></tds:GetSystemDateAndTimeResponse></s:Body>
              </s:Envelope>`
            }
          }
        },
        async target => {
          await withTempDir(async tmpDir => {
            const res = await runCli(
              [
                target.baseUrl,
                '--device',
                '--device-category',
                'ip_camera',
                '--depth',
                '0',
                '--no-history',
                '--json',
                '--output',
                'cam-hik'
              ],
              { cwd: tmpDir }
            );
            assert.equal(res.code, 2, `Expected exit 2 for unactivated Hikvision camera, got ${res.code}\n${res.stderr}`);
            const report = JSON.parse(fs.readFileSync(path.join(tmpDir, 'cam-hik.json'), 'utf8'));
            const stack = report.stacks[target.baseUrl];
            assert.equal(stack.deviceInfo.category, 'ip_camera');
            assert.equal(stack.deviceInfo.vendor, 'Hikvision');
            assert.equal(stack.deviceInfo.modelName, 'DS-2CD2043G2-I');

            const devFinding = report.findings.find(f => f.checkId === 'device-security');
            assert.ok(devFinding);
            assert.equal(devFinding.severity, 'CRITICAL');
            assert.ok(devFinding.files.some(f => /Unactivated Hikvision/i.test(f.name)));
            assert.ok(devFinding.files.some(f => /ONVIF|Device Info/i.test(f.name)));
            assertNonIntrusiveHttpRequests(target.requests, 'T2.2 Hikvision/ONVIF');
          });
        }
      );
    });

    test('T2.3 CLI scans Dahua (magicBox.cgi) and Axis (axis-cgi) loopback targets as ip_camera', async () => {
      const dahuaTarget = await startMockTarget({
        routes: {
          '/cgi-bin/magicBox.cgi?action=getSystemInfo': {
            status: 200,
            headers: { 'Content-Type': 'text/plain; charset=utf-8' },
            body: 'deviceType=IPC-HDW5442TM-AS\nserialNumber=DAHUA-E2E-9988\nhardwareVersion=1.00\n'
          }
        }
      });
      const axisTarget = await startMockTarget({
        routes: {
          '/axis-cgi/param.cgi?action=list&group=Brand': {
            status: 200,
            headers: { 'Content-Type': 'text/plain; charset=utf-8' },
            body: 'Brand=AXIS\nProdShortName=AXIS P3245-V\nSerialNumber=ACCC8E123456\n'
          }
        }
      });

      try {
        await withTempDir(async tmpDir => {
          const dahuaRes = await runCli(
            [
              dahuaTarget.baseUrl,
              '--device',
              '--device-category',
              'camera',
              '--depth',
              '0',
              '--no-history',
              '--json',
              '--output',
              'dahua'
            ],
            { cwd: tmpDir }
          );
          assert.equal(dahuaRes.code, 2, `stderr: ${dahuaRes.stderr}`);
          const dahuaReport = JSON.parse(fs.readFileSync(path.join(tmpDir, 'dahua.json'), 'utf8'));
          const dahuaFinding = dahuaReport.findings.find(f => f.checkId === 'device-security');
          assert.ok(dahuaFinding, 'Expected device-security finding for Dahua camera');
          assert.equal(dahuaFinding.deviceCategory, 'ip_camera');
          assert.equal(dahuaFinding.device?.category, 'ip_camera');
          assert.equal(dahuaFinding.device?.vendor, 'Dahua');
          assert.equal(dahuaFinding.device?.modelName, 'IPC-HDW5442TM-AS');
          assert.ok(dahuaFinding.files.some(f => /Dahua IP Camera/i.test(f.name)));
          assertNonIntrusiveHttpRequests(dahuaTarget.requests, 'T2.3 Dahua');

          const axisRes = await runCli(
            [
              axisTarget.baseUrl,
              '--device',
              '--device-category',
              'camera',
              '--depth',
              '0',
              '--no-history',
              '--json',
              '--output',
              'axis'
            ],
            { cwd: tmpDir }
          );
          assert.equal(axisRes.code, 2, `stderr: ${axisRes.stderr}`);
          const axisReport = JSON.parse(fs.readFileSync(path.join(tmpDir, 'axis.json'), 'utf8'));
          const axisFinding = axisReport.findings.find(f => f.checkId === 'device-security');
          assert.ok(axisFinding, 'Expected device-security finding for Axis camera');
          assert.equal(axisFinding.deviceCategory, 'ip_camera');
          assert.equal(axisFinding.device?.category, 'ip_camera');
          assert.equal(axisFinding.device?.vendor, 'Axis');
          assert.equal(axisFinding.device?.modelName, 'AXIS P3245-V');
          assert.ok(axisFinding.files.some(f => /Axis Network Camera/i.test(f.name)));
          assertNonIntrusiveHttpRequests(axisTarget.requests, 'T2.3 Axis');
        });
      } finally {
        await dahuaTarget.close();
        await axisTarget.close();
      }
    });

    test('T2.4 Server API POST /api/fingerprint & POST /api/scan combine real loopback RTSP wire + HTTP camera mock', async () => {
      const rtspServer = await startLoopbackRtspServer('unauthenticated');
      const camHttp = await startMockTarget({
        routes: {
          '/': {
            status: 401,
            headers: {
              Server: 'App-webs/',
              'WWW-Authenticate': 'Basic realm="Hikvision IP Camera"'
            },
            body: 'Unauthorized'
          },
          '/onvif/device_service': {
            status: 200,
            headers: { 'Content-Type': 'application/soap+xml; charset=utf-8' },
            body: `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><tds:GetSystemDateAndTimeResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><tds:UTCDateTime/></tds:GetSystemDateAndTimeResponse></s:Body></s:Envelope>`
          }
        }
      });

      const realCamFetcher = async (url, opts = {}) => {
        const parsed = new URL(url);
        const port = parsed.port ? Number(parsed.port) : (parsed.protocol === 'https:' ? 443 : 80);
        if (port === 80) {
          return fetch(`${camHttp.baseUrl}${parsed.pathname}${parsed.search}`, {
            method: opts.method || 'GET',
            headers: opts.headers,
            body: opts.body
          });
        }
        const err = new Error(`connect ECONNREFUSED ${parsed.hostname}:${port}`);
        err.code = 'ECONNREFUSED';
        throw err;
      };

      try {
        await withAppHarness(
          {
            inMemory: true,
            fetcher: realCamFetcher,
            tcpProbe: async (_host, port) => ({ open: port === 554 || port === 80, banner: '' }),
            rtspProbe: async (_host, port, probeOpts) => {
              if (port === 554) {
                return probeRtspService('127.0.0.1', rtspServer.port, probeOpts);
              }
              return { ok: false, port };
            }
          },
          async app => {
            const fpRes = await app.jsonFetch('/api/fingerprint', {
              method: 'POST',
              body: {
                target: '192.168.68.70',
                deviceMode: true,
                deviceCategory: 'camera',
                allowPrivate: true
              }
            });
            assert.equal(fpRes.status, 200, fpRes.text);
            assert.equal(fpRes.data.deviceInfo?.category, 'ip_camera');

            const scanRes = await app.jsonFetch('/api/scan', {
              method: 'POST',
              body: {
                target: '192.168.68.70',
                profile: 'device',
                deviceCategory: 'ip_camera',
                allowPrivate: true,
                maxDepth: 0,
                noHistory: true
              }
            });
            assert.equal(scanRes.status, 202, scanRes.text);

            const events = await app.readSse(`/api/scan/${scanRes.data.scanId}/stream`, { timeoutMs: 25000 });
            const fpEvt = events.find(e => e.event === 'fingerprint');
            assert.equal(fpEvt?.data?.deviceInfo?.category, 'ip_camera');

            const devCheckEvt = events.find(e => e.event === 'check' && e.data?.checkId === 'device-security');
            assert.ok(devCheckEvt, 'Expected device-security SSE check event');
            assert.equal(devCheckEvt.data.deviceCategory, 'ip_camera');
            assert.ok(
              devCheckEvt.data.files.some(f => /Unauthenticated RTSP Live Video Stream Exposure/i.test(f.name)),
              'Expected RTSP unauthenticated stream finding from real loopback RTSP server'
            );

            for (const msg of rtspServer.wireLogs) {
              assert.equal(/Authorization:/i.test(msg), false);
            }
            assertNonIntrusiveHttpRequests(camHttp.requests, 'T2.4 IP Camera HTTP+RTSP');
          }
        );
      } finally {
        await rtspServer.close();
        await camHttp.close();
      }
    });
  });

  describe('Tier 3 — PC / Workstation / Server E2E (SSH, VNC, Dev Servers & Disambiguation)', () => {
    test('T3.1 Real loopback SSH-2.0 & VNC RFB banner TCP servers classify as pc_workstation via Server API', async () => {
      const sshSrv = await startBannerTcpServer('SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n');
      const vncSrv = await startBannerTcpServer('RFB 003.008\n');

      const refusedFetcher = async url => {
        const err = new Error(`connect ECONNREFUSED ${url}`);
        err.code = 'ECONNREFUSED';
        throw err;
      };

      const loopbackBannerProbe = async (_host, port, opts = {}) => {
        if (port === 22) return probeSingleTcpPort('127.0.0.1', sshSrv.port, opts);
        if (port === 5900) return probeSingleTcpPort('127.0.0.1', vncSrv.port, opts);
        return { port, open: false, banner: '' };
      };

      try {
        await withAppHarness(
          {
            inMemory: true,
            fetcher: refusedFetcher,
            tcpProbe: loopbackBannerProbe
          },
          async app => {
            const fpRes = await app.jsonFetch('/api/fingerprint', {
              method: 'POST',
              body: {
                target: '192.168.68.120',
                deviceMode: true,
                deviceCategory: 'pc',
                allowPrivate: true
              }
            });
            assert.equal(fpRes.status, 200, fpRes.text);
            assert.equal(fpRes.data.deviceInfo?.category, 'pc_workstation');
            assert.equal(fpRes.data.deviceInfo?.osFamily, 'Linux');
            assert.equal(fpRes.data.activeChecksCount, 1);
            assert.deepEqual(fpRes.data.activeChecks.map(c => c.id), ['device-security']);

            const scanRes = await app.jsonFetch('/api/scan', {
              method: 'POST',
              body: {
                target: '192.168.68.120',
                profile: 'smart',
                deviceMode: true,
                deviceCategory: 'pc_workstation',
                allowPrivate: true,
                noHistory: true
              }
            });
            assert.equal(scanRes.status, 202, scanRes.text);

            const events = await app.readSse(`/api/scan/${scanRes.data.scanId}/stream`, { timeoutMs: 25000 });
            const completeEvt = events.find(e => e.event === 'complete');
            const results = completeEvt?.data?.result?.results || [];
            assert.equal(results.length, 1, 'HTTP-less workstation must run only device-security');
            assert.equal(results[0].checkId, 'device-security');
            assert.equal(results[0].deviceCategory, 'pc_workstation');

            const sshFile = results[0].files.find(f => f.port === 22);
            const vncFile = results[0].files.find(f => f.port === 5900);
            assert.ok(sshFile, 'Expected SSH finding');
            assert.match(sshFile.evidenceQuote || sshFile.preview || '', /SSH-2\.0-OpenSSH_8\.9p1/);
            assert.ok(vncFile, 'Expected VNC RFB finding');
            assert.match(vncFile.evidenceQuote || vncFile.preview || '', /RFB 003\.008/);

            assert.equal(sshSrv.inboundLogs.length, 0, 'SSH banner probe must not send auth/brute-force payloads');
            assert.equal(vncSrv.inboundLogs.length, 0, 'VNC banner probe must not send auth/brute-force payloads');
          }
        );
      } finally {
        await sshSrv.close();
        await vncSrv.close();
      }
    });

    test('T3.2 CLI --device --device-category pc_workstation scans Werkzeug & Index-of open share without TV/camera misclassification', async () => {
      const werkzeugTarget = await startMockTarget({
        routes: {
          '/': {
            status: 200,
            headers: { Server: 'Werkzeug/3.0.1 Python/3.11.6', 'Content-Type': 'text/html; charset=utf-8' },
            body: '<html><head><title>Werkzeug Debugger</title></head><body><div class="__debugger__">Interactive Console</div></body></html>'
          }
        }
      });

      const shareTarget = await startMockTarget({
        routes: {
          '/': {
            status: 200,
            headers: { Server: 'SimpleHTTP/0.6 Python/3.11.6', 'Content-Type': 'text/html; charset=utf-8' },
            body: '<html><head><title>Directory listing for /</title></head><body><h1>Directory listing for /</h1><a href="secrets.txt">secrets.txt</a></body></html>'
          }
        }
      });

      try {
        await withTempDir(async tmpDir => {
          const wRes = await runCli(
            [
              werkzeugTarget.baseUrl,
              '--device',
              '--device-category',
              'pc_workstation',
              '--depth',
              '0',
              '--no-history',
              '--json',
              '--output',
              'werkzeug'
            ],
            { cwd: tmpDir }
          );
          assert.equal(wRes.code, 2, `Expected exit 2 for Werkzeug debugger, got ${wRes.code}\n${wRes.stderr}`);
          const wJson = JSON.parse(fs.readFileSync(path.join(tmpDir, 'werkzeug.json'), 'utf8'));
          assert.equal(wJson.stacks[werkzeugTarget.baseUrl].deviceInfo.category, 'pc_workstation');
          assert.equal(wJson.stacks[werkzeugTarget.baseUrl].deviceInfo.vendor, 'Python / Flask');
          assertNonIntrusiveHttpRequests(werkzeugTarget.requests, 'T3.2 Werkzeug');

          const sRes = await runCli(
            [
              shareTarget.baseUrl,
              '--device',
              '--device-category',
              'pc_workstation',
              '--depth',
              '0',
              '--no-history',
              '--json',
              '--output',
              'share'
            ],
            { cwd: tmpDir }
          );
          assert.equal(sRes.code, 2, `Expected exit 2 for open HTTP share, got ${sRes.code}\n${sRes.stderr}`);
          const sJson = JSON.parse(fs.readFileSync(path.join(tmpDir, 'share.json'), 'utf8'));
          assert.equal(sJson.stacks[shareTarget.baseUrl].deviceInfo.category, 'pc_workstation');
          assert.ok(
            sJson.findings.some(f => f.checkId === 'device-security' && f.files.some(x => /Directory Listing|Open File Share/i.test(x.name)))
          );
          assertNonIntrusiveHttpRequests(shareTarget.requests, 'T3.2 Open HTTP Share');
        });
      } finally {
        await werkzeugTarget.close();
        await shareTarget.close();
      }
    });

    test('T3.3 Shared port 3000 Express/Vite dev server with SSH classifies as pc_workstation (never LG webOS)', async () => {
      const sshSrv = await startBannerTcpServer('SSH-2.0-OpenSSH_9.3\r\n');
      const devHttp = await startMockTarget({
        routes: {
          '/': {
            status: 200,
            headers: { 'X-Powered-By': 'Express', 'Content-Type': 'text/html; charset=utf-8' },
            body: '<!DOCTYPE html><html><head><script type="module" src="/@vite/client"></script></head><body><h1>Local Vite + Express App</h1></body></html>'
          }
        }
      });

      const devFetcher = async (url, opts = {}) => {
        const parsed = new URL(url);
        const port = parsed.port ? Number(parsed.port) : (parsed.protocol === 'https:' ? 443 : 80);
        if (port === 3000) {
          return fetch(`${devHttp.baseUrl}${parsed.pathname}${parsed.search}`, {
            method: opts.method || 'GET',
            headers: opts.headers
          });
        }
        const err = new Error(`connect ECONNREFUSED ${parsed.hostname}:${port}`);
        err.code = 'ECONNREFUSED';
        throw err;
      };

      try {
        await withAppHarness(
          {
            inMemory: true,
            fetcher: devFetcher,
            tcpProbe: async (_host, port, opts = {}) => {
              if (port === 22) return probeSingleTcpPort('127.0.0.1', sshSrv.port, opts);
              if (port === 3000) return { open: true, banner: '' };
              return { open: false, banner: '' };
            }
          },
          async app => {
            const fpRes = await app.jsonFetch('/api/fingerprint', {
              method: 'POST',
              body: {
                target: '192.168.68.150',
                deviceMode: true,
                allowPrivate: true
              }
            });
            assert.equal(fpRes.status, 200, fpRes.text);
            assert.equal(fpRes.data.deviceInfo?.category, 'pc_workstation');
            assert.notEqual(fpRes.data.deviceInfo?.vendor, 'LG');
            assertNonIntrusiveHttpRequests(devHttp.requests, 'T3.3 Express/Vite');
          }
        );
      } finally {
        await sshSrv.close();
        await devHttp.close();
      }
    });
  });

  describe('Tier 4 — Server API, Web UI Contract & T2.1 Security Boundary E2E', () => {
    test('T4.1 GET /api/meta exposes deviceCategories & Web UI serves device-category controls', async () => {
      await withAppHarness({ inMemory: true }, async app => {
        const meta = await app.jsonFetch('/api/meta');
        assert.equal(meta.status, 200);
        assert.ok(meta.data.deviceCategories && typeof meta.data.deviceCategories === 'object');
        assert.ok(meta.data.deviceCategories.smart_tv);
        assert.ok(meta.data.deviceCategories.ip_camera);
        assert.ok(meta.data.deviceCategories.pc_workstation);
        assert.ok(Array.isArray(meta.data.presets) && meta.data.presets.some(p => p.id === 'device'));
        assert.ok(meta.data.profiles?.device);

        const htmlRes = await app.fetchApi('/');
        assert.equal(htmlRes.status, 200);
        const html = await htmlRes.text();
        assert.match(html, /id="device-category-wrap"/);
        assert.match(html, /id="opt-device-category"/);
        assert.match(html, /value="smart_tv"/);
        assert.match(html, /value="ip_camera"/);
        assert.match(html, /value="pc_workstation"/);
        assert.match(html, /id="tech-detect-device-row"/);
        assert.match(html, /id="results-device-info"/);

        const appJsRes = await app.fetchApi('/app.js');
        assert.equal(appJsRes.status, 200);
        const appJs = await appJsRes.text();
        assert.match(appJs, /\brenderDeviceInfoHtml\b/);
        assert.match(appJs, /\bnormalizeTargetScheme\b/);
        assert.match(appJs, /\bnormalizeStacksList\b/);
        assert.match(appJs, /deviceCategory/);
      });
    });

    test('T4.2 Server API rejects invalid deviceCategory (400) and enforces T2.1 allowPrivate: false boundary', async () => {
      await withAppHarness({ inMemory: true }, async app => {
        const badFp = await app.jsonFetch('/api/fingerprint', {
          method: 'POST',
          body: { target: '127.0.0.1', allowPrivate: true, deviceCategory: 'nonexistent_cat' }
        });
        assert.equal(badFp.status, 400);

        const badScan = await app.jsonFetch('/api/scan', {
          method: 'POST',
          body: { target: '127.0.0.1', allowPrivate: true, deviceCategory: 'nonexistent_cat' }
        });
        assert.equal(badScan.status, 400);

        // T2.1 boundary: allowPrivate omitted/false must reject 127.0.0.1 regardless of profile or device flags
        const boundaryBodies = [
          { target: 'http://127.0.0.1:4321' },
          { target: 'http://127.0.0.1:4321', profile: 'smart' },
          { target: 'http://127.0.0.1:4321', profile: 'device' },
          { target: '127.0.0.1', deviceMode: true, deviceCategory: 'smart_tv' },
          { target: 'http://127.0.0.1:4321', allowPrivate: false, profile: 'device', deviceMode: true }
        ];
        for (const payload of boundaryBodies) {
          const res = await app.jsonFetch('/api/scan', { method: 'POST', body: payload });
          assert.equal(res.status, 400, `Expected 400 without allowPrivate: true for ${JSON.stringify(payload)}`);
        }
      });
    });

    test('T4.3 POST /api/scan SSE fingerprint & check events and HTML/Markdown exports render deviceInfo', async () => {
      await withMockTarget(
        {
          routes: {
            '/api/v2/': {
              status: 200,
              headers: { 'Content-Type': 'application/json', Server: 'Tizen/6.0' },
              body: buildSamsungPayload('127.0.0.1')
            }
          }
        },
        async target => {
          await withAppHarness({ inMemory: true }, async app => {
            const startRes = await app.jsonFetch('/api/scan', {
              method: 'POST',
              body: {
                target: `"127.0.0.1:${target.port}\\"`,
                profile: 'device',
                deviceMode: true,
                deviceCategory: 'smart_tv',
                allowPrivate: true,
                maxDepth: 0,
                noHistory: true
              }
            });
            assert.equal(startRes.status, 202, startRes.text);
            assert.equal(startRes.data.targets[0], target.baseUrl);
            assert.equal(startRes.data.deviceMode, true);
            assert.equal(startRes.data.deviceCategory, 'smart_tv');

            const events = await app.readSse(`/api/scan/${startRes.data.scanId}/stream`, { timeoutMs: 25000 });
            const fpEvt = events.find(e => e.event === 'fingerprint');
            assert.ok(fpEvt?.data?.deviceInfo?.detected);
            assert.equal(fpEvt.data.deviceInfo.category, 'smart_tv');
            assert.equal(fpEvt.data.deviceInfo.vendor, 'Samsung');
            assert.equal(fpEvt.data.deviceInfo.modelName, 'UN55TU7000FXZA');

            const devCheckEvt = events.find(e => e.event === 'check' && e.data?.checkId === 'device-security');
            assert.ok(devCheckEvt);
            assert.equal(devCheckEvt.data.deviceCategory, 'smart_tv');
            assert.ok(devCheckEvt.data.device?.vendor === 'Samsung');
            assert.ok(Array.isArray(devCheckEvt.data.openPorts));

            const htmlExp = await app.fetchApi(`/api/scan/${startRes.data.scanId}/export?format=html`);
            assert.equal(htmlExp.status, 200);
            const htmlTxt = await htmlExp.text();
            assert.match(htmlTxt, /Samsung/i);
            assert.match(htmlTxt, /UN55TU7000FXZA/);

            const mdExp = await app.fetchApi(`/api/scan/${startRes.data.scanId}/export?format=markdown`);
            assert.equal(mdExp.status, 200);
            const mdTxt = await mdExp.text();
            assert.match(mdTxt, /Samsung/i);
            assert.match(mdTxt, /UN55TU7000FXZA/);

            const jsonExp = await app.jsonFetch(`/api/scan/${startRes.data.scanId}/export?format=json`);
            assert.equal(jsonExp.status, 200);
            assert.equal(jsonExp.data.stacks?.[0]?.deviceInfo?.category, 'smart_tv');

            assertNonIntrusiveHttpRequests(target.requests, 'T4.3 Server API Export');
          });
        }
      );
    });

    test('T4.4 CLI --tv, --camera, and --pc shorthand flags set deviceMode, allowPrivate, and deviceCategory E2E', async () => {
      const tvTarget = await startMockTarget({
        routes: {
          '/api/v2/': {
            status: 200,
            headers: { 'Content-Type': 'application/json', Server: 'Tizen/6.0' },
            body: buildSamsungPayload('127.0.0.1')
          }
        }
      });
      const camTarget = await startMockTarget({
        routes: {
          '/ISAPI/System/deviceInfo': {
            status: 200,
            headers: { 'Content-Type': 'application/xml; charset=utf-8', Server: 'App-webs/' },
            body: '<DeviceInfo><deviceName>Side Gate Cam</deviceName><model>DS-2CD2143G2-I</model></DeviceInfo>'
          }
        }
      });
      const pcTarget = await startMockTarget({
        routes: {
          '/': {
            status: 200,
            headers: { Server: 'Werkzeug/3.0.1 Python/3.11.6', 'Content-Type': 'text/html; charset=utf-8' },
            body: '<html><head><title>Werkzeug Debugger</title></head><body><div class="__debugger__">Console</div></body></html>'
          }
        }
      });

      try {
        const tvDetect = await runCli([`127.0.0.1:${tvTarget.port}`, '--tv', '--detect', '--json']);
        assert.equal(tvDetect.code, 0, tvDetect.stderr);
        const tvJson = JSON.parse(tvDetect.stdout);
        assert.equal(tvJson.deviceMode, true);
        assert.equal(tvJson.allowPrivate, true);
        assert.equal(tvJson.deviceCategory, 'smart_tv');
        assert.equal(tvJson.deviceInfo?.category, 'smart_tv');

        const camDetect = await runCli([`127.0.0.1:${camTarget.port}`, '--camera', '--detect', '--json']);
        assert.equal(camDetect.code, 0, camDetect.stderr);
        const camJson = JSON.parse(camDetect.stdout);
        assert.equal(camJson.deviceMode, true);
        assert.equal(camJson.allowPrivate, true);
        assert.equal(camJson.deviceCategory, 'ip_camera');
        assert.equal(camJson.deviceInfo?.category, 'ip_camera');

        const pcDetect = await runCli([`127.0.0.1:${pcTarget.port}`, '--pc', '--detect', '--json']);
        assert.equal(pcDetect.code, 0, pcDetect.stderr);
        const pcJson = JSON.parse(pcDetect.stdout);
        assert.equal(pcJson.deviceMode, true);
        assert.equal(pcJson.allowPrivate, true);
        assert.equal(pcJson.deviceCategory, 'pc_workstation');
        assert.equal(pcJson.deviceInfo?.category, 'pc_workstation');

        await withTempDir(async tmpDir => {
          const camScan = await runCli(
            [camTarget.baseUrl, '--camera', '--depth', '0', '--no-history', '--json', '--output', 'cam-shorthand'],
            { cwd: tmpDir }
          );
          assert.equal(camScan.code, 2, `Expected exit 2 for --camera scan, got ${camScan.code}\n${camScan.stderr}`);
          const camReport = JSON.parse(fs.readFileSync(path.join(tmpDir, 'cam-shorthand.json'), 'utf8'));
          assert.equal(camReport.stacks[camTarget.baseUrl].deviceInfo.category, 'ip_camera');
          assertNonIntrusiveHttpRequests(camTarget.requests, 'T4.4 --camera');

          const pcScan = await runCli(
            [pcTarget.baseUrl, '--pc', '--depth', '0', '--no-history', '--json', '--output', 'pc-shorthand'],
            { cwd: tmpDir }
          );
          assert.equal(pcScan.code, 2, `Expected exit 2 for --pc scan, got ${pcScan.code}\n${pcScan.stderr}`);
          const pcReport = JSON.parse(fs.readFileSync(path.join(tmpDir, 'pc-shorthand.json'), 'utf8'));
          assert.equal(pcReport.stacks[pcTarget.baseUrl].deviceInfo.category, 'pc_workstation');
          assertNonIntrusiveHttpRequests(pcTarget.requests, 'T4.4 --pc');
        });
      } finally {
        await tvTarget.close();
        await camTarget.close();
        await pcTarget.close();
      }
    });

    test('T4.5 Bare public IP without device flags runs dual-scheme direct checks without LAN hijack, while explicit deviceCategory enables camera discovery', async () => {
      const probedPortsWithoutFlags = [];
      await withAppHarness(
        {
          inMemory: true,
          tcpProbe: async (_host, port) => {
            probedPortsWithoutFlags.push(port);
            return { open: port === 80 || port === 443 || port === 8080, banner: '' };
          },
          tlsConnect: async ({ minVersion }) => {
            if (minVersion) throw new Error('rejected');
            return {
              cert: { valid_to: new Date(Date.now() + 90 * 86_400_000).toUTCString() },
              protocol: 'TLSv1.3',
              authorized: false,
              authorizationError: 'ERR_TLS_CERT_ALTNAME_INVALID'
            };
          },
          fetcher: async (url) => {
            if (url.startsWith('https://104.21.43.139') || url.startsWith('http://104.21.43.139')) {
              return new Response(
                '<html><title>Direct IP access not allowed | Cloudflare</title><body>Error 1003</body></html>',
                {
                  status: 403,
                  headers: { server: 'cloudflare', 'cf-ray': 'e2e-dfw', 'content-type': 'text/html' }
                }
              );
            }
            return new Response('Not Found', { status: 404 });
          }
        },
        async app => {
          const publicScan = await app.jsonFetch('/api/scan', {
            method: 'POST',
            body: {
              target: '104.21.43.139',
              profile: 'smart',
              checks: ['origin-source-ip', 'ssl-tls', 'http-redirect', 'device-security'],
              maxDepth: 0,
              noHistory: true
            }
          });
          assert.equal(publicScan.status, 202, publicScan.text);
          assert.deepEqual(publicScan.data.targets, ['https://104.21.43.139', 'http://104.21.43.139']);
          assert.equal(publicScan.data.deviceMode, false);

          const events = await app.readSse(`/api/scan/${publicScan.data.scanId}/stream`, { timeoutMs: 25000 });
          const completeEvt = events.find(e => e.event === 'complete');
          assert.equal(completeEvt?.data?.status, 'completed');
          assert.deepEqual(probedPortsWithoutFlags.filter(p => p !== 80 && p !== 443), []);

          const results = completeEvt?.data?.result?.results || [];
          const originRes = results.filter(r => r.checkId === 'origin-source-ip');
          assert.equal(originRes.length, 2);
          assert.ok(originRes.every(r => r.status === 'SAFE' && r.isCdnEdge === true));

          const sslRes = results.filter(r => r.checkId === 'ssl-tls');
          assert.equal(sslRes.length, 2);
          assert.ok(sslRes.every(r => r.status === 'VULNERABLE'));

          const devRes = results.filter(r => r.checkId === 'device-security');
          assert.ok(devRes.every(r => r.status === 'SAFE'));

          // Explicit deviceCategory on a bare public IP enables deviceMode and runs camera checks
          const camFp = await app.jsonFetch('/api/fingerprint', {
            method: 'POST',
            body: {
              target: '198.51.100.77',
              deviceCategory: 'ip_camera'
            }
          });
          assert.equal(camFp.status, 200, camFp.text);
        }
      );

      const probedPortsWithFlag = [];
      await withAppHarness(
        {
          inMemory: true,
          tcpProbe: async (_host, port) => {
            probedPortsWithFlag.push(port);
            return { open: port === 80 || port === 554, banner: '' };
          },
          fetcher: async (url) => {
            if (url.endsWith('/ISAPI/System/deviceInfo')) {
              return new Response(
                '<DeviceInfo><deviceName>Public Cam</deviceName><model>DS-2CD2143</model></DeviceInfo>',
                {
                  status: 200,
                  headers: { 'content-type': 'application/xml', server: 'App-webs/' }
                }
              );
            }
            if (url.startsWith('http://198.51.100.77')) {
              return new Response('Unauthorized', {
                status: 401,
                headers: { server: 'App-webs/', 'www-authenticate': 'Basic realm="Hikvision"' }
              });
            }
            const err = new Error('connect ECONNREFUSED 198.51.100.77:443');
            err.code = 'ECONNREFUSED';
            throw err;
          }
        },
        async app => {
          const camScan = await app.jsonFetch('/api/scan', {
            method: 'POST',
            body: {
              target: '198.51.100.77',
              deviceCategory: 'ip_camera',
              checks: ['device-security'],
              maxDepth: 0,
              noHistory: true
            }
          });
          assert.equal(camScan.status, 202, camScan.text);
          assert.equal(camScan.data.deviceMode, true);
          assert.equal(camScan.data.deviceCategory, 'ip_camera');

          const events = await app.readSse(`/api/scan/${camScan.data.scanId}/stream`, { timeoutMs: 25000 });
          const fpEvt = events.find(e => e.event === 'fingerprint');
          assert.equal(fpEvt?.data?.deviceInfo?.category, 'ip_camera');
          assert.ok(probedPortsWithFlag.includes(554));
        }
      );
    });
  });
});
