import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';

import { mergeConfig } from '../../core/config.js';
import { AuthSessionManager } from '../../core/auth-session.js';
import { runScanner } from '../../scan.js';
import { runCli } from '../../e2e/helpers/cli-runner.mjs';

function makeResponse({ status = 200, headers = {}, body = '' } = {}) {
  const hdrs = new Headers();
  for (const [k, v] of Object.entries(headers)) {
    hdrs.set(k, v);
  }
  return {
    ok: status >= 200 && status < 400,
    status,
    statusText: String(status),
    headers: hdrs,
    url: '',
    async text() {
      return typeof body === 'string' ? body : JSON.stringify(body);
    },
    async json() {
      return typeof body === 'string' ? JSON.parse(body) : body;
    }
  };
}

function startMockHttpServer(handler) {
  return new Promise((resolve, reject) => {
    const server = http.createServer(handler);
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolve({
        server,
        port: addr.port,
        close: () => new Promise(res => server.close(() => res()))
      });
    });
  });
}

test('mergeConfig forwards deviceMode and deviceCategory with CLI precedence over .secscanrc', () => {
  const fromConfig = mergeConfig({}, { deviceMode: true, deviceCategory: 'ip_camera' });
  assert.equal(fromConfig.deviceMode, true);
  assert.equal(fromConfig.deviceCategory, 'ip_camera');

  const fromCli = mergeConfig(
    { device: true, deviceCategory: 'smart_tv' },
    { deviceMode: false, deviceCategory: 'pc_workstation' }
  );
  assert.equal(fromCli.deviceMode, true);
  assert.equal(fromCli.deviceCategory, 'smart_tv');

  const defaults = mergeConfig({}, {});
  assert.equal(defaults.deviceMode, false);
  assert.equal(defaults.deviceCategory, null);
});

test('CLI --help documents --device-category and Smart TV / IP Camera / PC categories; invalid --device-category exits 1', async () => {
  const helpRes = await runCli(['--help']);
  assert.equal(helpRes.code, 0);
  assert.match(helpRes.stdout, /--camera/);
  assert.match(helpRes.stdout, /--pc/);
  assert.match(helpRes.stdout, /--tv/);
  assert.match(helpRes.stdout, /--device-category\s+<cat>/);
  assert.match(helpRes.stdout, /Smart TVs,\s*IP Cameras\/NVRs,\s*PCs\/Workstations\/Servers/);

  const badCatRes = await runCli(['192.168.68.53', '--device', '--device-category', 'bogus-category']);
  assert.equal(badCatRes.code, 1);
  assert.match(badCatRes.stderr, /Invalid --device-category/);
});

test('CLI --detect and --doctor normalize quoted trailing-backslash target and print deviceInfo', async () => {
  const srv = await startMockHttpServer((req, res) => {
    if (req.url === '/api/v2/') {
      res.writeHead(200, { 'Content-Type': 'application/json', Server: 'Tizen/5.5 Samsung' });
      res.end(JSON.stringify({
        device: {
          type: 'Samsung SmartTV',
          name: '[TV] Living Room',
          modelName: 'UN55TU7000',
          os: 'Tizen 5.5',
          wifiMac: 'AA:BB:CC:DD:EE:FF'
        }
      }));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html', Server: 'Tizen/5.5 Samsung' });
    res.end('<html><title>Samsung Smart TV</title></html>');
  });

  try {
    const quotedTarget = `"127.0.0.1:${srv.port}\\"`;

    const detectJsonRes = await runCli(['--detect', '--device', '--device-category', 'tv', '--json', quotedTarget]);
    assert.equal(detectJsonRes.code, 0, detectJsonRes.stderr);
    const parsed = JSON.parse(detectJsonRes.stdout);
    assert.equal(parsed.ok, true);
    assert.equal(parsed.target, `http://127.0.0.1:${srv.port}`);
    assert.ok(parsed.deviceInfo?.detected);
    assert.equal(parsed.deviceInfo.category, 'smart_tv');
    assert.equal(parsed.deviceInfo.vendor, 'Samsung');
    assert.equal(parsed.deviceInfo.modelName, 'UN55TU7000');

    const detectTextRes = await runCli(['--detect', '--device', '--device-category', 'tv', quotedTarget]);
    assert.equal(detectTextRes.code, 0, detectTextRes.stderr);
    assert.match(detectTextRes.stdout, /Device Category\s*:\s*Smart TV/i);
    assert.match(detectTextRes.stdout, /Samsung/);
    assert.match(detectTextRes.stdout, /UN55TU7000/);

    const doctorRes = await runCli(['--doctor', '--allow-private', '--json', quotedTarget]);
    assert.equal(doctorRes.code, 0, doctorRes.stderr);
    const docJson = JSON.parse(doctorRes.stdout);
    assert.equal(docJson.targets[0].ok, true);
    assert.equal(docJson.targets[0].targetUrl, `http://127.0.0.1:${srv.port}`);
  } finally {
    await srv.close();
  }
});

test('runScanner normalizes quoted/backslash targets, forwards fetchWithRetry args, and deduplicates TCP port sweep via cachedDeviceScan', async () => {
  await assert.rejects(
    () => runScanner({
      targets: ['http://192.168.68.53/\\admin'],
      allowPrivate: true,
      noHistory: true,
      silent: true,
      setExitCode: false,
      fetcher: async () => makeResponse({ status: 200 })
    }),
    /Invalid URL|backslash/i
  );

  const portProbeCounts = new Map();
  const rootAttemptUrls = [];
  const openDevicePorts = new Set([8001, 8002, 8080, 9197]);

  const tcpProbe = async (_host, port) => {
    portProbeCounts.set(port, (portProbeCounts.get(port) || 0) + 1);
    return { open: openDevicePorts.has(port), banner: '' };
  };

  const fetcher = async (url) => {
    if (url === 'http://192.168.68.53/' || url === 'http://192.168.68.53') {
      rootAttemptUrls.push(url);
      const err = new Error('connect ECONNREFUSED 192.168.68.53:80');
      err.code = 'ECONNREFUSED';
      throw err;
    }
    if (url.includes(':8001/api/v2/')) {
      return makeResponse({
        status: 200,
        headers: { 'content-type': 'application/json', server: 'Tizen/6.0' },
        body: {
          device: {
            type: 'Samsung SmartTV',
            name: 'Living Room TV',
            modelName: 'QN65Q80A',
            os: 'Tizen 6.0',
            wifiMac: '11:22:33:44:55:66'
          }
        }
      });
    }
    if (url.includes(':8080') || url.includes(':9197') || url.includes(':8002')) {
      return makeResponse({
        status: 200,
        headers: { 'content-type': 'text/plain', server: 'Samsung-UPnP/1.0' },
        body: 'UPnP device ok'
      });
    }
    return makeResponse({ status: 404, body: 'Not Found' });
  };

  const originalLog = console.log;
  const capturedLogs = [];
  console.log = (...args) => capturedLogs.push(args.join(' '));
  try {
    const report = await runScanner({
      targets: ['"192.168.68.53\\"'],
      profile: 'smart',
      deviceMode: true,
      deviceCategory: 'smart_tv',
      allowPrivate: true,
      maxDepth: 0,
      noHistory: true,
      setExitCode: false,
      returnFull: true,
      tcpProbe,
      fetcher
    });

    assert.equal(report.stacks['http://192.168.68.53'].recommendedProfile, 'device');
    const dp = report.stacks['http://192.168.68.53'].deviceInfo;
    assert.ok(dp?.detected);
    assert.equal(dp.category, 'smart_tv');
    assert.equal(dp.vendor, 'Samsung');
    assert.equal(dp.basePortClosed, true);

    // TCP port sweep for 8001 ran once (in fingerprint) and was reused via cachedDeviceScan in device-security
    assert.equal(portProbeCounts.get(8001), 1, 'Expected port 8001 TCP probe to run once without duplicate sweep');

    const devFinding = report.results.find(r => r.checkId === 'device-security');
    assert.ok(devFinding, 'device-security finding must be present');
    assert.ok(Array.isArray(devFinding.files) && devFinding.files.length > 0, 'device-security must keep full sub-findings');

    // Verify failFast / retries=0 forwarded without retry backoff on closed port 80
    assert.ok(rootAttemptUrls.length <= 2, `Expected fail-fast on closed port 80 without 3x retries, got ${rootAttemptUrls.length}`);

    const summaryText = capturedLogs.join('\n');
    assert.match(summaryText, /📺 Device \(http:\/\/192\.168\.68\.53\):/);
    assert.match(summaryText, /Samsung/);
    assert.match(summaryText, /QN65Q80A/);
    assert.match(summaryText, /🔎 Device Sub-Findings/);
  } finally {
    console.log = originalLog;
  }
});

test('runScanner skips HTTP-only checks cleanly when basePortClosed and no active HTTP/HTTPS origins exist', async () => {
  const closedHttpRequests = [];
  const openPorts = new Set([445, 3389, 22]);

  const tcpProbe = async (_host, port) => {
    if (port === 22) return { open: true, banner: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6' };
    return { open: openPorts.has(port), banner: '' };
  };

  const fetcher = async (url) => {
    closedHttpRequests.push(url);
    const err = new Error('connect ECONNREFUSED');
    err.code = 'ECONNREFUSED';
    throw err;
  };

  const report = await runScanner({
    targets: ['http://192.168.68.99'],
    profile: 'smart',
    deviceMode: true,
    deviceCategory: 'pc_workstation',
    allowPrivate: true,
    maxDepth: 0,
    noHistory: true,
    silent: true,
    setExitCode: false,
    returnFull: true,
    tcpProbe,
    fetcher
  });

  const fp = report.stacks['http://192.168.68.99'];
  assert.equal(fp.deviceInfo.category, 'pc_workstation');
  assert.equal(fp.deviceInfo.basePortClosed, true);
  assert.equal(fp.deviceInfo.activeHttpOrigin, null);
  assert.equal(fp.deviceInfo.activeHttpsOrigin, null);

  // Only non-HTTP device/OS checks should execute; HTTP-only checks must be skipped cleanly
  const nonHttpCheckIds = new Set(['device-security', 'os-security']);
  assert.ok(report.results.length >= 1 && report.results.length <= 2);
  assert.ok(report.results.every(r => nonHttpCheckIds.has(r.checkId)));
  const deviceFinding = report.results.find(r => r.checkId === 'device-security');
  assert.ok(deviceFinding);
  assert.notEqual(deviceFinding.status, 'SAFE');
  assert.ok(Array.isArray(deviceFinding.files) && deviceFinding.files.length > 0);
  // Check phase should not send HTTP requests to closed port 80
  assert.equal(closedHttpRequests.filter(u => u.includes('/.git') || u.includes('/robots.txt')).length, 0);
});

test('runScanner preserves TCP banner across cachedDeviceScan (SSHv1 HIGH & VNC RFB) with 1 tcpProbe per port', async () => {
  const portProbeCounts = new Map();
  const tcpProbe = async (_host, port) => {
    portProbeCounts.set(port, (portProbeCounts.get(port) || 0) + 1);
    if (port === 22) return { open: true, banner: 'SSH-1.5-OpenSSH_3.8' };
    if (port === 5900) return { open: true, banner: 'RFB 003.008' };
    return { open: false, banner: '' };
  };

  const fetcher = async () => {
    const err = new Error('connect ECONNREFUSED');
    err.code = 'ECONNREFUSED';
    throw err;
  };

  const report = await runScanner({
    targets: ['http://192.168.68.88'],
    profile: 'smart',
    deviceMode: true,
    allowPrivate: true,
    maxDepth: 0,
    noHistory: true,
    silent: true,
    setExitCode: false,
    returnFull: true,
    tcpProbe,
    fetcher
  });

  assert.equal(portProbeCounts.get(22), 1);
  assert.equal(portProbeCounts.get(5900), 1);

  const devFinding = report.results.find(r => r.checkId === 'device-security');
  assert.ok(devFinding, 'device-security finding must be present');
  const sshFile = devFinding.files.find(f => f.port === 22);
  const vncFile = devFinding.files.find(f => f.port === 5900);
  assert.ok(sshFile, 'SSH finding must be present');
  assert.equal(sshFile.name, 'Exposed Legacy SSHv1 Service (22/TCP)');
  assert.equal(sshFile.severity, 'HIGH');
  assert.equal(sshFile.statusTag, 'VULNERABLE');
  assert.ok(vncFile, 'VNC finding must be present');
  assert.match(vncFile.matchedSignal, /VNC RFB 003\.008/);
});

test('AuthSessionManager.wrapFetch preserves isDefaultFetch when set and omits it when absent', () => {
  const mgr = new AuthSessionManager();
  const baseWithFlag = async () => ({ status: 200, headers: new Headers() });
  baseWithFlag.isDefaultFetch = true;
  baseWithFlag.hasCustomFetcher = false;
  const wrappedWithFlag = mgr.wrapFetch(baseWithFlag);
  assert.equal(wrappedWithFlag.isDefaultFetch, true);
  assert.equal(wrappedWithFlag.hasCustomFetcher, false);

  const baseWithoutFlag = async () => ({ status: 200, headers: new Headers() });
  baseWithoutFlag.hasCustomFetcher = true;
  const wrappedWithoutFlag = mgr.wrapFetch(baseWithoutFlag);
  assert.equal('isDefaultFetch' in wrappedWithoutFlag, false);
  assert.equal(wrappedWithoutFlag.hasCustomFetcher, true);
});

test('runScanner bounds per-page check concurrency cleanly and respects checkConcurrency option', async () => {
  const selectedChecks = [
    'security-headers',
    'cookie-security',
    'http-methods',
    'http-redirect',
    'cors',
    'sql-errors',
    'php-version',
    'system-health',
    'sri-supply-chain',
    'ai-llm-exposure'
  ];

  const measureMaxInFlight = async (checkConcurrencyOpt) => {
    let checkPhaseStarted = false;
    let inFlight = 0;
    let maxInFlight = 0;

    const fetcher = async () => {
      if (checkPhaseStarted) {
        inFlight += 1;
        if (inFlight > maxInFlight) maxInFlight = inFlight;
      }
      try {
        await new Promise(resolve => setTimeout(resolve, 25));
        return makeResponse({
          status: 200,
          headers: { 'content-type': 'text/html' },
          body: '<html><head><title>Test</title></head><body>ok</body></html>'
        });
      } finally {
        if (checkPhaseStarted) {
          inFlight -= 1;
        }
      }
    };

    const report = await runScanner({
      targets: ['http://192.168.68.77'],
      checks: selectedChecks,
      ...(checkConcurrencyOpt !== undefined ? { checkConcurrency: checkConcurrencyOpt } : {}),
      allowPrivate: true,
      maxDepth: 0,
      noHistory: true,
      silent: true,
      setExitCode: false,
      returnFull: true,
      multiPort: false,
      fetcher,
      onProgress: (evt) => {
        if (evt?.phase === 'fingerprint') {
          checkPhaseStarted = true;
        }
      }
    });

    assert.equal(report.results.length, selectedChecks.length);
    return maxInFlight;
  };

  const boundedTwo = await measureMaxInFlight(2);
  assert.equal(boundedTwo, 2, `Expected max 2 concurrent checks with checkConcurrency=2, got ${boundedTwo}`);

  const boundedDefault = await measureMaxInFlight(undefined);
  assert.ok(
    boundedDefault >= 4 && boundedDefault <= 8,
    `Expected default bounded check concurrency between 4 and 8 for 10 checks, got ${boundedDefault}`
  );
});

test('runScanner destroys governedFetch keep-alive agents on failure (saveReport EISDIR leaves 0 open sockets)', async () => {
  const openSockets = new Set();
  const srv = await startMockHttpServer((_req, res) => {
    res.writeHead(200, {
      'Content-Type': 'text/html',
      Server: 'Apache/2.4.63 (Unix)',
      Connection: 'keep-alive'
    });
    res.end('<html><head><title>KeepAlive Test</title></head><body>ok</body></html>');
  });
  srv.server.keepAliveTimeout = 60000;
  srv.server.on('connection', (sock) => {
    openSockets.add(sock);
    sock.on('close', () => openSockets.delete(sock));
  });

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secscan-eisdir-'));
  const outputStem = path.join(tmpDir, 'out_is_dir');
  fs.mkdirSync(`${outputStem}.json`, { recursive: true });

  try {
    await assert.rejects(
      () => runScanner({
        targets: [`http://127.0.0.1:${srv.port}`],
        checks: ['security-headers'],
        allowPrivate: true,
        maxDepth: 0,
        noHistory: true,
        silent: true,
        setExitCode: false,
        multiPort: false,
        json: true,
        output: outputStem
      }),
      (err) => err && err.code === 'EISDIR'
    );

    await new Promise(resolve => setTimeout(resolve, 30));
    assert.equal(openSockets.size, 0, `Expected 0 open keep-alive sockets after EISDIR throw, found ${openSockets.size}`);
  } finally {
    for (const sock of openSockets) {
      try { sock.destroy(); } catch {}
    }
    await srv.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('CLI --camera, --pc, --tv, and category --profile flags set deviceMode, allowPrivate, and deviceCategory cleanly', async () => {
  const camSrv = await startMockHttpServer((req, res) => {
    if (req.url === '/ISAPI/System/deviceInfo') {
      res.writeHead(200, { 'Content-Type': 'application/xml', Server: 'App-webs/' });
      res.end('<DeviceInfo><deviceName>Gate Cam</deviceName><model>DS-2CD2143</model></DeviceInfo>');
      return;
    }
    res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="Hikvision"' });
    res.end('Unauthorized');
  });

  const pcSrv = await startMockHttpServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html', Server: 'Werkzeug/3.0.1 Python/3.11' });
    res.end('<html><title>Werkzeug Debugger</title></html>');
  });

  const tvSrv = await startMockHttpServer((req, res) => {
    if (req.url === '/api/v2/') {
      res.writeHead(200, { 'Content-Type': 'application/json', Server: 'Tizen/6.0' });
      res.end(JSON.stringify({ device: { type: 'Samsung SmartTV', modelName: 'QN55Q80C', OS: 'Tizen' } }));
      return;
    }
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
  });

  try {
    const camRes = await runCli([`127.0.0.1:${camSrv.port}`, '--camera', '--detect', '--json']);
    assert.equal(camRes.code, 0, camRes.stderr);
    const camJson = JSON.parse(camRes.stdout);
    assert.equal(camJson.deviceMode, true);
    assert.equal(camJson.allowPrivate, true);
    assert.equal(camJson.deviceCategory, 'ip_camera');
    assert.equal(camJson.deviceInfo?.category, 'ip_camera');

    const pcRes = await runCli([`127.0.0.1:${pcSrv.port}`, '--pc', '--detect', '--json']);
    assert.equal(pcRes.code, 0, pcRes.stderr);
    const pcJson = JSON.parse(pcRes.stdout);
    assert.equal(pcJson.deviceMode, true);
    assert.equal(pcJson.allowPrivate, true);
    assert.equal(pcJson.deviceCategory, 'pc_workstation');
    assert.equal(pcJson.deviceInfo?.category, 'pc_workstation');

    const tvRes = await runCli([`127.0.0.1:${tvSrv.port}`, '--tv', '--detect', '--json']);
    assert.equal(tvRes.code, 0, tvRes.stderr);
    const tvJson = JSON.parse(tvRes.stdout);
    assert.equal(tvJson.deviceMode, true);
    assert.equal(tvJson.allowPrivate, true);
    assert.equal(tvJson.deviceCategory, 'smart_tv');
    assert.equal(tvJson.deviceInfo?.category, 'smart_tv');

    // Explicit --device-category overrides --tv
    const overrideRes = await runCli([`127.0.0.1:${camSrv.port}`, '--tv', '--device-category', 'ip_camera', '--detect', '--json']);
    assert.equal(overrideRes.code, 0, overrideRes.stderr);
    const overrideJson = JSON.parse(overrideRes.stdout);
    assert.equal(overrideJson.deviceCategory, 'ip_camera');

    // Category-specific --profile infers deviceCategory when --device-category is omitted
    const profCamRes = await runCli([`127.0.0.1:${camSrv.port}`, '--profile', 'camera', '--detect', '--json']);
    assert.equal(profCamRes.code, 0, profCamRes.stderr);
    const profCamJson = JSON.parse(profCamRes.stdout);
    assert.equal(profCamJson.deviceMode, true);
    assert.equal(profCamJson.allowPrivate, true);
    assert.equal(profCamJson.deviceCategory, 'ip_camera');

    const profPcRes = await runCli([`127.0.0.1:${pcSrv.port}`, '--profile', 'workstation', '--detect', '--json']);
    assert.equal(profPcRes.code, 0, profPcRes.stderr);
    const profPcJson = JSON.parse(profPcRes.stdout);
    assert.equal(profPcJson.deviceMode, true);
    assert.equal(profPcJson.deviceCategory, 'pc_workstation');
  } finally {
    await camSrv.close();
    await pcSrv.close();
    await tvSrv.close();
  }
});

test('runScanner on bare public IP without device flags does NOT trigger multi-port sweep or hijack profile', async () => {
  const probedPorts = [];
  const report = await runScanner({
    targets: ['http://104.21.43.139'],
    profile: 'smart',
    allowPrivate: true,
    maxDepth: 0,
    noHistory: true,
    silent: true,
    setExitCode: false,
    returnFull: true,
    checks: ['device-security'],
    tcpProbe: async (_h, p) => {
      probedPorts.push(p);
      return { open: [80, 443, 8080, 8443].includes(p), banner: '' };
    },
    fetcher: async () => makeResponse({
      status: 403,
      headers: { server: 'cloudflare', 'cf-ray': '8abc-MIA' },
      body: '<html><title>Direct IP access not allowed</title></html>'
    })
  });

  assert.deepEqual(probedPorts, []);
  const fp = report.stacks['http://104.21.43.139'];
  assert.equal(fp.primary, 'cloudflare');
  assert.notEqual(fp.recommendedProfile, 'device');
  const devResult = report.results.find(r => r.checkId === 'device-security');
  assert.ok(devResult);
  assert.equal(devResult.status, 'SAFE');
  assert.match(devResult.reason || '', /public host without device scan mode enabled/i);
});

test('runScanner on bare public IP with explicit deviceCategory activates deviceMode and camera checks without hijacking omitted-flag scans', async () => {
  const probedPorts = [];
  const camReport = await runScanner({
    targets: ['198.51.100.77'],
    profile: 'smart',
    deviceCategory: 'ip_camera',
    maxDepth: 0,
    noHistory: true,
    silent: true,
    setExitCode: false,
    returnFull: true,
    checks: ['device-security'],
    tcpProbe: async (_h, p) => {
      probedPorts.push(p);
      return { open: p === 80 || p === 554, banner: '' };
    },
    rtspProbe: async (_h, port) => ({
      ok: true,
      port,
      status: 200,
      server: 'Hikvision-RTSP/1.0',
      describeStatus: 200,
      hasSdp: true,
      unauthenticatedStream: true
    }),
    fetcher: async (url) => {
      if (url.endsWith('/ISAPI/System/deviceInfo')) {
        return makeResponse({
          status: 200,
          headers: { 'content-type': 'application/xml', server: 'App-webs/' },
          body: '<DeviceInfo><deviceName>Perimeter Cam</deviceName><model>DS-2CD2143</model></DeviceInfo>'
        });
      }
      if (url.startsWith('http://198.51.100.77')) {
        return makeResponse({
          status: 401,
          headers: { server: 'App-webs/', 'www-authenticate': 'Basic realm="Hikvision"' },
          body: 'Unauthorized'
        });
      }
      const err = new Error('connect ECONNREFUSED 198.51.100.77:443');
      err.code = 'ECONNREFUSED';
      throw err;
    }
  });

  assert.ok(probedPorts.includes(554), 'Explicit deviceCategory on bare public IP should probe camera ports');
  const fp = camReport.stacks['http://198.51.100.77'];
  assert.equal(fp.primary, 'device');
  assert.equal(fp.deviceInfo?.category, 'ip_camera');
  const devResult = camReport.results.find(r => r.checkId === 'device-security');
  assert.ok(devResult);
  assert.equal(devResult.status, 'VULNERABLE');
  assert.equal(devResult.deviceCategory, 'ip_camera');
});
