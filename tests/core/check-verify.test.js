import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyFindingBeforeReport } from '../../core/check-verify.js';
import { createTrackedFetch } from '../../core/reproduction.js';
import { EnrichEngine } from '../../core/enrich.js';
import runDeviceCheck from '../../checks/device-security.js';

describe('Pre-Report Verification Gate (verifyFindingBeforeReport) — Non-HTTP/TCP & HTTP Strictness', () => {
  test('preserves raw method:TCP, tcp://, and rtsp:// findings even when HTTP probes returned 404/405', () => {
    const traces404 = [
      { method: 'GET', url: 'http://192.168.68.53/', status: 404, responseSnippet: 'Not Found' },
      { method: 'GET', url: 'http://192.168.68.53:5555/', status: 404, responseSnippet: 'Cannot GET /' }
    ];

    const tcpFinding = verifyFindingBeforeReport({
      name: 'Android ADB Exposed',
      checkId: 'device-security',
      status: 'VULNERABLE',
      severity: 'CRITICAL',
      method: 'TCP',
      path: ':5555',
      url: 'http://192.168.68.53:5555/',
      observedStatus: 404,
      reproduction: { method: 'TCP', url: 'tcp://192.168.68.53:5555', responseStatus: 404 }
    }, { capturedTraces: traces404 });

    assert.equal(tcpFinding.status, 'VULNERABLE');
    assert.equal(tcpFinding.severity, 'CRITICAL');

    const rtspFinding = verifyFindingBeforeReport({
      name: 'RTSP Stream Exposed',
      checkId: 'device-security',
      status: 'VULNERABLE',
      severity: 'HIGH',
      method: 'RTSP',
      url: 'rtsp://192.168.1.20:554/stream1',
      reproduction: { method: 'OPTIONS', url: 'rtsp://192.168.1.20:554/stream1', responseStatus: 405 }
    }, { capturedTraces: traces404 });

    assert.equal(rtspFinding.status, 'VULNERABLE');

    const tcpSchemeFinding = verifyFindingBeforeReport({
      name: 'Telnet Port Open',
      checkId: 'device-security',
      status: 'SUSPICIOUS',
      severity: 'HIGH',
      url: 'tcp://192.168.1.1:23'
    }, { capturedTraces: [{ method: 'GET', url: 'tcp://192.168.1.1:23', status: 404 }] });

    assert.equal(tcpSchemeFinding.status, 'SUSPICIOUS');
  });

  test('preserves device-security port-exposed findings (ADB 5555, RTSP 554, SMB 445, SSH 22, RDP 3389, VNC 5900, 8080/TCP) against 404 HTTP probes', () => {
    const traces = [
      { method: 'GET', url: 'http://192.168.68.53:8080/', status: 404, responseSnippet: 'Not Found' },
      { method: 'GET', url: 'http://192.168.68.53:9197/dmr', status: 404, responseSnippet: 'Not Found' }
    ];

    const port8080Fallback = verifyFindingBeforeReport({
      name: 'device-security',
      checkId: 'device-security',
      status: 'SUSPICIOUS',
      severity: 'LOW',
      path: '/api/v2/',
      url: 'http://192.168.68.53:8080/',
      observedStatus: 200,
      files: [
        {
          name: 'Smart TV Companion Web / DIAL Service Port Exposed (8080/TCP)',
          path: '/api/v2/',
          url: 'http://192.168.68.53:8080/',
          port: 8080,
          method: 'GET',
          status: 404,
          matchedSignal: 'Smart TV companion HTTP port 8080 open'
        }
      ]
    }, { capturedTraces: traces });

    assert.equal(port8080Fallback.status, 'SUSPICIOUS');

    const mixedPorts = verifyFindingBeforeReport({
      name: 'device-security',
      checkId: 'device-security',
      status: 'VULNERABLE',
      severity: 'CRITICAL',
      path: ':5555',
      url: 'http://192.168.68.53:5555/',
      files: [
        { name: 'ADB (5555/TCP)', path: ':5555', url: 'http://192.168.68.53:5555/', port: 5555, method: 'TCP', status: 200 },
        { name: 'RTSP (554/TCP)', path: ':554', url: 'http://192.168.68.53:554/', port: 554, method: 'TCP', status: 200 },
        { name: 'SMB (445/TCP)', path: ':445', url: 'http://192.168.68.53:445/', port: 445, method: 'TCP', status: 200 },
        { name: 'SSH (22/TCP)', path: ':22', url: 'http://192.168.68.53:22/', port: 22, method: 'TCP', status: 200 },
        { name: 'RDP (3389/TCP)', path: ':3389', url: 'http://192.168.68.53:3389/', port: 3389, method: 'TCP', status: 200 },
        { name: 'VNC (5900/TCP)', path: ':5900', url: 'http://192.168.68.53:5900/', port: 5900, method: 'TCP', status: 200 }
      ]
    }, { capturedTraces: traces });

    assert.equal(mixedPorts.status, 'VULNERABLE');
  });

  test('end-to-end device-security + createTrackedFetch + EnrichEngine keeps TCP 5555 VULNERABLE with nc -vz when HTTP returns 404', async () => {
    const ip = '192.168.68.99';
    const baseFetch = async (url) => {
      if (url.includes(':5555')) {
        return { status: 404, headers: {}, text: 'Not Found' };
      }
      return { status: 404, headers: {}, text: 'Not Found' };
    };
    baseFetch.hasCustomFetcher = true;
    const tracked = createTrackedFetch(baseFetch);

    const tcpProbe = async (_host, port) => ({
      port,
      open: port === 5555
    });

    const raw = await runDeviceCheck(`http://${ip}`, tracked, {
      allowPrivate: true,
      tcpProbe
    });
    assert.equal(raw.status, 'VULNERABLE');

    const engine = new EnrichEngine();
    const enriched = engine.enrichFinding({
      target: `http://${ip}`,
      checkId: 'device-security',
      ...raw
    }, { capturedTraces: tracked.getTraces() });

    assert.equal(enriched.status, 'VULNERABLE');
    assert.equal(enriched.reproduction?.method, 'TCP');
    assert.equal(enriched.reproduction?.curl, `nc -vz '${ip}' 5555`);
  });

  test('negative controls: HTTP-only device-security, env, ignition, and sensitive-files findings with 404/405/redirect STILL downgrade to SAFE', () => {
    const envDowngraded = verifyFindingBeforeReport({
      name: 'env exposure',
      checkId: 'env',
      status: 'VULNERABLE',
      severity: 'CRITICAL',
      url: 'https://example.com/.env',
      observedStatus: 404,
      files: [{ path: '/.env', url: 'https://example.com/.env', status: 404 }]
    });
    assert.equal(envDowngraded.status, 'SAFE');

    const ignitionDowngraded = verifyFindingBeforeReport({
      name: 'ignition RCE',
      checkId: 'ignition',
      status: 'VULNERABLE',
      severity: 'CRITICAL',
      url: 'https://example.com/_ignition/execute-solution',
      files: [{ path: '/_ignition/execute-solution', url: 'https://example.com/_ignition/execute-solution', status: 200, preview: 'The route _ignition/execute-solution could not be found.' }]
    });
    assert.equal(ignitionDowngraded.status, 'SAFE');

    const sensitiveRedirectDowngraded = verifyFindingBeforeReport({
      name: 'sensitive files',
      checkId: 'sensitive-files',
      status: 'VULNERABLE',
      severity: 'MEDIUM',
      url: 'https://example.com/.git/config'
    }, {
      capturedTraces: [
        {
          method: 'GET',
          url: 'https://example.com/.git/config',
          finalUrl: 'https://example.com/login',
          redirected: true,
          status: 200
        }
      ]
    });
    assert.equal(sensitiveRedirectDowngraded.status, 'SAFE');

    // HTTP-only device-security finding (no TCP/port-exposed markers) with 404 must still downgrade
    const httpOnlyDeviceDowngraded = verifyFindingBeforeReport({
      name: 'device-security',
      checkId: 'device-security',
      status: 'VULNERABLE',
      severity: 'HIGH',
      path: '/api/v2/',
      url: 'http://192.168.68.53:8001/api/v2/',
      files: [
        {
          name: 'Samsung Smart TV REST API',
          path: '/api/v2/',
          url: 'http://192.168.68.53:8001/api/v2/',
          method: 'GET',
          status: 404
        }
      ]
    }, {
      capturedTraces: [
        { method: 'GET', url: 'http://192.168.68.53:8001/api/v2/', status: 404, responseSnippet: 'Not Found' }
      ]
    });
    assert.equal(httpOnlyDeviceDowngraded.status, 'SAFE');
  });
});
