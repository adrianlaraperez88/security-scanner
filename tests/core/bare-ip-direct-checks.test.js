import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { getScanners } from '../../core/registry.js';
import { selectScannersForStack } from '../../core/profiles.js';
import runHttpRedirect from '../../checks/http-redirect.js';
import { run as runOriginSourceIp } from '../../checks/origin-source-ip.js';
import { groupFindings } from '../../core/html-report.js';
import { runScanner } from '../../scan.js';
import { createAppServer } from '../../core/server.js';

const FUTURE_CERT = new Date(Date.now() + 90 * 86_400_000).toUTCString();

function makeResponse({ status = 200, headers = {}, body = '<html>ok</html>', url = '' } = {}) {
  return {
    status,
    url,
    headers: new Headers(headers),
    text: async () => (typeof body === 'string' ? body : JSON.stringify(body))
  };
}

function dispatchServer(server, pathname, { method = 'POST', body } = {}) {
  return new Promise((resolve, reject) => {
    const raw = body !== undefined ? JSON.stringify(body) : '';
    const req = http.request({
      hostname: '127.0.0.1',
      port: server.address().port,
      path: pathname,
      method,
      headers: body !== undefined
        ? {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(raw)
          }
        : {}
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(text); } catch {}
        resolve({ status: res.statusCode, text, json });
      });
    });
    req.on('error', reject);
    if (body !== undefined) req.write(raw);
    req.end();
  });
}

describe('R2: Direct-Server Checks for Bare Public IPs', () => {
  test('selectScannersForStack includes origin-source-ip in smart profile', async () => {
    const scanners = await getScanners();

    const genericSel = selectScannersForStack(scanners, {
      profile: 'smart',
      fp: { detectedTags: [] }
    });
    assert.ok(genericSel.activeScanners.some(s => s.name === 'origin-source-ip'));
    assert.ok(genericSel.activeScanners.some(s => s.name === 'subdomain-takeover'));
    assert.ok(genericSel.activeScanners.some(s => s.name === 'ssl-tls'));
    assert.ok(genericSel.activeScanners.some(s => s.name === 'http-redirect'));

    const cfSel = selectScannersForStack(scanners, {
      profile: 'smart',
      fp: { detectedTags: ['cloudflare'] }
    });
    assert.ok(cfSel.activeScanners.some(s => s.name === 'origin-source-ip'));
  });

  test('http-redirect returns SAFE when port 80 refuses connection and coordinates via siblingSchemes', async () => {
    const connRefusedFetch = async () => {
      const err = new Error('connect ECONNREFUSED 198.51.100.51:80');
      err.code = 'ECONNREFUSED';
      throw err;
    };
    const closed80Res = await runHttpRedirect('https://198.51.100.51/', connRefusedFetch, {
      siblingSchemes: ['https:']
    });
    assert.equal(closed80Res.status, 'SAFE');
    assert.equal(closed80Res.severity, 'NONE');
    assert.match(closed80Res.detail, /port 80 is closed\/unreachable/i);

    // Without https sibling, http:// keeps legacy skip message
    const httpOnlySkip = await runHttpRedirect('http://198.51.100.51/', async () => ({ status: 200, headers: {} }), {
      siblingSchemes: ['http:']
    });
    assert.equal(httpOnlySkip.status, 'SAFE');
    assert.match(httpOnlySkip.detail, /already HTTP/i);

    // With https sibling, http:// runs the same redirect probe so groupFindings stays consistent
    const noRedirectFetch = async () => ({ status: 200, headers: {}, text: 'Plaintext HTTP' });
    const httpsRes = await runHttpRedirect('https://104.21.43.139/', noRedirectFetch, {
      siblingSchemes: ['https:', 'http:']
    });
    const httpRes = await runHttpRedirect('http://104.21.43.139/', noRedirectFetch, {
      siblingSchemes: ['https:', 'http:']
    });
    assert.equal(httpsRes.status, 'VULNERABLE');
    assert.equal(httpRes.status, 'VULNERABLE');
    const grouped = groupFindings([
      { target: 'https://104.21.43.139/', checkId: 'http-redirect', ...httpsRes },
      { target: 'http://104.21.43.139/', checkId: 'http-redirect', ...httpRes }
    ]);
    assert.equal(grouped.length, 1);
    assert.equal(grouped[0].status, 'VULNERABLE');
    assert.equal(grouped[0].pages.length, 2);
  });

  test('runScanner executes direct-server checks on dual-scheme bare Cloudflare IP without device hijack or scheme contradictions', async () => {
    const report = await runScanner({
      targets: ['104.21.43.139'],
      profile: 'smart',
      maxDepth: 0,
      noHistory: true,
      silent: true,
      setExitCode: false,
      returnFull: true,
      portProbe: async () => ({ open: true, banner: '' }),
      tlsConnect: async ({ minVersion }) => {
        if (minVersion) throw new Error('rejected');
        return {
          cert: { valid_to: FUTURE_CERT },
          protocol: 'TLSv1.3',
          authorized: false,
          authorizationError: 'ERR_TLS_CERT_ALTNAME_INVALID'
        };
      },
      fetcher: async (url) => {
        if (url.startsWith('https://104.21.43.139')) {
          return makeResponse({
            status: 403,
            headers: { server: 'cloudflare', 'cf-ray': '9999-DFW', 'content-type': 'text/html' },
            body: '<html><title>Direct IP access not allowed | Cloudflare</title><body>Error 1003</body></html>'
          });
        }
        return makeResponse({
          status: 403,
          headers: { server: 'cloudflare', 'cf-ray': '9999-DFW', 'content-type': 'text/html' },
          body: '<html><title>Direct IP access not allowed | Cloudflare</title><body>Error 1003</body></html>'
        });
      }
    });

    assert.ok(report.stacks['https://104.21.43.139']);
    assert.ok(report.stacks['http://104.21.43.139']);
    assert.equal(Boolean(report.stacks['https://104.21.43.139'].deviceInfo?.detected), false);
    assert.equal(Boolean(report.stacks['http://104.21.43.139'].deviceInfo?.detected), false);
    assert.notEqual(report.stacks['https://104.21.43.139'].recommendedProfile, 'device');

    const executedChecks = new Set(report.results.map(r => r.checkId));
    for (const expected of ['origin-source-ip', 'ssl-tls', 'http-redirect', 'security-headers', 'server-disclosure']) {
      assert.ok(executedChecks.has(expected), `Expected smart bare-IP scan to execute ${expected}`);
    }

    const originResults = report.results.filter(r => r.checkId === 'origin-source-ip');
    assert.ok(originResults.length >= 2);
    for (const r of originResults) {
      assert.equal(r.status, 'SAFE');
      assert.equal(r.isCdnEdge, true);
      assert.equal(r.cdnProvider, 'Cloudflare');
    }

    const grouped = groupFindings(report.results);
    const sslGroups = grouped.filter(g => g.checkId === 'ssl-tls');
    assert.equal(sslGroups.length, 1);
    assert.equal(sslGroups[0].status, 'VULNERABLE');

    const redirectGroups = grouped.filter(g => g.checkId === 'http-redirect');
    assert.equal(redirectGroups.length, 1);
    assert.equal(redirectGroups[0].status, 'SAFE');

    const originGroups = grouped.filter(g => g.checkId === 'origin-source-ip');
    assert.equal(originGroups.length, 1);
    assert.equal(originGroups[0].status, 'SAFE');
  });

  test('runScanner groups dual-scheme bare non-CDN origin IP with valid TLS, 301 HTTP->HTTPS redirect, and origin leak consistently', async () => {
    const report = await runScanner({
      targets: ['198.51.100.52'],
      profile: 'smart',
      checks: ['origin-source-ip', 'ssl-tls', 'http-redirect', 'security-headers', 'server-disclosure'],
      maxDepth: 0,
      noHistory: true,
      silent: true,
      setExitCode: false,
      returnFull: true,
      tlsConnect: async ({ minVersion }) => {
        if (minVersion) throw new Error('rejected');
        return {
          cert: { valid_to: FUTURE_CERT },
          protocol: 'TLSv1.3',
          authorized: true
        };
      },
      fetcher: async (url) => {
        if (url.startsWith('http://198.51.100.52')) {
          return makeResponse({
            status: 301,
            headers: {
              server: 'Apache/2.4.58 (Ubuntu)',
              location: 'https://198.51.100.52/',
              'content-type': 'text/html'
            },
            body: ''
          });
        }
        return makeResponse({
          status: 200,
          headers: {
            server: 'Apache/2.4.58 (Ubuntu)',
            'x-origin-ip': '10.0.12.34',
            'content-type': 'text/html'
          },
          body: '<html><head><title>Apache2 Ubuntu Default Page: It works</title></head><body>It works!</body></html>'
        });
      }
    });

    assert.ok(report.stacks['https://198.51.100.52']);
    assert.ok(report.stacks['http://198.51.100.52']);

    const grouped = groupFindings(report.results);
    const sslGroups = grouped.filter(g => g.checkId === 'ssl-tls');
    assert.equal(sslGroups.length, 1);
    assert.equal(sslGroups[0].status, 'SAFE');

    const redirectGroups = grouped.filter(g => g.checkId === 'http-redirect');
    assert.equal(redirectGroups.length, 1);
    assert.equal(redirectGroups[0].status, 'SAFE');

    const originHttps = report.results.find(r => r.checkId === 'origin-source-ip' && r.target.startsWith('https://'));
    assert.equal(originHttps?.status, 'SUSPICIOUS');
    assert.equal(originHttps?.isCdnEdge, false);
  });

  test('runScanner handles http-only non-CDN bare IP and https-only bare IP with closed port 80 & SNI alert', async () => {
    // 1. HTTP-only non-CDN public IP serving default nginx page
    const httpOnlyReport = await runScanner({
      targets: ['198.51.100.50'],
      profile: 'smart',
      maxDepth: 0,
      noHistory: true,
      silent: true,
      setExitCode: false,
      returnFull: true,
      fetcher: async (url) => {
        if (url.startsWith('http://198.51.100.50')) {
          return makeResponse({
            status: 200,
            headers: { server: 'nginx/1.24.0', 'content-type': 'text/html' },
            body: '<html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1></body></html>'
          });
        }
        const err = new Error('connect ECONNREFUSED 198.51.100.50:443');
        err.code = 'ECONNREFUSED';
        throw err;
      }
    });

    const httpOnlySsl = httpOnlyReport.results.find(r => r.checkId === 'ssl-tls');
    assert.equal(httpOnlySsl.status, 'SUSPICIOUS');
    assert.equal(httpOnlySsl.severity, 'HIGH');
    assert.match(httpOnlySsl.detail, /not using HTTPS/i);

    const httpOnlyOrigin = httpOnlyReport.results.find(r => r.checkId === 'origin-source-ip');
    assert.equal(httpOnlyOrigin.status, 'SUSPICIOUS');
    assert.equal(httpOnlyOrigin.severity, 'MEDIUM');
    assert.equal(httpOnlyOrigin.poeLevel, 3);

    // 2. HTTPS-only bare IP (port 80 closed) with SNI-required TLS alert
    const httpsOnlyReport = await runScanner({
      targets: ['198.51.100.51'],
      profile: 'smart',
      checks: ['ssl-tls', 'http-redirect', 'origin-source-ip', 'security-headers', 'server-disclosure'],
      maxDepth: 0,
      noHistory: true,
      silent: true,
      setExitCode: false,
      returnFull: true,
      tlsConnect: async () => {
        throw Object.assign(new Error('tlsv1 alert unrecognized name'), {
          code: 'ERR_SSL_TLSV1_ALERT_UNRECOGNIZED_NAME'
        });
      },
      fetcher: async (url) => {
        if (url.startsWith('https://198.51.100.51')) {
          return makeResponse({
            status: 200,
            headers: { server: 'Caddy', 'content-type': 'text/html' },
            body: '<html><body>Secure Endpoint</body></html>'
          });
        }
        const err = new Error('connect ECONNREFUSED 198.51.100.51:80');
        err.code = 'ECONNREFUSED';
        throw err;
      }
    });

    const httpsOnlyRedirect = httpsOnlyReport.results.find(r => r.checkId === 'http-redirect');
    assert.equal(httpsOnlyRedirect.status, 'SAFE');
    assert.match(httpsOnlyRedirect.detail, /port 80 is closed\/unreachable/i);

    const httpsOnlySsl = httpsOnlyReport.results.find(r => r.checkId === 'ssl-tls');
    assert.equal(httpsOnlySsl.status, 'ERROR');
    assert.equal(httpsOnlySsl.sniRequired, true);
    assert.match(httpsOnlySsl.reason, /SNI/i);

    const httpsOnlyOrigin = httpsOnlyReport.results.find(r => r.checkId === 'origin-source-ip');
    assert.equal(httpsOnlyOrigin.status, 'SAFE');
    assert.equal(httpsOnlyOrigin.isCdnEdge, false);
  });

  test('server API POST /api/scan runs direct-server checks on bare public IP without device hijack or contradictions', async () => {
    const server = createAppServer({
      inMemory: true,
      tlsConnect: async ({ minVersion }) => {
        if (minVersion) throw new Error('rejected');
        return {
          cert: { valid_to: FUTURE_CERT },
          protocol: 'TLSv1.3',
          authorized: false,
          authorizationError: 'ERR_TLS_CERT_ALTNAME_INVALID'
        };
      },
      fetcher: async (url) => {
        if (url.startsWith('https://104.21.43.139')) {
          return new Response('<html><title>Direct IP access not allowed | Cloudflare</title></html>', {
            status: 403,
            headers: { 'content-type': 'text/html', server: 'cloudflare', 'cf-ray': '1234-LAX' }
          });
        }
        if (url.startsWith('http://104.21.43.139')) {
          return new Response('<html><title>Direct IP access not allowed | Cloudflare</title></html>', {
            status: 200,
            headers: { 'content-type': 'text/html', server: 'cloudflare', 'cf-ray': '1234-LAX' }
          });
        }
        return new Response('ok', { status: 200 });
      }
    });

    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    try {
      const scanRes = await dispatchServer(server, '/api/scan', {
        body: {
          target: '104.21.43.139',
          profile: 'smart',
          checks: ['origin-source-ip', 'ssl-tls', 'http-redirect', 'security-headers', 'server-disclosure'],
          maxDepth: 0,
          noHistory: true
        }
      });
      assert.equal(scanRes.status, 202);
      assert.deepEqual(scanRes.json.targets, ['https://104.21.43.139', 'http://104.21.43.139']);

      let finalJob = null;
      for (let i = 0; i < 200; i++) {
        const poll = await dispatchServer(server, `/api/scan/${encodeURIComponent(scanRes.json.scanId)}`, { method: 'GET' });
        if (poll.json?.status === 'completed' || poll.json?.status === 'failed') {
          finalJob = poll.json;
          break;
        }
        await new Promise(r => setTimeout(r, 25));
      }

      assert.equal(finalJob?.status, 'completed');
      const results = finalJob.result?.results || [];
      const checkIds = new Set(results.map(r => r.checkId));
      for (const expected of ['origin-source-ip', 'ssl-tls', 'http-redirect', 'security-headers', 'server-disclosure']) {
        assert.ok(checkIds.has(expected), `Expected server scan to execute ${expected}`);
      }

      const grouped = groupFindings(results);
      const sslGroups = grouped.filter(g => g.checkId === 'ssl-tls');
      assert.equal(sslGroups.length, 1);
      assert.equal(sslGroups[0].status, 'VULNERABLE');

      const redirectGroups = grouped.filter(g => g.checkId === 'http-redirect');
      assert.equal(redirectGroups.length, 1);
      assert.equal(redirectGroups[0].status, 'VULNERABLE');

      const originResults = results.filter(r => r.checkId === 'origin-source-ip');
      for (const r of originResults) {
        assert.equal(r.status, 'SAFE');
        assert.equal(r.isCdnEdge, true);
      }

      // Direct check sanity: origin-source-ip works directly as well
      const directOrigin = await runOriginSourceIp('https://104.21.43.139/', async () => ({
        status: 403,
        headers: { server: 'cloudflare', 'cf-ray': '1234-LAX' },
        text: 'Direct IP access not allowed'
      }));
      assert.equal(directOrigin.status, 'SAFE');
    } finally {
      await new Promise(resolve => server.close(resolve));
      server.emit('close');
    }
  });
});
