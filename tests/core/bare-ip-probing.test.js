import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import http from 'node:http';
import {
  isBareIpTarget,
  resolveBareIpTargets,
  normalizeTargetInput,
  validateTargets
} from '../../core/validator.js';
import { runScanner } from '../../scan.js';
import { buildExecutiveResume, generateReport, generateMarkdownReport } from '../../core/report.js';
import { createAppServer, MAX_SCAN_TARGETS } from '../../core/server.js';

function makeResponse({ status = 200, headers = {}, body = '<html>ok</html>', url = '' } = {}) {
  return {
    status,
    url,
    headers: new Headers(headers),
    text: async () => (typeof body === 'string' ? body : JSON.stringify(body))
  };
}

function dispatchServer(server, pathname, { method = 'POST', body = {} } = {}) {
  return new Promise((resolve, reject) => {
    const raw = JSON.stringify(body);
    const req = http.request({
      hostname: '127.0.0.1',
      port: server.address().port,
      path: pathname,
      method,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(raw)
      }
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
    req.write(raw);
    req.end();
  });
}

describe('R1: Bare IP Target Detection & Dual-Scheme Probing', () => {
  test('isBareIpTarget identifies bare scheme-less port-less IPv4/IPv6 targets accurately', () => {
    assert.equal(isBareIpTarget('104.21.43.139'), true);
    assert.equal(isBareIpTarget('"104.21.43.139\\"'), true);
    assert.equal(isBareIpTarget("'104.21.43.139/'"), true);
    assert.equal(isBareIpTarget('104.21.43.139/api?v=1#top'), true);
    assert.equal(isBareIpTarget('192.168.1.50'), true);
    assert.equal(isBareIpTarget('::1'), true);
    assert.equal(isBareIpTarget('[::1]'), true);
    assert.equal(isBareIpTarget('2001:db8::1/status'), true);
    assert.equal(isBareIpTarget('[2001:db8::1]/status?x=1'), true);

    // Explicit scheme -> false
    assert.equal(isBareIpTarget('http://104.21.43.139'), false);
    assert.equal(isBareIpTarget('https://104.21.43.139'), false);
    assert.equal(isBareIpTarget('http://[::1]'), false);
    assert.equal(isBareIpTarget('file:///etc/passwd'), false);

    // Explicit port -> false
    assert.equal(isBareIpTarget('104.21.43.139:80'), false);
    assert.equal(isBareIpTarget('104.21.43.139:443'), false);
    assert.equal(isBareIpTarget('104.21.43.139:8080'), false);
    assert.equal(isBareIpTarget('104.21.43.139:8080/admin'), false);
    assert.equal(isBareIpTarget('[::1]:8443'), false);
    assert.equal(isBareIpTarget('[::1]:8001'), false);

    // Domain names, hostnames, invalid / empty -> false
    assert.equal(isBareIpTarget('example.com'), false);
    assert.equal(isBareIpTarget('localhost'), false);
    assert.equal(isBareIpTarget('nas.local'), false);
    assert.equal(isBareIpTarget('104.21.43.139.evil.com'), false);
    assert.equal(isBareIpTarget('999.999.999.999'), false);
    assert.equal(isBareIpTarget(''), false);
    assert.equal(isBareIpTarget('   '), false);
    assert.equal(isBareIpTarget(null), false);
    assert.equal(isBareIpTarget(undefined), false);
    assert.equal(isBareIpTarget(123), false);

    // normalizeTargetInput contract remains synchronous and untouched
    assert.equal(normalizeTargetInput('104.21.43.139'), 'http://104.21.43.139');
    assert.equal(normalizeTargetInput('::1'), 'http://[::1]');
  });

  test('resolveBareIpTargets handles both-reachable, https-only, http-only, and neither-reachable matrices', async () => {
    // 1. Both https:// and http:// reachable
    const bothRes = await resolveBareIpTargets(['104.21.43.139'], {
      fetcher: async (url) => {
        if (url.startsWith('https://')) return makeResponse({ status: 403, body: 'Direct IP access not allowed' });
        if (url.startsWith('http://')) return makeResponse({ status: 301, headers: { location: 'https://104.21.43.139/' }, body: '' });
        throw new Error('Unexpected URL');
      }
    });
    assert.deepEqual(bothRes.targets, ['https://104.21.43.139', 'http://104.21.43.139']);
    assert.deepEqual(bothRes.probeSummary.get('104.21.43.139'), {
      httpsReachable: true,
      httpReachable: true,
      httpsSniRequired: false,
      resolvedTargets: ['https://104.21.43.139', 'http://104.21.43.139']
    });

    // 2. Only https:// reachable (port 80 refuses)
    const httpsOnlyRes = await resolveBareIpTargets(['104.21.43.139'], {
      fetcher: async (url) => {
        if (url.startsWith('https://')) return makeResponse({ status: 200, body: 'ok' });
        const err = new Error('connect ECONNREFUSED 104.21.43.139:80');
        err.code = 'ECONNREFUSED';
        throw err;
      }
    });
    assert.deepEqual(httpsOnlyRes.targets, ['https://104.21.43.139']);
    assert.equal(httpsOnlyRes.probeSummary.get('104.21.43.139').httpsReachable, true);
    assert.equal(httpsOnlyRes.probeSummary.get('104.21.43.139').httpReachable, false);

    // 3. Only http:// reachable (port 443 refuses)
    const httpOnlyRes = await resolveBareIpTargets(['104.21.43.139'], {
      fetcher: async (url) => {
        if (url.startsWith('http://')) return makeResponse({ status: 200, body: 'ok' });
        const err = new Error('connect ECONNREFUSED 104.21.43.139:443');
        err.code = 'ECONNREFUSED';
        throw err;
      }
    });
    assert.deepEqual(httpOnlyRes.targets, ['http://104.21.43.139']);
    assert.equal(httpOnlyRes.probeSummary.get('104.21.43.139').httpsReachable, false);
    assert.equal(httpOnlyRes.probeSummary.get('104.21.43.139').httpReachable, true);

    // 4. Neither reachable -> fallback to [httpUrl]
    const neitherRes = await resolveBareIpTargets(['104.21.43.139'], {
      fetcher: async () => {
        const err = new Error('connect ECONNREFUSED');
        err.code = 'ECONNREFUSED';
        throw err;
      }
    });
    assert.deepEqual(neitherRes.targets, ['http://104.21.43.139']);
    assert.equal(neitherRes.probeSummary.get('104.21.43.139').httpsReachable, false);
    assert.equal(neitherRes.probeSummary.get('104.21.43.139').httpReachable, false);
  });

  test('resolveBareIpTargets counts TLS cert-mismatch and self-signed errors on 443 as HTTPS-reachable', async () => {
    for (const makeTlsErr of [
      () => Object.assign(new Error("Hostname/IP does not match certificate's altnames"), { code: 'ERR_TLS_CERT_ALTNAME_INVALID' }),
      () => Object.assign(new Error('self-signed certificate'), { code: 'DEPTH_ZERO_SELF_SIGNED_CERT' })
    ]) {
      const res = await resolveBareIpTargets(['104.21.43.139'], {
        fetcher: async (url) => {
          if (url.startsWith('https://')) throw makeTlsErr();
          const err = new Error('connect ECONNREFUSED');
          err.code = 'ECONNREFUSED';
          throw err;
        }
      });
      assert.deepEqual(res.targets, ['https://104.21.43.139']);
      assert.equal(res.probeSummary.get('104.21.43.139').httpsReachable, true);
      assert.equal(res.probeSummary.get('104.21.43.139').httpReachable, false);
    }
  });

  test('resolveBareIpTargets preserves IPv6 bracketing, path/query tails, tcpProbe gating, and deduplication', async () => {
    const tcpCalls = [];
    const fetcherCalls = [];
    const res = await resolveBareIpTargets(
      ['2606:4700:4700::1111/status?ok=1', '104.21.43.139', 'https://104.21.43.139', 'example.com', '104.21.43.139:8080'],
      {
        tcpProbe: async (host, port) => {
          tcpCalls.push({ host, port });
          if (host === '2606:4700:4700::1111') return { open: port === 443 };
          if (host === '104.21.43.139') return { open: port === 443 || port === 80 };
          return { open: false };
        },
        fetcher: async (url) => {
          fetcherCalls.push(url);
          return makeResponse({ status: 200 });
        }
      }
    );

    assert.deepEqual(res.targets, [
      'https://[2606:4700:4700::1111]/status?ok=1',
      'https://104.21.43.139',
      'http://104.21.43.139',
      'https://example.com',
      'http://104.21.43.139:8080'
    ]);
    // 2606:4700:4700::1111 had port 80 closed in tcpProbe, so fetcher must NOT be called for http://[2606:4700:4700::1111]
    assert.equal(fetcherCalls.includes('http://[2606:4700:4700::1111]/status?ok=1'), false);
    assert.equal(fetcherCalls.includes('https://[2606:4700:4700::1111]/status?ok=1'), true);
    assert.ok(tcpCalls.some(c => c.host === '2606:4700:4700::1111' && c.port === 443));
  });

  test('resolveBareIpTargets enforces SSRF and Asset Gate BEFORE probing and never opens raw OS sockets with custom fetcher', async () => {
    let probeCalls = 0;
    const countingFetcher = async () => {
      probeCalls++;
      return makeResponse({ status: 200 });
    };
    const countingTcpProbe = async () => {
      probeCalls++;
      return { open: true };
    };

    // 1. Private IP without allowPrivate -> blocked before probing
    const privRes = await resolveBareIpTargets(['127.0.0.1', '192.168.1.1'], {
      allowPrivate: false,
      fetcher: countingFetcher,
      tcpProbe: countingTcpProbe
    });
    assert.equal(probeCalls, 0);
    assert.deepEqual(privRes.targets, ['http://127.0.0.1', 'http://192.168.1.1']);
    assert.equal(validateTargets(privRes.targets, { allowPrivate: false }).valid, false);

    // 2. Cloud metadata IP even with allowPrivate: true -> blocked before probing
    const metaRes = await resolveBareIpTargets(['169.254.169.254'], {
      allowPrivate: true,
      fetcher: countingFetcher,
      tcpProbe: countingTcpProbe
    });
    assert.equal(probeCalls, 0);
    assert.deepEqual(metaRes.targets, ['http://169.254.169.254']);
    assert.equal(validateTargets(metaRes.targets, { allowPrivate: true }).valid, false);

    // 3. Asset-gate deny rule -> blocked before probing
    const gateRes = await resolveBareIpTargets(['104.21.43.139'], {
      scopeRules: [{ ruleType: 'exact_ip', pattern: '104.21.43.139', isAllowed: false }],
      fetcher: countingFetcher,
      tcpProbe: countingTcpProbe
    });
    assert.equal(probeCalls, 0);
    assert.deepEqual(gateRes.targets, ['http://104.21.43.139']);
    assert.equal(gateRes.probeSummary.get('104.21.43.139').blocked, true);

    // 4. Custom fetcher without tcpProbe must NOT open raw OS sockets
    const origConnect = net.Socket.prototype.connect;
    let socketConnectCount = 0;
    net.Socket.prototype.connect = function (...args) {
      socketConnectCount++;
      return origConnect.apply(this, args);
    };
    try {
      const isolatedRes = await resolveBareIpTargets(['104.21.43.139'], {
        fetcher: async () => makeResponse({ status: 200 })
      });
      assert.equal(socketConnectCount, 0);
      assert.deepEqual(isolatedRes.targets, ['https://104.21.43.139', 'http://104.21.43.139']);
    } finally {
      net.Socket.prototype.connect = origConnect;
    }
  });

  test('runScanner integrates bare public IP probing across both https:// and http:// (and single-scheme HTTPS)', async () => {
    const requestedUrls = [];
    const dualReport = await runScanner({
      targets: ['104.21.43.139'],
      profile: 'smart',
      checks: ['security-headers', 'ssl-tls'],
      maxDepth: 0,
      noHistory: true,
      silent: true,
      setExitCode: false,
      returnFull: true,
      fetcher: async (url) => {
        requestedUrls.push(url);
        if (url.startsWith('https://')) {
          return makeResponse({
            status: 403,
            headers: { server: 'cloudflare', 'cf-ray': '9999-DFW', 'content-type': 'text/html' },
            body: '<html><title>Direct IP access not allowed | Cloudflare</title></html>'
          });
        }
        return makeResponse({
          status: 403,
          headers: { server: 'cloudflare', 'cf-ray': '9999-DFW', 'content-type': 'text/html' },
          body: '<html><title>Direct IP access not allowed | Cloudflare</title></html>'
        });
      }
    });

    assert.ok(dualReport.stacks['https://104.21.43.139']);
    assert.ok(dualReport.stacks['http://104.21.43.139']);
    assert.equal(dualReport.bareIpProbeSummary['104.21.43.139'].httpsReachable, true);
    assert.equal(dualReport.bareIpProbeSummary['104.21.43.139'].httpReachable, true);
    assert.ok(requestedUrls.some(u => u.startsWith('https://104.21.43.139')));
    assert.ok(requestedUrls.some(u => u.startsWith('http://104.21.43.139')));

    // Only HTTPS reachable -> only https://104.21.43.139 scanned
    const httpsOnlyReport = await runScanner({
      targets: ['104.21.43.139'],
      profile: 'smart',
      checks: ['security-headers'],
      maxDepth: 0,
      noHistory: true,
      silent: true,
      setExitCode: false,
      returnFull: true,
      fetcher: async (url) => {
        if (url.startsWith('https://')) {
          return makeResponse({
            status: 200,
            headers: { server: 'nginx', 'content-type': 'text/html' },
            body: '<html><title>HTTPS Only</title></html>'
          });
        }
        const err = new Error('connect ECONNREFUSED 104.21.43.139:80');
        err.code = 'ECONNREFUSED';
        throw err;
      }
    });

    assert.ok(httpsOnlyReport.stacks['https://104.21.43.139']);
    assert.equal(httpsOnlyReport.stacks['http://104.21.43.139'], undefined);
  });

  test('runScanner preserves explicit scheme/port targets unchanged and falls back cleanly when neither port 443 nor 80 responds', async () => {
    // 1. Explicit scheme (https://104.21.43.139) is NOT expanded to http://
    const explicitHttpsUrls = [];
    const explicitHttpsReport = await runScanner({
      targets: ['https://104.21.43.139'],
      profile: 'smart',
      checks: ['security-headers'],
      maxDepth: 0,
      noHistory: true,
      silent: true,
      setExitCode: false,
      returnFull: true,
      fetcher: async (url) => {
        explicitHttpsUrls.push(url);
        return makeResponse({
          status: 403,
          headers: { server: 'cloudflare', 'cf-ray': '1111-MIA', 'content-type': 'text/html' },
          body: '<html><title>CF</title></html>'
        });
      }
    });
    assert.ok(explicitHttpsReport.stacks['https://104.21.43.139']);
    assert.equal(explicitHttpsReport.stacks['http://104.21.43.139'], undefined);
    assert.equal(explicitHttpsReport.bareIpProbeSummary, undefined);
    assert.equal(explicitHttpsUrls.some(u => u.startsWith('http://104.21.43.139')), false);

    // 2. Explicit port (104.21.43.139:8080) is NOT expanded to 443/80
    const explicitPortReport = await runScanner({
      targets: ['104.21.43.139:8080'],
      profile: 'smart',
      checks: ['security-headers'],
      maxDepth: 0,
      noHistory: true,
      silent: true,
      setExitCode: false,
      returnFull: true,
      fetcher: async () => makeResponse({
        status: 200,
        headers: { server: 'nginx', 'content-type': 'text/html' },
        body: '<html><body>Custom Port</body></html>'
      })
    });
    assert.ok(explicitPortReport.stacks['http://104.21.43.139:8080']);
    assert.equal(explicitPortReport.stacks['https://104.21.43.139'], undefined);
    assert.equal(explicitPortReport.bareIpProbeSummary, undefined);

    // 3. Bare IP where neither 443 nor 80 responds falls back to ['http://198.51.100.99'] without crashing
    const unreachableReport = await runScanner({
      targets: ['198.51.100.99'],
      profile: 'smart',
      checks: ['security-headers'],
      maxDepth: 0,
      noHistory: true,
      silent: true,
      setExitCode: false,
      returnFull: true,
      fetcher: async () => {
        const err = new Error('connect ECONNREFUSED');
        err.code = 'ECONNREFUSED';
        throw err;
      }
    });
    assert.ok(unreachableReport.stacks['http://198.51.100.99']);
    assert.equal(unreachableReport.stacks['https://198.51.100.99'], undefined);
    assert.deepEqual(unreachableReport.bareIpProbeSummary['198.51.100.99'], {
      httpsReachable: false,
      httpReachable: false,
      httpsSniRequired: false,
      resolvedTargets: ['http://198.51.100.99']
    });
  });

  test('server API POST /api/scan and POST /api/fingerprint expand reachable bare IP targets', async () => {
    const server = createAppServer({
      inMemory: true,
      fetcher: async (url) => {
        if (url.startsWith('https://104.21.43.139')) {
          return new Response('<html><title>CF</title></html>', {
            status: 403,
            headers: { 'content-type': 'text/html', server: 'cloudflare', 'cf-ray': '1234-LAX' }
          });
        }
        if (url.startsWith('http://104.21.43.139')) {
          return new Response('<html><title>CF HTTP</title></html>', {
            status: 403,
            headers: { 'content-type': 'text/html', server: 'cloudflare', 'cf-ray': '1234-LAX' }
          });
        }
        return new Response('ok', { status: 200 });
      }
    });

    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    try {
      const fpRes = await dispatchServer(server, '/api/fingerprint', {
        body: { target: '104.21.43.139' }
      });
      assert.equal(fpRes.status, 200);
      assert.equal(fpRes.json.target, 'https://104.21.43.139');
      assert.deepEqual(fpRes.json.targets, ['https://104.21.43.139', 'http://104.21.43.139']);

      const scanRes = await dispatchServer(server, '/api/scan', {
        body: { target: '104.21.43.139', profile: 'smart', checks: ['security-headers'], maxDepth: 0, noHistory: true }
      });
      assert.equal(scanRes.status, 202);
      assert.deepEqual(scanRes.json.targets, ['https://104.21.43.139', 'http://104.21.43.139']);

      // Wait for scan completion cleanly before closing server
      for (let i = 0; i < 200; i++) {
        const poll = await dispatchServer(server, `/api/scan/${encodeURIComponent(scanRes.json.scanId)}`, { method: 'GET', body: undefined });
        if (poll.json?.status === 'completed' || poll.json?.status === 'failed') break;
        await new Promise(r => setTimeout(r, 25));
      }
    } finally {
      await new Promise(resolve => server.close(resolve));
      server.emit('close');
    }
  });
});

describe('Step 2 Security Remediation Regressions (FINDING-1A, FINDING-1B, FINDING-2)', () => {
  test('FINDING-1A: resolveBareIpTargets bounds concurrent scheme probes to <= 16 across 35 distinct bare IPs', async () => {
    const ips = Array.from({ length: 35 }, (_, i) => `198.51.100.${i + 1}`);
    let inFlight = 0;
    let maxInFlight = 0;
    let totalProbes = 0;

    const res = await resolveBareIpTargets(ips, {
      concurrency: 100, // Even high requested concurrency must be capped so maxInFlight <= 16
      tcpProbe: async () => {
        inFlight++;
        totalProbes++;
        maxInFlight = Math.max(maxInFlight, inFlight);
        await new Promise(r => setTimeout(r, 20));
        inFlight--;
        return { open: true };
      }
    });

    assert.equal(totalProbes, 70);
    assert.equal(res.targets.length, 70);
    assert.ok(maxInFlight >= 2 && maxInFlight <= 16, `Expected maxInFlight <= 16, got ${maxInFlight}`);
  });

  test('FINDING-1A: resolveBareIpTargets deduplicates origin probes across 30 path-tailed entries while preserving tails & per-entry governance', async () => {
    const pathTargets = Array.from({ length: 30 }, (_, i) => `198.51.100.1/path${i}`);
    const tcpCalls = [];

    const res = await resolveBareIpTargets(pathTargets, {
      tcpProbe: async (host, port) => {
        tcpCalls.push({ host, port });
        await new Promise(r => setTimeout(r, 15));
        return { open: port === 443 || port === 80 };
      }
    });

    assert.equal(tcpCalls.length, 2, `Expected exactly 2 origin probes (443 & 80), got ${tcpCalls.length}`);
    assert.deepEqual(
      tcpCalls.map(c => c.port).sort((a, b) => a - b),
      [80, 443]
    );
    assert.equal(res.targets.length, 60);
    for (let i = 0; i < 30; i++) {
      assert.ok(res.targets.includes(`https://198.51.100.1/path${i}`), `Missing https tail /path${i}`);
      assert.ok(res.targets.includes(`http://198.51.100.1/path${i}`), `Missing http tail /path${i}`);
    }

    // Verify path-aware scopeRules still execute per-entry without cache poisoning
    let scopedProbes = 0;
    const scopedRes = await resolveBareIpTargets(['198.51.100.1/secret', '198.51.100.1/public'], {
      scopeRules: [{ ruleType: 'fuzzy_url', pattern: '*/secret*', isAllowed: false }],
      tcpProbe: async () => {
        scopedProbes++;
        return { open: true };
      }
    });
    assert.equal(scopedProbes, 2);
    assert.equal(scopedRes.probeSummary.get('198.51.100.1/secret').blocked, true);
    assert.equal(scopedRes.probeSummary.get('198.51.100.1/public').httpsReachable, true);
    assert.equal(scopedRes.probeSummary.get('198.51.100.1/public').httpReachable, true);
  });

  test('FINDING-1B: POST /api/scan returns 429 with 0 tcpProbe/fetcher calls when 3 scans are already running', async () => {
    let trackProbes = false;
    let tcpCallsDuring4th = 0;
    let fetchCallsDuring4th = 0;

    const server = createAppServer({
      inMemory: true,
      tcpProbe: async () => {
        if (trackProbes) tcpCallsDuring4th++;
        return { open: true };
      },
      portProbe: async () => [],
      tlsConnect: async () => ({ cert: null, protocol: null, authorized: false }),
      fetcher: async () => {
        if (trackProbes) fetchCallsDuring4th++;
        await new Promise(r => setTimeout(r, 150));
        return new Response('<html><title>Slow</title></html>', {
          status: 200,
          headers: { 'content-type': 'text/html' }
        });
      }
    });

    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const scanIds = [];
    try {
      for (let i = 0; i < 3; i++) {
        const start = await dispatchServer(server, '/api/scan', {
          body: {
            target: `https://203.0.113.${10 + i}`,
            profile: 'quick',
            checks: ['security-headers'],
            maxDepth: 0,
            noiseProfile: 'off',
            noHistory: true
          }
        });
        assert.equal(start.status, 202);
        scanIds.push(start.json.scanId);
      }

      trackProbes = true;
      const bareIps = Array.from({ length: 30 }, (_, i) => `198.51.100.${i + 1}`);
      const fourth = await dispatchServer(server, '/api/scan', {
        body: { targets: bareIps, profile: 'quick', maxDepth: 0, noHistory: true }
      });
      trackProbes = false;

      assert.equal(fourth.status, 429);
      assert.match(String(fourth.json?.error || ''), /Maximum concurrent scans reached/i);
      assert.equal(tcpCallsDuring4th, 0, '4th request rejected with 429 must trigger 0 tcpProbe calls');
      assert.equal(fetchCallsDuring4th, 0, '4th request rejected with 429 must trigger 0 fetcher calls');
    } finally {
      for (const id of scanIds) {
        for (let i = 0; i < 400; i++) {
          const poll = await dispatchServer(server, `/api/scan/${encodeURIComponent(id)}`, { method: 'GET', body: undefined });
          if (poll.json?.status === 'completed' || poll.json?.status === 'failed') break;
          await new Promise(r => setTimeout(r, 25));
        }
      }
      await new Promise(resolve => server.close(resolve));
      server.emit('close');
    }
  });

  test('FINDING-1B: POST /api/scan rejects > MAX_SCAN_TARGETS with 400 and 0 probe calls', async () => {
    let tcpCalls = 0;
    let fetchCalls = 0;
    const server = createAppServer({
      inMemory: true,
      tcpProbe: async () => {
        tcpCalls++;
        return { open: true };
      },
      fetcher: async () => {
        fetchCalls++;
        return new Response('ok', { status: 200 });
      }
    });

    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    try {
      const oversizedTargets = Array.from({ length: MAX_SCAN_TARGETS + 1 }, (_, i) => `198.51.100.${(i % 250) + 1}`);
      const res = await dispatchServer(server, '/api/scan', {
        body: { targets: oversizedTargets, profile: 'quick', noHistory: true }
      });

      assert.equal(res.status, 400);
      assert.match(String(res.json?.error || ''), /Too many targets/i);
      assert.equal(tcpCalls, 0);
      assert.equal(fetchCalls, 0);
    } finally {
      await new Promise(resolve => server.close(resolve));
      server.emit('close');
    }
  });

  test('FINDING-2: POST /api/fingerprint on closed-port non-device target (deviceMode: false) does not strip checks and matches POST /api/scan', async () => {
    let postFingerprintFastDrain = false;
    const makeClosedServer = (extraOpts = {}) => createAppServer({
      inMemory: true,
      dnsResolver: async (host) => [host],
      tcpProbe: async () => ({ open: false }),
      portProbe: async () => [],
      rtspProbe: async () => ({ open: false }),
      udpProbe: async () => ({ open: false }),
      tlsProbe: async () => ({ supported: false }),
      tlsConnect: async () => {
        const err = new Error('connect ECONNREFUSED');
        err.code = 'ECONNREFUSED';
        throw err;
      },
      fetcher: async () => {
        if (postFingerprintFastDrain) {
          return new Response('', { status: 404 });
        }
        const err = new Error('connect ECONNREFUSED');
        err.code = 'ECONNREFUSED';
        throw err;
      },
      ...extraOpts
    });

    // Case A: Private LAN target with allowPrivate: true, deviceMode: false, closed ports
    const privServer = makeClosedServer({ allowPrivate: true });
    await new Promise(resolve => privServer.listen(0, '127.0.0.1', resolve));
    try {
      const fpRes = await dispatchServer(privServer, '/api/fingerprint', {
        body: { target: '192.168.1.50', allowPrivate: true, deviceMode: false, timeout: 1000 }
      });
      assert.equal(fpRes.status, 200);
      assert.equal(fpRes.json.deviceInfo?.basePortClosed, true);
      assert.equal(fpRes.json.deviceInfo?.detected, false);
      assert.ok(fpRes.json.activeChecksCount > 1, `Expected >1 active checks, got ${fpRes.json.activeChecksCount}`);
      assert.notDeepEqual(fpRes.json.activeChecks.map(c => c.id), ['device-security']);

      const scanRes = await dispatchServer(privServer, '/api/scan', {
        body: {
          target: '192.168.1.50',
          allowPrivate: true,
          deviceMode: false,
          profile: 'smart',
          maxDepth: 0,
          concurrency: 10,
          timeout: 1000,
          noiseProfile: 'off',
          noHistory: true
        }
      });
      assert.equal(scanRes.status, 202);
      let scanJob = null;
      for (let i = 0; i < 400; i++) {
        const jobObj = privServer.context?.jobs?.get(scanRes.json.scanId);
        if (jobObj?.events?.some(e => e.type === 'fingerprint')) {
          postFingerprintFastDrain = true;
        }
        const poll = await dispatchServer(privServer, `/api/scan/${encodeURIComponent(scanRes.json.scanId)}`, { method: 'GET', body: undefined });
        if (poll.json?.status === 'completed' || poll.json?.status === 'failed') {
          scanJob = poll.json;
          break;
        }
        await new Promise(r => setTimeout(r, 25));
      }
      assert.equal(scanJob?.status, 'completed');
      const scanStack = scanJob.result?.stacks?.[0];
      assert.ok(scanStack);
      assert.equal(fpRes.json.activeChecksCount, scanStack.activeChecksCount);
      assert.equal(fpRes.json.skippedChecksCount, scanStack.skippedChecksCount);
    } finally {
      postFingerprintFastDrain = false;
      await new Promise(resolve => privServer.close(resolve));
      privServer.emit('close');
    }

    // Case B: Public IP with multiPort: true, deviceMode: false, closed ports
    const pubServer = makeClosedServer({ multiPort: true });
    await new Promise(resolve => pubServer.listen(0, '127.0.0.1', resolve));
    try {
      const fpRes = await dispatchServer(pubServer, '/api/fingerprint', {
        body: { target: '198.51.100.10', deviceMode: false }
      });
      assert.equal(fpRes.status, 200);
      assert.equal(fpRes.json.deviceInfo?.basePortClosed, true);
      assert.equal(fpRes.json.deviceInfo?.detected, false);
      assert.ok(fpRes.json.activeChecksCount > 1);
      assert.notDeepEqual(fpRes.json.activeChecks.map(c => c.id), ['device-security']);
    } finally {
      await new Promise(resolve => pubServer.close(resolve));
      pubServer.emit('close');
    }
  });
});

describe('Step 2.4: Bare-IP HTTPS SNI-Alert Noise Fix & Point-by-Point Executive Audit Resume', () => {
  test('resolveBareIpTargets sets httpsSniRequired: true on SSL alert 40 / SNI handshake rejection while keeping httpsReachable: true', async () => {
    for (const makeSniErr of [
      () => Object.assign(new Error('write EPROTO: ssl/tls alert handshake failure: SSL alert number 40'), { code: 'EPROTO' }),
      () => Object.assign(new Error('sslv3 alert handshake failure'), { code: 'ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE' }),
      () => Object.assign(new Error('tlsv1 alert unrecognized name'), { code: 'ERR_SSL_TLSV1_ALERT_UNRECOGNIZED_NAME' })
    ]) {
      const res = await resolveBareIpTargets(['104.21.43.139'], {
        fetcher: async (url) => {
          if (url.startsWith('https://')) throw makeSniErr();
          return makeResponse({
            status: 403,
            headers: { server: 'cloudflare', 'cf-ray': '8888-DFW' },
            body: 'Direct IP access not allowed'
          });
        }
      });

      assert.deepEqual(res.targets, ['https://104.21.43.139', 'http://104.21.43.139']);
      assert.deepEqual(res.probeSummary.get('104.21.43.139'), {
        httpsReachable: true,
        httpReachable: true,
        httpsSniRequired: true,
        resolvedTargets: ['https://104.21.43.139', 'http://104.21.43.139']
      });
    }
  });

  test('runScanner scopes HTTPS checks on SNI-rejected bare IP (e.g., 104.21.43.139) to TLS/Origin/OS/Device and builds Executive Audit Resume', async () => {
    const report = await runScanner({
      targets: ['104.21.43.139'],
      profile: 'smart',
      checks: ['ssl-tls', 'origin-source-ip', 'os-security', 'security-headers', 'cors', 'cookie-security', 'server-disclosure', 'http-redirect'],
      maxDepth: 0,
      noHistory: true,
      silent: true,
      setExitCode: false,
      returnFull: true,
      portProbe: async () => ({ open: false, banner: '' }),
      tlsConnect: async () => {
        throw Object.assign(new Error('write EPROTO: ssl/tls alert handshake failure: SSL alert number 40'), {
          code: 'ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE'
        });
      },
      fetcher: async (url) => {
        if (url.startsWith('https://104.21.43.139')) {
          throw Object.assign(new Error('write EPROTO: ssl/tls alert handshake failure: SSL alert number 40'), {
            code: 'EPROTO'
          });
        }
        return makeResponse({
          status: 403,
          headers: {
            server: 'cloudflare',
            'cf-ray': '9999-MIA',
            'content-type': 'text/html'
          },
          body: '<html><title>Direct IP access not allowed | Cloudflare</title><body>Error 1003</body></html>'
        });
      }
    });

    assert.equal(report.bareIpProbeSummary['104.21.43.139'].httpsReachable, true);
    assert.equal(report.bareIpProbeSummary['104.21.43.139'].httpReachable, true);
    assert.equal(report.bareIpProbeSummary['104.21.43.139'].httpsSniRequired, true);

    // HTTPS target must only run non-HTTP-body checks (ssl-tls, origin-source-ip, os-security)
    // and must NOT produce EPROTO errors on security-headers, cors, cookies, server-disclosure, http-redirect
    const httpsChecks = report.results.filter(r => r.target.startsWith('https://104.21.43.139')).map(r => r.checkId);
    for (const c of httpsChecks) {
      assert.ok(['ssl-tls', 'origin-source-ip', 'os-security', 'device-security'].includes(c), `Unexpected HTTP-body check on SNI-rejected HTTPS bare IP: ${c}`);
    }
    const httpChecks = report.results.filter(r => r.target.startsWith('http://104.21.43.139')).map(r => r.checkId);
    assert.ok(httpChecks.includes('security-headers'));
    assert.ok(httpChecks.includes('cors'));
    assert.ok(httpChecks.includes('cookie-security'));
    assert.ok(httpChecks.includes('server-disclosure'));
    assert.ok(httpChecks.includes('http-redirect'));

    // Executive Resume must be attached and populated
    assert.ok(report.executiveResume);
    assert.ok(Array.isArray(report.executiveResume.osPosture));
    assert.equal(report.executiveResume.osPosture.length, 2);
    assert.ok(Array.isArray(report.executiveResume.findingsByPoint));
    assert.ok(Array.isArray(report.executiveResume.improvementsAndFixes));
    assert.ok(report.executiveResume.improvementsAndFixes.some(s => /bare-IP dual-scheme audit active/i.test(s)));
    assert.ok(Array.isArray(report.executiveResume.cliLines));
    assert.ok(report.executiveResume.cliLines.some(l => l.includes('EXECUTIVE AUDIT RESUME (POINT-BY-POINT)')));

    // Verify JSON & Markdown report integration
    const jsonRep = generateReport(report.results, report.risk, report.stacks, {
      cveCoverage: report.cveCoverage,
      executiveResume: report.executiveResume
    });
    assert.ok(jsonRep.executiveResume);
    const mdRep = generateMarkdownReport({
      targets: ['https://104.21.43.139', 'http://104.21.43.139'],
      results: report.results,
      risk: report.risk,
      stacks: report.stacks,
      cveCoverage: report.cveCoverage,
      executiveResume: report.executiveResume
    });
    assert.match(mdRep, /## Executive Audit Resume \(Point-by-Point\)/);
    assert.match(mdRep, /### 1\. Operating System & Device Posture/);
    assert.match(mdRep, /### 2\. Market CVE & Advisory Coverage/);
    assert.match(mdRep, /### 3\. Security Findings by Point/);
    assert.match(mdRep, /### 4\. What Was Improved & Fixed/);
  });

  test('buildExecutiveResume orders findingsByPoint CRITICAL -> HIGH -> MEDIUM -> LOW and summarizes OS EOL & fixes', () => {
    const resume = buildExecutiveResume(
      [
        {
          checkId: 'security-headers',
          name: 'Missing Security Headers',
          status: 'SUSPICIOUS',
          severity: 'LOW',
          target: 'http://198.51.100.20',
          detail: 'Missing X-Frame-Options',
          fix: 'Add X-Frame-Options: DENY'
        },
        {
          checkId: 'os-security',
          name: 'OpenSSH regreSSHion RCE',
          status: 'VULNERABLE',
          severity: 'CRITICAL',
          cve: 'CVE-2024-6387',
          target: 'http://198.51.100.20',
          detail: 'OpenSSH 9.2p1 vulnerable to regreSSHion',
          fix: 'Upgrade OpenSSH to 9.8p1 or distro backport'
        }
      ],
      {
        'http://198.51.100.20': {
          summary: 'Apache',
          osInfo: {
            detected: true,
            osName: 'Ubuntu Linux',
            familyLabel: 'Linux Distribution',
            version: '18.04',
            isEol: true,
            eolReason: 'Ubuntu 18.04 LTS reached standard EOL in May 2023'
          }
        }
      },
      {
        cveCoverage: {
          totalAdvisories: 132,
          coveredCount: 132,
          partialCount: 0,
          missingCount: 0,
          coveragePercent: 100,
          kevTotal: 35,
          kevCovered: 35
        },
        diff: {
          fixedFindings: [
            { prev: { severity: 'HIGH', name: 'Exposed .env', target: 'http://198.51.100.20' } }
          ]
        }
      }
    );

    assert.equal(resume.osPosture.length, 1);
    assert.equal(resume.osPosture[0].osName, 'Ubuntu Linux');
    assert.equal(resume.osPosture[0].isEol, true);
    assert.equal(resume.findingsByPoint.length, 2);
    assert.equal(resume.findingsByPoint[0].pointNumber, 1);
    assert.equal(resume.findingsByPoint[0].severity, 'CRITICAL');
    assert.equal(resume.findingsByPoint[1].pointNumber, 2);
    assert.equal(resume.findingsByPoint[1].severity, 'LOW');
    assert.ok(resume.improvementsAndFixes.some(s => s.includes('Fixed since previous scan')));
  });

  test('resolveBareIpTargets handles null options safely without throwing TypeError', async () => {
    const emptyRes = await resolveBareIpTargets([], null);
    assert.deepEqual(emptyRes.targets, []);
    assert.equal(emptyRes.probeSummary.size, 0);

    const urlRes = await resolveBareIpTargets(['https://example.com'], null);
    assert.deepEqual(urlRes.targets, ['https://example.com']);
    assert.equal(urlRes.probeSummary.size, 0);
  });
});
