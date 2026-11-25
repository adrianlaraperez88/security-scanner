import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Duplex } from 'node:stream';
import {
  canonicalizeIpAddress,
  canonicalizeResolvedIps,
  parseSourceIpMap,
  resolveConfiguredSourceIps,
  ResolveCache,
  resolveAndValidateTarget
} from '../../core/validator.js';
import {
  dialPinnedSourceIpRequest,
  fetchWithRetry,
  createGovernedFetch
} from '../../core/fetch.js';
import { TargetPinStore } from '../../core/guard.js';
import {
  buildCurlCommand,
  createTrackedFetch,
  buildReproductionContext
} from '../../core/reproduction.js';

/**
 * Creates an in-memory Duplex socket that simulates an HTTP/1.1 origin server
 * without requiring OS loopback bind permissions.
 */
function createMockHttpSocket({ status = 200, statusText = 'OK', headers = {}, body = 'pinned-ok', onRequest = null } = {}) {
  let reqRaw = '';
  let responded = false;

  const sock = new Duplex({
    read() {},
    write(chunk, _enc, cb) {
      reqRaw += Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk);
      if (!responded && reqRaw.includes('\r\n\r\n')) {
        responded = true;
        if (typeof onRequest === 'function') {
          onRequest(reqRaw);
        }
        const bodyBuf = Buffer.from(body, 'utf8');
        const hdrLines = [
          `HTTP/1.1 ${status} ${statusText}`,
          `Content-Length: ${bodyBuf.byteLength}`,
          'Connection: close'
        ];
        for (const [k, v] of Object.entries(headers)) {
          hdrLines.push(`${k}: ${v}`);
        }
        const responseBytes = Buffer.concat([
          Buffer.from(hdrLines.join('\r\n') + '\r\n\r\n', 'utf8'),
          bodyBuf
        ]);
        queueMicrotask(() => {
          sock.push(responseBytes);
          sock.push(null);
        });
      }
      cb();
    }
  });

  sock.setTimeout = () => sock;
  sock.setNoDelay = () => sock;
  sock.setKeepAlive = () => sock;
  queueMicrotask(() => sock.emit('connect'));
  return sock;
}

test('validator: canonicalizeIpAddress & canonicalizeResolvedIps unmap IPv4-mapped IPv6, strip zones, sort, and deduplicate (ARTEX canonicalIPs)', () => {
  assert.equal(canonicalizeIpAddress('::ffff:192.0.2.1'), '192.0.2.1');
  assert.equal(canonicalizeIpAddress('[::ffff:203.0.113.7]'), '203.0.113.7');
  assert.equal(canonicalizeIpAddress('2001:DB8::1%eth0'), '2001:db8::1');

  const list = canonicalizeResolvedIps([
    '203.0.113.9',
    '::ffff:203.0.113.7',
    { address: '203.0.113.8' },
    '203.0.113.7',
    '2001:DB8::1%en0'
  ]);
  assert.deepEqual(list, ['2001:db8::1', '203.0.113.7', '203.0.113.8', '203.0.113.9']);
});

test('validator: ResolveCache coalesces concurrent lookups (singleflight), caches positive answers, and supports fresh=true (ARTEX TestPinnedDialFreshLookupCollapsed)', async () => {
  let lookups = 0;
  let currentAnswer = ['203.0.113.9'];
  let nowMs = 1000;

  const cache = new ResolveCache({
    ttlMs: 10000,
    timeoutMs: 2000,
    now: () => nowMs,
    resolver: async () => {
      lookups += 1;
      await new Promise(r => setTimeout(r, 25));
      return currentAnswer;
    }
  });

  // 1. Two concurrent lookups share 1 underlying DNS call
  const [res1, res2] = await Promise.all([
    cache.lookup('App.Example.com.'),
    cache.lookup('app.example.com')
  ]);
  assert.equal(lookups, 1);
  assert.deepEqual(res1.ips, ['203.0.113.9']);
  assert.deepEqual(res2.ips, ['203.0.113.9']);

  // 2. Subsequent lookup within TTL uses cached entry without calling resolver
  currentAnswer = ['203.0.113.7'];
  const cachedRes = await cache.lookup('app.example.com');
  assert.equal(lookups, 1);
  assert.equal(cachedRes.cached, true);
  assert.deepEqual(cachedRes.ips, ['203.0.113.9']);

  // 3. fresh: true bypasses cache, coalesces concurrent fresh lookups, and updates cache
  const [fresh1, fresh2] = await Promise.all([
    cache.lookup('app.example.com', { fresh: true }),
    cache.lookup('app.example.com', { fresh: true })
  ]);
  assert.equal(lookups, 2);
  assert.deepEqual(fresh1.ips, ['203.0.113.7']);
  assert.deepEqual(fresh2.ips, ['203.0.113.7']);

  // 4. Cache now holds the updated fresh answer
  const afterFresh = await cache.lookup('app.example.com');
  assert.equal(lookups, 2);
  assert.equal(afterFresh.cached, true);
  assert.deepEqual(afterFresh.ips, ['203.0.113.7']);
});

test('validator: parseSourceIpMap & resolveAndValidateTarget apply explicit Source-IP overrides while blocking cloud metadata IPs', async () => {
  const parsed = parseSourceIpMap('example.com=203.0.113.50,*.api.example.com=203.0.113.51|203.0.113.52,203.0.113.99');
  assert.deepEqual(parsed.defaultIps, ['203.0.113.99']);
  assert.deepEqual(parsed.hostMap.get('example.com'), ['203.0.113.50']);
  assert.deepEqual(
    resolveConfiguredSourceIps('v1.api.example.com', { sourceIpMap: 'example.com=203.0.113.50,*.api.example.com=203.0.113.51' }),
    ['203.0.113.51']
  );

  // Explicit Source IP is used without querying DNS
  let dnsCalled = false;
  const okRes = await resolveAndValidateTarget('https://app.example.com/login', {
    sourceIp: '203.0.113.50',
    resolver: async () => {
      dnsCalled = true;
      return ['93.184.216.34'];
    }
  });
  assert.equal(okRes.valid, true);
  assert.equal(dnsCalled, false, 'DNS resolver must not be queried when explicit sourceIp is configured');
  assert.deepEqual(okRes.resolvedIps, ['203.0.113.50']);
  assert.equal(okRes.sourceIp, '203.0.113.50');
  assert.equal(okRes.sourceIpUsed, true);

  // Metadata IP in sourceIp MUST be blocked even when allowPrivate: true
  const metaRes = await resolveAndValidateTarget('https://app.example.com/', {
    sourceIp: '169.254.169.254',
    allowPrivate: true
  });
  assert.equal(metaRes.valid, false);
  assert.equal(metaRes.code, 'DNS_REBIND_OR_PRIVATE_IP');

  // Invalid IP in sourceIp fails closed with INVALID_SOURCE_IP
  const badIpRes = await resolveAndValidateTarget('https://app.example.com/', {
    sourceIp: '999.999.999.999'
  });
  assert.equal(badIpRes.valid, false);
  assert.equal(badIpRes.code, 'INVALID_SOURCE_IP');
});

test('fetch: dialPinnedSourceIpRequest connects strictly to pinned Source IP, preserves Host header, and tries canonical IPs in order (ARTEX TestPinnedDialConnectsOnlyToPinnedAddresses & TestPinnedDialTriesAddressesInOrder)', async () => {
  const dialed = [];
  const capturedRequests = [];

  const baseDialer = ({ address }) => {
    dialed.push(address);
    if (address === '203.0.113.7:8080') {
      const err = new Error('connect ECONNREFUSED 203.0.113.7:8080');
      err.code = 'ECONNREFUSED';
      throw err;
    }
    return createMockHttpSocket({
      status: 200,
      headers: { 'Content-Type': 'text/plain', 'X-Served-By': address },
      body: 'reached-second-source-ip',
      onRequest: (rawReq) => capturedRequests.push(rawReq)
    });
  };

  // Pass unsorted IPs plus an IPv6 address with family='tcp4' (must skip IPv6, sort IPv4, fail on .7, succeed on .8)
  const res = await dialPinnedSourceIpRequest('http://app.example.com:8080/api/health?check=1', {
    method: 'GET',
    resolvedIps: ['203.0.113.8', '2001:db8::1', '203.0.113.7'],
    sourceIp: '203.0.113.8',
    family: 'tcp4',
    baseDialer
  });

  assert.equal(res.status, 200);
  assert.equal(res.text, 'reached-second-source-ip');
  assert.equal(res.resolvedIp, '203.0.113.8');
  assert.equal(res.dialedAddress, '203.0.113.8:8080');
  assert.deepEqual(dialed, ['203.0.113.7:8080', '203.0.113.8:8080']);
  assert.equal(capturedRequests.length, 1);
  assert.match(capturedRequests[0], /^GET \/api\/health\?check=1 HTTP\/1\.1\r\n/i);
  assert.match(capturedRequests[0], /\r\nHost: app\.example\.com:8080\r\n/i);
});

test('fetch: createGovernedFetch routes HTTP requests to Source IP, re-dials on pin updates (no keep-alive reuse), and blocks mid-scan DNS rebinding (ARTEX TestPinnedDialNoReuseAcrossCalls)', async () => {
  const dialed = [];
  let currentDnsIps = ['203.0.113.7'];
  const pinStore = new TargetPinStore({ allowPrivate: false });

  const governedFetch = createGovernedFetch({
    dnsResolver: async () => currentDnsIps,
    targetPinStore: pinStore,
    usePinnedDialer: true,
    retries: 0,
    baseDialer: ({ address }) => {
      dialed.push(address);
      return createMockHttpSocket({
        status: 200,
        body: `from-${address}`
      });
    }
  });

  const first = await governedFetch('http://app.example.com/status');
  assert.equal(first.status, 200);
  assert.equal(first.text, 'from-203.0.113.7:80');
  assert.equal(first.resolvedIp, '203.0.113.7');
  assert.equal(first.dialedAddress, '203.0.113.7:80');

  // If operator revokes and re-pins to 203.0.113.8, next request dials 203.0.113.8 (no stale keep-alive reuse)
  pinStore.clear('app.example.com');
  pinStore.pin('app.example.com', ['203.0.113.8']);
  currentDnsIps = ['203.0.113.8'];

  const second = await governedFetch('http://app.example.com/status');
  assert.equal(second.status, 200);
  assert.equal(second.text, 'from-203.0.113.8:80');
  assert.deepEqual(dialed, ['203.0.113.7:80', '203.0.113.8:80']);

  // If DNS rebinds outside pin to 203.0.113.99 (or 127.0.0.1), dial is blocked before opening a connection
  currentDnsIps = ['203.0.113.99'];
  await assert.rejects(
    () => governedFetch('http://app.example.com/status'),
    /DNS pin mismatch/i
  );
  assert.equal(dialed.length, 2, 'Blocked rebind must not dial a third connection');
});

test('reproduction: buildCurlCommand & buildReproductionContext include --resolve <host>:<port>:<sourceIp> when Source-IP routing is active', async () => {
  const curl = buildCurlCommand({
    method: 'GET',
    url: 'https://fearlessbull.com/api/v1/status',
    sourceIp: '203.0.113.50'
  });
  assert.ok(curl.includes("--resolve 'fearlessbull.com:443:203.0.113.50'"), `Unexpected curl: ${curl}`);

  const baseFetch = createGovernedFetch({
    sourceIp: '203.0.113.50',
    fetcher: async (url, init) => ({
      status: 200,
      headers: { 'content-type': 'application/json' },
      text: '{"debug":true}',
      url,
      resolvedIp: init.resolvedIp,
      sourceIp: init.sourceIp,
      dialedAddress: init.dialedAddress
    })
  });

  const tracked = createTrackedFetch(baseFetch);
  const res = await tracked('https://app.example.com/debug');
  assert.equal(res.sourceIp, '203.0.113.50');
  assert.equal(res.dialedAddress, '203.0.113.50:443');

  const repro = buildReproductionContext(
    {
      name: 'Origin Exposure',
      checkId: 'origin-source-ip',
      target: 'https://app.example.com',
      url: 'https://app.example.com/debug',
      status: 'VULNERABLE',
      severity: 'HIGH',
      evidenceQuotes: ['{"debug":true}']
    },
    { capturedTraces: tracked.getTraces() }
  );

  assert.equal(repro.sourceIp, '203.0.113.50');
  assert.equal(repro.dialedAddress, '203.0.113.50:443');
  assert.ok(repro.curl.includes("--resolve 'app.example.com:443:203.0.113.50'"), `Expected --resolve in ${repro.curl}`);
});

test('fetch: createGovernedFetch pools keep-alive connections safely per pin version and evicts sockets when pin changes or destroyAgents is called', async () => {
  const http = await import('node:http');
  let connCount = 0;
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
  });
  server.on('connection', () => {
    connCount += 1;
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  try {
    const pinStore = new TargetPinStore({ allowPrivate: true });
    const governedFetch = createGovernedFetch({
      allowPrivate: true,
      enforceDnsValidation: true,
      targetPinStore: pinStore,
      dnsResolver: async () => ['127.0.0.1'],
      retries: 0
    });

    // Multiple requests under the same pin reuse the pooled keep-alive socket
    await governedFetch(`http://pooled.example.test:${port}/a`);
    await governedFetch(`http://pooled.example.test:${port}/b`);
    await governedFetch(`http://pooled.example.test:${port}/c`);
    assert.equal(connCount, 1, `Expected 1 TCP connection via keep-alive pool, got ${connCount}`);

    // Updating the pin version evicts idle keep-alive sockets so next request opens a fresh connection
    pinStore.clear('pooled.example.test');
    pinStore.pin('pooled.example.test', ['127.0.0.1']);
    await governedFetch(`http://pooled.example.test:${port}/d`);
    assert.equal(connCount, 2, `Expected new TCP connection after pin version change, got ${connCount}`);

    governedFetch.destroyAgents();
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
