import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';

import {
  classifyCdnIp,
  detectCdnFromHttp,
  extractSpfIps,
  extractHeaderOriginIps,
  discoverWebsiteRealIp
} from '../../core/real-ip-finder.js';
import { createAppServer } from '../../core/server.js';

function dispatchRequest(server, pathname, { method = 'POST', body = undefined, headers = {} } = {}) {
  return new Promise((resolve) => {
    const rawBody = body === undefined
      ? ''
      : (typeof body === 'string' ? body : JSON.stringify(body));

    const chunks = rawBody ? [Buffer.from(rawBody, 'utf8')] : [];
    const req = Object.assign(Readable.from(chunks), {
      url: pathname,
      method,
      headers: {
        host: '127.0.0.1:4321',
        ...(body !== undefined ? { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(rawBody)) } : {}),
        ...Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]))
      }
    });

    const resHeaders = {};
    const bodyChunks = [];
    const res = {
      statusCode: 200,
      headersSent: false,
      setHeader(name, val) {
        resHeaders[name.toLowerCase()] = val;
      },
      getHeader(name) {
        return resHeaders[name.toLowerCase()];
      },
      writeHead(code, hdrs) {
        this.statusCode = code;
        this.headersSent = true;
        if (hdrs) {
          for (const [k, v] of Object.entries(hdrs)) {
            resHeaders[k.toLowerCase()] = v;
          }
        }
      },
      write(chunk) {
        if (chunk) bodyChunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), 'utf8'));
      },
      end(chunk) {
        if (chunk) bodyChunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), 'utf8'));
        this.headersSent = true;
        const text = Buffer.concat(bodyChunks).toString('utf8');
        let json = null;
        try {
          json = JSON.parse(text);
        } catch {}
        resolve({
          status: this.statusCode,
          headers: resHeaders,
          text,
          json
        });
      }
    };

    server.emit('request', req, res);
  });
}

describe('Real / Origin IP Finder (core/real-ip-finder.js)', () => {
  test('classifyCdnIp and detectCdnFromHttp accurately classify major CDNs and non-CDN origin IPs', () => {
    assert.deepEqual(classifyCdnIp('104.21.10.5'), { isCdn: true, provider: 'Cloudflare' });
    assert.deepEqual(classifyCdnIp('2606:4700::1'), { isCdn: true, provider: 'Cloudflare' });
    assert.deepEqual(detectCdnFromHttp({ 'cf-ray': '8abc1234-SJC' }), { isCdn: true, provider: 'Cloudflare' });

    assert.deepEqual(classifyCdnIp('13.32.10.1'), { isCdn: true, provider: 'AWS CloudFront' });
    assert.deepEqual(detectCdnFromHttp({ 'x-amz-cf-id': 'cf-id-123' }), { isCdn: true, provider: 'AWS CloudFront' });

    assert.deepEqual(classifyCdnIp('151.101.1.1'), { isCdn: true, provider: 'Fastly' });
    assert.deepEqual(detectCdnFromHttp({ 'x-fastly-request-id': 'fastly-1' }), { isCdn: true, provider: 'Fastly' });

    assert.deepEqual(classifyCdnIp('23.32.10.1'), { isCdn: true, provider: 'Akamai' });
    assert.deepEqual(detectCdnFromHttp({ 'x-akamai-transformed': '9 - 0 pmb=mRUM,1' }), { isCdn: true, provider: 'Akamai' });

    assert.deepEqual(classifyCdnIp('199.83.128.1'), { isCdn: true, provider: 'Imperva / Incapsula' });
    assert.deepEqual(detectCdnFromHttp({ 'x-iinfo': '10-123456-0' }), { isCdn: true, provider: 'Imperva / Incapsula' });

    assert.deepEqual(classifyCdnIp('192.88.134.1'), { isCdn: true, provider: 'Sucuri' });
    assert.deepEqual(detectCdnFromHttp({ 'x-sucuri-id': '12001' }), { isCdn: true, provider: 'Sucuri' });

    assert.deepEqual(classifyCdnIp('203.0.113.50'), { isCdn: false, provider: null });
    assert.deepEqual(classifyCdnIp('93.184.216.34'), { isCdn: false, provider: null });
    assert.deepEqual(detectCdnFromHttp({ server: 'nginx/1.26.0' }, ['origin.example.com']), {
      isCdn: false,
      provider: null
    });
  });

  test('extractSpfIps and extractHeaderOriginIps extract ip4/ip6/a mechanisms and disclosed server IPs', () => {
    const spf = extractSpfIps([
      ['v=spf1 ip4:203.0.113.50 ip6:2001:db8::10 a:mail.example.com -all']
    ]);
    assert.deepEqual(spf.ips, [
      { ip: '203.0.113.50', mechanism: 'ip4' },
      { ip: '2001:db8::10', mechanism: 'ip6' }
    ]);
    assert.deepEqual(spf.hostnames, ['mail.example.com']);

    const bodyHtml = '<table><tr><th>SERVER_ADDR</th><td>203.0.113.53</td></tr></table>';
    const leaked = extractHeaderOriginIps(
      {
        'X-Origin-IP': '203.0.113.51',
        'X-Real-Server-IP': '203.0.113.52:8443'
      },
      bodyHtml
    );
    assert.deepEqual(leaked.sort(), ['203.0.113.51', '203.0.113.52', '203.0.113.53']);
  });

  test('discoverWebsiteRealIp returns direct non-CDN IP with 100% confidence', async () => {
    const dnsResolver = async (host, rrtype) => {
      if (host === 'example.com' && rrtype === 'A') return ['93.184.216.34'];
      return [];
    };

    const fetchFn = async () => ({
      status: 200,
      headers: { server: 'nginx/1.26.0' },
      text: async () => '<html><head><title>Example Domain</title></head><body>Hello</body></html>'
    });

    const result = await discoverWebsiteRealIp('https://example.com', {
      dnsResolver,
      fetchFn
    });

    assert.equal(result.isBehindCdn, false);
    assert.equal(result.cdnProvider, null);
    assert.equal(result.realIp, '93.184.216.34');
    assert.equal(result.realIpConfidence, 100);
    assert.equal(result.verifiedOrigin, true);
  });

  test('discoverWebsiteRealIp discovers and verifies origin IP behind Cloudflare via SPF, direct subdomain, and probeFn', async () => {
    const dnsResolver = async (host, rrtype) => {
      if (host === 'example.com' && rrtype === 'A') return ['104.21.1.1'];
      if (host === 'example.com' && rrtype === 'TXT') return [['v=spf1 ip4:203.0.113.50 -all']];
      if (host === 'direct.example.com' && rrtype === 'A') return ['203.0.113.50'];
      return [];
    };

    const fetchFn = async () => ({
      status: 200,
      headers: { 'cf-ray': '8abc1234-SJC', server: 'cloudflare' },
      text: async () => '<html><head><title>Acme Portal</title></head><body>Acme Portal Home</body></html>'
    });

    const probedIps = [];
    const probeFn = async (_url, candidateIp) => {
      probedIps.push(candidateIp);
      return {
        status: 200,
        headers: { server: 'nginx/1.26.0' },
        text: async () => '<html><head><title>Acme Portal</title></head><body>Acme Portal Home</body></html>'
      };
    };

    const result = await discoverWebsiteRealIp('https://example.com', {
      dnsResolver,
      fetchFn,
      probeFn
    });

    assert.equal(result.isBehindCdn, true);
    assert.equal(result.cdnProvider, 'Cloudflare');
    assert.equal(result.realIp, '203.0.113.50');
    assert.equal(result.verifiedOrigin, true);
    assert.ok(result.realIpConfidence >= 95);
    assert.deepEqual(probedIps, ['203.0.113.50']);

    const originCandidate = result.candidates.find(c => c.ip === '203.0.113.50');
    assert.ok(originCandidate);
    assert.ok(originCandidate.sources.includes('spf-txt'));
    assert.ok(originCandidate.sources.includes('subdomain:direct'));
    assert.equal(originCandidate.verifiedOriginMatch, true);
  });

  test('Boundary Security Regression: untrusted metadata, loopback, and private RFC1918 candidates are blocked, never probed, and never selected', async () => {
    const forbiddenIps = ['169.254.169.254', '127.0.0.1', '10.0.0.1', '192.168.1.1'];

    const dnsResolver = async (host, rrtype) => {
      if (host === 'example.com' && rrtype === 'A') return ['104.21.1.1'];
      if (host === 'example.com' && rrtype === 'TXT') {
        return [['v=spf1 ip4:169.254.169.254 ip4:127.0.0.1 ip4:10.0.0.1 ip4:192.168.1.1 -all']];
      }
      if (host === 'example.com' && rrtype === 'MX') {
        return [{ priority: 10, exchange: 'mail.example.com' }];
      }
      if (host === 'mail.example.com' && rrtype === 'A') return ['127.0.0.1'];
      if (host === 'direct.example.com' && rrtype === 'A') return ['10.0.0.1'];
      if (host === 'origin.example.com' && rrtype === 'A') return ['169.254.169.254'];
      return [];
    };

    const fetchFn = async () => ({
      status: 200,
      headers: {
        'cf-ray': '8abc1234-SJC',
        server: 'cloudflare',
        'X-Origin-IP': '169.254.169.254',
        'X-Real-Server-IP': '192.168.1.1'
      },
      text: async () => '<html><head><title>Protected</title></head><body>SERVER_ADDR=127.0.0.1</body></html>'
    });

    const probedIps = [];
    const probeFn = async (_url, candidateIp) => {
      probedIps.push(candidateIp);
      return {
        status: 200,
        headers: { server: 'nginx' },
        text: async () => '<html><head><title>Protected</title></head></html>'
      };
    };

    const result = await discoverWebsiteRealIp('https://example.com', {
      allowPrivate: false,
      dnsResolver,
      fetchFn,
      probeFn
    });

    for (const forbiddenIp of forbiddenIps) {
      assert.equal(probedIps.includes(forbiddenIp), false, `Forbidden IP ${forbiddenIp} must never be probed`);
      assert.notEqual(result.realIp, forbiddenIp, `Forbidden IP ${forbiddenIp} must never be selected as realIp`);

      const cand = result.candidates.find(c => c.ip === forbiddenIp);
      assert.ok(cand, `Expected ${forbiddenIp} to be recorded as a policy-blocked candidate`);
      assert.equal(cand.blockedByPolicy, true, `Expected ${forbiddenIp} to have blockedByPolicy: true`);
      assert.equal(cand.confidence, 0);
      assert.equal(cand.verifiedOriginMatch, false);
    }
  });

  test('POST /api/real-ip returns 200 for valid targets and 400/403 for disallowed targets', async () => {
    const dnsResolver = async (host, rrtype) => {
      if (host === 'example.com' && rrtype === 'A') return ['104.21.1.1'];
      if (host === 'example.com' && rrtype === 'TXT') return [['v=spf1 ip4:203.0.113.50 -all']];
      if (host === 'direct.example.com' && rrtype === 'A') return ['203.0.113.50'];
      return [];
    };

    const fetcher = async () => ({
      status: 200,
      headers: new Map([
        ['cf-ray', '8abc1234-SJC'],
        ['server', 'cloudflare']
      ]),
      text: async () => '<html><head><title>Example App</title></head><body>OK</body></html>'
    });

    const server = createAppServer({
      inMemory: true,
      dnsResolver,
      fetcher
    });

    try {
      const okRes = await dispatchRequest(server, '/api/real-ip', {
        method: 'POST',
        body: { target: 'https://example.com', verifyCandidates: false }
      });
      assert.equal(okRes.status, 200);
      assert.equal(okRes.json?.isBehindCdn, true);
      assert.equal(okRes.json?.realIp, '203.0.113.50');

      const metaRes = await dispatchRequest(server, '/api/real-ip', {
        method: 'POST',
        body: { target: 'http://169.254.169.254/latest/meta-data/' }
      });
      assert.ok(metaRes.status === 400 || metaRes.status === 403, `Expected 400 or 403 for metadata IP, got ${metaRes.status}`);

      const govRes = await dispatchRequest(server, '/api/real-ip', {
        method: 'POST',
        body: { target: 'https://whitehouse.gov' }
      });
      assert.ok(govRes.status === 400 || govRes.status === 403, `Expected 400 or 403 for .gov domain, got ${govRes.status}`);
    } finally {
      server.emit('close');
    }
  });
});
