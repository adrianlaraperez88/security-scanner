import { test } from 'node:test';
import assert    from 'node:assert/strict';
import { mockFetch, mockFetchMap, mockFetchError } from '../helpers/mock-fetch.js';
import run from '../../checks/php-cgi-exposure.js';

const BASE = 'https://example.com';

test('php-cgi-exposure: SAFE when all paths return 404', async () => {
  const r = await run(BASE, mockFetch({ status: 404, text: 'Not Found' }));
  assert.equal(r.status, 'SAFE');
  assert.equal(r.severity, 'NONE');
});

test('php-cgi-exposure: HIGH when /fpm-ping returns "pong"', async () => {
  const fetch = mockFetchMap({
    '/fpm-ping': { status: 200, text: 'pong' }
  });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'HIGH');
  assert.ok(r.findings.some(f => f.path === '/fpm-ping'));
});

test('php-cgi-exposure: HIGH when /php-status or /php-fpm-status returns FPM status page and notes CVE-2026-129292', async () => {
  for (const statusPath of ['/php-status', '/php-fpm-status']) {
    const fetch = mockFetchMap({
      [statusPath]: {
        status: 200,
        text  : 'pool: www\nprocess manager: dynamic\nidle processes: 4\nactive processes: 1'
      }
    });
    const r = await run(BASE, fetch);
    assert.equal(r.status, 'VULNERABLE');
    assert.equal(r.severity, 'HIGH');
    const item = r.findings.find(f => f.path === statusPath);
    assert.ok(item, `Expected finding for ${statusPath}`);
    assert.match(item.detail, /CVE-2026-129292/);
    assert.match(r.fix, /CVE-2026-129292/);
  }
});

test('php-cgi-exposure: HIGH when /cgi-bin/php accessible with PHP signal and notes CVE-2026-129538', async () => {
  const fetch = mockFetchMap({
    '/cgi-bin/php': { status: 200, text: 'Content-type: text/html\n\nphp version detected' }
  });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'HIGH');
  const item = r.findings.find(f => f.path === '/cgi-bin/php');
  assert.ok(item);
  assert.match(item.detail, /CVE-2026-129538/);
  assert.match(r.fix, /CVE-2026-129538/);
});

test('php-cgi-exposure: avoids FPs on "sponge"/"ping-pong" and generic 200 HTML mentioning php, handles undefined text', async () => {
  const fpPing = await run(BASE, mockFetchMap({
    '/fpm-ping': { status: 200, text: 'sponge ping-pong tournament' },
    '/php-fpm-ping': { status: 200, text: 'ping-pong' }
  }));
  assert.equal(fpPing.status, 'SAFE');

  const fpHtml = await run(BASE, mockFetch({
    status: 200,
    headers: { 'content-type': 'text/html' },
    text: '<!doctype html><html><body>Learn PHP programming today</body></html>'
  }));
  assert.equal(fpHtml.status, 'SAFE');

  const undefText = await run(BASE, mockFetch({ status: 200 }));
  assert.equal(undefText.status, 'SAFE');
});

test('php-cgi-exposure: ERROR when all requests throw or governance blocks', async () => {
  const r = await run(BASE, mockFetchError('ECONNREFUSED'));
  assert.equal(r.status, 'ERROR');
  assert.match(r.reason, /ECONNREFUSED/);

  const govErr = new Error('Request blocked by SSRF policy');
  govErr.isGovernanceBlock = true;
  const govRes = await run(BASE, async () => { throw govErr; });
  assert.equal(govRes.status, 'ERROR');
  assert.match(govRes.reason, /SSRF policy/);
});
