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

test('php-cgi-exposure: HIGH when /php-status returns FPM status page', async () => {
  const fetch = mockFetchMap({
    '/php-status': {
      status: 200,
      text  : 'pool: www\nprocess manager: dynamic\nidle processes: 4\nactive processes: 1'
    }
  });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'HIGH');
  assert.ok(r.findings.some(f => f.path === '/php-status'));
});

test('php-cgi-exposure: HIGH when /cgi-bin/php accessible with PHP signal', async () => {
  const fetch = mockFetchMap({
    '/cgi-bin/php': { status: 200, text: 'Content-type: text/html\n\nphp version detected' }
  });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'HIGH');
});

test('php-cgi-exposure: SAFE when all requests throw', async () => {
  const r = await run(BASE, mockFetchError('ECONNREFUSED'));
  assert.equal(r.status, 'SAFE');
});
