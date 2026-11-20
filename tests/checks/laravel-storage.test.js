import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mockFetch, mockFetchError } from '../helpers/mock-fetch.js';
import run from '../../checks/laravel-storage.js';

const BASE = 'https://example.com';

test('laravel-storage: VULNERABLE on 200 plain-text Laravel log with exception or stack trace', async () => {
  const r = await run(BASE, mockFetch({
    status: 200,
    headers: { 'content-type': 'text/plain' },
    text: '[2025-01-01 00:00:00] production.ERROR: RuntimeException in /var/www/app/Http/Controllers/Test.php\nStack trace:\n#0 ...'
  }));
  assert.equal(r.name, 'laravel log exposure');
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'HIGH');
});

test('laravel-storage: SAFE on 404/500 with exception text, 200 HTML catch-all, or undefined text', async () => {
  const r404 = await run(BASE, mockFetch({ status: 404, text: 'Not Found: unhandled exception in stack trace' }));
  assert.equal(r404.status, 'SAFE');

  const rHtml = await run(BASE, mockFetch({
    status: 200,
    headers: { 'content-type': 'text/html; charset=utf-8' },
    text: '<!doctype html><html><body>Exception handling guide and stack trace docs</body></html>'
  }));
  assert.equal(rHtml.status, 'SAFE');

  const rUndef = await run(BASE, mockFetch({ status: 200 }));
  assert.equal(rUndef.status, 'SAFE');
});

test('laravel-storage: normalizes URL query string and propagates ERROR with reason', async () => {
  let seenUrl = null;
  await run('https://example.com/dashboard?tab=1', async (u) => {
    seenUrl = u;
    return { status: 404, text: 'Not Found' };
  });
  assert.equal(seenUrl, 'https://example.com/storage/logs/laravel.log');

  const netErr = await run(BASE, mockFetchError('ETIMEDOUT'));
  assert.equal(netErr.status, 'ERROR');
  assert.match(netErr.reason, /ETIMEDOUT/);

  const govErr = new Error('Request blocked by SSRF policy');
  govErr.isGovernanceBlock = true;
  const govRes = await run(BASE, async () => { throw govErr; });
  assert.equal(govRes.status, 'ERROR');
  assert.match(govRes.reason, /SSRF policy/);
});
