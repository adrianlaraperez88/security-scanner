import { test } from 'node:test';
import assert    from 'node:assert/strict';
import { mockFetch, mockFetchError } from '../helpers/mock-fetch.js';
import run from '../../checks/cookie-security.js';

const BASE = 'https://example.com';

test('cookie-security: SAFE when no cookies set', async () => {
  const fetch = mockFetch({ status: 200, headers: {}, text: 'ok' });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SAFE');
});

test('cookie-security: SAFE when all flags present', async () => {
  const fetch = mockFetch({
    status: 200,
    headers: { 'set-cookie': 'session=abc; Secure; HttpOnly; SameSite=Strict' },
    text: 'ok'
  });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SAFE');
});

test('cookie-security: SUSPICIOUS+HIGH when Secure missing', async () => {
  const fetch = mockFetch({
    status: 200,
    headers: { 'set-cookie': 'session=abc; HttpOnly; SameSite=Strict' },
    text: 'ok'
  });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SUSPICIOUS');
  assert.equal(r.severity, 'HIGH');
  assert.ok(r.issues.some(i => i.issue.includes('Secure')));
});

test('cookie-security: SUSPICIOUS+MEDIUM when HttpOnly missing', async () => {
  const fetch = mockFetch({
    status: 200,
    headers: { 'set-cookie': 'session=abc; Secure; SameSite=Strict' },
    text: 'ok'
  });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SUSPICIOUS');
  assert.ok(r.issues.some(i => i.issue.includes('HttpOnly')));
});

test('cookie-security: ERROR on fetch failure', async () => {
  const r = await run(BASE, mockFetchError());
  assert.equal(r.status, 'ERROR');
});
