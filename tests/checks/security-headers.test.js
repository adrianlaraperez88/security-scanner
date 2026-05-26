import { test } from 'node:test';
import assert    from 'node:assert/strict';
import { mockFetch, mockFetchError } from '../helpers/mock-fetch.js';
import run from '../../checks/security-headers.js';

const BASE = 'https://example.com';

const ALL_HEADERS = {
  'strict-transport-security': 'max-age=31536000',
  'x-content-type-options'  : 'nosniff',
  'x-frame-options'         : 'DENY',
  'content-security-policy' : "default-src 'self'",
  'referrer-policy'         : 'strict-origin-when-cross-origin',
  'permissions-policy'      : 'geolocation=()',
};

test('security-headers: SAFE when all headers present', async () => {
  const fetch = mockFetch({ status: 200, headers: ALL_HEADERS, text: 'ok' });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SAFE');
  assert.equal(r.severity, 'NONE');
});

test('security-headers: SUSPICIOUS+HIGH when all 6 missing', async () => {
  const fetch = mockFetch({ status: 200, headers: {}, text: 'ok' });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SUSPICIOUS');
  assert.equal(r.severity, 'HIGH');
  assert.equal(r.missing.length, 6);
});

test('security-headers: MEDIUM when 2-3 headers missing', async () => {
  const { 'content-security-policy': _, 'permissions-policy': __, ...partial } = ALL_HEADERS;
  const fetch = mockFetch({ status: 200, headers: partial, text: 'ok' });
  const r = await run(BASE, fetch);
  assert.equal(r.severity, 'MEDIUM');
  assert.equal(r.missing.length, 2);
});

test('security-headers: ERROR on fetch failure', async () => {
  const r = await run(BASE, mockFetchError());
  assert.equal(r.status, 'ERROR');
});
