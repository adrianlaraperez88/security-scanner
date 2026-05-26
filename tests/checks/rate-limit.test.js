import { test } from 'node:test';
import assert    from 'node:assert/strict';
import { mockFetch, mockFetchError } from '../helpers/mock-fetch.js';
import run from '../../checks/rate-limit.js';

const BASE = 'https://example.com';

test('rate-limit: SAFE when 429 returned', async () => {
  const fetch = mockFetch({ status: 429, text: 'Too Many Requests' });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SAFE');
});

test('rate-limit: SAFE when X-RateLimit-Limit header present', async () => {
  const fetch = mockFetch({ status: 200, headers: { 'x-ratelimit-limit': '100' }, text: 'ok' });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SAFE');
});

test('rate-limit: SUSPICIOUS when all burst requests succeed with no limits', async () => {
  const fetch = mockFetch({ status: 200, headers: {}, text: 'ok' });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SUSPICIOUS');
  assert.equal(r.severity, 'MEDIUM');
});

test('rate-limit: ERROR when all requests fail', async () => {
  const r = await run(BASE, mockFetchError());
  assert.equal(r.status, 'ERROR');
});
