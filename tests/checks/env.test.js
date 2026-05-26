import { test } from 'node:test';
import assert    from 'node:assert/strict';
import { mockFetch, mockFetchError } from '../helpers/mock-fetch.js';
import run from '../../checks/env.js';

const BASE = 'https://example.com';

test('env: VULNERABLE when APP_KEY found in 200 response', async () => {
  const fetch = mockFetch({ status: 200, text: 'APP_KEY=base64:abc123\nDB_PASSWORD=secret' });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'CRITICAL');
});

test('env: SUSPICIOUS when .env returns HTTP 403', async () => {
  const fetch = mockFetch({ status: 403, text: 'Forbidden' });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SUSPICIOUS');
  assert.equal(r.severity, 'MEDIUM');
});

test('env: SAFE when all paths return 404', async () => {
  const fetch = mockFetch({ status: 404, text: 'Not Found' });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SAFE');
  assert.equal(r.severity, 'NONE');
});

test('env: SAFE when 200 but no sensitive keys in body', async () => {
  const fetch = mockFetch({ status: 200, text: 'just a webpage with no secrets' });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SAFE');
});

test('env: ERROR when all paths throw', async () => {
  const fetch = mockFetchError('network failure');
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'ERROR');
});
