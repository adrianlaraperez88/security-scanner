import { test } from 'node:test';
import assert    from 'node:assert/strict';
import { mockFetch, mockFetchError } from '../helpers/mock-fetch.js';
import run from '../../checks/git.js';

const BASE = 'https://example.com';

test('git: VULNERABLE when ref: found in HEAD', async () => {
  const fetch = mockFetch({ status: 200, text: 'ref: refs/heads/main' });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'HIGH');
});

test('git: SAFE when HEAD returns 404', async () => {
  const fetch = mockFetch({ status: 404, text: 'Not Found' });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SAFE');
});

test('git: SAFE when HEAD exists but no ref:', async () => {
  const fetch = mockFetch({ status: 200, text: 'some other content' });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SAFE');
});

test('git: ERROR on fetch failure', async () => {
  const r = await run(BASE, mockFetchError('connection refused'));
  assert.equal(r.status, 'ERROR');
});
