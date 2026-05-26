import { test } from 'node:test';
import assert    from 'node:assert/strict';
import { mockFetch, mockFetchError } from '../helpers/mock-fetch.js';
import run from '../../checks/cors.js';

const BASE = 'https://example.com';

test('cors: SAFE when ACAO not set', async () => {
  const fetch = mockFetch({ status: 200, headers: {}, text: 'ok' });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SAFE');
});

test('cors: VULNERABLE when ACAO is wildcard *', async () => {
  const fetch = mockFetch({ status: 200, headers: { 'access-control-allow-origin': '*' }, text: 'ok' });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'MEDIUM');
});

test('cors: VULNERABLE+HIGH when origin reflected with credentials', async () => {
  const fetch = mockFetch({
    status: 200,
    headers: {
      'access-control-allow-origin'     : 'https://evil.attacker.example.com',
      'access-control-allow-credentials': 'true'
    },
    text: 'ok'
  });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'HIGH');
});

test('cors: VULNERABLE+MEDIUM when origin reflected without credentials', async () => {
  const fetch = mockFetch({
    status: 200,
    headers: { 'access-control-allow-origin': 'https://evil.attacker.example.com' },
    text: 'ok'
  });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'MEDIUM');
});

test('cors: ERROR on fetch failure', async () => {
  const r = await run(BASE, mockFetchError());
  assert.equal(r.status, 'ERROR');
});
