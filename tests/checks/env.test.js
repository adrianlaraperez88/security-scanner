import { test } from 'node:test';
import assert    from 'node:assert/strict';
import { mockFetch, mockFetchMap, mockFetchError } from '../helpers/mock-fetch.js';
import run from '../../checks/env.js';

const BASE = 'https://example.com';

test('env: VULNERABLE when APP_KEY found in 200 response', async () => {
  const fetch = mockFetch({ status: 200, text: 'APP_KEY=base64:abc123\nDB_PASSWORD=secret' });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'CRITICAL');
});

test('env: SAFE when blanket dotfile rule returns HTTP 403 for all dotfiles (including /.secscan_dotfile_probe), SUSPICIOUS when only /.env returns 403', async () => {
  const blanket403 = mockFetch({ status: 403, text: 'Forbidden' });
  const rSafe = await run(BASE, blanket403);
  assert.equal(rSafe.status, 'SAFE');
  assert.equal(rSafe.severity, 'NONE');

  const specific403 = mockFetchMap({
    '/.env': { status: 403, text: 'Forbidden' },
    '/.secscan_dotfile_probe': { status: 404, text: 'Not Found' }
  });
  const rSusp = await run(BASE, specific403);
  assert.equal(rSusp.status, 'SUSPICIOUS');
  assert.equal(rSusp.severity, 'MEDIUM');
  assert.equal(rSusp.path, '/.env');
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

test('env: avoids HTML fallback FPs, confirms reproducibility, and redacts secrets in evidenceQuotes', async () => {
  const htmlFp = await run(BASE, mockFetch({
    status: 200,
    headers: { 'content-type': 'text/html' },
    text: '<html><body><p>Set APP_KEY=value in docs</p></body></html>'
  }));
  assert.equal(htmlFp.status, 'SAFE');

  const r = await run(BASE, mockFetch({
    status: 200,
    headers: { 'content-type': 'text/plain' },
    text: 'APP_KEY=base64:superSecretAppKey999\nDB_PASSWORD=topSecretPassword123\n',
    trafficId: 'tx-env-1'
  }));
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.reproVerified, true);
  assert.equal(r.path, '/.env');
  assert.match(r.detail, /Confirmed reproducible \.env exposure/);
  assert.equal(r.poeLevel, 3);
  assert.equal(r.trafficId, 'tx-env-1');
  assert.ok(Array.isArray(r.evidenceQuotes) && r.evidenceQuotes.length > 0);
  assert.equal(r.evidenceQuotes.join('\n').includes('superSecretAppKey999'), false);
});
