import { test } from 'node:test';
import assert    from 'node:assert/strict';
import { mockFetch, mockFetchMap, mockFetchError } from '../helpers/mock-fetch.js';
import run from '../../checks/magento-checks.js';

const BASE = 'https://example.com';

test('magento-checks: SAFE when no Magento paths accessible', async () => {
  const r = await run(BASE, mockFetch({ status: 404, text: 'Not Found' }));
  assert.equal(r.status, 'SAFE');
  assert.equal(r.severity, 'NONE');
});

test('magento-checks: CRITICAL when /app/etc/local.xml returns DB credentials', async () => {
  const fetch = mockFetchMap({
    '/app/etc/local.xml': {
      status: 200,
      text  : '<connection><host>localhost</host><username>root</username><password>secret123</password></connection>'
    }
  });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'CRITICAL');
  assert.ok(r.findings.some(f => f.path === '/app/etc/local.xml'));
});

test('magento-checks: HIGH when /downloader/ accessible', async () => {
  const fetch = mockFetchMap({
    '/downloader/': { status: 200, text: '<title>Magento Connect Manager</title> downloader package' }
  });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'HIGH');
});

test('magento-checks: MEDIUM when /magento_version accessible', async () => {
  const fetch = mockFetchMap({
    '/magento_version': { status: 200, text: 'Magento/2.4.5' }
  });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.ok(r.findings.some(f => f.path === '/magento_version'));
});

test('magento-checks: ERROR when all requests fail', async () => {
  const r = await run(BASE, mockFetchError('connection refused'));
  assert.equal(r.status, 'SAFE');
});
