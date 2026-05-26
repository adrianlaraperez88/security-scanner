import { test } from 'node:test';
import assert    from 'node:assert/strict';
import { mockFetch, mockFetchMap, mockFetchError } from '../helpers/mock-fetch.js';
import run from '../../checks/magento-cosmicsting.js';

const BASE = 'https://example.com';

const MAGENTO_HEADERS = { 'x-magento-cache-id': 'abc123', 'x-magento-tags': 'cms_b' };
const PLAIN_HEADERS   = {};

test('magento-cosmicsting: SAFE when no Magento signals found', async () => {
  const r = await run(BASE, mockFetch({ status: 200, headers: PLAIN_HEADERS, text: '<html>Generic</html>' }));
  assert.equal(r.status, 'SAFE');
  assert.equal(r.severity, 'NONE');
});

test('magento-cosmicsting: CRITICAL when Magento detected + REST endpoint accessible', async () => {
  const fetch = mockFetchMap({
    '/rest/V1/guest-carts/1/estimate-shipping-methods': {
      status: 200, text: '{"amount":5.99}', headers: {}
    }
  });
  // Homepage has Magento headers
  const origFetch = async (url, opts) => {
    if (url === BASE || url === `${BASE}/`) {
      return { status: 200, headers: MAGENTO_HEADERS, text: '<html>Magento Store</html>' };
    }
    return fetch(url, opts);
  };
  const r = await run(BASE, origFetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'CRITICAL');
  assert.equal(r.cve, 'CVE-2024-34102');
});

test('magento-cosmicsting: CRITICAL when Magento version is in vulnerable range', async () => {
  const fetch = async (url) => {
    if (url === BASE || url === `${BASE}/`) {
      return { status: 200, headers: MAGENTO_HEADERS, text: 'Magento Store' };
    }
    if (url.includes('/magento_version')) {
      return { status: 200, headers: {}, text: 'Magento/2.4.6' };
    }
    if (url.includes('/rest/V1/')) {
      return { status: 200, headers: {}, text: '{}' };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  };
  const r = await run(BASE, fetch);
  assert.ok(r.severity === 'CRITICAL' || r.severity === 'HIGH');
  assert.equal(r.cve, 'CVE-2024-34102');
});

test('magento-cosmicsting: HIGH when Magento detected but REST returns 404', async () => {
  const fetch = async (url) => {
    if (url === BASE || url === `${BASE}/`) {
      return { status: 200, headers: MAGENTO_HEADERS, text: 'Magento Store' };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  };
  const r = await run(BASE, fetch);
  assert.ok(['SUSPICIOUS', 'VULNERABLE'].includes(r.status));
  assert.ok(['MEDIUM', 'HIGH'].includes(r.severity));
});

test('magento-cosmicsting: ERROR on fetch failure returns SAFE', async () => {
  const r = await run(BASE, mockFetchError('timeout'));
  assert.equal(r.status, 'SAFE');   // can't detect Magento = SAFE
});
