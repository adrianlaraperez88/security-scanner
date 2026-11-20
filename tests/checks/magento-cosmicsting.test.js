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

test('magento-cosmicsting: SUSPICIOUS (HIGH) when Magento detected + REST endpoint accessible but version unknown', async () => {
  const fetch = mockFetchMap({
    '/rest/V1/guest-carts/1/estimate-shipping-methods': {
      status: 200, text: '{"amount":5.99}', headers: {}
    }
  });
  const origFetch = async (url, opts) => {
    if (url === BASE || url === `${BASE}/`) {
      return { status: 200, headers: MAGENTO_HEADERS, text: '<html>Magento Store</html>' };
    }
    return fetch(url, opts);
  };
  const r = await run(BASE, origFetch);
  assert.equal(r.status, 'SUSPICIOUS');
  assert.equal(r.severity, 'HIGH');
  assert.equal(r.cve, 'CVE-2024-34102');
});

test('magento-cosmicsting: CRITICAL when Magento version is in vulnerable range (2.4.6)', async () => {
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
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'CRITICAL');
  assert.equal(r.cve, 'CVE-2024-34102');
});

test('magento-cosmicsting: SAFE when patched Magento 2.4.7-p1 is detected', async () => {
  const fetch = async (url) => {
    if (url === BASE || url === `${BASE}/`) {
      return { status: 200, headers: MAGENTO_HEADERS, text: 'Magento Store' };
    }
    if (url.includes('/magento_version')) {
      return { status: 200, headers: {}, text: 'Magento/2.4.7-p1 (Community)' };
    }
    return { status: 200, headers: {}, text: '{}' };
  };
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SAFE');
  assert.equal(r.severity, 'NONE');
});

test('magento-cosmicsting: SUSPICIOUS (MEDIUM) when Magento detected and REST returns 404 or 403 WAF block', async () => {
  for (const status of [404, 403]) {
    const fetch = async (url) => {
      if (url === BASE || url === `${BASE}/`) {
        return { status: 200, headers: MAGENTO_HEADERS, text: 'Magento Store' };
      }
      if (url.includes('/rest/V1/')) {
        return { status, headers: {}, text: 'Blocked/Not Found' };
      }
      return { status: 404, headers: {}, text: 'Not Found' };
    };
    const r = await run(BASE, fetch);
    assert.equal(r.status, 'SUSPICIOUS');
    assert.equal(r.severity, 'MEDIUM');
  }
});

test('magento-cosmicsting: safely handles undefined res.text and returns ERROR on network or governance failure', async () => {
  const undefText = await run(BASE, mockFetch({ status: 200, headers: {} }));
  assert.equal(undefText.status, 'SAFE');

  const netErr = await run(BASE, mockFetchError('timeout'));
  assert.equal(netErr.status, 'ERROR');
  assert.match(netErr.reason, /timeout/);

  const govErr = new Error('Request blocked by SSRF policy');
  govErr.isGovernanceBlock = true;
  const govOnRest = await run(BASE, async (url) => {
    if (url === BASE || url === `${BASE}/`) {
      return { status: 200, headers: MAGENTO_HEADERS, text: 'Magento' };
    }
    if (url.includes('/rest/V1/')) throw govErr;
    return { status: 404, text: '' };
  });
  assert.equal(govOnRest.status, 'ERROR');
});
