import { test } from 'node:test';
import assert    from 'node:assert/strict';
import { mockFetch, mockFetchMap, mockFetchError } from '../helpers/mock-fetch.js';
import run from '../../checks/drupal-checks.js';

const BASE = 'https://example.com';

const DRUPAL_HEADERS  = { 'x-drupal-cache': 'MISS' };
const GENERIC_HEADERS = {};

test('drupal-checks: SAFE when no Drupal signals found', async () => {
  const r = await run(BASE, mockFetch({ status: 200, headers: GENERIC_HEADERS, text: '<html>Generic</html>' }));
  assert.equal(r.status, 'SAFE');
  assert.equal(r.severity, 'NONE');
});

test('drupal-checks: CRITICAL when Drupal 7 detected via CHANGELOG.txt', async () => {
  const fetch = async (url) => {
    if (url === BASE || url === `${BASE}/`) {
      return { status: 200, headers: DRUPAL_HEADERS, text: '<html>Drupal site</html>' };
    }
    if (url.includes('/CHANGELOG.txt')) {
      return { status: 200, headers: {}, text: 'Drupal 7.99, 2024-10-01\n' };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  };
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'CRITICAL');
  assert.equal(r.version, '7.99');
});

test('drupal-checks: HIGH when Drupal 9.x detected (EOL Nov 2023)', async () => {
  const fetch = async (url) => {
    if (url === BASE || url === `${BASE}/`) {
      return { status: 200, headers: DRUPAL_HEADERS, text: 'drupal site' };
    }
    if (url.includes('/core/CHANGELOG.txt')) {
      return { status: 200, headers: {}, text: 'Drupal 9.5.11, 2023-09-15' };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  };
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'HIGH');
  assert.equal(r.version, '9.5.11');
});

test('drupal-checks: LOW when Drupal detected but CHANGELOG returns 404', async () => {
  const fetch = async (url) => {
    if (url === BASE || url === `${BASE}/`) {
      return { status: 200, headers: DRUPAL_HEADERS, text: '<html>site</html>' };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  };
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SUSPICIOUS');  // Drupal found, version unknown
  assert.equal(r.severity, 'LOW');
});

test('drupal-checks: LOW when CHANGELOG accessible but version is current Drupal 10', async () => {
  const fetch = async (url) => {
    if (url === BASE || url === `${BASE}/`) {
      return { status: 200, headers: DRUPAL_HEADERS, text: 'drupal' };
    }
    if (url.includes('/core/CHANGELOG.txt')) {
      return { status: 200, headers: {}, text: 'Drupal 10.4.1, 2025-01-15' };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  };
  const r = await run(BASE, fetch);
  assert.ok(['LOW', 'MEDIUM'].includes(r.severity));  // Not EOL but CHANGELOG exposed
});

test('drupal-checks: SAFE on fetch failure', async () => {
  const r = await run(BASE, mockFetchError('timeout'));
  assert.equal(r.status, 'SAFE');
});
