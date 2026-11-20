import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mockFetch, mockFetchError } from '../helpers/mock-fetch.js';
import run from '../../checks/nextjs-checks.js';

const BASE = 'https://example.com';

test('nextjs-checks: VULNERABLE+CRITICAL on CVE-2025-29927 middleware bypass', async () => {
  const fetch = async (url, options = {}) => {
    if (url === `${BASE}/admin`) {
      if (options.headers && options.headers['x-middleware-subrequest']) {
        return { status: 200, headers: {}, text: '<html><body>Admin Dashboard</body></html>' };
      }
      return { status: 403, headers: {}, text: 'Forbidden' };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  };

  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'CRITICAL');
  assert.ok(r.findings.some(f => f.name.includes('CVE-2025-29927') && f.severity === 'CRITICAL'));
});

test('nextjs-checks: VULNERABLE+HIGH on exposed /_next/static/chunks/main.js.map', async () => {
  const fetch = async (url) => {
    if (url === BASE) {
      return {
        status: 200,
        headers: {},
        text: '<html><head><script src="/_next/static/chunks/main.js"></script></head></html>'
      };
    }
    if (url === `${BASE}/_next/static/chunks/main.js.map`) {
      return {
        status: 200,
        headers: {},
        text: '{"version":3,"sources":["webpack://_N_E/./pages/index.tsx"]}'
      };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  };

  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'HIGH');
  assert.ok(r.findings.some(f => f.name === 'exposed next.js source maps'));
});

test('nextjs-checks: SUSPICIOUS+HIGH on __NEXT_DATA__ secret exposure', async () => {
  const fetch = async (url) => {
    if (url === BASE) {
      return {
        status: 200,
        headers: {},
        text: '<html><body><script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"databaseUrl":"postgres://user:pass@db:5432/prod"}}}</script></body></html>'
      };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  };

  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SUSPICIOUS');
  assert.equal(r.severity, 'HIGH');
  assert.ok(r.findings.some(f => f.name === 'sensitive data leak in __NEXT_DATA__'));
});

test('nextjs-checks: SAFE on clean response', async () => {
  const fetch = mockFetch({ status: 404, text: 'Not Found' });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SAFE');
  assert.equal(r.severity, 'NONE');
});

test('nextjs-checks: ERROR on network failure', async () => {
  const r = await run(BASE, mockFetchError('network unreachable'));
  assert.equal(r.status, 'ERROR');
  assert.equal(r.severity, 'NONE');
});
