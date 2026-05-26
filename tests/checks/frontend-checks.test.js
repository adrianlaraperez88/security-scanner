import { test } from 'node:test';
import assert    from 'node:assert/strict';
import { mockFetch, mockFetchError } from '../helpers/mock-fetch.js';
import run from '../../checks/frontend-checks.js';

const BASE = 'https://example.com';

test('frontend: VULNERABLE when source map found', async () => {
  const fetch = (url) => {
    if (url === BASE) {
      return { status: 200, text: '<script src="/static/js/main.js"></script>' };
    }
    if (url.includes('main.js.map')) {
      return { status: 200, text: '{"version":3,"sources":["main.js"]}' };
    }
    return { status: 404, text: 'not found' };
  };
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'HIGH');
  assert.ok(r.findings.some(f => f.name === 'exposed source maps'));
});

test('frontend: SUSPICIOUS when dev mode signatures found', async () => {
  const fetch = (url) => {
    if (url === BASE) {
      return { status: 200, text: '<div>Download the React DevTools for a better experience</div>' };
    }
    return { status: 404, text: 'not found' };
  };
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SUSPICIOUS');
  assert.equal(r.severity, 'LOW');
  assert.ok(r.findings.some(f => f.name === 'development build detected'));
});

test('frontend: SUSPICIOUS when potential credentials found in HTML', async () => {
  const fetch = (url) => {
    if (url === BASE) {
      return { status: 200, text: 'const config = { apiKey: "AIzaSyB-xyz123abc456", projectId: "my-project" };' };
    }
    return { status: 404, text: 'not found' };
  };
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SUSPICIOUS');
  assert.ok(r.findings.some(f => f.name === 'potential generic api key exposure'));
});

test('frontend: SAFE when nothing found', async () => {
  const fetch = mockFetch({ status: 200, text: '<html><body>hello</body></html>' });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SAFE');
});
