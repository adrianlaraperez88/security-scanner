import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mockFetch, mockFetchError } from '../helpers/mock-fetch.js';
import run from '../../checks/http-methods.js';

const BASE = 'https://example.com';

test('http-methods: detects TRACE echo, 2xx PUT/DELETE, and OPTIONS Allow header', async () => {
  const fetch = async (_url, opts) => {
    const m = opts?.method;
    if (m === 'TRACE') return { status: 200, headers: { 'content-type': 'message/http' }, text: 'TRACE / HTTP/1.1\r\nHost: example.com' };
    if (m === 'PUT') return { status: 201, headers: {}, text: 'Created' };
    if (m === 'DELETE') return { status: 204, headers: {}, text: '' };
    if (m === 'OPTIONS') return { status: 200, headers: { Allow: 'GET, POST, PUT' }, text: '' };
    return { status: 405, headers: {}, text: 'Method Not Allowed' };
  };

  const r = await run(BASE, fetch);
  assert.equal(r.name, 'http methods');
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'HIGH');
  assert.equal(r.findings.length, 4);
});

test('http-methods: avoids FPs on 3xx redirects for PUT/DELETE, HTML TRACE mention, and handles undefined text', async () => {
  const redirectFetch = async (_url, opts) => {
    const m = opts?.method;
    if (m === 'PUT' || m === 'DELETE') return { status: 302, headers: { location: 'https://example.com/login' }, text: '' };
    if (m === 'TRACE') return { status: 200, headers: { 'content-type': 'text/html' }, text: '<html><body>Stack trace guide</body></html>' };
    if (m === 'OPTIONS') return { status: 200, headers: { Allow: 'GET, HEAD, OUTPUT' }, text: '' };
    return { status: 405, headers: {}, text: '' };
  };
  const r = await run(BASE, redirectFetch);
  assert.equal(r.status, 'SAFE');

  const htmlSpaFetch = async (_url, opts) => {
    const m = opts?.method;
    if (m === 'PUT' || m === 'DELETE') {
      return { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' }, text: '<!DOCTYPE html><html><body>SPA Fallback</body></html>' };
    }
    return { status: 405, headers: {}, text: '' };
  };
  const rSpa = await run(BASE, htmlSpaFetch);
  assert.equal(rSpa.status, 'SAFE');

  const safe405 = await run(BASE, mockFetch({ status: 405 }));
  assert.equal(safe405.status, 'SAFE');
});

test('http-methods: returns ERROR on all-failed requests, invalid URL, or governance block', async () => {
  const bad = await run('not-a-url', mockFetch({ status: 200 }));
  assert.equal(bad.status, 'ERROR');

  const netErr = await run(BASE, mockFetchError('ETIMEDOUT'));
  assert.equal(netErr.status, 'ERROR');
  assert.match(netErr.reason, /ETIMEDOUT/);

  const govErr = new Error('Request blocked by SSRF policy');
  govErr.isGovernanceBlock = true;
  const govRes = await run(BASE, async () => { throw govErr; });
  assert.equal(govRes.status, 'ERROR');
  assert.match(govRes.reason, /SSRF policy/);
});
