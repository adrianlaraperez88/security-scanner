import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mockFetch, mockFetchError } from '../helpers/mock-fetch.js';
import run from '../../checks/xss.js';

test('xss: detects unescaped reflected XSS payload in HTML responses', async () => {
  const r = await run('https://example.com/search?q=hello', async (urlStr) => {
    const u = new URL(urlStr);
    return {
      status: 200,
      headers: { 'content-type': 'text/html' },
      text: `<html><body>Results for ${u.searchParams.get('q')}</body></html>`
    };
  });
  assert.equal(r.name, 'reflected xss');
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'HIGH');
  assert.equal(r.findings[0].parameter, 'q');
});

test('xss: avoids FPs on HTML-encoded output, application/json responses, no-query URLs, and undefined text', async () => {
  const encoded = await run('https://example.com/search?q=hello', async (urlStr) => {
    const u = new URL(urlStr);
    const escaped = String(u.searchParams.get('q')).replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return { status: 200, headers: { 'content-type': 'text/html' }, text: `<p>${escaped}</p>` };
  });
  assert.equal(encoded.status, 'SAFE');

  const jsonRes = await run('https://example.com/api?q=hello', async (urlStr) => {
    const u = new URL(urlStr);
    return {
      status: 200,
      headers: { 'content-type': 'application/json' },
      text: JSON.stringify({ q: u.searchParams.get('q') })
    };
  });
  assert.equal(jsonRes.status, 'SAFE');

  const noParams = await run('https://example.com/', mockFetch({ status: 200, text: 'OK' }));
  assert.equal(noParams.status, 'SAFE');

  const undefText = await run('https://example.com/search?q=1', mockFetch({ status: 200 }));
  assert.equal(undefText.status, 'SAFE');
});

test('xss: returns ERROR on invalid URL, total network failure on parameterized URL, or governance block', async () => {
  const bad = await run('not-a-url', mockFetch({ status: 200 }));
  assert.equal(bad.status, 'ERROR');

  const netErr = await run('https://example.com/search?q=1', mockFetchError('ECONNREFUSED'));
  assert.equal(netErr.status, 'ERROR');
  assert.match(netErr.reason, /ECONNREFUSED/);

  const govErr = new Error('Request blocked by SSRF policy');
  govErr.isGovernanceBlock = true;
  const govRes = await run('https://example.com/search?q=1', async () => { throw govErr; });
  assert.equal(govRes.status, 'ERROR');
  assert.match(govRes.reason, /SSRF policy/);
});
