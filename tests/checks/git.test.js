import { test } from 'node:test';
import assert    from 'node:assert/strict';
import { mockFetch, mockFetchError } from '../helpers/mock-fetch.js';
import run from '../../checks/git.js';

const BASE = 'https://example.com';

test('git: VULNERABLE when ref: found in HEAD', async () => {
  const fetch = mockFetch({ status: 200, text: 'ref: refs/heads/main' });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'HIGH');
});

test('git: SAFE when HEAD returns 404 (even if body contains ref:)', async () => {
  const fetch = mockFetch({ status: 404, text: 'Not Found' });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SAFE');

  const r404Ref = await run(BASE, mockFetch({ status: 404, text: 'ref: refs/heads/main' }));
  assert.equal(r404Ref.status, 'SAFE');

  const r500Ref = await run(BASE, mockFetch({ status: 500, text: 'ref: refs/heads/main' }));
  assert.equal(r500Ref.status, 'SAFE');
});

test('git: SAFE on 200 HTML catch-all, missing ref:, or undefined text', async () => {
  const fetch = mockFetch({ status: 200, text: 'some other content' });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SAFE');

  const htmlCatchAll = await run(BASE, mockFetch({
    status: 200,
    headers: { 'content-type': 'text/html' },
    text: '<html><body>ref: 12345</body></html>'
  }));
  assert.equal(htmlCatchAll.status, 'SAFE');

  const undefText = await run(BASE, mockFetch({ status: 200 }));
  assert.equal(undefText.status, 'SAFE');
});

test('git: normalizes target URL with query string cleanly', async () => {
  let requested = null;
  const r = await run('https://example.com/page?q=1', async (url) => {
    requested = url;
    return { status: 200, text: 'ref: refs/heads/main' };
  });
  assert.equal(requested, 'https://example.com/.git/HEAD');
  assert.equal(r.status, 'VULNERABLE');
});

test('git: ERROR on fetch failure, invalid URL, or governance block', async () => {
  const r = await run(BASE, mockFetchError('connection refused'));
  assert.equal(r.status, 'ERROR');

  const badUrl = await run('not-a-url', mockFetch({ status: 200 }));
  assert.equal(badUrl.status, 'ERROR');

  const govErr = new Error('Request blocked by SSRF policy');
  govErr.isGovernanceBlock = true;
  const govRes = await run(BASE, async () => { throw govErr; });
  assert.equal(govRes.status, 'ERROR');
  assert.match(govRes.reason, /SSRF policy/);
});
