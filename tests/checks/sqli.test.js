import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mockFetch, mockFetchError } from '../helpers/mock-fetch.js';
import run from '../../checks/sqli.js';

test('sqli: detects error-based SQLi and time-based SQLi above baseline', async () => {
  const errRes = await run('https://example.com/search?id=1', mockFetch({
    status: 500,
    text: 'You have an error in your SQL syntax near ...'
  }));
  assert.equal(errRes.name, 'sql injection');
  assert.equal(errRes.status, 'VULNERABLE');
  assert.equal(errRes.severity, 'CRITICAL');
  assert.ok(errRes.findings.some(f => f.type === 'SQLI_ERROR' && f.parameter === 'id'));

  const timeRes = await run(
    'https://example.com/item?id=1',
    async (url) => {
      if (url.includes('SLEEP')) {
        await new Promise(r => setTimeout(r, 140));
      }
      return { status: 200, text: 'ok' };
    },
    { delayThresholdMs: 100 }
  );
  assert.equal(timeRes.status, 'VULNERABLE');
  assert.ok(timeRes.findings.some(f => f.type === 'SQLI_TIME' && f.parameter === 'id'));
});

test('sqli: avoids slow-baseline FP, handles no-query URLs and undefined text safely', async () => {
  const slowServerRes = await run(
    'https://example.com/item?id=1',
    async () => {
      await new Promise(r => setTimeout(r, 140));
      return { status: 200, text: 'ok' };
    },
    { delayThresholdMs: 100 }
  );
  assert.equal(slowServerRes.status, 'SAFE');

  const noParams = await run('https://example.com/about', mockFetch({ status: 200, text: 'Hello' }));
  assert.equal(noParams.status, 'SAFE');

  const undefText = await run('https://example.com/item?id=1', mockFetch({ status: 200 }));
  assert.equal(undefText.status, 'SAFE');
});

test('sqli: returns ERROR on invalid URL, total network failure on parameterized URL, or governance block', async () => {
  const bad = await run('not-a-url', mockFetch({ status: 200 }));
  assert.equal(bad.status, 'ERROR');

  const netErr = await run('https://example.com/item?id=1', mockFetchError('ECONNREFUSED'));
  assert.equal(netErr.status, 'ERROR');
  assert.match(netErr.reason, /ECONNREFUSED/);

  const govErr = new Error('Request blocked by SSRF policy');
  govErr.isGovernanceBlock = true;
  const govRes = await run('https://example.com/item?id=1', async () => { throw govErr; });
  assert.equal(govRes.status, 'ERROR');
  assert.match(govRes.reason, /SSRF policy/);
});
