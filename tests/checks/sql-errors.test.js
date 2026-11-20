import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mockFetch, mockFetchError } from '../helpers/mock-fetch.js';
import run from '../../checks/sql-errors.js';

const BASE = 'https://example.com';

test('sql-errors: detects MySQL/PostgreSQL error leakage on single-quote probe', async () => {
  const fetch = async (url) => {
    const u = new URL(url);
    if (u.searchParams.get('id') === "'") {
      return { status: 500, text: "You have an error in your SQL syntax; check the manual near ''" };
    }
    return { status: 200, text: 'OK' };
  };

  const r = await run(BASE, fetch);
  assert.equal(r.name, 'sql error disclosure');
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'HIGH');
});

test('sql-errors: avoids FP on generic "syntax error" JSON and pre-existing baseline SQL patterns', async () => {
  const jsonSyntaxErr = await run(BASE, mockFetch({
    status: 400,
    headers: { 'content-type': 'application/json' },
    text: '{"error":"Syntax error in JSON payload"}'
  }));
  assert.equal(jsonSyntaxErr.status, 'SAFE');

  // Pattern already present on baseline page (e.g. a tutorial page mentioning sqlstate)
  const baselineMention = await run(BASE, mockFetch({
    status: 200,
    text: 'Documentation: SQLSTATE[42000] means syntax error or access violation.'
  }));
  assert.equal(baselineMention.status, 'SAFE');

  const undefText = await run(BASE, mockFetch({ status: 200 }));
  assert.equal(undefText.status, 'SAFE');
});

test('sql-errors: safely appends query parameter to URLs that already have query params', async () => {
  const seen = [];
  await run('https://example.com/items?cat=books', async (url) => {
    seen.push(url);
    return { status: 200, text: 'OK' };
  });
  for (const u of seen) {
    assert.equal(u.split('?').length, 2, `Malformed query URL: ${u}`);
  }
  assert.ok(seen.some(u => new URL(u).searchParams.get('cat') === 'books' && new URL(u).searchParams.get('id') === "'"));
});

test('sql-errors: returns ERROR on all-failed network requests, invalid URL, or governance block', async () => {
  const bad = await run('not-a-url', mockFetch({ status: 200 }));
  assert.equal(bad.status, 'ERROR');

  const netErr = await run(BASE, mockFetchError('ECONNRESET'));
  assert.equal(netErr.status, 'ERROR');
  assert.match(netErr.reason, /ECONNRESET/);

  const govErr = new Error('Request blocked by SSRF policy');
  govErr.isGovernanceBlock = true;
  const govRes = await run(BASE, async () => { throw govErr; });
  assert.equal(govRes.status, 'ERROR');
  assert.match(govRes.reason, /SSRF policy/);
});
