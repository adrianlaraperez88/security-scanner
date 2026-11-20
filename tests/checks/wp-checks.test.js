import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mockFetch, mockFetchMap, mockFetchError } from '../helpers/mock-fetch.js';
import run from '../../checks/wp-checks.js';

const BASE = 'https://example.com';

test('wp-checks: detects xmlrpc.php, /wp-json/wp/v2/users, and real wp-login.php form', async () => {
  const fetch = mockFetchMap({
    '/xmlrpc.php': { status: 200, text: '<?xml version="1.0"?><methodResponse><params/></methodResponse>' },
    '/wp-json/wp/v2/users': { status: 200, headers: { 'content-type': 'application/json' }, text: '[{"id":1,"slug":"admin"}]' },
    '/wp-login.php': {
      status: 200,
      headers: { 'content-type': 'text/html' },
      text: '<html><body><form name="loginform" id="loginform"><input name="log" id="user_login"><input name="pwd"><input id="wp-submit"></form></body></html>'
    }
  });

  const r = await run(BASE, fetch);
  assert.equal(r.name, 'wordpress checks');
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'MEDIUM');
  assert.equal(r.findings.length, 3);
});

test('wp-checks: avoids FPs on generic SPA login page or HTML /wp-json/wp/v2/users fallback, handles undefined text', async () => {
  const spaCatchAll = await run(BASE, mockFetch({
    status: 200,
    headers: { 'content-type': 'text/html' },
    text: '<!doctype html><html><body><h1>Log in to our App</h1><p>"slug": "ignored-in-html"</p></body></html>'
  }));
  assert.equal(spaCatchAll.status, 'SAFE');

  const undefText = await run(BASE, mockFetch({ status: 200 }));
  assert.equal(undefText.status, 'SAFE');
});

test('wp-checks: normalizes query URL and returns ERROR on network failure or governance block', async () => {
  const seen = [];
  await run('https://example.com/blog?p=42', async (u) => {
    seen.push(u);
    return { status: 404, text: 'Not Found' };
  });
  assert.ok(seen.includes('https://example.com/xmlrpc.php'));
  assert.ok(seen.includes('https://example.com/wp-json/wp/v2/users'));
  assert.ok(seen.includes('https://example.com/wp-login.php'));

  const netErr = await run(BASE, mockFetchError('ECONNREFUSED'));
  assert.equal(netErr.status, 'ERROR');
  assert.match(netErr.reason, /ECONNREFUSED/);

  const govErr = new Error('Request blocked by SSRF policy');
  govErr.isGovernanceBlock = true;
  const govRes = await run(BASE, async () => { throw govErr; });
  assert.equal(govRes.status, 'ERROR');
  assert.match(govRes.reason, /SSRF policy/);
});
