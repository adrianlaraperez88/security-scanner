import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mockFetch, mockFetchMap, mockFetchError } from '../helpers/mock-fetch.js';
import run from '../../checks/sensitive-files.js';

const BASE = 'https://example.com';

test('sensitive-files: detects /.DS_Store with Bud1 magic bytes, /composer.lock, and /.git/config', async () => {
  const fetch = mockFetchMap({
    '/.DS_Store': { status: 200, text: '\x00\x00\x00\x01Bud1\x00\x00\x10\x00' },
    '/composer.lock': { status: 200, text: '{"packages":[{"name":"laravel/framework","version":"v10.0.0","dist":{}}]}' },
    '/.git/config': { status: 200, text: '[core]\n\trepositoryformatversion = 0\n[remote "origin"]' }
  });

  const r = await run(BASE, fetch);
  assert.equal(r.name, 'sensitive files');
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'HIGH');
  assert.ok(r.files.some(f => f.path === '/.DS_Store'));
  assert.ok(r.files.some(f => f.path === '/composer.lock'));
  assert.ok(r.files.some(f => f.path === '/.git/config'));
});

test('sensitive-files: avoids FPs on catch-all 200 HTML for /.DS_Store and /.htaccess, and handles undefined text', async () => {
  const catchAllHtml = await run(BASE, mockFetch({
    status: 200,
    headers: { 'content-type': 'text/html' },
    text: '<!doctype html><html><body>Options and RewriteRule guide — Bud1</body></html>'
  }));
  assert.equal(catchAllHtml.status, 'SAFE');

  const nonBud1DsStore = await run(BASE, mockFetchMap({
    '/.DS_Store': { status: 200, text: 'plain text fallback page without magic header' }
  }));
  assert.equal(nonBud1DsStore.status, 'SAFE');

  const undefText = await run(BASE, mockFetch({ status: 200 }));
  assert.equal(undefText.status, 'SAFE');
});

test('sensitive-files: normalizes query URL and returns ERROR on total failure or governance block', async () => {
  const seen = [];
  await run('https://example.com/sub?a=1', async (u) => {
    seen.push(u);
    return { status: 404, text: 'Not Found' };
  });
  assert.ok(seen.every(u => !u.includes('?a=1')));
  assert.ok(seen.includes('https://example.com/.DS_Store'));

  const netErr = await run(BASE, mockFetchError('ECONNREFUSED'));
  assert.equal(netErr.status, 'ERROR');
  assert.match(netErr.reason, /ECONNREFUSED/);

  const govErr = new Error('Request blocked by SSRF policy');
  govErr.isGovernanceBlock = true;
  const govRes = await run(BASE, async () => { throw govErr; });
  assert.equal(govRes.status, 'ERROR');
  assert.match(govRes.reason, /SSRF policy/);
});

test('sensitive-files: prevents generic JSON/JS/SPA fallback false positives and skips transient non-reproducible hits', async () => {
  const jsonFallback = await run(BASE, mockFetch({
    status: 200,
    headers: { 'content-type': 'application/json' },
    text: '{"name":"web-app","version":"1.2.3","Options":"default"}'
  }));
  assert.equal(jsonFallback.status, 'SAFE');

  const spaHtmlWithoutHeader = await run(BASE, mockFetch({
    status: 200,
    headers: { 'content-type': 'text/plain' },
    text: '<app-root ng-version="19.0"></app-root><script src="/main.js"></script><div class="require">Options RewriteRule</div>'
  }));
  assert.equal(spaHtmlWithoutHeader.status, 'SAFE');

  let calls = 0;
  const transientHit = await run(BASE, async (u) => {
    if (u.endsWith('/.htaccess')) {
      calls++;
      if (calls === 1) return { status: 200, text: 'RewriteEngine On\nRewriteRule ^admin$ /403 [F]\n' };
      return { status: 404, text: 'Not Found' };
    }
    return { status: 404, text: 'Not Found' };
  });
  assert.equal(transientHit.status, 'SAFE');
});

test('sensitive-files: includes exact reproducible path, detail, files[], findings[], evidenceQuotes, and poeLevel on real exposures', async () => {
  const fetch = mockFetchMap({
    '/.htaccess': {
      status: 200,
      headers: { 'content-type': 'text/plain' },
      text: 'RewriteEngine On\nRewriteRule ^legacy/(.*)$ /v2/$1 [R=301,L]\nOptions -Indexes\n',
      trafficId: 'tx-ht-1'
    },
    '/composer.json': {
      status: 200,
      headers: { 'content-type': 'application/json' },
      text: JSON.stringify({ name: 'acme/portal', require: { php: '^8.2' } })
    }
  });

  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.reproVerified, true);
  assert.equal(r.path, '/composer.json');
  assert.match(r.detail, /\/composer\.json/);
  assert.match(r.detail, /\/\.htaccess/);
  assert.equal(r.files.length, 2);
  assert.equal(r.findings.length, 2);
  assert.ok(Array.isArray(r.evidenceQuotes) && r.evidenceQuotes.length >= 1);
  assert.equal(r.poeLevel, 3);
  assert.equal(r.trafficId, 'tx-ht-1');
});
