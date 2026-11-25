import { test } from 'node:test';
import assert from 'node:assert/strict';
import { run as runSsti } from '../../checks/ssti-check.js';
import { run as runCachePoisoning } from '../../checks/cache-poisoning.js';
import { run as runHttpDesync } from '../../checks/http-desync-smuggling.js';
import { run as runBolaMassAssignment } from '../../checks/bola-mass-assignment.js';

test('ssti-check: detects server-side template arithmetic evaluation (7919*13=102947) and ignores raw reflection', async () => {
  // 1. Vulnerable Jinja2 template evaluating {{7919*13}} -> 102947
  const vulnRes = await runSsti('https://app.example.com/render?name=guest', async (url) => {
    const u = new URL(url);
    const name = u.searchParams.get('name') || '';
    if (name.includes('{{7919*13}}')) {
      return {
        status: 200,
        headers: { 'content-type': 'text/html' },
        text: '<html><body>Hello secscan102947ssti!</body></html>',
        trafficId: 'tr-ssti-1'
      };
    }
    return { status: 200, headers: { 'content-type': 'text/html' }, text: '<html><body>Hello guest!</body></html>' };
  });
  assert.equal(vulnRes.status, 'VULNERABLE');
  assert.equal(vulnRes.severity, 'CRITICAL');
  assert.ok(vulnRes.evidenceQuotes.includes('secscan102947ssti'));

  // 2. Safe target that merely reflects the un-evaluated literal "secscan{{7919*13}}ssti"
  const safeRes = await runSsti('https://app.example.com/render?name=guest', async (url) => ({
    status: 200,
    headers: { 'content-type': 'text/html' },
    text: `<html><body>Echo: ${decodeURIComponent(url)}</body></html>`
  }));
  assert.equal(safeRes.status, 'SAFE');
});

test('cache-poisoning: uses isolated ?secscan_cb= cache-buster and distinguishes confirmed cache persistence from unkeyed reflection', async () => {
  let poisonedCache = false;
  const vulnRes = await runCachePoisoning('https://cdn.example.com/', async (url, opts = {}) => {
    assert.ok(url.includes('secscan_cb='), 'Must include cache-buster query param');
    const xfh = opts.headers?.['X-Forwarded-Host'];
    if (xfh === 'secscan-cache-canary.invalid') {
      poisonedCache = true;
    }
    if (poisonedCache) {
      return {
        status: 200,
        headers: { 'content-type': 'text/html', 'x-cache': 'HIT' },
        text: '<script src="https://secscan-cache-canary.invalid/app.js"></script>'
      };
    }
    return { status: 200, headers: {}, text: '<html>Clean</html>' };
  });
  assert.equal(vulnRes.status, 'VULNERABLE');
  assert.equal(vulnRes.severity, 'HIGH');
  assert.equal(vulnRes.findings[0].persistedInCache, true);
});

test('http-desync-smuggling: detects upstream framing parser mismatch on multi-tier proxies and stays SAFE on standard servers', async () => {
  const suspRes = await runHttpDesync('https://proxy.example.com/', async (_url, opts = {}) => {
    if (opts.method === 'POST') {
      return {
        status: 502,
        headers: { via: '1.1 front-proxy' },
        text: 'Bad Gateway: conflicting Content-Length and Transfer-Encoding on upstream'
      };
    }
    return { status: 200, headers: { via: '1.1 front-proxy' }, text: 'OK' };
  });
  assert.equal(suspRes.status, 'SUSPICIOUS');
  assert.equal(suspRes.severity, 'HIGH');

  const safeRes = await runHttpDesync('https://direct.example.com/', async () => ({
    status: 200,
    headers: { server: 'nginx' },
    text: 'OK'
  }));
  assert.equal(safeRes.status, 'SAFE');
});

test('bola-mass-assignment: detects unauthenticated /api/users/1 PII & admin role leak while rejecting catch-all 200 responses', async () => {
  const vulnRes = await runBolaMassAssignment('https://api.example.com/', async (url) => {
    if (url.endsWith('/api/users/99999991')) {
      return { status: 404, headers: { 'content-type': 'application/json' }, text: '{"error":"Not found"}' };
    }
    if (url.endsWith('/api/users/1')) {
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        text: '{"id":1,"email":"ceo@example.com","role":"admin","isAdmin":true}'
      };
    }
    return { status: 404, headers: {}, text: '' };
  });
  assert.equal(vulnRes.status, 'VULNERABLE');
  assert.equal(vulnRes.severity, 'HIGH');
  assert.equal(vulnRes.findings[0].hasSensitivePii, true);
  assert.equal(vulnRes.findings[0].hasPrivilegeAttributes, true);
});
