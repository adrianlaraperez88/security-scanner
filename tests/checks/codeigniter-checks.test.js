import { test } from 'node:test';
import assert    from 'node:assert/strict';
import { mockFetch, mockFetchMap, mockFetchError } from '../helpers/mock-fetch.js';
import run from '../../checks/codeigniter-checks.js';

const BASE = 'https://example.com';

test('codeigniter-checks: SAFE when no CodeIgniter signals found', async () => {
  const r = await run(BASE, mockFetch({ status: 404, text: 'Not Found' }));
  assert.equal(r.status, 'SAFE');
  assert.equal(r.severity, 'NONE');
});

test('codeigniter-checks: HIGH when /application/logs/ returns directory listing', async () => {
  const fetch = mockFetchMap({
    '/application/logs/': {
      status: 200,
      text  : '<html>Index of /application/logs<br><a href="log-2025-04-21.php">log-2025-04-21.php</a></html>'
    }
  });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'HIGH');
});

test('codeigniter-checks: CRITICAL when CodeIgniter 4.5.x detected (< 4.6.2)', async () => {
  const fetch = mockFetchMap({
    '/index.php/welcome/index': {
      status: 200,
      text  : '<html>Welcome to CodeIgniter Version 4.5.7!</html>'
    }
  });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'CRITICAL');
  assert.ok(r.findings.some(f => f.cve === 'CVE-2025-54418'));
});

test('codeigniter-checks: SAFE when CodeIgniter 4.6.2 detected (patched)', async () => {
  const fetch = mockFetchMap({
    '/index.php/welcome/index': {
      status: 200,
      text  : '<html>Welcome to CodeIgniter Version 4.6.2!</html>'
    }
  });
  const r = await run(BASE, fetch);
  // Version 4.6.2 is patched — should not flag CVE-2025-54418
  const hasCVE = (r.findings ?? []).some(f => f.cve === 'CVE-2025-54418');
  assert.equal(hasCVE, false);
});

test('codeigniter-checks: ERROR when all requests throw', async () => {
  const r = await run(BASE, mockFetchError('ECONNREFUSED'));
  assert.equal(r.status, 'SAFE');
});
