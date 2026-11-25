import { test } from 'node:test';
import assert from 'node:assert/strict';
import { run as runDomXss } from '../../checks/dom-xss-sinks.js';
import { run as runXxe } from '../../checks/xxe-injection.js';
import { run as runCrlf } from '../../checks/crlf-header-injection.js';
import { run as runSsrfSurface } from '../../checks/ssrf-surface.js';

test('dom-xss-sinks: detects direct location.hash -> innerHTML sink and unverified postMessage listener', async () => {
  const vulnRes = await runDomXss('https://app.example.com/', async () => ({
    status: 200,
    headers: { 'content-type': 'text/html' },
    text: `
      <html><body><script>
        document.getElementById('out').innerHTML = location.hash.slice(1);
        window.addEventListener('message', (e) => {
          document.body.innerHTML = e.data;
        });
      </script></body></html>
    `
  }));
  assert.equal(vulnRes.status, 'VULNERABLE');
  assert.equal(vulnRes.severity, 'HIGH');
  assert.equal(vulnRes.findings.length, 2);

  const safeRes = await runDomXss('https://app.example.com/', async () => ({
    status: 200,
    headers: { 'content-type': 'text/html' },
    text: '<html><body><script>console.log("safe");</script></body></html>'
  }));
  assert.equal(safeRes.status, 'SAFE');
});

test('xxe-injection: detects DOCTYPE entity expansion (secscan_xxe_eval_9412) and ignores raw XML echo', async () => {
  const vulnRes = await runXxe('https://api.example.com/xml', async (_url, opts = {}) => {
    if (opts.body && opts.body.includes('<!ENTITY secscanxxe')) {
      return {
        status: 200,
        headers: { 'content-type': 'application/xml' },
        text: '<response><result>secscan_xxe_eval_9412</result></response>'
      };
    }
    return { status: 200, headers: {}, text: '' };
  });
  assert.equal(vulnRes.status, 'VULNERABLE');
  assert.equal(vulnRes.severity, 'HIGH');
  assert.ok(vulnRes.evidenceQuotes.includes('secscan_xxe_eval_9412'));

  // Raw reflection of the XML request body must NOT trigger a false positive
  const echoRes = await runXxe('https://api.example.com/xml', async (_url, opts = {}) => ({
    status: 200,
    headers: { 'content-type': 'text/plain' },
    text: `Received: ${opts.body}`
  }));
  assert.equal(echoRes.status, 'SAFE');
});

test('crlf-header-injection: detects injected X-SecScan-Crlf response header and ignores body reflection', async () => {
  const vulnRes = await runCrlf('https://app.example.com/go', async () => ({
    status: 302,
    headers: {
      location: '/',
      'x-secscan-crlf': 'crlf9812injected'
    },
    text: ''
  }));
  assert.equal(vulnRes.status, 'VULNERABLE');
  assert.equal(vulnRes.severity, 'HIGH');

  // Mere body reflection of crlf9812injected without actual response header must be SAFE
  const bodyOnlyRes = await runCrlf('https://app.example.com/go', async (url) => ({
    status: 200,
    headers: { 'content-type': 'text/html' },
    text: `Redirecting to ${decodeURIComponent(url)}`
  }));
  assert.equal(bodyOnlyRes.status, 'SAFE');
});

test('ssrf-surface: detects backend URL-fetcher exception referencing secscan-ssrf-probe.invalid', async () => {
  const vulnRes = await runSsrfSurface('https://api.example.com/fetch?url=https://example.com', async (url) => {
    if (url.includes('secscan-ssrf-probe.invalid')) {
      return {
        status: 500,
        headers: { 'content-type': 'text/plain' },
        text: 'Error: getaddrinfo ENOTFOUND secscan-ssrf-probe.invalid'
      };
    }
    return { status: 200, headers: {}, text: 'ok' };
  });
  assert.equal(vulnRes.status, 'VULNERABLE');
  assert.equal(vulnRes.severity, 'HIGH');
  assert.ok(vulnRes.evidenceQuotes[0].includes('secscan-ssrf-probe.invalid'));
});
