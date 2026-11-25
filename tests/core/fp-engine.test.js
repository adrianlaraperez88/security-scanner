import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import {
  SOFT_404_MARKERS,
  computeStructuralSimilarity,
  isSoft404Response,
  verifyDifferentialProbe,
  ensureVerbatimEvidenceQuotes,
  classifyFindingConfidence
} from '../../core/fp-engine.js';
import {
  computeStructuralSimilarity as reExportedComputeStructuralSimilarity,
  isSoft404Response as reExportedIsSoft404Response,
  verifyDifferentialProbe as reExportedVerifyDifferentialProbe,
  ensureVerbatimEvidenceQuotes as reExportedEnsureVerbatimEvidenceQuotes,
  classifyFindingConfidence as reExportedClassifyFindingConfidence,
  verifyFindingBeforeReport
} from '../../core/check-verify.js';
import runCve20244577 from '../../checks/cve-2024-4577.js';
import runCveTomcat from '../../checks/cve-tomcat.js';

describe('FP Engine re-exports from core/check-verify.js', () => {
  test('re-exports all core FP engine helpers identically', () => {
    assert.equal(reExportedComputeStructuralSimilarity, computeStructuralSimilarity);
    assert.equal(reExportedIsSoft404Response, isSoft404Response);
    assert.equal(reExportedVerifyDifferentialProbe, verifyDifferentialProbe);
    assert.equal(reExportedEnsureVerbatimEvidenceQuotes, ensureVerbatimEvidenceQuotes);
    assert.equal(reExportedClassifyFindingConfidence, classifyFindingConfidence);
    assert.ok(Array.isArray(SOFT_404_MARKERS) && SOFT_404_MARKERS.length > 0);
  });
});

describe('computeStructuralSimilarity', () => {
  test('returns 1 for identical strings and empty strings, and 0 for empty vs non-empty', () => {
    assert.equal(computeStructuralSimilarity('<html><body><h1>Hello World</h1></body></html>', '<html><body><h1>Hello World</h1></body></html>'), 1);
    assert.equal(computeStructuralSimilarity('', ''), 1);
    assert.equal(computeStructuralSimilarity('   \n\t  ', ''), 1);
    assert.equal(computeStructuralSimilarity(null, undefined), 1);
    assert.equal(computeStructuralSimilarity('', '<html><body>Hello</body></html>'), 0);
    assert.equal(computeStructuralSimilarity('<html><body>Hello</body></html>', ''), 0);
  });

  test('returns >= 0.82 for structurally near-identical HTML pages differing only in dynamic path/timestamp', () => {
    const template = (reqPath, ts) => `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Application Portal</title>
  <link rel="stylesheet" href="/static/app.bundle.css">
</head>
<body>
  <header class="site-header">
    <nav class="main-nav">
      <a href="/">Home</a>
      <a href="/docs">Documentation</a>
      <a href="/support">Support</a>
      <a href="/status">System Status</a>
    </nav>
  </header>
  <main class="error-shell">
    <section class="notice-card">
      <h1>Resource Unavailable</h1>
      <p>The requested route could not be located on this application server. Please verify the address or return to the main dashboard to continue browsing available workspace resources.</p>
      <p class="meta">Requested path: ${reqPath}</p>
      <p class="timestamp">Generated at: ${ts}</p>
    </section>
  </main>
  <footer class="site-footer">
    <span>Acme Platform Services Inc. All rights reserved.</span>
  </footer>
</body>
</html>`;

    const pageA = template('/admin-panel-alpha-111', '2026-11-23T10:00:01Z');
    const pageB = template('/nonexistent-probe-999', '2026-11-23T10:04:59Z');
    const similarity = computeStructuralSimilarity(pageA, pageB);

    assert.ok(similarity >= 0.82, `Expected similarity >= 0.82, got ${similarity}`);
    assert.ok(similarity <= 1, `Expected similarity <= 1, got ${similarity}`);
    assert.equal(similarity, computeStructuralSimilarity(pageB, pageA));
  });

  test('returns < 0.4 for completely different pages (Admin Dashboard table vs 404 Not Found page)', () => {
    const adminDashboard = `<!DOCTYPE html>
<html>
<head><title>Internal Admin Dashboard</title></head>
<body>
  <aside class="sidebar"><ul><li>Users</li><li>Billing</li><li>API Keys</li><li>Audit Logs</li></ul></aside>
  <main>
    <h1>User Management Console</h1>
    <table id="users-table">
      <thead><tr><th>ID</th><th>Email</th><th>Role</th><th>Last Login</th><th>MFA</th></tr></thead>
      <tbody>
        <tr><td>1001</td><td>alice@corp.internal</td><td>SuperAdmin</td><td>2026-11-23</td><td>Enabled</td></tr>
        <tr><td>1002</td><td>bob@corp.internal</td><td>Operator</td><td>2026-11-22</td><td>Enabled</td></tr>
        <tr><td>1003</td><td>carol@corp.internal</td><td>Auditor</td><td>2026-11-21</td><td>Disabled</td></tr>
      </tbody>
    </table>
    <form method="POST" action="/admin/users/export"><button type="submit">Export CSV</button></form>
  </main>
</body>
</html>`;

    const notFoundPage = `<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
  <div class="error-box">
    <h1>404</h1>
    <p>Sorry, the page you are looking for does not exist or has been moved.</p>
    <a href="/">Go back home</a>
  </div>
</body>
</html>`;

    const similarity = computeStructuralSimilarity(adminDashboard, notFoundPage);
    assert.ok(similarity < 0.4, `Expected similarity < 0.4, got ${similarity}`);
    assert.ok(similarity >= 0, `Expected similarity >= 0, got ${similarity}`);
  });

  test('handles oversized strings (> 100,000 chars) safely in < 50ms', () => {
    // Warm up JIT on small inputs first so timing reflects bounded linear algorithm cost
    computeStructuralSimilarity('<div>warmup alpha beta gamma</div>', '<div>warmup alpha beta delta</div>');

    const chunkA = '<div class="row"><span>alpha beta gamma delta epsilon zeta</span></div>';
    const chunkB = '<div class="row"><span>alpha beta gamma delta epsilon theta</span></div>';
    const bigA = chunkA.repeat(2000); // ~142,000 chars
    const bigB = chunkB.repeat(2000); // ~142,000 chars

    assert.ok(bigA.length > 100000);
    assert.ok(bigB.length > 100000);

    const t0 = performance.now();
    const score = computeStructuralSimilarity(bigA, bigB);
    const elapsedMs = performance.now() - t0;

    assert.ok(Number.isFinite(score) && score >= 0 && score <= 1);
    assert.ok(elapsedMs < 50, `Expected oversized similarity computation in < 50ms, took ${elapsedMs.toFixed(2)}ms`);
  });
});

describe('isSoft404Response', () => {
  test('detects Next.js soft-404 HTML with status 200', () => {
    const nextSoft404 = {
      status: 200,
      text: '<!DOCTYPE html><html><head><title>404: This page could not be found</title></head><body><div><h1 class="next-error-h1">404</h1><h2>This page could not be found.</h2></div></body></html>'
    };
    assert.equal(isSoft404Response(nextSoft404), true);

    const nextMarkerOnly = {
      status: 200,
      text: '<html><body><h1 class="next-error-h1">404</h1><h2>This page could not be found.</h2></body></html>'
    };
    assert.equal(isSoft404Response(nextMarkerOnly), true);

    const nextTitleOnly = {
      status: 200,
      text: '<html><head><title>404: This page could not be found</title></head><body>Missing</body></html>'
    };
    assert.equal(isSoft404Response(nextTitleOnly), true);
  });

  test('detects JSON soft-404 with status 200', () => {
    const jsonSoft404 = {
      status: 200,
      text: '{"statusCode":404,"message":"Cannot GET /admin","error":"Not Found"}'
    };
    assert.equal(isSoft404Response(jsonSoft404), true);
  });

  test('detects custom SPA soft-404 via structural similarity (>= 0.82) against baseline404Res', () => {
    const buildSpaShell = (route) => `<!DOCTYPE html>
<html>
<head><title>My Custom SPA</title><script src="/assets/index.js"></script></head>
<body>
  <div id="app">
    <header><nav><a href="/">Home</a><a href="/pricing">Pricing</a><a href="/about">About</a></nav></header>
    <main class="fallback-view">
      <h2>Nothing to see here</h2>
      <p>We could not match the requested workspace route in the client router. Use the navigation bar above to continue.</p>
      <span data-route="${route}">Route state initialized</span>
    </main>
  </div>
</body>
</html>`;

    const baseline404Res = { status: 200, text: buildSpaShell('/__nonexistent_baseline_9f8a7b') };
    const probedRes = { status: 200, text: buildSpaShell('/admin/settings') };

    assert.equal(isSoft404Response(probedRes), false);
    assert.equal(isSoft404Response(probedRes, baseline404Res), true);
    assert.equal(isSoft404Response(probedRes, baseline404Res, { similarityThreshold: 0.999 }), false);
  });

  test('returns false for genuine 200 responses and invalid inputs', () => {
    const genuineAdmin = {
      status: 200,
      text: '<html><body><h1>Internal Admin Dashboard</h1></body></html>'
    };
    const baseline404Res = {
      status: 404,
      text: '<html><head><title>Error</title></head><body><div class="err"><p>Requested path does not exist on this server. Return to homepage.</p></div></body></html>'
    };

    assert.equal(isSoft404Response(genuineAdmin), false);
    assert.equal(isSoft404Response(genuineAdmin, baseline404Res), false);
    assert.equal(isSoft404Response(null), false);
    assert.equal(isSoft404Response(undefined), false);
  });
});

describe('verifyDifferentialProbe', () => {
  const adminValidator = (res) =>
    res.status === 200 && /internal admin dashboard|uid=0\(root\)|secret_key/i.test(res.text || '');

  test('passes (confirmed: true) when attackRes matches validator, controlRes does not, and attackRes is not soft-404', () => {
    const baselineRes = {
      status: 200,
      text: '<html><body><div class="err"><h1>Oops</h1><p>Page missing from application router.</p></div></body></html>'
    };
    const controlRes = {
      status: 403,
      text: '<html><body><h1>403 Forbidden</h1><p>Access denied to protected resource.</p></body></html>'
    };
    const attackRes = {
      status: 200,
      text: '<html><body><h1>Internal Admin Dashboard</h1><table><tr><td>uid=0(root)</td></tr></table></body></html>'
    };

    const result = verifyDifferentialProbe({
      baselineRes,
      attackRes,
      controlRes,
      validator: adminValidator
    });

    assert.equal(result.confirmed, true);
    assert.match(result.reason, /passed/i);
  });

  test('passes (confirmed: true) when controlRes matches validator but has low structural similarity to attackRes', () => {
    const validator = (res) => res.status === 200 && res.text.includes('token');
    const controlRes = {
      status: 200,
      text: '<html><body><p>Public login form token=public_csrf_123</p></body></html>'
    };
    const attackRes = {
      status: 200,
      text: '{"users":[{"id":1,"email":"admin@corp.local","role":"superadmin"}],"debug":{"token":"leaked_admin_jwt","db":"postgres://prod:5432/core"}}'
    };

    assert.equal(validator(controlRes), true);
    assert.equal(validator(attackRes), true);
    assert.ok(computeStructuralSimilarity(attackRes.text, controlRes.text) < 0.85);

    const result = verifyDifferentialProbe({
      attackRes,
      controlRes,
      validator
    });

    assert.equal(result.confirmed, true);
  });

  test('rejects (confirmed: false) when controlRes also matches validator with high structural similarity (>= 0.85)', () => {
    const sharedBody = (id) => `<!DOCTYPE html>
<html>
<head><title>App Shell</title></head>
<body>
  <header><nav><a href="/">Home</a><a href="/about">About</a><a href="/contact">Contact</a></nav></header>
  <main>
    <h1>Internal Admin Dashboard</h1>
    <p>Welcome to the standard cached marketing page rendered identically for every request path regardless of headers.</p>
    <span class="req-id">${id}</span>
  </main>
</body>
</html>`;

    const attackRes = { status: 200, text: sharedBody('req-attack-001') };
    const controlRes = { status: 200, text: sharedBody('req-control-002') };

    const result = verifyDifferentialProbe({
      attackRes,
      controlRes,
      validator: adminValidator
    });

    assert.equal(result.confirmed, false);
    assert.match(result.reason, /negative control/i);
  });

  test('rejects (confirmed: false) when attackRes matches soft-404 baseline', () => {
    const soft404Template = (path) => `<!DOCTYPE html>
<html>
<head><title>Portal Fallback</title></head>
<body>
  <div class="wrapper">
    <h1>Page Missing</h1>
    <p>The server could not find the document you requested. Please check the URL or visit our documentation portal.</p>
    <code>${path}</code>
  </div>
</body>
</html>`;

    const baselineRes = { status: 200, text: soft404Template('/__random_not_found_42') };
    const attackRes = { status: 200, text: soft404Template('/admin/secret') };

    const result = verifyDifferentialProbe({
      baselineRes,
      attackRes,
      controlRes: { status: 403, text: 'Forbidden' },
      validator: (res) => res.status === 200
    });

    assert.equal(result.confirmed, false);
    assert.match(result.reason, /soft-404/i);
  });

  test('rejects (confirmed: false) when attackRes fails validator or validator is missing', () => {
    const noMatch = verifyDifferentialProbe({
      attackRes: { status: 404, text: 'Not Found' },
      validator: adminValidator
    });
    assert.equal(noMatch.confirmed, false);

    const noValidator = verifyDifferentialProbe({
      attackRes: { status: 200, text: 'Internal Admin Dashboard' }
    });
    assert.equal(noValidator.confirmed, false);
  });
});

describe('ensureVerbatimEvidenceQuotes', () => {
  test('preserves verbatim quotes that already exist in captured HTTP traces', () => {
    const traces = [
      {
        trafficId: 'tr-101',
        url: 'https://target.example.com/.env',
        status: 200,
        responseHeaders: { 'content-type': 'text/plain', server: 'nginx/1.24.0' },
        responseSnippet: 'APP_ENV=production\nDB_PASSWORD=supersecret\nAPP_KEY=base64:abcdef123456'
      }
    ];

    const finding = {
      checkId: 'env',
      trafficId: 'tr-101',
      url: 'https://target.example.com/.env',
      status: 'VULNERABLE',
      evidenceQuotes: ['DB_PASSWORD=supersecret', 'APP_ENV=production']
    };

    const result = ensureVerbatimEvidenceQuotes(finding, traces);
    assert.deepEqual(result.evidenceQuotes, ['DB_PASSWORD=supersecret', 'APP_ENV=production']);
    assert.equal(result, finding);
  });

  test('augments synthetic human prose quotes with a real verbatim responseSnippet substring from capturedTraces', () => {
    const traces = [
      {
        trafficId: 'tr-202',
        url: 'https://target.example.com/cgi-bin/php',
        status: 200,
        responseHeaders: { 'content-type': 'application/octet-stream', 'x-powered-by': 'PHP/8.1.2' },
        responseSnippet: 'X-Powered-By: PHP/8.1.2\n<?php phpinfo(); ?>\nroot:x:0:0:root:/root:/bin/bash'
      }
    ];

    const finding = {
      checkId: 'php-cgi-exposure',
      trafficId: 'tr-202',
      url: 'https://target.example.com/cgi-bin/php',
      status: 'VULNERABLE',
      evidenceQuotes: ['HTTP 200 non-HTML response on /cgi-bin/php']
    };

    const result = ensureVerbatimEvidenceQuotes(finding, traces);
    assert.notEqual(result, finding);
    // Original quote preserved and real verbatim snippet appended
    assert.equal(result.evidenceQuotes.length, 2);
    assert.equal(result.evidenceQuotes[0], 'HTTP 200 non-HTML response on /cgi-bin/php');
    assert.ok(result.evidenceQuotes[1].length >= 8);
    assert.ok(
      result.evidenceQuotes[1].includes('X-Powered-By: PHP/8.1.2') ||
      result.evidenceQuotes[1].includes('phpinfo()'),
      `Expected verbatim trace snippet, got: ${result.evidenceQuotes[1]}`
    );
    // Original finding object is not mutated
    assert.equal(finding.evidenceQuotes.length, 1);
  });

  test('falls back to real verbatim non-noise response headers when responseSnippet is empty', () => {
    const traces = [
      {
        url: 'https://target.example.com/admin',
        status: 200,
        responseHeaders: {
          host: 'target.example.com',
          authorization: '<REDACTED>',
          'x-nextjs-matched-path': '/admin/dashboard'
        },
        responseSnippet: ''
      }
    ];

    const finding = {
      checkId: 'cve-nextjs-react',
      reproduction: { url: 'https://target.example.com/admin' },
      status: 'VULNERABLE',
      evidenceQuotes: ['x-middleware-subrequest bypassed auth on /admin']
    };

    const result = ensureVerbatimEvidenceQuotes(finding, traces);
    assert.equal(result.evidenceQuotes.length, 2);
    assert.equal(result.evidenceQuotes[1], 'x-nextjs-matched-path: /admin/dashboard');
  });
});

describe('classifyFindingConfidence & verifyFindingBeforeReport', () => {
  test('classifies VULNERABLE with poeLevel >= 3 and verbatim quotes as CONFIRMED_EXPLOITABLE with score >= 90', () => {
    const activeFinding = {
      checkId: 'sqli',
      name: 'SQL Injection',
      status: 'VULNERABLE',
      severity: 'CRITICAL',
      poeLevel: 3,
      detail: 'SQLi confirmed via error-based injection',
      evidenceQuotes: ['You have an error in your SQL syntax near']
    };
    const activeSnapshot = structuredClone(activeFinding);
    const activeConf = classifyFindingConfidence(activeFinding);

    assert.equal(activeConf.confidenceTier, 'CONFIRMED_EXPLOITABLE');
    assert.ok(activeConf.confidenceScore >= 90, `Expected score >= 90, got ${activeConf.confidenceScore}`);
    assert.equal(activeConf.confidenceScore, 95);
    assert.deepEqual(activeFinding, activeSnapshot);

    const passiveVersionFinding = {
      checkId: 'cve-apache-httpd',
      name: 'Apache HTTPd Advisory',
      status: 'VULNERABLE',
      severity: 'HIGH',
      poeLevel: 3,
      detail: 'Banner version Apache/2.4.49 is within range of CVE-2021-41773',
      evidenceQuotes: ['Server: Apache/2.4.49 (Unix)']
    };
    const passiveConf = classifyFindingConfidence(passiveVersionFinding);
    assert.equal(passiveConf.confidenceTier, 'CONFIRMED_EXPLOITABLE');
    assert.equal(passiveConf.confidenceScore, 90);
  });

  test('classifies VULNERABLE without poeLevel >= 3 as VERSION_ATTRIBUTED (score 82)', () => {
    const res = classifyFindingConfidence({
      checkId: 'cve-node-express',
      status: 'VULNERABLE',
      poeLevel: 2,
      evidenceQuotes: ['X-Powered-By: Express']
    });
    assert.equal(res.confidenceTier, 'VERSION_ATTRIBUTED');
    assert.equal(res.confidenceScore, 82);
  });

  test('classifies SUSPICIOUS distro-backport / semver-range findings as HEURISTIC_ADVISORY (score 55)', () => {
    const backportFinding = {
      checkId: 'os-security',
      status: 'SUSPICIOUS',
      severity: 'MEDIUM',
      detail: 'OpenSSL 1.1.1f may include Ubuntu distro backport security patches'
    };
    assert.deepEqual(classifyFindingConfidence(backportFinding), {
      confidenceTier: 'HEURISTIC_ADVISORY',
      confidenceScore: 55
    });

    const semverRangeFinding = {
      checkId: 'cve-node-express',
      status: 'SUSPICIOUS',
      severity: 'MEDIUM',
      detail: 'Dependency uses semver ranges (^4.17.0) in package.json constraints'
    };
    assert.deepEqual(classifyFindingConfidence(semverRangeFinding), {
      confidenceTier: 'HEURISTIC_ADVISORY',
      confidenceScore: 55
    });

    const nonHeuristicSuspicious = {
      checkId: 'cve-nginx-tls',
      status: 'SUSPICIOUS',
      severity: 'LOW',
      detail: 'Detected nginx 1.24.0 on TLS listener'
    };
    assert.deepEqual(classifyFindingConfidence(nonHeuristicSuspicious), {
      confidenceTier: 'VERSION_ATTRIBUTED',
      confidenceScore: 70
    });
  });

  test('classifies SAFE findings as INFORMATIONAL (score 100)', () => {
    assert.deepEqual(
      classifyFindingConfidence({ checkId: 'env', status: 'SAFE', severity: 'NONE' }),
      { confidenceTier: 'INFORMATIONAL', confidenceScore: 100 }
    );
  });

  test('verifyFindingBeforeReport attaches confidenceTier and confidenceScore automatically', () => {
    const traces = [
      {
        trafficId: 'tr-303',
        url: 'https://target.example.com/cgi-bin/php',
        status: 200,
        responseHeaders: { 'content-type': 'text/plain' },
        responseSnippet: 'PHP Version 8.1.2 - System Linux web01'
      }
    ];

    const verified = verifyFindingBeforeReport({
      checkId: 'php-cgi-exposure',
      trafficId: 'tr-303',
      url: 'https://target.example.com/cgi-bin/php',
      status: 'VULNERABLE',
      severity: 'HIGH',
      poeLevel: 3,
      evidenceQuotes: ['HTTP 200 non-HTML response on /cgi-bin/php']
    }, { capturedTraces: traces });

    assert.equal(verified.status, 'VULNERABLE');
    assert.equal(verified.confidenceTier, 'CONFIRMED_EXPLOITABLE');
    assert.ok(verified.confidenceScore >= 90);
    assert.ok(
      verified.evidenceQuotes.some(q => q.includes('PHP Version 8.1.2')),
      'Expected verifyFindingBeforeReport to augment synthetic quote from capturedTraces'
    );

    const safeOut = verifyFindingBeforeReport({
      checkId: 'env',
      status: 'SAFE',
      severity: 'NONE'
    });
    assert.equal(safeOut.confidenceTier, 'INFORMATIONAL');
    assert.equal(safeOut.confidenceScore, 100);
  });

  test('verifyFindingBeforeReport resets confidenceTier to INFORMATIONAL and confidenceScore to 100 when downgrading a 404 FP to SAFE', () => {
    const downgradedByStatus = verifyFindingBeforeReport({
      checkId: 'env',
      name: 'Exposed .env',
      status: 'VULNERABLE',
      severity: 'CRITICAL',
      poeLevel: 3,
      confidenceTier: 'CONFIRMED_EXPLOITABLE',
      confidenceScore: 95,
      url: 'https://target.example.com/.env',
      observedStatus: 404,
      evidenceQuotes: ['DB_PASSWORD=fake']
    });

    assert.equal(downgradedByStatus.status, 'SAFE');
    assert.equal(downgradedByStatus.severity, 'NONE');
    assert.equal(downgradedByStatus.confidenceTier, 'INFORMATIONAL');
    assert.equal(downgradedByStatus.confidenceScore, 100);

    const downgradedByTrace = verifyFindingBeforeReport({
      checkId: 'sensitive-files',
      name: 'Sensitive Config',
      status: 'VULNERABLE',
      severity: 'HIGH',
      poeLevel: 3,
      confidenceTier: 'CONFIRMED_EXPLOITABLE',
      confidenceScore: 95,
      trafficId: 'tr-404',
      url: 'https://target.example.com/config.yml',
      evidenceQuotes: ['secret: value']
    }, {
      capturedTraces: [
        {
          trafficId: 'tr-404',
          url: 'https://target.example.com/config.yml',
          status: 404,
          responseSnippet: 'Not Found'
        }
      ]
    });

    assert.equal(downgradedByTrace.status, 'SAFE');
    assert.equal(downgradedByTrace.confidenceTier, 'INFORMATIONAL');
    assert.equal(downgradedByTrace.confidenceScore, 100);
  });
});

describe('Step 2D Security Remediation Regression Tests (FINDING-6, FINDING-7a, FINDING-8)', () => {
  test('FINDING-6: cve-2024-4577 ignores reflected query-string echoes and still detects real PHP-CGI RCE', async () => {
    // 1. Server echoes req.url/query string containing allow_url_include -> must NOT report VULNERABLE
    const rawEchoFetch = async (url) => {
      if (url.includes('/cgi-bin/php-cgi.exe')) {
        return {
          status: 200,
          headers: { 'content-type': 'text/plain' },
          text: `Echoed URI: ${url.replace(/^https?:\/\/[^/]+/, '')}`
        };
      }
      return { status: 404, headers: {}, text: 'Not Found' };
    };
    const rawEchoRes = await runCve20244577('https://example.com', rawEchoFetch);
    assert.notEqual(rawEchoRes.status, 'VULNERABLE', 'Reflected raw injection query must not trigger VULNERABLE');

    // 2. Server echoes URL-decoded query string (-d allow_url_include=1 -d safe_mode=0 -n) -> must NOT report VULNERABLE
    const decodedEchoFetch = async (url) => {
      if (url.includes('/cgi-bin/php-cgi.exe?')) {
        return {
          status: 200,
          headers: { 'content-type': 'text/plain' },
          text: 'Debug query: -d allow_url_include=1 -d safe_mode=0 -n'
        };
      }
      if (url.endsWith('/cgi-bin/php-cgi.exe')) {
        return { status: 200, headers: { 'content-type': 'text/plain' }, text: 'plain page' };
      }
      return { status: 404, headers: {}, text: 'Not Found' };
    };
    const decodedEchoRes = await runCve20244577('https://example.com', decodedEchoFetch);
    assert.notEqual(decodedEchoRes.status, 'VULNERABLE', 'Reflected decoded injection query must not trigger VULNERABLE');

    // 3. Real PHP-CGI execution output still triggers VULNERABLE / CRITICAL
    const realRceFetch = async (url) => {
      if (url.includes('/cgi-bin/php-cgi.exe')) {
        return {
          status: 200,
          headers: { 'content-type': 'text/html' },
          text: 'Content-type: text/html\nallow_url_include => On\nallow_url_include=1'
        };
      }
      return { status: 404, headers: {}, text: 'Not Found' };
    };
    const realRceRes = await runCve20244577('https://example.com', realRceFetch);
    assert.equal(realRceRes.status, 'VULNERABLE');
    assert.equal(realRceRes.severity, 'CRITICAL');
  });

  test('FINDING-7a: classifyFindingConfidence enforces quote length >= 8, non-synthetic text, non-rejected status, and trace match', () => {
    // Rejects synthetic prose quotes
    const syntheticRes = classifyFindingConfidence({
      status: 'VULNERABLE',
      poeLevel: 3,
      evidenceQuotes: ['x-middleware-subrequest bypassed HTTP 403 -> HTTP 200 on /admin']
    });
    assert.equal(syntheticRes.confidenceTier, 'VERSION_ATTRIBUTED');
    assert.equal(syntheticRes.confidenceScore, 82);

    // Rejects short (< 8 chars) quotes
    const shortRes = classifyFindingConfidence({
      status: 'VULNERABLE',
      poeLevel: 3,
      evidenceQuotes: ['  abc  ', '1234567']
    });
    assert.equal(shortRes.confidenceTier, 'VERSION_ATTRIBUTED');
    assert.equal(shortRes.confidenceScore, 82);

    // Rejects when verificationStatus === 'rejected'
    const rejectedRes = classifyFindingConfidence({
      status: 'VULNERABLE',
      poeLevel: 3,
      verificationStatus: 'rejected',
      evidenceQuotes: ['SQLSTATE[42000]: Syntax error near line 1']
    });
    assert.equal(rejectedRes.confidenceTier, 'VERSION_ATTRIBUTED');
    assert.equal(rejectedRes.confidenceScore, 82);

    // Rejects when capturedTraces are provided and quote only appears in a non-triggering trace
    const crossTraceRes = classifyFindingConfidence(
      {
        status: 'VULNERABLE',
        poeLevel: 3,
        trafficId: 'tx-trigger',
        url: 'https://example.com/admin',
        evidenceQuotes: ['ONLY_IN_BASELINE_TRACE_987654']
      },
      {
        capturedTraces: [
          {
            trafficId: 'tx-baseline',
            url: 'https://example.com/',
            status: 200,
            responseSnippet: 'ONLY_IN_BASELINE_TRACE_987654'
          },
          {
            trafficId: 'tx-trigger',
            url: 'https://example.com/admin',
            status: 200,
            responseSnippet: 'Generic admin landing page'
          }
        ]
      }
    );
    assert.equal(crossTraceRes.confidenceTier, 'VERSION_ATTRIBUTED');
    assert.equal(crossTraceRes.confidenceScore, 82);

    // Confirms when quote is >= 8 chars, non-synthetic, not rejected, and verbatim in matched trace
    const validTraceRes = classifyFindingConfidence(
      {
        status: 'VULNERABLE',
        poeLevel: 3,
        trafficId: 'tx-trigger',
        url: 'https://example.com/admin',
        evidenceQuotes: ['Internal Admin Secret Panel']
      },
      {
        capturedTraces: [
          {
            trafficId: 'tx-trigger',
            url: 'https://example.com/admin',
            status: 200,
            responseSnippet: '<html><body><h1>Internal Admin Secret Panel</h1></body></html>'
          }
        ]
      }
    );
    assert.equal(validTraceRes.confidenceTier, 'CONFIRMED_EXPLOITABLE');
    assert.equal(validTraceRes.confidenceScore, 95);
  });

  test('FINDING-8: cve-tomcat ignores unauthenticated readonly headers and derives SUSPICIOUS severity from findings', async () => {
    // 1. Spoofed x-tomcat-readonly / x-defaultservlet-readonly headers MUST NOT downgrade VULNERABLE Tomcat with PUT enabled
    const spoofedFetch = async (_url, opts = {}) => {
      if (opts.method === 'OPTIONS') {
        return {
          status: 200,
          headers: {
            server: 'Apache Tomcat/10.1.30',
            allow: 'GET, HEAD, POST, PUT, DELETE, OPTIONS',
            'x-tomcat-readonly': 'true',
            'x-defaultservlet-readonly': 'true'
          },
          text: ''
        };
      }
      return {
        status: 200,
        headers: {
          server: 'Apache Tomcat/10.1.30',
          'x-tomcat-readonly': 'true',
          'x-defaultservlet-readonly': 'true'
        },
        text: '<html><body>Apache Tomcat/10.1.30</body></html>'
      };
    };
    const vulnRes = await runCveTomcat('https://tomcat.example.com', spoofedFetch);
    assert.equal(vulnRes.status, 'VULNERABLE');
    assert.equal(vulnRes.severity, 'CRITICAL');

    // 2. When OPTIONS Allow explicitly omits PUT (and HTTP/2 is off), downgrades to SUSPICIOUS with MEDIUM severity (never CRITICAL)
    const putDisabledFetch = async (_url, opts = {}) => {
      if (opts.method === 'OPTIONS') {
        return {
          status: 200,
          headers: {
            server: 'Apache Tomcat/10.1.30',
            allow: 'GET, HEAD, POST, OPTIONS'
          },
          text: ''
        };
      }
      return {
        status: 200,
        headers: { server: 'Apache Tomcat/10.1.30' },
        text: '<html><body>Apache Tomcat/10.1.30</body></html>'
      };
    };
    const suspRes = await runCveTomcat('https://tomcat.example.com', putDisabledFetch);
    assert.equal(suspRes.status, 'SUSPICIOUS');
    assert.equal(suspRes.severity, 'MEDIUM');
    assert.notEqual(suspRes.severity, 'CRITICAL');
  });
});
