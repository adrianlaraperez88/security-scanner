import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import envCheck from '../../checks/env.js';
import securityHeadersCheck from '../../checks/security-headers.js';
import laravelAuthCheck from '../../checks/laravel-auth.js';
import ignitionCheck from '../../checks/ignition.js';
import livewireCheck from '../../checks/laravel-livewire.js';
import phpunitCheck from '../../checks/phpunit-rce.js';
import cve4577Check from '../../checks/cve-2024-4577.js';
import aiLlmCheck from '../../checks/ai-llm-exposure.js';
import pythonCheck from '../../checks/python-checks.js';
import nodeCheck from '../../checks/node-checks.js';
import magentoCheck from '../../checks/magento-checks.js';
import laravelDebugCheck from '../../checks/laravel-debug.js';
import phpErrorsCheck from '../../checks/php-errors.js';
import { createTrackedFetch } from '../../core/reproduction.js';
import { EnrichEngine } from '../../core/enrich.js';
import { verifyFindingBeforeReport } from '../../core/check-verify.js';
import { getScanners } from '../../core/registry.js';
import { generatePlaybookFixSolution } from '../../core/ai-advisor.js';
import { createAppServer } from '../../core/server.js';

const BASE = 'https://example.com';

const SPA_HTML = `<!doctype html>
<html lang="en"><head><title>App</title></head>
<body><app-root></app-root><script>
  const x = { "id": 1, "name": "Demo", "email": "support@example.com", "version": "1.0.0", "dependencies": "none" };
  // rules always cursor ignition spatie secret voyager == >= .
</script></body></html>`;

test('bank-reproducibility: HTML SPA 200 catch-all does NOT trigger false positives across CVE & framework checks', async () => {
  const spaFetch = async () => ({
    status: 200,
    headers: { 'content-type': 'text/html; charset=utf-8' },
    text: SPA_HTML
  });

  const checks = [
    ['env', envCheck],
    ['laravel-auth', laravelAuthCheck],
    ['ignition', ignitionCheck],
    ['laravel-livewire', livewireCheck],
    ['phpunit-rce', phpunitCheck],
    ['cve-2024-4577', cve4577Check],
    ['ai-llm-exposure', aiLlmCheck],
    ['python-checks', pythonCheck],
    ['node-checks', nodeCheck],
    ['magento-checks', magentoCheck],
  ];

  for (const [label, fn] of checks) {
    const res = await fn(BASE, spaFetch);
    assert.equal(res.status, 'SAFE', `${label} should return SAFE on SPA HTML fallback, got ${res.status} (${res.detail || ''})`);
  }
});

test('bank-reproducibility: env check skips placeholder-only .env.example templates and transient flaky responses', async () => {
  const placeholderRes = await envCheck(BASE, async (url) => {
    if (url.endsWith('/.env.example')) {
      return { status: 200, headers: { 'content-type': 'text/plain' }, text: 'APP_KEY=\nDB_HOST=null\nDB_PASSWORD=changeme\n' };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  });
  assert.equal(placeholderRes.status, 'SAFE');

  let calls = 0;
  const flakyRes = await envCheck(BASE, async (url) => {
    if (url.endsWith('/.env')) {
      calls++;
      if (calls === 1) return { status: 200, headers: { 'content-type': 'text/plain' }, text: 'APP_KEY=secret123456' };
      return { status: 404, headers: {}, text: 'Not Found' };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  });
  assert.equal(flakyRes.status, 'SAFE');
});

test('bank-reproducibility: laravel-auth rejects error JSON on login/register and confirms genuine /api/user leak', async () => {
  const safeApiRes = await laravelAuthCheck(BASE, async (url) => {
    if (url.endsWith('/api/login') || url.endsWith('/api/register')) {
      return { status: 200, headers: { 'content-type': 'application/json' }, text: '{"success":false,"message":"Invalid credentials"}' };
    }
    return { status: 401, headers: { 'content-type': 'application/json' }, text: '{"message":"Unauthenticated."}' };
  });
  assert.equal(safeApiRes.status, 'SAFE');

  const vulnRes = await laravelAuthCheck(BASE, async (url) => {
    if (url.endsWith('/api/user')) {
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        text: '{"id":42,"name":"Admin User","email":"admin@example.com"}',
        trafficId: 'tx-auth-1'
      };
    }
    return { status: 401, headers: {}, text: 'Unauthorized' };
  });
  assert.equal(vulnRes.status, 'VULNERABLE');
  assert.equal(vulnRes.severity, 'CRITICAL');
  assert.equal(vulnRes.path, '/api/user');
  assert.equal(vulnRes.reproVerified, true);
  assert.equal(vulnRes.files.length, 1);
  assert.equal(vulnRes.trafficId, 'tx-auth-1');
  assert.ok(Array.isArray(vulnRes.evidenceQuotes) && vulnRes.evidenceQuotes.length > 0);
});

test('bank-reproducibility: security-headers confirms reproducibility and populates files, detail, and evidenceQuotes', async () => {
  const res = await securityHeadersCheck(BASE, async () => ({
    status: 200,
    headers: { 'x-content-type-options': 'nosniff' },
    text: '<html>ok</html>',
    trafficId: 'tx-hdr-1'
  }));
  assert.equal(res.status, 'SUSPICIOUS');
  assert.equal(res.severity, 'HIGH');
  assert.equal(res.reproVerified, true);
  assert.equal(res.path, '/');
  assert.equal(res.observedStatus, 200);
  assert.equal(res.trafficId, 'tx-hdr-1');
  assert.ok(res.detail.includes('missing 5 security header(s)'));
  assert.ok(Array.isArray(res.files) && res.files.length === 1);
  assert.ok(Array.isArray(res.evidenceQuotes) && res.evidenceQuotes.length >= 1);
});

test('bank-reproducibility: ignition confirms genuine Facade\\\\Ignition JSON RCE with reproVerified=true', async () => {
  const vulnRes = await ignitionCheck(BASE, async () => ({
    status: 500,
    headers: { 'content-type': 'application/json' },
    text: '{"message":"Facade\\\\Ignition\\\\Solutions\\\\MakeViewVariableOptionalSolution failed"}',
    trafficId: 'tx-ign-1'
  }));
  assert.equal(vulnRes.status, 'VULNERABLE');
  assert.equal(vulnRes.severity, 'CRITICAL');
  assert.equal(vulnRes.cve, 'CVE-2021-3129');
  assert.equal(vulnRes.reproVerified, true);
  assert.equal(vulnRes.path, '/_ignition/execute-solution');
  assert.equal(vulnRes.trafficId, 'tx-ign-1');
  assert.ok(Array.isArray(vulnRes.evidenceQuotes) && vulnRes.evidenceQuotes.length === 1);
});

test('bank-reproducibility: real Laravel production fixtures (tools.infsalesgroup.com & fearlessbull.com) produce zero false positives and 100% accurate reproduction/verify commands', async () => {
  const TARGET = 'https://tools.infsalesgroup.com';
  // Simulates production Laravel + Nginx + Livewire:
  // - /.env and any dotfile return 403 via blanket `location ~ /\. { deny all; }`
  // - /api/user redirects (302 -> /login) or returns 401 {"message":"Unauthenticated."} with Accept: application/json
  // - /livewire/livewire.js returns 200 (patched v3), /livewire/update returns 404, /livewire/upload-file returns 419 CSRF mismatch
  // - root HTML mentions "Laravel Framework", "Warning: authorized users only", and "stack trace" in normal prose
  const prodLaravelFetch = async (url, opts = {}) => {
    const u = new URL(url);
    if (u.pathname.startsWith('/.')) {
      return { status: 403, headers: { 'content-type': 'text/html' }, text: '<html><head><title>403 Forbidden</title></head></html>' };
    }
    if (u.pathname === '/api/user') {
      const accept = opts?.headers?.Accept || opts?.headers?.accept || '';
      if (accept.includes('application/json')) {
        return { status: 401, headers: { 'content-type': 'application/json' }, text: '{"message":"Unauthenticated."}' };
      }
      if (opts?.followRedirects === false) {
        return { status: 302, headers: { location: `${TARGET}/login` }, text: '' };
      }
      return {
        status: 200,
        url: `${TARGET}/login`,
        finalUrl: `${TARGET}/login`,
        redirected: true,
        headers: { 'content-type': 'text/html' },
        text: '<html><body>Login</body></html>'
      };
    }
    if (u.pathname === '/livewire/livewire.js') {
      return { status: 200, headers: { 'content-type': 'application/javascript' }, text: 'Livewire.start();' };
    }
    if (u.pathname === '/livewire/upload-file') {
      return { status: 419, headers: { 'content-type': 'text/html' }, text: 'CSRF token mismatch.' };
    }
    if (u.pathname === '/') {
      return {
        status: 200,
        headers: { 'content-type': 'text/html' },
        text: '<html><body><p>Built on Laravel Framework. Warning: authorized users only. Read our stack trace tutorial.</p></body></html>'
      };
    }
    return { status: 404, headers: { 'content-type': 'text/html' }, text: 'Not Found' };
  };

  assert.equal((await envCheck(TARGET, prodLaravelFetch)).status, 'SAFE');
  assert.equal((await laravelAuthCheck(TARGET, prodLaravelFetch)).status, 'SAFE');
  assert.equal((await livewireCheck(TARGET, prodLaravelFetch)).status, 'SAFE');
  assert.equal((await laravelDebugCheck(TARGET, prodLaravelFetch)).status, 'SAFE');
  assert.equal((await phpErrorsCheck(TARGET, prodLaravelFetch)).status, 'SAFE');

  // Verify that when /api/user genuinely leaks user JSON, EnrichEngine + generatePlaybookFixSolution preserve Accept: application/json and exact endpoint URL
  const enrichEngine = new EnrichEngine();
  const tracked = createTrackedFetch(async (url) => {
    if (url.endsWith('/api/user')) {
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        text: '{"id":7,"name":"Jane","email":"jane@example.com"}',
        trafficId: 'tx-real-api-user'
      };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  });
  const rawAuthRes = await laravelAuthCheck(TARGET, tracked);
  const enrichedAuth = enrichEngine.enrichFinding({
    target: TARGET,
    checkId: 'laravel-auth',
    ...rawAuthRes
  }, { capturedTraces: tracked.getTraces() });

  assert.equal(enrichedAuth.status, 'VULNERABLE');
  assert.equal(enrichedAuth.reproduction.url, `${TARGET}/api/user`);
  assert.equal(enrichedAuth.reproduction.requestHeaders.Accept, 'application/json');
  assert.ok(enrichedAuth.reproduction.curl.includes("Accept: application/json"));

  const advisorFix = generatePlaybookFixSolution(enrichedAuth);
  assert.ok(advisorFix.verifyCommand.includes(`${TARGET}/api/user`));
  assert.equal(advisorFix.verifyCommand.includes('/.env'), false);
});

test('bank-reproducibility: end-to-end live server scan auto-binds evidence snapshots for 1-Click Retest and verifies advisor commands', async () => {
  const targetUrl = 'http://127.0.0.1:8080';

  const mockFetcher = async (url, opts = {}) => {
    const u = new URL(url);
    if (u.pathname.startsWith('/.htaccess')) {
      return new Response('RewriteEngine On\nRewriteRule ^ index.php [L]\n', {
        status: 200,
        headers: { 'content-type': 'text/plain' }
      });
    }
    if (u.pathname.startsWith('/.')) {
      return new Response('<html><body>403 Forbidden</body></html>', {
        status: 403,
        headers: { 'content-type': 'text/html' }
      });
    }
    if (u.pathname === '/api/user') {
      const accept = opts?.headers?.Accept || opts?.headers?.accept || '';
      if (accept.includes('application/json')) {
        return new Response(JSON.stringify({ message: 'Unauthenticated.' }), {
          status: 401,
          headers: { 'content-type': 'application/json' }
        });
      }
      return new Response('', {
        status: 302,
        headers: { location: `${targetUrl}/login` }
      });
    }
    if (u.pathname === '/livewire/livewire.js') {
      return new Response('Livewire.start();', {
        status: 200,
        headers: { 'content-type': 'application/javascript' }
      });
    }
    if (u.pathname === '/livewire/upload-file') {
      return new Response('CSRF token mismatch', {
        status: 419,
        headers: { 'content-type': 'text/html' }
      });
    }
    if (u.pathname === '/' || u.pathname === '/login') {
      return new Response(
        '<html><head><title>Laravel App</title></head><body><p>Powered by Laravel Framework. Warning: authorized users only.</p><script src="/build/app.js"></script></body></html>',
        { status: 200, headers: { 'content-type': 'text/html' } }
      );
    }
    return new Response('Not Found', {
      status: 404,
      headers: { 'content-type': 'text/plain' }
    });
  };

  const server = createAppServer({
    inMemory: true,
    allowPrivate: true,
    dnsResolver: async () => ['93.184.216.34'],
    fetcher: mockFetcher,
    retestOptions: {
      dnsResolver: async () => ['93.184.216.34'],
      fetcher: mockFetcher
    }
  });

  const invokeServer = async (method, urlPath, bodyObj = null) => {
    const chunks = bodyObj ? [Buffer.from(JSON.stringify(bodyObj))] : [];
    const req = Object.assign(Readable.from(chunks), {
      url: urlPath,
      method,
      headers: {
        host: '127.0.0.1:4321',
        ...(bodyObj ? { 'content-type': 'application/json' } : {})
      }
    });
    let resolveEnd;
    const donePromise = new Promise(r => { resolveEnd = r; });
    const res = {
      headers: {},
      statusCode: 200,
      body: '',
      setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
      writeHead(code, hdrs = {}) {
        this.statusCode = code;
        for (const [k, v] of Object.entries(hdrs)) this.headers[k.toLowerCase()] = v;
      },
      end(chunk) {
        if (chunk) this.body += Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk);
        resolveEnd();
      }
    };
    server.emit('request', req, res);
    await donePromise;
    return { status: res.statusCode, json: res.body ? JSON.parse(res.body) : null };
  };

  try {
    const startRes = await invokeServer('POST', '/api/scan', {
      targets: [targetUrl],
      profile: 'cms',
      noiseProfile: 'off',
      maxDepth: 0,
      noHistory: true,
      allowPrivate: true
    });
    const { scanId } = startRes.json;
    assert.ok(scanId, 'Expected scanId from POST /api/scan');

    let jobData = null;
    for (let i = 0; i < 80; i++) {
      await new Promise(r => setTimeout(r, 50));
      const jr = await invokeServer('GET', `/api/scan/${scanId}`);
      jobData = jr.json;
      if (jobData.status === 'completed' || jobData.status === 'failed') break;
    }
    assert.equal(jobData.status, 'completed');

    const findings = jobData.result.results;
    const byId = Object.fromEntries(findings.map(f => [f.checkId, f]));

    assert.equal(byId['env']?.status, 'SAFE');
    assert.equal(byId['laravel-auth']?.status, 'SAFE');
    assert.equal(byId['laravel-livewire']?.status, 'SAFE');
    assert.equal(byId['laravel-debug']?.status, 'SAFE');
    assert.equal(byId['php-errors']?.status, 'SAFE');

    const sf = byId['sensitive-files'];
    assert.equal(sf?.status, 'VULNERABLE');
    assert.equal(sf?.reproduction?.url, `${targetUrl}/.htaccess`);
    assert.ok(sf?.reproduction?.curl.includes(`${targetUrl}/.htaccess`));

    // Verify /api/ai/remediate endpoint returns exact /.htaccess verifyCommand
    const advRes = await invokeServer('POST', '/api/ai/remediate', { finding: sf, audience: 'pro' });
    assert.equal(advRes.status, 200);
    assert.ok(advRes.json.verifyCommand.includes(`${targetUrl}/.htaccess`));
    assert.equal(advRes.json.verifyCommand.includes('/.htaccess/.env'), false);

    // Verify 1-Click Retest works immediately via auto-bound proof snapshot
    const findingId = encodeURIComponent(`sensitive-files::${targetUrl}`);
    const retestRes = await invokeServer('POST', `/api/findings/${findingId}/retest`, { allowPrivate: true });
    assert.equal(retestRes.status, 200);
    assert.equal(retestRes.json.retest.verdict, 'reproduced');
  } finally {
    server.emit('close');
  }
});

test('bank-reproducibility: fearlessbull.com Laravel 11 + Caddy JSON 404 echoing route path ("The route _ignition/execute-solution could not be found.") returns SAFE across all 64 checks and pre-report gate', async () => {
  const FEARLESS = 'https://fearlessbull.com';
  const enrichEngine = new EnrichEngine();

  // Exact reproduction of fearlessbull.com (Caddy + Laravel 11):
  // - Any 404 with Accept: application/json returns HTTP 404 Content-Type: application/json
  //   with body: {"message":"The route <path> could not be found."}
  // - Protected routes (/admin, /dashboard, /nova, /filament, /telescope, /horizon) redirect 302 -> /login
  // - Root / returns 200 HTML with full security headers
  const fearlessFetch = async (url, opts = {}) => {
    const u = new URL(url);
    const accept = String(opts?.headers?.Accept || opts?.headers?.accept || '').toLowerCase();
    const commonHeaders = {
      'alt-svc': 'h3=":443"; ma=2592000',
      'cache-control': 'no-cache, private',
      'referrer-policy': 'strict-origin-when-cross-origin',
      'strict-transport-security': 'max-age=31536000; includeSubDomains',
      'vary': 'Accept-Encoding',
      'via': '0.0 Caddy',
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'content-security-policy': "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'",
      'permissions-policy': 'camera=(), microphone=(), geolocation=()',
      'x-ratelimit-limit': '60',
      'x-ratelimit-remaining': '59'
    };

    if (u.protocol === 'http:') {
      return {
        status: 308,
        url: u.href,
        finalUrl: u.href,
        redirected: false,
        headers: { location: u.href.replace(/^http:/, 'https:') },
        text: ''
      };
    }

    if (u.pathname === '/' || u.pathname === '/login') {
      return {
        status: 200,
        url: u.href,
        finalUrl: u.href,
        redirected: false,
        headers: { ...commonHeaders, 'content-type': 'text/html; charset=UTF-8' },
        text: '<!DOCTYPE html><html><head><title>Fearless Bull</title></head><body><h1>Welcome to Fearless Bull</h1></body></html>'
      };
    }

    if (['/admin', '/dashboard', '/nova', '/filament', '/telescope', '/horizon'].includes(u.pathname)) {
      if (opts?.followRedirects === false) {
        return {
          status: 302,
          url: u.href,
          finalUrl: u.href,
          redirected: false,
          headers: { ...commonHeaders, location: `${FEARLESS}/login` },
          text: ''
        };
      }
      return {
        status: 200,
        url: `${FEARLESS}/login`,
        finalUrl: `${FEARLESS}/login`,
        redirected: true,
        headers: { ...commonHeaders, 'content-type': 'text/html; charset=UTF-8' },
        text: '<!DOCTYPE html><html><head><title>Login - Fearless Bull</title></head><body><form>Login</form></body></html>'
      };
    }

    const routeName = u.pathname.replace(/^\/+/, '');
    if (accept.includes('application/json')) {
      return {
        status: 404,
        url: u.href,
        finalUrl: u.href,
        redirected: false,
        headers: { ...commonHeaders, 'content-type': 'application/json' },
        text: JSON.stringify({
          message: `The route ${routeName} could not be found.`
        })
      };
    }

    return {
      status: 404,
      url: u.href,
      finalUrl: u.href,
      redirected: false,
      headers: { ...commonHeaders, 'content-type': 'text/html; charset=UTF-8' },
      text: `<!DOCTYPE html><html><head><title>404 Not Found</title></head><body>The route ${routeName} could not be found.</body></html>`
    };
  };

  // 1. Direct ignition check test against fearlessbull.com 404 JSON response
  const ignRes = await ignitionCheck(FEARLESS, fearlessFetch);
  assert.equal(ignRes.status, 'SAFE', `ignition.js must return SAFE on HTTP 404 JSON echoing _ignition/execute-solution, got ${ignRes.status}`);

  // 2. Also test generic HTTP 500 JSON {"message":"Server Error"} without Ignition signatures
  const generic500Ign = await ignitionCheck(FEARLESS, async () => ({
    status: 500,
    headers: { 'content-type': 'application/json' },
    text: '{"message":"Server Error"}'
  }));
  assert.equal(generic500Ign.status, 'SAFE', 'ignition.js must return SAFE on generic 500 {"message":"Server Error"}');

  // 3. Run all 64 checks against fearlessbull.com fixture with trackedFetch + EnrichEngine pre-report gate
  const allScanners = await getScanners();
  for (const scanner of allScanners) {
    if (scanner.name === 'ssl-tls') continue; // ssl-tls uses live TCP TLS socket
    const tracked = createTrackedFetch(fearlessFetch);
    const raw = await scanner.run(FEARLESS, tracked, { tlsProbe: null, alpnProbe: null });
    const enriched = enrichEngine.enrichFinding({
      target: FEARLESS,
      checkId: scanner.name,
      ...raw,
      meta: scanner.meta
    }, { capturedTraces: tracked.getTraces() });

    assert.equal(
      enriched.status,
      'SAFE',
      `Check "${scanner.name}" produced false positive (${enriched.status}: ${enriched.detail || ''}) on fearlessbull.com 404/redirect fixture`
    );
  }

  // 4. Verify Pre-Report Gate (verifyFindingBeforeReport) catches and downgrades any hypothetical buggy check that claims VULNERABLE on a 404 trace
  const trackedBuggy = createTrackedFetch(fearlessFetch);
  await trackedBuggy(`${FEARLESS}/_ignition/execute-solution`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: '{"solution":"Facade\\\\Ignition\\\\Solutions\\\\MakeViewVariableOptionalSolution"}'
  });
  const gated = enrichEngine.enrichFinding({
    target: FEARLESS,
    checkId: 'ignition',
    name: 'ignition RCE (CVE-2021-3129)',
    status: 'VULNERABLE',
    severity: 'CRITICAL',
    path: '/_ignition/execute-solution',
    detail: 'Synthetic buggy check output on 404',
    files: [{ path: '/_ignition/execute-solution', url: `${FEARLESS}/_ignition/execute-solution`, status: 404 }]
  }, { capturedTraces: trackedBuggy.getTraces() });

  assert.equal(gated.status, 'SAFE', 'Pre-report gate must downgrade 404 finding to SAFE');
  assert.equal(gated.reproduction, undefined, 'Downgraded SAFE finding must not emit a 404 curl reproduction block');
  assert.ok(typeof verifyFindingBeforeReport === 'function');
});
