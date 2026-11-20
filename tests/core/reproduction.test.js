import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  sanitizeHeadersForRepro,
  shellQuoteSingle,
  buildCurlCommand,
  createTrackedFetch,
  selectTriggerTrace,
  buildReproductionContext
} from '../../core/reproduction.js';
import { EnrichEngine } from '../../core/enrich.js';
import {
  generateSingleFindingMarkdown,
  generateCsvReport
} from '../../core/report.js';
import { generateHtmlReport } from '../../core/html-report.js';
import { buildClientCsvReport } from '../../ui/app.js';

describe('Reproduction & Post-Fix Verification Context', () => {
  test('sanitizeHeadersForRepro redacts sensitive credentials and strips control chars', () => {
    const clean = sanitizeHeadersForRepro({
      Authorization: 'Bearer super-secret-jwt\r\nInjected: yes',
      Cookie: 'session=abc123',
      'X-API-Key': 'key-999',
      Origin: 'https://evil.attacker.example.com',
      'User-Agent': 'Mozilla/5.0'
    });

    assert.equal(clean.Authorization, '<REDACTED>');
    assert.equal(clean.Cookie, '<REDACTED>');
    assert.equal(clean['X-API-Key'], '<REDACTED>');
    assert.equal(clean.Origin, 'https://evil.attacker.example.com');
    assert.equal(clean['User-Agent'], undefined);
  });

  test('shellQuoteSingle & buildCurlCommand produce shell-safe HTTP(S) curl commands only', () => {
    assert.equal(shellQuoteSingle("a'b\nc"), "'a'\\''b c'");

    const cmd = buildCurlCommand({
      method: 'POST',
      url: "https://example.com/api?q=it's",
      headers: {
        Authorization: 'Bearer topsecret',
        'X-Forwarded-Host': 'evil.example'
      },
      body: '{"test":true}',
      http2: true
    });

    assert.ok(cmd.includes('curl -i -sS --http2 -X POST'));
    assert.ok(cmd.includes("Authorization: <REDACTED>"));
    assert.ok(cmd.includes("X-Forwarded-Host: evil.example"));
    assert.ok(!cmd.includes('topsecret'));
    assert.equal(buildCurlCommand({ url: 'file:///etc/passwd' }), null);
  });

  test('createTrackedFetch captures traces, preserves governance props, and selectTriggerTrace prefers matching path', async () => {
    const baseFetch = async (url, opts) => {
      if (url.endsWith('/.env.backup')) return { status: 404, headers: {}, text: 'Not Found' };
      if (url.endsWith('/.env')) return { status: 200, headers: {}, text: 'APP_KEY=123456', trafficId: 'tx_env_1' };
      return { status: 200, headers: { 'access-control-allow-origin': opts?.headers?.Origin || '' }, text: 'ok' };
    };
    baseFetch.governance = { allowPrivate: false };
    baseFetch.tlsAlpnProbe = async () => ({ probed: true });

    const tracked = createTrackedFetch(baseFetch);
    assert.deepEqual(tracked.governance, { allowPrivate: false });
    assert.equal(typeof tracked.tlsAlpnProbe, 'function');

    await tracked('https://app.example.com/.env.backup');
    await tracked('https://app.example.com/.env');

    const traces = tracked.getTraces();
    assert.equal(traces.length, 2);

    const chosen = selectTriggerTrace(traces, { target: 'https://app.example.com', path: '/.env' });
    assert.equal(chosen.url, 'https://app.example.com/.env');
    assert.equal(chosen.status, 200);
    assert.equal(chosen.trafficId, 'tx_env_1');
  });

  test('buildReproductionContext returns null for SAFE and full steps/curl/verifyFix for VULNERABLE', () => {
    assert.equal(buildReproductionContext({ name: 'cors', status: 'SAFE', target: 'https://example.com' }), null);

    const repro = buildReproductionContext({
      name: 'cors misconfiguration',
      checkId: 'cors',
      status: 'VULNERABLE',
      severity: 'HIGH',
      target: 'https://api.example.com/v1/user',
      detail: 'Evil origin reflected with credentials',
      fix: 'Whitelist trusted origins.'
    });

    assert.ok(repro);
    assert.equal(repro.method, 'GET');
    assert.equal(repro.requestHeaders.Origin, 'https://evil.attacker.example.com');
    assert.ok(repro.curl.includes("Origin: https://evil.attacker.example.com"));
    assert.ok(Array.isArray(repro.steps) && repro.steps.length === 3);
    assert.ok(repro.verifyFix.includes('SAFE'));
  });

  test('EnrichEngine + Markdown/HTML/CSV/UI-CSV reports surface How to Reproduce & Verify Fix cleanly', () => {
    const engine = new EnrichEngine();
    const enriched = engine.enrichFinding({
      name: 'env file exposure',
      checkId: 'env',
      status: 'VULNERABLE',
      severity: 'CRITICAL',
      target: 'https://internal.example.com',
      path: '/.env',
      detail: 'Exposed .env with APP_KEY'
    }, {
      capturedTraces: [
        {
          method: 'GET',
          url: 'https://internal.example.com/.env',
          headers: { Authorization: '<REDACTED>' },
          status: 200,
          responseSnippet: 'APP_KEY=redacted_example',
          trafficId: 'tx_123'
        }
      ]
    });

    assert.ok(enriched.reproduction);
    assert.equal(enriched.reproduction.url, 'https://internal.example.com/.env');
    assert.equal(enriched.trafficId, 'tx_123');
    assert.equal(enriched._capturedTraces, undefined);

    const md = generateSingleFindingMarkdown(enriched);
    assert.ok(md.includes('#### How to Reproduce & Verify Fix'));
    assert.ok(md.includes('https://internal.example.com/.env'));
    assert.equal((md.match(/`{3,}/g) || []).length % 2, 0);

    const html = generateHtmlReport([enriched], { level: 'CRITICAL', grade: 'F', score: 20 });
    assert.ok(html.includes('How to Reproduce &amp; Verify Fix'));
    assert.ok(html.includes('https://internal.example.com/.env'));

    const serverCsv = generateCsvReport([enriched]);
    assert.ok(serverCsv.includes(',How to Reproduce\r\n'));
    assert.ok(serverCsv.includes('https://internal.example.com/.env'));

    const clientCsv = buildClientCsvReport([enriched]);
    assert.ok(clientCsv.includes(',How to Reproduce\r\n'));
    assert.ok(clientCsv.includes('https://internal.example.com/.env'));
  });

  test('HTML/Markdown/CSV reproduction neutralizes XSS & CSV formulas from target URLs/details', () => {
    const finding = {
      name: 'xss',
      checkId: 'xss',
      status: 'VULNERABLE',
      severity: 'HIGH',
      target: 'https://example.com/search?q=<script>alert(1)</script>',
      detail: '=cmd|calc',
      reproduction: {
        summary: '=HYPERLINK("http://evil")',
        method: 'GET',
        url: 'https://example.com/search?q=<script>alert(1)</script>',
        observedSignal: '```unclosed fence <img onerror=alert(1)>',
        steps: ['Send GET request with <script>alert(1)</script>'],
        curl: "curl -i -sS 'https://example.com/search?q=<script>alert(1)</script>'",
        verifyFix: 'Ensure encoded output and SAFE status.'
      }
    };

    const md = generateSingleFindingMarkdown(finding);
    assert.equal((md.match(/`{3,}/g) || []).length % 2, 0);

    const html = generateHtmlReport([finding], { level: 'HIGH', grade: 'D', score: 20 });
    assert.equal(html.includes('<script>alert(1)</script>'), false);
    assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));

    const csv = generateCsvReport([finding]);
    assert.ok(csv.includes("'=HYPERLINK("));
  });

  test('selectTriggerTrace & reports prioritize finding.files[] paths and share Matched Files + Reproducible proof', () => {
    const traces = [
      { method: 'GET', url: 'https://example.com/composer.json', headers: {}, status: 404, responseSnippet: 'Not Found' },
      { method: 'GET', url: 'https://example.com/.htaccess', headers: {}, status: 200, responseSnippet: 'RewriteEngine On\nRewriteRule ^admin /403' }
    ];
    const finding = {
      name: 'sensitive files',
      checkId: 'sensitive-files',
      status: 'VULNERABLE',
      severity: 'MEDIUM',
      target: 'https://example.com',
      path: '/.htaccess',
      reproVerified: true,
      detail: 'Confirmed reproducible exposure of 1 sensitive file(s): /.htaccess (HTTP 200, RewriteEngine On)',
      files: [{ path: '/.htaccess', url: 'https://example.com/.htaccess', status: 200, matchedSignal: 'RewriteEngine On', reproducible: true }],
      evidenceQuotes: ['RewriteEngine On RewriteRule ^admin /403'],
      fix: 'Remove sensitive configuration or metadata files from the web root.'
    };

    const repro = buildReproductionContext(finding, { capturedTraces: traces });
    assert.equal(repro.url, 'https://example.com/.htaccess');
    assert.equal(repro.responseStatus, 200);
    assert.equal(repro.reproducible, true);
    assert.ok(repro.curl.includes('https://example.com/.htaccess'));
    assert.equal(repro.matchedEvidence.length, 1);

    const enriched = { ...finding, reproduction: repro };
    const md = generateSingleFindingMarkdown(enriched);
    assert.match(md, /Matched Files & Exposed Paths/);
    assert.match(md, /Reproducible\*\*: Yes \(Confirmed\)/);
    assert.match(md, /\/\.htaccess/);

    const html = generateHtmlReport([enriched], { level: 'HIGH', grade: 'D', score: 20 });
    assert.match(html, /Matched Files \(1\)/);
    assert.match(html, /Confirmed Reproducible/);
    assert.match(html, /https:\/\/example\.com\/\.htaccess/);
  });

  test('preserves explicit Accept: application/json header in curl while stripping default scanner Accept and handles >25 traces and comma-joined paths', async () => {
    const cleanExplicit = sanitizeHeadersForRepro({
      Accept: 'application/json',
      'User-Agent': 'Mozilla/5.0'
    });
    assert.equal(cleanExplicit.Accept, 'application/json');
    assert.equal(cleanExplicit['User-Agent'], undefined);

    const cleanDefault = sanitizeHeadersForRepro({
      Accept: 'text/html,application/json,*/*'
    });
    assert.equal(cleanDefault.Accept, undefined);

    // Tracked fetch with >25 probes must still capture the 40th probe
    const baseFetch = async (url) => ({
      status: url.includes('hit=1') ? 200 : 404,
      headers: {},
      text: url.includes('hit=1') ? 'root:x:0:0:' : 'Not Found',
      trafficId: url.includes('hit=1') ? 'tx_40' : null
    });
    const tracked = createTrackedFetch(baseFetch);
    for (let i = 0; i < 40; i++) {
      await tracked(`https://example.com/page?p=${i}${i === 39 ? '&hit=1' : ''}`, {
        headers: { Accept: 'application/json' }
      });
    }
    const traces = tracked.getTraces();
    assert.equal(traces.length, 40);

    const repro = buildReproductionContext({
      name: 'local file inclusion (LFI)',
      checkId: 'php-lfi',
      status: 'VULNERABLE',
      severity: 'CRITICAL',
      target: 'https://example.com/page',
      path: '/page?p=39&hit=1, /page?p=40',
      missing: ['Content-Security-Policy']
    }, { capturedTraces: traces });

    assert.equal(repro.url, 'https://example.com/page?p=39&hit=1');
    assert.equal(repro.trafficId, 'tx_40');
    assert.equal(repro.requestHeaders.Accept, 'application/json');
    assert.ok(repro.curl.includes("Accept: application/json"));

    // summarizeObservedSignal uses finding.missing / finding.issues instead of raw HTML snippet
    const headerRepro = buildReproductionContext({
      name: 'security headers',
      checkId: 'security-headers',
      status: 'SUSPICIOUS',
      severity: 'MEDIUM',
      target: 'https://example.com',
      missing: ['Content-Security-Policy', 'X-Frame-Options']
    }, {
      capturedTraces: [
        { method: 'GET', url: 'https://example.com/', headers: {}, status: 200, responseSnippet: '<html lang="en"><head><title>App</title></head></html>' }
      ]
    });
    assert.match(headerRepro.observedSignal, /Missing security header\(s\): Content-Security-Policy, X-Frame-Options/);
    assert.equal(headerRepro.observedSignal.includes('<html'), false);
  });
});
