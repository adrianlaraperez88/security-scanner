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

  test('createTrackedFetch forwards positional retries/timeout args and preserves guard + hasCustomFetcher', async () => {
    const received = [];
    const baseFetch = async (url, opts, retries, timeout) => {
      received.push({ url, opts, retries, timeout });
      return { status: 200, headers: {}, text: 'ok' };
    };
    baseFetch.hasCustomFetcher = true;
    baseFetch.guard = { name: 'scope-guard' };
    baseFetch.governance = { allowPrivate: true };

    const tracked = createTrackedFetch(baseFetch);
    assert.equal(tracked.hasCustomFetcher, true);
    assert.deepEqual(tracked.guard, { name: 'scope-guard' });
    assert.deepEqual(tracked.governance, { allowPrivate: true });

    await tracked('http://192.168.68.53:8001/api/v2/', { method: 'GET' }, 0, 750);
    assert.equal(received.length, 1);
    assert.equal(received[0].retries, 0);
    assert.equal(received[0].timeout, 750);
  });

  test('buildReproductionContext emits nc -vz and Test-NetConnection for TCP/UDP & device-security port findings without HTTP 404 trace pollution', () => {
    const noisyHttpTraces = [
      { method: 'GET', url: 'http://192.168.68.53/', headers: {}, status: 404, responseSnippet: 'Not Found' },
      { method: 'GET', url: 'http://192.168.68.53:8080/', headers: {}, status: 404, responseSnippet: '404 Not Found' }
    ];

    const tcpRepro = buildReproductionContext({
      name: 'Android Debug Bridge (ADB) Exposed',
      checkId: 'device-security',
      status: 'VULNERABLE',
      severity: 'CRITICAL',
      method: 'TCP',
      host: '192.168.68.53',
      port: 5555,
      path: ':5555',
      url: 'http://192.168.68.53:5555/',
      detail: 'ADB port 5555/TCP open without authentication',
      fix: 'Disable ADB over Network.'
    }, { capturedTraces: noisyHttpTraces });

    assert.equal(tcpRepro.method, 'TCP');
    assert.equal(tcpRepro.url, 'tcp://192.168.68.53:5555');
    assert.equal(tcpRepro.curl, "nc -vz '192.168.68.53' 5555");
    assert.equal(tcpRepro.curl.includes('-X TCP'), false);
    assert.equal(tcpRepro.responseStatus, undefined);
    assert.equal(tcpRepro.reproducible, true);
    assert.ok(tcpRepro.steps.some(s => s.includes('Test-NetConnection')));
    assert.ok(tcpRepro.verifyFix.includes('Test-NetConnection'));

    // Aggregated device-security finding shape (method/port inside files[])
    const aggRepro = buildReproductionContext({
      name: 'device-security',
      checkId: 'device-security',
      status: 'VULNERABLE',
      severity: 'CRITICAL',
      target: 'http://192.168.68.53',
      path: ':5555',
      url: 'http://192.168.68.53:5555/',
      device: { host: '192.168.68.53' },
      files: [
        {
          name: 'Android Debug Bridge (5555/TCP)',
          path: ':5555',
          url: 'http://192.168.68.53:5555/',
          port: 5555,
          method: 'TCP',
          status: 200,
          matchedSignal: 'ADB TCP port 5555 open'
        }
      ]
    }, { capturedTraces: noisyHttpTraces });

    assert.equal(aggRepro.method, 'TCP');
    assert.equal(aggRepro.curl, "nc -vz '192.168.68.53' 5555");
    assert.equal(aggRepro.responseStatus, undefined);
  });

  test('buildReproductionContext handles rtsp:// / rtsps:// safely by stripping embedded credentials', () => {
    const rtspRepro = buildReproductionContext({
      name: 'RTSP Unauthenticated Stream',
      checkId: 'device-security',
      status: 'VULNERABLE',
      severity: 'HIGH',
      method: 'RTSP',
      url: 'rtsp://admin:SuperSecret123@192.168.1.20:554/stream1',
      detail: 'RTSP stream responded to OPTIONS'
    }, {
      capturedTraces: [{ method: 'GET', url: 'http://192.168.1.20/', status: 404, responseSnippet: 'Not Found' }]
    });

    assert.equal(rtspRepro.url, 'rtsp://192.168.1.20:554/stream1');
    assert.equal(rtspRepro.curl, "curl -i -sS --request OPTIONS 'rtsp://192.168.1.20:554/stream1'");
    assert.equal(rtspRepro.curl.includes('SuperSecret123'), false);
    assert.equal(rtspRepro.curl.includes('admin'), false);
    assert.equal(rtspRepro.responseStatus, undefined);
    assert.equal(rtspRepro.reproducible, true);

    // Sub-items in files[] with rtsp:// credentials must also strip userinfo in matchedEvidence[].url
    const rtspSubItemRepro = buildReproductionContext({
      name: 'RTSP Streams Exposed',
      checkId: 'device-security',
      status: 'VULNERABLE',
      severity: 'HIGH',
      method: 'DESCRIBE',
      url: 'rtsp://admin:SuperSecret123@192.168.1.20:554/stream1',
      files: [
        {
          name: 'RTSP Primary Stream',
          url: 'rtsp://operator:TopSecret99@192.168.1.20:554/live',
          method: 'DESCRIBE',
          matchedSignal: 'RTSP DESCRIBE returned SDP'
        }
      ]
    });
    assert.equal(rtspSubItemRepro.method, 'DESCRIBE');
    assert.equal(rtspSubItemRepro.curl, "curl -i -sS --request DESCRIBE 'rtsp://192.168.1.20:554/stream1'");
    assert.ok(rtspSubItemRepro.steps[0].includes('--request DESCRIBE'));
    assert.ok(rtspSubItemRepro.verifyFix.includes('RTSP DESCRIBE'));
    assert.equal(rtspSubItemRepro.matchedEvidence[0].url, 'rtsp://192.168.1.20:554/live');
    assert.equal(rtspSubItemRepro.matchedEvidence[0].url.includes('TopSecret99'), false);
    assert.equal(rtspSubItemRepro.matchedEvidence[0].url.includes('operator'), false);

    // Non-HTTP ssh:// port finding aligns steps/verifyFix with nc -vz & Test-NetConnection
    const sshRepro = buildReproductionContext({
      name: 'SSH Port Exposed',
      checkId: 'device-security',
      status: 'SUSPICIOUS',
      severity: 'LOW',
      url: 'ssh://root:toor@192.168.1.10:22/',
      files: [{ url: 'ssh://root:toor@192.168.1.10:22/', matchedSignal: 'SSH-2.0-OpenSSH_9.0' }]
    });
    assert.equal(sshRepro.curl, "nc -vz '192.168.1.10' 22");
    assert.ok(sshRepro.steps[0].includes("nc -vz '192.168.1.10' 22"));
    assert.ok(sshRepro.steps[0].includes('Test-NetConnection -ComputerName 192.168.1.10 -Port 22'));
    assert.ok(sshRepro.verifyFix.includes('Test-NetConnection -ComputerName 192.168.1.10 -Port 22'));
    assert.equal(sshRepro.matchedEvidence[0].url, 'ssh://192.168.1.10:22/');
  });

  test('buildReproductionContext resists shell injection on malicious hosts, invalid ports, and RTSP paths', () => {
    const evilHostRepro = buildReproductionContext({
      name: 'TCP Port',
      checkId: 'device-security',
      status: 'VULNERABLE',
      method: 'TCP',
      host: '192.168.1.1; rm -rf /',
      port: 5555
    });
    assert.equal(evilHostRepro.curl, null);

    const cmdSubHostRepro = buildReproductionContext({
      name: 'TCP Port',
      checkId: 'device-security',
      status: 'VULNERABLE',
      method: 'TCP',
      host: '$(id)',
      port: 23
    });
    assert.equal(cmdSubHostRepro.curl, null);

    const evilPortRepro = buildReproductionContext({
      name: 'TCP Port',
      checkId: 'device-security',
      status: 'VULNERABLE',
      method: 'TCP',
      host: '192.168.1.10',
      port: '554;id'
    });
    assert.equal(evilPortRepro.curl, null);

    const outOfRangePortRepro = buildReproductionContext({
      name: 'TCP Port',
      checkId: 'device-security',
      status: 'VULNERABLE',
      method: 'TCP',
      host: '192.168.1.10',
      port: 99999
    });
    assert.equal(outOfRangePortRepro.curl, null);

    const rtspQuoteRepro = buildReproductionContext({
      name: 'RTSP',
      checkId: 'device-security',
      status: 'VULNERABLE',
      url: "rtsp://192.168.1.20:554/it's$(id)"
    });
    assert.ok(rtspQuoteRepro.curl.startsWith("curl -i -sS --request OPTIONS '"));
    assert.ok(rtspQuoteRepro.curl.includes("'\\''"));
  });

  test('selectTriggerTrace & EnrichEngine keep same-origin 404 trace on :3000 instead of jumping to :80 200 OK', () => {
    const traces = [
      { method: 'GET', url: 'http://192.168.1.80/', headers: {}, status: 200, responseSnippet: '<html>Hello</html>' },
      { method: 'GET', url: 'http://192.168.1.80:3000/', headers: {}, status: 404, responseSnippet: '404 Not Found' }
    ];

    const lgFinding = {
      name: 'device-security',
      checkId: 'device-security',
      status: 'SUSPICIOUS',
      severity: 'MEDIUM',
      target: 'http://192.168.1.80',
      path: '/',
      url: 'http://192.168.1.80:3000/',
      method: 'GET',
      port: 3000,
      observedStatus: 404,
      detail: 'LG webOS SSAP service on port 3000 (HTTP 404)',
      files: [
        {
          name: 'LG webOS Smart TV SSAP Control Service Exposed (3000/TCP)',
          path: '/',
          url: 'http://192.168.1.80:3000/',
          port: 3000,
          method: 'GET',
          status: 404,
          matchedSignal: 'LG webOS service on port 3000 (HTTP 404)'
        }
      ]
    };

    const engine = new EnrichEngine();
    const enriched = engine.enrichFinding(lgFinding, { capturedTraces: traces });
    assert.equal(enriched.status, 'SUSPICIOUS');
    assert.equal(enriched.reproduction?.url, 'http://192.168.1.80:3000/');
    assert.equal(enriched.reproduction?.responseStatus, 404);
    assert.equal(enriched.reproduction?.curl, "curl -i -sS 'http://192.168.1.80:3000/'");

    // When :3000 trace is absent and only :80 trace exists, selectTriggerTrace must NOT jump across origins
    const missingOriginTrace = selectTriggerTrace(
      [{ method: 'GET', url: 'http://192.168.1.80/', headers: {}, status: 200, responseSnippet: 'Hello' }],
      lgFinding
    );
    assert.equal(missingOriginTrace, null);
  });
});
