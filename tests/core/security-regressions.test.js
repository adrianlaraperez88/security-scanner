import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';

import { generateCheckTemplate } from '../../core/catalog.js';
import { validateTargetUrl } from '../../core/validator.js';
import { fetchWithRetry } from '../../core/fetch.js';
import { generateHtmlReport } from '../../core/html-report.js';
import { createAppServer } from '../../core/server.js';
import { saveHistory, loadHistoryById } from '../../core/history.js';
import { selectScannersForStack, ACTIVE_FUZZING_CHECKS } from '../../core/profiles.js';

// Helper for testing server in-memory without TCP socket sandbox restrictions
function createMockRes() {
  const headers = {};
  return {
    headers,
    statusCode: 200,
    headersSent: false,
    body: '',
    setHeader(name, val) {
      headers[name.toLowerCase()] = val;
    },
    writeHead(code, hdrs) {
      this.statusCode = code;
      this.headersSent = true;
      if (hdrs) {
        for (const [k, v] of Object.entries(hdrs)) {
          headers[k.toLowerCase()] = v;
        }
      }
    },
    end(chunk) {
      if (chunk) this.body += chunk;
      this.headersSent = true;
    }
  };
}

// ── FINDING-1 Regressions: Catalog Template Injection & Name Validation ─────

test('FINDING-1: generateCheckTemplate rejects invalid check names', () => {
  const invalidNames = [
    'invalid name with spaces',
    'check;rm -rf /',
    'check!injection',
    'check@name',
    'a', // too short (< 2)
    'a'.repeat(45), // too long (> 40)
    'check_with_underscore',
    'check/slash',
    ''
  ];

  for (const name of invalidNames) {
    assert.throws(
      () => generateCheckTemplate(name),
      /Invalid check name/,
      `Expected generateCheckTemplate("${name}") to throw Invalid check name error`
    );
  }
});

test('FINDING-1: generateCheckTemplate neutralizes */ comment breakouts in title', () => {
  const badTitle = 'SafeTitle */ console.log("PWNED"); /* safe again';
  const template = generateCheckTemplate('comment-breakout-test', {
    title: badTitle
  });

  // Verify safeCommentTitle does not contain unescaped */ or /*
  assert.ok(!template.checkCode.includes('*/ console.log("PWNED"); /*'));
  assert.ok(template.checkCode.includes('SafeTitle  console.log("PWNED");  safe again scanner'));

  // Verify the generated checkCode contains JSON.stringify escaped title
  assert.ok(template.checkCode.includes(`title: ${JSON.stringify(badTitle)}`));
});

test('FINDING-1: generateCheckTemplate uses JSON.stringify to neutralize string breakouts', () => {
  const breakoutTitle = "BreakoutTitle'; process.exit(1); '";
  const breakoutCat = "Category'; evil(); '";
  const breakoutFix = "Fix'; evil(); '";

  const template = generateCheckTemplate('string-breakout-test', {
    title: breakoutTitle,
    category: breakoutCat,
    defaultFix: breakoutFix
  });

  // Must not have unescaped single-quote breakouts
  assert.ok(!template.checkCode.includes("title: 'BreakoutTitle';"));
  assert.ok(template.checkCode.includes(`title: ${JSON.stringify(breakoutTitle)}`));
  assert.ok(template.checkCode.includes(`category: ${JSON.stringify(breakoutCat)}`));
  assert.ok(template.checkCode.includes(`defaultFix: ${JSON.stringify(breakoutFix)}`));

  // Test code descriptions must also use JSON.stringify
  assert.ok(template.testCode.includes('test("string-breakout-test: SAFE on normal response"'));
});

// ── FINDING-2 Regressions: SSRF Validation & Manual Redirect Handling ────────

test('FINDING-2: validateTargetUrl blocks obfuscated, shorthand, and IPv6 bypass targets', () => {
  const blockedUrls = [
    'http://[::127.0.0.1]',
    'http://[::169.254.169.254]',
    'http://[64:ff9b::127.0.0.1]',
    'http://[2002:7f00:1::]',
    'http://127.1',
    'http://127.0.1',
    'http://example.com\\@127.0.0.1',
    'http://example.com\\test'
  ];

  for (const url of blockedUrls) {
    const res = validateTargetUrl(url);
    assert.equal(res.valid, false, `Expected validateTargetUrl("${url}") to be invalid`);
    assert.ok(res.error, `Expected an error message for "${url}"`);
  }
});

test('FINDING-2: validateTargetUrl allows valid public HTTP and HTTPS URLs', () => {
  const validUrls = [
    'https://example.com',
    'http://example.com/path?foo=bar#section',
    'https://93.184.216.34'
  ];

  for (const url of validUrls) {
    const res = validateTargetUrl(url);
    assert.equal(res.valid, true, `Expected validateTargetUrl("${url}") to be valid: ${res.error}`);
    assert.ok(res.normalized);
  }
});

test('FINDING-2: fetchWithRetry blocks redirects to internal SSRF targets', async () => {
  const originalFetch = globalThis.fetch;
  try {
    // Mock globalThis.fetch to simulate a 302 redirect to AWS/cloud metadata IP
    globalThis.fetch = async () => {
      return new Response('', {
        status: 302,
        headers: {
          location: 'http://169.254.169.254/latest/meta-data/'
        }
      });
    };

    await assert.rejects(
      async () => {
        await fetchWithRetry('https://example.com/', {}, 0, 3000);
      },
      /Redirect blocked by SSRF policy/
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

// ── FINDING-3 Regressions: HTML Report & UI Prototype Pollution / XSS ────────

test('FINDING-3: generateHtmlReport escapes HTML in risk.score and single quotes', () => {
  const maliciousResults = [
    {
      name: "xss-check' onclick='alert(1)'",
      target: 'https://example.com',
      status: 'VULNERABLE',
      severity: 'HIGH',
      detail: "<script>alert('xss')</script>"
    }
  ];

  const maliciousRisk = {
    level: 'HIGH',
    grade: 'F',
    score: '<script>alert("score-xss")</script>',
    summary: 'Testing HTML escaping'
  };

  const html = generateHtmlReport(maliciousResults, maliciousRisk);

  // Escaping assertions
  assert.ok(!html.includes('<script>alert("score-xss")</script>'));
  assert.ok(html.includes('&lt;script&gt;alert(&quot;score-xss&quot;)&lt;/script&gt;'));
  assert.ok(html.includes('&#39;')); // single quotes escaped
  assert.ok(!html.includes("<script>alert('xss')</script>"));
});

test('FINDING-3: generateHtmlReport safely handles prototype properties without leakage', () => {
  const resultsWithPrototypeKeys = [
    {
      name: 'prototype-lookup-test',
      target: 'https://example.com',
      status: 'toString',
      severity: 'constructor',
      detail: 'Prototype pollution test'
    }
  ];

  const riskWithPrototypeKeys = {
    level: 'toString',
    grade: 'constructor',
    score: 10,
    summary: 'Testing prototype pollution robustness'
  };

  const html = generateHtmlReport(resultsWithPrototypeKeys, riskWithPrototypeKeys);

  // Must not leak function bodies or crash
  assert.ok(!html.includes('function toString()'));
  assert.ok(!html.includes('function Object()'));
  assert.ok(html.includes('Security Scan Report'));
});

// ── FINDING-4 Regressions: Server Host/Origin, URL Parsing, & Payload Limits ─

test('FINDING-4: createAppServer enforces Host allowlist on GET requests (403)', async () => {
  const server = createAppServer();
  const req = Object.assign(Readable.from([]), {
    url: '/api/history',
    method: 'GET',
    headers: { host: 'evil.example.com' }
  });
  const res = createMockRes();

  server.emit('request', req, res);

  // Let event loop process request
  await new Promise(r => setTimeout(r, 10));

  assert.equal(res.statusCode, 403);
  const json = JSON.parse(res.body);
  assert.equal(json.error, 'Forbidden: Invalid Origin or Host header');
});

test('FINDING-4: createAppServer blocks disallowed Origin header (403)', async () => {
  const server = createAppServer();
  const req = Object.assign(Readable.from([]), {
    url: '/api/history',
    method: 'GET',
    headers: {
      host: '127.0.0.1:4321',
      origin: 'http://malicious.attacker.com'
    }
  });
  const res = createMockRes();

  server.emit('request', req, res);

  await new Promise(r => setTimeout(r, 10));

  assert.equal(res.statusCode, 403);
  const json = JSON.parse(res.body);
  assert.equal(json.error, 'Forbidden: Invalid Origin or Host header');
});

test('FINDING-4: createAppServer handles malformed Host header safely (403)', async () => {
  const server = createAppServer();
  const req = Object.assign(Readable.from([]), {
    url: '/api/history',
    method: 'GET',
    headers: { host: '[::1' }
  });
  const res = createMockRes();

  server.emit('request', req, res);

  await new Promise(r => setTimeout(r, 10));

  assert.equal(res.statusCode, 403);
  const json = JSON.parse(res.body);
  assert.equal(json.error, 'Forbidden: Invalid Origin or Host header');
});

test('FINDING-4: createAppServer handles multi-chunk >64KB POST bodies without ERR_HTTP_HEADERS_SENT', async () => {
  const server = createAppServer();

  // Create stream with oversized JSON body (> 64KB)
  const chunkList = ['{"data":"'];
  for (let i = 0; i < 5; i++) {
    chunkList.push('a'.repeat(16384));
  }
  chunkList.push('"}');

  const req = Object.assign(Readable.from(chunkList), {
    url: '/api/scan',
    method: 'POST',
    headers: {
      host: '127.0.0.1:4321',
      'content-type': 'application/json'
    }
  });
  const res = createMockRes();

  server.emit('request', req, res);

  await new Promise(r => setTimeout(r, 30));

  assert.equal(res.statusCode, 413);
  const json = JSON.parse(res.body);
  assert.equal(json.error, 'Payload too large (max 64KB)');
});

test('FINDING-4: createAppServer allows valid local requests with 200', async () => {
  const server = createAppServer();
  const req = Object.assign(Readable.from([]), {
    url: '/api/meta',
    method: 'GET',
    headers: {
      host: '127.0.0.1:4321'
    }
  });
  const res = createMockRes();

  server.emit('request', req, res);

  await new Promise(r => setTimeout(r, 20));

  assert.equal(res.statusCode, 200);
  const json = JSON.parse(res.body);
  assert.equal(json.version, '2.2.0');
  assert.ok(Array.isArray(json.presets));
});

// ── Step 2D Regressions: Boundary & Reliability (FINDING-1, FINDING-2, FINDING-3) ──

test('FINDING-1: generateHtmlReport handles null stack items and avoids double-escaping ampersands', () => {
  const results = [
    { name: 'ssl-tls', target: 'https://example.com', status: 'SAFE', severity: 'NONE' }
  ];
  const risk = { level: 'LOW', grade: 'A+', score: 0 };
  const stacks = [
    {
      target: 'https://example.com',
      stack: [null, { tech: 'Node & Express', score: 5 }],
      detectedTags: [null, 'nodejs', 'express']
    }
  ];

  // Must not throw TypeError
  const html = generateHtmlReport(results, risk, stacks);
  assert.ok(html.includes('Node &amp; Express(5)'));
  assert.ok(!html.includes('Node &amp;amp; Express(5)'));
});

test('FINDING-1: POST /api/report/html handles report generation errors with 500', async () => {
  const server = createAppServer();
  // Pass results array containing null element which causes an unexpected error during risk/report generation
  const req = Object.assign(
    Readable.from([Buffer.from(JSON.stringify({
      results: [null]
    }))]),
    {
      url: '/api/report/html',
      method: 'POST',
      headers: {
        host: '127.0.0.1:4321',
        'content-type': 'application/json'
      }
    }
  );
  const res = createMockRes();

  server.emit('request', req, res);

  await new Promise(r => setTimeout(r, 20));

  assert.equal(res.statusCode, 500);
  const json = JSON.parse(res.body);
  assert.ok(json.error.includes('Failed to generate HTML report:'));
});

test('FINDING-2: saveHistory persists stacks and loadHistoryById restores record.stacks', () => {
  const targets = ['https://history-stacks-test.example.com'];
  const results = [
    { name: 'ssl-tls', target: 'https://history-stacks-test.example.com', status: 'SAFE', severity: 'NONE' }
  ];
  const risk = { level: 'LOW', grade: 'A+', score: 0 };
  const stacks = [
    {
      target: 'https://history-stacks-test.example.com',
      summary: 'Node.js',
      activeChecksCount: 10
    }
  ];

  const savedPath = saveHistory(targets, results, risk, stacks);
  try {
    assert.ok(fs.existsSync(savedPath));
    const fileName = path.basename(savedPath);
    const loaded = loadHistoryById(fileName);
    assert.ok(loaded);
    assert.deepEqual(loaded.stacks, stacks);
  } finally {
    if (fs.existsSync(savedPath)) {
      fs.unlinkSync(savedPath);
    }
  }
});

test('FINDING-2: ACTIVE_FUZZING_CHECKS contains expected parameterized fuzzing checks', () => {
  assert.ok(ACTIVE_FUZZING_CHECKS instanceof Set);
  assert.ok(ACTIVE_FUZZING_CHECKS.has('xss'));
  assert.ok(ACTIVE_FUZZING_CHECKS.has('sqli'));
  assert.ok(ACTIVE_FUZZING_CHECKS.has('open-redirect'));
  assert.ok(ACTIVE_FUZZING_CHECKS.has('php-lfi'));
});

test('FINDING-3: selectScannersForStack safely handles malformed fp.stack and string detectedTags', () => {
  const mockScanners = [
    { name: 'laravel-debug', tags: ['laravel'] },
    { name: 'php-version', tags: ['php'] },
    { name: 'ssl-tls', tags: ['all'] }
  ];

  // Case 1: fp.stack contains null and string items
  const res1 = selectScannersForStack(mockScanners, {
    profile: 'smart',
    fp: { stack: [null, 'laravel'] }
  });
  assert.ok(Array.isArray(res1.activeScanners));
  assert.ok(res1.activeScanners.some(s => s.name === 'laravel-debug'));
  assert.ok(res1.activeScanners.some(s => s.name === 'ssl-tls'));

  // Case 2: fp.detectedTags is a comma-separated string instead of array
  const res2 = selectScannersForStack(mockScanners, {
    profile: 'smart',
    fp: { detectedTags: 'laravel,php' }
  });
  assert.ok(Array.isArray(res2.activeScanners));
  assert.ok(res2.activeScanners.some(s => s.name === 'laravel-debug'));
  assert.ok(res2.activeScanners.some(s => s.name === 'php-version'));
  assert.ok(res2.activeScanners.some(s => s.name === 'ssl-tls'));
});
