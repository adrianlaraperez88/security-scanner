import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Fuzzer } from '../../core/fuzzer.js';

test('Fuzzer: detects reflected XSS', async () => {
  const payload = '<script>alert(1)</script>';
  const mockFetch = async (urlStr) => {
    const u = new URL(urlStr);
    return {
      status: 200,
      text: `<html><body>Input was ${u.searchParams.get('q')}</body></html>`
    };
  };

  const fuzzer = new Fuzzer(mockFetch);
  const results = await fuzzer.fuzz('https://example.com?q=test', payload, 'XSS_REFLECTED');

  assert.equal(results.length, 1);
  assert.equal(results[0].parameter, 'q');
});

test('Fuzzer: ignores XSS reflection in application/json responses', async () => {
  const payload = '<script>alert(1)</script>';
  const mockFetch = async (urlStr) => {
    const u = new URL(urlStr);
    return {
      status: 200,
      headers: { 'content-type': 'application/json; charset=utf-8' },
      text: JSON.stringify({ q: u.searchParams.get('q') })
    };
  };

  const fuzzer = new Fuzzer(mockFetch);
  const results = await fuzzer.fuzz('https://example.com?q=test', payload, 'XSS_REFLECTED');
  assert.equal(results.length, 0);
});

test('Fuzzer: detects error-based SQLi', async () => {
  const payload = "'";
  const mockFetch = async () => ({
    status: 500,
    text: 'You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version...'
  });

  const fuzzer = new Fuzzer(mockFetch);
  const results = await fuzzer.fuzz('https://example.com?id=1', payload, 'SQLI_ERROR');

  assert.equal(results.length, 1);
  assert.equal(results[0].type, 'SQLI_ERROR');
});

test('Fuzzer: detects time-based SQLi when payload duration exceeds baseline + threshold', async () => {
  const payload = "SLEEP(5)";
  const mockFetch = async (urlStr) => {
    if (urlStr.includes('SLEEP')) {
      await new Promise(r => setTimeout(r, 150));
    }
    return { status: 200, text: 'ok' };
  };

  const fuzzer = new Fuzzer(mockFetch);
  const results = await fuzzer.fuzz('https://example.com?id=1', payload, 'SQLI_TIME', { delayThresholdMs: 100 });

  assert.equal(results.length, 1);
  assert.equal(results[0].type, 'SQLI_TIME');
});

test('Fuzzer: does NOT false-positive SQLI_TIME on consistently slow server', async () => {
  const payload = "SLEEP(5)";
  const mockFetch = async () => {
    await new Promise(r => setTimeout(r, 140));
    return { status: 200, text: 'ok' };
  };

  const fuzzer = new Fuzzer(mockFetch);
  const results = await fuzzer.fuzz('https://example.com?id=1', payload, 'SQLI_TIME', { delayThresholdMs: 100 });
  assert.equal(results.length, 0);
});

test('Fuzzer: safely handles nullish responses and undefined res.text', async () => {
  const fuzzer = new Fuzzer(async () => ({ status: 200 }));
  const r1 = await fuzzer.fuzz('https://example.com?q=1', '<script>x</script>', 'XSS_REFLECTED');
  assert.deepEqual(r1, []);

  assert.equal(fuzzer.isVulnerable(null, 'x', 'XSS_REFLECTED', 0), false);
  assert.equal(fuzzer.isVulnerable(undefined, 'x', 'SQLI_ERROR', 0), false);
});

test('Fuzzer: fuzzDetailed exposes governanceError and networkSuccess=false on total failure', async () => {
  const govErr = new Error('Request blocked by SSRF policy');
  govErr.isGovernanceBlock = true;
  const govFuzzer = new Fuzzer(async () => { throw govErr; });

  const govDetail = await govFuzzer.fuzzDetailed('https://example.com?id=1&b=2', "'", 'SQLI_ERROR');
  assert.equal(govDetail.findings.length, 0);
  assert.equal(govDetail.networkSuccess, false);
  assert.equal(govDetail.governanceError, govErr);
  assert.equal(govDetail.attempted, 1);

  const netFuzzer = new Fuzzer(async () => { throw new Error('ECONNREFUSED'); });
  const netDetail = await netFuzzer.fuzzDetailed('https://example.com?id=1&b=2', "'", 'SQLI_ERROR');
  assert.equal(netDetail.findings.length, 0);
  assert.equal(netDetail.networkSuccess, false);
  assert.equal(netDetail.governanceError, null);
  assert.equal(netDetail.attempted, 2);
  assert.match(netDetail.lastError.message, /ECONNREFUSED/);
});

test('Fuzzer: fuzzes JSON API forms (contentType: json) and detects second-order STORED_REFLECTED payloads across verificationUrls', async () => {
  let storedNote = '';
  const capturedContentTypes = [];
  const payload = '<script>alert("stored_canary_99")</script>';

  const mockFetch = async (urlStr, opts = {}) => {
    const method = (opts.method || 'GET').toUpperCase();
    if (method === 'POST' && urlStr === 'https://example.com/api/orders/create') {
      capturedContentTypes.push(opts.headers?.['Content-Type']);
      const parsed = JSON.parse(opts.body || '{}');
      if (parsed.notes) storedNote = parsed.notes;
      if (String(parsed.customerId || '').includes("'")) {
        return {
          status: 500,
          headers: { 'content-type': 'application/json' },
          text: JSON.stringify({ error: 'You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version' })
        };
      }
      // Does NOT reflect synchronously in POST response
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        text: JSON.stringify({ status: 'saved' })
      };
    }
    if (method === 'GET' && urlStr === 'https://example.com/admin/orders/list') {
      return {
        status: 200,
        headers: { 'content-type': 'text/html' },
        text: `<html><body><div class="order-notes">${storedNote}</div></body></html>`
      };
    }
    return { status: 200, headers: { 'content-type': 'text/html' }, text: '<html></html>' };
  };

  const jsonForm = {
    pageUrl: 'https://example.com/admin/orders/create',
    actionUrl: 'https://example.com/api/orders/create',
    method: 'POST',
    contentType: 'json',
    formType: 'js_ajax_endpoint',
    fields: [
      { name: 'customerId', type: 'text', value: '100' },
      { name: 'notes', type: 'textarea', value: 'initial' }
    ],
    hiddenFields: {}
  };

  const fuzzer = new Fuzzer(mockFetch);

  // 1. Test JSON body SQLi detection
  const sqliDetail = await fuzzer.fuzzDetailed('https://example.com/admin/orders/create', "'", 'SQLI_ERROR', {
    discoveredForms: [jsonForm]
  });
  assert.ok(capturedContentTypes.includes('application/json'));
  assert.equal(sqliDetail.findings.length, 1);
  assert.equal(sqliDetail.findings[0].parameter, 'customerId');
  assert.equal(sqliDetail.findings[0].method, 'POST');

  // 2. Test Second-Order (Stored) reflection across verificationUrls
  const storedDetail = await fuzzer.fuzzDetailed(
    'https://example.com/admin/orders/create',
    payload,
    'XSS_REFLECTED',
    {
      discoveredForms: [jsonForm],
      verificationUrls: ['https://example.com/admin/orders/list']
    }
  );
  assert.ok(
    storedDetail.findings.some(
      f =>
        f.type === 'STORED_REFLECTED' &&
        f.parameter === 'notes' &&
        f.storedOnUrl === 'https://example.com/admin/orders/list'
    ),
    `Expected STORED_REFLECTED finding on notes (got ${JSON.stringify(storedDetail.findings)})`
  );
});
