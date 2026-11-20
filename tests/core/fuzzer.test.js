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
