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

test('Fuzzer: detects time-based SQLi', async () => {
  const payload = "SLEEP(5)";
  const mockFetch = async () => {
    await new Promise(r => setTimeout(r, 5000));
    return { status: 200, text: 'ok' };
  };

  const fuzzer = new Fuzzer(mockFetch);
  const results = await fuzzer.fuzz('https://example.com?id=1', payload, 'SQLI_TIME');
  
  assert.equal(results.length, 1);
  assert.equal(results[0].type, 'SQLI_TIME');
});
