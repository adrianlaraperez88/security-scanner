import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mockFetch, mockFetchError } from '../helpers/mock-fetch.js';
import run from '../../checks/sri-supply-chain.js';

const BASE = 'https://example.com';

test('sri-supply-chain: CRITICAL+VULNERABLE on polyfill.io and bootcss.com scripts', async () => {
  const fetch = mockFetch({
    status: 200,
    text: `
      <html>
        <head>
          <script src="https://cdn.polyfill.io/v3/polyfill.min.js"></script>
          <script src="https://cdn.bootcss.com/jquery/3.4.1/jquery.min.js" integrity="sha384-abc"></script>
        </head>
      </html>
    `
  });

  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'CRITICAL');
  assert.ok(r.findings.some(f => f.name === 'compromised cdn script domain' && f.severity === 'CRITICAL'));
});

test('sri-supply-chain: SUSPICIOUS on external CDN scripts missing integrity attribute', async () => {
  const fetch = mockFetch({
    status: 200,
    text: `
      <html>
        <head>
          <script src="https://cdn.jsdelivr.net/npm/vue@3/dist/vue.global.js"></script>
          <script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
          <script src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js"></script>
        </head>
      </html>
    `
  });

  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SUSPICIOUS');
  assert.equal(r.severity, 'MEDIUM');
  assert.ok(r.findings.some(f => f.name === 'external scripts missing sri'));
});

test('sri-supply-chain: SAFE when external scripts have integrity="sha384-..." or are same-origin', async () => {
  const fetch = mockFetch({
    status: 200,
    text: `
      <html>
        <head>
          <script src="/static/js/main.js"></script>
          <script src="https://example.com/assets/vendor.js"></script>
          <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js" integrity="sha384-1H217gwSVyLSIfaLxHbE7dRb3v4mYCKbpQvzx0cegeju1MVsGrX5xXxAvs/HgeFs" crossorigin="anonymous"></script>
        </head>
      </html>
    `
  });

  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SAFE');
  assert.equal(r.severity, 'NONE');
});

test('sri-supply-chain: ERROR on fetch failure', async () => {
  const r = await run(BASE, mockFetchError('timeout'));
  assert.equal(r.status, 'ERROR');
  assert.equal(r.severity, 'NONE');
});
