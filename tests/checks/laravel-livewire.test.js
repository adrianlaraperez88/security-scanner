import { test } from 'node:test';
import assert    from 'node:assert/strict';
import { mockFetch, mockFetchMap, mockFetchError } from '../helpers/mock-fetch.js';
import run from '../../checks/laravel-livewire.js';

const BASE = 'https://example.com';

test('livewire: SAFE when all paths return 404', async () => {
  const r = await run(BASE, mockFetch({ status: 404, text: 'Not Found' }));
  assert.equal(r.status, 'SAFE');
  assert.equal(r.severity, 'NONE');
});

test('livewire: CRITICAL when /livewire/update returns 200 with Livewire JSON', async () => {
  const fetch = mockFetchMap({
    '/livewire/update': { status: 200, text: '{"html":"<div>test</div>","effects":{},"components":[]}' },
    '/livewire/livewire.js': { status: 200, text: 'Livewire.start()' }
  });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'CRITICAL');
  assert.equal(r.cve, 'CVE-2025-54068');
});

test('livewire: SAFE when /livewire/update returns 419 CSRF mismatch without vulnerable version, HIGH when vulnerable version (< 3.6.4) is disclosed or 422 returned', async () => {
  const safeCsrfFetch = mockFetchMap({
    '/livewire/livewire.js': { status: 200, text: 'Livewire.start() /* Livewire v3.6.4 */' },
    '/livewire/update': { status: 419, text: 'CSRF token mismatch' }
  });
  const rSafe = await run(BASE, safeCsrfFetch);
  assert.equal(rSafe.status, 'SAFE');

  const vulnVer419Fetch = mockFetchMap({
    '/livewire/livewire.js': { status: 200, text: 'Livewire.start() /* Livewire v3.5.0 */' },
    '/livewire/update': { status: 419, text: 'CSRF token mismatch' }
  });
  const rHigh = await run(BASE, vulnVer419Fetch);
  assert.equal(rHigh.status, 'SUSPICIOUS');
  assert.equal(rHigh.severity, 'HIGH');
  assert.equal(rHigh.cve, 'CVE-2025-54068');

  const unauth422Fetch = mockFetchMap({
    '/livewire/update': { status: 422, text: '{"message":"The components field is required."}' }
  });
  const r422 = await run(BASE, unauth422Fetch);
  assert.equal(r422.status, 'SUSPICIOUS');
  assert.equal(r422.severity, 'HIGH');
});

test('livewire: HIGH when /livewire/upload-file returns 422', async () => {
  const fetch = mockFetchMap({
    '/livewire/update'     : { status: 404, text: 'Not Found' },
    '/livewire/upload-file': { status: 422, text: '{"message":"validation error"}' }
  });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SUSPICIOUS');
  assert.equal(r.severity, 'HIGH');
  assert.equal(r.cve, 'CVE-2024-47823');
});

test('livewire: SAFE when Livewire JS found without vulnerable version and endpoints locked, MEDIUM when vulnerable version (< 3.6.4) is disclosed', async () => {
  const safeFetch = mockFetchMap({
    '/livewire/livewire.js': { status: 200, text: 'Livewire.start() window.livewire_token' },
    '/livewire/update'     : { status: 404, text: 'Not Found' },
    '/livewire/upload-file': { status: 404, text: 'Not Found' }
  });
  const rSafe = await run(BASE, safeFetch);
  assert.equal(rSafe.status, 'SAFE');

  const vulnJsFetch = mockFetchMap({
    '/livewire/livewire.js': { status: 200, text: 'Livewire.start() /* Livewire v3.6.2 */' },
    '/livewire/update'     : { status: 404, text: 'Not Found' },
    '/livewire/upload-file': { status: 404, text: 'Not Found' }
  });
  const rMed = await run(BASE, vulnJsFetch);
  assert.equal(rMed.status, 'SUSPICIOUS');
  assert.equal(rMed.severity, 'MEDIUM');
  assert.equal(rMed.version, '3.6.2');
});
