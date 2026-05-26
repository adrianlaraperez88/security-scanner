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

test('livewire: HIGH when /livewire/update returns 419 (CSRF protected but exists)', async () => {
  const fetch = mockFetchMap({
    '/livewire/update': { status: 419, text: 'CSRF token mismatch' }
  });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SUSPICIOUS');
  assert.equal(r.severity, 'HIGH');
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

test('livewire: MEDIUM when Livewire JS found but endpoints locked', async () => {
  const fetch = mockFetchMap({
    '/livewire/livewire.js': { status: 200, text: 'Livewire.start() window.livewire_token' },
    '/livewire/update'     : { status: 404, text: 'Not Found' },
    '/livewire/upload-file': { status: 404, text: 'Not Found' }
  });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SUSPICIOUS');
  assert.equal(r.severity, 'MEDIUM');
});
