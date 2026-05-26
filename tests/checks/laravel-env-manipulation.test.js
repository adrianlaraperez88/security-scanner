import { test } from 'node:test';
import assert    from 'node:assert/strict';
import { mockFetchMap, mockFetchError } from '../helpers/mock-fetch.js';
import run from '../../checks/laravel-env-manipulation.js';

const BASE = 'https://example.com';

const NORMAL_PAGE = { status: 200, text: '<html><head><title>App</title></head><body>Welcome</body></html>' };
const DEBUG_PAGE  = { status: 200, text: '<html><body>Whoops\nAPP_ENV=local\nvendor/laravel/framework\n#0 /var/www...</body></html>' };
const ERROR_PAGE  = { status: 500, text: 'Internal Server Error' };

test('laravel-env-manipulation: SAFE when both baseline and attack responses are identical', async () => {
  const r = await run(BASE, mockFetchMap({ '': NORMAL_PAGE }));
  assert.equal(r.status, 'SAFE');
  assert.equal(r.severity, 'NONE');
});

test('laravel-env-manipulation: HIGH when ?--env=local triggers Whoops debug output', async () => {
  const fetch = mockFetchMap({
    '/?--env=local'   : DEBUG_PAGE,
    '/?--env=testing' : DEBUG_PAGE,
    '/'               : NORMAL_PAGE,
  });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'HIGH');
  assert.equal(r.cve, 'CVE-2024-52301');
  assert.ok(r.signals?.length > 0);
});

test('laravel-env-manipulation: MEDIUM when status changes from 200 to 500', async () => {
  const fetch = mockFetchMap({
    '/?--env=local'   : ERROR_PAGE,
    '/?--env=testing' : ERROR_PAGE,
    '/'               : NORMAL_PAGE,
  });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SUSPICIOUS');
  assert.equal(r.severity, 'MEDIUM');
});

test('laravel-env-manipulation: ERROR when baseline request fails', async () => {
  const r = await run(BASE, mockFetchError('timeout'));
  assert.equal(r.status, 'ERROR');
});
