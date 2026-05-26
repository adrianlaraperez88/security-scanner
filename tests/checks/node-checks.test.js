import { test } from 'node:test';
import assert    from 'node:assert/strict';
import { mockFetch, mockFetchError } from '../helpers/mock-fetch.js';
import run from '../../checks/node-checks.js';

const BASE = 'https://example.com';

test('node: VULNERABLE when package.json found', async () => {
  const fetch = (url) => {
    if (url.includes('package.json')) {
      return { status: 200, text: '{"name": "test", "dependencies": {"express": "4.18.2"}}' };
    }
    return { status: 404, text: 'not found' };
  };
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'MEDIUM');
  assert.ok(r.findings.some(f => f.name === 'node package metadata disclosure'));
});

test('node: VULNERABLE when node_modules exposed', async () => {
  const fetch = (url) => {
    if (url.includes('/node_modules/express/package.json')) {
      return { status: 200, text: '{"name": "express", "version": "4.18.2"}' };
    }
    return { status: 404, text: 'not found' };
  };
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'HIGH');
  assert.ok(r.findings.some(f => f.name === 'node_modules directory exposure'));
});

test('node: SUSPICIOUS when Express header found', async () => {
  const fetch = (url) => {
    if (url === BASE) {
      return { status: 200, text: 'ok', headers: { 'x-powered-by': 'Express' } };
    }
    return { status: 404, headers: {} };
  };
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SUSPICIOUS');
  assert.equal(r.severity, 'LOW');
});

test('node: SAFE when nothing found', async () => {
  const fetch = mockFetch({ status: 404, text: 'Not Found' });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SAFE');
});
