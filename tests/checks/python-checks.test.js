import { test } from 'node:test';
import assert    from 'node:assert/strict';
import { mockFetch, mockFetchError } from '../helpers/mock-fetch.js';
import run from '../../checks/python-checks.js';

const BASE = 'https://example.com';

test('python: VULNERABLE when requirements.txt found', async () => {
  const fetch = (url) => {
    if (url.includes('requirements.txt')) {
      return { status: 200, text: 'django==4.2.1\nrequests>=2.25.1' };
    }
    return { status: 404, text: 'not found' };
  };
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'MEDIUM');
  assert.ok(r.findings.some(f => f.name === 'python requirements disclosure'));
});

test('python: CRITICAL when Django debug mode found', async () => {
  const fetch = (url) => {
    if (url.includes('_non_existent_path')) {
      return { status: 404, text: 'Debug mode is on. Using the URLconf defined in project.urls, Django tried these URL patterns...' };
    }
    return { status: 404, text: 'not found' };
  };
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'CRITICAL');
  assert.ok(r.findings.some(f => f.name === 'django debug mode enabled'));
});

test('python: CRITICAL when Flask debugger found', async () => {
  const fetch = (url) => {
    if (url.includes('_non_existent_path')) {
      return { status: 500, text: 'The debugger is active! Werkzeug Debugger' };
    }
    return { status: 404, text: 'not found' };
  };
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'CRITICAL');
  assert.ok(r.findings.some(f => f.name === 'flask/werkzeug debugger active'));
});

test('python: SAFE when nothing found', async () => {
  const fetch = mockFetch({ status: 404, text: 'Not Found' });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SAFE');
  assert.equal(r.severity, 'NONE');
});
