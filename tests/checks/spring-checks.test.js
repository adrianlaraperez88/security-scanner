import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mockFetch, mockFetchError } from '../helpers/mock-fetch.js';
import run from '../../checks/spring-checks.js';

const BASE = 'https://example.com';

test('spring-checks: CRITICAL on /actuator/env and /actuator/heapdump', async () => {
  const fetch = async (url) => {
    if (url === `${BASE}/actuator/env`) {
      return {
        status: 200,
        headers: {},
        text: '{"activeProfiles":["prod"],"propertySources":[{"name":"systemEnvironment"}]}'
      };
    }
    if (url === `${BASE}/actuator/heapdump`) {
      return {
        status: 200,
        headers: { 'content-type': 'application/octet-stream' },
        text: 'JAVA PROFILE 1.0.2'
      };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  };

  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'CRITICAL');
  assert.ok(r.findings.some(f => f.name === 'exposed spring boot actuator env' && f.severity === 'CRITICAL'));
  assert.ok(r.findings.some(f => f.name === 'exposed spring boot actuator heapdump' && f.severity === 'CRITICAL'));
});

test('spring-checks: HIGH on /actuator/mappings', async () => {
  const fetch = async (url) => {
    if (url === `${BASE}/actuator/mappings`) {
      return {
        status: 200,
        headers: {},
        text: '{"contexts":{"application":{"mappings":{"dispatcherServlets":{"dispatcherServlet":[]}}}}}'
      };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  };

  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'HIGH');
  assert.ok(r.findings.some(f => f.name === 'exposed spring boot actuator mappings' && f.severity === 'HIGH'));
});

test('spring-checks: MEDIUM on /v3/api-docs', async () => {
  const fetch = async (url) => {
    if (url === `${BASE}/v3/api-docs`) {
      return {
        status: 200,
        headers: {},
        text: '{"openapi":"3.0.1","info":{"title":"API"},"paths":{"/users":{}}}'
      };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  };

  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SUSPICIOUS');
  assert.equal(r.severity, 'MEDIUM');
  assert.ok(r.findings.some(f => f.name === 'exposed spring openapi docs' && f.severity === 'MEDIUM'));
});

test('spring-checks: SAFE when all endpoints return 404', async () => {
  const fetch = mockFetch({ status: 404, text: 'Not Found' });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SAFE');
  assert.equal(r.severity, 'NONE');
});

test('spring-checks: ERROR when all requests throw', async () => {
  const r = await run(BASE, mockFetchError('network error'));
  assert.equal(r.status, 'ERROR');
  assert.equal(r.severity, 'NONE');
});
