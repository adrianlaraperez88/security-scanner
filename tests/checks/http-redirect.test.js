import { test } from 'node:test';
import assert from 'node:assert/strict';
import run from '../../checks/http-redirect.js';
import { mockFetch, mockFetchError } from '../helpers/mock-fetch.js';
import { createGovernedFetch } from '../../core/fetch.js';
import { TrafficStore } from '../../core/traffic.js';

const BASE = 'https://example.com/app?next=/home';

test('http-redirect: uses fetchWithRetry (never raw globalThis.fetch), passes followRedirects: false, preserves path+query', async () => {
  const origFetch = globalThis.fetch;
  let seenUrl = null;
  let seenOpts = null;

  globalThis.fetch = async () => {
    throw new Error('globalThis.fetch must not be called by http-redirect');
  };

  try {
    const spyFetch = async (url, opts) => {
      seenUrl = url;
      seenOpts = opts;
      return {
        status: 301,
        headers: { location: 'HTTPS://example.com/app?next=/home' }
      };
    };

    const r = await run('https://example.com:8443/app?next=/home', spyFetch);
    assert.equal(r.name, 'https redirect');
    assert.equal(r.status, 'SAFE');
    assert.equal(r.severity, 'NONE');
    assert.equal(seenUrl, 'http://example.com/app?next=/home');
    assert.equal(seenOpts?.followRedirects, false);
  } finally {
    globalThis.fetch = origFetch;
  }
});

test('http-redirect: skips http:// targets safely and handles Headers instances', async () => {
  const skipped = await run('http://example.com/login', mockFetch({ status: 200 }));
  assert.equal(skipped.status, 'SAFE');

  const r = await run(BASE, async () => ({
    status: 302,
    headers: new Headers({ Location: 'https://example.com/app?next=/home' })
  }));
  assert.equal(r.status, 'SAFE');
  assert.match(r.detail, /302 temporary/);
});

test('http-redirect: VULNERABLE on HTTP 200 and SUSPICIOUS on non-HTTPS redirect', async () => {
  const vuln = await run(BASE, mockFetch({ status: 200, text: 'Plain HTTP' }));
  assert.equal(vuln.status, 'VULNERABLE');
  assert.equal(vuln.severity, 'MEDIUM');

  const susp = await run(BASE, mockFetch({ status: 302, headers: { location: 'http://other.example.com/' } }));
  assert.equal(susp.status, 'SUSPICIOUS');
  assert.equal(susp.severity, 'LOW');

  const missingLoc = await run(BASE, mockFetch({ status: 301, headers: {} }));
  assert.equal(missingLoc.status, 'SUSPICIOUS');
  assert.match(missingLoc.detail, /missing Location/i);
});

test('http-redirect: returns ERROR on invalid URL, network failure, and governance blocks (createGovernedFetch)', async () => {
  const bad = await run('not-a-url', mockFetch({ status: 200 }));
  assert.equal(bad.status, 'ERROR');

  const errRes = await run(BASE, mockFetchError('ECONNREFUSED'));
  assert.equal(errRes.status, 'ERROR');
  assert.match(errRes.reason, /ECONNREFUSED/);

  let fetcherCalls = 0;
  const blockedFetch = createGovernedFetch({
    allowPrivate: false,
    scopeRules: [{ ruleType: 'fuzzy_domain', pattern: '*.allowed.example', isAllowed: true }],
    retries: 0,
    fetcher: async () => {
      fetcherCalls += 1;
      return new Response('', { status: 301, headers: { location: 'https://allowed.example/' } });
    }
  });

  for (const blockedTarget of [
    'https://127.0.0.1/',
    'https://portal.gov/',
    'https://evil.example/'
  ]) {
    const r = await run(blockedTarget, blockedFetch);
    assert.equal(r.status, 'ERROR', `Expected ERROR for blocked target ${blockedTarget}`);
  }
  assert.equal(fetcherCalls, 0);

  // allowPrivate: true permits private IP and logs to TrafficStore
  const trafficStore = new TrafficStore();
  const privFetch = createGovernedFetch({
    allowPrivate: true,
    trafficStore,
    retries: 0,
    fetcher: async () => new Response('ok', { status: 200 })
  });
  const privRes = await run('https://192.168.1.10/app', privFetch);
  assert.equal(privRes.status, 'VULNERABLE');
  assert.ok(privRes.trafficId);
  trafficStore.close();
});
