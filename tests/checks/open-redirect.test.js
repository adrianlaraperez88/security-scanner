import { test } from 'node:test';
import assert from 'node:assert/strict';
import run from '../../checks/open-redirect.js';
import { mockFetch, mockFetchError } from '../helpers/mock-fetch.js';
import { createGovernedFetch } from '../../core/fetch.js';

const BASE = 'https://example.com/login?next=/home';

test('open-redirect: uses fetchWithRetry with followRedirects: false and normalizes existing query params', async () => {
  const origFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    throw new Error('globalThis.fetch must not be called by open-redirect');
  };

  const seenUrls = [];
  try {
    const spyFetch = async (url, opts) => {
      seenUrls.push({ url, followRedirects: opts?.followRedirects });
      return { status: 200, headers: {} };
    };

    const r = await run(BASE, spyFetch);
    assert.equal(r.name, 'open redirect');
    assert.equal(r.status, 'SAFE');
    assert.ok(seenUrls.length > 0);
    for (const call of seenUrls) {
      assert.equal(call.followRedirects, false);
      assert.equal(call.url.split('?').length, 2, `Malformed URL with multiple ?: ${call.url}`);
    }
  } finally {
    globalThis.fetch = origFetch;
  }
});

test('open-redirect: detects external redirect (plain headers, Headers instance, protocol-relative) without FP on query param', async () => {
  const vulnPlain = await run('https://example.com/go', async (url) => {
    if (url.includes('redirect=')) {
      return { status: 302, headers: { Location: 'https://evil.attacker.example.com/phish' } };
    }
    return { status: 200, headers: {} };
  });
  assert.equal(vulnPlain.status, 'VULNERABLE');
  assert.equal(vulnPlain.severity, 'MEDIUM');

  const vulnHeaders = await run('https://example.com/go', async () => ({
    status: 307,
    headers: new Headers({ location: '//evil.attacker.example.com/login' })
  }));
  assert.equal(vulnHeaders.status, 'VULNERABLE');

  // Same-host redirect containing evil host only inside query string must NOT FP
  const fpSafe = await run('https://example.com/go', mockFetch({
    status: 302,
    headers: { location: '/login?err=https://evil.attacker.example.com' }
  }));
  assert.equal(fpSafe.status, 'SAFE');
});

test('open-redirect: partial transient errors still return SAFE if at least one request succeeds, all-fail returns ERROR', async () => {
  let count = 0;
  const partialFetch = async () => {
    count += 1;
    if (count === 1) throw new Error('transient timeout');
    return { status: 200, headers: {} };
  };
  const ok = await run('https://example.com/', partialFetch);
  assert.equal(ok.status, 'SAFE');

  const allFail = await run('https://example.com/', mockFetchError('ECONNREFUSED'));
  assert.equal(allFail.status, 'ERROR');
  assert.match(allFail.reason, /ECONNREFUSED/);

  const badUrl = await run('not-a-url', mockFetch({ status: 200 }));
  assert.equal(badUrl.status, 'ERROR');
});

test('open-redirect: fails immediately with ERROR on governance blocks and supports allowPrivate: true', async () => {
  let fetcherCalls = 0;
  const blockedFetch = createGovernedFetch({
    allowPrivate: false,
    enforceDnsValidation: true,
    dnsResolver: async () => ['127.0.0.1'],
    retries: 0,
    fetcher: async () => {
      fetcherCalls += 1;
      return new Response('', { status: 200 });
    }
  });

  const govBlock = await run('https://portal.gov/', blockedFetch);
  assert.equal(govBlock.status, 'ERROR');
  assert.equal(fetcherCalls, 0);

  const dnsBlock = await run('https://rebind.example/', blockedFetch);
  assert.equal(dnsBlock.status, 'ERROR');
  assert.equal(fetcherCalls, 0);

  // Spy governance block stops on 1st parameter without iterating all 15
  let attempts = 0;
  const spyGov = async () => {
    attempts += 1;
    const err = new Error('Request blocked by SSRF policy');
    err.isGovernanceBlock = true;
    throw err;
  };
  const immediate = await run('https://example.com/', spyGov);
  assert.equal(immediate.status, 'ERROR');
  assert.equal(attempts, 1);

  const privFetch = createGovernedFetch({
    allowPrivate: true,
    retries: 0,
    fetcher: async () => new Response('', {
      status: 302,
      headers: { location: 'https://evil.attacker.example.com' }
    })
  });
  const privRes = await run('http://10.0.0.5/login', privFetch);
  assert.equal(privRes.status, 'VULNERABLE');
});
