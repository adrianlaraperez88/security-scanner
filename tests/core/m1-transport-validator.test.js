import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import {
  normalizeTargetInput,
  validateTargetUrl,
  validateTargets,
  voidsExemption,
  isPrivateOrReservedIP,
  resolveAndValidateTarget
} from '../../core/validator.js';
import { TargetPinStore } from '../../core/guard.js';
import { fetchWithRetry, createGovernedFetch } from '../../core/fetch.js';
import { AuthSessionManager } from '../../core/auth-session.js';
import { createTrackedFetch } from '../../core/reproduction.js';

describe('M1: Target Normalization & Validator', () => {
  test('normalizeTargetInput strips outer quotes and trailing backslashes/slashes while inferring scheme cleanly', () => {
    assert.equal(normalizeTargetInput('"192.168.68.53\\"'), 'http://192.168.68.53');
    assert.equal(normalizeTargetInput('192.168.68.53"'), 'http://192.168.68.53');
    assert.equal(normalizeTargetInput('"192.168.68.53"\\'), 'http://192.168.68.53');
    assert.equal(normalizeTargetInput("'192.168.68.53:8443'"), 'https://192.168.68.53:8443');
    assert.equal(normalizeTargetInput('192.168.68.53:443/'), 'https://192.168.68.53:443');
    assert.equal(normalizeTargetInput('192.168.68.53:8080\\'), 'http://192.168.68.53:8080');
    assert.equal(normalizeTargetInput('http://192.168.68.53\\'), 'http://192.168.68.53');
    assert.equal(normalizeTargetInput('https://192.168.68.53:8443/'), 'https://192.168.68.53:8443');
    assert.equal(normalizeTargetInput('nas.local\\'), 'https://nas.local');
    assert.equal(normalizeTargetInput('nas.local:80\\'), 'http://nas.local:80');
    assert.equal(normalizeTargetInput('example.com/'), 'https://example.com');
    assert.equal(normalizeTargetInput('localhost:3000\\'), 'http://localhost:3000');
    assert.equal(normalizeTargetInput('localhost:443'), 'https://localhost:443');
    assert.equal(normalizeTargetInput('::1'), 'http://[::1]');
    assert.equal(normalizeTargetInput('2001:db8::1/status'), 'http://[2001:db8::1]/status');
    assert.equal(normalizeTargetInput('[::1]:8443\\'), 'https://[::1]:8443');
    assert.equal(normalizeTargetInput('[::1]:8001'), 'http://[::1]:8001');
  });

  test('normalizeTargetInput handles empty/non-string inputs and preserves non-HTTP schemes and internal SSRF backslashes', () => {
    assert.equal(normalizeTargetInput(''), '');
    assert.equal(normalizeTargetInput('   '), '');
    assert.equal(normalizeTargetInput('""'), '');
    assert.equal(normalizeTargetInput("''"), '');
    assert.equal(normalizeTargetInput('\\'), '');
    assert.equal(normalizeTargetInput(null), '');
    assert.equal(normalizeTargetInput(undefined), '');
    assert.equal(normalizeTargetInput(123), '');

    assert.equal(normalizeTargetInput('file:///etc/passwd'), 'file:///etc/passwd');
    assert.equal(normalizeTargetInput('javascript:alert(1)'), 'javascript:alert(1)');
    assert.equal(normalizeTargetInput('https://example.com/a\\b'), 'https://example.com/a\\b');
    assert.equal(normalizeTargetInput('http://127.0.0.1/\\admin'), 'http://127.0.0.1/\\admin');
    assert.equal(normalizeTargetInput('http://example.com\\@127.0.0.1'), 'http://example.com\\@127.0.0.1');
  });

  test('validateTargetUrl remains strict by default and supports { normalize: true }; validateTargets defaults to { normalize: true }', () => {
    assert.equal(validateTargetUrl('"192.168.68.53\\"', { allowPrivate: true }).valid, false);
    assert.equal(validateTargetUrl('192.168.68.53"', { allowPrivate: true }).valid, false);

    const optIn = validateTargetUrl('"192.168.68.53\\"', { allowPrivate: true, normalize: true });
    assert.equal(optIn.valid, true);
    assert.equal(optIn.normalized, 'http://192.168.68.53');

    const batchPrivate = validateTargets(
      ['"192.168.68.53\\"', '192.168.68.53"', 'http://192.168.68.53\\', 'nas.local\\'],
      { allowPrivate: true }
    );
    assert.equal(batchPrivate.valid, true);
    assert.deepEqual(batchPrivate.targets, [
      'http://192.168.68.53',
      'http://192.168.68.53',
      'http://192.168.68.53',
      'https://nas.local'
    ]);

    // SSRF internal backslashes & non-HTTP schemes MUST still fail validateTargets
    for (const bad of [
      'https://example.com/a\\b',
      'http://127.0.0.1/\\admin',
      'http://example.com\\@127.0.0.1',
      '127.0.0.1\\@evil.com',
      'file:///etc/passwd',
      'javascript:alert(1)'
    ]) {
      const res = validateTargets([bad], { allowPrivate: true });
      assert.equal(res.valid, false, `Expected validateTargets(["${bad}"]) to reject`);
    }
  });

  test('validateTargetUrl rejects ASCII control chars and tab-smuggled obfuscated IPs across all option combinations', () => {
    const smuggledUrls = [
      'http://0x7f\t000001/',
      'http://0x7f000001:\t80/',
      'http://0x5d\tb8d822/',
      'http://0177\t.0.0.1/',
      'http://127\t.1/',
      'http://213070\t6433/',
      'http://192.168.68.53/\r\nHost: evil.com',
      'http://192.168.68.53/\x00admin',
      'http://example.com/\x00'
    ];

    for (const bad of smuggledUrls) {
      for (const allowPrivate of [false, true]) {
        for (const normalize of [false, true]) {
          const res = validateTargetUrl(bad, { allowPrivate, normalize });
          assert.equal(
            res.valid,
            false,
            `Expected validateTargetUrl(${JSON.stringify(bad)}, { allowPrivate: ${allowPrivate}, normalize: ${normalize} }) to reject`
          );
        }
      }
    }
  });
});

describe('M1: fetchWithRetry Options, failFast, Timer Cleanup & Wrapper Forwarding', () => {
  test('fetchWithRetry honors options.retries = 0 and ignores null/empty/boolean coercion', async () => {
    let attempts = 0;
    const flakyFetcher = async () => {
      attempts++;
      const err = new Error('transient');
      err.code = 'ECONNRESET';
      throw err;
    };

    await assert.rejects(
      () => fetchWithRetry('https://example.com/', { retries: 0, fetcher: flakyFetcher }, 2, 1000),
      /Fetch failed: transient/
    );
    assert.equal(attempts, 1, 'options.retries = 0 must execute only 1 attempt');

    // Invalid/null/empty options.retries must fall back to positional retries (1 -> 2 attempts)
    attempts = 0;
    await assert.rejects(
      () => fetchWithRetry('https://example.com/', { retries: null, timeout: '', fetcher: flakyFetcher }, 1, 1000),
      /Fetch failed: transient/
    );
    assert.equal(attempts, 2, 'null options.retries must fall back to positional retries=1');
  });

  test('fetchWithRetry honors options.timeout and does not leak retries/timeout/failFast into activeFetcher RequestInit', async () => {
    let seenInit = null;
    const slowOrCleanFetcher = async (_url, init) => {
      seenInit = init;
      return new Promise((resolve, reject) => {
        const t = setTimeout(() => resolve({ status: 200, headers: {}, text: 'ok' }), 400);
        init.signal?.addEventListener('abort', () => {
          clearTimeout(t);
          const err = new Error('The operation was aborted');
          err.name = 'AbortError';
          reject(err);
        }, { once: true });
      });
    };

    await assert.rejects(
      () => fetchWithRetry('https://example.com/', {
        retries: 0,
        timeout: 40,
        failFast: true,
        guard: () => ({ allowed: true }),
        fetcher: slowOrCleanFetcher
      }, 2, 10000),
      /Fetch failed/
    );

    assert.ok(seenInit);
    assert.equal('retries' in seenInit, false);
    assert.equal('timeout' in seenInit, false);
    assert.equal('failFast' in seenInit, false);
    assert.equal('guard' in seenInit, false);
  });

  test('fetchWithRetry failFast short-circuits retries immediately on ECONNREFUSED, ETIMEDOUT, AbortError, and Undici cause.code', async () => {
    const cases = [
      () => Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }),
      () => Object.assign(new Error('connect ETIMEDOUT'), { code: 'ETIMEDOUT' }),
      () => Object.assign(new Error('network unreachable'), { code: 'ENETUNREACH' }),
      () => Object.assign(new Error('The operation was aborted'), { name: 'AbortError' }),
      () => Object.assign(new TypeError('fetch failed'), {
        cause: Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:80'), { code: 'ECONNREFUSED' })
      }),
      () => Object.assign(new TypeError('fetch failed'), {
        cause: { errors: [Object.assign(new Error('connect EHOSTUNREACH'), { code: 'EHOSTUNREACH' })] }
      })
    ];

    for (const makeErr of cases) {
      let attempts = 0;
      const start = Date.now();
      let caught = null;
      try {
        await fetchWithRetry('https://example.com/', {
          retries: 3,
          failFast: true,
          fetcher: async () => {
            attempts++;
            throw makeErr();
          }
        });
      } catch (err) {
        caught = err;
      }
      const elapsed = Date.now() - start;
      assert.ok(caught, 'Expected fetchWithRetry to throw');
      assert.equal(attempts, 1, `failFast must stop after 1 attempt (got ${attempts})`);
      assert.ok(elapsed < 350, `failFast must not sleep 500ms+ backoff (took ${elapsed}ms)`);
    }

    // Verify .cause.code promotion onto wrapped.code
    let wrappedErr = null;
    try {
      await fetchWithRetry('https://example.com/', {
        retries: 0,
        fetcher: async () => {
          throw Object.assign(new TypeError('fetch failed'), {
            cause: Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' })
          });
        }
      });
    } catch (err) {
      wrappedErr = err;
    }
    assert.equal(wrappedErr?.code, 'ECONNREFUSED');

    // Verify direct AggregateError with empty message short-circuits failFast (1 attempt) and preserves .code
    let aggAttempts = 0;
    let aggWrapped = null;
    const aggStart = Date.now();
    try {
      await fetchWithRetry('https://example.com/', {
        retries: 2,
        timeout: 150,
        failFast: true,
        fetcher: async () => {
          aggAttempts++;
          throw new AggregateError(
            [Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:80'), { code: 'ECONNREFUSED' })],
            ''
          );
        }
      });
    } catch (err) {
      aggWrapped = err;
    }
    const aggElapsed = Date.now() - aggStart;
    assert.equal(aggAttempts, 1, `Direct AggregateError failFast must execute 1 attempt (got ${aggAttempts})`);
    assert.ok(aggElapsed < 350, `Direct AggregateError failFast must not sleep retry backoff (took ${aggElapsed}ms)`);
    assert.equal(aggWrapped?.code, 'ECONNREFUSED');
  });

  test('fetchWithRetry failFast traverses nested AggregateError, multi-hop cause chains, and guards cyclic error graphs', async () => {
    const nestedEconnrefused = () => new AggregateError(
      [new AggregateError([Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' })], '')],
      ''
    );
    const nestedAbort = () => new AggregateError(
      [new AggregateError([Object.assign(new Error('aborted'), { name: 'AbortError' })], '')],
      ''
    );
    const nestedTimeout = () => new AggregateError(
      [new AggregateError([Object.assign(new Error('timed out'), { name: 'TimeoutError' })], '')],
      ''
    );
    const causeNestedEconnrefused = () => new TypeError('fetch failed', {
      cause: new AggregateError(
        [new AggregateError([Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' })], '')],
        ''
      )
    });

    for (const [label, makeErr, expectedCode] of [
      ['nested-agg-econnrefused', nestedEconnrefused, 'ECONNREFUSED'],
      ['nested-agg-aborterror', nestedAbort, undefined],
      ['nested-agg-timeouterror', nestedTimeout, undefined],
      ['cause-nested-agg-econnrefused', causeNestedEconnrefused, 'ECONNREFUSED']
    ]) {
      let attempts = 0;
      let caught = null;
      const start = Date.now();
      try {
        await fetchWithRetry('https://example.com/', {
          retries: 2,
          timeout: 150,
          failFast: true,
          fetcher: async () => {
            attempts++;
            throw makeErr();
          }
        });
      } catch (err) {
        caught = err;
      }
      const elapsed = Date.now() - start;
      assert.ok(caught, `${label}: expected fetchWithRetry to throw`);
      assert.equal(attempts, 1, `${label}: failFast must execute 1 attempt (got ${attempts})`);
      assert.ok(elapsed < 350, `${label}: failFast must not sleep retry backoff (took ${elapsed}ms)`);
      assert.equal(caught.code, expectedCode, `${label}: expected wrapped.code=${expectedCode}`);
    }

    // Cyclic .cause and .errors references must not infinite-loop or throw RangeError
    let cyclicTransientAttempts = 0;
    await assert.rejects(
      () => fetchWithRetry('https://example.com/', {
        retries: 1,
        timeout: 150,
        failFast: true,
        fetcher: async () => {
          cyclicTransientAttempts++;
          const a = new Error('transient');
          const b = new AggregateError([a], '');
          a.cause = b;
          b.cause = a;
          b.errors.push(b);
          throw b;
        }
      }),
      /Fetch failed/
    );
    assert.equal(cyclicTransientAttempts, 2, 'Cyclic non-failFast error should complete normal retries without hanging');

    // Cyclic graph with a sibling ECONNREFUSED must still detect failFast and extract code
    let cyclicFailFastAttempts = 0;
    let cyclicWrapped = null;
    const cyclicStart = Date.now();
    try {
      await fetchWithRetry('https://example.com/', {
        retries: 2,
        timeout: 150,
        failFast: true,
        fetcher: async () => {
          cyclicFailFastAttempts++;
          const loopA = new Error('wrapper');
          loopA.cause = loopA;
          const leaf = Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' });
          const agg = new AggregateError([loopA, leaf], '');
          agg.cause = agg;
          throw agg;
        }
      });
    } catch (err) {
      cyclicWrapped = err;
    }
    const cyclicElapsed = Date.now() - cyclicStart;
    assert.equal(cyclicFailFastAttempts, 1);
    assert.ok(cyclicElapsed < 350, `Cyclic failFast must short-circuit promptly (took ${cyclicElapsed}ms)`);
    assert.equal(cyclicWrapped?.code, 'ECONNREFUSED');
  });

  test('fetchWithRetry supports live closed-port ECONNREFUSED failFast and external AbortSignal cleanup', async () => {
    // Bind an ephemeral server then close it immediately to get a guaranteed closed local port
    const srv = net.createServer();
    await new Promise(resolve => srv.listen(0, '127.0.0.1', resolve));
    const { port } = srv.address();
    await new Promise(resolve => srv.close(resolve));

    const start = Date.now();
    let caught = null;
    try {
      await fetchWithRetry(`http://127.0.0.1:${port}/`, {
        allowPrivate: true,
        retries: 2,
        timeout: 2000,
        failFast: true
      });
    } catch (err) {
      caught = err;
    }
    const elapsed = Date.now() - start;
    assert.ok(caught, 'Closed port should reject');
    assert.ok(elapsed < 450, `Live closed-port failFast should return promptly without 500ms retry sleep (took ${elapsed}ms)`);

    // External signal pre-aborted should reject without invoking fetcher
    const ac = new AbortController();
    ac.abort();
    let fetcherCalled = false;
    await assert.rejects(
      () => fetchWithRetry('https://example.com/', {
        retries: 2,
        signal: ac.signal,
        fetcher: async () => {
          fetcherCalled = true;
          return { status: 200, headers: {}, text: 'ok' };
        }
      }),
      /Fetch failed/
    );
    assert.equal(fetcherCalled, false);
  });

  test('AuthSessionManager.wrapFetch + createTrackedFetch forward (...rest) and preserve hasCustomFetcher & metadata', async () => {
    const calls = [];
    const governedFetch = createGovernedFetch({
      allowPrivate: true,
      fetcher: async (url, opts) => {
        calls.push({ url, opts });
        return { status: 200, headers: { 'set-cookie': 'sid=abc; Path=/' }, text: 'ok' };
      }
    });
    assert.equal(governedFetch.hasCustomFetcher, true);

    const auth = new AuthSessionManager({ target: 'https://example.com' });
    const authWrapped = auth.wrapFetch(governedFetch);
    assert.equal(authWrapped.hasCustomFetcher, true);
    assert.equal(authWrapped.governance, governedFetch.governance);
    assert.equal(authWrapped.guard, governedFetch.guard);

    const tracked = createTrackedFetch(authWrapped);
    assert.equal(tracked.hasCustomFetcher, true);
    assert.equal(tracked.governance, governedFetch.governance);

    // Verify positional args (retries=0, timeout=120) survive createTrackedFetch -> auth.wrapFetch -> governedFetch
    const slowBase = async (url, opts, retries, timeout) => {
      calls.push({ url, opts, retries, timeout });
      return { status: 200, headers: {}, text: 'ok' };
    };
    slowBase.hasCustomFetcher = false;
    slowBase.governance = { allowPrivate: false };
    slowBase.guard = { id: 'g1' };
    slowBase.governor = { id: 'gov1' };
    slowBase.trafficStore = { id: 'ts1' };

    const chained = createTrackedFetch(auth.wrapFetch(slowBase));
    assert.equal(chained.hasCustomFetcher, false);
    assert.deepEqual(chained.guard, { id: 'g1' });
    assert.deepEqual(chained.governor, { id: 'gov1' });
    assert.deepEqual(chained.trafficStore, { id: 'ts1' });

    await chained('https://example.com/test', { headers: { 'X-Test': '1' } }, 0, 120);
    const lastCall = calls[calls.length - 1];
    assert.equal(lastCall.retries, 0);
    assert.equal(lastCall.timeout, 120);
  });

  test('FINDING-1 regression: voidsExemption, isPrivateOrReservedIP, resolveAndValidateTarget, TargetPinStore, and createGovernedFetch reject ::ffff:0:0:0/96 IPv4-translated private IPs', async () => {
    const privateTranslated = [
      '::ffff:0:127.0.0.1',
      '::ffff:0:10.0.0.1',
      '::ffff:0:192.168.1.1',
      '::ffff:0:172.16.0.1',
      '::ffff:0:100.64.0.1',
      '::ffff:0:7f00:1'
    ];

    for (const ip of privateTranslated) {
      assert.equal(voidsExemption(ip), true, `Expected voidsExemption("${ip}") to be true`);
      assert.equal(isPrivateOrReservedIP(ip), true, `Expected isPrivateOrReservedIP("${ip}") to be true`);

      const dnsRes = await resolveAndValidateTarget('https://rebind.example.com', {
        allowPrivate: false,
        resolver: async () => [{ address: ip, family: 6 }]
      });
      assert.equal(dnsRes.valid, false, `Expected resolveAndValidateTarget to reject ${ip}`);
      assert.equal(dnsRes.code, 'DNS_REBIND_OR_PRIVATE_IP');

      const pinStore = new TargetPinStore({ allowPrivate: false });
      const pinRes = pinStore.verifyOrPin('rebind.example.com', [ip]);
      assert.equal(pinRes.valid, false, `Expected TargetPinStore.verifyOrPin to reject ${ip}`);
      assert.equal(pinRes.code, 'DNS_REBIND_OR_PRIVATE_IP');

      let dialerCalled = false;
      const governed = createGovernedFetch({
        allowPrivate: false,
        dnsResolver: async () => [{ address: ip, family: 6 }],
        retries: 0,
        baseDialer: async () => {
          dialerCalled = true;
          return { status: 200, headers: {}, text: 'should not dial' };
        }
      });
      await assert.rejects(
        () => governed('https://rebind.example.com/'),
        (err) => err?.isGovernanceBlock === true && err?.code === 'DNS_REBIND_OR_PRIVATE_IP'
      );
      assert.equal(dialerCalled, false, `Expected baseDialer not to be called for ${ip}`);
    }

    // Public IPv4-translated IPv6 remains permitted when allowPrivate: false
    assert.equal(voidsExemption('::ffff:0:8.8.8.8'), false);
    assert.equal(isPrivateOrReservedIP('::ffff:0:8.8.8.8'), false);
    const pubDns = await resolveAndValidateTarget('https://public.example.com', {
      allowPrivate: false,
      resolver: async () => [{ address: '::ffff:0:8.8.8.8', family: 6 }]
    });
    assert.equal(pubDns.valid, true);
  });
});
