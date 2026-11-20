import { test } from 'node:test';
import assert from 'node:assert/strict';
import run from '../../checks/ssl-tls.js';
import { createGovernedFetch } from '../../core/fetch.js';
import { TargetPinStore } from '../../core/guard.js';
import { mockFetch } from '../helpers/mock-fetch.js';

const FUTURE_CERT = new Date(Date.now() + 90 * 86_400_000).toUTCString();
const SOON_CERT = new Date(Date.now() + 15 * 86_400_000).toUTCString();
const URGENT_CERT = new Date(Date.now() + 3 * 86_400_000).toUTCString();
const EXPIRED_CERT = new Date(Date.now() - 5 * 86_400_000).toUTCString();

test('ssl-tls: returns SUSPICIOUS (HIGH) for non-HTTPS public HTTP targets and ERROR for invalid URLs', async () => {
  const bad = await run('not-a-url');
  assert.equal(bad.status, 'ERROR');
  assert.equal(bad.name, 'ssl/tls check');

  const httpRes = await run('http://example.com');
  assert.equal(httpRes.name, 'ssl/tls check');
  assert.equal(httpRes.status, 'SUSPICIOUS');
  assert.equal(httpRes.severity, 'HIGH');
});

test('ssl-tls: SAFE on valid TLS 1.3 cert when deprecated TLS 1.0/1.1 are rejected', async () => {
  const r = await run('https://example.com', mockFetch({ status: 200 }), {
    tlsConnect: async ({ minVersion }) => {
      if (minVersion) throw new Error('protocol rejected');
      return {
        cert: { valid_to: FUTURE_CERT },
        protocol: 'TLSv1.3',
        authorized: true,
        authorizationError: null
      };
    }
  });
  assert.equal(r.name, 'ssl/tls check');
  assert.equal(r.status, 'SAFE');
  assert.equal(r.severity, 'NONE');
});

test('ssl-tls: detects expired, <7d, <30d, untrusted, and weak TLS 1.0/1.1 fallback', async () => {
  const expired = await run('https://example.com', null, {
    tlsConnect: async ({ minVersion }) => {
      if (minVersion) throw new Error('rejected');
      return { cert: { valid_to: EXPIRED_CERT }, protocol: 'TLSv1.2', authorized: true };
    }
  });
  assert.equal(expired.status, 'VULNERABLE');
  assert.equal(expired.severity, 'CRITICAL');

  const urgent = await run('https://example.com', null, {
    tlsConnect: async ({ minVersion }) => {
      if (minVersion) throw new Error('rejected');
      return { cert: { valid_to: URGENT_CERT }, protocol: 'TLSv1.2', authorized: true };
    }
  });
  assert.equal(urgent.status, 'VULNERABLE');
  assert.equal(urgent.severity, 'CRITICAL');

  const soonUntrusted = await run('https://example.com', null, {
    tlsConnect: async ({ minVersion }) => {
      if (minVersion) throw new Error('rejected');
      return {
        cert: { valid_to: SOON_CERT },
        protocol: 'TLSv1.2',
        authorized: false,
        authorizationError: 'DEPTH_ZERO_SELF_SIGNED_CERT'
      };
    }
  });
  assert.equal(soonUntrusted.status, 'VULNERABLE');
  assert.equal(soonUntrusted.severity, 'HIGH');

  const weakFallback = await run('https://example.com', null, {
    tlsConnect: async () => ({
      cert: { valid_to: FUTURE_CERT },
      protocol: 'TLSv1.2',
      authorized: true
    })
  });
  assert.equal(weakFallback.status, 'VULNERABLE');
  assert.equal(weakFallback.severity, 'MEDIUM');
  assert.ok(weakFallback.issues.some(i => i.issue.includes('TLS 1.0')));
  assert.ok(weakFallback.issues.some(i => i.issue.includes('TLS 1.1')));
});

test('ssl-tls: enforces SSRF, built-in .gov deny, scopeRules, DNS pinning & anti-override BEFORE tlsConnect', async () => {
  let tlsCalls = 0;
  const countingTls = async ({ minVersion }) => {
    tlsCalls += 1;
    if (minVersion) throw new Error('rejected');
    return { cert: { valid_to: FUTURE_CERT }, protocol: 'TLSv1.3', authorized: true };
  };

  for (const blocked of [
    'https://127.0.0.1/',
    'https://localhost/',
    'https://169.254.169.254/',
    'https://portal.gov/',
    'http://127.0.0.1/'
  ]) {
    const r = await run(blocked, mockFetch({ status: 200 }), { tlsConnect: countingTls });
    assert.equal(r.status, 'ERROR', `Expected ERROR for ${blocked}`);
  }
  assert.equal(tlsCalls, 0);

  // Governed fetch with shared TargetPinStore & DNS rebind protection
  const pinStore = new TargetPinStore({ allowPrivate: false });
  pinStore.verifyOrPin('rebind.allowed.example', ['93.184.216.34']);

  const governedRebind = createGovernedFetch({
    targetPinStore: pinStore,
    dnsResolver: async () => ['127.0.0.1'],
    scopeRules: [{ ruleType: 'fuzzy_domain', pattern: '*.allowed.example', isAllowed: true }],
    allowPrivate: false
  });

  const rebindRes = await run('https://rebind.allowed.example/', governedRebind, {
    allowPrivate: true, // caller attempts override — must be ignored
    dnsResolver: async () => ['93.184.216.34'],
    tlsConnect: countingTls
  });
  assert.equal(rebindRes.status, 'ERROR');
  assert.match(rebindRes.reason, /127\.0\.0\.1|DNS pin mismatch/i);
  assert.equal(tlsCalls, 0);

  // Pinned IP & SNI servername passed to tlsConnect; IP literal omits servername
  let capturedOpts = null;
  const governedOk = createGovernedFetch({
    dnsResolver: async () => ['93.184.216.34'],
    scopeRules: [{ ruleType: 'fuzzy_domain', pattern: '*.allowed.example', isAllowed: true }],
    allowPrivate: false
  });
  const okRes = await run('https://app.allowed.example/', governedOk, {
    tlsConnect: async (opts) => {
      if (!opts.minVersion) capturedOpts = opts;
      if (opts.minVersion) throw new Error('rejected');
      return { cert: { valid_to: FUTURE_CERT }, protocol: 'TLSv1.3', authorized: true };
    }
  });
  assert.equal(okRes.status, 'SAFE');
  assert.equal(capturedOpts.host, '93.184.216.34');
  assert.equal(capturedOpts.servername, 'app.allowed.example');

  let ipOpts = null;
  const privFetch = createGovernedFetch({ allowPrivate: true });
  const privRes = await run('https://192.168.1.50:8443/', privFetch, {
    tlsConnect: async (opts) => {
      if (!opts.minVersion) ipOpts = opts;
      if (opts.minVersion) throw new Error('rejected');
      return { cert: { valid_to: FUTURE_CERT }, protocol: 'TLSv1.3', authorized: true };
    }
  });
  assert.equal(privRes.status, 'SAFE');
  assert.equal(ipOpts.host, '192.168.1.50');
  assert.equal(ipOpts.port, 8443);
  assert.equal(ipOpts.servername, undefined);

  // Metadata IP remains blocked even with allowPrivate: true
  const metaBlocked = await run('https://169.254.169.254/', privFetch, { tlsConnect: countingTls });
  assert.equal(metaBlocked.status, 'ERROR');
});
