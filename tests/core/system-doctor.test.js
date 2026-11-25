import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { runSystemDoctor, diagnoseTarget, maskProxyUrl } from '../../core/system-doctor.js';

test('system-doctor: maskProxyUrl masks username and password credentials safely', () => {
  assert.equal(maskProxyUrl(null), null);
  assert.equal(maskProxyUrl(''), null);
  assert.equal(
    maskProxyUrl('http://proxy.corp.internal:8080'),
    'http://proxy.corp.internal:8080'
  );

  const masked = maskProxyUrl('http://admin:secretPassword123@proxy.corp.internal:8080');
  assert.ok(!masked.includes('admin'));
  assert.ok(!masked.includes('secretPassword123'));
  assert.ok(masked.includes('***:***@proxy.corp.internal:8080'));

  const userOnly = maskProxyUrl('http://admin@proxy.corp.internal:8080');
  assert.ok(!userOnly.includes('admin'));
  assert.ok(userOnly.includes('***'));
});

test('system-doctor: runSystemDoctor returns structured health metrics and masks proxy credentials', async () => {
  const tmpHistory = fs.mkdtempSync(path.join(os.tmpdir(), 'secscan-hist-'));
  const tmpReports = fs.mkdtempSync(path.join(os.tmpdir(), 'secscan-rep-'));

  try {
    const mockEnv = {
      HTTP_PROXY: 'http://user:pass123@proxy.example.com:3128',
      HTTPS_PROXY: 'http://secure-user:pass456@secure-proxy.example.com:3128',
      NO_PROXY: 'localhost,127.0.0.1,.internal.net',
      GEMINI_API_KEY: 'mock-gemini-key'
    };

    const doc = await runSystemDoctor({
      historyDir: tmpHistory,
      reportsDir: tmpReports,
      env: mockEnv
    });

    assert.equal(typeof doc.ok, 'boolean');
    assert.ok(typeof doc.generatedAt === 'string');
    assert.equal(doc.environment.nodeOk, true);
    assert.equal(doc.environment.sqliteAvailable, true);

    // Storage access
    assert.equal(doc.storage.historyDir.writable, true);
    assert.equal(doc.storage.reportsDir.writable, true);

    // Proxy credential masking
    assert.equal(doc.proxy.configured, true);
    assert.ok(doc.proxy.httpProxy.includes('***:***@proxy.example.com:3128'));
    assert.ok(!doc.proxy.httpProxy.includes('pass123'));
    assert.ok(doc.proxy.httpsProxy.includes('***:***@secure-proxy.example.com:3128'));
    assert.ok(!doc.proxy.httpsProxy.includes('pass456'));
    assert.equal(doc.proxy.noProxy, 'localhost,127.0.0.1,.internal.net');

    // AI configuration
    assert.equal(doc.ai.configured, true);
    assert.ok(doc.ai.providers.includes('gemini'));
    assert.equal(doc.ai.activeProfilesCount, 1);

    // Checks count (84 scanners)
    assert.equal(doc.checks.count, 84);
    assert.equal(doc.checks.available, true);
    assert.ok(doc.checks.scanners.includes('system-health'));
    assert.ok(doc.checks.scanners.includes('api-communication'));
  } finally {
    fs.rmSync(tmpHistory, { recursive: true, force: true });
    fs.rmSync(tmpReports, { recursive: true, force: true });
  }
});

test('system-doctor: runSystemDoctor inspects active profiles and providers from mock llmPool', async () => {
  const tmpHistory = fs.mkdtempSync(path.join(os.tmpdir(), 'secscan-hist-'));
  const tmpReports = fs.mkdtempSync(path.join(os.tmpdir(), 'secscan-rep-'));

  try {
    const mockLlmPool = {
      getStatus: () => ({
        profiles: [
          { id: 'gemini-flash', provider: 'gemini', enabled: true },
          { id: 'claude-sonnet', provider: 'anthropic', enabled: true },
          { id: 'disabled-gpt', provider: 'openai', enabled: false }
        ]
      })
    };

    const doc = await runSystemDoctor({
      historyDir: tmpHistory,
      reportsDir: tmpReports,
      llmPool: mockLlmPool,
      env: {}
    });

    assert.equal(doc.ai.configured, true);
    assert.equal(doc.ai.activeProfilesCount, 2);
    assert.deepEqual(doc.ai.providers.sort(), ['anthropic', 'gemini']);
  } finally {
    fs.rmSync(tmpHistory, { recursive: true, force: true });
    fs.rmSync(tmpReports, { recursive: true, force: true });
  }
});

test('system-doctor: diagnoseTarget strictly blocks cloud metadata (169.254.169.254, 100.100.100.200) even when allowPrivate: true', async () => {
  const metaIps = [
    'http://169.254.169.254/latest/meta-data/',
    'http://100.100.100.200/latest/meta-data/',
    'http://metadata.google.internal/computeMetadata/v1/'
  ];

  for (const target of metaIps) {
    const res = await diagnoseTarget(target, { allowPrivate: true });
    assert.equal(res.ok, false);
    assert.equal(res.issueOrigin, 'policy_block');
    assert.equal(res.stage, 'url_validation');
    assert.ok(res.reason.includes('metadata') || res.reason.includes('blocked'));
  }
});

test('system-doctor: diagnoseTarget blocks asset scope violations via evaluateAssetGate', async () => {
  const scopeRules = [
    { ruleType: 'domain', pattern: 'trusted.example.com', isAllowed: true }
  ];

  const res = await diagnoseTarget('https://untrusted.example.com', {
    scopeRules,
    allowPrivate: false
  });

  assert.equal(res.ok, false);
  assert.equal(res.issueOrigin, 'policy_block');
  assert.equal(res.stage, 'asset_gate');
  assert.equal(res.code, 'TARGET_OUT_OF_SCOPE');
});

test('system-doctor: diagnoseTarget differentiates target_website domain failure vs local_pc DNS failure', async () => {
  // 1. Target domain does not exist, but local DNS functions
  const mockTargetResolver = async (host) => {
    if (host === 'nonexistent-subdomain-123456.com') {
      throw new Error('getaddrinfo ENOTFOUND nonexistent-subdomain-123456.com');
    }
    if (host === 'localhost') {
      return ['127.0.0.1'];
    }
    return ['93.184.216.34'];
  };

  const domainFail = await diagnoseTarget('http://nonexistent-subdomain-123456.com', {
    dnsResolver: mockTargetResolver,
    allowPrivate: true
  });

  assert.equal(domainFail.ok, false);
  assert.equal(domainFail.issueOrigin, 'target_website');
  assert.equal(domainFail.stage, 'dns_resolution');

  // 2. Entire local PC network / DNS resolver is failing
  const mockOfflineResolver = async () => {
    throw new Error('getaddrinfo ENOTFOUND (network offline)');
  };

  const localPcFail = await diagnoseTarget('http://example.com', {
    dnsResolver: mockOfflineResolver,
    allowPrivate: true
  });

  assert.equal(localPcFail.ok, false);
  assert.equal(localPcFail.issueOrigin, 'local_pc');
  assert.equal(localPcFail.stage, 'dns_resolution');
});

test('system-doctor: diagnoseTarget HTTP probe handles 200 OK, 5xx server errors, ECONNREFUSED, and timeouts', async () => {
  const dummyResolver = async () => ['93.184.216.34'];

  // 1. Success 200 OK
  const okFetcher = async () => ({ status: 200, text: 'Welcome' });
  const okRes = await diagnoseTarget('https://example.com', {
    dnsResolver: dummyResolver,
    fetcher: okFetcher
  });
  assert.equal(okRes.ok, true);
  assert.equal(okRes.status, 200);
  assert.equal(okRes.issueOrigin, null);
  assert.ok(typeof okRes.latencyMs === 'number');

  // 2. HTTP 502 Bad Gateway -> target_website
  const errorFetcher = async () => ({ status: 502, text: 'Bad Gateway' });
  const errorRes = await diagnoseTarget('https://example.com', {
    dnsResolver: dummyResolver,
    fetcher: errorFetcher
  });
  assert.equal(errorRes.ok, false);
  assert.equal(errorRes.issueOrigin, 'target_website');
  assert.equal(errorRes.status, 502);

  // 3. ECONNREFUSED -> target_website
  const refusedFetcher = async () => {
    const err = new Error('connect ECONNREFUSED 93.184.216.34:443');
    err.code = 'ECONNREFUSED';
    throw err;
  };
  const refusedRes = await diagnoseTarget('https://example.com:443', {
    dnsResolver: dummyResolver,
    fetcher: refusedFetcher
  });
  assert.equal(refusedRes.ok, false);
  assert.equal(refusedRes.issueOrigin, 'target_website');
  assert.ok(refusedRes.reason.includes('ECONNREFUSED'));

  // 4. Timeout -> target_website triage
  const timeoutFetcher = async () => {
    const err = new Error('The operation was aborted');
    err.code = 'ABORT_ERR';
    throw err;
  };
  const timeoutRes = await diagnoseTarget('https://example.com', {
    dnsResolver: dummyResolver,
    fetcher: timeoutFetcher,
    timeoutMs: 100
  });
  assert.equal(timeoutRes.ok, false);
  assert.equal(timeoutRes.issueOrigin, 'target_website');
  assert.ok(timeoutRes.reason.includes('timed out'));
});

test('CANDIDATE-2: diagnoseTarget enforces TargetPinStore and blocks 302 redirect to private IP', async () => {
  // 1. Redirect from public target to 127.0.0.1 is blocked during HTTP probe even with fetcher hook
  const redirectFetcher = async () => ({
    status: 302,
    headers: { location: 'http://127.0.0.1/admin' },
    text: async () => ''
  });
  const redirectRes = await diagnoseTarget('https://public.example.com/', {
    allowPrivate: false,
    dnsResolver: async () => ['93.184.216.34'],
    fetcher: redirectFetcher
  });
  assert.equal(redirectRes.ok, false);
  assert.equal(redirectRes.stage, 'http_probe');
  assert.equal(redirectRes.issueOrigin, 'policy_block');
  assert.match(redirectRes.reason, /SSRF policy|private|loopback/i);

  // 2. DNS rebinding between Stage 3 and Stage 4 is caught by shared TargetPinStore
  let calls = 0;
  const rebindResolver = async () => {
    calls += 1;
    return calls === 1 ? ['93.184.216.34'] : ['93.184.216.35'];
  };
  const rebindRes = await diagnoseTarget('https://rebind.example.com/', {
    allowPrivate: false,
    dnsResolver: rebindResolver,
    fetcher: async () => ({ status: 200, text: 'ok' })
  });
  assert.equal(rebindRes.ok, false);
  assert.equal(rebindRes.stage, 'http_probe');
  assert.equal(rebindRes.issueOrigin, 'policy_block');
  assert.match(rebindRes.reason, /DNS pin mismatch|rebind/i);
});

test('CANDIDATE-3: diagnoseTarget honors timeoutMs with retries=0 against slow target without 30s retry delay', async () => {
  let attempts = 0;
  const slowAbortAwareFetcher = (_url, init) => {
    attempts += 1;
    return new Promise((_resolve, reject) => {
      if (init?.signal?.aborted) {
        const err = new Error('The operation was aborted');
        err.name = 'AbortError';
        reject(err);
        return;
      }
      init?.signal?.addEventListener('abort', () => {
        const err = new Error('The operation was aborted');
        err.name = 'AbortError';
        reject(err);
      }, { once: true });
    });
  };

  // Exercise the default globalThis.fetch path (fetcher: null) as well as retries=0 & effectiveTimeout
  const originalFetch = globalThis.fetch;
  globalThis.fetch = slowAbortAwareFetcher;
  try {
    const start = Date.now();
    const res = await diagnoseTarget('http://127.0.0.1:8080/slow', {
      allowPrivate: true,
      timeoutMs: 120
    });
    const elapsed = Date.now() - start;

    assert.equal(attempts, 1, 'diagnoseTarget must invoke fetch with retries=0 (1 attempt only)');
    assert.equal(res.ok, false);
    assert.equal(res.stage, 'http_probe');
    assert.equal(res.issueOrigin, 'target_website');
    assert.match(res.reason, /timed out/i);
    assert.ok(elapsed < 2000, `Expected timeout abort well under 2000ms (no 3x10s retries), took ${elapsed}ms`);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('CANDIDATE-10: runSystemDoctor is non-mutating by default, omits absolute host paths, and reads getPoolStatus()', async () => {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'secscan-doc10-'));
  const missingHistory = path.join(tmpRoot, 'nonexistent-history');
  const existingReports = path.join(tmpRoot, 'reports');
  fs.mkdirSync(existingReports, { recursive: true });

  try {
    const emptyRealLikePool = {
      getPoolStatus: () => ({ profiles: [] })
    };
    const doc = await runSystemDoctor({
      historyDir: missingHistory,
      reportsDir: existingReports,
      llmPool: emptyRealLikePool,
      env: {}
    });

    assert.equal(fs.existsSync(missingHistory), false, 'probeWrites:false must not create missing directory');
    assert.equal(fs.readdirSync(existingReports).length, 0, 'probeWrites:false must not write probe files');
    assert.equal(doc.storage.historyDir.writable, true);
    assert.equal(doc.storage.reportsDir.writable, true);
    assert.ok(!doc.storage.historyDir.path.includes(tmpRoot), 'Must not expose absolute host path');
    assert.ok(!doc.storage.reportsDir.path.includes(tmpRoot), 'Must not expose absolute host path');
    assert.equal(doc.ai.configured, false);
    assert.equal(doc.ai.activeProfilesCount, 0);

    // Active pool via getPoolStatus
    const activePool = {
      getPoolStatus: () => ({
        profiles: [{ id: 'gemini', provider: 'gemini', enabled: true }]
      })
    };
    const docActive = await runSystemDoctor({
      historyDir: missingHistory,
      reportsDir: existingReports,
      llmPool: activePool,
      probeWrites: true,
      env: {}
    });
    assert.equal(fs.existsSync(missingHistory), true, 'probeWrites:true creates/probes target directory');
    assert.equal(docActive.ai.configured, true);
    assert.equal(docActive.ai.activeProfilesCount, 1);
    assert.deepEqual(docActive.ai.providers, ['gemini']);
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
});
