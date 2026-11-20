import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { mockFetch } from '../helpers/mock-fetch.js';
import { createGovernedFetch } from '../../core/fetch.js';
import { runScanner } from '../../scan.js';
import run, { meta, name, cwe, owasp, cvssScore, tags } from '../../checks/system-health.js';

const BASE = 'https://example.com';

test('system-health: exports valid metadata, tags, and constants', () => {
  assert.equal(name, 'system-health');
  assert.equal(cwe, 'CWE-200');
  assert.equal(owasp, 'A05:2021-Security Misconfiguration');
  assert.equal(cvssScore, 5.3);
  assert.ok(tags.includes('all') && tags.includes('ops') && tags.includes('system'));
  assert.equal(meta.id, 'system-health');
  assert.equal(meta.category, 'Network & Transport');
  assert.ok(meta.plainExplanation.length > 0);
  assert.ok(meta.whyItMatters.length > 0);
  assert.ok(meta.defaultFix.length > 0);
});

test('system-health: SAFE on normal response with unexposed endpoints and valid TLS', async () => {
  const fetch = async (url) => {
    if (url === `${BASE}/` || url === BASE) {
      return {
        status: 200,
        headers: { 'content-type': 'text/html', 'content-encoding': 'gzip' },
        text: '<html><body>Welcome</body></html>',
        durationMs: 120
      };
    }
    // All operational endpoints 404
    return { status: 404, headers: {}, text: 'Not Found' };
  };

  const r = await run(BASE, fetch, {
    tlsProbe: () => ({ daysRemaining: 120 })
  });

  assert.equal(r.name, 'system-health');
  assert.equal(r.status, 'SAFE');
  assert.equal(r.severity, 'NONE');
  assert.deepEqual(r.issues, []);
  assert.deepEqual(r.evidenceQuotes, []);
});

test('system-health: bare {"status":"UP"} on /health is NOT flagged as vulnerable (remains SAFE)', async () => {
  const fetch = async (url) => {
    if (url.includes('/health')) {
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        text: '{"status":"UP"}'
      };
    }
    return { status: 200, headers: { 'content-type': 'text/plain' }, text: 'OK', durationMs: 50 };
  };

  const r = await run('http://example.com', fetch, {
    allowPrivate: true
  });

  assert.equal(r.name, 'system-health');
  assert.equal(r.status, 'SAFE');
  assert.equal(r.severity, 'NONE');
  assert.deepEqual(r.evidenceQuotes, []);
});

test('system-health: VULNERABLE (MEDIUM) on /actuator/health or /health leaking internal components/db/disk details with evidenceQuotes >= 8 chars', async () => {
  const leakedPayload = JSON.stringify({
    status: 'UP',
    components: {
      db: { status: 'UP', details: { database: 'PostgreSQL', validationQuery: 'isValid()' } },
      diskSpace: { status: 'UP', details: { total: 107374182400, free: 42949672960 } },
      redis: { status: 'UP', details: { version: '7.2.4' } }
    }
  });

  const fetch = async (url) => {
    if (url.endsWith('/actuator/health')) {
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        text: leakedPayload
      };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  };

  const r = await run(BASE, fetch, {
    tlsProbe: () => ({ daysRemaining: 90 })
  });

  assert.equal(r.name, 'system-health');
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'MEDIUM');
  assert.equal(r.cwe, 'CWE-200');
  assert.ok(r.evidenceQuotes.length > 0);
  for (const quote of r.evidenceQuotes) {
    assert.ok(quote.length >= 8, `Expected evidenceQuote >= 8 chars, got "${quote}"`);
  }
  assert.ok(r.issues.some(i => i.status === 'VULNERABLE' && i.endpoint === '/actuator/health'));
});

test('system-health: VULNERABLE (MEDIUM) on /metrics and /prometheus leaking operational telemetry signals with evidenceQuotes >= 8 chars', async () => {
  const metricsPayload = `# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds.
# TYPE process_cpu_seconds_total counter
process_cpu_seconds_total 12.45
# HELP go_goroutines Number of goroutines that currently exist.
# TYPE go_goroutines gauge
go_goroutines 42
`;

  const fetch = async (url) => {
    if (url.endsWith('/metrics')) {
      return {
        status: 200,
        headers: { 'content-type': 'text/plain; version=0.0.4' },
        text: metricsPayload
      };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  };

  const r = await run(BASE, fetch, {
    tlsProbe: () => ({ daysRemaining: 60 })
  });

  assert.equal(r.name, 'system-health');
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'MEDIUM');
  assert.equal(r.cwe, 'CWE-200');
  assert.ok(r.evidenceQuotes.length > 0);
  for (const quote of r.evidenceQuotes) {
    assert.ok(quote.length >= 8, `Expected quote >= 8 chars, got "${quote}"`);
  }
});

test('system-health: VULNERABLE (MEDIUM) on /server-status and /nginx_status', async () => {
  const nginxPayload = `Active connections: 291
server accepts handled requests
 16630948 16630948 31070465
Reading: 6 Writing: 179 Waiting: 106
`;

  const fetch = async (url) => {
    if (url.endsWith('/nginx_status')) {
      return {
        status: 200,
        headers: { 'content-type': 'text/plain' },
        text: nginxPayload
      };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  };

  const r = await run(BASE, fetch, {
    tlsProbe: () => ({ daysRemaining: 50 })
  });

  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'MEDIUM');
  assert.ok(r.evidenceQuotes.some(q => q.includes('Active connections') && q.length >= 8));
});

test('system-health: SUSPICIOUS (HIGH) on main target 5xx error status', async () => {
  const fetch = async (url) => {
    if (url === `${BASE}/` || url === BASE) {
      return {
        status: 502,
        headers: {},
        text: '502 Bad Gateway - Upstream timeout',
        durationMs: 80
      };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  };

  const r = await run(BASE, fetch, {
    tlsProbe: () => ({ daysRemaining: 100 })
  });

  assert.equal(r.status, 'SUSPICIOUS');
  assert.equal(r.severity, 'HIGH');
  assert.ok(r.issues.some(i => i.issue.includes('502')));
});

test('system-health: SUSPICIOUS (LOW) on slow response TTFB (>= 3000ms)', async () => {
  const fetch = async (url) => {
    if (url === `${BASE}/` || url === BASE) {
      return {
        status: 200,
        headers: { 'content-type': 'text/plain' },
        text: 'hello',
        durationMs: 3500
      };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  };

  const r = await run(BASE, fetch, {
    tlsProbe: () => ({ daysRemaining: 100 })
  });

  assert.equal(r.status, 'SUSPICIOUS');
  assert.equal(r.severity, 'LOW');
  assert.ok(r.issues.some(i => i.issue.includes('3500ms') || i.issue.includes('TTFB')));
});

test('system-health: SUSPICIOUS (LOW) on missing HTTP compression (>4096 bytes text/html without content-encoding)', async () => {
  const largeBody = 'A'.repeat(5000);
  const fetch = async (url) => {
    if (url === `${BASE}/` || url === BASE) {
      return {
        status: 200,
        headers: { 'content-type': 'text/html' }, // no content-encoding
        text: largeBody,
        durationMs: 100
      };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  };

  const r = await run(BASE, fetch, {
    tlsProbe: () => ({ daysRemaining: 100 })
  });

  assert.equal(r.status, 'SUSPICIOUS');
  assert.equal(r.severity, 'LOW');
  assert.ok(r.issues.some(i => i.issue.includes('compression')));
});

test('system-health: TLS certificate expiration evaluations (CRITICAL <=0, HIGH <=14, MEDIUM <=30)', async () => {
  const dummyFetch = mockFetch({ status: 200, text: 'ok', headers: {} });

  // Expired: daysRemaining <= 0 -> VULNERABLE CRITICAL
  const expired = await run(BASE, dummyFetch, {
    tlsProbe: () => ({ daysRemaining: -2 })
  });
  assert.equal(expired.status, 'VULNERABLE');
  assert.equal(expired.severity, 'CRITICAL');
  assert.ok(expired.issues.some(i => i.issue.includes('expired')));

  // Expiring soon: daysRemaining <= 14 -> SUSPICIOUS HIGH
  const soon = await run(BASE, dummyFetch, {
    tlsProbe: () => ({ daysRemaining: 10 })
  });
  assert.equal(soon.status, 'SUSPICIOUS');
  assert.equal(soon.severity, 'HIGH');
  assert.ok(soon.issues.some(i => i.issue.includes('10 days')));

  // Expiring soon: daysRemaining <= 30 -> SUSPICIOUS MEDIUM
  const medium = await run(BASE, dummyFetch, {
    tlsProbe: () => ({ daysRemaining: 25 })
  });
  assert.equal(medium.status, 'SUSPICIOUS');
  assert.equal(medium.severity, 'MEDIUM');
  assert.ok(medium.issues.some(i => i.issue.includes('25 days')));
});

test('system-health: cleanly handles governance error blocks', async () => {
  const govBlockedFetch = async () => ({
    isGovernanceBlock: true,
    code: 'SSRF_POLICY_BLOCKED',
    reason: 'Redirect blocked by SSRF policy'
  });

  const r = await run(BASE, govBlockedFetch);
  assert.equal(r.name, 'system-health');
  assert.equal(r.status, 'ERROR');
  assert.equal(r.severity, 'NONE');
  assert.ok(r.reason.includes('SSRF policy'));
});

test('system-health: returns ERROR for invalid target URLs', async () => {
  const r = await run('not-a-valid-url', mockFetch({ status: 200 }));
  assert.equal(r.name, 'system-health');
  assert.equal(r.status, 'ERROR');
  assert.equal(r.severity, 'NONE');
  assert.equal(r.reason, 'Invalid URL');
});

test('CANDIDATE-6: runScanner with allowPrivate:true scans 127.0.0.1 system-health cleanly instead of SSRF block', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secscan-c6-'));
  const localFetcher = async (url) => {
    if (String(url).endsWith('/metrics')) {
      return {
        status: 200,
        headers: new Headers({ 'content-type': 'text/plain' }),
        text: async () => '# HELP process_cpu_seconds_total CPU usage\nprocess_cpu_seconds_total 4.2\n'
      };
    }
    return {
      status: 200,
      headers: new Headers({ 'content-type': 'text/html' }),
      text: async () => '<html><body>Hello local</body></html>'
    };
  };

  try {
    const out = await runScanner({
      targets: ['http://127.0.0.1:8080'],
      allowPrivate: true,
      checks: ['system-health'],
      maxDepth: 0,
      noHistory: true,
      silent: true,
      setExitCode: false,
      returnFull: true,
      fetcher: localFetcher,
      output: path.join(tmpDir, 'out')
    });
    const sh = out.results.find((f) => f.checkId === 'system-health');
    assert.ok(sh, 'system-health result should be present');
    assert.notEqual(sh.status, 'ERROR');
    assert.equal(sh.status, 'VULNERABLE');
    assert.ok(sh.evidenceQuotes.some((q) => q.includes('process_cpu_seconds_total')));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('CANDIDATE-6: system-health TLS probing enforces governedTlsAlpnProbe / TargetPinStore / governor', async () => {
  let calls = 0;
  const rebindResolver = async () => {
    calls += 1;
    return calls === 1 ? ['93.184.216.34'] : ['93.184.216.35'];
  };
  const governedFetch = createGovernedFetch({
    enforceDnsValidation: true,
    dnsResolver: rebindResolver,
    fetcher: async () => ({ status: 200, headers: new Headers({}), text: async () => 'ok' })
  });

  // 1. Governed HTTP fetch pins 93.184.216.34; subsequent TLS probe catches DNS rebinding
  const r = await run('https://rebind-health.example/', governedFetch, {
    tlsProbe: () => ({ daysRemaining: 5 })
  });
  assert.equal(r.status, 'ERROR');
  assert.match(r.reason, /DNS pin mismatch|rebind|SSRF/i);

  // 2. Built-in .gov block runs before any TLS probe
  const govRes = await run('https://agency.gov/', mockFetch({ status: 200 }), {
    tlsProbe: () => ({ daysRemaining: 5 })
  });
  assert.equal(govRes.status, 'ERROR');
  assert.match(govRes.reason, /gov|deny|policy/i);
});
