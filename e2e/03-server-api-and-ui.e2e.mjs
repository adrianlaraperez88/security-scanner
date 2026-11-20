import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { startAppHarness, withAppHarness } from './helpers/app-server-harness.mjs';
import { withTempDir, REPO_ROOT } from './helpers/cli-runner.mjs';
import { createStackTarget, withMockTarget } from './helpers/mock-target-server.mjs';

const ALL_7_TABS = [
  'new-scan',
  'scan-results',
  'tasks-sessions',
  'dual-graph',
  'traffic-replay',
  'history',
  'catalog'
];

const ALL_7_COMPONENTS = [
  'asset-dsl-search.js',
  'coverage-graph.js',
  'evidence-viewer.js',
  'exploration-graph.js',
  'session-explorer.js',
  'system-guardrails.js',
  'traffic-inspector.js'
];

const ALL_JEV_TRUE = {
  q1_in_scope: true,
  q2_authorized: true,
  q3_non_destructive: true,
  q4_rate_bounded: true,
  q5_no_exfiltration: true,
  q6_evidence_only: true,
  q7_rollback_safe: true,
  q8_least_privilege: true
};

function rawHttpRequest({ host = '127.0.0.1', port, method = 'GET', path: reqPath = '/', headers = {}, body = '' }) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host, port, method, path: reqPath, headers }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          text: Buffer.concat(chunks).toString('utf8')
        });
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

describe('F4 & F7: Server HTTP/SSE APIs, SQLite Stores, Guardrails & 7-Tab UI', () => {
  describe('Tier 1 — Server API & UI Serving Happy Paths', () => {
    test('T1.1 GET /api/meta returns v2.2.0, dynamic totalChecks, categories[], and cveCoverageSummary', async () => {
      await withAppHarness({ inMemory: true }, async app => {
        const res = await app.jsonFetch('/api/meta');
        assert.equal(res.status, 200);
        assert.equal(res.data.version, '2.2.0');
        assert.ok(Array.isArray(res.data.checks) && res.data.checks.length >= 54);
        assert.equal(res.data.totalChecks, res.data.checks.length);
        assert.ok(Array.isArray(res.data.categories) && res.data.categories.length >= 14);
        assert.ok(res.data.presets && res.data.profiles);
        assert.ok(
          res.data.cveCoverageSummary && typeof res.data.cveCoverageSummary === 'object',
          'Expected cveCoverageSummary in GET /api/meta'
        );
      });
    });

    test('T1.2 POST /api/fingerprint detects mock Next.js target with allowPrivate: true', async () => {
      const target = await createStackTarget('nextjs', 'vulnerable');
      try {
        await withAppHarness({ inMemory: true }, async app => {
          const res = await app.jsonFetch('/api/fingerprint', {
            method: 'POST',
            body: { target: target.baseUrl, allowPrivate: true }
          });
          assert.equal(res.status, 200, res.text);
          assert.equal(res.data.recommendedProfile, 'modern');
          assert.ok(res.data.activeChecksCount > 0);
          assert.ok(res.data.fingerprint?.detectedTags?.includes('nextjs'));
        });
      } finally {
        await target.close();
      }
    });

    test('T1.3 POST /api/scan + SSE stream emits full lifecycle events and completes at 100%', async () => {
      await withMockTarget(
        {
          routes: {
            '/': { status: 200, body: '<html><body><a href="/sub">Sub</a></body></html>' },
            '/.env': { status: 200, body: 'APP_KEY=base64:sse_test_key\n' },
            '/sub': { status: 200, body: '<html><body>Subpage</body></html>' }
          }
        },
        async target => {
          await withAppHarness({ inMemory: true }, async app => {
            const startRes = await app.jsonFetch('/api/scan', {
              method: 'POST',
              body: {
                target: target.baseUrl,
                profile: 'quick',
                allowPrivate: true,
                noHistory: true,
                maxDepth: 0,
                noiseProfile: 'quiet'
              }
            });
            assert.equal(startRes.status, 202, startRes.text);
            const scanId = startRes.data.scanId;
            assert.ok(scanId);

            const events = await app.readSse(`/api/scan/${scanId}/stream`, { timeoutMs: 25000 });
            const eventNames = events.map(e => e.event);
            assert.ok(eventNames.includes('start'), `Missing start event in [${eventNames.join(',')}]`);
            assert.ok(eventNames.includes('fingerprint'), `Missing fingerprint event`);
            assert.ok(eventNames.includes('check'), `Missing check event`);
            assert.ok(eventNames.includes('complete'), `Missing complete event`);

            const statusRes = await app.jsonFetch(`/api/scan/${scanId}`);
            assert.equal(statusRes.status, 200);
            assert.equal(statusRes.data.status, 'completed');
            assert.equal(statusRes.data.progress, 100);
            assert.ok(Array.isArray(statusRes.data.result?.results));
          });
        }
      );
    });

    test('T1.4 TrafficStore ingest, GET /api/traffic?status=2xx, and RFC-9110 replay', async () => {
      await withMockTarget(
        {
          routes: {
            '/echo': reqInfo => ({
              status: 200,
              body: {
                ok: true,
                customHeader: reqInfo.headers['x-e2e-test'] || null,
                hadConnectionHeader: Boolean(reqInfo.headers['x-hop-secret'])
              }
            })
          }
        },
        async target => {
          await withAppHarness({ inMemory: true }, async app => {
            const ingest = await app.jsonFetch('/api/traffic/ingest', {
              method: 'POST',
              body: {
                source: 'external',
                method: 'GET',
                url: `${target.baseUrl}/echo`,
                statusCode: 200,
                reqHeaders: {
                  Connection: 'keep-alive, x-hop-secret',
                  'X-Hop-Secret': 'should-be-stripped',
                  'X-E2E-Test': 'replay-ok'
                },
                resHeaders: { 'content-type': 'application/json' },
                resBody: '{"ok":true}'
              }
            });
            assert.equal(ingest.status, 201, ingest.text);
            const exchangeId = ingest.data.recorded.id;
            assert.ok(exchangeId);

            const query2xx = await app.jsonFetch('/api/traffic?status=2xx');
            assert.equal(query2xx.status, 200);
            assert.ok(query2xx.data.exchanges.length >= 1, 'status=2xx must match 200 exchange');
            assert.equal(typeof query2xx.data.total, 'number');
            assert.ok(query2xx.data.total >= query2xx.data.exchanges.length);

            const replay = await app.jsonFetch(`/api/traffic/${exchangeId}/replay`, {
              method: 'POST',
              body: { allowPrivate: true }
            });
            assert.equal(replay.status, 200, replay.text);
            assert.equal(replay.data.replayExchange?.source, 'replay');
            const parsedBody = JSON.parse(replay.data.replayExchange.resBody);
            assert.equal(parsedBody.customHeader, 'replay-ok');
            assert.equal(parsedBody.hadConnectionHeader, false, 'Hop-by-hop headers must be stripped');
          });
        }
      );
    });

    test('T1.5 EvidenceStore bind, S1 verify, and live retest verdict transition (vulnerable -> fixed)', async () => {
      let patched = false;
      await withMockTarget(
        {
          routes: reqInfo => {
            if (reqInfo.pathname === '/leak') {
              return patched
                ? { status: 404, body: 'Not Found' }
                : { status: 200, body: 'SECRET_TOKEN=live_evidence_quote_12345' };
            }
            return { status: 200, body: 'ok' };
          }
        },
        async target => {
          await withAppHarness({ inMemory: true }, async app => {
            const findingId = 'e2e-finding-1';
            const bind = await app.jsonFetch(`/api/findings/${findingId}/evidence`, {
              method: 'POST',
              body: {
                url: `${target.baseUrl}/leak`,
                statusCode: 200,
                resHeaders: { 'content-type': 'text/plain' },
                resBody: 'SECRET_TOKEN=live_evidence_quote_12345',
                quote: 'live_evidence_quote_12345',
                poeLevel: 3
              }
            });
            assert.equal(bind.status, 200, bind.text);
            assert.equal(bind.data.verification?.status, 'verified');

            const verify = await app.jsonFetch(`/api/findings/${findingId}/verify`, {
              method: 'POST',
              body: { poeLevel: 3, evidenceQuotes: ['live_evidence_quote_12345'] }
            });
            assert.equal(verify.status, 200);
            assert.equal(verify.data.assessment?.status, 'verified');

            patched = true;
            const retest = await app.jsonFetch(`/api/findings/${findingId}/retest`, {
              method: 'POST',
              body: { allowPrivate: true, evidenceQuotes: ['live_evidence_quote_12345'] }
            });
            assert.equal(retest.status, 200, retest.text);
            assert.equal(retest.data.retest?.verdict, 'fixed');
          });
        }
      );
    });

    test('T1.6 POST /api/guard/evaluate supports mode:"all" (and omitted combined fields) & PUT /api/guard/settings', async () => {
      await withAppHarness({ inMemory: true }, async app => {
        const put = await app.jsonFetch('/api/guard/settings', {
          method: 'PUT',
          body: {
            noiseProfile: 'quiet',
            scopeRules: [{ action: 'allow', pattern: 'example.com' }]
          }
        });
        assert.equal(put.status, 200, put.text);
        assert.equal(put.data.noiseProfile, 'quiet');

        const get = await app.jsonFetch('/api/guard/settings');
        assert.equal(get.status, 200);
        assert.equal(get.data.noiseProfile, 'quiet');

        const evalRes = await app.jsonFetch('/api/guard/evaluate', {
          method: 'POST',
          body: {
            target: 'https://example.com/api',
            toolName: 'GET',
            jevAnswers: ALL_JEV_TRUE
          }
        });
        assert.equal(evalRes.status, 200, evalRes.text);
        assert.equal(evalRes.data.mode, 'all');
        assert.equal(evalRes.data.allowed, true);
        assert.equal(evalRes.data.gate?.allowed, true);
        assert.equal(typeof evalRes.data.risk?.score, 'number');
        assert.equal(evalRes.data.jev?.approved, true);
      });
    });

    test('T1.7 GET /api/scan/:id/export exports JSON, CSV, Markdown, and HTML', async () => {
      await withMockTarget(
        {
          routes: {
            '/': { status: 200, body: '<html><body>Home</body></html>' },
            '/.env': { status: 200, body: 'APP_KEY=base64:export_test_key\n' }
          }
        },
        async target => {
          await withAppHarness({ inMemory: true }, async app => {
            const start = await app.jsonFetch('/api/scan', {
              method: 'POST',
              body: { target: target.baseUrl, profile: 'quick', allowPrivate: true, noHistory: true, maxDepth: 0 }
            });
            assert.equal(start.status, 202);
            const scanId = start.data.scanId;
            await app.readSse(`/api/scan/${scanId}/stream`);

            for (const [fmt, expectedPattern] of [
              ['json', /"findings"/],
              ['csv', /Check ID,Title,Status/],
              ['markdown', /# Security Verification Report/],
              ['html', /<!DOCTYPE html>/i]
            ]) {
              const exp = await app.fetchApi(`/api/scan/${scanId}/export?format=${fmt}`);
              assert.equal(exp.status, 200, `Export format ${fmt} failed`);
              const txt = await exp.text();
              assert.match(txt, expectedPattern, `Export format ${fmt} mismatch`);
            }
          });
        }
      );
    });

    test('T1.8 GET / serves ui/index.html with strict CSP, nosniff, X-Frame-Options, Referrer-Policy', async () => {
      await withAppHarness({ inMemory: true }, async app => {
        const res = await app.fetchApi('/');
        assert.equal(res.status, 200);
        assert.match(res.headers.get('content-type') || '', /text\/html/i);
        assert.match(res.headers.get('content-security-policy') || '', /default-src 'self'/);
        assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
        assert.equal(res.headers.get('x-frame-options'), 'DENY');
        assert.equal(res.headers.get('referrer-policy'), 'no-referrer');
        const html = await res.text();
        assert.match(html, /Security Scanner/i);
      });
    });

    test('T1.9 GET /app.js, /styles.css, and all 7 /components/*.js return 200 with valid MIME types', async () => {
      await withAppHarness({ inMemory: true }, async app => {
        const appJs = await app.fetchApi('/app.js');
        assert.equal(appJs.status, 200);
        assert.match(appJs.headers.get('content-type') || '', /application\/javascript/i);

        const css = await app.fetchApi('/styles.css');
        assert.equal(css.status, 200);
        assert.match(css.headers.get('content-type') || '', /text\/css/i);

        for (const comp of ALL_7_COMPONENTS) {
          const r = await app.fetchApi(`/components/${comp}`);
          assert.equal(r.status, 200, `Failed to fetch /components/${comp}`);
          assert.match(r.headers.get('content-type') || '', /application\/javascript/i);
        }
      });
    });

    test('T1.10 ui/index.html defines all 7 tabs with WAI-ARIA tablist/tab/tabpanel attributes', async () => {
      await withAppHarness({ inMemory: true }, async app => {
        const html = await (await app.fetchApi('/')).text();
        assert.match(html, /role="tablist"/);
        for (const tab of ALL_7_TABS) {
          assert.match(html, new RegExp(`data-tab="${tab}"`), `Missing tab button data-tab="${tab}"`);
          assert.match(
            html,
            new RegExp(`(?:id="tab-${tab}"[^>]*role="tabpanel"|role="tabpanel"[^>]*id="tab-${tab}")`),
            `Missing tabpanel #tab-${tab}`
          );
          assert.match(html, new RegExp(`aria-controls="tab-${tab}"`), `Missing aria-controls="tab-${tab}"`);
          assert.match(html, new RegExp(`aria-labelledby="tab-btn-${tab}"`), `Missing aria-labelledby="tab-btn-${tab}"`);
        }
      });
    });

    test('T1.11 ui/index.html exposes CVE Coverage Audit view in Tab 7 and CVE summary banner in Tab 2', async () => {
      await withAppHarness({ inMemory: true }, async app => {
        const html = await (await app.fetchApi('/')).text();
        assert.match(html, /CVE Coverage/i, 'Missing CVE Coverage Audit UI view in Tab 7');
        assert.match(html, /cve-coverage|cve-audit|cveCoverage/i, 'Missing CVE coverage DOM hooks in ui/index.html');
        assert.match(html, /tab-scan-results[\s\S]*cve/i, 'Missing CVE coverage banner hook in Tab 2 scan results');
      });
    });

    test('T1.12 ui/app.js renders cvssScore & cveIds badges and system-guardrails preserves isAllowed/ruleType', async () => {
      await withAppHarness({ inMemory: true }, async app => {
        const appJs = await (await app.fetchApi('/app.js')).text();
        assert.match(appJs, /\bcvssScore\b/);
        assert.match(appJs, /\bcveIds\b/);
        assert.match(appJs, /['"]agent['"][\s\S]{0,250}addEventListener|addEventListener\(\s*['"]agent['"]/);

        const guardJs = await (await app.fetchApi('/components/system-guardrails.js')).text();
        assert.match(guardJs, /\bisAllowed\b/);
        assert.match(guardJs, /\bruleType\b/);
      });
    });
  });

  describe('Tier 2 — Security Limits, SSRF, Host/Origin, Persistence & Edge Cases', () => {
    test('T2.1 POST /api/scan blocks private 127.0.0.1 without allowPrivate and always blocks 169.254.169.254', async () => {
      await withAppHarness({ inMemory: true }, async app => {
        const r1 = await app.jsonFetch('/api/scan', {
          method: 'POST',
          body: { target: 'http://127.0.0.1:4321' }
        });
        assert.equal(r1.status, 400);

        const r2 = await app.jsonFetch('/api/scan', {
          method: 'POST',
          body: { target: 'http://169.254.169.254/latest/meta-data/', allowPrivate: true }
        });
        assert.equal(r2.status, 400);
      });
    });

    test('T2.2 untrusted Host or Origin header returns 403', async () => {
      await withAppHarness({ inMemory: true }, async app => {
        const badHost = await rawHttpRequest({
          port: app.port,
          path: '/api/meta',
          headers: { Host: 'evil.attacker.com' }
        });
        assert.equal(badHost.status, 403);

        const badOrigin = await rawHttpRequest({
          port: app.port,
          path: '/api/meta',
          headers: { Host: `127.0.0.1:${app.port}`, Origin: 'https://evil.attacker.com' }
        });
        assert.equal(badOrigin.status, 403);
      });
    });

    test('T2.3 IPv6 loopback Host [::1] and Origin http://[::1] are permitted (200)', async () => {
      await withAppHarness({ inMemory: true }, async app => {
        const res = await rawHttpRequest({
          port: app.port,
          path: '/api/meta',
          headers: {
            Host: `[::1]:${app.port}`,
            Origin: `http://[::1]:${app.port}`
          }
        });
        assert.equal(res.status, 200, `Expected [::1] Host/Origin to be allowed, got ${res.status}: ${res.text}`);
      });
    });

    test('T2.4 oversized body (>64KB) returns 413, non-JSON returns 415, malformed JSON returns 400', async () => {
      await withAppHarness({ inMemory: true }, async app => {
        const huge = 'x'.repeat(70 * 1024);
        const r413 = await rawHttpRequest({
          port: app.port,
          method: 'POST',
          path: '/api/fingerprint',
          headers: {
            Host: `127.0.0.1:${app.port}`,
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(huge)
          },
          body: huge
        });
        assert.equal(r413.status, 413);

        // Also test parseOptionalJsonBody oversized payload (POST /api/findings/:id/verify)
        const rOpt413 = await rawHttpRequest({
          port: app.port,
          method: 'POST',
          path: '/api/findings/test-id/verify',
          headers: {
            Host: `127.0.0.1:${app.port}`,
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(huge)
          },
          body: huge
        });
        assert.equal(rOpt413.status, 413);

        const r415 = await app.fetchApi('/api/fingerprint', {
          method: 'POST',
          headers: { 'Content-Type': 'text/plain' },
          body: '{"target":"https://example.com"}'
        });
        assert.equal(r415.status, 415);

        const r400 = await app.fetchApi('/api/fingerprint', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: '{bad_json'
        });
        assert.equal(r400.status, 400);
      });
    });

    test('T2.5 POST /api/guard/evaluate fails closed on incomplete JEV or .gov target; invalid noiseProfile returns 400', async () => {
      await withAppHarness({ inMemory: true }, async app => {
        const badNoise = await app.jsonFetch('/api/guard/settings', {
          method: 'PUT',
          body: { noiseProfile: 'invalid_turbo' }
        });
        assert.equal(badNoise.status, 400);

        const evalFail = await app.jsonFetch('/api/guard/evaluate', {
          method: 'POST',
          body: {
            target: 'https://agency.gov/login',
            toolName: 'POST',
            jevAnswers: { ...ALL_JEV_TRUE, q8_least_privilege: false }
          }
        });
        assert.equal(evalFail.status, 200, evalFail.text);
        assert.equal(evalFail.data.mode, 'all');
        assert.equal(evalFail.data.allowed, false);
        assert.equal(evalFail.data.gate?.allowed, false);
        assert.equal(evalFail.data.jev?.approved, false);
      });
    });

    test('T2.6 EvidenceStore handles gzip-header plain-text corpus and maxRedirects:0 on retest/replay', async () => {
      let hitDest = 0;
      await withMockTarget(
        {
          routes: reqInfo => {
            if (reqInfo.pathname === '/redir') {
              return { status: 302, headers: { Location: '/dest' }, body: '' };
            }
            if (reqInfo.pathname === '/dest') {
              hitDest++;
              return { status: 200, body: 'DEST_REACHED' };
            }
            return { status: 200, body: 'ok' };
          }
        },
        async target => {
          await withAppHarness({ inMemory: true, retestOptions: { maxRedirects: 0 } }, async app => {
            // 1. Gzip header with already-decompressed plain-text body
            const ev = await app.jsonFetch('/api/findings/gzip-plain-1/evidence', {
              method: 'POST',
              body: {
                url: `${target.baseUrl}/gzip-case`,
                statusCode: 200,
                resHeaders: { 'content-encoding': 'gzip', 'content-type': 'text/plain' },
                resBody: 'plain text corpus containing verbatim_gzip_quote_123',
                quote: 'verbatim_gzip_quote_123',
                poeLevel: 3
              }
            });
            assert.equal(ev.status, 200, ev.text);
            assert.equal(ev.data.verification?.status, 'verified');

            // 2. maxRedirects: 0 on EvidenceStore retest
            await app.jsonFetch('/api/findings/redir-finding/evidence', {
              method: 'POST',
              body: {
                url: `${target.baseUrl}/redir`,
                statusCode: 200,
                resBody: 'initial_quote_12345',
                quote: 'initial_quote_12345',
                poeLevel: 3
              }
            });
            const retestRes = await app.jsonFetch('/api/findings/redir-finding/retest', {
              method: 'POST',
              body: { allowPrivate: true }
            });
            assert.ok(retestRes.status === 200 || retestRes.status === 400);
            assert.equal(hitDest, 0, 'maxRedirects:0 on retest must not follow redirect to /dest');

            // 3. maxRedirects: 0 on TrafficStore replay
            const ing = await app.jsonFetch('/api/traffic/ingest', {
              method: 'POST',
              body: { source: 'external', method: 'GET', url: `${target.baseUrl}/redir`, statusCode: 302 }
            });
            const exId = ing.data.recorded.id;
            const rep = await app.jsonFetch(`/api/traffic/${exId}/replay`, {
              method: 'POST',
              body: { allowPrivate: true }
            });
            assert.equal(rep.status, 400, `Expected maxRedirects:0 replay to reject 302 hop, got ${rep.status}: ${rep.text}`);
            assert.equal(hitDest, 0, 'maxRedirects:0 on replay must not follow redirect to /dest');
          });
        }
      );
    });

    test('T2.7 file-backed Task allowPrivate persists across server restart', async () => {
      await withTempDir(async historyDir => {
        let taskId;
        const app1 = await startAppHarness({ historyDir });
        try {
          const created = await app1.jsonFetch('/api/tasks', {
            method: 'POST',
            body: {
              title: 'Private Persistence Task',
              target: 'http://127.0.0.1:4321',
              allowPrivate: true
            }
          });
          assert.equal(created.status, 201, created.text);
          taskId = created.data.task.id;
          assert.equal(created.data.task.allowPrivate, true);
        } finally {
          await app1.close();
        }

        const app2 = await startAppHarness({ historyDir });
        try {
          const loaded = await app2.jsonFetch(`/api/tasks/${taskId}`);
          assert.equal(loaded.status, 200, loaded.text);
          assert.equal(
            loaded.data.task.allowPrivate,
            true,
            'Expected allowPrivate to persist in SQLite tasks table across restart'
          );
        } finally {
          await app2.close();
        }
      });
    });

    test('T2.8 static path traversal returns 403 and invalid component names return 403', async () => {
      await withAppHarness({ inMemory: true }, async app => {
        for (const badPath of [
          '/../package.json',
          '/%2e%2e/package.json',
          '/components/../../package.json',
          '/components/BadName!.js'
        ]) {
          const res = await rawHttpRequest({
            port: app.port,
            path: badPath,
            headers: { Host: `127.0.0.1:${app.port}` }
          });
          assert.equal(res.status, 403, `Expected 403 for ${badPath}, got ${res.status}`);
        }
      });
    });

    test('T2.9 ui/app.js uses inline notifications with zero alert() calls', async () => {
      const appJs = fs.readFileSync(path.join(REPO_ROOT, 'ui', 'app.js'), 'utf8');
      assert.equal(/\balert\s*\(/.test(appJs), false, 'ui/app.js must not use blocking alert() dialogs');
    });

    test('T2.10 ui/index.html & ui/app.js expose all catalog categories dynamically without stale 54/v2.1 strings', async () => {
      const html = fs.readFileSync(path.join(REPO_ROOT, 'ui', 'index.html'), 'utf8');
      assert.equal(/All 54 vulnerability checks/i.test(html), false, 'Stale hardcoded 54 checks subtitle should be updated');
      const hasStaticCatPills =
        html.includes('Supply Chain Security') &&
        html.includes('Network &amp; Transport') &&
        html.includes('Injection &amp; Input');
      const appJs = fs.readFileSync(path.join(REPO_ROOT, 'ui', 'app.js'), 'utf8');
      const rendersDynamicCategories = /meta\.categories|renderCategoryPills/.test(appJs);
      assert.ok(
        hasStaticCatPills || rendersDynamicCategories,
        'Expected all catalog categories to be rendered in Tab 7'
      );
    });

    test('T2.11 POST /api/scan rejects 4th concurrent scan with 429', async () => {
      await withMockTarget(
        {
          routes: {
            '/': { status: 200, body: '<html><body>slow</body></html>' },
            '/.env': { delayMs: 2500, status: 404, body: 'Not Found' }
          }
        },
        async target => {
          await withAppHarness({ inMemory: true }, async app => {
            const scanIds = [];
            for (let i = 0; i < 3; i++) {
              const r = await app.jsonFetch('/api/scan', {
                method: 'POST',
                body: { target: target.baseUrl, profile: 'quick', allowPrivate: true, noHistory: true, maxDepth: 0 }
              });
              assert.equal(r.status, 202);
              scanIds.push(r.data.scanId);
            }

            const fourth = await app.jsonFetch('/api/scan', {
              method: 'POST',
              body: { target: target.baseUrl, profile: 'quick', allowPrivate: true, noHistory: true, maxDepth: 0 }
            });
            assert.equal(fourth.status, 429);

            await Promise.all(scanIds.map(id => app.readSse(`/api/scan/${id}/stream`)));
          });
        }
      );
    });

    test('T2.12 POST /api/scan honors maxDepth: 0 (does not coerce 0 || 3)', async () => {
      await withMockTarget(
        {
          routes: {
            '/': { status: 200, body: '<html><body><a href="/crawl-should-not-hit">Sub</a></body></html>' },
            '/crawl-should-not-hit': { status: 200, body: '<html><body>Crawled!</body></html>' }
          }
        },
        async target => {
          await withAppHarness({ inMemory: true }, async app => {
            const start = await app.jsonFetch('/api/scan', {
              method: 'POST',
              body: { target: target.baseUrl, profile: 'quick', allowPrivate: true, noHistory: true, maxDepth: 0 }
            });
            assert.equal(start.status, 202);
            await app.readSse(`/api/scan/${start.data.scanId}/stream`);
            const crawled = target.requests.some(r => r.pathname === '/crawl-should-not-hit');
            assert.equal(crawled, false, 'maxDepth: 0 in POST /api/scan must not crawl linked subpages');
          });
        }
      );
    });
  });
});
