import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { runCli, withTempDir } from './helpers/cli-runner.mjs';
import { withAppHarness } from './helpers/app-server-harness.mjs';
import { createStackTarget, withMockTarget } from './helpers/mock-target-server.mjs';

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

describe('Tier 3 (Pairwise Combinatorial) & Tier 4 (Real-World Multi-Stack Scenarios)', () => {
  describe('Tier 3 — Pairwise Combinatorial Interactions (8 Tests)', () => {
    test('P1 .secscanrc + CLI override + simultaneous JSON/HTML/Markdown/CSV report generation', async () => {
      const target = await createStackTarget('nginx', 'vulnerable');
      try {
        await withTempDir(async tmpDir => {
          fs.writeFileSync(
            path.join(tmpDir, '.secscanrc'),
            JSON.stringify({
              targets: [target.baseUrl],
              profile: 'quick',
              allowPrivate: true,
              noHistory: true
            })
          );

          const res = await runCli(
            [
              '--profile',
              'nginx',
              '--json',
              '--html',
              '--markdown',
              'combined.md',
              '--csv',
              'combined.csv',
              '--output',
              'combined'
            ],
            { cwd: tmpDir }
          );
          assert.equal(res.code, 2, res.stderr);
          const json = JSON.parse(fs.readFileSync(path.join(tmpDir, 'combined.json'), 'utf8'));
          const html = fs.readFileSync(path.join(tmpDir, 'combined.html'), 'utf8');
          const md = fs.readFileSync(path.join(tmpDir, 'combined.md'), 'utf8');
          const csv = fs.readFileSync(path.join(tmpDir, 'combined.csv'), 'utf8');

          assert.ok(json.findings.some(f => (f.cveIds || []).includes('CVE-2026-123007')));
          assert.match(html, /CVE-2026-123007/);
          assert.match(md, /CVE-2026-123007/);
          assert.ok(csv.startsWith('\uFEFF') && csv.includes('\r\n'));
        });
      } finally {
        await target.close();
      }
    });

    test('P2 Fingerprint -> smart profile -> EnrichEngine (cveIds/cwe/owasp) -> cveCoverage summary', async () => {
      const target = await createStackTarget('nextjs', 'vulnerable');
      try {
        await withTempDir(async tmpDir => {
          const res = await runCli(
            [target.baseUrl, '--allow-private', '--profile', 'smart', '--no-history', '--json', '--output', 'smart-cve'],
            { cwd: tmpDir }
          );
          assert.equal(res.code, 2, res.stderr);
          const report = JSON.parse(fs.readFileSync(path.join(tmpDir, 'smart-cve.json'), 'utf8'));
          assert.ok(report.findings.some(f => Array.isArray(f.cveIds) && f.cveIds.includes('CVE-2025-29927')));
          assert.ok(report.cveCoverage && typeof report.cveCoverage.coveragePercent === 'number');
        });
      } finally {
        await target.close();
      }
    });

    test('P3 POST /api/scan -> SSE lifecycle -> GET /api/scan/:id/export (all 4 formats)', async () => {
      const target = await createStackTarget('spring', 'vulnerable');
      try {
        await withAppHarness({ inMemory: true }, async app => {
          const start = await app.jsonFetch('/api/scan', {
            method: 'POST',
            body: { target: target.baseUrl, profile: 'spring', allowPrivate: true, noHistory: true, maxDepth: 0 }
          });
          assert.equal(start.status, 202);
          const events = await app.readSse(`/api/scan/${start.data.scanId}/stream`);
          assert.ok(events.some(e => e.event === 'start'));
          assert.ok(events.some(e => e.event === 'complete'));

          for (const fmt of ['json', 'markdown', 'csv', 'html']) {
            const exp = await app.fetchApi(`/api/scan/${start.data.scanId}/export?format=${fmt}`);
            assert.equal(exp.status, 200);
          }
        });
      } finally {
        await target.close();
      }
    });

    test('P4 POST /api/scan -> GET /api/traffic?status=2xx -> replay -> Evidence bind/verify/retest (gzip)', async () => {
      let vulnerable = true;
      await withMockTarget(
        {
          routes: reqInfo => {
            if (reqInfo.pathname === '/') {
              return { status: 200, gzip: true, body: '<html><body>Root</body></html>' };
            }
            if (reqInfo.pathname === '/.env') {
              return vulnerable
                ? { status: 200, gzip: true, body: 'APP_KEY=base64:pairwise_gzip_secret\n' }
                : { status: 404, body: 'Not Found' };
            }
            return { status: 404, body: 'Not Found' };
          }
        },
        async target => {
          await withAppHarness({ inMemory: true }, async app => {
            const scan = await app.jsonFetch('/api/scan', {
              method: 'POST',
              body: { target: target.baseUrl, profile: 'quick', allowPrivate: true, noHistory: true, maxDepth: 0 }
            });
            assert.equal(scan.status, 202);
            await app.readSse(`/api/scan/${scan.data.scanId}/stream`);

            const traffic = await app.jsonFetch('/api/traffic?status=2xx');
            assert.equal(traffic.status, 200);
            assert.ok(traffic.data.exchanges.length >= 1);
            assert.ok(traffic.data.total >= traffic.data.exchanges.length);

            const envEx = traffic.data.exchanges.find(e => e.path === '/.env' || String(e.url).includes('/.env'));
            assert.ok(envEx, 'Expected /.env exchange in 2xx traffic');

            const replayed = await app.jsonFetch(`/api/traffic/${envEx.id}/replay`, {
              method: 'POST',
              body: { allowPrivate: true }
            });
            assert.equal(replayed.status, 200);

            const bound = await app.jsonFetch('/api/findings/pw-env-1/evidence', {
              method: 'POST',
              body: {
                exchangeId: envEx.id,
                quote: 'pairwise_gzip_secret',
                poeLevel: 3
              }
            });
            assert.equal(bound.status, 200, bound.text);
            assert.equal(bound.data.verification?.status, 'verified');

            vulnerable = false;
            const retest = await app.jsonFetch('/api/findings/pw-env-1/retest', {
              method: 'POST',
              body: { allowPrivate: true, evidenceQuotes: ['pairwise_gzip_secret'] }
            });
            assert.equal(retest.status, 200);
            assert.equal(retest.data.retest?.verdict, 'fixed');
          });
        }
      );
    });

    test('P5 PUT /api/guard/settings -> POST /api/guard/evaluate (mode:all) -> POST /api/scan gate enforcement', async () => {
      const target = await createStackTarget('clean-hardened');
      try {
        await withAppHarness({ inMemory: true }, async app => {
          const put = await app.jsonFetch('/api/guard/settings', {
            method: 'PUT',
            body: {
              noiseProfile: 'quiet',
              scopeRules: [{ action: 'deny', pattern: '*127.0.0.1*' }]
            }
          });
          assert.equal(put.status, 200);

          const evalDeny = await app.jsonFetch('/api/guard/evaluate', {
            method: 'POST',
            body: { target: target.baseUrl, toolName: 'GET', jevAnswers: ALL_JEV_TRUE }
          });
          assert.equal(evalDeny.status, 200);
          assert.equal(evalDeny.data.gate?.allowed, false);

          const blockedScan = await app.jsonFetch('/api/scan', {
            method: 'POST',
            body: { target: target.baseUrl, allowPrivate: true, noHistory: true }
          });
          assert.ok(blockedScan.status === 400 || blockedScan.status === 403);
          assert.equal(target.requests.length, 0);
        });
      } finally {
        await target.close();
      }
    });

    test('P6 Registry checks <-> GET /api/cves/coverage zero orphan checks consistency', async () => {
      await withAppHarness({ inMemory: true }, async app => {
        const meta = await app.jsonFetch('/api/meta');
        const cov = await app.jsonFetch('/api/cves/coverage');
        assert.equal(meta.status, 200);
        assert.equal(cov.status, 200);
        assert.equal(meta.data.totalChecks, meta.data.checks.length);
        assert.deepEqual(cov.data.orphanChecks, [], `Unexpected orphan checks: ${JSON.stringify(cov.data.orphanChecks)}`);
      });
    });

    test('P7 Agent task + Dual-Graph exploration/coverage + Asset DSL ingest/query + Asset tree', async () => {
      await withAppHarness({ inMemory: true }, async app => {
        const taskRes = await app.jsonFetch('/api/tasks', {
          method: 'POST',
          body: { title: 'Pairwise Graph Task', target: 'http://127.0.0.1:8080', allowPrivate: true }
        });
        assert.equal(taskRes.status, 201);
        const taskId = taskRes.data.task.id;

        const ingest = await app.jsonFetch('/api/assets/ingest', {
          method: 'POST',
          body: {
            taskId,
            tool: 'httpx',
            output: JSON.stringify({ url: 'https://api.example.com/v1/users', status_code: 200, tech: ['Spring'] })
          }
        });
        assert.equal(ingest.status, 200, ingest.text);

        const dsl = await app.jsonFetch('/api/assets?dsl=kind%3Dendpoint');
        assert.equal(dsl.status, 200);

        const expGraph = await app.jsonFetch(`/api/graph/exploration/${taskId}`);
        const covGraph = await app.jsonFetch(`/api/graph/coverage?taskId=${taskId}`);
        const assetTree = await app.jsonFetch(`/api/findings/asset-tree?taskId=${taskId}`);
        assert.equal(expGraph.status, 200);
        assert.equal(covGraph.status, 200);
        assert.equal(assetTree.status, 200);
      });
    });

    test('P8 GET /api/meta + GET /api/cves/coverage parity with UI HTML/JS markers', async () => {
      await withAppHarness({ inMemory: true }, async app => {
        const meta = await app.jsonFetch('/api/meta');
        const cov = await app.jsonFetch('/api/cves/coverage');
        const html = await (await app.fetchApi('/')).text();
        const appJs = await (await app.fetchApi('/app.js')).text();

        assert.equal(meta.data.version, '2.2.0');
        assert.equal(meta.data.cveCoverageSummary.totalAdvisories, cov.data.summary.totalAdvisories);
        assert.match(html, /tab-catalog/);
        assert.match(appJs, /\/api\/cves\/(coverage|audit)/);
      });
    });
  });

  describe('Tier 4 — Real-World Multi-Stack Application Scenarios (6 Scenarios)', () => {
    test('Scenario 1: Compromised Enterprise Hybrid Edge (NGINX HTTP/2 + Spring Actuator + .env via CLI)', async () => {
      const target = await createStackTarget('multi-stack-enterprise', 'vulnerable');
      try {
        await withTempDir(async tmpDir => {
          const res = await runCli(
            [
              target.baseUrl,
              '--allow-private',
              '--profile',
              'smart',
              '--no-history',
              '--json',
              '--html',
              '--markdown',
              'enterprise.md',
              '--output',
              'enterprise'
            ],
            { cwd: tmpDir }
          );
          assert.equal(res.code, 2, res.stderr);
          const report = JSON.parse(fs.readFileSync(path.join(tmpDir, 'enterprise.json'), 'utf8'));
          assert.ok(report.findings.some(f => f.checkId === 'env' && f.status === 'VULNERABLE'));
          assert.ok(report.findings.some(f => (f.cveIds || []).includes('CVE-2026-123007')));
          assert.ok(report.findings.some(f => (f.cveIds || []).includes('CVE-2026-114938')));
          assert.ok(report.cveCoverage && typeof report.cveCoverage.totalAdvisories === 'number');

          const html = fs.readFileSync(path.join(tmpDir, 'enterprise.html'), 'utf8');
          const md = fs.readFileSync(path.join(tmpDir, 'enterprise.md'), 'utf8');
          assert.match(html, /CVE-2026-123007/);
          assert.match(md, /CVE-2026-114938/);
        });
      } finally {
        await target.close();
      }
    });

    test('Scenario 2: Vulnerable Modern SaaS (Next.js + Node/Express + CORS via Server API/SSE/Traffic/Evidence)', async () => {
      const target = await createStackTarget('modern-saas', 'vulnerable');
      try {
        await withAppHarness({ inMemory: true }, async app => {
          const start = await app.jsonFetch('/api/scan', {
            method: 'POST',
            body: { target: target.baseUrl, profile: 'modern', allowPrivate: true, noHistory: true, maxDepth: 0 }
          });
          assert.equal(start.status, 202);
          const events = await app.readSse(`/api/scan/${start.data.scanId}/stream`);
          assert.ok(events.some(e => e.event === 'complete'));

          const scanRes = await app.jsonFetch(`/api/scan/${start.data.scanId}`);
          const results = scanRes.data.result.results;
          assert.ok(results.some(f => (f.cveIds || []).includes('CVE-2025-29927')));
          assert.ok(results.some(f => (f.checkId === 'cors' || f.name === 'cors misconfiguration') && f.status === 'VULNERABLE'));

          const traffic2xx = await app.jsonFetch('/api/traffic?status=2xx');
          assert.ok(traffic2xx.data.total >= 1);

          const exported = await app.jsonFetch(`/api/scan/${start.data.scanId}/export?format=json`);
          assert.equal(exported.status, 200);
          assert.ok(Array.isArray(exported.data.findings));
        });
      } finally {
        await target.close();
      }
    });

    test('Scenario 3: Legacy CMS & PHP Hosting (WordPress + RSSSL + Apache + PHP-CGI via CLI --force-all)', async () => {
      const target = await createStackTarget('legacy-cms-php', 'vulnerable');
      try {
        await withTempDir(async tmpDir => {
          const res = await runCli(
            [target.baseUrl, '--allow-private', '--force-all', '--depth', '0', '--no-history', '--json', '--output', 'legacy'],
            { cwd: tmpDir }
          );
          assert.equal(res.code, 2, res.stderr);
          const report = JSON.parse(fs.readFileSync(path.join(tmpDir, 'legacy.json'), 'utf8'));
          assert.ok(report.findings.some(f => (f.cveIds || []).includes('CVE-2024-4577')));
          assert.ok(report.findings.some(f => (f.cveIds || []).includes('CVE-2024-10924')));
          assert.ok(report.findings.some(f => f.checkId === 'wp-checks' && f.status !== 'SAFE'));
        });
      } finally {
        await target.close();
      }
    });

    test('Scenario 4: Hardened Production FinTech + Distro Backport (Zero VULNERABLE False Positives)', async () => {
      const hardened = await createStackTarget('clean-hardened');
      const backport = await createStackTarget('apache', 'backport');
      try {
        await withTempDir(async tmpDir => {
          const rClean = await runCli(
            [hardened.baseUrl, '--allow-private', '--force-all', '--depth', '0', '--no-history', '--json', '--output', 'fintech'],
            { cwd: tmpDir }
          );
          assert.equal(rClean.code, 0, rClean.stderr);
          const cleanJson = JSON.parse(fs.readFileSync(path.join(tmpDir, 'fintech.json'), 'utf8'));
          assert.equal(cleanJson.summary.vulnerable, 0);
          assert.ok(['LOW', 'MEDIUM'].includes(cleanJson.summary.level));

          const rBackport = await runCli(
            [backport.baseUrl, '--allow-private', '--profile', 'apache', '--depth', '0', '--no-history', '--json', '--output', 'bp'],
            { cwd: tmpDir }
          );
          assert.ok([0, 1].includes(rBackport.code), `Backport must not exit 2 (VULNERABLE): ${rBackport.code}`);
          const bpJson = JSON.parse(fs.readFileSync(path.join(tmpDir, 'bp.json'), 'utf8'));
          assert.equal(bpJson.summary.vulnerable, 0, 'Distro backport must never produce VULNERABLE FP');
        });
      } finally {
        await hardened.close();
        await backport.close();
      }
    });

    test('Scenario 5: Internal Audit with SSRF Redirect Trap & Guardrails', async () => {
      const trap = await createStackTarget('ssrf-redirect-trap');
      try {
        await withAppHarness({ inMemory: true }, async app => {
          const guardBlocked = await app.jsonFetch('/api/guard/evaluate', {
            method: 'POST',
            body: {
              target: 'https://agency.gov/admin',
              toolName: 'POST',
              jevAnswers: ALL_JEV_TRUE
            }
          });
          assert.equal(guardBlocked.status, 200);
          assert.equal(guardBlocked.data.gate?.allowed, false);

          const scan = await app.jsonFetch('/api/scan', {
            method: 'POST',
            body: { target: trap.baseUrl, profile: 'quick', allowPrivate: true, noHistory: true, maxDepth: 2 }
          });
          assert.equal(scan.status, 202);
          await app.readSse(`/api/scan/${scan.data.scanId}/stream`);
          const result = await app.jsonFetch(`/api/scan/${scan.data.scanId}`);
          assert.equal(result.data.status, 'completed');
          assert.equal(
            result.data.result.results.some(f => String(f.detail || '').includes('ami-id')),
            false
          );
        });
      } finally {
        await trap.close();
      }
    });

    test('Scenario 6: CI/CD Missing-CVE Governance Gate (CLI + HTTP API Parity)', async () => {
      await withTempDir(async tmpDir => {
        const uncoveredCatalog = path.join(tmpDir, 'ci-gate-missing.json');
        fs.writeFileSync(
          uncoveredCatalog,
          JSON.stringify([
            {
              cveId: 'CVE-2099-55555',
              ecosystem: 'apache',
              severity: 'CRITICAL',
              cvssScore: 9.8,
              kev: true,
              title: 'CI Gate Missing KEV'
            }
          ])
        );

        const failGate = await runCli(
          ['--cve-audit', '--tech', 'nextjs,spring,apache', '--cve-catalog', uncoveredCatalog, '--fail-on-missing-cves', '--json'],
          { cwd: tmpDir }
        );
        assert.notEqual(failGate.code, 0);
        const failJson = JSON.parse(failGate.stdout);
        assert.ok(failJson.summary.kevMissing >= 1);

        const coveredCatalog = path.join(tmpDir, 'ci-gate-pass.json');
        fs.writeFileSync(
          coveredCatalog,
          JSON.stringify([
            {
              cveId: 'CVE-2025-29927',
              ecosystem: 'nextjs',
              severity: 'CRITICAL',
              cvssScore: 9.1,
              kev: true,
              title: 'Covered Next.js CVE'
            }
          ])
        );

        await withAppHarness({ inMemory: true }, async app => {
          const apiAudit = await app.jsonFetch('/api/cves/audit', {
            method: 'POST',
            body: {
              techTags: ['nextjs', 'spring', 'apache'],
              advisories: JSON.parse(fs.readFileSync(uncoveredCatalog, 'utf8'))
            }
          });
          assert.equal(apiAudit.status, 200);
          assert.ok(apiAudit.data.summary.kevMissing >= 1);

          const cliPass = await runCli(
            ['--cve-audit', '--tech', 'unknown_empty_filter', '--fail-on-missing-cves', '--json'],
            { cwd: tmpDir }
          );
          assert.equal(cliPass.code, 0);
        });
      });
    });
  });
});
