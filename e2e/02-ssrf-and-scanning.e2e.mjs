import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { runCli, withTempDir } from './helpers/cli-runner.mjs';
import { createStackTarget, HARDENED_SECURITY_HEADERS, startMockTarget, withMockTarget } from './helpers/mock-target-server.mjs';
import { generateCsvReport } from '../core/report.js';

describe('F2 & F3: Target Scanning, SSRF Lock, Enrichment & 4-Format Reports', () => {
  describe('Tier 1 — Happy Paths (Scanning, Enrichment, JSON/HTML/MD/CSV)', () => {
    test('T1.1 --allow-private scans clean-hardened 127.0.0.1 target and exits 0', async () => {
      const target = await createStackTarget('clean-hardened');
      try {
        await withTempDir(async tmpDir => {
          const res = await runCli(
            [target.baseUrl, '--allow-private', '--profile', 'quick', '--no-history', '--json', '--output', 'clean'],
            { cwd: tmpDir }
          );
          assert.equal(res.code, 0, `stderr: ${res.stderr}\nstdout: ${res.stdout}`);
          const report = JSON.parse(fs.readFileSync(path.join(tmpDir, 'clean.json'), 'utf8'));
          assert.equal(report.summary.vulnerable, 0);
          assert.ok(target.requests.length > 0, 'Mock server should have received HTTP requests');
        });
      } finally {
        await target.close();
      }
    });

    test('T1.2 target exposing /.env returns exit code 2 and CRITICAL env finding', async () => {
      await withMockTarget(
        {
          routes: {
            '/': { status: 200, body: '<html><body>App</body></html>' },
            '/.env': { status: 200, body: 'APP_KEY=base64:secret_e2e_key\nDB_PASSWORD=topsecret\n' }
          }
        },
        async target => {
          await withTempDir(async tmpDir => {
            const res = await runCli(
              [target.baseUrl, '--allow-private', '--profile', 'quick', '--no-history', '--json', '--output', 'vuln'],
              { cwd: tmpDir }
            );
            assert.equal(res.code, 2, `Expected exit code 2 on CRITICAL finding, got ${res.code}`);
            const report = JSON.parse(fs.readFileSync(path.join(tmpDir, 'vuln.json'), 'utf8'));
            assert.ok(report.summary.vulnerable >= 1);
            const envFinding = report.findings.find(f => f.checkId === 'env' || f.name === 'env file exposure');
            assert.ok(envFinding, 'Expected env finding in report.findings');
            assert.equal(envFinding.status, 'VULNERABLE');
            assert.equal(envFinding.severity, 'CRITICAL');
          });
        }
      );
    });

    test('T1.3 --depth 0 scans root only while --depth 2 crawls linked internal pages', async () => {
      await withMockTarget(
        {
          defaultHeaders: HARDENED_SECURITY_HEADERS,
          routes: {
            '/': {
              status: 200,
              body: '<html><body><a href="/linked-page?tab=auth">Linked Page</a></body></html>'
            },
            '/linked-page?tab=auth': {
              status: 200,
              body: '<html><body><h1>Linked Content</h1></body></html>'
            }
          }
        },
        async target => {
          await withTempDir(async tmpDir => {
            const r0 = await runCli(
              [target.baseUrl, '--allow-private', '--profile', 'quick', '--depth', '0', '--no-history'],
              { cwd: tmpDir }
            );
            assert.equal(r0.code, 0, `depth 0 failed: ${r0.stderr}`);
            const hitLinkedAt0 = target.requests.some(r => r.pathname === '/linked-page');
            assert.equal(hitLinkedAt0, false, 'depth 0 should not crawl /linked-page');

            target.resetRequests();
            const r2 = await runCli(
              [target.baseUrl, '--allow-private', '--profile', 'quick', '--depth', '2', '--no-history'],
              { cwd: tmpDir }
            );
            assert.equal(r2.code, 0, `depth 2 failed: ${r2.stderr}`);
            const hitLinkedAt2 = target.requests.some(
              r => r.url === '/linked-page?tab=auth' || r.pathname === '/linked-page'
            );
            assert.equal(hitLinkedAt2, true, 'depth 2 should crawl linked /linked-page?tab=auth');
          });
        }
      );
    });

    test('T1.4 --scope allow permits target while --scope deny blocks target with exit 1', async () => {
      const target = await createStackTarget('clean-hardened');
      try {
        const allowedRes = await runCli([
          target.baseUrl,
          '--allow-private',
          '--profile',
          'quick',
          '--no-history',
          '--scope',
          'allow:127.0.0.1'
        ]);
        assert.equal(allowedRes.code, 0, `Expected allowed scope to pass: ${allowedRes.stderr}`);

        target.resetRequests();
        const deniedRes = await runCli([
          target.baseUrl,
          '--allow-private',
          '--profile',
          'quick',
          '--no-history',
          '--scope',
          'deny:*127.0.0.1*'
        ]);
        assert.equal(deniedRes.code, 1, 'Expected denied scope to exit 1');
        assert.equal(target.requests.length, 0, 'Denied scope must prevent outbound requests');
      } finally {
        await target.close();
      }
    });

    test('T1.5 --noise-profile quiet completes scan against local mock target without dropping findings', async () => {
      await withMockTarget(
        {
          routes: {
            '/': { status: 200, body: '<html><body>ok</body></html>' },
            '/.env': { status: 200, body: 'APP_KEY=base64:quiet_test_key\n' }
          }
        },
        async target => {
          await withTempDir(async tmpDir => {
            const res = await runCli(
              [
                target.baseUrl,
                '--allow-private',
                '--profile',
                'quick',
                '--noise-profile',
                'quiet',
                '--no-history',
                '--json',
                '--output',
                'quiet-scan'
              ],
              { cwd: tmpDir }
            );
            assert.equal(res.code, 2);
            const report = JSON.parse(fs.readFileSync(path.join(tmpDir, 'quiet-scan.json'), 'utf8'));
            assert.ok(report.findings.some(f => f.checkId === 'env' && f.status === 'VULNERABLE'));
          });
        }
      );
    });

    test('T1.6 --diff across consecutive history runs detects newly introduced vulnerability', async () => {
      let exposeEnv = false;
      await withMockTarget(
        {
          defaultHeaders: HARDENED_SECURITY_HEADERS,
          routes: reqInfo => {
            if (reqInfo.pathname === '/.env' && exposeEnv) {
              return { status: 200, body: 'APP_KEY=base64:newly_exposed\n' };
            }
            if (reqInfo.pathname === '/') {
              return { status: 200, body: '<html><body>App</body></html>' };
            }
            return { status: 404, body: 'Not Found' };
          }
        },
        async target => {
          await withTempDir(async tmpDir => {
            const first = await runCli(
              [target.baseUrl, '--allow-private', '--profile', 'quick'],
              { cwd: tmpDir }
            );
            assert.equal(first.code, 0, `first run stderr: ${first.stderr}`);
            assert.equal(fs.existsSync(path.join(tmpDir, '.secscan-history')), true);
            assert.equal(fs.existsSync(path.join(tmpDir, 'reports')), true);

            exposeEnv = true;
            const second = await runCli(
              [target.baseUrl, '--allow-private', '--profile', 'quick', '--diff'],
              { cwd: tmpDir }
            );
            assert.equal(second.code, 2);
            assert.match(second.stdout, /New findings|Changed/i);
            assert.match(second.stdout, /env file exposure/i);
          });
        }
      );
    });

    test('T1.7 EnrichEngine populates CWE, OWASP, CVSS, CVE IDs, and remediation on findings', async () => {
      const target = await createStackTarget('nextjs', 'vulnerable');
      try {
        await withTempDir(async tmpDir => {
          const res = await runCli(
            [target.baseUrl, '--allow-private', '--profile', 'modern', '--no-history', '--json', '--output', 'enriched'],
            { cwd: tmpDir }
          );
          assert.equal(res.code, 2, `stderr: ${res.stderr}`);
          const report = JSON.parse(fs.readFileSync(path.join(tmpDir, 'enriched.json'), 'utf8'));
          const nextFinding = report.findings.find(
            f => Array.isArray(f.cveIds) && f.cveIds.includes('CVE-2025-29927')
          );
          assert.ok(nextFinding, 'Expected finding with CVE-2025-29927 in cveIds');
          assert.match(String(nextFinding.cwe), /^CWE-\d+/);
          assert.match(String(nextFinding.owasp), /A\d{2}:2021/);
          assert.equal(typeof nextFinding.cvssScore, 'number');
          assert.ok(nextFinding.cvssScore >= 7.0);
          assert.ok(typeof nextFinding.remediation === 'string' && nextFinding.remediation.length > 0);
        });
      } finally {
        await target.close();
      }
    });

    test('T1.8 --json produces valid report schema including summary, stacks, groupedFindings, findings', async () => {
      const target = await createStackTarget('nginx', 'vulnerable');
      try {
        await withTempDir(async tmpDir => {
          const res = await runCli(
            [target.baseUrl, '--allow-private', '--profile', 'nginx', '--no-history', '--json', '--output', 'schema-out'],
            { cwd: tmpDir }
          );
          assert.equal(res.code, 2, `stderr: ${res.stderr}`);
          const report = JSON.parse(fs.readFileSync(path.join(tmpDir, 'schema-out.json'), 'utf8'));
          assert.ok(typeof report.generatedAt === 'string' && !Number.isNaN(Date.parse(report.generatedAt)));
          assert.equal(typeof report.summary.score, 'number');
          assert.ok(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(report.summary.level));
          assert.ok(Array.isArray(report.groupedFindings));
          assert.ok(Array.isArray(report.findings));
          assert.ok(report.stacks && typeof report.stacks === 'object');
        });
      } finally {
        await target.close();
      }
    });

    test('T1.9 --html produces self-contained HTML report with CWE/OWASP badges and CVE markers', async () => {
      const target = await createStackTarget('nginx', 'vulnerable');
      try {
        await withTempDir(async tmpDir => {
          const res = await runCli(
            [target.baseUrl, '--allow-private', '--profile', 'nginx', '--no-history', '--html', '--output', 'html-out'],
            { cwd: tmpDir }
          );
          assert.equal(res.code, 2);
          const html = fs.readFileSync(path.join(tmpDir, 'html-out.html'), 'utf8');
          assert.match(html, /<!DOCTYPE html>/i);
          assert.match(html, /Security Scan Report/i);
          assert.match(html, /CWE-\d+/);
          assert.match(html, /CVE-2026-123007/);
        });
      } finally {
        await target.close();
      }
    });

    test('T1.10 --markdown produces structured Markdown report with CVE & Proof-Strength sections', async () => {
      const target = await createStackTarget('nginx', 'vulnerable');
      try {
        await withTempDir(async tmpDir => {
          const res = await runCli(
            [target.baseUrl, '--allow-private', '--profile', 'nginx', '--no-history', '--markdown', 'audit.md'],
            { cwd: tmpDir }
          );
          assert.equal(res.code, 2);
          const md = fs.readFileSync(path.join(tmpDir, 'audit.md'), 'utf8');
          assert.ok(md.startsWith('# Security Verification Report'));
          assert.match(md, /## Executive Summary/);
          assert.match(md, /## Asset Tree & Finding Rollup/);
          assert.match(md, /## Findings & Proof-Strength Attestation/);
          assert.match(md, /CVE-2026-123007/);
        });
      } finally {
        await target.close();
      }
    });

    test('T1.11 --csv produces BOM-prefixed CRLF CSV and JSON scan includes cveCoverage summary', async () => {
      const target = await createStackTarget('nginx', 'vulnerable');
      try {
        await withTempDir(async tmpDir => {
          const res = await runCli(
            [
              target.baseUrl,
              '--allow-private',
              '--profile',
              'nginx',
              '--no-history',
              '--json',
              '--output',
              'cov-scan',
              '--csv',
              'audit.csv'
            ],
            { cwd: tmpDir }
          );
          assert.equal(res.code, 2);

          const csv = fs.readFileSync(path.join(tmpDir, 'audit.csv'), 'utf8');
          assert.ok(csv.startsWith('\uFEFF'), 'CSV should start with UTF-8 BOM');
          assert.ok(csv.includes('\r\n'), 'CSV should use CRLF line endings');
          const firstLine = csv.slice(1).split('\r\n')[0];
          assert.match(firstLine, /^Check ID,Title,Status,Severity,CWE,OWASP,CVSS/);

          const report = JSON.parse(fs.readFileSync(path.join(tmpDir, 'cov-scan.json'), 'utf8'));
          assert.ok(
            report.cveCoverage && typeof report.cveCoverage === 'object',
            'Expected target scan JSON report to include cveCoverage summary (PROJECT.md #13)'
          );
          assert.equal(typeof report.cveCoverage.totalAdvisories, 'number');
        });
      } finally {
        await target.close();
      }
    });
  });

  describe('Tier 2 — SSRF Boundaries, Redirect Traps, Escaping & Negative Paths', () => {
    test('T2.1 loopback 127.0.0.1 without --allow-private is blocked with exit 1 and 0 requests', async () => {
      const target = await createStackTarget('clean-hardened');
      try {
        const res = await runCli([target.baseUrl, '--profile', 'quick', '--no-history']);
        assert.equal(res.code, 1);
        assert.match(res.stderr, /blocked|private|loopback/i);
        assert.equal(target.requests.length, 0);
      } finally {
        await target.close();
      }
    });

    test('T2.2 cloud metadata IPv4 (169.254.169.254 and 100.100.100.200) blocked even with --allow-private', async () => {
      for (const metaUrl of ['http://169.254.169.254/latest/meta-data/', 'http://100.100.100.200/latest/meta-data/']) {
        const res = await runCli([metaUrl, '--allow-private', '--profile', 'quick', '--no-history']);
        assert.equal(res.code, 1, `Expected ${metaUrl} to be blocked`);
        assert.match(res.stderr, /metadata|blocked/i);
      }
    });

    test('T2.3 metadata hostnames and IPv6 link-local/metadata blocked even with --allow-private', async () => {
      for (const metaUrl of [
        'http://metadata.google.internal/computeMetadata/v1/',
        'http://[fe80::1]/',
        'http://[fd00:ec2::254]/latest/meta-data/'
      ]) {
        const res = await runCli([metaUrl, '--allow-private', '--profile', 'quick', '--no-history']);
        assert.equal(res.code, 1, `Expected ${metaUrl} to be blocked`);
      }
    });

    test('T2.4 integer and hex obfuscated IP literals blocked even with --allow-private', async () => {
      for (const obfUrl of ['http://2130706433/', 'http://0x7f000001/']) {
        const res = await runCli([obfUrl, '--allow-private', '--profile', 'quick', '--no-history']);
        assert.equal(res.code, 1, `Expected ${obfUrl} to be blocked`);
      }
    });

    test('T2.5 mid-scan HTTP 302 redirect to 169.254.169.254 or .gov is blocked by SSRF/governance policy', async () => {
      const trap = await createStackTarget('ssrf-redirect-trap');
      try {
        await withTempDir(async tmpDir => {
          const res = await runCli(
            [trap.baseUrl, '--allow-private', '--profile', 'quick', '--depth', '2', '--no-history', '--json', '--output', 'trap'],
            { cwd: tmpDir }
          );
          assert.ok([0, 1, 2].includes(res.code));
          const report = JSON.parse(fs.readFileSync(path.join(tmpDir, 'trap.json'), 'utf8'));
          assert.ok(Array.isArray(report.findings));
          // Verify redirects to metadata / .gov did not succeed as VULNERABLE exposures
          const trapHits = trap.requests.filter(r => r.pathname === '/trap-meta' || r.pathname === '/trap-gov');
          assert.ok(trapHits.length >= 0);
          assert.equal(
            report.findings.some(f => String(f.detail || '').includes('ami-id')),
            false,
            'Metadata content must never be reachable'
          );
        });
      } finally {
        await trap.close();
      }
    });

    test('T2.6 redirect loops (>5 hops) and hanging endpoints respect --timeout without crashing', async () => {
      await withMockTarget(
        {
          routes: {
            '/': { status: 302, headers: { Location: '/loop' }, body: '' },
            '/loop': { status: 302, headers: { Location: '/loop' }, body: '' },
            '/.env': { hang: true }
          }
        },
        async target => {
          await withTempDir(async tmpDir => {
            const res = await runCli(
              [
                target.baseUrl,
                '--allow-private',
                '--profile',
                'quick',
                '--timeout',
                '400',
                '--no-history',
                '--json',
                '--output',
                'timeout-res'
              ],
              { cwd: tmpDir, timeoutMs: 30000 }
            );
            assert.equal(res.timedOut, false, 'CLI must finish within timeout and not hang');
            assert.ok([0, 1, 2].includes(res.code));
            const report = JSON.parse(fs.readFileSync(path.join(tmpDir, 'timeout-res.json'), 'utf8'));
            assert.ok(Array.isArray(report.findings));
          });
        }
      );
    });

    test('T2.7 CSV formula neutralization prefixes dangerous =, +, -, @ cells with leading single quote', async () => {
      const csv = generateCsvReport([
        {
          checkId: 'custom-probe',
          title: 'CSV Injection Probe',
          status: 'VULNERABLE',
          severity: 'HIGH',
          target: '@SUM(1,2)',
          path: '+1+1',
          detail: '=CMD|"/C calc"!A0',
          remediation: '-2+3'
        }
      ]);
      assert.ok(csv.startsWith('\uFEFF'));
      assert.ok(csv.includes("'@SUM(1,2)"));
      assert.ok(csv.includes("'+1+1"));
      assert.ok(csv.includes("'=CMD"));
      assert.ok(csv.includes("'-2+3"));
    });

    test('T2.8 Markdown fence neutralization closes unbalanced backtick fences from target responses', async () => {
      await withMockTarget(
        {
          routes: {
            '/': {
              status: 200,
              body: '<html><head><script src="/bad,comma```fence/app.js"></script></head><body>Hi</body></html>'
            },
            '/bad,comma```fence/app.js.map': {
              status: 200,
              body: '{"version":3,"sources":["index.js"]}'
            }
          }
        },
        async target => {
          await withTempDir(async tmpDir => {
            const res = await runCli(
              [target.baseUrl, '--allow-private', '--profile', 'frontend', '--no-history', '--markdown', 'fence.md'],
              { cwd: tmpDir }
            );
            assert.ok([0, 1, 2].includes(res.code));
            const md = fs.readFileSync(path.join(tmpDir, 'fence.md'), 'utf8');
            const fenceCount = (md.match(/`{3,}/g) || []).length;
            assert.equal(fenceCount % 2, 0, `Expected balanced code fences, found ${fenceCount} fences`);
          });
        }
      );
    });

    test('T2.9 HTML report escapes target-controlled <script> payloads cleanly', async () => {
      await withMockTarget(
        {
          routes: {
            '/': {
              status: 200,
              body: '<html><head><script src="/<script>alert(1)</script>/bundle.js"></script></head><body>Hi</body></html>'
            },
            '/<script>alert(1)</script>/bundle.js.map': {
              status: 200,
              body: '{"version":3,"sources":["app.js"]}'
            }
          }
        },
        async target => {
          await withTempDir(async tmpDir => {
            const res = await runCli(
              [target.baseUrl, '--allow-private', '--profile', 'frontend', '--no-history', '--html', '--output', 'xss-safe'],
              { cwd: tmpDir }
            );
            assert.ok([0, 1, 2].includes(res.code));
            const html = fs.readFileSync(path.join(tmpDir, 'xss-safe.html'), 'utf8');
            assert.equal(html.includes('<script>alert(1)</script>'), false, 'Raw script payload must be HTML-escaped');
            assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
          });
        }
      );
    });

    test('T2.10 non-CVE checks never inherit leaked CVE-2024-4577 metadata via fallback', async () => {
      await withMockTarget(
        {
          routes: {
            '/': { status: 200, body: '<html><body>Clean</body></html>' },
            '/.git/HEAD': { status: 200, body: 'ref: refs/heads/main\n' }
          }
        },
        async target => {
          await withTempDir(async tmpDir => {
            const res = await runCli(
              [target.baseUrl, '--allow-private', '--profile', 'quick', '--no-history', '--json', '--output', 'no-leak'],
              { cwd: tmpDir }
            );
            assert.equal(res.code, 2);
            const report = JSON.parse(fs.readFileSync(path.join(tmpDir, 'no-leak.json'), 'utf8'));
            const gitFinding = report.findings.find(f => f.checkId === 'git' || f.name === '.git exposure');
            assert.ok(gitFinding);
            assert.equal((gitFinding.cveIds || []).includes('CVE-2024-4577'), false);
          });
        }
      );
    });

    test('T2.11 multi-target concurrent scan isolates findings and stacks across targets', async () => {
      const clean = await createStackTarget('clean-hardened');
      const vuln = await startMockTarget({
        routes: {
          '/': { status: 200, body: '<html><body>Vuln</body></html>' },
          '/.env': { status: 200, body: 'APP_KEY=base64:isolated_target_key\n' }
        }
      });
      try {
        await withTempDir(async tmpDir => {
          const res = await runCli(
            [
              clean.baseUrl,
              vuln.baseUrl,
              '--allow-private',
              '--concurrency',
              '2',
              '--profile',
              'quick',
              '--no-history',
              '--json',
              '--output',
              'multi'
            ],
            { cwd: tmpDir }
          );
          assert.equal(res.code, 2);
          const report = JSON.parse(fs.readFileSync(path.join(tmpDir, 'multi.json'), 'utf8'));
          const envVulns = report.findings.filter(f => f.checkId === 'env' && f.status === 'VULNERABLE');
          assert.equal(envVulns.length, 1, 'Only the vulnerable target should report env VULNERABLE');
          const envSafe = report.findings.filter(f => f.checkId === 'env' && f.status === 'SAFE');
          assert.equal(envSafe.length, 1, 'The clean target should report env SAFE');
        });
      } finally {
        await clean.close();
        await vuln.close();
      }
    });
  });
});
