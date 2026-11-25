import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { runCli, withTempDir } from './helpers/cli-runner.mjs';
import { withAppHarness } from './helpers/app-server-harness.mjs';
import { startMockTarget } from './helpers/mock-target-server.mjs';
import { scaffoldCveLab } from '../core/cve-lab-runner.js';

describe('F9: Next-Gen PC Local Audit, OAST Blind Callbacks, Declarative CVE Templates & Lab Scaffolder (CLI + API)', () => {
  test('T1.1 secscan --pc-local --json runs zero-shell host security audit and returns structured 4-check report', async () => {
    const res = await runCli(['--pc-local', '--json']);
    assert.equal(res.code, 0, `stderr: ${res.stderr}\nstdout: ${res.stdout}`);
    const report = JSON.parse(res.stdout);

    assert.ok(report && typeof report === 'object');
    assert.equal(report.summary.totalChecks, 4);
    assert.ok(Array.isArray(report.findings));
    assert.equal(report.findings.length, 4);
    assert.ok(Array.isArray(report.listeningSockets));
  });

  test('T1.2 secscan <target> --templates <yaml> executes declarative YAML CVE template with Soft-404 FP protection', async () => {
    const tplPath = path.resolve('templates/cve-2025-29927-template.yaml');
    const target = await startMockTarget({
      routes: async reqInfo => {
        if (reqInfo.pathname === '/admin') {
          if (reqInfo.headers['x-middleware-subrequest']) {
            return {
              status: 200,
              headers: { 'Content-Type': 'text/html' },
              body: '<html><body><h1>Internal Admin Dashboard</h1></body></html>'
            };
          }
          return { status: 403, body: 'Forbidden' };
        }
        return { status: 200, body: '<html><body>Home</body></html>' };
      }
    });

    try {
      await withTempDir(async tmpDir => {
        const res = await runCli(
          [
            target.baseUrl,
            '--allow-private',
            '--no-history',
            '--depth',
            '0',
            '--check',
            'security-headers',
            '--templates',
            tplPath,
            '--json',
            '--output',
            'tpl-scan'
          ],
          { cwd: tmpDir }
        );
        assert.ok([0, 1, 2].includes(res.code), res.stderr);
        const report = JSON.parse(fs.readFileSync(path.join(tmpDir, 'tpl-scan.json'), 'utf8'));
        const tplFinding = report.findings.find(f => f.checkId === 'cve-2025-29927-template');
        assert.ok(tplFinding, 'Expected declarative template finding in scan report');
        assert.equal(tplFinding.status, 'VULNERABLE');
        assert.equal(tplFinding.severity, 'CRITICAL');
        assert.ok(tplFinding.cveIds.includes('CVE-2025-29927'));
      });
    } finally {
      await target.close();
    }
  });

  test('T1.3 scaffoldCveLab creates hardened Tri-State lab files in isolated labsDir and rejects duplicates/traversal', async () => {
    await withTempDir(async tmpDir => {
      const created = scaffoldCveLab('CVE-2024-34351', { labsDir: tmpDir });
      assert.equal(created.cveId, 'CVE-2024-34351');
      assert.equal(created.filesCreated.length, 5);

      const labFolder = path.join(tmpDir, 'CVE-2024-34351');
      for (const fname of ['manifest.json', 'Dockerfile', 'docker-compose.yml', 'server.mjs', 'README.md']) {
        assert.ok(fs.existsSync(path.join(labFolder, fname)), `Missing ${fname}`);
      }
      const composeText = fs.readFileSync(path.join(labFolder, 'docker-compose.yml'), 'utf8');
      assert.match(composeText, /127\.0\.0\.1:/);
      assert.match(composeText, /cap_drop/i);
      assert.match(composeText, /no-new-privileges:true/i);

      // Duplicate without overwrite throws 409
      assert.throws(
        () => scaffoldCveLab('CVE-2024-34351', { labsDir: tmpDir }),
        err => err.statusCode === 409
      );
    });

    const badCli = await runCli(['--new-cve-lab', '../../etc/passwd']);
    assert.equal(badCli.code, 1);
  });

  test('T1.4 REST API: GET /api/system/pc-audit, POST /api/templates/run, and POST /api/cves/labs/scaffold enforce guardrails', async () => {
    const target = await startMockTarget({
      routes: {
        '/actuator/info': {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
          body: { springBoot: { version: '3.3.3' }, springFramework: { version: '6.1.12' } }
        }
      }
    });

    try {
      await withAppHarness({ inMemory: true, allowPrivate: true }, async app => {
        // 1. GET /api/system/pc-audit
        const pcRes = await app.jsonFetch('/api/system/pc-audit');
        assert.equal(pcRes.status, 200, pcRes.text);
        assert.equal(pcRes.data.summary.totalChecks, 4);

        // 2. POST /api/templates/run (valid template)
        const tplRaw = fs.readFileSync(path.resolve('templates/spring-actuator-exposure.yaml'), 'utf8');
        const runRes = await app.jsonFetch('/api/templates/run', {
          method: 'POST',
          body: {
            template: tplRaw,
            targetUrl: target.baseUrl,
            allowPrivate: true
          }
        });
        assert.equal(runRes.status, 200, runRes.text);
        assert.equal(runRes.data.finding.status, 'VULNERABLE');

        // 3. POST /api/templates/run (rejects ReDoS regex template with 400)
        const redosRes = await app.jsonFetch('/api/templates/run', {
          method: 'POST',
          body: {
            targetUrl: target.baseUrl,
            allowPrivate: true,
            template: {
              id: 'redos-bad-tpl',
              info: { name: 'Bad ReDoS', severity: 'HIGH' },
              http: [
                {
                  method: 'GET',
                  path: ['{{BaseURL}}/'],
                  matchers: [{ type: 'regex', regex: ['(a+)+$'] }]
                }
              ]
            }
          }
        });
        assert.equal(redosRes.status, 400);

        // 4. POST /api/cves/labs/scaffold (rejects path traversal and existing lab overwrite without flag)
        const badScaffold = await app.jsonFetch('/api/cves/labs/scaffold', {
          method: 'POST',
          body: { cveId: '../etc/passwd' }
        });
        assert.equal(badScaffold.status, 400);

        const dupScaffold = await app.jsonFetch('/api/cves/labs/scaffold', {
          method: 'POST',
          body: { cveId: 'CVE-2025-29927' }
        });
        assert.equal(dupScaffold.status, 409);
      });
    } finally {
      await target.close();
    }
  });
});
