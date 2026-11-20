import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { runCli, withTempDir } from './helpers/cli-runner.mjs';
import { createStackTarget, HARDENED_SECURITY_HEADERS, withMockTarget } from './helpers/mock-target-server.mjs';

const EXPECTED_18_PROFILES = [
  'smart',
  'quick',
  'api',
  'laravel',
  'wordpress',
  'php',
  'symfony',
  'magento',
  'drupal',
  'codeigniter',
  'node',
  'python',
  'spring',
  'nginx',
  'frontend',
  'modern',
  'cms',
  'full'
];

describe('F1: CLI Flags, Profiles, Checks & .secscanrc Config', () => {
  describe('Tier 1 — Happy Paths & Core CLI Discovery', () => {
    test('T1.1 --profiles lists all 18+ scan profiles and exits 0', async () => {
      const res = await runCli(['--profiles']);
      assert.equal(res.code, 0, `stderr: ${res.stderr}\nstdout: ${res.stdout}`);
      assert.match(res.stdout, /Available profiles:/i);
      for (const profile of EXPECTED_18_PROFILES) {
        assert.match(
          res.stdout,
          new RegExp(`\\b${profile}\\b`),
          `Expected profile "${profile}" in --profiles output`
        );
      }
    });

    test('T1.2 --list-checks displays check table with >= 54 checks and exits 0', async () => {
      const res = await runCli(['--list-checks']);
      assert.equal(res.code, 0, `stderr: ${res.stderr}`);
      assert.match(res.stdout, /Available Security Checks/i);
      assert.match(res.stdout, /ID\s+Category\s+Tags\s+Title/);
      const countMatch = res.stdout.match(/\((\d+)\s+total\)/i);
      assert.ok(countMatch, `Expected "(N total)" in --list-checks output:\n${res.stdout}`);
      const count = Number(countMatch[1]);
      assert.ok(count >= 54, `Expected >= 54 checks, got ${count}`);
      assert.match(res.stdout, /\benv\b/);
      assert.match(res.stdout, /\bnextjs-checks\b/);
    });

    test('T1.3 --help exits 0 and prints usage with 18+ profiles', async () => {
      const res = await runCli(['--help']);
      assert.equal(res.code, 0, `Expected --help to exit 0, got ${res.code}.\nstdout: ${res.stdout}\nstderr: ${res.stderr}`);
      assert.match(res.stdout, /Usage:\s*secscan/i);
      assert.match(res.stdout, /18\+?\s+profiles/i);
    });

    test('T1.4 --version exits 0 and reports 2.2.0', async () => {
      const res = await runCli(['--version']);
      assert.equal(res.code, 0, `Expected --version to exit 0, got ${res.code}.\nstdout: ${res.stdout}\nstderr: ${res.stderr}`);
      assert.match(res.stdout, /\b2\.2\.0\b/);
    });

    test('T1.5 --detect --allow-private fingerprints local Next.js target and exits 0', async () => {
      const target = await createStackTarget('nextjs', 'vulnerable');
      try {
        const res = await runCli(['--detect', '--allow-private', target.baseUrl]);
        assert.equal(res.code, 0, `stderr: ${res.stderr}\nstdout: ${res.stdout}`);
        assert.match(res.stdout, /Tech Stack Detection & Profile Recommendation/i);
        assert.match(res.stdout, /\bnextjs\b/i);
        assert.match(res.stdout, /Recommended Profile\s*:\s*modern/i);
        assert.match(res.stdout, /Relevant Checks Activated\s*:\s*\d+\s+active/i);
      } finally {
        await target.close();
      }
    });

    test('T1.6 .secscanrc in isolated cwd configures targets, profile, allowPrivate, and noHistory', async () => {
      const target = await createStackTarget('clean-hardened');
      try {
        await withTempDir(async tmpDir => {
          fs.writeFileSync(
            path.join(tmpDir, '.secscanrc'),
            JSON.stringify({
              targets: [target.baseUrl],
              profile: 'quick',
              allowPrivate: true,
              noHistory: true,
              json: true,
              output: 'rc-report'
            })
          );

          const res = await runCli([], { cwd: tmpDir });
          assert.equal(res.code, 0, `stderr: ${res.stderr}\nstdout: ${res.stdout}`);
          assert.equal(fs.existsSync(path.join(tmpDir, 'rc-report.json')), true, 'Expected rc-report.json from .secscanrc');
          assert.equal(fs.existsSync(path.join(tmpDir, '.secscan-history')), false, 'Expected no .secscan-history when noHistory:true');
          assert.equal(fs.existsSync(path.join(tmpDir, 'reports')), false, 'Expected no reports dir when noHistory:true');
        });
      } finally {
        await target.close();
      }
    });
  });

  describe('Tier 2 — Validation, Error Paths & Edge Cases', () => {
    test('T2.1 running with no arguments prints Usage and exits 1', async () => {
      const res = await runCli([]);
      assert.equal(res.code, 1);
      assert.match(res.stdout, /Usage:\s*secscan/i);
    });

    test('T2.2 invalid --noise-profile exits 1 with clear error message', async () => {
      const res = await runCli(['http://127.0.0.1:4321', '--allow-private', '--noise-profile', 'turbo_invalid']);
      assert.equal(res.code, 1);
      assert.match(res.stderr, /Invalid --noise-profile/i);
    });

    test('T2.3 invalid numeric args and missing flag values exit 1 cleanly', async () => {
      const invalidCases = [
        ['http://127.0.0.1:4321', '--allow-private', '--port', 'abc'],
        ['http://127.0.0.1:4321', '--allow-private', '--concurrency', '0'],
        ['http://127.0.0.1:4321', '--allow-private', '--timeout', 'NaN'],
        ['http://127.0.0.1:4321', '--allow-private', '--depth', '-1'],
        ['http://127.0.0.1:4321', '--allow-private', '--output']
      ];

      for (const argv of invalidCases) {
        const res = await runCli(argv);
        assert.equal(
          res.code,
          1,
          `Expected exit code 1 for invalid args [${argv.join(' ')}], got ${res.code}\nstdout: ${res.stdout}\nstderr: ${res.stderr}`
        );
        assert.doesNotMatch(res.stderr, /UnhandledPromiseRejection|TypeError:/);
      }
    });

    test('T2.4 unknown CLI flag exits 1 cleanly instead of silently ignoring', async () => {
      const res = await runCli(['http://127.0.0.1:4321', '--allow-private', '--nonexistent-flag-xyz']);
      assert.equal(
        res.code,
        1,
        `Expected exit code 1 for unknown flag, got ${res.code}\nstdout: ${res.stdout}\nstderr: ${res.stderr}`
      );
    });

    test('T2.5 malformed .secscanrc warns gracefully and CLI flags override .secscanrc values', async () => {
      await withMockTarget(
        {
          defaultHeaders: HARDENED_SECURITY_HEADERS,
          routes: { '/': { status: 200, body: '<html><body>ok</body></html>' } }
        },
        async target => {
          await withTempDir(async tmpDir => {
            fs.writeFileSync(path.join(tmpDir, '.secscanrc'), '{ bad json');
            const res1 = await runCli(
              [target.baseUrl, '--allow-private', '--profile', 'quick', '--no-history'],
              { cwd: tmpDir }
            );
            assert.equal(res1.code, 0, `stderr: ${res1.stderr}`);
            assert.match(res1.stdout + res1.stderr, /Failed to parse \.secscanrc/i);

            fs.writeFileSync(
              path.join(tmpDir, '.secscanrc'),
              JSON.stringify({ profile: 'full', noHistory: false, allowPrivate: false })
            );
            const res2 = await runCli(
              [target.baseUrl, '--allow-private', '--profile', 'quick', '--no-history', '--json', '--output', 'cli-win'],
              { cwd: tmpDir }
            );
            assert.equal(res2.code, 0, `stderr: ${res2.stderr}`);
            const report = JSON.parse(fs.readFileSync(path.join(tmpDir, 'cli-win.json'), 'utf8'));
            assert.ok(
              report.summary.totalChecks <= 12,
              `Expected CLI --profile quick to override .secscanrc full (got ${report.summary.totalChecks} checks)`
            );
            assert.equal(fs.existsSync(path.join(tmpDir, '.secscan-history')), false);
          });
        }
      );
    });

    test('T2.6 --new-check scaffolds plugin & test in cwd, and rejects invalid check names', async () => {
      await withTempDir(async tmpDir => {
        const valid = await runCli(['--new-check', 'e2e-sample-check'], { cwd: tmpDir });
        assert.equal(valid.code, 0, `stderr: ${valid.stderr}`);
        assert.equal(fs.existsSync(path.join(tmpDir, 'checks', 'e2e-sample-check.js')), true);
        assert.equal(fs.existsSync(path.join(tmpDir, 'tests', 'checks', 'e2e-sample-check.test.js')), true);

        const invalid = await runCli(['--new-check', 'INVALID_NAME!'], { cwd: tmpDir });
        assert.equal(invalid.code, 1);
      });
    });
  });
});
