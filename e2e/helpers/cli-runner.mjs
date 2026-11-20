import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
export const REPO_ROOT = path.resolve(__dirname, '..', '..');
export const CLI_PATH = path.resolve(REPO_ROOT, 'bin', 'cli.js');

/**
 * Creates an isolated temp workspace under `os.tmpdir()`, executes `fn(tmpDir)`,
 * and cleans up with Windows-safe retries.
 *
 * @template T
 * @param {(tmpDir: string) => Promise<T>|T} fn
 * @param {string} [prefix='secscan-e2e-']
 * @returns {Promise<T>}
 */
export async function withTempDir(fn, prefix = 'secscan-e2e-') {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  try {
    return await fn(tmpDir);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  }
}

/**
 * Runs `bin/cli.js` in a subprocess with an isolated temp `cwd` unless `cwd` is explicitly provided.
 *
 * @param {string[]} args
 * @param {object} [options]
 * @param {string} [options.cwd]
 * @param {Record<string, string>} [options.env]
 * @param {number} [options.timeoutMs=45000]
 */
export async function runCli(args = [], options = {}) {
  const { cwd: providedCwd, env: extraEnv, timeoutMs = 45000 } = options;

  const execInDir = async workDir => {
    return new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [CLI_PATH, ...args], {
        cwd: workDir,
        env: { ...process.env, ...(extraEnv || {}) },
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true
      });

      const stdoutChunks = [];
      const stderrChunks = [];
      let timedOut = false;

      child.stdout.on('data', chunk => stdoutChunks.push(chunk));
      child.stderr.on('data', chunk => stderrChunks.push(chunk));

      const timer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGTERM');
        setTimeout(() => {
          if (!child.killed) child.kill('SIGKILL');
        }, 1500).unref();
      }, timeoutMs);

      child.once('error', err => {
        clearTimeout(timer);
        reject(err);
      });

      child.once('close', (code, signal) => {
        clearTimeout(timer);
        resolve({
          code: code ?? (timedOut ? 124 : 1),
          signal,
          timedOut,
          stdout: Buffer.concat(stdoutChunks).toString('utf8'),
          stderr: Buffer.concat(stderrChunks).toString('utf8'),
          cwd: workDir
        });
      });
    });
  };

  if (providedCwd) {
    return execInDir(providedCwd);
  }

  return withTempDir(tmpDir => execInDir(tmpDir));
}
