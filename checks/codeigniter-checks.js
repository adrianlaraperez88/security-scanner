export const tags = ['codeigniter', 'php', 'all'];

/**
 * CodeIgniter Security Checks
 *
 * CVE-2025-54418 (CVSS 10.0) — CodeIgniter4 < 4.6.2
 *   Command injection via ImageMagick handler — unauthenticated RCE
 *   via malicious file upload names or text input.
 *
 * General exposure checks:
 *   - /application/logs/  — log files with stack traces and credentials
 *   - /system/            — CodeIgniter system directory
 *   - /application/config/database.php — database credentials
 *   - Version detection via error pages / response content
 */

// CodeIgniter version patterns in error pages / meta
const VERSION_RE = /CodeIgniter\s+Version\s+([\d.]+)/i;

// CVE-2025-54418 vulnerable version: CodeIgniter4 < 4.6.2
function isVulnerableCI4(version) {
  const [major, minor, patch = 0] = version.split('.').map(Number);
  if (major !== 4) return false;
  if (minor < 6) return true;
  if (minor === 6 && patch < 2) return true;
  return false;
}

const CHECKS = [
  // ── Log / config file exposure ────────────────────────────────────────────
  {
    path    : '/application/logs/',
    signals : ['log-', '.php', 'index of', 'parent directory'],
    severity: 'HIGH',
    detail  : 'CodeIgniter log directory listing — stack traces and credentials exposed'
  },
  {
    path    : '/application/config/database.php',
    signals : ['<?php', 'hostname', 'password', 'database', 'dbdriver'],
    severity: 'CRITICAL',
    detail  : 'CodeIgniter database config accessible — DB credentials exposed'
  },
  {
    path    : '/system/',
    signals : ['index of', 'codeigniter', 'parent directory', 'core', 'database'],
    severity: 'HIGH',
    detail  : 'CodeIgniter /system/ directory browsable — source code accessible'
  },

  // ── Admin / install ───────────────────────────────────────────────────────
  {
    path    : '/install/',
    signals : ['install', 'codeigniter', 'database', 'setup'],
    severity: 'HIGH',
    detail  : 'CodeIgniter install script accessible — should be removed in production'
  },
];

export default async function run(target, fetchWithRetry) {
  const findings = [];
  let detectedVersion = null;

  // ── Step 1: Detect CodeIgniter + version ──────────────────────────────────
  try {
    const res  = await fetchWithRetry(target);
    const body = res.text;
    const m    = body.match(VERSION_RE);
    if (m) detectedVersion = m[1];
  } catch { /* skip */ }

  // Also probe the default CI welcome page
  try {
    const res  = await fetchWithRetry(`${target}/index.php/welcome/index`);
    const body = res.text;
    if (res.status === 200 && body.toLowerCase().includes('codeigniter')) {
      const m = body.match(VERSION_RE);
      if (m) detectedVersion = m[1];
      findings.push({
        path    : '/index.php/welcome/index',
        severity: 'LOW',
        detail  : 'CodeIgniter default welcome page accessible — confirms CI installation'
      });
    }
  } catch { /* skip */ }

  // ── Step 2: CVE-2025-54418 — version check ────────────────────────────────
  if (detectedVersion && isVulnerableCI4(detectedVersion)) {
    findings.push({
      path    : '/',
      severity: 'CRITICAL',
      detail  : `CodeIgniter ${detectedVersion} detected — vulnerable to CVE-2025-54418 (CVSS 10.0) command injection via ImageMagick handler`,
      cve     : 'CVE-2025-54418'
    });
  }

  // ── Step 3: Path-based exposure checks ───────────────────────────────────
  for (const check of CHECKS) {
    try {
      const res = await fetchWithRetry(`${target}${check.path}`);
      if (res.status !== 200) continue;

      const body     = res.text.toLowerCase();
      const hasSignal = check.signals.some(s => body.includes(s));

      if (hasSignal) {
        findings.push({ path: check.path, severity: check.severity, detail: check.detail });
      }
    } catch { /* unreachable */ }
  }

  if (!findings.length) {
    return { name: 'codeigniter exposure', status: 'SAFE', severity: 'NONE' };
  }

  const maxSev = findings.some(f => f.severity === 'CRITICAL') ? 'CRITICAL'
               : findings.some(f => f.severity === 'HIGH')     ? 'HIGH'
               : 'LOW';

  return {
    name    : 'codeigniter exposure',
    status  : maxSev === 'LOW' ? 'SUSPICIOUS' : 'VULNERABLE',
    severity: maxSev,
    version : detectedVersion ?? 'unknown',
    findings,
    detail  : `${findings.length} CodeIgniter issue(s) found`,
    fix     : "Update CodeIgniter to version 4.6.2 or higher immediately to patch CVE-2025-54418. Deny public access to 'application/logs' and 'system' directories in your web server configuration."
  };
}
