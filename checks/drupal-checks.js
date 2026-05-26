export const tags = ['drupal', 'php', 'all'];

/**
 * Drupal Security Checks
 *
 * CVEs covered:
 *   CVE-2025-13081 — Drupal Core object injection
 *   CVE-2024-55638 — Deserialization of untrusted data
 *   Drupal 7 EOL  — January 5, 2025 (CRITICAL — no more security patches)
 *   Drupal 9 EOL  — November 2023
 *
 * Detection approach (passive):
 *   1. Detect Drupal via headers (X-Generator, X-Drupal-Cache)
 *   2. Extract version from CHANGELOG.txt or meta generator tag
 *   3. Flag EOL versions as CRITICAL/HIGH
 *   4. Check exposed admin paths and file directories
 */

const CHANGELOG_PATHS = [
  '/CHANGELOG.txt',          // Drupal 7
  '/core/CHANGELOG.txt',     // Drupal 8/9/10/11
];

// Version extracted from "Drupal X.Y.Z, YYYY-MM-DD"
const VERSION_RE = /Drupal\s+([\d]+\.[\d.]+)/i;

// Drupal 7 EOL: Jan 2025 | Drupal 9 EOL: Nov 2023
function evaluateVersion(version) {
  const maj = parseInt(version?.split('.')[0] ?? '0', 10);
  if (maj <= 7)  return { eol: true,  severity: 'CRITICAL', label: `Drupal ${version} — EOL, no security patches` };
  if (maj === 9) return { eol: true,  severity: 'HIGH',     label: `Drupal ${version} — EOL since Nov 2023` };
  if (maj === 10) return { eol: false, severity: 'MEDIUM',  label: `Drupal ${version} — check for CVE-2025-13081 / CVE-2024-55638` };
  return { eol: false, severity: 'LOW', label: `Drupal ${version} — version disclosed (check advisories)` };
}

const PATH_CHECKS = [
  {
    path    : '/user/register',
    signals : ['create new account', 'register', 'username', 'email address'],
    severity: 'MEDIUM',
    detail  : 'Drupal open user registration — verify CAPTCHA and email verification are enforced'
  },
  {
    path    : '/sites/default/files/',
    signals : ['index of', 'parent directory', '.php', '.tar'],
    severity: 'HIGH',
    detail  : 'Drupal files directory browsable — may expose uploaded files or PHP scripts'
  },
  {
    path    : '/admin/reports/status',
    signals : ['site status', 'drupal', 'database', 'php version'],
    severity: 'HIGH',
    detail  : 'Drupal admin status report accessible without authentication'
  },
];

async function detectDrupal(target, fetchWithRetry) {
  try {
    const res  = await fetchWithRetry(target);
    const h    = res.headers ?? {};
    const html = res.text.toLowerCase();

    const byHeader = h['x-generator']?.toLowerCase().includes('drupal')
                  || !!h['x-drupal-cache']
                  || !!h['x-drupal-dynamic-cache'];

    const byHtml   = html.includes('drupal')
                  || html.includes('/sites/default/files');

    return byHeader || byHtml;
  } catch {
    return false;
  }
}

async function getVersion(target, fetchWithRetry) {
  for (const p of CHANGELOG_PATHS) {
    try {
      const res = await fetchWithRetry(`${target}${p}`);
      if (res.status !== 200) continue;

      const m = res.text.match(VERSION_RE);
      if (m) return { version: m[1], path: p };
    } catch { /* skip */ }
  }
  return { version: null, path: null };
}

export default async function run(target, fetchWithRetry) {
  // ── Step 1: Detect Drupal ─────────────────────────────────────────────────
  const isDrupal = await detectDrupal(target, fetchWithRetry);
  if (!isDrupal) {
    return { name: 'drupal exposure', status: 'SAFE', severity: 'NONE' };
  }

  const findings = [];

  // ── Step 2: Version extraction ────────────────────────────────────────────
  const { version, path: changelogPath } = await getVersion(target, fetchWithRetry);

  if (changelogPath) {
    // CHANGELOG.txt itself being accessible is an info leak
    findings.push({
      path    : changelogPath,
      severity: 'LOW',
      detail  : `CHANGELOG.txt accessible — reveals exact Drupal version${version ? ` (${version})` : ''}`
    });
  }

  if (version) {
    const vEval = evaluateVersion(version);
    if (vEval.eol || vEval.severity !== 'LOW') {
      findings.push({
        path    : changelogPath ?? '/',
        severity: vEval.severity,
        detail  : vEval.label,
        cve     : vEval.severity === 'CRITICAL' ? 'EOL + CVE-2025-13081, CVE-2024-55638'
                : vEval.severity === 'HIGH'     ? 'EOL + last patch cycle ended'
                : 'CVE-2025-13081, CVE-2024-55638'
      });
    }
  } else {
    // Drupal found but no version — still a risk signal
    findings.push({
      path    : '/',
      severity: 'LOW',
      detail  : 'Drupal detected — could not determine version. Verify it is fully patched.'
    });
  }

  // ── Step 3: Admin/file path checks ───────────────────────────────────────
  for (const check of PATH_CHECKS) {
    try {
      const res = await fetchWithRetry(`${target}${check.path}`);
      if (res.status !== 200) continue;

      const body = res.text.toLowerCase();
      if (check.signals.some(s => body.includes(s))) {
        findings.push({ path: check.path, severity: check.severity, detail: check.detail });
      }
    } catch { /* unreachable */ }
  }

  const maxSev = findings.some(f => f.severity === 'CRITICAL') ? 'CRITICAL'
               : findings.some(f => f.severity === 'HIGH')     ? 'HIGH'
               : findings.some(f => f.severity === 'MEDIUM')   ? 'MEDIUM'
               : 'LOW';

  return {
    name    : 'drupal exposure',
    status  : maxSev === 'LOW' ? 'SUSPICIOUS' : 'VULNERABLE',
    severity: maxSev,
    version : version ?? 'unknown',
    findings,
    detail  : `${findings.length} Drupal security issue(s) found`,
    fix     : "Upgrade Drupal to a supported version (10.x or 11.x) immediately, as Drupal 7 and 9 are EOL. Patch for CVE-2025-13081 and CVE-2024-55638, and restrict access to 'CHANGELOG.txt' and 'sites/default/files' browsing."
  };
}
