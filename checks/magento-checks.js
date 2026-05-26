export const tags = ['magento', 'all'];

/**
 * Magento Admin Panel + Credential File Exposure
 *
 * Checks for misconfigured Magento installations where:
 *  - Admin panels are accessible to the public
 *  - Database credential files are web-accessible
 *  - Debug/health endpoints leak server information
 *  - Log files containing stack traces are readable
 */

const CHECKS = [
  // ── Credential files (CRITICAL) ─────────────────────────────────────────
  {
    path    : '/app/etc/local.xml',
    signals : ['<connection>', '<host>', '<username>', '<password>'],
    severity: 'CRITICAL',
    detail  : 'Magento 1 config — DB credentials in plaintext XML'
  },
  {
    path    : '/app/etc/env.php',
    signals : ['db', 'host', 'password', 'crypt', '<?php'],
    severity: 'CRITICAL',
    detail  : 'Magento 2 config — credentials and encryption key'
  },

  // ── Admin panels (HIGH) ───────────────────────────────────────────────────
  {
    path    : '/downloader/',
    signals : ['magento connect', 'downloader', 'package'],
    severity: 'HIGH',
    detail  : 'Magento Connect installer/admin panel accessible'
  },
  {
    path    : '/admin/dashboard',
    signals : ['magento', 'dashboard', 'admin'],
    severity: 'HIGH',
    detail  : 'Magento admin panel accessible at /admin'
  },
  {
    path    : '/backend/',
    signals : ['magento', 'dashboard'],
    severity: 'HIGH',
    detail  : 'Magento admin panel accessible at /backend'
  },

  // ── Version/info disclosure (MEDIUM) ─────────────────────────────────────
  {
    path    : '/magento_version',
    signals : ['magento', '.'],      // any version string "x.y.z"
    severity: 'MEDIUM',
    detail  : 'Magento version disclosed — enables targeted CVE exploitation'
  },
  {
    path    : '/pub/health_check.php',
    signals : ['ok', 'maintenance', 'magento'],
    severity: 'LOW',
    detail  : 'Magento health check accessible — leaks environment status'
  },

  // ── Log files (HIGH) ──────────────────────────────────────────────────────
  {
    path    : '/var/log/system.log',
    signals : ['magento', 'exception', 'error', 'warning', 'critical'],
    severity: 'HIGH',
    detail  : 'Magento system log readable — may contain credentials or internal paths'
  },
  {
    path    : '/var/log/exception.log',
    signals : ['exception', 'stack trace', '#0', 'vendor/magento'],
    severity: 'HIGH',
    detail  : 'Magento exception log readable — stack traces expose internal paths'
  },
];

export default async function run(target, fetchWithRetry) {
  const found = [];

  for (const check of CHECKS) {
    try {
      const res = await fetchWithRetry(`${target}${check.path}`);
      if (res.status !== 200) continue;

      const body     = res.text.toLowerCase();
      const hasSignal = check.signals.some(s => body.includes(s.toLowerCase()));
      if (hasSignal) {
        found.push({ path: check.path, severity: check.severity, detail: check.detail });
      }
    } catch { /* unreachable */ }
  }

  if (!found.length) {
    return { name: 'magento exposure', status: 'SAFE', severity: 'NONE' };
  }

  const maxSev = found.some(f => f.severity === 'CRITICAL') ? 'CRITICAL'
               : found.some(f => f.severity === 'HIGH')     ? 'HIGH'
               : 'MEDIUM';

  return {
    name    : 'magento exposure',
    status  : 'VULNERABLE',
    severity: maxSev,
    findings: found,
    detail  : `${found.length} Magento misconfiguration(s) found`,
    fix     : "Secure your Magento installation by denying access to the 'app/etc/', 'var/log/', and 'downloader/' directories. Move the admin panel to a non-default URL and restrict it to trusted IPs."
  };
}
