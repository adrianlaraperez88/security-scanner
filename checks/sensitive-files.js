export const tags = ['all'];

/**
 * Checks for sensitive files accidentally exposed at the web root.
 * composer.lock is the most critical — reveals exact dependency versions
 * including any with known CVEs attackers can target directly.
 */
const FILES = [
  {
    path    : '/composer.json',
    severity: 'MEDIUM',
    reason  : 'Reveals dependency names and version constraints',
    signals : ['"require"', '"name"', '"version"']
  },
  {
    path    : '/composer.lock',
    severity: 'HIGH',
    reason  : 'Reveals exact dependency versions — attacker can look up CVEs for each',
    signals : ['"packages"', '"version"', '"dist"']
  },
  {
    path    : '/package.json',
    severity: 'LOW',
    reason  : 'Frontend dependency disclosure',
    signals : ['"dependencies"', '"scripts"', '"version"']
  },
  {
    path    : '/package-lock.json',
    severity: 'LOW',
    reason  : 'Exact frontend dependency versions',
    signals : ['"lockfileVersion"', '"packages"']
  },
  {
    path    : '/.htaccess',
    severity: 'MEDIUM',
    reason  : 'Web server configuration exposed',
    signals : ['RewriteRule', 'Options', 'Allow from', 'Deny from']
  },
  {
    path    : '/artisan',
    severity: 'MEDIUM',
    reason  : 'Laravel CLI entry point exposed — confirms stack and root path',
    signals : ['artisan', 'Laravel', 'Illuminate']
  },
  {
    path    : '/.DS_Store',
    severity: 'MEDIUM',
    reason  : 'macOS artifact — reveals directory structure to attackers',
    signals : [] // Binary file, just check status 200
  },
  {
    path    : '/web.config',
    severity: 'MEDIUM',
    reason  : 'IIS configuration file exposed',
    signals : ['<configuration>', '<system.web>', 'connectionStrings']
  },
  {
    path    : '/storage/logs/laravel.log',
    severity: 'HIGH',
    reason  : 'Application log file exposed (checked separately in laravel-storage.js)',
    signals : ['[error]', 'exception', 'stack trace'],
    skip    : true   // Already handled by laravel-storage.js
  },
  {
    path    : '/.git/config',
    severity: 'HIGH',
    reason  : 'Git config exposed — reveals remote URL and branch info',
    signals : ['[core]', '[remote', 'repositoryformatversion']
  },
];

export default async function run(target, fetchWithRetry) {
  const found = [];

  for (const file of FILES) {
    if (file.skip) continue;

    try {
      const res = await fetchWithRetry(`${target}${file.path}`);

      if (res.status !== 200) continue;

      // Verify the body actually looks like the expected file
      const isReal = file.signals.length === 0 ||
                     file.signals.some(sig => res.text.includes(sig));

      if (isReal) {
        found.push({ path: file.path, severity: file.severity, reason: file.reason });
      }

    } catch { /* path unreachable — skip */ }
  }

  if (found.length === 0) {
    return { name: 'sensitive files', status: 'SAFE', severity: 'NONE' };
  }

  const maxSev = found.some(f => f.severity === 'HIGH')   ? 'HIGH'
               : found.some(f => f.severity === 'MEDIUM') ? 'MEDIUM'
               : 'LOW';

  return {
    name    : 'sensitive files',
    status  : 'VULNERABLE',
    severity: maxSev,
    files   : found,
    fix     : 'Remove sensitive configuration or metadata files from the web root or deny access to them in your web server configuration (e.g., .htaccess, composer.json, etc.).'
  };
}
