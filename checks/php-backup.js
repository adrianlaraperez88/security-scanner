export const tags = ['php', 'all'];

/**
 * Checks for PHP source code backup files at the web root.
 *
 * Backup files (.bak, .old, ~) bypass PHP execution and are served as
 * raw plaintext — immediately leaking database passwords, API keys,
 * and full application source code.
 *
 * This is one of the most common real-world findings in PHP app pentests.
 */
const BACKUP_FILES = [
  // Generic PHP root files
  { path: '/index.php.bak',      signals: ['<?php', 'require', 'include', 'define'] },
  { path: '/index.php.old',      signals: ['<?php', 'require', 'include', 'define'] },
  { path: '/index.php~',         signals: ['<?php', 'require', 'include', 'define'] },

  // Config backups (highest value — may contain credentials)
  { path: '/config.php.bak',     signals: ['<?php', 'DB_', 'database', 'password', 'host', 'user'] },
  { path: '/config.php.old',     signals: ['<?php', 'DB_', 'database', 'password'] },
  { path: '/config.php~',        signals: ['<?php', 'DB_', 'database', 'password'] },
  { path: '/configuration.php.bak', signals: ['<?php', 'database', 'password'] },
  { path: '/database.php.bak',   signals: ['<?php', 'host', 'password', 'database'] },

  // .env backups
  { path: '/.env.bak',           signals: ['APP_KEY', 'DB_PASSWORD', 'DB_HOST', '='] },
  { path: '/.env.old',           signals: ['APP_KEY', 'DB_PASSWORD', 'DB_HOST', '='] },
  { path: '/.env~',              signals: ['APP_KEY', 'DB_PASSWORD', 'DB_HOST', '='] },

  // Framework-specific
  { path: '/wp-config.php.bak',  signals: ['<?php', 'DB_NAME', 'DB_USER', 'DB_PASSWORD'] },
  { path: '/settings.php.bak',   signals: ['<?php', 'database', 'drupal'] },
  { path: '/app.php.bak',        signals: ['<?php', 'kernel', 'symfony', 'laravel'] },
];

// Signals that indicate a real file (not a 200 catch-all page)
const IS_SOURCE_CODE = ['<?php', 'DB_', 'password', 'database', 'APP_KEY', 'secret'];

export default async function run(target, fetchWithRetry) {
  const found = [];

  for (const file of BACKUP_FILES) {
    try {
      const res = await fetchWithRetry(`${target}${file.path}`);

      if (res.status !== 200) continue;

      // Confirm it's actually a backup file and not a catch-all page
      const body     = res.text;
      const hasSignal = file.signals.some(s => body.includes(s))
                     || IS_SOURCE_CODE.some(s => body.includes(s));

      if (hasSignal) {
        found.push({
          path  : file.path,
          detail: 'PHP source/config served as plaintext — contains credentials'
        });
      }

    } catch { /* path unreachable */ }
  }

  if (!found.length) {
    return { name: 'php backup files', status: 'SAFE', severity: 'NONE' };
  }

  return {
    name    : 'php backup files',
    status  : 'VULNERABLE',
    severity: 'HIGH',
    files   : found,
    detail  : `${found.length} backup file(s) expose PHP source code as plaintext`,
    fix     : "Remove all backup files (.bak, .old, ~, .swp) from the web server and ensure your deployment process excludes these artifacts from production."
  };
}
