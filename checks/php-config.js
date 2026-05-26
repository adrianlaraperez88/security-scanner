export const tags = ['php', 'all'];

/**
 * Checks for PHP application config files exposed at common paths.
 * These files typically contain database credentials, API keys, or secrets.
 *
 * Covers:
 *  - Generic PHP (config.php, database.php, db.php)
 *  - Symfony (parameters.yml, doctrine.yaml)
 *  - Magento 1.x (app/etc/local.xml)
 *  - Magento 2.x (app/etc/env.php)
 *  - Drupal (sites/default/settings.php)
 *  - CakePHP (config/app.php)
 *  - CodeIgniter (application/config/database.php)
 */
const CONFIG_FILES = [
  // ── Generic PHP ───────────────────────────────────────────────────────────
  {
    path   : '/config.php',
    signals: ['<?php', 'password', 'database', 'host', 'DB_'],
    severity: 'HIGH'
  },
  {
    path   : '/configuration.php',
    signals: ['<?php', 'password', 'database'],
    severity: 'HIGH'
  },
  {
    path   : '/config/database.php',
    signals: ['<?php', 'password', 'host', 'database'],
    severity: 'HIGH'
  },
  {
    path   : '/includes/config.php',
    signals: ['<?php', 'password', 'DB_', 'database'],
    severity: 'HIGH'
  },
  {
    path   : '/include/config.php',
    signals: ['<?php', 'password', 'DB_', 'database'],
    severity: 'HIGH'
  },
  {
    path   : '/db.php',
    signals: ['<?php', 'password', 'mysql', 'pgsql', 'mysqli'],
    severity: 'HIGH'
  },

  // ── Symfony ───────────────────────────────────────────────────────────────
  {
    path   : '/app/config/parameters.yml',
    signals: ['database_host', 'database_password', 'secret', 'mailer_'],
    severity: 'CRITICAL',
    note   : 'Symfony parameters file — contains DB credentials and app secret'
  },
  {
    path   : '/config/packages/doctrine.yaml',
    signals: ['doctrine', 'database', 'driver', 'dsn'],
    severity: 'MEDIUM'
  },

  // ── Magento 1.x ──────────────────────────────────────────────────────────
  {
    path   : '/app/etc/local.xml',
    signals: ['<connection>', '<host>', '<username>', '<password>'],
    severity: 'CRITICAL',
    note   : 'Magento 1 config — DB credentials in plaintext XML'
  },

  // ── Magento 2.x ──────────────────────────────────────────────────────────
  {
    path   : '/app/etc/env.php',
    signals: ['<?php', 'db', 'host', 'password', 'crypt'],
    severity: 'CRITICAL',
    note   : 'Magento 2 config — credentials and encryption key'
  },

  // ── Drupal ────────────────────────────────────────────────────────────────
  {
    path   : '/sites/default/settings.php',
    signals: ['<?php', 'database', 'drupal', 'username', 'password'],
    severity: 'HIGH'
  },

  // ── CakePHP ───────────────────────────────────────────────────────────────
  {
    path   : '/config/app.php',
    signals: ['<?php', 'password', 'host', 'database', 'SecuritySalt'],
    severity: 'HIGH'
  },

  // ── CodeIgniter ────────────────────────────────────────────────────────────
  {
    path   : '/application/config/database.php',
    signals: ['<?php', 'hostname', 'password', 'database', 'dbdriver'],
    severity: 'HIGH'
  },
];

export default async function run(target, fetchWithRetry) {
  const found = [];

  for (const file of CONFIG_FILES) {
    try {
      const res = await fetchWithRetry(`${target}${file.path}`);

      if (res.status !== 200) continue;

      const body      = res.text;
      const hasSignal = file.signals.some(s => body.includes(s));

      if (hasSignal) {
        found.push({
          path    : file.path,
          severity: file.severity,
          detail  : file.note ?? 'Config file with credentials accessible'
        });
      }

    } catch { /* path unreachable */ }
  }

  if (!found.length) {
    return { name: 'php config exposure', status: 'SAFE', severity: 'NONE' };
  }

  const maxSev = found.some(f => f.severity === 'CRITICAL') ? 'CRITICAL' : 'HIGH';

  return {
    name    : 'php config exposure',
    status  : 'VULNERABLE',
    severity: maxSev,
    files   : found,
    detail  : `${found.length} config file(s) with credentials publicly accessible`,
    fix     : 'IMMEDIATELY move configuration files out of the web root or deny all public access via server configuration. Rotate all database passwords and API keys found in these files.'
  };
}
