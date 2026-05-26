/**
 * Scan profiles — pre-defined check sets for common use cases.
 *
 * Profiles filter which checks run. The `checks` array contains
 * the file-stem names (without .js) of the checks to include.
 * If `checks` is null, ALL checks run (filtered only by tech tags).
 */
export const PROFILES = {
  quick: {
    description: 'Fast scan of the highest-impact checks only (~5–10s)',
    checks: [
      'ssl-tls',
      'env',
      'security-headers',
      'server-disclosure',
      'http-redirect',
      'git',
      'sensitive-files',
    ]
  },

  api: {
    description: 'REST API security audit — rate limiting, CORS, JWT, auth routes',
    checks: [
      'ssl-tls',
      'cors',
      'security-headers',
      'rate-limit',
      'http-methods',
      'http-redirect',
      'api-endpoints',
      'jwt-security',
      'cookie-security',
      'laravel-auth',
      'server-disclosure',
      'open-redirect',
    ]
  },

  laravel: {
    description: 'Laravel application full audit',
    checks: [
      'ssl-tls',
      'env',
      'git',
      'ignition',
      'laravel-debug',
      'laravel-storage',
      'laravel-telescope',
      'laravel-auth',
      'laravel-livewire',
      'laravel-env-manipulation',
      'security-headers',
      'cors',
      'sensitive-files',
      'server-disclosure',
      'http-redirect',
      'rate-limit',
      'cookie-security',
      'phpunit-rce',
      'php-version',
      'php-backup',
      'php-config',
      'clickjacking',
      'sql-errors',
      'jwt-security',
    ]
  },

  wordpress: {
    description: 'WordPress site security audit',
    checks: [
      'ssl-tls',
      'wp-checks',
      'security-headers',
      'cors',
      'directory-listing',
      'git',
      'sensitive-files',
      'server-disclosure',
      'http-redirect',
      'clickjacking',
    ]
  },

  php: {
    description: 'Generic PHP application audit (Symfony, Magento, CodeIgniter, CakePHP, Drupal)',
    checks: [
      'ssl-tls',
      'php-version',
      'phpunit-rce',
      'php-backup',
      'php-config',
      'php-lfi',
      'php-cgi-exposure',
      'php-errors',
      'php-info',
      'env',
      'sensitive-files',
      'git',
      'security-headers',
      'cors',
      'cookie-security',
      'clickjacking',
      'sql-errors',
      'server-disclosure',
      'http-redirect',
      'rate-limit',
      'symfony-checks',
    ]
  },

  symfony: {
    description: 'Symfony framework security audit',
    checks: [
      'ssl-tls',
      'symfony-checks',
      'php-version',
      'phpunit-rce',
      'php-backup',
      'php-config',
      'php-lfi',
      'env',
      'sensitive-files',
      'security-headers',
      'cors',
      'clickjacking',
      'sql-errors',
      'cookie-security',
      'server-disclosure',
      'http-redirect',
    ]
  },

  magento: {
    description: 'Magento / Adobe Commerce security audit — CVE-2024-34102 and admin exposure',
    checks: [
      'ssl-tls',
      'magento-cosmicsting',
      'magento-checks',
      'php-version',
      'phpunit-rce',
      'php-backup',
      'php-cgi-exposure',
      'security-headers',
      'cors',
      'cookie-security',
      'clickjacking',
      'sql-errors',
      'server-disclosure',
      'http-redirect',
      'rate-limit',
      'open-redirect',
      'sensitive-files',
    ]
  },

  drupal: {
    description: 'Drupal CMS security audit — EOL detection and exposure checks',
    checks: [
      'ssl-tls',
      'drupal-checks',
      'php-version',
      'phpunit-rce',
      'php-backup',
      'php-config',
      'php-cgi-exposure',
      'security-headers',
      'cors',
      'cookie-security',
      'clickjacking',
      'sql-errors',
      'server-disclosure',
      'http-redirect',
      'sensitive-files',
    ]
  },

  codeigniter: {
    description: 'CodeIgniter framework audit — CVE-2025-54418 and exposure checks',
    checks: [
      'ssl-tls',
      'codeigniter-checks',
      'php-version',
      'phpunit-rce',
      'php-backup',
      'php-config',
      'php-lfi',
      'php-cgi-exposure',
      'security-headers',
      'cors',
      'cookie-security',
      'sql-errors',
      'server-disclosure',
      'http-redirect',
      'sensitive-files',
    ]
  },

  node: {
    description: 'Node.js / Express security audit',
    checks: [
      'ssl-tls',
      'node-checks',
      'security-headers',
      'cors',
      'cookie-security',
      'rate-limit',
      'http-methods',
      'http-redirect',
      'jwt-security',
      'api-endpoints',
      'server-disclosure',
      'sensitive-files',
    ]
  },

  python: {
    description: 'Python (Django/Flask) security audit',
    checks: [
      'ssl-tls',
      'python-checks',
      'security-headers',
      'cors',
      'cookie-security',
      'rate-limit',
      'http-methods',
      'http-redirect',
      'jwt-security',
      'api-endpoints',
      'server-disclosure',
      'sensitive-files',
    ]
  },

  frontend: {
    description: 'Modern Frontend (React, Angular, Vue) security audit',
    checks: [
      'ssl-tls',
      'frontend-checks',
      'security-headers',
      'http-redirect',
      'sensitive-files',
      'server-disclosure',
    ]
  },

  full: {
    description: 'All checks — comprehensive audit (default)',
    checks: null   // null = no filtering, run everything
  }
};

/**
 * Returns the array of allowed check names for a profile,
 * or null if all checks should run (full profile).
 */
export function getProfileChecks(profileName) {
  const profile = PROFILES[profileName?.toLowerCase()];
  if (!profile) {
    console.warn(`⚠️  Unknown profile "${profileName}" — defaulting to full`);
    return null;
  }
  return profile.checks;   // may be null for 'full'
}

export function listProfiles() {
  return Object.entries(PROFILES).map(([name, p]) =>
    `  ${name.padEnd(12)} ${p.description}`
  ).join('\n');
}
