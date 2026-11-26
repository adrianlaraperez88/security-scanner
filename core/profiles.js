import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Scan profiles — pre-defined check sets for common use cases.
 *
 * Profiles filter which checks run. The `checks` array contains
 * the file-stem names (without .js) of the checks to include.
 * If `checks` is null, ALL checks run (filtered only by tech tags).
 */
export const PROFILES = {
  smart: {
    description: 'Smart Auto-Detect — fingerprints the site tech stack first and runs universal + matching technology checks (recommended)',
    checks: null,
    smart: true
  },

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
      'ai-llm-exposure',
    ]
  },

  api: {
    description: 'REST & GraphQL API security audit — rate limiting, CORS, JWT, injection & auth',
    checks: [
      'ssl-tls',
      'system-health',
      'origin-source-ip',
      'api-security-spectrum',
      'bola-mass-assignment',
      'ssti-check',
      'cache-poisoning',
      'http-desync-smuggling',
      'dom-xss-sinks',
      'xxe-injection',
      'crlf-header-injection',
      'ssrf-surface',
      'cors',
      'security-headers',
      'rate-limit',
      'http-methods',
      'http-redirect',
      'api-endpoints',
      'api-communication',
      'graphql',
      'jwt-security',
      'cookie-security',
      'env',
      'git',
      'sql-errors',
      'sqli',
      'xss',
      'server-disclosure',
      'open-redirect',
      'ai-llm-exposure',
      'cve-2026-123007',
      'cve-2026-123633',
      'cve-2026-123634',
      'cve-nginx-http3',
      'cve-nginx-tls',
      'cve-2026-114938',
      'cve-jdk-advisories',
      'cve-nextjs-react',
      'cve-spring-framework',
      'cve-tomcat',
      'cve-python-web',
      'cve-node-express',
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
      'php-errors',
      'php-info',
      'php-lfi',
      'php-cgi-exposure',
      'php-session-upload-progress',
      'cve-2024-4577',
      'cve-php-ecosystem',
      'admin-panels',
      'robots-sitemap',
      'clickjacking',
      'sql-errors',
      'sqli',
      'xss',
      'jwt-security',
    ]
  },

  wordpress: {
    description: 'WordPress site security audit',
    checks: [
      'ssl-tls',
      'wp-checks',
      'cve-wordpress-ecosystem',
      'security-headers',
      'cors',
      'cookie-security',
      'directory-listing',
      'env',
      'git',
      'sensitive-files',
      'server-disclosure',
      'http-redirect',
      'clickjacking',
      'php-version',
      'php-backup',
      'php-config',
      'php-errors',
      'php-info',
      'php-lfi',
      'php-cgi-exposure',
      'phpunit-rce',
      'cve-2024-4577',
      'sql-errors',
      'admin-panels',
      'robots-sitemap',
      'sqli',
      'xss',
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
      'cve-2024-4577',
      'cve-php-ecosystem',
      'cve-apache-httpd',
      'env',
      'sensitive-files',
      'git',
      'security-headers',
      'cors',
      'cookie-security',
      'clickjacking',
      'sql-errors',
      'sqli',
      'xss',
      'admin-panels',
      'robots-sitemap',
      'server-disclosure',
      'http-redirect',
      'rate-limit',
      'symfony-checks',
      'yii-checks',
      'codeigniter-checks',
      'drupal-checks',
      'magento-checks',
    ]
  },

  yii: {
    description: 'Yii 1.x & Yii 2.x framework security audit — Gii, Debug toolbar, CVE-2024-58136 & config exposure',
    checks: [
      'ssl-tls',
      'yii-checks',
      'php-version',
      'phpunit-rce',
      'php-backup',
      'php-config',
      'php-lfi',
      'php-errors',
      'php-info',
      'php-cgi-exposure',
      'php-session-upload-progress',
      'cve-2024-4577',
      'cve-php-ecosystem',
      'env',
      'sensitive-files',
      'security-headers',
      'cors',
      'cookie-security',
      'clickjacking',
      'sql-errors',
      'sqli',
      'xss',
      'admin-panels',
      'robots-sitemap',
      'server-disclosure',
      'http-redirect',
      'rate-limit',
      'runtime-sca',
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
      'php-errors',
      'php-info',
      'cve-2024-4577',
      'cve-php-ecosystem',
      'env',
      'sensitive-files',
      'security-headers',
      'cors',
      'clickjacking',
      'sql-errors',
      'sqli',
      'xss',
      'admin-panels',
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
      'php-lfi',
      'php-errors',
      'php-info',
      'php-cgi-exposure',
      'cve-2024-4577',
      'security-headers',
      'cors',
      'cookie-security',
      'clickjacking',
      'sql-errors',
      'sqli',
      'xss',
      'admin-panels',
      'robots-sitemap',
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
      'php-lfi',
      'php-errors',
      'php-info',
      'php-cgi-exposure',
      'cve-2024-4577',
      'security-headers',
      'cors',
      'cookie-security',
      'clickjacking',
      'sql-errors',
      'sqli',
      'xss',
      'admin-panels',
      'robots-sitemap',
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
      'php-errors',
      'php-info',
      'php-cgi-exposure',
      'cve-2024-4577',
      'security-headers',
      'cors',
      'cookie-security',
      'clickjacking',
      'sql-errors',
      'sqli',
      'xss',
      'admin-panels',
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
      'cve-node-express',
      'security-headers',
      'cors',
      'cookie-security',
      'rate-limit',
      'http-methods',
      'http-redirect',
      'jwt-security',
      'api-endpoints',
      'graphql',
      'sqli',
      'xss',
      'server-disclosure',
      'sensitive-files',
      'nextjs-checks',
      'cve-nextjs-react',
      'ai-llm-exposure',
      'sri-supply-chain',
    ]
  },

  python: {
    description: 'Python (Django/Flask) security audit',
    checks: [
      'ssl-tls',
      'python-checks',
      'cve-python-web',
      'security-headers',
      'cors',
      'cookie-security',
      'rate-limit',
      'http-methods',
      'http-redirect',
      'jwt-security',
      'api-endpoints',
      'sqli',
      'xss',
      'server-disclosure',
      'sensitive-files',
    ]
  },

  spring: {
    description: 'Spring Boot / Java application security audit',
    checks: [
      'ssl-tls', 'system-health', 'spring-checks', 'cve-2026-114938', 'cve-jdk-advisories', 'cve-spring-framework', 'cve-tomcat',
      'security-headers', 'cors', 'cookie-security',
      'rate-limit', 'http-methods', 'http-redirect', 'jwt-security', 'api-endpoints',
      'sqli', 'xss', 'server-disclosure', 'sensitive-files', 'env', 'git'
    ]
  },

  nginx: {
    description: 'NGINX web server & HTTP/2 reverse proxy security audit',
    checks: [
      'ssl-tls',
      'system-health',
      'security-headers',
      'server-disclosure',
      'cve-2026-123007',
      'cve-2026-123633',
      'cve-2026-123634',
      'cve-nginx-http3',
      'cve-nginx-tls',
      'cors',
      'http-methods',
      'http-redirect',
      'rate-limit',
      'sensitive-files',
    ]
  },

  apache: {
    description: 'Apache HTTP Server & proxy CVE security audit',
    checks: [
      'ssl-tls',
      'system-health',
      'security-headers',
      'server-disclosure',
      'cve-apache-httpd',
      'cors',
      'http-methods',
      'http-redirect',
      'directory-listing',
      'sensitive-files',
    ]
  },

  ops: {
    description: 'System health, telemetry, TLS, headers, and operational stability audit',
    checks: [
      'system-health',
      'device-security',
      'os-security',
      'origin-source-ip',
      'subdomain-takeover',
      'iis-shortname',
      'ssl-tls',
      'security-headers',
      'server-disclosure',
      'rate-limit',
      'http-methods',
      'http-redirect',
      'api-endpoints',
      'api-security-spectrum',
    ]
  },

  device: {
    description: 'Smart TV, IP Camera/NVR, PC/Workstation & Network Device audit — non-intrusive multi-port discovery (Samsung Tizen, LG webOS, Roku, Cast, AirPlay, RTSP/ONVIF/Hikvision/Dahua/Axis, SMB/RDP/WinRM/SSH/VNC/CUPS/Docker/Ollama/dev servers, Routers, Printers, NAS)',
    checks: [
      'device-security',
      'os-security',
      'ssl-tls',
      'system-health',
      'origin-source-ip',
      'security-headers',
      'server-disclosure',
      'admin-panels',
      'api-endpoints',
      'cors',
      'http-methods',
      'http-redirect',
      'cookie-security',
      'sensitive-files',
    ]
  },

  frontend: {
    description: 'Modern Frontend (React, Angular, Vue) security audit',
    checks: [
      'ssl-tls',
      'frontend-checks',
      'api-communication',
      'cors',
      'api-endpoints',
      'graphql',
      'jwt-security',
      'security-headers',
      'http-redirect',
      'sensitive-files',
      'server-disclosure',
      'robots-sitemap',
      'xss',
      'nextjs-checks',
      'cve-nextjs-react',
      'ai-llm-exposure',
      'sri-supply-chain',
      'runtime-sca',
    ]
  },

  modern: {
    description: 'Modern Web, Next.js, Node & AI/Supply-Chain security audit',
    checks: [
      'ssl-tls',
      'security-headers',
      'cors',
      'frontend-checks',
      'api-communication',
      'nextjs-checks',
      'cve-nextjs-react',
      'node-checks',
      'cve-node-express',
      'ai-llm-exposure',
      'sri-supply-chain',
      'runtime-sca',
      'jwt-security',
      'rate-limit',
      'api-endpoints',
      'graphql',
      'http-methods',
      'open-redirect',
      'server-disclosure',
      'clickjacking',
      'robots-sitemap',
      'sqli',
      'xss',
      'cookie-security',
      'env',
      'git',
      'sensitive-files',
      'http-redirect',
      'cve-2026-123007',
      'cve-2026-123633',
      'cve-2026-123634',
      'cve-nginx-http3',
      'cve-nginx-tls',
    ]
  },

  cms: {
    description: 'CMS & E-Commerce security audit (WordPress, Laravel, Magento, Drupal, PHP)',
    checks: [
      'ssl-tls',
      'security-headers',
      'wp-checks',
      'cve-wordpress-ecosystem',
      'drupal-checks',
      'magento-checks',
      'magento-cosmicsting',
      'codeigniter-checks',
      'laravel-auth',
      'laravel-debug',
      'laravel-livewire',
      'laravel-env-manipulation',
      'laravel-storage',
      'laravel-telescope',
      'ignition',
      'symfony-checks',
      'yii-checks',
      'php-version',
      'php-config',
      'php-backup',
      'php-cgi-exposure',
      'php-info',
      'php-errors',
      'php-lfi',
      'phpunit-rce',
      'cve-2024-4577',
      'cve-php-ecosystem',
      'cve-apache-httpd',
      'directory-listing',
      'admin-panels',
      'robots-sitemap',
      'sql-errors',
      'sqli',
      'xss',
      'env',
      'git',
      'sensitive-files',
      'cookie-security',
      'clickjacking',
      'http-redirect',
      'runtime-sca',
    ]
  },

  full: {
    description: 'All checks — comprehensive audit (default)',
    checks: null   // null = no filtering, run everything
  }
};

export const DEVICE_PROFILE_ALIASES = new Set([
  'tv',
  'smart-tv',
  'smart_tv',
  'iot',
  'camera',
  'cam',
  'nvr',
  'ip-camera',
  'ip_camera',
  'pc',
  'workstation',
  'server',
  'pc-workstation',
  'pc_workstation',
  'lan'
]);

export const YII_PROFILE_ALIASES = new Set([
  'yii1',
  'yii2',
  'yii-1',
  'yii-2'
]);

/**
 * Returns the array of allowed check names for a profile,
 * or null if all checks should run (full profile).
 */
export function getProfileChecks(profileName) {
  const norm = profileName?.toLowerCase();
  const resolvedName = DEVICE_PROFILE_ALIASES.has(norm)
    ? 'device'
    : (YII_PROFILE_ALIASES.has(norm) ? 'yii' : norm);
  const profile = PROFILES[resolvedName];
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

/**
 * Parameterized active fuzzing checks to run across all discovered pages.
 */
export const ACTIVE_FUZZING_CHECKS = new Set(['xss', 'sqli', 'open-redirect', 'php-lfi']);

/**
 * Selects active scanners and identifies skipped scanners based on profile and detected tech stack.
 *
 * @param {Array} scanners - Array of scanner check objects ({ name, tags, run, ... })
 * @param {object} [options={}]
 * @param {string} [options.profile='smart'] - Scan profile name
 * @param {object} [options.fp=null] - Fingerprint result ({ detectedTags, stack, primary })
 * @param {Array|string} [options.techOverride=null] - User-supplied tech tags to override/augment detection
 * @param {boolean} [options.forceAll=false] - When true, forces execution of all scanners
 * @returns {{ activeScanners: Array, skippedScanners: Array, effectiveProfile: string, detectedTags?: string[], reason?: string }}
 */
export function selectScannersForStack(scanners = [], { profile = 'smart', fp = null, techOverride = null, forceAll = false } = {}) {
  if (forceAll === true) {
    return {
      activeScanners: [...scanners],
      skippedScanners: [],
      effectiveProfile: profile,
      reason: 'Force-all enabled: running all checks'
    };
  }

  const overrideTags = Array.isArray(techOverride)
    ? techOverride.map(t => String(t).toLowerCase().trim()).filter(Boolean)
    : typeof techOverride === 'string'
    ? techOverride.split(',').map(t => t.toLowerCase().trim()).filter(Boolean)
    : [];

  const rawTags = Array.isArray(fp?.detectedTags)
    ? fp.detectedTags
    : typeof fp?.detectedTags === 'string'
    ? fp.detectedTags.split(',')
    : Array.isArray(fp?.stack)
    ? fp.stack
        .filter(Boolean)
        .map(s => (typeof s === 'string' ? s : s?.tech))
        .filter(Boolean)
    : [];
  const detectedTags = new Set(
    rawTags
      .map(t => String(t).toLowerCase().trim())
      .filter(Boolean)
  );

  const profileChecks = getProfileChecks(profile);

  const activeScanners = [];
  const skippedScanners = [];

  if (overrideTags.length > 0) {
    for (const s of scanners) {
      if (Array.isArray(profileChecks) && !profileChecks.includes(s.name)) {
        skippedScanners.push(s);
      } else {
        const sTags = Array.isArray(s.tags) ? s.tags.map(t => String(t).toLowerCase()) : [];
        if (sTags.includes('all') || sTags.includes('universal') || sTags.some(t => overrideTags.includes(t))) {
          activeScanners.push(s);
        } else {
          skippedScanners.push(s);
        }
      }
    }
  } else if (Array.isArray(profileChecks)) {
    for (const s of scanners) {
      if (profileChecks.includes(s.name)) {
        activeScanners.push(s);
      } else {
        skippedScanners.push(s);
      }
    }
  } else {
    const normProfile = String(profile || 'smart').toLowerCase();
    if (detectedTags.size > 0) {
      for (const s of scanners) {
        const sTags = Array.isArray(s.tags) ? s.tags.map(t => String(t).toLowerCase()) : [];
        if (sTags.includes('all') || sTags.includes('universal') || sTags.some(t => detectedTags.has(t))) {
          activeScanners.push(s);
        } else {
          skippedScanners.push(s);
        }
      }
    } else {
      if (normProfile === 'full') {
        activeScanners.push(...scanners);
      } else {
        for (const s of scanners) {
          const sTags = Array.isArray(s.tags) ? s.tags.map(t => String(t).toLowerCase()) : [];
          if (sTags.includes('all') || sTags.includes('universal')) {
            activeScanners.push(s);
          } else {
            skippedScanners.push(s);
          }
        }
      }
    }
  }

  return {
    activeScanners,
    skippedScanners,
    effectiveProfile: profile,
    detectedTags: Array.from(detectedTags)
  };
}

/**
 * Validates profile definitions against known checks to prevent unknown check IDs,
 * duplicate entries, invalid profile shapes, or unprofiled checks.
 *
 * @param {object | Array | Set} [optionsOrKnownChecks={}]
 * @returns {{
 *   valid: boolean,
 *   errors: string[],
 *   warnings: string[],
 *   unprofiledChecks: string[],
 *   stats: { totalProfiles: number, explicitProfiles: number, totalKnownChecks: number }
 * }}
 */
export function validateProfiles(optionsOrKnownChecks = {}) {
  const isCollection = Array.isArray(optionsOrKnownChecks) || optionsOrKnownChecks instanceof Set;
  const opts = isCollection
    ? { knownChecks: optionsOrKnownChecks }
    : (optionsOrKnownChecks && typeof optionsOrKnownChecks === 'object' ? optionsOrKnownChecks : {});

  const {
    knownChecks = null,
    profiles = PROFILES,
    requireAllChecksProfiled = true
  } = opts;

  let knownList;
  if (knownChecks === null || knownChecks === undefined) {
    const checksDir = path.join(__dirname, '../checks');
    knownList = fs.readdirSync(checksDir)
      .filter(f => f.endsWith('.js'))
      .map(f => f.replace(/\.js$/, ''))
      .sort();
  } else {
    knownList = Array.from(knownChecks)
      .map(item => (typeof item === 'string' ? item : item?.name))
      .filter(Boolean);
  }

  const knownSet = new Set(knownList);
  const errors = [];
  const warnings = [];
  const profiledChecks = new Set();

  const entries = profiles && typeof profiles === 'object' ? Object.entries(profiles) : [];
  let explicitProfiles = 0;

  for (const [profileName, profile] of entries) {
    if (!profile || typeof profile !== 'object') {
      errors.push(`Profile "${profileName}" must be an object`);
      continue;
    }

    if (typeof profile.description !== 'string' || !profile.description.trim()) {
      errors.push(`Profile "${profileName}" is missing a non-empty description`);
    }

    if (profile.checks === null) {
      if (profileName !== 'smart' && profileName !== 'full' && profile.smart !== true) {
        errors.push(`Profile "${profileName}" has checks: null but is not smart/full`);
      }
      continue;
    }

    if (!Array.isArray(profile.checks)) {
      errors.push(`Profile "${profileName}" must have an array of checks or null`);
      continue;
    }

    explicitProfiles += 1;

    if (profile.checks.length === 0) {
      errors.push(`Profile "${profileName}" has an empty checks array`);
      continue;
    }

    const seenInProfile = new Set();
    for (const checkId of profile.checks) {
      if (typeof checkId !== 'string' || !checkId.trim()) {
        errors.push(`Profile "${profileName}" contains an invalid check ID: ${String(checkId)}`);
        continue;
      }
      if (seenInProfile.has(checkId)) {
        errors.push(`Profile "${profileName}" contains duplicate check ID "${checkId}"`);
      }
      seenInProfile.add(checkId);

      if (!knownSet.has(checkId)) {
        errors.push(`Profile "${profileName}" references unknown check ID "${checkId}"`);
      } else {
        profiledChecks.add(checkId);
      }
    }
  }

  const unprofiledChecks = [...knownSet].filter(id => !profiledChecks.has(id)).sort();
  if (requireAllChecksProfiled && unprofiledChecks.length > 0) {
    errors.push(`Unprofiled check(s) not included in any explicit profile: ${unprofiledChecks.join(', ')}`);
  } else if (unprofiledChecks.length > 0) {
    warnings.push(`Unprofiled check(s): ${unprofiledChecks.join(', ')}`);
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
    unprofiledChecks,
    stats: {
      totalProfiles: entries.length,
      explicitProfiles,
      totalKnownChecks: knownSet.size
    }
  };
}
