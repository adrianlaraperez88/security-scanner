import { test } from 'node:test';
import assert from 'node:assert/strict';
import { getScanners } from '../../core/registry.js';
import { PROFILES, listProfiles, validateProfiles } from '../../core/profiles.js';
import { PRESETS, CHECK_CATALOG, CWE_OWASP_MAP, getCheckInfo, getCheckMeta } from '../../core/catalog.js';

test('profiles: validateProfiles() passes with 0 errors and 0 unprofiled checks across all 85 scanners', async () => {
  const scanners = await getScanners();
  assert.equal(scanners.length, 85);

  const report = validateProfiles(scanners);
  assert.equal(report.valid, true, `Expected valid profiles, got errors: ${report.errors.join('; ')}`);
  assert.deepEqual(report.errors, []);
  assert.deepEqual(report.unprofiledChecks, []);
  assert.equal(report.stats.totalProfiles, 22);
  assert.equal(report.stats.explicitProfiles, 20);
  assert.equal(report.stats.totalKnownChecks, 85);

  // Also verify no-args validateProfiles() reads checks/ synchronously
  const syncReport = validateProfiles();
  assert.equal(syncReport.valid, true);
  assert.equal(syncReport.stats.totalKnownChecks, 85);

  // Verify listProfiles() includes all 20 profiles including apache and ops
  const listed = listProfiles();
  for (const profileName of Object.keys(PROFILES)) {
    assert.ok(listed.includes(profileName), `listProfiles() missing ${profileName}`);
  }
  assert.ok(PROFILES.apache);
  for (const required of ['ssl-tls', 'security-headers', 'server-disclosure', 'cve-apache-httpd', 'cors', 'http-methods', 'http-redirect', 'directory-listing', 'sensitive-files']) {
    assert.ok(PROFILES.apache.checks.includes(required), `PROFILES.apache missing ${required}`);
  }
  assert.ok(PROFILES.ops);
  for (const required of ['system-health', 'ssl-tls', 'security-headers', 'server-disclosure', 'rate-limit', 'http-methods', 'http-redirect', 'api-endpoints']) {
    assert.ok(PROFILES.ops.checks.includes(required), `PROFILES.ops missing ${required}`);
  }
});

test('profiles: explicit profiles fix historical omissions and have no duplicates', () => {
  for (const [name, profile] of Object.entries(PROFILES)) {
    if (profile.checks === null) continue;
    assert.ok(Array.isArray(profile.checks) && profile.checks.length > 0, `Profile ${name} must have checks`);
    assert.equal(new Set(profile.checks).size, profile.checks.length, `Duplicate check in profile ${name}`);
  }

  // api profile: has graphql/sqli/xss/sql-errors/env/git and removes stack-specific laravel-auth/spring-checks
  for (const required of ['graphql', 'env', 'git', 'sql-errors', 'sqli', 'xss']) {
    assert.ok(PROFILES.api.checks.includes(required), `PROFILES.api missing ${required}`);
  }
  assert.ok(!PROFILES.api.checks.includes('laravel-auth'));
  assert.ok(!PROFILES.api.checks.includes('spring-checks'));

  // laravel, wordpress, php, modern, cms omissions fixed
  for (const c of ['cve-2024-4577', 'php-errors', 'php-info', 'php-lfi', 'php-cgi-exposure', 'admin-panels', 'robots-sitemap', 'sqli', 'xss']) {
    assert.ok(PROFILES.laravel.checks.includes(c), `PROFILES.laravel missing ${c}`);
    assert.ok(PROFILES.wordpress.checks.includes(c), `PROFILES.wordpress missing ${c}`);
  }
  for (const c of ['cve-2024-4577', 'codeigniter-checks', 'drupal-checks', 'magento-checks', 'admin-panels', 'robots-sitemap', 'sqli', 'xss']) {
    assert.ok(PROFILES.php.checks.includes(c), `PROFILES.php missing ${c}`);
  }
  for (const c of ['api-communication', 'api-endpoints', 'graphql', 'http-methods', 'open-redirect', 'server-disclosure', 'clickjacking', 'robots-sitemap', 'sqli', 'xss']) {
    assert.ok(PROFILES.modern.checks.includes(c), `PROFILES.modern missing ${c}`);
  }
  for (const c of ['api-communication', 'cors', 'api-endpoints', 'graphql', 'jwt-security']) {
    assert.ok(PROFILES.frontend.checks.includes(c), `PROFILES.frontend missing ${c}`);
    assert.ok(PROFILES.api.checks.includes(c), `PROFILES.api missing ${c}`);
  }
  for (const c of ['codeigniter-checks', 'laravel-livewire', 'laravel-auth', 'symfony-checks', 'admin-panels', 'robots-sitemap', 'sqli', 'xss', 'cve-wordpress-ecosystem', 'cve-php-ecosystem', 'cve-apache-httpd']) {
    assert.ok(PROFILES.cms.checks.includes(c), `PROFILES.cms missing ${c}`);
  }

  // Verify all 8 new ecosystem CVE check placements across profiles
  const expectedPlacements = {
    'cve-nextjs-react': ['modern', 'frontend', 'node', 'api'],
    'cve-spring-framework': ['spring', 'api'],
    'cve-tomcat': ['spring', 'api'],
    'cve-apache-httpd': ['apache', 'php', 'cms'],
    'cve-wordpress-ecosystem': ['wordpress', 'cms'],
    'cve-python-web': ['python', 'api'],
    'cve-node-express': ['node', 'modern', 'api'],
    'cve-php-ecosystem': ['php', 'laravel', 'symfony', 'cms'],
    'cve-jdk-advisories': ['spring', 'api'],
    'cve-nginx-http3': ['nginx', 'api', 'modern'],
    'cve-nginx-tls': ['nginx', 'api', 'modern'],
    'cve-2026-123634': ['nginx', 'api', 'modern']
  };
  for (const [checkId, profileList] of Object.entries(expectedPlacements)) {
    for (const pName of profileList) {
      assert.ok(PROFILES[pName].checks.includes(checkId), `PROFILES.${pName} missing ${checkId}`);
    }
  }
});

test('profiles: validateProfiles() detects unknown, duplicate, and unprofiled checks', () => {
  const unknownRes = validateProfiles({
    knownChecks: ['ssl-tls'],
    profiles: { custom: { description: 'Custom', checks: ['ssl-tls', 'does-not-exist'] } }
  });
  assert.equal(unknownRes.valid, false);
  assert.ok(unknownRes.errors.some(e => e.includes('does-not-exist')));

  const dupRes = validateProfiles({
    knownChecks: ['ssl-tls'],
    profiles: { custom: { description: 'Custom', checks: ['ssl-tls', 'ssl-tls'] } }
  });
  assert.equal(dupRes.valid, false);
  assert.ok(dupRes.errors.some(e => e.includes('duplicate')));

  const unprofiledRes = validateProfiles({
    knownChecks: ['ssl-tls', 'graphql'],
    profiles: { custom: { description: 'Custom', checks: ['ssl-tls'] } },
    requireAllChecksProfiled: true
  });
  assert.equal(unprofiledRes.valid, false);
  assert.deepEqual(unprofiledRes.unprofiledChecks, ['graphql']);
});

test('catalog: PRESETS check lists are cloned directly from PROFILES with 100% parity', () => {
  for (const preset of PRESETS) {
    const profile = PROFILES[preset.id];
    assert.ok(profile, `Preset ${preset.id} must have corresponding profile`);
    assert.deepEqual(preset.checks, profile.checks);
    if (Array.isArray(preset.checks)) {
      assert.notEqual(preset.checks, profile.checks, `Preset ${preset.id} checks must be cloned, not shared reference`);
    }
  }
});

test('catalog: getCheckInfo(res.name) resolves 100% of all 68 check return name strings', () => {
  const expectedReturnNames = [
    ['admin-panels', 'admin panel exposure'],
    ['ai-llm-exposure', 'ai & llm exposure'],
    ['api-communication', 'api communication'],
    ['api-communication', 'client-side api communication & endpoint discovery'],
    ['api-endpoints', 'api docs exposure'],
    ['clickjacking', 'clickjacking protection'],
    ['codeigniter-checks', 'codeigniter exposure'],
    ['cookie-security', 'cookie security'],
    ['cors', 'cors misconfiguration'],
    ['cve-2024-4577', 'php-cgi RCE (CVE-2024-4577)'],
    ['cve-2026-114938', 'Java4Shell Base64 Decoder Heap Overflow (CVE-2026-114938)'],
    ['cve-2026-123007', 'NGINX HTTP/2 Flow-Control Heap Overflow (CVE-2026-123007)'],
    ['cve-2026-123633', 'NGINX HTTP/2 Upstream Proxy UAF (CVE-2026-123633)'],
    ['cve-2026-123634', 'NGINX Resolver & Upstream Proxy UAF Advisory (CVE-2026-123634)'],
    ['cve-jdk-advisories', 'JDK & Java Security Advisories (CVE-2026-91403, CVE-2026-114820, CVE-2026-114939, CVE-2026-114940, CVE-2026-22016, CVE-2026-34282, CVE-2026-47063, CVE-2026-91398, CVE-2026-91453)'],
    ['cve-jdk-advisories', 'JDK Security Advisory (CVE-2026-91403)'],
    ['cve-jdk-advisories', 'JDK Unconfirmed Version Advisory (CVE-2026-114820)'],
    ['cve-nginx-http3', 'NGINX HTTP/3 Security Advisories (CVE-2026-121810, CVE-2026-95101, CVE-2026-90439)'],
    ['cve-nginx-http3', 'NGINX HTTP/3 Vulnerability (CVE-2026-121810)'],
    ['cve-nginx-http3', 'NGINX HTTP/3 Advisory (CVE-2026-90439)'],
    ['cve-nginx-http3', 'NGINX HTTP/3 Distro Backport Check (CVE-2026-121810)'],
    ['cve-nginx-http3', 'NGINX HTTP/3 Suppressed Version Advisory'],
    ['cve-nginx-tls', 'NGINX TLS 1.3 Security Advisories (CVE-2026-118899, CVE-2026-97629, CVE-2025-23419)'],
    ['cve-nginx-tls', 'NGINX TLS 1.3 Vulnerability (CVE-2026-118899)'],
    ['cve-nginx-tls', 'NGINX TLS 1.3 Advisory (CVE-2026-97629)'],
    ['cve-nginx-tls', 'NGINX TLS 1.3 Distro Backport Check (CVE-2025-23419)'],
    ['cve-nginx-tls', 'NGINX TLS 1.3 Suppressed Version Advisory'],
    ['cve-apache-httpd', 'Apache HTTP Server CVEs (CVE-2024-38476, CVE-2024-38477, CVE-2024-39573, CVE-2024-27316)'],
    ['cve-apache-httpd', 'Apache HTTP Server Vulnerability (CVE-2024-38476)'],
    ['cve-apache-httpd', 'Apache HTTP Server Distro Backport Check (CVE-2024-27316)'],
    ['cve-nextjs-react', 'Next.js & React Server Components CVEs (CVE-2025-55182, CVE-2024-34351, CVE-2024-46982)'],
    ['cve-nextjs-react', 'React Server Components / Next.js Flight Protocol Exposure (CVE-2025-55182)'],
    ['cve-nextjs-react', 'Next.js Server Actions Host-Header SSRF / Redirect Reflection (CVE-2024-34351)'],
    ['cve-nextjs-react', 'Next.js Cache Poisoning via x-now-route-matches (CVE-2024-46982)'],
    ['cve-node-express', 'Node.js & Express Ecosystem CVEs (CVE-2024-29041, CVE-2024-43796, CVE-2024-37890, CVE-2025-27152)'],
    ['cve-node-express', 'Express Open Redirect in response.redirect (CVE-2024-29041)'],
    ['cve-node-express', 'ws WebSocket Server Header Count DoS (CVE-2024-37890)'],
    ['cve-node-express', 'axios SSRF & Credential Leakage on Absolute URLs (CVE-2025-27152)'],
    ['cve-php-ecosystem', 'PHP, Laravel & Symfony Ecosystem CVEs (CVE-2025-1217, CVE-2025-27515, CVE-2024-50342 & Nov 2026 PHP CVEs)'],
    ['cve-php-ecosystem', 'PHP HTTP Header Parsing Vulnerability (CVE-2025-1217)'],
    ['cve-php-ecosystem', 'PHP Ecosystem Vulnerability (CVE-2026-129289)'],
    ['cve-php-ecosystem', 'PHP Distro Backport Check (CVE-2026-48841)'],
    ['cve-php-ecosystem', 'Laravel File Validation Bypass (CVE-2025-27515)'],
    ['cve-php-ecosystem', 'Symfony HttpFoundation Request URL Parsing Flaw (CVE-2024-50342)'],
    ['cve-python-web', 'Python Web Ecosystem CVEs (CVE-2024-45230, CVE-2024-53907, CVE-2025-26699, CVE-2024-47874, CVE-2024-56326)'],
    ['cve-python-web', 'Python Web Ecosystem CVEs (CVE-2024-45230, CVE-2024-53907, CVE-2025-26699, CVE-2024-47874)'],
    ['cve-python-web', 'Django SQL injection via JSONField HasKey (CVE-2024-53907)'],
    ['cve-python-web', 'FastAPI / Starlette Multipart Form Memory Exhaustion DoS (CVE-2024-47874)'],
    ['cve-python-web', 'Jinja2 Sandboxed Environment Format String Execution Bypass (CVE-2024-56326)'],
    ['cve-spring-framework', 'Spring Boot & Spring Framework CVEs (CVE-2024-38816, CVE-2024-38819, CVE-2025-22235, CVE-2024-22262)'],
    ['cve-spring-framework', 'Spring WebMvc/WebFlux Path Traversal (CVE-2024-38816)'],
    ['cve-spring-framework', 'Spring Boot EndpointRequest Matcher Bypass (CVE-2025-22235)'],
    ['cve-spring-framework', 'Spring UriComponentsBuilder Open Redirect / SSRF (CVE-2024-22262)'],
    ['cve-tomcat', 'Apache Tomcat CVEs (CVE-2025-24813, CVE-2024-50379, CVE-2025-31650)'],
    ['cve-tomcat', 'Apache Tomcat Vulnerability (CVE-2025-24813)'],
    ['cve-tomcat', 'Apache Tomcat Distro Backport Check (CVE-2024-50379)'],
    ['cve-wordpress-ecosystem', 'WordPress Core & Plugin CVEs (CVE-2024-10924, CVE-2024-4439, CVE-2024-6307)'],
    ['cve-wordpress-ecosystem', 'Really Simple Security Authentication Bypass (CVE-2024-10924)'],
    ['cve-wordpress-ecosystem', 'WordPress Core Avatar Block Stored XSS (CVE-2024-4439)'],
    ['directory-listing', 'directory listing'],
    ['drupal-checks', 'drupal exposure'],
    ['env', 'env file exposure'],
    ['frontend-checks', 'frontend security'],
    ['git', '.git exposure'],
    ['graphql', 'graphql introspection'],
    ['http-methods', 'http methods'],
    ['http-redirect', 'https redirect'],
    ['ignition', 'ignition RCE (CVE-2021-3129)'],
    ['jwt-security', 'jwt security'],
    ['laravel-auth', 'laravel auth routes'],
    ['laravel-debug', 'laravel debug exposure'],
    ['laravel-env-manipulation', 'laravel env manipulation (CVE-2024-52301)'],
    ['laravel-livewire', 'livewire exposure (CVE-2025-54068)'],
    ['laravel-livewire', 'livewire exposure (CVE-2024-47823)'],
    ['laravel-storage', 'laravel log exposure'],
    ['laravel-telescope', 'telescope/horizon exposure'],
    ['laravel-telescope', 'laravel telescope exposed'],
    ['laravel-telescope', 'laravel horizon exposed'],
    ['magento-checks', 'magento exposure'],
    ['magento-cosmicsting', 'magento CosmicSting (CVE-2024-34102)'],
    ['nextjs-checks', 'nextjs security'],
    ['node-checks', 'node security'],
    ['open-redirect', 'open redirect'],
    ['php-backup', 'php backup files'],
    ['php-cgi-exposure', 'php-cgi/fpm exposure'],
    ['php-config', 'php config exposure'],
    ['php-errors', 'php error exposure'],
    ['php-info', 'php info exposure'],
    ['php-lfi', 'local file inclusion (LFI)'],
    ['php-version', 'php version (eol)'],
    ['phpunit-rce', 'phpunit RCE (CVE-2017-9841)'],
    ['python-checks', 'python security'],
    ['rate-limit', 'rate limiting'],
    ['robots-sitemap', 'robots.txt disclosure'],
    ['security-headers', 'security headers'],
    ['sensitive-files', 'sensitive files'],
    ['server-disclosure', 'server version disclosure'],
    ['spring-checks', 'spring boot security'],
    ['sql-errors', 'sql error disclosure'],
    ['sqli', 'sql injection'],
    ['sri-supply-chain', 'supply chain & sri'],
    ['ssl-tls', 'ssl/tls check'],
    ['system-health', 'system-health'],
    ['system-health', 'system & operational health exposure'],
    ['symfony-checks', 'symfony misconfiguration'],
    ['yii-checks', 'yii-checks'],
    ['yii-checks', 'yii misconfiguration'],
    ['wp-checks', 'wordpress checks'],
    ['xss', 'reflected xss']
  ];

  for (const [checkId, returnedName] of expectedReturnNames) {
    const info = getCheckInfo(returnedName);
    assert.equal(info.id, checkId, `Expected getCheckInfo("${returnedName}") to resolve to "${checkId}", got "${info.id}"`);
    assert.notEqual(info.category, 'General Security', `Expected "${returnedName}" not to fall back to General Security`);
  }
});

test('catalog: CWE_OWASP_MAP populates cveIds for codeigniter-checks, drupal-checks, and laravel-livewire', () => {
  assert.deepEqual(CWE_OWASP_MAP['codeigniter-checks'].cveIds, ['CVE-2025-54418']);
  assert.deepEqual(getCheckMeta('codeigniter-checks').cveIds, ['CVE-2025-54418']);

  assert.deepEqual(CWE_OWASP_MAP['drupal-checks'].cveIds, ['CVE-2025-13081', 'CVE-2024-55638']);
  assert.deepEqual(getCheckMeta('drupal-checks').cveIds, ['CVE-2025-13081', 'CVE-2024-55638']);

  assert.deepEqual(CWE_OWASP_MAP['laravel-livewire'].cveIds, ['CVE-2025-54068', 'CVE-2024-47823']);
  assert.deepEqual(getCheckMeta('laravel-livewire').cveIds, ['CVE-2025-54068', 'CVE-2024-47823']);
});

test('catalog: resolveCweOwaspFallback uses generic CWE-94 with cveIds: [] for unknown rce/cmd/exec IDs', () => {
  for (const customId of ['custom-rce-check', 'arbitrary-cmd-runner', 'code-exec-probe']) {
    const info = getCheckInfo(customId);
    assert.equal(info.cwe, 'CWE-94');
    assert.deepEqual(info.cveIds, []);
    assert.ok(!info.references.some(r => r.includes('CVE-2024-4577')));
  }

  // Known CVE-2024-4577 check remains intact
  assert.deepEqual(getCheckInfo('cve-2024-4577').cveIds, ['CVE-2024-4577']);
});

test('registry: getScanners() returns 85 deterministically sorted scanners with normalized tags and meta', async () => {
  const scanners = await getScanners();
  assert.equal(scanners.length, 85);

  const names = scanners.map(s => s.name);
  const sorted = [...names].sort();
  assert.deepEqual(names, sorted);

  for (const s of scanners) {
    assert.equal(typeof s.run, 'function');
    assert.ok(Array.isArray(s.tags) && s.tags.length > 0);
    assert.ok(s.meta && typeof s.meta.remediation === 'string' && s.meta.remediation.length > 0);
    assert.ok(Array.isArray(s.meta.cveIds));
    assert.ok(Array.isArray(s.meta.references));
    assert.ok(Object.hasOwn(CWE_OWASP_MAP, s.name), `Expected CWE_OWASP_MAP entry for ${s.name}`);
    assert.ok(Object.hasOwn(CHECK_CATALOG, s.name), `Expected CHECK_CATALOG entry for ${s.name}`);
  }
});
