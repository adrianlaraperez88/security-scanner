import { createHash } from 'crypto';

export const tags = ['php', 'all'];

/**
 * Detects CVE-2017-9841: Remote Code Execution via exposed PHPUnit vendor directory.
 *
 * PHPUnit ships eval-stdin.php which literally runs eval(php://stdin).
 * If /vendor is web-accessible (wrong document root), any unauthenticated
 * attacker can execute arbitrary PHP with a single POST request.
 *
 * This CVE is in the CISA Known Exploited Vulnerabilities (KEV) catalog.
 *
 * Detection levels:
 *   CRITICAL  → File accessible + POST confirms code execution (RCE proven)
 *   HIGH      → File returns 200 on GET (accessible but POST not confirmed)
 *   SAFE      → File returns 404/403
 */
const PHPUNIT_PATHS = [
  '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
  '/vendor/phpunit/src/Util/PHP/eval-stdin.php',
  '/vendor/phpunit/phpunit/Util/PHP/eval-stdin.php',
];

// Compute expected response for our probe payload
const TOKEN    = 'secscan_rce_probe_2025';
const EXPECTED = createHash('md5').update(TOKEN).digest('hex');
const PHP_PROBE = `<?php echo md5('${TOKEN}'); ?>`;

export default async function run(target, fetchWithRetry) {
  for (const p of PHPUNIT_PATHS) {
    const url = `${target}${p}`;

    try {
      // ── Step 1: Is the file accessible? ─────────────────────────────────
      const getRes = await fetchWithRetry(url);
      if (getRes.status !== 200) continue;

      // ── Step 2: Can we execute PHP? (confirm RCE) ─────────────────────
      let rceConfirmed = false;
      try {
        const postRes = await fetchWithRetry(url, {
          method : 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body   : PHP_PROBE,
        });

        if (postRes.text.includes(EXPECTED)) {
          rceConfirmed = true;
        }
      } catch { /* POST failed — file is there but RCE not confirmed */ }

      if (rceConfirmed) {
        return {
          name    : 'phpunit RCE (CVE-2017-9841)',
          status  : 'VULNERABLE',
          severity: 'CRITICAL',
          path    : p,
          detail  : 'Unauthenticated Remote Code Execution confirmed — PHP code executed via eval-stdin.php',
          fix     : "CRITICAL: Remove 'vendor/phpunit' from your production server immediately. Ensure your web root is set correctly (e.g., to the 'public' or 'www' folder) so the 'vendor' directory is not web-accessible.",
          cve     : 'CVE-2017-9841'
        };
      }

      // File accessible but couldn't confirm RCE (WAF may block POST body)
      return {
        name    : 'phpunit RCE (CVE-2017-9841)',
        status  : 'VULNERABLE',
        severity: 'HIGH',
        path    : p,
        detail  : 'eval-stdin.php is publicly accessible — likely exploitable (CVE-2017-9841)',
        fix     : "Remove 'vendor/phpunit' from your production server or deny access to the 'vendor' directory in your web server configuration.",
        cve     : 'CVE-2017-9841'
      };

    } catch { /* path unreachable */ }
  }

  return { name: 'phpunit RCE (CVE-2017-9841)', status: 'SAFE', severity: 'NONE' };
}
