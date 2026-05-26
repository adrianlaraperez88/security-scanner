export const tags = ['php', 'all'];

/**
 * Detects end-of-life (EOL) PHP versions via response headers.
 *
 * Focus: PHP 8.0+ (relevant to modern stacks).
 * EOL PHP receives zero security patches — any new CVE is permanently unpatched.
 *
 * Version severity (PHP 8.x focused):
 *   8.0  → CRITICAL  (EOL Nov 2023, 18+ months without patches)
 *   8.1  → HIGH      (EOL Dec 2025)
 *   8.2  → MEDIUM    (EOL Dec 2026 — approaching)
 *   8.3+ → LOW       (active support, but version disclosure is still info leak)
 */
const EOL_MAP = {
  '8.0': { eolDate: 'Nov 2023', severity: 'CRITICAL', status: 'EOL'      },
  '8.1': { eolDate: 'Dec 2025', severity: 'HIGH',     status: 'EOL'      },
  '8.2': { eolDate: 'Dec 2026', severity: 'MEDIUM',   status: 'Upcoming' },
};

// Patterns that may expose PHP version information
const VERSION_RE   = /PHP\/(8\.\d+(?:\.\d+)?)/i;
const LEGACY_RE    = /PHP\/(5\.|7\.)/i;   // still flag 5.x and 7.x as CRITICAL

export default async function run(target, fetchWithRetry) {
  try {
    const res     = await fetchWithRetry(target);
    const headers = res.headers ?? {};

    // Primary source: X-Powered-By: PHP/8.1.28
    const powered   = headers['x-powered-by'] ?? '';
    // Sometimes in Server: PHP/8.x embedded
    const server    = headers['server'] ?? '';

    const combined  = `${powered} ${server}`;

    // ── Legacy PHP (5.x, 7.x) ────────────────────────────────────────────
    if (LEGACY_RE.test(combined)) {
      const match   = combined.match(LEGACY_RE);
      const version = match?.[1] ?? 'legacy';
      return {
        name    : 'php version (eol)',
        status  : 'VULNERABLE',
        severity: 'CRITICAL',
        detail  : `PHP ${version} is critically EOL — no security patches available`,
        fix     : 'Upgrade IMMEDIATELY to a supported PHP version (8.3 or 8.4+). PHP 5.x and 7.x have been EOL for years and are highly vulnerable.',
        version : version.replace('/', ''),
        header  : powered || server,
      };
    }

    // ── PHP 8.x ──────────────────────────────────────────────────────────
    const match = combined.match(VERSION_RE);
    if (!match) {
      return { name: 'php version (eol)', status: 'SAFE', severity: 'NONE', detail: 'PHP version not disclosed in headers' };
    }

    const fullVersion  = match[1];                        // e.g. "8.1.28"
    const minorVersion = fullVersion.split('.').slice(0, 2).join('.');  // "8.1"
    const eolInfo      = EOL_MAP[minorVersion];

    if (eolInfo && (eolInfo.status === 'EOL' || eolInfo.status === 'Upcoming')) {
      const isEol = eolInfo.status === 'EOL';
      return {
        name    : 'php version (eol)',
        status  : isEol ? 'VULNERABLE' : 'SUSPICIOUS',
        severity: eolInfo.severity,
        detail  : isEol
          ? `PHP ${fullVersion} reached EOL ${eolInfo.eolDate} — no security patches`
          : `PHP ${fullVersion} reaches EOL ${eolInfo.eolDate} — plan upgrade`,
        fix     : isEol 
          ? `Upgrade to PHP 8.3 or 8.4+ immediately as PHP ${fullVersion} no longer receives security updates.`
          : `Plan an upgrade to PHP 8.3 or 8.4+ soon; PHP ${fullVersion} will reach EOL in ${eolInfo.eolDate}.`,
        version : fullVersion,
        eolDate : eolInfo.eolDate,
        header  : powered || server,
      };
    }

    // PHP 8.3+ with version disclosed — low severity (info leak)
    return {
      name    : 'php version (eol)',
      status  : 'SUSPICIOUS',
      severity: 'LOW',
      detail  : `PHP ${fullVersion} is current, but version disclosed in headers — remove X-Powered-By`,
      fix     : "Set 'expose_php = Off' in your php.ini and remove the 'X-Powered-By' header to prevent version disclosure.",
      version : fullVersion,
      header  : powered || server,
    };

  } catch (e) {
    return { name: 'php version (eol)', status: 'ERROR', severity: 'LOW', reason: e.message };
  }
}
