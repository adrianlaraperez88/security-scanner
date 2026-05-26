export const tags = ['magento', 'all'];

/**
 * CVE-2024-34102 "CosmicSting" — Magento/Adobe Commerce XXE → File Read → RCE
 * CVSS 9.8 — Critically exploited throughout 2024
 *
 * An unauthenticated XXE vulnerability in the REST API allows attackers to
 * read arbitrary server files. Combined with a deserialization gadget, it
 * chains to full RCE. Affected: Adobe Commerce / Magento < 2.4.7-p1.
 *
 * Detection strategy (passive):
 *   1. Detect Magento via headers/HTML signals
 *   2. Probe version from known endpoints (/magento_version, health_check)
 *   3. Check if the vulnerable REST endpoint responds (confirms exposure)
 *   4. Flag CRITICAL if Magento confirmed + REST API accessible
 *
 * NOTE: We do NOT send actual XXE payloads — just confirm endpoint accessibility
 * and version, which is sufficient for a responsible scanner.
 */

const MAGENTO_SIGNALS_HEADERS = [
  'x-magento-cache-id',
  'x-magento-tags',
  'x-magento-vary',
  'x-magento-cache-debug',
];

const MAGENTO_SIGNALS_HTML = [
  'mage.cookies',
  'mage_',
  'magento',
  '/pub/static/',
  'requirejs-config',   // Magento RequireJS config
];

const VERSION_PATHS = [
  '/magento_version',
  '/pub/health_check.php',
];

// REST API endpoint known to be vulnerable in CosmicSting
const COSMICSTING_ENDPOINT = '/rest/V1/guest-carts/1/estimate-shipping-methods';

async function detectMagento(target, fetchWithRetry) {
  try {
    const res  = await fetchWithRetry(target);
    const html = res.text.toLowerCase();
    const h    = res.headers ?? {};

    const headerHit = MAGENTO_SIGNALS_HEADERS.some(k => h[k]);
    const htmlHit   = MAGENTO_SIGNALS_HTML.some(s => html.includes(s));

    return { detected: headerHit || htmlHit, source: headerHit ? 'headers' : 'html' };
  } catch {
    return { detected: false };
  }
}

async function detectVersion(target, fetchWithRetry) {
  for (const p of VERSION_PATHS) {
    try {
      const res = await fetchWithRetry(`${target}${p}`);
      if (res.status === 200) {
        const match = res.text.match(/(\d+\.\d+\.\d+)/);
        if (match) return { version: match[1], path: p };
      }
    } catch { /* skip */ }
  }
  return { version: null };
}

function isVulnerableVersion(v) {
  if (!v) return null;  // unknown
  const [major, minor, patch] = v.split('.').map(Number);
  if (major !== 2) return false;
  if (minor < 4) return true;   // < 2.4.x
  if (minor === 4) {
    if (patch < 7) return true; // 2.4.0–2.4.6 = vulnerable
    if (patch === 7) return true; // 2.4.7 without -p1 (can't distinguish without sub-patch)
  }
  return false;
}

export default async function run(target, fetchWithRetry) {
  // ── Step 1: Is this Magento? ──────────────────────────────────────────────
  const { detected } = await detectMagento(target, fetchWithRetry);

  if (!detected) {
    return { name: 'magento CosmicSting (CVE-2024-34102)', status: 'SAFE', severity: 'NONE' };
  }

  // ── Step 2: Try to detect version ─────────────────────────────────────────
  const { version, path: vPath } = await detectVersion(target, fetchWithRetry);
  const vulnVersion = isVulnerableVersion(version);

  // ── Step 3: Probe the CosmicSting REST endpoint ───────────────────────────
  let endpointReachable = false;
  let endpointStatus    = 0;
  try {
    const res = await fetchWithRetry(`${target}${COSMICSTING_ENDPOINT}`, {
      method : 'POST',
      headers: { 'Content-Type': 'application/json' },
      body   : JSON.stringify({
        address: {
          region_code: 'CA', country_id: 'US',
          street: ['123 Main St'], postcode: '90210',
          city: 'LA', telephone: '5555555555',
          firstname: 'Probe', lastname: 'Test',
          email: 'probe@example.com'
        }
      }),
    });
    endpointStatus    = res.status;
    endpointReachable = res.status !== 404 && res.status !== 502;
  } catch { /* endpoint unreachable */ }

  // ── Evaluate ──────────────────────────────────────────────────────────────
  if (endpointReachable && (vulnVersion === true || vulnVersion === null)) {
    return {
      name    : 'magento CosmicSting (CVE-2024-34102)',
      status  : 'VULNERABLE',
      severity: 'CRITICAL',
      detail  : version
        ? `Magento ${version} detected + REST API accessible — vulnerable to CVE-2024-34102 (CosmicSting)`
        : `Magento detected + REST API accessible — verify version < 2.4.7-p1 for CVE-2024-34102`,
      fix     : "CRITICAL: Adobe Commerce / Magento is vulnerable to CosmicSting (XXE). Update immediately to 2.4.7-p1+, 2.4.6-p6+, 2.4.5-p8+, or 2.4.4-p9+.",
      version,
      endpoint: COSMICSTING_ENDPOINT,
      cve     : 'CVE-2024-34102'
    };
  }

  if (vulnVersion === true) {
    return {
      name    : 'magento CosmicSting (CVE-2024-34102)',
      status  : 'VULNERABLE',
      severity: 'CRITICAL',
      detail  : `Magento ${version} is in the vulnerable range for CVE-2024-34102 (CosmicSting)`,
      fix     : `Update Magento ${version} to a patched version immediately (e.g., 2.4.7-p1+) to prevent remote code execution via XXE.`,
      version,
      cve     : 'CVE-2024-34102'
    };
  }

  // Magento detected, REST endpoint accessible, version unknown/safe
  if (endpointReachable) {
    return {
      name    : 'magento CosmicSting (CVE-2024-34102)',
      status  : 'SUSPICIOUS',
      severity: 'HIGH',
      detail  : `Magento detected + REST API accessible — verify version is >= 2.4.7-p1 (CVE-2024-34102)`,
      fix     : "Confirm your Magento installation is updated to at least 2.4.7-p1 or equivalent to protect against the CosmicSting (CVE-2024-34102) exploit.",
      version  : version ?? 'unknown',
      endpoint: COSMICSTING_ENDPOINT,
      cve     : 'CVE-2024-34102'
    };
  }

  return {
    name    : 'magento CosmicSting (CVE-2024-34102)',
    status  : 'SUSPICIOUS',
    severity: 'MEDIUM',
    detail  : `Magento detected — REST endpoint not directly accessible. Ensure version >= 2.4.7-p1`,
    fix     : "Ensure your Magento version is patched against CVE-2024-34102 and that sensitive REST API endpoints are not publicly accessible.",
    version  : version ?? 'unknown',
    cve     : 'CVE-2024-34102'
  };
}
