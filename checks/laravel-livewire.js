export const tags = ['laravel', 'all'];

/**
 * Livewire Endpoint Exposure
 *
 * CVE-2025-54068 (CVSS 9.8) — Livewire v3 < 3.6.4
 *   Hydration RCE: unauthenticated POST to /livewire/update with crafted
 *   component property data allows remote code execution.
 *
 * CVE-2024-47823 (CVSS 8.1) — Livewire v2 < 2.12.7, v3 < 3.5.2
 *   File upload extension bypass: /livewire/upload-file accepts PHP scripts
 *   when using getClientOriginalName() storage pattern.
 *
 * Detection (passive — we probe endpoints but don't exploit):
 *   - /livewire/livewire.js        → confirms Livewire is installed
 *   - POST /livewire/update        → 200=active, 419=exists+CSRF-protected, 404=safe
 *   - POST /livewire/upload-file   → 200/422=accessible, 404=safe
 */
const LIVEWIRE_JS_PATHS = [
  '/livewire/livewire.js',
  '/vendor/livewire/livewire/dist/livewire.js',
];

// Minimal valid Livewire v3 update payload (won't trigger RCE, just endpoint probe)
const UPDATE_PAYLOAD = JSON.stringify({
  _token    : 'probe',
  components: [{ snapshot: '{}', updates: [], calls: [] }]
});

export default async function run(target, fetchWithRetry) {
  // ── Step 1: Detect Livewire presence ─────────────────────────────────────
  let livewireDetected = false;
  for (const jsPath of LIVEWIRE_JS_PATHS) {
    try {
      const res = await fetchWithRetry(`${target}${jsPath}`);
      if (res.status === 200 && res.text.includes('Livewire')) {
        livewireDetected = true;
        break;
      }
    } catch { /* skip */ }
  }

  // Also check HTML body for Livewire signals
  if (!livewireDetected) {
    try {
      const home = await fetchWithRetry(target);
      const body = home.text.toLowerCase();
      if (body.includes('livewire') || body.includes('wire:') || body.includes('data-livewire')) {
        livewireDetected = true;
      }
    } catch { /* skip */ }
  }

  // ── Step 2: Probe the update endpoint (CVE-2025-54068) ───────────────────
  let updateStatus   = 0;
  let updateBodySnip = '';
  try {
    const res = await fetchWithRetry(`${target}/livewire/update`, {
      method : 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body   : UPDATE_PAYLOAD,
    });
    updateStatus   = res.status;
    updateBodySnip = res.text.slice(0, 200).toLowerCase();
  } catch { /* endpoint unreachable */ }

  // ── Step 3: Probe the upload endpoint (CVE-2024-47823) ───────────────────
  let uploadStatus = 0;
  try {
    const res = await fetchWithRetry(`${target}/livewire/upload-file`, {
      method : 'POST',
      headers: { 'Content-Type': 'application/json' },
      body   : '{}',
    });
    uploadStatus = res.status;
  } catch { /* endpoint unreachable */ }

  // ── Evaluate ──────────────────────────────────────────────────────────────

  // Update endpoint fully active (200 with Livewire JSON response) → critical
  if (updateStatus === 200 && (updateBodySnip.includes('html') || updateBodySnip.includes('effects'))) {
    return {
      name    : 'livewire exposure (CVE-2025-54068)',
      status  : 'VULNERABLE',
      severity: 'CRITICAL',
      detail  : '/livewire/update returned a valid Livewire response — hydration RCE (CVE-2025-54068) likely',
      fix     : 'CRITICAL: Update Livewire to version 3.6.4 or higher immediately to patch the hydration RCE (CVE-2025-54068).',
      cve     : 'CVE-2025-54068',
      paths   : ['/livewire/update']
    };
  }

  // Endpoint exists but CSRF-protected (still exploitable with social engineering)
  if (updateStatus === 419 || updateStatus === 422) {
    return {
      name    : 'livewire exposure (CVE-2025-54068)',
      status  : 'SUSPICIOUS',
      severity: 'HIGH',
      detail  : `/livewire/update exists (HTTP ${updateStatus}) — confirm Livewire version < 3.6.4 (CVE-2025-54068)`,
      fix     : 'Update Livewire to version 3.6.4+ (v3) or 2.12.7+ (v2) and ensure CSRF protection is active on all Livewire endpoints.',
      cve     : 'CVE-2025-54068',
      paths   : ['/livewire/update']
    };
  }

  // Upload endpoint accessible
  if (uploadStatus === 200 || uploadStatus === 422) {
    return {
      name    : 'livewire exposure (CVE-2024-47823)',
      status  : 'SUSPICIOUS',
      severity: 'HIGH',
      detail  : `/livewire/upload-file is accessible (HTTP ${uploadStatus}) — verify Livewire version < 2.12.7 / 3.5.2 (CVE-2024-47823)`,
      fix     : 'Update Livewire to version 3.5.2+ (v3) or 2.12.7+ (v2) to patch the file upload extension bypass (CVE-2024-47823).',
      cve     : 'CVE-2024-47823',
      paths   : ['/livewire/upload-file']
    };
  }

  // Livewire JS found but endpoints locked down
  if (livewireDetected) {
    return {
      name    : 'livewire exposure (CVE-2025-54068)',
      status  : 'SUSPICIOUS',
      severity: 'MEDIUM',
      detail  : 'Livewire detected but endpoints are not directly accessible — ensure version >= 3.6.4',
      fix     : 'Ensure Livewire is updated to at least v3.6.4 (for v3) or v2.12.7 (for v2) to protect against known RCE and upload vulnerabilities.'
    };
  }

  return { name: 'livewire exposure (CVE-2025-54068)', status: 'SAFE', severity: 'NONE' };
}
