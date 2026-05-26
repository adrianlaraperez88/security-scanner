export const tags = ['laravel', 'all'];

/**
 * Tests for Ignition debug page / CVE-2021-3129 (Laravel RCE via Ignition).
 * Sends a POST to _ignition/execute-solution (as the real exploit does) and
 * inspects the response — a GET returns 405 on both patched and unpatched versions.
 */
export default async function run(target, fetchWithRetry) {
  try {
    // POST with a minimal payload matching the Ignition request shape
    const res = await fetchWithRetry(`${target}/_ignition/execute-solution`, {
      method  : 'POST',
      headers : { 'Content-Type': 'application/json' },
      body    : JSON.stringify({
        solution   : 'Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution',
        parameters : { variableName: 'test', viewFile: '/etc/passwd' }
      })
    });

    const html = res.text.toLowerCase();

    // Patched versions → 404 / 403 / empty body
    // Vulnerable versions → 500 with Ignition error body OR even a response
    if (
      res.status === 200 ||
      html.includes('ignition') ||
      html.includes('facade\\ignition') ||
      html.includes('spatie')
    ) {
      return {
        name     : 'ignition RCE (CVE-2021-3129)',
        status   : 'VULNERABLE',
        severity : 'CRITICAL',
        fix      : "CRITICAL: Disable Laravel debug mode (APP_DEBUG=false) in your .env file immediately. Update 'facade/ignition' to a non-vulnerable version or uninstall it in production."
      };
    }

    // 500 without recognizable ignition body — still suspicious
    if (res.status === 500) {
      return {
        name     : 'ignition RCE (CVE-2021-3129)',
        status   : 'SUSPICIOUS',
        severity : 'HIGH',
        detail   : 'Endpoint returned 500 — may be vulnerable',
        fix      : "Ensure 'APP_DEBUG=false' is set in production and that the '/_ignition' endpoints are blocked or removed from the production environment."
      };
    }

    return { name: 'ignition RCE (CVE-2021-3129)', status: 'SAFE', severity: 'NONE' };

  } catch (e) {
    return { name: 'ignition RCE (CVE-2021-3129)', status: 'ERROR', severity: 'LOW', reason: e.message };
  }
}