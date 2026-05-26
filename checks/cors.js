export const tags = ['all'];

/**
 * Tests for CORS misconfiguration by sending a request with a hostile Origin
 * and inspecting Access-Control-Allow-Origin / Access-Control-Allow-Credentials.
 */
const EVIL_ORIGIN = 'https://evil.attacker.example.com';

export default async function run(target, fetchWithRetry) {
  try {
    const res     = await fetchWithRetry(target, { headers: { Origin: EVIL_ORIGIN } });
    const headers = res.headers || {};

    const acao = (headers['access-control-allow-origin']      || '').trim();
    const acac = (headers['access-control-allow-credentials'] || '').trim().toLowerCase();

    // Wildcard — any origin can read the response
    if (acao === '*') {
      return {
        name     : 'cors misconfiguration',
        status   : 'VULNERABLE',
        severity : 'MEDIUM',
        detail   : 'Access-Control-Allow-Origin: * (wildcard)',
        fix      : "Replace the wildcard '*' with a specific whitelist of trusted origins in your Access-Control-Allow-Origin header."
      };
    }

    // Origin reflected back — attacker can read credentialed responses
    if (acao === EVIL_ORIGIN) {
      const credentialed = acac === 'true';
      return {
        name     : 'cors misconfiguration',
        status   : 'VULNERABLE',
        severity : credentialed ? 'HIGH' : 'MEDIUM',
        detail   : `Evil origin reflected${credentialed ? ' with credentials' : ''}`,
        fix      : "Validate the 'Origin' header against a strict whitelist of trusted domains and do not reflect it back if it's untrusted."
      };
    }

    return { name: 'cors misconfiguration', status: 'SAFE', severity: 'NONE' };

  } catch (e) {
    return { name: 'cors misconfiguration', status: 'ERROR', severity: 'LOW', reason: e.message };
  }
}
