export const tags = ['all'];

/**
 * Inspects Set-Cookie response headers for missing security attributes.
 *
 * Missing Secure   → cookie sent over plain HTTP (credential theft)
 * Missing HttpOnly → readable by JavaScript (XSS escalation)
 * Missing SameSite → cross-site request forgery risk
 */
export default async function run(target, fetchWithRetry) {
  try {
    const res     = await fetchWithRetry(target);
    const setCookie = res.headers?.['set-cookie'] ?? '';

    if (!setCookie) {
      return { name: 'cookie security', status: 'SAFE', severity: 'NONE', detail: 'No cookies set' };
    }

    // set-cookie header can be a comma-joined multi-value string
    const cookies = setCookie.split(/,(?=[^ ])/);
    const issues  = [];

    for (const cookie of cookies) {
      const low  = cookie.toLowerCase();
      const name = (cookie.split('=')[0] ?? 'cookie').trim();

      if (!low.includes('secure'))   issues.push({ cookie: name, issue: 'Missing Secure flag — sent over HTTP',    severity: 'HIGH'   });
      if (!low.includes('httponly')) issues.push({ cookie: name, issue: 'Missing HttpOnly — readable via JS (XSS)', severity: 'MEDIUM' });
      if (!low.includes('samesite')) issues.push({ cookie: name, issue: 'Missing SameSite — CSRF risk',            severity: 'MEDIUM' });
    }

    if (!issues.length) {
      return { name: 'cookie security', status: 'SAFE', severity: 'NONE' };
    }

    const maxSev = issues.some(i => i.severity === 'HIGH') ? 'HIGH' : 'MEDIUM';
    return {
      name    : 'cookie security',
      status  : 'SUSPICIOUS',
      severity: maxSev,
      issues,
      fix     : "Configure all sensitive cookies with 'HttpOnly', 'Secure', and 'SameSite=Strict' (or Lax) attributes to protect against XSS, credential theft, and CSRF."
    };

  } catch (e) {
    return { name: 'cookie security', status: 'ERROR', severity: 'LOW', reason: e.message };
  }
}
