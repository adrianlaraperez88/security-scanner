export const tags = ['all'];

/**
 * Clickjacking protection check.
 *
 * Modern browsers use CSP frame-ancestors; legacy use X-Frame-Options.
 * A robust implementation needs BOTH:
 *
 *   - X-Frame-Options: DENY or SAMEORIGIN
 *   - Content-Security-Policy: frame-ancestors 'none' or 'self'
 *
 * Missing either can allow an attacker to embed the page in an iframe
 * and trick users into performing unintended actions.
 */
export default async function run(target, fetchWithRetry) {
  try {
    const res     = await fetchWithRetry(target);
    const headers = res.headers ?? {};

    const xfo = (headers['x-frame-options'] ?? '').toLowerCase().trim();
    const csp = (headers['content-security-policy'] ?? '').toLowerCase();

    const hasXfo           = xfo === 'deny' || xfo === 'sameorigin';
    const xfoAllowFrom     = xfo.startsWith('allow-from');          // deprecated/risky
    const hasCspFrameAnc   = csp.includes('frame-ancestors');
    const issues           = [];

    if (!hasXfo && !hasCspFrameAnc) {
      issues.push({ issue: 'No X-Frame-Options or CSP frame-ancestors — iframe embedding possible', severity: 'MEDIUM' });
    } else if (xfoAllowFrom) {
      issues.push({ issue: 'X-Frame-Options: ALLOW-FROM is deprecated and ignored by most browsers', severity: 'LOW' });
    }

    if (hasXfo && !hasCspFrameAnc) {
      // X-Frame-Options is ignored by some modern browsers that use CSP instead
      issues.push({ issue: 'X-Frame-Options set but no CSP frame-ancestors — modern browsers may ignore XFO', severity: 'LOW' });
    }

    if (issues.length === 0) {
      return { name: 'clickjacking protection', status: 'SAFE', severity: 'NONE' };
    }

    const maxSev = issues.some(i => i.severity === 'MEDIUM') ? 'MEDIUM' : 'LOW';
    return {
      name    : 'clickjacking protection',
      status  : 'SUSPICIOUS',
      severity: maxSev,
      issues,
      fix     : "Add 'X-Frame-Options: DENY' (or SAMEORIGIN) and 'Content-Security-Policy: frame-ancestors none' (or 'self') headers to prevent unauthorized embedding in iframes."
    };

  } catch (e) {
    return { name: 'clickjacking protection', status: 'ERROR', severity: 'LOW', reason: e.message };
  }
}
