export const tags = ['all'];

/**
 * Checks for missing security-related HTTP response headers.
 * Missing headers are a very common finding in web application audits.
 */
const REQUIRED_HEADERS = {
  'strict-transport-security' : 'HSTS (Strict-Transport-Security)',
  'x-content-type-options'    : 'X-Content-Type-Options',
  'x-frame-options'           : 'X-Frame-Options',
  'content-security-policy'   : 'Content-Security-Policy',
  'referrer-policy'           : 'Referrer-Policy',
  'permissions-policy'        : 'Permissions-Policy',
};

export default async function run(target, fetchWithRetry) {
  try {
    const res     = await fetchWithRetry(target);
    const headers = res.headers || {};

    const missing = Object.entries(REQUIRED_HEADERS)
      .filter(([key]) => !headers[key])
      .map(([, label]) => label);

    if (missing.length === 0) {
      return { name: 'security headers', status: 'SAFE', severity: 'NONE' };
    }

    const severity = missing.length >= 4 ? 'HIGH' : missing.length >= 2 ? 'MEDIUM' : 'LOW';

    return {
      name     : 'security headers',
      status   : 'SUSPICIOUS',
      severity,
      missing,
      fix      : "Implement the missing security headers in your web server configuration (e.g., in Nginx 'add_header' or Apache 'Header set') to protect against XSS, clickjacking, and mime-type sniffing."
    };

  } catch (e) {
    return { name: 'security headers', status: 'ERROR', severity: 'LOW', reason: e.message };
  }
}
