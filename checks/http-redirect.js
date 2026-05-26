import { URL } from 'url';

export const tags = ['all'];

/**
 * Checks whether plain HTTP requests are properly redirected to HTTPS.
 *
 * Uses fetch with redirect:'manual' so we see the raw 3xx response
 * rather than following it — a 301 to https:// is the correct behavior.
 */
export default async function run(target) {
  let parsed;
  try { parsed = new URL(target); } catch {
    return { name: 'https redirect', status: 'ERROR', severity: 'LOW', reason: 'Invalid URL' };
  }

  if (parsed.protocol !== 'https:') {
    return { name: 'https redirect', status: 'SAFE', severity: 'NONE', detail: 'Target is already HTTP — HTTPS check skipped' };
  }

  const httpUrl = `http://${parsed.hostname}${parsed.pathname}`;

  try {
    const controller = new AbortController();
    const timer      = setTimeout(() => controller.abort(), 10000);

    const res = await fetch(httpUrl, {
      redirect: 'manual',   // ← critical: don't follow the redirect
      signal  : controller.signal,
      headers : { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.1)' }
    });

    clearTimeout(timer);

    const location  = res.headers.get('location') || '';
    const isRedirect = [301, 302, 307, 308].includes(res.status);

    if (isRedirect && location.toLowerCase().startsWith('https://')) {
      const permanent = [301, 308].includes(res.status);
      return {
        name    : 'https redirect',
        status  : 'SAFE',
        severity: 'NONE',
        detail  : `HTTP → HTTPS redirect in place (${res.status}${permanent ? ' permanent' : ' temporary'})`
      };
    }

    if (res.status === 200) {
      return {
        name    : 'https redirect',
        status  : 'VULNERABLE',
        severity: 'MEDIUM',
        detail  : 'HTTP returns 200 (no HTTPS redirect) — plain-text traffic is possible',
        fix     : "Implement a permanent (301) redirect from HTTP to HTTPS in your web server configuration to force secure connections."
      };
    }

    if (isRedirect && !location.startsWith('https://')) {
      return {
        name    : 'https redirect',
        status  : 'SUSPICIOUS',
        severity: 'LOW',
        detail  : `Redirect destination is not HTTPS: ${location}`,
        fix     : "Ensure that all HTTP redirects point to the HTTPS version of your site."
      };
    }

    return { name: 'https redirect', status: 'SAFE', severity: 'NONE' };

  } catch {
    // HTTP port closed or connection refused → likely HTTPS-only, which is fine
    return { name: 'https redirect', status: 'SAFE', severity: 'NONE', detail: 'HTTP port appears closed (HTTPS-only)' };
  }
}
