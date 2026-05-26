import { URL } from 'url';

export const tags = ['all'];

/**
 * Tests for open redirect vulnerabilities by injecting a hostile URL into
 * common redirect parameters and checking if the server blindly follows it.
 *
 * Uses fetch with redirect:'manual' so we inspect the raw Location header.
 */
const REDIRECT_PARAMS = [
  'redirect', 'url', 'next', 'return', 'return_url',
  'returnUrl', 'callback', 'continue', 'dest', 'destination',
  'go', 'goto', 'target', 'redir', 'redirect_to',
];

const EVIL_HOST = 'evil.attacker.example.com';
const EVIL_URL  = `https://${EVIL_HOST}`;

export default async function run(target) {
  for (const param of REDIRECT_PARAMS) {
    const testUrl = `${target}?${param}=${encodeURIComponent(EVIL_URL)}`;

    try {
      const controller = new AbortController();
      const timer      = setTimeout(() => controller.abort(), 8000);

      const res = await fetch(testUrl, {
        redirect: 'manual',   // ← critical: inspect the Location header raw
        signal  : controller.signal,
        headers : { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.1)' }
      });

      clearTimeout(timer);

      const location   = res.headers.get('location') || '';
      const isRedirect = [301, 302, 303, 307, 308].includes(res.status);

      if (isRedirect && location.includes(EVIL_HOST)) {
        return {
          name    : 'open redirect',
          status  : 'VULNERABLE',
          severity: 'MEDIUM',
          detail  : `?${param}= parameter redirects to arbitrary external URLs`,
          fix     : "Validate all redirect destinations against a strict whitelist of allowed domains or use a fixed mapping for internal paths only.",
          location
        };
      }

    } catch { /* network error / timeout — skip param */ }
  }

  return { name: 'open redirect', status: 'SAFE', severity: 'NONE' };
}
