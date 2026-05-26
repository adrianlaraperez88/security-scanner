export const tags = ['all'];

/**
 * Checks common paths for Apache/Nginx directory listing.
 * A directory listing lets attackers enumerate files and discover sensitive data.
 */
const SENSITIVE_PATHS = [
  '/backup',
  '/backup/',
  '/uploads',
  '/uploads/',
  '/storage',
  '/files',
  '/logs',
  '/tmp',
  '/old',
  '/data',
];

const LISTING_SIGNALS = [
  'index of /',
  'directory listing',
  'parent directory',
  '<a href="../">'
];

export default async function run(target, fetchWithRetry) {
  for (const p of SENSITIVE_PATHS) {
    try {
      const res  = await fetchWithRetry(`${target}${p}`);
      const html = res.text.toLowerCase();

      if (res.status === 200 && LISTING_SIGNALS.some(s => html.includes(s))) {
        return {
          name     : 'directory listing',
          status   : 'VULNERABLE',
          severity : 'HIGH',
          path     : p,
          fix      : "Disable directory indexing in your web server configuration (e.g., 'Options -Indexes' in Apache or 'autoindex off' in Nginx)."
        };
      }

    } catch { /* unreachable path — skip */ }
  }

  return { name: 'directory listing', status: 'SAFE', severity: 'NONE' };
}
