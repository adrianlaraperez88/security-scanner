export const tags = ['all'];

/**
 * Parses robots.txt for Disallow entries that reveal sensitive paths.
 * Developers sometimes accidentally leak admin panels, API endpoints,
 * and backup locations this way.
 */
const SENSITIVE_PREFIXES = [
  '/admin', '/administrator', '/wp-admin',
  '/backup', '/backups', '/db',
  '/config', '/conf',
  '/.env', '/env',
  '/api/internal', '/private', '/secret', '/internal',
  '/phpinfo', '/setup', '/install',
];

export default async function run(target, fetchWithRetry) {
  try {
    const res = await fetchWithRetry(`${target}/robots.txt`);

    if (res.status !== 200) {
      return { name: 'robots.txt disclosure', status: 'SAFE', severity: 'NONE' };
    }

    const lines = res.text.split('\n').map(l => l.trim().toLowerCase());

    const disallowed = lines
      .filter(l => l.startsWith('disallow:'))
      .map(l => l.replace('disallow:', '').trim())
      .filter(Boolean);

    const leaked = disallowed.filter(path =>
      SENSITIVE_PREFIXES.some(prefix => path.startsWith(prefix))
    );

    if (leaked.length > 0) {
      return {
        name     : 'robots.txt disclosure',
        status   : 'SUSPICIOUS',
        severity : 'LOW',
        paths    : leaked.slice(0, 10),
        fix      : "Avoid listing sensitive or administrative directories in robots.txt. Use 'X-Robots-Tag: noindex' headers or proper authentication to protect sensitive areas without alerting crawlers to their existence."
      };
    }

    return { name: 'robots.txt disclosure', status: 'SAFE', severity: 'NONE' };

  } catch (e) {
    return { name: 'robots.txt disclosure', status: 'ERROR', severity: 'LOW', reason: e.message };
  }
}
