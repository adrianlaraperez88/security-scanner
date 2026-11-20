import { isHtmlOrScript, isRedirectedToDifferentPath } from '../core/check-verify.js';

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
    const robotsUrl = `${target}/robots.txt`;
    const res = await fetchWithRetry(robotsUrl, { followRedirects: false });

    if (res.status !== 200 || isRedirectedToDifferentPath(res, robotsUrl) || isHtmlOrScript(res, res.text)) {
      return { name: 'robots.txt disclosure', status: 'SAFE', severity: 'NONE' };
    }

    const rawText = typeof res?.text === 'string' ? res.text : '';
    const lines = rawText.split('\n').map(l => l.trim().toLowerCase());

    const disallowed = lines
      .filter(l => l.startsWith('disallow:'))
      .map(l => l.replace('disallow:', '').trim())
      .filter(Boolean);

    const leaked = disallowed.filter(path =>
      SENSITIVE_PREFIXES.some(prefix => path.startsWith(prefix))
    );

    if (leaked.length > 0) {
      const topLeaked = leaked.slice(0, 10);
      const quote = `Disallow: ${topLeaked[0]}`;
      return {
        name          : 'robots.txt disclosure',
        status        : 'SUSPICIOUS',
        severity      : 'LOW',
        path          : '/robots.txt',
        url           : robotsUrl,
        paths         : topLeaked,
        detail        : `robots.txt discloses sensitive path(s): ${topLeaked.join(', ')}`,
        files         : [{
          path         : '/robots.txt',
          url          : robotsUrl,
          method       : 'GET',
          status       : 200,
          matchedSignal: quote,
          reproducible : true,
          preview      : quote
        }],
        ...(quote.length >= 8 ? { evidenceQuotes: [quote] } : {}),
        ...(res?.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
        fix           : "Avoid listing sensitive or administrative directories in robots.txt. Use 'X-Robots-Tag: noindex' headers or proper authentication to protect sensitive areas without alerting crawlers to their existence."
      };
    }

    return { name: 'robots.txt disclosure', status: 'SAFE', severity: 'NONE' };

  } catch (e) {
    return { name: 'robots.txt disclosure', status: 'ERROR', severity: 'LOW', reason: e.message };
  }
}
