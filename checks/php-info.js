import {
  isRedirectedToDifferentPath,
  isFrameworkRouteErrorResponse,
  extractVerbatimSnippet,
  confirmReproducible
} from '../core/check-verify.js';

export const tags = ['php', 'laravel', 'wordpress', 'drupal', 'magento', 'symfony', 'codeigniter', 'joomla'];

const PATHS = [
  '/phpinfo.php',
  '/info.php',
  '/test.php',
  '/php.php',
  '/phptest.php',
];

function isPhpInfoPage(res, reqUrl) {
  if (res?.status !== 200 || (reqUrl && isRedirectedToDifferentPath(res, reqUrl))) return false;
  const raw = typeof res.text === 'string' ? res.text : '';
  if (isFrameworkRouteErrorResponse(res, raw)) return false;
  const html = raw.toLowerCase();
  return html.includes('php version') && html.includes('configuration');
}

export default async function run(target, fetchWithRetry) {
  let fetchErrors = 0;

  for (const p of PATHS) {
    try {
      const url = `${target}${p}`;
      const res = await fetchWithRetry(url, { followRedirects: false });
      if (!isPhpInfoPage(res, url)) continue;

      const { confirmed, res: cRes } = await confirmReproducible(
        url,
        fetchWithRetry,
        { followRedirects: false },
        (r) => isPhpInfoPage(r, url)
      );
      if (!confirmed) continue;

      const finalRes = cRes || res;
      const preview = extractVerbatimSnippet(finalRes.text || res.text || '', /php version/i) || 'PHP Version configuration table';
      return {
        name          : 'php info exposure',
        status        : 'VULNERABLE',
        severity      : 'HIGH',
        path          : p,
        detail        : `Confirmed reproducible phpinfo() exposure at ${p}`,
        files         : [{ path: p, url, method: 'GET', status: 200, matchedSignal: 'phpinfo() PHP Version + Configuration', reproducible: true, preview }],
        reproVerified : true,
        poeLevel      : 3,
        evidenceQuotes: [preview],
        ...(finalRes?.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {}),
        fix           : "Delete any files that call 'phpinfo()' from your production server, as they leak detailed environment and configuration data."
      };
    } catch {
      fetchErrors++;
    }
  }

  if (fetchErrors === PATHS.length) {
    return { name: 'php info exposure', status: 'ERROR', severity: 'LOW', reason: 'All paths unreachable' };
  }

  return { name: 'php info exposure', status: 'SAFE', severity: 'NONE' };
}
