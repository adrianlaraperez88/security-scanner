import {
  isRedirectedToDifferentPath,
  isFrameworkRouteErrorResponse,
  extractVerbatimSnippet,
  confirmReproducible
} from '../core/check-verify.js';

export const tags = ['all'];

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

function isRealDirectoryListing(res, reqUrl) {
  if (res?.status !== 200 || (reqUrl && isRedirectedToDifferentPath(res, reqUrl))) return null;
  const raw = typeof res.text === 'string' ? res.text : '';
  if (isFrameworkRouteErrorResponse(res, raw)) return null;
  const lower = raw.toLowerCase();
  if (/<title>\s*index of \//i.test(lower) || lower.includes('index of /')) return 'Index of /';
  if (lower.includes('directory listing for')) return 'Directory listing for';
  if (lower.includes('parent directory') && /<a href=["'][^"']*["']>/i.test(lower) && (lower.includes('<pre>') || lower.includes('last modified'))) {
    return 'Parent Directory index';
  }
  if (lower.includes('<a href="../">') && (lower.includes('last modified') || lower.includes('<pre>'))) {
    return 'Directory parent link index';
  }
  return null;
}

export default async function run(target, fetchWithRetry) {
  for (const p of SENSITIVE_PATHS) {
    try {
      const url = `${target}${p}`;
      const res = await fetchWithRetry(url, { followRedirects: false });
      const signal = isRealDirectoryListing(res, url);
      if (!signal) continue;

      const { confirmed, res: cRes } = await confirmReproducible(
        url,
        fetchWithRetry,
        { followRedirects: false },
        (r) => Boolean(isRealDirectoryListing(r, url))
      );
      if (!confirmed) continue;

      const finalRes = cRes || res;
      const preview = extractVerbatimSnippet(finalRes.text || res.text || '', /index of \/|directory listing|parent directory/i) || signal;
      return {
        name          : 'directory listing',
        status        : 'VULNERABLE',
        severity      : 'HIGH',
        path          : p,
        detail        : `Confirmed reproducible directory listing at ${p} (${signal})`,
        files         : [{
          path         : p,
          url,
          method       : 'GET',
          status       : 200,
          matchedSignal: signal,
          reproducible : true,
          preview
        }],
        reproVerified : true,
        poeLevel      : preview.length >= 8 ? 3 : 2,
        ...(preview.length >= 8 ? { evidenceQuotes: [preview] } : {}),
        ...(finalRes?.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {}),
        fix           : "Disable directory indexing in your web server configuration (e.g., 'Options -Indexes' in Apache or 'autoindex off' in Nginx)."
      };
    } catch { /* unreachable path */ }
  }

  return { name: 'directory listing', status: 'SAFE', severity: 'NONE' };
}
