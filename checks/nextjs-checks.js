import { redactSecretsInText } from '../core/ai-advisor.js';
import {
  getHeader,
  isHtmlOrScript,
  isRedirectedToDifferentPath,
  isFrameworkRouteErrorResponse,
  parseJsonObject,
  extractVerbatimSnippet,
  confirmReproducible
} from '../core/check-verify.js';

export const tags = ['nextjs'];

export default async function run(target, fetchWithRetry) {
  const base = target.replace(/\/+$/, '');
  const found = [];
  let networkSuccess = false;

  // 1. CVE-2025-29927 Next.js Middleware Authorization Bypass
  const protectedPaths = ['/admin', '/dashboard'];
  for (const path of protectedPaths) {
    try {
      const targetUrl = `${base}${path}`;
      const initialRes = await fetchWithRetry(targetUrl, { followRedirects: false });
      networkSuccess = true;

      const location = getHeader(initialRes?.headers, 'location');
      const isProtected =
        [401, 403, 302, 307, 308].includes(initialRes?.status) ||
        (location && /login/i.test(location));

      if (isProtected) {
        const bypassHeaders = [
          'middleware:middleware:middleware:middleware:middleware',
          'src/middleware:src/middleware:src/middleware:src/middleware:src/middleware'
        ];

        for (const bypassVal of bypassHeaders) {
          try {
            const opts = { headers: { 'x-middleware-subrequest': bypassVal }, followRedirects: false };
            const bypassRes = await fetchWithRetry(targetUrl, opts);
            networkSuccess = true;

            if (
              bypassRes?.status === 200 &&
              !isRedirectedToDifferentPath(bypassRes, targetUrl) &&
              !isFrameworkRouteErrorResponse(bypassRes, bypassRes.text) &&
              bypassRes.text &&
              bypassRes.text.trim().length > 0
            ) {
              const { confirmed, res: cRes } = await confirmReproducible(
                targetUrl,
                fetchWithRetry,
                opts,
                (r) =>
                  r?.status === 200 &&
                  !isRedirectedToDifferentPath(r, targetUrl) &&
                  !isFrameworkRouteErrorResponse(r, r.text) &&
                  typeof r.text === 'string' &&
                  r.text.trim().length > 0
              );
              if (!confirmed) continue;

              const finalRes = cRes || bypassRes;
              const quote = `x-middleware-subrequest bypassed HTTP ${initialRes.status} -> HTTP 200 on ${path}`;
              found.push({
                name         : 'nextjs middleware auth bypass (CVE-2025-29927)',
                findingStatus: 'VULNERABLE',
                path,
                url          : targetUrl,
                method       : 'GET',
                status       : 200,
                severity     : 'CRITICAL',
                matchedSignal: `x-middleware-subrequest: ${bypassVal}`,
                reproducible : true,
                preview      : quote,
                cve          : 'CVE-2025-29927',
                reason       : `Protected path ${path} returned HTTP ${initialRes.status} normally, but consistently returned HTTP 200 when 'x-middleware-subrequest: ${bypassVal}' was supplied.`,
                ...(finalRes?.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {})
              });
              break;
            }
          } catch { /* bypass probe failed */ }
        }
      }
    } catch { /* initial probe failed */ }
  }

  // 2. Next.js Build Manifest / Source Map Leak
  let homeRes;
  try {
    homeRes = await fetchWithRetry(target);
    networkSuccess = true;
  } catch { /* baseline failed */ }

  if (homeRes?.text) {
    const html = homeRes.text;

    if (html.includes('/_next/static/')) {
      try {
        const mapUrl = `${base}/_next/static/chunks/main.js.map`;
        const mapRes = await fetchWithRetry(mapUrl);
        networkSuccess = true;
        const parsedMap = mapRes?.status === 200 && !isHtmlOrScript(mapRes, mapRes.text) ? parseJsonObject(mapRes.text) : null;
        if (parsedMap && (Array.isArray(parsedMap.sources) || parsedMap.version === 3)) {
          const { confirmed, res: cRes } = await confirmReproducible(
            mapUrl,
            fetchWithRetry,
            {},
            (r) => r?.status === 200 && Boolean(parseJsonObject(r.text)?.sources || parseJsonObject(r.text)?.version === 3)
          );
          if (confirmed) {
            const finalRes = cRes || mapRes;
            const snippet = extractVerbatimSnippet(finalRes.text || mapRes.text, '"sources"') || 'Next.js main.js.map version 3 JSON';
            found.push({
              name         : 'exposed next.js source maps',
              findingStatus: 'VULNERABLE',
              path         : '/_next/static/chunks/main.js.map',
              url          : mapUrl,
              method       : 'GET',
              status       : 200,
              severity     : 'HIGH',
              matchedSignal: 'SourceMap JSON ("sources"/"version":3)',
              reproducible : true,
              preview      : snippet,
              reason       : 'Next.js source map (main.js.map) is publicly accessible, allowing reconstruction of front-end source code.',
              ...(finalRes?.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {})
            });
          }
        }
      } catch { /* map probe failed */ }

      try {
        const manUrl = `${base}/_buildManifest.js`;
        const manifestRes = await fetchWithRetry(manUrl);
        networkSuccess = true;
        const mText = typeof manifestRes?.text === 'string' ? manifestRes.text : '';
        if (
          manifestRes?.status === 200 &&
          (mText.includes('__BUILD_MANIFEST') || mText.includes('sortedPages'))
        ) {
          const { confirmed, res: cRes } = await confirmReproducible(
            manUrl,
            fetchWithRetry,
            {},
            (r) => r?.status === 200 && typeof r.text === 'string' && (r.text.includes('__BUILD_MANIFEST') || r.text.includes('sortedPages'))
          );
          if (confirmed) {
            const finalRes = cRes || manifestRes;
            const snippet = extractVerbatimSnippet(finalRes.text || mText, '__BUILD_MANIFEST') || '__BUILD_MANIFEST exposed';
            found.push({
              name         : 'next.js build manifest leak',
              path         : '/_buildManifest.js',
              url          : manUrl,
              method       : 'GET',
              status       : 200,
              severity     : 'HIGH',
              matchedSignal: '__BUILD_MANIFEST / sortedPages',
              reproducible : true,
              preview      : snippet,
              reason       : 'Next.js build manifest (_buildManifest.js) is publicly accessible, exposing internal client routes.',
              ...(finalRes?.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {})
            });
          }
        }
      } catch { /* manifest probe failed */ }
    }

    if (html.includes('__NEXT_DATA__')) {
      const sensitivePattern = /"(?:secret|privateKey|databaseUrl|password)"\s*:\s*"[^"]+"/i;
      const m = sensitivePattern.exec(html);
      if (m) {
        const safeSnippet = redactSecretsInText(extractVerbatimSnippet(html, sensitivePattern) || '__NEXT_DATA__ sensitive key');
        found.push({
          name         : 'sensitive data leak in __NEXT_DATA__',
          path         : '/',
          url          : target,
          method       : 'GET',
          status       : homeRes.status ?? 200,
          severity     : 'HIGH',
          matchedSignal: '__NEXT_DATA__ sensitive credential key',
          reproducible : true,
          preview      : safeSnippet,
          reason       : 'Sensitive keys (secret, privateKey, databaseUrl, or password) found in __NEXT_DATA__ script block.',
          ...(homeRes?.trafficId !== undefined ? { trafficId: homeRes.trafficId } : {})
        });
      }
    }
  }

  if (!networkSuccess) {
    return { name: 'nextjs security', status: 'ERROR', severity: 'NONE', reason: 'Target unreachable' };
  }

  if (found.length === 0) {
    return { name: 'nextjs security', status: 'SAFE', severity: 'NONE' };
  }

  const maxSev = found.some(f => f.severity === 'CRITICAL') ? 'CRITICAL'
               : found.some(f => f.severity === 'HIGH')     ? 'HIGH'
               : found.some(f => f.severity === 'MEDIUM')   ? 'MEDIUM'
               : 'LOW';
  const primary = found[0];
  const evidenceQuotes = found.map(f => f.preview).filter(q => typeof q === 'string' && q.length >= 8).slice(0, 5);
  const cveHit = found.find(f => f.cve);

  return {
    name          : 'nextjs security',
    status        : found.some(f => f.findingStatus === 'VULNERABLE') ? 'VULNERABLE' : 'SUSPICIOUS',
    severity      : maxSev,
    path          : cveHit?.path || primary.path,
    ...(cveHit ? { cve: cveHit.cve, cveIds: [cveHit.cve] } : {}),
    detail        : `Confirmed ${found.length} Next.js security issue(s): ${found.map(f => f.name).join(', ')}`,
    findings      : found.map(f => ({ name: f.name, severity: f.severity, path: f.path, url: f.url, status: f.status, matchedSignal: f.matchedSignal, preview: f.preview, reason: f.reason })),
    files         : found,
    reproVerified : true,
    poeLevel      : evidenceQuotes.length > 0 ? 3 : 2,
    ...(evidenceQuotes.length > 0 ? { evidenceQuotes } : {}),
    ...(primary.trafficId !== undefined ? { trafficId: primary.trafficId } : {}),
    fix           : 'Upgrade Next.js to 14.2.25+, 15.1.8+, or 15.2.1+ to remediate CVE-2025-29927. Disable production browser source maps in next.config.js, and ensure private credentials or database connection strings are never exposed in page props or __NEXT_DATA__.'
  };
}
