import { redactSecretsInText } from '../core/ai-advisor.js';
import {
  isHtmlOrScript,
  parseJsonObject,
  extractVerbatimSnippet,
  confirmReproducible
} from '../core/check-verify.js';

export const tags = ['frontend', 'react', 'angular', 'vue', 'nextjs'];

export default async function run(target, fetchWithRetry) {
  const found = [];
  let mainResponse;

  try {
    mainResponse = await fetchWithRetry(target);
  } catch {
    return { name: 'frontend security', status: 'ERROR', severity: 'NONE', reason: 'Target unreachable' };
  }

  const html = typeof mainResponse?.text === 'string' ? mainResponse.text : '';
  const lowHtml = html.toLowerCase();

  // 1. Source Map Detection
  const scriptRegex = /<script\b[^>]*src=["']([^"']+\.js)/gi;
  const scriptPaths = [];
  let match;
  while ((match = scriptRegex.exec(html)) !== null) {
    const path = match[1];
    if (path.startsWith('http')) continue;
    scriptPaths.push(path);
  }

  for (const path of scriptPaths.slice(0, 3)) {
    try {
      const mapPath = `${path.startsWith('/') ? path : `/${path}`}.map`;
      const mapUrl = `${target}${mapPath}`;
      const res = await fetchWithRetry(mapUrl);
      const parsedMap = res?.status === 200 && !isHtmlOrScript(res, res.text) ? parseJsonObject(res.text) : null;
      if (parsedMap && (Array.isArray(parsedMap.sources) || parsedMap.version === 3)) {
        const { confirmed, res: cRes } = await confirmReproducible(
          mapUrl,
          fetchWithRetry,
          {},
          (r) => r?.status === 200 && Boolean(parseJsonObject(r.text)?.sources || parseJsonObject(r.text)?.version === 3)
        );
        if (confirmed) {
          const finalRes = cRes || res;
          const preview = extractVerbatimSnippet(finalRes.text || res.text || '', '"sources"') || 'JavaScript source map JSON';
          found.push({
            name         : 'exposed source maps',
            path         : mapPath,
            url          : mapUrl,
            method       : 'GET',
            status       : 200,
            statusTag    : 'VULNERABLE',
            severity     : 'HIGH',
            matchedSignal: 'SourceMap JSON ("sources")',
            reproducible : true,
            preview,
            reason       : `A source map was found at ${mapPath}, allowing attackers to reconstruct your original source code.`,
            ...(finalRes?.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {})
          });
          break;
        }
      }
    } catch { /* ignore */ }
  }

  // 2. Development Mode Detection
  if (lowHtml.includes('react devtools') || lowHtml.includes('vue-devtools')) {
    const devToken = lowHtml.includes('react devtools') ? 'react devtools' : 'vue-devtools';
    found.push({
      name         : 'development build detected',
      path         : '/',
      url          : target,
      method       : 'GET',
      status       : mainResponse?.status ?? 200,
      statusTag    : 'SUSPICIOUS',
      severity     : 'LOW',
      matchedSignal: devToken,
      reproducible : true,
      preview      : extractVerbatimSnippet(html, devToken) || devToken,
      reason       : 'The application appears to be running a development build of React or Vue, which contains extra debugging information.',
      ...(mainResponse?.trafficId !== undefined ? { trafficId: mainResponse.trafficId } : {})
    });
  }

  // 3. Potential Credential Exposure
  const secretPatterns = [
    { name: 'Generic API Key', regex: /api[-_]?key["']?\s*:\s*["'][a-zA-Z0-9_\-]{20,}["']?/i },
    { name: 'Firebase Project ID', regex: /["']?projectId["']?\s*:\s*["'][a-z0-9\-]{10,}["']?/i },
  ];

  for (const pattern of secretPatterns) {
    const m = pattern.regex.exec(html);
    if (m) {
      found.push({
        name         : `potential ${pattern.name.toLowerCase()} exposure`,
        path         : '/',
        url          : target,
        method       : 'GET',
        status       : mainResponse?.status ?? 200,
        statusTag    : 'SUSPICIOUS',
        severity     : 'MEDIUM',
        matchedSignal: pattern.name,
        reproducible : true,
        preview      : redactSecretsInText(m[0].slice(0, 100)),
        reason       : `A potential ${pattern.name} was found hardcoded in the root HTML.`,
        ...(mainResponse?.trafficId !== undefined ? { trafficId: mainResponse.trafficId } : {})
      });
    }
  }

  if (found.length === 0) {
    return { name: 'frontend security', status: 'SAFE', severity: 'NONE' };
  }

  const maxSev = found.some(f => f.severity === 'HIGH')   ? 'HIGH'
               : found.some(f => f.severity === 'MEDIUM') ? 'MEDIUM'
               : 'LOW';
  const primary = found[0];
  const evidenceQuotes = found.map(f => f.preview).filter(q => typeof q === 'string' && q.length >= 8).slice(0, 5);

  return {
    name          : 'frontend security',
    status        : found.some(f => f.statusTag === 'VULNERABLE') ? 'VULNERABLE' : 'SUSPICIOUS',
    severity      : maxSev,
    path          : primary.path,
    detail        : `Confirmed ${found.length} frontend issue(s): ${found.map(f => f.name).join(', ')}`,
    findings      : found.map(f => ({ name: f.name, severity: f.severity, path: f.path, url: f.url, status: f.status, matchedSignal: f.matchedSignal, preview: f.preview, reason: f.reason })),
    files         : found,
    reproVerified : true,
    poeLevel      : evidenceQuotes.length > 0 ? 3 : 2,
    ...(evidenceQuotes.length > 0 ? { evidenceQuotes } : {}),
    ...(primary.trafficId !== undefined ? { trafficId: primary.trafficId } : {}),
    fix           : 'Disable source map generation in your production build (e.g., GEN_SOURCE_MAP=false for CRA). Ensure you are using production builds of React/Vue/Angular, and never hardcode secrets in client-side code.'
  };
}
