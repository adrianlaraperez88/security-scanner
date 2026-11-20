import {
  isHtmlOrScript,
  isRedirectedToDifferentPath,
  parseJsonObject,
  extractVerbatimSnippet,
  confirmReproducible
} from '../core/check-verify.js';

export const tags = ['all'];

const API_DOC_PATHS = [
  '/swagger',
  '/swagger-ui',
  '/swagger-ui.html',
  '/swagger/index.html',
  '/api/documentation',
  '/api-docs',
  '/api-docs.json',
  '/openapi.json',
  '/openapi.yaml',
  '/swagger.json',
  '/swagger.yaml',
  '/docs',
  '/api/docs',
  '/redoc',
  '/api/swagger',
];

function matchApiDocSignal(res, reqUrl) {
  if (res?.status !== 200 || isRedirectedToDifferentPath(res, reqUrl)) return null;
  const text = typeof res.text === 'string' ? res.text : '';
  if (!text) return null;

  // JSON OpenAPI / Swagger / Hydra JSON-LD spec
  if (!isHtmlOrScript(res, text)) {
    const json = parseJsonObject(text);
    if (json && !Array.isArray(json)) {
      if ((json.openapi || json.swagger) && (json.paths || json.info)) {
        return json.openapi ? `OpenAPI ${json.openapi} spec` : `Swagger ${json.swagger} spec`;
      }
      if (
        json['@context'] &&
        (json['@type'] === 'hydra:EntryPoint' ||
          json['@type'] === 'ApiDocumentation' ||
          text.includes('http://www.w3.org/ns/hydra/core#'))
      ) {
        return 'Hydra JSON-LD API documentation';
      }
    }
    const lower = text.toLowerCase();
    if ((lower.includes('openapi:') || lower.includes('swagger:')) && lower.includes('paths:')) {
      return 'OpenAPI/Swagger YAML specification';
    }
    return null;
  }

  // Interactive HTML UI (Swagger UI / ReDoc) — require genuine widget markers
  const lower = text.toLowerCase();
  if (lower.includes('swagger-ui') || lower.includes('swaggeruibundle')) return 'Swagger UI widget';
  if (lower.includes('redoc.standalone.js') || lower.includes('<redoc')) return 'ReDoc API UI';
  return null;
}

export default async function run(target, fetchWithRetry) {
  const fetchOpts = { followRedirects: false };
  for (const p of API_DOC_PATHS) {
    try {
      const url = `${target}${p}`;
      const res = await fetchWithRetry(url, fetchOpts);
      const signal = matchApiDocSignal(res, url);
      if (!signal) continue;

      const { confirmed, res: cRes } = await confirmReproducible(
        url,
        fetchWithRetry,
        fetchOpts,
        (r) => Boolean(matchApiDocSignal(r, url))
      );
      if (!confirmed) continue;

      const finalRes = cRes || res;
      const preview = extractVerbatimSnippet(finalRes.text || res.text || '', /swagger-ui|swaggeruibundle|redoc|"openapi"|"swagger"|openapi:|hydra/i) || signal;
      return {
        name          : 'api docs exposure',
        status        : 'SUSPICIOUS',
        severity      : 'MEDIUM',
        path          : p,
        detail        : `Public API documentation confirmed at ${p} (${signal})`,
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
        fix           : 'Disable public API documentation endpoints in production or restrict access via authentication.'
      };
    } catch { /* unreachable path */ }
  }

  return { name: 'api docs exposure', status: 'SAFE', severity: 'NONE' };
}
