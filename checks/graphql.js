import {
  isHtmlOrScript,
  isRedirectedToDifferentPath,
  isFrameworkRouteErrorResponse,
  parseJsonObject,
  extractVerbatimSnippet,
  confirmReproducible
} from '../core/check-verify.js';

export const tags = ['all'];

const GRAPHQL_PATHS = [
  '/graphql',
  '/api/graphql',
  '/graphql/console',
  '/graphql/v1',
  '/api/v1/graphql',
];

const INTROSPECTION_QUERY = JSON.stringify({
  query: '{ __schema { types { name } } }'
});

const INTROSPECTION_HEADERS = { 'Content-Type': 'application/json', 'Accept': 'application/json' };

const PLAYGROUND_SIGNALS = [
  'graphiql',
  'graphql playground',
  'graphql-playground',
  'graphql-voyager',
  'apollo-sandbox',
];

function isIntrospectionSchema(res, reqUrl) {
  if (res?.status !== 200 || (reqUrl && isRedirectedToDifferentPath(res, reqUrl))) return false;
  const text = typeof res.text === 'string' ? res.text : '';
  if (!text || isHtmlOrScript(res, text) || isFrameworkRouteErrorResponse(res, text)) return false;
  const json = parseJsonObject(text);
  const schema = json?.data?.__schema || json?.__schema;
  return Boolean(schema && Array.isArray(schema.types));
}

function matchPlayground(res, reqUrl) {
  if (res?.status !== 200 || (reqUrl && isRedirectedToDifferentPath(res, reqUrl))) return null;
  const raw = typeof res.text === 'string' ? res.text : '';
  if (isFrameworkRouteErrorResponse(res, raw)) return null;
  const lower = raw.toLowerCase();
  return PLAYGROUND_SIGNALS.find(s => lower.includes(s)) || null;
}

export default async function run(target, fetchWithRetry) {
  for (const p of GRAPHQL_PATHS) {
    try {
      const url = `${target}${p}`;
      const postOpts = { method: 'POST', headers: INTROSPECTION_HEADERS, body: INTROSPECTION_QUERY, followRedirects: false };
      const res = await fetchWithRetry(url, postOpts);

      if (isIntrospectionSchema(res, url)) {
        const { confirmed, res: cRes } = await confirmReproducible(
          url,
          fetchWithRetry,
          postOpts,
          (r) => isIntrospectionSchema(r, url)
        );
        if (confirmed) {
          const finalRes = cRes || res;
          const preview = extractVerbatimSnippet(finalRes.text || res.text || '', '"__schema"') || 'GraphQL __schema.types returned';
          return {
            name          : 'graphql introspection',
            status        : 'VULNERABLE',
            severity      : 'MEDIUM',
            path          : p,
            detail        : `Confirmed reproducible GraphQL introspection enabled at ${p} — full schema exposed`,
            files         : [{ path: p, url, method: 'POST', status: 200, matchedSignal: '__schema.types JSON', reproducible: true, preview }],
            reproVerified : true,
            poeLevel      : 3,
            evidenceQuotes: [preview],
            ...(finalRes?.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {}),
            fix           : 'Disable GraphQL introspection in your production environment configuration (e.g., in Apollo Server, set introspection: false).'
          };
        }
      }

      const getRes = await fetchWithRetry(url, { followRedirects: false });
      const uiSignal = matchPlayground(getRes, url);
      if (uiSignal) {
        const { confirmed, res: cRes } = await confirmReproducible(
          url,
          fetchWithRetry,
          { followRedirects: false },
          (r) => Boolean(matchPlayground(r, url))
        );
        if (confirmed) {
          const finalRes = cRes || getRes;
          const preview = extractVerbatimSnippet(finalRes.text || getRes.text || '', uiSignal) || uiSignal;
          return {
            name          : 'graphql introspection',
            status        : 'SUSPICIOUS',
            severity      : 'LOW',
            path          : p,
            detail        : `GraphQL Playground/GraphiQL UI publicly accessible at ${p} (${uiSignal})`,
            files         : [{ path: p, url, method: 'GET', status: 200, matchedSignal: uiSignal, reproducible: true, preview }],
            reproVerified : true,
            poeLevel      : 3,
            evidenceQuotes: [preview],
            ...(finalRes?.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {}),
            fix           : 'Disable the GraphQL Playground or GraphiQL interface in production or restrict access to trusted IPs.'
          };
        }
      }

    } catch { /* path unreachable */ }
  }

  return { name: 'graphql introspection', status: 'SAFE', severity: 'NONE' };
}
