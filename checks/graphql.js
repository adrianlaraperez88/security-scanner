export const tags = ['all'];

/**
 * GraphQL endpoint detection and introspection check.
 *
 * Introspection enabled in production gives attackers a complete
 * map of your GraphQL schema — every type, field, query, and mutation.
 * It should be disabled in production environments.
 */
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

const PLAYGROUND_SIGNALS = [
  'graphiql',
  'graphql playground',
  'graphql-playground',
  'voyager',
  '__schema',
];

export default async function run(target, fetchWithRetry) {
  for (const p of GRAPHQL_PATHS) {
    try {
      // 1. Send introspection query via POST (the real GraphQL way)
      const res = await fetchWithRetry(`${target}${p}`, {
        method  : 'POST',
        headers : { 'Content-Type': 'application/json' },
        body    : INTROSPECTION_QUERY
      });

      const body = res.text.toLowerCase();

      // Full schema returned → introspection is ON
      if (res.status === 200 && body.includes('"__schema"') && body.includes('"types"')) {
        return {
          name    : 'graphql introspection',
          status  : 'VULNERABLE',
          severity: 'MEDIUM',
          path    : p,
          detail  : 'Introspection enabled — full schema exposed to unauthenticated clients',
          fix     : 'Disable GraphQL introspection in your production environment configuration (e.g., in Apollo Server, set introspection: false).'
        };
      }

      // 2. Check if GraphQL Playground / GraphiQL UI is accessible via GET
      const getRes  = await fetchWithRetry(`${target}${p}`);
      const getBody = getRes.text.toLowerCase();

      if (getRes.status === 200 && PLAYGROUND_SIGNALS.some(s => getBody.includes(s))) {
        return {
          name    : 'graphql introspection',
          status  : 'SUSPICIOUS',
          severity: 'LOW',
          path    : p,
          detail  : 'GraphQL Playground/GraphiQL UI publicly accessible',
          fix     : 'Disable the GraphQL Playground or GraphiQL interface in production or restrict access to trusted IPs.'
        };
      }

    } catch { /* path unreachable */ }
  }

  return { name: 'graphql introspection', status: 'SAFE', severity: 'NONE' };
}
