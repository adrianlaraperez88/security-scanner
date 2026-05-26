export const tags = ['all'];

/**
 * Detects publicly accessible API documentation (Swagger / OpenAPI / Redoc).
 *
 * Public API docs give attackers a complete map of every endpoint, parameter,
 * expected input format, and authentication scheme — significantly reducing
 * the effort needed to probe the API.
 */
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

const DOC_SIGNALS = [
  'swagger-ui',
  'openapi',
  'swagger',
  '"paths":',
  '"info":',
  '"openapi":',
  'redoc',
  'api documentation',
];

export default async function run(target, fetchWithRetry) {
  for (const p of API_DOC_PATHS) {
    try {
      const res  = await fetchWithRetry(`${target}${p}`);

      if (res.status !== 200) continue;

      const body = res.text.toLowerCase();

      if (DOC_SIGNALS.some(s => body.includes(s))) {
        return {
          name    : 'api docs exposure',
          status  : 'SUSPICIOUS',
          severity: 'MEDIUM',
          path    : p,
          detail  : 'Public API documentation exposes full endpoint map to attackers',
          fix     : 'Disable public API documentation endpoints in production or restrict access via authentication.'
        };
      }

    } catch { /* unreachable path */ }
  }

  return { name: 'api docs exposure', status: 'SAFE', severity: 'NONE' };
}
