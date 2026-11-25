/**
 * Invicti / Burp Suite OpenAPI 2.0 (Swagger) & OpenAPI 3.0/3.1 Schema Importer
 * and Parameterized Endpoint Synthesizer.
 *
 * Parses `/openapi.json`, `/swagger.json`, `/v3/api-docs`, `/v2/api-docs`, or a supplied
 * OpenAPI JSON object/string into concrete parameterized requests, synthesized JSON
 * request bodies (with circular-safe local `$ref` resolution), and `§marker§` Intruder templates.
 */

export const MAX_OPENAPI_BYTES = 2 * 1024 * 1024; // 2 MiB
export const MAX_OPENAPI_ENDPOINTS = 200;
export const MAX_REF_DEPTH = 6;

const HTTP_METHODS = ['get', 'post', 'put', 'patch', 'delete', 'options', 'head'];
const DISCOVERY_PATHS = [
  '/openapi.json',
  '/swagger.json',
  '/v3/api-docs',
  '/v2/api-docs',
  '/api/openapi.json',
  '/api/swagger.json',
  '/api-docs/swagger.json'
];

function resolveLocalRef(rootSpec, refStr) {
  if (typeof refStr !== 'string' || !refStr.startsWith('#/')) return null;
  const parts = refStr
    .slice(2)
    .split('/')
    .map(p => p.replace(/~1/g, '/').replace(/~0/g, '~'));

  let cur = rootSpec;
  for (const part of parts) {
    if (!cur || typeof cur !== 'object' || !Object.hasOwn(cur, part)) {
      return null;
    }
    cur = cur[part];
  }
  return cur && typeof cur === 'object' ? cur : null;
}

function synthesizeSampleValue(schema, rootSpec, propName = '', depth = 0, seenRefs = new Set()) {
  if (!schema || typeof schema !== 'object' || depth > MAX_REF_DEPTH) {
    return 'sample';
  }

  if (typeof schema.$ref === 'string') {
    if (seenRefs.has(schema.$ref)) return 'circular_ref';
    const target = resolveLocalRef(rootSpec, schema.$ref);
    if (!target) return 'sample';
    const nextSeen = new Set(seenRefs);
    nextSeen.add(schema.$ref);
    return synthesizeSampleValue(target, rootSpec, propName, depth + 1, nextSeen);
  }

  if (schema.example !== undefined) return schema.example;
  if (schema.default !== undefined) return schema.default;
  if (Array.isArray(schema.enum) && schema.enum.length > 0) return schema.enum[0];

  const type = String(schema.type || '').toLowerCase();
  const format = String(schema.format || '').toLowerCase();
  const lowerName = String(propName || '').toLowerCase();

  if (type === 'integer' || type === 'number' || lowerName === 'id' || lowerName.endsWith('_id') || lowerName.endsWith('id')) {
    if (format === 'uuid' || lowerName.includes('uuid')) {
      return '550e8400-e29b-41d4-a716-446655440000';
    }
    return 1;
  }

  if (type === 'boolean') return true;

  if (type === 'array') {
    const itemSample = schema.items
      ? synthesizeSampleValue(schema.items, rootSpec, propName, depth + 1, seenRefs)
      : 'item';
    return [itemSample];
  }

  if (type === 'object' || (schema.properties && typeof schema.properties === 'object')) {
    const out = {};
    const props = schema.properties && typeof schema.properties === 'object' ? schema.properties : {};
    const keys = Object.keys(props).slice(0, 20);
    for (const k of keys) {
      out[k] = synthesizeSampleValue(props[k], rootSpec, k, depth + 1, seenRefs);
    }
    return out;
  }

  if (format === 'uuid' || lowerName.includes('uuid')) return '550e8400-e29b-41d4-a716-446655440000';
  if (format === 'email' || lowerName.includes('email')) return 'user@example.com';
  if (format === 'uri' || format === 'url' || lowerName.includes('url')) return 'https://example.com';
  if (format === 'date-time') return '2026-01-01T00:00:00Z';
  if (format === 'date') return '2026-01-01';
  return 'test';
}

/**
 * Parses an OpenAPI 3.0/3.1 or Swagger 2.0 specification (object or JSON string)
 * and synthesizes concrete parameterized endpoint descriptors and Intruder templates.
 *
 * @param {object | string} rawSpec
 * @param {string} [baseUrl='https://example.com']
 * @param {{ maxEndpoints?: number }} [options={}]
 */
export function parseOpenApiSpec(rawSpec, baseUrl = 'https://example.com', options = {}) {
  let spec = rawSpec;
  if (typeof rawSpec === 'string') {
    if (Buffer.byteLength(rawSpec, 'utf8') > MAX_OPENAPI_BYTES) {
      throw new Error(`OpenAPI specification exceeds maximum allowed size (${MAX_OPENAPI_BYTES} bytes)`);
    }
    try {
      spec = JSON.parse(rawSpec);
    } catch (err) {
      throw new Error(`Invalid OpenAPI JSON: ${err.message}`);
    }
  }

  if (!spec || typeof spec !== 'object' || Array.isArray(spec)) {
    throw new Error('OpenAPI specification must be a JSON object');
  }

  const isOpenApi3 = typeof spec.openapi === 'string' && spec.openapi.startsWith('3.');
  const isSwagger2 = typeof spec.swagger === 'string' && spec.swagger.startsWith('2.');
  if (!isOpenApi3 && !isSwagger2 && (!spec.paths || typeof spec.paths !== 'object')) {
    throw new Error('Object is not a valid OpenAPI 3.x or Swagger 2.0 specification (missing openapi/swagger version and paths)');
  }

  // Resolve base URL from spec servers[] or Swagger host/basePath
  let resolvedBase = baseUrl || 'https://example.com';
  try {
    const baseObj = new URL(resolvedBase);
    if (isOpenApi3 && Array.isArray(spec.servers) && spec.servers[0]?.url) {
      const srvUrl = String(spec.servers[0].url).trim();
      resolvedBase = new URL(srvUrl, baseObj.origin).href;
    } else if (isSwagger2 && typeof spec.basePath === 'string') {
      resolvedBase = new URL(spec.basePath, baseObj.origin).href;
    }
  } catch {
    resolvedBase = 'https://example.com';
  }
  resolvedBase = resolvedBase.replace(/\/+$/, '');

  const maxEndpoints = Math.min(
    MAX_OPENAPI_ENDPOINTS,
    Math.max(1, Number(options.maxEndpoints) || MAX_OPENAPI_ENDPOINTS)
  );

  const pathsObj = spec.paths && typeof spec.paths === 'object' ? spec.paths : {};
  const endpoints = [];
  const crawlSeedUrls = new Set();

  for (const [rawPath, pathItem] of Object.entries(pathsObj)) {
    if (!pathItem || typeof pathItem !== 'object') continue;
    const pathLevelParams = Array.isArray(pathItem.parameters) ? pathItem.parameters : [];

    for (const methodLower of HTTP_METHODS) {
      if (endpoints.length >= maxEndpoints) break;
      const op = pathItem[methodLower];
      if (!op || typeof op !== 'object') continue;

      const method = methodLower.toUpperCase();
      const opParams = Array.isArray(op.parameters) ? op.parameters : [];
      const allParams = [...pathLevelParams, ...opParams].map(p =>
        p && typeof p.$ref === 'string' ? resolveLocalRef(spec, p.$ref) || p : p
      );

      let concretePath = String(rawPath || '/');
      let intruderPath = String(rawPath || '/');
      const queryPairs = [];
      const intruderQueryPairs = [];
      const headers = {};
      const parametersMeta = [];

      // Replace {param} in path
      concretePath = concretePath.replace(/\{([^}]+)\}/g, (_, paramName) => {
        const pDef = allParams.find(p => p && p.in === 'path' && p.name === paramName);
        const schema = pDef?.schema || pDef || { type: 'integer' };
        const sample = synthesizeSampleValue(schema, spec, paramName);
        parametersMeta.push({ name: paramName, in: 'path', sample });
        return encodeURIComponent(String(sample));
      });

      intruderPath = intruderPath.replace(/\{([^}]+)\}/g, (_, paramName) => {
        const pDef = allParams.find(p => p && p.in === 'path' && p.name === paramName);
        const schema = pDef?.schema || pDef || { type: 'integer' };
        const sample = synthesizeSampleValue(schema, spec, paramName);
        return `§${sample}§`;
      });

      for (const p of allParams) {
        if (!p || typeof p !== 'object' || !p.name) continue;
        const schema = p.schema || p;
        const sample = synthesizeSampleValue(schema, spec, p.name);
        if (p.in === 'query') {
          queryPairs.push(`${encodeURIComponent(p.name)}=${encodeURIComponent(String(sample))}`);
          intruderQueryPairs.push(`${encodeURIComponent(p.name)}=§${encodeURIComponent(String(sample))}§`);
          parametersMeta.push({ name: p.name, in: 'query', sample });
        } else if (p.in === 'header') {
          headers[p.name] = String(sample);
          parametersMeta.push({ name: p.name, in: 'header', sample });
        } else if (p.in === 'body' && p.schema && !op.requestBody) {
          // Swagger 2.0 body parameter
          op._swagger2BodySchema = p.schema;
        }
      }

      // Synthesize JSON requestBody for OpenAPI 3.x or Swagger 2.0
      let sampleBody = null;
      const reqBodyObj = op.requestBody && typeof op.requestBody.$ref === 'string'
        ? resolveLocalRef(spec, op.requestBody.$ref)
        : op.requestBody;
      const jsonSchema =
        reqBodyObj?.content?.['application/json']?.schema ||
        op._swagger2BodySchema ||
        null;

      if (jsonSchema) {
        const synthesized = synthesizeSampleValue(jsonSchema, spec, 'body');
        headers['Content-Type'] = 'application/json';
        sampleBody = typeof synthesized === 'object' ? JSON.stringify(synthesized) : String(synthesized);
      }

      const relPath = concretePath.startsWith('/') ? concretePath : `/${concretePath}`;
      const relIntruderPath = intruderPath.startsWith('/') ? intruderPath : `/${intruderPath}`;
      const url = `${resolvedBase}${relPath}${queryPairs.length ? `?${queryPairs.join('&')}` : ''}`;
      const intruderTemplateUrl = `${resolvedBase}${relIntruderPath}${intruderQueryPairs.length ? `?${intruderQueryPairs.join('&')}` : ''}`;

      crawlSeedUrls.add(url);
      endpoints.push({
        method,
        pathTemplate: rawPath,
        url,
        intruderTemplateUrl,
        operationId: op.operationId || null,
        summary: op.summary || null,
        requiresAuth: Array.isArray(op.security) ? op.security.length > 0 : Boolean(spec.security?.length),
        headers,
        body: sampleBody,
        parameters: parametersMeta
      });
    }
    if (endpoints.length >= maxEndpoints) break;
  }

  return {
    version: spec.openapi || spec.swagger || 'unknown',
    title: spec.info?.title || 'OpenAPI Specification',
    baseUrl: resolvedBase,
    totalEndpoints: endpoints.length,
    crawlSeedUrls: Array.from(crawlSeedUrls),
    endpoints
  };
}

/**
 * Probes common OpenAPI / Swagger discovery paths on `targetUrl` using `fetchWithRetry`
 * and imports the first valid specification found.
 *
 * @param {string} targetUrl
 * @param {Function} fetchWithRetry
 * @param {{ maxEndpoints?: number }} [options={}]
 */
export async function discoverAndImportOpenApi(targetUrl, fetchWithRetry, options = {}) {
  const origin = new URL(targetUrl).origin;
  for (const pathCandidate of DISCOVERY_PATHS) {
    const candidateUrl = new URL(pathCandidate, origin).href;
    try {
      const res = await fetchWithRetry(candidateUrl, {
        headers: { Accept: 'application/json' },
        followRedirects: false
      });
      if (!res || res.status !== 200) continue;
      const text = String(res.text || '').trim();
      if (!text.startsWith('{')) continue;
      if (!text.includes('"paths"') || (!text.includes('"openapi"') && !text.includes('"swagger"'))) {
        continue;
      }
      const imported = parseOpenApiSpec(text, origin, options);
      return {
        discovered: true,
        schemaUrl: candidateUrl,
        ...imported
      };
    } catch (err) {
      if (err?.isGovernanceBlock) throw err;
    }
  }

  return {
    discovered: false,
    schemaUrl: null,
    totalEndpoints: 0,
    crawlSeedUrls: [],
    endpoints: []
  };
}
