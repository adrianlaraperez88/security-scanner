import { test } from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import {
  redactApiSecretPreview,
  redactEndpointQuery,
  stripSensitiveQueryParamsForProbe,
  extractApiSignalsFromHtml,
  extractApiEndpointsFromScript,
  inspectApiCommunication,
  isDestructiveApiRoute,
  isSafeReadOnlyApiRoute,
  filterSafeSameOriginApiRoutes,
  DEFAULT_MAX_SCRIPT_BYTES,
  DEFAULT_MAX_TOTAL_SCRIPT_BYTES,
  DEFAULT_MAX_JSON_BYTES
} from '../../core/api-discovery.js';
import { discoverApiRoutesFromPage } from '../../core/crawler.js';
import { fetchWithRetry, createGovernedFetch } from '../../core/fetch.js';
import { TaskQueue } from '../../core/queue.js';

test('redactApiSecretPreview: redacts tokens, passwords, Bearer JWTs, and URL credentials', () => {
  const sample = [
    'const cfg = { apiKey: "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGt9z1",',
    'dbPassword: "UltraSecretPassword123!",',
    'auth: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",',
    'uri: "https://svcuser:superpass99@db.internal:5432/app" };'
  ].join(' ');

  const redacted = redactApiSecretPreview(sample, 400);
  assert.ok(!redacted.includes('AIzaSyDaGmWKa4JsXZ'), 'Google API key must be redacted');
  assert.ok(!redacted.includes('UltraSecretPassword123'), 'Password must be redacted');
  assert.ok(!redacted.includes('eyJhbGciOiJIUzI1NiI'), 'JWT must be redacted');
  assert.ok(!redacted.includes('superpass99'), 'URL password must be redacted');
  assert.ok(redacted.includes('<REDACTED>'));
});

test('extractApiSignalsFromHtml: detects Angular, prioritizes main bundles over polyfills, parses CSP & Link headers, skips CDNs', () => {
  const html = `
    <!doctype html>
    <html>
      <head>
        <title>Angular App</title>
        <script src="https://cdn.jsdelivr.net/npm/zone.js@0.14.0/bundles/zone.umd.min.js"></script>
        <script src="/polyfills-FFHMD2TL.js" type="module"></script>
        <script src="/vendor.js"></script>
        <script src="/runtime.js"></script>
        <script src="/main-6X7K2L3M.js" type="module"></script>
      </head>
      <body>
        <app-root ng-version="18.2.0" ng-server-context="ssr"></app-root>
      </body>
    </html>
  `;
  const headers = {
    'content-security-policy': "default-src 'self'; connect-src 'self' 'none' 'unsafe-inline' data: blob: https://api.acme.example wss://ws.acme.example",
    'link': '<https://api.acme.example>; rel="preconnect", </api/openapi.json>; rel="service-desc"'
  };

  const signals = extractApiSignalsFromHtml(html, headers, 'https://app.acme.example');
  assert.ok(signals.frameworks.includes('angular'));
  assert.ok(signals.signals.includes('ng-version'));
  assert.ok(signals.signals.includes('ng-server-context'));
  assert.ok(signals.signals.includes('<app-root>'));
  assert.ok(signals.signals.includes('main+polyfills'));

  assert.deepEqual(signals.cspConnectSrc, ['https://api.acme.example', 'wss://ws.acme.example']);
  assert.equal(signals.linkHeaders.length, 2);

  // Only same-origin scripts kept; main-* comes ahead of polyfills/vendor/runtime
  assert.equal(signals.scriptUrls.length, 4);
  assert.ok(signals.scriptUrls[0].endsWith('/main-6X7K2L3M.js'), `Expected main bundle first, got ${signals.scriptUrls[0]}`);
  assert.ok(signals.scriptUrls.every(u => u.startsWith('https://app.acme.example/')));
  assert.ok(signals.skippedExternalScripts.some(u => u.includes('cdn.jsdelivr.net')));
});

test('extractApiEndpointsFromScript: extracts React/Axios/GraphQL/tRPC/WS/SSE endpoints and filters static & noisy CDN/schema hosts', () => {
  const js = `
    import axios from "axios";
    const svgNs = "http://www.w3.org/2000/svg";
    const schemaRef = "https://schema.org/Person";
    const cdn = "https://unpkg.com/react@18/umd/react.production.min.js";
    const docs = "https://angular.dev/errors/NG0100";
    const reactDocs = "https://reactjs.org/docs/error-decoder.html";
    const vueDocs = "https://vuejs.org/error-reference/";
    const client = axios.create({ baseURL: "https://api.partner.example/v2" });
    fetch("/api/users?role=member");
    fetch(\`/api/orders/\${orderId}\`);
    fetch("/api/logo.png");
    fetch("/_next/static/chunks/app.js");
    fetch("/node_modules/pkg/index.js");
    fetch("/static/styles.css");
    const gql = new ApolloClient({ uri: "/graphql" });
    const trpc = createTRPCProxyClient({ url: "/trpc/user.list" });
    const ws = new WebSocket("wss://stream.partner.example/live");
    const sse = new EventSource("/api/events");
  `;

  const res = extractApiEndpointsFromScript(js, 'https://app.example.com');
  assert.ok(res.sameOriginEndpoints.includes('/api/users?role=member'));
  assert.ok(res.sameOriginEndpoints.includes('/api/orders'));
  assert.ok(res.sameOriginEndpoints.includes('/graphql'));
  assert.ok(res.sameOriginEndpoints.includes('/trpc/user.list'));
  assert.ok(res.sameOriginEndpoints.includes('/api/events'));

  assert.ok(!res.sameOriginEndpoints.includes('/api/logo.png'));
  assert.ok(!res.sameOriginEndpoints.some(p => p.includes('_next/static') || p.includes('node_modules') || p.includes('/static/')));

  assert.ok(res.externalApiOrigins.includes('https://api.partner.example'));
  assert.ok(res.externalApiOrigins.includes('wss://stream.partner.example'));
  for (const noisy of ['http://www.w3.org', 'https://schema.org', 'https://unpkg.com', 'https://angular.dev', 'https://reactjs.org', 'https://vuejs.org']) {
    assert.ok(!res.externalApiOrigins.includes(noisy), `Expected noisy host ${noisy} to be filtered`);
  }

  assert.ok(res.clients.includes('Axios'));
  assert.ok(res.clients.includes('Fetch API'));
  assert.ok(res.clients.includes('Apollo GraphQL'));
  assert.ok(res.clients.includes('tRPC'));
  assert.ok(res.clients.includes('WebSocket'));
  assert.ok(res.clients.includes('Server-Sent Events'));
  assert.equal(res.issues.length, 0);
});

test('extractApiEndpointsFromScript: detects insecure http:// on https:// pages, localhost leaks on non-local targets, and redacts secrets', () => {
  const js = `
    fetch("http://legacy-api.partner.example/v1/profile");
    const devApi = { apiUrl: "http://localhost:8080/api" };
    const localIp = { backendUrl: "https://127.0.0.1:9000/v1" };
    const v6 = { endpoint: "http://[::1]:3001/graphql" };
    const corp = { serverUrl: "https://auth.corp.internal/oauth/token" };
    const tokenCfg = { apiKey: "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGt9z1", clientSecret: "prod_secret_9876543210abcd" };
  `;

  const prodRes = extractApiEndpointsFromScript(js, 'https://prod.example.com', { sourceUrl: '/main.js' });
  assert.ok(prodRes.issues.some(i => i.type === 'insecure_http_api' && i.severity === 'HIGH' && i.endpoint === 'http://legacy-api.partner.example'));
  assert.ok(prodRes.issues.some(i => i.type === 'localhost_api_leak' && i.severity === 'MEDIUM' && i.endpoint === 'http://localhost:8080'));
  assert.ok(prodRes.issues.some(i => i.type === 'localhost_api_leak' && i.endpoint === 'https://127.0.0.1:9000'));
  assert.ok(prodRes.issues.some(i => i.type === 'localhost_api_leak' && i.endpoint === 'http://[::1]:3001'));
  assert.ok(prodRes.issues.some(i => i.type === 'localhost_api_leak' && i.endpoint === 'https://auth.corp.internal'));

  const secretIssues = prodRes.issues.filter(i => i.type === 'client_secret_exposure');
  assert.ok(secretIssues.length >= 1);
  for (const si of secretIssues) {
    assert.ok(!si.detail.includes('AIzaSyDaGmWKa4JsXZ'), 'Raw API key must never leak in issue detail');
    assert.ok(!si.detail.includes('prod_secret_9876543210abcd'), 'Raw clientSecret must never leak in issue detail');
  }

  // Local target should NOT flag localhost_api_leak for localhost references
  const localRes = extractApiEndpointsFromScript(
    'fetch("http://localhost:8080/api/users");',
    'http://127.0.0.1:4200'
  );
  assert.equal(localRes.issues.some(i => i.type === 'localhost_api_leak'), false);
  assert.equal(localRes.issues.some(i => i.type === 'insecure_http_api'), false);
});

test('extractApiEndpointsFromScript: truncates scripts > 1.5 MiB before scanning', () => {
  const padding = '/* pad */ '.repeat(Math.ceil((DEFAULT_MAX_SCRIPT_BYTES + 1024) / 10));
  const oversized = padding.slice(0, DEFAULT_MAX_SCRIPT_BYTES + 64) + ' fetch("/api/after-1-5-mib");';
  const res = extractApiEndpointsFromScript(oversized, 'https://example.com');
  assert.equal(res.truncated, true);
  assert.equal(res.sameOriginEndpoints.includes('/api/after-1-5-mib'), false);
});

test('inspectApiCommunication: inspects Angular bundle + /assets/config.json while respecting SSRF boundary (never fetches cross-origin)', async () => {
  const fetchedUrls = [];
  const mockFetch = async (url) => {
    fetchedUrls.push(url);
    if (url === 'https://spa.example.com/') {
      return {
        status: 200,
        headers: { 'content-type': 'text/html' },
        text: `
          <html>
            <head>
              <script src="https://cdn.evil-third-party.example/tracker.js"></script>
              <script src="/polyfills-123.js"></script>
              <script src="/main-abc.js"></script>
            </head>
            <body><app-root ng-version="18.1.0"></app-root></body>
          </html>
        `
      };
    }
    if (url === 'https://spa.example.com/main-abc.js') {
      return {
        status: 200,
        headers: { 'content-type': 'application/javascript' },
        text: `
          import { HttpClient } from "@angular/common/http";
          export class UserService {
            constructor(http) { this.http = http; }
            load() {
              this.http.get("/assets/config.json");
              this.http.get("/api/v1/users");
              return fetch("https://external-api.example.org/v2/profile");
            }
          }
        `
      };
    }
    if (url === 'https://spa.example.com/polyfills-123.js') {
      return { status: 200, headers: { 'content-type': 'application/javascript' }, text: '// polyfills' };
    }
    if (url === 'https://spa.example.com/assets/config.json') {
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        text: JSON.stringify({
          apiBase: 'https://config-api.example.org',
          authUrl: 'https://spa.example.com/oauth/token'
        })
      };
    }
    return { status: 404, headers: {}, text: 'Not found' };
  };

  const result = await inspectApiCommunication('https://spa.example.com', mockFetch);
  assert.equal(result.usesApi, true);
  assert.equal(result.architecture, 'spa_api_client');
  assert.ok(result.clients.includes('Angular HttpClient'));
  assert.ok(result.clients.includes('Fetch API'));
  assert.ok(result.sameOriginEndpoints.includes('/api/v1/users'));
  assert.ok(result.sameOriginEndpoints.includes('/assets/config.json'));
  assert.ok(result.sameOriginEndpoints.includes('/oauth/token'));
  assert.ok(result.externalApiOrigins.includes('https://external-api.example.org'));
  assert.ok(result.externalApiOrigins.includes('https://config-api.example.org'));
  assert.equal(result.configFiles.length, 1);
  assert.equal(result.configFiles[0].path, '/assets/config.json');
  assert.equal(result.bundlesInspected, 2);

  // SSRF check: EVERY fetched URL must be strictly same-origin
  assert.ok(fetchedUrls.length > 0);
  for (const u of fetchedUrls) {
    assert.equal(new URL(u).origin, 'https://spa.example.com', `Unexpected cross-origin fetch: ${u}`);
  }
  // main-abc.js must be fetched before polyfills-123.js
  assert.ok(
    fetchedUrls.indexOf('https://spa.example.com/main-abc.js') <
    fetchedUrls.indexOf('https://spa.example.com/polyfills-123.js')
  );
});

test('inspectApiCommunication: returns usesApi=false for plain static HTML even with SPA HTML fallback on /config.json', async () => {
  const mockFetch = async () => ({
    status: 200,
    headers: { 'content-type': 'text/html' },
    text: '<html><body><h1>Static Brochure</h1><a href="/about">About</a></body></html>'
  });

  const res = await inspectApiCommunication('https://static.example.com', mockFetch);
  assert.equal(res.usesApi, false);
  assert.equal(res.architecture, 'traditional_web');
  assert.deepEqual(res.sameOriginEndpoints, []);
  assert.deepEqual(res.externalApiOrigins, []);
  assert.deepEqual(res.configFiles, []);
  assert.deepEqual(res.issues, []);
  assert.equal(res.bundlesInspected, 0);
});

test('discoverApiRoutesFromPage: discovers safe same-origin API routes and filters destructive/external routes for TaskQueue', async () => {
  const html = `
    <html>
      <body>
        <script src="/app.js"></script>
      </body>
    </html>
  `;
  const mockFetch = async (url) => {
    if (url.endsWith('/app.js')) {
      return {
        status: 200,
        headers: { 'content-type': 'application/javascript' },
        text: `
          fetch("/api/products");
          fetch("/graphql");
          fetch("/auth/logout");
          fetch("/api/users/delete");
          fetch("https://third-party.example.com/api/secret");
        `
      };
    }
    return { status: 404, headers: {}, text: '' };
  };

  const routes = await discoverApiRoutesFromPage('https://shop.example.com', html, mockFetch);
  assert.ok(routes.includes('/api/products'));
  assert.ok(routes.includes('/graphql'));
  assert.equal(routes.includes('/auth/logout'), false);
  assert.equal(routes.includes('/api/users/delete'), false);
  assert.equal(routes.some(r => r.includes('third-party.example.com')), false);

  const q = new TaskQueue('https://shop.example.com');
  q.push(routes);
  assert.ok(q.seen.has('https://shop.example.com/api/products'));
  assert.ok(q.seen.has('https://shop.example.com/graphql'));
});

test('inspectApiCommunication: classifies api_service, ssr_hybrid_api, enforces 4 MiB / maxBundles caps, and handles unreachable targets safely', async () => {
  // 1. JSON root -> api_service
  const jsonService = await inspectApiCommunication('https://api.service.example/', async () => ({
    status: 404,
    headers: {},
    text: ''
  }), {
    rootResponse: {
      status: 200,
      headers: { 'content-type': 'application/json' },
      text: JSON.stringify({ service: 'orders', routes: ['/v1/orders', '/v1/health'] })
    },
    maxBundles: 0,
    maxConfigProbes: 0
  });
  assert.equal(jsonService.usesApi, true);
  assert.equal(jsonService.architecture, 'api_service');
  assert.ok(jsonService.sameOriginEndpoints.includes('/v1/orders'));

  // 2. Next.js SSR + inline script + CSP connect-src insecure HTTP leak -> ssr_hybrid_api
  const ssrRes = await inspectApiCommunication('https://next-ssr.example.com', async () => ({
    status: 404,
    headers: {},
    text: ''
  }), {
    rootResponse: {
      status: 200,
      headers: {
        'content-type': 'text/html',
        'content-security-policy': "connect-src 'self' http://legacy-ssr.example.com https://gql.example.com"
      },
      text: `
        <html>
          <body>
            <script id="__NEXT_DATA__" type="application/json">{}</script>
            <script>fetch('/api/session');</script>
          </body>
        </html>
      `
    },
    maxBundles: 0,
    maxConfigProbes: 0
  });
  assert.equal(ssrRes.usesApi, true);
  assert.equal(ssrRes.architecture, 'ssr_hybrid_api');
  assert.ok(ssrRes.sameOriginEndpoints.includes('/api/session'));
  assert.ok(ssrRes.externalApiOrigins.includes('https://gql.example.com'));
  assert.ok(ssrRes.issues.some(i => i.type === 'insecure_http_api' && i.endpoint === 'http://legacy-ssr.example.com'));

  // 3. Bounds: maxBundles=5 & <= 4 MiB total downloaded bytes
  const bigChunk = 'x'.repeat(1_572_864);
  const fetchedScripts = [];
  const boundedRes = await inspectApiCommunication('https://bounded.example.com', async (url) => {
    fetchedScripts.push(url);
    return {
      status: 200,
      headers: { 'content-type': 'application/javascript' },
      text: `${bigChunk};fetch("/api/never-reached-if-cut");`
    };
  }, {
    rootResponse: {
      status: 200,
      headers: { 'content-type': 'text/html' },
      text: Array.from({ length: 7 }, (_, idx) => `<script src="/bundle-${idx}.js"></script>`).join('')
    },
    maxConfigProbes: 0
  });
  assert.ok(boundedRes.bundlesInspected <= 3, `Expected 4 MiB cap to stop after <= 3 bundles of 1.5 MiB each, inspected ${boundedRes.bundlesInspected}`);
  assert.ok(fetchedScripts.length <= 3);

  // 4. Unreachable target returns safe non-throwing result
  const downRes = await inspectApiCommunication('https://down.example.com', async () => {
    throw new Error('ECONNREFUSED');
  });
  assert.equal(downRes.reachable, false);
  assert.equal(downRes.usesApi, false);
  assert.equal(downRes.architecture, 'traditional_web');
});

test('CANDIDATE-1: extractApiEndpointsFromScript and redactApiSecretPreview resist ReDoS on -eyJ.repeat(20480) (<200ms)', () => {
  const payload = '-eyJ'.repeat(20480);
  const t0 = performance.now();
  const res = extractApiEndpointsFromScript(payload, 'https://example.com');
  const preview = redactApiSecretPreview(payload, 240);
  const elapsedMs = performance.now() - t0;

  assert.equal(res.issues.length, 0);
  assert.ok(preview.length <= 240);
  assert.ok(elapsedMs < 200, `Expected linear runtime < 200ms, got ${elapsedMs.toFixed(1)}ms`);
});

test('CANDIDATE-3: query-string secret hygiene masks sensitive query params at extraction and strips them before TaskQueue', async () => {
  const js = `
    fetch("/api/x?access_token=SECRET_XYZ&foo=bar");
    fetch("/api/y?sig=SECRET_SIG");
    fetch("/api/users?role=member");
    fetch("https://spa.example.com/api/z?api_key=SECRET_KEY_123&page=2");
  `;
  const extracted = extractApiEndpointsFromScript(js, 'https://spa.example.com');
  assert.ok(extracted.sameOriginEndpoints.includes('/api/x?access_token=<REDACTED>&foo=bar'));
  assert.ok(extracted.sameOriginEndpoints.includes('/api/y?sig=<REDACTED>'));
  assert.ok(extracted.sameOriginEndpoints.includes('/api/users?role=member'));
  assert.ok(extracted.sameOriginEndpoints.includes('/api/z?api_key=<REDACTED>&page=2'));

  const inspected = await inspectApiCommunication('https://spa.example.com', async (url) => {
    if (url === 'https://spa.example.com/main.js') {
      return { status: 200, headers: { 'content-type': 'application/javascript' }, text: js };
    }
    if (url === 'https://spa.example.com/assets/config.json') {
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        text: JSON.stringify({ endpoint: '/api/cfg?token=SECRET_CFG_TOK&mode=read' })
      };
    }
    return { status: 404, headers: {}, text: '' };
  }, {
    rootResponse: {
      status: 200,
      headers: {
        'content-type': 'text/html',
        link: '</api/link?sig=SECRET_LINK>; rel="service-desc"'
      },
      text: '<html><body><script src="/main.js"></script></body></html>'
    }
  });

  const serialized = JSON.stringify(inspected);
  for (const secret of ['SECRET_XYZ', 'SECRET_SIG', 'SECRET_KEY_123', 'SECRET_CFG_TOK', 'SECRET_LINK']) {
    assert.ok(!serialized.includes(secret), `Secret ${secret} must never leak into inspectApiCommunication output`);
  }
  assert.ok(inspected.configFiles[0].endpoints.includes('/api/cfg?token=<REDACTED>&mode=read'));

  const routes = await discoverApiRoutesFromPage(
    'https://spa.example.com',
    '<html><body><script src="/main.js"></script></body></html>',
    async (url) => url.endsWith('/main.js')
      ? { status: 200, headers: { 'content-type': 'application/javascript' }, text: js }
      : { status: 404, headers: {}, text: '' }
  );
  const q = new TaskQueue('https://spa.example.com');
  q.push(routes);
  const queued = Array.from(q.pending);
  assert.ok(queued.includes('https://spa.example.com/api/x?foo=bar'));
  assert.ok(queued.includes('https://spa.example.com/api/y'));
  assert.ok(queued.includes('https://spa.example.com/api/users?role=member'));
  assert.ok(!JSON.stringify(queued).includes('SECRET_XYZ'));
  assert.ok(!JSON.stringify(queued).includes('SECRET_SIG'));
  assert.equal(redactEndpointQuery('/api/y?sig=SECRET_SIG'), '/api/y?sig=<REDACTED>');
  assert.equal(stripSensitiveQueryParamsForProbe('/api/x?access_token=SECRET_XYZ&foo=bar'), '/api/x?foo=bar');
});

test('CANDIDATE-4 & CANDIDATE-5: fetchWithRetry maxBytes streaming cap, manual redirect lock, JSON slice before parse, shared 4 MiB budget, and crawl memoization', async () => {
  // 1. Streaming maxBytes cap on ReadableStream Response + non-stream fallback
  let cancelled = false;
  const stream = new ReadableStream({
    pull(controller) {
      controller.enqueue(new TextEncoder().encode('A'.repeat(1024)));
    },
    cancel() {
      cancelled = true;
    }
  });
  const streamRes = await fetchWithRetry('https://stream.example.com/big.js', {
    maxBytes: 2500,
    dnsResolver: async () => ['93.184.216.34'],
    fetcher: async () => new Response(stream, { status: 200, headers: { 'content-type': 'application/javascript' } })
  }, 0, 2000);
  assert.equal(streamRes.text.length, 2500);
  assert.equal(cancelled, true, 'Expected streaming reader to cancel after hitting maxBytes');

  const fallbackRes = await fetchWithRetry('https://fallback.example.com/big.js', {
    maxBytes: 128,
    dnsResolver: async () => ['93.184.216.34'],
    fetcher: async () => ({ status: 200, headers: {}, text: async () => 'B'.repeat(500) })
  }, 0, 2000);
  assert.equal(fallbackRes.text.length, 128);

  // 2. Cross-origin 302 redirect on bundle & config is NOT followed via governed fetch
  const fetchedTargets = [];
  const governed = createGovernedFetch({
    dnsResolver: async () => ['93.184.216.34'],
    retries: 0,
    fetcher: async (url) => {
      fetchedTargets.push(url);
      if (url === 'https://redir.example.com/') {
        return new Response('<html><script src="/main.js"></script></html>', {
          status: 200,
          headers: { 'content-type': 'text/html' }
        });
      }
      if (url === 'https://redir.example.com/main.js') {
        return new Response('', {
          status: 302,
          headers: { location: 'https://thirdparty.example/evil.js' }
        });
      }
      if (url === 'https://redir.example.com/assets/config.json') {
        return new Response('', {
          status: 302,
          headers: { location: 'https://thirdparty.example/evil.json' }
        });
      }
      if (url.startsWith('https://thirdparty.example/')) {
        return new Response('fetch("https://leaked-by-redirect.example/api");', {
          status: 200,
          headers: { 'content-type': 'application/javascript' }
        });
      }
      return new Response('Not found', { status: 404 });
    }
  });
  const redirRes = await inspectApiCommunication('https://redir.example.com/', governed);
  assert.equal(fetchedTargets.some(u => u.includes('thirdparty.example')), false, 'Must never follow 302 redirect to thirdparty.example');
  assert.equal(redirRes.externalApiOrigins.includes('https://leaked-by-redirect.example'), false);

  // 3. Oversized JSON config & inline + config budget shared against 4 MiB total
  const oversizedTextPlainJson = '{' + '"k":"' + 'x'.repeat(2_200_000) + '"}';
  const budgetCalls = [];
  const budgetRes = await inspectApiCommunication('https://budget.example.com', async (url) => {
    budgetCalls.push(url);
    if (url.endsWith('/assets/config.json')) {
      return { status: 200, headers: { 'content-type': 'application/json' }, text: oversizedTextPlainJson };
    }
    return {
      status: 200,
      headers: { 'content-type': 'application/javascript' },
      text: `${'y'.repeat(1_572_864)};fetch("/api/from-bundle");`
    };
  }, {
    rootResponse: {
      status: 200,
      headers: { 'content-type': 'text/plain' },
      text: `<html><script>${'z'.repeat(1_500_000)}</script><script src="/b1.js"></script><script src="/b2.js"></script><script src="/b3.js"></script></html>`
    },
    maxConfigProbes: 2
  });
  assert.ok(budgetRes.bundlesInspected <= 2, `Expected inline 1.5MB + bundles to hit 4MiB cap before 3rd bundle, got ${budgetRes.bundlesInspected}`);
  assert.ok(DEFAULT_MAX_JSON_BYTES === 524_288 && DEFAULT_MAX_TOTAL_SCRIPT_BYTES === 4_194_304);

  // 4. Multi-page crawl HTML reuse & bundle/config memoization via seenBundleUrls
  const memoFetches = [];
  const memoFetch = async (url) => {
    memoFetches.push(url);
    if (url === 'https://memo.example.com/main.js') {
      return { status: 200, headers: { 'content-type': 'application/javascript' }, text: 'fetch("/api/v1/items");' };
    }
    return { status: 404, headers: {}, text: '' };
  };
  const seenBundleUrls = new Set();
  const seenConfigUrls = new Set();
  const pageHtml = '<html><body><script src="/main.js"></script></body></html>';
  const r1 = await discoverApiRoutesFromPage('https://memo.example.com/', pageHtml, memoFetch, { seenBundleUrls, seenConfigUrls });
  const r2 = await discoverApiRoutesFromPage('https://memo.example.com/about', pageHtml, memoFetch, { seenBundleUrls, seenConfigUrls });
  const r3 = await discoverApiRoutesFromPage('https://memo.example.com/pricing', pageHtml, memoFetch, { seenBundleUrls, seenConfigUrls });
  assert.ok(r1.includes('/api/v1/items'));
  assert.deepEqual(r2, []);
  assert.deepEqual(r3, []);
  assert.equal(memoFetches.filter(u => u.endsWith('/main.js')).length, 1, 'Expected /main.js to be fetched exactly once');
  assert.equal(memoFetches.some(u => u.endsWith('/about') || u.endsWith('/pricing')), false, 'Expected passed HTML not to be re-fetched');
});

test('CANDIDATE-6: destructive route filters safely decode percent-escapes and reject malformed % encodings', () => {
  assert.equal(isDestructiveApiRoute('/api/%6cogout'), true);
  assert.equal(isDestructiveApiRoute('/api/u/%64elete'), true);
  assert.equal(isDestructiveApiRoute('/api/%256cogout'), true);
  assert.equal(isDestructiveApiRoute('/api/v1/user%2fdelete'), true);
  assert.equal(isDestructiveApiRoute('/api/%ZZlogout'), true);
  assert.equal(isDestructiveApiRoute('/api/100%'), true);
  assert.equal(isDestructiveApiRoute('/api/items/hello%20world'), false);

  assert.equal(isSafeReadOnlyApiRoute('/api/%6cogout'), false);
  assert.equal(isSafeReadOnlyApiRoute('/api/u/%64elete'), false);
  assert.equal(isSafeReadOnlyApiRoute('/api/%ZZ'), false);
  assert.equal(isSafeReadOnlyApiRoute('/api/config.%6a%73on'), false);
  assert.equal(isSafeReadOnlyApiRoute('/api/v1/catalog'), true);

  const filtered = filterSafeSameOriginApiRoutes(
    ['/api/%6cogout', '/api/u/%64elete', '/api/%ZZ', '/api/v1/products?access_token=SEC&page=1'],
    'https://shop.example.com'
  );
  assert.deepEqual(filtered, ['/api/v1/products?page=1']);
});
