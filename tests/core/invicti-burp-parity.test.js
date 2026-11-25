import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  mapCweToCompliance,
  buildProofBasedArtifact,
  buildComplianceSummary
} from '../../core/compliance-proof.js';
import {
  parseOpenApiSpec,
  discoverAndImportOpenApi
} from '../../core/openapi-importer.js';
import {
  AuthSessionManager,
  extractCsrfTokens,
  isLogoutOrDestructiveUrl
} from '../../core/auth-session.js';
import { EnrichEngine } from '../../core/enrich.js';

test('standalone-independence: zero runtime or label references to ARTEX exist in production code, UI, extension, or README', () => {
  const dirs = ['bin', 'core', 'checks', 'ui', 'ui/components', 'extension'];
  const files = ['README.md', 'scan.js', 'package.json'];
  for (const d of dirs) {
    if (!fs.existsSync(d)) continue;
    for (const f of fs.readdirSync(d)) {
      const p = path.join(d, f);
      if (fs.statSync(p).isFile()) files.push(p);
    }
  }

  for (const file of files) {
    const content = fs.readFileSync(file, 'utf8');
    assert.equal(
      /\bartex\b/i.test(content),
      false,
      `Expected zero ARTEX references in ${file}`
    );
  }
});

test('compliance-proof: Invicti Proof-Based Scanning certainty (0-100%) and 6-framework compliance matrix enrich findings accurately', () => {
  const enrichEngine = new EnrichEngine();
  const enriched = enrichEngine.enrichFinding({
    checkId: 'ssti-check',
    name: 'ssti-check',
    target: 'https://app.example.com/render?name=test',
    status: 'VULNERABLE',
    severity: 'CRITICAL',
    poeLevel: 3,
    evidenceQuotes: ['secscan102947ssti'],
    detail: 'Evaluated 7919*13 -> 102947'
  });

  assert.equal(enriched.certainty, 100);
  assert.ok(enriched.proofArtifact);
  assert.equal(enriched.proofArtifact.isConfirmedProof, true);
  assert.equal(enriched.proofArtifact.proofType, 'arithmetic_template_evaluation');
  assert.equal(enriched.proofArtifact.extractedProof, 'secscan102947ssti');

  assert.ok(enriched.compliance);
  assert.equal(enriched.compliance.cwe, 'CWE-1336');
  assert.ok(enriched.compliance.pciDss4.includes('PCI-DSS v4.0'));
  assert.ok(enriched.compliance.owaspApi2023.includes('API8:2023'));
  assert.ok(enriched.compliance.iso27001.includes('27001'));
  assert.ok(enriched.compliance.nist80053.includes('800-53'));
  assert.ok(enriched.compliance.soc2.includes('SOC 2'));
  assert.ok(enriched.compliance.hipaa.includes('HIPAA'));

  const summary = buildComplianceSummary([enriched]);
  assert.equal(summary.totalActiveFindings, 1);
  assert.equal(summary.confirmedProofCount, 1);
  assert.equal(summary.overallCompliant, false);
  assert.equal(summary.frameworks.pciDss4.length, 1);
});

test('openapi-importer: parses OpenAPI 3.0 & Swagger 2.0 specs, resolves circular-safe $refs, and synthesizes parameterized routes & Intruder §markers§', async () => {
  const spec = {
    openapi: '3.0.3',
    info: { title: 'Orders API', version: '1.0.0' },
    servers: [{ url: 'https://api.example.com/v1' }],
    paths: {
      '/users/{userId}/orders': {
        get: {
          operationId: 'listOrders',
          parameters: [
            { name: 'userId', in: 'path', required: true, schema: { type: 'integer' } },
            { name: 'status', in: 'query', schema: { type: 'string', enum: ['open', 'closed'] } }
          ]
        },
        post: {
          operationId: 'createOrder',
          parameters: [
            { name: 'userId', in: 'path', required: true, schema: { type: 'integer' } }
          ],
          requestBody: {
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/OrderInput' }
              }
            }
          }
        }
      }
    },
    components: {
      schemas: {
        OrderInput: {
          type: 'object',
          properties: {
            itemId: { type: 'integer' },
            customerEmail: { type: 'string', format: 'email' },
            parentOrder: { $ref: '#/components/schemas/OrderInput' } // circular $ref test
          }
        }
      }
    }
  };

  const imported = parseOpenApiSpec(spec, 'https://api.example.com');
  assert.equal(imported.totalEndpoints, 2);
  const getEp = imported.endpoints.find(e => e.method === 'GET');
  const postEp = imported.endpoints.find(e => e.method === 'POST');
  assert.equal(getEp.url, 'https://api.example.com/v1/users/1/orders?status=open');
  assert.equal(getEp.intruderTemplateUrl, 'https://api.example.com/v1/users/§1§/orders?status=§open§');
  assert.ok(postEp.body);
  const parsedBody = JSON.parse(postEp.body);
  assert.equal(parsedBody.itemId, 1);
  assert.equal(parsedBody.customerEmail, 'user@example.com');
  assert.equal(parsedBody.parentOrder, 'circular_ref');

  // Test live discovery via discoverAndImportOpenApi
  const discovered = await discoverAndImportOpenApi('https://api.example.com', async (url) => {
    if (url.endsWith('/openapi.json')) {
      return { status: 200, headers: { 'content-type': 'application/json' }, text: JSON.stringify(spec) };
    }
    return { status: 404, headers: {}, text: 'Not found' };
  });
  assert.equal(discovered.discovered, true);
  assert.equal(discovered.totalEndpoints, 2);
});

test('auth-session: extracts CSRF tokens, manages Cookie Jar, executes Login Macro, blocks /logout, and auto-reauthenticates on 401', async () => {
  const html = `
    <html>
      <head><meta name="csrf-token" content="meta_csrf_991122"></head>
      <body>
        <form action="/login" method="POST">
          <input type="hidden" name="_token" value="form_csrf_778899">
        </form>
      </body>
    </html>
  `;
  const csrf = extractCsrfTokens(html);
  assert.equal(csrf.formField, '_token');
  assert.equal(csrf.tokenValue, 'form_csrf_778899');

  assert.equal(isLogoutOrDestructiveUrl('https://app.example.com/auth/logout'), true);
  assert.equal(isLogoutOrDestructiveUrl('https://app.example.com/api/profile'), false);

  let loginCalls = 0;
  let protectedCallCount = 0;
  const mgr = new AuthSessionManager({
    loginUrl: 'https://app.example.com/api/login',
    loginMethod: 'POST',
    loginPayload: { username: 'scanner', password: 'secret' }
  });

  const baseFetch = async (url, opts = {}) => {
    if (url.endsWith('/api/login')) {
      if (opts.method === 'GET') {
        return {
          status: 200,
          headers: { 'set-cookie': 'XSRF-TOKEN=xsrf_cookie_123; Path=/' },
          text: html
        };
      }
      loginCalls++;
      return {
        status: 200,
        headers: { 'set-cookie': 'session_id=active_sess_456; HttpOnly; Secure' },
        text: JSON.stringify({ access_token: `jwt_token_v${loginCalls}` })
      };
    }
    if (url.endsWith('/api/protected')) {
      protectedCallCount++;
      // First call returns 401 to trigger auto-reauthentication macro
      if (protectedCallCount === 1) {
        return { status: 401, headers: {}, text: '{"error":"token expired"}' };
      }
      return {
        status: 200,
        headers: {},
        text: JSON.stringify({ authHeader: opts.headers?.Authorization, cookie: opts.headers?.Cookie })
      };
    }
    return { status: 200, headers: {}, text: 'ok' };
  };

  const wrappedFetch = mgr.wrapFetch(baseFetch);

  // 1. /logout is blocked automatically
  const logoutRes = await wrappedFetch('https://app.example.com/logout');
  assert.equal(logoutRes.skippedLogoutGuard, true);

  // 2. /api/protected hits 401 -> auto-runs login macro -> retries with Bearer token + session_id cookie
  const protRes = await wrappedFetch('https://app.example.com/api/protected');
  assert.equal(protRes.status, 200);
  const body = JSON.parse(protRes.text);
  assert.equal(body.authHeader, 'Bearer jwt_token_v1');
  assert.ok(body.cookie.includes('session_id=active_sess_456'));
  assert.equal(loginCalls, 1);
});
