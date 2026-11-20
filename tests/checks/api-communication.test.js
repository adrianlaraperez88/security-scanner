import { test } from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { mockFetchError } from '../helpers/mock-fetch.js';
import { createGovernedFetch } from '../../core/fetch.js';
import run, { meta, tags } from '../../checks/api-communication.js';

const BASE = 'https://app.example.com';

test('api-communication: exports expected tags and metadata', () => {
  for (const expectedTag of ['all', 'frontend', 'angular', 'react', 'vue', 'nextjs', 'api']) {
    assert.ok(tags.includes(expectedTag), `Missing tag ${expectedTag}`);
  }
  assert.equal(meta.id, 'api-communication');
  assert.equal(meta.category, 'API Security');
  assert.equal(meta.cwe, 'CWE-200');
  assert.equal(meta.owasp, 'A05:2021-Security Misconfiguration');
  assert.equal(meta.cvssScore, 5.3);
});

test('api-communication: SAFE with full apiCommunication inventory on clean Angular SPA with protected API routes', async () => {
  const fetch = async (url) => {
    if (url === BASE) {
      return {
        status: 200,
        headers: { 'content-type': 'text/html' },
        text: '<html><head><script src="/main-es2022.js"></script></head><body><app-root ng-version="18.2.0"></app-root></body></html>'
      };
    }
    if (url === `${BASE}/main-es2022.js`) {
      return {
        status: 200,
        headers: { 'content-type': 'application/javascript' },
        text: `
          import { HttpClient, provideHttpClient } from '@angular/common/http';
          const apiBase = 'https://api.example.com/v1';
          this.http.get('/api/v1/health');
          this.http.get('/api/v1/orders');
        `
      };
    }
    if (url === `${BASE}/api/v1/health`) {
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        text: '{"ok":true,"status":"UP"}'
      };
    }
    if (url === `${BASE}/api/v1/orders`) {
      return {
        status: 401,
        headers: { 'content-type': 'application/json' },
        text: '{"error":"Unauthorized"}'
      };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  };

  const r = await run(BASE, fetch);
  assert.equal(r.name, 'api communication');
  assert.equal(r.status, 'SAFE');
  assert.equal(r.severity, 'NONE');
  assert.ok(r.apiCommunication, 'Expected apiCommunication object on SAFE result');
  assert.equal(r.apiCommunication.usesApi, true);
  assert.ok(r.apiCommunication.sameOriginEndpoints.includes('/api/v1/health'));
  assert.ok(r.apiCommunication.sameOriginEndpoints.includes('/api/v1/orders'));
  assert.ok(r.apiCommunication.externalApiOrigins.some(o => o.includes('https://api.example.com')));
  assert.equal(typeof r.detail, 'string');
  assert.equal(typeof r.fix, 'string');
});

test('api-communication: SUSPICIOUS+MEDIUM on unauthenticated sensitive JSON user data exposure', async () => {
  const fetch = async (url) => {
    if (url === BASE) {
      return {
        status: 200,
        headers: { 'content-type': 'text/html' },
        text: '<html><body><script src="/bundle.js"></script></body></html>'
      };
    }
    if (url === `${BASE}/bundle.js`) {
      return {
        status: 200,
        headers: { 'content-type': 'application/javascript' },
        text: `fetch('/api/v1/users').then(r => r.json());`
      };
    }
    if (url === `${BASE}/api/v1/users`) {
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        text: JSON.stringify({
          users: [
            { id: 1, email: 'alice@example.com', roles: ['admin'] },
            { id: 2, email: 'bob@example.com', roles: ['editor'] }
          ]
        })
      };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  };

  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SUSPICIOUS');
  assert.equal(r.severity, 'MEDIUM');
  assert.ok(r.findings.some(f => f.endpoint === '/api/v1/users' && f.severity === 'MEDIUM'));
  assert.ok(r.evidenceQuotes.length > 0);
});

test('api-communication: VULNERABLE+HIGH on unauthenticated JSON API credential/token leak with redaction', async () => {
  const rawSecret = ['sk', 'live', '9876543210abcdef12345678'].join('_');
  const fetch = async (url) => {
    if (url === BASE) {
      return {
        status: 200,
        headers: { 'content-type': 'text/html' },
        text: '<html><body><script src="/app.js"></script></body></html>'
      };
    }
    if (url === `${BASE}/app.js`) {
      return {
        status: 200,
        headers: { 'content-type': 'application/javascript' },
        text: `axios.get('/api/internal/settings');`
      };
    }
    if (url === `${BASE}/api/internal/settings`) {
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        text: JSON.stringify({
          environment: 'production',
          apiKey: rawSecret,
          dbPassword: 'super_secret_db_password_123'
        })
      };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  };

  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'HIGH');
  assert.ok(r.findings.some(f => f.endpoint === '/api/internal/settings' && f.severity === 'HIGH'));
  assert.ok(!JSON.stringify(r).includes(rawSecret), 'Raw secret must be redacted from result');
  assert.ok(!JSON.stringify(r).includes('super_secret_db_password_123'), 'Raw password must be redacted');
});

test('api-communication: VULNERABLE+HIGH on plaintext http:// external API origin from https:// frontend', async () => {
  const fetch = async (url) => {
    if (url === BASE) {
      return {
        status: 200,
        headers: { 'content-type': 'text/html' },
        text: '<html><body><app-root ng-version="17.0.0"></app-root><script src="/main.js"></script></body></html>'
      };
    }
    if (url === `${BASE}/main.js`) {
      return {
        status: 200,
        headers: { 'content-type': 'application/javascript' },
        text: `
          const environment = { production: true, apiUrl: 'http://api.insecure-backend.example.com/v1' };
          httpClient.get(environment.apiUrl + '/items');
        `
      };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  };

  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'HIGH');
  assert.ok(r.findings.some(f => f.severity === 'HIGH' && /http/i.test(f.detail)));
});

test('api-communication: SUSPICIOUS+MEDIUM on localhost/dev API URL baked into production bundle', async () => {
  const fetch = async (url) => {
    if (url === BASE) {
      return {
        status: 200,
        headers: { 'content-type': 'text/html' },
        text: '<html><body><script src="/main.js"></script></body></html>'
      };
    }
    if (url === `${BASE}/main.js`) {
      return {
        status: 200,
        headers: { 'content-type': 'application/javascript' },
        text: `
          const apiBase = 'http://localhost:4200/api';
          fetch(apiBase + '/status');
        `
      };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  };

  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SUSPICIOUS');
  assert.equal(r.severity, 'MEDIUM');
  assert.ok(r.findings.some(f => f.severity === 'MEDIUM' && /localhost/i.test(f.detail + ' ' + (f.endpoint || ''))));
});

test('api-communication: skips state-changing endpoints (/logout, /signout, /delete) during active GET probing', async () => {
  const calledUrls = [];
  const fetch = async (url) => {
    calledUrls.push(url);
    if (url === BASE) {
      return {
        status: 200,
        headers: { 'content-type': 'text/html' },
        text: '<html><body><script src="/app.js"></script></body></html>'
      };
    }
    if (url === `${BASE}/app.js`) {
      return {
        status: 200,
        headers: { 'content-type': 'application/javascript' },
        text: `
          fetch('/api/v1/logout');
          fetch('/auth/signout');
          fetch('/api/v1/delete');
          fetch('/api/v1/status');
        `
      };
    }
    if (url === `${BASE}/api/v1/status`) {
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        text: '{"ok":true}'
      };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  };

  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SAFE');
  assert.ok(!calledUrls.includes(`${BASE}/api/v1/logout`), 'Must not probe /logout');
  assert.ok(!calledUrls.includes(`${BASE}/auth/signout`), 'Must not probe /signout');
  assert.ok(!calledUrls.includes(`${BASE}/api/v1/delete`), 'Must not probe /delete');
  assert.ok(calledUrls.includes(`${BASE}/api/v1/status`), 'Should probe safe read-only /status');
});

test('api-communication: VULNERABLE+HIGH on exposed runtime config (/assets/config.json) leaking API token', async () => {
  const rawToken = ['ghp', '1234567890abcdefghijklmnopqrstuv'].join('_');
  const fetch = async (url) => {
    if (url === BASE) {
      return {
        status: 200,
        headers: { 'content-type': 'text/html' },
        text: '<html><body><app-root ng-version="18.0.0"></app-root></body></html>'
      };
    }
    if (url === `${BASE}/assets/config.json`) {
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        text: JSON.stringify({
          apiUrl: 'https://api.example.com/v1',
          apiToken: rawToken
        })
      };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  };

  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'HIGH');
  assert.ok(r.apiCommunication.configFiles.some(c => c.path === '/assets/config.json'));
  assert.ok(!JSON.stringify(r).includes(rawToken), 'Raw token must be redacted');
});

test('api-communication: ERROR on unreachable target', async () => {
  const r = await run(BASE, mockFetchError('ECONNREFUSED'));
  assert.equal(r.name, 'api communication');
  assert.equal(r.status, 'ERROR');
  assert.equal(r.severity, 'LOW');
  assert.match(r.reason, /ECONNREFUSED/);
});

test('CANDIDATE-1 & CANDIDATE-9: checks/api-communication resists ReDoS on -eyJ.repeat(20480) (<200ms) and omits raw PII/jwt/bearer values from evidenceQuotes', async () => {
  const redosVal = '-eyJ'.repeat(20480);
  const fetch = async (url) => {
    if (url === BASE) {
      return {
        status: 200,
        headers: { 'content-type': 'text/html' },
        text: '<html><body><script src="/app.js"></script></body></html>'
      };
    }
    if (url === `${BASE}/app.js`) {
      return {
        status: 200,
        headers: { 'content-type': 'application/javascript' },
        text: `fetch('/api/profile'); fetch('/api/redos');`
      };
    }
    if (url === `${BASE}/api/profile`) {
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        text: JSON.stringify({
          jwt: 'opaque_jwt_value_999',
          bearer: 'opaque_bearer_888',
          email: 'pii.user@example.com'
        })
      };
    }
    if (url === `${BASE}/api/redos`) {
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        text: JSON.stringify({ blob: redosVal })
      };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  };

  const t0 = performance.now();
  const r = await run(BASE, fetch);
  const elapsedMs = performance.now() - t0;

  assert.ok(elapsedMs < 200, `Expected linear timing < 200ms, got ${elapsedMs.toFixed(1)}ms`);
  assert.equal(r.status, 'VULNERABLE');
  assert.ok(r.evidenceQuotes.length > 0);
  const serialized = JSON.stringify(r);
  assert.ok(!serialized.includes('opaque_jwt_value_999'), 'Raw jwt scalar must not leak in evidenceQuotes');
  assert.ok(!serialized.includes('opaque_bearer_888'), 'Raw bearer scalar must not leak in evidenceQuotes');
  assert.ok(!serialized.includes('pii.user@example.com'), 'Raw email PII must not leak in evidenceQuotes');
  assert.ok(r.evidenceQuotes.some(q => q.includes('/api/profile') && q.includes('jwt') && q.includes('email')));
});

test('CANDIDATE-3, CANDIDATE-4 & CANDIDATE-6: redacts endpoint query secrets, skips percent-encoded destructive routes, and blocks cross-origin 302 probes', async () => {
  const fetched = [];
  const governed = createGovernedFetch({
    dnsResolver: async () => ['93.184.216.34'],
    retries: 0,
    fetcher: async (url) => {
      fetched.push(url);
      if (url === BASE || url === `${BASE}/`) {
        return new Response('<html><body><script src="/app.js"></script></body></html>', {
          status: 200,
          headers: { 'content-type': 'text/html' }
        });
      }
      if (url === `${BASE}/app.js`) {
        return new Response(`
          fetch('/api/x?access_token=SECRET_XYZ&foo=bar');
          fetch('/api/y?sig=SECRET_SIG');
          fetch('/api/%6cogout');
          fetch('/api/u/%64elete');
          fetch('/api/thirdparty-leak');
        `, { status: 200, headers: { 'content-type': 'application/javascript' } });
      }
      if (url === `${BASE}/api/x?foo=bar`) {
        return new Response(JSON.stringify({ email: 'alice@example.com' }), {
          status: 200,
          headers: { 'content-type': 'application/json' }
        });
      }
      if (url === `${BASE}/api/y`) {
        return new Response(JSON.stringify({ users: [{ id: 1, name: 'Bob' }] }), {
          status: 200,
          headers: { 'content-type': 'application/json' }
        });
      }
      if (url === `${BASE}/api/thirdparty-leak`) {
        return new Response('', {
          status: 302,
          headers: { location: 'https://thirdparty.example/data.json' }
        });
      }
      if (url.startsWith('https://thirdparty.example/')) {
        return new Response(JSON.stringify({ api_key: ['sk', 'live', 'thirdparty', '999999999999'].join('_') }), {
          status: 200,
          headers: { 'content-type': 'application/json' }
        });
      }
      return new Response('Not Found', { status: 404 });
    }
  });

  const r = await run(BASE, governed);
  const serialized = JSON.stringify(r);
  assert.ok(!serialized.includes('SECRET_XYZ'), 'Raw access_token query secret must not leak');
  assert.ok(!serialized.includes('SECRET_SIG'), 'Raw sig query secret must not leak');
  assert.ok(!serialized.includes('thirdparty.example'), 'Cross-origin 302 target must never be reported');
  assert.ok(!fetched.some(u => u.includes('thirdparty.example')), 'Must never follow 302 to thirdparty.example');
  assert.ok(!fetched.some(u => u.includes('%6cogout') || u.includes('%64elete')), 'Must never probe percent-encoded destructive routes');
  assert.ok(r.findings.some(f => f.endpoint === '/api/x?access_token=<REDACTED>&foo=bar'));
  assert.ok(r.findings.some(f => f.endpoint === '/api/y?sig=<REDACTED>'));
});
