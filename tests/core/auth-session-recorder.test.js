import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';

import { AuthSessionManager, parseLoginFormHtml } from '../../core/auth-session.js';
import { createAppServer } from '../../core/server.js';
import { renderRecordedSessionPreview } from '../../ui/app.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '../..');

function dispatchRequest(server, pathname, { method = 'POST', body = undefined, headers = {} } = {}) {
  return new Promise((resolve) => {
    const rawBody = body === undefined
      ? ''
      : (typeof body === 'string' ? body : JSON.stringify(body));

    const chunks = rawBody ? [Buffer.from(rawBody, 'utf8')] : [];
    const req = Object.assign(Readable.from(chunks), {
      url: pathname,
      method,
      headers: {
        host: '127.0.0.1:4321',
        ...(body !== undefined ? { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(rawBody)) } : {}),
        ...Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]))
      }
    });

    const resHeaders = {};
    const bodyChunks = [];
    const res = {
      statusCode: 200,
      headersSent: false,
      setHeader(name, val) {
        resHeaders[name.toLowerCase()] = val;
      },
      getHeader(name) {
        return resHeaders[name.toLowerCase()];
      },
      writeHead(code, hdrs) {
        this.statusCode = code;
        this.headersSent = true;
        if (hdrs) {
          for (const [k, v] of Object.entries(hdrs)) {
            resHeaders[k.toLowerCase()] = v;
          }
        }
      },
      write(chunk) {
        if (chunk) bodyChunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), 'utf8'));
      },
      end(chunk) {
        if (chunk) bodyChunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), 'utf8'));
        this.headersSent = true;
        const text = Buffer.concat(bodyChunks).toString('utf8');
        let json = null;
        try {
          json = JSON.parse(text);
        } catch {}
        resolve({
          status: this.statusCode,
          headers: resHeaders,
          text,
          json
        });
      }
    };

    server.emit('request', req, res);
  });
}

describe('Authenticated Login & Session Recorder', () => {
  test('parseLoginFormHtml discovers form action, method, email/user_login & password/user_pass fields, hidden CSRF inputs, and rejects cross-origin/javascript actions', () => {
    const emailFormHtml = `
      <form action="/auth/signin" method="post">
        <input type="hidden" name="_token" value="csrf_abc_123">
        <input type="email" name="email" required>
        <input type="password" name="password" required>
        <button type="submit">Login</button>
      </form>
    `;
    const parsedEmail = parseLoginFormHtml(emailFormHtml, 'https://app.example.com/login');
    assert.equal(parsedEmail.hasPasswordInput, true);
    assert.equal(parsedEmail.method, 'POST');
    assert.equal(parsedEmail.actionUrl, 'https://app.example.com/auth/signin');
    assert.equal(parsedEmail.usernameField, 'email');
    assert.equal(parsedEmail.passwordField, 'password');
    assert.deepEqual(parsedEmail.hiddenFields, { _token: 'csrf_abc_123' });

    const wpFormHtml = `
      <form action="/wp-login.php" method="POST">
        <input type="hidden" name="wp_nonce" value="nonce_xyz">
        <input type="text" name="user_login">
        <input type="password" name="user_pass">
      </form>
    `;
    const parsedWp = parseLoginFormHtml(wpFormHtml, 'https://blog.example.com/login');
    assert.equal(parsedWp.hasPasswordInput, true);
    assert.equal(parsedWp.actionUrl, 'https://blog.example.com/wp-login.php');
    assert.equal(parsedWp.usernameField, 'user_login');
    assert.equal(parsedWp.passwordField, 'user_pass');
    assert.deepEqual(parsedWp.hiddenFields, { wp_nonce: 'nonce_xyz' });

    const crossOriginForm = `
      <form action="https://evil.attacker.invalid/steal" method="POST">
        <input type="text" name="username">
        <input type="password" name="password">
      </form>
    `;
    const parsedCrossOrigin = parseLoginFormHtml(crossOriginForm, 'https://app.example.com/login');
    assert.equal(parsedCrossOrigin.actionUrl, 'https://app.example.com/login');

    const jsActionForm = `
      <form action="javascript:alert(1)" method="POST">
        <input type="text" name="username">
        <input type="password" name="password">
      </form>
    `;
    const parsedJsWithBase = parseLoginFormHtml(jsActionForm, 'https://app.example.com/login');
    assert.equal(parsedJsWithBase.actionUrl, 'https://app.example.com/login');
    const parsedJsNoBase = parseLoginFormHtml(jsActionForm, '');
    assert.equal(parsedJsNoBase.actionUrl, '');
  });

  test('AuthSessionManager auto-discovers /login, logs in with username/password, redacts password in getRecordedSession(), and exports/restores via fromRecordedSession()', async () => {
    const requestedUrls = [];
    const mockFetch = async (url, opts = {}) => {
      requestedUrls.push({ url, method: opts.method || 'GET', body: opts.body || null });

      if (url === 'https://app.example.com/login' && (opts.method || 'GET') === 'GET') {
        return {
          status: 200,
          url: 'https://app.example.com/login',
          headers: {
            'set-cookie': 'XSRF-TOKEN=xsrf_init_001; Path=/'
          },
          text: `
            <html>
              <body>
                <form action="/login" method="POST">
                  <input type="hidden" name="_token" value="form_csrf_555">
                  <input type="email" name="email">
                  <input type="password" name="password">
                </form>
              </body>
            </html>
          `
        };
      }

      if (url === 'https://app.example.com/login' && opts.method === 'POST') {
        assert.match(String(opts.body || ''), /email=admin%40example\.com/);
        assert.match(String(opts.body || ''), /password=SuperSecretPass%21/);
        assert.match(String(opts.body || ''), /_token=form_csrf_555/);
        return {
          status: 200,
          headers: {
            'set-cookie': 'session_id=sess_live_999; HttpOnly; Path=/'
          },
          text: JSON.stringify({ access_token: 'jwt_header.jwt_payload.jwt_sig' })
        };
      }

      return { status: 404, headers: {}, text: 'Not Found' };
    };

    const mgr = new AuthSessionManager({
      targetUrl: 'https://app.example.com',
      username: 'admin@example.com',
      password: 'SuperSecretPass!'
    });

    const outcome = await mgr.executeLoginMacro(mockFetch);
    assert.equal(outcome.authenticated, true);
    assert.equal(outcome.loginUrl, 'https://app.example.com/login');
    assert.ok(requestedUrls.some(r => r.url === 'https://app.example.com/login' && r.method === 'POST'));

    const summary = mgr.getRecordedSession();
    assert.equal(summary.authenticated, true);
    assert.equal(summary.username, 'admin@example.com');
    assert.equal(summary.password, '[REDACTED]');
    assert.equal(summary.cookies.session_id, '[CAPTURED]');
    assert.equal(summary.hasBearerToken, true);
    assert.ok(Array.isArray(summary.steps) && summary.steps.length >= 2);
    assert.equal(summary.steps[0].action, 'preflight_get');
    assert.equal(summary.steps[1].action, 'submit_credentials');

    const exported = mgr.exportRecordedSession();
    assert.equal(exported.cookies.session_id, 'sess_live_999');
    assert.equal(exported.bearerToken, 'jwt_header.jwt_payload.jwt_sig');
    assert.equal(exported.password, '[REDACTED]');

    const restored = AuthSessionManager.fromRecordedSession(exported);
    const restoredHeaders = restored.getAuthHeaders();
    assert.match(restoredHeaders.Cookie, /session_id=sess_live_999/);
    assert.equal(restoredHeaders.Authorization, 'Bearer jwt_header.jwt_payload.jwt_sig');
    assert.equal(restored.getRecordedSession().authenticated, true);
    assert.equal(restored.getRecordedSession().steps.length, summary.steps.length);
  });

  test('server.js POST /api/auth/record-session, GET /api/auth/sessions, and DELETE /api/auth/sessions/:id record, list redacted, delete, and block SSRF targets', async () => {
    const fetcher = async (url, opts = {}) => {
      if (url === 'https://portal.example.com/login' && (opts.method || 'GET') === 'GET') {
        return {
          status: 200,
          url: 'https://portal.example.com/login',
          headers: { 'set-cookie': 'csrf_cookie=tok123; Path=/' },
          text: '<form action="/login" method="POST"><input type="text" name="username"><input type="password" name="password"></form>'
        };
      }
      if (url === 'https://portal.example.com/login' && opts.method === 'POST') {
        return {
          status: 200,
          headers: { 'set-cookie': 'auth_sid=real_secret_sid_value; HttpOnly; Path=/' },
          text: JSON.stringify({ access_token: 'eyJhbGciOiJIUzI1NiJ9.payload.sig' })
        };
      }
      return { status: 404, headers: {}, text: 'Not found' };
    };

    const server = createAppServer({
      inMemory: true,
      fetcher
    });

    try {
      // 1. Record session via POST /api/auth/record-session
      const recRes = await dispatchRequest(server, '/api/auth/record-session', {
        method: 'POST',
        body: {
          targetUrl: 'https://portal.example.com',
          username: 'qa_admin',
          password: 'TopSecretPassword123!'
        }
      });
      assert.equal(recRes.status, 200);
      assert.equal(recRes.json?.authenticated, true);
      assert.ok(recRes.json?.sessionId);
      assert.equal(recRes.json?.password, '[REDACTED]');
      assert.equal(recRes.json?.cookies?.auth_sid, '[CAPTURED]');
      assert.equal(recRes.json?.bearerToken, undefined);

      const sessionId = recRes.json.sessionId;

      // 2. List recorded sessions with redacted secrets
      const listRes = await dispatchRequest(server, '/api/auth/sessions', { method: 'GET' });
      assert.equal(listRes.status, 200);
      assert.ok(Array.isArray(listRes.json?.sessions));
      const found = listRes.json.sessions.find(s => s.sessionId === sessionId);
      assert.ok(found);
      assert.equal(found.password, '[REDACTED]');
      assert.equal(found.cookies.auth_sid, '[CAPTURED]');
      assert.equal(found.bearerToken, undefined);

      // 3. Delete session
      const delRes = await dispatchRequest(server, `/api/auth/sessions/${encodeURIComponent(sessionId)}`, {
        method: 'DELETE'
      });
      assert.equal(delRes.status, 200);
      assert.equal(delRes.json?.deleted, true);
      assert.equal(delRes.json?.sessionId, sessionId);

      // 4. Verify deleted
      const listAfter = await dispatchRequest(server, '/api/auth/sessions', { method: 'GET' });
      assert.equal(listAfter.status, 200);
      assert.equal(listAfter.json.sessions.some(s => s.sessionId === sessionId), false);

      // 5. Block SSRF targets (169.254.169.254 and .gov)
      const metaRes = await dispatchRequest(server, '/api/auth/record-session', {
        method: 'POST',
        body: {
          targetUrl: 'http://169.254.169.254/latest/meta-data/',
          username: 'admin',
          password: 'pw'
        }
      });
      assert.ok(metaRes.status === 400 || metaRes.status === 403, `Expected 400/403 for 169.254.169.254, got ${metaRes.status}`);

      const govRes = await dispatchRequest(server, '/api/auth/record-session', {
        method: 'POST',
        body: {
          targetUrl: 'https://agency.gov/login',
          username: 'admin',
          password: 'pw'
        }
      });
      assert.ok(govRes.status === 400 || govRes.status === 403, `Expected 400/403 for .gov target, got ${govRes.status}`);
    } finally {
      server.emit('close');
    }
  });

  test('ui/index.html and ui/app.js expose Authenticated Login & Session Recorder controls and renderRecordedSessionPreview neutralizes XSS', () => {
    const html = fs.readFileSync(path.join(REPO_ROOT, 'ui', 'index.html'), 'utf8');
    const appJs = fs.readFileSync(path.join(REPO_ROOT, 'ui', 'app.js'), 'utf8');

    assert.match(html, /id="adv-auth-username"/);
    assert.match(html, /id="adv-auth-password"/);
    assert.match(html, /id="adv-auth-login-url"/);
    assert.match(html, /id="adv-auth-type"/);
    assert.match(html, /id="btn-test-record-login"/);
    assert.match(html, /id="btn-discover-openapi"/);
    assert.match(html, /id="recorded-session-banner"/);

    assert.match(appJs, /\/api\/auth\/record-session/);
    assert.match(appJs, /\/api\/openapi\/import/);
    assert.match(appJs, /renderRecordedSessionPreview/);
    assert.match(appJs, /'auth_session'/);

    const elements = {
      'recorded-session-banner': {
        classList: {
          removed: [],
          remove(cls) { this.removed.push(cls); }
        },
        scrollIntoView() {}
      },
      'recorded-session-status-badge': { textContent: '' },
      'recorded-session-cookies-badge': { textContent: '' },
      'recorded-session-body': { innerHTML: '' }
    };

    const prevDocument = globalThis.document;
    globalThis.document = {
      getElementById(id) {
        return elements[id] || null;
      }
    };

    try {
      renderRecordedSessionPreview({
        sessionId: 'sess-12345678-abcd',
        authenticated: true,
        loginUrl: 'https://example.com/login?next=<script>alert(1)</script>',
        username: 'admin"<img src=x onerror=alert(2)>',
        cookieCount: 2,
        cookieNames: ['session_id', 'XSRF-TOKEN<script>'],
        csrfHeaderName: 'X-XSRF-TOKEN',
        hasBearerToken: true,
        bearerTokenPreview: 'eyJhbGciOiJI...',
        steps: [
          {
            step: 1,
            action: 'preflight_get',
            url: 'https://example.com/login',
            status: 200,
            csrfDetected: true,
            cookiesHarvested: ['XSRF-TOKEN']
          },
          {
            step: 2,
            action: 'submit_credentials',
            url: 'https://example.com/login',
            status: 200,
            contentType: 'form',
            tokenExtracted: true,
            cookiesHarvested: ['session_id']
          }
        ]
      });

      assert.ok(elements['recorded-session-banner'].classList.removed.includes('hidden'));
      assert.match(elements['recorded-session-status-badge'].textContent, /Authenticated \(Session sess-123\)/);
      assert.match(elements['recorded-session-cookies-badge'].textContent, /2 Cookie\(s\) · JWT: Captured/);

      const renderedBody = elements['recorded-session-body'].innerHTML;
      assert.equal(renderedBody.includes('<script>alert(1)</script>'), false);
      assert.equal(renderedBody.includes('<img src=x onerror=alert(2)>'), false);
      assert.match(renderedBody, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
      assert.match(renderedBody, /&lt;img src=x onerror=alert\(2\)&gt;/);
      assert.match(renderedBody, /preflight_get/);
      assert.match(renderedBody, /submit_credentials/);
    } finally {
      globalThis.document = prevDocument;
    }
  });
});
