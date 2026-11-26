import { test } from 'node:test';
import assert from 'node:assert/strict';
import runYiiChecks from '../../checks/yii-checks.js';
import runCvePhpEcosystem from '../../checks/cve-php-ecosystem.js';
import { evaluateTechnologyVersion, extractRuntimeScaFromResponse } from '../../core/runtime-sca.js';
import { AuthSessionManager } from '../../core/auth-session.js';

const BASE = 'https://satprocess.com/broadbandAdmin/index.php/site/login';

test('yii-checks: returns SAFE when no Gii, Debug toolbar, stack traces, or logs are exposed', async () => {
  const fetch = async () => ({
    status: 200,
    headers: { 'content-type': 'text/html' },
    text: '<html><body><h1>Welcome</h1></body></html>'
  });
  const res = await runYiiChecks(BASE, fetch);
  assert.equal(res.status, 'SAFE');
  assert.equal(res.severity, 'NONE');
});

test('yii-checks: detects exposed Yii Gii Code Generator under subpath (/broadbandAdmin/index.php/gii)', async () => {
  const fetch = async (url) => {
    if (url === 'https://satprocess.com/broadbandAdmin/index.php/gii') {
      return {
        status: 200,
        headers: { 'content-type': 'text/html' },
        text: '<html><title>Yii Code Generator</title><body><h1>Welcome to Yii Code Generator</h1><ul><li>Model Generator</li><li>Controller Generator</li><li>CRUD Generator</li></ul></body></html>'
      };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  };
  const res = await runYiiChecks(BASE, fetch);
  assert.equal(res.status, 'VULNERABLE');
  assert.equal(res.severity, 'CRITICAL');
  assert.ok(res.detail.includes('Gii Code Generator'));
});

test('yii-checks: detects Yii 2 Debug Module headers (X-Debug-Tag / X-Debug-Link)', async () => {
  const fetch = async () => ({
    status: 200,
    headers: {
      'x-debug-tag': '67450a1b2c3d4',
      'x-debug-link': '/debug/default/view?tag=67450a1b2c3d4'
    },
    text: '<html><body>Yii2 App</body></html>'
  });
  const res = await runYiiChecks('https://yii2.example.com', fetch);
  assert.equal(res.status, 'VULNERABLE');
  assert.equal(res.severity, 'HIGH');
  assert.ok(res.detail.includes('X-Debug-Tag'));
});

test('yii-checks: detects Yii 1 YII_DEBUG CException stack traces and protected/runtime/application.log', async () => {
  const fetchStack = async () => ({
    status: 500,
    headers: { 'content-type': 'text/html' },
    text: '<html><body><h1>CDbException</h1><p>CDbConnection failed to open the DB connection.</p><h3>Stack Trace</h3><pre>#0 /var/www/framework/db/CDbConnection.php(399): CDbConnection->open()</pre></body></html>'
  });
  const resStack = await runYiiChecks(BASE, fetchStack);
  assert.equal(resStack.status, 'VULNERABLE');
  assert.equal(resStack.severity, 'HIGH');
  assert.ok(resStack.detail.includes('YII_DEBUG'));

  const fetchLog = async (url) => {
    if (url === 'https://satprocess.com/broadbandAdmin/protected/runtime/application.log') {
      return {
        status: 200,
        headers: { 'content-type': 'text/plain' },
        text: '2026/11/25 12:00:00 [error] [exception.CHttpException.404] exception \'CHttpException\' with message \'Unable to resolve the request.\' in /var/www/framework/web/CWebApplication.php:286\nStack trace:\n#0 /var/www/index.php(13): CApplication->run()'
      };
    }
    return { status: 200, headers: { 'content-type': 'text/html' }, text: '<html><body>OK</body></html>' };
  };
  const resLog = await runYiiChecks(BASE, fetchLog);
  assert.equal(resLog.status, 'VULNERABLE');
  assert.equal(resLog.severity, 'HIGH');
  assert.equal(resLog.path, '/protected/runtime/application.log');
});

test('Runtime SCA & cve-php-ecosystem: detects Yii 2 CVE-2024-58136 and Yii 1.1 EOL CVE-2021-3692', async () => {
  const yii2Eval = evaluateTechnologyVersion('yii2', '2.0.51');
  assert.ok(yii2Eval);
  assert.equal(yii2Eval.id, 'yii');
  assert.equal(yii2Eval.status, 'Out of date');
  assert.equal(yii2Eval.isVulnerable, true);
  assert.ok(yii2Eval.cveIds.includes('CVE-2024-58136'));
  assert.equal(yii2Eval.highestCvss, 9.8);

  const yii1Eval = evaluateTechnologyVersion('yii1', '1.1.28');
  assert.ok(yii1Eval);
  assert.equal(yii1Eval.isEol, true);
  assert.ok(yii1Eval.cveIds.includes('CVE-2021-3692'));

  const scaFromHeaders = extractRuntimeScaFromResponse({
    headers: { 'X-Powered-By': 'PHP/8.2.28, Yii Framework/2.0.49' },
    html: '<html></html>'
  });
  const yiiFinding = scaFromHeaders.findings.find(f => f.id === 'yii');
  assert.ok(yiiFinding);
  assert.ok(yiiFinding.cveIds.includes('CVE-2024-58136'));

  // cve-php-ecosystem composer.lock check for yiisoft/yii2
  const cveRes = await runCvePhpEcosystem('https://yii2.example.com', async (url) => {
    if (url.endsWith('/composer.lock')) {
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        text: JSON.stringify({
          packages: [{ name: 'yiisoft/yii2', version: '2.0.51' }]
        })
      };
    }
    return { status: 200, headers: {}, text: 'OK' };
  });
  assert.equal(cveRes.status, 'VULNERABLE');
  assert.equal(cveRes.severity, 'CRITICAL');
  assert.ok(cveRes.cveIds.includes('CVE-2024-58136'));
});

test('AuthSessionManager: Yii 1 LoginForm_username selector matches Yii 2 loginform-username input seamlessly', async () => {
  const mgr = new AuthSessionManager({
    targetUrl: 'https://yii2.example.com/index.php?r=site/login',
    loginSequence: {
      name: 'Yii Cross-Version Sequence',
      actions: [
        { type: 'navigate', url: 'https://yii2.example.com/index.php?r=site/login' },
        { type: 'change_input', selectorType: 'id', selector: 'LoginForm_username', value: 'admin' },
        { type: 'change_input', selectorType: 'id', selector: 'LoginForm_password', value: 'secret123', isSecret: true },
        { type: 'click_button', selectorType: 'name', selector: 'login-button' }
      ]
    }
  });

  let submittedBody = '';
  const mockFetch = async (url, opts = {}) => {
    if (opts.method === 'POST') {
      submittedBody = String(opts.body || '');
      return {
        status: 200,
        url: 'https://yii2.example.com/index.php?r=site/index',
        headers: {
          'set-cookie': 'PHPSESSID=newsession999; path=/; HttpOnly, _identity-frontend=authdata; path=/; HttpOnly'
        },
        text: '<html><body><a href="/index.php?r=site/logout">Logout (admin)</a></body></html>'
      };
    }
    return {
      status: 200,
      url: 'https://yii2.example.com/index.php?r=site/login',
      headers: {
        'set-cookie': 'PHPSESSID=prelogin111; path=/, _csrf-frontend=csrfcookie; path=/'
      },
      text: `
        <html>
          <head>
            <meta name="csrf-param" content="_csrf-frontend">
            <meta name="csrf-token" content="yii2Token987">
          </head>
          <body>
            <form id="login-form" action="/index.php?r=site/login" method="post">
              <input type="hidden" name="_csrf-frontend" value="yii2Token987">
              <input type="text" id="loginform-username" name="LoginForm[username]">
              <input type="password" id="loginform-password" name="LoginForm[password]">
              <button type="submit" name="login-button" value="1">Login</button>
            </form>
          </body>
        </html>
      `
    };
  };

  const outcome = await mgr.executeLoginSequence(mockFetch);
  assert.equal(outcome.authenticated, true);
  const params = new URLSearchParams(submittedBody);
  assert.equal(params.get('_csrf-frontend'), 'yii2Token987');
  assert.equal(params.get('LoginForm[username]'), 'admin');
  assert.equal(params.get('LoginForm[password]'), 'secret123');
});
