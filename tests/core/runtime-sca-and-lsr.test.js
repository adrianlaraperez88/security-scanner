import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import {
  RUNTIME_SCA_CATALOG,
  parseSemver,
  compareSemver,
  evaluateTechnologyVersion,
  extractRuntimeScaFromResponse,
  detectRuntimeScaFindings,
  sanitizeRuntimeSca
} from '../../core/runtime-sca.js';
import runRuntimeScaCheck from '../../checks/runtime-sca.js';
import {
  MAX_SEQUENCE_STEPS,
  decodeBase32,
  generateTotpCode,
  inspectLoginPageDom,
  extractLoginErrorFromResponse,
  normalizeSystemVariables,
  exportSystemVariables,
  normalizeLoginSequence,
  parseLsrSequence,
  exportLsrSequence,
  AuthSessionManager
} from '../../core/auth-session.js';
import {
  renderRuntimeScaTable,
  renderTechDetectScaPreview
} from '../../ui/app.js';
import { withAppHarness } from '../../e2e/helpers/app-server-harness.mjs';
import { withTempDir, REPO_ROOT } from '../../e2e/helpers/cli-runner.mjs';
import { withMockTarget } from '../../e2e/helpers/mock-target-server.mjs';

const ALL_JEV_TRUE = {
  q1_in_scope: true,
  q2_authorized: true,
  q3_non_destructive: true,
  q4_rate_bounded: true,
  q5_no_exfiltration: true,
  q6_evidence_only: true,
  q7_rollback_safe: true,
  q8_least_privilege: true
};

// RFC 6238 Appendix B test vector seeds in Base32
const RFC6238_SHA1_BASE32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; // "12345678901234567890"
const RFC6238_SHA256_BASE32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA'; // 32 bytes
const RFC6238_SHA512_BASE32 =
  'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA'; // 64 bytes

describe('Runtime SCA Dependency Engine & Visual Multi-Step Login Sequence Recorder (.lsr + TOTP MFA)', () => {
  describe('1. Runtime SCA Findings Engine & Check Module', () => {
    test('1.1 Branch-aware version evaluation matches all 6 Invicti reference technologies', () => {
      // 1) Moment.js 2.9.0 - 2.23.0 -> Out of date, CVSS 7.5, Latest Branch N/A, Overall Latest 2.31.0 (CVSS 0.0)
      const momentRow = evaluateTechnologyVersion('Moment.js', ['2.9.0', '2.23.0']);
      assert.ok(momentRow);
      assert.equal(momentRow.name, 'Moment.js');
      assert.equal(momentRow.status, 'Out of date');
      assert.equal(momentRow.isOutOfDate, true);
      assert.equal(momentRow.identifiedVersion, '2.9.0 - 2.23.0');
      assert.equal(momentRow.highestCvss, 7.5);
      assert.equal(momentRow.identifiedVersionDisplay, '2.9.0 - 2.23.0 (Highest CVSS: 7.5)');
      assert.equal(momentRow.latestBranchVersion, 'N/A');
      assert.equal(momentRow.latestBranchDisplay, 'N/A');
      assert.equal(momentRow.overallLatestVersion, '2.31.0');
      assert.equal(momentRow.overallLatestCvss, 0.0);
      assert.equal(momentRow.overallLatestDisplay, '2.31.0 (Highest CVSS: 0.0)');
      assert.match(momentRow.recommendedAction, /Recommend updating to version 2\.31\.0/);

      // 2) Lodash 4.18.1 -> Up to date, CVSS 0.0, Latest Branch N/A, Overall Latest 4.18.1 (CVSS 0.0)
      const lodashRow = evaluateTechnologyVersion('Lodash', '4.18.1');
      assert.ok(lodashRow);
      assert.equal(lodashRow.name, 'Lodash');
      assert.equal(lodashRow.status, 'Up to date');
      assert.equal(lodashRow.isOutOfDate, false);
      assert.equal(lodashRow.identifiedVersion, '4.18.1');
      assert.equal(lodashRow.highestCvss, 0.0);
      assert.equal(lodashRow.identifiedVersionDisplay, '4.18.1 (Highest CVSS: 0.0)');
      assert.equal(lodashRow.latestBranchVersion, 'N/A');
      assert.equal(lodashRow.overallLatestVersion, '4.18.1');
      assert.equal(lodashRow.overallLatestCvss, 0.0);
      assert.equal(lodashRow.recommendedAction, '');

      // 3) jQuery 1.3.2 - 3.7.1 -> Out of date, CVSS 6.1, Latest Branch 3.7.1 (CVSS 0.0), Overall Latest 4.0.0 (CVSS 0.0)
      const jqueryRow = evaluateTechnologyVersion('jQuery', '1.3.2 - 3.7.1');
      assert.ok(jqueryRow);
      assert.equal(jqueryRow.name, 'jQuery');
      assert.equal(jqueryRow.status, 'Out of date');
      assert.equal(jqueryRow.identifiedVersion, '1.3.2 - 3.7.1');
      assert.equal(jqueryRow.highestCvss, 6.1);
      assert.equal(jqueryRow.identifiedVersionDisplay, '1.3.2 - 3.7.1 (Highest CVSS: 6.1)');
      assert.equal(jqueryRow.latestBranchVersion, '3.7.1');
      assert.equal(jqueryRow.latestBranchCvss, 0.0);
      assert.equal(jqueryRow.latestBranchDisplay, '3.7.1 (Highest CVSS: 0.0)');
      assert.equal(jqueryRow.overallLatestVersion, '4.0.0');
      assert.equal(jqueryRow.overallLatestCvss, 0.0);
      assert.equal(jqueryRow.overallLatestDisplay, '4.0.0 (Highest CVSS: 0.0)');
      assert.match(jqueryRow.recommendedAction, /Recommend updating to version 4\.0\.0/);

      // 4) Bootstrap 3.3.2 - 4.5.2 -> Out of date, CVSS 6.1, Latest Branch 4.6.2 (CVSS 0.0), Overall Latest 5.3.9 (CVSS 0.0)
      const bootstrapRow = evaluateTechnologyVersion('Bootstrap', ['3.3.2', '4.5.2']);
      assert.ok(bootstrapRow);
      assert.equal(bootstrapRow.name, 'Bootstrap');
      assert.equal(bootstrapRow.status, 'Out of date');
      assert.equal(bootstrapRow.identifiedVersion, '3.3.2 - 4.5.2');
      assert.equal(bootstrapRow.highestCvss, 6.1);
      assert.equal(bootstrapRow.latestBranchVersion, '4.6.2');
      assert.equal(bootstrapRow.latestBranchCvss, 0.0);
      assert.equal(bootstrapRow.latestBranchDisplay, '4.6.2 (Highest CVSS: 0.0)');
      assert.equal(bootstrapRow.overallLatestVersion, '5.3.9');
      assert.equal(bootstrapRow.overallLatestCvss, 0.0);
      assert.equal(bootstrapRow.overallLatestDisplay, '5.3.9 (Highest CVSS: 0.0)');
      assert.match(bootstrapRow.recommendedAction, /Recommend updating to version 5\.3\.9/);

      // 5) AngularJS 1.6.6 - 1.8.2 -> Out of date / EOL, CVSS 7.5, Latest Branch 1.8.3 (CVSS 7.5), Overall Latest 1.8.3 (CVSS 7.5)
      const angularJsRow = evaluateTechnologyVersion('AngularJS', '1.6.6 - 1.8.2');
      assert.ok(angularJsRow);
      assert.equal(angularJsRow.name, 'AngularJS');
      assert.equal(angularJsRow.status, 'Out of date');
      assert.equal(angularJsRow.isEol, true);
      assert.equal(angularJsRow.identifiedVersion, '1.6.6 - 1.8.2');
      assert.equal(angularJsRow.highestCvss, 7.5);
      assert.equal(angularJsRow.latestBranchVersion, '1.8.3');
      assert.equal(angularJsRow.latestBranchCvss, 7.5);
      assert.equal(angularJsRow.latestBranchDisplay, '1.8.3 (Highest CVSS: 7.5)');
      assert.equal(angularJsRow.overallLatestVersion, '1.8.3');
      assert.equal(angularJsRow.overallLatestCvss, 7.5);
      assert.equal(angularJsRow.overallLatestDisplay, '1.8.3 (Highest CVSS: 7.5)');
      assert.match(angularJsRow.recommendedAction, /End-of-Life.*Migrate to modern Angular/i);

      // 6) Angular 20.3.26 - 20.3.34 -> Out of date, CVSS 6.1, Latest Branch 20.3.35 (CVSS 0.0), Overall Latest 22.2.6 (CVSS 0.0)
      const angularRow = evaluateTechnologyVersion('Angular', ['20.3.26', '20.3.34']);
      assert.ok(angularRow);
      assert.equal(angularRow.name, 'Angular');
      assert.equal(angularRow.status, 'Out of date');
      assert.equal(angularRow.identifiedVersion, '20.3.26 - 20.3.34');
      assert.equal(angularRow.highestCvss, 6.1);
      assert.equal(angularRow.latestBranchVersion, '20.3.35');
      assert.equal(angularRow.latestBranchCvss, 0.0);
      assert.equal(angularRow.latestBranchDisplay, '20.3.35 (Highest CVSS: 0.0)');
      assert.equal(angularRow.overallLatestVersion, '22.2.6');
      assert.equal(angularRow.overallLatestCvss, 0.0);
      assert.equal(angularRow.overallLatestDisplay, '22.2.6 (Highest CVSS: 0.0)');
      assert.match(angularRow.recommendedAction, /Recommend updating to version 22\.2\.6/);
    });

    test('1.2 parseSemver, extractRuntimeScaFromResponse & detectRuntimeScaFindings parse HTML/bundles/headers and reject cache-busters', async () => {
      // Reject timestamps, year-based cache-busters, IPv4 addresses, and hex hashes
      assert.equal(parseSemver('20261125'), null);
      assert.equal(parseSemver('2026.11.25'), null);
      assert.equal(parseSemver('192.168.1.1'), null);
      assert.equal(parseSemver('a8f9c0d1e2'), null);
      assert.equal(compareSemver('3.4.1', '3.7.1'), -1);
      assert.equal(compareSemver('4.18.1', '4.18.1'), 0);

      const sampleHtml = `
        <!doctype html>
        <html ng-version="20.3.26">
          <head>
            <meta name="generator" content="WordPress 6.5.2" />
            <link rel="stylesheet" href="/assets/bootstrap-4.5.2.min.css" />
            <script src="/static/jquery-1.3.2.min.js"></script>
            <script src="/static/jquery-3.7.1.min.js"></script>
            <script src="/static/app.bundle.js?v=2026.11.25"></script>
            <script src="/static/vendor.js"></script>
            <script src="https://evil.example.com/cross-origin-bundle.js"></script>
          </head>
          <body data-sca-versions="moment.js:2.9.0-2.23.0;angularjs:1.6.6-1.8.2">
            <h1>Portal</h1>
          </body>
        </html>
      `;

      const bundle1 = `
        /*! Bootstrap v3.3.2 (https://getbootstrap.com/) */
        /*! Lodash v4.18.1 */
        /** @license Angular v20.3.34 */
      `;

      const extracted = extractRuntimeScaFromResponse({
        html: sampleHtml,
        headers: {
          Server: 'nginx/1.24.0',
          'X-Powered-By': 'PHP/8.1.20'
        },
        pageUrl: '/',
        bundleTexts: [{ url: '/static/vendor.js', text: bundle1 }]
      });

      assert.ok(extracted.totalIdentified >= 8);
      const byId = Object.fromEntries(extracted.findings.map(f => [f.id, f]));
      assert.equal(byId['moment.js'].identifiedVersion, '2.9.0 - 2.23.0');
      assert.equal(byId['lodash'].status, 'Up to date');
      assert.equal(byId['jquery'].identifiedVersion, '1.3.2 - 3.7.1');
      assert.equal(byId['bootstrap'].identifiedVersion, '3.3.2 - 4.5.2');
      assert.equal(byId['angularjs'].identifiedVersion, '1.6.6 - 1.8.2');
      assert.equal(byId['angular'].identifiedVersion, '20.3.26 - 20.3.34');
      assert.equal(byId['nginx'].status, 'Out of date');
      assert.equal(byId['php'].highestCvss, 9.8);

      // Test detectRuntimeScaFindings same-origin bundle probing & cross-origin rejection
      const fetchedUrls = [];
      const mockFetch = async (url) => {
        fetchedUrls.push(url);
        if (url === 'https://portal.example.com/') {
          return {
            status: 200,
            url: 'https://portal.example.com/',
            headers: { 'content-type': 'text/html' },
            text: sampleHtml
          };
        }
        if (url.includes('/static/vendor.js')) {
          return {
            status: 200,
            url,
            headers: { 'content-type': 'application/javascript' },
            text: bundle1
          };
        }
        return {
          status: 200,
          url,
          headers: { 'content-type': 'application/javascript' },
          text: '// empty bundle'
        };
      };

      const detected = await detectRuntimeScaFindings('https://portal.example.com/', mockFetch, {
        maxBundles: 4
      });
      assert.equal(
        fetchedUrls.some(u => u.includes('evil.example.com')),
        false,
        'Cross-origin script URLs must never be fetched by detectRuntimeScaFindings'
      );
      assert.ok(detected.findings.some(f => f.id === 'lodash' && f.status === 'Up to date'));
      assert.ok(detected.findings.some(f => f.id === 'angular' && f.identifiedVersion === '20.3.26 - 20.3.34'));

      const sanitized = sanitizeRuntimeSca(detected);
      assert.ok(sanitized && Array.isArray(sanitized.findings));
    });

    test('1.3 checks/runtime-sca.js transitions accurately across VULNERABLE, SUSPICIOUS, and SAFE', async () => {
      // 1) VULNERABLE when an outdated dependency has CVEs / CVSS >= 4.0
      const vulnRes = await runRuntimeScaCheck(
        'https://target.example.com',
        async () => ({ status: 200, headers: {}, text: '' }),
        {
          rootResponse: {
            status: 200,
            url: 'https://target.example.com/',
            headers: {},
            text: '<script src="/jquery-3.4.1.min.js"></script><script src="/lodash-4.18.1.min.js"></script>'
          },
          maxBundles: 0
        }
      );
      assert.equal(vulnRes.status, 'VULNERABLE');
      assert.equal(vulnRes.severity, 'MEDIUM');
      assert.equal(vulnRes.cvssScore, 6.1);
      assert.ok(vulnRes.cveIds.includes('CVE-2020-11022'));
      assert.equal(vulnRes.runtimeSca.totalIdentified, 2);

      // 2) SUSPICIOUS when a dependency is outdated relative to overallLatestVersion but has 0.0 CVSS
      const suspRes = await runRuntimeScaCheck(
        'https://target.example.com',
        async () => ({ status: 200, headers: {}, text: '' }),
        {
          rootResponse: {
            status: 200,
            url: 'https://target.example.com/',
            headers: {},
            text: '<script src="/jquery-3.7.1.min.js"></script>'
          },
          maxBundles: 0
        }
      );
      assert.equal(suspRes.status, 'SUSPICIOUS');
      assert.equal(suspRes.severity, 'LOW');
      assert.equal(suspRes.cvssScore, 0);

      // 3) SAFE when all detected dependencies are up to date
      const safeRes = await runRuntimeScaCheck(
        'https://target.example.com',
        async () => ({ status: 200, headers: {}, text: '' }),
        {
          rootResponse: {
            status: 200,
            url: 'https://target.example.com/',
            headers: {},
            text: '<script src="/lodash-4.18.1.min.js"></script><script src="/jquery-4.0.0.min.js"></script>'
          },
          maxBundles: 0
        }
      );
      assert.equal(safeRes.status, 'SAFE');
      assert.equal(safeRes.severity, 'NONE');
      assert.equal(safeRes.runtimeSca.upToDateCount, 2);
      assert.equal(safeRes.runtimeSca.outOfDateCount, 0);
    });
  });

  describe('2. Login Sequence Recorder (.lsr), RFC 6238 TOTP MFA, Secrets Vault, Restrictions & Session Detection', () => {
    test('2.1 generateTotpCode matches RFC 6238 Appendix B test vectors (SHA1, SHA256, SHA512, 6 & 8 digits) and rejects invalid Base32', () => {
      // T = 59s (timestamp = 59000 ms)
      const sha1_8 = generateTotpCode(RFC6238_SHA1_BASE32, {
        digits: 8,
        period: 30,
        algorithm: 'SHA1',
        timestamp: 59_000
      });
      assert.equal(sha1_8.code, '94287082');
      assert.equal(sha1_8.digits, 8);
      assert.equal(sha1_8.algorithm, 'SHA1');
      assert.equal(sha1_8.counter, 1);
      assert.equal(sha1_8.remainingSeconds, 1);

      const sha1_6 = generateTotpCode(RFC6238_SHA1_BASE32, {
        digits: 6,
        period: 30,
        algorithm: 'SHA1',
        timestamp: 59_000
      });
      assert.equal(sha1_6.code, '287082');

      // T = 1111111109s
      const sha1_t2 = generateTotpCode(RFC6238_SHA1_BASE32, {
        digits: 8,
        period: 30,
        algorithm: 'SHA1',
        timestamp: 1_111_111_109_000
      });
      assert.equal(sha1_t2.code, '07081804');

      // SHA256 at T = 59s
      const sha256_8 = generateTotpCode(RFC6238_SHA256_BASE32, {
        digits: 8,
        period: 30,
        algorithm: 'SHA256',
        timestamp: 59_000
      });
      assert.equal(sha256_8.code, '46119246');

      const sha256_6 = generateTotpCode(RFC6238_SHA256_BASE32, {
        digits: 6,
        period: 30,
        algorithm: 'SHA-256',
        timestamp: 59_000
      });
      assert.equal(sha256_6.code, '119246');

      // SHA512 at T = 59s
      const sha512_8 = generateTotpCode(RFC6238_SHA512_BASE32, {
        digits: 8,
        period: 30,
        algorithm: 'SHA512',
        timestamp: 59_000
      });
      assert.equal(sha512_8.code, '90693936');

      const sha512_6 = generateTotpCode(RFC6238_SHA512_BASE32, {
        digits: 6,
        period: 30,
        algorithm: 'SHA-512',
        timestamp: 59_000
      });
      assert.equal(sha512_6.code, '693936');

      // Invalid Base32 & invalid parameter rejections
      assert.throws(() => decodeBase32(''), /Base32 secret is empty/);
      assert.throws(() => decodeBase32('INVALID_890!'), /Invalid Base32 character/);
      assert.throws(() => generateTotpCode(RFC6238_SHA1_BASE32, { digits: 7 }), /Invalid TOTP digits/);
      assert.throws(() => generateTotpCode(RFC6238_SHA1_BASE32, { period: 5 }), /Invalid TOTP period/);
      assert.throws(() => generateTotpCode(RFC6238_SHA1_BASE32, { algorithm: 'MD5' }), /Unsupported TOTP algorithm/);
    });

    test('2.2 inspectLoginPageDom extracts forms, password inputs, OTP candidates, buttons, and CSRF tokens while stripping scripts', () => {
      const loginHtml = `
        <!doctype html>
        <html>
          <head>
            <title>Corporate SSO &amp; MFA Portal</title>
            <meta name="csrf-token" content="meta_csrf_998877" />
            <script>
              const fake = '<form action="/evil"><input id="evil_script_input" type="password"></form>';
            </script>
            <style>.hidden { display: none; }</style>
          </head>
          <body>
            <!-- <input id="commented_out_input" name="commented" /> -->
            <form id="sso-form" action="/auth/step1" method="POST">
              <input type="hidden" name="_token" value="form_csrf_112233" />
              <label for="login_email">Corporate Email</label>
              <input id="login_email" name="email" type="email" placeholder="user@corp.example" />
              <label for="login_pwd">Password</label>
              <input id="login_pwd" name="password" type="password" />
              <label for="totp_code">2FA Verification Code</label>
              <input id="totp_code" name="otp_code" type="text" autocomplete="one-time-code" placeholder="6-digit OTP" />
              <button id="btn_signin" type="submit">Sign In</button>
            </form>
          </body>
        </html>
      `;

      const dom = inspectLoginPageDom(loginHtml, 'https://sso.example.com/login');
      assert.equal(dom.title, 'Corporate SSO & MFA Portal');
      assert.equal(dom.hasPasswordInput, true);
      assert.equal(dom.hasMfaOrOtpField, true);
      assert.equal(dom.csrf.formField, '_token');
      assert.equal(dom.csrf.tokenValue, 'form_csrf_112233');
      assert.equal(dom.forms.length, 1);
      assert.equal(dom.forms[0].actionUrl, 'https://sso.example.com/auth/step1');
      assert.equal(dom.forms[0].hiddenFields._token, 'form_csrf_112233');

      // Ensure <script> and <!-- comment --> inputs were stripped
      assert.equal(dom.inputs.some(i => i.id === 'evil_script_input' || i.id === 'commented_out_input'), false);

      const emailInp = dom.inputs.find(i => i.id === 'login_email');
      assert.ok(emailInp);
      assert.equal(emailInp.label, 'Corporate Email');

      const pwdInp = dom.inputs.find(i => i.id === 'login_pwd');
      assert.ok(pwdInp);
      assert.equal(pwdInp.isPassword, true);

      const otpInp = dom.inputs.find(i => i.id === 'totp_code');
      assert.ok(otpInp);
      assert.equal(otpInp.isOtpCandidate, true);

      assert.equal(dom.buttons.length, 1);
      assert.equal(dom.buttons[0].id, 'btn_signin');
      assert.equal(dom.buttons[0].text, 'Sign In');
    });

    test('2.3 Multi-step .lsr execution (Stage 1 Wrapper -> Stage 2 App Login -> Stage 3 TOTP MFA), secrets redaction, restrictions & mid-scan re-auth', async () => {
      const submittedPayloads = [];
      let mfaVerifyCount = 0;

      const lsrSequence = {
        name: 'WrapperSequence',
        targetUrl: 'https://portal.example.com',
        secrets: [
          { name: 'wrapperPassword', value: 'WrapperSuperSecret!1' },
          { name: 'appPassword', value: 'AppSecondSecret!2' }
        ],
        otpConfig: {
          enabled: true,
          secret: RFC6238_SHA1_BASE32,
          digits: 6,
          period: 30,
          algorithm: 'SHA1'
        },
        restrictions: [
          '/portal/terminate-account',
          '*/admin/factory-reset*'
        ],
        sessionDetection: {
          statusCodes: [401],
          redirectPattern: '/wrapper/login',
          loggedOutPattern: 'Session Expired - Please Sign In'
        },
        actions: [
          // Stage 1: Wrapper gate
          { type: 'navigate', url: 'https://portal.example.com/wrapper/login' },
          { type: 'change_input', selectorType: 'id', selector: 'wrapper_user', value: 'wrapper_admin' },
          { type: 'change_input', selectorType: 'id', selector: 'wrapper_pass', value: '{{SECRET:wrapperPassword}}', secretName: 'wrapperPassword', isSecret: true },
          { type: 'click_button', selectorType: 'id', selector: 'wrapper_submit' },
          // Stage 2: Secondary app login
          { type: 'change_input', selectorType: 'id', selector: 'app_user', value: 'sec_analyst' },
          { type: 'change_input', selectorType: 'id', selector: 'app_pass', secretName: 'appPassword', isSecret: true },
          { type: 'click_button', selectorType: 'text', selector: 'Continue to 2FA' },
          // Stage 3: TOTP MFA
          { type: 'fill_otp', selectorType: 'id', selector: 'mfa_totp' },
          { type: 'click_button', selectorType: 'id', selector: 'verify_mfa_btn' }
        ]
      };

      const mockFetch = async (url, opts = {}) => {
        const method = (opts.method || 'GET').toUpperCase();
        if (method === 'GET' && url === 'https://portal.example.com/wrapper/login') {
          return {
            status: 200,
            url,
            headers: { 'set-cookie': 'wrapper_pre=1; Path=/' },
            text: `
              <form action="/wrapper/auth" method="POST">
                <input type="hidden" name="_token" value="wrap_csrf_1" />
                <input id="wrapper_user" name="w_user" type="text" />
                <input id="wrapper_pass" name="w_pass" type="password" />
                <button id="wrapper_submit" type="submit">Enter Wrapper</button>
              </form>
            `
          };
        }
        if (method === 'POST' && url === 'https://portal.example.com/wrapper/auth') {
          const params = Object.fromEntries(new URLSearchParams(opts.body || '').entries());
          submittedPayloads.push({ stage: 1, params });
          return {
            status: 302,
            url,
            headers: {
              location: '/app/login',
              'set-cookie': 'wrapper_session=wrap_ok; Path=/'
            },
            text: ''
          };
        }
        if (method === 'GET' && url === 'https://portal.example.com/app/login') {
          return {
            status: 200,
            url,
            headers: {},
            text: `
              <form action="/app/login" method="POST">
                <input type="hidden" name="csrf_token" value="app_csrf_2" />
                <input id="app_user" name="username" type="text" />
                <input id="app_pass" name="password" type="password" />
                <button id="app_submit" type="submit">Continue to 2FA</button>
              </form>
            `
          };
        }
        if (method === 'POST' && url === 'https://portal.example.com/app/login') {
          const params = Object.fromEntries(new URLSearchParams(opts.body || '').entries());
          submittedPayloads.push({ stage: 2, params });
          return {
            status: 200,
            url: 'https://portal.example.com/app/mfa',
            headers: { 'set-cookie': 'pre_mfa=stage2_ok; Path=/' },
            text: `
              <form action="/app/mfa/verify" method="POST">
                <input id="mfa_totp" name="totp_code" type="text" autocomplete="one-time-code" />
                <button id="verify_mfa_btn" type="submit">Verify Code</button>
              </form>
            `
          };
        }
        if (method === 'POST' && url === 'https://portal.example.com/app/mfa/verify') {
          const params = Object.fromEntries(new URLSearchParams(opts.body || '').entries());
          submittedPayloads.push({ stage: 3, params });
          mfaVerifyCount += 1;
          return {
            status: 200,
            url,
            headers: { 'set-cookie': `auth_session=full_access_${mfaVerifyCount}; Path=/` },
            text: JSON.stringify({ access_token: `jwt_mfa_token_${mfaVerifyCount}` })
          };
        }
        return { status: 404, url, headers: {}, text: 'Not Found' };
      };

      const mgr = new AuthSessionManager({
        targetUrl: 'https://portal.example.com',
        loginSequence: lsrSequence,
        maxReauthAttempts: 3
      });

      const outcome = await mgr.executeLoginMacro(mockFetch);
      assert.equal(outcome.authenticated, true);
      assert.equal(outcome.authMethod, 'login_sequence');
      assert.equal(outcome.stepsExecuted, 9);
      assert.equal(mgr.bearerToken, 'jwt_mfa_token_1');
      assert.equal(mgr.cookies.get('wrapper_session'), 'wrap_ok');
      assert.equal(mgr.cookies.get('auth_session'), 'full_access_1');

      // Verify all 3 form submissions resolved secrets, CSRF, and 6-digit TOTP code
      assert.equal(submittedPayloads.length, 3);
      assert.equal(submittedPayloads[0].params.w_user, 'wrapper_admin');
      assert.equal(submittedPayloads[0].params.w_pass, 'WrapperSuperSecret!1');
      assert.equal(submittedPayloads[0].params._token, 'wrap_csrf_1');

      assert.equal(submittedPayloads[1].params.username, 'sec_analyst');
      assert.equal(submittedPayloads[1].params.password, 'AppSecondSecret!2');
      assert.equal(submittedPayloads[1].params.csrf_token, 'app_csrf_2');

      assert.match(submittedPayloads[2].params.totp_code, /^\d{6}$/);

      // Verify secret redaction in getRecordedSession({ includeSecrets: false }) and exportLsrSequence
      const publicSession = mgr.getRecordedSession({ includeSecrets: false });
      const serializedSession = JSON.stringify(publicSession);
      assert.equal(serializedSession.includes('WrapperSuperSecret!1'), false);
      assert.equal(serializedSession.includes('AppSecondSecret!2'), false);
      assert.equal(serializedSession.includes(RFC6238_SHA1_BASE32), false);

      const exportedRedacted = exportLsrSequence(mgr.loginSequence, { includeSecrets: false });
      assert.equal(exportedRedacted.secrets[0].value, '[SECRET]');
      assert.equal(exportedRedacted.otpConfig.secret, '[REDACTED]');

      // Verify custom restrictions block in wrapFetch
      let protectedCalls = 0;
      const scanFetch = mgr.wrapFetch(async (url, opts) => {
        if (url.startsWith('https://portal.example.com/api/orders')) {
          protectedCalls += 1;
          if (protectedCalls === 1) {
            // Simulate mid-scan session expiration
            return {
              status: 200,
              url,
              headers: { 'content-type': 'text/html' },
              text: '<html><body>Session Expired - Please Sign In</body></html>'
            };
          }
          return {
            status: 200,
            url,
            headers: { 'content-type': 'application/json' },
            text: JSON.stringify({ ok: true, authHeader: opts.headers.Authorization })
          };
        }
        return mockFetch(url, opts);
      });

      const restrictedRes1 = await scanFetch('https://portal.example.com/portal/terminate-account');
      assert.equal(restrictedRes1.status, 204);
      assert.equal(restrictedRes1.restrictedUrl, true);

      const restrictedRes2 = await scanFetch('https://portal.example.com/v2/admin/factory-reset?confirm=1');
      assert.equal(restrictedRes2.status, 204);
      assert.equal(restrictedRes2.restrictedUrl, true);

      // Verify mid-scan sessionDetection triggers automatic multi-step re-authentication with fresh TOTP
      const ordersRes = await scanFetch('https://portal.example.com/api/orders');
      assert.equal(ordersRes.status, 200);
      assert.equal(mgr.reauthCount, 2);
      assert.equal(mfaVerifyCount, 2);
      const parsedOrders = JSON.parse(ordersRes.text);
      assert.equal(parsedOrders.authHeader, 'Bearer jwt_mfa_token_2');
    });

    test('2.4 Rejects cross-origin SSRF in .lsr navigate and click_button steps', async () => {
      const mgr = new AuthSessionManager({
        targetUrl: 'https://portal.example.com',
        loginSequence: {
          name: 'CrossOriginAttempt.lsr',
          targetUrl: 'https://portal.example.com',
          actions: [
            { type: 'navigate', url: 'https://evil-attacker.example.org/steal' }
          ]
        }
      });

      await assert.rejects(
        () => mgr.executeLoginMacro(async () => ({ status: 200, headers: {}, text: '' })),
        /Blocked cross-origin login sequence URL/
      );
    });

    test('2.5 System Variables ({{VAR:name}} & {{SECRET:name}}): normalize/export masking, single-place credential rotation across sequences, and OTP seed resolution', async () => {
      const rawVars = [
        { name: 'corp_user', value: 'sec_ops_admin', category: 'username', isSecret: false },
        { name: 'corp_pass', value: 'InitialPass#2025', category: 'password', isSecret: true },
        { name: 'corp_otp_seed', value: RFC6238_SHA1_BASE32, category: 'otp_seed', isSecret: true },
        { name: '__proto__', value: 'polluted' }
      ];

      const normalized = normalizeSystemVariables(rawVars);
      assert.equal(normalized.length, 3);
      assert.equal(normalized.some(v => v.name === '__proto__'), false);

      const exportedMasked = exportSystemVariables(normalized, { includeSecrets: false });
      const userVar = exportedMasked.find(v => v.name === 'corp_user');
      const passVar = exportedMasked.find(v => v.name === 'corp_pass');
      const otpVar = exportedMasked.find(v => v.name === 'corp_otp_seed');
      assert.equal(userVar.value, 'sec_ops_admin');
      assert.equal(userVar.isSecret, false);
      assert.equal(passVar.value, '[SECRET]');
      assert.equal(passVar.isSecret, true);
      assert.equal(passVar.hasValue, true);
      assert.equal(otpVar.value, '[SECRET]');
      assert.equal(otpVar.isSecret, true);
      assert.equal(otpVar.hasValue, true);

      // Two distinct .lsr sequences both reference {{VAR:corp_user}}, {{SECRET:corp_pass}}, and {{VAR:corp_otp_seed}}
      const seqPortalA = {
        name: 'PortalA.lsr',
        targetUrl: 'https://a.example.com',
        otpConfig: {
          enabled: true,
          secret: '{{VAR:corp_otp_seed}}',
          digits: 6,
          period: 30,
          algorithm: 'SHA1'
        },
        actions: [
          { type: 'navigate', url: 'https://a.example.com/login' },
          { type: 'change_input', selectorType: 'id', selector: 'user_a', value: '{{VAR:corp_user}}' },
          { type: 'change_input', selectorType: 'id', selector: 'pass_a', value: '{{SECRET:corp_pass}}' },
          { type: 'fill_otp', selectorType: 'id', selector: 'otp_a' },
          { type: 'click_button', selectorType: 'id', selector: 'btn_a' }
        ]
      };

      const seqPortalB = {
        name: 'PortalB.lsr',
        targetUrl: 'https://b.example.com',
        otpConfig: {
          enabled: true,
          secretName: 'corp_otp_seed',
          digits: 6,
          period: 30,
          algorithm: 'SHA1'
        },
        actions: [
          { type: 'navigate', url: 'https://b.example.com/signin' },
          { type: 'change_input', selectorType: 'id', selector: 'user_b', value: '{{VAR:corp_user}}' },
          { type: 'change_input', selectorType: 'id', selector: 'pass_b', secretName: 'corp_pass' },
          { type: 'fill_otp', selectorType: 'id', selector: 'otp_b', secretName: 'corp_otp_seed' },
          { type: 'click_button', selectorType: 'id', selector: 'btn_b' }
        ]
      };

      // Server accepts only the rotated password 'RotatedPass#2026'
      let activeServerPassword = 'RotatedPass#2026';
      const makePortalFetcher = (origin, suffix) => async (url, opts = {}) => {
        const method = (opts.method || 'GET').toUpperCase();
        if (method === 'GET') {
          return {
            status: 200,
            url,
            headers: {},
            text: `
              <form action="${origin}/auth" method="POST">
                <input id="user_${suffix}" name="u" type="text" />
                <input id="pass_${suffix}" name="p" type="password" />
                <input id="otp_${suffix}" name="o" type="text" autocomplete="one-time-code" />
                <button id="btn_${suffix}" type="submit">Login</button>
              </form>
            `
          };
        }
        const params = Object.fromEntries(new URLSearchParams(opts.body || '').entries());
        if (params.u === 'sec_ops_admin' && params.p === activeServerPassword && /^\d{6}$/.test(params.o || '')) {
          return {
            status: 200,
            url,
            headers: { 'set-cookie': `sid_${suffix}=valid_session; Path=/` },
            text: JSON.stringify({ access_token: `jwt_${suffix}_ok` })
          };
        }
        return {
          status: 401,
          url,
          headers: {},
          text: JSON.stringify({ error: 'Invalid rotated credentials' })
        };
      };

      // Rotate corp_pass in ONE place (systemVariables) without editing seqPortalA or seqPortalB
      const rotatedVars = normalizeSystemVariables([
        ...rawVars,
        { name: 'corp_pass', value: 'RotatedPass#2026', category: 'password', isSecret: true }
      ]);

      const mgrA = new AuthSessionManager({
        targetUrl: 'https://a.example.com',
        loginSequence: seqPortalA,
        systemVariables: rotatedVars
      });
      const resA = await mgrA.executeLoginMacro(makePortalFetcher('https://a.example.com', 'a'));
      assert.equal(resA.authenticated, true);
      assert.equal(mgrA.bearerToken, 'jwt_a_ok');
      assert.equal(resA.diagnostics.length, 0);

      const mgrB = new AuthSessionManager({
        targetUrl: 'https://b.example.com',
        loginSequence: seqPortalB,
        systemVariables: rotatedVars
      });
      const resB = await mgrB.executeLoginMacro(makePortalFetcher('https://b.example.com', 'b'));
      assert.equal(resB.authenticated, true);
      assert.equal(mgrB.bearerToken, 'jwt_b_ok');
      assert.equal(resB.diagnostics.length, 0);
    });

    test('2.6 Per-Step Play Diagnostics & Visual domSnapshot (SELECTOR_NOT_FOUND, UNRESOLVED_VARIABLE, OTP_CONFIG_ERROR, LOGIN_ERROR_BANNER_DETECTED, HTTP_AUTH_ERROR)', async () => {
      const loginFormHtml = `
        <!doctype html>
        <html>
          <head><title>Portal Sign In</title></head>
          <body>
            <form action="/login" method="POST">
              <input type="hidden" name="_token" value="csrf_preflight_1" />
              <label for="email">Email</label>
              <input id="email" name="email" type="email" />
              <label for="password">Password</label>
              <input id="password" name="password" type="password" />
              <button id="submit_btn" type="submit">Log In</button>
            </form>
          </body>
        </html>
      `;

      // A) SELECTOR_NOT_FOUND + UNRESOLVED_VARIABLE + OTP_CONFIG_ERROR + LOGIN_ERROR_BANNER_DETECTED
      // Even though GET /login sets an unauthenticated preflight XSRF-TOKEN cookie,
      // authenticated MUST be false and diagnostics must report the exact broken steps!
      const failingMgr = new AuthSessionManager({
        targetUrl: 'https://diag.example.com',
        loginSequence: {
          name: 'BrokenSequence.lsr',
          targetUrl: 'https://diag.example.com',
          actions: [
            { type: 'navigate', url: 'https://diag.example.com/login' },
            { type: 'change_input', selectorType: 'id', selector: 'email', value: '{{VAR:missing_user_var}}' },
            { type: 'change_input', selectorType: 'id', selector: 'wrong_pass_selector', value: 'SomePass123' },
            { type: 'fill_otp', selectorType: 'id', selector: 'missing_otp_input' },
            { type: 'click_button', selectorType: 'id', selector: 'submit_btn' }
          ]
        }
      });

      const failOutcome = await failingMgr.executeLoginMacro(async (url, opts = {}) => {
        const method = (opts.method || 'GET').toUpperCase();
        if (method === 'GET') {
          return {
            status: 200,
            url,
            headers: { 'set-cookie': 'XSRF-TOKEN=preflight_only_cookie; Path=/' },
            text: loginFormHtml
          };
        }
        // POST /login returns HTTP 200 with an HTML alert-danger error banner and no session cookie
        return {
          status: 200,
          url,
          headers: {},
          text: `
            <!doctype html>
            <html>
              <body>
                <div class="alert alert-danger">Invalid username or password</div>
                ${loginFormHtml}
              </body>
            </html>
          `
        };
      });

      assert.equal(
        failOutcome.authenticated,
        false,
        'Preflight XSRF-TOKEN cookie must NOT cause authenticated=true when steps fail or no post-submit session artifact is issued'
      );
      const codes = failOutcome.diagnostics.map(d => d.code);
      assert.ok(codes.includes('UNRESOLVED_VARIABLE'), `Expected UNRESOLVED_VARIABLE in ${codes}`);
      assert.ok(codes.includes('SELECTOR_NOT_FOUND'), `Expected SELECTOR_NOT_FOUND in ${codes}`);
      assert.ok(codes.includes('OTP_CONFIG_ERROR'), `Expected OTP_CONFIG_ERROR in ${codes}`);
      assert.ok(codes.includes('LOGIN_ERROR_BANNER_DETECTED'), `Expected LOGIN_ERROR_BANNER_DETECTED in ${codes}`);

      const selectorDiag = failOutcome.diagnostics.find(d => d.code === 'SELECTOR_NOT_FOUND');
      assert.match(selectorDiag.detail, /#email/);
      assert.match(selectorDiag.detail, /#password/);

      const bannerDiag = failOutcome.diagnostics.find(d => d.code === 'LOGIN_ERROR_BANNER_DETECTED');
      assert.match(bannerDiag.detail, /Invalid username or password/);

      const submitStepRecord = failOutcome.sequenceSteps[4];
      assert.equal(submitStepRecord.stepStatus, 'error');
      assert.equal(submitStepRecord.domSnapshot.pageErrorBanner, 'Invalid username or password');

      // B) HTTP_AUTH_ERROR when server returns HTTP 401 JSON { "error": "Invalid credentials" }
      const http401Mgr = new AuthSessionManager({
        targetUrl: 'https://diag.example.com',
        systemVariables: [
          { name: 'corp_user', value: 'alice@example.com', category: 'username' },
          { name: 'corp_pass', value: 'WrongSecret', category: 'password', isSecret: true }
        ],
        loginSequence: {
          name: 'Http401Sequence.lsr',
          targetUrl: 'https://diag.example.com',
          actions: [
            { type: 'navigate', url: 'https://diag.example.com/login' },
            { type: 'change_input', selectorType: 'id', selector: 'email', value: '{{VAR:corp_user}}' },
            { type: 'change_input', selectorType: 'id', selector: 'password', value: '{{SECRET:corp_pass}}' },
            { type: 'click_button', selectorType: 'id', selector: 'submit_btn' }
          ]
        }
      });

      const http401Outcome = await http401Mgr.executeLoginMacro(async (url, opts = {}) => {
        if ((opts.method || 'GET').toUpperCase() === 'GET') {
          return { status: 200, url, headers: {}, text: loginFormHtml };
        }
        return {
          status: 401,
          url,
          headers: { 'content-type': 'application/json' },
          text: JSON.stringify({ error: 'Invalid credentials' })
        };
      });

      assert.equal(http401Outcome.authenticated, false);
      const httpErrDiag = http401Outcome.diagnostics.find(d => d.code === 'HTTP_AUTH_ERROR');
      assert.ok(httpErrDiag);
      assert.match(httpErrDiag.detail, /HTTP 401.*"Invalid credentials"/);
      assert.equal(http401Outcome.sequenceSteps[3].domSnapshot.pageErrorBanner, 'Invalid credentials');

      // Verify passing steps populate domSnapshot inputs (isFilled, filledValueMasked, boundVariable) & buttons (wasClicked)
      const step2Snap = http401Outcome.sequenceSteps[1].domSnapshot;
      const emailSnap = step2Snap.inputs.find(i => i.id === 'email');
      assert.ok(emailSnap);
      assert.equal(emailSnap.isFilled, true);
      assert.equal(emailSnap.filledValueMasked, 'alice@example.com');
      assert.equal(emailSnap.boundVariable, 'corp_user');

      const step3Snap = http401Outcome.sequenceSteps[2].domSnapshot;
      const passSnap = step3Snap.inputs.find(i => i.id === 'password');
      assert.ok(passSnap);
      assert.equal(passSnap.isFilled, true);
      assert.equal(passSnap.filledValueMasked, '••••••••');
      assert.equal(passSnap.boundVariable, 'corp_pass');

      const step4Snap = http401Outcome.sequenceSteps[3].domSnapshot;
      assert.ok(step4Snap.buttons.some(b => b.id === 'submit_btn' && b.wasClicked === true));
    });
  });

  describe('3. Server API & UI E2E Integration', () => {
    test('3.1 POST /api/auth/inspect-page, /api/auth/otp-preview, /api/auth/sequences, /api/auth/record-session, /api/sca/analyze & /api/scan', async () => {
      await withMockTarget(
        {
          routes: (reqInfo) => {
            if (reqInfo.pathname === '/wrapper/login' && reqInfo.method === 'GET') {
              return {
                status: 200,
                headers: { 'Set-Cookie': 'wrapper_init=1; Path=/' },
                body: `
                  <!doctype html>
                  <html>
                    <head><title>Wrapper Login</title></head>
                    <body>
                      <form id="wrap-form" action="/wrapper/login" method="POST">
                        <input type="hidden" name="_token" value="csrf_tok_abc" />
                        <label for="user_input">Username</label>
                        <input id="user_input" name="username" type="text" />
                        <label for="pass_input">Password</label>
                        <input id="pass_input" name="password" type="password" />
                        <label for="otp_input">OTP Code</label>
                        <input id="otp_input" name="otp" type="text" autocomplete="one-time-code" />
                        <button id="login_btn" type="submit">Sign In</button>
                      </form>
                    </body>
                  </html>
                `
              };
            }
            if (reqInfo.pathname === '/wrapper/login' && reqInfo.method === 'POST') {
              const params = Object.fromEntries(new URLSearchParams(reqInfo.body || '').entries());
              if (params.username === 'admin' && params.password === 'VaultSecret!99' && /^\d{6}$/.test(params.otp || '')) {
                return {
                  status: 200,
                  headers: { 'Set-Cookie': 'portal_sid=authenticated_123; Path=/' },
                  body: { access_token: 'lsr_live_jwt_token' }
                };
              }
              return { status: 401, body: { error: 'Invalid credentials or OTP' } };
            }
            return {
              status: 200,
              headers: {
                Server: 'nginx/1.24.0',
                'X-Powered-By': 'Express/4.18.2'
              },
              body: `
                <!doctype html>
                <html ng-version="20.3.26">
                  <head>
                    <script src="/assets/jquery-3.4.1.min.js"></script>
                    <script src="/assets/lodash-4.18.1.min.js"></script>
                  </head>
                  <body data-sca-versions="moment.js:2.9.0-2.23.0;bootstrap:3.3.2-4.5.2;angularjs:1.6.6-1.8.2">
                    <h1>Authenticated Portal Dashboard</h1>
                  </body>
                </html>
              `
            };
          }
        },
        async (mockTarget) => {
          await withAppHarness({ inMemory: true }, async (app) => {
            // 1) POST /api/auth/inspect-page blocks private IP when allowPrivate: false
            const blockedInspect = await app.jsonFetch('/api/auth/inspect-page', {
              method: 'POST',
              body: {
                targetUrl: `${mockTarget.baseUrl}/wrapper/login`,
                allowPrivate: false
              }
            });
            assert.ok([400, 403].includes(blockedInspect.status));
            assert.ok(blockedInspect.data?.error);

            // 2) POST /api/auth/inspect-page succeeds when allowPrivate: true
            const okInspect = await app.jsonFetch('/api/auth/inspect-page', {
              method: 'POST',
              body: {
                targetUrl: `${mockTarget.baseUrl}/wrapper/login`,
                allowPrivate: true
              }
            });
            assert.equal(okInspect.status, 200);
            assert.equal(okInspect.data.ok, true);
            assert.equal(okInspect.data.title, 'Wrapper Login');
            assert.equal(okInspect.data.hasPasswordInput, true);
            assert.equal(okInspect.data.hasMfaOrOtpField, true);
            assert.equal(okInspect.data.forms.length, 1);
            assert.ok(okInspect.data.inputs.some(i => i.id === 'otp_input' && i.isOtpCandidate));
            assert.ok(okInspect.data.buttons.some(b => b.id === 'login_btn'));

            // 3) POST /api/auth/otp-preview validates TOTP & masks secret
            const otpPreview = await app.jsonFetch('/api/auth/otp-preview', {
              method: 'POST',
              body: {
                secret: RFC6238_SHA1_BASE32,
                digits: 6,
                period: 30,
                algorithm: 'SHA1'
              }
            });
            assert.equal(otpPreview.status, 200);
            assert.equal(otpPreview.data.valid, true);
            assert.match(otpPreview.data.code, /^\d{6}$/);
            assert.equal(otpPreview.data.secretMasked, '[CONFIGURED]');
            assert.equal(JSON.stringify(otpPreview.data).includes(RFC6238_SHA1_BASE32), false);

            // 4) POST /api/auth/sequences, GET /api/auth/sequences, DELETE /api/auth/sequences/:id
            const sequencePayload = {
              name: 'WrapperSequence.lsr',
              targetUrl: mockTarget.baseUrl,
              secrets: [{ name: 'adminPass', value: 'VaultSecret!99' }],
              otpConfig: {
                enabled: true,
                secret: RFC6238_SHA1_BASE32,
                digits: 6,
                period: 30,
                algorithm: 'SHA1'
              },
              restrictions: ['/logout', '/account/delete'],
              sessionDetection: {
                statusCodes: [401, 403],
                redirectPattern: '/wrapper/login'
              },
              actions: [
                { type: 'navigate', url: `${mockTarget.baseUrl}/wrapper/login` },
                { type: 'change_input', selectorType: 'id', selector: 'user_input', value: 'admin' },
                { type: 'change_input', selectorType: 'id', selector: 'pass_input', secretName: 'adminPass', isSecret: true },
                { type: 'fill_otp', selectorType: 'id', selector: 'otp_input' },
                { type: 'click_button', selectorType: 'id', selector: 'login_btn' }
              ]
            };

            const saveSeqRes = await app.jsonFetch('/api/auth/sequences', {
              method: 'POST',
              body: {
                allowPrivate: true,
                sequence: sequencePayload
              }
            });
            assert.equal(saveSeqRes.status, 200);
            assert.equal(saveSeqRes.data.saved, true);
            const seqId = saveSeqRes.data.sequenceId;
            assert.ok(seqId);
            assert.equal(saveSeqRes.data.sequence.secrets[0].value, '[SECRET]');
            assert.equal(saveSeqRes.data.sequence.otpConfig.secret, '[REDACTED]');

            const listSeqRes = await app.jsonFetch('/api/auth/sequences');
            assert.equal(listSeqRes.status, 200);
            assert.equal(listSeqRes.data.sequences.length, 1);
            assert.equal(listSeqRes.data.sequences[0].sequenceId, seqId);
            assert.equal(JSON.stringify(listSeqRes.data).includes('VaultSecret!99'), false);

            // 5) POST /api/auth/record-session replays saved sequenceId with stored vault secrets & TOTP
            const recordRes = await app.jsonFetch('/api/auth/record-session', {
              method: 'POST',
              body: {
                allowPrivate: true,
                targetUrl: mockTarget.baseUrl,
                sequenceId: seqId
              }
            });
            assert.equal(recordRes.status, 200);
            assert.equal(recordRes.data.authenticated, true);
            assert.equal(recordRes.data.authMethod, 'login_sequence');
            assert.equal(recordRes.data.hasBearerToken, true);
            assert.ok(recordRes.data.cookieNames.includes('portal_sid'));

            // 6) POST /api/sca/analyze analyzes live target and extracts runtimeSca findings
            const scaAnalyzeRes = await app.jsonFetch('/api/sca/analyze', {
              method: 'POST',
              body: {
                target: mockTarget.baseUrl,
                allowPrivate: true
              }
            });
            assert.equal(scaAnalyzeRes.status, 200);
            assert.ok(scaAnalyzeRes.data.runtimeSca);
            assert.ok(scaAnalyzeRes.data.runtimeSca.totalIdentified >= 6);

            // 7) POST /api/scan executes scan with multi-step .lsr sequence and populates runtimeSca
            const startScanRes = await app.jsonFetch('/api/scan', {
              method: 'POST',
              body: {
                target: mockTarget.baseUrl,
                allowPrivate: true,
                noHistory: true,
                checks: ['runtime-sca'],
                maxDepth: 0,
                sequenceId: seqId,
                jev: ALL_JEV_TRUE
              }
            });
            assert.equal(startScanRes.status, 202);
            const scanId = startScanRes.data.scanId || startScanRes.data.id;
            assert.ok(scanId);

            // Poll /api/scan/:id until completed
            let scanJob = null;
            for (let i = 0; i < 60; i++) {
              const pollRes = await app.jsonFetch(`/api/scan/${scanId}`);
              if (
                pollRes.data?.status === 'completed' ||
                pollRes.data?.status === 'done' ||
                pollRes.data?.status === 'failed' ||
                pollRes.data?.status === 'error'
              ) {
                scanJob = pollRes.data;
                break;
              }
              await new Promise(r => setTimeout(r, 100));
            }
            assert.ok(scanJob, 'Expected scan job to complete');
            assert.ok(['completed', 'done'].includes(scanJob.status));
            assert.ok(scanJob.result?.runtimeSca, 'Expected runtimeSca on completed scan result');
            assert.ok(scanJob.result.runtimeSca.totalIdentified >= 6);
            assert.ok(scanJob.result.runtimeSca.outOfDateCount >= 5);

            // 8) DELETE /api/auth/sequences/:id removes the saved sequence
            const delSeqRes = await app.jsonFetch(`/api/auth/sequences/${encodeURIComponent(seqId)}`, {
              method: 'DELETE'
            });
            assert.equal(delSeqRes.status, 200);
            assert.equal(delSeqRes.data.deleted, true);

            const afterDelList = await app.jsonFetch('/api/auth/sequences');
            assert.equal(afterDelList.data.sequences.length, 0);
          });
        }
      );
    });

    test('3.2 ui/app.js renderRuntimeScaTable and renderTechDetectScaPreview render all 6 Invicti columns and escape untrusted HTML', () => {
      const prevDocument = globalThis.document;
      const makeEl = () => ({
        classList: {
          hidden: true,
          add(c) { if (c === 'hidden') this.hidden = true; },
          remove(c) { if (c === 'hidden') this.hidden = false; },
          toggle(c, force) { if (c === 'hidden') this.hidden = Boolean(force); }
        },
        textContent: '',
        innerHTML: '',
        className: ''
      });
      const elements = new Map();
      const getEl = (id) => {
        if (!elements.has(id)) elements.set(id, makeEl());
        return elements.get(id);
      };
      globalThis.document = {
        getElementById: getEl,
        querySelectorAll: () => []
      };

      try {
        const sampleSca = {
          totalIdentified: 6,
          outOfDateCount: 5,
          upToDateCount: 1,
          highestCvss: 7.5,
          findings: [
            evaluateTechnologyVersion('Moment.js', '2.9.0 - 2.23.0'),
            evaluateTechnologyVersion('Lodash', '4.18.1'),
            evaluateTechnologyVersion('jQuery', '1.3.2 - 3.7.1'),
            evaluateTechnologyVersion('Bootstrap', '3.3.2 - 4.5.2'),
            evaluateTechnologyVersion('AngularJS', '1.6.6 - 1.8.2'),
            {
              ...evaluateTechnologyVersion('Angular', '20.3.26 - 20.3.34'),
              name: 'Angular <img src=x onerror=alert(1)>',
              recommendedAction: 'Update to 22.2.6 <script>evil()</script>'
            }
          ]
        };

        renderTechDetectScaPreview(sampleSca);
        const previewRow = getEl('tech-detect-sca-row');
        assert.equal(previewRow.classList.hidden, false);
        assert.match(previewRow.innerHTML, /Runtime SCA \(6 detected · 5 out of date\)/);
        assert.equal(previewRow.innerHTML.includes('<img src=x'), false);
        assert.match(previewRow.innerHTML, /&lt;img src=x onerror=alert\(1\)&gt;/);

        renderRuntimeScaTable(sampleSca);
        const card = getEl('results-runtime-sca-card');
        const countEl = getEl('results-sca-count');
        const tbody = getEl('results-runtime-sca-tbody');

        assert.equal(card.classList.hidden, false);
        assert.equal(countEl.textContent, '6');

        // Verify all 6 Invicti rows & columns are present and XSS payloads are escaped
        assert.match(tbody.innerHTML, /Moment\.js/);
        assert.match(tbody.innerHTML, /2\.9\.0 - 2\.23\.0/);
        assert.match(tbody.innerHTML, /2\.31\.0/);
        assert.match(tbody.innerHTML, /Lodash/);
        assert.match(tbody.innerHTML, /✅ Up to date/);
        assert.match(tbody.innerHTML, /⚠️ Out of date/);
        assert.match(tbody.innerHTML, /1\.3\.2 - 3\.7\.1/);
        assert.match(tbody.innerHTML, /3\.3\.2 - 4\.5\.2/);
        assert.match(tbody.innerHTML, /1\.6\.6 - 1\.8\.2/);
        assert.match(tbody.innerHTML, /20\.3\.26 - 20\.3\.34/);
        assert.equal(tbody.innerHTML.includes('<script>evil()</script>'), false);
        assert.match(tbody.innerHTML, /&lt;script&gt;evil\(\)&lt;\/script&gt;/);
      } finally {
        globalThis.document = prevDocument;
      }
    });

    test('3.3 Server Persistence & REST Endpoints (/api/auth/variables & /api/auth/sequences/:id) across server restart + SSRF block on {{VAR:evil_url}}', async () => {
      await withTempDir(async (tmpHistoryDir) => {
        await withMockTarget(
          {
            routes: (reqInfo) => {
              if (reqInfo.pathname === '/sso/login' && reqInfo.method === 'GET') {
                return {
                  status: 200,
                  headers: { 'Set-Cookie': 'XSRF-TOKEN=preflight_tok; Path=/' },
                  body: `
                    <form action="/sso/login" method="POST">
                      <input id="sso_user" name="user" type="text" />
                      <input id="sso_pass" name="pass" type="password" />
                      <input id="sso_otp" name="otp" type="text" autocomplete="one-time-code" />
                      <button id="sso_submit" type="submit">SSO Login</button>
                    </form>
                  `
                };
              }
              if (reqInfo.pathname === '/sso/login' && reqInfo.method === 'POST') {
                const params = Object.fromEntries(new URLSearchParams(reqInfo.body || '').entries());
                if (params.user === 'shared_admin' && params.pass === 'RotatedGlobalSecret!2026' && /^\d{6}$/.test(params.otp || '')) {
                  return {
                    status: 200,
                    headers: { 'Set-Cookie': 'sso_sid=persisted_ok; Path=/' },
                    body: { access_token: 'persisted_var_jwt' }
                  };
                }
                return {
                  status: 200,
                  body: '<div class="alert alert-danger">Invalid username or password</div>'
                };
              }
              return { status: 200, body: 'OK' };
            }
          },
          async (mockTarget) => {
            let savedSeqId = null;

            // Instance 1: Create System Variables & Reusable Sequence and persist to disk (inMemory: false)
            await withAppHarness({ historyDir: tmpHistoryDir, inMemory: false }, async (app1) => {
              // 1) POST /api/auth/variables
              const postVarsRes = await app1.jsonFetch('/api/auth/variables', {
                method: 'POST',
                body: {
                  variables: [
                    { name: 'corp_user', value: 'shared_admin', category: 'username', isSecret: false },
                    { name: 'corp_pass', value: 'OldPassword!2025', category: 'password', isSecret: true },
                    { name: 'corp_otp_seed', value: RFC6238_SHA1_BASE32, category: 'otp_seed', isSecret: true },
                    { name: 'evil_url', value: 'http://127.0.0.1:22/ssh', category: 'url', isSecret: false }
                  ]
                }
              });
              assert.equal(postVarsRes.status, 200);
              assert.equal(postVarsRes.data.saved, true);

              // 2) GET /api/auth/variables masks secrets
              const getVarsRes = await app1.jsonFetch('/api/auth/variables');
              assert.equal(getVarsRes.status, 200);
              const passEntry = getVarsRes.data.variables.find(v => v.name === 'corp_pass');
              assert.ok(passEntry);
              assert.equal(passEntry.value, '[SECRET]');
              assert.equal(passEntry.hasValue, true);
              assert.equal(JSON.stringify(getVarsRes.data).includes('OldPassword!2025'), false);

              // 3) SSRF block when {{VAR:evil_url}} resolves to http://127.0.0.1 with allowPrivate: false
              const ssrfInspectRes = await app1.jsonFetch('/api/auth/inspect-page', {
                method: 'POST',
                body: {
                  targetUrl: '{{VAR:evil_url}}',
                  allowPrivate: false
                }
              });
              assert.ok([400, 403].includes(ssrfInspectRes.status));

              // 4) POST /api/auth/sequences referencing {{VAR:corp_user}}, {{SECRET:corp_pass}}, and {{VAR:corp_otp_seed}}
              const saveSeqRes = await app1.jsonFetch('/api/auth/sequences', {
                method: 'POST',
                body: {
                  allowPrivate: true,
                  sequence: {
                    name: 'ReusableSso.lsr',
                    targetUrl: mockTarget.baseUrl,
                    otpConfig: {
                      enabled: true,
                      secretName: 'corp_otp_seed',
                      digits: 6,
                      period: 30,
                      algorithm: 'SHA1'
                    },
                    actions: [
                      { type: 'navigate', url: `${mockTarget.baseUrl}/sso/login` },
                      { type: 'change_input', selectorType: 'id', selector: 'sso_user', value: '{{VAR:corp_user}}' },
                      { type: 'change_input', selectorType: 'id', selector: 'sso_pass', value: '{{SECRET:corp_pass}}' },
                      { type: 'fill_otp', selectorType: 'id', selector: 'sso_otp' },
                      { type: 'click_button', selectorType: 'id', selector: 'sso_submit' }
                    ]
                  }
                }
              });
              assert.equal(saveSeqRes.status, 200);
              savedSeqId = saveSeqRes.data.sequenceId;
              assert.ok(savedSeqId);

              // Verify disk files were written
              assert.equal(fs.existsSync(path.join(tmpHistoryDir, 'system-variables.json')), true);
              assert.equal(fs.existsSync(path.join(tmpHistoryDir, 'auth-sequences.json')), true);
            });

            // Instance 2: Simulate Server Restart on the same historyDir
            await withAppHarness({ historyDir: tmpHistoryDir, inMemory: false }, async (app2) => {
              // 1) Verify sequence and system variables survived restart
              const getSeqById = await app2.jsonFetch(`/api/auth/sequences/${encodeURIComponent(savedSeqId)}`);
              assert.equal(getSeqById.status, 200);
              assert.equal(getSeqById.data.sequence.name, 'ReusableSso.lsr');

              // 2) Play sequence BEFORE rotating corp_pass -> should fail with LOGIN_ERROR_BANNER_DETECTED
              const failPlayRes = await app2.jsonFetch('/api/auth/record-session', {
                method: 'POST',
                body: {
                  allowPrivate: true,
                  targetUrl: mockTarget.baseUrl,
                  sequenceId: savedSeqId
                }
              });
              assert.equal(failPlayRes.status, 200);
              assert.equal(failPlayRes.data.authenticated, false);
              assert.ok(
                failPlayRes.data.diagnostics.some(d => d.code === 'LOGIN_ERROR_BANNER_DETECTED'),
                'Expected LOGIN_ERROR_BANNER_DETECTED before password rotation'
              );

              // 3) Rotate corp_pass via PUT /api/auth/variables/corp_pass without editing the sequence
              const putVarRes = await app2.jsonFetch('/api/auth/variables/corp_pass', {
                method: 'PUT',
                body: {
                  value: 'RotatedGlobalSecret!2026',
                  category: 'password',
                  isSecret: true
                }
              });
              assert.equal(putVarRes.status, 200);
              assert.equal(putVarRes.data.updated, true);
              assert.equal(putVarRes.data.variable.value, '[SECRET]');

              // 4) Update sequence metadata via PUT /api/auth/sequences/:id
              const putSeqRes = await app2.jsonFetch(`/api/auth/sequences/${encodeURIComponent(savedSeqId)}`, {
                method: 'PUT',
                body: {
                  allowPrivate: true,
                  sequence: {
                    ...getSeqById.data.sequence,
                    restrictions: ['/sso/logout']
                  }
                }
              });
              assert.equal(putSeqRes.status, 200);
              assert.deepEqual(putSeqRes.data.sequence.restrictions, ['/sso/logout']);

              // 5) Play sequence AFTER rotating corp_pass in System Variables -> succeeds!
              const okPlayRes = await app2.jsonFetch('/api/auth/record-session', {
                method: 'POST',
                body: {
                  allowPrivate: true,
                  targetUrl: mockTarget.baseUrl,
                  sequenceId: savedSeqId
                }
              });
              assert.equal(okPlayRes.status, 200);
              assert.equal(okPlayRes.data.authenticated, true);
              assert.equal(okPlayRes.data.diagnostics.length, 0);
              assert.ok(okPlayRes.data.cookieNames.includes('sso_sid'));

              // 6) DELETE /api/auth/variables/:name
              const delVarRes = await app2.jsonFetch('/api/auth/variables/evil_url', {
                method: 'DELETE'
              });
              assert.equal(delVarRes.status, 200);
              assert.equal(delVarRes.data.deleted, true);
              assert.equal(delVarRes.data.variables.some(v => v.name === 'evil_url'), false);
            });
          }
        );
      });
    });

    test('3.4 Modular Documentation Verification (README.md and all 5 docs/*.md exist and are non-empty)', () => {
      const requiredDocs = [
        'README.md',
        'docs/authentication-and-lsr.md',
        'docs/web-ui-guide.md',
        'docs/runtime-sca-and-cve-audits.md',
        'docs/network-origin-ip-and-devices.md',
        'docs/cli-and-api-reference.md'
      ];

      for (const relPath of requiredDocs) {
        const fullPath = path.join(REPO_ROOT, relPath);
        assert.equal(fs.existsSync(fullPath), true, `Expected ${relPath} to exist`);
        const content = fs.readFileSync(fullPath, 'utf8').trim();
        assert.ok(content.length > 500, `Expected ${relPath} to be non-empty (got ${content.length} chars)`);
      }
    });

    test('3.5 Network Abort Resilience & Built-In /api/auth/demo-login Working Example Flow', async () => {
      // 1) Verify executeLoginSequence catches "Fetch failed: The operation was aborted" on Step 1 navigate
      // and returns structured NETWORK_TIMEOUT_OR_ABORT diagnostics + a visual blueprint domSnapshot instead of throwing
      const abortMgr = new AuthSessionManager({
        targetUrl: 'https://unreachable-portal.example.com',
        loginSequence: {
          name: 'WrapperSequence.lsr',
          targetUrl: 'https://unreachable-portal.example.com',
          actions: [
            { type: 'navigate', url: 'https://unreachable-portal.example.com/login' },
            { type: 'change_input', selectorType: 'id', selector: 'email', value: 'analyst@example.com' },
            { type: 'change_input', selectorType: 'id', selector: 'password', value: 'SecretPass!1', isSecret: true },
            { type: 'click_button', selectorType: 'text', selector: 'Log In' }
          ]
        }
      });

      const abortedOutcome = await abortMgr.executeLoginSequence(async () => {
        throw new Error('Fetch failed: The operation was aborted');
      });

      assert.equal(abortedOutcome.authenticated, false);
      assert.ok(Array.isArray(abortedOutcome.diagnostics) && abortedOutcome.diagnostics.length > 0);
      assert.equal(abortedOutcome.diagnostics[0].code, 'NETWORK_TIMEOUT_OR_ABORT');
      assert.equal(abortedOutcome.diagnostics[0].step, 1);
      assert.match(abortedOutcome.diagnostics[0].detail, /Fetch failed: The operation was aborted/);
      assert.ok(abortedOutcome.sequenceSteps.length >= 1);
      assert.ok(abortedOutcome.sequenceSteps[0].domSnapshot, 'Expected fallback visual blueprint domSnapshot even when Step 1 times out');
      assert.ok(abortedOutcome.sequenceSteps[0].domSnapshot.inputs.some(inp => inp.id === 'email'));
      assert.ok(abortedOutcome.sequenceSteps[0].domSnapshot.buttons.some(btn => btn.text === 'Log In'));

      // 2) Verify built-in /api/auth/demo-login endpoint + Save + Edit (PUT) + Play end-to-end
      await withAppHarness({}, async app => {
        const demoUrl = `${app.baseUrl}/api/auth/demo-login`;

        const inspectRes = await app.jsonFetch('/api/auth/inspect-page', {
          method: 'POST',
          body: { targetUrl: demoUrl }
        });
        assert.equal(inspectRes.status, 200);
        assert.equal(inspectRes.data.forms.length, 1);
        assert.ok(inspectRes.data.inputs.some(i => i.id === 'email'));
        assert.ok(inspectRes.data.inputs.some(i => i.id === 'password'));
        assert.ok(inspectRes.data.inputs.some(i => i.id === 'otp_code' && i.isOtpCandidate));

        const saveDemoSeq = await app.jsonFetch('/api/auth/sequences', {
          method: 'POST',
          body: {
            sequence: {
              name: 'DemoEnterpriseMFA.lsr',
              targetUrl: demoUrl,
              otpConfig: {
                enabled: true,
                secret: 'JBSWY3DPEHPK3PXP',
                digits: 6,
                period: 30,
                algorithm: 'SHA1',
                inputSelector: 'otp_code'
              },
              actions: [
                { type: 'navigate', url: demoUrl },
                { type: 'change_input', selectorType: 'id', selector: 'email', fieldName: 'email', value: 'admin@infsalesgroup.example' },
                { type: 'change_input', selectorType: 'id', selector: 'password', fieldName: 'password', value: 'InvictiDemo#2026!', isSecret: true },
                { type: 'fill_otp', selectorType: 'id', selector: 'otp_code', fieldName: 'otp_code' },
                { type: 'click_button', selectorType: 'text', selector: 'Log In' }
              ],
              restrictions: ['/logout', '/signout'],
              sessionDetection: {
                statusCodes: [401, 403],
                redirectPattern: '/login',
                loggedOutPattern: 'Invalid username or password|Session Expired',
                loggedInPattern: 'Sign Out|authenticated'
              }
            }
          }
        });
        assert.equal(saveDemoSeq.status, 200);
        const demoSeqId = saveDemoSeq.data.sequenceId || saveDemoSeq.data.sequence?.id;
        assert.ok(demoSeqId);

        const playDemoRes = await app.jsonFetch('/api/auth/record-session', {
          method: 'POST',
          body: {
            targetUrl: demoUrl,
            sequenceId: demoSeqId
          }
        });
        assert.equal(playDemoRes.status, 200);
        assert.equal(playDemoRes.data.authenticated, true);
        assert.equal(playDemoRes.data.diagnostics.length, 0);
        assert.ok(playDemoRes.data.cookieNames.includes('SECSCAN_DEMO_SESSION'));
        assert.ok(playDemoRes.data.hasBearerToken);
        assert.equal(playDemoRes.data.steps.length, 5);
        assert.ok(playDemoRes.data.steps[4].domSnapshot);

        // Verify DELETE /api/auth/sequences/:id supports deleting by sequence name as well as sequenceId
        const delByNameRes = await app.jsonFetch('/api/auth/sequences/DemoEnterpriseMFA.lsr', {
          method: 'DELETE'
        });
        assert.equal(delByNameRes.status, 200);
        assert.equal(delByNameRes.data.deleted, true);

        const listAfterDel = await app.jsonFetch('/api/auth/sequences');
        assert.equal(listAfterDel.status, 200);
        assert.equal(listAfterDel.data.sequences.some(s => s.sequenceId === demoSeqId), false);
      });
    });

    test('3.6 Yii 1.x /broadbandAdmin/index.php/site/login .lsr Authenticated Post-Login Website & Form Scan (GET & POST Forms + Logout Guard)', async () => {
      const authenticatedPhpSessions = new Set();
      let logoutEndpointCalled = false;
      const visitedAuthenticatedPaths = new Set();

      await withMockTarget(
        {
          routes: (reqInfo) => {
            const cookieHeader = String(reqInfo.headers?.cookie || '');
            const hasPhpSess = cookieHeader.includes('PHPSESSID=yii_sess_1');
            const isAuthed = hasPhpSess && authenticatedPhpSessions.has('yii_sess_1');

            // Logout route — if called, destroys session! Must be blocked by logout guard
            if (
              reqInfo.pathname === '/broadbandAdmin/index.php/site/logout' ||
              (reqInfo.pathname === '/broadbandAdmin/index.php' && String(reqInfo.search || '').includes('r=site/logout'))
            ) {
              logoutEndpointCalled = true;
              authenticatedPhpSessions.clear();
              return { status: 302, headers: { Location: '/broadbandAdmin/index.php/site/login' }, body: '' };
            }

            // Yii 1.x Login Page (GET & POST)
            if (reqInfo.pathname === '/broadbandAdmin/index.php/site/login') {
              if (reqInfo.method === 'GET') {
                return {
                  status: 200,
                  headers: {
                    'Content-Type': 'text/html; charset=utf-8',
                    'Set-Cookie': [
                      'PHPSESSID=yii_sess_1; Path=/; HttpOnly',
                      'YII_CSRF_TOKEN=yii_csrf_tok_1; Path=/'
                    ]
                  },
                  body: `<!DOCTYPE html>
<html>
<head><title>BroadbandAdmin - Login</title></head>
<body>
  <form id="login-form" action="/broadbandAdmin/index.php/site/login" method="post">
    <div style="display:none"><input type="hidden" value="yii_csrf_tok_1" name="YII_CSRF_TOKEN" /></div>
    <label for="LoginForm_username">Username</label>
    <input name="LoginForm[username]" id="LoginForm_username" type="text" />
    <label for="LoginForm_password">Password</label>
    <input name="LoginForm[password]" id="LoginForm_password" type="password" />
    <input type="submit" name="yt0" value="Login" />
  </form>
</body>
</html>`
                };
              }

              if (reqInfo.method === 'POST') {
                const params = Object.fromEntries(new URLSearchParams(reqInfo.body || '').entries());
                if (
                  hasPhpSess &&
                  params.YII_CSRF_TOKEN === 'yii_csrf_tok_1' &&
                  params['LoginForm[username]'] === 'al13456' &&
                  params['LoginForm[password]'] === 'YiiAdminSecret!2026' &&
                  params.yt0 === 'Login'
                ) {
                  // Authenticate existing PHPSESSID in-place (no new Set-Cookie on 302)
                  authenticatedPhpSessions.add('yii_sess_1');
                  return {
                    status: 302,
                    headers: { Location: '/broadbandAdmin/index.php/site/index' },
                    body: ''
                  };
                }
                return {
                  status: 200,
                  headers: { 'Content-Type': 'text/html; charset=utf-8' },
                  body: '<div class="errorSummary">Incorrect username or password.</div><input type="password" id="LoginForm_password" name="LoginForm[password]" />'
                };
              }
            }

            // Protected Post-Login Dashboard (/broadbandAdmin/index.php/site/index or /broadbandAdmin/index.php)
            if (
              reqInfo.pathname === '/broadbandAdmin/index.php/site/index' ||
              reqInfo.pathname === '/broadbandAdmin/index.php'
            ) {
              if (!isAuthed) {
                return { status: 302, headers: { Location: '/broadbandAdmin/index.php/site/login' }, body: '' };
              }
              visitedAuthenticatedPaths.add(reqInfo.pathname);
              return {
                status: 200,
                headers: { 'Content-Type': 'text/html; charset=utf-8' },
                body: `<!DOCTYPE html>
<html>
<head><title>BroadbandAdmin Dashboard</title></head>
<body>
  <nav>
    <a href="/broadbandAdmin/index.php/customer/admin">Manage Customers</a>
    <a href="/broadbandAdmin/index.php/router/update">Router Settings</a>
    <a href="/broadbandAdmin/index.php?r=site/logout">Logout (al13456)</a>
    <a href="/broadbandAdmin/index.php/site/logout">Sign Out</a>
  </nav>
</body>
</html>`
              };
            }

            // Protected Post-Login Page 1: GET Search Form (/broadbandAdmin/index.php/customer/admin)
            if (reqInfo.pathname === '/broadbandAdmin/index.php/customer/admin') {
              if (!isAuthed) {
                return { status: 302, headers: { Location: '/broadbandAdmin/index.php/site/login' }, body: '' };
              }
              visitedAuthenticatedPaths.add(reqInfo.pathname);
              const qParams = new URLSearchParams(reqInfo.search || '');
              const searchVal = qParams.get('Customer[search]') || '';
              return {
                status: 200,
                headers: { 'Content-Type': 'text/html; charset=utf-8' },
                body: `<!DOCTYPE html>
<html>
<body>
  <h1>Customer Directory</h1>
  <form method="get" action="/broadbandAdmin/index.php/customer/admin">
    <input type="text" id="Customer_search" name="Customer[search]" value="" />
    <input type="submit" value="Search" />
  </form>
  <div class="results">Results for: ${searchVal}</div>
</body>
</html>`
              };
            }

            // Protected Post-Login Page 2: POST Form with CSRF (/broadbandAdmin/index.php/router/update)
            if (reqInfo.pathname === '/broadbandAdmin/index.php/router/update') {
              if (!isAuthed) {
                return { status: 302, headers: { Location: '/broadbandAdmin/index.php/site/login' }, body: '' };
              }
              visitedAuthenticatedPaths.add(reqInfo.pathname);
              if (reqInfo.method === 'POST') {
                const bodyParams = Object.fromEntries(new URLSearchParams(reqInfo.body || '').entries());
                const hostVal = bodyParams['Router[hostname]'] || '';
                if (bodyParams.YII_CSRF_TOKEN === 'yii_csrf_tok_1' && hostVal.includes("'")) {
                  return {
                    status: 500,
                    headers: { 'Content-Type': 'text/html; charset=utf-8' },
                    body: 'CDbCommand failed to execute the SQL statement: SQLSTATE[42000]: You have an error in your SQL syntax near ' + hostVal
                  };
                }
                return { status: 200, body: 'Router updated OK' };
              }
              return {
                status: 200,
                headers: { 'Content-Type': 'text/html; charset=utf-8' },
                body: `<!DOCTYPE html>
<html>
<body>
  <h1>Update Router Configuration</h1>
  <form method="post" action="/broadbandAdmin/index.php/router/update">
    <input type="hidden" name="YII_CSRF_TOKEN" value="yii_csrf_tok_1" />
    <input type="text" id="Router_hostname" name="Router[hostname]" value="edge-router-01" />
    <button type="submit">Save Router</button>
  </form>
</body>
</html>`
              };
            }

            return { status: 404, body: 'Not Found' };
          }
        },
        async (mockTarget) => {
          const loginUrl = `${mockTarget.baseUrl}/broadbandAdmin/index.php/site/login`;

          await withAppHarness({}, async (app) => {
            // 1. Inspect the Yii login page and verify YII_CSRF_TOKEN + LoginForm_username + yt0 button are detected
            const inspectRes = await app.jsonFetch('/api/auth/inspect-page', {
              method: 'POST',
              body: { targetUrl: loginUrl, allowPrivate: true }
            });
            assert.equal(inspectRes.status, 200);
            assert.equal(inspectRes.data.csrf.formField, 'YII_CSRF_TOKEN');
            assert.ok(inspectRes.data.inputs.some(i => i.id === 'LoginForm_username' && i.name === 'LoginForm[username]'));
            assert.ok(inspectRes.data.buttons.some(b => b.name === 'yt0' && b.text === 'Login'));

            // 2. Launch a scan directly targeting the login URL (/broadbandAdmin/index.php/site/login) with an .lsr sequence
            const yiiLsr = {
              name: 'BroadbandAdminYii.lsr',
              targetUrl: loginUrl,
              actions: [
                { type: 'navigate', url: loginUrl },
                { type: 'change_input', selectorType: 'id', selector: 'LoginForm_username', fieldName: 'LoginForm_username', value: 'al13456' },
                { type: 'change_input', selectorType: 'id', selector: 'LoginForm_password', fieldName: 'LoginForm_password', value: 'YiiAdminSecret!2026', isSecret: true },
                { type: 'click_button', selectorType: 'text', selector: 'Login' }
              ],
              restrictions: ['/broadbandAdmin/index.php/site/logout']
            };

            const startScanRes = await app.jsonFetch('/api/scan', {
              method: 'POST',
              body: {
                target: loginUrl,
                allowPrivate: true,
                noHistory: true,
                maxDepth: 1,
                checks: ['xss', 'sqli'],
                loginSequence: yiiLsr,
                jev: ALL_JEV_TRUE
              }
            });
            assert.equal(startScanRes.status, 202);
            const scanId = startScanRes.data.scanId || startScanRes.data.id;
            assert.ok(scanId);

            let scanRes = null;
            for (let i = 0; i < 200; i++) {
              const pollRes = await app.jsonFetch(`/api/scan/${scanId}`);
              if (
                pollRes.data?.status === 'completed' ||
                pollRes.data?.status === 'done' ||
                pollRes.data?.status === 'failed' ||
                pollRes.data?.status === 'error'
              ) {
                scanRes = pollRes.data;
                break;
              }
              await new Promise(r => setTimeout(r, 100));
            }
            assert.ok(scanRes, 'Expected Yii post-login scan job to complete');

            assert.equal(scanRes.status, 'completed');
            assert.equal(scanRes.result.authSession.authenticated, true, 'Expected Yii .lsr login to authenticate PHPSESSID');
            assert.match(scanRes.result.authSession.postLoginUrl || '', /\/broadbandAdmin\/index\.php\/site\/index$/);
            assert.equal(logoutEndpointCalled, false, 'Expected logout links (/site/logout and ?r=site/logout) to be skipped');

            // Verify PHP tech stack was detected from /index.php + PHPSESSID + YII_CSRF_TOKEN
            assert.ok(
              scanRes.result.stacks[0].detectedTags.includes('php'),
              `Expected PHP tag to be detected on Yii target (got ${JSON.stringify(scanRes.result.stacks[0].detectedTags)})`
            );

            // Verify post-login pages were crawled even though target was /broadbandAdmin/index.php/site/login
            assert.equal(visitedAuthenticatedPaths.has('/broadbandAdmin/index.php/site/index'), true);
            assert.equal(visitedAuthenticatedPaths.has('/broadbandAdmin/index.php/customer/admin'), true);
            assert.equal(visitedAuthenticatedPaths.has('/broadbandAdmin/index.php/router/update'), true);

            // Verify discoveredMenus and discoveredForms are populated in scanRes.result
            assert.ok(Array.isArray(scanRes.result.discoveredMenus) && scanRes.result.discoveredMenus.length >= 3);
            assert.ok(scanRes.result.discoveredMenus.some(m => m.label === 'Manage Customers' && m.auditStatus === 'crawled'));
            assert.ok(scanRes.result.discoveredMenus.some(m => m.label === 'Router Settings' && m.auditStatus === 'crawled'));
            assert.ok(scanRes.result.discoveredMenus.some(m => m.kind === 'logout' && m.auditStatus === 'logout_protected'));

            assert.ok(Array.isArray(scanRes.result.discoveredForms) && scanRes.result.discoveredForms.length >= 2);
            assert.ok(scanRes.result.discoveredForms.some(f => f.method === 'GET' && f.fields.some(fld => fld.name === 'Customer[search]')));
            assert.ok(scanRes.result.discoveredForms.some(f => f.method === 'POST' && f.csrfField === 'YII_CSRF_TOKEN' && f.fields.some(fld => fld.name === 'Router[hostname]')));

            // Verify GET form on /customer/admin was synthesized and fuzzed (finding reflected XSS on Customer[search])
            const xssVulnerable = scanRes.result.results.find(
              r => r.checkId === 'xss' && r.status === 'VULNERABLE'
            );
            assert.ok(xssVulnerable, 'Expected reflected XSS to be detected on post-login GET form Customer[search]');

            // Verify POST form on /router/update was fuzzed with YII_CSRF_TOKEN preserved (finding SQLi on Router[hostname])
            const sqliVulnerable = scanRes.result.results.find(
              r => r.checkId === 'sqli' && r.status === 'VULNERABLE'
            );
            assert.ok(sqliVulnerable, 'Expected SQL injection to be detected on post-login POST form Router[hostname]');

            // Verify automatic in-scan RBAC/BFLA matrix ran on discovered menus & forms without triggering logout
            assert.ok(scanRes.result.rbacMatrix, 'Expected rbacMatrix to be populated on authenticated scan result');
            assert.ok(scanRes.result.rbacMatrix.summary.enforcedCount >= 2);
            const logoutMenuEntry = scanRes.result.discoveredMenus.find(m => m.kind === 'logout');
            assert.equal(logoutMenuEntry?.accessControlStatus, 'skipped');
          });
        }
      );
    });

    test('2.13 Multi-Role RBAC/BFLA Access Control Matrix & Zero-Touch SBOM CVE Drift Monitor (/api/asm/sbom & /api/asm/rbac-audit)', async () => {
      const { auditMenuAndFormAccessControl } = await import('../../core/rbac-matrix.js');
      const { buildSbomAndCveDriftReport } = await import('../../core/sbom-monitor.js');

      // 1. Direct unit test of auditMenuAndFormAccessControl (enforced vs bfla_unauthenticated vs bfla_low_privilege vs skipped logout)
      let destructiveCalled = false;
      const menus = [
        { parentMenu: 'Manage Tools', label: 'Providers Configuration', kind: 'submenu', url: 'https://portal.example.com/admin/config' },
        { parentMenu: 'Manage Tools', label: 'Unprotected Zip Export', kind: 'submenu', url: 'https://portal.example.com/admin/zip-export' },
        { parentMenu: 'Manage Tools', label: 'Role Leak Audit Log', kind: 'submenu', url: 'https://portal.example.com/admin/audit-log' },
        { parentMenu: 'Account', label: 'Logout', kind: 'logout', url: 'https://portal.example.com/site/logout' },
        { parentMenu: 'Danger', label: 'Purge All', kind: 'submenu', url: 'https://portal.example.com/admin/delete-all' }
      ];
      const forms = [
        { formName: 'Save Config', method: 'POST', actionUrl: 'https://portal.example.com/admin/config' }
      ];

      const mockRbacFetch = async (url, opts = {}) => {
        if (url.includes('logout') || url.includes('delete')) {
          destructiveCalled = true;
        }
        const cookie = String(opts.headers?.Cookie || opts.headers?.cookie || '');
        if (url === 'https://portal.example.com/admin/config') {
          return { status: 302, headers: { location: '/site/login' }, text: '' };
        }
        if (url === 'https://portal.example.com/admin/zip-export') {
          // Vulnerable to unauthenticated BFLA!
          return {
            status: 200,
            headers: { 'content-type': 'application/json' },
            text: JSON.stringify({ zips: ['33101', '90210'] })
          };
        }
        if (url === 'https://portal.example.com/admin/audit-log') {
          if (cookie.includes('role=low_priv')) {
            // Vulnerable to low-privilege vertical BFLA!
            return {
              status: 200,
              headers: { 'content-type': 'text/html' },
              text: '<html><body><h1>Internal Audit Log Table</h1></body></html>'
            };
          }
          return { status: 403, headers: { 'content-type': 'text/html' }, text: 'Forbidden' };
        }
        return { status: 404, headers: {}, text: 'Not Found' };
      };

      const rbacReport = await auditMenuAndFormAccessControl({
        discoveredMenus: menus,
        discoveredForms: forms,
        unauthFetch: mockRbacFetch,
        secondaryAuthHeaders: { Cookie: 'role=low_priv' }
      });

      assert.equal(destructiveCalled, false, 'Destructive/logout URLs must never be probed');
      assert.equal(rbacReport.summary.status, 'VULNERABLE');
      assert.equal(rbacReport.summary.enforcedCount, 2); // menu + form for /admin/config
      assert.equal(rbacReport.summary.unauthenticatedBflaCount, 1); // /admin/zip-export
      assert.equal(rbacReport.summary.lowPrivilegeBflaCount, 1); // /admin/audit-log
      assert.equal(rbacReport.summary.skippedCount, 2); // logout + delete-all
      assert.equal(rbacReport.findings.length, 2);
      assert.ok(rbacReport.findings.some(f => f.accessControlStatus === 'bfla_unauthenticated' && f.cwe === 'CWE-285'));
      assert.ok(rbacReport.findings.some(f => f.accessControlStatus === 'bfla_low_privilege' && f.cwe === 'CWE-285'));

      // 2. Direct unit test of buildSbomAndCveDriftReport (Zero-Touch in-memory CVE drift monitor)
      const sbomReport = buildSbomAndCveDriftReport([
        {
          id: 'hist-1',
          timestamp: '2026-11-25T12:00:00Z',
          targets: ['https://satprocess.com/broadbandAdmin/index.php'],
          runtimeSca: {
            findings: [
              { key: 'yii', tech: 'Yii PHP Framework', version: '2.0.45', category: 'Framework', source: 'composer.lock' },
              { key: 'php', tech: 'PHP', version: '8.2.10', category: 'Runtime', source: 'X-Powered-By' }
            ]
          }
        }
      ]);

      assert.equal(sbomReport.zeroTouchMode, true);
      assert.equal(sbomReport.totalTargets, 1);
      assert.equal(sbomReport.vulnerableTargetsCount, 1);
      assert.equal(sbomReport.outOfDateComponentsCount, 2);
      assert.equal(sbomReport.vulnerableComponentsCount, 2);
      assert.ok(sbomReport.driftAlerts.some(a => a.cveIds.includes('CVE-2024-58136')));

      // 3. Test REST endpoints GET /api/asm/sbom and POST /api/asm/rbac-audit
      await withMockTarget(
        {
          routes: (reqInfo) => {
            if (reqInfo.pathname === '/admin/protected') {
              return { status: 401, body: 'Unauthorized' };
            }
            if (reqInfo.pathname === '/admin/leaked-panel') {
              return {
                status: 200,
                headers: { 'Content-Type': 'text/html' },
                body: '<html><body><h1>Admin Panel Without Auth Check</h1></body></html>'
              };
            }
            return { status: 404, body: 'Not Found' };
          }
        },
        async (mockSrv) => {
          await withAppHarness({}, async (app) => {
            const sbomApiRes = await app.jsonFetch('/api/asm/sbom');
            assert.equal(sbomApiRes.status, 200);
            assert.equal(sbomApiRes.data.zeroTouchMode, true);
            assert.ok(Array.isArray(sbomApiRes.data.targets));

            const rbacApiRes = await app.jsonFetch('/api/asm/rbac-audit', {
              method: 'POST',
              body: {
                allowPrivate: true,
                discoveredMenus: [
                  { parentMenu: 'Admin', label: 'Protected Settings', kind: 'submenu', url: `${mockSrv.baseUrl}/admin/protected` },
                  { parentMenu: 'Admin', label: 'Leaked Panel', kind: 'submenu', url: `${mockSrv.baseUrl}/admin/leaked-panel` },
                  { parentMenu: 'Admin', label: 'Logout', kind: 'logout', url: `${mockSrv.baseUrl}/admin/logout` }
                ],
                discoveredForms: []
              }
            });
            assert.equal(rbacApiRes.status, 200);
            assert.equal(rbacApiRes.data.rbacMatrix.summary.enforcedCount, 1);
            assert.equal(rbacApiRes.data.rbacMatrix.summary.unauthenticatedBflaCount, 1);
            assert.equal(rbacApiRes.data.rbacMatrix.summary.skippedCount, 1);

            // Verify SSRF block when allowPrivate is false on private loopback URL
            const ssrfBlockedRes = await app.jsonFetch('/api/asm/rbac-audit', {
              method: 'POST',
              body: {
                allowPrivate: false,
                discoveredMenus: [
                  { parentMenu: 'Admin', label: 'Internal', kind: 'submenu', url: `${mockSrv.baseUrl}/admin/protected` }
                ]
              }
            });
            assert.ok(ssrfBlockedRes.status === 400 || ssrfBlockedRes.status === 403);
          });
        }
      );
    });

    test('2.14 Token, Cookie & WebStorage (localStorage / sessionStorage) Harvester + JWT Expiry Inspection & Origin-Scoped Session Lookup', async () => {
      const {
        inspectExtractedJwtMeta,
        extractWebStorageAndTokensFromResponse,
        AuthSessionManager
      } = await import('../../core/auth-session.js');

      // 1. Verify inspectExtractedJwtMeta decodes valid 3-part JWTs and checks exp
      const futureExp = Math.floor(Date.now() / 1000) + 3600;
      const headerB64 = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
      const payloadB64 = Buffer.from(JSON.stringify({ sub: 'admin@satprocess.com', iss: 'broadband-sso', exp: futureExp })).toString('base64url');
      const validJwt = `${headerB64}.${payloadB64}.sig_test_123`;

      const jwtMeta = inspectExtractedJwtMeta(validJwt);
      assert.equal(jwtMeta.isJwt, true);
      assert.equal(jwtMeta.alg, 'HS256');
      assert.equal(jwtMeta.subject, 'admin@satprocess.com');
      assert.equal(jwtMeta.issuer, 'broadband-sso');
      assert.equal(jwtMeta.isExpired, false);
      assert.ok(jwtMeta.remainingSeconds > 3500);

      // 2. Verify extractWebStorageAndTokensFromResponse extracts localStorage, sessionStorage, headers, and URL hash tokens
      const spaLoginHtml = `
        <html>
        <body>
          <script>
            localStorage.setItem('access_token', '${validJwt}');
            window.localStorage['tenant_id'] = 'broadband_prod';
            sessionStorage.setItem('csrf_session_token', 'sess_tok_998877');
          </script>
        </body>
        </html>
      `;
      const extracted = extractWebStorageAndTokensFromResponse(
        spaLoginHtml,
        { 'x-auth-token': 'hdr_api_token_555' },
        'https://portal.example.com/dashboard#id_token=hash_id_tok_777'
      );
      assert.equal(extracted.localStorageItems.access_token, validJwt);
      assert.equal(extracted.localStorageItems.tenant_id, 'broadband_prod');
      assert.equal(extracted.sessionStorageItems.csrf_session_token, 'sess_tok_998877');
      assert.ok(extracted.extractedTokens.some(t => t.source === 'local_storage' && t.key === 'access_token'));
      assert.ok(extracted.extractedTokens.some(t => t.source === 'header' && t.key === 'x-auth-token'));
      assert.ok(extracted.extractedTokens.some(t => t.source === 'url' && t.key === 'id_token'));

      // 3. Verify .lsr extract_token step with source: 'local_storage' promotes localStorage token to bearerToken
      const mgr = new AuthSessionManager({
        targetUrl: 'https://portal.example.com/login',
        loginSequence: {
          name: 'SpaLocalStorageAuth.lsr',
          targetUrl: 'https://portal.example.com/login',
          actions: [
            { type: 'navigate', url: 'https://portal.example.com/login' },
            { type: 'extract_token', source: 'local_storage', key: 'access_token' }
          ]
        }
      });

      const seqOutcome = await mgr.executeLoginSequence(async () => ({
        status: 200,
        url: 'https://portal.example.com/login',
        headers: { 'set-cookie': 'PHPSESSID=spa_sess_42; Path=/; HttpOnly' },
        text: spaLoginHtml
      }));
      assert.equal(seqOutcome.authenticated, true);
      assert.equal(mgr.bearerToken, validJwt);
      assert.equal(seqOutcome.jwtMeta.isJwt, true);
      assert.equal(seqOutcome.jwtMeta.subject, 'admin@satprocess.com');

      const fullSession = mgr.getRecordedSession({ includeSecrets: true });
      assert.equal(fullSession.authArtifacts.hasToken, true);
      assert.equal(fullSession.authArtifacts.hasCookies, true);
      assert.equal(fullSession.authArtifacts.hasLocalStorage, true);
      assert.equal(fullSession.authArtifacts.bearerToken, validJwt);
      assert.match(fullSession.authArtifacts.cookieHeader, /PHPSESSID=spa_sess_42/);
      assert.equal(fullSession.authArtifacts.localStorageItems.access_token, validJwt);

      // 4. Verify POST /api/auth/record-session (includeArtifactValues: true) & GET /api/auth/sessions?includeArtifactValues=1&origin=...
      await withAppHarness({}, async (app) => {
        const demoUrl = `${app.baseUrl}/api/auth/demo-login`;
        const recRes = await app.jsonFetch('/api/auth/record-session', {
          method: 'POST',
          body: {
            targetUrl: demoUrl,
            allowPrivate: true,
            includeArtifactValues: true,
            loginSequence: {
              name: 'DemoTokenHarvest.lsr',
              targetUrl: demoUrl,
              otpConfig: {
                enabled: true,
                secret: 'JBSWY3DPEHPK3PXP',
                digits: 6,
                period: 30,
                algorithm: 'SHA1',
                inputSelector: 'otp_code'
              },
              actions: [
                { type: 'navigate', url: demoUrl },
                { type: 'change_input', selectorType: 'id', selector: 'email', value: 'auditor@infsalesgroup.com' },
                { type: 'change_input', selectorType: 'id', selector: 'password', value: 'DemoEnterprisePass2026!', isSecret: true },
                { type: 'fill_otp', selectorType: 'id', selector: 'otp_code' },
                { type: 'click_button', selectorType: 'text', selector: 'Log In' }
              ]
            }
          }
        });
        assert.equal(recRes.status, 200);
        assert.equal(recRes.data.authenticated, true);
        assert.equal(recRes.data.password, '[REDACTED]');
        assert.ok(recRes.data.authArtifacts, 'Expected authArtifacts in record-session response');
        assert.equal(recRes.data.authArtifacts.hasToken, true);
        assert.equal(recRes.data.authArtifacts.hasCookies, true);
        assert.equal(recRes.data.authArtifacts.hasLocalStorage, true);
        assert.ok(recRes.data.authArtifacts.bearerToken);
        assert.ok(recRes.data.authArtifacts.cookieHeader.includes('SECSCAN_DEMO_SESSION='));
        assert.ok(recRes.data.authArtifacts.localStorageItems.demo_access_token);

        // Query active sessions filtered by origin
        const sessListRes = await app.jsonFetch('/api/auth/sessions?includeArtifactValues=1');
        assert.equal(sessListRes.status, 200);
        assert.ok(sessListRes.data.sessions.length >= 1);
        assert.ok(sessListRes.data.sessions[0].authArtifacts?.bearerToken);

        // Query with non-matching origin must return 0 sessions (origin isolation)
        const otherOriginRes = await app.jsonFetch('/api/auth/sessions?includeArtifactValues=1&origin=https://unrelated-origin.example.org');
        assert.equal(otherOriginRes.status, 200);
        assert.equal(otherOriginRes.data.sessions.length, 0);
      });
    });

    test('3.7 Target Systems Registry, 1-Click Clone, Delta Fix Verification (open_issues_only vs full_profile) & Scheduler API', async () => {
      const {
        normalizeTargetSystem,
        cloneTargetSystemConfig,
        computeNextScheduleRunAt,
        extractUnfixedChecksFromResults,
        mergeDeltaScanSummary,
        resolveChecksForTargetSystemRun,
        exportTargetSystem
      } = await import('../../core/target-systems.js');

      // 1) Unit tests for core/target-systems.js
      const baseNow = new Date('2026-11-26T00:00:00.000Z');
      const nextDaily = computeNextScheduleRunAt({ enabled: true, interval: 'daily' }, baseNow);
      assert.equal(nextDaily, '2026-11-27T00:00:00.000Z');
      assert.equal(computeNextScheduleRunAt({ enabled: false, interval: 'daily' }, baseNow), null);

      const sys = normalizeTargetSystem({
        name: 'Broadband Portal Prod',
        environment: 'production',
        targetUrl: 'https://portal.example.com/broadbandAdmin/index.php',
        profile: 'smart',
        allowPrivate: false,
        sequenceId: 'seq_yii_123',
        sequenceName: 'BroadbandYii.lsr',
        authHeader: 'Bearer super_secret_token_999',
        customHeaders: {
          Authorization: 'Bearer custom_hdr_secret',
          'X-Api-Key': 'api_key_secret_123',
          'X-Tenant-Id': 'broadband-us'
        },
        schedule: {
          interval: 'daily',
          mode: 'open_issues_only'
        }
      });

      assert.match(sys.id, /^ts_/);
      assert.equal(sys.environment, 'production');
      assert.equal(sys.authMethod, 'lsr');
      assert.equal(sys.schedule.enabled, true);
      assert.equal(sys.schedule.interval, 'daily');
      assert.equal(sys.schedule.intervalMinutes, 1440);
      assert.equal(sys.schedule.mode, 'open_issues_only');
      assert.ok(sys.schedule.nextRunAt);

      // Verify exportTargetSystem masks secrets when includeSecrets: false
      const exportedPublic = exportTargetSystem(sys, { includeSecrets: false });
      assert.equal(exportedPublic.hasAuthHeader, true);
      assert.equal(exportedPublic.authHeader, '[REDACTED]');
      assert.equal(exportedPublic.customHeaders.Authorization, '[REDACTED]');
      assert.equal(exportedPublic.customHeaders['X-Api-Key'], '[REDACTED]');
      assert.equal(exportedPublic.customHeaders['X-Tenant-Id'], 'broadband-us');

      // Verify normalizeTargetSystem preserves existing unredacted secrets when updated with '[REDACTED]'
      const updatedSys = normalizeTargetSystem(
        {
          name: 'Broadband Portal Prod v2',
          authHeader: '[REDACTED]',
          customHeaders: {
            Authorization: '[REDACTED]',
            'X-Api-Key': '[REDACTED]',
            'X-Tenant-Id': 'broadband-eu'
          }
        },
        sys
      );
      assert.equal(updatedSys.authHeader, 'Bearer super_secret_token_999');
      assert.equal(updatedSys.customHeaders.Authorization, 'Bearer custom_hdr_secret');
      assert.equal(updatedSys.customHeaders['X-Api-Key'], 'api_key_secret_123');
      assert.equal(updatedSys.customHeaders['X-Tenant-Id'], 'broadband-eu');

      // Verify extractUnfixedChecksFromResults and mergeDeltaScanSummary (full_profile -> open_issues_only delta)
      const initialScanResults = [
        { checkId: 'xss', name: 'Reflected XSS', status: 'VULNERABLE', severity: 'HIGH', category: 'Injection' },
        { checkId: 'sqli', name: 'SQL Injection', status: 'VULNERABLE', severity: 'CRITICAL', category: 'Injection' },
        { checkId: 'cors', name: 'CORS Misconfiguration', status: 'SUSPICIOUS', severity: 'MEDIUM', category: 'Configuration' },
        { checkId: 'ssl-tls', name: 'SSL/TLS', status: 'SAFE', severity: 'NONE', category: 'Transport' }
      ];
      const extracted = extractUnfixedChecksFromResults(initialScanResults);
      assert.deepEqual(extracted.unfixedCheckIds, ['xss', 'sqli', 'cors']);
      assert.equal(extracted.vulnerableCount, 2);
      assert.equal(extracted.suspiciousCount, 1);

      const summaryAfterFull = mergeDeltaScanSummary(
        null,
        {
          scanId: 'scan_full_1',
          results: initialScanResults,
          risk: { grade: 'D', level: 'HIGH', score: 68 }
        },
        'full_profile'
      );
      assert.deepEqual(summaryAfterFull.unfixedCheckIds, ['xss', 'sqli', 'cors']);
      assert.equal(summaryAfterFull.fixedInLastRunCount, 0);

      // Now simulate an open_issues_only re-scan that tests ['xss', 'sqli'] where 'xss' is now SAFE and 'sqli' is still VULNERABLE,
      // while 'cors' was not re-tested in this partial run:
      // - 'xss' must be removed from unfixedCheckIds and recorded in fixedInLastRunCheckIds
      // - 'sqli' (still vulnerable) and 'cors' (untested open check) must remain in unfixedCheckIds
      const deltaSummary = mergeDeltaScanSummary(
        summaryAfterFull,
        {
          scanId: 'scan_delta_2',
          results: [
            { checkId: 'xss', name: 'Reflected XSS', status: 'SAFE', severity: 'NONE', category: 'Injection' },
            { checkId: 'sqli', name: 'SQL Injection', status: 'VULNERABLE', severity: 'CRITICAL', category: 'Injection' }
          ],
          risk: { grade: 'C', level: 'MEDIUM', score: 35 }
        },
        'open_issues_only',
        ['xss', 'sqli']
      );
      assert.deepEqual(deltaSummary.fixedInLastRunCheckIds, ['xss']);
      assert.equal(deltaSummary.fixedInLastRunCount, 1);
      assert.deepEqual(deltaSummary.unfixedCheckIds, ['sqli', 'cors']);

      // Verify resolveChecksForTargetSystemRun
      const sysWithSummary = normalizeTargetSystem({ ...sys, lastScanSummary: deltaSummary }, sys);
      const resolvedOpenOnly = resolveChecksForTargetSystemRun(sysWithSummary, 'open_issues_only');
      assert.deepEqual(resolvedOpenOnly.checks, ['sqli', 'cors']);
      assert.equal(resolvedOpenOnly.fallbackToFullProfile, false);

      // Verify cloneTargetSystemConfig creates fresh ID, applies overrides, and disables schedule by default
      const clonedSys = cloneTargetSystemConfig(sysWithSummary, {
        name: 'Broadband Portal Staging',
        environment: 'staging',
        targetUrl: 'https://staging-portal.example.com/broadbandAdmin/index.php',
        copyUnfixedChecks: true
      });
      assert.notEqual(clonedSys.id, sysWithSummary.id);
      assert.equal(clonedSys.name, 'Broadband Portal Staging');
      assert.equal(clonedSys.environment, 'staging');
      assert.equal(clonedSys.targetUrl, 'https://staging-portal.example.com/broadbandAdmin/index.php');
      assert.equal(clonedSys.schedule.enabled, false);
      assert.equal(clonedSys.lastScanSummary, null);
      assert.deepEqual(clonedSys.checks, ['sqli', 'cors']);

      // 2) End-to-End Server API & Scheduler tests (/api/target-systems)
      await withMockTarget(
        {
          routes: () => ({
            status: 200,
            headers: {
              'Content-Type': 'text/html',
              Server: 'nginx/1.24.0'
            },
            body: '<!doctype html><html><head><script src="/jquery-3.4.1.min.js"></script></head><body>Portal</body></html>'
          })
        },
        async (mockTarget) => {
          await withAppHarness({ inMemory: true }, async (app) => {
            // A) POST /api/target-systems
            const createRes = await app.jsonFetch('/api/target-systems', {
              method: 'POST',
              body: {
                name: 'Prod Broadband System',
                environment: 'production',
                targetUrl: mockTarget.baseUrl,
                allowPrivate: true,
                profile: 'smart',
                maxDepth: 0,
                customHeaders: {
                  Authorization: 'Bearer secret_prod_jwt',
                  'X-Env': 'prod'
                },
                schedule: {
                  interval: 'daily',
                  mode: 'open_issues_only'
                },
                lastScanSummary: {
                  lastGrade: 'C',
                  unfixedChecks: [
                    { id: 'runtime-sca', name: 'Runtime SCA', status: 'VULNERABLE', severity: 'MEDIUM', category: 'Supply Chain' }
                  ]
                }
              }
            });
            assert.equal(createRes.status, 201);
            const createdSys = createRes.data.system;
            assert.ok(createdSys?.id);
            assert.equal(createdSys.customHeaders.Authorization, '[REDACTED]');
            assert.equal(createdSys.customHeaders['X-Env'], 'prod');
            assert.equal(createdSys.schedule.enabled, true);
            assert.equal(createdSys.schedule.interval, 'daily');
            assert.deepEqual(createdSys.lastScanSummary.unfixedCheckIds, ['runtime-sca']);

            // B) GET /api/target-systems lists the system with redacted secrets
            const listRes = await app.jsonFetch('/api/target-systems');
            assert.equal(listRes.status, 200);
            assert.equal(listRes.data.systems.length, 1);
            assert.equal(listRes.data.systems[0].id, createdSys.id);
            assert.equal(listRes.data.systems[0].customHeaders.Authorization, '[REDACTED]');

            // C) POST /api/target-systems/:id/clone clones with overrides and disables schedule by default
            const cloneRes = await app.jsonFetch(`/api/target-systems/${encodeURIComponent(createdSys.id)}/clone`, {
              method: 'POST',
              body: {
                name: 'Staging Broadband Clone',
                environment: 'staging',
                targetUrl: `${mockTarget.baseUrl}/staging`,
                copyUnfixedChecks: true
              }
            });
            assert.equal(cloneRes.status, 201);
            const cloned = cloneRes.data.system;
            assert.equal(cloneRes.data.clonedFromId, createdSys.id);
            assert.notEqual(cloned.id, createdSys.id);
            assert.equal(cloned.name, 'Staging Broadband Clone');
            assert.equal(cloned.environment, 'staging');
            assert.equal(cloned.schedule.enabled, false);
            assert.deepEqual(cloned.checks, ['runtime-sca']);

            // D) PUT /api/target-systems/:id updates schedule/config and preserves redacted secret headers
            const putRes = await app.jsonFetch(`/api/target-systems/${encodeURIComponent(createdSys.id)}`, {
              method: 'PUT',
              body: {
                name: 'Prod Broadband System (Updated)',
                customHeaders: {
                  Authorization: '[REDACTED]',
                  'X-Env': 'prod-v2'
                },
                schedule: {
                  interval: 'every_6h',
                  mode: 'open_issues_only'
                }
              }
            });
            assert.equal(putRes.status, 200);
            assert.equal(putRes.data.system.name, 'Prod Broadband System (Updated)');
            assert.equal(putRes.data.system.schedule.interval, 'every_6h');
            assert.equal(putRes.data.system.customHeaders['X-Env'], 'prod-v2');

            // E) POST /api/target-systems/:id/run (mode: 'open_issues_only') launches delta verification scan
            const runRes = await app.jsonFetch(`/api/target-systems/${encodeURIComponent(createdSys.id)}/run`, {
              method: 'POST',
              body: {
                mode: 'open_issues_only'
              }
            });
            assert.equal(runRes.status, 202);
            assert.equal(runRes.data.mode, 'open_issues_only');
            assert.deepEqual(runRes.data.checks, ['runtime-sca']);
            const scanId = runRes.data.scanId;
            assert.ok(scanId);

            // Wait for scan job completion and verify lastScanSummary is updated on the Target System
            let finishedJob = null;
            for (let i = 0; i < 60; i++) {
              const pollRes = await app.jsonFetch(`/api/scan/${scanId}`);
              if (['completed', 'done', 'failed', 'error'].includes(pollRes.data?.status)) {
                finishedJob = pollRes.data;
                break;
              }
              await new Promise(r => setTimeout(r, 100));
            }
            assert.ok(finishedJob, 'Expected target-system delta verification scan to finish');
            assert.ok(['completed', 'done'].includes(finishedJob.status));

            const getUpdatedSys = await app.jsonFetch(`/api/target-systems/${encodeURIComponent(createdSys.id)}`);
            assert.equal(getUpdatedSys.status, 200);
            assert.equal(getUpdatedSys.data.system.lastScanSummary.lastScanId, scanId);
            assert.equal(getUpdatedSys.data.system.lastScanSummary.lastMode, 'open_issues_only');
            assert.ok(getUpdatedSys.data.system.lastScanSummary.unfixedCheckIds.includes('runtime-sca'));

            // F) DELETE /api/target-systems/:id deletes the cloned system
            const delCloneRes = await app.jsonFetch(`/api/target-systems/${encodeURIComponent(cloned.id)}`, {
              method: 'DELETE'
            });
            assert.equal(delCloneRes.status, 200);
            assert.equal(delCloneRes.data.deleted, true);

            const afterDelList = await app.jsonFetch('/api/target-systems');
            assert.equal(afterDelList.data.systems.length, 1);
            assert.equal(afterDelList.data.systems[0].id, createdSys.id);
          });
        }
      );
    });
  });
});
