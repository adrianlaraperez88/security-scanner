import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  escapeHtml,
  renderCategoryPills,
  formatClientCsvCell,
  buildClientCsvReport,
  parseCustomHeadersInput,
  buildClientSarifReport,
  renderApiCommunicationSection,
  renderApiAiOutput,
  handleScanOriginTrigger,
  normalizeTargetScheme,
  isBareIpInput,
  preserveBareIpOrNormalize,
  normalizeStacksList,
  renderDeviceInfoHtml,
  renderMatchedEvidenceHtml,
  renderScanResults,
  getCanonicalOrigin,
  scanBrowserWebStorageForTokens,
  renderAuthArtifactsCard,
  renderTargetSystemsUi,
  openLsrStudioDetailView,
  closeLsrStudioDetailView,
  renderLsrInlineStepsSummary
} from '../../ui/app.js';
import {
  renderCveCoveragePanel,
  buildCoverageQueryUrl,
  flattenAuditRows,
  filterCveRows,
  parseCustomAdvisoriesInput
} from '../../ui/components/cve-coverage.js';
import { buildAiFixHtml } from '../../ui/components/evidence-viewer.js';
import {
  renderSystemGuardrails,
  inferRuleType,
  serializeScopeRules,
  parseScopeRulesText,
  getProviderModelHint
} from '../../ui/components/system-guardrails.js';
import { evaluateAssetGate } from '../../core/guard.js';
import { normalizeTargetInput } from '../../core/validator.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '../..');
const UI_DIR = path.join(REPO_ROOT, 'ui');
const UI_COMPONENTS_DIR = path.join(UI_DIR, 'components');

const ALL_7_TABS = [
  'new-scan',
  'scan-results',
  'tasks-sessions',
  'dual-graph',
  'traffic-replay',
  'history',
  'catalog'
];

describe('UI Components, Accessibility, CSP Hygiene & CVE Coverage (M5)', () => {
  test('escapeHtml escapes HTML special characters and handles nullish/numeric inputs', () => {
    assert.equal(escapeHtml(null), '');
    assert.equal(escapeHtml(undefined), '');
    assert.equal(escapeHtml(42), '42');
    assert.equal(
      escapeHtml('<script>alert("xss" & \'test\')</script>'),
      '&lt;script&gt;alert(&quot;xss&quot; &amp; &#39;test&#39;)&lt;/script&gt;'
    );
  });

  test('ui/index.html defines all 7 tabs with matching WAI-ARIA tablist/tab/tabpanel attributes', () => {
    const html = fs.readFileSync(path.join(UI_DIR, 'index.html'), 'utf8');
    assert.match(html, /<nav[^>]*class="nav-tabs"[^>]*role="tablist"/);

    for (const tab of ALL_7_TABS) {
      assert.match(
        html,
        new RegExp(`id="tab-btn-${tab}"`),
        `Missing id="tab-btn-${tab}" on tab button`
      );
      assert.match(
        html,
        new RegExp(`data-tab="${tab}"[^>]*role="tab"|role="tab"[^>]*data-tab="${tab}"`),
        `Missing role="tab" for ${tab}`
      );
      assert.match(
        html,
        new RegExp(`aria-controls="tab-${tab}"`),
        `Missing aria-controls="tab-${tab}"`
      );
      assert.match(
        html,
        new RegExp(`id="tab-${tab}"[^>]*role="tabpanel"|role="tabpanel"[^>]*id="tab-${tab}"`),
        `Missing role="tabpanel" for #tab-${tab}`
      );
      assert.match(
        html,
        new RegExp(`aria-labelledby="tab-btn-${tab}"`),
        `Missing aria-labelledby="tab-btn-${tab}"`
      );
    }
  });

  test('ui/index.html removes hardcoded 54 check counts and exposes CVE Coverage UI hooks', () => {
    const html = fs.readFileSync(path.join(UI_DIR, 'index.html'), 'utf8');
    assert.equal(/All 54 vulnerability checks/i.test(html), false);
    assert.equal(/Force All 54 Checks/i.test(html), false);
    assert.match(html, /id="catalog-total-text"/);
    assert.match(html, /id="force-all-count"/);
    assert.match(html, /id="total-checks-badge"/);

    // Tab 2 CVE banner & Tab 7 CVE Coverage Audit sub-view
    assert.match(html, /id="results-cve-coverage-banner"/);
    assert.match(html, /id="btn-view-catalog-cve-coverage"/);
    assert.match(html, /id="catalog-cve-coverage-view"/);
    assert.match(html, /id="cve-coverage-root"/);

    // Distinct catalog categories filterable
    assert.ok(html.includes('Supply Chain Security'));
    assert.ok(html.includes('Network &amp; Transport'));
    assert.ok(html.includes('Injection &amp; Input'));
    assert.equal(typeof renderCategoryPills, 'function');
  });

  test('CSP & UX hygiene: zero alert/confirm/prompt/eval and zero inline on* HTML attributes across ui/', () => {
    const filesToCheck = [
      path.join(UI_DIR, 'index.html'),
      path.join(UI_DIR, 'app.js'),
      ...fs.readdirSync(UI_COMPONENTS_DIR).map(f => path.join(UI_COMPONENTS_DIR, f))
    ];

    for (const filePath of filesToCheck) {
      const content = fs.readFileSync(filePath, 'utf8');
      const rel = path.relative(REPO_ROOT, filePath);

      assert.equal(/\balert\s*\(/.test(content), false, `${rel} must not contain alert()`);
      assert.equal(/\bconfirm\s*\(/.test(content), false, `${rel} must not contain confirm()`);
      assert.equal(/\bprompt\s*\(/.test(content), false, `${rel} must not contain prompt()`);
      assert.equal(/\beval\s*\(/.test(content), false, `${rel} must not contain eval()`);
      assert.equal(/\bnew\s+Function\s*\(/.test(content), false, `${rel} must not contain new Function()`);

      if (filePath.endsWith('.html')) {
        assert.equal(/\bon[a-z]+\s*=/i.test(content), false, `${rel} must not contain inline on* attributes`);
      } else {
        // Check HTML template attributes inside JS (e.g. onclick=, onload=)
        assert.equal(
          /\s+on(?:click|change|input|submit|load|error|keydown|keyup|mouseover)\s*=/i.test(content),
          false,
          `${rel} must not inject inline on* HTML attributes`
        );
      }
    }
  });

  test('ui/app.js handles agent SSE events, cvssScore/cveIds badges, optional chaining, and 250-node feed cap', () => {
    const appJs = fs.readFileSync(path.join(UI_DIR, 'app.js'), 'utf8');
    assert.match(appJs, /'agent'/);
    assert.match(appJs, /\bcvssScore\b/);
    assert.match(appJs, /\bcveIds\b/);
    assert.match(appJs, /diff\?\./);
    assert.match(appJs, /item\?\.prev\?\./);
    assert.match(appJs, /item\?\.curr\?\./);
    assert.match(appJs, /250/);
  });

  test('ui/components/cve-coverage.js exports panel & pure helpers for query, flattening, filtering, and JSON parsing', async () => {
    assert.equal(typeof renderCveCoveragePanel, 'function');
    // Calling with null container should gracefully no-op
    await renderCveCoveragePanel(null);

    assert.equal(buildCoverageQueryUrl(), '/api/cves/coverage');
    assert.equal(buildCoverageQueryUrl({ tech: 'nextjs, spring', feed: true }), '/api/cves/coverage?tech=nextjs%2Cspring&feed=1');
    assert.equal(buildCoverageQueryUrl({ tech: ['tomcat', 'java'], feed: false }), '/api/cves/coverage?tech=tomcat%2Cjava');

    const sampleAudit = {
      missing: [
        { cveId: 'CVE-2025-11111', ecosystem: 'nextjs', severity: 'HIGH', cvssScore: 7.5, kev: false, title: 'Non-KEV missing' },
        { cveId: 'CVE-2025-29927', ecosystem: 'nextjs', severity: 'CRITICAL', cvssScore: 9.1, kev: true, title: 'Next.js KEV missing' }
      ],
      partial: [
        { cveId: 'CVE-2024-50379', ecosystem: 'tomcat', severity: 'CRITICAL', cvssScore: 9.8, kev: false, cwe: 'CWE-362', checks: ['cve-tomcat'] }
      ],
      covered: [
        { cveId: 'CVE-2026-123007', ecosystem: 'nginx', severity: 'CRITICAL', cvssScore: 9.8, kev: true, cwe: 'CWE-122', checks: ['cve-2026-123007'] }
      ]
    };

    const rows = flattenAuditRows(sampleAudit);
    assert.equal(rows.length, 4);
    assert.equal(rows[0].cveId, 'CVE-2025-29927'); // KEV missing sorted first
    assert.equal(rows[1].cveId, 'CVE-2025-11111');
    assert.equal(rows[2].status, 'partial');
    assert.equal(rows[3].status, 'covered');

    assert.equal(filterCveRows(rows, { status: 'missing' }).length, 2);
    assert.equal(filterCveRows(rows, { ecosystem: 'tomcat' }).length, 1);
    assert.equal(filterCveRows(rows, { search: 'CWE-122' })[0].cveId, 'CVE-2026-123007');
    assert.equal(filterCveRows(rows, { search: 'cve-tomcat' })[0].cveId, 'CVE-2024-50379');

    assert.equal(parseCustomAdvisoriesInput('').valid, false);
    assert.equal(parseCustomAdvisoriesInput('{bad json').valid, false);
    assert.equal(parseCustomAdvisoriesInput('{"foo":1}').valid, false);
    const arrRes = parseCustomAdvisoriesInput('[{"cveId":"CVE-2025-29927"}]');
    assert.equal(arrRes.valid, true);
    assert.equal(arrRes.advisories.length, 1);
    const wrappedRes = parseCustomAdvisoriesInput('{"advisories":[{"cveId":"CVE-2025-29927"}]}');
    assert.equal(wrappedRes.valid, true);
    assert.equal(wrappedRes.advisories.length, 1);
  });

  test('ui/components/system-guardrails.js preserves isAllowed and ruleType matching core/guard.js', () => {
    assert.equal(typeof renderSystemGuardrails, 'function');

    assert.equal(inferRuleType('10.0.0.0/8'), 'cidr');
    assert.equal(inferRuleType('2001:db8::/32'), 'cidr');
    assert.equal(inferRuleType('192.168.1.5'), 'exact_ip');
    assert.equal(inferRuleType('192.168.*'), 'fuzzy_ip');
    assert.equal(inferRuleType('*.example.com'), 'fuzzy_domain');
    assert.equal(inferRuleType('.gov'), 'fuzzy_domain');
    assert.equal(inferRuleType('api.example.com'), 'exact_domain');
    assert.equal(inferRuleType('https://api.example.com/v1'), 'exact_url');
    assert.equal(inferRuleType('https://api.example.com/v1/*'), 'fuzzy_url');

    const rulesFromCore = [
      { id: 'r1', isAllowed: false, ruleType: 'cidr', pattern: '10.0.0.0/8' },
      { id: 'r2', isAllowed: false, ruleType: 'fuzzy_domain', pattern: '*.corp.internal' },
      { id: 'r3', isAllowed: true, ruleType: 'exact_url', pattern: 'https://app.example.com/health' },
      { id: 'r4', isAllowed: true, ruleType: 'exact_domain', pattern: 'app.example.com' }
    ];

    const serialized = serializeScopeRules(rulesFromCore);
    assert.equal(
      serialized,
      [
        'deny:cidr:10.0.0.0/8',
        'deny:fuzzy_domain:*.corp.internal',
        'allow:exact_url:https://app.example.com/health',
        'allow:exact_domain:app.example.com'
      ].join('\n')
    );

    const parsed = parseScopeRulesText(
      [
        serialized,
        'deny:172.16.0.0/12',
        'allow:https://staging.example.com/api',
        'deny:2001:db8::/32'
      ].join('\n')
    );

    assert.equal(parsed[0].isAllowed, false);
    assert.equal(parsed[0].ruleType, 'cidr');
    assert.equal(parsed[0].pattern, '10.0.0.0/8');

    assert.equal(parsed[2].isAllowed, true);
    assert.equal(parsed[2].ruleType, 'exact_url');
    assert.equal(parsed[2].pattern, 'https://app.example.com/health');

    assert.equal(parsed[4].isAllowed, false);
    assert.equal(parsed[4].ruleType, 'cidr');
    assert.equal(parsed[4].pattern, '172.16.0.0/12');

    assert.equal(parsed[5].isAllowed, true);
    assert.equal(parsed[5].ruleType, 'exact_url');
    assert.equal(parsed[5].pattern, 'https://staging.example.com/api');

    assert.equal(parsed[6].isAllowed, false);
    assert.equal(parsed[6].ruleType, 'cidr');
    assert.equal(parsed[6].pattern, '2001:db8::/32');

    // Verify round-tripped rules work identically in core/guard.js evaluateAssetGate
    const deniedCidr = evaluateAssetGate({ url: 'http://internal.example.com', ip: '10.1.2.3' }, { rules: parsed });
    assert.equal(deniedCidr.allowed, false);

    const deniedWildcard = evaluateAssetGate('https://admin.corp.internal', { rules: parsed });
    assert.equal(deniedWildcard.allowed, false);

    const allowedDomain = evaluateAssetGate('https://app.example.com/home', { rules: parsed });
    assert.equal(allowedDomain.allowed, true);
  });

  test('CANDIDATE-6: client CSV fallback neutralizes formula-leading characters (=, +, -, @, tab, cr, leading whitespace)', () => {
    assert.equal(formatClientCsvCell('=1+1'), '"\'=1+1"');
    assert.equal(formatClientCsvCell('+cmd|\' /C calc\'!A0'), '"\'+cmd|\' /C calc\'!A0"');
    assert.equal(formatClientCsvCell('-2+3'), '"\'-2+3"');
    assert.equal(formatClientCsvCell('@SUM(1,1)'), '"\'@SUM(1,1)"');
    assert.equal(formatClientCsvCell('\t=1+1'), '"\'\t=1+1"');
    assert.equal(formatClientCsvCell('\r=1+1'), '"\'\r=1+1"');
    assert.equal(formatClientCsvCell('  =HYPERLINK("https://evil.test")'), '"\'  =HYPERLINK(""https://evil.test"")"');
    assert.equal(formatClientCsvCell('Normal "quoted" text'), '"Normal ""quoted"" text"');

    const csv = buildClientCsvReport([
      {
        status: 'VULNERABLE',
        severity: 'HIGH',
        name: 'test-check',
        title: '+cmd',
        target: 'https://example.com',
        detail: '=1+1',
        fix: '@SUM(1,1)'
      }
    ]);
    assert.ok(csv.startsWith('\uFEFF'), 'Client CSV fallback must include UTF-8 BOM');
    assert.ok(csv.includes('\r\n'), 'Client CSV fallback must use CRLF');
    assert.ok(csv.includes('"\'+cmd"'));
    assert.ok(csv.includes('"\'=1+1"'));
    assert.ok(csv.includes('"\'@SUM(1,1)"'));
  });

  test('v2.3 ui/index.html exposes System Doctor, SARIF export, AI Action Roadmap, and Custom Headers hooks with zero inline on* attributes', () => {
    const html = fs.readFileSync(path.join(UI_DIR, 'index.html'), 'utf8');

    assert.match(html, /class="header-right"/);
    assert.match(html, /id="btn-open-system-doctor"/);
    assert.match(html, /id="system-doctor-backdrop"[^>]*role="dialog"[^>]*aria-modal="true"[^>]*aria-labelledby="system-doctor-title"/);
    assert.match(html, /id="doctor-target-input"/);
    assert.match(html, /id="doctor-allow-private"/);
    assert.match(html, /id="btn-run-target-diagnose"/);

    assert.match(html, /id="custom-headers-input"/);
    assert.match(html, /id="btn-export-sarif"/);
    assert.match(html, /id="btn-generate-ai-summary"/);
    assert.match(html, /id="ai-summary-container"/);

    assert.equal(/\bon[a-z]+\s*=/i.test(html), false, 'ui/index.html must have zero inline on* attributes');
  });

  test('v2.3 ui/app.js & ui/components/evidence-viewer.js wire System Doctor, AI Advisor, SARIF, and Custom Headers cleanly', () => {
    const appJs = fs.readFileSync(path.join(UI_DIR, 'app.js'), 'utf8');
    const evJs = fs.readFileSync(path.join(UI_COMPONENTS_DIR, 'evidence-viewer.js'), 'utf8');

    for (const content of [appJs, evJs]) {
      assert.equal(/\balert\s*\(/.test(content), false);
      assert.equal(/\beval\s*\(/.test(content), false);
    }

    assert.match(appJs, /\/api\/system\/doctor/);
    assert.match(appJs, /\/api\/system\/diagnose-target/);
    assert.match(appJs, /\/api\/ai\/remediate/);
    assert.match(appJs, /\/api\/ai\/summary/);
    assert.match(appJs, /\bsarif\b/i);
    assert.match(appJs, /\bops\b/);

    assert.match(evJs, /data-ev-action="ai-fix"/);
    assert.match(evJs, /data-role="ev-ai-fix-panel"/);
    assert.match(evJs, /\/api\/ai\/remediate/);

    // Pure helpers: parseCustomHeadersInput
    assert.deepEqual(parseCustomHeadersInput('   \n  '), { valid: true, headers: undefined });
    const parsedOk = parseCustomHeadersInput('X-Api-Key: secret-123\nX-Custom-Env: staging');
    assert.equal(parsedOk.valid, true);
    assert.deepEqual(parsedOk.headers, { 'X-Api-Key': 'secret-123', 'X-Custom-Env': 'staging' });
    assert.equal(parseCustomHeadersInput('InvalidLineNoColon').valid, false);
    assert.equal(parseCustomHeadersInput('X-Test: bad\x00value').valid, false);
    assert.equal(parseCustomHeadersInput('Host: evil.example').valid, false);
    assert.equal(parseCustomHeadersInput('Transfer-Encoding: chunked').valid, false);
    assert.equal(parseCustomHeadersInput('Keep-Alive: timeout=5').valid, false);
    assert.equal(parseCustomHeadersInput('__proto__: bad').valid, false);
    assert.equal(parseCustomHeadersInput(Array.from({ length: 33 }, (_, i) => `X-H-${i}: 1`).join('\n')).valid, false);
    assert.equal(parseCustomHeadersInput(`X-Big: ${'A'.repeat(8500)}`).valid, false);

    // C11: generateAiSummaryRoadmap sends { scanId, audience } without full scanResult when scanId exists
    assert.match(appJs, /const payload = scanId\s*\?\s*\{\s*scanId,\s*audience\s*\}/);

    // Pure helper: buildClientSarifReport produces valid SARIF 2.1.0
    const sarif = buildClientSarifReport({
      results: [
        {
          checkId: 'security-headers',
          status: 'VULNERABLE',
          severity: 'HIGH',
          target: 'https://example.com',
          detail: 'Missing CSP',
          cwe: 'CWE-693',
          cvssScore: 6.5
        },
        {
          checkId: 'ssl-tls',
          status: 'SAFE',
          severity: 'NONE',
          target: 'https://example.com'
        }
      ]
    });
    assert.equal(sarif.version, '2.1.0');
    assert.equal(sarif.runs[0].tool.driver.rules.length, 1);
    assert.equal(sarif.runs[0].results.length, 1);
    assert.equal(sarif.runs[0].results[0].level, 'error');

    // Pure helper: buildAiFixHtml escapes untrusted strings
    const fixHtml = buildAiFixHtml({
      mode: 'ai',
      provider: 'gemini',
      model: 'gemini-2.5-flash',
      audience: 'pro',
      plainExplanation: 'Missing <script>alert(1)</script> header',
      rootCause: 'No CSP configured',
      solutionSteps: ['Add CSP header'],
      patchSnippet: 'add_header Content-Security-Policy "default-src \'self\'";',
      patchLanguage: 'nginx',
      verifyCommand: 'curl -sI https://example.com',
      verifyExpected: 'CSP header present',
      developerPrompt: 'Fix CSP'
    });
    assert.match(fixHtml, /AI Powered/);
    assert.equal(fixHtml.includes('<script>alert(1)</script>'), false);
    assert.ok(fixHtml.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
  });

  test('v2.3 ui/components/system-guardrails.js includes Gemini provider option, model hints, and masked key status', () => {
    const guardJs = fs.readFileSync(path.join(UI_COMPONENTS_DIR, 'system-guardrails.js'), 'utf8');
    assert.match(guardJs, /<option value="gemini">Google Gemini \(generateContent\)<\/option>/);
    assert.match(guardJs, /<option value="openai-responses">/);
    assert.match(guardJs, /Key Configured/);
    assert.match(guardJs, /No Key/);
    assert.equal(guardJs.includes('p.apiKey}</code>'), false, 'Raw/masked apiKey string must not be rendered');

    const geminiHint = getProviderModelHint('gemini');
    assert.equal(geminiHint.defaultModel, 'gemini-2.5-flash');
    assert.match(geminiHint.placeholder, /gemini-2\.5-flash/);
    assert.match(guardJs, /Auto-discovered/);
    assert.match(guardJs, /data-edit-profile/);
  });

  test('v2.3 ui/index.html & ui/app.js expose SPA API Communication preview, results card, and Ask AI triggers', () => {
    const html = fs.readFileSync(path.join(UI_DIR, 'index.html'), 'utf8');

    // Tab 1 Tech Detect Banner API Communication row hooks
    assert.match(html, /id="tech-detect-api-row"/);
    assert.match(html, /id="tech-detect-api-badge"/);
    assert.match(html, /id="tech-detect-api-details"/);
    assert.match(html, /id="tech-detect-api-endpoints"/);
    assert.match(html, /id="btn-analyze-detect-api"/);
    assert.match(html, /id="tech-detect-api-ai-output"/);
    assert.match(html, /🤖 Ask AI About APIs/);

    // Tab 2 Scan Results API Card hooks
    assert.match(html, /id="results-api-card"/);
    assert.match(html, /id="results-api-summary"/);
    assert.match(html, /id="results-api-endpoints"/);
    assert.match(html, /id="btn-analyze-results-api"/);
    assert.match(html, /id="results-api-ai-output"/);

    const appJs = fs.readFileSync(path.join(UI_DIR, 'app.js'), 'utf8');
    // Client wiring for POST /api/ai/analyze-api
    assert.match(appJs, /apiPost\('\/api\/ai\/analyze-api'/);
    assert.match(appJs, /data-scan-origin/);
    assert.match(appJs, /handleScanOriginTrigger/);
    assert.match(appJs, /renderApiCommunicationSection/);
    assert.match(appJs, /renderApiAiOutput/);

    // Prioritizes scanId on results analysis payload
    assert.match(appJs, /const payload = scanId\s*\?\s*\{\s*scanId,\s*audience\s*\}\s*:\s*\{/);

    // SSE fingerprint updates live-tech-chips when apiCommunication.usesApi is true
    assert.match(appJs, /apiComm\?\.usesApi/);
    assert.match(appJs, /chip-api-active/);
  });

  test('renderApiCommunicationSection populates status badge, chips, endpoints, and external backend scan triggers with XSS safety', () => {
    const mockBadge = { textContent: '', className: '' };
    const mockDetails = { innerHTML: '' };
    const mockEndpoints = { innerHTML: '', classList: { remove() {}, add() {} } };
    const mockBtn = { classList: { remove() {} }, disabled: false };

    // Case 1: Uses API with Angular HttpClient, same-origin endpoints & external backend origins
    renderApiCommunicationSection({
      statusBadgeEl: mockBadge,
      detailsEl: mockDetails,
      endpointsEl: mockEndpoints,
      analyzeBtnEl: mockBtn,
      apiComm: {
        usesApi: true,
        architecture: 'spa_rest',
        clients: ['Angular HttpClient', '<script>alert(1)</script>'],
        protocols: ['rest'],
        sameOriginEndpoints: ['/api/v1/orders', '/api/<img src=x onerror=alert(2)>/users'],
        externalApiOrigins: ['https://api.backend.example'],
        summary: 'Detected Angular HttpClient with 2 routes & 1 external API.'
      }
    });

    assert.equal(mockBadge.textContent, 'Yes — SPA / API Client');
    assert.match(mockBadge.className, /badge-api-active/);
    assert.match(mockDetails.innerHTML, /Angular HttpClient/);
    assert.match(mockDetails.innerHTML, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
    assert.equal(mockDetails.innerHTML.includes('<script>alert(1)</script>'), false);
    assert.match(mockEndpoints.innerHTML, /class="api-endpoint-pill"/);
    assert.match(mockEndpoints.innerHTML, /\/api\/v1\/orders/);
    assert.match(mockEndpoints.innerHTML, /&lt;img src=x onerror=alert\(2\)&gt;/);
    assert.equal(mockEndpoints.innerHTML.includes('<img src=x onerror=alert(2)>'), false);
    assert.match(mockEndpoints.innerHTML, /class="api-external-pill"/);
    assert.match(mockEndpoints.innerHTML, /data-scan-origin="https:\/\/api\.backend\.example"/);
    assert.match(mockEndpoints.innerHTML, /🎯 Scan Backend API/);

    // Case 2: Not detected / usesApi: false
    renderApiCommunicationSection({
      statusBadgeEl: mockBadge,
      detailsEl: mockDetails,
      endpointsEl: mockEndpoints,
      analyzeBtnEl: mockBtn,
      apiComm: { usesApi: false }
    });

    assert.equal(mockBadge.textContent, 'Not Detected');
    assert.match(mockBadge.className, /badge-api-inactive/);
    assert.match(mockDetails.innerHTML, /No client-side SPA API frameworks/);
    assert.equal(mockEndpoints.innerHTML, '');
  });

  test('renderApiAiOutput renders AI vs playbook modes, recommendations, LLM pool settings navigation, and neutralizes XSS', () => {
    const mockContainer = {
      innerHTML: '',
      classList: { remove() {} },
      querySelector() { return null; }
    };

    // Case 1: Playbook fallback due to no LLM configured
    renderApiAiOutput(mockContainer, {
      mode: 'playbook',
      audience: 'pro',
      fallbackReason: 'no_llm_configured',
      headline: 'Deterministic Playbook: Secure Angular & SPA API Communication',
      explanation: 'Target uses client-side API requests to external servers with untrusted token: <svg onload=alert(3)>.',
      recommendations: [
        'Enforce strict CSP connect-src directives',
        'Verify CORS headers on backend APIs: <b onmouseover=alert(4)>test</b>'
      ],
      configGuidance: 'proxy.conf.json:\n{ "/api": { "target": "https://api.backend.example", "secure": true } }',
      nextScanTargets: ['https://api.backend.example'],
      developerPrompt: 'Audit Angular HttpClient authentication interceptors and token storage.'
    });

    assert.match(mockContainer.innerHTML, /Built-in Playbook/);
    assert.match(mockContainer.innerHTML, /Developer \/ Pro/);
    assert.match(mockContainer.innerHTML, /btn-goto-llm-pool/);
    assert.match(mockContainer.innerHTML, /Configure LLM in Settings \(Tab 7\)/);
    assert.match(mockContainer.innerHTML, /Deterministic Playbook/);
    assert.match(mockContainer.innerHTML, /&lt;svg onload=alert\(3\)&gt;/);
    assert.equal(mockContainer.innerHTML.includes('<svg onload=alert(3)>'), false);
    assert.match(mockContainer.innerHTML, /&lt;b onmouseover=alert\(4\)&gt;/);
    assert.equal(mockContainer.innerHTML.includes('<b onmouseover=alert(4)>'), false);
    assert.match(mockContainer.innerHTML, /proxy\.conf\.json/);
    assert.match(mockContainer.innerHTML, /data-scan-origin="https:\/\/api\.backend\.example"/);
    assert.match(mockContainer.innerHTML, /btn-copy-api-prompt/);

    // Case 2: Live AI response
    renderApiAiOutput(mockContainer, {
      mode: 'ai',
      provider: 'gemini',
      model: 'gemini-2.5-flash',
      audience: 'beginner',
      headline: 'AI Security Assessment: SPA Client Endpoints',
      explanation: 'Analysis performed with Gemini AI advisor.',
      recommendations: ['Do not store private API keys in client JavaScript bundles.'],
      nextScanTargets: []
    });

    assert.match(mockContainer.innerHTML, /AI Powered \(gemini \/ gemini-2\.5-flash\)/);
    assert.match(mockContainer.innerHTML, /Owner \/ Beginner/);
  });

  test('handleScanOriginTrigger enforces https?:// URL validation and rejects invalid/dangerous schemes', () => {
    // Dangerous or invalid schemes must be rejected
    assert.equal(handleScanOriginTrigger('javascript:alert(1)'), false);
    assert.equal(handleScanOriginTrigger('data:text/html,<script>alert(1)</script>'), false);
    assert.equal(handleScanOriginTrigger('file:///etc/passwd'), false);
    assert.equal(handleScanOriginTrigger('ftp://example.com'), false);
    assert.equal(handleScanOriginTrigger(''), false);
    assert.equal(handleScanOriginTrigger(null), false);
    assert.equal(handleScanOriginTrigger(undefined), false);

    // Valid http / https origins accepted
    assert.equal(handleScanOriginTrigger('https://api.backend.example'), true);
    assert.equal(handleScanOriginTrigger('http://127.0.0.1:8080'), true);
  });

  test('external CVE DB query URL builder, multi-format JSON parser, and Docker live auto-sync configuration', () => {
    assert.equal(
      buildCoverageQueryUrl({
        tech: 'laravel',
        feed: true,
        provider: 'osv',
        packages: 'laravel/framework@11.30.0'
      }),
      '/api/cves/coverage?tech=laravel&feed=1&provider=osv&packages=laravel%2Fframework%4011.30.0'
    );

    const nvdInput = parseCustomAdvisoriesInput(JSON.stringify({
      vulnerabilities: [{ cve: { id: 'CVE-2026-44001' } }]
    }));
    assert.equal(nvdInput.valid, true);
    assert.equal(nvdInput.advisories.length, 1);

    const osvBatchInput = parseCustomAdvisoriesInput(JSON.stringify({
      results: [{ vulns: [{ id: 'GHSA-1234', aliases: ['CVE-2026-44002'] }] }]
    }));
    assert.equal(osvBatchInput.valid, true);
    assert.equal(osvBatchInput.advisories.length, 1);

    // Verify Dockerfile, docker-compose.yml, .dockerignore, and package.json scripts exist and configure live auto-sync
    const dockerfile = fs.readFileSync(path.join(REPO_ROOT, 'Dockerfile'), 'utf8');
    assert.match(dockerfile, /FROM node:24-alpine/);
    assert.match(dockerfile, /HOST=0\.0\.0\.0/);
    assert.match(dockerfile, /EXPOSE 4321/);

    const compose = fs.readFileSync(path.join(REPO_ROOT, 'docker-compose.yml'), 'utf8');
    assert.match(compose, /"--watch"/);
    assert.match(compose, /\.\/checks:\/app\/checks/);
    assert.match(compose, /\.\/core:\/app\/core/);
    assert.match(compose, /\.\/ui:\/app\/ui/);
    assert.match(compose, /develop:/);

    const pkg = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8'));
    assert.ok(pkg.scripts['docker:up']);
    assert.ok(pkg.scripts['docker:watch']);
    assert.ok(pkg.scripts['ui:watch']);
  });

  test('M3 UI: normalizeTargetScheme mirrors validator.js for quoted, trailing-backslash, IPv6, localhost & bare domain inputs', () => {
    assert.equal(normalizeTargetScheme('"192.168.68.53\\"'), 'http://192.168.68.53');
    assert.equal(normalizeTargetScheme('192.168.68.53"'), 'http://192.168.68.53');
    assert.equal(normalizeTargetScheme('http://192.168.68.53\\'), 'http://192.168.68.53');
    assert.equal(normalizeTargetScheme('192.168.1.1:8443'), 'https://192.168.1.1:8443');
    assert.equal(normalizeTargetScheme('localhost:3000'), 'http://localhost:3000');
    assert.equal(normalizeTargetScheme('localhost:443'), 'https://localhost:443');
    assert.equal(normalizeTargetScheme('::1'), 'http://[::1]');
    assert.equal(normalizeTargetScheme('nas.local\\'), 'https://nas.local');
    assert.equal(normalizeTargetScheme('nas.local:80'), 'http://nas.local:80');
    assert.equal(normalizeTargetScheme('192.168.01.1'), 'https://192.168.01.1');
    assert.equal(normalizeTargetScheme('fe80::1%eth0'), 'http://[fe80::1%eth0]');
    for (const edge of ['192.168.01.1', 'fe80::1%eth0', 'fe80::1%', 'fe80::1%eth0%1', '192.168.0.1', '::1%lo']) {
      assert.equal(normalizeTargetScheme(edge), normalizeTargetInput(edge), `Parity failed for ${edge}`);
    }
  });

  test('R1 UI: isBareIpInput and preserveBareIpOrNormalize preserve scheme-less port-less IPs on blur/submit', () => {
    assert.equal(isBareIpInput('104.21.43.139'), true);
    assert.equal(isBareIpInput('"104.21.43.139\\"'), true);
    assert.equal(isBareIpInput('::1'), true);
    assert.equal(isBareIpInput('[::1]'), true);
    assert.equal(isBareIpInput('104.21.43.139:8080'), false);
    assert.equal(isBareIpInput('http://104.21.43.139'), false);
    assert.equal(isBareIpInput('example.com'), false);

    assert.equal(preserveBareIpOrNormalize('104.21.43.139'), '104.21.43.139');
    assert.equal(preserveBareIpOrNormalize('"104.21.43.139\\"'), '104.21.43.139');
    assert.equal(preserveBareIpOrNormalize('::1'), '::1');
    assert.equal(preserveBareIpOrNormalize('104.21.43.139:8443'), 'https://104.21.43.139:8443');
    assert.equal(preserveBareIpOrNormalize('example.com'), 'https://example.com');
  });

  test('M3 UI: ui/index.html & ui/app.js expose device preset, Device Category selector, allowPrivate auto-toggle & CSP compliance', () => {
    const html = fs.readFileSync(path.join(UI_DIR, 'index.html'), 'utf8');
    assert.match(html, /id="device-category-wrap"/);
    assert.match(html, /id="opt-device-category"/);
    assert.match(html, /value="all"/);
    assert.match(html, /value="smart_tv"/);
    assert.match(html, /value="ip_camera"/);
    assert.match(html, /value="pc_workstation"/);
    assert.match(html, /id="tech-detect-device-row"/);
    assert.match(html, /id="live-device-summary"/);
    assert.match(html, /id="results-device-info"/);

    const appJs = fs.readFileSync(path.join(UI_DIR, 'app.js'), 'utf8');
    assert.match(appJs, /id:\s*'device'/);
    assert.match(appJs, /allowPrivateEl\.checked\s*=\s*true/);
    assert.match(appJs, /deviceMode/);
    assert.match(appJs, /deviceCategory/);
  });

  test('M3 UI: normalizeStacksList, renderDeviceInfoHtml, and renderMatchedEvidenceHtml handle Array/Object stacks, device badges & XSS escaping', () => {
    const arrNorm = normalizeStacksList([{ target: 'http://192.168.68.53', primary: 'device' }]);
    assert.equal(arrNorm.length, 1);
    assert.equal(arrNorm[0].target, 'http://192.168.68.53');

    const objNorm = normalizeStacksList({
      'http://192.168.68.53': { primary: 'device', summary: 'Samsung Smart TV' }
    });
    assert.equal(objNorm.length, 1);
    assert.equal(objNorm[0].target, 'http://192.168.68.53');
    assert.equal(objNorm[0].summary, 'Samsung Smart TV');

    const singleNorm = normalizeStacksList({ primary: 'device', deviceInfo: { detected: true } });
    assert.equal(singleNorm.length, 1);

    const devHtml = renderDeviceInfoHtml({
      detected: true,
      category: 'smart_tv',
      categoryLabel: 'Smart TV & Streaming Media Device',
      vendor: 'Samsung <script>x</script>',
      modelName: 'UN55TU7000',
      os: 'Tizen 5.5',
      macAddress: 'AA:BB:CC:DD:EE:FF',
      openPorts: [8001, 8002],
      openServices: [{ port: 8001, scheme: 'http', label: 'Samsung TV API' }],
      basePortClosed: true
    });
    assert.match(devHtml, /Smart TV &amp; Streaming Media Device/);
    assert.match(devHtml, /UN55TU7000/);
    assert.match(devHtml, /8001\/HTTP/);
    assert.equal(devHtml.includes('<script>'), false);

    const evHtml = renderMatchedEvidenceHtml({
      files: [
        {
          name: 'Open RTSP Stream',
          port: 554,
          scheme: 'rtsp',
          method: 'RTSP',
          status: 200,
          statusTag: 'SUSPICIOUS',
          matchedSignal: 'RTSP DESCRIBE <img src=x>'
        }
      ]
    });
    assert.match(evHtml, /SUSPICIOUS/);
    assert.match(evHtml, /Port 554\/RTSP/);
    assert.match(evHtml, /\(RTSP\)/);
    assert.equal(evHtml.includes('(HTTP 200)'), false);
    assert.equal(evHtml.includes('<img src=x>'), false);
  });

  test('M3 UI: renderScanResults supports both Array stacks and keyed Object stacks with deviceInfo', () => {
    const prevDocument = globalThis.document;
    const makeEl = () => ({
      classList: {
        hidden: false,
        add(c) { if (c === 'hidden') this.hidden = true; },
        remove(c) { if (c === 'hidden') this.hidden = false; },
        toggle(c, force) { if (c === 'hidden') this.hidden = Boolean(force); }
      },
      textContent: '',
      innerHTML: '',
      className: '',
      value: '',
      checked: false,
      querySelectorAll: () => []
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
      const sampleDevice = {
        detected: true,
        category: 'ip_camera',
        categoryLabel: 'IP Camera / NVR',
        vendor: 'Hikvision',
        modelName: 'DS-2CD2043',
        openPorts: [80, 554]
      };
      renderScanResults({
        results: [
          {
            checkId: 'device-security',
            name: 'device-security',
            target: 'http://192.168.1.50',
            status: 'SUSPICIOUS',
            severity: 'MEDIUM'
          }
        ],
        risk: { grade: 'B', score: 15, level: 'MEDIUM', summary: 'Camera exposed.' },
        stacks: {
          'http://192.168.1.50': {
            primary: 'device',
            summary: 'Hikvision IP Camera',
            detectedTags: ['device', 'ip_camera'],
            activeChecksCount: 8,
            skippedChecksCount: 40,
            deviceInfo: sampleDevice
          }
        }
      });

      assert.equal(getEl('results-stack-card').classList.hidden, false);
      assert.equal(getEl('results-device-info').classList.hidden, false);
      assert.match(getEl('results-device-info').innerHTML, /Hikvision/);
      assert.match(getEl('results-device-info').innerHTML, /DS-2CD2043/);
    } finally {
      globalThis.document = prevDocument;
    }
  });

  test('Dedicated Login & LSR Studio Tab (#tab-login-lsr), Compact Advanced LSR Selector, Top Token/Cookie Harvester Bar & renderAuthArtifactsCard XSS safety', () => {
    const html = fs.readFileSync(path.join(UI_DIR, 'index.html'), 'utf8');

    // 1. Verify dedicated Login & LSR Studio tab button and panel
    assert.match(html, /id="tab-btn-login-lsr"/);
    assert.match(html, /id="tab-login-lsr"[^>]*role="tabpanel"|role="tabpanel"[^>]*id="tab-login-lsr"/);
    assert.match(html, /id="lsr-studio-token-vault-card"/);
    assert.match(html, /id="lsr-studio-token-vault-body"/);

    // 2. Verify Top-of-Scan Quick Auth, Token Harvester & Local Store Bar in #tab-new-scan
    assert.match(html, /id="top-auth-token-bar"/);
    assert.match(html, /id="top-lsr-select"/);
    assert.match(html, /id="btn-top-get-auth-token"/);
    assert.match(html, /id="btn-top-check-local-store"/);
    assert.match(html, /id="btn-top-create-lsr"/);
    assert.match(html, /id="btn-top-open-lsr-studio"/);
    assert.match(html, /id="top-auth-artifacts-card"/);
    assert.match(html, /id="top-auth-artifacts-body"/);

    // 3. Verify compact Advanced Options LSR selector (#adv-lsr-select)
    assert.match(html, /id="adv-lsr-select"/);
    assert.match(html, /id="btn-adv-create-lsr"/);
    assert.match(html, /id="btn-adv-open-lsr-studio"/);
    assert.match(html, /id="btn-adv-get-token"/);
    assert.match(html, /id="btn-adv-check-local-store"/);

    // 4. Verify getCanonicalOrigin & renderAuthArtifactsCard escape untrusted values
    assert.equal(getCanonicalOrigin('https://satprocess.com/broadbandAdmin/index.php/site/login'), 'https://satprocess.com');

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
      className: '',
      dataset: {},
      addEventListener: () => {},
      querySelectorAll: () => []
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
      renderAuthArtifactsCard(
        {
          origin: 'https://satprocess.com',
          sequenceName: 'BroadbandAdmin.lsr <img src=x onerror=alert(1)>',
          sessionId: 'sess_12345678',
          hasToken: true,
          bearerToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbDEzNDU2IiwiZXhwIjoxOTk5OTk5OTk5fQ.sig',
          bearerTokenPreview: 'eyJhbGciOiJI...',
          hasCookies: true,
          cookieNames: ['PHPSESSID', 'YII_CSRF_TOKEN'],
          cookieHeader: 'PHPSESSID=abc; YII_CSRF_TOKEN=xyz',
          hasLocalStorage: true,
          localStorageItems: { access_token: 'tok_123' },
          sessionStorageItems: {}
        },
        { sourceLabel: 'Found in Local Store' }
      );

      const topBodyHtml = getEl('top-auth-artifacts-body').innerHTML;
      assert.match(topBodyHtml, /https:\/\/satprocess\.com/);
      assert.match(topBodyHtml, /PHPSESSID/);
      assert.match(topBodyHtml, /access_token/);
      assert.equal(topBodyHtml.includes('<img src=x'), false, 'Must escape XSS in sequenceName');
    } finally {
      globalThis.document = prevDocument;
    }
  });

  test('Saved Target Systems Bar, 1-Click Clone, Fast Fix Verification & Schedule Manager UI + renderTargetSystemsUi XSS safety', () => {
    const html = fs.readFileSync(path.join(UI_DIR, 'index.html'), 'utf8');

    const requiredTargetSystemIds = [
      'target-systems-quick-bar',
      'target-system-select',
      'target-system-name',
      'target-system-env',
      'btn-save-target-system',
      'btn-clone-target-system',
      'btn-run-target-system-fixes',
      'btn-toggle-target-systems-manager',
      'target-systems-manager-card',
      'target-system-editor-panel',
      'ts-edit-schedule-interval',
      'ts-edit-schedule-mode',
      'target-systems-list'
    ];

    for (const id of requiredTargetSystemIds) {
      assert.match(
        html,
        new RegExp(`id="${id}"`),
        `Expected id="${id}" in ui/index.html`
      );
    }

    const prevDocument = globalThis.document;
    const makeEl = () => ({
      classList: {
        hidden: false,
        add(c) { if (c === 'hidden') this.hidden = true; },
        remove(c) { if (c === 'hidden') this.hidden = false; },
        toggle(c, force) { if (c === 'hidden') this.hidden = Boolean(force); }
      },
      textContent: '',
      innerHTML: '',
      className: '',
      value: '',
      dataset: {},
      addEventListener: () => {},
      querySelectorAll: () => []
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
      renderTargetSystemsUi([
        {
          id: 'ts_prod_1',
          name: 'Broadband Portal <script>alert(1)</script>',
          environment: 'production',
          targetUrl: 'https://satprocess.com/broadbandAdmin/index.php',
          profile: 'smart',
          sequenceId: 'seq_1',
          sequenceName: 'BroadbandYii.lsr <img src=x onerror=alert(2)>',
          schedule: {
            enabled: true,
            interval: 'daily',
            mode: 'open_issues_only',
            nextRunAt: '2026-11-27T00:00:00.000Z'
          },
          lastScanSummary: {
            lastGrade: 'C',
            fixedInLastRunCount: 2,
            unfixedCheckIds: ['xss', 'sqli']
          }
        }
      ]);

      const selectHtml = getEl('target-system-select').innerHTML;
      const listHtml = getEl('target-systems-list').innerHTML;

      assert.equal(getEl('target-systems-count-badge').textContent, '1');
      assert.match(getEl('ts-summary-scheduled-pill').textContent, /1 Scheduled/);
      assert.match(getEl('ts-summary-open-issues-pill').textContent, /2 Open Issues Tracked/);

      assert.match(selectHtml, /Broadband Portal &lt;script&gt;alert\(1\)&lt;\/script&gt;/);
      assert.match(selectHtml, /2 open issues/);
      assert.equal(selectHtml.includes('<script>alert(1)</script>'), false);

      // Verify environment badge, schedule pill, open-issue delta badges, and action buttons
      assert.match(listHtml, /ts-env-badge production/);
      assert.match(listHtml, /ts-schedule-pill active/);
      assert.match(listHtml, /daily · Open Issues Only/);
      assert.match(listHtml, /2 Open Check\(s\): xss, sqli/);
      assert.match(listHtml, /2 Fixed in Last Run!/);
      assert.match(listHtml, /data-ts-action="run-fixes"/);
      assert.match(listHtml, /data-ts-action="run-full"/);
      assert.match(listHtml, /data-ts-action="load"/);
      assert.match(listHtml, /data-ts-action="clone"/);
      assert.match(listHtml, /data-ts-action="edit"/);
      assert.match(listHtml, /data-ts-action="delete"/);
      assert.equal(listHtml.includes('<script>alert(1)</script>'), false);
      assert.equal(listHtml.includes('<img src=x'), false);
    } finally {
      globalThis.document = prevDocument;
    }
  });

  test('Login & LSR Studio Master-Detail Targets View shows only targets by default and opens detail config on Edit or Add Target Login', () => {
    const html = fs.readFileSync(path.join(UI_DIR, 'index.html'), 'utf8');

    // Master view is visible by default; detail configuration view is hidden by default
    assert.match(html, /id="lsr-studio-targets-master-card"[^>]*class="[^"]*lsr-studio-targets-master-card"/);
    assert.match(html, /id="lsr-studio-detail-config-view"[^>]*class="[^"]*hidden"/);
    assert.match(html, /id="btn-lsr-studio-add-target"/);
    assert.match(html, /id="btn-lsr-studio-back-to-targets"/);
    assert.match(html, /id="btn-lsr-studio-open-visual-builder"/);
    assert.match(html, /id="btn-lsr-studio-save-detail"/);
    assert.match(html, /id="studio-sequence-name-input"/);
    assert.match(html, /id="lsr-studio-inline-steps-list"/);

    const prevDocument = globalThis.document;
    const makeEl = (initialHidden = false) => ({
      classList: {
        hidden: initialHidden,
        add(c) { if (c === 'hidden') this.hidden = true; },
        remove(c) { if (c === 'hidden') this.hidden = false; },
        toggle(c, force) { if (c === 'hidden') this.hidden = Boolean(force); },
        contains(c) { return c === 'hidden' ? this.hidden : false; }
      },
      textContent: '',
      innerHTML: '',
      className: '',
      value: '',
      checked: false,
      dataset: {},
      focus: () => {},
      scrollIntoView: () => {},
      addEventListener: () => {},
      querySelectorAll: () => []
    });
    const elements = new Map();
    elements.set('lsr-studio-targets-master-card', makeEl(false));
    elements.set('lsr-studio-detail-config-view', makeEl(true));
    const getEl = (id) => {
      if (!elements.has(id)) elements.set(id, makeEl(false));
      return elements.get(id);
    };
    globalThis.document = {
      getElementById: getEl,
      querySelectorAll: () => []
    };

    try {
      // 1. Default state: master card visible, detail config hidden
      assert.equal(getEl('lsr-studio-targets-master-card').classList.hidden, false);
      assert.equal(getEl('lsr-studio-detail-config-view').classList.hidden, true);

      // 2. Click Edit on a target sequence -> reveals detail configuration view and populates fields & steps
      openLsrStudioDetailView({
        sequenceId: 'seq_fearless',
        name: 'fearlessbull.lsr',
        targetUrl: 'https://fearlessbull.com/login',
        actions: [
          { type: 'navigate', url: 'https://fearlessbull.com/login' },
          { type: 'change_input', selectorType: 'id', selector: 'email', value: 'trader@example.com' },
          { type: 'click_button', selectorType: 'text', selector: 'Log in' }
        ]
      }, { isNew: false });

      assert.equal(getEl('lsr-studio-detail-config-view').classList.hidden, false);
      assert.equal(getEl('studio-target-url').value, 'https://fearlessbull.com/login');
      assert.equal(getEl('studio-sequence-name-input').value, 'fearlessbull.lsr');
      assert.match(getEl('lsr-studio-detail-mode-badge').textContent, /Edit Target/);
      assert.match(getEl('lsr-studio-inline-steps-list').innerHTML, /Step 1/);
      assert.match(getEl('lsr-studio-inline-steps-list').innerHTML, /fearlessbull\.com\/login/);

      // 3. Back to targets list -> hides detail configuration view and shows master targets list
      closeLsrStudioDetailView();
      assert.equal(getEl('lsr-studio-detail-config-view').classList.hidden, true);
      assert.equal(getEl('lsr-studio-targets-master-card').classList.hidden, false);

      // 4. Click + Add Target Login -> opens detail configuration view in Add mode
      openLsrStudioDetailView(null, { isNew: true });
      assert.equal(getEl('lsr-studio-detail-config-view').classList.hidden, false);
      assert.match(getEl('lsr-studio-detail-mode-badge').textContent, /Add New Target/);
      renderLsrInlineStepsSummary();
      assert.match(getEl('lsr-studio-inline-steps-list').innerHTML, /No login steps recorded yet/);
    } finally {
      globalThis.document = prevDocument;
    }
  });
});
