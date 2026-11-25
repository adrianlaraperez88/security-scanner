export const tags = ['all', 'python', 'django', 'flask', 'fastapi', 'php', 'laravel', 'symfony', 'java', 'spring', 'node', 'express'];

export const meta = {
  id: 'ssti-check',
  title: 'Server-Side Template Injection (SSTI — Jinja2, Twig, Freemarker, EL, ERB, EJS)',
  category: 'Injection & Input',
  plainExplanation:
    'Tests URL query parameters with non-destructive arithmetic template expressions across Jinja2/Twig/Pebble ({{7919*13}}), Freemarker/Spring EL/Thymeleaf (${7919*13}), and ERB/EJS (<%= 7919*13 %>), verifying that the server evaluates the expression to 102947 without reflecting the un-evaluated formula.',
  whyItMatters:
    'When user input is concatenated directly into a server-side template string before rendering, attackers can execute arbitrary template expressions, read sensitive configuration objects, and achieve remote code execution (RCE) on the underlying server.',
  defaultFix:
    'Never pass user-supplied strings as template source code (e.g., avoid render_template_string(user_input) or Twig::createTemplate(user_input)). Always pass user data as named context variables into pre-compiled static templates.',
  cwe: 'CWE-1336',
  owasp: 'A03:2021-Injection',
  cvssScore: 9.8,
  cveIds: [],
  references: [
    'https://cwe.mitre.org/data/definitions/1336.html',
    'https://portswigger.net/web-security/server-side-template-injection'
  ]
};

const GOVERNANCE_ERROR_CODES = new Set([
  'SSRF_POLICY_BLOCKED',
  'TARGET_RULE_BLOCKED',
  'TARGET_OUT_OF_SCOPE',
  'DNS_REBIND_OR_PRIVATE_IP'
]);

function isGovernanceBlock(err) {
  if (!err) return false;
  if (err.isGovernanceBlock === true || GOVERNANCE_ERROR_CODES.has(err.code)) return true;
  const msg = String(err.message || '');
  return (
    msg.startsWith('Redirect blocked by SSRF policy') ||
    msg.startsWith('Request blocked by SSRF policy') ||
    msg.startsWith('[SECSCAN platform control')
  );
}

// 7919 * 13 = 102947
const EXPECTED_RESULT = 'secscan102947ssti';
const SSTI_PROBES = [
  {
    engine: 'Jinja2 / Twig / Pebble / Nunjucks',
    payload: 'secscan{{7919*13}}ssti',
    rawExpr: '{{7919*13}}'
  },
  {
    engine: 'Freemarker / Spring EL / Thymeleaf / Mako',
    payload: 'secscan${7919*13}ssti',
    rawExpr: '${7919*13}'
  },
  {
    engine: 'ERB / EJS / JSP',
    payload: 'secscan<%= 7919*13 %>ssti',
    rawExpr: '<%= 7919*13 %>'
  }
];

const CANDIDATE_PARAMS = ['name', 'q', 'template', 'view', 'msg', 'title'];

export async function run(targetInput, fetchWithRetry) {
  const targets = Array.isArray(targetInput) ? targetInput : [targetInput];
  const primaryTarget = String(targets[0] || '');
  if (!primaryTarget) {
    return {
      name: meta.title,
      checkId: meta.id,
      target: '',
      status: 'SAFE',
      detail: 'No valid target URL provided.'
    };
  }

  let anyNetworkSuccess = false;
  let lastError = null;
  const findings = [];
  const evidenceQuotes = [];
  let matchedTrafficId = null;
  let matchedUrl = primaryTarget;

  // Build candidate URLs with parameters to test (max 4 targets)
  const urlsToTest = [];
  for (const t of targets.slice(0, 4)) {
    try {
      const u = new URL(String(t));
      urlsToTest.push(u);
    } catch {
      // ignore invalid URL
    }
  }

  if (urlsToTest.length === 0) {
    return {
      name: meta.title,
      checkId: meta.id,
      target: primaryTarget,
      status: 'SAFE',
      detail: 'No valid target URLs to test for SSTI.'
    };
  }

  for (const baseUrlObj of urlsToTest) {
    let baselineBody = '';
    try {
      const baseRes = await fetchWithRetry(baseUrlObj.href, { followRedirects: false });
      anyNetworkSuccess = true;
      if (!baseRes || baseRes.status === 404 || baseRes.status === 405 || baseRes.status === 410) {
        continue;
      }
      baselineBody = String(baseRes.text || '');
      if (baselineBody.includes(EXPECTED_RESULT)) {
        continue;
      }
    } catch (err) {
      if (isGovernanceBlock(err)) throw err;
      lastError = err;
      continue;
    }

    const existingParams = Array.from(baseUrlObj.searchParams.keys());
    const paramsToProbe = existingParams.length > 0
      ? existingParams.slice(0, 4)
      : CANDIDATE_PARAMS.slice(0, 2);

    for (const param of paramsToProbe) {
      for (const probe of SSTI_PROBES) {
        const probeUrl = new URL(baseUrlObj.href);
        probeUrl.searchParams.set(param, probe.payload);

        let res;
        try {
          res = await fetchWithRetry(probeUrl.href, { followRedirects: false });
          anyNetworkSuccess = true;
        } catch (err) {
          if (isGovernanceBlock(err)) throw err;
          lastError = err;
          continue;
        }

        if (!res || res.status !== 200) continue;
        const body = String(res.text || '');

        // Must contain the evaluated arithmetic product ("secscan102947ssti") AND not merely echo "7919*13"
        if (body.includes(EXPECTED_RESULT) && !body.includes(probe.rawExpr)) {
          evidenceQuotes.push(EXPECTED_RESULT);
          matchedTrafficId = res.trafficId || matchedTrafficId;
          matchedUrl = probeUrl.href;
          findings.push({
            parameter: param,
            engine: probe.engine,
            payload: probe.payload,
            expectedEvaluation: EXPECTED_RESULT,
            url: probeUrl.href,
            status: res.status,
            issue: `Parameter "${param}" evaluated server-side template expression "${probe.payload}" into "${EXPECTED_RESULT}" (${probe.engine}).`,
            matchedSignal: EXPECTED_RESULT
          });
          break;
        }
      }
      if (findings.length > 0) break;
    }
    if (findings.length > 0) break;
  }

  if (!anyNetworkSuccess && lastError) {
    return {
      name: meta.title,
      checkId: meta.id,
      target: primaryTarget,
      status: 'ERROR',
      detail: `Target request failed: ${lastError.message}`
    };
  }

  if (findings.length > 0) {
    return {
      name: meta.title,
      checkId: meta.id,
      target: primaryTarget,
      url: matchedUrl,
      status: 'VULNERABLE',
      severity: 'CRITICAL',
      findings,
      evidenceQuotes: Array.from(new Set(evidenceQuotes)),
      poeLevel: 3,
      ...(matchedTrafficId ? { trafficId: matchedTrafficId } : {}),
      detail: findings[0].issue
    };
  }

  return {
    name: meta.title,
    checkId: meta.id,
    target: primaryTarget,
    status: 'SAFE',
    detail: 'No Server-Side Template Injection (SSTI) arithmetic evaluation detected.'
  };
}

export default run;
