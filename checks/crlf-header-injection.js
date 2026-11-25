export const tags = ['all', 'nginx', 'apache', 'php', 'node', 'python', 'java'];

export const meta = {
  id: 'crlf-header-injection',
  title: 'HTTP Response Splitting & CRLF Header Injection',
  category: 'Injection & Input',
  plainExplanation:
    'Probes redirect and query parameters with URL-encoded CR/LF sequences (%0d%0aX-SecScan-Crlf: crlf9812) and verifies whether an actual X-SecScan-Crlf HTTP header is injected into the response headers.',
  whyItMatters:
    'When user input containing CR (\\r) and LF (\\n) characters is copied into an HTTP response header (such as Location or Set-Cookie) without newline stripping, attackers can inject arbitrary headers, set malicious cookies, or split the HTTP response body.',
  defaultFix:
    'Strip or reject CR (\\r, %0d) and LF (\\n, %0a) characters before writing any user-derived value into HTTP response headers.',
  cwe: 'CWE-113',
  owasp: 'A03:2021-Injection',
  cvssScore: 7.5,
  cveIds: [],
  references: [
    'https://cwe.mitre.org/data/definitions/113.html',
    'https://owasp.org/www-community/vulnerabilities/CRLF_Injection'
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

function getHeader(headers, name) {
  if (!headers || typeof headers !== 'object') return '';
  const lower = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (String(k).toLowerCase() === lower) return String(v ?? '');
  }
  return '';
}

const INJECTED_HEADER_NAME = 'x-secscan-crlf';
const INJECTED_HEADER_VAL = 'crlf9812injected';

export async function run(targetInput, fetchWithRetry) {
  const target = Array.isArray(targetInput) ? targetInput[0] : targetInput;
  if (!target || typeof target !== 'string') {
    return {
      name: meta.title,
      checkId: meta.id,
      target: String(target || ''),
      status: 'SAFE',
      detail: 'No valid target URL provided.'
    };
  }

  let parsed;
  try {
    parsed = new URL(target);
  } catch {
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      status: 'SAFE',
      detail: 'Invalid target URL.'
    };
  }

  const baseNoQuery = `${parsed.origin}${parsed.pathname || '/'}`;
  const probeUrl = `${baseNoQuery}?redirect=%2F%0d%0aX-SecScan-Crlf%3A%20${INJECTED_HEADER_VAL}`;

  let res;
  try {
    res = await fetchWithRetry(probeUrl, { followRedirects: false });
  } catch (err) {
    if (isGovernanceBlock(err)) throw err;
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      status: 'ERROR',
      detail: `Target request failed: ${err.message}`
    };
  }

  if (!res || res.status === 404 || res.status === 405 || res.status === 410) {
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      status: 'SAFE',
      detail: 'No CRLF response header injection detected.'
    };
  }

  const injectedVal = getHeader(res.headers, INJECTED_HEADER_NAME);
  if (injectedVal && injectedVal.toLowerCase().includes(INJECTED_HEADER_VAL)) {
    const quote = `X-SecScan-Crlf: ${injectedVal}`;
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      url: probeUrl,
      status: 'VULNERABLE',
      severity: 'HIGH',
      findings: [
        {
          url: probeUrl,
          status: res.status,
          injectedHeader: quote,
          matchedSignal: quote,
          issue: `CRLF injection in query parameter caused server to emit injected HTTP response header "${quote}".`
        }
      ],
      evidenceQuotes: [quote],
      poeLevel: 3,
      ...(res.trafficId ? { trafficId: res.trafficId } : {}),
      detail: `Server emitted injected HTTP response header "${quote}" via CRLF sequence.`
    };
  }

  return {
    name: meta.title,
    checkId: meta.id,
    target,
    status: 'SAFE',
    detail: 'No CRLF response header injection detected.'
  };
}

export default run;
