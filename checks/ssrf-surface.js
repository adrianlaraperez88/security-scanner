export const tags = ['all', 'api', 'node', 'python', 'php', 'java', 'spring', 'nextjs'];

export const meta = {
  id: 'ssrf-surface',
  title: 'Server-Side Request Forgery (SSRF) URL Parameter & Backend Fetcher Surface',
  category: 'Injection & Input',
  plainExplanation:
    'Tests URL/webhook/callback query parameters (?url=, ?webhook=, ?uri=) with a non-routable RFC 2606 domain (http://secscan-ssrf-probe.invalid/) to detect whether the backend server attempts an outbound HTTP fetch and leaks HTTP client connection errors.',
  whyItMatters:
    'Unvalidated server-side URL fetchers allow attackers to pivot into internal VPC networks, query cloud instance metadata services (169.254.169.254), and scan internal ports.',
  defaultFix:
    'Validate user-supplied URLs against a strict domain allowlist, resolve DNS once and connect directly to the validated IP (PinnedDialer), and block all RFC1918, loopback, link-local, and cloud metadata IP ranges.',
  cwe: 'CWE-918',
  owasp: 'A10:2021-Server-Side Request Forgery',
  cvssScore: 8.6,
  cveIds: [],
  references: [
    'https://cwe.mitre.org/data/definitions/918.html',
    'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/'
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

const SSRF_CANARY_HOST = 'secscan-ssrf-probe.invalid';
const SSRF_CANARY_URL = `http://${SSRF_CANARY_HOST}/`;
const URL_PARAM_CANDIDATES = ['url', 'uri', 'webhook', 'callback', 'dest', 'proxy', 'feed'];

function extractResponseQuote(res) {
  const cleanBody = String(res?.text || '')
    .slice(0, 4096)
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/\s{2,}/g, ' ')
    .trim();
  if (cleanBody.length >= 8) {
    return cleanBody.slice(0, 120);
  }
  const hdrs = res?.headers;
  if (hdrs && typeof hdrs === 'object') {
    const entries = typeof hdrs.entries === 'function' ? Array.from(hdrs.entries()) : Object.entries(hdrs);
    for (const [k, v] of entries) {
      const line = `${k}: ${Array.isArray(v) ? v.join(', ') : String(v ?? '')}`
        .replace(/[\r\n\t]+/g, ' ')
        .trim();
      if (line.length >= 8) return line.slice(0, 120);
    }
  }
  return null;
}

export async function run(targetInput, fetchWithRetry, options = {}) {
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

  let parsed;
  try {
    parsed = new URL(primaryTarget);
  } catch {
    return {
      name: meta.title,
      checkId: meta.id,
      target: primaryTarget,
      status: 'SAFE',
      detail: 'Invalid target URL.'
    };
  }

  const existingUrlParams = Array.from(parsed.searchParams.keys()).filter(k =>
    URL_PARAM_CANDIDATES.includes(k.toLowerCase())
  );
  const paramToTest = existingUrlParams[0] || 'url';
  const probeUrlObj = new URL(parsed.href);
  probeUrlObj.searchParams.set(paramToTest, SSRF_CANARY_URL);
  const probeUrl = probeUrlObj.href;

  let res;
  try {
    res = await fetchWithRetry(probeUrl, { followRedirects: false });
  } catch (err) {
    if (isGovernanceBlock(err)) throw err;
    return {
      name: meta.title,
      checkId: meta.id,
      target: primaryTarget,
      status: 'ERROR',
      detail: `Target request failed: ${err.message}`
    };
  }

  if (!res || res.status === 404 || res.status === 405 || res.status === 410) {
    return {
      name: meta.title,
      checkId: meta.id,
      target: primaryTarget,
      status: 'SAFE',
      detail: 'No SSRF backend URL-fetcher behavior detected.'
    };
  }

  const body = String(res.text || '');
  // Match backend HTTP client / DNS resolver exception referencing our RFC 2606 .invalid probe host
  const fetcherErrMatch = body.match(
    new RegExp(
      `(?:getaddrinfo\\s+ENOTFOUND|Could\\s+not\\s+resolve\\s+host:|java\\.net\\.UnknownHostException:|requests\\.exceptions\\.ConnectionError|urllib\\.error\\.URLError|cURL\\s+error\\s+6:| dial\\s+tcp:\\s+lookup)\\s*[^\\r\\n<"]{0,60}${SSRF_CANARY_HOST.replace(/\./g, '\\.')}`,
      'i'
    )
  );

  if (fetcherErrMatch) {
    const quote = fetcherErrMatch[0].replace(/\s+/g, ' ').trim();
    return {
      name: meta.title,
      checkId: meta.id,
      target: primaryTarget,
      url: probeUrl,
      status: 'VULNERABLE',
      severity: 'HIGH',
      findings: [
        {
          parameter: paramToTest,
          probeHost: SSRF_CANARY_HOST,
          url: probeUrl,
          status: res.status,
          matchedSignal: quote,
          issue: `Parameter "${paramToTest}" triggered an outbound server-side HTTP/DNS request to "${SSRF_CANARY_HOST}" and disclosed backend fetcher error: "${quote}".`
        }
      ],
      evidenceQuotes: [quote],
      poeLevel: 3,
      ...(res.trafficId ? { trafficId: res.trafficId } : {}),
      detail: `Parameter "${paramToTest}" triggered an outbound server-side HTTP request (${quote}).`
    };
  }

  if (options?.oastServer && options.oastServer.running === true) {
    const probe = options.oastServer.issueProbe({
      checkId: meta.id,
      target: primaryTarget,
      parameter: paramToTest
    });
    const oastUrlObj = new URL(parsed.href);
    oastUrlObj.searchParams.set(paramToTest, probe.callbackUrl);
    const oastProbeUrl = oastUrlObj.href;

    let oastRes = null;
    try {
      oastRes = await fetchWithRetry(oastProbeUrl, { followRedirects: false });
    } catch (err) {
      if (isGovernanceBlock(err)) throw err;
    }

    const interaction = await options.oastServer.waitForInteraction(
      probe.tokenId,
      options.oastWaitMs ?? 500
    );
    if (interaction) {
      const oastQuote = `OAST callback verified token=${probe.tokenId} (${interaction.method} ${interaction.path})`;
      const responseQuote = extractResponseQuote(oastRes);
      const evidenceQuotes = responseQuote ? [oastQuote, responseQuote] : [oastQuote];
      return {
        name: meta.title,
        checkId: meta.id,
        target: primaryTarget,
        url: oastProbeUrl,
        status: 'VULNERABLE',
        severity: 'CRITICAL',
        findings: [
          {
            parameter: paramToTest,
            probeUrl: probe.callbackUrl,
            tokenId: probe.tokenId,
            url: oastProbeUrl,
            status: oastRes?.status ?? 0,
            matchedSignal: oastQuote,
            oastVerified: true,
            issue: `Parameter "${paramToTest}" triggered a verified out-of-band HTTP callback to OAST token "${probe.tokenId}" (${interaction.method} ${interaction.path}).`
          }
        ],
        evidenceQuotes,
        poeLevel: 3,
        reproVerified: true,
        oastVerified: true,
        ...(oastRes?.trafficId ? { trafficId: oastRes.trafficId } : {}),
        detail: `Parameter "${paramToTest}" triggered a cryptographically verified blind OAST callback (token=${probe.tokenId}).`
      };
    }
  }

  return {
    name: meta.title,
    checkId: meta.id,
    target: primaryTarget,
    status: 'SAFE',
    detail: 'No SSRF backend URL-fetcher surface detected.'
  };
}

export default run;
