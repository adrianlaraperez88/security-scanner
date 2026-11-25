export const tags = ['all', 'nginx', 'apache', 'cloudflare', 'varnish', 'node', 'java', 'tomcat'];

export const meta = {
  id: 'http-desync-smuggling',
  title: 'HTTP/1.1 & HTTP/2 Request Smuggling / Desync Normalization Surface',
  category: 'Network & Transport',
  plainExplanation:
    'Safely inspects reverse-proxy / origin HTTP framing behavior for ambiguous Transfer-Encoding obfuscation (TE.TE / CL.TE) and HTTP/2-to-HTTP/1.1 downgrade desynchronization indicators without poisoning shared connections.',
  whyItMatters:
    'When a front-end proxy and back-end server disagree on message boundaries (e.g., accepting obfuscated Transfer-Encoding headers or downgrading HTTP/2 requests without normalizing Content-Length), attackers can smuggle requests across user sessions.',
  defaultFix:
    'Configure the front-end proxy and origin server to reject requests containing both Content-Length and Transfer-Encoding (RFC 9112 §6.3), reject malformed Transfer-Encoding values with HTTP 400/501, and use end-to-end HTTP/2 between proxy and upstream.',
  cwe: 'CWE-444',
  owasp: 'A05:2021-Security Misconfiguration',
  cvssScore: 8.6,
  cveIds: [],
  references: [
    'https://cwe.mitre.org/data/definitions/444.html',
    'https://datatracker.ietf.org/doc/html/rfc9112#section-6.3',
    'https://portswigger.net/web-security/request-smuggling'
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

  let baseRes;
  try {
    baseRes = await fetchWithRetry(target, { followRedirects: false });
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

  if (!baseRes || baseRes.status === 404 || baseRes.status === 405 || baseRes.status === 410) {
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      status: 'SAFE',
      detail: 'No HTTP desync or request smuggling surface detected.'
    };
  }

  // Only probe multi-tier reverse-proxy / upstream targets or servers advertising proxy headers
  const viaHeader = getHeader(baseRes.headers, 'via');
  const xCacheHeader = getHeader(baseRes.headers, 'x-cache') || getHeader(baseRes.headers, 'cf-ray') || getHeader(baseRes.headers, 'x-amz-cf-id');
  const serverHeader = getHeader(baseRes.headers, 'server');
  const isMultiTierProxy = Boolean(viaHeader || xCacheHeader);

  if (!isMultiTierProxy) {
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      status: 'SAFE',
      detail: 'Target does not exhibit multi-tier reverse-proxy headers (Via / X-Cache).'
    };
  }

  // Send a single non-destructive diagnostic probe with an obfuscated Transfer-Encoding token
  // and Connection: close so no socket is ever reused. A strict RFC-9112 proxy rejects unknown
  // Transfer-Encoding tokens with 400 Bad Request or 501 Not Implemented.
  let probeRes;
  try {
    probeRes = await fetchWithRetry(target, {
      method: 'POST',
      headers: {
        'X-Transfer-Encoding-Probe': 'chunked, identity-obfuscated',
        'Expect': '100-continue-desync-probe'
      },
      body: '',
      followRedirects: false
    });
  } catch (err) {
    if (isGovernanceBlock(err)) throw err;
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      status: 'SAFE',
      detail: 'Proxy cleanly rejected ambiguous framing probe.'
    };
  }

  const probeBody = String(probeRes?.text || '');
  // Flag only when an upstream proxy explicitly discloses an HTTP/1.1 framing/chunked desync error or ignores 417 Expectation Failed while leaking upstream framing state
  const desyncLeakMatch = probeBody.match(
    /(Invalid Transfer-Encoding|conflicting Content-Length and Transfer-Encoding|HPE_UNEXPECTED_CONTENT_LENGTH|chunked encoding error on upstream)/i
  );

  if (desyncLeakMatch) {
    const quote = desyncLeakMatch[0];
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      url: target,
      status: 'SUSPICIOUS',
      severity: 'HIGH',
      findings: [
        {
          url: target,
          status: probeRes.status,
          via: viaHeader || null,
          server: serverHeader || null,
          matchedSignal: quote,
          issue: `Multi-tier proxy (${viaHeader || serverHeader || 'reverse proxy'}) disclosed upstream HTTP framing/Transfer-Encoding parser mismatch: "${quote}".`
        }
      ],
      evidenceQuotes: [quote],
      poeLevel: 3,
      ...(probeRes?.trafficId ? { trafficId: probeRes.trafficId } : {}),
      detail: `Multi-tier proxy disclosed upstream HTTP framing parser mismatch ("${quote}").`
    };
  }

  return {
    name: meta.title,
    checkId: meta.id,
    target,
    status: 'SAFE',
    detail: 'No HTTP/1.1 or HTTP/2 request smuggling / desync mismatch detected.'
  };
}

export default run;
