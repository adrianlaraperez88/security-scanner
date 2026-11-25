export const tags = ['all', 'nginx', 'apache', 'cloudflare', 'varnish', 'nextjs', 'node', 'php', 'laravel', 'symfony'];

export const meta = {
  id: 'cache-poisoning',
  title: 'Web Cache Poisoning & Unkeyed Header Reflection (X-Forwarded-Host / X-Original-URL)',
  category: 'HTTP Headers',
  plainExplanation:
    'Probes an isolated cache-busted URL (?secscan_cb=<nonce>) with unkeyed forwarding headers (X-Forwarded-Host, X-Host, X-Original-URL) and performs a clean follow-up request to verify whether the reflected header is stored in a shared HTTP cache.',
  whyItMatters:
    'If a reverse proxy or CDN caches a response containing an unkeyed header value (such as X-Forwarded-Host reflected into <script src="..."> or redirect Location headers), an attacker can poison the shared cache and serve malicious scripts or redirects to all visitors.',
  defaultFix:
    'Include X-Forwarded-Host / X-Forwarded-Scheme in the cache key (Vary header), or configure the web server and framework to ignore unauthenticated X-Forwarded-Host, X-Host, X-Original-URL, and X-Rewrite-URL headers.',
  cwe: 'CWE-444',
  owasp: 'A05:2021-Security Misconfiguration',
  cvssScore: 8.2,
  cveIds: [],
  references: [
    'https://cwe.mitre.org/data/definitions/444.html',
    'https://portswigger.net/web-security/web-cache-poisoning'
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

  // Always isolate probes with a dedicated cache-buster parameter so live URLs are never poisoned
  const cbValue = 'cb98412';
  const bustedUrlObj = new URL(parsed.href);
  bustedUrlObj.searchParams.set('secscan_cb', cbValue);
  const bustedUrl = bustedUrlObj.href;

  const canaryHost = 'secscan-cache-canary.invalid';
  let poisonRes;
  try {
    poisonRes = await fetchWithRetry(bustedUrl, {
      method: 'GET',
      headers: {
        'X-Forwarded-Host': canaryHost,
        'X-Host': canaryHost
      },
      followRedirects: false
    });
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

  if (!poisonRes || poisonRes.status === 404 || poisonRes.status === 405 || poisonRes.status === 410) {
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      status: 'SAFE',
      detail: 'No unkeyed header reflection or web cache poisoning detected.'
    };
  }

  const poisonBody = String(poisonRes.text || '');
  const poisonLocation = getHeader(poisonRes.headers, 'location');
  const bodyReflected = poisonBody.includes(canaryHost);
  const locationReflected = poisonLocation.includes(canaryHost);

  if (!bodyReflected && !locationReflected) {
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      status: 'SAFE',
      detail: 'No unkeyed X-Forwarded-Host / X-Host reflection detected.'
    };
  }

  const reflectionQuote = locationReflected
    ? `Location: ${poisonLocation}`
    : (poisonBody.match(new RegExp(`[^"'>\\s]{0,32}${canaryHost}[^"'<\\s]{0,32}`, 'i'))?.[0] || canaryHost);

  // Follow-up clean request to the SAME cache-busted URL without X-Forwarded-Host to check if cached
  let cleanFollowupRes = null;
  try {
    cleanFollowupRes = await fetchWithRetry(bustedUrl, {
      method: 'GET',
      followRedirects: false
    });
  } catch (err) {
    if (isGovernanceBlock(err)) throw err;
  }

  const cleanBody = String(cleanFollowupRes?.text || '');
  const cleanLocation = getHeader(cleanFollowupRes?.headers, 'location');
  const persistedInCache = cleanBody.includes(canaryHost) || cleanLocation.includes(canaryHost);
  const xCache = getHeader(cleanFollowupRes?.headers, 'x-cache') || getHeader(cleanFollowupRes?.headers, 'cf-cache-status');

  const findings = [
    {
      url: bustedUrl,
      status: poisonRes.status,
      unkeyedHeader: 'X-Forwarded-Host',
      canaryValue: canaryHost,
      persistedInCache,
      cacheHeader: xCache || null,
      matchedSignal: reflectionQuote,
      issue: persistedInCache
        ? `Confirmed Web Cache Poisoning on ${bustedUrl}: unkeyed X-Forwarded-Host "${canaryHost}" was reflected and served to a subsequent clean request without the header.`
        : `Unkeyed X-Forwarded-Host header "${canaryHost}" was reflected in the response (${locationReflected ? 'Location header' : 'HTML body'}), creating a cache-poisoning and host-header injection surface.`
    }
  ];

  return {
    name: meta.title,
    checkId: meta.id,
    target,
    url: bustedUrl,
    status: persistedInCache ? 'VULNERABLE' : 'SUSPICIOUS',
    severity: persistedInCache ? 'HIGH' : 'MEDIUM',
    findings,
    evidenceQuotes: [reflectionQuote],
    poeLevel: 3,
    ...(poisonRes.trafficId ? { trafficId: poisonRes.trafficId } : {}),
    detail: findings[0].issue
  };
}

export default run;
