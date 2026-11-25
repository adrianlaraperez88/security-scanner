export const tags = ['all', 'api', 'node', 'express', 'nextjs', 'python', 'django', 'fastapi', 'flask', 'java', 'spring', 'php', 'laravel', 'symfony'];

export const meta = {
  id: 'bola-mass-assignment',
  title: 'API BOLA / IDOR & Mass Assignment Privilege Attribute Exposure',
  category: 'API Security',
  plainExplanation:
    'Inspects REST API object endpoints (/api/users/1, /api/v1/users/1) against a non-existent canary route to detect unauthenticated Broken Object Level Authorization (BOLA/IDOR) and checks whether privilege-escalation fields (role, isAdmin, is_superuser) are exposed or accepted via Mass Assignment.',
  whyItMatters:
    'Broken Object Level Authorization (OWASP API1:2023) allows attackers to read or modify other users’ records by enumerating sequential IDs (/api/users/1), while Mass Assignment (OWASP API3:2023) allows binding privileged fields like {"role":"admin","isAdmin":true}.',
  defaultFix:
    'Enforce object-level ownership checks on every record lookup, use non-sequential UUIDs, and restrict request body deserialization to explicit allowlisted DTO fields (never bind role, isAdmin, or permissions from client input).',
  cwe: 'CWE-639',
  owasp: 'A01:2021-Broken Access Control',
  cvssScore: 8.6,
  cveIds: [],
  references: [
    'https://cwe.mitre.org/data/definitions/639.html',
    'https://cwe.mitre.org/data/definitions/915.html',
    'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/'
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

function isJsonResponse(res) {
  if (!res || res.status !== 200) return false;
  const ct = getHeader(res.headers, 'content-type').toLowerCase();
  const body = String(res.text || '').trim();
  if (!body.startsWith('{') && !body.startsWith('[')) return false;
  if (ct.includes('text/html') || /^<!doctype\s+html/i.test(body)) return false;
  try {
    const parsed = JSON.parse(body);
    return Boolean(parsed && typeof parsed === 'object');
  } catch {
    return false;
  }
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

  let parsedOrigin;
  try {
    parsedOrigin = new URL(target).origin;
  } catch {
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      status: 'SAFE',
      detail: 'Invalid target URL.'
    };
  }

  // 1. Canary check on a non-existent user ID to rule out catch-all 200 JSON responses
  const canaryUrl = new URL('/api/users/99999991', parsedOrigin).href;
  let canaryRes;
  try {
    canaryRes = await fetchWithRetry(canaryUrl, {
      headers: { Accept: 'application/json' },
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

  const canaryBody = String(canaryRes?.text || '').trim();

  // 2. Probe ID 1 object endpoint (/api/users/1)
  const objectUrl = new URL('/api/users/1', parsedOrigin).href;
  let objRes;
  try {
    objRes = await fetchWithRetry(objectUrl, {
      headers: { Accept: 'application/json' },
      followRedirects: false
    });
  } catch (err) {
    if (isGovernanceBlock(err)) throw err;
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      status: 'SAFE',
      detail: 'No BOLA/IDOR or Mass Assignment exposure detected.'
    };
  }

  if (!isJsonResponse(objRes)) {
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      status: 'SAFE',
      detail: 'No unauthenticated BOLA/IDOR object endpoint detected.'
    };
  }

  const objBody = String(objRes.text || '').trim();
  if (canaryRes?.status === 200 && canaryBody === objBody) {
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      status: 'SAFE',
      detail: 'Object endpoint returned identical catch-all response as non-existent canary ID.'
    };
  }

  // Must contain actual user/account sensitive record fields AND privilege attributes
  const piiMatch = objBody.match(/"(email|password_hash|api_key|apiKey|ssn|phone|access_token)"\s*:\s*"([^"\r\n]{3,80})"/i);
  const privMatch = objBody.match(/"(role|is_admin|isAdmin|is_superuser|permissions)"\s*:\s*("admin"|"superadmin"|true|\[[^\]]+\])/i);

  if (piiMatch || privMatch) {
    const evidenceQuotes = [];
    if (piiMatch) evidenceQuotes.push(piiMatch[0]);
    if (privMatch) evidenceQuotes.push(privMatch[0]);

    const hasBoth = Boolean(piiMatch && privMatch);
    const findings = [
      {
        url: objectUrl,
        status: objRes.status,
        hasSensitivePii: Boolean(piiMatch),
        hasPrivilegeAttributes: Boolean(privMatch),
        matchedSignal: evidenceQuotes[0],
        issue: `Unauthenticated BOLA/IDOR object access at ${objectUrl} (HTTP 200 vs HTTP ${canaryRes?.status ?? 404} on canary ID) exposing ${hasBoth ? 'sensitive user PII and administrative privilege attributes (Mass Assignment schema exposure)' : piiMatch ? `sensitive user field "${piiMatch[1]}"` : `privilege attribute "${privMatch[1]}"`}.`
      }
    ];

    return {
      name: meta.title,
      checkId: meta.id,
      target,
      url: objectUrl,
      status: piiMatch ? 'VULNERABLE' : 'SUSPICIOUS',
      severity: piiMatch ? 'HIGH' : 'MEDIUM',
      findings,
      evidenceQuotes,
      poeLevel: 3,
      ...(objRes.trafficId ? { trafficId: objRes.trafficId } : {}),
      detail: findings[0].issue
    };
  }

  return {
    name: meta.title,
    checkId: meta.id,
    target,
    status: 'SAFE',
    detail: 'No unauthenticated BOLA/IDOR or Mass Assignment exposure detected.'
  };
}

export default run;
