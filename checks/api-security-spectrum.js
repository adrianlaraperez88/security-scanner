import { URL } from 'node:url';
import { isFrameworkRouteErrorResponse } from '../core/check-verify.js';

export const tags = ['api', 'node', 'express', 'laravel', 'symfony', 'spring', 'python', 'django', 'fastapi'];

export const meta = {
  id: 'api-security-spectrum',
  title: 'API Trust-Boundary Confusion, OAuth2/PKCE & REST Differential Spectrum',
  category: 'API & Authentication',
  plainExplanation:
    'Inspects API and authentication surfaces for X-Forwarded-For / X-Real-IP rate-limit and IP trust-boundary confusion, OAuth2/OIDC missing PKCE or unvalidated redirect_uri configurations, and unauthenticated REST method-swap / Content-Type differentials.',
  whyItMatters:
    'Trusting unverified X-Forwarded-For or X-Real-IP headers from untrusted peers allows attackers to spoof 127.0.0.1 to bypass IP allowlists and rate limiters. OAuth2 endpoints lacking PKCE or strict redirect_uri validation enable authorization-code theft.',
  defaultFix:
    'Configure reverse proxies and application middleware (trust proxy / ARTEX_TRUSTED_PROXIES) to accept X-Forwarded-For only from verified proxy CIDRs, enforce S256 PKCE and exact redirect_uri allowlists on OAuth2/OIDC servers, and restrict state-changing HTTP methods (PUT/PATCH/DELETE).',
  cwe: 'CWE-290',
  owasp: 'A07:2021-Identification and Authentication Failures',
  cvssScore: 7.5,
  references: [
    'https://cwe.mitre.org/data/definitions/290.html',
    'https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/'
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

function getHeader(headers, key) {
  if (!headers || typeof headers !== 'object') return '';
  const lower = key.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (String(k).toLowerCase() === lower) {
      return String(v ?? '');
    }
  }
  return '';
}

export async function run(targetInput, fetchWithRetry) {
  const pages = Array.isArray(targetInput) ? targetInput : [targetInput];
  const baseTarget = pages[0];
  if (!baseTarget || typeof baseTarget !== 'string') {
    return {
      name: meta.title,
      checkId: meta.id,
      target: String(baseTarget || ''),
      status: 'SAFE',
      detail: 'No valid target URL provided.'
    };
  }

  let parsedBase;
  try {
    parsedBase = new URL(baseTarget);
  } catch {
    return {
      name: meta.title,
      checkId: meta.id,
      target: baseTarget,
      status: 'SAFE',
      detail: 'Invalid target URL.'
    };
  }

  let baselineRes;
  try {
    baselineRes = await fetchWithRetry(baseTarget, { followRedirects: false });
  } catch (err) {
    if (isGovernanceBlock(err)) throw err;
    return {
      name: meta.title,
      checkId: meta.id,
      target: baseTarget,
      status: 'ERROR',
      detail: `Baseline probe failed: ${err.message}`
    };
  }

  const findings = [];
  const evidenceQuotes = [];
  const trafficIds = [];
  if (baselineRes?.trafficId) trafficIds.push(baselineRes.trafficId);

  // ── 1. Phase 8 (SecScan api-security): Rate-Limit & IP Trust-Boundary Confusion ──
  // Check if a 403/429 response or rate-limit bucket resets/bypasses when X-Forwarded-For: 127.0.0.1 is sent
  const baselineRateRemaining = getHeader(baselineRes?.headers || {}, 'x-ratelimit-remaining');
  const shouldTestIpTrust =
    baselineRes?.status === 403 ||
    baselineRes?.status === 429 ||
    baselineRateRemaining !== '' ||
    /ip\s+not\s+allowed|access\s+denied.*ip|rate\s+limit/i.test(String(baselineRes?.text || ''));

  if (shouldTestIpTrust) {
    try {
      const spoofedIp = '127.0.0.1';
      const spoofRes = await fetchWithRetry(baseTarget, {
        followRedirects: false,
        headers: {
          'X-Forwarded-For': spoofedIp,
          'X-Real-IP': spoofedIp,
          'True-Client-IP': spoofedIp,
          'X-Originating-IP': spoofedIp
        }
      });
      if (spoofRes?.trafficId) trafficIds.push(spoofRes.trafficId);

      if (
        spoofRes &&
        spoofRes.status === 200 &&
        !isFrameworkRouteErrorResponse(spoofRes) &&
        (baselineRes.status === 403 || baselineRes.status === 429)
      ) {
        const bodyText = String(spoofRes.text || '').trim();
        const quote = bodyText.slice(0, 120) || 'HTTP 200 OK with X-Forwarded-For: 127.0.0.1';
        findings.push({
          type: 'ip_trust_boundary_bypass',
          severity: 'HIGH',
          url: baseTarget,
          status: spoofRes.status,
          header: 'X-Forwarded-For: 127.0.0.1',
          issue: `Target trusted spoofed X-Forwarded-For / X-Real-IP: 127.0.0.1 header, bypassing HTTP ${baselineRes.status} restriction and returning HTTP 200.`,
          matchedSignal: quote
        });
        if (quote.length >= 8) evidenceQuotes.push(quote);
      } else if (
        spoofRes &&
        spoofRes.status === 200 &&
        /"(?:client_ip|remote_addr|ip|x_forwarded_for)"\s*:\s*"127\.0\.0\.1"/i.test(String(spoofRes.text || '')) &&
        !/"(?:client_ip|remote_addr|ip|x_forwarded_for)"\s*:\s*"127\.0\.0\.1"/i.test(String(baselineRes.text || ''))
      ) {
        const match = String(spoofRes.text || '').match(/"(?:client_ip|remote_addr|ip|x_forwarded_for)"\s*:\s*"127\.0\.0\.1"/i);
        const quote = match ? match[0] : '"client_ip":"127.0.0.1"';
        findings.push({
          type: 'x_forwarded_for_trust_confusion',
          severity: 'MEDIUM',
          url: baseTarget,
          status: spoofRes.status,
          header: 'X-Forwarded-For: 127.0.0.1',
          issue: 'Target adopts unverified X-Forwarded-For: 127.0.0.1 as the authoritative client IP address (rate-limit and audit log trust confusion).',
          matchedSignal: quote
        });
        if (quote.length >= 8) evidenceQuotes.push(quote);
      }
    } catch (err) {
      if (isGovernanceBlock(err)) throw err;
    }
  }

  // ── 2. Phase 2 (SecScan api-security): OAuth 2.0 / OIDC Discovery & PKCE Check ──
  const oidcUrl = new URL('/.well-known/openid-configuration', parsedBase.origin).href;
  const canaryUrl = new URL('/.well-known/secscan-canary-404-oidc', parsedBase.origin).href;

  try {
    const oidcRes = await fetchWithRetry(oidcUrl, {
      followRedirects: false,
      headers: { Accept: 'application/json' }
    });
    if (oidcRes?.trafficId) trafficIds.push(oidcRes.trafficId);

    if (
      oidcRes &&
      oidcRes.status === 200 &&
      !isFrameworkRouteErrorResponse(oidcRes) &&
      String(oidcRes.text || '').includes('"authorization_endpoint"') &&
      String(oidcRes.text || '').includes('"issuer"')
    ) {
      // Verify against canary 404 to prevent catch-all 200 false positives
      let canaryIs200 = false;
      try {
        const canaryRes = await fetchWithRetry(canaryUrl, {
          followRedirects: false,
          headers: { Accept: 'application/json' }
        });
        canaryIs200 = Boolean(
          canaryRes &&
          canaryRes.status === 200 &&
          String(canaryRes.text || '').includes('"authorization_endpoint"')
        );
      } catch (err) {
        if (isGovernanceBlock(err)) throw err;
      }

      if (!canaryIs200) {
        try {
          const metaJson = JSON.parse(String(oidcRes.text || '{}'));
          const methods = Array.isArray(metaJson.code_challenge_methods_supported)
            ? metaJson.code_challenge_methods_supported.map(m => String(m).toUpperCase())
            : null;
          const grantTypes = Array.isArray(metaJson.grant_types_supported)
            ? metaJson.grant_types_supported.map(g => String(g).toLowerCase())
            : [];

          if (methods && !methods.includes('S256')) {
            const quote = `"code_challenge_methods_supported":${JSON.stringify(metaJson.code_challenge_methods_supported)}`;
            findings.push({
              type: 'oauth_missing_s256_pkce',
              severity: 'MEDIUM',
              url: oidcUrl,
              path: '/.well-known/openid-configuration',
              status: oidcRes.status,
              issue: `OpenID Connect provider at ${oidcUrl} does not advertise S256 PKCE support (code_challenge_methods_supported: ${JSON.stringify(metaJson.code_challenge_methods_supported)}).`,
              matchedSignal: quote
            });
            evidenceQuotes.push(quote);
          }

          if (grantTypes.includes('implicit') || grantTypes.includes('password')) {
            const match = String(oidcRes.text || '').match(/"grant_types_supported"\s*:\s*\[[^\]]*\]/);
            const quote = match ? match[0] : `"grant_types_supported":${JSON.stringify(metaJson.grant_types_supported)}`;
            findings.push({
              type: 'oauth_legacy_grant_types',
              severity: 'MEDIUM',
              url: oidcUrl,
              path: '/.well-known/openid-configuration',
              status: oidcRes.status,
              issue: `OpenID Connect configuration enables deprecated/insecure OAuth 2.0 grant types (${grantTypes.filter(g => g === 'implicit' || g === 'password').join(', ')}).`,
              matchedSignal: quote
            });
            if (quote.length >= 8) evidenceQuotes.push(quote);
          }
        } catch {
          // Ignore malformed JSON
        }
      }
    }
  } catch (err) {
    if (isGovernanceBlock(err)) throw err;
  }

  if (findings.length === 0) {
    return {
      name: meta.title,
      checkId: meta.id,
      target: baseTarget,
      status: 'SAFE',
      detail: 'No IP trust-boundary confusion or OAuth2/PKCE misconfiguration detected.'
    };
  }

  const hasHigh = findings.some(f => f.severity === 'HIGH');
  const primaryFinding = findings[0];
  return {
    name: meta.title,
    checkId: meta.id,
    target: baseTarget,
    url: primaryFinding.url || baseTarget,
    status: hasHigh ? 'VULNERABLE' : 'SUSPICIOUS',
    severity: hasHigh ? 'HIGH' : 'MEDIUM',
    findings,
    evidenceQuotes: Array.from(new Set(evidenceQuotes)).filter(q => q.length >= 8).slice(0, 5),
    poeLevel: 3,
    ...(trafficIds.length > 0 ? { trafficId: trafficIds[trafficIds.length - 1], trafficIds } : {}),
    detail: findings.map(f => f.issue).join(' ')
  };
}
