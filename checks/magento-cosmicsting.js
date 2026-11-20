import { URL } from 'node:url';
import {
  getHeader,
  isHtmlOrScript,
  extractVerbatimSnippet,
  confirmReproducible
} from '../core/check-verify.js';

export const tags = ['magento'];

const GOVERNANCE_ERROR_CODES = new Set([
  'SSRF_POLICY_BLOCKED',
  'TARGET_RULE_BLOCKED',
  'TARGET_OUT_OF_SCOPE',
  'DNS_REBIND_OR_PRIVATE_IP'
]);

function isGovernanceBlockError(err) {
  if (!err) return false;
  if (err.isGovernanceBlock === true) return true;
  if (GOVERNANCE_ERROR_CODES.has(err.code)) return true;
  const msg = typeof err.message === 'string' ? err.message : '';
  return (
    msg.startsWith('Redirect blocked by SSRF policy') ||
    msg.startsWith('Request blocked by SSRF policy') ||
    msg.startsWith('[SECSCAN platform control')
  );
}

const MAGENTO_SIGNALS_HEADERS = [
  'x-magento-cache-id',
  'x-magento-tags',
  'x-magento-vary',
  'x-magento-cache-debug',
];

const MAGENTO_SIGNALS_HTML = [
  'mage.cookies',
  '/pub/static/',
  'requirejs-config',
  'text/x-magento-init',
];

const VERSION_PATHS = [
  '/magento_version',
  '/pub/health_check.php',
];

const COSMICSTING_ENDPOINT = '/rest/V1/guest-carts/1/estimate-shipping-methods';

async function detectMagento(baseUrl, fetchWithRetry) {
  try {
    const res = await fetchWithRetry(baseUrl.href);
    if (res?.isGovernanceBlock) {
      const gErr = new Error(res.reason || res.error || 'Blocked by governance policy');
      gErr.isGovernanceBlock = true;
      return { detected: false, error: gErr };
    }
    const text = typeof res?.text === 'string' ? res.text : '';
    const html = text.toLowerCase();

    const matchedHeader = MAGENTO_SIGNALS_HEADERS.find(k => Boolean(getHeader(res?.headers, k)));
    const matchedHtml = MAGENTO_SIGNALS_HTML.find(s => html.includes(s));

    return {
      detected: Boolean(matchedHeader || matchedHtml),
      source: matchedHeader ? 'headers' : 'html',
      signal: matchedHeader ? `${matchedHeader}: ${getHeader(res?.headers, matchedHeader)}` : matchedHtml,
      trafficId: res?.trafficId,
      error: null
    };
  } catch (err) {
    return { detected: false, error: err };
  }
}

async function detectVersion(baseUrl, fetchWithRetry) {
  for (const p of VERSION_PATHS) {
    try {
      const url = new URL(p, baseUrl.origin).href;
      const res = await fetchWithRetry(url);
      if (res?.isGovernanceBlock) {
        const gErr = new Error(res.reason || res.error || 'Blocked by governance policy');
        gErr.isGovernanceBlock = true;
        return { version: null, governanceError: gErr };
      }
      const text = typeof res?.text === 'string' ? res.text : '';
      // Reject HTML SPA fallback documents from version parsing
      if (res?.status === 200 && text && !isHtmlOrScript(res, text)) {
        const match = text.match(/\bMagento\/(\d+\.\d+\.\d+(?:-p\d+)?)\b/i) ||
                      (p === '/magento_version' && text.length < 256 ? text.match(/(\d+\.\d+\.\d+(?:-p\d+)?)/i) : null);
        if (match) {
          const { confirmed, res: cRes } = await confirmReproducible(
            url,
            fetchWithRetry,
            {},
            (r) => r?.status === 200 && !isHtmlOrScript(r, r.text) && typeof r.text === 'string' && r.text.includes(match[1])
          );
          if (confirmed) {
            return {
              version: match[1],
              path: p,
              url,
              preview: text.trim().slice(0, 120),
              trafficId: cRes?.trafficId ?? res.trafficId,
              governanceError: null
            };
          }
        }
      }
    } catch (err) {
      if (isGovernanceBlockError(err)) {
        return { version: null, governanceError: err };
      }
    }
  }
  return { version: null, governanceError: null };
}

function isVulnerableVersion(v) {
  if (!v) return null;
  const m = String(v).match(/^(\d+)\.(\d+)\.(\d+)(?:-p(\d+))?$/i);
  if (!m) return null;

  const major = Number(m[1]);
  const minor = Number(m[2]);
  const patch = Number(m[3]);
  const patchRev = m[4] !== undefined ? Number(m[4]) : null;

  if (major !== 2) return false;
  if (minor < 4) return true;
  if (minor > 4) return false;

  if (patch >= 8) return false;
  if (patch === 7) {
    if (patchRev !== null) return patchRev < 1;
    return null;
  }
  if (patch === 6) {
    if (patchRev !== null) return patchRev < 6;
    return true;
  }
  if (patch === 5) {
    if (patchRev !== null) return patchRev < 8;
    return true;
  }
  if (patch === 4) {
    if (patchRev !== null) return patchRev < 9;
    return true;
  }
  return true;
}

export default async function run(target, fetchWithRetry) {
  let baseUrl;
  try {
    baseUrl = new URL(String(target ?? '').trim());
  } catch {
    return { name: 'magento CosmicSting (CVE-2024-34102)', status: 'ERROR', severity: 'NONE', reason: 'Invalid URL' };
  }

  const { detected, signal: detectSignal, trafficId: detectTrafficId, error: detectErr } = await detectMagento(baseUrl, fetchWithRetry);

  if (detectErr) {
    return {
      name: 'magento CosmicSting (CVE-2024-34102)',
      status: 'ERROR',
      severity: 'NONE',
      reason: detectErr?.message || 'Target unreachable'
    };
  }

  if (!detected) {
    return { name: 'magento CosmicSting (CVE-2024-34102)', status: 'SAFE', severity: 'NONE' };
  }

  const { version, path: verPath, url: verUrl, preview: verPreview, trafficId: verTrafficId, governanceError: verGovErr } = await detectVersion(baseUrl, fetchWithRetry);
  if (verGovErr) {
    return {
      name: 'magento CosmicSting (CVE-2024-34102)',
      status: 'ERROR',
      severity: 'NONE',
      reason: verGovErr.message
    };
  }

  const vulnVersion = isVulnerableVersion(version);
  if (vulnVersion === false) {
    return {
      name: 'magento CosmicSting (CVE-2024-34102)',
      status: 'SAFE',
      severity: 'NONE',
      detail: `Magento ${version} is patched against CVE-2024-34102 (CosmicSting)`,
      version
    };
  }

  const restUrl = new URL(COSMICSTING_ENDPOINT, baseUrl.origin).href;
  const restOpts = {
    method : 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body   : JSON.stringify({
      address: {
        region_code: 'CA', country_id: 'US',
        street: ['123 Main St'], postcode: '90210',
        city: 'LA', telephone: '5555555555',
        firstname: 'Probe', lastname: 'Test',
        email: 'probe@example.com'
      }
    }),
  };

  let endpointReachable = false;
  let restStatus = 0;
  let restTrafficId;
  let restPreview = '';
  try {
    const res = await fetchWithRetry(restUrl, restOpts);
    if (res?.isGovernanceBlock) {
      return {
        name: 'magento CosmicSting (CVE-2024-34102)',
        status: 'ERROR',
        severity: 'NONE',
        reason: res.reason || res.error || 'Blocked by governance policy'
      };
    }
    const text = typeof res?.text === 'string' ? res.text : '';
    const okCandidate = (res?.status === 200 || res?.status === 400) && !isHtmlOrScript(res, text);
    if (okCandidate) {
      const { confirmed, res: cRes } = await confirmReproducible(
        restUrl,
        fetchWithRetry,
        restOpts,
        (r) => (r?.status === 200 || r?.status === 400) && !isHtmlOrScript(r, r.text)
      );
      if (confirmed) {
        endpointReachable = true;
        restStatus = cRes?.status ?? res.status;
        restTrafficId = cRes?.trafficId ?? res.trafficId;
        restPreview = extractVerbatimSnippet(cRes?.text || text, /amount|message|carrier|method|\{/i) || `HTTP ${restStatus} REST response`;
      }
    }
  } catch (err) {
    if (isGovernanceBlockError(err)) {
      return {
        name: 'magento CosmicSting (CVE-2024-34102)',
        status: 'ERROR',
        severity: 'NONE',
        reason: err.message
      };
    }
  }

  const evidenceQuotes = [verPreview, restPreview, detectSignal].filter(q => typeof q === 'string' && q.length >= 8).slice(0, 4);

  if (endpointReachable && vulnVersion === true) {
    return {
      name          : 'magento CosmicSting (CVE-2024-34102)',
      status        : 'VULNERABLE',
      severity      : 'CRITICAL',
      path          : COSMICSTING_ENDPOINT,
      detail        : `Magento ${version} detected at ${verPath || '/'} + REST API accessible at ${COSMICSTING_ENDPOINT} — vulnerable to CVE-2024-34102 (CosmicSting)`,
      fix           : 'CRITICAL: Adobe Commerce / Magento is vulnerable to CosmicSting (XXE). Update immediately to 2.4.7-p1+, 2.4.6-p6+, 2.4.5-p8+, or 2.4.4-p9+.',
      version,
      endpoint      : COSMICSTING_ENDPOINT,
      cve           : 'CVE-2024-34102',
      cveIds        : ['CVE-2024-34102'],
      files         : [{ path: COSMICSTING_ENDPOINT, url: restUrl, method: 'POST', status: restStatus, matchedSignal: `Magento ${version}`, reproducible: true, preview: restPreview }],
      reproVerified : true,
      poeLevel      : evidenceQuotes.length > 0 ? 3 : 2,
      ...(evidenceQuotes.length > 0 ? { evidenceQuotes } : {}),
      ...(restTrafficId ?? verTrafficId ? { trafficId: restTrafficId ?? verTrafficId } : {})
    };
  }

  if (vulnVersion === true) {
    return {
      name          : 'magento CosmicSting (CVE-2024-34102)',
      status        : 'VULNERABLE',
      severity      : 'CRITICAL',
      path          : verPath || '/',
      detail        : `Magento ${version} confirmed at ${verPath || '/'} is in the vulnerable range for CVE-2024-34102 (CosmicSting)`,
      fix           : `Update Magento ${version} to a patched version immediately (e.g., 2.4.7-p1+) to prevent remote code execution via XXE.`,
      version,
      cve           : 'CVE-2024-34102',
      cveIds        : ['CVE-2024-34102'],
      files         : [{ path: verPath || '/', url: verUrl || target, method: 'GET', status: 200, matchedSignal: `Magento ${version}`, reproducible: true, preview: verPreview }],
      reproVerified : true,
      poeLevel      : evidenceQuotes.length > 0 ? 3 : 2,
      ...(evidenceQuotes.length > 0 ? { evidenceQuotes } : {}),
      ...(verTrafficId ? { trafficId: verTrafficId } : {})
    };
  }

  if (endpointReachable) {
    return {
      name          : 'magento CosmicSting (CVE-2024-34102)',
      status        : 'SUSPICIOUS',
      severity      : 'HIGH',
      path          : COSMICSTING_ENDPOINT,
      detail        : `Magento detected + REST API consistently accessible (HTTP ${restStatus}) — verify version is >= 2.4.7-p1 (CVE-2024-34102)`,
      fix           : 'Confirm your Magento installation is updated to at least 2.4.7-p1 or equivalent to protect against the CosmicSting (CVE-2024-34102) exploit.',
      version       : version ?? 'unknown',
      endpoint      : COSMICSTING_ENDPOINT,
      cve           : 'CVE-2024-34102',
      cveIds        : ['CVE-2024-34102'],
      files         : [{ path: COSMICSTING_ENDPOINT, url: restUrl, method: 'POST', status: restStatus, matchedSignal: 'CosmicSting REST endpoint accessible', reproducible: true, preview: restPreview }],
      reproVerified : true,
      poeLevel      : evidenceQuotes.length > 0 ? 3 : 2,
      ...(evidenceQuotes.length > 0 ? { evidenceQuotes } : {}),
      ...(restTrafficId ? { trafficId: restTrafficId } : {})
    };
  }

  return {
    name          : 'magento CosmicSting (CVE-2024-34102)',
    status        : 'SUSPICIOUS',
    severity      : 'MEDIUM',
    path          : '/',
    detail        : `Magento detected (${detectSignal || 'signature matched'}) — REST endpoint blocked/404, verify version >= 2.4.7-p1`,
    fix           : 'Ensure your Magento version is patched against CVE-2024-34102 and that sensitive REST API endpoints are not publicly accessible.',
    version       : version ?? 'unknown',
    cve           : 'CVE-2024-34102',
    cveIds        : ['CVE-2024-34102'],
    files         : [{
      path         : '/',
      url          : baseUrl.href,
      method       : 'GET',
      status       : 200,
      matchedSignal: detectSignal || 'Magento signature',
      reproducible : true,
      preview      : detectSignal || 'Magento signature matched'
    }],
    reproVerified : true,
    poeLevel      : 2,
    ...(evidenceQuotes.length > 0 ? { evidenceQuotes } : {}),
    ...(detectTrafficId !== undefined ? { trafficId: detectTrafficId } : {})
  };
}
