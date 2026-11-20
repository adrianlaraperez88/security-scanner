import { URL } from 'node:url';

export const tags = ['all'];

function getHeader(headers, name) {
  if (!headers || typeof headers !== 'object') return '';
  const targetLower = String(name).toLowerCase();
  if (typeof headers.get === 'function') {
    return String(headers.get(name) ?? headers.get(targetLower) ?? '');
  }
  for (const [k, v] of Object.entries(headers)) {
    if (String(k).toLowerCase() === targetLower && v !== undefined && v !== null) {
      return Array.isArray(v) ? v.join(', ') : String(v);
    }
  }
  return '';
}

function isHtmlResponse(res, text) {
  const ct = getHeader(res?.headers, 'content-type').toLowerCase();
  if (ct.includes('text/html') || ct.includes('application/xhtml+xml')) return true;
  return /^\s*(?:<!doctype\s+html|<html\b)/i.test(text);
}

export default async function run(target, fetchWithRetry) {
  let baseUrl;
  try {
    baseUrl = new URL(String(target ?? '').trim());
  } catch {
    return { name: '.git exposure', status: 'ERROR', severity: 'NONE', reason: 'Invalid URL' };
  }

  try {
    const headUrl = new URL('/.git/HEAD', baseUrl.origin).href;
    const res = await fetchWithRetry(headUrl);
    if (res?.isGovernanceBlock) {
      return {
        name: '.git exposure',
        status: 'ERROR',
        severity: 'NONE',
        reason: res.reason || res.error || 'Blocked by governance policy'
      };
    }

    const text = typeof res?.text === 'string' ? res.text : '';

    if (res?.status === 200 && !isHtmlResponse(res, text) && /^\s*ref:\s*\S+/im.test(text)) {
      let confirmed = true;
      let confirmRes = null;
      try {
        confirmRes = await fetchWithRetry(headUrl);
        const confirmText = typeof confirmRes?.text === 'string' ? confirmRes.text : '';
        confirmed = Boolean(confirmRes?.status === 200 && !isHtmlResponse(confirmRes, confirmText) && /^\s*ref:\s*\S+/im.test(confirmText));
      } catch {
        confirmed = false;
      }

      if (confirmed) {
        const refMatch = text.match(/^\s*ref:\s*\S+/im)?.[0]?.trim() || 'ref: refs/heads/';
        const trafficId = confirmRes?.trafficId ?? res?.trafficId;
        return {
          name: '.git exposure',
          status: 'VULNERABLE',
          severity: 'HIGH',
          path: '/.git/HEAD',
          detail: `Confirmed reproducible .git metadata exposure at /.git/HEAD (HTTP 200, matched "${refMatch.slice(0, 60)}")`,
          reproVerified: true,
          poeLevel: refMatch.length >= 8 ? 3 : 2,
          ...(refMatch.length >= 8 ? { evidenceQuotes: [refMatch.slice(0, 120)] } : {}),
          fix: "Remove the '.git' folder from the production web server or deny all access strictly in your web server configuration.",
          ...(trafficId !== undefined ? { trafficId } : {})
        };
      }
    }

    return {
      name: '.git exposure',
      status: 'SAFE',
      severity: 'NONE'
    };

  } catch (e) {
    return {
      name: '.git exposure',
      status: 'ERROR',
      severity: 'NONE',
      reason: e?.message || 'Request failed'
    };
  }
}
