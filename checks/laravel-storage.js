import { URL } from 'node:url';
import {
  isRedirectedToDifferentPath,
  extractVerbatimSnippet,
  confirmReproducible
} from '../core/check-verify.js';

export const tags = ['laravel'];

const LOG_PATH = '/storage/logs/laravel.log';

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

function isExposedLaravelLog(res, logUrl) {
  if (!res || res.status !== 200 || isRedirectedToDifferentPath(res, logUrl)) return false;
  const rawText = typeof res.text === 'string' ? res.text : '';
  if (!rawText || isHtmlResponse(res, rawText)) return false;
  const text = rawText.toLowerCase();
  return text.includes('exception') || text.includes('stack trace');
}

export default async function run(target, fetchWithRetry) {
  let baseUrl;
  try {
    baseUrl = new URL(String(target ?? '').trim());
  } catch {
    return { name: 'laravel log exposure', status: 'ERROR', severity: 'NONE', reason: 'Invalid URL' };
  }

  try {
    const logUrl = new URL(LOG_PATH, baseUrl.origin).href;
    const fetchOpts = { followRedirects: false };
    const res = await fetchWithRetry(logUrl, fetchOpts);
    if (res?.isGovernanceBlock) {
      return {
        name: 'laravel log exposure',
        status: 'ERROR',
        severity: 'NONE',
        reason: res.reason || res.error || 'Blocked by governance policy'
      };
    }

    if (isExposedLaravelLog(res, logUrl)) {
      const { confirmed, res: confirmRes } = await confirmReproducible(
        logUrl,
        fetchWithRetry,
        fetchOpts,
        (r) => isExposedLaravelLog(r, logUrl)
      );
      if (confirmed) {
        const finalRes = confirmRes || res;
        const finalText = typeof finalRes?.text === 'string' ? finalRes.text : (res?.text || '');
        const snippet = extractVerbatimSnippet(finalText, /exception|stack trace/i) || 'Laravel log stack trace exposed';
        const trafficId = finalRes?.trafficId ?? res?.trafficId;
        return {
          name          : 'laravel log exposure',
          status        : 'VULNERABLE',
          severity      : 'HIGH',
          path          : LOG_PATH,
          url           : logUrl,
          detail        : `Confirmed reproducible Laravel application log exposure at ${LOG_PATH}`,
          files         : [{
            path         : LOG_PATH,
            url          : logUrl,
            method       : 'GET',
            status       : 200,
            matchedSignal: 'Laravel log exception / stack trace',
            reproducible : true,
            preview      : snippet
          }],
          reproVerified : true,
          poeLevel      : snippet.length >= 8 ? 3 : 2,
          ...(snippet.length >= 8 ? { evidenceQuotes: [snippet] } : {}),
          ...(trafficId !== undefined ? { trafficId } : {}),
          fix           : "Deny public access to the '/storage' directory in your web server configuration or move the storage folder outside of the web root."
        };
      }
    }

    return {
      name: 'laravel log exposure',
      status: 'SAFE',
      severity: 'NONE'
    };

  } catch (e) {
    return {
      name: 'laravel log exposure',
      status: 'ERROR',
      severity: 'NONE',
      reason: e?.message || 'Request failed'
    };
  }
}
