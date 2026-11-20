import { URL } from 'node:url';

export const tags = ['php', 'laravel', 'wordpress', 'drupal', 'magento', 'symfony', 'codeigniter', 'joomla'];

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

/**
 * PHP-CGI / PHP-FPM Direct Exposure
 */
const CGI_SIGNALS = [
  'x-powered-by: php',
  'php version',
  'usage: php',
  'no input file specified',
  'php credits',
  'cgi/1.1'
];

const CHECKS = [
  // ── PHP-FPM endpoints ─────────────────────────────────────────────────────
  {
    path    : '/fpm-ping',
    isPing  : true,
    signals : [],
    severity: 'HIGH',
    detail  : 'PHP-FPM ping endpoint accessible — FPM exposed directly to internet'
  },
  {
    path    : '/php-fpm-ping',
    isPing  : true,
    signals : [],
    severity: 'HIGH',
    detail  : 'PHP-FPM ping endpoint accessible at /php-fpm-ping'
  },
  {
    path    : '/php-status',
    signals : ['pool:', 'process manager:', 'idle processes:', 'active processes:'],
    severity: 'HIGH',
    detail  : 'PHP-FPM status page accessible — leaks worker count, request rate, memory usage, and exposes stored XSS vector (CVE-2026-129292) on unpatched PHP'
  },
  {
    path    : '/php-fpm-status',
    signals : ['pool:', 'process manager:', 'idle processes:'],
    severity: 'HIGH',
    detail  : 'PHP-FPM status page accessible at /php-fpm-status — potential CVE-2026-129292 stored XSS vector on unpatched PHP'
  },

  // ── PHP CGI binary paths ──────────────────────────────────────────────────
  {
    path    : '/cgi-bin/php',
    signals : CGI_SIGNALS,
    severity: 'HIGH',
    detail  : 'PHP CGI binary directly accessible at /cgi-bin/php — potential CVE-2024-4577 and CVE-2026-129538 (PATH_INFO OOB R/W) vector'
  },
  {
    path    : '/cgi-bin/php-cgi',
    signals : CGI_SIGNALS,
    severity: 'HIGH',
    detail  : 'PHP CGI binary directly accessible at /cgi-bin/php-cgi — potential CVE-2024-4577 and CVE-2026-129538 (PATH_INFO OOB R/W) vector'
  },
  {
    path    : '/php-cgi/php.cgi',
    signals : CGI_SIGNALS,
    severity: 'HIGH',
    detail  : 'PHP CGI binary accessible at /php-cgi/php.cgi (common XAMPP/Windows path) — potential CVE-2024-4577 and CVE-2026-129538 vector'
  },
];

export default async function run(target, fetchWithRetry) {
  let baseUrl;
  try {
    baseUrl = new URL(String(target ?? '').trim());
  } catch {
    return { name: 'php-cgi/fpm exposure', status: 'ERROR', severity: 'NONE', reason: 'Invalid URL' };
  }

  const found = [];
  let networkSuccess = false;
  let lastError = null;

  for (const check of CHECKS) {
    try {
      const checkUrl = new URL(check.path, baseUrl.origin).href;
      const res = await fetchWithRetry(checkUrl, { followRedirects: false });
      if (res?.isGovernanceBlock) {
        return {
          name: 'php-cgi/fpm exposure',
          status: 'ERROR',
          severity: 'NONE',
          reason: res.reason || res.error || 'Blocked by governance policy'
        };
      }

      networkSuccess = true;
      if (res?.status !== 200) continue;

      const rawText = typeof res?.text === 'string' ? res.text : '';
      const body = rawText.toLowerCase();

      if (check.isPing) {
        if (!isHtmlResponse(res, rawText) && body.trim() === 'pong') {
          found.push({
            path: check.path,
            url: checkUrl,
            method: 'GET',
            status: 200,
            severity: check.severity,
            matchedSignal: 'PHP-FPM ping "pong"',
            reproducible: true,
            preview: `HTTP 200 pong on ${check.path}`,
            detail: check.detail,
            ...(res?.trafficId !== undefined ? { trafficId: res.trafficId } : {})
          });
        }
        continue;
      }

      if (isHtmlResponse(res, rawText)) continue;

      const matchedSig = check.signals.find(s => body.includes(s.toLowerCase()));
      if (matchedSig) {
        const preview = rawText.replace(/[\r\n\t]+/g, ' ').trim().slice(0, 120) || matchedSig;
        found.push({
          path: check.path,
          url: checkUrl,
          method: 'GET',
          status: 200,
          severity: check.severity,
          matchedSignal: matchedSig,
          reproducible: true,
          preview,
          detail: check.detail,
          ...(res?.trafficId !== undefined ? { trafficId: res.trafficId } : {})
        });
      }
    } catch (err) {
      if (isGovernanceBlockError(err)) {
        return { name: 'php-cgi/fpm exposure', status: 'ERROR', severity: 'NONE', reason: err.message };
      }
      lastError = err;
    }
  }

  if (!found.length) {
    if (!networkSuccess) {
      return {
        name: 'php-cgi/fpm exposure',
        status: 'ERROR',
        severity: 'NONE',
        reason: lastError?.message || 'Target unreachable'
      };
    }
    return { name: 'php-cgi/fpm exposure', status: 'SAFE', severity: 'NONE' };
  }

  const primary = found[0];
  const evidenceQuotes = found.map(f => f.preview).filter(q => typeof q === 'string' && q.length >= 8).slice(0, 5);

  return {
    name          : 'php-cgi/fpm exposure',
    status        : 'VULNERABLE',
    severity      : 'HIGH',
    path          : primary.path,
    findings      : found,
    files         : found,
    detail        : `${found.length} PHP-FPM/CGI endpoint(s) publicly accessible: ${found.map(f => f.path).join(', ')}`,
    reproVerified : true,
    poeLevel      : evidenceQuotes.length > 0 ? 3 : 2,
    ...(evidenceQuotes.length > 0 ? { evidenceQuotes } : {}),
    ...(primary.trafficId !== undefined ? { trafficId: primary.trafficId } : {}),
    fix           : "Restrict access to '/php-status', '/php-fpm-status', and '/fpm-ping' to local or trusted IP addresses in your Nginx/Apache configuration, remove or strictly protect any CGI binaries in '/cgi-bin/', and upgrade PHP to 8.2.36+, 8.3.37+, 8.4.28+, 8.5.13+, or 8.6.0+ to mitigate CVE-2026-129292 and CVE-2026-129538."
  };
}
