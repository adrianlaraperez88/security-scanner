import { URL } from 'node:url';
import { redactSecretsInText } from '../core/ai-advisor.js';

export const tags = ['all'];

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
  if (ct.includes('javascript') || ct.includes('ecmascript') || ct.includes('text/css')) return true;
  const trimmed = String(text || '').trimStart().slice(0, 1200);
  if (/^(?:<!doctype\s+html|<html\b|<head\b|<body\b|<app-root\b)/i.test(trimmed)) return true;
  if (/<script\b/i.test(trimmed) && (/<div\b/i.test(trimmed) || /<app-root\b/i.test(trimmed) || /__NEXT_DATA__/i.test(trimmed))) {
    return true;
  }
  return false;
}

function tryParseJsonObject(text) {
  const trimmed = String(text || '').trim();
  if (!trimmed.startsWith('{') || trimmed.length > 524_288) return null;
  try {
    const parsed = JSON.parse(trimmed);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function buildEvidenceSnippet(text, signal = '') {
  const raw = String(text || '');
  const idx = signal ? raw.indexOf(signal) : -1;
  const slice = idx >= 0
    ? raw.slice(Math.max(0, idx - 20), idx + 140)
    : raw.slice(0, 160);
  const clean = redactSecretsInText(slice.replace(/[\r\n\t]+/g, ' ').replace(/\s{2,}/g, ' ').trim());
  if (clean.length >= 8) return clean;
  if (signal && signal.length >= 8) return redactSecretsInText(signal);
  return '';
}

/**
 * Checks for sensitive files accidentally exposed at the web root.
 * Strict structural matching + repeat confirmation prevents false positives on SPA fallbacks
 * or generic JSON error pages.
 */
const FILES = [
  {
    path    : '/composer.json',
    severity: 'MEDIUM',
    reason  : 'Reveals dependency names and version constraints',
    signals : ['"require"', '"name"'],
    match   : (text) => {
      const obj = tryParseJsonObject(text);
      if (!obj) return null;
      const hasComposerDeps = Boolean(
        (obj.require && typeof obj.require === 'object' && !Array.isArray(obj.require)) ||
        (obj['require-dev'] && typeof obj['require-dev'] === 'object' && !Array.isArray(obj['require-dev'])) ||
        (obj.autoload && typeof obj.autoload === 'object') ||
        Array.isArray(obj.repositories)
      );
      const hasPkgName = typeof obj.name === 'string' && obj.name.includes('/');
      if (!hasComposerDeps || (!hasPkgName && !obj.type && !obj.description && !obj.license)) return null;
      return hasPkgName ? `composer.json manifest (${obj.name})` : '"require"';
    }
  },
  {
    path    : '/composer.lock',
    severity: 'HIGH',
    reason  : 'Reveals exact dependency versions — attacker can look up CVEs for each',
    signals : ['"packages"', '"version"', '"dist"'],
    match   : (text) => {
      const obj = tryParseJsonObject(text);
      if (!obj || !Array.isArray(obj.packages)) return null;
      const looksLikeLock = Boolean(
        Array.isArray(obj._readme) ||
        typeof obj['content-hash'] === 'string' ||
        Array.isArray(obj['packages-dev']) ||
        obj.packages.some(p => p && typeof p.name === 'string' && typeof p.version === 'string' && (p.dist || p.source))
      );
      return looksLikeLock ? '"packages" lockfile' : null;
    }
  },
  {
    path    : '/package.json',
    severity: 'LOW',
    reason  : 'Frontend dependency disclosure',
    signals : ['"dependencies"', '"scripts"', '"version"'],
    match   : (text) => {
      const obj = tryParseJsonObject(text);
      if (!obj || typeof obj.name !== 'string' || !obj.name.trim()) return null;
      const hasNpmSection = Boolean(
        (obj.dependencies && typeof obj.dependencies === 'object' && !Array.isArray(obj.dependencies)) ||
        (obj.devDependencies && typeof obj.devDependencies === 'object' && !Array.isArray(obj.devDependencies)) ||
        (obj.scripts && typeof obj.scripts === 'object' && !Array.isArray(obj.scripts)) ||
        (obj.peerDependencies && typeof obj.peerDependencies === 'object')
      );
      return hasNpmSection ? `package.json manifest (${obj.name})` : null;
    }
  },
  {
    path    : '/package-lock.json',
    severity: 'LOW',
    reason  : 'Exact frontend dependency versions',
    signals : ['"lockfileVersion"', '"packages"'],
    match   : (text) => {
      const obj = tryParseJsonObject(text);
      if (!obj || !Number.isFinite(Number(obj.lockfileVersion))) return null;
      if (!obj.packages && !obj.dependencies) return null;
      return `"lockfileVersion": ${obj.lockfileVersion}`;
    }
  },
  {
    path    : '/.htaccess',
    severity: 'MEDIUM',
    reason  : 'Web server configuration exposed',
    signals : ['RewriteRule', 'Options', 'Allow from', 'Deny from'],
    match   : (text) => {
      const trimmed = String(text || '').trim();
      if (!trimmed || trimmed.startsWith('{') || trimmed.startsWith('[')) return null;
      if (/\b(?:function\s*\(|import\s+[\w{*]|export\s+(?:default|const|function|class)|window\.|document\.)/.test(trimmed.slice(0, 1000))) {
        return null;
      }
      const m = trimmed.match(/^\s*(?:RewriteEngine\s+(?:on|off)|RewriteRule\s+\S[^\r\n]+|RewriteCond\s+\S[^\r\n]+|Options\s+[+-][A-Za-z]+|(?:Allow|Deny)\s+from\s+\S+|Require\s+(?:all|ip|host|valid-user)\b|ErrorDocument\s+\d{3}\s+\S+|DirectoryIndex\s+\S+)/im);
      return m ? m[0].trim() : null;
    }
  },
  {
    path    : '/artisan',
    severity: 'MEDIUM',
    reason  : 'Laravel CLI entry point exposed — confirms stack and root path',
    signals : ['artisan', 'Laravel', 'Illuminate'],
    match   : (text) => {
      const s = String(text || '');
      const hasPhpPrefix = /^(?:#!\/usr\/bin\/(?:env\s+)?php|<\?php)\b/m.test(s.slice(0, 300));
      if (!hasPhpPrefix) return null;
      const sig = ['Illuminate', 'Laravel', 'artisan'].find(k => s.includes(k));
      return sig ? `PHP artisan (${sig})` : null;
    }
  },
  {
    path    : '/.DS_Store',
    severity: 'MEDIUM',
    reason  : 'macOS artifact — reveals directory structure to attackers',
    signals : ['Bud1'],
    match   : (text) => (String(text || '').slice(0, 16).includes('Bud1') ? 'Bud1 DS_Store header' : null)
  },
  {
    path    : '/web.config',
    severity: 'MEDIUM',
    reason  : 'IIS configuration file exposed',
    signals : ['<configuration>', '<system.web>', 'connectionStrings'],
    match   : (text) => {
      const s = String(text || '');
      if (!/<configuration[\s>]/i.test(s)) return null;
      const m = s.match(/<(?:system\.web|system\.webServer|connectionStrings|appSettings)[\s>]/i);
      return m ? m[0] : null;
    }
  },
  {
    path    : '/storage/logs/laravel.log',
    severity: 'HIGH',
    reason  : 'Application log file exposed (checked separately in laravel-storage.js)',
    signals : ['[error]', 'exception', 'stack trace'],
    skip    : true   // Already handled by laravel-storage.js
  },
  {
    path    : '/.git/config',
    severity: 'HIGH',
    reason  : 'Git config exposed — reveals remote URL and branch info',
    signals : ['[core]', '[remote', 'repositoryformatversion'],
    match   : (text) => {
      const s = String(text || '');
      if (!/^\s*\[core\]/m.test(s)) return null;
      const m = s.match(/(?:repositoryformatversion\s*=\s*\d+|^\s*\[remote\s+["'][^"']+["']\])/m);
      return m ? `[core] ${m[0].trim()}` : null;
    }
  },
];

export default async function run(target, fetchWithRetry) {
  let baseUrl;
  try {
    baseUrl = new URL(String(target ?? '').trim());
  } catch {
    return { name: 'sensitive files', status: 'ERROR', severity: 'NONE', reason: 'Invalid URL' };
  }

  const found = [];
  let networkSuccess = false;
  let lastError = null;
  let firstTrafficId = undefined;

  for (const file of FILES) {
    if (file.skip) continue;

    try {
      const fileUrl = new URL(file.path, baseUrl.origin).href;
      const res = await fetchWithRetry(fileUrl);
      if (res?.isGovernanceBlock) {
        return {
          name: 'sensitive files',
          status: 'ERROR',
          severity: 'NONE',
          reason: res.reason || res.error || 'Blocked by governance policy'
        };
      }

      networkSuccess = true;
      if (res?.status !== 200) continue;

      const text = typeof res?.text === 'string' ? res.text : '';
      if (!text || isHtmlResponse(res, text)) continue;

      const matchedSignal = typeof file.match === 'function'
        ? file.match(text)
        : (file.signals.find(sig => text.includes(sig)) || null);

      if (!matchedSignal) continue;

      // Reproducibility confirmation probe (prevents single-request/transient FPs)
      let confirmed = true;
      let confirmRes = null;
      try {
        confirmRes = await fetchWithRetry(fileUrl);
        if (confirmRes?.isGovernanceBlock) {
          confirmed = false;
        } else {
          const confirmText = typeof confirmRes?.text === 'string' ? confirmRes.text : '';
          const confirmSignal = (confirmRes?.status === 200 && confirmText && !isHtmlResponse(confirmRes, confirmText))
            ? (typeof file.match === 'function'
                ? file.match(confirmText)
                : (file.signals.find(sig => confirmText.includes(sig)) || null))
            : null;
          confirmed = Boolean(confirmSignal);
        }
      } catch {
        confirmed = false;
      }

      if (!confirmed) continue;

      const ct = getHeader(confirmRes?.headers || res?.headers, 'content-type') || 'unknown';
      const quote = buildEvidenceSnippet(text, typeof matchedSignal === 'string' ? matchedSignal : '');
      const trafficId = confirmRes?.trafficId ?? res?.trafficId;
      if (firstTrafficId === undefined && trafficId !== undefined) {
        firstTrafficId = trafficId;
      }

      found.push({
        path: file.path,
        url: fileUrl,
        method: 'GET',
        status: 200,
        contentType: ct.slice(0, 80),
        severity: file.severity,
        reason: file.reason,
        matchedSignal: String(matchedSignal).slice(0, 120),
        reproducible: true,
        ...(quote ? { preview: quote } : {})
      });
    } catch (err) {
      if (isGovernanceBlockError(err)) {
        return {
          name: 'sensitive files',
          status: 'ERROR',
          severity: 'NONE',
          reason: err.message
        };
      }
      lastError = err;
    }
  }

  if (found.length === 0) {
    if (!networkSuccess) {
      return {
        name: 'sensitive files',
        status: 'ERROR',
        severity: 'NONE',
        reason: lastError?.message || 'Target unreachable'
      };
    }
    return { name: 'sensitive files', status: 'SAFE', severity: 'NONE' };
  }

  const maxSev = found.some(f => f.severity === 'HIGH')   ? 'HIGH'
               : found.some(f => f.severity === 'MEDIUM') ? 'MEDIUM'
               : 'LOW';
  const evidenceQuotes = found.map(f => f.preview).filter(q => typeof q === 'string' && q.trim().length >= 8).slice(0, 5);
  const summaryList = found.map(f => `${f.path} (HTTP ${f.status}, ${f.matchedSignal})`).join('; ');

  return {
    name          : 'sensitive files',
    status        : 'VULNERABLE',
    severity      : maxSev,
    path          : found[0].path,
    detail        : `Confirmed reproducible exposure of ${found.length} sensitive file(s): ${summaryList}`,
    reproVerified : true,
    files         : found,
    findings      : found.map(f => ({
      path: f.path,
      url: f.url,
      method: f.method,
      status: 'VULNERABLE',
      severity: f.severity,
      detail: `${f.path} returned HTTP ${f.status} (${f.contentType}) matching ${f.matchedSignal}`,
      reason: f.reason,
      matchedSignal: f.matchedSignal,
      reproducible: true
    })),
    poeLevel      : evidenceQuotes.length > 0 ? 3 : 2,
    ...(evidenceQuotes.length > 0 ? { evidenceQuotes } : {}),
    ...(firstTrafficId !== undefined ? { trafficId: firstTrafficId } : {}),
    fix           : 'Remove sensitive configuration or metadata files from the web root or deny access to them in your web server configuration (e.g., .htaccess, composer.json, etc.).'
  };
}
