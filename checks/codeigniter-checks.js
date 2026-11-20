import {
  isHtmlOrScript,
  isRedirectedToDifferentPath,
  isFrameworkRouteErrorResponse,
  extractVerbatimSnippet,
  confirmReproducible
} from '../core/check-verify.js';

export const tags = ['codeigniter'];

const VERSION_RE = /CodeIgniter\s+Version\s+([\d.]+)/i;

function isVulnerableCI4(version) {
  const [major, minor, patch = 0] = version.split('.').map(Number);
  if (major !== 4) return false;
  if (minor < 6) return true;
  if (minor === 6 && patch < 2) return true;
  return false;
}

const CHECKS = [
  {
    path    : '/application/logs/',
    severity: 'HIGH',
    detail  : 'CodeIgniter log directory listing — stack traces and credentials exposed',
    validate: (res) => {
      const text = typeof res?.text === 'string' ? res.text : '';
      const lower = text.toLowerCase();
      return lower.includes('index of') || /href=["'][^"']*log-\d{4}-\d{2}-\d{2}\.php/i.test(text);
    },
    signalDesc: 'CodeIgniter log directory index'
  },
  {
    path    : '/application/config/database.php',
    severity: 'CRITICAL',
    detail  : 'CodeIgniter database config accessible — DB credentials exposed',
    validate: (res) => {
      const text = typeof res?.text === 'string' ? res.text : '';
      if (isHtmlOrScript(res, text)) return false;
      return text.includes('<?php') && /\$db\[|dbdriver|password/i.test(text);
    },
    signalDesc: 'PHP database.php source'
  },
  {
    path    : '/system/',
    severity: 'HIGH',
    detail  : 'CodeIgniter /system/ directory browsable — source code accessible',
    validate: (res) => {
      const lower = (typeof res?.text === 'string' ? res.text : '').toLowerCase();
      return lower.includes('index of') && (lower.includes('parent directory') || lower.includes('codeigniter') || lower.includes('core'));
    },
    signalDesc: 'CodeIgniter /system/ directory index'
  },
  {
    path    : '/install/',
    severity: 'HIGH',
    detail  : 'CodeIgniter install script accessible — should be removed in production',
    validate: (res) => {
      const lower = (typeof res?.text === 'string' ? res.text : '').toLowerCase();
      return lower.includes('codeigniter') && (lower.includes('install') || lower.includes('setup'));
    },
    signalDesc: 'CodeIgniter installer UI'
  },
];

export default async function run(target, fetchWithRetry) {
  const findings = [];
  let detectedVersion = null;
  let versionUrl = target;
  let versionPath = '/';

  try {
    const res  = await fetchWithRetry(target);
    const body = typeof res?.text === 'string' ? res.text : '';
    const m    = body.match(VERSION_RE);
    if (m) detectedVersion = m[1];
  } catch { /* skip */ }

  try {
    const welcomeUrl = `${target}/index.php/welcome/index`;
    const res  = await fetchWithRetry(welcomeUrl);
    const body = typeof res?.text === 'string' ? res.text : '';
    if (res?.status === 200 && body.toLowerCase().includes('welcome to codeigniter')) {
      const m = body.match(VERSION_RE);
      if (m) {
        detectedVersion = m[1];
        versionUrl = welcomeUrl;
        versionPath = '/index.php/welcome/index';
      }
      const { confirmed, res: cRes } = await confirmReproducible(
        welcomeUrl,
        fetchWithRetry,
        {},
        (r) => r?.status === 200 && typeof r?.text === 'string' && r.text.toLowerCase().includes('codeigniter')
      );
      if (confirmed) {
        findings.push({
          path         : '/index.php/welcome/index',
          url          : welcomeUrl,
          method       : 'GET',
          status       : 200,
          severity     : 'LOW',
          matchedSignal: 'Welcome to CodeIgniter',
          reproducible : true,
          preview      : extractVerbatimSnippet(body, 'CodeIgniter') || 'Welcome to CodeIgniter',
          detail       : 'CodeIgniter default welcome page accessible — confirms CI installation',
          ...(cRes?.trafficId ?? res.trafficId !== undefined ? { trafficId: cRes?.trafficId ?? res.trafficId } : {})
        });
      }
    }
  } catch { /* skip */ }

  if (detectedVersion && isVulnerableCI4(detectedVersion)) {
    const quote = `CodeIgniter Version ${detectedVersion}`;
    findings.push({
      path         : versionPath,
      url          : versionUrl,
      method       : 'GET',
      status       : 200,
      severity     : 'CRITICAL',
      matchedSignal: quote,
      reproducible : true,
      preview      : quote,
      detail       : `CodeIgniter ${detectedVersion} detected — vulnerable to CVE-2025-54418 (CVSS 10.0) command injection via ImageMagick handler`,
      cve          : 'CVE-2025-54418'
    });
  }

  for (const check of CHECKS) {
    try {
      const checkUrl = `${target}${check.path}`;
      const res = await fetchWithRetry(checkUrl, { followRedirects: false });
      if (
        res?.status !== 200 ||
        isRedirectedToDifferentPath(res, checkUrl) ||
        isFrameworkRouteErrorResponse(res, res?.text) ||
        !check.validate(res)
      ) {
        continue;
      }

      const { confirmed, res: cRes } = await confirmReproducible(
        checkUrl,
        fetchWithRetry,
        { followRedirects: false },
        (r) => r?.status === 200 && !isRedirectedToDifferentPath(r, checkUrl) && check.validate(r)
      );
      if (!confirmed) continue;

      const finalRes = cRes || res;
      const preview = extractVerbatimSnippet(finalRes.text || res.text || '', /index of|log-|\$db|codeigniter/i) || check.signalDesc;
      findings.push({
        path         : check.path,
        url          : checkUrl,
        method       : 'GET',
        status       : 200,
        severity     : check.severity,
        matchedSignal: check.signalDesc,
        reproducible : true,
        preview,
        detail       : check.detail,
        ...(finalRes?.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {})
      });
    } catch { /* unreachable */ }
  }

  if (!findings.length) {
    return { name: 'codeigniter exposure', status: 'SAFE', severity: 'NONE' };
  }

  const maxSev = findings.some(f => f.severity === 'CRITICAL') ? 'CRITICAL'
               : findings.some(f => f.severity === 'HIGH')     ? 'HIGH'
               : 'LOW';
  const primary = findings[0];
  const evidenceQuotes = findings.map(f => f.preview).filter(q => typeof q === 'string' && q.length >= 8).slice(0, 5);
  const cveHit = findings.find(f => f.cve);

  return {
    name          : 'codeigniter exposure',
    status        : maxSev === 'LOW' ? 'SUSPICIOUS' : 'VULNERABLE',
    severity      : maxSev,
    path          : cveHit?.path || primary.path,
    version       : detectedVersion ?? 'unknown',
    ...(cveHit ? { cve: cveHit.cve, cveIds: [cveHit.cve] } : {}),
    findings,
    files         : findings,
    detail        : `Confirmed ${findings.length} CodeIgniter issue(s): ${findings.map(f => `${f.path} (${f.severity})`).join(', ')}`,
    reproVerified : true,
    poeLevel      : evidenceQuotes.length > 0 ? 3 : 2,
    ...(evidenceQuotes.length > 0 ? { evidenceQuotes } : {}),
    ...(primary.trafficId !== undefined ? { trafficId: primary.trafficId } : {}),
    fix           : "Update CodeIgniter to version 4.6.2 or higher immediately to patch CVE-2025-54418. Deny public access to 'application/logs' and 'system' directories in your web server configuration."
  };
}
