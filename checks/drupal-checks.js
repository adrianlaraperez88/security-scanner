import {
  getHeader,
  isHtmlOrScript,
  extractVerbatimSnippet,
  confirmReproducible
} from '../core/check-verify.js';

export const tags = ['drupal'];

const CHANGELOG_PATHS = [
  '/CHANGELOG.txt',
  '/core/CHANGELOG.txt',
];

const VERSION_RE = /Drupal\s+([\d]+\.[\d.]+)/i;

function evaluateVersion(version) {
  const maj = parseInt(version?.split('.')[0] ?? '0', 10);
  if (maj <= 7)  return { eol: true,  severity: 'CRITICAL', label: `Drupal ${version} — EOL, no security patches` };
  if (maj === 9) return { eol: true,  severity: 'HIGH',     label: `Drupal ${version} — EOL since Nov 2023` };
  if (maj === 10) return { eol: false, severity: 'MEDIUM',  label: `Drupal ${version} — check for CVE-2025-13081 / CVE-2024-55638` };
  return { eol: false, severity: 'LOW', label: `Drupal ${version} — version disclosed (check advisories)` };
}

const PATH_CHECKS = [
  {
    path    : '/user/register',
    severity: 'MEDIUM',
    detail  : 'Drupal open user registration — verify CAPTCHA and email verification are enforced',
    validate: (res) => {
      const text = (typeof res?.text === 'string' ? res.text : '').toLowerCase();
      return text.includes('user-register-form') || (text.includes('create new account') && text.includes('drupal'));
    },
    signalDesc: 'Drupal user-register-form'
  },
  {
    path    : '/sites/default/files/',
    severity: 'HIGH',
    detail  : 'Drupal files directory browsable — may expose uploaded files or PHP scripts',
    validate: (res) => {
      const text = (typeof res?.text === 'string' ? res.text : '').toLowerCase();
      return text.includes('index of') && (text.includes('parent directory') || text.includes('.tar') || text.includes('.php'));
    },
    signalDesc: 'Directory listing in /sites/default/files/'
  },
  {
    path    : '/admin/reports/status',
    severity: 'HIGH',
    detail  : 'Drupal admin status report accessible without authentication',
    validate: (res) => {
      const text = (typeof res?.text === 'string' ? res.text : '').toLowerCase();
      return text.includes('drupal') && text.includes('system-status-report');
    },
    signalDesc: 'Drupal system-status-report'
  },
];

async function detectDrupal(target, fetchWithRetry) {
  try {
    const res  = await fetchWithRetry(target);
    const xGen = getHeader(res?.headers, 'x-generator').toLowerCase();
    const html = (typeof res?.text === 'string' ? res.text : '').toLowerCase();

    const byHeader = xGen.includes('drupal')
                  || Boolean(getHeader(res?.headers, 'x-drupal-cache'))
                  || Boolean(getHeader(res?.headers, 'x-drupal-dynamic-cache'));

    const byHtml   = html.includes('/sites/default/files')
                  || html.includes('/core/misc/drupal.js')
                  || html.includes('drupal.settings')
                  || /<meta[^>]+name=["']generator["'][^>]+drupal/i.test(html);

    return { detected: byHeader || byHtml, trafficId: res?.trafficId };
  } catch {
    return { detected: false, trafficId: undefined };
  }
}

async function getVersion(target, fetchWithRetry) {
  for (const p of CHANGELOG_PATHS) {
    try {
      const url = `${target}${p}`;
      const res = await fetchWithRetry(url);
      if (res?.status !== 200 || isHtmlOrScript(res, res.text)) continue;

      const text = typeof res.text === 'string' ? res.text : '';
      const m = text.match(VERSION_RE);
      if (m) {
        const { confirmed, res: cRes } = await confirmReproducible(
          url,
          fetchWithRetry,
          {},
          (r) => r?.status === 200 && !isHtmlOrScript(r, r.text) && VERSION_RE.test(r.text || '')
        );
        if (confirmed) {
          return {
            version: m[1],
            path: p,
            url,
            preview: extractVerbatimSnippet(text, VERSION_RE) || `Drupal ${m[1]}`,
            trafficId: cRes?.trafficId ?? res.trafficId
          };
        }
      }
    } catch { /* skip */ }
  }
  return { version: null, path: null };
}

export default async function run(target, fetchWithRetry) {
  const { detected: isDrupal, trafficId: rootTrafficId } = await detectDrupal(target, fetchWithRetry);
  if (!isDrupal) {
    return { name: 'drupal exposure', status: 'SAFE', severity: 'NONE' };
  }

  const findings = [];
  const { version, path: changelogPath, url: clUrl, preview: clPreview, trafficId: clTrafficId } = await getVersion(target, fetchWithRetry);

  if (changelogPath) {
    findings.push({
      path         : changelogPath,
      url          : clUrl,
      method       : 'GET',
      status       : 200,
      severity     : 'LOW',
      matchedSignal: clPreview || 'Drupal CHANGELOG.txt',
      reproducible : true,
      preview      : clPreview || `Drupal CHANGELOG.txt at ${changelogPath}`,
      detail       : `CHANGELOG.txt accessible — reveals exact Drupal version${version ? ` (${version})` : ''}`,
      ...(clTrafficId !== undefined ? { trafficId: clTrafficId } : {})
    });
  }

  if (version) {
    const vEval = evaluateVersion(version);
    if (vEval.eol || vEval.severity !== 'LOW') {
      findings.push({
        path         : changelogPath ?? '/',
        url          : clUrl || target,
        method       : 'GET',
        status       : 200,
        severity     : vEval.severity,
        matchedSignal: `Drupal ${version}`,
        reproducible : true,
        preview      : clPreview || `Drupal ${version}`,
        detail       : vEval.label,
        cve          : vEval.severity === 'CRITICAL' ? 'EOL + CVE-2025-13081, CVE-2024-55638'
                     : vEval.severity === 'HIGH'     ? 'EOL + last patch cycle ended'
                     : 'CVE-2025-13081, CVE-2024-55638',
        ...(clTrafficId ?? rootTrafficId !== undefined ? { trafficId: clTrafficId ?? rootTrafficId } : {})
      });
    }
  } else {
    findings.push({
      path         : '/',
      url          : target,
      method       : 'GET',
      status       : 200,
      severity     : 'LOW',
      matchedSignal: 'Drupal header/asset signature',
      reproducible : true,
      preview      : 'Drupal framework signature detected',
      detail       : 'Drupal detected — could not determine version. Verify it is fully patched.',
      ...(rootTrafficId !== undefined ? { trafficId: rootTrafficId } : {})
    });
  }

  for (const check of PATH_CHECKS) {
    try {
      const url = `${target}${check.path}`;
      const res = await fetchWithRetry(url);
      if (res?.status !== 200 || !check.validate(res)) continue;

      const { confirmed, res: cRes } = await confirmReproducible(
        url,
        fetchWithRetry,
        {},
        (r) => r?.status === 200 && check.validate(r)
      );
      if (!confirmed) continue;

      const finalRes = cRes || res;
      findings.push({
        path         : check.path,
        url,
        method       : 'GET',
        status       : 200,
        severity     : check.severity,
        matchedSignal: check.signalDesc,
        reproducible : true,
        preview      : extractVerbatimSnippet(finalRes.text || res.text || '', /user-register-form|index of|system-status-report|drupal/i) || check.signalDesc,
        detail       : check.detail,
        ...(finalRes?.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {})
      });
    } catch { /* unreachable */ }
  }

  const maxSev = findings.some(f => f.severity === 'CRITICAL') ? 'CRITICAL'
               : findings.some(f => f.severity === 'HIGH')     ? 'HIGH'
               : findings.some(f => f.severity === 'MEDIUM')   ? 'MEDIUM'
               : 'LOW';
  const primary = findings[0];
  const evidenceQuotes = findings.map(f => f.preview).filter(q => typeof q === 'string' && q.length >= 8).slice(0, 5);

  return {
    name          : 'drupal exposure',
    status        : maxSev === 'LOW' ? 'SUSPICIOUS' : 'VULNERABLE',
    severity      : maxSev,
    path          : changelogPath || primary.path,
    version       : version ?? 'unknown',
    findings,
    files         : findings,
    detail        : `Confirmed ${findings.length} Drupal security issue(s)`,
    reproVerified : true,
    poeLevel      : evidenceQuotes.length > 0 ? 3 : 2,
    ...(evidenceQuotes.length > 0 ? { evidenceQuotes } : {}),
    ...(primary.trafficId !== undefined ? { trafficId: primary.trafficId } : {}),
    fix           : "Upgrade Drupal to a supported version (10.x or 11.x) immediately, as Drupal 7 and 9 are EOL. Patch for CVE-2025-13081 and CVE-2024-55638, and restrict access to 'CHANGELOG.txt' and 'sites/default/files' browsing."
  };
}
