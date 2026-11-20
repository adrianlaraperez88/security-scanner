import { redactSecretsInText } from '../core/ai-advisor.js';
import {
  isHtmlOrScript,
  isRedirectedToDifferentPath,
  isFrameworkRouteErrorResponse,
  extractVerbatimSnippet,
  confirmReproducible
} from '../core/check-verify.js';

export const tags = ['symfony'];

const CHECKS = [
  {
    path    : '/app_dev.php',
    severity: 'CRITICAL',
    detail  : 'Symfony dev front controller deployed in production — bypasses security config',
    validate: (res) => {
      const lower = (typeof res?.text === 'string' ? res.text : '').toLowerCase();
      return lower.includes('symfony') && (lower.includes('_profiler') || lower.includes('sf-toolbar') || lower.includes('sfwdt'));
    },
    signalDesc: 'Symfony dev profiler/toolbar'
  },
  {
    path    : '/_profiler',
    severity: 'HIGH',
    detail  : 'Symfony web profiler accessible — leaks all requests, DB queries, env vars, session data',
    validate: (res) => {
      const lower = (typeof res?.text === 'string' ? res.text : '').toLowerCase();
      return lower.includes('symfony') && (lower.includes('profiler') || lower.includes('sf-toolbar'));
    },
    signalDesc: 'Symfony /_profiler UI'
  },
  {
    path    : '/_profiler/phpinfo',
    severity: 'HIGH',
    detail  : 'Symfony profiler phpinfo page accessible — full PHP configuration exposed',
    validate: (res) => {
      const lower = (typeof res?.text === 'string' ? res.text : '').toLowerCase();
      return lower.includes('php version') && (lower.includes('configuration') || lower.includes('php extension'));
    },
    signalDesc: 'Symfony phpinfo() output'
  },
  {
    path    : '/_wdt',
    severity: 'MEDIUM',
    detail  : 'Symfony web debug toolbar endpoint accessible',
    validate: (res) => {
      const lower = (typeof res?.text === 'string' ? res.text : '').toLowerCase();
      return lower.includes('sf-toolbar') || lower.includes('sfwdt');
    },
    signalDesc: 'Symfony Web Debug Toolbar'
  },
  {
    path    : '/app/config/parameters.yml',
    severity: 'CRITICAL',
    detail  : 'Symfony parameters.yml exposed — contains DB credentials and app secret',
    validate: (res) => {
      const text = typeof res?.text === 'string' ? res.text : '';
      return !isHtmlOrScript(res, text) && /database_host\s*:|database_password\s*:|secret\s*:/i.test(text) && text.includes('parameters:');
    },
    signalDesc: 'Symfony parameters.yml YAML'
  },
];

export default async function run(target, fetchWithRetry) {
  const findings = [];

  for (const check of CHECKS) {
    try {
      const url = `${target}${check.path}`;
      const res = await fetchWithRetry(url, { followRedirects: false });
      if (
        res?.status !== 200 ||
        isRedirectedToDifferentPath(res, url) ||
        isFrameworkRouteErrorResponse(res, res?.text) ||
        !check.validate(res)
      ) {
        continue;
      }

      const { confirmed, res: cRes } = await confirmReproducible(
        url,
        fetchWithRetry,
        { followRedirects: false },
        (r) => r?.status === 200 && !isRedirectedToDifferentPath(r, url) && check.validate(r)
      );
      if (!confirmed) continue;

      const finalRes = cRes || res;
      const preview = redactSecretsInText(
        extractVerbatimSnippet(finalRes.text || res.text || '', /symfony|sf-toolbar|php version|database_password|parameters:/i) || check.signalDesc
      );
      findings.push({
        path         : check.path,
        url,
        method       : 'GET',
        status       : 200,
        severity     : check.severity,
        matchedSignal: check.signalDesc,
        reproducible : true,
        preview,
        detail       : check.detail,
        ...(finalRes?.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {})
      });
    } catch { /* path unreachable */ }
  }

  if (!findings.length) {
    return { name: 'symfony misconfiguration', status: 'SAFE', severity: 'NONE' };
  }

  const maxSev = findings.some(f => f.severity === 'CRITICAL') ? 'CRITICAL' : 'HIGH';
  const primary = findings[0];
  const evidenceQuotes = findings.map(f => f.preview).filter(q => typeof q === 'string' && q.length >= 8).slice(0, 5);

  return {
    name          : 'symfony misconfiguration',
    status        : 'VULNERABLE',
    severity      : maxSev,
    path          : primary.path,
    findings,
    files         : findings,
    detail        : `Confirmed ${findings.length} Symfony misconfiguration(s): ${findings.map(f => f.path).join(', ')}`,
    reproVerified : true,
    poeLevel      : evidenceQuotes.length > 0 ? 3 : 2,
    ...(evidenceQuotes.length > 0 ? { evidenceQuotes } : {}),
    ...(primary.trafficId !== undefined ? { trafficId: primary.trafficId } : {}),
    fix           : "Set 'APP_DEBUG=0' and 'APP_ENV=prod' in your .env file. Remove 'app_dev.php' from the public directory and ensure the '/_profiler' routes are disabled or restricted to localhost."
  };
}
