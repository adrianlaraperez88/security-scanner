import {
  isHtmlOrScript,
  isRedirectedToDifferentPath,
  isFrameworkRouteErrorResponse,
  extractVerbatimSnippet,
  confirmReproducible
} from '../core/check-verify.js';

export const tags = ['python', 'django', 'flask', 'fastapi'];

const REQ_LINE_RE = /^[a-zA-Z0-9_.\-\[\]]+\s*(?:==|>=|<=|~=|!=)\s*[0-9]+(?:\.[0-9]+)*/m;

const CHECKS = [
  {
    path: '/requirements.txt',
    name: 'python requirements disclosure',
    severity: 'MEDIUM',
    reason: 'Reveals full list of dependencies and versions — helps attackers identify CVEs.',
    validate: (res) => {
      const text = typeof res?.text === 'string' ? res.text : '';
      return !isHtmlOrScript(res, text) && REQ_LINE_RE.test(text);
    },
    signalDesc: 'pip requirement specifier line'
  },
  {
    path: '/pip-log.txt',
    name: 'pip install log exposure',
    severity: 'MEDIUM',
    reason: 'Leaks installation history and potentially local paths.',
    validate: (res) => {
      const text = typeof res?.text === 'string' ? res.text : '';
      return !isHtmlOrScript(res, text) && (text.includes('pip install') || text.includes('Successfully installed'));
    },
    signalDesc: 'pip-log.txt entries'
  },
  {
    path: '/__pycache__/',
    name: 'python bytecode cache exposure',
    severity: 'MEDIUM',
    reason: 'Reveals internal directory structure and compiled file names.',
    validate: (res) => {
      const text = typeof res?.text === 'string' ? res.text : '';
      const lower = text.toLowerCase();
      return (lower.includes('index of') && (lower.includes('__pycache__') || lower.includes('.pyc'))) ||
             (text.includes('.pyc') && /href=["'][^"']*\.pyc["']/i.test(text));
    },
    signalDesc: '__pycache__ directory index'
  },
  {
    path: '/venv/bin/activate',
    name: 'python virtualenv exposure',
    severity: 'HIGH',
    reason: 'Reveals that a virtual environment is improperly exposed in the web root.',
    validate: (res) => {
      const text = typeof res?.text === 'string' ? res.text : '';
      return !isHtmlOrScript(res, text) && text.includes('VIRTUAL_ENV') && text.includes('deactivate');
    },
    signalDesc: 'VIRTUAL_ENV activate script'
  },
  {
    path: '/.env/bin/activate',
    name: 'python virtualenv exposure (hidden)',
    severity: 'HIGH',
    reason: 'Reveals an improperly exposed virtual environment (hidden directory).',
    validate: (res) => {
      const text = typeof res?.text === 'string' ? res.text : '';
      return !isHtmlOrScript(res, text) && text.includes('VIRTUAL_ENV') && text.includes('deactivate');
    },
    signalDesc: 'hidden virtualenv activate script'
  }
];

export default async function run(target, fetchWithRetry) {
  const found = [];

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
      const preview = extractVerbatimSnippet(finalRes.text || res.text || '', /==|>=|VIRTUAL_ENV|pip install|Index of|\.pyc/i) || check.signalDesc;
      found.push({
        name         : check.name,
        path         : check.path,
        url,
        method       : 'GET',
        status       : 200,
        severity     : check.severity,
        matchedSignal: check.signalDesc,
        reproducible : true,
        preview,
        reason       : check.reason,
        ...(finalRes?.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {})
      });
    } catch { /* ignore */ }
  }

  try {
    const probePath = `/_non_existent_path_${Math.random().toString(36).substring(7)}`;
    const probeUrl = `${target}${probePath}`;
    const probe = await fetchWithRetry(probeUrl);
    const txt = (typeof probe?.text === 'string' ? probe.text : '').toLowerCase();

    if (txt.includes('django') && txt.includes('debug') && txt.includes('using the urlconf defined in')) {
      const { confirmed } = await confirmReproducible(
        probeUrl,
        fetchWithRetry,
        {},
        (r) => typeof r?.text === 'string' && r.text.toLowerCase().includes('using the urlconf defined in')
      );
      if (confirmed) {
        const preview = extractVerbatimSnippet(probe.text, 'Using the URLconf defined in') || 'Django DEBUG=True URLconf error page';
        found.push({
          name         : 'django debug mode enabled',
          path         : probePath,
          url          : probeUrl,
          method       : 'GET',
          status       : probe?.status ?? 404,
          severity     : 'CRITICAL',
          matchedSignal: 'Django URLconf debug page',
          reproducible : true,
          preview,
          reason       : 'Django is running with DEBUG=True. This leaks your entire URL structure, settings, and environment variables.',
          ...(probe?.trafficId !== undefined ? { trafficId: probe.trafficId } : {})
        });
      }
    }

    if (txt.includes('werkzeug debugger') || txt.includes('the debugger is active') || txt.includes('debugger pin')) {
      const { confirmed } = await confirmReproducible(
        probeUrl,
        fetchWithRetry,
        {},
        (r) => typeof r?.text === 'string' && /werkzeug debugger|the debugger is active|debugger pin/i.test(r.text)
      );
      if (confirmed) {
        const preview = extractVerbatimSnippet(probe.text, /werkzeug debugger|the debugger is active|debugger pin/i) || 'Werkzeug interactive debugger active';
        found.push({
          name         : 'flask/werkzeug debugger active',
          path         : probePath,
          url          : probeUrl,
          method       : 'GET',
          status       : probe?.status ?? 500,
          severity     : 'CRITICAL',
          matchedSignal: 'Werkzeug Debugger',
          reproducible : true,
          preview,
          reason       : 'The Flask/Werkzeug interactive debugger is active. This often allows remote code execution (RCE) via the debug console.',
          ...(probe?.trafficId !== undefined ? { trafficId: probe.trafficId } : {})
        });
      }
    }
  } catch { /* ignore */ }

  if (found.length === 0) {
    return { name: 'python security', status: 'SAFE', severity: 'NONE' };
  }

  const maxSev = found.some(f => f.severity === 'CRITICAL') ? 'CRITICAL'
               : found.some(f => f.severity === 'HIGH')     ? 'HIGH'
               : 'MEDIUM';
  const primary = found[0];
  const evidenceQuotes = found.map(f => f.preview).filter(q => typeof q === 'string' && q.length >= 8).slice(0, 5);

  return {
    name          : 'python security',
    status        : 'VULNERABLE',
    severity      : maxSev,
    path          : primary.path,
    detail        : `Confirmed ${found.length} Python security issue(s): ${found.map(f => f.name).join(', ')}`,
    findings      : found.map(f => ({ name: f.name, severity: f.severity, path: f.path, url: f.url, status: f.status, matchedSignal: f.matchedSignal, preview: f.preview, reason: f.reason })),
    files         : found,
    reproVerified : true,
    poeLevel      : evidenceQuotes.length > 0 ? 3 : 2,
    ...(evidenceQuotes.length > 0 ? { evidenceQuotes } : {}),
    ...(primary.trafficId !== undefined ? { trafficId: primary.trafficId } : {}),
    fix           : 'Move requirements.txt and virtualenvs outside the web root. Ensure DEBUG=False in production for Django/Flask, and never expose the Werkzeug debugger to the public internet.'
  };
}
