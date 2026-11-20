import {
  isRedirectedToDifferentPath,
  isFrameworkRouteErrorResponse,
  extractVerbatimSnippet,
  confirmReproducible
} from '../core/check-verify.js';

export const tags = ['laravel'];

const CHECKS = [
  {
    paths  : ['/telescope', '/telescope/requests', '/telescope/queries'],
    signals: ['laravel telescope', 'telescope::night', 'telescope-toolbar', '/vendor/telescope/', '<div id="telescope"'],
    name   : 'Laravel Telescope'
  },
  {
    paths  : ['/horizon', '/horizon/dashboard', '/horizon/api/stats'],
    signals: ['laravel horizon', 'horizon-ui', '/vendor/horizon/', '<div id="horizon"', '"failedJobs"'],
    name   : 'Laravel Horizon'
  },
];

function matchDashboard(check, res, reqUrl) {
  if (res?.status !== 200 || (reqUrl && isRedirectedToDifferentPath(res, reqUrl))) return null;
  const raw = typeof res.text === 'string' ? res.text : '';
  if (isFrameworkRouteErrorResponse(res, raw)) return null;
  const html = raw.toLowerCase();
  return check.signals.find(s => html.includes(s.toLowerCase())) || null;
}

export default async function run(target, fetchWithRetry) {
  for (const check of CHECKS) {
    for (const p of check.paths) {
      try {
        const url = `${target}${p}`;
        const res = await fetchWithRetry(url, { followRedirects: false });
        const signal = matchDashboard(check, res, url);
        if (!signal) continue;

        const { confirmed, res: cRes } = await confirmReproducible(
          url,
          fetchWithRetry,
          { followRedirects: false },
          (r) => Boolean(matchDashboard(check, r, url))
        );
        if (!confirmed) continue;

        const finalRes = cRes || res;
        const preview = extractVerbatimSnippet(finalRes.text || res.text || '', signal) || `${check.name} (${signal})`;

        return {
          name          : `${check.name.toLowerCase()} exposed`,
          status        : 'VULNERABLE',
          severity      : 'HIGH',
          path          : p,
          detail        : `${check.name} dashboard confirmed accessible at ${p} (matched ${signal})`,
          files         : [{ path: p, url, method: 'GET', status: 200, matchedSignal: signal, reproducible: true, preview }],
          reproVerified : true,
          poeLevel      : 3,
          evidenceQuotes: [preview],
          ...(finalRes?.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {}),
          fix           : `Restrict access to ${check.name} by configuring the gate in your ${check.name}ServiceProvider to only allow authorized users or IP addresses.`
        };
      } catch { /* unreachable path */ }
    }
  }

  return { name: 'telescope/horizon exposure', status: 'SAFE', severity: 'NONE' };
}
