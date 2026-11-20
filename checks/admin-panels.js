import {
  isRedirectedToDifferentPath,
  isFrameworkRouteErrorResponse,
  extractVerbatimSnippet,
  confirmReproducible
} from '../core/check-verify.js';

export const tags = ['all'];

const PANELS = [
  {
    path   : '/phpmyadmin',
    name   : 'phpMyAdmin',
    signals: ['pma_navigation', 'pmalogo', '<title>phpmyadmin']
  },
  {
    path   : '/adminer.php',
    name   : 'Adminer',
    signals: ['adminer', 'name="auth[server]"', 'name="auth[db]"']
  },
  {
    path   : '/adminer',
    name   : 'Adminer',
    signals: ['adminer', 'name="auth[server]"', 'name="auth[db]"']
  },
  {
    path   : '/_debugbar/open',
    name   : 'PHP DebugBar',
    signals: ['phpdebugbar', 'debugbar']
  },
  {
    path   : '/nova',
    name   : 'Laravel Nova',
    signals: ['laravel nova', 'nova-api']
  },
  {
    path   : '/filament',
    name   : 'Filament Admin',
    signals: ['filament-vite', 'filament-core', 'fi-simple-layout']
  },
  {
    path   : '/cpanel',
    name   : 'cPanel',
    signals: ['cpanel &amp; whm', 'cpanel, inc.', 'cpanel login']
  },
];

function matchPanelSignal(panel, res, reqUrl) {
  if (res?.status !== 200 || (reqUrl && isRedirectedToDifferentPath(res, reqUrl))) return null;
  const raw = typeof res.text === 'string' ? res.text : '';
  if (isFrameworkRouteErrorResponse(res, raw)) return null;
  const lower = raw.toLowerCase();
  return panel.signals.find(s => lower.includes(s.toLowerCase())) || null;
}

export default async function run(target, fetchWithRetry) {
  const found = [];

  for (const panel of PANELS) {
    try {
      const url = `${target}${panel.path}`;
      const res = await fetchWithRetry(url, { followRedirects: false });
      const matched = matchPanelSignal(panel, res, url);
      if (!matched) continue;

      const { confirmed, res: cRes } = await confirmReproducible(
        url,
        fetchWithRetry,
        { followRedirects: false },
        (r) => Boolean(matchPanelSignal(panel, r, url))
      );
      if (!confirmed) continue;

      const finalRes = cRes || res;
      const preview = extractVerbatimSnippet(finalRes.text || res.text || '', matched) || `${panel.name} signature (${matched})`;
      found.push({
        path         : panel.path,
        name         : panel.name,
        url,
        method       : 'GET',
        status       : 200,
        severity     : 'HIGH',
        matchedSignal: matched,
        reproducible : true,
        preview,
        detail       : `${panel.name} interface exposed at ${panel.path}`,
        ...(finalRes?.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {})
      });
    } catch { /* path unreachable */ }
  }

  if (found.length === 0) {
    return { name: 'admin panel exposure', status: 'SAFE', severity: 'NONE' };
  }

  const primary = found[0];
  const evidenceQuotes = found.map(f => f.preview).filter(q => typeof q === 'string' && q.length >= 8).slice(0, 5);

  return {
    name          : 'admin panel exposure',
    status        : 'VULNERABLE',
    severity      : 'HIGH',
    path          : primary.path,
    panels        : found,
    files         : found,
    detail        : `Confirmed ${found.length} exposed admin interface(s): ${found.map(f => `${f.name} (${f.path})`).join(', ')}`,
    reproVerified : true,
    poeLevel      : evidenceQuotes.length > 0 ? 3 : 2,
    ...(evidenceQuotes.length > 0 ? { evidenceQuotes } : {}),
    ...(primary.trafficId !== undefined ? { trafficId: primary.trafficId } : {}),
    fix           : 'Restrict access to admin panels by IP address or move them to a non-obvious URL.'
  };
}
