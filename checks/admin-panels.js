export const tags = ['all'];

/**
 * Probes for popular admin panels and database tools left publicly accessible.
 * Each panel is verified by looking for content signals, not just HTTP 200,
 * to avoid false positives from catch-all pages.
 */
const PANELS = [
  {
    path   : '/phpmyadmin',
    name   : 'phpMyAdmin',
    signals: ['phpmyadmin', 'pma_navigation', 'pmalogo']
  },
  {
    path   : '/adminer.php',
    name   : 'Adminer',
    signals: ['adminer', 'db=', '<h1>Login</h1>']
  },
  {
    path   : '/adminer',
    name   : 'Adminer',
    signals: ['adminer', 'db=']
  },
  {
    path   : '/_debugbar/open',
    name   : 'PHP DebugBar',
    signals: ['debugbar', 'phpdebugbar']
  },
  {
    path   : '/nova',
    name   : 'Laravel Nova',
    signals: ['laravel nova', '"nova"', 'nova-api']
  },
  {
    path   : '/filament',
    name   : 'Filament Admin',
    signals: ['filament', 'filament-vite', 'filament-core']
  },
  {
    path   : '/cpanel',
    name   : 'cPanel',
    signals: ['cpanel', 'whm', 'cPanel &amp; WHM']
  },
];

export default async function run(target, fetchWithRetry) {
  const found = [];

  for (const panel of PANELS) {
    try {
      const res  = await fetchWithRetry(`${target}${panel.path}`);
      const html = res.text.toLowerCase();

      // Must be a 200, and body must match known signals
      if (res.status === 200 && panel.signals.some(s => html.includes(s.toLowerCase()))) {
        found.push({ path: panel.path, name: panel.name });
      }

    } catch { /* path unreachable — skip */ }
  }

  if (found.length === 0) {
    return { name: 'admin panel exposure', status: 'SAFE', severity: 'NONE' };
  }

  return {
    name    : 'admin panel exposure',
    status  : 'VULNERABLE',
    severity: 'HIGH',
    panels  : found,
    detail  : 'Admin interfaces should not be publicly accessible',
    fix     : 'Restrict access to admin panels by IP address or move them to a non-obvious URL.'
  };
}
