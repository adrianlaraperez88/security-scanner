export const tags = ['laravel', 'all'];

/**
 * Checks for publicly accessible Laravel Telescope and Horizon dashboards.
 *
 * Telescope leaks: all requests, DB queries, exceptions, jobs, mail.
 * Horizon leaks:   queue job details, payloads, failed job data.
 *
 * Both should be restricted to authenticated/admin users or disabled in prod.
 */
const CHECKS = [
  {
    paths  : ['/telescope', '/telescope/requests', '/telescope/queries'],
    signals: ['laravel telescope', 'telescope::night', 'telescope-toolbar', '"telescope"'],
    name   : 'Laravel Telescope'
  },
  {
    paths  : ['/horizon', '/horizon/dashboard', '/horizon/api/stats'],
    signals: ['laravel horizon', 'horizon-ui', '"horizon"', 'queue dashboard'],
    name   : 'Laravel Horizon'
  },
];

export default async function run(target, fetchWithRetry) {
  for (const check of CHECKS) {
    for (const p of check.paths) {
      try {
        const res  = await fetchWithRetry(`${target}${p}`);
        const html = res.text.toLowerCase();

        if (res.status === 200 && check.signals.some(s => html.includes(s.toLowerCase()))) {
          return {
            name    : `${check.name.toLowerCase()} exposed`,
            status  : 'VULNERABLE',
            severity: 'HIGH',
            path    : p,
            detail  : `${check.name} dashboard is publicly accessible — leaks sensitive runtime data`,
            fix     : `Restrict access to ${check.name} by configuring the gate in your ${check.name}ServiceProvider to only allow authorized users or IP addresses.`
          };
        }

        // 302 redirecting to login is fine (protected) — skip
        // 403 is fine — skip
        // 200 without signals — might be a catch-all page — skip

      } catch { /* unreachable path */ }
    }
  }

  return { name: 'telescope/horizon exposure', status: 'SAFE', severity: 'NONE' };
}
