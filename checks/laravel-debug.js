export const tags = ['laravel', 'php', 'all'];

// Indicators of an active debug/error page.
// NOTE: csrf-token is intentionally excluded — it's present on every Laravel app
//       and is NOT a debug indicator.
const INDICATORS = [
  'whoops',
  'stack trace',
  'laravel framework',
  'vendor/laravel',
  'illuminate\\',
];

export default async function run(target, fetchWithRetry) {
  try {
    const res  = await fetchWithRetry(target);
    const html = res.text.toLowerCase();

    const hits = INDICATORS.filter(i => html.includes(i));

    if (hits.length === 0) {
      return { name: 'laravel debug exposure', status: 'SAFE', severity: 'NONE' };
    }

    return {
      name     : 'laravel debug exposure',
      status   : 'SUSPICIOUS',
      severity : hits.length >= 2 ? 'HIGH' : 'LOW',
      hits     : hits.length,
      matched  : hits,
      fix      : "Deactivate debug mode in production by setting 'APP_DEBUG=false' in your .env file and clearing the cache using 'php artisan config:clear'."
    };

  } catch (e) {
    return { name: 'laravel debug exposure', status: 'ERROR', severity: 'LOW', reason: e.message };
  }
}