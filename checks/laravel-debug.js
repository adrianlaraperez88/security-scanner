import { extractVerbatimSnippet, confirmReproducible } from '../core/check-verify.js';

export const tags = ['laravel'];

// Indicators of an active Laravel debug/error page.
// Generic prose ("laravel framework" alone) is not sufficient without a stack/debug marker.
const STRONG_DEBUG_INDICATORS = [
  'whoops',
  'vendor/laravel',
  'illuminate\\',
  'facade\\ignition',
  'spatie\\laravel-ignition',
  'phpdebugbar',
  '#0 /'
];

const INDICATORS = [
  'whoops',
  'stack trace',
  'laravel framework',
  'vendor/laravel',
  'illuminate\\',
  'facade\\ignition',
  'spatie\\laravel-ignition',
  'phpdebugbar',
  '#0 /'
];

function matchDebugIndicators(rawText) {
  const html = typeof rawText === 'string' ? rawText.toLowerCase() : '';
  if (!html) return [];
  const hasStrong = STRONG_DEBUG_INDICATORS.some(i => html.includes(i));
  if (!hasStrong) return [];
  return INDICATORS.filter(i => html.includes(i));
}

export default async function run(target, fetchWithRetry) {
  try {
    const res = await fetchWithRetry(target);
    const rawText = typeof res?.text === 'string' ? res.text : '';
    const hits = matchDebugIndicators(rawText);

    if (hits.length === 0) {
      return { name: 'laravel debug exposure', status: 'SAFE', severity: 'NONE' };
    }

    const { confirmed, res: confirmRes } = await confirmReproducible(
      target,
      fetchWithRetry,
      {},
      (r) => matchDebugIndicators(r?.text).length > 0
    );
    if (!confirmed) {
      return { name: 'laravel debug exposure', status: 'SAFE', severity: 'NONE' };
    }

    const finalRes = confirmRes || res;
    const finalText = typeof finalRes?.text === 'string' ? finalRes.text : rawText;
    const primaryHit = hits[0];
    const snippet = extractVerbatimSnippet(finalText, primaryHit) || `Laravel debug indicator: ${primaryHit}`;
    let path = '/';
    try {
      const u = new URL(target);
      path = `${u.pathname || '/'}${u.search || ''}`;
    } catch { /* default / */ }

    return {
      name          : 'laravel debug exposure',
      status        : 'SUSPICIOUS',
      severity      : hits.length >= 2 ? 'HIGH' : 'LOW',
      path,
      url           : target,
      hits          : hits.length,
      matched       : hits,
      detail        : `Laravel debug indicators exposed (${hits.join(', ')}) on ${path}`,
      files         : [{
        path,
        url          : target,
        method       : 'GET',
        status       : finalRes?.status ?? 200,
        matchedSignal: hits.join(', '),
        reproducible : true,
        preview      : snippet
      }],
      reproVerified : true,
      poeLevel      : snippet.length >= 8 ? 3 : 2,
      ...(snippet.length >= 8 ? { evidenceQuotes: [snippet] } : {}),
      ...(finalRes?.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {}),
      fix           : "Deactivate debug mode in production by setting 'APP_DEBUG=false' in your .env file and clearing the cache using 'php artisan config:clear'."
    };

  } catch (e) {
    return { name: 'laravel debug exposure', status: 'ERROR', severity: 'LOW', reason: e.message };
  }
}