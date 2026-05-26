export const tags = ['all'];

/**
 * Detects missing rate limiting by sending a burst of rapid requests.
 *
 * An API with no rate limiting is trivially brute-forced for authentication
 * and allows DoS via request flooding.
 *
 * What we look for:
 *  SAFE      → any 429 response, or X-RateLimit-* / RateLimit-* headers present
 *  SUSPICIOUS → all burst requests return 2xx with no rate limit signals
 */
const BURST_SIZE = 15;

export default async function run(target, fetchWithRetry) {
  try {
    // Fire BURST_SIZE requests in parallel
    const requests = Array.from({ length: BURST_SIZE }, () =>
      fetchWithRetry(target).catch(() => null)
    );

    const responses = await Promise.all(requests);
    const valid = responses.filter(Boolean);

    if (valid.length === 0) {
      return { name: 'rate limiting', status: 'ERROR', severity: 'LOW', reason: 'All burst requests failed' };
    }

    // ── Check for rate limit signals ──────────────────────────────────────
    const has429 = valid.some(r => r.status === 429);

    const hasRateLimitHeaders = valid.some(r => {
      const h = r.headers || {};
      return h['x-ratelimit-limit']    ||
             h['x-rate-limit-limit']   ||
             h['ratelimit-limit']      ||
             h['retry-after'];
    });

    if (has429 || hasRateLimitHeaders) {
      return {
        name    : 'rate limiting',
        status  : 'SAFE',
        severity: 'NONE',
        detail  : has429 ? '429 Too Many Requests returned' : 'Rate limit headers detected'
      };
    }

    // ── All requests succeeded — no rate limiting ─────────────────────────
    const successCount = valid.filter(r => r.status < 400).length;

    if (successCount >= Math.floor(BURST_SIZE * 0.8)) {
      return {
        name    : 'rate limiting',
        status  : 'SUSPICIOUS',
        severity: 'MEDIUM',
        detail  : `${successCount}/${BURST_SIZE} burst requests succeeded — no rate limiting detected (brute-force risk)`,
        fix     : "Implement rate limiting at the application level (e.g., Laravel's ThrottleRequests) or web server level (e.g., Nginx 'limit_req') to protect against brute-force and DoS attacks."
      };
    }

    return { name: 'rate limiting', status: 'SAFE', severity: 'NONE' };

  } catch (e) {
    return { name: 'rate limiting', status: 'ERROR', severity: 'LOW', reason: e.message };
  }
}
