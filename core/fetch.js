export async function fetchWithRetry(url, options = {}, retries = 2, timeout = 10000) {
  for (let i = 0; i <= retries; i++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    try {
      const res = await fetch(url, {
        method: options.method || 'GET',
        body: options.body || undefined,
        redirect: 'follow',
        signal: controller.signal,
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.1)',
          'Accept': 'text/html,application/json,*/*',
          ...(options.headers || {})
        }
      });

      clearTimeout(timer);

      const text = await res.text();

      return {
        status: res.status,
        headers: Object.fromEntries(res.headers.entries()),
        text: text || ''
      };

    } catch (e) {
      clearTimeout(timer);
      if (i === retries) throw new Error(`Fetch failed: ${e.message}`);
      // Short pause before retry
      await new Promise(r => setTimeout(r, 500 * (i + 1)));
    }
  }
}