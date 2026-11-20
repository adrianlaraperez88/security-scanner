import {
  DEFAULT_MAX_HTML_BYTES,
  inspectApiCommunication,
  isSafeReadOnlyApiRoute,
  stripSensitiveQueryParamsForProbe
} from './api-discovery.js';

/**
 * Lightweight link extractor and crawler logic.
 */
export async function crawlPage(url, fetchWithRetry, options = {}) {
  const includeResponse = Boolean(options?.includeResponse);
  try {
    const res = await fetchWithRetry(url, {
      sameOriginRedirects: true,
      maxBytes: options?.maxBytes || DEFAULT_MAX_HTML_BYTES
    });
    if (!res || res.status !== 200) {
      return includeResponse ? { links: [], response: res || null } : [];
    }

    const html = typeof res?.text === 'string' ? res.text : '';
    if (!html) {
      return includeResponse ? { links: [], response: res } : [];
    }
    const links = [];

    // Extract href/src/action preserving ?query parameters (including ?page=2) while stripping #fragment
    const regex = /(?:href|src|action)=["']([^"'>\s#]+)(?:#[^"'>\s]*)?["']/gi;

    let match;
    while ((match = regex.exec(html)) !== null) {
      const rawLink = match[1].trim().replace(/&amp;/gi, '&');
      if (rawLink) {
        links.push(rawLink);
      }
    }

    // Clean up duplicates, empty links, and non-HTTP schemes
    const cleanLinks = [...new Set(links)].filter(
      l => l && !/^(?:data|mailto|javascript|tel):/i.test(l)
    );
    return includeResponse ? { links: cleanLinks, response: res } : cleanLinks;

  } catch (e) {
    return includeResponse ? { links: [], response: null } : [];
  }
}

/**
 * Discovers safe, read-only same-origin API routes referenced by a crawled page's HTML,
 * client-side JS bundles, or runtime config files so callers can enqueue them into TaskQueue.
 *
 * @param {string} url
 * @param {string|null|undefined} html
 * @param {Function} fetchWithRetry
 * @param {object} [options={}]
 * @returns {Promise<string[]>}
 */
export async function discoverApiRoutesFromPage(url, html, fetchWithRetry, options = {}) {
  try {
    const baseObj = new URL(url);
    if (!['http:', 'https:'].includes(baseObj.protocol)) return [];

    const rootResponse = options.rootResponse
      ?? (typeof html === 'string'
        ? { status: 200, headers: options.headers || {}, text: html }
        : undefined);

    const inspection = await inspectApiCommunication(baseObj.href, fetchWithRetry, {
      maxBundles: options.maxBundles ?? 3,
      maxConfigProbes: options.maxConfigProbes ?? 3,
      ...options,
      ...(rootResponse ? { rootResponse } : {})
    });

    const maxRoutes = Number.isFinite(Number(options.maxRoutes)) && Number(options.maxRoutes) > 0
      ? Math.floor(Number(options.maxRoutes))
      : 20;

    const routes = [];
    const seen = new Set();
    for (const ep of inspection?.sameOriginEndpoints || []) {
      if (!isSafeReadOnlyApiRoute(ep)) continue;
      const cleanEp = stripSensitiveQueryParamsForProbe(ep);
      if (!cleanEp) continue;
      let resolved;
      try {
        resolved = new URL(cleanEp, baseObj.href);
      } catch {
        continue;
      }
      if (resolved.origin !== baseObj.origin) continue;
      if (!['http:', 'https:'].includes(resolved.protocol)) continue;
      const route = `${resolved.pathname}${resolved.search}`;
      if (!isSafeReadOnlyApiRoute(route)) continue;
      if (!seen.has(route)) {
        seen.add(route);
        routes.push(route);
        if (routes.length >= maxRoutes) break;
      }
    }
    return routes;
  } catch {
    return [];
  }
}
