const STATIC_ASSET_EXT_RE = /\.(?:js|mjs|cjs|css|less|scss|sass|woff2?|ttf|eot|otf|png|jpe?g|gif|svg|ico|webp|avif|bmp|tiff?|mp4|webm|ogg|mp3|wav|flac|aac|pdf|zip|tar|gz|tgz|bz2|7z|rar|map|wasm)$/i;
export const LOGOUT_URL_RE = /(?:^|[\/?&=])(?:log[-_]?out|sign[-_]?out|log[-_]?off|kill[-_]?session|destroy[-_]?session)(?:[\/?&#=]|$)/i;

/**
 * A simple Task Queue for Scanner 2.0.
 * Manages URL deduplication and ensures we only scan within the identified domain.
 */
export class TaskQueue {
  constructor(baseUrl, options = {}) {
    this.baseUrl       = new URL(baseUrl);
    this.options       = options && typeof options === 'object' ? options : {};
    this.shouldEnqueue = typeof options?.shouldEnqueue === 'function' ? options.shouldEnqueue : null;
    this.seen          = new Set();
    this.pending       = [];
    this.results       = [];
    
    // Add the initial target
    this.push(baseUrl);
  }

  /**
   * Push one or more URLs into the queue.
   * Filters out duplicates, static asset files, logout links, and off-domain links.
   */
  push(input, basePageUrl = null) {
    const urls = Array.isArray(input) ? input : [input];
    const resolveBase = (typeof basePageUrl === 'string' && basePageUrl.trim())
      ? basePageUrl.trim()
      : this.baseUrl.href;
    
    for (let u of urls) {
      try {
        // Resolve relative to basePageUrl (or baseUrl) if needed
        const resolved = new URL(u, resolveBase).href.replace(/\/+$/, '');
        const urlObj   = new URL(resolved);
        const isInitialSeed = this.seen.size === 0;

        if (!isInitialSeed) {
          if (STATIC_ASSET_EXT_RE.test(urlObj.pathname || '')) {
            continue;
          }
          if (
            this.options?.allowLogoutUrls !== true &&
            LOGOUT_URL_RE.test((urlObj.pathname || '') + (urlObj.search || ''))
          ) {
            continue;
          }
          if (this.shouldEnqueue && !this.shouldEnqueue(resolved)) {
            continue;
          }
        }

        // Stay on domain and only scan http/s
        if (urlObj.hostname === this.baseUrl.hostname && 
            ['http:', 'https:'].includes(urlObj.protocol) &&
            !this.seen.has(resolved)) {
          
          this.seen.add(resolved);
          this.pending.push(resolved);
        }
      } catch (e) {
        // Invalid URL, skip
      }
    }
  }

  /**
   * Get the next URL to scan.
   */
  pop() {
    return this.pending.shift();
  }

  isEmpty() {
    return this.pending.length === 0;
  }

  get size() {
    return this.pending.length;
  }

  get totalFound() {
    return this.seen.size;
  }
}
