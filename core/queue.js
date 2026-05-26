/**
 * A simple Task Queue for Scanner 2.0.
 * Manages URL deduplication and ensures we only scan within the identified domain.
 */
export class TaskQueue {
  constructor(baseUrl) {
    this.baseUrl   = new URL(baseUrl);
    this.seen      = new Set();
    this.pending   = [];
    this.results   = [];
    
    // Add the initial target
    this.push(baseUrl);
  }

  /**
   * Push one or more URLs into the queue.
   * Filters out duplicates and off-domain links.
   */
  push(input) {
    const urls = Array.isArray(input) ? input : [input];
    
    for (let u of urls) {
      try {
        // Resolve relative to base if needed
        const resolved = new URL(u, this.baseUrl.href).href.replace(/\/+$/, '');
        const urlObj   = new URL(resolved);

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
