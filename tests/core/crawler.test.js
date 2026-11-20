import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TaskQueue } from '../../core/queue.js';
import { crawlPage } from '../../core/crawler.js';

test('TaskQueue: deduplicates, filters static asset extensions, and locks to domain', () => {
  const q = new TaskQueue('https://example.com');
  
  q.push('https://example.com/page1');
  q.push('https://example.com/page1'); // duplicate
  q.push('https://other.com/ext');     // off-domain
  q.push('/relative');                // relative
  q.push('/build/assets/app.js');     // static JS asset (filtered)
  q.push('/build/assets/app.css');    // static CSS asset (filtered)
  q.push('/fonts/inter.woff2');       // static font asset (filtered)
  q.push('/images/logo.png');         // static image asset (filtered)
  
  assert.equal(q.totalFound, 3); // '/', '/page1', '/relative'
  assert.equal(q.pending.length, 3); // '/', '/page1', '/relative'
});

test('crawlPage: extracts links from HTML', async () => {
  const mockFetch = async () => ({
    status: 200,
    text: `
      <html>
        <a href="/about">About</a>
        <img src="img.png">
        <script src="/js/app.js"></script>
        <a href="https://external.com">External</a>
      </html>
    `
  });

  const links = await crawlPage('https://example.com', mockFetch);
  assert.ok(links.includes('/about'));
  assert.ok(links.includes('img.png'));
  assert.ok(links.includes('/js/app.js'));
  assert.ok(links.includes('https://external.com'));
});

test('crawlPage: preserves ?query params, decodes &amp;, strips #fragment, and handles empty/missing res.text', async () => {
  const mockFetch = async () => ({
    status: 200,
    text: `
      <html>
        <a href="/search?q=test&amp;page=2#results">Search</a>
        <a href="?page=2#top">Next</a>
        <a href="?page=2#bottom">Next Duplicate</a>
        <a href="https://example.com/items?id=42#sec">Item</a>
        <a href="javascript:alert(1)">JS</a>
      </html>
    `
  });

  const links = await crawlPage('https://example.com', mockFetch);
  assert.ok(links.includes('/search?q=test&page=2'));
  assert.ok(links.includes('?page=2'));
  assert.equal(links.filter(l => l === '?page=2').length, 1);
  assert.ok(links.includes('https://example.com/items?id=42'));
  assert.equal(links.some(l => l.includes('#')), false);
  assert.equal(links.some(l => l.startsWith('javascript:')), false);

  const emptyLinks = await crawlPage('https://example.com', async () => ({ status: 200 }));
  assert.deepEqual(emptyLinks, []);
});
