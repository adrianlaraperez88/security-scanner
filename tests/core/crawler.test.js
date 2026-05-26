import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TaskQueue } from '../../core/queue.js';
import { crawlPage } from '../../core/crawler.js';

test('TaskQueue: deduplicates and locks to domain', () => {
  const q = new TaskQueue('https://example.com');
  
  q.push('https://example.com/page1');
  q.push('https://example.com/page1'); // duplicate
  q.push('https://other.com/ext');     // off-domain
  q.push('/relative');                // relative
  
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
