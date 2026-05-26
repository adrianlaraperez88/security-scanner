/**
 * Lightweight link extractor and crawler logic.
 */
export async function crawlPage(url, fetchWithRetry) {
  try {
    const res = await fetchWithRetry(url);
    if (res.status !== 200) return [];

    const html = res.text;
    const links = [];
    
    // Simple but effective regex for <a> and <script>/<img> attributes
    const regex = /(?:href|src|action)=["']([^"'>\s#?]+)(?:\?[^"'>\s#]*)?(?:#[^"'>\s]*)?["']/gi;
    
    let match;
    while ((match = regex.exec(html)) !== null) {
      links.push(match[1]);
    }

    // Clean up duplicates and empty links
    return [...new Set(links)].filter(l => l && !l.startsWith('data:') && !l.startsWith('mailto:') && !l.startsWith('javascript:'));

  } catch (e) {
    return [];
  }
}
