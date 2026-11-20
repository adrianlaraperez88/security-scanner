/**
 * Okapi BM25 lexical tool selector ("tool RAG"). Projects the full tool universe
 * (built-in agent tools, checks/*.js descriptors, MCP tools) down to the top-K tools relevant
 * to the current intent/goal, always keeping the write-back + load_skill tools.
 */

export const BM25_K1 = 1.2;
export const BM25_B = 0.75;

export const DEFAULT_ALWAYS_INCLUDE = Object.freeze([
  'insert_assets',
  'record_fact',
  'report_finding',
  'record_coverage',
  'load_skill',
]);

const STOPWORDS = new Set([
  'a', 'an', 'and', 'the', 'of', 'to', 'in', 'on', 'for', 'is', 'are', 'be', 'with', 'by', 'or', 'as', 'at', 'it', 'this', 'that',
]);

export function tokenize(text) {
  if (text == null) return [];
  return String(text)
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((t) => t && !STOPWORDS.has(t));
}

function docTerms(doc) {
  if (typeof doc === 'string') return tokenize(doc);
  if (Array.isArray(doc)) return doc.flatMap((d) => tokenize(d));
  if (doc && Array.isArray(doc.terms)) return doc.terms.flatMap((d) => tokenize(d));
  if (doc && typeof doc.text === 'string') return tokenize(doc.text);
  // Tool descriptor: name weighted x2, tags x1, description x1.
  const name = tokenize(doc?.name);
  const tags = Array.isArray(doc?.tags) ? doc.tags.flatMap((t) => tokenize(t)) : tokenize(doc?.tags);
  return [...name, ...name, ...tags, ...tokenize(doc?.description)];
}

/**
 * Okapi BM25 over a small corpus.
 *
 * @param {string[]|string} queryTerms
 * @param {Array<string|object>} docs
 * @returns {number[]} one score per doc (same order)
 */
export function scoreBm25(queryTerms, docs = [], { k1 = BM25_K1, b = BM25_B } = {}) {
  const terms = Array.isArray(queryTerms) ? queryTerms.flatMap((t) => tokenize(t)) : tokenize(queryTerms);
  const uniqueTerms = Array.from(new Set(terms));
  const N = docs.length;
  if (N === 0 || uniqueTerms.length === 0) return docs.map(() => 0);

  const tfs = docs.map((d) => {
    const m = new Map();
    for (const t of docTerms(d)) m.set(t, (m.get(t) || 0) + 1);
    return m;
  });
  const lengths = tfs.map((m) => {
    let s = 0;
    for (const v of m.values()) s += v;
    return s;
  });
  const avgdl = lengths.reduce((a, c) => a + c, 0) / N || 1;

  const idf = new Map();
  for (const t of uniqueTerms) {
    let n = 0;
    for (const m of tfs) if (m.has(t)) n++;
    idf.set(t, Math.log(1 + (N - n + 0.5) / (n + 0.5)));
  }

  return tfs.map((m, i) => {
    let score = 0;
    const dl = lengths[i];
    for (const t of uniqueTerms) {
      const f = m.get(t) || 0;
      if (!f) continue;
      score += idf.get(t) * ((f * (k1 + 1)) / (f + k1 * (1 - b + b * (dl / avgdl))));
    }
    return score;
  });
}

/**
 * Select tools relevant to `query`.
 *
 * @param {string|string[]} query
 * @param {Array<{name: string, description?: string, tags?: string[]}>} allTools
 * @returns {Array<object>} alwaysInclude tools (in order present) followed by top-K BM25 hits
 */
export function projectTools(query, allTools = [], { topK = 12, alwaysInclude = DEFAULT_ALWAYS_INCLUDE } = {}) {
  const pinned = new Set(alwaysInclude);
  const result = [];
  const taken = new Set();
  for (const name of alwaysInclude) {
    const tool = allTools.find((t) => t.name === name);
    if (tool && !taken.has(name)) {
      result.push(tool);
      taken.add(name);
    }
  }
  const candidates = allTools.filter((t) => !pinned.has(t.name));
  const scores = scoreBm25(query, candidates);
  const ranked = candidates
    .map((tool, i) => ({ tool, score: scores[i], i }))
    .filter((r) => r.score > 0)
    .sort((a, b) => b.score - a.score || a.i - b.i)
    .slice(0, Math.max(0, topK));
  for (const r of ranked) {
    result.push(r.tool);
    taken.add(r.tool.name);
  }
  return result;
}

/**
 * Build tool descriptors from loaded scanners (`getScanners()` output).
 */
export function checkDescriptorsFromScanners(scanners = []) {
  return scanners.map((s) => ({
    name: s.name,
    kind: 'check',
    description: [s.meta?.title, s.meta?.plainExplanation, s.meta?.whyItMatters].filter(Boolean).join('. '),
    tags: [s.meta?.category, ...(s.tags || []), s.meta?.cwe].filter(Boolean).map(String),
  }));
}

/**
 * Convenience: load all checks/*.js descriptors (dynamic import to avoid load cost until needed).
 */
export async function loadCheckDescriptors() {
  const { getScanners } = await import('./registry.js');
  return checkDescriptorsFromScanners(await getScanners());
}

export function mcpToolDescriptors(mcpTools = []) {
  return mcpTools.map((t) => ({
    name: t.name,
    kind: 'mcp',
    description: t.description || '',
    tags: ['mcp', ...(t.tags || [])],
  }));
}
