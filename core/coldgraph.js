/**
 * Cold-graph compaction (SecScan hot-set R rounds / K hops).
 *
 * Hot seeds: `begin`, unresolved `goal`s, active (pending/running) `intent`s, any node
 * touched in the last R rounds, and every `finding`. Every node within K undirected edge
 * hops of a hot seed is also hot. Remaining completed intent/fact/hint subtrees are folded
 * into synthetic `digest` nodes that can be expanded on demand (`expand_digest`).
 */

import crypto from 'node:crypto';

export const DEFAULT_HOT_ROUNDS = 6;
export const DEFAULT_HOP_RADIUS = 2;

const UNRESOLVED_GOAL_STATUSES = new Set(['open', 'pending', 'active', 'running', 'in_progress']);
const ACTIVE_INTENT_STATUSES = new Set(['pending', 'running']);
const FOLDABLE_TYPES = new Set(['intent', 'fact', 'hint']);
const SETTLED_INTENT_STATUSES = new Set(['completed', 'failed', 'cancelled', 'done', 'skipped', 'timeout']);

function nodeType(n) {
  return String(n?.node_type ?? n?.nodeType ?? n?.type ?? '').toLowerCase();
}

function parseData(n) {
  if (n?.data && typeof n.data === 'object') return n.data;
  if (typeof n?.data_json === 'string') {
    try {
      return JSON.parse(n.data_json) || {};
    } catch {
      return {};
    }
  }
  return {};
}

/**
 * Resolves the round in which a node was last touched. Looks at `node.round`,
 * `data.round`, `data.lastRound`. Unknown rounds are treated as "current" (hot) so that
 * unlabeled nodes are never folded away by accident.
 */
export function nodeRound(node, currentRound = 1) {
  const data = parseData(node);
  const r = node?.round ?? data.lastRound ?? data.round ?? data.roundNo;
  const n = Number(r);
  return Number.isFinite(n) ? n : currentRound;
}

function fromId(e) {
  return e.from_node_id ?? e.fromNodeId ?? e.from;
}
function toId(e) {
  return e.to_node_id ?? e.toNodeId ?? e.to;
}

function buildAdjacency(edges = []) {
  const adj = new Map();
  for (const e of edges) {
    const a = fromId(e);
    const b = toId(e);
    if (!a || !b) continue;
    if (!adj.has(a)) adj.set(a, new Set());
    if (!adj.has(b)) adj.set(b, new Set());
    adj.get(a).add(b);
    adj.get(b).add(a);
  }
  return adj;
}

/**
 * @returns {{ hotIds: Set<string>, seedIds: Set<string>, coldIds: Set<string> }}
 */
export function computeHotSet(
  graph = {},
  { currentRound = 1, R = DEFAULT_HOT_ROUNDS, K = DEFAULT_HOP_RADIUS } = {}
) {
  const nodes = graph.nodes || [];
  const edges = graph.edges || [];
  const seedIds = new Set();

  for (const n of nodes) {
    const t = nodeType(n);
    const status = String(n.status || '').toLowerCase();
    const round = nodeRound(n, currentRound);
    if (t === 'begin' || t === 'finding') seedIds.add(n.id);
    else if (t === 'goal' && UNRESOLVED_GOAL_STATUSES.has(status)) seedIds.add(n.id);
    else if (t === 'intent' && ACTIVE_INTENT_STATUSES.has(status)) seedIds.add(n.id);
    else if (currentRound - round < R) seedIds.add(n.id);
  }

  const adj = buildAdjacency(edges);
  const hotIds = new Set(seedIds);
  let frontier = Array.from(seedIds);
  for (let hop = 0; hop < K && frontier.length > 0; hop++) {
    const next = [];
    for (const id of frontier) {
      for (const nb of adj.get(id) || []) {
        if (!hotIds.has(nb)) {
          hotIds.add(nb);
          next.push(nb);
        }
      }
    }
    frontier = next;
  }

  const coldIds = new Set();
  for (const n of nodes) if (!hotIds.has(n.id)) coldIds.add(n.id);
  return { hotIds, seedIds, coldIds };
}

function isFoldable(n) {
  const t = nodeType(n);
  if (!FOLDABLE_TYPES.has(t)) return false;
  const status = String(n.status || '').toLowerCase();
  if (t === 'intent') return SETTLED_INTENT_STATUSES.has(status);
  if (t === 'fact' && status === 'origin') return false;
  return true;
}

function digestIdFor(ids) {
  const h = crypto.createHash('sha256').update([...ids].sort().join('|')).digest('hex').slice(0, 16);
  return `digest_${h}`;
}

function firstWords(s, n = 80) {
  const str = String(s || '').replace(/\s+/g, ' ').trim();
  return str.length > n ? `${str.slice(0, n - 1)}…` : str;
}

/**
 * Fold cold completed subtrees into digest nodes.
 *
 * @returns {{ nodes: object[], edges: object[], digests: object[], expansions: Map<string, {nodes: object[], edges: object[]}>,
 *   hotIds: Set<string>, foldedCount: number, original: object }}
 */
export function foldColdGraph(
  graph = {},
  { currentRound = 1, R = DEFAULT_HOT_ROUNDS, K = DEFAULT_HOP_RADIUS, graphStore = null, minGroupSize = 2 } = {}
) {
  const rawNodes = graph.nodes || [];
  const edges = graph.edges || [];
  const byId = new Map(rawNodes.map((n) => [n.id, n]));

  // Persisted digests whose members are all still present are recomputed fresh, so drop them.
  const nodes = rawNodes.filter((n) => {
    if (nodeType(n) !== 'digest') return true;
    const collapsed = parseData(n).collapsedNodeIds;
    return !(Array.isArray(collapsed) && collapsed.length > 0 && collapsed.every((id) => byId.has(id)));
  });
  const nodeIdSet = new Set(nodes.map((n) => n.id));
  const liveEdges = edges.filter((e) => nodeIdSet.has(fromId(e)) && nodeIdSet.has(toId(e)));

  const { hotIds } = computeHotSet({ nodes, edges: liveEdges }, { currentRound, R, K });
  const foldable = new Set(nodes.filter((n) => !hotIds.has(n.id) && isFoldable(n)).map((n) => n.id));

  // Connected components over foldable nodes only.
  const adj = new Map();
  for (const e of liveEdges) {
    const a = fromId(e);
    const b = toId(e);
    if (!foldable.has(a) || !foldable.has(b)) continue;
    if (!adj.has(a)) adj.set(a, new Set());
    if (!adj.has(b)) adj.set(b, new Set());
    adj.get(a).add(b);
    adj.get(b).add(a);
  }
  const seen = new Set();
  const groups = [];
  for (const id of foldable) {
    if (seen.has(id)) continue;
    const comp = [];
    const stack = [id];
    seen.add(id);
    while (stack.length) {
      const cur = stack.pop();
      comp.push(cur);
      for (const nb of adj.get(cur) || []) {
        if (!seen.has(nb)) {
          seen.add(nb);
          stack.push(nb);
        }
      }
    }
    if (comp.length >= minGroupSize) groups.push(comp);
  }

  const memberToDigest = new Map();
  const digests = [];
  const expansions = new Map();
  const taskId = nodes[0]?.task_id ?? nodes[0]?.taskId ?? graph.task?.id ?? null;

  for (const comp of groups) {
    const members = comp.map((id) => byId.get(id)).filter(Boolean);
    const id = digestIdFor(comp);
    const counts = {};
    for (const m of members) counts[nodeType(m)] = (counts[nodeType(m)] || 0) + 1;
    const titles = members.slice(0, 5).map((m) => firstWords(m.title || m.summary, 60));
    const rounds = members.map((m) => nodeRound(m, currentRound));
    const compSet = new Set(comp);
    const memberEdges = liveEdges.filter((e) => compSet.has(fromId(e)) && compSet.has(toId(e)));
    const data = {
      collapsedNodeIds: [...comp].sort(),
      collapsedCount: comp.length,
      counts,
      sampleTitles: titles,
      roundRange: [Math.min(...rounds), Math.max(...rounds)],
    };
    const digest = {
      id,
      task_id: taskId,
      taskId,
      node_type: 'digest',
      nodeType: 'digest',
      type: 'digest',
      title: `Digest: ${comp.length} cold nodes (${Object.entries(counts)
        .map(([k, v]) => `${v} ${k}`)
        .join(', ')})`,
      status: 'active',
      summary: titles.join(' | '),
      data,
      data_json: JSON.stringify(data),
      synthetic: true,
    };
    digests.push(digest);
    expansions.set(id, { nodes: members, edges: memberEdges });
    for (const m of comp) memberToDigest.set(m, id);

    if (graphStore && taskId && typeof graphStore.addNode === 'function') {
      try {
        if (!graphStore.getNode(id)) {
          graphStore.addNode({
            id,
            task_id: taskId,
            node_type: 'digest',
            title: digest.title,
            summary: digest.summary,
            data,
          });
        }
      } catch {
        /* persistence of digests is best-effort */
      }
    }
  }

  const keptNodes = nodes.filter((n) => !memberToDigest.has(n.id));
  const outNodes = [...keptNodes, ...digests];

  const edgeSeen = new Set();
  const outEdges = [];
  for (const e of liveEdges) {
    const a = memberToDigest.get(fromId(e)) ?? fromId(e);
    const b = memberToDigest.get(toId(e)) ?? toId(e);
    if (a === b) continue;
    const key = `${a}->${b}:${e.edge_type ?? e.type ?? ''}`;
    if (edgeSeen.has(key)) continue;
    edgeSeen.add(key);
    outEdges.push({
      ...e,
      from_node_id: a,
      to_node_id: b,
      fromNodeId: a,
      toNodeId: b,
      from: a,
      to: b,
      ...(a !== fromId(e) || b !== toId(e) ? { folded: true } : {}),
    });
  }

  return {
    nodes: outNodes,
    edges: outEdges,
    digests,
    expansions,
    hotIds,
    foldedCount: memberToDigest.size,
    original: { ...graph, nodes: rawNodes, edges },
  };
}

/**
 * Unfold a digest node (`expand_digest`). `graph` may be the fold result, or any graph whose
 * nodes include the digest (members are then resolved from `graph.original`, `graph.nodes`,
 * or `graphStore`).
 *
 * @returns {{ digest: object|null, nodes: object[], edges: object[], missingIds: string[] }}
 */
export function expandDigest(digestNodeId, graph = {}, { graphStore = null } = {}) {
  const digest =
    (graph.digests || []).find((d) => d.id === digestNodeId) ||
    (graph.nodes || []).find((n) => n.id === digestNodeId && nodeType(n) === 'digest') ||
    (graphStore?.getNode ? graphStore.getNode(digestNodeId) : null);
  if (!digest || nodeType(digest) !== 'digest') {
    return { digest: null, nodes: [], edges: [], missingIds: [] };
  }
  if (graph.expansions instanceof Map && graph.expansions.has(digestNodeId)) {
    const ex = graph.expansions.get(digestNodeId);
    return { digest, nodes: ex.nodes, edges: ex.edges, missingIds: [] };
  }
  const ids = parseData(digest).collapsedNodeIds || [];
  const pool = new Map();
  for (const n of graph.original?.nodes || []) pool.set(n.id, n);
  for (const n of graph.nodes || []) if (!pool.has(n.id)) pool.set(n.id, n);
  const nodes = [];
  const missingIds = [];
  for (const id of ids) {
    const n = pool.get(id) || (graphStore?.getNode ? graphStore.getNode(id) : null);
    if (n) nodes.push(n);
    else missingIds.push(id);
  }
  const idSet = new Set(ids);
  const edgePool = graph.original?.edges || graph.edges || [];
  const edges = edgePool.filter((e) => idSet.has(fromId(e)) && idSet.has(toId(e)));
  return { digest, nodes, edges, missingIds };
}
