/**
 * Exploration Graph (DAG) Component
 * Interactive SVG DAG for agent exploration nodes (begin, goal, intent, fact, finding, hint, digest).
 */

const SVG_NS = 'http://www.w3.org/2000/svg';

const COL_W = 270;
const ROW_H = 112;
const NODE_W = 216;
const NODE_H = 74;
const PAD_X = 36;
const PAD_Y = 36;

export const NODE_TYPE_META = Object.freeze({
  begin: { label: 'Start', color: '#64748b', bg: 'rgba(100,116,139,0.18)', badge: 'BEGIN' },
  task: { label: 'Root Task', color: '#64748b', bg: 'rgba(100,116,139,0.18)', badge: 'TASK' },
  goal: { label: 'Goal', color: '#2ea043', bg: 'rgba(46,160,67,0.18)', badge: 'GOAL' },
  intent: { label: 'Intent', color: '#58a6ff', bg: 'rgba(88,166,255,0.18)', badge: 'INTENT' },
  fact: { label: 'Fact', color: '#d29922', bg: 'rgba(210,153,34,0.18)', badge: 'FACT' },
  finding: { label: 'Finding', color: '#f85149', bg: 'rgba(248,81,73,0.18)', badge: 'FINDING' },
  hint: { label: 'Hint', color: '#bc8cff', bg: 'rgba(188,140,255,0.18)', badge: 'HINT' },
  digest: { label: 'Digest', color: '#2dd4bf', bg: 'rgba(45,212,191,0.18)', badge: 'DIGEST' },
});

export const EDGE_TYPE_COLORS = Object.freeze({
  spawns: '#2ea043',
  derived_from: '#6366f1',
  yields: '#d29922',
  proves: '#f85149',
  covers: '#2dd4bf',
});

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function getNodeType(node) {
  const raw = String(node?.nodeType || node?.node_type || node?.type || 'fact').toLowerCase();
  const status = String(node?.status || node?.state || '').toLowerCase();
  if (raw === 'fact' && status === 'origin') return 'begin';
  return raw;
}

function getNodeState(node) {
  return String(node?.status || node?.state || 'pending').toLowerCase();
}

function getEdgeEndpoints(edge) {
  return {
    src: String(edge?.fromNodeId ?? edge?.from_node_id ?? edge?.from ?? edge?.src ?? ''),
    dst: String(edge?.toNodeId ?? edge?.to_node_id ?? edge?.to ?? edge?.dst ?? ''),
    rel: String(edge?.edgeType ?? edge?.edge_type ?? edge?.type ?? edge?.rel ?? 'spawns').toLowerCase(),
  };
}

function getNodeLabel(node) {
  if (!node) return '';
  if (node.title && String(node.title).trim()) return String(node.title).trim();
  if (node.summary && String(node.summary).trim()) return String(node.summary).trim();
  const data = node.data && typeof node.data === 'object' ? node.data : null;
  if (data) {
    for (const k of ['name', 'title', 'summary', 'text', 'description', 'body']) {
      if (typeof data[k] === 'string' && data[k].trim()) return data[k].trim();
    }
  }
  return String(node.id || 'node');
}

function truncText(text, max = 32) {
  const s = String(text || '').replace(/\s+/g, ' ').trim();
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

function pushMap(map, key, val) {
  let list = map.get(key);
  if (!list) {
    list = [];
    map.set(key, list);
  }
  list.push(val);
}

/**
 * Contracts collapsed active digest nodes by absorbing their covered members
 * and rewiring edges. Digest IDs present in `expandedDigests` remain expanded.
 */
export function collapseDigestGraph(nodes = [], edges = [], expandedDigests = new Set()) {
  const expanded =
    expandedDigests instanceof Set
      ? expandedDigests
      : new Set(Array.isArray(expandedDigests) ? expandedDigests : []);

  const safeNodes = Array.isArray(nodes) ? nodes : [];
  const safeEdges = Array.isArray(edges) ? edges : [];

  const activeDigests = new Set();
  const collapsedDigests = new Set();
  const digestMembersMap = new Map();

  for (const n of safeNodes) {
    const nt = String(n?.nodeType || n?.node_type || n?.type || '').toLowerCase();
    const st = getNodeState(n);
    if (nt === 'digest' && st !== 'superseded') {
      const id = String(n.id);
      activeDigests.add(id);
      if (!expanded.has(id)) {
        collapsedDigests.add(id);
      }
      digestMembersMap.set(id, new Set());
    }
  }

  const memberToDigest = new Map();
  for (const e of safeEdges) {
    const { src, dst, rel } = getEdgeEndpoints(e);
    if (rel === 'covers' && activeDigests.has(src) && dst) {
      let members = digestMembersMap.get(src);
      if (!members) {
        members = new Set();
        digestMembersMap.set(src, members);
      }
      members.add(dst);
      if (collapsedDigests.has(src)) {
        memberToDigest.set(dst, src);
      }
    }
  }

  // Fallback: inspect data.member_ids if no explicit `covers` edges exist
  for (const n of safeNodes) {
    const id = String(n.id);
    if (!activeDigests.has(id)) continue;
    const members = digestMembersMap.get(id);
    const memberIds = n.data?.member_ids;
    if (members && members.size === 0 && memberIds && typeof memberIds === 'object') {
      const combined = [...(memberIds.facts || []), ...(memberIds.intents || [])];
      for (const mid of combined) {
        const sid = String(mid);
        members.add(sid);
        if (collapsedDigests.has(id)) {
          memberToDigest.set(sid, id);
        }
      }
    }
  }

  const viewNodes = safeNodes.filter(n => {
    const nt = String(n?.nodeType || n?.node_type || n?.type || '').toLowerCase();
    const st = getNodeState(n);
    if (nt === 'digest') return st !== 'superseded';
    return !memberToDigest.has(String(n.id));
  });

  const remap = id => memberToDigest.get(id) ?? id;
  const seen = new Set();
  const rewired = [];
  const produced = new Set();

  for (const e of safeEdges) {
    const { src: rawSrc, dst: rawDst, rel } = getEdgeEndpoints(e);
    if (rel === 'covers') {
      // Keep covers edges only for expanded digests so visual grouping remains clear
      if (activeDigests.has(rawSrc) && expanded.has(rawSrc)) {
        rewired.push(e);
      }
      continue;
    }
    const src = remap(rawSrc);
    const dst = remap(rawDst);
    if (!src || !dst || src === dst) continue;
    const dedupKey = `${src}::${rel}::${dst}`;
    if (seen.has(dedupKey)) continue;
    seen.add(dedupKey);
    if (rel === 'yields') {
      produced.add(`${src}::${dst}`);
    }
    if (src === rawSrc && dst === rawDst) {
      rewired.push(e);
    } else {
      rewired.push({
        ...e,
        from: src,
        to: dst,
        fromNodeId: src,
        toNodeId: dst,
        src,
        dst,
        type: rel,
        edgeType: rel,
        rel,
      });
    }
  }

  const viewEdges = rewired.filter(e => {
    const { src, dst, rel } = getEdgeEndpoints(e);
    return !(rel === 'derived_from' && produced.has(`${dst}::${src}`));
  });

  return {
    nodes: viewNodes,
    edges: viewEdges,
    viewNodes,
    viewEdges,
    digestMembersMap,
  };
}

/**
 * Auto-layers DAG nodes left-to-right by longest path (cycle-safe DFS back-edge break)
 * with 4-pass barycenter sweep to minimize edge crossings.
 * Returns Map<nodeId, { x, y, col, row }>.
 */
export function computeLayout(nodes = [], edges = []) {
  const safeNodes = Array.isArray(nodes) ? nodes : [];
  const safeEdges = Array.isArray(edges) ? edges : [];
  const order = safeNodes.map(n => String(n.id));
  const idSet = new Set(order);

  const valid = [];
  for (const e of safeEdges) {
    const { src, dst } = getEdgeEndpoints(e);
    if (src && dst && src !== dst && idSet.has(src) && idSet.has(dst)) {
      valid.push({ src, dst });
    }
  }

  const out = new Map();
  for (const e of valid) pushMap(out, e.src, e.dst);

  // Cycle-safe DFS to detect back-edges
  const seen = new Map(); // 0=unvisited, 1=visiting, 2=done
  const back = new Set();
  for (const root of order) {
    if ((seen.get(root) ?? 0) !== 0) continue;
    const stack = [{ u: root, i: 0 }];
    seen.set(root, 1);
    while (stack.length > 0) {
      const top = stack[stack.length - 1];
      const nbrs = out.get(top.u) || [];
      if (top.i >= nbrs.length) {
        seen.set(top.u, 2);
        stack.pop();
        continue;
      }
      const v = nbrs[top.i++];
      const st = seen.get(v) ?? 0;
      if (st === 1) {
        back.add(`${top.u}->${v}`);
      } else if (st === 0) {
        seen.set(v, 1);
        stack.push({ u: v, i: 0 });
      }
    }
  }

  const dagSucc = new Map();
  const indeg = new Map(order.map(id => [id, 0]));
  for (const e of valid) {
    if (back.has(`${e.src}->${e.dst}`)) continue;
    pushMap(dagSucc, e.src, e.dst);
    indeg.set(e.dst, (indeg.get(e.dst) ?? 0) + 1);
  }

  const layer = new Map(order.map(id => [id, 0]));
  const queue = order.filter(id => (indeg.get(id) ?? 0) === 0);
  for (let qi = 0; qi < queue.length; qi++) {
    const u = queue[qi];
    for (const v of dagSucc.get(u) || []) {
      layer.set(v, Math.max(layer.get(v) ?? 0, (layer.get(u) ?? 0) + 1));
      const d = (indeg.get(v) ?? 0) - 1;
      indeg.set(v, d);
      if (d === 0) queue.push(v);
    }
  }

  const maxLayer = Math.max(0, ...layer.values());
  const columns = Array.from({ length: maxLayer + 1 }, () => []);
  for (const id of order) {
    columns[layer.get(id) ?? 0].push(id);
  }

  const colIndexOf = new Map();
  columns.forEach((ids, c) => ids.forEach(id => colIndexOf.set(id, c)));

  const neighbors = new Map();
  for (const e of valid) {
    const cs = colIndexOf.get(e.src);
    const cd = colIndexOf.get(e.dst);
    if (cs === undefined || cd === undefined || Math.abs(cs - cd) !== 1) continue;
    pushMap(neighbors, e.src, e.dst);
    pushMap(neighbors, e.dst, e.src);
  }

  const sweep = dir => {
    const start = dir === 1 ? 1 : columns.length - 2;
    const end = dir === 1 ? columns.length : -1;
    for (let c = start; c !== end; c += dir) {
      const ref = c - dir;
      if (ref < 0 || ref >= columns.length) continue;
      const refIndex = new Map(columns[ref].map((id, i) => [id, i]));
      const scored = columns[c].map((id, i) => {
        const ns = (neighbors.get(id) || [])
          .map(nid => refIndex.get(nid))
          .filter(v => v !== undefined);
        const bary = ns.length ? ns.reduce((a, b) => a + b, 0) / ns.length : i;
        return { id, bary, i };
      });
      scored.sort((a, b) => a.bary - b.bary || a.i - b.i);
      columns[c] = scored.map(s => s.id);
    }
  };

  for (let iter = 0; iter < 4; iter++) {
    sweep(1);
    sweep(-1);
  }

  const maxCount = Math.max(1, ...columns.map(c => c.length));
  const totalHeight = maxCount * ROW_H;
  const positions = new Map();

  columns.forEach((ids, col) => {
    const colHeight = ids.length * ROW_H;
    const offsetY = Math.max(0, (totalHeight - colHeight) / 2);
    ids.forEach((id, row) => {
      positions.set(id, {
        x: PAD_X + col * COL_W,
        y: PAD_Y + offsetY + row * ROW_H,
        col,
        row,
      });
    });
  });

  return positions;
}

function svgEl(tag, attrs = {}, text = null) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v !== null && v !== undefined) {
      el.setAttribute(k, String(v));
    }
  }
  if (text !== null && text !== undefined) {
    el.textContent = String(text);
  }
  return el;
}

/**
 * Renders the interactive Exploration DAG + Node Detail Side Panel into `container`.
 */
export function renderExplorationGraph(container, graphData = {}, options = {}) {
  if (!container) return;

  const allNodes = Array.isArray(graphData.nodes) ? graphData.nodes : [];
  const allEdges = Array.isArray(graphData.edges) ? graphData.edges : [];
  const anchors = Array.isArray(graphData.anchors) ? graphData.anchors : [];

  const expandedDigests =
    options.expandedDigests instanceof Set ? options.expandedDigests : new Set();
  let selectedNodeId = options.selectedNodeId || null;

  container.innerHTML = `
    <div class="graph-explorer-shell">
      <div class="graph-toolbar">
        <div class="graph-legend">
          ${Object.entries(NODE_TYPE_META)
            .filter(([k]) => k !== 'task')
            .map(
              ([k, meta]) => `
            <span class="graph-legend-item">
              <span class="graph-legend-dot" style="background:${meta.color}"></span>
              <span>${escapeHtml(meta.label)}</span>
            </span>
          `
            )
            .join('')}
        </div>
        <div class="graph-toolbar-actions">
          <span class="graph-count-pill" id="dag-counts-pill">0 nodes · 0 edges</span>
          <button type="button" class="btn-secondary btn-small" data-dag-action="expand-all">Expand All Digests</button>
          <button type="button" class="btn-secondary btn-small" data-dag-action="collapse-all">Collapse Digests</button>
        </div>
      </div>
      <div class="graph-split-body">
        <div class="graph-canvas-wrap" data-role="canvas-wrap"></div>
        <aside class="graph-detail-panel" data-role="detail-panel">
          <div class="graph-detail-empty">
            <strong>Select a node</strong>
            <p>Click any node in the Exploration DAG to inspect its evidence, anchors, or digest members. Click a Digest node to expand/collapse its folded nodes.</p>
          </div>
        </aside>
      </div>
    </div>
  `;

  const canvasWrap = container.querySelector('[data-role="canvas-wrap"]');
  const detailPanel = container.querySelector('[data-role="detail-panel"]');
  const countsPill = container.querySelector('#dag-counts-pill');

  function renderDetailPanel(node, digestMembersMap) {
    if (!node) {
      detailPanel.innerHTML = `
        <div class="graph-detail-empty">
          <strong>Select a node</strong>
          <p>Click any node in the Exploration DAG to inspect its metadata, anchors, or digest members.</p>
        </div>
      `;
      return;
    }

    const nType = getNodeType(node);
    const meta = NODE_TYPE_META[nType] || NODE_TYPE_META.fact;
    const stateStr = getNodeState(node);
    const title = getNodeLabel(node);
    const nodeAnchors = anchors.filter(a => String(a.nodeId || a.node_id) === String(node.id));
    const members = digestMembersMap.get(String(node.id));

    let extraHtml = '';
    if (nType === 'digest' && members) {
      const isExpanded = expandedDigests.has(String(node.id));
      extraHtml += `
        <div class="detail-section">
          <div class="detail-section-header">
            <span>Folded Members (${members.size})</span>
            <button type="button" class="btn-secondary btn-small" data-toggle-digest="${escapeHtml(node.id)}">
              ${isExpanded ? 'Collapse Digest' : 'Expand Digest'}
            </button>
          </div>
          <ul class="detail-member-list">
            ${Array.from(members)
              .map(mid => {
                const mNode = allNodes.find(x => String(x.id) === mid);
                return `<li><code>${escapeHtml(mid)}</code> — ${escapeHtml(mNode ? getNodeLabel(mNode) : 'member')}</li>`;
              })
              .join('')}
          </ul>
        </div>
      `;
    }

    if (nodeAnchors.length > 0) {
      extraHtml += `
        <div class="detail-section">
          <div class="detail-section-header">Anchored Assets (${nodeAnchors.length})</div>
          <ul class="detail-member-list">
            ${nodeAnchors
              .map(a => `<li><code>${escapeHtml(a.assetId || a.asset_id)}</code> (${escapeHtml(a.relation || 'targets')})</li>`)
              .join('')}
          </ul>
        </div>
      `;
    }

    detailPanel.innerHTML = `
      <div class="graph-detail-card">
        <div class="graph-detail-top">
          <span class="graph-type-badge" style="color:${meta.color};background:${meta.bg};border:1px solid ${meta.color}40">${escapeHtml(meta.badge)}</span>
          <span class="graph-status-badge">${escapeHtml(stateStr)}</span>
        </div>
        <h4 class="graph-detail-title">${escapeHtml(title)}</h4>
        <div class="graph-detail-meta">
          <div><span>Node ID:</span> <code>${escapeHtml(node.id)}</code></div>
          ${node.severity ? `<div><span>Severity:</span> <strong>${escapeHtml(node.severity)}</strong></div>` : ''}
          ${node.poeLevel ? `<div><span>PoE Level:</span> <strong>L${Number(node.poeLevel)}</strong></div>` : ''}
          ${node.claimOwner ? `<div><span>Claim Owner:</span> <code>${escapeHtml(node.claimOwner)}</code></div>` : ''}
        </div>
        ${node.summary ? `<p class="graph-detail-summary">${escapeHtml(node.summary)}</p>` : ''}
        ${extraHtml}
        <div class="detail-section">
          <div class="detail-section-header">Structured Payload</div>
          <pre class="code-block detail-json"><code>${escapeHtml(JSON.stringify(node.data || {}, null, 2))}</code></pre>
        </div>
      </div>
    `;

    const toggleBtn = detailPanel.querySelector('[data-toggle-digest]');
    if (toggleBtn) {
      toggleBtn.addEventListener('click', () => {
        const did = toggleBtn.getAttribute('data-toggle-digest');
        if (expandedDigests.has(did)) expandedDigests.delete(did);
        else expandedDigests.add(did);
        draw();
      });
    }
  }

  function draw() {
    if (allNodes.length === 0) {
      canvasWrap.innerHTML = `
        <div class="empty-state">
          <span class="empty-icon">🧭</span>
          <h3 class="empty-title">No Exploration Graph Nodes Yet</h3>
          <p class="empty-text">Run a security scan or create an Agentic Verification Task to populate the exploration DAG.</p>
        </div>
      `;
      if (countsPill) countsPill.textContent = '0 nodes · 0 edges';
      return;
    }

    const { viewNodes, viewEdges, digestMembersMap } = collapseDigestGraph(
      allNodes,
      allEdges,
      expandedDigests
    );
    const positions = computeLayout(viewNodes, viewEdges);

    if (countsPill) {
      countsPill.textContent = `${viewNodes.length} nodes · ${viewEdges.length} edges`;
    }

    let maxX = 640;
    let maxY = 320;
    for (const pos of positions.values()) {
      if (pos.x + NODE_W + PAD_X > maxX) maxX = pos.x + NODE_W + PAD_X;
      if (pos.y + NODE_H + PAD_Y > maxY) maxY = pos.y + NODE_H + PAD_Y;
    }

    const svg = svgEl('svg', {
      class: 'dag-svg',
      viewBox: `0 0 ${maxX} ${maxY}`,
      width: maxX,
      height: maxY,
      role: 'img',
      'aria-label': 'Exploration Graph DAG',
    });

    // Arrowhead markers
    const defs = svgEl('defs');
    for (const [rel, color] of Object.entries(EDGE_TYPE_COLORS)) {
      const marker = svgEl('marker', {
        id: `dag-arrow-${rel}`,
        viewBox: '0 0 10 10',
        refX: '9',
        refY: '5',
        markerWidth: '6',
        markerHeight: '6',
        orient: 'auto-start-reverse',
      });
      marker.appendChild(svgEl('path', { d: 'M 0 1 L 10 5 L 0 9 z', fill: color }));
      defs.appendChild(marker);
    }
    svg.appendChild(defs);

    const edgesLayer = svgEl('g', { class: 'dag-edges-layer' });
    const nodesLayer = svgEl('g', { class: 'dag-nodes-layer' });

    for (const e of viewEdges) {
      const { src, dst, rel } = getEdgeEndpoints(e);
      const p1 = positions.get(src);
      const p2 = positions.get(dst);
      if (!p1 || !p2) continue;

      const x1 = p1.x + NODE_W;
      const y1 = p1.y + NODE_H / 2;
      const x2 = p2.x;
      const y2 = p2.y + NODE_H / 2;
      const dx = Math.max(40, Math.abs(x2 - x1) * 0.45);
      const pathD =
        x2 >= x1
          ? `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`
          : `M ${p1.x + NODE_W / 2} ${p1.y} C ${p1.x + NODE_W / 2} ${p1.y - 50}, ${p2.x + NODE_W / 2} ${p2.y - 50}, ${p2.x + NODE_W / 2} ${p2.y}`;

      const color = EDGE_TYPE_COLORS[rel] || '#58a6ff';
      const path = svgEl('path', {
        d: pathD,
        fill: 'none',
        stroke: color,
        'stroke-width': rel === 'proves' ? '2.4' : '1.8',
        'stroke-dasharray': rel === 'covers' ? '5 4' : null,
        'stroke-opacity': '0.82',
        'marker-end': EDGE_TYPE_COLORS[rel] ? `url(#dag-arrow-${rel})` : null,
      });
      edgesLayer.appendChild(path);

      // Edge label at midpoint
      const midX = (x1 + x2) / 2;
      const midY = (y1 + y2) / 2 - 6;
      const label = svgEl(
        'text',
        {
          x: midX,
          y: midY,
          fill: color,
          'font-size': '10',
          'font-weight': '600',
          'text-anchor': 'middle',
        },
        rel
      );
      edgesLayer.appendChild(label);
    }

    for (const node of viewNodes) {
      const id = String(node.id);
      const pos = positions.get(id);
      if (!pos) continue;

      const nType = getNodeType(node);
      const meta = NODE_TYPE_META[nType] || NODE_TYPE_META.fact;
      const st = getNodeState(node);
      const isSelected = selectedNodeId === id;
      const isDigest = nType === 'digest';
      const memberCount = digestMembersMap.get(id)?.size || 0;

      const g = svgEl('g', {
        class: `dag-node ${isSelected ? 'selected' : ''}`,
        transform: `translate(${pos.x}, ${pos.y})`,
        style: 'cursor: pointer;',
      });

      g.appendChild(
        svgEl('rect', {
          width: NODE_W,
          height: NODE_H,
          rx: '8',
          fill: '#161b22',
          stroke: isSelected ? '#f0f6fc' : meta.color,
          'stroke-width': isSelected ? '2.5' : '1.5',
        })
      );

      // Left accent stripe
      g.appendChild(
        svgEl('rect', {
          x: '0',
          y: '0',
          width: '6',
          height: NODE_H,
          rx: '3',
          fill: meta.color,
        })
      );

      // Type badge
      g.appendChild(
        svgEl(
          'text',
          {
            x: '14',
            y: '19',
            fill: meta.color,
            'font-size': '10',
            'font-weight': '700',
          },
          isDigest ? `${meta.badge} (${memberCount})` : meta.badge
        )
      );

      // Status pill on top-right
      g.appendChild(
        svgEl(
          'text',
          {
            x: NODE_W - 10,
            y: '19',
            fill: '#8b949e',
            'font-size': '10',
            'text-anchor': 'end',
          },
          isDigest ? (expandedDigests.has(id) ? '▼ expanded' : '▶ click to expand') : st
        )
      );

      // Title
      g.appendChild(
        svgEl(
          'text',
          {
            x: '14',
            y: '41',
            fill: '#f0f6fc',
            'font-size': '12.5',
            'font-weight': '600',
          },
          truncText(getNodeLabel(node), 26)
        )
      );

      // Subtitle / severity / ID
      const subText = node.severity
        ? `Severity: ${node.severity}${node.poeLevel ? ` · PoE L${node.poeLevel}` : ''}`
        : truncText(id, 28);
      g.appendChild(
        svgEl(
          'text',
          {
            x: '14',
            y: '60',
            fill: '#8b949e',
            'font-size': '10.5',
          },
          subText
        )
      );

      g.addEventListener('click', () => {
        selectedNodeId = id;
        if (isDigest) {
          if (expandedDigests.has(id)) expandedDigests.delete(id);
          else expandedDigests.add(id);
        }
        if (typeof options.onSelectNode === 'function') {
          options.onSelectNode(node);
        }
        draw();
      });

      nodesLayer.appendChild(g);
    }

    svg.appendChild(edgesLayer);
    svg.appendChild(nodesLayer);

    canvasWrap.innerHTML = '';
    canvasWrap.appendChild(svg);

    const activeNode = allNodes.find(n => String(n.id) === selectedNodeId) || null;
    renderDetailPanel(activeNode, digestMembersMap);
  }

  container.querySelector('[data-dag-action="expand-all"]')?.addEventListener('click', () => {
    for (const n of allNodes) {
      if (getNodeType(n) === 'digest') expandedDigests.add(String(n.id));
    }
    draw();
  });

  container.querySelector('[data-dag-action="collapse-all"]')?.addEventListener('click', () => {
    expandedDigests.clear();
    draw();
  });

  draw();
}
