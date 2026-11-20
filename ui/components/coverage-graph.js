/**
 * Asset Coverage Graph Component
 * Hierarchical SVG graph (root_domain / ip -> subdomain -> service -> endpoint)
 * with automatic sibling folding (FOLD_LIMIT = 20) and finding indicators.
 */

const SVG_NS = 'http://www.w3.org/2000/svg';

export const FOLD_LIMIT = 20;
export const FOLD_STEP = 20;

export const ASSET_KIND_META = Object.freeze({
  company: { label: 'Company', color: '#64748b', badge: 'ORG', rank: 0 },
  root_domain: { label: 'Root Domain', color: '#6366f1', badge: 'ROOT', rank: 1 },
  ip: { label: 'IP Address', color: '#0891b2', badge: 'IP', rank: 1 },
  subdomain: { label: 'Subdomain', color: '#3b82f6', badge: 'SUB', rank: 2 },
  service: { label: 'Service', color: '#f59e0b', badge: 'SVC', rank: 3 },
  app: { label: 'App', color: '#d946ef', badge: 'APP', rank: 3 },
  endpoint: { label: 'Endpoint', color: '#f43f5e', badge: 'END', rank: 4 },
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

function getNodeId(n) {
  return String(n?.id ?? n?.key ?? '');
}

function getNodeKind(n) {
  return String(n?.assetType || n?.asset_type || n?.kind || n?.type || 'endpoint').toLowerCase();
}

function getNodeLabel(n) {
  if (!n) return '';
  const kind = getNodeKind(n);
  if (kind === 'service') {
    const parts = [];
    if (n.port) parts.push(`:${n.port}`);
    if (n.title || n.page_title) parts.push(n.title || n.page_title);
    if (n.statusCode || n.status_code) parts.push(`[${n.statusCode || n.status_code}]`);
    if (parts.length > 0) return parts.join(' · ');
  }
  if (kind === 'endpoint' && n.path) {
    return String(n.path);
  }
  return String(n.label || n.host || n.url || n.key || n.id || '');
}

function truncText(text, max = 28) {
  const s = String(text || '').replace(/\s+/g, ' ').trim();
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

function resolveShownLimit(expandedParents, groupId, parentId) {
  if (!expandedParents) return FOLD_LIMIT;
  if (expandedParents instanceof Map) {
    return expandedParents.get(groupId) ?? expandedParents.get(parentId) ?? FOLD_LIMIT;
  }
  if (expandedParents instanceof Set) {
    return expandedParents.has(groupId) || expandedParents.has(parentId) ? Infinity : FOLD_LIMIT;
  }
  if (typeof expandedParents === 'object') {
    const val = expandedParents[groupId] ?? expandedParents[parentId];
    if (typeof val === 'number') return val;
    if (val === true) return Infinity;
  }
  return FOLD_LIMIT;
}

/**
 * Top-down cascading sibling fold (`FOLD_LIMIT = 20` per kind under each parent).
 * Supports both GraphStore edges (`from` parent -> `to` child) and ARTEX edges (`src` child -> `dst` parent).
 */
export function computeVisible(nodes = [], edges = [], expandedParents = new Map()) {
  const safeNodes = Array.isArray(nodes) ? nodes : [];
  const safeEdges = Array.isArray(edges) ? edges : [];

  const byId = new Map();
  for (const n of safeNodes) {
    const id = getNodeId(n);
    if (id) byId.set(id, n);
  }

  const parentOf = new Map();
  const childrenOf = new Map();

  const linkParentChild = (parentId, childId) => {
    if (!parentId || !childId || parentId === childId) return;
    if (!byId.has(parentId) || !byId.has(childId)) return;
    if (!parentOf.has(childId)) {
      parentOf.set(childId, parentId);
    }
    let arr = childrenOf.get(parentId);
    if (!arr) {
      arr = [];
      childrenOf.set(parentId, arr);
    }
    if (!arr.includes(childId)) {
      arr.push(childId);
    }
  };

  for (const e of safeEdges) {
    if (e.from !== undefined || e.fromAssetId !== undefined) {
      const parentId = String(e.from ?? e.fromAssetId ?? '');
      const childId = String(e.to ?? e.toAssetId ?? '');
      linkParentChild(parentId, childId);
    } else if (e.src !== undefined && e.dst !== undefined) {
      // ARTEX convention: src is child, dst is parent
      linkParentChild(String(e.dst), String(e.src));
    }
  }

  for (const n of safeNodes) {
    const childId = getNodeId(n);
    const parentId = n.parentAssetId || n.parent_asset_id;
    if (parentId && byId.has(String(parentId))) {
      linkParentChild(String(parentId), childId);
    }
  }

  const renderNodes = [];
  const visible = new Set();
  const foldNodes = [];
  const queue = [];

  for (const n of safeNodes) {
    const id = getNodeId(n);
    if (!id) continue;
    if (!parentOf.has(id)) {
      queue.push(id);
      visible.add(id);
    }
  }

  for (let qi = 0; qi < queue.length; qi++) {
    const parentId = queue[qi];
    const kids = childrenOf.get(parentId) || [];
    if (kids.length === 0) continue;

    const groups = new Map();
    for (const ck of kids) {
      const cn = byId.get(ck);
      if (!cn) continue;
      const kind = getNodeKind(cn);
      let g = groups.get(kind);
      if (!g) {
        g = [];
        groups.set(kind, g);
      }
      g.push(cn);
    }

    for (const [kind, arr] of groups) {
      arr.sort((a, b) => {
        const at = Boolean(a.tested);
        const bt = Boolean(b.tested);
        if (at !== bt) return at ? -1 : 1;
        return getNodeLabel(a).localeCompare(getNodeLabel(b));
      });

      const groupId = `${parentId}::${kind}`;
      const shown = resolveShownLimit(expandedParents, groupId, parentId);
      const visibleChildren = arr.slice(0, shown);
      const hidden = arr.slice(shown);

      for (const c of visibleChildren) {
        const cid = getNodeId(c);
        if (!visible.has(cid)) {
          visible.add(cid);
          queue.push(cid);
        }
      }

      if (hidden.length > 0) {
        foldNodes.push({
          fold: true,
          id: `fold:${groupId}`,
          key: `fold:${groupId}`,
          groupId,
          parentId,
          parentKey: parentId,
          kind,
          count: hidden.length,
          hidden,
          label: `+${hidden.length} more`,
        });
      }
    }
  }

  for (const n of safeNodes) {
    const id = getNodeId(n);
    if (visible.has(id)) {
      renderNodes.push({ ...n, id, fold: false, kind: getNodeKind(n) });
    }
  }

  const renderEdges = [];
  for (const [childId, parentId] of parentOf.entries()) {
    if (visible.has(parentId) && visible.has(childId)) {
      renderEdges.push({
        id: `cov_${parentId}_${childId}`,
        from: parentId,
        to: childId,
        type: 'contains',
      });
    }
  }

  for (const f of foldNodes) {
    renderNodes.push(f);
    renderEdges.push({
      id: `cov_${f.parentId}_${f.id}`,
      from: f.parentId,
      to: f.id,
      type: 'fold',
    });
  }

  return {
    nodes: renderNodes,
    edges: renderEdges,
    renderNodes,
    renderEdges,
    visibleIds: visible,
  };
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
 * Computes layered tree coordinates for visible coverage nodes.
 */
function layoutCoverageTree(renderNodes, renderEdges) {
  const NODE_W = 210;
  const NODE_H = 62;
  const COL_GAP = 255;
  const ROW_GAP = 82;
  const PAD = 32;

  const childrenMap = new Map();
  const hasParent = new Set();
  const byId = new Map(renderNodes.map(n => [String(n.id), n]));

  for (const e of renderEdges) {
    const p = String(e.from);
    const c = String(e.to);
    if (!byId.has(p) || !byId.has(c)) continue;
    hasParent.add(c);
    let arr = childrenMap.get(p);
    if (!arr) {
      arr = [];
      childrenMap.set(p, arr);
    }
    arr.push(c);
  }

  const roots = renderNodes.filter(n => !hasParent.has(String(n.id))).map(n => String(n.id));
  const depthMap = new Map();
  const queue = roots.map(id => ({ id, depth: 0 }));
  const visited = new Set();

  while (queue.length > 0) {
    const { id, depth } = queue.shift();
    if (visited.has(id)) continue;
    visited.add(id);
    depthMap.set(id, depth);
    for (const childId of childrenMap.get(id) || []) {
      queue.push({ id: childId, depth: depth + 1 });
    }
  }

  const columns = [];
  for (const n of renderNodes) {
    const id = String(n.id);
    const d = depthMap.get(id) ?? 0;
    if (!columns[d]) columns[d] = [];
    columns[d].push(id);
  }

  const maxRows = Math.max(1, ...columns.map(c => (c ? c.length : 0)));
  const totalHeight = maxRows * ROW_GAP;
  const positions = new Map();

  columns.forEach((colIds, colIdx) => {
    if (!colIds) return;
    const colH = colIds.length * ROW_GAP;
    const offsetY = Math.max(0, (totalHeight - colH) / 2);
    colIds.forEach((id, rowIdx) => {
      positions.set(id, {
        x: PAD + colIdx * COL_GAP,
        y: PAD + offsetY + rowIdx * ROW_GAP,
        w: NODE_W,
        h: NODE_H,
      });
    });
  });

  const width = Math.max(640, PAD * 2 + Math.max(1, columns.length) * COL_GAP);
  const height = Math.max(300, PAD * 2 + totalHeight);

  return { positions, width, height, NODE_W, NODE_H };
}

/**
 * Renders the interactive hierarchical Asset Coverage Graph into `container`.
 */
export function renderCoverageGraph(container, coverageData = {}, options = {}) {
  if (!container) return;

  const rawNodes = Array.isArray(coverageData.nodes) ? coverageData.nodes : [];
  const rawEdges = Array.isArray(coverageData.edges) ? coverageData.edges : [];
  const stats = coverageData.stats || {};
  const expanded = options.expandedParents instanceof Map ? options.expandedParents : new Map();
  let selectedAssetId = options.selectedAssetId || null;

  container.innerHTML = `
    <div class="graph-explorer-shell">
      <div class="graph-toolbar">
        <div class="graph-legend">
          ${['root_domain', 'ip', 'subdomain', 'service', 'endpoint']
            .map(k => {
              const meta = ASSET_KIND_META[k];
              return `
                <span class="graph-legend-item">
                  <span class="graph-legend-dot" style="background:${meta.color}"></span>
                  <span>${escapeHtml(meta.label)}</span>
                </span>
              `;
            })
            .join('')}
        </div>
        <div class="graph-toolbar-actions">
          <span class="graph-count-pill" data-role="cov-stats-pill">
            ${Number(stats.totalAssets ?? rawNodes.length)} assets · ${Number(stats.testedAssets ?? 0)} tested (${Number(stats.coveragePct ?? 0)}%) · ${Number(stats.totalFindings ?? 0)} findings
          </span>
          <button type="button" class="btn-secondary btn-small" data-cov-action="reset-folds">Reset Folds (20)</button>
        </div>
      </div>
      <div class="graph-split-body">
        <div class="graph-canvas-wrap" data-role="cov-canvas"></div>
        <aside class="graph-detail-panel" data-role="cov-detail">
          <div class="graph-detail-empty">
            <strong>Select an asset</strong>
            <p>Click any asset node to view host, IP, port, status code, scope status, and anchored findings. Click <code>+N more</code> badges to expand folded siblings.</p>
          </div>
        </aside>
      </div>
    </div>
  `;

  const canvasWrap = container.querySelector('[data-role="cov-canvas"]');
  const detailPanel = container.querySelector('[data-role="cov-detail"]');

  function renderAssetDetail(asset) {
    if (!asset) return;
    const kind = getNodeKind(asset);
    const meta = ASSET_KIND_META[kind] || ASSET_KIND_META.endpoint;
    detailPanel.innerHTML = `
      <div class="graph-detail-card">
        <div class="graph-detail-top">
          <span class="graph-type-badge" style="color:${meta.color};border:1px solid ${meta.color}40">${escapeHtml(meta.label)}</span>
          <span class="graph-status-badge">${asset.tested ? 'Tested' : 'Untested'}</span>
        </div>
        <h4 class="graph-detail-title">${escapeHtml(getNodeLabel(asset) || asset.key)}</h4>
        <div class="graph-detail-meta">
          <div><span>Key:</span> <code>${escapeHtml(asset.key || asset.id)}</code></div>
          ${asset.host ? `<div><span>Host:</span> <code>${escapeHtml(asset.host)}</code></div>` : ''}
          ${asset.ip ? `<div><span>IP:</span> <code>${escapeHtml(asset.ip)}</code></div>` : ''}
          ${asset.port ? `<div><span>Port:</span> <code>${Number(asset.port)}</code></div>` : ''}
          ${asset.service ? `<div><span>Service:</span> <code>${escapeHtml(asset.service)}</code></div>` : ''}
          ${asset.statusCode ? `<div><span>HTTP Status:</span> <code>${Number(asset.statusCode)}</code></div>` : ''}
          <div><span>In Scope:</span> <strong>${asset.inScope === false ? 'No (Out of Scope)' : 'Yes'}</strong></div>
          <div><span>Findings:</span> <strong>${Number(asset.findingCount ?? asset.finding_count ?? 0)}</strong></div>
          <div><span>Anchors:</span> <strong>${Number(asset.anchorCount ?? asset.anchor_count ?? 0)}</strong></div>
        </div>
        ${asset.url ? `<p class="graph-detail-summary"><code>${escapeHtml(asset.url)}</code></p>` : ''}
      </div>
    `;
  }

  function draw() {
    if (rawNodes.length === 0) {
      canvasWrap.innerHTML = `
        <div class="empty-state">
          <span class="empty-icon">🕸️</span>
          <h3 class="empty-title">No Asset Coverage Nodes Yet</h3>
          <p class="empty-text">Run a scan or ingest external tool output (nmap, httpx, nuclei, ffuf, bbot) to build the asset hierarchy.</p>
        </div>
      `;
      return;
    }

    const { renderNodes, renderEdges } = computeVisible(rawNodes, rawEdges, expanded);
    const { positions, width, height, NODE_W, NODE_H } = layoutCoverageTree(renderNodes, renderEdges);

    const svg = svgEl('svg', {
      class: 'dag-svg',
      viewBox: `0 0 ${width} ${height}`,
      width,
      height,
      role: 'img',
      'aria-label': 'Asset Coverage Graph',
    });

    const edgesLayer = svgEl('g');
    const nodesLayer = svgEl('g');

    for (const e of renderEdges) {
      const p1 = positions.get(String(e.from));
      const p2 = positions.get(String(e.to));
      if (!p1 || !p2) continue;
      const x1 = p1.x + NODE_W;
      const y1 = p1.y + NODE_H / 2;
      const x2 = p2.x;
      const y2 = p2.y + NODE_H / 2;
      const dx = Math.max(30, (x2 - x1) * 0.45);
      edgesLayer.appendChild(
        svgEl('path', {
          d: `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`,
          fill: 'none',
          stroke: e.type === 'fold' ? '#8b949e' : '#30363d',
          'stroke-width': '1.6',
          'stroke-dasharray': e.type === 'fold' ? '4 4' : null,
        })
      );
    }

    for (const node of renderNodes) {
      const id = String(node.id);
      const pos = positions.get(id);
      if (!pos) continue;

      const g = svgEl('g', {
        transform: `translate(${pos.x}, ${pos.y})`,
        style: 'cursor: pointer;',
      });

      if (node.fold) {
        const meta = ASSET_KIND_META[node.kind] || ASSET_KIND_META.endpoint;
        g.appendChild(
          svgEl('rect', {
            width: NODE_W,
            height: NODE_H,
            rx: '8',
            fill: '#21262d',
            stroke: meta.color,
            'stroke-width': '1.5',
            'stroke-dasharray': '5 3',
          })
        );
        g.appendChild(
          svgEl(
            'text',
            { x: NODE_W / 2, y: 27, fill: meta.color, 'font-size': '12', 'font-weight': '700', 'text-anchor': 'middle' },
            `+${node.count} more ${meta.label}s`
          )
        );
        g.appendChild(
          svgEl(
            'text',
            { x: NODE_W / 2, y: 45, fill: '#8b949e', 'font-size': '10.5', 'text-anchor': 'middle' },
            `Click to expand (+${Math.min(FOLD_STEP, node.count)})`
          )
        );
        g.addEventListener('click', () => {
          const prev = expanded.get(node.groupId) ?? FOLD_LIMIT;
          expanded.set(node.groupId, prev + FOLD_STEP);
          draw();
        });
      } else {
        const kind = getNodeKind(node);
        const meta = ASSET_KIND_META[kind] || ASSET_KIND_META.endpoint;
        const findingCount = Number(node.findingCount ?? node.finding_count ?? 0);
        const isSelected = selectedAssetId === id;
        const inScope = node.inScope !== false && node.in_scope !== false;

        g.appendChild(
          svgEl('rect', {
            width: NODE_W,
            height: NODE_H,
            rx: '8',
            fill: node.tested ? '#161b22' : '#0d1117',
            stroke: isSelected ? '#f0f6fc' : findingCount > 0 ? '#f85149' : meta.color,
            'stroke-width': isSelected ? '2.4' : '1.5',
            'stroke-dasharray': inScope ? null : '5 3',
          })
        );

        g.appendChild(
          svgEl('rect', {
            x: '0',
            y: '0',
            width: '5',
            height: NODE_H,
            rx: '2',
            fill: node.tested ? meta.color : '#484f58',
          })
        );

        g.appendChild(
          svgEl(
            'text',
            { x: '12', y: '18', fill: meta.color, 'font-size': '10', 'font-weight': '700' },
            `${meta.badge}${node.tested ? ' · TESTED' : ''}`
          )
        );

        if (findingCount > 0) {
          g.appendChild(
            svgEl('rect', {
              x: NODE_W - 56,
              y: '6',
              width: '48',
              height: '18',
              rx: '9',
              fill: 'rgba(248, 81, 73, 0.22)',
              stroke: '#f85149',
              'stroke-width': '1',
            })
          );
          g.appendChild(
            svgEl(
              'text',
              { x: NODE_W - 32, y: '18', fill: '#ff7b72', 'font-size': '10', 'font-weight': '700', 'text-anchor': 'middle' },
              `${findingCount} vuln`
            )
          );
        }

        g.appendChild(
          svgEl(
            'text',
            { x: '12', y: '38', fill: '#f0f6fc', 'font-size': '12', 'font-weight': '600' },
            truncText(getNodeLabel(node), 25)
          )
        );

        const sub = node.ip && node.host !== node.ip ? node.ip : node.service || node.source || '';
        g.appendChild(
          svgEl(
            'text',
            { x: '12', y: '53', fill: '#8b949e', 'font-size': '10' },
            truncText(sub || (!inScope ? 'Out of scope' : 'In scope'), 28)
          )
        );

        g.addEventListener('click', () => {
          selectedAssetId = id;
          renderAssetDetail(node);
          if (typeof options.onSelectAsset === 'function') {
            options.onSelectAsset(node);
          }
          draw();
        });
      }

      nodesLayer.appendChild(g);
    }

    svg.appendChild(edgesLayer);
    svg.appendChild(nodesLayer);
    canvasWrap.innerHTML = '';
    canvasWrap.appendChild(svg);

    if (selectedAssetId) {
      const selectedNode = rawNodes.find(n => getNodeId(n) === selectedAssetId);
      if (selectedNode) renderAssetDetail(selectedNode);
    }
  }

  container.querySelector('[data-cov-action="reset-folds"]')?.addEventListener('click', () => {
    expanded.clear();
    draw();
  });

  draw();
}
