/**
 * Traffic Inspector & Live RFC-9110 Replay Component
 * Queries FTS5-backed traffic exchanges, inspects split request/response,
 * runs live RFC-9110 replay, and manages HMAC-tainted traffic rewrite rules.
 */

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

async function fetchJson(url, opts = {}) {
  const res = await fetch(url, {
    ...opts,
    headers: {
      Accept: 'application/json',
      ...(opts.body ? { 'Content-Type': 'application/json' } : {}),
      ...(opts.headers || {}),
    },
  });
  const data = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
  if (!res.ok) {
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  return data;
}

function formatHeadersText(headers) {
  if (!headers || typeof headers !== 'object') return '';
  return Object.entries(headers)
    .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : String(v)}`)
    .join('\n');
}

function statusClass(code) {
  const n = Number(code) || 0;
  if (n >= 500) return 'status-5xx';
  if (n >= 400) return 'status-4xx';
  if (n >= 300) return 'status-3xx';
  if (n >= 200) return 'status-2xx';
  return 'status-other';
}

/**
 * Renders the Traffic & Replay workspace into `container`.
 */
export async function renderTrafficInspector(container, options = {}) {
  if (!container) return;

  let exchanges = [];
  let selectedExchange = null;
  let rewriteRules = [];

  container.innerHTML = `
    <div class="traffic-shell">
      <div class="traffic-header">
        <div>
          <h2 class="section-title">HTTP Traffic Store &amp; RFC-9110 Replay</h2>
          <p class="section-subtitle">Full-text search captured exchanges, replay modified requests, and manage HMAC-tainted rewrite rules</p>
        </div>
        <div class="traffic-header-actions">
          <button type="button" class="btn-secondary" data-tr-action="toggle-rewrites">⚙️ Rewrite Rules (<span data-role="rewrite-count">0</span>)</button>
          <button type="button" class="btn-secondary" data-tr-action="refresh">🔄 Refresh</button>
        </div>
      </div>

      <!-- Filter Bar -->
      <div class="traffic-filter-bar">
        <input type="search" class="search-input traffic-search" data-role="tr-search" placeholder="FTS5 search URL, headers, status, or body...">
        <select class="form-select" data-role="tr-host">
          <option value="">All Hosts</option>
        </select>
        <select class="form-select" data-role="tr-method">
          <option value="">All Methods</option>
          <option value="GET">GET</option>
          <option value="POST">POST</option>
          <option value="PUT">PUT</option>
          <option value="PATCH">PATCH</option>
          <option value="DELETE">DELETE</option>
          <option value="HEAD">HEAD</option>
          <option value="OPTIONS">OPTIONS</option>
        </select>
        <select class="form-select" data-role="tr-status">
          <option value="">All Statuses</option>
          <option value="2xx">2xx Success</option>
          <option value="3xx">3xx Redirect</option>
          <option value="4xx">4xx Client Error</option>
          <option value="5xx">5xx Server Error</option>
        </select>
        <button type="button" class="btn-primary" data-tr-action="query">Search</button>
      </div>

      <div class="feedback-banner hidden" data-role="tr-feedback"></div>

      <!-- Rewrite Rules Drawer -->
      <div class="rewrite-rules-panel hidden" data-role="rewrites-panel">
        <div class="panel-sub-header">
          <h3>Traffic Rewrite Rules (HMAC Taint Guard)</h3>
          <button type="button" class="btn-secondary btn-small" data-tr-action="toggle-rewrites">Hide</button>
        </div>
        <form class="rewrite-form" data-role="rewrite-form">
          <input type="text" class="form-input" data-role="rw-name" placeholder="Rule Name (e.g. Auth Header Injection)" required>
          <input type="text" class="form-input" data-role="rw-host" placeholder="Scope Host (* for all)" value="*">
          <select class="form-select" data-role="rw-phase">
            <option value="request">request</option>
            <option value="response">response</option>
          </select>
          <select class="form-select" data-role="rw-target">
            <option value="header">header</option>
            <option value="body">body</option>
            <option value="query">query</option>
          </select>
          <input type="text" class="form-input" data-role="rw-pattern" placeholder="Match pattern (e.g. X-Test)" required>
          <input type="text" class="form-input" data-role="rw-replace" placeholder="Replace value">
          <label class="checkbox-label">
            <input type="checkbox" data-role="rw-regex">
            <span>Regex</span>
          </label>
          <label class="checkbox-label">
            <input type="checkbox" data-role="rw-sensitive">
            <span>Sensitive (HMAC Taint)</span>
          </label>
          <button type="submit" class="btn-primary btn-small">+ Add Rule</button>
        </form>
        <div class="rewrite-rules-list" data-role="rewrite-rules-list"></div>
      </div>

      <!-- Split Traffic Grid -->
      <div class="traffic-split-layout">
        <div class="traffic-list-pane">
          <div class="pane-title">Captured Exchanges (<span data-role="tr-count">0</span>)</div>
          <div class="traffic-list" data-role="tr-list"></div>
        </div>

        <div class="traffic-detail-pane" data-role="tr-detail">
          <div class="empty-state">
            <span class="empty-icon">📡</span>
            <h3 class="empty-title">Select an HTTP Exchange</h3>
            <p class="empty-text">Click any captured request in the list to inspect full headers &amp; body or execute a live RFC-9110 replay.</p>
          </div>
        </div>
      </div>
    </div>
  `;

  const searchInput = container.querySelector('[data-role="tr-search"]');
  const hostSelect = container.querySelector('[data-role="tr-host"]');
  const methodSelect = container.querySelector('[data-role="tr-method"]');
  const statusSelect = container.querySelector('[data-role="tr-status"]');
  const listEl = container.querySelector('[data-role="tr-list"]');
  const countEl = container.querySelector('[data-role="tr-count"]');
  const detailEl = container.querySelector('[data-role="tr-detail"]');
  const feedbackEl = container.querySelector('[data-role="tr-feedback"]');
  const rewritesPanel = container.querySelector('[data-role="rewrites-panel"]');
  const rewriteCountEl = container.querySelector('[data-role="rewrite-count"]');
  const rewriteListEl = container.querySelector('[data-role="rewrite-rules-list"]');
  const rewriteForm = container.querySelector('[data-role="rewrite-form"]');

  function showFeedback(msg, isError = false) {
    feedbackEl.className = `feedback-banner ${isError ? 'error' : 'success'}`;
    feedbackEl.textContent = msg;
    feedbackEl.classList.remove('hidden');
  }

  async function loadHosts() {
    try {
      const data = await fetchJson('/api/traffic/hosts');
      const hosts = Array.isArray(data.hosts) ? data.hosts : Array.isArray(data) ? data : [];
      const current = hostSelect.value;
      hostSelect.innerHTML =
        '<option value="">All Hosts</option>' +
        hosts
          .map(h => {
            const name = typeof h === 'string' ? h : h.host;
            const count = typeof h === 'object' && h.count ? ` (${h.count})` : '';
            return `<option value="${escapeHtml(name)}">${escapeHtml(name)}${escapeHtml(count)}</option>`;
          })
          .join('');
      if (current) hostSelect.value = current;
    } catch {
      /* host list optional on empty store */
    }
  }

  async function loadRewriteRules() {
    try {
      const data = await fetchJson('/api/traffic/rewrite-rules');
      rewriteRules = Array.isArray(data.rules) ? data.rules : Array.isArray(data) ? data : [];
      if (rewriteCountEl) rewriteCountEl.textContent = String(rewriteRules.length);

      if (rewriteRules.length === 0) {
        rewriteListEl.innerHTML = '<div class="empty-muted">No traffic rewrite rules configured.</div>';
        return;
      }

      rewriteListEl.innerHTML = rewriteRules
        .map(r => {
          const sensitive = Boolean(r.isSensitive || r.is_sensitive);
          return `
            <div class="rewrite-rule-row">
              <div class="rewrite-rule-info">
                <strong>${escapeHtml(r.name)}</strong>
                <span class="ev-pill">${escapeHtml(r.phase)} / ${escapeHtml(r.target)}</span>
                <code>${escapeHtml(r.scopeHost || r.scope_host || '*')}</code>
                <code>${escapeHtml(r.matchPattern || r.match_pattern)} → ${escapeHtml(r.replaceValue ?? r.replace_value ?? '')}</code>
                ${sensitive ? '<span class="taint-badge">🔒 HMAC Sensitive Taint</span>' : ''}
              </div>
              <button type="button" class="btn-secondary btn-small" data-del-rule="${escapeHtml(r.id)}">Delete</button>
            </div>
          `;
        })
        .join('');

      rewriteListEl.querySelectorAll('[data-del-rule]').forEach(btn => {
        btn.addEventListener('click', async () => {
          const id = btn.getAttribute('data-del-rule');
          try {
            await fetchJson(`/api/traffic/rewrite-rules/${encodeURIComponent(id)}`, { method: 'DELETE' });
            await loadRewriteRules();
          } catch (err) {
            showFeedback(`Failed to delete rule: ${err.message}`, true);
          }
        });
      });
    } catch (err) {
      rewriteListEl.innerHTML = `<div class="empty-muted">${escapeHtml(err.message)}</div>`;
    }
  }

  function renderExchangeList() {
    if (countEl) countEl.textContent = String(exchanges.length);
    if (exchanges.length === 0) {
      listEl.innerHTML = '<div class="empty-muted">No HTTP exchanges match the current filters.</div>';
      return;
    }

    listEl.innerHTML = exchanges
      .map(ex => {
        const active = selectedExchange?.id === ex.id;
        const sc = ex.statusCode ?? ex.status_code ?? ex.status ?? 0;
        const tainted = Boolean(ex.taintedSensitive || ex.tainted_sensitive);
        return `
          <button type="button" class="traffic-row ${active ? 'active' : ''}" data-ex-id="${escapeHtml(ex.id)}">
            <span class="http-method method-${escapeHtml(String(ex.method || 'GET').toLowerCase())}">${escapeHtml(ex.method || 'GET')}</span>
            <span class="http-status ${statusClass(sc)}">${sc || '—'}</span>
            <span class="traffic-url" title="${escapeHtml(ex.url)}">${escapeHtml(ex.host || '')}${escapeHtml(ex.path || ex.url || '')}</span>
            <span class="traffic-meta">
              ${tainted ? '<span class="taint-dot" title="HMAC Sensitive Tainted">🔒</span>' : ''}
              ${ex.source ? `<span class="traffic-source">${escapeHtml(ex.source)}</span>` : ''}
              ${ex.durationMs !== undefined ? `<span>${Math.round(Number(ex.durationMs))}ms</span>` : ''}
            </span>
          </button>
        `;
      })
      .join('');

    listEl.querySelectorAll('[data-ex-id]').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.getAttribute('data-ex-id');
        selectExchange(id);
      });
    });
  }

  function renderExchangeDetail(ex) {
    if (!ex) return;
    const sc = ex.statusCode ?? ex.status_code ?? ex.status ?? 0;
    const reqHeadersJson = JSON.stringify(ex.reqHeaders || {}, null, 2);

    detailEl.innerHTML = `
      <div class="traffic-inspector-card">
        <div class="traffic-detail-head">
          <div class="traffic-detail-title">
            <span class="http-method method-${escapeHtml(String(ex.method || 'GET').toLowerCase())}">${escapeHtml(ex.method)}</span>
            <span class="http-status ${statusClass(sc)}">${sc || '—'}</span>
            <code class="traffic-full-url">${escapeHtml(ex.url)}</code>
          </div>
          <div class="traffic-detail-badges">
            ${ex.taintedSensitive ? '<span class="taint-badge">🔒 HMAC Tainted</span>' : ''}
            ${ex.rewriteApplied ? '<span class="ev-pill">✏️ Rewrite Applied</span>' : ''}
            <button type="button" class="btn-primary btn-small" data-tr-action="toggle-replay">⚡ Replay Request</button>
          </div>
        </div>

        <!-- Replay Editor (Collapsible) -->
        <div class="replay-panel hidden" data-role="replay-panel">
          <div class="panel-sub-header">
            <h4>Live RFC-9110 Request Replay</h4>
            <button type="button" class="btn-secondary btn-small" data-tr-action="toggle-replay">Close</button>
          </div>
          <form class="replay-form" data-role="replay-form">
            <div class="replay-url-row">
              <select class="form-select" data-role="replay-method">
                ${['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']
                  .map(m => `<option value="${m}" ${m === ex.method ? 'selected' : ''}>${m}</option>`)
                  .join('')}
              </select>
              <input type="text" class="form-input" data-role="replay-url" value="${escapeHtml(ex.url)}">
              <button type="submit" class="btn-success" data-role="replay-send-btn">🚀 Send Replay</button>
            </div>
            <div class="replay-options-row">
              <label class="checkbox-label">
                <input type="checkbox" data-role="replay-allow-private">
                <span>Allow Private Target</span>
              </label>
            </div>
            <div class="replay-editors-grid">
              <div class="form-group">
                <label class="form-label">Request Headers (JSON)</label>
                <textarea class="form-textarea mono-textarea" rows="5" data-role="replay-headers">${escapeHtml(reqHeadersJson)}</textarea>
              </div>
              <div class="form-group">
                <label class="form-label">Request Body</label>
                <textarea class="form-textarea mono-textarea" rows="5" data-role="replay-body">${escapeHtml(ex.reqBody || '')}</textarea>
              </div>
            </div>
          </form>
          <div class="replay-result hidden" data-role="replay-result"></div>
        </div>

        <!-- Split Request / Response -->
        <div class="split-req-res">
          <div class="http-pane">
            <div class="http-pane-title">Request (${Number(ex.reqSize || 0)} B)</div>
            <pre class="code-block http-headers-pre"><code>${escapeHtml(formatHeadersText(ex.reqHeaders) || '(no headers)')}</code></pre>
            <pre class="code-block http-body-pre"><code>${escapeHtml(ex.reqBody || '(empty body)')}</code></pre>
          </div>
          <div class="http-pane">
            <div class="http-pane-title">Response (${Number(ex.resSize || 0)} B · ${Math.round(Number(ex.durationMs || 0))}ms)</div>
            <pre class="code-block http-headers-pre"><code>${escapeHtml(formatHeadersText(ex.resHeaders) || '(no headers)')}</code></pre>
            <pre class="code-block http-body-pre"><code>${escapeHtml((ex.resBody || '').slice(0, 12000) || '(empty body)')}</code></pre>
          </div>
        </div>
      </div>
    `;

    const replayPanel = detailEl.querySelector('[data-role="replay-panel"]');
    detailEl.querySelectorAll('[data-tr-action="toggle-replay"]').forEach(btn => {
      btn.addEventListener('click', () => replayPanel.classList.toggle('hidden'));
    });

    const replayForm = detailEl.querySelector('[data-role="replay-form"]');
    const replayResult = detailEl.querySelector('[data-role="replay-result"]');
    const sendBtn = detailEl.querySelector('[data-role="replay-send-btn"]');

    replayForm?.addEventListener('submit', async e => {
      e.preventDefault();
      const method = detailEl.querySelector('[data-role="replay-method"]').value;
      const url = detailEl.querySelector('[data-role="replay-url"]').value.trim();
      const headersRaw = detailEl.querySelector('[data-role="replay-headers"]').value.trim();
      const body = detailEl.querySelector('[data-role="replay-body"]').value;
      const allowPrivate = Boolean(detailEl.querySelector('[data-role="replay-allow-private"]')?.checked);

      let headers = {};
      if (headersRaw) {
        try {
          headers = JSON.parse(headersRaw);
        } catch (err) {
          showFeedback(`Invalid headers JSON: ${err.message}`, true);
          return;
        }
      }

      if (sendBtn) sendBtn.disabled = true;
      try {
        const res = await fetchJson(`/api/traffic/${encodeURIComponent(ex.id)}/replay`, {
          method: 'POST',
          body: JSON.stringify({ method, url, headers, body, allowPrivate }),
        });
        const resp = res.response || {};
        replayResult.innerHTML = `
          <div class="replay-result-head">
            <strong>Live Replay Response:</strong>
            <span class="http-status ${statusClass(resp.statusCode || resp.status)}">HTTP ${Number(resp.statusCode || resp.status || 0)}</span>
            ${res.replayExchange?.id ? `<code>${escapeHtml(res.replayExchange.id)}</code>` : ''}
          </div>
          <pre class="code-block http-headers-pre"><code>${escapeHtml(formatHeadersText(resp.headers))}</code></pre>
          <pre class="code-block http-body-pre"><code>${escapeHtml((resp.body || '').slice(0, 8000) || '(empty body)')}</code></pre>
        `;
        replayResult.classList.remove('hidden');
        await queryTraffic();
      } catch (err) {
        showFeedback(`Replay failed: ${err.message}`, true);
      } finally {
        if (sendBtn) sendBtn.disabled = false;
      }
    });
  }

  async function selectExchange(id) {
    try {
      const data = await fetchJson(`/api/traffic/${encodeURIComponent(id)}`);
      selectedExchange = data.exchange || data;
      renderExchangeList();
      renderExchangeDetail(selectedExchange);
    } catch (err) {
      showFeedback(`Could not load exchange ${id}: ${err.message}`, true);
    }
  }

  async function queryTraffic() {
    const params = new URLSearchParams();
    if (searchInput.value.trim()) params.set('search', searchInput.value.trim());
    if (hostSelect.value) params.set('host', hostSelect.value);
    if (methodSelect.value) params.set('method', methodSelect.value);
    if (statusSelect.value) params.set('status', statusSelect.value);
    if (options.taskId) params.set('taskId', options.taskId);
    params.set('limit', '100');

    try {
      const data = await fetchJson(`/api/traffic?${params.toString()}`);
      exchanges = Array.isArray(data.exchanges) ? data.exchanges : Array.isArray(data) ? data : [];
      renderExchangeList();
    } catch (err) {
      showFeedback(`Traffic query failed: ${err.message}`, true);
    }
  }

  container.querySelectorAll('[data-tr-action="toggle-rewrites"]').forEach(btn => {
    btn.addEventListener('click', () => {
      rewritesPanel.classList.toggle('hidden');
    });
  });

  container.querySelector('[data-tr-action="refresh"]').addEventListener('click', async () => {
    await Promise.all([loadHosts(), queryTraffic(), loadRewriteRules()]);
  });

  container.querySelector('[data-tr-action="query"]').addEventListener('click', queryTraffic);
  searchInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') queryTraffic();
  });
  hostSelect.addEventListener('change', queryTraffic);
  methodSelect.addEventListener('change', queryTraffic);
  statusSelect.addEventListener('change', queryTraffic);

  rewriteForm.addEventListener('submit', async e => {
    e.preventDefault();
    const payload = {
      name: container.querySelector('[data-role="rw-name"]').value.trim() || 'Rewrite Rule',
      scopeHost: container.querySelector('[data-role="rw-host"]').value.trim() || '*',
      phase: container.querySelector('[data-role="rw-phase"]').value,
      target: container.querySelector('[data-role="rw-target"]').value,
      matchPattern: container.querySelector('[data-role="rw-pattern"]').value,
      replaceValue: container.querySelector('[data-role="rw-replace"]').value,
      isRegex: container.querySelector('[data-role="rw-regex"]').checked,
      isSensitive: container.querySelector('[data-role="rw-sensitive"]').checked,
    };
    try {
      await fetchJson('/api/traffic/rewrite-rules', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      container.querySelector('[data-role="rw-pattern"]').value = '';
      container.querySelector('[data-role="rw-replace"]').value = '';
      await loadRewriteRules();
      showFeedback('Rewrite rule added.');
    } catch (err) {
      showFeedback(`Failed to add rewrite rule: ${err.message}`, true);
    }
  });

  await Promise.all([loadHosts(), queryTraffic(), loadRewriteRules()]);
}
