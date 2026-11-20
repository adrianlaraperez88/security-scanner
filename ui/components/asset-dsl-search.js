/**
 * Asset DSL Search & Scan Output Ingestion Component
 * Real-time autocomplete for all 19 ARTEX DSL fields + ingestion modal for nmap/nuclei/httpx/ffuf/bbot.
 */

export const DSL_FIELDS = Object.freeze([
  {
    name: 'domain',
    desc: 'Domain or hostname of the asset',
    kind: 'string',
    ops: ['=', '==', '!='],
  },
  {
    name: 'host',
    desc: 'Hostname or IP literal of the asset',
    kind: 'string',
    ops: ['=', '==', '!='],
  },
  {
    name: 'ip',
    desc: 'IPv4 or IPv6 address',
    kind: 'string',
    ops: ['==', '!=', '='],
  },
  {
    name: 'port',
    desc: 'Network port number (1-65535)',
    kind: 'number',
    ops: ['=', '==', '!=', '>', '>=', '<', '<='],
  },
  {
    name: 'service',
    desc: 'Service name or fingerprint (http, https, ssh, nginx)',
    kind: 'string',
    ops: ['=', '==', '!='],
  },
  {
    name: 'protocol',
    desc: 'Transport or application protocol (tcp, http, https)',
    kind: 'string',
    ops: ['=', '==', '!='],
  },
  {
    name: 'url',
    desc: 'Full normalized URL of service or endpoint',
    kind: 'string',
    ops: ['=', '==', '!='],
  },
  {
    name: 'path',
    desc: 'URL path component',
    kind: 'string',
    ops: ['=', '==', '!='],
  },
  {
    name: 'title',
    desc: 'HTTP page title or banner',
    kind: 'string',
    ops: ['=', '==', '!='],
  },
  {
    name: 'status',
    desc: 'HTTP response status code',
    kind: 'number',
    ops: ['=', '==', '!=', '>', '>=', '<', '<='],
  },
  {
    name: 'source',
    desc: 'Discovery source (scanner, crawl, dns, nmap, nuclei, httpx, ffuf, bbot)',
    kind: 'string',
    ops: ['=', '==', '!='],
  },
  {
    name: 'company',
    desc: 'Company ID or company name',
    kind: 'string',
    ops: ['=', '==', '!='],
  },
  {
    name: 'c_segment',
    desc: 'Network C-segment (/24 for IPv4, /48 for IPv6)',
    kind: 'string',
    ops: ['=', '==', '!='],
  },
  {
    name: 'type',
    desc: 'Asset type (root_domain, ip, subdomain, app, service, endpoint)',
    kind: 'enum',
    ops: ['=', '==', '!='],
    values: ['root_domain', 'ip', 'subdomain', 'app', 'service', 'endpoint'],
  },
  {
    name: 'scope',
    desc: 'Scope status (in, out, true, false)',
    kind: 'enum',
    ops: ['=', '==', '!='],
    values: ['in', 'out', 'true', 'false'],
  },
  {
    name: 'confidence',
    desc: 'Asset confidence score or level',
    kind: 'number',
    ops: ['=', '==', '!=', '>=', '<='],
  },
  {
    name: 'verified',
    desc: 'Whether asset is verified (true/false)',
    kind: 'boolean',
    ops: ['=', '==', '!='],
    values: ['true', 'false'],
  },
  {
    name: 'severity',
    desc: 'Severity of anchored findings (CRITICAL, HIGH, MEDIUM, LOW, INFO)',
    kind: 'enum',
    ops: ['=', '==', '!=', '>=', '<='],
    values: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
  },
  {
    name: 'finding',
    desc: 'Title, summary, or existence of anchored findings',
    kind: 'string',
    ops: ['=', '==', '!='],
  },
]);

const LOGIC_OPS = [
  { label: 'AND', desc: 'Both conditions must match' },
  { label: 'OR', desc: 'Either condition matches' },
];

const QUICK_CHIPS = [
  { label: 'domain=', insert: 'domain=' },
  { label: 'type=endpoint', insert: 'type=endpoint' },
  { label: 'status=200', insert: 'status=200' },
  { label: 'verified=true', insert: 'verified=true' },
  { label: 'AND', insert: 'AND ' },
  { label: 'OR', insert: 'OR ' },
];

const OP_DESCRIPTIONS = {
  '=': 'fuzzy / match',
  '==': 'exact match',
  '!=': 'exclude',
  '>': 'greater than',
  '>=': 'greater or equal',
  '<': 'less than',
  '<=': 'less or equal',
};

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Generates contextual DSL autocomplete suggestions for `inputText` at `cursor`.
 */
export function getDslSuggestions(inputText = '', cursor = String(inputText || '').length) {
  const text = String(inputText || '');
  const pos = Math.max(0, Math.min(Number(cursor) || 0, text.length));
  const before = text.slice(0, pos);

  const tokenMatch = before.match(/([^\s()]*)$/);
  const currentToken = tokenMatch?.[1] ?? '';
  const tokenStart = pos - currentToken.length;

  // Field + operator + optional partial value -> suggest known enum/boolean values if available
  const opMatch = currentToken.match(/^([a-z_]+)(==|!=|>=|<=|=|>|<)(.*)$/i);
  if (opMatch) {
    const fieldName = opMatch[1].toLowerCase();
    const op = opMatch[2];
    const partialVal = opMatch[3].toLowerCase();
    const fieldSpec = DSL_FIELDS.find(f => f.name === fieldName);
    if (fieldSpec && Array.isArray(fieldSpec.values)) {
      return fieldSpec.values
        .filter(v => v.toLowerCase().startsWith(partialVal))
        .map(v => ({
          kind: 'value',
          label: `${fieldName}${op}${v}`,
          desc: `${fieldSpec.name} value`,
          replaceStart: tokenStart,
          replaceEnd: pos,
          insertText: `${fieldName}${op}${v} `,
        }));
    }
    return [];
  }

  // Exact known field name -> suggest operators
  const exactField = DSL_FIELDS.find(f => f.name === currentToken.toLowerCase());
  if (exactField) {
    return exactField.ops.map(op => ({
      kind: 'operator',
      label: `${exactField.name}${op}`,
      desc: OP_DESCRIPTIONS[op] || 'operator',
      replaceStart: tokenStart,
      replaceEnd: pos,
      insertText: `${exactField.name}${op}`,
    }));
  }

  const beforeToken = before.slice(0, tokenStart).trimEnd();
  const afterExpression =
    beforeToken.length > 0 && !/\b(AND|OR)\s*$/i.test(beforeToken) && !beforeToken.endsWith('(');

  if (/^(a|an|and|o|or)$/i.test(currentToken) && afterExpression) {
    return LOGIC_OPS.filter(l => l.label.startsWith(currentToken.toUpperCase())).map(l => ({
      kind: 'logic',
      label: l.label,
      desc: l.desc,
      replaceStart: tokenStart,
      replaceEnd: pos,
      insertText: `${l.label} `,
    }));
  }

  if (!currentToken && afterExpression) {
    return LOGIC_OPS.map(l => ({
      kind: 'logic',
      label: l.label,
      desc: l.desc,
      replaceStart: pos,
      replaceEnd: pos,
      insertText: `${l.label} `,
    }));
  }

  const prefix = currentToken.toLowerCase();
  return DSL_FIELDS.filter(f => f.name.startsWith(prefix)).map(f => ({
    kind: 'field',
    label: f.name,
    desc: f.desc,
    replaceStart: tokenStart,
    replaceEnd: pos,
    insertText: f.name,
  }));
}

/**
 * Mounts the Asset DSL Search bar, quick chips, autocomplete popover, and
 * external scan ingestion modal (`POST /api/assets/ingest`).
 */
export function mountAssetDslSearch(container, onQuery, options = {}) {
  if (!container) return null;

  container.innerHTML = `
    <div class="dsl-search-shell">
      <div class="dsl-input-row">
        <div class="dsl-input-wrap">
          <input
            type="text"
            class="form-input dsl-input"
            data-role="dsl-input"
            placeholder="Filter assets with DSL: e.g. domain=example.com AND type=endpoint AND status=200"
            spellcheck="false"
            autocomplete="off"
          >
          <div class="dsl-autocomplete hidden" data-role="dsl-dropdown"></div>
        </div>
        <button type="button" class="btn-primary" data-role="dsl-submit">🔍 Query Assets</button>
        <button type="button" class="btn-secondary" data-role="dsl-clear">Clear</button>
        <button type="button" class="btn-secondary" data-role="dsl-open-ingest">📥 Ingest Scan Output</button>
      </div>

      <div class="dsl-chips-row">
        <span class="dsl-chips-label">Quick DSL:</span>
        <div class="dsl-chips-list" data-role="dsl-chips">
          ${QUICK_CHIPS.map(
            c => `<button type="button" class="dsl-chip" data-insert="${escapeHtml(c.insert)}">${escapeHtml(c.label)}</button>`
          ).join('')}
        </div>
        <span class="dsl-status-text" data-role="dsl-status">Ready (${DSL_FIELDS.length} DSL fields)</span>
      </div>

      <!-- Ingestion Modal -->
      <div class="modal-backdrop hidden" data-role="ingest-modal">
        <div class="modal-card" role="dialog" aria-modal="true" aria-label="Ingest External Scan Output">
          <div class="modal-header">
            <h3>📥 Ingest External Scan Output</h3>
            <button type="button" class="btn-secondary btn-small" data-role="ingest-close">✕</button>
          </div>
          <div class="modal-body">
            <div class="form-group">
              <label class="form-label">Tool Format</label>
              <select class="form-select" data-role="ingest-format">
                <option value="httpx">httpx (JSONL)</option>
                <option value="nuclei">nuclei (JSONL)</option>
                <option value="nmap">nmap (XML / Greppable / Text)</option>
                <option value="ffuf">ffuf (JSON)</option>
                <option value="bbot">bbot (JSONL)</option>
              </select>
            </div>
            <div class="form-group">
              <label class="form-label">Optional Task ID</label>
              <input type="text" class="form-input" data-role="ingest-task-id" placeholder="Leave empty for global asset graph">
            </div>
            <div class="form-group">
              <label class="form-label">Raw Tool Output</label>
              <textarea class="form-textarea dsl-ingest-textarea" rows="8" data-role="ingest-raw" placeholder="Paste JSONL, JSON, or nmap output here..."></textarea>
            </div>
            <div class="feedback-banner hidden" data-role="ingest-feedback"></div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn-secondary" data-role="ingest-cancel">Cancel</button>
            <button type="button" class="btn-primary" data-role="ingest-submit">Ingest Into Asset Graph</button>
          </div>
        </div>
      </div>
    </div>
  `;

  const input = container.querySelector('[data-role="dsl-input"]');
  const dropdown = container.querySelector('[data-role="dsl-dropdown"]');
  const statusEl = container.querySelector('[data-role="dsl-status"]');
  const btnSubmit = container.querySelector('[data-role="dsl-submit"]');
  const btnClear = container.querySelector('[data-role="dsl-clear"]');
  const btnOpenIngest = container.querySelector('[data-role="dsl-open-ingest"]');
  const ingestModal = container.querySelector('[data-role="ingest-modal"]');
  const ingestClose = container.querySelector('[data-role="ingest-close"]');
  const ingestCancel = container.querySelector('[data-role="ingest-cancel"]');
  const ingestSubmit = container.querySelector('[data-role="ingest-submit"]');
  const ingestFormat = container.querySelector('[data-role="ingest-format"]');
  const ingestTaskId = container.querySelector('[data-role="ingest-task-id"]');
  const ingestRaw = container.querySelector('[data-role="ingest-raw"]');
  const ingestFeedback = container.querySelector('[data-role="ingest-feedback"]');

  function setStatus(text, isError = false) {
    if (!statusEl) return;
    statusEl.textContent = text;
    statusEl.classList.toggle('is-error', Boolean(isError));
  }

  function renderSuggestions() {
    const pos = input.selectionStart ?? input.value.length;
    const suggestions = getDslSuggestions(input.value, pos).slice(0, 10);
    if (suggestions.length === 0) {
      dropdown.classList.add('hidden');
      dropdown.innerHTML = '';
      return;
    }

    dropdown.innerHTML = suggestions
      .map(
        (s, idx) => `
        <button type="button" class="dsl-suggestion-item" data-sugg-idx="${idx}">
          <span class="dsl-sugg-kind kind-${escapeHtml(s.kind)}">${escapeHtml(s.kind)}</span>
          <code class="dsl-sugg-label">${escapeHtml(s.label)}</code>
          <span class="dsl-sugg-desc">${escapeHtml(s.desc)}</span>
        </button>
      `
      )
      .join('');
    dropdown.classList.remove('hidden');

    dropdown.querySelectorAll('.dsl-suggestion-item').forEach(btn => {
      btn.addEventListener('mousedown', ev => {
        ev.preventDefault();
        const idx = Number(btn.getAttribute('data-sugg-idx'));
        const s = suggestions[idx];
        if (!s) return;
        const val = input.value;
        const updated = val.slice(0, s.replaceStart) + s.insertText + val.slice(s.replaceEnd);
        const newCursor = s.replaceStart + s.insertText.length;
        input.value = updated;
        input.focus();
        input.setSelectionRange(newCursor, newCursor);
        renderSuggestions();
      });
    });
  }

  function triggerQuery() {
    dropdown.classList.add('hidden');
    if (typeof onQuery === 'function') {
      onQuery(input.value.trim());
    }
  }

  input.addEventListener('input', renderSuggestions);
  input.addEventListener('focus', renderSuggestions);
  input.addEventListener('blur', () => {
    setTimeout(() => dropdown.classList.add('hidden'), 120);
  });
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter') {
      e.preventDefault();
      triggerQuery();
    } else if (e.key === 'Escape') {
      dropdown.classList.add('hidden');
    }
  });

  btnSubmit.addEventListener('click', triggerQuery);
  btnClear.addEventListener('click', () => {
    input.value = '';
    dropdown.classList.add('hidden');
    triggerQuery();
  });

  container.querySelectorAll('.dsl-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const snippet = chip.getAttribute('data-insert') || '';
      const cur = input.value;
      const sep = cur && !cur.endsWith(' ') && !cur.endsWith('(') ? ' ' : '';
      input.value = cur + sep + snippet;
      input.focus();
      renderSuggestions();
    });
  });

  function closeModal() {
    ingestModal.classList.add('hidden');
  }

  btnOpenIngest.addEventListener('click', () => {
    if (options.defaultTaskId && !ingestTaskId.value) {
      ingestTaskId.value = options.defaultTaskId;
    }
    ingestFeedback.classList.add('hidden');
    ingestModal.classList.remove('hidden');
  });

  ingestClose.addEventListener('click', closeModal);
  ingestCancel.addEventListener('click', closeModal);

  ingestSubmit.addEventListener('click', async () => {
    const format = ingestFormat.value;
    const rawInput = ingestRaw.value.trim();
    const taskId = ingestTaskId.value.trim() || undefined;

    if (!rawInput) {
      ingestFeedback.className = 'feedback-banner error';
      ingestFeedback.textContent = 'Please paste raw tool output to ingest.';
      ingestFeedback.classList.remove('hidden');
      return;
    }

    ingestSubmit.disabled = true;
    try {
      const res = await fetch('/api/assets/ingest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ format, rawInput, taskId }),
      });
      const data = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);

      const count = data.ingestedCount ?? data.assets?.length ?? 0;
      ingestFeedback.className = 'feedback-banner success';
      ingestFeedback.textContent = `Ingested ${count} assets from ${format} output.`;
      ingestFeedback.classList.remove('hidden');
      ingestRaw.value = '';
      if (typeof options.onIngested === 'function') {
        options.onIngested(data);
      } else {
        triggerQuery();
      }
    } catch (err) {
      ingestFeedback.className = 'feedback-banner error';
      ingestFeedback.textContent = `Ingestion failed: ${err.message}`;
      ingestFeedback.classList.remove('hidden');
    } finally {
      ingestSubmit.disabled = false;
    }
  });

  return {
    setStatus,
    getQuery: () => input.value.trim(),
    setQuery: q => {
      input.value = String(q || '');
    },
  };
}
