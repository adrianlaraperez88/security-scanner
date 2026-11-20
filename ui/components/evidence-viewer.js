/**
 * Evidence Viewer & 1-Click Retest Component
 * S1 Receipt Verification, PoE Level 1-4, reportStale indicator, bound HTTP snapshots
 * with verbatim quote highlighting (>= 8 chars), and Retest history.
 */

const MIN_QUOTE_LEN = 8;

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
 * Safely escapes `text` and highlights exact (or whitespace-collapsed) occurrences
 * of `quote` when `quote.length >= 8`.
 */
export function highlightVerbatimQuote(text, quote) {
  const raw = String(text || '');
  const q = String(quote || '').trim();
  if (!raw || q.length < MIN_QUOTE_LEN) {
    return escapeHtml(raw);
  }

  const lowerRaw = raw.toLowerCase();
  const lowerQ = q.toLowerCase();
  const idx = lowerRaw.indexOf(lowerQ);
  if (idx === -1) {
    return escapeHtml(raw);
  }

  const parts = [];
  let cursor = 0;
  let matchIdx = idx;
  while (matchIdx !== -1) {
    if (matchIdx > cursor) {
      parts.push(escapeHtml(raw.slice(cursor, matchIdx)));
    }
    const matched = raw.slice(matchIdx, matchIdx + q.length);
    parts.push(`<mark class="evidence-quote-highlight">${escapeHtml(matched)}</mark>`);
    cursor = matchIdx + q.length;
    matchIdx = lowerRaw.indexOf(lowerQ, cursor);
  }
  if (cursor < raw.length) {
    parts.push(escapeHtml(raw.slice(cursor)));
  }
  return parts.join('');
}

function getFindingId(finding) {
  if (!finding) return '';
  if (finding.id) return String(finding.id);
  const check = finding.checkId || finding.name || 'finding';
  const target = finding.target || finding.pages?.[0] || '';
  return target ? `${check}::${target}` : String(check);
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

/**
 * Builds escaped HTML for an AI / Playbook Fix Solution response from `POST /api/ai/remediate`.
 */
export function buildAiFixHtml(solution) {
  if (!solution || typeof solution !== 'object') return '';
  const isAi = solution.mode === 'ai';
  const modeLabel = isAi
    ? `🤖 AI Powered${solution.provider || solution.model ? ` (${[solution.provider, solution.model].filter(Boolean).join(' / ')})` : ''}`
    : '📘 Built-in Playbook';
  const audienceLabel = solution.audience === 'beginner' ? 'Owner / Beginner' : 'Developer / Pro';
  const steps = Array.isArray(solution.solutionSteps) ? solution.solutionSteps : [];

  return `
    <div class="ai-fix-card">
      <div class="ai-fix-header">
        <div class="ai-fix-badges">
          <span class="ev-pill ${isAi ? 'ai-mode-badge' : 'playbook-mode-badge'}">${escapeHtml(modeLabel)}</span>
          <span class="ev-pill">${escapeHtml(audienceLabel)}</span>
          ${solution.stack ? `<span class="ev-pill">Stack: ${escapeHtml(solution.stack)}</span>` : ''}
        </div>
        ${solution.fallbackReason ? `<span class="form-hint">Fallback: ${escapeHtml(solution.fallbackReason)}</span>` : ''}
      </div>

      ${solution.plainExplanation ? `<div class="ai-fix-section"><strong>Explanation:</strong> <p>${escapeHtml(solution.plainExplanation)}</p></div>` : ''}
      ${solution.rootCause ? `<div class="ai-fix-section"><strong>Root Cause:</strong> <p>${escapeHtml(solution.rootCause)}</p></div>` : ''}

      ${steps.length > 0 ? `
        <div class="ai-fix-section">
          <strong>Solution Steps:</strong>
          <ol class="ai-fix-steps">
            ${steps.map(s => `<li>${escapeHtml(s)}</li>`).join('')}
          </ol>
        </div>
      ` : ''}

      ${solution.patchSnippet ? `
        <div class="ai-fix-section">
          <div class="ai-fix-code-head">
            <strong>Suggested Patch${solution.patchLanguage ? ` (${escapeHtml(solution.patchLanguage)})` : ''}</strong>
            <button type="button" class="btn-secondary btn-small" data-ai-copy="patch">📋 Copy Patch</button>
          </div>
          <pre class="code-block ai-fix-code"><code>${escapeHtml(solution.patchSnippet)}</code></pre>
        </div>
      ` : ''}

      ${solution.verifyCommand || solution.verifyExpected ? `
        <div class="ai-fix-section ai-fix-verify">
          ${solution.verifyCommand ? `<div><strong>Verify Command:</strong> <code>${escapeHtml(solution.verifyCommand)}</code></div>` : ''}
          ${solution.verifyExpected ? `<div><strong>Expected Result:</strong> ${escapeHtml(solution.verifyExpected)}</div>` : ''}
        </div>
      ` : ''}

      ${solution.developerPrompt ? `
        <details class="ai-fix-prompt-details">
          <summary>💬 Developer Handoff Prompt</summary>
          <div class="ai-fix-code-head">
            <span class="form-hint">Copy and paste this prompt to an engineer or coding assistant</span>
            <button type="button" class="btn-secondary btn-small" data-ai-copy="prompt">📋 Copy Prompt</button>
          </div>
          <pre class="code-block ai-fix-code"><code>${escapeHtml(solution.developerPrompt)}</code></pre>
        </details>
      ` : ''}
    </div>
  `;
}

/**
 * Renders an AI / Playbook Fix Solution into `slotEl` and wires CSP-safe copy listeners.
 */
export function renderAiFixIntoSlot(slotEl, solution, onCopyFallback = null) {
  if (!slotEl) return;
  slotEl.innerHTML = buildAiFixHtml(solution);
  slotEl.classList.remove('hidden');

  const wireCopy = (selector, text, defaultLabel) => {
    const btn = slotEl.querySelector(selector);
    if (!btn || !text) return;
    btn.addEventListener('click', async () => {
      try {
        await navigator.clipboard?.writeText(text);
        btn.textContent = '✓ Copied';
        setTimeout(() => {
          btn.textContent = defaultLabel;
        }, 1800);
      } catch {
        if (typeof onCopyFallback === 'function') {
          onCopyFallback(`Copy manually:\n${text}`);
        }
      }
    });
  };

  wireCopy('[data-ai-copy="patch"]', solution?.patchSnippet, '📋 Copy Patch');
  wireCopy('[data-ai-copy="prompt"]', solution?.developerPrompt, '📋 Copy Prompt');
}

/**
 * Renders the S1 Evidence Receipt Viewer & 1-Click Retest Drawer into `container`.
 */
export async function renderEvidenceViewer(container, finding, options = {}) {
  if (!container) return;

  const findingId = getFindingId(finding);
  const title = finding?.meta?.title || finding?.title || finding?.name || findingId;
  const repro = finding?.reproduction && typeof finding.reproduction === 'object' ? finding.reproduction : null;
  const reproSectionHtml = repro ? `
      <div class="evidence-section finding-repro-box">
        <div class="finding-repro-header">
          <h4 class="evidence-section-title" style="margin:0">🔁 How to Reproduce &amp; Verify Fix</h4>
          ${repro.curl ? '<button type="button" class="btn-secondary btn-small" data-ev-action="copy-repro">📋 Copy Curl</button>' : ''}
        </div>
        ${repro.observedSignal ? `<div class="finding-repro-signal"><span>Observed Signal:</span> <code>${escapeHtml(repro.observedSignal)}</code></div>` : ''}
        ${Array.isArray(repro.steps) && repro.steps.length ? `<ol class="finding-repro-steps">${repro.steps.map(s => `<li>${escapeHtml(s)}</li>`).join('')}</ol>` : ''}
        ${repro.curl ? `<pre class="finding-repro-cmd"><code>${escapeHtml(repro.curl)}</code></pre>` : ''}
      </div>` : '';

  container.innerHTML = `
    <div class="evidence-viewer-shell">
      <div class="evidence-header">
        <div>
          <div class="evidence-eyebrow">S1 Evidence Receipts &amp; Retest</div>
          <h3 class="evidence-title">${escapeHtml(title)}</h3>
          <code class="evidence-finding-id">${escapeHtml(findingId)}</code>
        </div>
        <div class="evidence-header-actions">
          <button type="button" class="btn-secondary btn-small" data-ev-action="refresh">🔄 Refresh</button>
          ${typeof options.onClose === 'function' ? '<button type="button" class="btn-secondary btn-small" data-ev-action="close">✕ Close</button>' : ''}
        </div>
      </div>

      <div class="evidence-status-bar" data-role="ev-status-bar">
        <span class="ev-pill">Loading evidence...</span>
      </div>

      <div class="feedback-banner hidden" data-role="ev-feedback"></div>

      <div class="evidence-actions-bar">
        <div class="ev-verify-controls">
          <label class="form-label-inline">
            PoE Level:
            <select class="form-select form-select-compact" data-role="ev-poe-select">
              <option value="1">L1 — Heuristic</option>
              <option value="2">L2 — Circumstantial</option>
              <option value="3" selected>L3 — Confirmed Proof</option>
              <option value="4">L4 — Re-verified</option>
            </select>
          </label>
          <button type="button" class="btn-primary btn-small" data-ev-action="verify">✓ Run S1 Quote Verification</button>
        </div>
        <div class="ev-retest-controls">
          <button type="button" class="btn-secondary btn-small" data-ev-action="ai-fix">🤖 AI Fix Solution</button>
          <label class="checkbox-label">
            <input type="checkbox" data-role="ev-allow-private">
            <span>Allow Private Target</span>
          </label>
          <button type="button" class="btn-success btn-small" data-ev-action="retest">🔁 1-Click Retest</button>
        </div>
      </div>

      <div class="ai-fix-slot hidden" data-role="ev-ai-fix-panel"></div>

      ${reproSectionHtml}
      <div class="evidence-section">
        <h4 class="evidence-section-title">Bound HTTP Snapshots (<span data-role="ev-bindings-count">0</span>)</h4>
        <div class="evidence-snapshots-list" data-role="ev-snapshots"></div>
      </div>

      <div class="evidence-section">
        <h4 class="evidence-section-title">Retest History (<span data-role="ev-retests-count">0</span>)</h4>
        <div class="evidence-retests-list" data-role="ev-retests"></div>
      </div>

      <details class="evidence-bind-details">
        <summary>➕ Bind Traffic Exchange or HTTP Snapshot</summary>
        <form class="evidence-bind-form" data-role="ev-bind-form">
          <div class="evidence-bind-grid">
            <div class="form-group">
              <label class="form-label">Snapshot Role</label>
              <select class="form-select" data-role="bind-role">
                <option value="proof">proof</option>
                <option value="verification">verification</option>
                <option value="baseline">baseline</option>
                <option value="supporting">supporting</option>
              </select>
            </div>
            <div class="form-group">
              <label class="form-label">Traffic Exchange ID <span class="form-hint">(Optional if supplying HTTP details)</span></label>
              <input type="text" class="form-input" data-role="bind-exchange-id" placeholder="ex_...">
            </div>
            <div class="form-group">
              <label class="form-label">URL <span class="form-hint">(for new snapshot)</span></label>
              <input type="text" class="form-input" data-role="bind-url" value="${escapeHtml(finding?.target || '')}" placeholder="https://example.com/...">
            </div>
            <div class="form-group">
              <label class="form-label">Method &amp; Status Code</label>
              <div class="inline-pair">
                <select class="form-select" data-role="bind-method">
                  <option value="GET">GET</option>
                  <option value="POST">POST</option>
                  <option value="HEAD">HEAD</option>
                  <option value="PUT">PUT</option>
                </select>
                <input type="number" class="form-input" data-role="bind-status" value="200" min="100" max="599">
              </div>
            </div>
            <div class="form-group full-width">
              <label class="form-label">Verbatim Evidence Quote <span class="form-hint">(&ge; 8 chars matching snapshot body)</span></label>
              <input type="text" class="form-input" data-role="bind-quote" placeholder="Exact substring from response body...">
            </div>
            <div class="form-group full-width">
              <label class="form-label">Response Body Snippet <span class="form-hint">(when creating a new snapshot)</span></label>
              <textarea class="form-textarea" rows="3" data-role="bind-body" placeholder="HTTP response body containing the verbatim quote..."></textarea>
            </div>
            <div class="form-group full-width">
              <label class="form-label">Note</label>
              <input type="text" class="form-input" data-role="bind-note" placeholder="Optional receipt note">
            </div>
          </div>
          <button type="submit" class="btn-primary btn-small">Bind Evidence Receipt</button>
        </form>
      </details>
    </div>
  `;

  const statusBar = container.querySelector('[data-role="ev-status-bar"]');
  const feedbackEl = container.querySelector('[data-role="ev-feedback"]');
  const snapshotsEl = container.querySelector('[data-role="ev-snapshots"]');
  const retestsEl = container.querySelector('[data-role="ev-retests"]');
  const bindingsCountEl = container.querySelector('[data-role="ev-bindings-count"]');
  const retestsCountEl = container.querySelector('[data-role="ev-retests-count"]');
  const poeSelect = container.querySelector('[data-role="ev-poe-select"]');
  const aiFixPanel = container.querySelector('[data-role="ev-ai-fix-panel"]');
  const bindForm = container.querySelector('[data-role="ev-bind-form"]');

  let currentEvidence = null;

  function showFeedback(msg, isError = false) {
    feedbackEl.className = `feedback-banner ${isError ? 'error' : 'success'}`;
    feedbackEl.textContent = msg;
    feedbackEl.classList.remove('hidden');
  }

  function renderData(data) {
    currentEvidence = data || {};
    const st = data?.state || {};
    const vStatus = String(st.verificationStatus || st.verification_status || 'unverified').toLowerCase();
    const poeLevel = Number(st.poeLevel ?? st.poe_level ?? finding?.poeLevel ?? 0);
    const evVer = Number(st.evidenceVersion ?? st.evidence_version ?? 0);
    const repVer = Number(st.reportEvidenceVersion ?? st.report_evidence_version ?? 0);
    const reportStale = Boolean(data?.reportStale ?? st.reportStale ?? evVer > repVer);

    if (poeLevel >= 1 && poeLevel <= 4 && poeSelect) {
      poeSelect.value = String(poeLevel);
    }

    statusBar.innerHTML = `
      <span class="ev-pill ev-status-${escapeHtml(vStatus)}">Receipt: ${escapeHtml(vStatus.toUpperCase())}</span>
      <span class="ev-pill ev-poe">PoE Level ${poeLevel || '—'}</span>
      <span class="ev-pill">Evidence v${evVer} / Report v${repVer}</span>
      ${reportStale ? '<span class="ev-pill ev-stale">⚠️ Report Stale</span>' : ''}
      ${st.verificationNote ? `<span class="ev-note">${escapeHtml(st.verificationNote)}</span>` : ''}
    `;

    const bindings = Array.isArray(data?.bindings) ? data.bindings : [];
    const snapshots = Array.isArray(data?.snapshots) ? data.snapshots : [];
    const retests = Array.isArray(data?.retests) ? data.retests : [];

    if (bindingsCountEl) bindingsCountEl.textContent = String(bindings.length);
    if (retestsCountEl) retestsCountEl.textContent = String(retests.length);

    if (bindings.length === 0) {
      snapshotsEl.innerHTML = '<div class="empty-muted">No bound HTTP snapshots yet. Use the form below to bind a traffic exchange or snapshot.</div>';
    } else {
      snapshotsEl.innerHTML = bindings
        .map(b => {
          const snap = b.snapshot || snapshots.find(s => s.id === b.snapshotId) || {};
          const bodyText = snap.resBody || snap.res_body || snap.responseBody || '';
          const role = String(b.role || 'proof').toLowerCase();
          const quote = b.quote || '';
          const quoteValid = quote.trim().length >= MIN_QUOTE_LEN;
          return `
            <div class="ev-snapshot-card">
              <div class="ev-snapshot-head">
                <span class="ev-role-badge role-${escapeHtml(role)}">${escapeHtml(role.toUpperCase())}</span>
                <span class="ev-method">${escapeHtml(snap.method || 'GET')}</span>
                <code class="ev-url">${escapeHtml(snap.url || '—')}</code>
                <span class="ev-code">${snap.statusCode ? `HTTP ${Number(snap.statusCode)}` : ''}</span>
              </div>
              ${
                quote
                  ? `<div class="ev-quote-box">
                       <span class="ev-quote-label">Verbatim Quote (${quote.trim().length} chars ${quoteValid ? '✓' : '< 8 chars'}):</span>
                       <code>${escapeHtml(quote)}</code>
                     </div>`
                  : ''
              }
              ${
                bodyText
                  ? `<pre class="code-block ev-body-preview"><code>${highlightVerbatimQuote(bodyText.slice(0, 4000), quote)}</code></pre>`
                  : '<div class="empty-muted">No response body captured.</div>'
              }
              ${b.note ? `<div class="ev-binding-note">Note: ${escapeHtml(b.note)}</div>` : ''}
            </div>
          `;
        })
        .join('');
    }

    if (retests.length === 0) {
      retestsEl.innerHTML = '<div class="empty-muted">No retests executed yet. Click "1-Click Retest" to replay the proof snapshot.</div>';
    } else {
      retestsEl.innerHTML = retests
        .slice()
        .reverse()
        .map(rt => {
          const verdict = String(rt.verdict || 'inconclusive').toLowerCase();
          const quotes = Array.isArray(rt.matchedQuotes) ? rt.matchedQuotes : [];
          return `
            <div class="ev-retest-row">
              <span class="ev-verdict-badge verdict-${escapeHtml(verdict)}">${escapeHtml(verdict.toUpperCase())}</span>
              <span>HTTP ${rt.statusCode ? Number(rt.statusCode) : '—'}</span>
              <span>${quotes.length} matched quote${quotes.length === 1 ? '' : 's'}</span>
              ${rt.notes ? `<span class="ev-retest-note">${escapeHtml(rt.notes)}</span>` : ''}
              <span class="ev-retest-time">${rt.createdAt ? escapeHtml(new Date(rt.createdAt).toLocaleString()) : ''}</span>
            </div>
          `;
        })
        .join('');
    }
  }

  async function loadEvidence() {
    if (options.initialEvidence) {
      renderData(options.initialEvidence);
      options.initialEvidence = null;
      return;
    }
    try {
      const data = await fetchJson(`/api/findings/${encodeURIComponent(findingId)}/evidence`);
      renderData(data);
    } catch (err) {
      statusBar.innerHTML = `<span class="ev-pill ev-status-rejected">Unavailable</span>`;
      showFeedback(`Could not load evidence: ${err.message}`, true);
    }
  }

  container.querySelector('[data-ev-action="close"]')?.addEventListener('click', () => {
    if (typeof options.onClose === 'function') options.onClose();
  });

  container.querySelector('[data-ev-action="refresh"]')?.addEventListener('click', loadEvidence);

  container.querySelector('[data-ev-action="copy-repro"]')?.addEventListener('click', async () => {
    const cmd = repro?.curl;
    if (!cmd) return;
    try {
      await navigator.clipboard?.writeText(cmd);
      showFeedback('Reproduction curl command copied to clipboard.');
    } catch {
      showFeedback(`Copy manually: ${cmd}`);
    }
  });

  container.querySelector('[data-ev-action="verify"]')?.addEventListener('click', async () => {
    const poeLevel = Number(poeSelect?.value || 3);
    const quotes = (currentEvidence?.bindings || []).map(b => b.quote).filter(Boolean);
    try {
      const res = await fetchJson(`/api/findings/${encodeURIComponent(findingId)}/verify`, {
        method: 'POST',
        body: JSON.stringify({ poeLevel, evidenceQuotes: quotes }),
      });
      await loadEvidence();
      const status = res?.assessment?.status || res?.state?.verificationStatus || 'completed';
      showFeedback(`S1 verification completed: ${status}`);
      if (typeof options.onUpdated === 'function') options.onUpdated(res);
    } catch (err) {
      showFeedback(`Verification failed: ${err.message}`, true);
    }
  });

  container.querySelector('[data-ev-action="ai-fix"]')?.addEventListener('click', async () => {
    const btn = container.querySelector('[data-ev-action="ai-fix"]');
    if (!aiFixPanel) return;
    if (btn) {
      btn.disabled = true;
      btn.textContent = '🤖 Generating Fix...';
    }
    aiFixPanel.classList.remove('hidden');
    aiFixPanel.innerHTML = '<div class="empty-muted">Generating stack-aware fix solution...</div>';
    try {
      const solution = await fetchJson('/api/ai/remediate', {
        method: 'POST',
        body: JSON.stringify({
          finding,
          stack: options.stack || null,
          audience: options.audience || 'pro'
        })
      });
      renderAiFixIntoSlot(aiFixPanel, solution, msg => showFeedback(msg));
    } catch (err) {
      aiFixPanel.innerHTML = `<div class="feedback-banner error">Failed to generate AI fix solution: ${escapeHtml(err.message)}</div>`;
      showFeedback(`AI fix failed: ${err.message}`, true);
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = '🤖 AI Fix Solution';
      }
    }
  });

  container.querySelector('[data-ev-action="retest"]')?.addEventListener('click', async () => {
    const btn = container.querySelector('[data-ev-action="retest"]');
    const allowPrivate = Boolean(container.querySelector('[data-role="ev-allow-private"]')?.checked);
    if (btn) btn.disabled = true;
    try {
      const res = await fetchJson(`/api/findings/${encodeURIComponent(findingId)}/retest`, {
        method: 'POST',
        body: JSON.stringify({ allowPrivate }),
      });
      await loadEvidence();
      showFeedback(`Retest completed: ${res.verdict || res.retest?.verdict || 'done'}`);
      if (typeof options.onUpdated === 'function') options.onUpdated(res);
    } catch (err) {
      showFeedback(`Retest failed: ${err.message}`, true);
    } finally {
      if (btn) btn.disabled = false;
    }
  });

  bindForm?.addEventListener('submit', async e => {
    e.preventDefault();
    const role = container.querySelector('[data-role="bind-role"]').value;
    const exchangeId = container.querySelector('[data-role="bind-exchange-id"]').value.trim();
    const url = container.querySelector('[data-role="bind-url"]').value.trim();
    const method = container.querySelector('[data-role="bind-method"]').value;
    const statusCode = Number(container.querySelector('[data-role="bind-status"]').value) || 200;
    const quote = container.querySelector('[data-role="bind-quote"]').value.trim();
    const resBody = container.querySelector('[data-role="bind-body"]').value;
    const note = container.querySelector('[data-role="bind-note"]').value.trim();

    if (!exchangeId && !url) {
      showFeedback('Provide either a Traffic Exchange ID or a Target URL.', true);
      return;
    }

    try {
      const payload = exchangeId
        ? { exchangeId, role, quote, note }
        : {
            role,
            quote,
            note,
            snapshot: { method, url, statusCode, resBody, responseBody: resBody },
          };
      await fetchJson(`/api/findings/${encodeURIComponent(findingId)}/evidence`, {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      showFeedback('Evidence snapshot bound successfully.');
      await loadEvidence();
    } catch (err) {
      showFeedback(`Failed to bind evidence: ${err.message}`, true);
    }
  });

  await loadEvidence();
}
