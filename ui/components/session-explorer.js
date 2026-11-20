/**
 * Tasks & Agent Sessions Explorer Component
 * Manages Agentic Verification Tasks, planner rounds, intent steering/cancellation,
 * gap-free activity timeline (mergeBySeq), and ephemeral /btw side questions.
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

/**
 * Deduplicates and merges activity log entries by sequence number (`seq`),
 * returning them sorted ascending so overlapping poll/SSE events never duplicate.
 */
export function mergeBySeq(current = [], incoming = []) {
  const bySeq = new Map();
  for (const item of Array.isArray(current) ? current : []) {
    if (item && item.seq !== undefined && item.seq !== null) {
      bySeq.set(Number(item.seq), item);
    }
  }
  for (const item of Array.isArray(incoming) ? incoming : []) {
    if (item && item.seq !== undefined && item.seq !== null) {
      bySeq.set(Number(item.seq), item);
    }
  }
  return Array.from(bySeq.values()).sort((a, b) => Number(a.seq) - Number(b.seq));
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
 * Renders the Tasks & Agent Sessions workspace into `container`.
 */
export async function renderSessionExplorer(container, options = {}) {
  if (!container) return;

  let tasks = [];
  let selectedTaskId = options.selectedTaskId || null;
  let taskDetail = null;
  let timeline = [];

  container.innerHTML = `
    <div class="sessions-shell">
      <div class="sessions-header">
        <div>
          <h2 class="section-title">Agentic Verification Tasks &amp; Sessions</h2>
          <p class="section-subtitle">Launch autonomous planner-worker tasks, steer active intents, inspect gap-free timelines, and ask read-only /btw questions</p>
        </div>
        <button type="button" class="btn-secondary" data-se-action="refresh">🔄 Refresh Tasks</button>
      </div>

      <!-- Create Task Card -->
      <form class="session-create-card" data-role="se-create-form">
        <div class="session-create-grid">
          <div class="form-group">
            <label class="form-label">Target URL <span class="required">*</span></label>
            <input type="text" class="form-input" data-role="se-target" placeholder="https://example.com" required>
          </div>
          <div class="form-group">
            <label class="form-label">Verification Goal</label>
            <input type="text" class="form-input" data-role="se-goal" placeholder="Verify auth boundaries, API exposure & headers">
          </div>
          <div class="form-group session-create-options">
            <label class="checkbox-label">
              <input type="checkbox" data-role="se-rotate" checked>
              <span>Multi-LLM Worker Rotation</span>
            </label>
            <label class="checkbox-label">
              <input type="checkbox" data-role="se-allow-private">
              <span>Allow Authorized Internal / Private Targets</span>
            </label>
            <button type="submit" class="btn-primary" data-role="se-create-btn">🤖 Create Agentic Task</button>
          </div>
        </div>
      </form>

      <div class="feedback-banner hidden" data-role="se-feedback"></div>

      <div class="sessions-split-layout">
        <!-- Tasks Sidebar -->
        <aside class="sessions-list-pane">
          <div class="pane-title">Tasks (<span data-role="se-tasks-count">0</span>)</div>
          <div class="sessions-list" data-role="se-tasks-list"></div>
        </aside>

        <!-- Task Detail Workspace -->
        <section class="sessions-detail-pane" data-role="se-detail-pane">
          <div class="empty-state">
            <span class="empty-icon">🤖</span>
            <h3 class="empty-title">Select or Create a Verification Task</h3>
            <p class="empty-text">Inspect exploration intents, trigger planner rounds, steer active workers, and ask /btw questions.</p>
          </div>
        </section>
      </div>
    </div>
  `;

  const feedbackEl = container.querySelector('[data-role="se-feedback"]');
  const tasksCountEl = container.querySelector('[data-role="se-tasks-count"]');
  const tasksListEl = container.querySelector('[data-role="se-tasks-list"]');
  const detailPane = container.querySelector('[data-role="se-detail-pane"]');
  const createForm = container.querySelector('[data-role="se-create-form"]');

  function showFeedback(msg, isError = false) {
    feedbackEl.className = `feedback-banner ${isError ? 'error' : 'success'}`;
    feedbackEl.textContent = msg;
    feedbackEl.classList.remove('hidden');
  }

  function renderTasksList() {
    if (tasksCountEl) tasksCountEl.textContent = String(tasks.length);
    if (tasks.length === 0) {
      tasksListEl.innerHTML = '<div class="empty-muted">No verification tasks created yet.</div>';
      return;
    }

    tasksListEl.innerHTML = tasks
      .map(t => {
        const isActive = t.id === selectedTaskId;
        const st = String(t.status || 'pending').toLowerCase();
        return `
          <button type="button" class="session-task-card ${isActive ? 'active' : ''}" data-task-id="${escapeHtml(t.id)}">
            <div class="session-task-top">
              <span class="session-status status-${escapeHtml(st)}">${escapeHtml(st.toUpperCase())}</span>
              ${t.llmRotate || t.llm_rotate ? '<span class="ev-pill">🔁 LLM Rotate</span>' : ''}
            </div>
            <div class="session-task-title">${escapeHtml(t.title || t.target || t.id)}</div>
            <div class="session-task-meta">${escapeHtml(t.goal || 'Standard security audit')}</div>
          </button>
        `;
      })
      .join('');

    tasksListEl.querySelectorAll('[data-task-id]').forEach(btn => {
      btn.addEventListener('click', () => {
        const tid = btn.getAttribute('data-task-id');
        timeline = [];
        selectTask(tid);
      });
    });
  }

  function renderTaskDetail() {
    if (!taskDetail?.task) {
      return;
    }

    const t = taskDetail.task;
    const graph = taskDetail.graph || { nodes: [], edges: [] };
    const coverage = taskDetail.coverage || {};
    const nodes = Array.isArray(graph.nodes) ? graph.nodes : [];
    const intents = nodes.filter(n => String(n.nodeType || n.node_type || n.type).toLowerCase() === 'intent');
    const findings = nodes.filter(n => String(n.nodeType || n.node_type || n.type).toLowerCase() === 'finding');
    const llmRotate = Boolean(t.llmRotate ?? t.llm_rotate);

    detailPane.innerHTML = `
      <div class="session-workspace">
        <div class="session-ws-header">
          <div>
            <h3>${escapeHtml(t.title || t.target || t.id)}</h3>
            <div class="session-ws-sub">
              <span>Target: <code>${escapeHtml(t.target || '—')}</code></span>
              <span>·</span>
              <span>Status: <strong>${escapeHtml(t.status || 'pending')}</strong></span>
              <span>·</span>
              <span>Findings: <strong>${findings.length}</strong></span>
            </div>
            ${t.goal ? `<p class="session-goal-text">Goal: ${escapeHtml(t.goal)}</p>` : ''}
          </div>
          <div class="session-ws-actions">
            <label class="checkbox-label">
              <input type="checkbox" data-role="ws-rotate-toggle" ${llmRotate ? 'checked' : ''}>
              <span>Worker Rotation</span>
            </label>
            <button type="button" class="btn-primary btn-small" data-se-action="plan">🧠 Trigger Planner Round</button>
            <button type="button" class="btn-secondary btn-small" data-se-action="poll">🔄 Sync</button>
            ${typeof options.onOpenGraph === 'function' ? '<button type="button" class="btn-secondary btn-small" data-se-action="open-graph">🕸️ View DAG</button>' : ''}
          </div>
        </div>

        <!-- Coverage Ledger Bar -->
        ${
          coverage.summary || coverage.coveragePct !== undefined
            ? `<div class="session-coverage-bar">
                 <span>Coverage Ledger: <strong>${Number(coverage.coveragePct ?? coverage.summary?.coveragePct ?? 0)}%</strong></span>
                 <span>Gaps: <strong>${Number(coverage.gaps?.length ?? coverage.summary?.gapCount ?? 0)}</strong></span>
                 <span>Graph Nodes: <strong>${nodes.length}</strong></span>
               </div>`
            : ''
        }

        <!-- Active Intents Control -->
        <div class="session-section">
          <h4>Verification Intents (${intents.length})</h4>
          <div class="intents-list" data-role="ws-intents">
            ${
              intents.length === 0
                ? '<div class="empty-muted">No intents dispatched yet. Click "Trigger Planner Round" to decompose and dispatch intents.</div>'
                : intents
                    .map(intent => {
                      const st = String(intent.status || 'pending').toLowerCase();
                      const title = intent.title || intent.summary || intent.data?.summary || intent.id;
                      const isTerminal = st === 'completed' || st === 'cancelled' || st === 'failed';
                      return `
                        <div class="intent-row" data-intent-id="${escapeHtml(intent.id)}">
                          <div class="intent-info">
                            <span class="session-status status-${escapeHtml(st)}">${escapeHtml(st)}</span>
                            <strong class="intent-title">${escapeHtml(title)}</strong>
                            ${intent.claimOwner ? `<code class="intent-owner">${escapeHtml(intent.claimOwner)}</code>` : ''}
                          </div>
                          ${
                            !isTerminal
                              ? `<div class="intent-controls">
                                   <input type="text" class="form-input form-input-compact" data-steer-input="${escapeHtml(intent.id)}" placeholder="Steer instruction...">
                                   <button type="button" class="btn-secondary btn-small" data-steer-btn="${escapeHtml(intent.id)}">Steer</button>
                                   <button type="button" class="btn-danger-soft btn-small" data-cancel-btn="${escapeHtml(intent.id)}">Cancel</button>
                                 </div>`
                              : ''
                          }
                        </div>
                      `;
                    })
                    .join('')
            }
          </div>
        </div>

        <!-- Ephemeral /btw Side Question -->
        <div class="session-section">
          <h4>Ephemeral <code>/btw</code> Side Question (Read-Only)</h4>
          <form class="btw-form" data-role="btw-form">
            <input type="text" class="form-input" data-role="btw-input" placeholder="/btw what endpoints or headers have been verified so far?">
            <button type="submit" class="btn-secondary" data-role="btw-submit">Ask /btw</button>
          </form>
          <div class="btw-answer hidden" data-role="btw-answer"></div>
        </div>

        <!-- Gap-Free Activity Timeline -->
        <div class="session-section">
          <h4>Gap-Free Activity Timeline (${timeline.length} events)</h4>
          <div class="activity-timeline" data-role="ws-timeline">
            ${
              timeline.length === 0
                ? '<div class="empty-muted">No activity events recorded yet.</div>'
                : timeline
                    .slice()
                    .reverse()
                    .map(ev => {
                      const timeStr = ev.createdAt ? new Date(ev.createdAt).toLocaleTimeString() : '';
                      return `
                        <div class="timeline-row">
                          <span class="timeline-seq">#${Number(ev.seq)}</span>
                          <span class="timeline-actor">${escapeHtml(ev.actor || 'system')}</span>
                          <span class="timeline-type">${escapeHtml(ev.eventType || ev.event_type || 'event')}</span>
                          <span class="timeline-summary">${escapeHtml(ev.summary || '')}</span>
                          <span class="timeline-time">${escapeHtml(timeStr)}</span>
                        </div>
                      `;
                    })
                    .join('')
            }
          </div>
        </div>
      </div>
    `;

    // Wire Workspace Events
    detailPane.querySelector('[data-se-action="plan"]')?.addEventListener('click', async () => {
      const btn = detailPane.querySelector('[data-se-action="plan"]');
      if (btn) btn.disabled = true;
      try {
        await fetchJson(`/api/tasks/${encodeURIComponent(t.id)}/plan`, {
          method: 'POST',
          body: JSON.stringify({ force: true }),
        });
        showFeedback('Planner round triggered.');
        await selectTask(t.id, true);
      } catch (err) {
        showFeedback(`Planner failed: ${err.message}`, true);
      } finally {
        if (btn) btn.disabled = false;
      }
    });

    detailPane.querySelector('[data-se-action="poll"]')?.addEventListener('click', () => {
      selectTask(t.id, true);
    });

    detailPane.querySelector('[data-se-action="open-graph"]')?.addEventListener('click', () => {
      if (typeof options.onOpenGraph === 'function') {
        options.onOpenGraph(t.id);
      }
    });

    detailPane.querySelector('[data-role="ws-rotate-toggle"]')?.addEventListener('change', async ev => {
      try {
        await fetchJson(`/api/tasks/${encodeURIComponent(t.id)}/llm`, {
          method: 'PUT',
          body: JSON.stringify({ llm_rotate: ev.target.checked, llmRotate: ev.target.checked }),
        });
        showFeedback(`Multi-LLM rotation ${ev.target.checked ? 'enabled' : 'disabled'}.`);
      } catch (err) {
        showFeedback(`Could not update rotation setting: ${err.message}`, true);
      }
    });

    detailPane.querySelectorAll('[data-steer-btn]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const nodeId = btn.getAttribute('data-steer-btn');
        const inputEl = detailPane.querySelector(`[data-steer-input="${CSS.escape(nodeId)}"]`);
        const instruction = inputEl?.value.trim();
        if (!instruction) return;
        try {
          await fetchJson(
            `/api/tasks/${encodeURIComponent(t.id)}/intents/${encodeURIComponent(nodeId)}/steer`,
            { method: 'POST', body: JSON.stringify({ instruction }) }
          );
          showFeedback(`Steered intent ${nodeId}.`);
          await selectTask(t.id, true);
        } catch (err) {
          showFeedback(`Steer failed: ${err.message}`, true);
        }
      });
    });

    detailPane.querySelectorAll('[data-cancel-btn]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const nodeId = btn.getAttribute('data-cancel-btn');
        try {
          await fetchJson(
            `/api/tasks/${encodeURIComponent(t.id)}/intents/${encodeURIComponent(nodeId)}/cancel`,
            { method: 'POST', body: JSON.stringify({}) }
          );
          showFeedback(`Cancelled intent ${nodeId}.`);
          await selectTask(t.id, true);
        } catch (err) {
          showFeedback(`Cancel failed: ${err.message}`, true);
        }
      });
    });

    const btwForm = detailPane.querySelector('[data-role="btw-form"]');
    const btwInput = detailPane.querySelector('[data-role="btw-input"]');
    const btwAnswer = detailPane.querySelector('[data-role="btw-answer"]');
    btwForm?.addEventListener('submit', async e => {
      e.preventDefault();
      const question = btwInput.value.trim();
      if (!question) return;
      btwAnswer.textContent = 'Thinking (ephemeral read-only)...';
      btwAnswer.classList.remove('hidden');
      try {
        const res = await fetchJson(`/api/tasks/${encodeURIComponent(t.id)}/sidequestion`, {
          method: 'POST',
          body: JSON.stringify({ question }),
        });
        const ans = res.answer || res.text || res.response || JSON.stringify(res);
        btwAnswer.innerHTML = `
          <div class="btw-badge">Read-only /btw response (graph untouched)</div>
          <div class="btw-text">${escapeHtml(ans)}</div>
        `;
      } catch (err) {
        btwAnswer.textContent = `Error: ${err.message}`;
      }
    });
  }

  async function selectTask(taskId, incremental = false) {
    selectedTaskId = taskId;
    renderTasksList();

    const lastSeq = incremental && timeline.length > 0 ? timeline[timeline.length - 1].seq : 0;
    try {
      const data = await fetchJson(
        `/api/tasks/${encodeURIComponent(taskId)}?sinceSeq=${Number(lastSeq) || 0}`
      );
      taskDetail = data;
      timeline = mergeBySeq(incremental ? timeline : [], data.activity || []);
      renderTaskDetail();
    } catch (err) {
      showFeedback(`Failed to load task ${taskId}: ${err.message}`, true);
    }
  }

  async function loadTasks() {
    try {
      const data = await fetchJson('/api/tasks');
      tasks = Array.isArray(data.tasks) ? data.tasks : Array.isArray(data) ? data : [];
      renderTasksList();
      if (!selectedTaskId && tasks.length > 0) {
        await selectTask(tasks[0].id);
      } else if (selectedTaskId) {
        await selectTask(selectedTaskId, true);
      }
    } catch (err) {
      showFeedback(`Could not load tasks: ${err.message}`, true);
    }
  }

  createForm.addEventListener('submit', async e => {
    e.preventDefault();
    const target = container.querySelector('[data-role="se-target"]').value.trim();
    const goal = container.querySelector('[data-role="se-goal"]').value.trim();
    const llmRotate = container.querySelector('[data-role="se-rotate"]').checked;
    const allowPrivate = Boolean(container.querySelector('[data-role="se-allow-private"]')?.checked);
    if (!target) return;

    const btn = container.querySelector('[data-role="se-create-btn"]');
    if (btn) btn.disabled = true;
    try {
      const res = await fetchJson('/api/tasks', {
        method: 'POST',
        body: JSON.stringify({
          target,
          goal: goal || `Verify security posture of ${target}`,
          mode: 'agent',
          llm_rotate: llmRotate,
          llmRotate,
          allowPrivate,
        }),
      });
      const created = res.task || res;
      showFeedback(`Created task ${created.id}`);
      timeline = [];
      await loadTasks();
      if (created?.id) {
        await selectTask(created.id);
      }
    } catch (err) {
      showFeedback(`Task creation failed: ${err.message}`, true);
    } finally {
      if (btn) btn.disabled = false;
    }
  });

  container.querySelector('[data-se-action="refresh"]').addEventListener('click', loadTasks);

  await loadTasks();
}
