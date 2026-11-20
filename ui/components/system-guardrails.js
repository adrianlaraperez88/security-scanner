/**
 * System Guardrails & Multi-LLM Pool Component
 * Configures Multi-Provider LLM Profiles + Circuit Breakers + Token Ledger,
 * Target Noise Governor + Per-Host Telemetry, Scope/Deny Rules & JEV Risk Evaluator.
 */

const JEV_QUESTIONS = [
  { id: 'q1_in_scope', label: 'Q1: Target is explicitly within authorized scope' },
  { id: 'q2_no_destructive_side_effects', label: 'Q2: No destructive side effects' },
  { id: 'q3_reversible', label: 'Q3: Action is reversible / read-safe' },
  { id: 'q4_within_rate_budget', label: 'Q4: Within target noise & rate budget' },
  { id: 'q5_no_credential_exfil', label: 'Q5: No credential or secret exfiltration' },
  { id: 'q6_no_cross_tenant_impact', label: 'Q6: No cross-tenant impact' },
  { id: 'q7_valid_verification_intent', label: 'Q7: Valid defensive verification intent' },
  { id: 'q8_least_privilege', label: 'Q8: Follows least-privilege probing' },
];

const KNOWN_RULE_TYPES = new Set([
  'exact_domain',
  'domain',
  'fuzzy_domain',
  'wildcard_domain',
  'suffix_domain',
  'exact_ip',
  'ip',
  'fuzzy_ip',
  'cidr',
  'exact_url',
  'fuzzy_url'
]);

/**
 * Infers the most specific `core/guard.js` ruleType for a scope/deny pattern string.
 * @param {string} pattern
 * @returns {string}
 */
export function inferRuleType(pattern) {
  const clean = String(pattern || '').trim();
  if (!clean) return 'exact_domain';
  if (/^https?:\/\//i.test(clean)) {
    return clean.includes('*') ? 'fuzzy_url' : 'exact_url';
  }
  if (/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(clean) || /^[0-9a-f:]+:[0-9a-f:]*\/\d{1,3}$/i.test(clean)) {
    return 'cidr';
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(clean) || (clean.includes(':') && /^[0-9a-f:\[\]]+$/i.test(clean))) {
    return 'exact_ip';
  }
  if (/^[\d.*]+$/.test(clean) && clean.includes('*')) {
    return 'fuzzy_ip';
  }
  if (clean.includes('*') || clean.startsWith('.')) {
    return 'fuzzy_domain';
  }
  return 'exact_domain';
}

/**
 * Serializes `core/guard.js` scope rules into line-delimited text while preserving
 * `isAllowed` and `ruleType`.
 * @param {Array<object|string>} scopeRules
 * @returns {string}
 */
export function serializeScopeRules(scopeRules = []) {
  if (!Array.isArray(scopeRules) || scopeRules.length === 0) return '';
  return scopeRules
    .map(r => {
      if (typeof r === 'string') return r;
      if (!r || typeof r !== 'object') return '';
      const isAllowed =
        typeof r.isAllowed === 'boolean'
          ? r.isAllowed
          : typeof r.is_allowed === 'boolean'
            ? r.is_allowed
            : !['deny', 'block'].includes(String(r.action || r.effect || '').toLowerCase());
      const prefix = isAllowed ? 'allow' : 'deny';
      const ruleType = String(r.ruleType || r.rule_type || r.kind || r.type || '').trim().toLowerCase();
      const pattern = String(r.pattern || r.value || '').trim();
      if (!pattern) return '';
      return ruleType ? `${prefix}:${ruleType}:${pattern}` : `${prefix}:${pattern}`;
    })
    .filter(Boolean)
    .join('\n');
}

/**
 * Parses line-delimited scope rule text (`allow|deny[:ruleType]:pattern`) into
 * normalized `core/guard.js` rule objects preserving `isAllowed` and `ruleType`.
 * @param {string} text
 * @returns {Array<{ action: 'allow'|'deny', isAllowed: boolean, ruleType: string, pattern: string, enabled: boolean }>}
 */
export function parseScopeRulesText(text) {
  const lines = String(text || '')
    .split(/\r?\n/)
    .map(s => s.trim())
    .filter(line => line.length > 0 && !line.startsWith('#'));

  return lines
    .map(line => {
      const firstColon = line.indexOf(':');
      if (firstColon === -1) {
        return {
          action: 'allow',
          isAllowed: true,
          ruleType: inferRuleType(line),
          pattern: line,
          enabled: true
        };
      }

      const head = line.slice(0, firstColon).trim().toLowerCase();
      const hasActionPrefix = head === 'allow' || head === 'deny' || head === 'block';
      const isAllowed = hasActionPrefix ? head === 'allow' : true;
      const rest = hasActionPrefix ? line.slice(firstColon + 1).trim() : line;

      const secondColon = rest.indexOf(':');
      let ruleType = '';
      let pattern = rest;

      if (secondColon !== -1) {
        const maybeType = rest.slice(0, secondColon).trim().toLowerCase();
        if (KNOWN_RULE_TYPES.has(maybeType)) {
          ruleType = maybeType;
          pattern = rest.slice(secondColon + 1).trim();
        }
      }

      if (!pattern) return null;
      if (!ruleType) {
        ruleType = inferRuleType(pattern);
      }

      return {
        action: isAllowed ? 'allow' : 'deny',
        isAllowed,
        ruleType,
        pattern,
        enabled: true
      };
    })
    .filter(Boolean);
}

const PROVIDER_MODEL_HINTS = {
  anthropic: {
    defaultModel: 'claude-sonnet-4-20250514',
    placeholder: 'Model (e.g. claude-sonnet-4-20250514)'
  },
  openai: {
    defaultModel: 'gpt-4o-mini',
    placeholder: 'Model (e.g. gpt-4o-mini, gpt-4o)'
  },
  'openai-responses': {
    defaultModel: 'gpt-4.1-mini',
    placeholder: 'Model (e.g. gpt-4.1-mini, o4-mini)'
  },
  gemini: {
    defaultModel: 'gemini-2.5-flash',
    placeholder: 'Model (e.g. gemini-2.5-flash)'
  },
  ollama: {
    defaultModel: 'llama3.1',
    placeholder: 'Model (e.g. llama3.1, qwen2.5)'
  }
};

/**
 * Returns model placeholder and default hint for a given LLM provider.
 * @param {string} provider
 * @returns {{ defaultModel: string, placeholder: string }}
 */
export function getProviderModelHint(provider) {
  const key = String(provider || '').trim().toLowerCase();
  return PROVIDER_MODEL_HINTS[key] || {
    defaultModel: 'gpt-4o-mini',
    placeholder: 'Model (e.g. gemini-2.5-flash, gpt-4o-mini)'
  };
}

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

/**
 * Renders the System Guardrails & Multi-LLM Pool panel into `container`.
 */
export async function renderSystemGuardrails(container, options = {}) {
  if (!container) return;

  container.innerHTML = `
    <div class="guardrails-shell">
      <div class="guardrails-header">
        <div>
          <h3 class="section-title">System Guardrails, Noise Governor &amp; Multi-LLM Pool</h3>
          <p class="section-subtitle">Configure multi-provider LLM failover profiles, circuit breakers, target noise pacing, and scope/JEV risk gates</p>
        </div>
        <button type="button" class="btn-secondary btn-small" data-sg-action="refresh">🔄 Refresh All</button>
      </div>

      <div class="feedback-banner hidden" data-role="sg-feedback"></div>

      <div class="guardrails-grid">
        <!-- 1. Multi-Provider LLM Pool -->
        <section class="guard-card">
          <div class="guard-card-header">
            <h4>🧠 Multi-Provider LLM Pool &amp; Breakers</h4>
            <span class="ev-pill" data-role="llm-usage-pill">0 calls · 0 tokens</span>
          </div>

          <div class="llm-profiles-list" data-role="llm-profiles-list"></div>

          <div class="llm-usage-summary" data-role="llm-usage-box"></div>

          <form class="guard-sub-form" data-role="llm-profile-form">
            <h5>Add / Update LLM Profile</h5>
            <div class="guard-form-grid">
              <input type="text" class="form-input" data-role="llm-id" placeholder="Profile ID (e.g. openai-primary)" required>
              <input type="text" class="form-input" data-role="llm-name" placeholder="Display Name (e.g. Primary Planner)">
              <select class="form-select" data-role="llm-provider">
                <option value="anthropic">anthropic</option>
                <option value="openai">openai (OpenAI-compatible)</option>
                <option value="openai-responses">openai-responses</option>
                <option value="gemini">Google Gemini (generateContent)</option>
                <option value="ollama">ollama (Local)</option>
              </select>
              <input type="text" class="form-input" data-role="llm-model" placeholder="Model (e.g. claude-sonnet-4-20250514)" required>
              <input type="text" class="form-input" data-role="llm-baseurl" placeholder="Base URL (optional override)">
              <input type="password" class="form-input" data-role="llm-apikey" placeholder="API Key (stored masked)">
            </div>
            <div class="form-hint" data-role="llm-model-hint">Default model for anthropic: claude-sonnet-4-20250514</div>
            <div class="guard-form-footer">
              <label class="checkbox-label">
                <input type="checkbox" data-role="llm-enabled" checked>
                <span>Enabled</span>
              </label>
              <button type="submit" class="btn-primary btn-small">Save LLM Profile</button>
            </div>
          </form>
        </section>

        <!-- 2. Target Noise Governor -->
        <section class="guard-card">
          <div class="guard-card-header">
            <h4>🎛️ Target Noise Governor &amp; Telemetry</h4>
            <span class="ev-pill" data-role="noise-profile-badge">balanced</span>
          </div>

          <div class="noise-controls-row">
            <label class="form-label-inline">
              Governor Profile:
              <select class="form-select form-select-compact" data-role="noise-profile-select">
                <option value="off">off (No throttling)</option>
                <option value="quiet">quiet (Stealth / low QPS)</option>
                <option value="balanced">balanced (Recommended)</option>
                <option value="aggressive">aggressive (High concurrency)</option>
              </select>
            </label>
            <button type="button" class="btn-primary btn-small" data-sg-action="save-noise">Apply Profile</button>
          </div>

          <div class="noise-totals-grid" data-role="noise-totals"></div>
          <div class="noise-hosts-table-wrap" data-role="noise-hosts"></div>
        </section>

        <!-- 3. Scope / Deny Rules & JEV Risk Evaluator -->
        <section class="guard-card guard-card-wide">
          <div class="guard-card-header">
            <h4>🛡️ Scope / Deny Rules &amp; JEV Closed-World Evaluator</h4>
            <span class="ev-pill">Fail-Closed Gate</span>
          </div>

          <div class="scope-evaluator-split">
            <form class="guard-sub-form" data-role="scope-form">
              <h5>Scope &amp; Deny Rules (1 rule per line: <code>allow|deny[:ruleType]:pattern</code>)</h5>
              <textarea class="form-textarea mono-textarea" rows="5" data-role="scope-rules-text" placeholder="allow:exact_domain:example.com&#10;deny:fuzzy_domain:*.gov&#10;deny:cidr:10.0.0.0/8"></textarea>
              <div class="guard-form-footer">
                <span class="form-hint">Built-in .gov/.edu &amp; private IP blocks remain active.</span>
                <button type="submit" class="btn-primary btn-small">Save Scope Rules</button>
              </div>
            </form>

            <form class="guard-sub-form" data-role="eval-form">
              <h5>Test Target Gate, Risk Score &amp; JEV 8-Question Judge</h5>
              <div class="guard-form-grid">
                <input type="text" class="form-input" data-role="eval-target" placeholder="Target URL or domain (e.g. https://api.example.com/v1)">
                <input type="text" class="form-input" data-role="eval-tool" placeholder="Tool / Method (e.g. GET, http_probe, replay)" value="GET">
              </div>
              <div class="jev-checks-grid">
                ${JEV_QUESTIONS.map(
                  q => `
                  <label class="checkbox-label jev-check-item">
                    <input type="checkbox" data-jev-id="${escapeHtml(q.id)}" checked>
                    <span>${escapeHtml(q.label)}</span>
                  </label>
                `
                ).join('')}
              </div>
              <div class="guard-form-footer">
                <button type="submit" class="btn-secondary btn-small">⚖️ Evaluate Gate &amp; Risk</button>
              </div>
              <div class="eval-result-box hidden" data-role="eval-result"></div>
            </form>
          </div>
        </section>
      </div>
    </div>
  `;

  const feedbackEl = container.querySelector('[data-role="sg-feedback"]');
  const profilesListEl = container.querySelector('[data-role="llm-profiles-list"]');
  const usagePillEl = container.querySelector('[data-role="llm-usage-pill"]');
  const usageBoxEl = container.querySelector('[data-role="llm-usage-box"]');
  const noiseBadgeEl = container.querySelector('[data-role="noise-profile-badge"]');
  const noiseSelectEl = container.querySelector('[data-role="noise-profile-select"]');
  const noiseTotalsEl = container.querySelector('[data-role="noise-totals"]');
  const noiseHostsEl = container.querySelector('[data-role="noise-hosts"]');
  const scopeTextEl = container.querySelector('[data-role="scope-rules-text"]');
  const evalResultEl = container.querySelector('[data-role="eval-result"]');

  function showFeedback(msg, isError = false) {
    feedbackEl.className = `feedback-banner ${isError ? 'error' : 'success'}`;
    feedbackEl.textContent = msg;
    feedbackEl.classList.remove('hidden');
  }

  function renderLlmPool(data) {
    const profiles = Array.isArray(data?.profiles) ? data.profiles : [];
    const breakers = data?.breakers || {};
    const usage = data?.usage || {};

    if (usagePillEl) {
      usagePillEl.textContent = `${Number(usage.totalCalls || 0)} calls · ${Number(usage.totalTokens || 0)} tokens`;
    }

    if (usageBoxEl) {
      usageBoxEl.innerHTML = `
        <div class="usage-ledger-row">
          <span>Input Tokens: <strong>${Number(usage.inputTokens || 0)}</strong></span>
          <span>Output Tokens: <strong>${Number(usage.outputTokens || 0)}</strong></span>
          <span>Est. Cost: <strong>$${Number(usage.totalCostUsd || 0).toFixed(4)}</strong></span>
        </div>
      `;
    }

    if (profiles.length === 0) {
      profilesListEl.innerHTML = '<div class="empty-muted">No LLM profiles configured. Add one below to enable agentic planner/worker rotation.</div>';
      return;
    }

    profilesListEl.innerHTML = profiles
      .map(p => {
        const br = breakers[p.id] || {};
        const state = br.state || (br.tripped ? 'tripped' : 'healthy');
        const hasKey = Boolean(p.hasApiKey);
        const isAutoDiscovered = Boolean(p.autoDiscovered || p.source === 'env' || p.discoveredFromEnv);
        return `
          <div class="llm-profile-row">
            <div class="llm-profile-info">
              <div class="llm-profile-top">
                <strong>${escapeHtml(p.name || p.id)}</strong>
                <code>${escapeHtml(p.provider)}/${escapeHtml(p.model)}</code>
                <span class="breaker-badge breaker-${escapeHtml(state)}">${escapeHtml(state.toUpperCase())}</span>
                <span class="ev-pill ${hasKey ? 'ev-status-verified' : ''}">${hasKey ? 'Key Configured' : 'No Key'}</span>
                ${isAutoDiscovered ? '<span class="ev-pill">Auto-discovered</span>' : ''}
              </div>
              <div class="llm-profile-meta">
                <span>ID: <code>${escapeHtml(p.id)}</code></span>
                ${br.consecutiveFailures ? `<span>Failures: ${Number(br.consecutiveFailures)}</span>` : ''}
              </div>
            </div>
            <div class="llm-profile-actions">
              <button type="button" class="btn-secondary btn-small" data-edit-profile="${escapeHtml(p.id)}">Edit</button>
              <button type="button" class="btn-secondary btn-small" data-reset-breaker="${escapeHtml(p.id)}">Reset Breaker</button>
              <button type="button" class="btn-danger-soft btn-small" data-del-profile="${escapeHtml(p.id)}">Delete</button>
            </div>
          </div>
        `;
      })
      .join('');

    profilesListEl.querySelectorAll('[data-edit-profile]').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.getAttribute('data-edit-profile');
        const profile = profiles.find(p => p.id === id);
        if (!profile) return;
        const idInput = container.querySelector('[data-role="llm-id"]');
        const nameInput = container.querySelector('[data-role="llm-name"]');
        const baseUrlInput = container.querySelector('[data-role="llm-baseurl"]');
        const apiKeyInput = container.querySelector('[data-role="llm-apikey"]');
        const enabledInput = container.querySelector('[data-role="llm-enabled"]');
        if (idInput) idInput.value = profile.id || '';
        if (nameInput) nameInput.value = profile.name || '';
        if (providerSelectEl && profile.provider) providerSelectEl.value = profile.provider;
        if (modelInputEl) modelInputEl.value = profile.model || '';
        if (baseUrlInput) baseUrlInput.value = profile.baseUrl || '';
        if (apiKeyInput) {
          apiKeyInput.value = '';
          apiKeyInput.placeholder = profile.hasApiKey
            ? 'Leave blank to keep existing key'
            : 'API Key (stored masked)';
        }
        if (enabledInput) enabledInput.checked = profile.enabled !== false;
        syncProviderModelHint();
      });
    });

    profilesListEl.querySelectorAll('[data-reset-breaker]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-reset-breaker');
        try {
          await fetchJson(`/api/llm/profiles/${encodeURIComponent(id)}/reset`, { method: 'POST', body: '{}' });
          showFeedback(`Breaker reset for ${id}.`);
          await loadAll();
        } catch (err) {
          showFeedback(`Reset failed: ${err.message}`, true);
        }
      });
    });

    profilesListEl.querySelectorAll('[data-del-profile]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-del-profile');
        try {
          await fetchJson(`/api/llm/profiles/${encodeURIComponent(id)}`, { method: 'DELETE' });
          showFeedback(`Removed profile ${id}.`);
          await loadAll();
        } catch (err) {
          showFeedback(`Delete failed: ${err.message}`, true);
        }
      });
    });
  }

  function renderGuardSettings(data) {
    const noise = data?.noise || {};
    const profile = noise.profile || 'balanced';
    if (noiseBadgeEl) noiseBadgeEl.textContent = profile;
    if (noiseSelectEl) noiseSelectEl.value = profile;

    const totals = noise.totals || {};
    noiseTotalsEl.innerHTML = `
      <div class="noise-stat"><span>Requests</span><strong>${Number(totals.requests || 0)}</strong></div>
      <div class="noise-stat"><span>Throttled</span><strong>${Number(totals.throttled || 0)}</strong></div>
      <div class="noise-stat"><span>429/503 Backoffs</span><strong>${Number(totals.backoffHits || 0)}</strong></div>
      <div class="noise-stat"><span>Dedup Cache Hits</span><strong>${Number(totals.cacheHits || 0)}</strong></div>
    `;

    const hosts = noise.hosts && typeof noise.hosts === 'object' ? Object.values(noise.hosts) : [];
    if (hosts.length === 0) {
      noiseHostsEl.innerHTML = '<div class="empty-muted">No live host egress telemetry recorded yet.</div>';
    } else {
      noiseHostsEl.innerHTML = `
        <table class="mini-table">
          <thead>
            <tr><th>Host</th><th>Reqs</th><th>In-Flight</th><th>Throttled</th><th>Backoffs</th><th>Cache Hits</th></tr>
          </thead>
          <tbody>
            ${hosts
              .map(
                h => `
              <tr>
                <td><code>${escapeHtml(h.host)}</code></td>
                <td>${Number(h.requests || 0)}</td>
                <td>${Number(h.inFlight || 0)}</td>
                <td>${Number(h.throttled || 0)}</td>
                <td>${Number(h.backoffHits || 0)}</td>
                <td>${Number(h.cacheHits || 0)}</td>
              </tr>
            `
              )
              .join('')}
          </tbody>
        </table>
      `;
    }

    const scopeRules = Array.isArray(data?.scopeRules) ? data.scopeRules : [];
    if (scopeTextEl) {
      scopeTextEl.value = serializeScopeRules(scopeRules);
    }
  }

  async function loadAll() {
    try {
      const [llmRes, guardRes] = await Promise.all([
        fetchJson('/api/llm/pool').catch(() => ({ profiles: [], breakers: {}, usage: {} })),
        fetchJson('/api/guard/settings').catch(() => ({ noise: { profile: 'balanced', totals: {}, hosts: {} }, scopeRules: [] })),
      ]);
      renderLlmPool(llmRes);
      renderGuardSettings(guardRes);
    } catch (err) {
      showFeedback(`Failed to load guardrails: ${err.message}`, true);
    }
  }

  const providerSelectEl = container.querySelector('[data-role="llm-provider"]');
  const modelInputEl = container.querySelector('[data-role="llm-model"]');
  const modelHintEl = container.querySelector('[data-role="llm-model-hint"]');

  function syncProviderModelHint() {
    if (!providerSelectEl) return;
    const provider = providerSelectEl.value;
    const hint = getProviderModelHint(provider);
    if (modelInputEl) {
      modelInputEl.placeholder = hint.placeholder;
    }
    if (modelHintEl) {
      modelHintEl.textContent = `Default model for ${provider}: ${hint.defaultModel}`;
    }
  }

  providerSelectEl?.addEventListener('change', syncProviderModelHint);
  syncProviderModelHint();

  container.querySelector('[data-sg-action="refresh"]').addEventListener('click', loadAll);

  container.querySelector('[data-role="llm-profile-form"]').addEventListener('submit', async e => {
    e.preventDefault();
    const payload = {
      id: container.querySelector('[data-role="llm-id"]').value.trim(),
      name: container.querySelector('[data-role="llm-name"]').value.trim() || undefined,
      provider: container.querySelector('[data-role="llm-provider"]').value,
      model: container.querySelector('[data-role="llm-model"]').value.trim(),
      baseUrl: container.querySelector('[data-role="llm-baseurl"]').value.trim() || undefined,
      apiKey: container.querySelector('[data-role="llm-apikey"]').value.trim() || undefined,
      enabled: container.querySelector('[data-role="llm-enabled"]').checked,
    };
    if (!payload.id || !payload.model) return;
    try {
      await fetchJson('/api/llm/profiles', { method: 'POST', body: JSON.stringify(payload) });
      container.querySelector('[data-role="llm-apikey"]').value = '';
      showFeedback(`Saved LLM profile ${payload.id}.`);
      await loadAll();
    } catch (err) {
      showFeedback(`Failed to save LLM profile: ${err.message}`, true);
    }
  });

  container.querySelector('[data-sg-action="save-noise"]').addEventListener('click', async () => {
    const noiseProfile = noiseSelectEl.value;
    try {
      await fetchJson('/api/guard/settings', {
        method: 'PUT',
        body: JSON.stringify({ noiseProfile }),
      });
      showFeedback(`Noise governor set to "${noiseProfile}".`);
      await loadAll();
    } catch (err) {
      showFeedback(`Failed to update noise governor: ${err.message}`, true);
    }
  });

  container.querySelector('[data-role="scope-form"]').addEventListener('submit', async e => {
    e.preventDefault();
    const scopeRules = parseScopeRulesText(scopeTextEl.value);
    try {
      await fetchJson('/api/guard/settings', {
        method: 'PUT',
        body: JSON.stringify({ scopeRules }),
      });
      showFeedback(`Saved ${scopeRules.length} scope rules.`);
      await loadAll();
    } catch (err) {
      showFeedback(`Failed to save scope rules: ${err.message}`, true);
    }
  });

  container.querySelector('[data-role="eval-form"]').addEventListener('submit', async e => {
    e.preventDefault();
    const target = container.querySelector('[data-role="eval-target"]').value.trim();
    const toolName = container.querySelector('[data-role="eval-tool"]').value.trim() || 'GET';
    const jevAnswers = {};
    container.querySelectorAll('[data-jev-id]').forEach(cb => {
      jevAnswers[cb.getAttribute('data-jev-id')] = cb.checked;
    });

    try {
      const payload = {
        mode: 'all',
        toolName,
        jevAnswers,
        ...(target ? { target } : {})
      };
      const res = await fetchJson('/api/guard/evaluate', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      const gate = res.gate || res.assetGate || (res.mode === 'asset' ? res.result || res : {});
      const risk = res.risk || (res.mode === 'risk' ? res.result || res : {});
      const jev = res.jev || res.decision || (res.mode === 'jev' ? res.result || res : {});
      const reasonText = gate.reason || jev.reason || (Array.isArray(risk.reasons) ? risk.reasons.join('; ') : risk.reason) || 'Evaluated';
      evalResultEl.innerHTML = `
        <div class="eval-verdict-row">
          ${target ? `<span>Asset Gate: <strong>${gate.allowed === false ? 'DENIED' : 'ALLOWED'}</strong></span>` : ''}
          <span>Risk Score: <strong>${Number(risk.score ?? 0)} / 100</strong> (${escapeHtml(risk.level || risk.band || 'low')})</span>
          <span>JEV Judge: <strong>${jev.approved ? 'APPROVED' : 'DENIED'}</strong></span>
        </div>
        <div class="eval-reason">${escapeHtml(reasonText)}</div>
      `;
      evalResultEl.classList.remove('hidden');
    } catch (err) {
      showFeedback(`Evaluation failed: ${err.message}`, true);
    }
  });

  await loadAll();
}
