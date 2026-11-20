/**
 * Security Scanner 2.2 · Autonomous Web Security & Verification Platform
 * Zero-Build Modular ES Application (7-Tab Navigation + Interactive Components)
 */

import { renderExplorationGraph } from './components/exploration-graph.js';
import { renderCoverageGraph } from './components/coverage-graph.js';
import { mountAssetDslSearch } from './components/asset-dsl-search.js';
import { renderEvidenceViewer, renderAiFixIntoSlot } from './components/evidence-viewer.js';
import { renderTrafficInspector } from './components/traffic-inspector.js';
import { renderSessionExplorer } from './components/session-explorer.js';
import { renderSystemGuardrails } from './components/system-guardrails.js';
import { renderCveCoveragePanel } from './components/cve-coverage.js';

// ── Application State ────────────────────────────────────────────────────────
const state = {
  presets: [],
  profiles: {},
  checks: [],
  selectedPreset: 'smart',
  recommendedProfile: 'smart',
  activeScanId: null,
  eventSource: null,
  currentResults: null,
  renderedFindings: [],
  viewMode: 'regular', // 'regular' | 'developer'
  history: [],
  diffSlotA: null,
  diffSlotB: null,
  resultsFilters: {
    status: 'all',
    severity: 'all',
    search: ''
  },
  catalogFilters: {
    category: 'all',
    search: ''
  },
  builderPreviewData: null,
  builderActiveTab: 'check',
  dualGraph: {
    activeSubView: 'exploration', // 'exploration' | 'coverage'
    selectedTaskId: '',
    dslCtrl: null,
    lastDsl: ''
  }
};

const PRESET_ICONS = {
  smart: '🧠',
  quick: '⚡',
  full: '🌐',
  modern: '🤖',
  cms: '🛍️',
  api: '🔌',
  ops: '🩺'
};

// ── Strict HTML Escaping Helper (XSS Protection) ────────────────────────────
export function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function showInlineBanner(elementId, message, isError = true) {
  if (typeof document === 'undefined') return;
  const el = document.getElementById(elementId);
  if (!el) return;
  el.className = `feedback-banner ${isError ? 'error' : 'success'}`;
  el.textContent = message;
  el.classList.remove('hidden');
}

function hideInlineBanner(elementId) {
  if (typeof document === 'undefined') return;
  const el = document.getElementById(elementId);
  if (el) el.classList.add('hidden');
}

// ── Server Connection Indicator ──────────────────────────────────────────────
function setServerStatus(connected, label) {
  if (typeof document === 'undefined') return;
  const dot = document.getElementById('server-status-dot');
  const text = document.getElementById('server-status-text');
  if (dot) {
    dot.classList.toggle('online', Boolean(connected));
    dot.classList.toggle('offline', !connected);
  }
  if (text) {
    text.textContent = label || (connected ? 'Server Connected' : 'Server Disconnected');
  }
}

// ── API Communication Helpers ────────────────────────────────────────────────
async function apiGet(endpoint) {
  let res;
  try {
    res = await fetch(endpoint, {
      headers: { Accept: 'application/json' }
    });
  } catch (err) {
    setServerStatus(false, 'Server Disconnected');
    throw new Error(
      `Cannot reach the local Security Scanner UI server (${err.message}). Make sure "npm run ui" or "secscan --ui" is running and refresh the page.`
    );
  }
  setServerStatus(true, 'Server Connected');
  if (!res.ok) {
    const errData = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
    throw new Error(errData.error || `HTTP ${res.status}`);
  }
  return res.json();
}

async function apiPost(endpoint, body) {
  let res;
  try {
    res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json'
      },
      body: JSON.stringify(body)
    });
  } catch (err) {
    setServerStatus(false, 'Server Disconnected');
    throw new Error(
      `Cannot reach the local Security Scanner UI server (${err.message}). Make sure "npm run ui" or "secscan --ui" is running and refresh the page.`
    );
  }
  setServerStatus(true, 'Server Connected');
  const data = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
  if (!res.ok) {
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  return data;
}

function triggerFileDownload(content, mimeType, filename) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ── Initialization ───────────────────────────────────────────────────────────
if (typeof document !== 'undefined') {
  document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initSystemDoctorModal();
    initNewScanForm();
    initResultsToolbar();
    initEvidenceDrawer();
    initDualGraphTab();
    initHistoryAndDiff();
    initCatalogAndBuilder();

    loadMeta();
    loadHistory();
  });
}

// ── Navigation Tabs ──────────────────────────────────────────────────────────
function initNavigation() {
  const navTabs = document.querySelector('.nav-tabs');
  const tabButtons = Array.from(document.querySelectorAll('.tab-btn'));

  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');
      switchTab(targetTab);
    });
  });

  if (navTabs && tabButtons.length > 0) {
    navTabs.addEventListener('keydown', e => {
      const currentIdx = tabButtons.indexOf(document.activeElement);
      if (currentIdx === -1) return;

      let nextIdx = -1;
      if (e.key === 'ArrowRight') {
        nextIdx = (currentIdx + 1) % tabButtons.length;
      } else if (e.key === 'ArrowLeft') {
        nextIdx = (currentIdx - 1 + tabButtons.length) % tabButtons.length;
      } else if (e.key === 'Home') {
        nextIdx = 0;
      } else if (e.key === 'End') {
        nextIdx = tabButtons.length - 1;
      }

      if (nextIdx !== -1) {
        e.preventDefault();
        const nextBtn = tabButtons[nextIdx];
        nextBtn.focus();
        switchTab(nextBtn.getAttribute('data-tab'));
      }
    });
  }

  const btnEmptyStart = document.getElementById('btn-empty-start');
  if (btnEmptyStart) {
    btnEmptyStart.addEventListener('click', () => switchTab('new-scan'));
  }

  const btnGotoResults = document.getElementById('btn-goto-results');
  if (btnGotoResults) {
    btnGotoResults.addEventListener('click', () => switchTab('scan-results'));
  }

  const btnOpenCveAudit = document.getElementById('btn-open-cve-audit-from-results');
  if (btnOpenCveAudit) {
    btnOpenCveAudit.addEventListener('click', () => {
      switchTab('catalog');
      document.getElementById('btn-view-catalog-cve-coverage')?.click();
    });
  }
}

function switchTab(rawTabId) {
  if (typeof document === 'undefined') return;
  const tabId = rawTabId === 'results' ? 'scan-results' : rawTabId;

  document.querySelectorAll('.tab-btn').forEach(btn => {
    const isActive = btn.getAttribute('data-tab') === tabId;
    btn.classList.toggle('active', isActive);
    btn.setAttribute('aria-selected', isActive ? 'true' : 'false');
    btn.setAttribute('tabindex', isActive ? '0' : '-1');
  });

  document.querySelectorAll('.tab-panel').forEach(panel => {
    panel.classList.toggle('active', panel.id === `tab-${tabId}`);
  });

  if (tabId === 'history') {
    loadHistory();
  } else if (tabId === 'tasks-sessions') {
    const root = document.getElementById('session-explorer-root');
    if (root) {
      renderSessionExplorer(root, {
        onOpenGraph: taskId => {
          state.dualGraph.selectedTaskId = taskId;
          switchTab('dual-graph');
        }
      });
    }
  } else if (tabId === 'dual-graph') {
    refreshDualGraphTab();
  } else if (tabId === 'traffic-replay') {
    const root = document.getElementById('traffic-inspector-root');
    if (root) {
      renderTrafficInspector(root);
    }
  }
}

// ── Load Server Metadata (/api/meta) ─────────────────────────────────────────
async function loadMeta() {
  try {
    const data = await apiGet('/api/meta');
    state.presets = data.presets || [];
    state.profiles = data.profiles || {};
    state.checks = data.checks || [];

    const totalChecks = Number(data.totalChecks ?? state.checks.length) || 0;
    const catalogBadge = document.getElementById('catalog-badge');
    const totalChecksBadge = document.getElementById('total-checks-badge');
    const catalogTotalText = document.getElementById('catalog-total-text');
    const forceAllCount = document.getElementById('force-all-count');
    if (catalogBadge) catalogBadge.textContent = String(totalChecks);
    if (totalChecksBadge) totalChecksBadge.textContent = String(totalChecks);
    if (catalogTotalText) catalogTotalText.textContent = totalChecks ? `all ${totalChecks}` : 'all';
    if (forceAllCount) forceAllCount.textContent = totalChecks ? `All ${totalChecks}` : 'All';

    const categories = Array.isArray(data.categories) && data.categories.length > 0
      ? data.categories
      : Array.from(new Set(state.checks.map(c => c?.meta?.category).filter(Boolean))).sort();
    renderCategoryPills(categories);

    renderPresetCards();
    renderCatalogGrid();
  } catch (err) {
    console.warn('Could not load /api/meta:', err.message);
  }
}

// ── Custom Headers Parser & Validator (synchronized with core/headers.js) ────
const RFC7230_TOKEN_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const FORBIDDEN_CUSTOM_HEADERS = new Set([
  'host',
  'content-length',
  'transfer-encoding',
  'connection',
  'keep-alive',
  'upgrade',
  'expect',
  'te',
  'trailer',
  'proxy-connection'
]);
const FORBIDDEN_HEADER_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const MAX_CUSTOM_HEADERS = 32;
const MAX_CUSTOM_HEADER_BYTES = 8192;
const HEADER_UTF8_ENCODER = new TextEncoder();

export function parseCustomHeadersInput(rawText) {
  const text = String(rawText ?? '');
  if (!text.trim()) {
    return { valid: true, headers: undefined };
  }

  const lines = text.split(/\r?\n/);
  const headers = {};
  const seenLower = new Set();
  let totalBytes = 0;

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    const trimmed = rawLine.trim();
    if (!trimmed) continue;

    if (/[\x00-\x08\x0A-\x1F\x7F]/.test(rawLine)) {
      return {
        valid: false,
        error: `Custom header line ${i + 1} contains invalid control characters.`
      };
    }

    const colonIdx = trimmed.indexOf(':');
    if (colonIdx <= 0) {
      return {
        valid: false,
        error: `Custom header line ${i + 1} must be in "Name: Value" format.`
      };
    }

    const name = trimmed.slice(0, colonIdx).trim();
    const value = trimmed.slice(colonIdx + 1).trim();
    if (!RFC7230_TOKEN_RE.test(name)) {
      return {
        valid: false,
        error: `Custom header "${name}" contains invalid characters in its name.`
      };
    }

    const lower = name.toLowerCase();
    if (FORBIDDEN_HEADER_KEYS.has(lower)) {
      return {
        valid: false,
        error: `Forbidden header name "${name}".`
      };
    }
    if (FORBIDDEN_CUSTOM_HEADERS.has(lower)) {
      return {
        valid: false,
        error: `Header "${name}" is reserved/hop-by-hop and cannot be overridden.`
      };
    }

    if (!seenLower.has(lower)) {
      seenLower.add(lower);
      if (seenLower.size > MAX_CUSTOM_HEADERS) {
        return {
          valid: false,
          error: `Too many custom headers (maximum ${MAX_CUSTOM_HEADERS} allowed).`
        };
      }
    } else {
      for (const existingKey of Object.keys(headers)) {
        if (existingKey.toLowerCase() === lower) {
          totalBytes -= HEADER_UTF8_ENCODER.encode(`${existingKey}: ${headers[existingKey]}\r\n`).length;
          delete headers[existingKey];
          break;
        }
      }
    }

    totalBytes += HEADER_UTF8_ENCODER.encode(`${name}: ${value}\r\n`).length;
    if (totalBytes > MAX_CUSTOM_HEADER_BYTES) {
      return {
        valid: false,
        error: `Custom headers exceed maximum total size of ${MAX_CUSTOM_HEADER_BYTES} bytes.`
      };
    }

    headers[name] = value;
  }

  return {
    valid: true,
    headers: seenLower.size > 0 ? headers : undefined
  };
}

// ── System Doctor Modal ──────────────────────────────────────────────────────
function initSystemDoctorModal() {
  const openBtn = document.getElementById('btn-open-system-doctor');
  const closeBtn = document.getElementById('btn-close-system-doctor');
  const refreshBtn = document.getElementById('btn-refresh-system-doctor');
  const backdrop = document.getElementById('system-doctor-backdrop');
  const diagnoseForm = document.getElementById('doctor-diagnose-form');

  openBtn?.addEventListener('click', openSystemDoctorModal);
  closeBtn?.addEventListener('click', closeSystemDoctorModal);
  refreshBtn?.addEventListener('click', loadSystemDoctor);

  backdrop?.addEventListener('click', e => {
    if (e.target === backdrop) {
      closeSystemDoctorModal();
    }
  });

  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && backdrop && !backdrop.classList.contains('hidden')) {
      closeSystemDoctorModal();
    }
  });

  diagnoseForm?.addEventListener('submit', async e => {
    e.preventDefault();
    await runDoctorTargetDiagnose();
  });
}

function openSystemDoctorModal() {
  const backdrop = document.getElementById('system-doctor-backdrop');
  if (!backdrop) return;

  const targetInput = document.getElementById('doctor-target-input');
  const scanUrlInput = document.getElementById('target-url');
  if (targetInput && !targetInput.value.trim() && scanUrlInput?.value.trim()) {
    targetInput.value = scanUrlInput.value.trim();
  }

  backdrop.classList.remove('hidden');
  loadSystemDoctor();
}

function closeSystemDoctorModal() {
  const backdrop = document.getElementById('system-doctor-backdrop');
  if (backdrop) backdrop.classList.add('hidden');
}

async function loadSystemDoctor() {
  const panel = document.getElementById('doctor-preflight-panel');
  if (!panel) return;
  hideInlineBanner('doctor-feedback');
  panel.innerHTML = '<div class="empty-muted">Running local preflight diagnostics...</div>';

  try {
    const data = await apiGet('/api/system/doctor');
    renderSystemDoctorPreflight(panel, data);
  } catch (err) {
    panel.innerHTML = `<div class="feedback-banner error">Failed to load System Doctor preflight: ${escapeHtml(err.message)}</div>`;
    showInlineBanner('doctor-feedback', `System Doctor error: ${err.message}`, true);
  }
}

function renderSystemDoctorPreflight(panel, data) {
  const env = data?.environment || {};
  const storage = data?.storage || {};
  const proxy = data?.proxy || {};
  const ai = data?.ai || {};
  const checks = data?.checks || {};
  const recs = Array.isArray(data?.recommendations) ? data.recommendations : [];

  const historyOk = Boolean(storage.historyDir?.writable && storage.historyDir?.readable);
  const reportsOk = Boolean(storage.reportsDir?.writable && storage.reportsDir?.readable);
  const proxySummary = proxy.configured
    ? [proxy.httpsProxy ? `HTTPS: ${proxy.httpsProxy}` : '', proxy.httpProxy ? `HTTP: ${proxy.httpProxy}` : '']
        .filter(Boolean)
        .join(' · ')
    : 'Direct connection (no proxy)';
  const providersList = Array.isArray(ai.providers) && ai.providers.length ? ai.providers.join(', ') : 'None';

  panel.innerHTML = `
    <div class="doctor-summary-row">
      <span class="ev-pill ${data?.ok ? 'ev-status-verified' : 'ev-stale'}">
        ${data?.ok ? '✅ Local Environment Ready' : '⚠️ Preflight Warnings Detected'}
      </span>
      <span class="form-hint">Checked ${data?.generatedAt ? escapeHtml(new Date(data.generatedAt).toLocaleTimeString()) : 'just now'}</span>
    </div>

    <div class="doctor-checks-grid">
      <div class="doctor-check-card">
        <div class="doctor-check-head">
          <strong>Runtime &amp; SQLite</strong>
          <span class="ev-pill ${env.nodeOk && env.sqliteAvailable ? 'ev-status-verified' : 'ev-status-rejected'}">
            ${env.nodeOk && env.sqliteAvailable ? 'OK' : 'ISSUE'}
          </span>
        </div>
        <div class="doctor-check-meta">
          <div>Node: <code>${escapeHtml(env.nodeVersion || 'unknown')}</code> (${escapeHtml(env.platform || '')}/${escapeHtml(env.arch || '')})</div>
          <div>node:sqlite: <strong>${env.sqliteAvailable ? 'Available' : 'Missing'}</strong></div>
        </div>
      </div>

      <div class="doctor-check-card">
        <div class="doctor-check-head">
          <strong>Disk Storage</strong>
          <span class="ev-pill ${historyOk && reportsOk ? 'ev-status-verified' : 'ev-status-rejected'}">
            ${historyOk && reportsOk ? 'WRITABLE' : 'READONLY'}
          </span>
        </div>
        <div class="doctor-check-meta">
          <div>History: <strong>${historyOk ? 'OK' : 'Error'}</strong> (<code>${escapeHtml(storage.historyDir?.path || '.secscan-history')}</code>)</div>
          <div>Reports: <strong>${reportsOk ? 'OK' : 'Error'}</strong> (<code>${escapeHtml(storage.reportsDir?.path || 'reports')}</code>)</div>
        </div>
      </div>

      <div class="doctor-check-card">
        <div class="doctor-check-head">
          <strong>Proxy &amp; Network</strong>
          <span class="ev-pill">${proxy.configured ? 'PROXY SET' : 'DIRECT'}</span>
        </div>
        <div class="doctor-check-meta">
          <div>${escapeHtml(proxySummary)}</div>
          ${proxy.noProxy ? `<div>NO_PROXY: <code>${escapeHtml(proxy.noProxy)}</code></div>` : ''}
        </div>
      </div>

      <div class="doctor-check-card">
        <div class="doctor-check-head">
          <strong>AI / LLM Pool</strong>
          <span class="ev-pill ${ai.activeProfilesCount > 0 ? 'ev-status-verified' : 'ev-stale'}">
            ${ai.activeProfilesCount > 0 ? `${Number(ai.activeProfilesCount)} Active` : 'Playbook Only'}
          </span>
        </div>
        <div class="doctor-check-meta">
          <div>Providers: ${escapeHtml(providersList)}</div>
          <div>Status: ${ai.configured ? 'Configured' : 'Built-in deterministic fallback active'}</div>
        </div>
      </div>

      <div class="doctor-check-card">
        <div class="doctor-check-head">
          <strong>Security Checks</strong>
          <span class="ev-pill ${Number(checks.count) >= 63 ? 'ev-status-verified' : 'ev-stale'}">
            ${Number(checks.count || 0)} Loaded
          </span>
        </div>
        <div class="doctor-check-meta">
          <div>Catalog status: ${checks.available ? 'Ready' : 'Unavailable'}</div>
        </div>
      </div>
    </div>

    ${recs.length > 0 ? `
      <div class="doctor-recommendations">
        <strong>Recommendations:</strong>
        <ul>
          ${recs.map(r => `<li>${escapeHtml(r)}</li>`).join('')}
        </ul>
      </div>
    ` : ''}
  `;
}

async function runDoctorTargetDiagnose() {
  const input = document.getElementById('doctor-target-input');
  const allowPrivateEl = document.getElementById('doctor-allow-private');
  const btn = document.getElementById('btn-run-target-diagnose');
  const resultBox = document.getElementById('doctor-diagnose-result');
  if (!input || !resultBox) return;

  let target = input.value.trim();
  if (!target) {
    input.focus();
    return;
  }
  if (!/^https?:\/\//i.test(target) && target.includes('.')) {
    target = `https://${target}`;
    input.value = target;
  }

  const allowPrivate = Boolean(allowPrivateEl?.checked);
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Diagnosing...';
  }
  resultBox.classList.remove('hidden');
  resultBox.innerHTML = '<div class="empty-muted">Probing DNS, policy gate, and HTTP reachability...</div>';

  try {
    const res = await apiPost('/api/system/diagnose-target', { target, allowPrivate });
    renderTargetDiagnoseResult(resultBox, res);
  } catch (err) {
    resultBox.innerHTML = `<div class="feedback-banner error">Diagnosis request failed: ${escapeHtml(err.message)}</div>`;
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = '🔍 Diagnose Target';
    }
  }
}

function renderTargetDiagnoseResult(resultBox, res) {
  const origin = res?.ok ? 'healthy' : (res?.issueOrigin || 'target_website');
  const originMeta = {
    healthy: { label: '✅ Healthy (Target Reachable)', cls: 'ev-status-verified' },
    local_pc: { label: '💻 Local PC / Network Issue (local_pc)', cls: 'ev-status-rejected' },
    policy_block: { label: '🛡️ Policy / Governance Block (policy_block)', cls: 'ev-stale' },
    target_website: { label: '🌐 Target Website Issue (target_website)', cls: 'ev-status-rejected' }
  }[origin] || { label: escapeHtml(origin), cls: 'ev-stale' };

  const ips = Array.isArray(res?.resolvedIps) && res.resolvedIps.length ? res.resolvedIps.join(', ') : '';

  resultBox.innerHTML = `
    <div class="doctor-triage-card">
      <div class="doctor-triage-head">
        <span class="ev-pill ${originMeta.cls}">${escapeHtml(originMeta.label)}</span>
        <span class="ev-pill">Origin: <code>${escapeHtml(origin)}</code></span>
        ${res?.stage ? `<span class="ev-pill">Stage: <code>${escapeHtml(res.stage)}</code></span>` : ''}
        ${res?.status ? `<span class="ev-pill">HTTP ${Number(res.status)}</span>` : ''}
        ${Number.isFinite(res?.latencyMs) ? `<span class="ev-pill">${Number(res.latencyMs)} ms</span>` : ''}
      </div>
      ${res?.reason ? `<div class="doctor-triage-reason"><strong>Diagnosis:</strong> ${escapeHtml(res.reason)}</div>` : ''}
      ${ips ? `<div class="doctor-triage-meta"><strong>Resolved IPs:</strong> <code>${escapeHtml(ips)}</code></div>` : ''}
      ${res?.recommendation ? `<div class="doctor-triage-fix"><strong>Remediation:</strong> ${escapeHtml(res.recommendation)}</div>` : ''}
    </div>
  `;
}

// ── Tab 1: New Scan (Guided Wizard + Agentic Options) ────────────────────────
function initNewScanForm() {
  const urlInput = document.getElementById('target-url');
  const banner = document.getElementById('url-validation-banner');
  const bannerText = document.getElementById('url-validation-text');
  const form = document.getElementById('scan-form');
  const btnToggleAdv = document.getElementById('btn-toggle-advanced');
  const advDrawer = document.getElementById('advanced-drawer');

  const btnDetect = document.getElementById('detect-stack-btn');
  const detectSpinner = document.getElementById('detect-stack-spinner');
  const detectBtnText = document.getElementById('detect-stack-btn-text');
  const techBanner = document.getElementById('tech-detect-banner');
  const btnCloseDetect = document.getElementById('btn-close-tech-detect');
  const btnApplyProfile = document.getElementById('btn-apply-recommended-profile');
  const allowPrivateEl = document.getElementById('allow-private-toggle');

  if (btnCloseDetect && techBanner) {
    btnCloseDetect.addEventListener('click', () => {
      techBanner.classList.add('hidden');
    });
  }

  if (btnApplyProfile) {
    btnApplyProfile.addEventListener('click', () => {
      selectPreset(state.recommendedProfile || 'smart');
      btnApplyProfile.textContent = '✓ Applied!';
      setTimeout(() => {
        btnApplyProfile.textContent = 'Apply Recommended Profile';
      }, 2000);
    });
  }

  urlInput.addEventListener('blur', () => {
    let val = urlInput.value.trim();
    if (val && !/^https?:\/\//i.test(val) && val.includes('.')) {
      urlInput.value = 'https://' + val;
      val = urlInput.value;
    }
    validateInputUrl(val);
  });

  urlInput.addEventListener('input', () => {
    validateInputUrl(urlInput.value.trim());
  });

  if (allowPrivateEl) {
    allowPrivateEl.addEventListener('change', () => {
      validateInputUrl(urlInput.value.trim());
    });
  }

  function validateInputUrl(val) {
    if (!val) {
      banner.classList.add('hidden');
      return true;
    }

    const allowPrivate = Boolean(allowPrivateEl?.checked);
    const METADATA_PATTERN = /^(https?:\/\/)?(169\.254\.|100\.100\.100\.200\b|metadata\.google\.internal\b|metadata\.goog\b|metadata\b|instance-data\b|0\.0\.0\.0\b)/i;
    if (METADATA_PATTERN.test(val)) {
      bannerText.textContent =
        '⚠️ SSRF Protection: Cloud metadata and reserved link-local addresses are always blocked.';
      banner.classList.remove('hidden');
      return false;
    }

    const PRIVATE_PATTERN = /^(https?:\/\/)?(localhost|127\.|0\.0\.0\.0|::1|\[::1\]|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/i;
    if (!allowPrivate && PRIVATE_PATTERN.test(val)) {
      bannerText.textContent =
        '⚠️ SSRF Protection: Localhost and private network IP addresses cannot be scanned unless "Allow Authorized Internal / Private Targets" is enabled.';
      banner.classList.remove('hidden');
      return false;
    }

    banner.classList.add('hidden');
    return true;
  }

  if (btnDetect) {
    btnDetect.addEventListener('click', async () => {
      let target = urlInput.value.trim();
      if (!target) {
        urlInput.focus();
        return;
      }

      if (!/^https?:\/\//i.test(target) && target.includes('.')) {
        target = 'https://' + target;
        urlInput.value = target;
      }

      if (!validateInputUrl(target)) {
        return;
      }

      const auth = document.getElementById('adv-auth')?.value.trim() || null;
      const timeout = parseInt(document.getElementById('adv-timeout')?.value, 10) || 10000;
      const allowPrivate = Boolean(allowPrivateEl?.checked);

      btnDetect.disabled = true;
      if (detectSpinner) detectSpinner.classList.remove('hidden');
      if (detectBtnText) detectBtnText.textContent = 'Detecting...';

      try {
        const data = await apiPost('/api/fingerprint', { target, auth, timeout, allowPrivate });
        renderTechDetectPreview(data);
      } catch (err) {
        if (bannerText) bannerText.textContent = `Tech detection failed: ${err.message}`;
        if (banner) banner.classList.remove('hidden');
      } finally {
        btnDetect.disabled = false;
        if (detectSpinner) detectSpinner.classList.add('hidden');
        if (detectBtnText) detectBtnText.textContent = '🔎 Detect Tech Stack';
      }
    });
  }

  const btnAnalyzeDetectApi = document.getElementById('btn-analyze-detect-api');
  if (btnAnalyzeDetectApi) {
    btnAnalyzeDetectApi.addEventListener('click', generateDetectApiAiAnalysis);
  }

  // Delegated listener for "🎯 Scan Backend API" buttons across the application
  document.addEventListener('click', e => {
    const scanOriginBtn = e.target.closest('[data-scan-origin]');
    if (scanOriginBtn) {
      const rawOrigin = scanOriginBtn.getAttribute('data-scan-origin') || '';
      handleScanOriginTrigger(rawOrigin);
    }
  });

  btnToggleAdv.addEventListener('click', () => {
    const isExpanded = btnToggleAdv.getAttribute('aria-expanded') === 'true';
    btnToggleAdv.setAttribute('aria-expanded', isExpanded ? 'false' : 'true');
    advDrawer.classList.toggle('hidden', isExpanded);
  });

  form.addEventListener('submit', async e => {
    e.preventDefault();

    let target = urlInput.value.trim();
    if (!target) {
      urlInput.focus();
      return;
    }

    if (!/^https?:\/\//i.test(target)) {
      target = 'https://' + target;
      urlInput.value = target;
    }

    if (!validateInputUrl(target)) {
      return;
    }

    const depth = parseInt(document.getElementById('adv-depth').value, 10) || 3;
    const concurrency = parseInt(document.getElementById('adv-concurrency').value, 10) || 5;
    const timeout = parseInt(document.getElementById('adv-timeout').value, 10) || 10000;
    const auth = document.getElementById('adv-auth').value.trim() || null;
    const tech = document.getElementById('adv-tech').value.trim() || null;
    const forceAll = Boolean(document.getElementById('opt-force-all')?.checked);
    const saveHistory = document.getElementById('adv-save-history').checked;
    const agentMode = Boolean(document.getElementById('opt-agent-mode')?.checked);
    const goal = document.getElementById('opt-agent-goal')?.value.trim() || '';
    const noiseProfile = document.getElementById('opt-noise-profile')?.value || 'balanced';
    const allowPrivate = Boolean(allowPrivateEl?.checked);

    const customHeadersRaw = document.getElementById('custom-headers-input')?.value || '';
    const parsedHeaders = parseCustomHeadersInput(customHeadersRaw);
    if (!parsedHeaders.valid) {
      bannerText.textContent = `⚠️ ${parsedHeaders.error}`;
      banner.classList.remove('hidden');
      if (advDrawer?.classList.contains('hidden')) {
        btnToggleAdv?.setAttribute('aria-expanded', 'true');
        advDrawer.classList.remove('hidden');
      }
      document.getElementById('custom-headers-input')?.focus();
      return;
    }

    await startScan({
      target,
      profile: state.selectedPreset,
      forceAll,
      maxDepth: depth,
      concurrency,
      timeout,
      auth,
      ...(parsedHeaders.headers ? { headers: parsedHeaders.headers } : {}),
      techOverride: tech,
      noHistory: !saveHistory,
      agent: agentMode,
      agentMode,
      goal: goal || undefined,
      noiseProfile,
      allowPrivate
    });
  });
}

function selectPreset(presetId) {
  state.selectedPreset = presetId;
  const container = document.getElementById('preset-cards');
  if (container) {
    container.querySelectorAll('.preset-card').forEach(c => {
      const isMatch = c.getAttribute('data-preset-id') === presetId;
      c.classList.toggle('active', isMatch);
    });
  }
}

export function handleScanOriginTrigger(rawOrigin) {
  if (!rawOrigin || typeof rawOrigin !== 'string') return false;
  const origin = rawOrigin.trim();
  if (!/^https?:\/\//i.test(origin)) return false;

  if (typeof document !== 'undefined') {
    if (typeof switchTab === 'function') {
      switchTab('new-scan');
    }
    const urlInput = document.getElementById('target-url');
    if (urlInput) {
      urlInput.value = origin;
      if (typeof urlInput.focus === 'function') urlInput.focus();
      if (typeof urlInput.scrollIntoView === 'function') {
        urlInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    }

    const banner = document.getElementById('url-validation-banner');
    const bannerText = document.getElementById('url-validation-text');
    if (banner && bannerText) {
      bannerText.textContent = `🎯 Loaded external backend API target: ${origin}. Ready to scan or detect tech stack.`;
      banner.className = 'validation-banner info';
      banner.classList.remove('hidden');
    }
  }
  return true;
}

export function renderApiCommunicationSection({
  statusBadgeEl,
  detailsEl,
  endpointsEl,
  analyzeBtnEl,
  apiComm
}) {
  const usesApi = Boolean(apiComm && apiComm.usesApi);

  if (statusBadgeEl) {
    statusBadgeEl.textContent = usesApi ? 'Yes — SPA / API Client' : 'Not Detected';
    statusBadgeEl.className = `badge badge-api-status ${usesApi ? 'badge-api-active' : 'badge-api-inactive'}`;
  }

  if (detailsEl) {
    if (!usesApi) {
      detailsEl.innerHTML = '<span class="form-hint">No client-side SPA API frameworks, fetch calls, or external endpoints detected in HTML or script bundles.</span>';
    } else {
      const chips = [];
      if (apiComm.architecture) {
        chips.push(`<span class="badge badge-outline">${escapeHtml(apiComm.architecture)}</span>`);
      }
      if (Array.isArray(apiComm.clients)) {
        for (const c of apiComm.clients) {
          chips.push(`<span class="badge badge-client">${escapeHtml(c)}</span>`);
        }
      }
      if (Array.isArray(apiComm.protocols)) {
        for (const p of apiComm.protocols) {
          chips.push(`<span class="badge badge-protocol">${escapeHtml(String(p).toUpperCase())}</span>`);
        }
      }
      const summaryText = apiComm.summary ? `<p class="api-summary-line">${escapeHtml(apiComm.summary)}</p>` : '';
      detailsEl.innerHTML = `
        <div class="api-chips-row">${chips.join(' ')}</div>
        ${summaryText}
      `;
    }
  }

  if (endpointsEl) {
    if (!usesApi) {
      endpointsEl.innerHTML = '';
      endpointsEl.classList.add('hidden');
    } else {
      endpointsEl.classList.remove('hidden');
      const sameOrigin = Array.isArray(apiComm.sameOriginEndpoints) ? apiComm.sameOriginEndpoints : [];
      const external = Array.isArray(apiComm.externalApiOrigins) ? apiComm.externalApiOrigins : [];

      let html = '';
      if (sameOrigin.length > 0) {
        html += `
          <div class="api-endpoints-group">
            <span class="api-group-title">Same-Origin Discovered Endpoints (${sameOrigin.length}):</span>
            <div class="api-pills-wrap">
              ${sameOrigin.map(ep => `<span class="api-endpoint-pill">${escapeHtml(ep)}</span>`).join('')}
            </div>
          </div>
        `;
      }

      if (external.length > 0) {
        html += `
          <div class="api-endpoints-group">
            <span class="api-group-title">External Backend API Origins (${external.length}):</span>
            <div class="api-external-list">
              ${external.map(orig => `
                <div class="api-origin-row">
                  <span class="api-external-pill">${escapeHtml(orig)}</span>
                  <button type="button" class="btn-secondary btn-small" data-scan-origin="${escapeHtml(orig)}">
                    🎯 Scan Backend API
                  </button>
                </div>
              `).join('')}
            </div>
          </div>
        `;
      }

      if (sameOrigin.length === 0 && external.length === 0) {
        html = '<span class="form-hint">Client-side API framework active, but no static endpoint URLs extracted from inspected bundles.</span>';
      }

      endpointsEl.innerHTML = html;
    }
  }

  if (analyzeBtnEl) {
    analyzeBtnEl.classList.remove('hidden');
  }
}

export function renderApiAiOutput(container, data) {
  if (!container || !data) return;
  const isAi = data.mode === 'ai';
  const modeLabel = isAi
    ? `🤖 AI Powered${data.provider || data.model ? ` (${[data.provider, data.model].filter(Boolean).join(' / ')})` : ''}`
    : '📘 Built-in Playbook';

  const isNoLlm = data.fallbackReason && (
    String(data.fallbackReason).includes('no_llm') ||
    String(data.fallbackReason).includes('no_active_profile') ||
    String(data.fallbackReason).includes('not_configured')
  );

  const headline = data.headline || (data.usesApi ? 'API Communication Security Analysis' : 'No Active Client-Side APIs Detected');
  const explanation = data.explanation || '';
  const recommendations = Array.isArray(data.recommendations) ? data.recommendations : [];
  const configGuidance = typeof data.configGuidance === 'string'
    ? data.configGuidance
    : Array.isArray(data.configGuidance)
    ? data.configGuidance.join('\n')
    : '';
  const nextTargets = Array.isArray(data.nextScanTargets) ? data.nextScanTargets : [];
  const devPrompt = data.developerPrompt || '';

  container.classList.remove('hidden');
  container.innerHTML = `
    <div class="api-ai-card">
      <div class="ai-fix-header">
        <div class="ai-fix-badges">
          <span class="ev-pill ${isAi ? 'ai-mode-badge' : 'playbook-mode-badge'}">${escapeHtml(modeLabel)}</span>
          <span class="ev-pill">${escapeHtml(data.audience === 'pro' ? 'Developer / Pro' : 'Owner / Beginner')}</span>
          ${data.architecture ? `<span class="ev-pill">${escapeHtml(data.architecture)}</span>` : ''}
        </div>
        ${data.fallbackReason ? `
          <div class="ai-fallback-meta">
            <span class="form-hint">Reason: ${escapeHtml(data.fallbackReason)}</span>
            ${isNoLlm ? `
              <button type="button" class="btn-secondary btn-small btn-goto-llm-pool">
                ⚙️ Configure LLM in Settings (Tab 7)
              </button>
            ` : ''}
          </div>
        ` : ''}
      </div>

      <h4 class="api-ai-headline">${escapeHtml(headline)}</h4>
      ${explanation ? `<p class="api-ai-explanation">${escapeHtml(explanation)}</p>` : ''}

      ${recommendations.length > 0 ? `
        <div class="api-ai-section">
          <strong>Recommended Remediation Steps</strong>
          <ul class="api-ai-list">
            ${recommendations.map(r => `<li>${escapeHtml(r)}</li>`).join('')}
          </ul>
        </div>
      ` : ''}

      ${configGuidance ? `
        <div class="api-ai-section">
          <strong>Configuration &amp; Hardening Guidance</strong>
          <pre class="code-block api-config-block"><code>${escapeHtml(configGuidance)}</code></pre>
        </div>
      ` : ''}

      ${nextTargets.length > 0 ? `
        <div class="api-ai-section">
          <strong>Suggested Next Targets (External Backend APIs)</strong>
          <div class="api-next-targets">
            ${nextTargets.map(target => `
              <div class="api-target-item">
                <span class="api-external-pill">${escapeHtml(target)}</span>
                <button type="button" class="btn-secondary btn-small" data-scan-origin="${escapeHtml(target)}">
                  🎯 Scan Backend API
                </button>
              </div>
            `).join('')}
          </div>
        </div>
      ` : ''}

      ${devPrompt ? `
        <details class="ai-fix-prompt-details">
          <summary>💬 Developer / LLM Prompt</summary>
          <div class="ai-fix-code-head">
            <span class="form-hint">Copy prompt for your coding agent or developer triage</span>
            <button type="button" class="btn-secondary btn-small btn-copy-api-prompt">📋 Copy Prompt</button>
          </div>
          <pre class="code-block ai-fix-code"><code>${escapeHtml(devPrompt)}</code></pre>
        </details>
      ` : ''}
    </div>
  `;

  const copyBtn = container.querySelector('.btn-copy-api-prompt');
  if (copyBtn && devPrompt) {
    copyBtn.addEventListener('click', async () => {
      try {
        await navigator.clipboard?.writeText(devPrompt);
        copyBtn.textContent = '✓ Copied';
        setTimeout(() => {
          copyBtn.textContent = '📋 Copy Prompt';
        }, 1800);
      } catch {
        // fallback
      }
    });
  }

  const llmBtn = container.querySelector('.btn-goto-llm-pool');
  if (llmBtn) {
    llmBtn.addEventListener('click', () => {
      switchTab('catalog');
      document.getElementById('btn-view-catalog-guardrails')?.click();
    });
  }
}

export async function generateDetectApiAiAnalysis() {
  const detectData = state.lastTechDetect;
  const target = detectData?.target || (typeof document !== 'undefined' ? document.getElementById('target-url')?.value.trim() : undefined);
  const fp = detectData?.fingerprint || {};
  const apiComm = fp.apiCommunication || detectData?.apiCommunication || null;
  const outputEl = typeof document !== 'undefined' ? document.getElementById('tech-detect-api-ai-output') : null;
  const btn = typeof document !== 'undefined' ? document.getElementById('btn-analyze-detect-api') : null;
  if (!outputEl) return;

  if (btn) {
    btn.disabled = true;
    btn.textContent = '🤖 Analyzing APIs...';
  }
  outputEl.classList.remove('hidden');
  outputEl.innerHTML = '<div class="empty-muted">Consulting AI advisor about client-side API communication &amp; backend endpoints...</div>';

  try {
    const audience = state.viewMode === 'developer' ? 'pro' : 'beginner';
    const payload = { target, apiCommunication: apiComm, audience };
    const res = await apiPost('/api/ai/analyze-api', payload);
    renderApiAiOutput(outputEl, res);
  } catch (err) {
    outputEl.innerHTML = `<div class="feedback-banner error">Failed to analyze APIs: ${escapeHtml(err.message)}</div>`;
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = '🤖 Ask AI About APIs';
    }
  }
}

export async function generateResultsApiAiAnalysis() {
  const resData = state.currentResults || {};
  const audience = state.viewMode === 'developer' ? 'pro' : 'beginner';
  const apiComm = resData.apiCommunication || resData.stacks?.[0]?.apiCommunication || null;
  const primaryTarget = resData.results?.[0]?.target || resData.target || undefined;
  const scanId = resData.scanId || resData.historyFile || state.activeScanId || undefined;
  const outputEl = typeof document !== 'undefined' ? document.getElementById('results-api-ai-output') : null;
  const btn = typeof document !== 'undefined' ? document.getElementById('btn-analyze-results-api') : null;
  if (!outputEl) return;

  if (btn) {
    btn.disabled = true;
    btn.textContent = '🤖 Analyzing APIs...';
  }
  outputEl.classList.remove('hidden');
  outputEl.innerHTML = '<div class="empty-muted">Consulting AI advisor about client-side API communication &amp; backend endpoints...</div>';

  try {
    const payload = scanId
      ? { scanId, audience }
      : { target: primaryTarget, apiCommunication: apiComm, audience };
    const res = await apiPost('/api/ai/analyze-api', payload);
    renderApiAiOutput(outputEl, res);
  } catch (err) {
    outputEl.innerHTML = `<div class="feedback-banner error">Failed to analyze APIs: ${escapeHtml(err.message)}</div>`;
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = '🤖 Ask AI About APIs';
    }
  }
}

export function renderTechDetectPreview(data) {
  const banner = document.getElementById('tech-detect-banner');
  if (!banner || !data) return;

  state.lastTechDetect = data;

  const fp = data.fingerprint || {};
  const targetEl = document.getElementById('tech-detect-target-text');
  const summaryEl = document.getElementById('tech-detect-summary-text');
  const badgesEl = document.getElementById('tech-detect-badges');
  const counterEl = document.getElementById('tech-detect-counter');
  const profileBadgeEl = document.getElementById('tech-detect-profile-badge');

  if (targetEl) targetEl.textContent = data.target || '—';
  if (summaryEl) summaryEl.textContent = fp.summary || 'Generic Web Application';

  const tags = Array.isArray(fp.detectedTags) && fp.detectedTags.length > 0
    ? fp.detectedTags
    : Array.isArray(fp.stack) && fp.stack.length > 0
    ? fp.stack.map(s => s.tech)
    : ['generic'];

  if (badgesEl) {
    badgesEl.innerHTML = tags.map(tag => {
      const cleanTag = escapeHtml(String(tag).trim());
      const safeClass = cleanTag.toLowerCase().replace(/[^a-z0-9_-]/gi, '');
      return `<span class="tech-badge tech-tag-${safeClass}">${cleanTag}</span>`;
    }).join('');
  }

  const activeCount = Number(data.activeChecksCount) || 0;
  const skippedCount = Number(data.skippedChecksCount) || 0;
  if (counterEl) {
    counterEl.innerHTML = `<strong>${activeCount} Relevant Checks Selected · ${skippedCount} Irrelevant Framework Checks Skipped</strong>`;
  }

  const recProfile = data.recommendedProfile || 'smart';
  state.recommendedProfile = recProfile;
  if (profileBadgeEl) {
    profileBadgeEl.textContent = recProfile;
  }

  const apiComm = fp.apiCommunication || data.apiCommunication || null;
  const apiBadge = document.getElementById('tech-detect-api-badge');
  const apiDetails = document.getElementById('tech-detect-api-details');
  const apiEndpoints = document.getElementById('tech-detect-api-endpoints');
  const btnAnalyzeDetect = document.getElementById('btn-analyze-detect-api');
  const apiAiOutput = document.getElementById('tech-detect-api-ai-output');

  if (apiAiOutput) {
    apiAiOutput.classList.add('hidden');
    apiAiOutput.innerHTML = '';
  }

  renderApiCommunicationSection({
    statusBadgeEl: apiBadge,
    detailsEl: apiDetails,
    endpointsEl: apiEndpoints,
    analyzeBtnEl: btnAnalyzeDetect,
    apiComm
  });

  banner.classList.remove('hidden');
  banner.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function renderPresetCards() {
  const container = document.getElementById('preset-cards');
  if (!container) return;

  const basePresets = state.presets.length > 0 ? [...state.presets] : [
    { id: 'smart', name: 'Smart Auto-Detect (Recommended)', tagline: 'Detects your site tech stack first & runs the right checks' },
    { id: 'quick', name: 'Quick Health Check', tagline: 'Fast 10-second check of SSL, headers & secrets' },
    { id: 'full', name: 'Full Website Audit', tagline: 'Complete security check across all technologies' },
    { id: 'modern', name: 'Modern Web & AI App', tagline: 'React, Next.js, Node.js, AI/LLM & supply chain' },
    { id: 'cms', name: 'CMS & E-Commerce', tagline: 'WordPress, Laravel, Magento, Drupal & PHP security' },
    { id: 'api', name: 'API & Backend Service', tagline: 'CORS, JWT, Rate Limiting, GraphQL & Auth' },
    { id: 'ops', name: 'Ops & System Health', tagline: 'Server health, metrics, actuator, TLS & availability checks' }
  ];

  if (!basePresets.some(p => p.id === 'ops') && state.profiles?.ops) {
    basePresets.push({
      id: 'ops',
      name: 'Ops & System Health',
      tagline: state.profiles.ops.description || 'Server health, metrics, actuator, TLS & availability checks'
    });
  }

  const presets = basePresets;

  container.innerHTML = presets
    .map(preset => {
      const icon = PRESET_ICONS[preset.id] || '🛡️';
      const isActive = preset.id === state.selectedPreset;
      return `
      <div class="preset-card ${isActive ? 'active' : ''}" data-preset-id="${escapeHtml(preset.id)}">
        <div class="preset-header">
          <span class="preset-icon">${icon}</span>
          <span class="preset-radio-indicator"></span>
        </div>
        <h3 class="preset-name">${escapeHtml(preset.name)}</h3>
        <p class="preset-tagline">${escapeHtml(preset.tagline || preset.description || '')}</p>
        <div class="preset-tags">
          <span class="preset-badge">Profile: ${escapeHtml(preset.id)}</span>
        </div>
      </div>
    `;
    })
    .join('');

  container.querySelectorAll('.preset-card').forEach(card => {
    card.addEventListener('click', () => {
      selectPreset(card.getAttribute('data-preset-id'));
    });
  });
}

// ── Execute Scan & Live SSE Streaming ────────────────────────────────────────
async function startScan(options) {
  const btnStart = document.getElementById('btn-start-scan');
  const spinner = document.getElementById('scan-spinner');
  const btnText = document.getElementById('btn-start-text');
  const progressPanel = document.getElementById('scan-progress-panel');
  const liveTargetUrl = document.getElementById('live-target-url');
  const livePhaseBadge = document.getElementById('live-phase-badge');
  const liveProgressFill = document.getElementById('live-progress-fill');
  const liveProgressPct = document.getElementById('live-progress-pct');
  const liveTechChips = document.getElementById('live-tech-chips');
  const livePagesCount = document.getElementById('live-pages-count');
  const liveVulnPill = document.getElementById('live-vuln-pill');
  const liveSuspiciousPill = document.getElementById('live-suspicious-pill');
  const liveSafePill = document.getElementById('live-safe-pill');
  const activityFeed = document.getElementById('live-activity-feed');
  const completeBanner = document.getElementById('scan-complete-banner');

  btnStart.disabled = true;
  spinner.classList.remove('hidden');
  btnText.textContent = 'Scanning in progress...';
  completeBanner.classList.add('hidden');

  progressPanel.classList.remove('hidden');
  progressPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

  liveTargetUrl.textContent = options.target;
  livePhaseBadge.textContent = 'Initializing...';
  liveProgressFill.style.width = '5%';
  liveProgressPct.textContent = '5%';
  livePagesCount.textContent = '1';
  liveTechChips.innerHTML = '<span class="chip-muted">Analyzing technology stack...</span>';
  activityFeed.innerHTML = '';
  hideInlineBanner('live-sse-banner');

  let vulnCount = 0;
  let suspiciousCount = 0;
  let safeCount = 0;
  let eventCounter = 0;
  let streamFinished = false;

  function updateFindingsCounts() {
    liveVulnPill.textContent = `🚨 ${vulnCount} Vulnerable`;
    liveSuspiciousPill.textContent = `⚠️ ${suspiciousCount} Suspicious`;
    liveSafePill.textContent = `✅ ${safeCount} Safe`;
  }
  updateFindingsCounts();

  try {
    const launchData = await apiPost('/api/scan', options);
    state.activeScanId = launchData.scanId;

    if (state.eventSource) {
      state.eventSource.close();
    }

    const sseUrl = `/api/scan/${encodeURIComponent(launchData.scanId)}/stream`;
    const es = new EventSource(sseUrl);
    state.eventSource = es;

    const handleSseMessage = evt => {
      try {
        hideInlineBanner('live-sse-banner');
        const data = JSON.parse(evt.data);
        eventCounter++;
        const counterEl = document.getElementById('live-checks-counter');
        if (counterEl) counterEl.textContent = `${eventCounter} events`;

        if (data.progress !== undefined) {
          liveProgressFill.style.width = `${data.progress}%`;
          liveProgressPct.textContent = `${data.progress}%`;
        }

        if (data.phase) {
          livePhaseBadge.textContent = formatPhaseName(data.phase);
        }

        if (data.type === 'fingerprint') {
          const tags = Array.isArray(data.detectedTags) && data.detectedTags.length > 0
            ? data.detectedTags
            : Array.isArray(data.stack) && data.stack.length > 0
            ? data.stack.map(s => s.tech)
            : [];

          if (tags.length > 0) {
            liveTechChips.innerHTML = tags
              .map(t => {
                const clean = escapeHtml(t);
                const safe = clean.toLowerCase().replace(/[^a-z0-9_-]/gi, '');
                return `<span class="chip chip-${safe}">${clean}</span>`;
              })
              .join('');
          } else {
            liveTechChips.innerHTML = '<span class="chip">Generic Web</span>';
          }

          const apiComm = data.apiCommunication || data.fingerprint?.apiCommunication;
          if (apiComm?.usesApi) {
            const apiChip = document.createElement('span');
            apiChip.className = 'chip chip-api-active';
            apiChip.textContent = '🔌 API Client';
            liveTechChips.appendChild(apiChip);
          }
        }

        if (data.type === 'crawl_complete' || data.type === 'crawl_depth') {
          if (data.pagesFound) {
            livePagesCount.textContent = String(data.pagesFound);
          }
        }

        if (data.type === 'check') {
          if (data.status === 'VULNERABLE') vulnCount++;
          else if (data.status === 'SUSPICIOUS') suspiciousCount++;
          else if (data.status === 'SAFE') safeCount++;
          updateFindingsCounts();
          appendFeedItem(activityFeed, data);
        }

        if (data.type === 'agent' || data.phase === 'agent') {
          appendFeedItem(activityFeed, {
            status: data.status || 'INFO',
            severity: data.severity || 'AGENT',
            title: data.message || data.detail || data.action || 'Agentic verification update',
            target: data.target || options.target
          });
        }

        if (data.type === 'complete' && data.result) {
          streamFinished = true;
          es.close();
          state.eventSource = null;
          state.currentResults = {
            ...data.result,
            scanId: launchData.scanId
          };

          liveProgressFill.style.width = '100%';
          liveProgressPct.textContent = '100%';
          livePhaseBadge.textContent = 'Complete';

          btnStart.disabled = false;
          spinner.classList.add('hidden');
          btnText.textContent = '🚀 Start Security Scan';

          const summaryEl = document.getElementById('scan-complete-summary');
          if (summaryEl && data.result.risk) {
            summaryEl.textContent = `Security Grade: ${data.result.risk.grade} (${data.result.risk.level} Risk) — ${data.result.risk.summary}`;
          }
          completeBanner.classList.remove('hidden');

          renderScanResults(state.currentResults);
          loadHistory();
        }

        if (data.type === 'error') {
          streamFinished = true;
          es.close();
          state.eventSource = null;
          btnStart.disabled = false;
          spinner.classList.add('hidden');
          btnText.textContent = '🚀 Start Security Scan';

          livePhaseBadge.textContent = 'Failed';
          const errDiv = document.createElement('div');
          errDiv.className = 'feed-item danger';
          errDiv.textContent = `Scan failed: ${data.error || 'Unknown error'}`;
          capFeedNodes(activityFeed, 250);
          activityFeed.appendChild(errDiv);
        }
      } catch (err) {
        console.error('Error handling SSE event:', err);
      }
    };

    es.onmessage = handleSseMessage;
    [
      'start',
      'fingerprinting',
      'fingerprint',
      'crawling',
      'crawl_depth',
      'crawl_complete',
      'scanning',
      'check',
      'agent',
      'finalizing',
      'complete',
      'error'
    ].forEach(eventType => {
      es.addEventListener(eventType, handleSseMessage);
    });

    es.onerror = () => {
      if (streamFinished || state.eventSource !== es) return;
      const sseBanner = document.getElementById('live-sse-banner');
      const isClosed = es.readyState === EventSource.CLOSED;
      if (isClosed) {
        es.close();
        state.eventSource = null;
        btnStart.disabled = false;
        spinner.classList.add('hidden');
        btnText.textContent = '🚀 Start Security Scan';
        livePhaseBadge.textContent = 'Disconnected';
      }
      if (sseBanner) {
        sseBanner.className = `feedback-banner ${isClosed ? 'error' : 'warning'}`;
        sseBanner.innerHTML = '';
        const msgSpan = document.createElement('span');
        msgSpan.textContent = isClosed
          ? '⚠️ Live scan stream disconnected. Check server status and retry your scan.'
          : '⚠️ Live scan stream interrupted — reconnecting automatically...';
        sseBanner.appendChild(msgSpan);
        if (isClosed) {
          const retryBtn = document.createElement('button');
          retryBtn.type = 'button';
          retryBtn.className = 'btn-secondary btn-small cve-retry-btn';
          retryBtn.textContent = '↻ Retry Scan';
          retryBtn.addEventListener('click', () => startScan(options));
          sseBanner.appendChild(retryBtn);

          const docBtn = document.createElement('button');
          docBtn.type = 'button';
          docBtn.className = 'btn-secondary btn-small cve-retry-btn';
          docBtn.textContent = '🩺 System Doctor';
          docBtn.addEventListener('click', openSystemDoctorModal);
          sseBanner.appendChild(docBtn);
        }
        sseBanner.classList.remove('hidden');
      }
    };
  } catch (err) {
    btnStart.disabled = false;
    spinner.classList.add('hidden');
    btnText.textContent = '🚀 Start Security Scan';

    const banner = document.getElementById('url-validation-banner');
    const bannerText = document.getElementById('url-validation-text');
    if (bannerText) {
      bannerText.innerHTML = '';
      const msgSpan = document.createElement('span');
      msgSpan.textContent = `Could not start scan: ${err.message} `;
      bannerText.appendChild(msgSpan);
      const docLink = document.createElement('button');
      docLink.type = 'button';
      docLink.className = 'btn-secondary btn-small inline-doctor-link';
      docLink.textContent = '🩺 Diagnose Connection';
      docLink.addEventListener('click', openSystemDoctorModal);
      bannerText.appendChild(docLink);
    }
    banner?.classList.remove('hidden');
  }
}

function formatPhaseName(phase) {
  switch (phase) {
    case 'initializing': return '🔍 Initializing';
    case 'fingerprinting': return '🧠 Tech Fingerprint';
    case 'crawling': return '🕸️ Crawling Pages';
    case 'scanning': return '⚙️ Running Checks';
    case 'agent': return '🤖 Agentic Verification';
    case 'finalizing': return '📊 Finalizing Analysis';
    case 'completed': return '✅ Completed';
    case 'failed': return '❌ Failed';
    default: return phase;
  }
}

const MAX_FEED_NODES = 250;

function capFeedNodes(feedContainer, maxNodes = MAX_FEED_NODES) {
  if (!feedContainer) return;
  while (feedContainer.children.length >= maxNodes) {
    feedContainer.removeChild(feedContainer.firstElementChild);
  }
}

function appendFeedItem(feedContainer, check) {
  if (!feedContainer) return;
  capFeedNodes(feedContainer, MAX_FEED_NODES);
  const item = document.createElement('div');
  const statusClass =
    check.status === 'VULNERABLE'
      ? 'danger'
      : check.status === 'SUSPICIOUS'
      ? 'warning'
      : 'safe';

  item.className = `feed-item ${statusClass}`;

  const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const icon =
    check.status === 'VULNERABLE'
      ? '🚨'
      : check.status === 'SUSPICIOUS'
      ? '⚠️'
      : check.severity === 'AGENT'
      ? '🤖'
      : '✅';

  item.innerHTML = `
    <span class="feed-time">${escapeHtml(time)}</span>
    <span class="feed-status">${icon} [${escapeHtml(check.severity || 'NONE')}]</span>
    <span class="feed-text">${escapeHtml(check.title || check.name)} → ${escapeHtml(check.target)}</span>
  `;

  feedContainer.appendChild(item);
  feedContainer.scrollTop = feedContainer.scrollHeight;
}

// ── Tab 2: Scan Results & Evidence View ──────────────────────────────────────
function initResultsToolbar() {
  document.querySelectorAll('[data-filter-status]').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('[data-filter-status]').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      state.resultsFilters.status = btn.getAttribute('data-filter-status');
      filterAndRenderFindings();
    });
  });

  const severitySelect = document.getElementById('filter-severity-select');
  severitySelect.addEventListener('change', () => {
    state.resultsFilters.severity = severitySelect.value;
    filterAndRenderFindings();
  });

  const searchInput = document.getElementById('findings-search');
  searchInput.addEventListener('input', () => {
    state.resultsFilters.search = searchInput.value.trim().toLowerCase();
    filterAndRenderFindings();
  });

  const btnToggleMode = document.getElementById('btn-toggle-view-mode');
  btnToggleMode.addEventListener('click', () => {
    state.viewMode = state.viewMode === 'regular' ? 'developer' : 'regular';
    const modeIcon = document.getElementById('mode-toggle-icon');
    const modeText = document.getElementById('mode-toggle-text');

    if (state.viewMode === 'developer') {
      modeIcon.textContent = '💻';
      modeText.textContent = 'Developer View';
      btnToggleMode.classList.add('dev-mode');
    } else {
      modeIcon.textContent = '👤';
      modeText.textContent = 'Regular Person View';
      btnToggleMode.classList.remove('dev-mode');
    }

    filterAndRenderFindings();
  });

  document.getElementById('btn-export-html').addEventListener('click', downloadHtmlReport);
  document.getElementById('btn-export-json').addEventListener('click', downloadJsonReport);
  document.getElementById('btn-export-markdown')?.addEventListener('click', () => exportScanFormat('markdown'));
  document.getElementById('btn-export-csv')?.addEventListener('click', () => exportScanFormat('csv'));
  document.getElementById('btn-export-sarif')?.addEventListener('click', () => exportScanFormat('sarif'));
  document.getElementById('btn-generate-ai-summary')?.addEventListener('click', generateAiSummaryRoadmap);
  document.getElementById('btn-analyze-results-api')?.addEventListener('click', generateResultsApiAiAnalysis);
}

function initEvidenceDrawer() {
  const backdrop = document.getElementById('evidence-drawer-backdrop');
  if (!backdrop) return;
  backdrop.addEventListener('click', e => {
    if (e.target === backdrop) {
      closeEvidenceDrawer();
    }
  });
}

function closeEvidenceDrawer() {
  const backdrop = document.getElementById('evidence-drawer-backdrop');
  if (backdrop) backdrop.classList.add('hidden');
}

function openEvidenceDrawer(finding) {
  const backdrop = document.getElementById('evidence-drawer-backdrop');
  const body = document.getElementById('evidence-drawer-body');
  if (!backdrop || !body) return;

  backdrop.classList.remove('hidden');
  renderEvidenceViewer(body, finding, {
    stack: state.currentResults?.stacks?.[0] || null,
    audience: state.viewMode === 'developer' ? 'pro' : 'beginner',
    onClose: closeEvidenceDrawer
  });
}

function groupFindingsClient(results = []) {
  if (!Array.isArray(results)) return [];

  const groups = new Map();

  for (const r of results) {
    if (!r || typeof r !== 'object') continue;

    const checkKey = String(r.checkId || r.name || 'unknown').toLowerCase().trim();
    const status = r.status || 'ERROR';
    const severity = r.severity || 'NONE';
    const groupKey = `${checkKey}::${status}::${severity}`;

    const pageUrl = r.target || '';

    if (!groups.has(groupKey)) {
      const pages = Array.isArray(r.pages) && r.pages.length
        ? [...r.pages]
        : (pageUrl ? [pageUrl] : []);
      const cveIds = collectCveIds(r);
      groups.set(groupKey, {
        ...r,
        ...(cveIds.length ? { cveIds } : {}),
        pages,
        pageCount: pages.length
      });
    } else {
      const existing = groups.get(groupKey);
      if (pageUrl && !existing.pages.includes(pageUrl)) {
        existing.pages.push(pageUrl);
        existing.pageCount = existing.pages.length;
      }
      if (!existing.detail && r.detail) existing.detail = r.detail;
      if (!existing.path && r.path) existing.path = r.path;
      if (!existing.reason && r.reason) existing.reason = r.reason;
      if (!existing.fix && r.fix) existing.fix = r.fix;
      if (!existing.reproduction && r.reproduction) existing.reproduction = r.reproduction;
      if (r.reproVerified === true) existing.reproVerified = true;
      if (Array.isArray(r.files) && r.files.length > 0) {
        const seenFiles = new Set((existing.files || []).map(f => f?.path || f?.url));
        const mergedFiles = [...(Array.isArray(existing.files) ? existing.files : [])];
        for (const f of r.files) {
          const key = f?.path || f?.url;
          if (key && !seenFiles.has(key)) {
            seenFiles.add(key);
            mergedFiles.push(f);
          }
        }
        existing.files = mergedFiles;
      }
      if (Array.isArray(r.evidenceQuotes) && r.evidenceQuotes.length > 0) {
        const mergedQuotes = new Set([...(Array.isArray(existing.evidenceQuotes) ? existing.evidenceQuotes : []), ...r.evidenceQuotes]);
        existing.evidenceQuotes = Array.from(mergedQuotes).slice(0, 6);
      }
      if (existing.cvssScore === undefined && r.cvssScore !== undefined) existing.cvssScore = r.cvssScore;
      const mergedCves = Array.from(new Set([...collectCveIds(existing), ...collectCveIds(r)]));
      if (mergedCves.length) existing.cveIds = mergedCves;
    }
  }

  const STATUS_RANK = { VULNERABLE: 0, SUSPICIOUS: 1, ERROR: 2, SAFE: 3 };
  const SEV_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, NONE: 4 };

  return Array.from(groups.values()).sort((a, b) => {
    const sr = (STATUS_RANK[a.status] ?? 4) - (STATUS_RANK[b.status] ?? 4);
    if (sr !== 0) return sr;
    return (SEV_RANK[a.severity] ?? 5) - (SEV_RANK[b.severity] ?? 5);
  });
}

function renderPagesListHtml(pages = []) {
  if (!Array.isArray(pages) || pages.length === 0) return '';

  const MAX_VISIBLE = 6;
  const visible = pages.slice(0, MAX_VISIBLE);
  const remaining = pages.length - visible.length;

  const itemsHtml = visible
    .map(p => `<li class="page-item-li"><code>${escapeHtml(p)}</code></li>`)
    .join('');

  const extraHtml = remaining > 0
    ? `<details class="pages-extra-details">
         <summary>+ ${remaining} more page${remaining > 1 ? 's' : ''}</summary>
         <ul class="pages-extra-list">
           ${pages.slice(MAX_VISIBLE).map(p => `<li class="page-item-li"><code>${escapeHtml(p)}</code></li>`).join('')}
         </ul>
       </details>`
    : '';

  return `
    <div class="finding-pages-box">
      <div class="finding-pages-heading">Pages (${pages.length}):</div>
      <ul class="finding-pages-list">
        ${itemsHtml}
      </ul>
      ${extraHtml}
    </div>
  `;
}

function collectCveIds(item) {
  if (!item || typeof item !== 'object') return [];
  const enrich = item.enrichment || {};
  const meta = item.meta || {};
  const rawList = [
    ...(Array.isArray(item.cveIds) ? item.cveIds : item.cveIds ? [item.cveIds] : []),
    ...(item.cve ? [item.cve] : []),
    ...(Array.isArray(enrich.cveIds) ? enrich.cveIds : enrich.cveIds ? [enrich.cveIds] : []),
    ...(enrich.cve ? [enrich.cve] : []),
    ...(Array.isArray(meta.cveIds) ? meta.cveIds : meta.cveIds ? [meta.cveIds] : []),
    ...(meta.cve ? [meta.cve] : [])
  ];
  const seen = new Set();
  const out = [];
  for (const val of rawList) {
    const clean = String(val || '').trim().toUpperCase();
    if (clean && !seen.has(clean)) {
      seen.add(clean);
      out.push(clean);
    }
  }
  return out;
}

function renderEnrichmentBadgesHtml(item) {
  const enrich = item.enrichment || {};
  const meta = item.meta || {};
  const cwe = item.cwe || enrich.cwe || meta.cwe || '';
  const owasp = item.owasp || enrich.owasp || meta.owasp || '';
  const cvss = item.cvssScore ?? item.cvss ?? enrich.cvssScore ?? enrich.cvss ?? meta.cvssScore ?? meta.cvss ?? null;
  const cveIds = collectCveIds(item);

  const badges = [];
  if (cwe) {
    badges.push(`<span class="enrich-badge enrich-cwe">${escapeHtml(cwe)}</span>`);
  }
  if (owasp) {
    badges.push(`<span class="enrich-badge enrich-owasp">${escapeHtml(owasp)}</span>`);
  }
  if (cvss !== null && cvss !== undefined && cvss !== '') {
    const score = typeof cvss === 'object' ? cvss.score ?? cvss.baseScore : cvss;
    if (score !== undefined && score !== null) {
      badges.push(`<span class="enrich-badge enrich-cvss">CVSS ${escapeHtml(score)}</span>`);
    }
  }
  for (const cveId of cveIds.slice(0, 4)) {
    badges.push(`<span class="enrich-badge enrich-cve">${escapeHtml(cveId)}</span>`);
  }
  if (cveIds.length > 4) {
    badges.push(`<span class="enrich-badge enrich-cve">+${cveIds.length - 4} CVEs</span>`);
  }
  return badges.join('');
}

function renderResultsCveCoverageBanner(cveCoverage) {
  const banner = document.getElementById('results-cve-coverage-banner');
  const summaryEl = document.getElementById('results-cve-coverage-summary');
  const kpisEl = document.getElementById('results-cve-coverage-kpis');
  const missingEl = document.getElementById('results-cve-coverage-missing');
  if (!banner) return;

  if (!cveCoverage || typeof cveCoverage !== 'object') {
    banner.classList.add('hidden');
    return;
  }

  const summary = cveCoverage.summary || {};
  const total = Number(summary.totalAdvisories ?? 0);
  const covered = Number(summary.coveredCount ?? 0);
  const partial = Number(summary.partialCount ?? 0);
  const missingCount = Number(summary.missingCount ?? 0);
  const kevMissing = Number(summary.kevMissing ?? 0);
  const pct = Number(summary.coveragePercent ?? (total === 0 ? 100 : 0));
  const tags = Array.isArray(cveCoverage.filter?.techTags) ? cveCoverage.filter.techTags : [];

  if (summaryEl) {
    summaryEl.textContent = tags.length > 0
      ? `Detected stack (${tags.join(', ')}): ${covered}/${total} known advisories covered (${pct}%)${partial ? `, ${partial} partial` : ''}.`
      : `Catalog advisory coverage: ${covered}/${total} advisories covered (${pct}%).`;
  }

  if (kpisEl) {
    kpisEl.innerHTML = `
      <span class="ev-pill">Coverage: <strong>${pct}%</strong></span>
      <span class="ev-pill">Covered: <strong>${covered}/${total}</strong></span>
      <span class="ev-pill ${missingCount > 0 ? 'kev-badge' : ''}">Missing: <strong>${missingCount}</strong></span>
      ${kevMissing > 0 ? `<span class="kev-badge">KEV Missing: ${kevMissing}</span>` : ''}
    `;
  }

  if (missingEl) {
    const missingItems = Array.isArray(cveCoverage.missing) ? cveCoverage.missing : [];
    if (missingItems.length > 0) {
      const top = missingItems.slice(0, 6);
      missingEl.innerHTML = `
        <span class="cve-missing-label">Uncovered advisories:</span>
        ${top.map(m => `<span class="enrich-badge enrich-cve">${escapeHtml(m.cveId || m.id)}</span>`).join('')}
        ${missingItems.length > 6 ? `<span class="form-hint">+${missingItems.length - 6} more</span>` : ''}
      `;
      missingEl.classList.remove('hidden');
    } else {
      missingEl.classList.add('hidden');
    }
  }

  banner.classList.remove('hidden');
}

export function renderScanResults(resultData) {
  const emptyState = document.getElementById('results-empty-state');
  const resultsContent = document.getElementById('results-content');

  if (!resultData || !Array.isArray(resultData.results)) {
    emptyState.classList.remove('hidden');
    resultsContent.classList.add('hidden');
    return;
  }

  emptyState.classList.add('hidden');
  resultsContent.classList.remove('hidden');

  const risk = resultData.risk || { grade: 'A+', score: 0, level: 'LOW', summary: 'All clear.' };
  const results = resultData.results;
  const grouped = groupFindingsClient(results);
  resultData.groupedResults = grouped;

  const gradeCircle = document.getElementById('result-grade-circle');
  const gradeLetter = document.getElementById('result-grade-letter');
  const riskPill = document.getElementById('result-risk-pill');
  const scoreText = document.getElementById('result-score-text');

  const safeGradeClass = String(risk.grade || 'a').toLowerCase().replace('+', 'plus').replace(/[^a-z0-9_-]/g, '');
  gradeCircle.className = `grade-circle grade-${safeGradeClass}`;
  gradeLetter.textContent = risk.grade || 'A+';

  const safeRiskLevel = String(risk.level || 'low').toLowerCase().replace(/[^a-z0-9_-]/g, '');
  riskPill.className = `risk-pill ${safeRiskLevel}`;
  riskPill.textContent = `${risk.level || 'LOW'} RISK`;
  scoreText.textContent = `Score: ${Number(risk.score) || 0} / 60`;

  const targetName = document.getElementById('result-target-name');
  const summaryText = document.getElementById('result-summary-text');
  const dateText = document.getElementById('result-date-text');
  const historyText = document.getElementById('result-history-file-text');

  const primaryTarget = results[0]?.target || 'Target Website';
  targetName.textContent = primaryTarget;
  summaryText.textContent = risk.summary || 'Security scan completed successfully.';
  dateText.textContent = `Audited: ${new Date(resultData.completedAt || Date.now()).toLocaleString()}`;
  if (resultData.htmlReportFile) {
    historyText.textContent = `Saved Report: ${resultData.htmlReportFile}`;
  } else if (resultData.historyFile) {
    historyText.textContent = `Archived: ${resultData.historyFile}`;
  } else {
    historyText.textContent = 'Saved in .secscan-history/ & reports/';
  }

  const vulns = grouped.filter(r => r.status === 'VULNERABLE');
  const suspicious = grouped.filter(r => r.status === 'SUSPICIOUS');
  const safe = grouped.filter(r => r.status === 'SAFE');
  const uniquePages = new Set(results.map(r => r.target).filter(Boolean));

  document.getElementById('metric-vulns').textContent = String(vulns.length);
  document.getElementById('metric-suspicious').textContent = String(suspicious.length);
  document.getElementById('metric-safe').textContent = String(safe.length);
  document.getElementById('metric-pages').textContent = String(resultData.pagesCount || uniquePages.size || 1);

  document.getElementById('count-all').textContent = String(grouped.length);
  document.getElementById('count-vuln').textContent = String(vulns.length);
  document.getElementById('count-suspicious').textContent = String(suspicious.length);
  document.getElementById('count-safe').textContent = String(safe.length);

  const stackCard = document.getElementById('results-stack-card');
  if (stackCard) {
    if (Array.isArray(resultData.stacks) && resultData.stacks.length > 0) {
      const primaryStack = resultData.stacks[0];
      const summaryEl = document.getElementById('results-stack-summary');
      const counterEl = document.getElementById('results-stack-counter');
      const badgesEl = document.getElementById('results-stack-badges');

      if (summaryEl) {
        summaryEl.textContent = primaryStack.summary || 'Generic Web Application';
      }

      const activeCount = Number(primaryStack.activeChecksCount) || grouped.length;
      const skippedCount = Number(primaryStack.skippedChecksCount) || 0;

      if (counterEl) {
        counterEl.innerHTML = `<strong>${activeCount} Relevant Checks Executed · ${skippedCount} Irrelevant Framework Checks Skipped</strong>`;
      }

      const tags = Array.isArray(primaryStack.detectedTags) && primaryStack.detectedTags.length > 0
        ? primaryStack.detectedTags
        : Array.isArray(primaryStack.stack) && primaryStack.stack.length > 0
        ? primaryStack.stack.map(s => s.tech)
        : ['generic'];

      if (badgesEl) {
        badgesEl.innerHTML = tags.map(tag => {
          const cleanTag = escapeHtml(String(tag).trim());
          const safeClass = cleanTag.toLowerCase().replace(/[^a-z0-9_-]/gi, '');
          return `<span class="tech-badge tech-tag-${safeClass}">${cleanTag}</span>`;
        }).join('');
      }

      stackCard.classList.remove('hidden');
    } else {
      stackCard.classList.add('hidden');
    }
  }

  const apiCard = document.getElementById('results-api-card');
  const apiSummary = document.getElementById('results-api-summary');
  const apiEndpoints = document.getElementById('results-api-endpoints');
  const btnAnalyzeResults = document.getElementById('btn-analyze-results-api');
  const resultsAiOutput = document.getElementById('results-api-ai-output');

  if (resultsAiOutput) {
    resultsAiOutput.classList.add('hidden');
    resultsAiOutput.innerHTML = '';
  }

  const apiComm = resultData.apiCommunication || resultData.stacks?.[0]?.apiCommunication || null;
  if (apiCard) {
    if (apiComm && apiComm.usesApi) {
      if (apiSummary) {
        apiSummary.textContent = apiComm.summary || `Detected ${apiComm.architecture || 'SPA API'} (${(apiComm.clients || []).join(', ') || 'HTTP API'}) with ${(apiComm.sameOriginEndpoints || []).length} same-origin route(s) and ${(apiComm.externalApiOrigins || []).length} external API origin(s).`;
      }
      renderApiCommunicationSection({
        statusBadgeEl: null,
        detailsEl: null,
        endpointsEl: apiEndpoints,
        analyzeBtnEl: btnAnalyzeResults,
        apiComm
      });
      apiCard.classList.remove('hidden');
    } else {
      apiCard.classList.add('hidden');
    }
  }

  const aiSummaryBox = document.getElementById('ai-summary-container');
  if (aiSummaryBox) {
    aiSummaryBox.classList.add('hidden');
    aiSummaryBox.innerHTML = '';
  }

  renderResultsCveCoverageBanner(resultData.cveCoverage);
  renderPriorityActionPlan(vulns, suspicious);
  filterAndRenderFindings();
}

function buildCompactSummaryPayload(sr) {
  const src = sr && typeof sr === 'object' ? sr : {};
  const all = Array.isArray(src.results) ? src.results : [];
  const compactFindings = all
    .filter(f => f && String(f.status || '').toUpperCase() !== 'SAFE')
    .slice(0, 50)
    .map(f => ({
      checkId: f.checkId || f.name,
      name: f.name,
      title: f.title,
      status: f.status,
      severity: f.severity,
      cvssScore: f.cvssScore,
      cwe: f.cwe,
      target: f.target
    }));
  return {
    targets: Array.isArray(src.targets) ? src.targets.slice(0, 10) : [],
    stacks: src.stacks?.primary ? { primary: src.stacks.primary } : null,
    cveCoverage: src.cveCoverage?.summary ? { summary: src.cveCoverage.summary } : null,
    results: compactFindings
  };
}

async function generateAiSummaryRoadmap() {
  if (!state.currentResults?.results) return;
  const container = document.getElementById('ai-summary-container');
  const btn = document.getElementById('btn-generate-ai-summary');
  if (!container) return;

  const audience = state.viewMode === 'developer' ? 'pro' : 'beginner';
  const scanId = state.currentResults.scanId || state.currentResults.historyFile || state.activeScanId || undefined;

  if (btn) {
    btn.disabled = true;
    btn.textContent = '🤖 Generating Roadmap...';
  }
  container.classList.remove('hidden');
  container.innerHTML = '<div class="empty-muted">Generating prioritized AI Action Roadmap...</div>';

  try {
    const payload = scanId
      ? { scanId, audience }
      : { scanResult: buildCompactSummaryPayload(state.currentResults), audience };
    const data = await apiPost('/api/ai/summary', payload);
    renderAiSummaryRoadmap(container, data);
  } catch (err) {
    container.innerHTML = `<div class="feedback-banner error">Failed to generate AI Action Roadmap: ${escapeHtml(err.message)}</div>`;
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = '🤖 AI Action Roadmap';
    }
  }
}

function renderAiSummaryRoadmap(container, data) {
  const isAi = data?.mode === 'ai';
  const modeLabel = isAi
    ? `🤖 AI Powered${data.provider || data.model ? ` (${[data.provider, data.model].filter(Boolean).join(' / ')})` : ''}`
    : '📘 Built-in Playbook';
  const topActions = Array.isArray(data?.topActions) ? data.topActions : [];
  const checklist = Array.isArray(data?.ownerChecklist) ? data.ownerChecklist : [];
  const handoffPrompt = data?.developerHandoffPrompt || '';

  container.innerHTML = `
    <div class="ai-summary-card">
      <div class="ai-fix-header">
        <div class="ai-fix-badges">
          <span class="ev-pill ${isAi ? 'ai-mode-badge' : 'playbook-mode-badge'}">${escapeHtml(modeLabel)}</span>
          <span class="ev-pill">${data?.audience === 'pro' ? 'Developer / Pro' : 'Owner / Beginner'}</span>
        </div>
        ${data?.fallbackReason ? `<span class="form-hint">Fallback: ${escapeHtml(data.fallbackReason)}</span>` : ''}
      </div>

      ${data?.headline ? `<h4 class="ai-summary-headline">${escapeHtml(data.headline)}</h4>` : ''}
      ${data?.summary ? `<p class="ai-summary-text">${escapeHtml(data.summary)}</p>` : ''}

      ${topActions.length > 0 ? `
        <div class="ai-fix-section">
          <strong>Prioritized Top Actions</strong>
          <ol class="ai-roadmap-list">
            ${topActions.map(a => `
              <li class="ai-roadmap-item">
                <div class="ai-roadmap-title"><strong>#${Number(a.priority || 1)} ${escapeHtml(a.title || '')}</strong></div>
                ${a.plainWhy ? `<div class="ai-roadmap-why">${escapeHtml(a.plainWhy)}</div>` : ''}
                ${a.firstStep ? `<div class="ai-roadmap-step"><span>Next Step:</span> ${escapeHtml(a.firstStep)}</div>` : ''}
                ${a.verifyCommand ? `<div class="ai-roadmap-verify"><code>${escapeHtml(a.verifyCommand)}</code></div>` : ''}
              </li>
            `).join('')}
          </ol>
        </div>
      ` : ''}

      ${checklist.length > 0 ? `
        <div class="ai-fix-section">
          <strong>Owner Checklist</strong>
          <ul class="ai-checklist">
            ${checklist.map(item => `<li>${escapeHtml(item)}</li>`).join('')}
          </ul>
        </div>
      ` : ''}

      ${handoffPrompt ? `
        <details class="ai-fix-prompt-details">
          <summary>💬 Developer Handoff Prompt</summary>
          <div class="ai-fix-code-head">
            <span class="form-hint">Share this complete remediation brief with your developer or coding agent</span>
            <button type="button" class="btn-secondary btn-small" id="btn-copy-ai-handoff">📋 Copy Handoff Prompt</button>
          </div>
          <pre class="code-block ai-fix-code"><code>${escapeHtml(handoffPrompt)}</code></pre>
        </details>
      ` : ''}
    </div>
  `;

  const copyBtn = document.getElementById('btn-copy-ai-handoff');
  if (copyBtn && handoffPrompt) {
    copyBtn.addEventListener('click', async () => {
      try {
        await navigator.clipboard?.writeText(handoffPrompt);
        copyBtn.textContent = '✓ Copied';
        setTimeout(() => {
          copyBtn.textContent = '📋 Copy Handoff Prompt';
        }, 1800);
      } catch {
        showInlineBanner('results-status-banner', 'Clipboard unavailable. Select and copy the prompt manually.', false);
      }
    });
  }
}

function renderPriorityActionPlan(vulns, suspicious) {
  const container = document.getElementById('priority-cards-container');
  const section = document.getElementById('action-plan-section');
  if (!container || !section) return;

  const priorityItems = [...vulns, ...suspicious].slice(0, 3);

  if (priorityItems.length === 0) {
    container.innerHTML = `
      <div class="priority-card priority-safe-card">
        <div class="priority-header">
          <span class="priority-rank">No Urgent Issues</span>
          <span class="priority-severity priority-safe-badge">SAFE</span>
        </div>
        <h4 class="priority-title">🎉 Great job! Your website passed all critical checks.</h4>
        <p class="priority-why-text">No immediate vulnerabilities require remediation. Regularly rerun this scan to maintain your high security grade.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = priorityItems
    .map((item, idx) => {
      const meta = item.meta || {};
      const title = meta.title || item.name;
      const severityClass = escapeHtml(String(item.severity || 'medium').toLowerCase().replace(/[^a-z0-9_-]/g, ''));
      const why = meta.whyItMatters || 'Exposes internal system operations or sensitive application behavior to unauthorized third parties.';
      const fix = item.fix || meta.defaultFix || 'Apply recommended server hardening and security patches.';
      const pages = Array.isArray(item.pages) && item.pages.length ? item.pages : (item.target ? [item.target] : []);

      return `
      <div class="priority-card ${severityClass}">
        <div class="priority-header">
          <span class="priority-rank">#${idx + 1} Priority Action</span>
          <span class="priority-severity ${severityClass}">${escapeHtml(item.severity || 'HIGH')}</span>
        </div>
        <h4 class="priority-title">${escapeHtml(title)}</h4>
        ${renderPagesListHtml(pages)}
        <div class="priority-body-section">
          <span class="priority-section-label">Why This Matters</span>
          <p class="priority-why-text">${escapeHtml(why)}</p>
        </div>
        <div class="priority-body-section">
          <span class="priority-section-label">Recommended Fix</span>
          <div class="priority-fix-box">💡 ${escapeHtml(fix)}</div>
        </div>
      </div>
    `;
    })
    .join('');
}

function renderMatchedEvidenceHtml(item) {
  if (!item) return '';
  const files = Array.isArray(item.files) && item.files.length > 0
    ? item.files
    : (Array.isArray(item.findings) ? item.findings : []);
  const quotes = Array.isArray(item.evidenceQuotes) ? item.evidenceQuotes : [];
  const missing = Array.isArray(item.missing) ? item.missing : [];
  if (files.length === 0 && quotes.length === 0 && missing.length === 0) return '';

  const filesHtml = files.length > 0
    ? `<div class="finding-why-box"><strong>📂 Matched Paths / Evidence (${files.length}):</strong> ${files.slice(0, 8).map(f => `<code>${escapeHtml(f.path || f.url || f.name || '')}</code>${f.status ? ` (HTTP ${escapeHtml(f.status)})` : ''}${f.matchedSignal ? ` — ${escapeHtml(f.matchedSignal)}` : (f.detail || f.issue || f.reason ? ` — ${escapeHtml(f.detail || f.issue || f.reason)}` : '')}${f.preview ? ` · <code>${escapeHtml(f.preview)}</code>` : ''}`).join('<br>')}</div>`
    : '';
  const missingHtml = missing.length > 0
    ? `<div class="finding-why-box"><strong>⚠️ Missing Security Headers (${missing.length}):</strong> ${missing.map(m => `<code>${escapeHtml(m)}</code>`).join(', ')}</div>`
    : '';
  const quotesHtml = quotes.length > 0
    ? `<div class="finding-why-box"><strong>🧾 Verbatim Proof:</strong> <code>${escapeHtml(quotes.slice(0, 3).join(' | '))}</code></div>`
    : '';
  return `${filesHtml}${missingHtml}${quotesHtml}`;
}

function renderReproductionBoxHtml(item, idx = null) {
  if (!item || item.status === 'SAFE') return '';
  const repro = item.reproduction;
  const target = Array.isArray(item.pages) && item.pages.length ? item.pages[0] : (item.target || '');
  const steps = Array.isArray(repro?.steps) && repro.steps.length
    ? repro.steps
    : (target ? [`Inspect or replay request against ${target}${item.path || ''}.`, `Confirm indicator (${item.detail || item.reason || item.status}).`, 'Apply remediation and re-run check or click Receipts & Retest to verify SAFE.'] : []);
  const curl = repro?.curl || '';
  if (!steps.length && !curl) return '';

  const isConfirmed = Boolean(repro?.reproducible || item.reproVerified);
  const reproBadge = isConfirmed
    ? '<span class="category-tag" style="color:#3fb950;border-color:rgba(63,185,80,0.4)">✓ Confirmed Reproducible</span>'
    : '<span class="category-tag">Trigger Trace</span>';

  return `
    <div class="finding-repro-box">
      <div class="finding-repro-header">
        <strong>🔁 How to Reproduce &amp; Verify Fix ${reproBadge}</strong>
        ${curl && idx !== null ? `<button type="button" class="btn-secondary btn-small btn-copy-repro" data-copy-repro-idx="${idx}">📋 Copy Curl</button>` : ''}
      </div>
      ${repro?.observedSignal ? `<div class="finding-repro-signal"><span>Observed:</span> <code>${escapeHtml(repro.observedSignal)}</code></div>` : ''}
      ${steps.length ? `<ol class="finding-repro-steps">${steps.map(s => `<li>${escapeHtml(s)}</li>`).join('')}</ol>` : ''}
      ${curl ? `<pre class="finding-repro-cmd"><code>${escapeHtml(curl)}</code></pre>` : ''}
    </div>
  `;
}

function filterAndRenderFindings() {
  const container = document.getElementById('findings-container');
  const countEl = document.getElementById('visible-findings-count');
  if (!container || !state.currentResults?.results) return;

  const groupedList = state.currentResults.groupedResults || groupFindingsClient(state.currentResults.results);
  const { status, severity, search } = state.resultsFilters;
  const isDevMode = state.viewMode === 'developer';

  const filtered = groupedList.filter(r => {
    if (status !== 'all' && r.status !== status) return false;
    if (severity !== 'all' && r.severity !== severity) return false;
    if (search) {
      const title = (r.meta?.title || '').toLowerCase();
      const name = (r.name || '').toLowerCase();
      const pagesStr = (Array.isArray(r.pages) ? r.pages.join(' ') : (r.target || '')).toLowerCase();
      const cat = (r.meta?.category || '').toLowerCase();
      const cwe = (r.cwe || r.enrichment?.cwe || '').toLowerCase();
      const cves = collectCveIds(r).join(' ').toLowerCase();
      if (!title.includes(search) && !name.includes(search) && !pagesStr.includes(search) && !cat.includes(search) && !cwe.includes(search) && !cves.includes(search)) {
        return false;
      }
    }
    return true;
  });

  state.renderedFindings = filtered;
  if (countEl) countEl.textContent = String(filtered.length);

  if (filtered.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <span class="empty-icon">🔍</span>
        <h3 class="empty-title">No matching checks found</h3>
        <p class="empty-text">Try adjusting your status, severity, or search filters above.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = filtered
    .map((item, idx) => {
      const meta = item.meta || {};
      const statusLower = escapeHtml(String(item.status || 'safe').toLowerCase().replace(/[^a-z0-9_-]/g, ''));
      const sevLower = escapeHtml(String(item.severity || 'none').toLowerCase().replace(/[^a-z0-9_-]/g, ''));
      const title = meta.title || item.name;
      const pages = Array.isArray(item.pages) && item.pages.length ? item.pages : (item.target ? [item.target] : []);
      const pagesBox = renderPagesListHtml(pages);
      const enrichBadges = renderEnrichmentBadgesHtml(item);

      let detailContent = '';
      if (!isDevMode) {
        const explanation = meta.plainExplanation || 'Checks for standard security compliance on this route.';
        const why = meta.whyItMatters;
        const fix = item.fix || meta.defaultFix;

        const matchedEvidenceBox = renderMatchedEvidenceHtml(item);
        const reproBox = renderReproductionBoxHtml(item, idx);

        detailContent = `
        <div class="finding-regular-view">
          ${pagesBox}
          ${item.detail ? `<div class="finding-why-box"><strong>Detected:</strong> ${escapeHtml(item.detail)}</div>` : ''}
          <p class="finding-explanation">${escapeHtml(explanation)}</p>
          ${why ? `<div class="finding-why-box"><strong>Why it matters:</strong> ${escapeHtml(why)}</div>` : ''}
          ${matchedEvidenceBox}
          ${reproBox}
          ${fix && item.status !== 'SAFE' ? `<div class="finding-fix-box"><strong>💡 How to fix:</strong> ${escapeHtml(fix)}</div>` : ''}
        </div>
      `;
      } else {
        const matchedEvidenceBox = renderMatchedEvidenceHtml(item);
        const reproBox = renderReproductionBoxHtml(item, idx);
        detailContent = `
        <div class="finding-developer-view">
          <div class="dev-row"><span class="dev-label">Check ID:</span><span class="dev-val">${escapeHtml(item.name)}</span></div>
          ${pagesBox}
          <div class="dev-row"><span class="dev-label">Severity:</span><span class="dev-val">${escapeHtml(item.severity || 'NONE')}</span></div>
          ${item.detail ? `<div class="dev-row"><span class="dev-label">Detail:</span><span class="dev-val">${escapeHtml(item.detail)}</span></div>` : ''}
          ${item.path ? `<div class="dev-row"><span class="dev-label">Path:</span><span class="dev-val">${escapeHtml(item.path)}</span></div>` : ''}
          ${item.reason ? `<div class="dev-row"><span class="dev-label">Reason:</span><span class="dev-val">${escapeHtml(item.reason)}</span></div>` : ''}
          ${matchedEvidenceBox}
          ${reproBox}
          ${item.fix ? `<div class="dev-row"><span class="dev-label">Fix Hint:</span><span class="dev-val">${escapeHtml(item.fix)}</span></div>` : ''}
        </div>
      `;
      }

      return `
      <div class="finding-card ${statusLower}">
        <div class="finding-top-row">
          <div class="finding-title-group">
            <span class="finding-status-badge ${statusLower}">${escapeHtml(item.status)}</span>
            <span class="finding-title">${escapeHtml(title)}</span>
          </div>
          <div class="finding-meta-badges">
            <span class="severity-pill ${sevLower}">${escapeHtml(item.severity || 'NONE')}</span>
            ${enrichBadges}
            <span class="category-tag">${pages.length} page${pages.length === 1 ? '' : 's'}</span>
            ${meta.category ? `<span class="category-tag">${escapeHtml(meta.category)}</span>` : ''}
            ${item.status !== 'SAFE' ? `<button type="button" class="btn-secondary btn-small btn-ai-fix" data-ai-fix-idx="${idx}">🤖 AI Fix Solution</button>` : ''}
            <button type="button" class="btn-secondary btn-small btn-receipts-retest" data-finding-idx="${idx}">
              🧾 Receipts &amp; Retest
            </button>
          </div>
        </div>
        ${detailContent}
        ${item.status !== 'SAFE' ? `<div class="ai-fix-slot hidden" data-ai-fix-slot="${idx}"></div>` : ''}
      </div>
    `;
    })
    .join('');

  container.querySelectorAll('.btn-ai-fix').forEach(btn => {
    btn.addEventListener('click', async () => {
      const idx = Number(btn.getAttribute('data-ai-fix-idx'));
      const finding = state.renderedFindings[idx];
      const slot = container.querySelector(`.ai-fix-slot[data-ai-fix-slot="${idx}"]`);
      if (!finding || !slot) return;

      btn.disabled = true;
      btn.textContent = '🤖 Generating...';
      slot.classList.remove('hidden');
      slot.innerHTML = '<div class="empty-muted">Generating stack-aware fix solution...</div>';

      try {
        const solution = await apiPost('/api/ai/remediate', {
          finding,
          stack: state.currentResults?.stacks?.[0] || null,
          audience: state.viewMode === 'developer' ? 'pro' : 'beginner'
        });
        renderAiFixIntoSlot(slot, solution, msg => showInlineBanner('results-status-banner', msg, false));
      } catch (err) {
        slot.innerHTML = `<div class="feedback-banner error">Failed to generate fix solution: ${escapeHtml(err.message)}</div>`;
      } finally {
        btn.disabled = false;
        btn.textContent = '🤖 AI Fix Solution';
      }
    });
  });

  container.querySelectorAll('.btn-receipts-retest').forEach(btn => {
    btn.addEventListener('click', () => {
      const idx = Number(btn.getAttribute('data-finding-idx'));
      const finding = state.renderedFindings[idx];
      if (finding) {
        openEvidenceDrawer(finding);
      }
    });
  });

  container.querySelectorAll('.btn-copy-repro').forEach(btn => {
    btn.addEventListener('click', async () => {
      const idx = Number(btn.getAttribute('data-copy-repro-idx'));
      const finding = state.renderedFindings[idx];
      const cmd = finding?.reproduction?.curl;
      if (!cmd) return;
      try {
        await navigator.clipboard?.writeText(cmd);
        btn.textContent = '✓ Copied';
        setTimeout(() => {
          btn.textContent = '📋 Copy Curl';
        }, 1800);
      } catch {
        showInlineBanner('results-status-banner', `Copy command manually: ${cmd}`, false);
      }
    });
  });
}

// ── Export Handlers ──────────────────────────────────────────────────────────
async function downloadHtmlReport() {
  if (!state.currentResults?.results) return;
  hideInlineBanner('results-status-banner');

  try {
    const data = await apiPost('/api/report/html', {
      results: state.currentResults.results,
      risk: state.currentResults.risk,
      stacks: state.currentResults.stacks,
      cveCoverage: state.currentResults.cveCoverage
    });
    triggerFileDownload(data.html, 'text/html;charset=utf-8', `security-report-${Date.now()}.html`);
  } catch (err) {
    showInlineBanner('results-status-banner', `Failed to generate HTML report: ${err.message}`, true);
  }
}

function downloadJsonReport() {
  if (!state.currentResults) return;
  const jsonStr = JSON.stringify(state.currentResults, null, 2);
  triggerFileDownload(jsonStr, 'application/json;charset=utf-8', `security-report-${Date.now()}.json`);
}

export function formatClientCsvCell(val) {
  let str = String(val ?? '');
  if (/^\s*[=+\-@\t\r]/.test(str)) {
    str = `'${str}`;
  }
  return `"${str.replace(/"/g, '""')}"`;
}

export function buildClientCsvReport(rows = []) {
  const escCsv = formatClientCsvCell;
  const header = ['Status', 'Severity', 'Check', 'Title', 'Target', 'CWE', 'OWASP', 'Detail', 'Fix', 'How to Reproduce'].join(',');
  const lines = (Array.isArray(rows) ? rows : []).map(r => {
    const repro = r.reproduction;
    const reproText = repro
      ? [repro.summary, repro.curl ? `Cmd: ${repro.curl}` : '', repro.verifyFix ? `Verify: ${repro.verifyFix}` : ''].filter(Boolean).join(' | ')
      : '';
    return [
      r.status,
      r.severity,
      r.name || r.checkId,
      r.meta?.title || r.title || r.name,
      r.target,
      r.cwe || r.enrichment?.cwe || '',
      r.owasp || r.enrichment?.owasp || '',
      r.detail || '',
      r.fix || r.meta?.defaultFix || '',
      reproText
    ]
      .map(escCsv)
      .join(',');
  });
  return '\uFEFF' + [header, ...lines].join('\r\n');
}

export function buildClientSarifReport(scanData) {
  const rows = Array.isArray(scanData)
    ? scanData
    : (Array.isArray(scanData?.results) ? scanData.results : []);
  const nonSafe = rows.filter(r => r && r.status !== 'SAFE');
  const rulesMap = new Map();
  const sarifResults = [];

  for (const f of nonSafe) {
    const ruleId = String(f.checkId || f.name || 'security-check');
    const meta = f.meta || {};
    const title = meta.title || f.title || ruleId;
    const cwe = f.cwe || f.enrichment?.cwe || meta.cwe || '';
    const owasp = f.owasp || f.enrichment?.owasp || meta.owasp || '';
    const cvss = f.cvssScore ?? f.enrichment?.cvssScore ?? meta.cvssScore ?? 5.3;
    const cveIds = collectCveIds(f);
    const fix = f.fix || meta.defaultFix || '';

    if (!rulesMap.has(ruleId)) {
      rulesMap.set(ruleId, {
        id: ruleId,
        name: title,
        shortDescription: { text: title },
        fullDescription: { text: meta.plainExplanation || title },
        help: { text: fix || 'Apply recommended security hardening.' },
        properties: {
          tags: ['security', cwe, owasp, ...cveIds].filter(Boolean),
          'security-severity': String(cvss)
        }
      });
    }

    const level = f.status === 'VULNERABLE' ? 'error' : f.status === 'SUSPICIOUS' ? 'warning' : 'note';
    sarifResults.push({
      ruleId,
      level,
      message: {
        text: `${title}: ${f.detail || f.reason || f.status}${fix ? ` — Fix: ${fix}` : ''}`
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: f.target || (Array.isArray(f.pages) && f.pages[0]) || 'about:blank'
            }
          }
        }
      ],
      properties: {
        status: f.status,
        severity: f.severity || 'MEDIUM',
        ...(cwe ? { cwe } : {}),
        ...(owasp ? { owasp } : {}),
        cvssScore: Number(cvss),
        ...(cveIds.length ? { cveIds } : {})
      }
    });
  }

  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'Security Scanner',
            version: '2.3.0',
            rules: Array.from(rulesMap.values())
          }
        },
        results: sarifResults
      }
    ]
  };
}

async function exportScanFormat(format) {
  if (!state.currentResults?.results) return;

  const scanId = state.currentResults.scanId || state.currentResults.historyFile || state.activeScanId;
  if (scanId) {
    try {
      const res = await fetch(`/api/scan/${encodeURIComponent(scanId)}/export?format=${encodeURIComponent(format)}`);
      if (res.ok) {
        const text = await res.text();
        const ext = format === 'markdown' ? 'md' : format;
        const mime =
          format === 'csv'
            ? 'text/csv;charset=utf-8'
            : format === 'sarif'
            ? 'application/sarif+json;charset=utf-8'
            : 'text/markdown;charset=utf-8';
        triggerFileDownload(text, mime, `security-report-${Date.now()}.${ext}`);
        return;
      }
    } catch {
      /* fallback to client-side formatting below */
    }
  }

  // Client-side fallback when exporting loaded/in-memory results without server scanId
  const rows = state.currentResults.results || [];
  if (format === 'sarif') {
    const sarif = buildClientSarifReport(state.currentResults);
    triggerFileDownload(
      JSON.stringify(sarif, null, 2),
      'application/sarif+json;charset=utf-8',
      `security-report-${Date.now()}.sarif`
    );
  } else if (format === 'csv') {
    triggerFileDownload(buildClientCsvReport(rows), 'text/csv;charset=utf-8', `security-report-${Date.now()}.csv`);
  } else {
    const risk = state.currentResults.risk || {};
    const mdLines = [
      `# Security Verification Report`,
      ``,
      `- **Grade**: ${risk.grade || 'N/A'} (${risk.level || 'LOW'} Risk, Score ${risk.score ?? 0})`,
      `- **Summary**: ${risk.summary || ''}`,
      ``,
      `## Findings (${rows.length})`,
      ``
    ];
    for (const r of rows) {
      mdLines.push(`### [${r.status}] ${r.meta?.title || r.name} (${r.severity || 'NONE'})`);
      mdLines.push(`- **Target**: ${r.target || '—'}`);
      if (r.detail) mdLines.push(`- **Detail**: ${r.detail}`);
      if (r.reproduction && r.status !== 'SAFE') {
        mdLines.push('- **How to Reproduce & Verify Fix**:');
        if (Array.isArray(r.reproduction.steps)) {
          r.reproduction.steps.forEach((s, idx) => mdLines.push(`  ${idx + 1}. ${s}`));
        }
        if (r.reproduction.curl) {
          mdLines.push('', '```bash', r.reproduction.curl, '```');
        }
      }
      if (r.fix || r.meta?.defaultFix) mdLines.push(`- **Fix**: ${r.fix || r.meta?.defaultFix}`);
      mdLines.push('');
    }
    triggerFileDownload(mdLines.join('\n'), 'text/markdown;charset=utf-8', `security-report-${Date.now()}.md`);
  }
}

// ── Tab 4: Dual-Graph Explorer ───────────────────────────────────────────────
function initDualGraphTab() {
  const btnExplore = document.getElementById('btn-dg-view-exploration');
  const btnCoverage = document.getElementById('btn-dg-view-coverage');
  const viewExplore = document.getElementById('dg-exploration-view');
  const viewCoverage = document.getElementById('dg-coverage-view');
  const taskSelect = document.getElementById('dg-task-select');
  const btnRefresh = document.getElementById('btn-dg-refresh');
  const dslRoot = document.getElementById('dg-dsl-search-root');

  if (dslRoot && !state.dualGraph.dslCtrl) {
    state.dualGraph.dslCtrl = mountAssetDslSearch(
      dslRoot,
      dsl => {
        state.dualGraph.lastDsl = dsl;
        loadAssetsTable(dsl);
      },
      {
        onIngested: () => {
          loadCoverageGraphView();
          loadAssetsTable(state.dualGraph.lastDsl);
        }
      }
    );
  }

  btnExplore?.addEventListener('click', () => {
    state.dualGraph.activeSubView = 'exploration';
    btnExplore.classList.add('active');
    btnCoverage.classList.remove('active');
    viewExplore.classList.remove('hidden');
    viewCoverage.classList.add('hidden');
    loadExplorationGraphView();
  });

  btnCoverage?.addEventListener('click', () => {
    state.dualGraph.activeSubView = 'coverage';
    btnCoverage.classList.add('active');
    btnExplore.classList.remove('active');
    viewCoverage.classList.remove('hidden');
    viewExplore.classList.add('hidden');
    loadCoverageGraphView();
    loadAssetsTable(state.dualGraph.lastDsl);
  });

  taskSelect?.addEventListener('change', () => {
    state.dualGraph.selectedTaskId = taskSelect.value;
    if (state.dualGraph.activeSubView === 'exploration') {
      loadExplorationGraphView();
    } else {
      loadCoverageGraphView();
      loadAssetsTable(state.dualGraph.lastDsl);
    }
  });

  btnRefresh?.addEventListener('click', refreshDualGraphTab);
}

async function refreshDualGraphTab() {
  const taskSelect = document.getElementById('dg-task-select');
  try {
    const data = await apiGet('/api/tasks');
    const tasks = Array.isArray(data.tasks) ? data.tasks : [];
    if (taskSelect) {
      taskSelect.innerHTML =
        '<option value="">Global / Latest Task</option>' +
        tasks
          .map(t => `<option value="${escapeHtml(t.id)}">${escapeHtml(t.title || t.target || t.id)}</option>`)
          .join('');
      if (!state.dualGraph.selectedTaskId && tasks.length > 0) {
        state.dualGraph.selectedTaskId = tasks[0].id;
      }
      taskSelect.value = state.dualGraph.selectedTaskId || '';
    }
  } catch {
    /* tasks list optional */
  }

  if (state.dualGraph.activeSubView === 'exploration') {
    await loadExplorationGraphView();
  } else {
    await Promise.all([loadCoverageGraphView(), loadAssetsTable(state.dualGraph.lastDsl)]);
  }
}

async function loadExplorationGraphView() {
  const root = document.getElementById('dg-exploration-graph-root');
  if (!root) return;
  const taskId = state.dualGraph.selectedTaskId;
  if (!taskId) {
    renderExplorationGraph(root, { nodes: [], edges: [], anchors: [] });
    return;
  }
  try {
    const data = await apiGet(`/api/graph/exploration/${encodeURIComponent(taskId)}`);
    renderExplorationGraph(root, data);
  } catch (err) {
    root.innerHTML = `<div class="empty-muted">Could not load exploration graph: ${escapeHtml(err.message)}</div>`;
  }
}

async function loadCoverageGraphView() {
  const root = document.getElementById('dg-coverage-graph-root');
  if (!root) return;
  const qs = state.dualGraph.selectedTaskId
    ? `?taskId=${encodeURIComponent(state.dualGraph.selectedTaskId)}`
    : '';
  try {
    const data = await apiGet(`/api/graph/coverage${qs}`);
    renderCoverageGraph(root, data);
  } catch (err) {
    root.innerHTML = `<div class="empty-muted">Could not load coverage graph: ${escapeHtml(err.message)}</div>`;
  }
}

async function loadAssetsTable(dsl = '') {
  const tbody = document.getElementById('dg-assets-tbody');
  const countEl = document.getElementById('dg-assets-count');
  if (!tbody) return;

  const params = new URLSearchParams();
  if (dsl) params.set('dsl', dsl);
  if (state.dualGraph.selectedTaskId) params.set('taskId', state.dualGraph.selectedTaskId);
  params.set('limit', '200');

  try {
    const data = await apiGet(`/api/assets?${params.toString()}`);
    const assets = Array.isArray(data.assets) ? data.assets : Array.isArray(data) ? data : [];
    if (countEl) countEl.textContent = String(assets.length);
    state.dualGraph.dslCtrl?.setStatus(`Found ${assets.length} matching assets`, false);

    if (assets.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty-table-cell">No assets match the current DSL query.</td></tr>';
      return;
    }

    tbody.innerHTML = assets
      .map(a => {
        const type = a.assetType || a.asset_type || a.type || 'asset';
        const ipPort = [a.ip, a.port].filter(Boolean).join(':') || '—';
        return `
          <tr>
            <td><span class="ev-pill">${escapeHtml(type)}</span></td>
            <td><code>${escapeHtml(a.host || a.key || a.id)}</code></td>
            <td><code>${escapeHtml(a.url || a.path || '—')}</code></td>
            <td><code>${escapeHtml(ipPort)}</code></td>
            <td>${a.statusCode ? Number(a.statusCode) : '—'}</td>
            <td>${escapeHtml(a.source || '—')}</td>
            <td>${a.verified ? '✅ Verified' : '—'}</td>
          </tr>
        `;
      })
      .join('');
  } catch (err) {
    state.dualGraph.dslCtrl?.setStatus(`DSL Error: ${err.message}`, true);
    tbody.innerHTML = `<tr><td colspan="7" class="empty-table-cell">${escapeHtml(err.message)}</td></tr>`;
  }
}

// ── Tab 6: History & Diff ────────────────────────────────────────────────────
function initHistoryAndDiff() {
  document.getElementById('btn-refresh-history').addEventListener('click', loadHistory);

  document.getElementById('btn-clear-slot-a').addEventListener('click', () => {
    state.diffSlotA = null;
    updateDiffSlotsUi();
  });

  document.getElementById('btn-clear-slot-b').addEventListener('click', () => {
    state.diffSlotB = null;
    updateDiffSlotsUi();
  });

  document.getElementById('btn-run-diff').addEventListener('click', executeDiffComparison);

  document.getElementById('btn-close-diff').addEventListener('click', () => {
    document.getElementById('diff-results-container').classList.add('hidden');
  });
}

async function loadHistory() {
  try {
    const data = await apiGet('/api/history');
    state.history = data.history || [];

    const badge = document.getElementById('history-badge');
    if (badge) badge.textContent = String(state.history.length);

    renderHistoryTable();
  } catch (err) {
    console.warn('Could not load history:', err.message);
  }
}

function renderHistoryTable() {
  const tbody = document.getElementById('history-tbody');
  if (!tbody) return;

  if (state.history.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="8" class="empty-table-cell">
          No saved scan history found. Run a new scan with "Save to history archive" enabled.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = state.history
    .map(item => {
      const dateStr = new Date(item.timestamp).toLocaleString([], {
        dateStyle: 'medium',
        timeStyle: 'short'
      });
      let targetHost = 'Unknown';
      if (item.targets?.[0]) {
        try {
          targetHost = new URL(item.targets[0]).hostname;
        } catch {
          targetHost = String(item.targets[0] || 'Unknown');
        }
      }
      const grade = item.risk?.grade || '—';
      const gradeClass = escapeHtml(String(grade).toLowerCase().replace('+', 'plus').replace(/[^a-z0-9_-]/g, ''));

      const isA = state.diffSlotA?.id === item.id;
      const isB = state.diffSlotB?.id === item.id;

      return `
      <tr>
        <td><strong>${escapeHtml(dateStr)}</strong></td>
        <td><code class="mono-blue">${escapeHtml(targetHost)}</code></td>
        <td>
          <span class="grade-letter history-grade-text grade-color-${gradeClass}">
            ${escapeHtml(grade)}
          </span>
          <span class="history-risk-level">(${escapeHtml(item.risk?.level || 'LOW')})</span>
        </td>
        <td><span class="badge-mini danger">🚨 ${Number(item.vulnerable) || 0}</span></td>
        <td><span class="badge-mini warning">⚠️ ${Number(item.suspicious) || 0}</span></td>
        <td>${Number(item.count) || 0}</td>
        <td>
          <button type="button" class="btn-secondary btn-small btn-view-history" data-history-id="${escapeHtml(item.id)}">
            View Report
          </button>
        </td>
        <td>
          <div class="diff-slot-btns">
            <button type="button" class="btn-slot-select ${isA ? 'active' : ''}" data-slot="A" data-history-id="${escapeHtml(item.id)}">
              Slot A
            </button>
            <button type="button" class="btn-slot-select ${isB ? 'active' : ''}" data-slot="B" data-history-id="${escapeHtml(item.id)}">
              Slot B
            </button>
          </div>
        </td>
      </tr>
    `;
    })
    .join('');

  tbody.querySelectorAll('.btn-view-history').forEach(btn => {
    btn.addEventListener('click', async () => {
      const id = btn.getAttribute('data-history-id');
      await viewHistoricalReport(id);
    });
  });

  tbody.querySelectorAll('.btn-slot-select').forEach(btn => {
    btn.addEventListener('click', () => {
      const slot = btn.getAttribute('data-slot');
      const id = btn.getAttribute('data-history-id');
      const record = state.history.find(h => h.id === id);

      if (slot === 'A') {
        state.diffSlotA = record;
      } else {
        state.diffSlotB = record;
      }

      updateDiffSlotsUi();
      renderHistoryTable();
    });
  });
}

function updateDiffSlotsUi() {
  const slotA = document.getElementById('diff-slot-a');
  const labelA = document.getElementById('diff-slot-a-label');
  const btnClearA = document.getElementById('btn-clear-slot-a');

  const slotB = document.getElementById('diff-slot-b');
  const labelB = document.getElementById('diff-slot-b-label');
  const btnClearB = document.getElementById('btn-clear-slot-b');

  const btnDiff = document.getElementById('btn-run-diff');

  if (state.diffSlotA) {
    slotA.classList.add('selected');
    const dateStr = new Date(state.diffSlotA?.timestamp || Date.now()).toLocaleDateString();
    labelA.textContent = `${state.diffSlotA?.targets?.[0] || state.diffSlotA?.id || 'Scan A'} (${dateStr})`;
    btnClearA.classList.remove('hidden');
  } else {
    slotA.classList.remove('selected');
    labelA.textContent = 'None selected (choose below)';
    btnClearA.classList.add('hidden');
  }

  if (state.diffSlotB) {
    slotB.classList.add('selected');
    const dateStr = new Date(state.diffSlotB?.timestamp || Date.now()).toLocaleDateString();
    labelB.textContent = `${state.diffSlotB?.targets?.[0] || state.diffSlotB?.id || 'Scan B'} (${dateStr})`;
    btnClearB.classList.remove('hidden');
  } else {
    slotB.classList.remove('selected');
    labelB.textContent = 'None selected (choose below)';
    btnClearB.classList.add('hidden');
  }

  btnDiff.disabled = !(state.diffSlotA && state.diffSlotB && state.diffSlotA.id !== state.diffSlotB.id);
}

async function viewHistoricalReport(historyId) {
  hideInlineBanner('history-status-banner');
  try {
    const data = await apiGet(`/api/history/${encodeURIComponent(historyId)}`);
    if (data?.record) {
      const results = Array.isArray(data.record?.results) ? data.record.results : [];
      state.currentResults = {
        results,
        risk: data.record?.risk,
        historyFile: historyId,
        stacks: data.record?.stacks || null,
        cveCoverage: data.record?.cveCoverage || null,
        pagesCount: results.length ? new Set(results.map(r => r.target)).size : 1,
        completedAt: data.record?.timestamp
      };

      switchTab('scan-results');
      renderScanResults(state.currentResults);
    }
  } catch (err) {
    showInlineBanner('history-status-banner', `Could not load scan record: ${err.message}`, true);
  }
}

async function executeDiffComparison() {
  if (!state.diffSlotA || !state.diffSlotB) return;
  hideInlineBanner('history-status-banner');

  try {
    const data = await apiPost('/api/diff', {
      previousId: state.diffSlotA.id,
      currentId: state.diffSlotB.id
    });

    renderDiffResults(data?.diff);
  } catch (err) {
    showInlineBanner('history-status-banner', `Comparison failed: ${err.message}`, true);
  }
}

function renderDiffResults(diff) {
  const container = document.getElementById('diff-results-container');
  const countNew = document.getElementById('diff-count-new');
  const countFixed = document.getElementById('diff-count-fixed');
  const countChanged = document.getElementById('diff-count-changed');
  const details = document.getElementById('diff-details-container');

  const newFindings = Array.isArray(diff?.newFindings) ? diff.newFindings : [];
  const fixedFindings = Array.isArray(diff?.fixedFindings) ? diff.fixedFindings : [];
  const changedFindings = Array.isArray(diff?.changedFindings) ? diff.changedFindings : [];

  countNew.textContent = String(newFindings.length);
  countFixed.textContent = String(fixedFindings.length);
  countChanged.textContent = String(changedFindings.length);

  let html = '';

  if (newFindings.length > 0) {
    html += `
      <div class="diff-group">
        <h4 class="diff-group-title diff-title-new">🆕 New Findings (${newFindings.length})</h4>
        ${newFindings
          .map(
            f => `
          <div class="diff-item new-finding">
            <div>
              <strong>[${escapeHtml(f?.severity || 'INFO')}] ${escapeHtml(f?.name || 'Check')}</strong>
              <div class="diff-item-sub">${escapeHtml(f?.target || '—')}</div>
            </div>
            <span class="finding-status-badge vulnerable">${escapeHtml(f?.status || 'VULNERABLE')}</span>
          </div>
        `
          )
          .join('')}
      </div>
    `;
  }

  if (fixedFindings.length > 0) {
    html += `
      <div class="diff-group">
        <h4 class="diff-group-title diff-title-fixed">✅ Resolved / Fixed Findings (${fixedFindings.length})</h4>
        ${fixedFindings
          .map(
            item => `
          <div class="diff-item fixed-finding">
            <div>
              <strong>${escapeHtml(item?.prev?.name ?? item?.name ?? 'Check')}</strong>
              <div class="diff-item-sub">${escapeHtml(item?.prev?.target ?? item?.target ?? '—')}</div>
            </div>
            <span class="finding-status-badge safe">RESOLVED</span>
          </div>
        `
          )
          .join('')}
      </div>
    `;
  }

  if (changedFindings.length > 0) {
    html += `
      <div class="diff-group">
        <h4 class="diff-group-title diff-title-changed">↕️ Changed Status Findings (${changedFindings.length})</h4>
        ${changedFindings
          .map(
            item => `
          <div class="diff-item changed-finding">
            <div>
              <strong>${escapeHtml(item?.curr?.name ?? item?.prev?.name ?? item?.name ?? 'Check')}</strong>
              <div class="diff-item-sub">${escapeHtml(item?.curr?.target ?? item?.prev?.target ?? item?.target ?? '—')}</div>
            </div>
            <span class="finding-status-badge suspicious">${escapeHtml(item?.prev?.status ?? '—')} → ${escapeHtml(item?.curr?.status ?? '—')}</span>
          </div>
        `
          )
          .join('')}
      </div>
    `;
  }

  if (!newFindings.length && !fixedFindings.length && !changedFindings.length) {
    html = '<p class="empty-muted">No changes detected between the two scan baselines.</p>';
  }

  details.innerHTML = html;
  container.classList.remove('hidden');
  container.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ── Tab 7: Checks Catalog, Scaffolder & System Guardrails ────────────────────
export function renderCategoryPills(categories = []) {
  if (typeof document === 'undefined') return;
  const container = document.getElementById('category-pills-container');
  if (!container) return;

  const uniqueCats = Array.from(
    new Set(
      (Array.isArray(categories) ? categories : [])
        .map(c => String(c || '').trim())
        .filter(Boolean)
    )
  ).sort((a, b) => a.localeCompare(b));

  if (state.catalogFilters.category !== 'all' && !uniqueCats.includes(state.catalogFilters.category)) {
    state.catalogFilters.category = 'all';
  }

  const allActive = state.catalogFilters.category === 'all';
  container.innerHTML =
    `<button type="button" class="category-pill ${allActive ? 'active' : ''}" data-category="all">All</button>` +
    uniqueCats
      .map(cat => {
        const isActive = state.catalogFilters.category === cat;
        return `<button type="button" class="category-pill ${isActive ? 'active' : ''}" data-category="${escapeHtml(cat)}">${escapeHtml(cat)}</button>`;
      })
      .join('');
}

function initCatalogAndBuilder() {
  const btnBrowse = document.getElementById('btn-view-catalog-browse');
  const btnCveCoverage = document.getElementById('btn-view-catalog-cve-coverage');
  const btnBuilder = document.getElementById('btn-view-catalog-builder');
  const btnGuardrails = document.getElementById('btn-view-catalog-guardrails');
  const viewBrowse = document.getElementById('catalog-browse-view');
  const viewCveCoverage = document.getElementById('catalog-cve-coverage-view');
  const viewBuilder = document.getElementById('catalog-builder-view');
  const viewGuardrails = document.getElementById('catalog-guardrails-view');

  function activateSubView(target) {
    btnBrowse?.classList.toggle('active', target === 'browse');
    btnCveCoverage?.classList.toggle('active', target === 'cve-coverage');
    btnBuilder?.classList.toggle('active', target === 'builder');
    btnGuardrails?.classList.toggle('active', target === 'guardrails');

    viewBrowse?.classList.toggle('hidden', target !== 'browse');
    viewCveCoverage?.classList.toggle('hidden', target !== 'cve-coverage');
    viewBuilder?.classList.toggle('hidden', target !== 'builder');
    viewGuardrails?.classList.toggle('hidden', target !== 'guardrails');

    if (target === 'guardrails') {
      const root = document.getElementById('system-guardrails-root');
      if (root) renderSystemGuardrails(root);
    } else if (target === 'cve-coverage') {
      const root = document.getElementById('cve-coverage-root');
      const primaryStackTags = state.currentResults?.stacks?.[0]?.detectedTags || [];
      if (root) {
        renderCveCoveragePanel(root, {
          coverageEndpoint: '/api/cves/coverage',
          auditEndpoint: '/api/cves/audit',
          initialTech: Array.isArray(primaryStackTags) ? primaryStackTags.join(',') : ''
        });
      }
    }
  }

  btnBrowse?.addEventListener('click', () => activateSubView('browse'));
  btnCveCoverage?.addEventListener('click', () => activateSubView('cve-coverage'));
  btnBuilder?.addEventListener('click', () => activateSubView('builder'));
  btnGuardrails?.addEventListener('click', () => activateSubView('guardrails'));

  const pillsContainer = document.getElementById('category-pills-container');
  pillsContainer?.addEventListener('click', e => {
    const pill = e.target.closest('.category-pill');
    if (!pill) return;
    pillsContainer.querySelectorAll('.category-pill').forEach(p => p.classList.remove('active'));
    pill.classList.add('active');
    state.catalogFilters.category = pill.getAttribute('data-category') || 'all';
    renderCatalogGrid();
  });

  const searchInput = document.getElementById('catalog-search-input');
  searchInput.addEventListener('input', () => {
    state.catalogFilters.search = searchInput.value.trim().toLowerCase();
    renderCatalogGrid();
  });

  document.getElementById('btn-builder-preview').addEventListener('click', () => {
    runScaffoldCheck(true);
  });

  document.getElementById('btn-builder-create').addEventListener('click', () => {
    runScaffoldCheck(false);
  });

  const btnPreviewCheck = document.getElementById('btn-preview-check');
  const btnPreviewTest = document.getElementById('btn-preview-test');
  const codeDisplay = document.getElementById('builder-code-display');

  btnPreviewCheck.addEventListener('click', () => {
    btnPreviewCheck.classList.add('active');
    btnPreviewTest.classList.remove('active');
    state.builderActiveTab = 'check';
    if (state.builderPreviewData) {
      codeDisplay.textContent = state.builderPreviewData.checkCode;
    }
  });

  btnPreviewTest.addEventListener('click', () => {
    btnPreviewTest.classList.add('active');
    btnPreviewCheck.classList.remove('active');
    state.builderActiveTab = 'test';
    if (state.builderPreviewData) {
      codeDisplay.textContent = state.builderPreviewData.testCode;
    }
  });

  document.getElementById('btn-copy-code').addEventListener('click', () => {
    if (codeDisplay.textContent) {
      navigator.clipboard.writeText(codeDisplay.textContent).then(() => {
        const copyBtn = document.getElementById('btn-copy-code');
        const orig = copyBtn.textContent;
        copyBtn.textContent = '✅ Copied!';
        setTimeout(() => (copyBtn.textContent = orig), 2000);
      });
    }
  });
}

function renderCatalogGrid() {
  const container = document.getElementById('checks-catalog-grid');
  if (!container) return;

  const { category, search } = state.catalogFilters;

  const filtered = state.checks.filter(c => {
    const meta = c.meta || {};
    if (category !== 'all' && meta.category !== category) return false;
    if (search) {
      const id = (c.id || '').toLowerCase();
      const title = (meta.title || '').toLowerCase();
      const tags = (c.tags || []).join(',').toLowerCase();
      const exp = (meta.plainExplanation || '').toLowerCase();
      if (!id.includes(search) && !title.includes(search) && !tags.includes(search) && !exp.includes(search)) {
        return false;
      }
    }
    return true;
  });

  if (filtered.length === 0) {
    container.innerHTML = `
      <div class="empty-state catalog-empty-state">
        <span class="empty-icon">🔎</span>
        <h3 class="empty-title">No checks match your filter</h3>
        <p class="empty-text">Try another category or clear your search term.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = filtered
    .map(c => {
      const meta = c.meta || {};
      const tags = Array.isArray(c.tags) ? c.tags : [];

      return `
      <div class="catalog-card">
        <div class="catalog-card-header">
          <h4 class="catalog-card-title">${escapeHtml(meta.title || c.id)}</h4>
          <span class="catalog-card-id">${escapeHtml(c.id)}</span>
        </div>
        <div class="catalog-card-tags">
          ${meta.category ? `<span class="category-tag">${escapeHtml(meta.category)}</span>` : ''}
          ${tags.map(t => `<span class="preset-badge">${escapeHtml(t)}</span>`).join('')}
        </div>
        <p class="catalog-desc">${escapeHtml(meta.plainExplanation || 'Performs security verification for this issue.')}</p>
        ${meta.whyItMatters ? `<div class="catalog-why"><strong>Why it matters:</strong> ${escapeHtml(meta.whyItMatters)}</div>` : ''}
        ${meta.defaultFix ? `<div class="catalog-fix"><strong>💡 Fix:</strong> ${escapeHtml(meta.defaultFix)}</div>` : ''}
      </div>
    `;
    })
    .join('');
}

async function runScaffoldCheck(dryRun) {
  const nameInput = document.getElementById('scaffold-name');
  const titleInput = document.getElementById('scaffold-title');
  const categoryInput = document.getElementById('scaffold-category');
  const tagsInput = document.getElementById('scaffold-tags');
  const explanationInput = document.getElementById('scaffold-plain-explanation');
  const whyInput = document.getElementById('scaffold-why-it-matters');
  const fixInput = document.getElementById('scaffold-default-fix');

  const feedback = document.getElementById('builder-feedback');
  const previewBox = document.getElementById('builder-preview-box');
  const codeDisplay = document.getElementById('builder-code-display');
  const checkFilenameLabel = document.getElementById('preview-check-filename');
  const testFilenameLabel = document.getElementById('preview-test-filename');

  const name = nameInput.value.trim().toLowerCase();
  const title = titleInput.value.trim();

  if (!name) {
    feedback.className = 'feedback-banner error';
    feedback.textContent = 'Check Identifier (ID) is required (e.g. cve-2026-example or custom-check).';
    feedback.classList.remove('hidden');
    nameInput.focus();
    return;
  }

  if (!/^[a-z0-9-]{2,40}$/.test(name)) {
    feedback.className = 'feedback-banner error';
    feedback.textContent = 'Check ID must be 2-40 lowercase letters, numbers, and hyphens only.';
    feedback.classList.remove('hidden');
    nameInput.focus();
    return;
  }

  if (!title) {
    feedback.className = 'feedback-banner error';
    feedback.textContent = 'Check Title is required.';
    feedback.classList.remove('hidden');
    titleInput.focus();
    return;
  }

  const tags = tagsInput.value.split(',').map(s => s.trim()).filter(Boolean);

  try {
    const res = await apiPost('/api/checks/scaffold', {
      name,
      title,
      category: categoryInput.value,
      tags: tags.length ? tags : ['all'],
      plainExplanation: explanationInput.value.trim(),
      whyItMatters: whyInput.value.trim(),
      defaultFix: fixInput.value.trim(),
      dryRun
    });

    state.builderPreviewData = res;
    checkFilenameLabel.textContent = res.checkFilename;
    testFilenameLabel.textContent = res.testFilename;
    codeDisplay.textContent = state.builderActiveTab === 'check' ? res.checkCode : res.testCode;

    previewBox.classList.remove('hidden');

    if (dryRun) {
      feedback.className = 'feedback-banner success';
      feedback.textContent = `👁️ Code preview generated for "${res.checkFilename}". Review the implementation below before creating files.`;
      feedback.classList.remove('hidden');
    } else {
      feedback.className = 'feedback-banner success';
      feedback.textContent = `🎉 Success! Created "${res.checkPath}" and "${res.testPath}". Reloading catalog...`;
      feedback.classList.remove('hidden');
      await loadMeta();
    }
  } catch (err) {
    feedback.className = 'feedback-banner error';
    feedback.textContent = `Error: ${err.message}`;
    feedback.classList.remove('hidden');
  }
}
