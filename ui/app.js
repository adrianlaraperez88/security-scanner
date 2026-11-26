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
  },
  loginSequence: createDefaultLoginSequence(),
  savedSequences: [],
  systemVariables: [],
  selectedLsrStepIndex: -1,
  lastInspectedPage: null,
  lastLsrPlayResult: null,
  lsrDraftDismissed: false
};

function createDefaultLoginSequence() {
  return {
    sequenceId: '',
    name: 'WrapperSequence.lsr',
    updatedAt: new Date().toISOString(),
    targetUrl: '',
    secrets: [],
    otpConfig: {
      enabled: false,
      secret: '',
      digits: 6,
      period: 30,
      algorithm: 'SHA1',
      inputSelector: 'auto'
    },
    actions: [],
    restrictions: ['/logout', '/signout', '/logoff'],
    sessionDetection: {
      statusCodes: [401, 403],
      redirectPattern: '/login',
      loggedOutPattern: '',
      loggedInPattern: ''
    }
  };
}

const PRESET_ICONS = {
  smart: '🧠',
  quick: '⚡',
  full: '🌐',
  modern: '🤖',
  cms: '🛍️',
  api: '🔌',
  device: '📺',
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

function isValidIpLiteral(value) {
  const str = String(value || '').trim();
  if (!str || /\s/.test(str)) return false;
  const v4 = str.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    return v4.slice(1).every(octet => {
      if (!/^(0|[1-9]\d{0,2})$/.test(octet)) return false;
      const n = Number(octet);
      return Number.isInteger(n) && n >= 0 && n <= 255;
    });
  }
  if (str.includes(':') && !str.includes('[') && !str.includes(']')) {
    const zoneMatch = str.match(/^([^%]+)(?:%([A-Za-z0-9_.-]+))?$/);
    if (!zoneMatch) return false;
    try {
      const u = new URL(`http://[${zoneMatch[1]}]`);
      return u.hostname.startsWith('[') && u.hostname.endsWith(']');
    } catch {
      return false;
    }
  }
  return false;
}

export function normalizeTargetScheme(rawTarget) {
  if (typeof rawTarget !== 'string') return '';
  let s = rawTarget.trim();
  if (!s) return '';

  let prev;
  do {
    prev = s;
    s = s.trim();
    s = s.replace(/^['"]+|['"]+$/g, '').trim();
    const schemeMatch = s.match(/^([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)([\s\S]*)$/);
    if (schemeMatch) {
      const [, scheme, rest] = schemeMatch;
      const tailRe = /[?#]/.test(rest) ? /\\+$/ : /[\\/]+$/;
      s = `${scheme}${rest.replace(tailRe, '')}`;
    } else {
      const tailRe = /[?#]/.test(s) ? /\\+$/ : /[\\/]+$/;
      s = s.replace(tailRe, '');
    }
  } while (s !== prev);

  if (!s) return '';
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(s) || /^(?:javascript|data|vbscript|file):/i.test(s)) {
    return s;
  }
  if (/\s/.test(s)) return s;

  const sepIdx = s.search(/[/?#]/);
  const hostCandidate = sepIdx === -1 ? s : s.slice(0, sepIdx);
  const tailCandidate = sepIdx === -1 ? '' : s.slice(sepIdx);
  if (isValidIpLiteral(hostCandidate) && hostCandidate.includes(':')) {
    return `http://[${hostCandidate}]${tailCandidate}`;
  }

  const v6Match = s.match(/^\[([^\]]+)\](?::(\d+))?(?:[/?#].*)?$/);
  if (v6Match && isValidIpLiteral(v6Match[1]) && v6Match[1].includes(':')) {
    const port = v6Match[2] || '';
    const scheme = port === '443' || port === '8443' ? 'https://' : 'http://';
    return `${scheme}${s}`;
  }

  const v4Match = s.match(/^(\d{1,3}(?:\.\d{1,3}){3})\.?(?::(\d+))?(?:[/?#].*)?$/);
  if (v4Match && isValidIpLiteral(v4Match[1])) {
    const port = v4Match[2] || '';
    const scheme = port === '443' || port === '8443' ? 'https://' : 'http://';
    return `${scheme}${s}`;
  }

  const localMatch = s.match(/^(?:[a-zA-Z0-9-]+\.)*localhost\.?(?::(\d+))?(?:[/?#].*)?$/i);
  if (localMatch) {
    const port = localMatch[1] || '';
    const scheme = port === '443' || port === '8443' ? 'https://' : 'http://';
    return `${scheme}${s}`;
  }

  const domPortMatch = s.match(/^[^/?#:]+:(\d+)(?:[/?#]|$)/);
  const domScheme = domPortMatch && domPortMatch[1] === '80' ? 'http://' : 'https://';
  return `${domScheme}${s}`;
}

function stripOuterTargetInput(rawTarget) {
  if (typeof rawTarget !== 'string') return '';
  let s = rawTarget.trim();
  if (!s) return '';
  let prev;
  do {
    prev = s;
    s = s.trim();
    s = s.replace(/^['"]+|['"]+$/g, '').trim();
    const schemeMatch = s.match(/^([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)([\s\S]*)$/);
    if (schemeMatch) {
      const [, scheme, rest] = schemeMatch;
      const tailRe = /[?#]/.test(rest) ? /\\+$/ : /[\\/]+$/;
      s = `${scheme}${rest.replace(tailRe, '')}`;
    } else {
      const tailRe = /[?#]/.test(s) ? /\\+$/ : /[\\/]+$/;
      s = s.replace(tailRe, '');
    }
  } while (s !== prev);
  return s;
}

export function isBareIpInput(rawTarget) {
  const s = stripOuterTargetInput(rawTarget);
  if (!s) return false;
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(s) || /^(?:javascript|data|vbscript|file):/i.test(s)) {
    return false;
  }
  if (/\s/.test(s)) return false;

  const sepIdx = s.search(/[/?#]/);
  const hostCandidate = sepIdx === -1 ? s : s.slice(0, sepIdx);
  if (isValidIpLiteral(hostCandidate) && hostCandidate.includes(':')) {
    return true;
  }

  const v6Match = s.match(/^\[([^\]]+)\](?::(\d+))?(?:[/?#].*)?$/);
  if (v6Match && isValidIpLiteral(v6Match[1]) && v6Match[1].includes(':')) {
    return !v6Match[2];
  }

  const v4Match = s.match(/^(\d{1,3}(?:\.\d{1,3}){3})\.?(?::(\d+))?(?:[/?#].*)?$/);
  if (v4Match && isValidIpLiteral(v4Match[1])) {
    return !v4Match[2];
  }

  return false;
}

export function preserveBareIpOrNormalize(rawTarget) {
  const s = stripOuterTargetInput(rawTarget);
  if (isBareIpInput(s)) return s;
  return normalizeTargetScheme(rawTarget);
}

export function validateInputUrl(val) {
  if (typeof document === 'undefined') return true;
  const banner = document.getElementById('url-validation-banner');
  const bannerText = document.getElementById('url-validation-text');
  const allowPrivateEl = document.getElementById('allow-private-toggle');
  if (!banner || !bannerText) return true;

  const trimmed = String(val || '').trim();
  if (!trimmed) {
    banner.classList.add('hidden');
    return true;
  }

  const candidate = normalizeTargetScheme(trimmed) || trimmed;
  const allowPrivate = Boolean(allowPrivateEl?.checked);
  const METADATA_PATTERN = /^(https?:\/\/)?(169\.254\.|100\.100\.100\.200\b|metadata\.google\.internal\b|metadata\.goog\b|metadata\b|instance-data\b|0\.0\.0\.0\b)/i;
  if (METADATA_PATTERN.test(candidate)) {
    banner.className = 'validation-banner';
    bannerText.textContent =
      '⚠️ SSRF Protection: Cloud metadata and reserved link-local addresses are always blocked.';
    banner.classList.remove('hidden');
    return false;
  }

  const PRIVATE_PATTERN = /^(https?:\/\/)?(localhost\b|[^/?#]+\.localhost\b|127\.|0\.0\.0\.0|::1|\[::1\]|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|([^/?#]+\.)?(local|internal)(?::\d+)?(?:[/?#]|$))/i;
  if (!allowPrivate && PRIVATE_PATTERN.test(candidate)) {
    banner.className = 'validation-banner';
    bannerText.textContent =
      '⚠️ SSRF Protection: Localhost and private network IP addresses cannot be scanned unless "Allow Authorized Internal / Private Targets" is enabled.';
    banner.classList.remove('hidden');
    return false;
  }

  banner.classList.add('hidden');
  return true;
}

export function normalizeStacksList(stacks) {
  if (!stacks || typeof stacks !== 'object') return [];
  if (Array.isArray(stacks)) {
    return stacks.filter(s => s && typeof s === 'object');
  }
  if (
    typeof stacks.primary === 'string' ||
    Array.isArray(stacks.stack) ||
    Array.isArray(stacks.detectedTags) ||
    (stacks.deviceInfo && typeof stacks.deviceInfo === 'object')
  ) {
    return [stacks];
  }
  return Object.entries(stacks)
    .filter(([, fp]) => fp && typeof fp === 'object')
    .map(([target, fp]) => ({ target, ...fp }));
}

export function renderDeviceInfoHtml(deviceInfo) {
  if (!deviceInfo || typeof deviceInfo !== 'object') return '';
  const hasPorts = Array.isArray(deviceInfo.openPorts) && deviceInfo.openPorts.length > 0;
  const hasServices = Array.isArray(deviceInfo.openServices) && deviceInfo.openServices.length > 0;
  if (!deviceInfo.detected && !deviceInfo.category && !hasPorts && !hasServices) {
    return '';
  }

  const categoryText = deviceInfo.categoryLabel || deviceInfo.category || 'Network Device';
  const titleText = deviceInfo.deviceName || deviceInfo.deviceType || '';
  const metaItems = [];
  if (deviceInfo.vendor && deviceInfo.vendor !== 'Unknown') {
    metaItems.push(`<span class="device-meta-item"><strong>Vendor:</strong> ${escapeHtml(deviceInfo.vendor)}</span>`);
  }
  if (deviceInfo.modelName) {
    metaItems.push(`<span class="device-meta-item"><strong>Model:</strong> ${escapeHtml(deviceInfo.modelName)}</span>`);
  }
  const osLabel = deviceInfo.os || deviceInfo.osFamily || '';
  if (osLabel) {
    metaItems.push(`<span class="device-meta-item"><strong>OS:</strong> ${escapeHtml(osLabel)}</span>`);
  }
  if (deviceInfo.macAddress) {
    metaItems.push(`<span class="device-meta-item"><strong>MAC:</strong> <code>${escapeHtml(deviceInfo.macAddress)}</code></span>`);
  }
  if (deviceInfo.firmwareVersion) {
    metaItems.push(`<span class="device-meta-item"><strong>Firmware:</strong> <code>${escapeHtml(deviceInfo.firmwareVersion)}</code></span>`);
  }
  if (deviceInfo.activeHttpOrigin) {
    metaItems.push(`<span class="device-meta-item"><strong>HTTP Origin:</strong> <code>${escapeHtml(deviceInfo.activeHttpOrigin)}</code></span>`);
  }
  if (deviceInfo.activeHttpsOrigin) {
    metaItems.push(`<span class="device-meta-item"><strong>HTTPS Origin:</strong> <code>${escapeHtml(deviceInfo.activeHttpsOrigin)}</code></span>`);
  }

  let portsHtml = '';
  if (hasServices) {
    const chips = deviceInfo.openServices.slice(0, 16).map(s => {
      const scheme = String(s?.scheme || 'tcp').toUpperCase();
      const label = s?.label || s?.service || '';
      return `<span class="device-port-chip"><code>${escapeHtml(s?.port)}/${escapeHtml(scheme)}</code>${label ? ` ${escapeHtml(label)}` : ''}</span>`;
    }).join('');
    portsHtml = `<div class="device-ports-list">${chips}</div>`;
  } else if (hasPorts) {
    const chips = deviceInfo.openPorts.slice(0, 16).map(p =>
      `<span class="device-port-chip"><code>${escapeHtml(p)}/TCP</code></span>`
    ).join('');
    portsHtml = `<div class="device-ports-list">${chips}</div>`;
  }

  const baseClosedNote = deviceInfo.basePortClosed
    ? '<div class="form-hint">Standard HTTP(S) 80/443 closed — device checks routed to active device ports.</div>'
    : '';

  return `
    <div class="device-info-card">
      <div class="device-info-header">
        <span class="device-cat-badge">📺 ${escapeHtml(categoryText)}</span>
        ${titleText ? `<span class="device-info-title">${escapeHtml(titleText)}</span>` : ''}
      </div>
      ${metaItems.length > 0 ? `<div class="device-meta-grid">${metaItems.join('')}</div>` : ''}
      ${portsHtml}
      ${baseClosedNote}
    </div>
  `;
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
    initLoginSequenceRecorder();
    initResultsToolbar();
    initEvidenceDrawer();
    initDualGraphTab();
    initHistoryAndDiff();
    initCatalogAndBuilder();

    loadMeta();
    loadHistory();
    loadSystemVariables();
    loadSavedLoginSequences();
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
    renderPresetCards();
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
  target = normalizeTargetScheme(target);
  input.value = target;

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
  const btnGetRealIp = document.getElementById('get-real-ip-btn');
  const btnAdvGetRealIp = document.getElementById('adv-get-real-ip-btn');
  const realIpSpinner = document.getElementById('real-ip-spinner');
  const realIpBtnText = document.getElementById('real-ip-btn-text');
  const realIpBanner = document.getElementById('real-ip-banner');
  const btnCloseRealIp = document.getElementById('real-ip-close-btn');
  const allowPrivateEl = document.getElementById('allow-private-toggle');
  const authUsernameEl = document.getElementById('adv-auth-username');
  const authPasswordEl = document.getElementById('adv-auth-password');
  const authLoginUrlEl = document.getElementById('adv-auth-login-url');
  const authTypeEl = document.getElementById('adv-auth-type');
  const recordedSessionIdEl = document.getElementById('adv-recorded-session-id');
  const btnRecordLogin = document.getElementById('btn-test-record-login');
  const btnDiscoverOpenApi = document.getElementById('btn-discover-openapi');
  const recordedSessionBanner = document.getElementById('recorded-session-banner');
  const btnCloseRecordedSession = document.getElementById('recorded-session-close-btn');

  if (btnCloseDetect && techBanner) {
    btnCloseDetect.addEventListener('click', () => {
      techBanner.classList.add('hidden');
    });
  }

  if (btnCloseRealIp && realIpBanner) {
    btnCloseRealIp.addEventListener('click', () => {
      realIpBanner.classList.add('hidden');
    });
  }

  if (btnCloseRecordedSession && recordedSessionBanner) {
    btnCloseRecordedSession.addEventListener('click', () => {
      recordedSessionBanner.classList.add('hidden');
    });
  }

  [authUsernameEl, authPasswordEl, authLoginUrlEl].forEach(el => {
    if (el && recordedSessionIdEl) {
      el.addEventListener('input', () => {
        recordedSessionIdEl.value = '';
      });
    }
  });

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
    if (val) {
      val = preserveBareIpOrNormalize(val);
      urlInput.value = val;
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

  if (btnDetect) {
    btnDetect.addEventListener('click', async () => {
      let target = urlInput.value.trim();
      if (!target) {
        urlInput.focus();
        return;
      }

      target = preserveBareIpOrNormalize(target);
      urlInput.value = target;

      if (!validateInputUrl(target)) {
        return;
      }

      const auth = document.getElementById('adv-auth')?.value.trim() || null;
      const timeout = parseInt(document.getElementById('adv-timeout')?.value, 10) || 10000;
      const allowPrivate = Boolean(allowPrivateEl?.checked);
      const deviceMode = state.selectedPreset === 'device';
      const deviceCategory = deviceMode ? (document.getElementById('opt-device-category')?.value || 'all') : 'all';

      btnDetect.disabled = true;
      if (detectSpinner) detectSpinner.classList.remove('hidden');
      if (detectBtnText) detectBtnText.textContent = 'Detecting...';

      try {
        const data = await apiPost('/api/fingerprint', {
          target,
          auth,
          timeout,
          allowPrivate,
          ...(deviceMode ? { deviceMode: true, deviceCategory } : {})
        });
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

  async function handleRealIpDiscovery() {
    let target = urlInput.value.trim();
    if (!target) {
      urlInput.focus();
      return;
    }

    target = preserveBareIpOrNormalize(target);
    urlInput.value = target;

    if (!validateInputUrl(target)) {
      return;
    }

    const allowPrivate = Boolean(allowPrivateEl?.checked);

    if (btnGetRealIp) btnGetRealIp.disabled = true;
    if (btnAdvGetRealIp) {
      btnAdvGetRealIp.disabled = true;
      btnAdvGetRealIp.textContent = '🌐 Resolving Real IP...';
    }
    if (realIpSpinner) realIpSpinner.classList.remove('hidden');
    if (realIpBtnText) realIpBtnText.textContent = 'Resolving...';

    try {
      const data = await apiPost('/api/real-ip', { target, allowPrivate });
      renderRealIpPreview(data);
    } catch (err) {
      if (bannerText) bannerText.textContent = `Real IP discovery failed: ${err.message}`;
      if (banner) banner.classList.remove('hidden');
    } finally {
      if (btnGetRealIp) btnGetRealIp.disabled = false;
      if (btnAdvGetRealIp) {
        btnAdvGetRealIp.disabled = false;
        btnAdvGetRealIp.textContent = '🌐 Auto-Find Real IP from Target URL';
      }
      if (realIpSpinner) realIpSpinner.classList.add('hidden');
      if (realIpBtnText) realIpBtnText.textContent = '🌐 Get Real IP';
    }
  }

  if (btnGetRealIp) {
    btnGetRealIp.addEventListener('click', handleRealIpDiscovery);
  }
  if (btnAdvGetRealIp) {
    btnAdvGetRealIp.addEventListener('click', handleRealIpDiscovery);
  }

  async function handleRecordLoginSession() {
    let target = urlInput.value.trim();
    if (!target) {
      urlInput.focus();
      return;
    }

    target = normalizeTargetScheme(target);
    urlInput.value = target;

    if (!validateInputUrl(target)) {
      return;
    }

    const username = authUsernameEl?.value.trim() || '';
    const password = authPasswordEl?.value || '';
    const loginUrlRaw = authLoginUrlEl?.value.trim() || '';
    const loginUrl = loginUrlRaw ? normalizeTargetScheme(loginUrlRaw) : '';
    const loginContentType = authTypeEl?.value || 'auto';
    const sourceIp = document.getElementById('adv-source-ip')?.value.trim() || '';
    const allowPrivate = Boolean(allowPrivateEl?.checked);

    if (btnRecordLogin) {
      btnRecordLogin.disabled = true;
      btnRecordLogin.textContent = '🔐 Recording Login Session...';
    }

    try {
      const data = await apiPost('/api/auth/record-session', {
        targetUrl: target,
        ...(loginUrl ? { loginUrl } : {}),
        username,
        password,
        loginContentType,
        ...(sourceIp ? { sourceIp } : {}),
        allowPrivate
      });
      if (recordedSessionIdEl) {
        recordedSessionIdEl.value = data.sessionId || '';
      }
      renderRecordedSessionPreview(data);
    } catch (err) {
      if (bannerText) bannerText.textContent = `Login recording failed: ${err.message}`;
      if (banner) banner.classList.remove('hidden');
    } finally {
      if (btnRecordLogin) {
        btnRecordLogin.disabled = false;
        btnRecordLogin.textContent = '🔐 Test & Record Login Session';
      }
    }
  }

  async function handleDiscoverOpenApi() {
    let target = urlInput.value.trim();
    if (!target) {
      urlInput.focus();
      return;
    }

    target = normalizeTargetScheme(target);
    urlInput.value = target;

    if (!validateInputUrl(target)) {
      return;
    }

    const allowPrivate = Boolean(allowPrivateEl?.checked);
    if (btnDiscoverOpenApi) {
      btnDiscoverOpenApi.disabled = true;
      btnDiscoverOpenApi.textContent = '📋 Discovering OpenAPI Routes...';
    }

    try {
      const data = await apiPost('/api/openapi/import', {
        targetUrl: target,
        allowPrivate
      });
      renderOpenApiDiscoveryPreview(data);
    } catch (err) {
      if (bannerText) bannerText.textContent = `OpenAPI discovery failed: ${err.message}`;
      if (banner) banner.classList.remove('hidden');
    } finally {
      if (btnDiscoverOpenApi) {
        btnDiscoverOpenApi.disabled = false;
        btnDiscoverOpenApi.textContent = '📋 Discover OpenAPI / Swagger Routes';
      }
    }
  }

  if (btnRecordLogin) {
    btnRecordLogin.addEventListener('click', handleRecordLoginSession);
  }
  if (btnDiscoverOpenApi) {
    btnDiscoverOpenApi.addEventListener('click', handleDiscoverOpenApi);
  }

  const btnAnalyzeDetectApi = document.getElementById('btn-analyze-detect-api');
  if (btnAnalyzeDetectApi) {
    btnAnalyzeDetectApi.addEventListener('click', generateDetectApiAiAnalysis);
  }

  // Delegated listener for backend API scan & Real IP candidate actions
  document.addEventListener('click', e => {
    const scanOriginBtn = e.target.closest('[data-scan-origin]');
    if (scanOriginBtn) {
      const rawOrigin = scanOriginBtn.getAttribute('data-scan-origin') || '';
      handleScanOriginTrigger(rawOrigin);
      return;
    }

    const pinSourceBtn = e.target.closest('[data-pin-source-ip]');
    if (pinSourceBtn) {
      const ip = (pinSourceBtn.getAttribute('data-pin-source-ip') || '').trim();
      if (!isValidIpLiteral(ip)) return;
      const sourceIpInput = document.getElementById('adv-source-ip');
      if (sourceIpInput) {
        sourceIpInput.value = ip;
      }
      if (advDrawer && advDrawer.classList.contains('hidden')) {
        btnToggleAdv?.setAttribute('aria-expanded', 'true');
        advDrawer.classList.remove('hidden');
      }
      sourceIpInput?.focus();
      return;
    }

    const useDirectBtn = e.target.closest('[data-use-direct-ip]');
    if (useDirectBtn) {
      const ip = (useDirectBtn.getAttribute('data-use-direct-ip') || '').trim();
      if (!isValidIpLiteral(ip)) return;
      const formattedHost = ip.includes(':') ? `[${ip}]` : ip;
      urlInput.value = 'http://' + formattedHost;
      validateInputUrl(urlInput.value.trim());
      urlInput.focus();
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

    target = preserveBareIpOrNormalize(target);
    urlInput.value = target;

    if (!validateInputUrl(target)) {
      return;
    }

    const depth = parseInt(document.getElementById('adv-depth').value, 10) || 3;
    const concurrency = parseInt(document.getElementById('adv-concurrency').value, 10) || 5;
    const timeout = parseInt(document.getElementById('adv-timeout').value, 10) || 10000;
    const auth = document.getElementById('adv-auth').value.trim() || null;
    const tech = document.getElementById('adv-tech').value.trim() || null;
    const sourceIp = document.getElementById('adv-source-ip')?.value.trim() || null;
    const checksFilter = document.getElementById('adv-checks')?.value.trim() || null;
    const forceAll = Boolean(document.getElementById('opt-force-all')?.checked);
    const saveHistory = document.getElementById('adv-save-history').checked;
    const agentMode = Boolean(document.getElementById('opt-agent-mode')?.checked);
    const goal = document.getElementById('opt-agent-goal')?.value.trim() || '';
    const noiseProfile = document.getElementById('opt-noise-profile')?.value || 'balanced';
    const allowPrivate = Boolean(allowPrivateEl?.checked);
    const username = document.getElementById('adv-auth-username')?.value.trim() || null;
    const password = document.getElementById('adv-auth-password')?.value || null;
    const loginUrlRaw = document.getElementById('adv-auth-login-url')?.value.trim() || null;
    const loginContentType = document.getElementById('adv-auth-type')?.value || 'auto';
    const recordedSessionId = document.getElementById('adv-recorded-session-id')?.value.trim() || null;
    const authMethod = document.getElementById('adv-auth-method')?.value || 'login_sequence';
    syncLsrConfigFromInputs();
    const lsrPayload = buildLoginSequencePayload({ includeSecrets: true });
    const hasLsrActions = Array.isArray(lsrPayload.actions) && lsrPayload.actions.length > 0;
    const hasLsrSecrets = Array.isArray(lsrPayload.secrets) && lsrPayload.secrets.length > 0;
    const hasLsrOtp = Boolean(lsrPayload.otpConfig?.secret || lsrPayload.otpConfig?.enabled);
    const useLoginSequence = authMethod === 'login_sequence' || hasLsrActions;

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

    const deviceMode = state.selectedPreset === 'device';
    const deviceCategory = deviceMode ? (document.getElementById('opt-device-category')?.value || 'all') : 'all';

    await startScan({
      target,
      profile: state.selectedPreset,
      ...(deviceMode ? { deviceMode: true, deviceCategory } : {}),
      forceAll,
      maxDepth: depth,
      concurrency,
      timeout,
      auth,
      ...(sourceIp ? { sourceIp } : {}),
      ...(checksFilter ? { checks: checksFilter } : {}),
      ...(parsedHeaders.headers ? { headers: parsedHeaders.headers } : {}),
      ...(username ? { username } : {}),
      ...(password ? { password } : {}),
      ...(loginUrlRaw ? { loginUrl: normalizeTargetScheme(loginUrlRaw) } : {}),
      ...(username || loginUrlRaw ? { loginContentType } : {}),
      ...(recordedSessionId ? { recordedSessionId } : {}),
      ...(useLoginSequence && (hasLsrActions || lsrPayload.sequenceId) ? { loginSequence: lsrPayload, sequenceId: state.loginSequence.sequenceId || '' } : {}),
      systemVariables: state.systemVariables,
      ...(hasLsrSecrets ? { secrets: lsrPayload.secrets } : {}),
      ...(hasLsrOtp ? { otpConfig: lsrPayload.otpConfig } : {}),
      ...(lsrPayload.restrictions?.length ? { restrictions: lsrPayload.restrictions } : {}),
      ...(useLoginSequence ? { sessionDetection: lsrPayload.sessionDetection } : {}),
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
  const isDevice = presetId === 'device';
  const catWrap = document.getElementById('device-category-wrap');
  if (catWrap) {
    catWrap.classList.toggle('hidden', !isDevice);
  }
  if (isDevice) {
    const allowPrivateEl = document.getElementById('allow-private-toggle');
    if (allowPrivateEl && !allowPrivateEl.checked) {
      allowPrivateEl.checked = true;
    }
    const urlInput = document.getElementById('target-url');
    if (urlInput) {
      validateInputUrl(urlInput.value.trim());
    }
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
  const primaryStack = normalizeStacksList(resData.stacks)[0] || null;
  const apiComm = resData.apiCommunication || primaryStack?.apiCommunication || null;
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

  const deviceRowEl = document.getElementById('tech-detect-device-row');
  if (deviceRowEl) {
    const devHtml = renderDeviceInfoHtml(fp.deviceInfo || data.deviceInfo || null);
    deviceRowEl.innerHTML = devHtml;
    deviceRowEl.classList.toggle('hidden', !devHtml);
  }

  renderTechDetectScaPreview(fp.runtimeSca || data.runtimeSca || null);

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

export function renderRealIpPreview(data) {
  if (typeof document === 'undefined') return;
  const banner = document.getElementById('real-ip-banner');
  if (!banner || !data) return;

  const primaryBadge = document.getElementById('real-ip-primary-badge');
  const cdnBadge = document.getElementById('real-ip-cdn-badge');
  const bodyEl = document.getElementById('real-ip-body');

  if (primaryBadge) {
    primaryBadge.textContent = data.realIp
      ? `Real IP: ${data.realIp} (${data.realIpConfidence || 100}% confidence)`
      : 'No Origin IP Found';
  }

  if (cdnBadge) {
    cdnBadge.textContent = data.isBehindCdn
      ? `Behind CDN/WAF: ${data.cdnProvider || 'Detected'}`
      : 'Direct Server (No CDN)';
  }

  if (bodyEl) {
    const primaryIpsText = (Array.isArray(data.primaryIps) ? data.primaryIps : []).join(', ') || 'None';
    const candidates = Array.isArray(data.candidates) ? data.candidates : [];

    const candidateRowsHtml = candidates.length > 0
      ? candidates.map(c => {
          const ip = String(c?.ip || '');
          const sourcesText = (Array.isArray(c?.sources) ? c.sources : []).join(', ') || '—';
          const statusLabel = c?.blockedByPolicy
            ? 'Blocked by Policy'
            : c?.isCdnEdge
              ? `CDN Edge (${c.cdnProvider || 'CDN'})`
              : c?.verifiedOriginMatch
                ? '✅ Verified Origin Match'
                : 'Origin Candidate';
          const confidenceText = `${Number(c?.confidence) || 0}%`;
          const reasonText = String(c?.reason || '');
          const actionsHtml = !c?.blockedByPolicy && isValidIpLiteral(ip)
            ? `
              <div class="real-ip-candidate-actions">
                <button type="button" class="btn-secondary btn-small" data-pin-source-ip="${escapeHtml(ip)}">📌 Pin as --source-ip</button>
                <button type="button" class="btn-secondary btn-small" data-use-direct-ip="${escapeHtml(ip)}">🎯 Switch Target to http://${escapeHtml(ip)}</button>
              </div>
            `
            : '';

          return `
            <div class="real-ip-candidate-row">
              <div class="real-ip-candidate-meta">
                <code>${escapeHtml(ip)}</code>
                <span class="badge">${escapeHtml(statusLabel)}</span>
                <span class="badge badge-confidence">${escapeHtml(confidenceText)}</span>
                <span class="form-hint">Sources: ${escapeHtml(sourcesText)}</span>
              </div>
              ${reasonText ? `<div class="real-ip-candidate-reason">${escapeHtml(reasonText)}</div>` : ''}
              ${actionsHtml}
            </div>
          `;
        }).join('')
      : '<div class="form-hint">No candidate IP addresses discovered.</div>';

    bodyEl.innerHTML = `
      <div class="tech-detect-summary-row">
        <span><strong>Hostname:</strong> <code>${escapeHtml(data.hostname || '—')}</code></span>
        <span> · <strong>Primary DNS A/AAAA:</strong> <code>${escapeHtml(primaryIpsText)}</code></span>
        <span> · <strong>Recommended Real IP:</strong> <code>${escapeHtml(data.realIp || 'N/A')}</code></span>
      </div>
      <div class="real-ip-candidates-list">
        ${candidateRowsHtml}
      </div>
    `;
  }

  banner.classList.remove('hidden');
  banner.scrollIntoView?.({ behavior: 'smooth', block: 'nearest' });
}

export function renderRecordedSessionPreview(data) {
  if (typeof document === 'undefined') return;
  const banner = document.getElementById('recorded-session-banner');
  if (!banner || !data) return;

  const statusBadge = document.getElementById('recorded-session-status-badge');
  const cookiesBadge = document.getElementById('recorded-session-cookies-badge');
  const bodyEl = document.getElementById('recorded-session-body');

  if (statusBadge) {
    statusBadge.textContent = data.authenticated
      ? `Authenticated (Session ${String(data.sessionId || '').slice(0, 8)})`
      : 'Login Incomplete';
  }

  if (cookiesBadge) {
    cookiesBadge.textContent = `${data.cookieCount || 0} Cookie(s) · JWT: ${data.hasBearerToken ? 'Captured' : 'None'}`;
  }

  if (bodyEl) {
    const cookieNamesText = Array.isArray(data.cookieNames) && data.cookieNames.length > 0
      ? data.cookieNames.join(', ')
      : 'None';
    const csrfText = data.csrfHeaderName || data.csrfFormField || 'None';
    const jwtText = data.bearerTokenPreview || (data.hasBearerToken ? 'Captured' : 'None');
    const steps = Array.isArray(data.steps) ? data.steps : [];

    const stepsHtml = steps.length > 0
      ? steps.map(step => {
          const stepNum = Number(step?.step) || 0;
          const action = String(step?.action || 'step');
          const url = String(step?.url || '');
          const status = Number(step?.status) || 0;
          const extra = [];
          if (step?.contentType) extra.push(`type=${step.contentType}`);
          if (step?.csrfDetected) extra.push('CSRF detected');
          if (step?.tokenExtracted) extra.push('JWT captured');
          if (Array.isArray(step?.cookiesHarvested) && step.cookiesHarvested.length > 0) {
            extra.push(`cookies: ${step.cookiesHarvested.join(', ')}`);
          }
          if (step?.error) extra.push(`error: ${step.error}`);
          return `
            <div class="real-ip-candidate-row">
              <div class="real-ip-candidate-meta">
                <span class="badge">Step ${escapeHtml(stepNum)}</span>
                <strong>${escapeHtml(action)}</strong>
                <code>${escapeHtml(url)}</code>
                <span class="badge badge-confidence">HTTP ${escapeHtml(status)}</span>
              </div>
              ${extra.length > 0 ? `<div class="real-ip-candidate-reason">${escapeHtml(extra.join(' · '))}</div>` : ''}
            </div>
          `;
        }).join('')
      : '<div class="form-hint">No login macro steps recorded yet.</div>';

    bodyEl.innerHTML = `
      <div class="tech-detect-summary-row">
        <span><strong>Login URL:</strong> <code>${escapeHtml(data.loginUrl || '—')}</code></span>
        <span> · <strong>Username:</strong> <code>${escapeHtml(data.username || '—')}</code></span>
        <span> · <strong>Cookies Captured:</strong> <code>${escapeHtml(cookieNamesText)}</code></span>
        <span> · <strong>CSRF Header/Field:</strong> <code>${escapeHtml(csrfText)}</code></span>
        <span> · <strong>Bearer JWT:</strong> <code>${escapeHtml(jwtText)}</code></span>
      </div>
      <div class="real-ip-candidates-list">
        ${stepsHtml}
      </div>
    `;
  }

  banner.classList.remove('hidden');
  banner.scrollIntoView?.({ behavior: 'smooth', block: 'nearest' });
}

export function renderOpenApiDiscoveryPreview(data) {
  if (typeof document === 'undefined') return;
  const banner = document.getElementById('recorded-session-banner');
  if (!banner || !data) return;

  const statusBadge = document.getElementById('recorded-session-status-badge');
  const cookiesBadge = document.getElementById('recorded-session-cookies-badge');
  const bodyEl = document.getElementById('recorded-session-body');

  const endpoints = Array.isArray(data.endpoints) ? data.endpoints : [];
  if (statusBadge) {
    statusBadge.textContent = data.discovered ? 'OpenAPI / Swagger Discovered' : 'No OpenAPI Schema Found';
  }
  if (cookiesBadge) {
    cookiesBadge.textContent = `${Number(data.totalEndpoints) || endpoints.length} Endpoint(s)`;
  }

  if (bodyEl) {
    const routesHtml = endpoints.length > 0
      ? endpoints.slice(0, 50).map(ep => `
          <div class="real-ip-candidate-row">
            <div class="real-ip-candidate-meta">
              <span class="badge">${escapeHtml(ep?.method || 'GET')}</span>
              <code>${escapeHtml(ep?.url || ep?.pathTemplate || '')}</code>
              ${ep?.operationId ? `<span class="form-hint">${escapeHtml(ep.operationId)}</span>` : ''}
              ${ep?.requiresAuth ? '<span class="badge badge-confidence">Auth</span>' : ''}
            </div>
            ${ep?.summary ? `<div class="real-ip-candidate-reason">${escapeHtml(ep.summary)}</div>` : ''}
          </div>
        `).join('')
      : '<div class="form-hint">No OpenAPI or Swagger specification found at standard discovery paths (/openapi.json, /swagger.json, /v3/api-docs).</div>';

    bodyEl.innerHTML = `
      <div class="tech-detect-summary-row">
        <span><strong>Specification:</strong> <code>${escapeHtml(data.title || 'OpenAPI')} (${escapeHtml(data.version || 'N/A')})</code></span>
        <span> · <strong>Schema URL:</strong> <code>${escapeHtml(data.schemaUrl || 'Not Found')}</code></span>
        <span> · <strong>Endpoints:</strong> <code>${escapeHtml(Number(data.totalEndpoints) || endpoints.length)}</code></span>
      </div>
      <div class="real-ip-candidates-list">
        ${routesHtml}
      </div>
    `;
  }

  banner.classList.remove('hidden');
  banner.scrollIntoView?.({ behavior: 'smooth', block: 'nearest' });
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
    {
      id: 'device',
      name: 'Smart TV, Camera, PC & LAN Device',
      tagline: 'Smart TVs, IP Cameras / NVRs, PCs / Workstations / Dev Servers, Routers & IoT',
      description: 'Non-intrusive multi-port device discovery and security audit for Smart TVs, IP cameras / NVRs, PCs / workstations / local servers, routers, printers, NAS, and smart home IoT hubs.'
    },
    { id: 'ops', name: 'Ops & System Health', tagline: 'Server health, metrics, actuator, TLS & availability checks' }
  ];

  if (!basePresets.some(p => p.id === 'device') && state.profiles?.device) {
    basePresets.push({
      id: 'device',
      name: 'Smart TV, Camera, PC & LAN Device',
      tagline: state.profiles.device.description || 'Smart TVs, IP Cameras / NVRs, PCs / Workstations / Dev Servers, Routers & IoT'
    });
  }

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
  const liveDeviceSummaryEl = document.getElementById('live-device-summary');
  if (liveDeviceSummaryEl) {
    liveDeviceSummaryEl.classList.add('hidden');
    liveDeviceSummaryEl.innerHTML = '';
  }
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

        if (data.type === 'auth_session' && data.authSession) {
          renderRecordedSessionPreview(data.authSession);
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

          const deviceInfo = data.deviceInfo || data.fingerprint?.deviceInfo || null;
          if (deviceInfo && (deviceInfo.detected || deviceInfo.category || (Array.isArray(deviceInfo.openPorts) && deviceInfo.openPorts.length > 0))) {
            const devChip = document.createElement('span');
            devChip.className = 'chip chip-device-active';
            devChip.textContent = `📺 ${deviceInfo.categoryLabel || deviceInfo.category || 'Device'}`;
            liveTechChips.appendChild(devChip);
            if (Array.isArray(deviceInfo.openPorts) && deviceInfo.openPorts.length > 0) {
              const portsChip = document.createElement('span');
              portsChip.className = 'chip';
              portsChip.textContent = `Ports: ${deviceInfo.openPorts.slice(0, 8).join(', ')}`;
              liveTechChips.appendChild(portsChip);
            }
            const liveDevEl = document.getElementById('live-device-summary');
            if (liveDevEl) {
              const devHtml = renderDeviceInfoHtml(deviceInfo);
              liveDevEl.innerHTML = devHtml;
              liveDevEl.classList.toggle('hidden', !devHtml);
            }
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
      'auth_session',
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
    stack: normalizeStacksList(state.currentResults?.stacks)[0] || null,
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

  const stackList = normalizeStacksList(resultData.stacks);
  const primaryStack = stackList[0] || null;
  const deviceInfo = stackList.find(s => s?.deviceInfo)?.deviceInfo || resultData.deviceInfo || null;
  const stackCard = document.getElementById('results-stack-card');
  if (stackCard) {
    if (stackList.length > 0 || deviceInfo?.detected) {
      const summaryEl = document.getElementById('results-stack-summary');
      const counterEl = document.getElementById('results-stack-counter');
      const badgesEl = document.getElementById('results-stack-badges');
      const deviceInfoEl = document.getElementById('results-device-info');

      if (summaryEl) {
        summaryEl.textContent = primaryStack?.summary || deviceInfo?.summary || 'Generic Web Application';
      }

      const activeCount = Number(primaryStack?.activeChecksCount) || grouped.length;
      const skippedCount = Number(primaryStack?.skippedChecksCount) || 0;

      if (counterEl) {
        counterEl.innerHTML = `<strong>${activeCount} Relevant Checks Executed · ${skippedCount} Irrelevant Framework Checks Skipped</strong>`;
      }

      const tags = Array.isArray(primaryStack?.detectedTags) && primaryStack.detectedTags.length > 0
        ? primaryStack.detectedTags
        : Array.isArray(primaryStack?.stack) && primaryStack.stack.length > 0
        ? primaryStack.stack.map(s => s.tech)
        : ['generic'];

      if (badgesEl) {
        badgesEl.innerHTML = tags.map(tag => {
          const cleanTag = escapeHtml(String(tag).trim());
          const safeClass = cleanTag.toLowerCase().replace(/[^a-z0-9_-]/gi, '');
          return `<span class="tech-badge tech-tag-${safeClass}">${cleanTag}</span>`;
        }).join('');
      }

      if (deviceInfoEl) {
        const devHtml = renderDeviceInfoHtml(deviceInfo);
        deviceInfoEl.innerHTML = devHtml;
        deviceInfoEl.classList.toggle('hidden', !devHtml);
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

  const apiComm = resultData.apiCommunication || primaryStack?.apiCommunication || null;
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

  const runtimeSca = resultData.runtimeSca
    || primaryStack?.runtimeSca
    || stackList.find(s => s?.runtimeSca)?.runtimeSca
    || results.find(r => r && (r.name === 'runtime-sca' || r.checkId === 'runtime-sca') && r.runtimeSca)?.runtimeSca
    || null;
  renderRuntimeScaTable(runtimeSca);

  renderCrawlInventorySection(resultData);
  renderResultsCveCoverageBanner(resultData.cveCoverage);
  renderPriorityActionPlan(vulns, suspicious);
  filterAndRenderFindings();
}

export function renderCrawlInventorySection(resultData) {
  const card = document.getElementById('results-crawl-inventory-card');
  if (!card) return;

  const menus = Array.isArray(resultData?.discoveredMenus) ? resultData.discoveredMenus : [];
  const forms = Array.isArray(resultData?.discoveredForms) ? resultData.discoveredForms : [];
  const rawPages = Array.isArray(resultData?.discoveredPages) && resultData.discoveredPages.length > 0
    ? resultData.discoveredPages
    : Array.from(new Set((Array.isArray(resultData?.results) ? resultData.results : []).map(r => r?.target).filter(Boolean)));

  if (menus.length === 0 && forms.length === 0 && rawPages.length <= 1) {
    card.classList.add('hidden');
    return;
  }

  const menusCountEl = document.getElementById('results-menus-count');
  const formsCountEl = document.getElementById('results-forms-count');
  const summaryEl = document.getElementById('results-crawl-inventory-summary');
  const kpisEl = document.getElementById('results-crawl-inventory-kpis');
  const groupsSummaryEl = document.getElementById('results-menus-groups-summary');
  const menusWrapEl = document.getElementById('results-menus-table-wrap');
  const menusTbody = document.getElementById('results-menus-tbody');
  const formsWrapEl = document.getElementById('results-forms-table-wrap');
  const formsTbody = document.getElementById('results-forms-tbody');
  const crawledCountEl = document.getElementById('results-crawled-urls-count');
  const crawledListEl = document.getElementById('results-crawled-urls-list');

  if (menusCountEl) menusCountEl.textContent = String(menus.length);
  if (formsCountEl) formsCountEl.textContent = String(forms.length);
  if (crawledCountEl) crawledCountEl.textContent = String(rawPages.length);

  // Group menus by parentMenu
  const groupCounts = new Map();
  for (const m of menus) {
    const g = String(m?.parentMenu || 'Main Menu').trim();
    groupCounts.set(g, (groupCounts.get(g) || 0) + 1);
  }

  if (summaryEl) {
    summaryEl.textContent = `Discovered ${menus.length} menu/submenu item(s) across ${groupCounts.size} navigation group(s), tested ${forms.length} form(s), and audited ${rawPages.length} unique URL(s).`;
  }

  const crawledMenusCount = menus.filter(m => m?.auditStatus === 'crawled' || m?.kind === 'submenu' || m?.kind === 'menu' || m?.kind === 'spa_route').length;
  if (kpisEl) {
    kpisEl.innerHTML = `
      <span class="ev-pill">Menu Groups: <strong>${groupCounts.size}</strong></span>
      <span class="ev-pill">Submenus &amp; Views: <strong>${menus.length}</strong></span>
      <span class="ev-pill">Forms Tested: <strong>${forms.length}</strong></span>
      <span class="ev-pill">Pages Audited: <strong>${rawPages.length}</strong></span>
    `;
  }

  if (groupsSummaryEl) {
    if (groupCounts.size > 0) {
      groupsSummaryEl.innerHTML = Array.from(groupCounts.entries())
        .map(([gName, count]) => `<span class="ev-pill">📂 <strong>${escapeHtml(gName)}</strong> (${count} item${count === 1 ? '' : 's'})</span>`)
        .join(' ');
      groupsSummaryEl.classList.remove('hidden');
    } else {
      groupsSummaryEl.innerHTML = '';
      groupsSummaryEl.classList.add('hidden');
    }
  }

  if (menusWrapEl && menusTbody) {
    if (menus.length > 0) {
      menusWrapEl.classList.remove('hidden');
      menusTbody.innerHTML = menus.map(m => {
        const parentMenu = escapeHtml(m.parentMenu || 'Main Menu');
        const label = escapeHtml(m.label || 'Menu Item');
        const kind = String(m.kind || 'menu');
        const kindBadge = kind === 'submenu'
          ? '<span class="ev-pill">Submenu</span>'
          : kind === 'spa_route'
            ? '<span class="ev-pill">SPA View</span>'
            : kind === 'external_app'
              ? '<span class="ev-pill">External App</span>'
              : kind === 'logout'
                ? '<span class="ev-pill">Logout Link</span>'
                : '<span class="ev-pill">Top Menu</span>';
        const ctrlText = m.controller ? ` · <code>${escapeHtml(m.controller)}</code>` : '';
        const triggerText = m.trigger ? `<div class="form-hint"><code>${escapeHtml(m.trigger)}</code>${ctrlText}</div>` : ctrlText;
        const urlHtml = m.url ? `<code>${escapeHtml(m.url)}</code>` : '<span class="form-hint">Client-side action</span>';

        const status = m.auditStatus || (kind === 'logout' ? 'logout_protected' : kind === 'external_app' ? 'external_app' : 'crawled');
        const statusBadge = status === 'logout_protected'
          ? '<span class="finding-status-badge safe" title="Skipped to preserve authenticated session">🛡️ Protected (Logout Guard)</span>'
          : status === 'external_app'
            ? '<span class="ev-pill" title="Points to a different application outside target subpath">↗ External App Link</span>'
            : '<span class="finding-status-badge safe">✓ Crawled &amp; Audited</span>';

        return `
          <tr>
            <td><strong>${parentMenu}</strong></td>
            <td><strong>${label}</strong></td>
            <td>${kindBadge}${triggerText}</td>
            <td>${urlHtml}</td>
            <td>${statusBadge}</td>
          </tr>
        `;
      }).join('');
    } else {
      menusTbody.innerHTML = '<tr><td colspan="5" class="empty-muted">No navigation menu or dropdown submenu blocks detected on crawled pages.</td></tr>';
    }
  }

  if (formsWrapEl && formsTbody) {
    if (forms.length > 0) {
      formsWrapEl.classList.remove('hidden');
      formsTbody.innerHTML = forms.map(f => {
        const formName = escapeHtml(f.formName || f.formId || 'HTML Form');
        const method = escapeHtml(String(f.method || 'GET').toUpperCase());
        const methodBadge = method === 'POST'
          ? '<span class="finding-status-badge suspicious">POST</span>'
          : '<span class="ev-pill">GET</span>';
        const typeLabel = f.formType === 'spa_view_controls' ? '<div class="form-hint">SPA View Controls</div>' : '';
        const pageUrl = escapeHtml(f.pageUrl || '');
        const actionUrl = escapeHtml(f.actionUrl || f.pageUrl || '');
        const fields = Array.isArray(f.fields) ? f.fields : [];
        const fieldsHtml = fields.length > 0
          ? fields.map(fld => `<span class="ev-pill"><code>${escapeHtml(fld.name)}</code> <small>(${escapeHtml(fld.type || 'text')})</small></span>`).join(' ')
          : '<span class="form-hint">No editable inputs</span>';
        const csrfHtml = f.csrfField
          ? `<span class="finding-status-badge safe">🔒 ${escapeHtml(f.csrfField)}</span>`
          : '<span class="form-hint">None</span>';
        const checks = Array.isArray(f.checksRun) && f.checksRun.length > 0
          ? f.checksRun
          : ['sqli', 'xss', 'open-redirect', 'php-lfi'];
        const checksHtml = checks.map(c => `<span class="enrich-badge enrich-cwe">${escapeHtml(c)}</span>`).join(' ');

        return `
          <tr>
            <td><strong>${formName}</strong>${typeLabel}</td>
            <td>${methodBadge}</td>
            <td>
              <div><small>Page:</small> <code>${pageUrl}</code></div>
              ${actionUrl !== pageUrl ? `<div><small>Action:</small> <code>${actionUrl}</code></div>` : ''}
            </td>
            <td>${fieldsHtml}</td>
            <td>${csrfHtml}</td>
            <td>${checksHtml}</td>
          </tr>
        `;
      }).join('');
    } else {
      formsTbody.innerHTML = '<tr><td colspan="6" class="empty-muted">No interactive HTML or SPA forms found on crawled pages.</td></tr>';
    }
  }

  if (crawledListEl) {
    crawledListEl.innerHTML = rawPages.map(u => `<div class="evidence-file-row"><code>${escapeHtml(u)}</code></div>`).join('');
  }

  card.classList.remove('hidden');
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
  const primaryForCompact = normalizeStacksList(src.stacks)[0] || null;
  return {
    targets: Array.isArray(src.targets) ? src.targets.slice(0, 10) : [],
    stacks: primaryForCompact?.primary ? { primary: primaryForCompact.primary } : null,
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

export function renderMatchedEvidenceHtml(item) {
  if (!item) return '';
  const files = Array.isArray(item.files) && item.files.length > 0
    ? item.files
    : (Array.isArray(item.findings) ? item.findings : []);
  const quotes = Array.isArray(item.evidenceQuotes) ? item.evidenceQuotes : [];
  const missing = Array.isArray(item.missing) ? item.missing : [];
  if (files.length === 0 && quotes.length === 0 && missing.length === 0) return '';

  const filesHtml = files.length > 0
    ? `<div class="finding-why-box"><strong>📂 Matched Paths / Evidence (${files.length}):</strong><div class="evidence-files-list">${files.slice(0, 12).map(f => {
        const statusTag = f?.statusTag ? String(f.statusTag).trim().toUpperCase() : '';
        const statusTagClass = statusTag.toLowerCase().replace(/[^a-z0-9_-]/g, '');
        const statusTagBadge = statusTag
          ? `<span class="finding-status-badge ${escapeHtml(statusTagClass)}">${escapeHtml(statusTag)}</span> `
          : '';
        const hasPort = f?.port !== undefined && f?.port !== null && f?.port !== '';
        const schemeSuffix = f?.scheme ? `/${escapeHtml(String(f.scheme).toUpperCase())}` : '';
        const portBadge = hasPort
          ? `<span class="ev-pill device-port-pill">Port ${escapeHtml(f.port)}${schemeSuffix}</span> `
          : '';
        const labelText = f?.name && (!f?.path || f.path === '/')
          ? `${f.name}${f.url ? ` (${f.url})` : ''}`
          : (f?.path || f?.url || f?.name || '');
        const protoMethod = f?.method ? String(f.method).trim().toUpperCase() : '';
        const isNonHttp = /^(TCP|UDP|RTSP|MDNS)$/.test(protoMethod);
        const statusText = isNonHttp
          ? ` (${escapeHtml(protoMethod)})`
          : (f?.status ? ` (HTTP ${escapeHtml(f.status)})` : '');
        const detailText = f?.matchedSignal
          ? ` — ${escapeHtml(f.matchedSignal)}`
          : (f?.detail || f?.issue || f?.reason ? ` — ${escapeHtml(f.detail || f.issue || f.reason)}` : '');
        const previewText = f?.preview ? ` · <code>${escapeHtml(f.preview)}</code>` : '';
        return `<div class="evidence-file-row">${statusTagBadge}${portBadge}<code>${escapeHtml(labelText)}</code>${statusText}${detailText}${previewText}</div>`;
      }).join('')}</div></div>`
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
          stack: normalizeStacksList(state.currentResults?.stacks)[0] || null,
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
      const primaryStackTags = normalizeStacksList(state.currentResults?.stacks)[0]?.detectedTags || [];
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


// ── Runtime SCA Findings Table & Tech Detect Preview ─────────────────────────
export function renderTechDetectScaPreview(runtimeSca) {
  if (typeof document === 'undefined') return;
  const rowEl = document.getElementById('tech-detect-sca-row');
  if (!rowEl) return;

  const findings = Array.isArray(runtimeSca?.findings)
    ? runtimeSca.findings
    : (Array.isArray(runtimeSca) ? runtimeSca : []);

  if (findings.length === 0) {
    rowEl.innerHTML = '';
    rowEl.classList.add('hidden');
    return;
  }

  const outOfDate = findings.filter(f => f?.status === 'Out of date' || f?.isOutOfDate);
  const badgesHtml = findings.slice(0, 10).map(item => {
    const isOld = item?.status === 'Out of date' || item?.isOutOfDate;
    const cls = isOld ? 'sca-status-pill out-of-date' : 'sca-status-pill up-to-date';
    const cvss = Number(item?.highestCvss || 0).toFixed(1);
    const nameVer = `${item?.name || item?.id || 'Tech'} ${item?.identifiedVersion || ''}`.trim();
    return `<span class="${cls}">${isOld ? '⚠️' : '✅'} ${escapeHtml(nameVer)}${Number(item?.highestCvss) > 0 ? ` (CVSS ${escapeHtml(cvss)})` : ''}</span>`;
  }).join('');

  rowEl.innerHTML = `
    <div class="tech-detect-sca-header">
      <span class="tech-detect-label">📦 Runtime SCA (${escapeHtml(findings.length)} detected${outOfDate.length > 0 ? ` · ${escapeHtml(outOfDate.length)} out of date` : ''}):</span>
    </div>
    <div class="tech-detect-sca-pills">${badgesHtml}</div>
  `;
  rowEl.classList.remove('hidden');
}

export function renderRuntimeScaTable(runtimeSca) {
  if (typeof document === 'undefined') return;
  const card = document.getElementById('results-runtime-sca-card');
  const countEl = document.getElementById('results-sca-count');
  const kpisEl = document.getElementById('results-sca-kpis');
  const tbody = document.getElementById('results-runtime-sca-tbody');
  if (!card || !tbody) return;

  const findings = Array.isArray(runtimeSca?.findings)
    ? runtimeSca.findings
    : (Array.isArray(runtimeSca) ? runtimeSca : []);

  if (findings.length === 0) {
    tbody.innerHTML = '';
    if (countEl) countEl.textContent = '0';
    if (kpisEl) kpisEl.innerHTML = '';
    card.classList.add('hidden');
    return;
  }

  const outOfDateCount = findings.filter(f => f?.status === 'Out of date' || f?.isOutOfDate).length;
  const upToDateCount = findings.length - outOfDateCount;
  const highestCvss = Math.max(0, ...findings.map(f => Number(f?.highestCvss) || 0));

  if (countEl) countEl.textContent = String(findings.length);
  if (kpisEl) {
    kpisEl.innerHTML = `
      <span class="cve-kpi ${outOfDateCount > 0 ? 'warn' : 'ok'}">⚠️ Out of date: <strong>${escapeHtml(outOfDateCount)}</strong></span>
      <span class="cve-kpi ok">✅ Up to date: <strong>${escapeHtml(upToDateCount)}</strong></span>
      <span class="cve-kpi ${highestCvss >= 7 ? 'danger' : highestCvss > 0 ? 'warn' : 'ok'}">🎯 Highest CVSS: <strong>${escapeHtml(highestCvss.toFixed(1))}</strong></span>
    `;
  }

  tbody.innerHTML = findings.map(item => {
    const isOutOfDate = item?.status === 'Out of date' || Boolean(item?.isOutOfDate);
    const icon = item?.icon || '📦';
    const cveList = Array.isArray(item?.cveIds) ? item.cveIds.slice(0, 6) : [];
    const cvePillsHtml = cveList.length > 0
      ? `<div class="sca-cve-pills">${cveList.map(cve => `<span class="enrich-badge enrich-cve">${escapeHtml(cve)}</span>`).join('')}</div>`
      : '';

    const statusBadgeHtml = isOutOfDate
      ? '<span class="sca-status-pill out-of-date">⚠️ Out of date</span>'
      : '<span class="sca-status-pill up-to-date">✅ Up to date</span>';

    const identifiedHtml = item?.identifiedVersion
      ? `<strong>${escapeHtml(item.identifiedVersion)}</strong> <span class="sca-cvss-meta">(Highest CVSS: ${escapeHtml(Number(item.highestCvss || 0).toFixed(1))})</span>`
      : 'N/A';

    const branchHtml = (item?.latestBranchVersion && item.latestBranchVersion !== 'N/A')
      ? `<strong>${escapeHtml(item.latestBranchVersion)}</strong> <span class="sca-cvss-meta">(Highest CVSS: ${escapeHtml(Number(item.latestBranchCvss || 0).toFixed(1))})</span>`
      : 'N/A';

    const overallHtml = (item?.overallLatestVersion && item.overallLatestVersion !== 'N/A')
      ? `<strong>${escapeHtml(item.overallLatestVersion)}</strong> <span class="sca-cvss-meta">(Highest CVSS: ${escapeHtml(Number(item.overallLatestCvss || 0).toFixed(1))})</span>`
      : 'N/A';

    return `
      <tr>
        <td>
          <div class="sca-name-cell">
            <span class="sca-tech-icon">${escapeHtml(icon)}</span>
            <div>
              <strong>${escapeHtml(item?.name || item?.id || 'Unknown')}</strong>
              ${cvePillsHtml}
            </div>
          </div>
        </td>
        <td>${statusBadgeHtml}</td>
        <td>${identifiedHtml}</td>
        <td>${branchHtml}</td>
        <td>${overallHtml}</td>
        <td class="sca-action-cell">${escapeHtml(item?.recommendedAction || '')}</td>
      </tr>
    `;
  }).join('');

  card.classList.remove('hidden');
}

// ── Visual Login Sequence Recorder (.lsr), System Variables & Visual Play ────
const LSR_FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const SYS_VARS_STORAGE_KEY = 'secscan_system_variables_v1';
const LSR_SEQUENCES_STORAGE_KEY = 'secscan_saved_sequences_v1';
const LSR_ACTIVE_SEQ_STORAGE_KEY = 'secscan_active_sequence_id_v1';

const SYS_VAR_CATEGORIES = {
  username: { icon: '👤', label: 'Username / Email', isSecret: false },
  password: { icon: '🔒', label: 'Password / Secret', isSecret: true },
  otp_seed: { icon: '🔑', label: 'TOTP / MFA Base32 Seed', isSecret: true },
  url: { icon: '🌐', label: 'Login / Target URL', isSecret: false },
  token: { icon: '🎟️', label: 'API Key / Token', isSecret: true },
  custom: { icon: '⚙️', label: 'Custom Variable', isSecret: false }
};

function isSecretVarCategory(category) {
  return Boolean(SYS_VAR_CATEGORIES[category]?.isSecret);
}

function normalizeSystemVariable(raw = {}) {
  if (!raw || typeof raw !== 'object') return null;
  const name = String(raw.name || '').trim();
  if (!name || LSR_FORBIDDEN_KEYS.has(name) || /[^a-zA-Z0-9_.-]/.test(name)) return null;
  const category = Object.hasOwn(SYS_VAR_CATEGORIES, raw.category) ? raw.category : 'custom';
  const isSecret = raw.isSecret !== undefined ? Boolean(raw.isSecret) : isSecretVarCategory(category);
  const value = raw.value !== undefined && raw.value !== null ? String(raw.value) : '';
  return {
    name,
    category,
    value,
    isSecret,
    updatedAt: raw.updatedAt || new Date().toISOString()
  };
}

function persistSystemVariablesToLocal() {
  try {
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(SYS_VARS_STORAGE_KEY, JSON.stringify(state.systemVariables));
    }
  } catch {
    // Ignore storage quota / privacy mode errors
  }
}

function persistSequencesToLocal() {
  try {
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(LSR_SEQUENCES_STORAGE_KEY, JSON.stringify(state.savedSequences));
      localStorage.setItem(LSR_ACTIVE_SEQ_STORAGE_KEY, state.loginSequence?.sequenceId || '');
    }
  } catch {
    // Ignore storage quota / privacy mode errors
  }
}

function showSysVarsStatus(message, isError = false) {
  const el = document.getElementById('sys-vars-status');
  if (!el) return;
  el.textContent = message;
  el.className = `form-hint lsr-sysvars-status ${isError ? 'error' : 'success'}`;
  el.classList.remove('hidden');
}

function renderSystemVariablesPanel() {
  if (typeof document === 'undefined') return;
  const listEl = document.getElementById('sys-vars-list');
  if (!listEl) return;

  const vars = state.systemVariables || [];
  if (vars.length === 0) {
    listEl.innerHTML = '<span class="form-hint">No system variables saved yet. Add shared usernames, passwords, TOTP seeds, or login URLs above.</span>';
    return;
  }

  listEl.innerHTML = vars.map(v => {
    const meta = SYS_VAR_CATEGORIES[v.category] || SYS_VAR_CATEGORIES.custom;
    const displayVal = v.isSecret ? '***' : (v.value || '(empty)');
    const bindTag = v.isSecret ? `{{SECRET:${v.name}}}` : `{{VAR:${v.name}}}`;
    return `
      <div class="lsr-sysvar-card" data-sysvar-name="${escapeHtml(v.name)}">
        <div class="lsr-sysvar-card-main">
          <span class="lsr-sysvar-icon" title="${escapeHtml(meta.label)}">${meta.icon}</span>
          <code class="lsr-sysvar-tag">{{VAR:${escapeHtml(v.name)}}}</code>
          ${v.isSecret ? `<code class="lsr-sysvar-alias" title="Also resolvable via ${escapeHtml(bindTag)}">${escapeHtml(bindTag)}</code>` : ''}
          <span class="badge badge-outline">${escapeHtml(meta.label)}</span>
          <span class="lsr-sysvar-val">${escapeHtml(displayVal)}</span>
        </div>
        <div class="lsr-sysvar-card-actions">
          <button
            type="button"
            class="btn-secondary btn-small"
            data-sysvar-action="edit"
            data-sysvar-name="${escapeHtml(v.name)}"
            title="Edit or rotate this variable across all .lsr sequences"
          >✏️ Edit / Rotate Value</button>
          <button
            type="button"
            class="btn-secondary btn-small"
            data-sysvar-action="delete"
            data-sysvar-name="${escapeHtml(v.name)}"
            aria-label="Delete system variable ${escapeHtml(v.name)}"
            title="Delete system variable"
          >🗑️</button>
        </div>
      </div>
    `;
  }).join('');
}

function renderModalSysVarsBar() {
  if (typeof document === 'undefined') return;
  const chipsEl = document.getElementById('lsr-modal-sysvars-chips');
  if (!chipsEl) return;
  const vars = state.systemVariables || [];
  if (vars.length === 0) {
    chipsEl.innerHTML = '<span class="form-hint">No system variables defined yet. Click "+ Add / Rotate Variable" to create shared credentials.</span>';
    return;
  }
  chipsEl.innerHTML = vars.map(v => {
    const meta = SYS_VAR_CATEGORIES[v.category] || SYS_VAR_CATEGORIES.custom;
    return `
      <button
        type="button"
        class="lsr-modal-sysvar-chip"
        data-lsr-bind-var="${escapeHtml(v.name)}"
        title="Click to bind {{VAR:${escapeHtml(v.name)}}} to the selected action"
      >
        <span>${meta.icon}</span>
        <code>{{VAR:${escapeHtml(v.name)}}}</code>
      </button>
    `;
  }).join('');
}

function buildVariableAndSecretOptionsHtml(selectedVal = '') {
  const vars = state.systemVariables || [];
  const secrets = state.loginSequence?.secrets || [];
  const parts = ['<option value="">Literal value (no variable / secret)</option>'];

  if (vars.length > 0) {
    const varOpts = vars.map(v => {
      const optVal = `VAR:${v.name}`;
      const meta = SYS_VAR_CATEGORIES[v.category] || SYS_VAR_CATEGORIES.custom;
      const isSelected = selectedVal === optVal || selectedVal === v.name;
      return `<option value="${escapeHtml(optVal)}" ${isSelected ? 'selected' : ''}>${meta.icon} {{VAR:${escapeHtml(v.name)}}} (${escapeHtml(v.category)})</option>`;
    }).join('');
    parts.push(`<optgroup label="🌐 System Variables ({{VAR:name}})">${varOpts}</optgroup>`);
  }

  if (secrets.length > 0) {
    const secOpts = secrets.map(s => {
      const optVal = `SECRET:${s.name}`;
      const isSelected = selectedVal === optVal || selectedVal === s.name;
      return `<option value="${escapeHtml(optVal)}" ${isSelected ? 'selected' : ''}>🗝️ {{SECRET:${escapeHtml(s.name)}}}</option>`;
    }).join('');
    parts.push(`<optgroup label="🗝️ Sequence Secrets ({{SECRET:name}})">${secOpts}</optgroup>`);
  }

  return parts.join('');
}

async function loadSystemVariables() {
  let localVars = [];
  try {
    if (typeof localStorage !== 'undefined') {
      const raw = localStorage.getItem(SYS_VARS_STORAGE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) {
          localVars = parsed.map(normalizeSystemVariable).filter(Boolean);
        }
      }
    }
  } catch {
    localVars = [];
  }
  if (localVars.length > 0) {
    state.systemVariables = localVars;
    renderSystemVariablesPanel();
    renderModalSysVarsBar();
  }

  if (typeof fetch !== 'function') return;
  try {
    const res = await fetch('/api/auth/variables', { headers: { Accept: 'application/json' } });
    if (!res.ok) return;
    const data = await res.json();
    const serverVars = Array.isArray(data?.variables) ? data.variables : (Array.isArray(data) ? data : null);
    if (serverVars) {
      const localMap = new Map(localVars.map(v => [v.name, v]));
      const merged = [];
      for (const rawSv of serverVars) {
        const sv = normalizeSystemVariable(rawSv);
        if (!sv) continue;
        const lv = localMap.get(sv.name);
        if (lv && (!sv.value || sv.value === '[SECRET]' || sv.value === '[REDACTED]' || sv.value === '***')) {
          sv.value = lv.value;
        }
        localMap.delete(sv.name);
        merged.push(sv);
      }
      for (const leftover of localMap.values()) {
        merged.push(leftover);
      }
      state.systemVariables = merged;
      persistSystemVariablesToLocal();
      renderSystemVariablesPanel();
      renderModalSysVarsBar();
      renderLsrActionProperties();
      if (state.lastInspectedPage) renderInspectedPageCanvas(state.lastInspectedPage);
    }
  } catch {
    // Graceful fallback to localStorage when backend route is unavailable
  }
}

async function saveSystemVariable({ name, category, value }) {
  const cleanName = String(name || '').trim();
  if (!cleanName || LSR_FORBIDDEN_KEYS.has(cleanName) || /[^a-zA-Z0-9_.-]/.test(cleanName)) {
    showSysVarsStatus('Variable name must contain only letters, numbers, "_", "-", or ".".', true);
    return { ok: false };
  }
  const cleanCat = Object.hasOwn(SYS_VAR_CATEGORIES, category) ? category : 'custom';
  const entry = normalizeSystemVariable({
    name: cleanName,
    category: cleanCat,
    value: value ?? '',
    isSecret: isSecretVarCategory(cleanCat),
    updatedAt: new Date().toISOString()
  });

  const existingIdx = state.systemVariables.findIndex(v => v.name === entry.name);
  if (existingIdx >= 0) {
    state.systemVariables[existingIdx] = entry;
  } else {
    state.systemVariables.push(entry);
  }
  persistSystemVariablesToLocal();

  if (typeof fetch === 'function') {
    try {
      const res = await fetch('/api/auth/variables', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify(entry)
      });
      if (res.ok) {
        const data = await res.json().catch(() => ({}));
        if (Array.isArray(data?.variables)) {
          const localMap = new Map(state.systemVariables.map(v => [v.name, v]));
          state.systemVariables = data.variables.map(raw => {
            const sv = normalizeSystemVariable(raw);
            if (!sv) return null;
            const lv = localMap.get(sv.name);
            if (lv && (!sv.value || sv.value === '[SECRET]' || sv.value === '[REDACTED]' || sv.value === '***')) {
              sv.value = lv.value;
            }
            return sv;
          }).filter(Boolean);
          persistSystemVariablesToLocal();
        }
      } else if (res.status !== 404 && res.status !== 405) {
        const errData = await res.json().catch(() => ({}));
        showSysVarsStatus(errData.error || `Failed to save variable (HTTP ${res.status})`, true);
      }
    } catch {
      // Keep local persistence if network is unavailable
    }
  }

  renderSystemVariablesPanel();
  renderModalSysVarsBar();
  renderLsrActionProperties();
  if (state.lastInspectedPage) renderInspectedPageCanvas(state.lastInspectedPage);
  showSysVarsStatus(`✅ Saved {{VAR:${entry.name}}} — all .lsr sequences using this variable will resolve the updated value.`, false);
  return { ok: true, variable: entry };
}

async function deleteSystemVariable(name) {
  const cleanName = String(name || '').trim();
  if (!cleanName) return;
  state.systemVariables = state.systemVariables.filter(v => v.name !== cleanName);
  persistSystemVariablesToLocal();

  if (typeof fetch === 'function') {
    try {
      await fetch(`/api/auth/variables/${encodeURIComponent(cleanName)}`, { method: 'DELETE' });
    } catch {
      // Ignore network/404 errors
    }
  }

  renderSystemVariablesPanel();
  renderModalSysVarsBar();
  renderLsrActionProperties();
  if (state.lastInspectedPage) renderInspectedPageCanvas(state.lastInspectedPage);
  showSysVarsStatus(`🗑️ Removed system variable {{VAR:${cleanName}}}.`, false);
}

function getLsrSecretDisplayMask(action) {
  if (!action) return '';
  const varMatch = typeof action.value === 'string' ? action.value.match(/^\{\{VAR:([^}]+)\}\}$/i) : null;
  if (varMatch) {
    const sysVar = (state.systemVariables || []).find(v => v.name === varMatch[1].trim());
    if (sysVar?.isSecret || action.isSecret) {
      return `*** (${action.value})`;
    }
    return action.value;
  }
  if (action.isSecret || action.secretName || /pass|pwd|secret/i.test(`${action.fieldName || ''} ${action.selector || ''}`)) {
    return '***';
  }
  return action.value || '';
}

function formatLsrStepLabel(action) {
  if (!action || typeof action !== 'object') return 'Step';
  switch (action.type) {
    case 'navigate':
      return `Navigate to ${action.url || '(target URL)'}`;
    case 'change_input': {
      const target = action.selector || action.fieldName || 'field';
      const valText = getLsrSecretDisplayMask(action) || '(empty)';
      if (action.selectorType === 'id') {
        return `Change INPUT with id ${target.replace(/^#/, '')} to ${valText}`;
      }
      if (action.selectorType === 'name') {
        return `Change INPUT named ${action.fieldName || target} to ${valText}`;
      }
      return `Change INPUT matching ${target} to ${valText}`;
    }
    case 'fill_otp': {
      const target = action.selector || action.fieldName || 'auto';
      if (!target || target === 'auto') {
        return 'Fill OTP code into auto-detected MFA INPUT';
      }
      if (action.selectorType === 'id') {
        return `Fill OTP code into INPUT with id ${target.replace(/^#/, '')}`;
      }
      if (action.selectorType === 'name') {
        return `Fill OTP code into INPUT named ${action.fieldName || target}`;
      }
      return `Fill OTP code into INPUT matching ${target}`;
    }
    case 'click_button': {
      const target = action.selector || 'Submit';
      if (action.selectorType === 'id') {
        return `Click on BUTTON with id ${target.replace(/^#/, '')}`;
      }
      if (action.selectorType === 'name') {
        return `Click on BUTTON named ${target}`;
      }
      if (action.selectorType === 'text') {
        return `Click on BUTTON with text ${target}`;
      }
      return `Click on BUTTON matching ${target}`;
    }
    case 'extract_token':
      return `Extract ${(action.source || 'json').toUpperCase()} token${action.key || action.tokenJsonPath ? ` (${action.tokenJsonPath || action.key})` : ''}`;
    case 'custom_request':
      return `${String(action.method || 'POST').toUpperCase()} ${action.url || '(custom request)'}`;
    default:
      return String(action.label || action.type || 'Step');
  }
}

function getLsrStepIcon(type) {
  switch (type) {
    case 'navigate': return '🧭';
    case 'change_input': return '⌨️';
    case 'fill_otp': return '🔑';
    case 'click_button': return '🖱️';
    case 'extract_token': return '🪪';
    case 'custom_request': return '📡';
    default: return '🔹';
  }
}

function normalizeClientLoginSequence(raw = {}) {
  const base = createDefaultLoginSequence();
  const src = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  const rawName = String(src.name || base.name).replace(/[\r\n]+/g, '').trim() || base.name;
  const name = /\.[a-zA-Z0-9]+$/.test(rawName) ? rawName : `${rawName}.lsr`;

  const secrets = Array.isArray(src.secrets)
    ? src.secrets
        .filter(s => s && typeof s === 'object' && s.name && !LSR_FORBIDDEN_KEYS.has(String(s.name).trim()))
        .map(s => ({
          name: String(s.name).trim(),
          value: s.value !== undefined && s.value !== null ? String(s.value) : '',
          description: typeof s.description === 'string' ? s.description.trim() : ''
        }))
    : [];

  const rawOtp = src.otpConfig && typeof src.otpConfig === 'object' ? src.otpConfig : {};
  const otpConfig = {
    enabled: Boolean(rawOtp.enabled ?? (rawOtp.secret || false)),
    secret: typeof rawOtp.secret === 'string' ? rawOtp.secret.trim() : '',
    digits: Number(rawOtp.digits) === 8 ? 8 : 6,
    period: Math.min(120, Math.max(15, parseInt(rawOtp.period, 10) || 30)),
    algorithm: ['SHA1', 'SHA256', 'SHA512'].includes(String(rawOtp.algorithm || '').toUpperCase())
      ? String(rawOtp.algorithm).toUpperCase()
      : 'SHA1',
    inputSelector: typeof rawOtp.inputSelector === 'string' && rawOtp.inputSelector.trim()
      ? rawOtp.inputSelector.trim()
      : 'auto'
  };

  const actions = Array.isArray(src.actions)
    ? src.actions
        .filter(a => a && typeof a === 'object' && a.type)
        .map((a, idx) => ({
          ...a,
          step: idx + 1,
          label: formatLsrStepLabel(a)
        }))
    : [];

  const restrictions = Array.isArray(src.restrictions)
    ? Array.from(new Set(src.restrictions.map(r => String(r || '').trim()).filter(Boolean)))
    : [...base.restrictions];

  const rawSd = src.sessionDetection && typeof src.sessionDetection === 'object' ? src.sessionDetection : {};
  const statusCodes = Array.isArray(rawSd.statusCodes)
    ? rawSd.statusCodes.map(Number).filter(n => Number.isInteger(n) && n >= 100 && n <= 599)
    : [401, 403];

  return {
    sequenceId: typeof src.sequenceId === 'string' ? src.sequenceId.trim() : '',
    name,
    updatedAt: src.updatedAt || new Date().toISOString(),
    targetUrl: typeof src.targetUrl === 'string' ? src.targetUrl.trim() : '',
    secrets,
    otpConfig,
    actions,
    restrictions,
    sessionDetection: {
      statusCodes: statusCodes.length > 0 ? statusCodes : [401, 403],
      redirectPattern: rawSd.redirectPattern !== undefined ? String(rawSd.redirectPattern || '').trim() : '/login',
      loggedOutPattern: String(rawSd.loggedOutPattern || '').trim(),
      loggedInPattern: String(rawSd.loggedInPattern || '').trim()
    }
  };
}

function syncLsrConfigFromInputs() {
  if (typeof document === 'undefined') return;
  const seq = state.loginSequence;

  const seqNameInput = document.getElementById('lsr-sequence-name');
  if (seqNameInput && seqNameInput.value.trim()) {
    const rawName = seqNameInput.value.trim();
    seq.name = /\.[a-zA-Z0-9]+$/.test(rawName) ? rawName : `${rawName}.lsr`;
  }

  const otpSecretEl = document.getElementById('otp-secret-input');
  const otpDigitsEl = document.getElementById('otp-digits-select');
  const otpPeriodEl = document.getElementById('otp-period-input');
  const otpAlgEl = document.getElementById('otp-algorithm-select');
  const otpSelEl = document.getElementById('otp-selector-input');

  const rawOtpSecret = otpSecretEl ? otpSecretEl.value.trim() : seq.otpConfig.secret;
  seq.otpConfig = {
    enabled: Boolean(seq.otpConfig.enabled || rawOtpSecret),
    secret: rawOtpSecret || seq.otpConfig.secret || '',
    digits: Number(otpDigitsEl?.value) === 8 ? 8 : 6,
    period: Math.min(120, Math.max(15, parseInt(otpPeriodEl?.value, 10) || 30)),
    algorithm: otpAlgEl?.value || 'SHA1',
    inputSelector: otpSelEl?.value.trim() || 'auto'
  };

  const statusCodesEl = document.getElementById('lsr-session-status-codes');
  const redirectEl = document.getElementById('lsr-session-redirect-pattern');
  const loggedOutEl = document.getElementById('lsr-session-logged-out-pattern');
  const loggedInEl = document.getElementById('lsr-session-logged-in-pattern');

  if (statusCodesEl) {
    const codes = statusCodesEl.value
      .split(',')
      .map(s => parseInt(s.trim(), 10))
      .filter(n => Number.isInteger(n) && n >= 100 && n <= 599);
    seq.sessionDetection.statusCodes = codes.length > 0 ? Array.from(new Set(codes)) : [401, 403];
  }
  if (redirectEl) seq.sessionDetection.redirectPattern = redirectEl.value.trim();
  if (loggedOutEl) seq.sessionDetection.loggedOutPattern = loggedOutEl.value.trim();
  if (loggedInEl) seq.sessionDetection.loggedInPattern = loggedInEl.value.trim();
}

function applyLsrStateToInputs() {
  if (typeof document === 'undefined') return;
  const seq = state.loginSequence;

  const seqNameInput = document.getElementById('lsr-sequence-name');
  if (seqNameInput) seqNameInput.value = seq.name || 'WrapperSequence.lsr';

  const otpSecretEl = document.getElementById('otp-secret-input');
  const otpDigitsEl = document.getElementById('otp-digits-select');
  const otpPeriodEl = document.getElementById('otp-period-input');
  const otpAlgEl = document.getElementById('otp-algorithm-select');
  const otpSelEl = document.getElementById('otp-selector-input');
  const otpStatusEl = document.getElementById('otp-preview-status');

  if (otpSecretEl && seq.otpConfig.secret && seq.otpConfig.secret !== '[SECRET]') {
    otpSecretEl.value = seq.otpConfig.secret;
  } else if (otpSecretEl && !seq.otpConfig.secret) {
    otpSecretEl.value = '';
  }
  if (otpDigitsEl) otpDigitsEl.value = String(seq.otpConfig.digits || 6);
  if (otpPeriodEl) otpPeriodEl.value = String(seq.otpConfig.period || 30);
  if (otpAlgEl) otpAlgEl.value = seq.otpConfig.algorithm || 'SHA1';
  if (otpSelEl) otpSelEl.value = seq.otpConfig.inputSelector || 'auto';
  if (otpStatusEl && !otpStatusEl.dataset.livePreview) {
    otpStatusEl.textContent = seq.otpConfig.enabled || seq.otpConfig.secret ? 'Configured (TOTP ready)' : 'Not configured';
    otpStatusEl.className = `lsr-otp-status-pill ${seq.otpConfig.enabled || seq.otpConfig.secret ? 'configured' : ''}`;
  }

  const statusCodesEl = document.getElementById('lsr-session-status-codes');
  const redirectEl = document.getElementById('lsr-session-redirect-pattern');
  const loggedOutEl = document.getElementById('lsr-session-logged-out-pattern');
  const loggedInEl = document.getElementById('lsr-session-logged-in-pattern');

  if (statusCodesEl) statusCodesEl.value = (seq.sessionDetection.statusCodes || [401, 403]).join(', ');
  if (redirectEl) redirectEl.value = seq.sessionDetection.redirectPattern ?? '/login';
  if (loggedOutEl) loggedOutEl.value = seq.sessionDetection.loggedOutPattern || '';
  if (loggedInEl) loggedInEl.value = seq.sessionDetection.loggedInPattern || '';

  renderSystemVariablesPanel();
  renderModalSysVarsBar();
  renderLsrSecretsChips();
  renderLsrSequenceCards();
  renderLsrRestrictionsList();
  renderLsrActionsList();
  renderLsrActionProperties();
}

function buildLoginSequencePayload({ includeSecrets = true, seqOverride = null } = {}) {
  if (!seqOverride) syncLsrConfigFromInputs();
  const seq = seqOverride || state.loginSequence;
  const secrets = (seq.secrets || []).map(s => ({
    name: s.name,
    value: includeSecrets ? s.value : '[SECRET]',
    description: s.description || ''
  }));
  const otpConfig = {
    ...seq.otpConfig,
    secret: seq.otpConfig.secret ? (includeSecrets ? seq.otpConfig.secret : '[SECRET]') : ''
  };
  const actions = (seq.actions || []).map((a, idx) => {
    const copy = { ...a, step: idx + 1 };
    if (!includeSecrets && copy.type === 'change_input' && copy.isSecret && !copy.secretName && !/^\{\{VAR:[^}]+\}\}$/i.test(String(copy.value || ''))) {
      copy.value = '[SECRET]';
    }
    copy.label = formatLsrStepLabel(copy);
    return copy;
  });

  return {
    ...(seq.sequenceId ? { sequenceId: seq.sequenceId } : {}),
    name: seq.name || 'WrapperSequence.lsr',
    updatedAt: seq.updatedAt || new Date().toISOString(),
    ...(seq.targetUrl ? { targetUrl: seq.targetUrl } : {}),
    secrets,
    otpConfig,
    actions,
    restrictions: [...(seq.restrictions || [])],
    sessionDetection: { ...seq.sessionDetection }
  };
}

function renderLsrSecretsChips() {
  const container = document.getElementById('lsr-secrets-chips');
  if (!container) return;
  const secrets = state.loginSequence.secrets || [];
  if (secrets.length === 0) {
    container.innerHTML = '<span class="form-hint">No sequence-local secrets added yet.</span>';
    return;
  }
  container.innerHTML = secrets.map((s, idx) => `
    <span class="lsr-secret-chip" data-secret-name="${escapeHtml(s.name)}">
      <span class="lsr-secret-icon">🗝️</span>
      <strong>${escapeHtml(s.name)}</strong>: <span class="lsr-secret-mask">***</span>
      <button type="button" class="lsr-chip-remove" data-remove-lsr-secret="${escapeHtml(idx)}" aria-label="Remove secret ${escapeHtml(s.name)}">✕</button>
    </span>
  `).join('');
}

function getDisplayedSequenceCards() {
  const saved = Array.isArray(state.savedSequences) ? state.savedSequences : [];
  const active = state.loginSequence;
  const activeHasContent = Boolean(
    active &&
    ((Array.isArray(active.actions) && active.actions.length > 0) ||
     (Array.isArray(active.secrets) && active.secrets.length > 0) ||
     active.otpConfig?.secret ||
     active.targetUrl)
  );
  if (saved.length > 0) {
    const activeInSaved = Boolean(
      active &&
      saved.some(s =>
        (s.sequenceId && active.sequenceId && s.sequenceId === active.sequenceId) ||
        (!active.sequenceId && s.name === active.name)
      )
    );
    if (activeHasContent && !activeInSaved && !state.lsrDraftDismissed) {
      return [active, ...saved];
    }
    return saved;
  }
  if (state.lsrDraftDismissed) {
    return [];
  }
  return active ? [active] : [];
}

function renderLsrReuseSelect() {
  const sel = document.getElementById('lsr-reuse-select');
  if (!sel) return;
  const saved = getDisplayedSequenceCards();
  const activeId = state.loginSequence?.sequenceId || '';
  const activeName = state.loginSequence?.name || '';

  const opts = ['<option value="">Select a saved .lsr sequence to reuse...</option>'];
  saved.forEach((seq, idx) => {
    const val = seq.sequenceId || `__idx_${idx}`;
    const stepCount = Array.isArray(seq.actions) ? seq.actions.length : 0;
    const isMatch = (seq.sequenceId && seq.sequenceId === activeId) || (!activeId && seq.name === activeName && idx === 0);
    const label = `${seq.name || 'Sequence.lsr'} (${stepCount} step${stepCount === 1 ? '' : 's'})${seq.targetUrl ? ` — ${seq.targetUrl}` : ''}`;
    opts.push(`<option value="${escapeHtml(val)}" ${isMatch ? 'selected' : ''}>${escapeHtml(label)}</option>`);
  });
  sel.innerHTML = opts.join('');
}

function getSelectedReuseSequence() {
  const sel = document.getElementById('lsr-reuse-select');
  const val = sel?.value || '';
  const cards = getDisplayedSequenceCards();
  if (!val) return cards[0] || null;
  if (val.startsWith('__idx_')) {
    const idx = parseInt(val.slice(6), 10);
    return Number.isInteger(idx) ? (cards[idx] || null) : null;
  }
  return cards.find(s => s.sequenceId === val) || (state.savedSequences || []).find(s => s.sequenceId === val) || null;
}

function renderLsrSequenceCards() {
  renderLsrReuseSelect();
  const listEl = document.getElementById('lsr-sequence-cards-list');
  if (!listEl) return;

  const cards = getDisplayedSequenceCards();
  if (cards.length === 0) {
    listEl.innerHTML = '<div class="empty-muted">No login sequences configured. Click <strong>🎬 New sequence</strong> to record one or <strong>⚡ Load Working Example</strong> to load a ready-to-run 2FA sequence.</div>';
    return;
  }

  listEl.innerHTML = cards.map((seq, idx) => {
    const isSaved = Boolean(seq.sequenceId && state.savedSequences.some(s => s.sequenceId === seq.sequenceId));
    const stepCount = Array.isArray(seq.actions) ? seq.actions.length : 0;
    const secretCount = Array.isArray(seq.secrets) ? seq.secrets.length : 0;
    const hasOtp = Boolean(seq.otpConfig?.enabled || seq.otpConfig?.secret);
    const updatedText = seq.updatedAt ? new Date(seq.updatedAt).toLocaleString() : 'Draft';
    const isActive = Boolean(
      !state.lsrDraftDismissed &&
      ((seq.sequenceId && seq.sequenceId === state.loginSequence.sequenceId) ||
       (!seq.sequenceId && !state.loginSequence.sequenceId && seq.name === state.loginSequence.name && idx === 0))
    );

    return `
      <div class="lsr-sequence-card ${isActive ? 'active' : ''}" data-lsr-seq-idx="${escapeHtml(idx)}">
        <div class="lsr-seq-card-info">
          <div class="lsr-seq-card-title-row">
            <span class="lsr-seq-icon">🎬</span>
            <strong class="lsr-seq-name">${escapeHtml(seq.name || 'WrapperSequence.lsr')}</strong>
            ${isActive ? '<span class="badge badge-primary">Active for Scan ✅</span>' : ''}
            <span class="badge badge-outline">${escapeHtml(stepCount)} step${stepCount === 1 ? '' : 's'}</span>
            ${secretCount > 0 ? `<span class="badge badge-outline">🗝️ ${escapeHtml(secretCount)}</span>` : ''}
            ${hasOtp ? '<span class="badge badge-outline">🔑 OTP</span>' : ''}
            ${!isSaved ? '<span class="badge">Draft</span>' : ''}
          </div>
          <div class="lsr-seq-card-meta">Last updated: ${escapeHtml(updatedText)}${seq.targetUrl ? ` · Target: ${escapeHtml(seq.targetUrl)}` : ''}</div>
        </div>
        <div class="lsr-seq-card-actions">
          ${!isActive ? `
            <button
              type="button"
              class="btn-secondary btn-small"
              data-lsr-card-action="use"
              data-lsr-seq-idx="${escapeHtml(idx)}"
              title="Use this saved sequence for upcoming scans"
            >✅ Use in Scan</button>
          ` : ''}
          <button
            type="button"
            class="btn-secondary btn-small"
            data-lsr-card-action="play"
            data-lsr-seq-idx="${escapeHtml(idx)}"
            title="Play and verify this sequence now"
          >▶️ Play</button>
          <button
            type="button"
            ${idx === 0 ? 'id="btn-edit-lsr-sequence"' : ''}
            class="btn-secondary btn-small"
            data-lsr-card-action="edit"
            data-lsr-seq-idx="${escapeHtml(idx)}"
            title="Edit sequence in Visual Login Sequence Recorder"
          >✏️ Edit</button>
          <button
            type="button"
            class="btn-secondary btn-small"
            data-lsr-card-action="duplicate"
            data-lsr-seq-idx="${escapeHtml(idx)}"
            title="Duplicate sequence"
          >📋 Duplicate</button>
          <button
            type="button"
            class="btn-secondary btn-small"
            data-lsr-card-action="export"
            data-lsr-seq-idx="${escapeHtml(idx)}"
            title="Export .lsr JSON file"
          >📥 Export</button>
          <button
            type="button"
            ${idx === 0 ? 'id="btn-delete-lsr-sequence"' : ''}
            class="btn-secondary btn-small"
            data-lsr-card-action="delete"
            data-lsr-seq-idx="${escapeHtml(idx)}"
            title="Delete sequence"
          >🗑️ Delete</button>
        </div>
      </div>
    `;
  }).join('');
}

function renderLsrRestrictionsList() {
  const listEl = document.getElementById('lsr-restrictions-list');
  if (!listEl) return;
  const items = state.loginSequence.restrictions || [];
  if (items.length === 0) {
    listEl.innerHTML = '<div class="empty-muted">No restricted URLs configured. Add paths like /logout or /signout to protect session integrity.</div>';
    return;
  }
  listEl.innerHTML = items.map((item, idx) => `
    <div class="lsr-restriction-row">
      <code>${escapeHtml(item)}</code>
      <button type="button" class="btn-secondary btn-small" data-remove-lsr-restriction="${escapeHtml(idx)}">✕ Remove</button>
    </div>
  `).join('');
}

function findPlayStepForAction(playRes, actionIdx) {
  if (!playRes || typeof playRes !== 'object') return null;
  const steps = Array.isArray(playRes.steps) && playRes.steps.length > 0
    ? playRes.steps
    : (Array.isArray(playRes.sequenceSteps) ? playRes.sequenceSteps : []);
  if (steps.length === 0) return null;
  return steps.find(st => Number(st.sequenceStep) === actionIdx + 1)
    || steps.find(st => Number(st.step) === actionIdx + 1)
    || steps[actionIdx]
    || null;
}

function getPlayStepStatus(st) {
  if (!st || typeof st !== 'object') return 'ok';
  if (st.stepStatus === 'error' || st.stepStatus === 'warning' || st.stepStatus === 'ok') {
    return st.stepStatus;
  }
  if (st.error || Number(st.status) >= 400) return 'error';
  if (Array.isArray(st.issues) && st.issues.length > 0) {
    return st.issues.some(i => i?.severity === 'error') ? 'error' : 'warning';
  }
  return 'ok';
}

function getPlayStepShortReason(st) {
  if (!st) return '';
  if (Array.isArray(st.issues) && st.issues.length > 0) {
    return st.issues[0].code || st.issues[0].title || 'Issue';
  }
  if (Number(st.status) >= 400) return `HTTP ${st.status}`;
  if (st.error) return String(st.error).slice(0, 32);
  return '';
}

function renderLsrActionsList() {
  const listEl = document.getElementById('lsr-actions-list');
  if (!listEl) return;
  const actions = state.loginSequence.actions || [];
  if (actions.length === 0) {
    listEl.innerHTML = '<div class="empty-muted">No login steps recorded yet. Use <strong>→ Load Page Forms</strong> on the left or the <strong>Quick Add</strong> buttons to build your login sequence.</div>';
    return;
  }
  if (state.selectedLsrStepIndex >= actions.length) {
    state.selectedLsrStepIndex = actions.length - 1;
  }

  const playRes = state.lastLsrPlayResult;

  listEl.innerHTML = actions.map((action, idx) => {
    const isSelected = idx === state.selectedLsrStepIndex;
    const icon = getLsrStepIcon(action.type);
    const label = formatLsrStepLabel(action);

    let statusBadgeHtml = '';
    let statusRowClass = '';
    const matchedStep = findPlayStepForAction(playRes, idx);
    if (matchedStep) {
      const stStatus = getPlayStepStatus(matchedStep);
      statusRowClass = `lsr-step-state-${stStatus}`;
      if (stStatus === 'ok') {
        const okText = matchedStep.status ? `HTTP ${matchedStep.status}` : 'OK';
        statusBadgeHtml = `<span class="lsr-step-status-badge ok">✅ ${escapeHtml(okText)}</span>`;
      } else if (stStatus === 'warning') {
        statusBadgeHtml = '<span class="lsr-step-status-badge warning">⚠️ Warning</span>';
      } else {
        const reason = getPlayStepShortReason(matchedStep);
        statusBadgeHtml = `<span class="lsr-step-status-badge error">❌ Failed${reason ? ` · ${escapeHtml(reason)}` : ''}</span>`;
      }
    }

    return `
      <div class="lsr-action-item ${isSelected ? 'active' : ''} ${statusRowClass}" data-lsr-step-idx="${escapeHtml(idx)}" role="button" tabindex="0">
        <span class="lsr-step-num">${escapeHtml(idx + 1)}</span>
        <span class="lsr-step-icon">${icon}</span>
        <span class="lsr-step-label">${escapeHtml(label)}</span>
        ${statusBadgeHtml}
        <button type="button" class="lsr-chip-remove" data-lsr-delete-step="${escapeHtml(idx)}" title="Delete Step ${escapeHtml(idx + 1)}" aria-label="Delete Step ${escapeHtml(idx + 1)}">✕</button>
      </div>
    `;
  }).join('');
}

function renderLsrActionProperties() {
  const propsEl = document.getElementById('lsr-action-properties');
  if (!propsEl) return;
  const idx = state.selectedLsrStepIndex;
  const actions = state.loginSequence.actions || [];
  if (idx < 0 || idx >= actions.length) {
    propsEl.innerHTML = '<div class="empty-muted">Select an action above to inspect or edit its selector, secret binding, and request properties.</div>';
    return;
  }

  const action = actions[idx];
  const varMatch = typeof action.value === 'string' ? action.value.match(/^\{\{VAR:([^}]+)\}\}$/i) : null;
  const selectedBindingVal = varMatch
    ? `VAR:${varMatch[1].trim()}`
    : (action.secretName ? `SECRET:${action.secretName}` : '');
  const secretOptionsHtml = buildVariableAndSecretOptionsHtml(selectedBindingVal);

  const quickVarChipsHtml = (state.systemVariables || []).length > 0
    ? `
      <div class="lsr-props-quick-vars">
        <span class="form-hint">Quick bind <code>{{VAR:...}}</code>:</span>
        ${state.systemVariables.map(v => `<button type="button" class="lsr-modal-sysvar-chip" data-lsr-insert-var="${escapeHtml(v.name)}">{{VAR:${escapeHtml(v.name)}}}</button>`).join('')}
      </div>
    `
    : '';

  let typeFieldsHtml = '';
  if (action.type === 'navigate') {
    typeFieldsHtml = `
      <div class="form-group full-width">
        <label for="lsr-prop-url" class="form-label">Target URL</label>
        <input type="text" id="lsr-prop-url" class="form-input form-input-compact" value="${escapeHtml(action.url || '')}" placeholder="https://example.com/login or {{VAR:login_url}}">
        ${quickVarChipsHtml}
      </div>
    `;
  } else if (action.type === 'change_input') {
    const isMasked = Boolean(action.isSecret || action.secretName);
    const isServerRedactedToken = action.value === '[REDACTED]' || action.value === '[SECRET]';
    const displayValue = isServerRedactedToken ? '' : (action.value || '');
    const valPlaceholder = isServerRedactedToken
      ? '•••••••• (Saved secret — leave blank to keep or type new value)'
      : (action.secretName ? `{{SECRET:${escapeHtml(action.secretName)}}}` : 'Enter field value or {{VAR:name}}');
    typeFieldsHtml = `
      <div class="form-group">
        <label for="lsr-prop-selector-type" class="form-label">Selector Type</label>
        <select id="lsr-prop-selector-type" class="form-select form-select-compact">
          <option value="id" ${action.selectorType === 'id' ? 'selected' : ''}>id</option>
          <option value="name" ${action.selectorType === 'name' ? 'selected' : ''}>name</option>
          <option value="css" ${action.selectorType === 'css' ? 'selected' : ''}>css</option>
        </select>
      </div>
      <div class="form-group">
        <label for="lsr-prop-selector" class="form-label">Selector / Field Name</label>
        <input type="text" id="lsr-prop-selector" class="form-input form-input-compact" value="${escapeHtml(action.selector || action.fieldName || '')}" placeholder="username or password">
      </div>
      <div class="form-group">
        <label for="lsr-prop-secret-name" class="form-label">System Variable / Secret Reference</label>
        <select id="lsr-prop-secret-name" class="form-select form-select-compact">${secretOptionsHtml}</select>
      </div>
      <div class="form-group">
        <label for="lsr-prop-value" class="form-label">Value ${selectedBindingVal ? '(bound)' : ''}</label>
        <input type="${isMasked ? 'password' : 'text'}" id="lsr-prop-value" class="form-input form-input-compact" ${isServerRedactedToken ? 'data-preserve-masked="1"' : ''} value="${escapeHtml(displayValue)}" placeholder="${valPlaceholder}">
      </div>
      <div class="form-group full-width">
        <label class="checkbox-label">
          <input type="checkbox" id="lsr-prop-is-secret" ${isMasked ? 'checked' : ''}>
          <span>Mask value as secret (<code>***</code>)</span>
        </label>
      </div>
    `;
  } else if (action.type === 'fill_otp') {
    typeFieldsHtml = `
      <div class="form-group">
        <label for="lsr-prop-selector-type" class="form-label">Selector Type</label>
        <select id="lsr-prop-selector-type" class="form-select form-select-compact">
          <option value="id" ${action.selectorType === 'id' ? 'selected' : ''}>id</option>
          <option value="name" ${action.selectorType === 'name' ? 'selected' : ''}>name</option>
          <option value="css" ${action.selectorType === 'css' ? 'selected' : ''}>css</option>
        </select>
      </div>
      <div class="form-group">
        <label for="lsr-prop-selector" class="form-label">OTP Field Selector / Name</label>
        <input type="text" id="lsr-prop-selector" class="form-input form-input-compact" value="${escapeHtml(action.selector || 'auto')}" placeholder="auto or totp">
      </div>
    `;
  } else if (action.type === 'click_button') {
    typeFieldsHtml = `
      <div class="form-group">
        <label for="lsr-prop-selector-type" class="form-label">Selector Type</label>
        <select id="lsr-prop-selector-type" class="form-select form-select-compact">
          <option value="text" ${action.selectorType === 'text' ? 'selected' : ''}>text</option>
          <option value="id" ${action.selectorType === 'id' ? 'selected' : ''}>id</option>
          <option value="name" ${action.selectorType === 'name' ? 'selected' : ''}>name</option>
          <option value="css" ${action.selectorType === 'css' ? 'selected' : ''}>css</option>
        </select>
      </div>
      <div class="form-group">
        <label for="lsr-prop-selector" class="form-label">Button Text / Selector</label>
        <input type="text" id="lsr-prop-selector" class="form-input form-input-compact" value="${escapeHtml(action.selector || '')}" placeholder="Log In">
      </div>
      <div class="form-group">
        <label for="lsr-prop-submit-url" class="form-label">Submit URL (Optional override)</label>
        <input type="text" id="lsr-prop-submit-url" class="form-input form-input-compact" value="${escapeHtml(action.submitUrl || '')}" placeholder="Auto from form action">
      </div>
      <div class="form-group">
        <label for="lsr-prop-content-type" class="form-label">Content-Type</label>
        <select id="lsr-prop-content-type" class="form-select form-select-compact">
          <option value="" ${!action.contentType ? 'selected' : ''}>Auto (from form)</option>
          <option value="form" ${action.contentType === 'form' ? 'selected' : ''}>application/x-www-form-urlencoded</option>
          <option value="json" ${action.contentType === 'json' ? 'selected' : ''}>application/json</option>
        </select>
      </div>
    `;
  } else if (action.type === 'extract_token') {
    typeFieldsHtml = `
      <div class="form-group">
        <label for="lsr-prop-token-source" class="form-label">Token Source</label>
        <select id="lsr-prop-token-source" class="form-select form-select-compact">
          <option value="json" ${action.source === 'json' ? 'selected' : ''}>JSON body</option>
          <option value="header" ${action.source === 'header' ? 'selected' : ''}>Response header</option>
          <option value="cookie" ${action.source === 'cookie' ? 'selected' : ''}>Cookie</option>
          <option value="csrf" ${action.source === 'csrf' ? 'selected' : ''}>CSRF DOM token</option>
        </select>
      </div>
      <div class="form-group">
        <label for="lsr-prop-token-key" class="form-label">Key / JSON Path</label>
        <input type="text" id="lsr-prop-token-key" class="form-input form-input-compact" value="${escapeHtml(action.tokenJsonPath || action.key || '')}" placeholder="token or data.accessToken">
      </div>
    `;
  } else if (action.type === 'custom_request') {
    const payloadStr = typeof action.payload === 'string'
      ? action.payload
      : (action.payload ? JSON.stringify(action.payload) : '');
    typeFieldsHtml = `
      <div class="form-group">
        <label for="lsr-prop-method" class="form-label">HTTP Method</label>
        <select id="lsr-prop-method" class="form-select form-select-compact">
          <option value="POST" ${action.method === 'POST' ? 'selected' : ''}>POST</option>
          <option value="GET" ${action.method === 'GET' ? 'selected' : ''}>GET</option>
          <option value="PUT" ${action.method === 'PUT' ? 'selected' : ''}>PUT</option>
        </select>
      </div>
      <div class="form-group">
        <label for="lsr-prop-content-type" class="form-label">Content-Type</label>
        <select id="lsr-prop-content-type" class="form-select form-select-compact">
          <option value="json" ${action.contentType === 'json' ? 'selected' : ''}>application/json</option>
          <option value="form" ${action.contentType === 'form' ? 'selected' : ''}>application/x-www-form-urlencoded</option>
        </select>
      </div>
      <div class="form-group full-width">
        <label for="lsr-prop-url" class="form-label">Request URL</label>
        <input type="text" id="lsr-prop-url" class="form-input form-input-compact" value="${escapeHtml(action.url || '')}" placeholder="https://example.com/api/login">
      </div>
      <div class="form-group full-width">
        <label for="lsr-prop-payload" class="form-label">Payload (JSON or key=val)</label>
        <input type="text" id="lsr-prop-payload" class="form-input form-input-compact" value="${escapeHtml(payloadStr)}" placeholder='{"username":"{{VAR:corp_user}}","password":"{{VAR:corp_pass}}"}'>
        ${quickVarChipsHtml}
      </div>
    `;
  }

  propsEl.innerHTML = `
    <div class="lsr-props-header">
      <strong>Action Properties (Step ${escapeHtml(idx + 1)})</strong>
    </div>
    <div class="lsr-props-grid">
      <div class="form-group full-width">
        <label for="lsr-prop-type" class="form-label">Action Type</label>
        <select id="lsr-prop-type" class="form-select form-select-compact">
          <option value="navigate" ${action.type === 'navigate' ? 'selected' : ''}>Navigate (GET URL)</option>
          <option value="change_input" ${action.type === 'change_input' ? 'selected' : ''}>Change Input Field</option>
          <option value="fill_otp" ${action.type === 'fill_otp' ? 'selected' : ''}>Fill OTP / TOTP Code</option>
          <option value="click_button" ${action.type === 'click_button' ? 'selected' : ''}>Click Submit Button</option>
          <option value="extract_token" ${action.type === 'extract_token' ? 'selected' : ''}>Extract Token</option>
          <option value="custom_request" ${action.type === 'custom_request' ? 'selected' : ''}>Custom HTTP Request</option>
        </select>
      </div>
      ${typeFieldsHtml}
    </div>
  `;
}

function appendLsrStep(stepObj) {
  const actions = state.loginSequence.actions;
  const normalized = {
    ...stepObj,
    step: actions.length + 1
  };
  normalized.label = formatLsrStepLabel(normalized);
  actions.push(normalized);
  state.selectedLsrStepIndex = actions.length - 1;
  state.loginSequence.updatedAt = new Date().toISOString();
  renderLsrActionsList();
  renderLsrActionProperties();
  renderLsrSequenceCards();
  if (!state.lastLsrPlayResult && !state.lastInspectedPage) {
    renderSequenceBlueprintCanvas(state.loginSequence);
  }
}

function createDefaultStepForType(type) {
  const fallbackUrl = document.getElementById('lsr-inspect-url')?.value.trim()
    || document.getElementById('adv-auth-login-url')?.value.trim()
    || document.getElementById('target-url')?.value.trim()
    || '';

  switch (type) {
    case 'navigate':
      return { type: 'navigate', url: fallbackUrl };
    case 'change_input':
      return { type: 'change_input', selectorType: 'id', selector: 'username', fieldName: 'username', value: '', secretName: '', isSecret: false };
    case 'fill_otp':
      return {
        type: 'fill_otp',
        selectorType: 'id',
        selector: state.loginSequence.otpConfig?.inputSelector || 'auto',
        fieldName: state.loginSequence.otpConfig?.inputSelector || ''
      };
    case 'click_button':
      return { type: 'click_button', selectorType: 'text', selector: 'Log In', submitUrl: '', method: 'POST', contentType: '' };
    case 'extract_token':
      return { type: 'extract_token', source: 'json', key: 'token', tokenJsonPath: 'token' };
    case 'custom_request':
      return { type: 'custom_request', method: 'POST', url: fallbackUrl, contentType: 'json', payload: '' };
    default:
      return { type: 'navigate', url: fallbackUrl };
  }
}

function renderInspectedPageCanvas(data) {
  const canvas = document.getElementById('lsr-visual-canvas');
  if (!canvas) return;
  state.lastInspectedPage = data;

  const pageUrl = data?.pageUrl || data?.url || '';
  const title = data?.title || 'Inspected Page';
  const csrf = data?.csrf || {};
  const forms = Array.isArray(data?.forms) ? data.forms : [];
  const inputs = Array.isArray(data?.inputs) ? data.inputs : [];
  const buttons = Array.isArray(data?.buttons) ? data.buttons : [];
  const secrets = state.loginSequence.secrets || [];
  const sysVars = state.systemVariables || [];

  const csrfText = csrf.formField
    ? `CSRF Auto-Handled: ${csrf.formField} (Dynamic per session)`
    : (csrf.headerName ? `CSRF Header Auto-Handled: ${csrf.headerName}` : 'No CSRF token detected');

  // Sort visible interactive inputs first, and place hidden inputs (like YII_CSRF_TOKEN) after with an Auto-Handled note
  const indexedInputs = inputs.map((inp, idx) => ({ inp, idx }));
  indexedInputs.sort((a, b) => {
    const aHidden = a.inp.type === 'hidden' ? 1 : 0;
    const bHidden = b.inp.type === 'hidden' ? 1 : 0;
    return aHidden - bHidden;
  });

  const inputsHtml = indexedInputs.length > 0
    ? indexedInputs.map(({ inp, idx }) => {
        const isHidden = inp.type === 'hidden';
        const isCsrfInput = Boolean(
          (csrf.formField && (inp.name === csrf.formField || inp.id === csrf.formField)) ||
          /csrf|xsrf|requestverificationtoken|authenticity_token/i.test(`${inp.name || ''} ${inp.id || ''}`)
        );
        if (isHidden) {
          return `
            <div class="lsr-inspect-field-card" data-lsr-input-card="${escapeHtml(idx)}">
              <div class="lsr-inspect-field-head">
                <div>
                  <strong>${escapeHtml(inp.displayLabel || inp.name || inp.id || 'hidden')}</strong>
                  <span class="badge">hidden</span>
                  ${isCsrfInput ? '<span class="badge badge-primary">🛡️ Dynamic CSRF Token (Auto-Harvested)</span>' : '<span class="badge badge-outline">Auto-Included Hidden Field</span>'}
                </div>
              </div>
              <div class="form-hint">
                ✅ <strong>Handled automatically:</strong> You do <em>not</em> need to record a step for <code>${escapeHtml(inp.name || inp.id || 'hidden')}</code>. The scanner automatically extracts a fresh token on every <code>Navigate</code> step and submits it with the form.
              </div>
            </div>
          `;
        }

        let defaultBinding = '';
        if (inp.isPassword) {
          const matchingVar = sysVars.find(v => v.category === 'password' || /pass|pwd|secret/i.test(v.name));
          const matchingSec = secrets.find(s => /pass|pwd|secret/i.test(s.name)) || secrets[0];
          if (matchingVar) defaultBinding = `VAR:${matchingVar.name}`;
          else if (matchingSec) defaultBinding = `SECRET:${matchingSec.name}`;
        } else if (/user|email|login/i.test(`${inp.name || ''} ${inp.id || ''} ${inp.type || ''}`)) {
          const matchingUserVar = sysVars.find(v => v.category === 'username' || /user|email/i.test(v.name));
          if (matchingUserVar) defaultBinding = `VAR:${matchingUserVar.name}`;
        }
        const secretOptions = buildVariableAndSecretOptionsHtml(defaultBinding);

        return `
          <div class="lsr-inspect-field-card" data-lsr-input-card="${escapeHtml(idx)}">
            <div class="lsr-inspect-field-head">
              <div>
                <strong>${escapeHtml(inp.displayLabel || inp.name || inp.id || inp.type || 'input')}</strong>
                <span class="badge">${escapeHtml(inp.type || 'text')}</span>
                ${inp.isPassword ? '<span class="badge badge-warning">password</span>' : ''}
                ${inp.isOtpCandidate ? '<span class="badge badge-primary">🔑 MFA / OTP</span>' : ''}
              </div>
              <button type="button" class="btn-secondary btn-small" data-lsr-record-input="${escapeHtml(idx)}">
                ${inp.isOtpCandidate ? '🔑 + Record OTP' : '+ Record Input'}
              </button>
            </div>
            ${!inp.isOtpCandidate ? `
              <div class="lsr-inspect-bind-row">
                <select class="form-select form-select-compact" data-lsr-input-secret="${escapeHtml(idx)}" aria-label="Bind variable or secret for ${escapeHtml(inp.name || inp.id || idx)}">
                  ${secretOptions}
                </select>
                <input
                  type="${inp.isPassword ? 'password' : 'text'}"
                  class="form-input form-input-compact"
                  data-lsr-input-val="${escapeHtml(idx)}"
                  value="${escapeHtml(inp.isPassword ? '' : (inp.value || ''))}"
                  placeholder="${inp.isPassword ? 'Or type password value' : 'Value to enter'}"
                >
              </div>
            ` : '<div class="form-hint">Appends a <code>Fill OTP code</code> step using your configured TOTP secret.</div>'}
          </div>
        `;
      }).join('')
    : '<div class="empty-muted">No form input elements discovered on this page.</div>';

  const buttonsHtml = buttons.length > 0
    ? buttons.map((btn, idx) => `
        <button type="button" class="lsr-inspect-btn-card" data-lsr-record-button="${escapeHtml(idx)}">
          <span class="lsr-inspect-btn-label">🖱️ ${escapeHtml(btn.displayLabel || btn.text || btn.id || btn.name || 'Submit')}</span>
          <span class="badge badge-outline">+ Record Click</span>
        </button>
      `).join('')
    : '<div class="empty-muted">No submit buttons discovered on this page.</div>';

  const formsMetaHtml = forms.length > 0
    ? forms.map(f => `
        <div class="lsr-inspect-form-meta">
          <span><strong>Form #${escapeHtml(Number(f.formIndex) + 1)}:</strong> <code>${escapeHtml(f.method || 'POST')}</code> <code>${escapeHtml(f.actionUrl || f.action || pageUrl)}</code></span>
          <span class="form-hint">(${escapeHtml(f.inputCount || 0)} input(s))</span>
        </div>
      `).join('')
    : '';

  canvas.innerHTML = `
    <div class="lsr-inspect-page-summary">
      <div class="lsr-inspect-page-title-row">
        <strong>🌐 ${escapeHtml(title)}</strong>
        <button type="button" class="btn-secondary btn-small" id="btn-lsr-record-nav-here">+ Record Navigate</button>
      </div>
      <div class="lsr-inspect-page-url"><code>${escapeHtml(pageUrl)}</code></div>
      <div class="lsr-inspect-badges">
        <span class="badge ${csrf.formField || csrf.headerName ? 'badge-primary' : ''}">🛡️ ${escapeHtml(csrfText)}</span>
        ${data?.hasPasswordInput ? '<span class="badge">🔒 Password Form</span>' : ''}
        ${data?.hasMfaOrOtpField ? '<span class="badge badge-primary">🔑 OTP Field Detected</span>' : ''}
      </div>
      ${formsMetaHtml}
    </div>
    <div class="lsr-inspect-section">
      <div class="lsr-inspect-section-title">Discovered Form Inputs (${escapeHtml(inputs.length)})</div>
      <div class="lsr-inspect-fields-list">${inputsHtml}</div>
    </div>
    <div class="lsr-inspect-section">
      <div class="lsr-inspect-section-title">Discovered Buttons (${escapeHtml(buttons.length)})</div>
      <div class="lsr-inspect-buttons-list">${buttonsHtml}</div>
    </div>
  `;
}

function buildClientSideDiagnostics(res) {
  if (!res || typeof res !== 'object') return [];
  if (Array.isArray(res.diagnostics) && res.diagnostics.length > 0) {
    return res.diagnostics;
  }

  const out = [];
  const steps = Array.isArray(res.steps) ? res.steps : (Array.isArray(res.sequenceSteps) ? res.sequenceSteps : []);
  for (let i = 0; i < steps.length; i++) {
    const st = steps[i];
    if (Array.isArray(st.issues) && st.issues.length > 0) {
      for (const iss of st.issues) {
        out.push({
          step: st.step || i + 1,
          sequenceStep: st.sequenceStep || st.step || i + 1,
          severity: iss.severity || 'error',
          code: iss.code || 'STEP_ISSUE',
          title: iss.title || iss.message || `Step ${st.sequenceStep || st.step || i + 1} failed`,
          detail: iss.detail || st.error || '',
          fixSuggestion: iss.fixSuggestion || iss.remediation || 'Check the selector or System Variable for this step.'
        });
      }
    } else if (st.error || Number(st.status) >= 400) {
      const code = Number(st.status) >= 400 ? `HTTP_${st.status}` : 'STEP_ERROR';
      out.push({
        step: st.step || i + 1,
        sequenceStep: st.sequenceStep || st.step || i + 1,
        severity: 'error',
        code,
        title: Number(st.status) >= 400
          ? `Target rejected step with HTTP ${st.status}`
          : `Step ${st.sequenceStep || st.step || i + 1} encountered an error`,
        detail: st.error || st.domSnapshot?.pageErrorBanner || `Step "${st.label || st.action || ''}" returned status ${st.status || 'error'}.`,
        fixSuggestion: Number(st.status) === 401 || Number(st.status) === 403
          ? 'Verify your {{VAR:username}} / {{VAR:password}} or {{SECRET:...}} credentials, CSRF token, or login URL.'
          : 'Inspect this step selector and payload in the visual preview below.'
      });
    }
  }

  if (out.length === 0 && !res.authenticated) {
    const rawErr = String(res.error || '');
    const isNetworkAbortOrTimeout = /aborted|timed?\s*out|ETIMEDOUT|ECONNREFUSED|ENOTFOUND|Fetch failed/i.test(rawErr);
    if (isNetworkAbortOrTimeout) {
      out.push({
        step: 1,
        sequenceStep: 1,
        severity: 'error',
        code: 'NETWORK_TIMEOUT_OR_ABORT',
        title: 'Step 1 (Navigate): Target Login URL Could Not Be Reached (Timed Out or Aborted)',
        detail: rawErr,
        fixSuggestion: 'Verify the Login URL in Step 1 is reachable from this machine, enable "Allow Authorized Internal / Private Targets" for internal servers, or click "⚡ Load Working Example" in the toolbar to test with the built-in demo login portal.'
      });
    } else {
      out.push({
        step: steps.length || 1,
        sequenceStep: steps.length || 1,
        severity: 'error',
        code: 'AUTH_INCOMPLETE',
        title: 'Login sequence did not establish an authenticated session',
        detail: rawErr || 'No session cookie or Bearer token was captured after executing all steps.',
        fixSuggestion: 'Check that your Submit button click step posts to the login form action and that credentials/OTP variables are set.'
      });
    }
  }

  return out;
}

function renderLsrDiagnosticsBanner(res, { includeInline = true } = {}) {
  if (typeof document === 'undefined') return;
  const targets = [
    document.getElementById('lsr-top-diagnostics-banner'),
    includeInline ? document.getElementById('lsr-inline-diagnostics-summary') : null
  ].filter(Boolean);

  if (targets.length === 0) return;
  if (!res) {
    for (const el of targets) {
      el.classList.add('hidden');
      el.innerHTML = '';
    }
    return;
  }

  const diagnostics = buildClientSideDiagnostics(res);
  const isFailureOrWarn = !res.authenticated || diagnostics.length > 0;

  if (isFailureOrWarn) {
    const hasError = !res.authenticated || diagnostics.some(d => d.severity === 'error');
    const headerText = hasError
      ? '❌ Login Sequence Issue Detected — Review What Is Incorrect Below'
      : `⚠️ Login Sequence Warnings (${escapeHtml(diagnostics.length)})`;

    const itemsHtml = diagnostics.map(d => {
      const stepNum = Number(d.sequenceStep || d.step || 1) || 1;
      const jumpIdx = Math.max(0, stepNum - 1);
      return `
        <div class="lsr-diag-item lsr-diag-${escapeHtml(d.severity === 'warning' ? 'warning' : 'error')}">
          <div class="lsr-diag-item-head">
            <div class="lsr-diag-badges">
              <span class="badge ${d.severity === 'warning' ? 'badge-warning' : 'badge-danger'}">Step ${escapeHtml(stepNum)}</span>
              <code>${escapeHtml(d.code || 'ISSUE')}</code>
              <strong>${escapeHtml(d.title || d.message || 'Step issue')}</strong>
            </div>
            <button type="button" class="btn-secondary btn-small" data-lsr-jump-step="${escapeHtml(jumpIdx)}">🔍 Inspect Step ${escapeHtml(stepNum)}</button>
          </div>
          ${d.detail ? `<div class="lsr-diag-detail">${escapeHtml(d.detail)}</div>` : ''}
          <div class="lsr-diag-fix">💡 <strong>How to Fix:</strong> ${escapeHtml(d.fixSuggestion || d.remediation || 'Check the selector or System Variable for this step.')}</div>
        </div>
      `;
    }).join('');

    const html = `
      <div class="lsr-diag-banner-header">${headerText}</div>
      <div class="lsr-diag-items-list">${itemsHtml}</div>
    `;

    for (const el of targets) {
      el.className = `lsr-top-diagnostics-banner ${hasError ? 'error' : 'warning'}`;
      el.innerHTML = html;
      el.classList.remove('hidden');
    }
    return;
  }

  const stepsCount = Array.isArray(res.steps) ? res.steps.length : (Array.isArray(res.sequenceSteps) ? res.sequenceSteps.length : 0);
  const csrfLabel = res.csrfHeaderName || res.csrfFormField || 'None';
  const successHtml = `
    <div class="lsr-diag-banner-header">
      ✅ Login Sequence Verified &amp; Authenticated — All ${escapeHtml(stepsCount)} step(s) passed (${escapeHtml(res.cookieCount || 0)} cookie(s) · JWT: ${res.hasBearerToken ? 'Captured' : 'None'} · CSRF: ${escapeHtml(csrfLabel)})
    </div>
  `;
  for (const el of targets) {
    el.className = 'lsr-top-diagnostics-banner success';
    el.innerHTML = successHtml;
    el.classList.remove('hidden');
  }
}

function getInputMatchKey(inp = {}) {
  return String(inp.id || inp.name || inp.selector || inp.selectorValue || '').replace(/^#/, '').trim().toLowerCase();
}

function getButtonMatchKey(btn = {}) {
  return String(btn.id || btn.name || btn.text || btn.displayLabel || btn.selector || btn.selectorValue || '').replace(/^#/, '').trim().toLowerCase();
}

function stepTargetsInput(step, inp) {
  if (!step || !inp) return false;
  if (step.type !== 'change_input' && step.action !== 'change_input' && step.type !== 'fill_otp' && step.action !== 'fill_otp') {
    return false;
  }
  const sel = String(step.selector || '').replace(/^#/, '').trim().toLowerCase();
  const fname = String(step.fieldName || '').trim().toLowerCase();
  const id = String(inp.id || '').trim().toLowerCase();
  const name = String(inp.name || '').trim().toLowerCase();
  const selVal = String(inp.selector || inp.selectorValue || '').replace(/^#/, '').trim().toLowerCase();
  if (step.type === 'fill_otp' || step.action === 'fill_otp') {
    if ((!sel || sel === 'auto') && inp.isOtpCandidate) return true;
  }
  return Boolean(
    (id && (id === sel || id === fname)) ||
    (name && (name === sel || name === fname)) ||
    (selVal && (selVal === sel || selVal === fname))
  );
}

function stepTargetsButton(step, btn) {
  if (!step || !btn) return false;
  if (step.type !== 'click_button' && step.action !== 'click_button') return false;
  const sel = String(step.selector || '').replace(/^#/, '').trim().toLowerCase();
  const id = String(btn.id || '').trim().toLowerCase();
  const name = String(btn.name || '').trim().toLowerCase();
  const text = String(btn.text || btn.displayLabel || '').trim().toLowerCase();
  return Boolean(
    (id && id === sel) ||
    (name && name === sel) ||
    (text && sel && (text === sel || text.includes(sel)))
  );
}

function renderVisualPlaySnapshot(playRes, selectedStepIdx = -1) {
  const canvas = document.getElementById('lsr-visual-canvas');
  if (!canvas || !playRes) return;

  const rawSteps = Array.isArray(playRes.steps) && playRes.steps.length > 0
    ? playRes.steps
    : (Array.isArray(playRes.sequenceSteps) ? playRes.sequenceSteps : []);

  if (rawSteps.length === 0) {
    const fallbackDiag = buildClientSideDiagnostics(playRes);
    canvas.innerHTML = `
      <div class="lsr-sim-header-row">
        <strong>🎬 Visual Step-by-Step Replay Preview</strong>
        ${state.lastInspectedPage ? '<button type="button" id="btn-lsr-back-to-inspector" class="btn-secondary btn-small">🔄 Back to Live Form Inspector</button>' : ''}
      </div>
      <div class="feedback-banner ${playRes.authenticated ? 'success' : 'error'}">
        ${escapeHtml(fallbackDiag[0]?.detail || playRes.error || 'No step execution details returned.')}
      </div>
    `;
    return;
  }

  let activeIdx = selectedStepIdx;
  if (!Number.isInteger(activeIdx) || activeIdx < 0 || activeIdx >= rawSteps.length) {
    const errIdx = rawSteps.findIndex(st => getPlayStepStatus(st) === 'error');
    const warnIdx = rawSteps.findIndex(st => getPlayStepStatus(st) === 'warning');
    activeIdx = errIdx >= 0 ? errIdx : (warnIdx >= 0 ? warnIdx : rawSteps.length - 1);
  }

  const activeStep = rawSteps[activeIdx];
  // Find nearest DOM snapshot at or prior to activeIdx, or fall back to lastInspectedPage
  let snap = activeStep?.domSnapshot || null;
  if (!snap) {
    for (let j = activeIdx - 1; j >= 0; j--) {
      if (rawSteps[j]?.domSnapshot) {
        snap = rawSteps[j].domSnapshot;
        break;
      }
    }
  }
  if (!snap && state.lastInspectedPage) {
    snap = state.lastInspectedPage;
  }

  // Timeline Switcher Bar
  const timelineHtml = rawSteps.map((st, i) => {
    const stStatus = getPlayStepStatus(st);
    const badgeEmoji = stStatus === 'error' ? '❌' : (stStatus === 'warning' ? '⚠️' : '✅');
    const stepNum = st.sequenceStep || st.step || i + 1;
    const shortAction = st.type === 'navigate'
      ? 'Navigate'
      : st.type === 'change_input'
      ? (st.fieldName || st.selector || 'Input')
      : st.type === 'fill_otp'
      ? 'OTP'
      : st.type === 'click_button'
      ? (st.selector || 'Submit')
      : (st.type || st.action || 'Step');
    return `
      <button
        type="button"
        class="lsr-timeline-pill ${i === activeIdx ? 'active' : ''} lsr-tl-${stStatus}"
        data-lsr-preview-step="${escapeHtml(i)}"
      >
        Step ${escapeHtml(stepNum)}: ${escapeHtml(shortAction)} ${badgeEmoji}
      </button>
    `;
  }).join('<span class="lsr-timeline-arrow" aria-hidden="true">→</span>');

  const httpStatus = Number(snap?.httpStatus || activeStep?.status || 0);
  const httpClass = httpStatus >= 400 ? 'err' : (httpStatus >= 200 ? 'ok' : 'neutral');
  const pageTitle = snap?.title || 'Target Login Page';
  const pageUrl = snap?.pageUrl || activeStep?.finalUrl || activeStep?.url || playRes.loginUrl || '';

  const stepIssues = Array.isArray(activeStep?.issues) && activeStep.issues.length > 0
    ? activeStep.issues
    : (Array.isArray(playRes.diagnostics)
      ? playRes.diagnostics.filter(d => Number(d.sequenceStep || d.step) === Number(activeStep?.sequenceStep || activeStep?.step))
      : []);

  const selectorIssue = stepIssues.find(iss =>
    iss?.code === 'SELECTOR_NOT_FOUND' || iss?.code === 'BUTTON_SELECTOR_NOT_FOUND'
  );

  // Build available selectors list from snapshot
  const snapInputs = Array.isArray(snap?.inputs) ? snap.inputs : [];
  const snapButtons = Array.isArray(snap?.buttons) ? snap.buttons : [];
  const availableInputSelectors = snapInputs.map(inp =>
    inp.selector || (inp.id ? `#${inp.id}` : (inp.name ? `[name="${inp.name}"]` : inp.type || 'input'))
  );
  const availableButtonSelectors = snapButtons.map(btn =>
    btn.selector || (btn.id ? `#${btn.id}` : (btn.text || btn.displayLabel || 'button'))
  );

  let selectorCalloutHtml = '';
  if (selectorIssue) {
    const availableList = selectorIssue.code === 'BUTTON_SELECTOR_NOT_FOUND'
      ? availableButtonSelectors
      : availableInputSelectors;
    selectorCalloutHtml = `
      <div class="lsr-sim-selector-callout">
        <div class="lsr-sim-callout-title">❌ Unmatched Selector in Step ${escapeHtml(activeStep?.sequenceStep || activeStep?.step || activeIdx + 1)}</div>
        <div>Looking for: <code>${escapeHtml(activeStep?.selector || selectorIssue.selector || '(unspecified)')}</code> (${escapeHtml(activeStep?.selectorType || 'selector')})</div>
        <div>Available on page: ${availableList.length > 0 ? availableList.map(s => `<code>${escapeHtml(s)}</code>`).join(' · ') : '<span class="form-hint">None detected on page</span>'}</div>
        ${selectorIssue.fixSuggestion ? `<div class="lsr-diag-fix">💡 ${escapeHtml(selectorIssue.fixSuggestion)}</div>` : ''}
      </div>
    `;
  }

  const otherIssuesHtml = stepIssues
    .filter(iss => iss !== selectorIssue)
    .map(iss => `
      <div class="lsr-sim-issue-callout lsr-diag-${escapeHtml(iss.severity === 'warning' ? 'warning' : 'error')}">
        <strong>${escapeHtml(iss.code || 'ISSUE')}: ${escapeHtml(iss.title || iss.message || 'Step Issue')}</strong>
        ${iss.detail ? `<div>${escapeHtml(iss.detail)}</div>` : ''}
        ${iss.fixSuggestion ? `<div class="lsr-diag-fix">💡 ${escapeHtml(iss.fixSuggestion)}</div>` : ''}
      </div>
    `).join('');

  // Enrich filled inputs & clicked buttons up through activeIdx
  const filledMap = new Map();
  const clickedMap = new Map();
  for (let i = 0; i <= activeIdx; i++) {
    const st = rawSteps[i];
    if (!st) continue;
    if (st.type === 'change_input' || st.action === 'change_input' || st.type === 'fill_otp' || st.action === 'fill_otp') {
      const selKey = String(st.selector || '').replace(/^#/, '').trim().toLowerCase();
      const fieldKey = String(st.fieldName || '').replace(/^#/, '').trim().toLowerCase();
      const seqAct = (state.loginSequence?.actions || [])[i];
      const rawBinding = seqAct?.value && /^\{\{VAR:[^}]+\}\}$/i.test(seqAct.value)
        ? (st.isSecret ? `•••••••• (${seqAct.value})` : (st.value && st.value !== '[REDACTED]' ? `${st.value} (${seqAct.value})` : seqAct.value))
        : (st.type === 'fill_otp' || st.action === 'fill_otp' ? '•••••• (TOTP)' : (st.isSecret ? '••••••••' : (st.value || seqAct?.value || '')));
      const entry = { stepNum: st.sequenceStep || st.step || i + 1, masked: rawBinding };
      if (selKey) filledMap.set(selKey, entry);
      if (fieldKey) filledMap.set(fieldKey, entry);
    }
    if (st.type === 'click_button' || st.action === 'click_button') {
      const key = String(st.selector || '').replace(/^#/, '').trim().toLowerCase();
      if (key) clickedMap.set(key, st.sequenceStep || st.step || i + 1);
    }
  }

  // Build complete merged list of all inputs from:
  // 1) Current step's domSnapshot (snapInputs)
  // 2) Other steps' domSnapshots in playRes
  // 3) Live inspected page (state.lastInspectedPage.inputs) if available
  // 4) All change_input / fill_otp actions in the sequence (so every input in the sequence is always visible on every step)
  const mergedInputs = [];
  const seenInputKeys = new Set();
  const registerInputCandidate = (candidate) => {
    if (!candidate || typeof candidate !== 'object') return;
    const rawId = String(candidate.id || (candidate.selectorType === 'id' ? candidate.selectorValue || candidate.selector : '') || '').replace(/^#/, '').trim();
    const rawName = String(candidate.name || candidate.fieldName || '').trim();
    const rawSel = String(candidate.selectorValue || candidate.selector || rawId || rawName || '').replace(/^#/, '').trim();
    const keys = [rawId.toLowerCase(), rawName.toLowerCase(), rawSel.toLowerCase()].filter(Boolean);
    if (keys.length === 0) return;
    if (keys.some(k => seenInputKeys.has(k))) return;
    keys.forEach(k => seenInputKeys.add(k));
    mergedInputs.push({
      ...candidate,
      id: rawId,
      name: rawName || rawSel,
      selectorType: candidate.selectorType || (rawId ? 'id' : 'name'),
      selectorValue: candidate.selectorValue || candidate.selector || rawId || rawName
    });
  };

  for (const inp of snapInputs) registerInputCandidate(inp);
  for (const st of rawSteps) {
    if (Array.isArray(st?.domSnapshot?.inputs)) {
      for (const inp of st.domSnapshot.inputs) registerInputCandidate(inp);
    }
  }
  if (Array.isArray(state.lastInspectedPage?.inputs)) {
    const inspectedUrl = String(state.lastInspectedPage.pageUrl || '').split('?')[0];
    const currentBaseUrl = String(pageUrl || '').split('?')[0];
    if (!inspectedUrl || !currentBaseUrl || inspectedUrl === currentBaseUrl) {
      for (const inp of state.lastInspectedPage.inputs) registerInputCandidate(inp);
    }
  }
  for (const st of rawSteps) {
    if (st && (st.type === 'change_input' || st.action === 'change_input' || st.type === 'fill_otp' || st.action === 'fill_otp')) {
      const cleanSel = String(st.selector || st.fieldName || 'input').replace(/^#/, '').trim() || 'input';
      registerInputCandidate({
        id: st.selectorType === 'id' ? cleanSel : '',
        name: st.fieldName || cleanSel,
        label: st.fieldName && st.fieldName !== cleanSel ? `${cleanSel} (${st.fieldName})` : cleanSel,
        displayLabel: st.fieldName && st.fieldName !== cleanSel ? `${cleanSel} (${st.fieldName})` : cleanSel,
        selectorType: st.selectorType || 'id',
        selectorValue: st.selector || cleanSel,
        type: (st.type === 'fill_otp' || st.action === 'fill_otp') ? 'text' : (st.isSecret ? 'password' : 'text'),
        isPassword: Boolean(st.isSecret),
        isOtpCandidate: st.type === 'fill_otp' || st.action === 'fill_otp'
      });
    }
  }
  for (const act of (state.loginSequence?.actions || [])) {
    if (act && (act.type === 'change_input' || act.type === 'fill_otp')) {
      const cleanSel = String(act.selector || act.fieldName || 'input').replace(/^#/, '').trim() || 'input';
      registerInputCandidate({
        id: act.selectorType === 'id' ? cleanSel : '',
        name: act.fieldName || cleanSel,
        label: act.fieldName && act.fieldName !== cleanSel ? `${cleanSel} (${act.fieldName})` : cleanSel,
        displayLabel: act.fieldName && act.fieldName !== cleanSel ? `${cleanSel} (${act.fieldName})` : cleanSel,
        selectorType: act.selectorType || 'id',
        selectorValue: act.selector || cleanSel,
        type: act.type === 'fill_otp' ? 'text' : (act.isSecret ? 'password' : 'text'),
        isPassword: Boolean(act.isSecret),
        isOtpCandidate: act.type === 'fill_otp'
      });
    }
  }

  // Sort visible interactive inputs first, followed by hidden/CSRF fields
  mergedInputs.sort((a, b) => {
    const aHidden = a.type === 'hidden' || a.isHidden ? 1 : 0;
    const bHidden = b.type === 'hidden' || b.isHidden ? 1 : 0;
    return aHidden - bHidden;
  });
  const displayInputs = mergedInputs;

  const inputsPreviewHtml = displayInputs.length > 0
    ? displayInputs.map(inp => {
        const isHidden = inp.type === 'hidden' || Boolean(inp.isHidden);
        const isCsrf = Boolean(
          inp.isCsrf ||
          (snap?.csrfField && (inp.name === snap.csrfField || inp.id === snap.csrfField)) ||
          /csrf|xsrf|requestverificationtoken|authenticity_token|^_token$/i.test(`${inp.name || ''} ${inp.id || ''}`)
        );
        const label = inp.displayLabel || inp.label || inp.name || inp.id || inp.type || 'input';
        const selectorDisp = inp.selector || (inp.id ? `#${inp.id}` : (inp.name ? `[name="${inp.name}"]` : inp.type || 'input'));
        const isTarget = stepTargetsInput(activeStep, inp);
        const matchKey = getInputMatchKey(inp);
        const filledInfo = filledMap.get(String(inp.id || '').toLowerCase())
          || filledMap.get(String(inp.name || '').toLowerCase())
          || filledMap.get(String(inp.selectorValue || '').replace(/^#/, '').toLowerCase())
          || filledMap.get(matchKey);

        const filledVal = filledInfo?.masked
          ? filledInfo.masked
          : (isHidden
              ? (inp.filledValueMasked || (inp.value ? `${String(inp.value).slice(0, 18)}… (Auto-Harvested)` : 'Auto-Harvested on Navigate'))
              : '');
        const isFilled = Boolean(filledInfo || (isHidden && filledVal));

        let statusPillHtml = '<span class="lsr-sim-status-pill untouched">⚪ Untouched</span>';
        let cardCls = 'untouched';
        if (isTarget) {
          statusPillHtml = '<span class="lsr-sim-status-pill target">🎯 Active Step Target</span>';
          cardCls = isFilled ? 'target filled' : 'target';
        } else if (isHidden) {
          statusPillHtml = `<span class="lsr-sim-status-pill filled">🛡️ ${isCsrf ? 'Auto-CSRF Token' : 'Auto-Hidden Field'}</span>`;
          cardCls = 'filled';
        } else if (isFilled) {
          statusPillHtml = `<span class="lsr-sim-status-pill filled">✅ Filled${filledInfo?.stepNum ? ` (Step ${escapeHtml(filledInfo.stepNum)})` : ''}</span>`;
          cardCls = 'filled';
        }

        return `
          <div class="lsr-sim-input-card ${cardCls}">
            <div class="lsr-sim-input-head">
              <div>
                <strong>${escapeHtml(label)}</strong>
                <code class="lsr-sim-selector-tag">${escapeHtml(selectorDisp)}</code>
                ${inp.isPassword ? '<span class="badge badge-warning">password</span>' : ''}
                ${inp.isOtpCandidate ? '<span class="badge badge-primary">🔑 OTP</span>' : ''}
                ${isHidden ? '<span class="badge badge-outline">hidden</span>' : ''}
              </div>
              ${statusPillHtml}
            </div>
            <div class="lsr-sim-input-box ${isFilled ? 'has-value' : ''}">
              ${filledVal ? `<code>${escapeHtml(filledVal)}</code>` : '<span class="form-hint">(waiting for step to fill)</span>'}
            </div>
          </div>
        `;
      }).join('')
    : '<div class="empty-muted">No form inputs rendered on this step snapshot.</div>';

  // Merge all buttons from snapshot, other step snapshots, and sequence click_button actions
  const mergedButtons = [];
  const seenBtnKeys = new Set();
  const registerButtonCandidate = (btn) => {
    if (!btn || typeof btn !== 'object') return;
    const rawId = String(btn.id || (btn.selectorType === 'id' ? btn.selectorValue || btn.selector : '') || '').replace(/^#/, '').trim();
    const rawName = String(btn.name || (btn.selectorType === 'name' ? btn.selectorValue || btn.selector : '') || '').trim();
    const rawText = String(btn.text || btn.displayLabel || btn.selectorValue || btn.selector || 'Submit').trim();
    const key = (rawId || rawName || rawText).toLowerCase();
    if (!key || seenBtnKeys.has(key)) return;
    seenBtnKeys.add(key);
    mergedButtons.push({
      ...btn,
      id: rawId,
      name: rawName,
      text: rawText,
      displayLabel: btn.displayLabel || rawText
    });
  };
  for (const b of snapButtons) registerButtonCandidate(b);
  for (const st of rawSteps) {
    if (Array.isArray(st?.domSnapshot?.buttons)) {
      for (const b of st.domSnapshot.buttons) registerButtonCandidate(b);
    }
  }
  for (const st of rawSteps) {
    if (st && (st.type === 'click_button' || st.action === 'click_button')) {
      registerButtonCandidate({
        selectorType: st.selectorType || 'text',
        selector: st.selector || 'Submit',
        text: st.selector || 'Submit'
      });
    }
  }
  for (const act of (state.loginSequence?.actions || [])) {
    if (act && act.type === 'click_button') {
      registerButtonCandidate({
        selectorType: act.selectorType || 'text',
        selector: act.selector || 'Submit',
        text: act.selector || 'Submit'
      });
    }
  }
  const displayButtons = mergedButtons;

  const buttonsPreviewHtml = displayButtons.length > 0
    ? displayButtons.map(btn => {
        const btnLabel = btn.displayLabel || btn.text || btn.id || btn.name || 'Submit';
        const btnSel = btn.selector || (btn.id ? `#${btn.id}` : (btn.name ? `[name="${btn.name}"]` : btnLabel));
        const isTarget = stepTargetsButton(activeStep, btn);
        const matchKey = getButtonMatchKey(btn);
        const clickedStepNum = btn.clickedInStep || (btn.clicked ? (activeStep?.sequenceStep || activeStep?.step || activeIdx + 1) : null)
          || clickedMap.get(String(btn.id || '').toLowerCase())
          || clickedMap.get(String(btn.name || '').toLowerCase())
          || clickedMap.get(String(btn.text || btn.displayLabel || '').toLowerCase())
          || clickedMap.get(matchKey);

        const isClicked = Boolean(clickedStepNum || isTarget);
        return `
          <div class="lsr-sim-button-card ${isClicked ? 'clicked' : ''} ${isTarget ? 'target' : ''}">
            <div class="lsr-sim-button-main">
              <span class="lsr-sim-button-pill">${escapeHtml(btnLabel)}</span>
              <code class="lsr-sim-selector-tag">${escapeHtml(btnSel)}</code>
            </div>
            ${clickedStepNum
              ? `<span class="lsr-sim-status-pill clicked">🖱️ Clicked in Step ${escapeHtml(clickedStepNum)}</span>`
              : (isTarget ? '<span class="lsr-sim-status-pill target">🎯 Active Step Target</span>' : '<span class="lsr-sim-status-pill untouched">⚪ Not clicked</span>')}
          </div>
        `;
      }).join('')
    : '<div class="empty-muted">No submit buttons rendered on this step snapshot.</div>';

  canvas.innerHTML = `
    <div class="lsr-sim-header-row">
      <strong>🎬 Visual Step-by-Step Replay Preview</strong>
      ${state.lastInspectedPage ? '<button type="button" id="btn-lsr-back-to-inspector" class="btn-secondary btn-small">🔄 Back to Live Form Inspector</button>' : ''}
    </div>
    <div class="lsr-timeline-bar" role="tablist" aria-label="Replay Step Timeline">
      ${timelineHtml}
    </div>
    <div class="lsr-sim-browser-card">
      <div class="lsr-sim-browser-chrome">
        <span class="lsr-sim-dots" aria-hidden="true"><span></span><span></span><span></span></span>
        ${httpStatus ? `<span class="lsr-sim-http-pill ${httpClass}">HTTP ${escapeHtml(httpStatus)}</span>` : ''}
        <strong class="lsr-sim-page-title">${escapeHtml(pageTitle)}</strong>
        <code class="lsr-sim-page-url">${escapeHtml(pageUrl || '(target URL)')}</code>
      </div>
      <div class="lsr-sim-browser-body">
        ${snap?.pageErrorBanner && !/fetch failed|operation was aborted|timed?\s*out/i.test(String(snap.pageErrorBanner)) ? `<div class="lsr-sim-page-error">🚨 <strong>Page Error Banner Detected:</strong> "${escapeHtml(snap.pageErrorBanner)}"</div>` : ''}
        ${selectorCalloutHtml}
        ${otherIssuesHtml}
        <div class="lsr-inspect-section">
          <div class="lsr-inspect-section-title">Visual Form Inputs Preview (${escapeHtml(displayInputs.length)})</div>
          <div class="lsr-sim-inputs-list">${inputsPreviewHtml}</div>
        </div>
        <div class="lsr-inspect-section">
          <div class="lsr-inspect-section-title">Visual Buttons Preview (${escapeHtml(displayButtons.length)})</div>
          <div class="lsr-sim-buttons-list">${buttonsPreviewHtml}</div>
        </div>
      </div>
    </div>
  `;
}

function buildSyntheticPlayResultFromSequence(seq, { errorText = '', markFirstStepFailed = false } = {}) {
  const s = seq || state.loginSequence || createDefaultLoginSequence();
  const actions = Array.isArray(s.actions) ? s.actions : [];
  const firstNav = actions.find(a => a.type === 'navigate' && a.url);
  const pageUrl = s.targetUrl || firstNav?.url || document.getElementById('lsr-inspect-url')?.value.trim() || '';

  const synthInputs = actions
    .filter(a => a.type === 'change_input' || a.type === 'fill_otp')
    .map(a => {
      const cleanSel = String(a.selector || a.fieldName || 'input').replace(/^#/, '').trim() || 'input';
      const isPass = Boolean(a.isSecret || /pass|pwd|secret/i.test(cleanSel));
      return {
        id: a.selectorType === 'id' ? cleanSel : '',
        name: a.fieldName || cleanSel,
        type: a.type === 'fill_otp' ? 'text' : (isPass ? 'password' : 'text'),
        label: cleanSel,
        displayLabel: cleanSel,
        selectorType: a.selectorType || 'id',
        selectorValue: a.selector || cleanSel,
        isPassword: isPass,
        isOtpCandidate: a.type === 'fill_otp',
        filledValueMasked: a.type === 'fill_otp' ? '•••••• (TOTP)' : getLsrSecretDisplayMask(a)
      };
    });

  const synthButtons = actions
    .filter(a => a.type === 'click_button')
    .map(a => {
      const cleanBtn = String(a.selector || 'Submit').replace(/^#/, '').trim() || 'Submit';
      return {
        id: a.selectorType === 'id' ? cleanBtn : '',
        name: a.selectorType === 'name' ? cleanBtn : '',
        type: 'submit',
        text: cleanBtn,
        displayLabel: cleanBtn,
        selectorType: a.selectorType || 'text',
        selectorValue: a.selector || cleanBtn,
        wasClicked: true
      };
    });

  const baseSnap = {
    pageUrl,
    title: `${s.name || 'WrapperSequence.lsr'} (Visual Sequence Preview)`,
    httpStatus: markFirstStepFailed ? 0 : 200,
    csrfDetected: true,
    pageErrorBanner: null,
    inputs: synthInputs,
    buttons: synthButtons
  };

  const steps = actions.map((act, idx) => ({
    step: idx + 1,
    sequenceStep: idx + 1,
    action: act.type,
    type: act.type,
    label: formatLsrStepLabel(act),
    selectorType: act.selectorType,
    selector: act.selector,
    fieldName: act.fieldName || act.selector,
    value: getLsrSecretDisplayMask(act),
    isSecret: Boolean(act.isSecret),
    url: act.url || act.submitUrl || pageUrl,
    status: markFirstStepFailed && idx === 0 ? 0 : 200,
    stepStatus: markFirstStepFailed && idx === 0 ? 'error' : 'ok',
    ...(markFirstStepFailed && idx === 0 && errorText
      ? {
          error: errorText,
          issues: [
            {
              step: 1,
              sequenceStep: 1,
              severity: 'error',
              code: /aborted|timed?\s*out|ETIMEDOUT/i.test(errorText) ? 'NETWORK_TIMEOUT_OR_ABORT' : 'NAVIGATION_HTTP_ERROR',
              title: `Step 1 (${act.type === 'navigate' ? 'Navigate' : act.type}): ${errorText}`,
              detail: errorText,
              fixSuggestion: 'Check that the Login URL in Step 1 is reachable, or click "→ Load Page Forms" on your target login URL.'
            }
          ]
        }
      : {}),
    domSnapshot: baseSnap
  }));

  return {
    authenticated: !markFirstStepFailed,
    error: errorText || '',
    loginUrl: pageUrl,
    steps
  };
}

function renderSequenceBlueprintCanvas(seq = null) {
  const targetSeq = seq || state.loginSequence;
  if (!targetSeq || !Array.isArray(targetSeq.actions) || targetSeq.actions.length === 0) return;
  const blueprintRes = buildSyntheticPlayResultFromSequence(targetSeq, { markFirstStepFailed: false });
  renderVisualPlaySnapshot(blueprintRes, state.selectedLsrStepIndex >= 0 ? state.selectedLsrStepIndex : 0);
}

function showLsrPlayOutput(html, variant = 'info') {
  const out = document.getElementById('lsr-play-output');
  if (!out) return;
  out.className = `lsr-play-output lsr-play-${variant}`;
  out.innerHTML = html;
  out.classList.remove('hidden');
}

async function loadSavedLoginSequences() {
  let localSequences = [];
  let localActiveId = '';
  try {
    if (typeof localStorage !== 'undefined') {
      const rawSeqs = localStorage.getItem(LSR_SEQUENCES_STORAGE_KEY);
      if (rawSeqs) {
        const parsed = JSON.parse(rawSeqs);
        if (Array.isArray(parsed)) {
          localSequences = parsed.map(s => normalizeClientLoginSequence(s));
        }
      }
      localActiveId = localStorage.getItem(LSR_ACTIVE_SEQ_STORAGE_KEY) || '';
    }
  } catch {
    localSequences = [];
  }

  if (localSequences.length > 0) {
    state.savedSequences = localSequences;
    const activeMatch = localActiveId
      ? localSequences.find(s => s.sequenceId === localActiveId)
      : null;
    if (activeMatch || (state.loginSequence.actions.length === 0 && !state.loginSequence.sequenceId)) {
      state.loginSequence = normalizeClientLoginSequence(activeMatch || localSequences[0]);
      applyLsrStateToInputs();
    } else {
      renderLsrSequenceCards();
    }
  }

  if (typeof fetch !== 'function') return;
  try {
    const res = await fetch('/api/auth/sequences', { headers: { Accept: 'application/json' } });
    if (!res.ok) return;
    const data = await res.json();
    if (Array.isArray(data?.sequences)) {
      const localMap = new Map(localSequences.filter(s => s.sequenceId).map(s => [s.sequenceId, s]));
      const merged = data.sequences.map(rawS => {
        const s = normalizeClientLoginSequence(rawS);
        const localMatch = s.sequenceId ? localMap.get(s.sequenceId) : null;
        if (localMatch) {
          // Preserve unmasked local secret values if server exported '[SECRET]'
          if (localMatch.otpConfig?.secret && (!s.otpConfig?.secret || s.otpConfig.secret === '[SECRET]' || s.otpConfig.secret === '[REDACTED]')) {
            s.otpConfig.secret = localMatch.otpConfig.secret;
          }
          const localSecretMap = new Map((localMatch.secrets || []).map(sec => [sec.name, sec.value]));
          s.secrets = (s.secrets || []).map(sec => ({
            ...sec,
            value: (!sec.value || sec.value === '[SECRET]' || sec.value === '[REDACTED]')
              ? (localSecretMap.get(sec.name) || sec.value)
              : sec.value
          }));
        }
        return s;
      });
      state.savedSequences = merged;
      persistSequencesToLocal();

      const preferredId = state.loginSequence.sequenceId || localActiveId;
      const activeSeq = preferredId
        ? state.savedSequences.find(s => s.sequenceId === preferredId)
        : null;
      if (activeSeq) {
        state.loginSequence = normalizeClientLoginSequence(activeSeq);
        applyLsrStateToInputs();
      } else if (state.savedSequences.length > 0 && state.loginSequence.actions.length === 0 && !state.loginSequence.sequenceId) {
        state.loginSequence = normalizeClientLoginSequence(state.savedSequences[0]);
        applyLsrStateToInputs();
      } else {
        renderLsrSequenceCards();
      }
    }
  } catch {
    // Graceful no-op when backend sequence store is unavailable
  }
}

function initLoginSequenceRecorder() {
  if (typeof document === 'undefined') return;

  const backdrop = document.getElementById('lsr-recorder-backdrop');
  const btnOpenNew = document.getElementById('btn-new-lsr-sequence');
  const btnImport = document.getElementById('btn-import-lsr-sequence');
  const importFileInput = document.getElementById('lsr-import-file-input');
  const btnClose = document.getElementById('btn-lsr-close');

  const sysVarNameEl = document.getElementById('sys-var-name-input');
  const sysVarCategoryEl = document.getElementById('sys-var-category-select');
  const sysVarValueEl = document.getElementById('sys-var-value-input');
  const btnSaveSysVar = document.getElementById('btn-save-sys-var');
  const sysVarsListEl = document.getElementById('sys-vars-list');

  const modalSysVarsBar = document.getElementById('lsr-modal-sysvars-bar');
  const btnToggleModalSysVar = document.getElementById('btn-lsr-toggle-modal-sysvar');
  const modalSysVarForm = document.getElementById('lsr-modal-sysvar-quick-form');
  const modalSysVarNameEl = document.getElementById('lsr-modal-sysvar-name');
  const modalSysVarCatEl = document.getElementById('lsr-modal-sysvar-cat');
  const modalSysVarValEl = document.getElementById('lsr-modal-sysvar-val');
  const btnModalSaveSysVar = document.getElementById('btn-lsr-modal-save-sysvar');

  const reuseSelectEl = document.getElementById('lsr-reuse-select');
  const btnUseSelectedLsr = document.getElementById('btn-use-selected-lsr');
  const btnPlaySelectedLsr = document.getElementById('btn-play-selected-lsr');
  const btnDuplicateSelectedLsr = document.getElementById('btn-duplicate-selected-lsr');
  const btnDeleteSelectedLsr = document.getElementById('btn-delete-selected-lsr');
  const btnRefreshLsrList = document.getElementById('btn-refresh-lsr-list');

  const topDiagnosticsEl = document.getElementById('lsr-top-diagnostics-banner');
  const inlineDiagnosticsEl = document.getElementById('lsr-inline-diagnostics-summary');

  const secretNameEl = document.getElementById('lsr-secret-name-input');
  const secretValueEl = document.getElementById('lsr-secret-value-input');
  const btnAddSecret = document.getElementById('btn-add-lsr-secret');
  const secretsChipsEl = document.getElementById('lsr-secrets-chips');

  const btnOpenOtp = document.getElementById('btn-open-otp-config');
  const otpPanel = document.getElementById('lsr-otp-config-panel');
  const btnTestOtp = document.getElementById('btn-test-otp-preview');
  const otpStatusEl = document.getElementById('otp-preview-status');

  const seqCardsList = document.getElementById('lsr-sequence-cards-list');
  const inspectUrlEl = document.getElementById('lsr-inspect-url');
  const btnInspectGo = document.getElementById('btn-lsr-inspect-go');
  const btnRecord = document.getElementById('btn-lsr-record');
  const btnAddOtpStep = document.getElementById('btn-lsr-add-otp-step');
  const btnSave = document.getElementById('btn-lsr-save');
  const btnDeleteSeqModal = document.getElementById('btn-lsr-delete-sequence');
  const btnPlay = document.getElementById('btn-lsr-play');
  const btnNewBlank = document.getElementById('btn-lsr-new-blank');
  const btnLoadExampleModal = document.getElementById('btn-lsr-load-example');
  const btnLoadExampleInline = document.getElementById('btn-load-example-lsr-inline');
  const visualCanvas = document.getElementById('lsr-visual-canvas');

  const actionsListEl = document.getElementById('lsr-actions-list');
  const actionPropsEl = document.getElementById('lsr-action-properties');
  const btnStepUp = document.getElementById('btn-lsr-step-up');
  const btnStepDown = document.getElementById('btn-lsr-step-down');
  const btnStepAdd = document.getElementById('btn-lsr-step-add');
  const btnStepDelete = document.getElementById('btn-lsr-step-delete');

  const restrictionInput = document.getElementById('lsr-restriction-input');
  const btnAddRestriction = document.getElementById('btn-add-lsr-restriction');
  const restrictionsListEl = document.getElementById('lsr-restrictions-list');

  const tabActionsBtn = document.getElementById('btn-lsr-tab-actions');
  const tabRestrictionsBtn = document.getElementById('btn-lsr-tab-restrictions');
  const tabSessionBtn = document.getElementById('btn-lsr-tab-session');
  const panelActions = document.getElementById('lsr-panel-actions');
  const panelRestrictions = document.getElementById('lsr-panel-restrictions');
  const panelSession = document.getElementById('lsr-panel-session');

  function openLsrModal(seqToLoad = null, { isNewBlank = false } = {}) {
    state.lsrDraftDismissed = false;
    if (isNewBlank) {
      state.loginSequence = createDefaultLoginSequence();
      state.selectedLsrStepIndex = -1;
      state.lastLsrPlayResult = null;
      state.lastInspectedPage = null;
      renderLsrDiagnosticsBanner(null, { includeInline: false });
    } else if (seqToLoad) {
      const prevId = state.loginSequence?.sequenceId || '';
      const normalized = normalizeClientLoginSequence(seqToLoad);
      // Preserve any unmasked secrets from existing state
      const existingMatch = (state.savedSequences || []).find(s => s.sequenceId && s.sequenceId === normalized.sequenceId) || state.loginSequence;
      if (existingMatch && existingMatch.sequenceId === normalized.sequenceId) {
        if (existingMatch.otpConfig?.secret && (!normalized.otpConfig?.secret || normalized.otpConfig.secret === '[SECRET]' || normalized.otpConfig.secret === '[REDACTED]')) {
          normalized.otpConfig.secret = existingMatch.otpConfig.secret;
        }
        const secMap = new Map((existingMatch.secrets || []).map(s => [s.name, s.value]));
        normalized.secrets = (normalized.secrets || []).map(s => ({
          ...s,
          value: (!s.value || s.value === '[SECRET]' || s.value === '[REDACTED]') ? (secMap.get(s.name) || s.value) : s.value
        }));
      }
      state.loginSequence = normalized;
      state.selectedLsrStepIndex = state.loginSequence.actions.length > 0 ? 0 : -1;
      if (state.loginSequence.sequenceId !== prevId) {
        state.lastLsrPlayResult = null;
        renderLsrDiagnosticsBanner(null, { includeInline: false });
      }
    } else if (state.selectedLsrStepIndex < 0 && state.loginSequence.actions.length > 0) {
      state.selectedLsrStepIndex = 0;
    }

    applyLsrStateToInputs();
    const firstNav = (state.loginSequence.actions || []).find(a => a.type === 'navigate' && a.url);
    const seqUrl = state.loginSequence.targetUrl || firstNav?.url || '';
    if (inspectUrlEl) {
      if (isNewBlank) {
        inspectUrlEl.value = document.getElementById('adv-auth-login-url')?.value.trim()
          || document.getElementById('target-url')?.value.trim()
          || '';
      } else if (seqUrl) {
        inspectUrlEl.value = seqUrl;
      } else if (!inspectUrlEl.value.trim()) {
        const candidate = document.getElementById('adv-auth-login-url')?.value.trim()
          || document.getElementById('target-url')?.value.trim()
          || '';
        if (candidate) inspectUrlEl.value = candidate;
      }
    }

    if (state.lastLsrPlayResult) {
      renderVisualPlaySnapshot(state.lastLsrPlayResult, state.selectedLsrStepIndex);
    } else if (state.loginSequence.actions.length > 0) {
      renderSequenceBlueprintCanvas(state.loginSequence);
    }

    switchLsrSubTab('actions');
    if (backdrop) {
      backdrop.classList.remove('hidden');
      document.getElementById('lsr-sequence-name')?.focus();
    }
  }

  function closeLsrModal() {
    syncLsrConfigFromInputs();
    renderLsrSequenceCards();
    if (backdrop) backdrop.classList.add('hidden');
  }

  function switchLsrSubTab(tabKey) {
    const map = [
      { key: 'actions', btn: tabActionsBtn, panel: panelActions },
      { key: 'restrictions', btn: tabRestrictionsBtn, panel: panelRestrictions },
      { key: 'session', btn: tabSessionBtn, panel: panelSession }
    ];
    for (const item of map) {
      const isMatch = item.key === tabKey;
      if (item.btn) {
        item.btn.classList.toggle('active', isMatch);
        item.btn.setAttribute('aria-selected', isMatch ? 'true' : 'false');
      }
      if (item.panel) {
        item.panel.classList.toggle('hidden', !isMatch);
      }
    }
  }

  function activateSequenceForScan(seq) {
    if (!seq) return;
    state.lsrDraftDismissed = false;
    state.loginSequence = normalizeClientLoginSequence(seq);
    state.selectedLsrStepIndex = state.loginSequence.actions.length > 0 ? 0 : -1;
    state.lastLsrPlayResult = null;
    persistSequencesToLocal();
    const authMethodEl = document.getElementById('adv-auth-method');
    if (authMethodEl) authMethodEl.value = 'login_sequence';
    applyLsrStateToInputs();
    if (inlineDiagnosticsEl) {
      inlineDiagnosticsEl.className = 'lsr-top-diagnostics-banner success';
      inlineDiagnosticsEl.innerHTML = `<div class="lsr-diag-banner-header">✅ Active sequence set to <strong>${escapeHtml(state.loginSequence.name)}</strong> (${escapeHtml(state.loginSequence.actions.length)} step(s)). Ready to scan or click Quick Play to verify.</div>`;
      inlineDiagnosticsEl.classList.remove('hidden');
    }
  }

  async function deleteLoginSequence(targetSeq) {
    if (!targetSeq) return;
    const deletedName = targetSeq.name || 'WrapperSequence.lsr';
    const targetId = targetSeq.sequenceId || '';

    // 1. Delete from backend store by sequenceId or sequence name
    const deleteKey = targetId || deletedName;
    if (deleteKey && typeof fetch === 'function') {
      try {
        await fetch(`/api/auth/sequences/${encodeURIComponent(deleteKey)}`, { method: 'DELETE' });
      } catch {
        // Ignore network/404 errors during delete
      }
    }

    // 2. Remove from state.savedSequences
    if (Array.isArray(state.savedSequences) && state.savedSequences.length > 0) {
      const matchIdx = state.savedSequences.findIndex(s =>
        s === targetSeq ||
        (targetId && s.sequenceId === targetId) ||
        (!targetId && !s.sequenceId && s.name === deletedName) ||
        s.name === deletedName
      );
      if (matchIdx >= 0) {
        state.savedSequences.splice(matchIdx, 1);
      }
    }

    // 3. Update active state.loginSequence or enter clean empty state
    const wasActive = Boolean(
      targetSeq === state.loginSequence ||
      (targetId && targetId === state.loginSequence.sequenceId) ||
      (!targetId && deletedName === state.loginSequence.name)
    );

    if (state.savedSequences.length === 0) {
      state.lsrDraftDismissed = true;
      state.loginSequence = createDefaultLoginSequence();
      state.selectedLsrStepIndex = -1;
      state.lastLsrPlayResult = null;
      state.lastInspectedPage = null;
      const recIdEl = document.getElementById('adv-recorded-session-id');
      if (recIdEl) recIdEl.value = '';
      if (visualCanvas) {
        visualCanvas.innerHTML = '<div class="empty-muted">🗑️ Sequence deleted. Enter a Login URL above and click <strong>→ Load Page Forms</strong>, or click <strong>⚡ Load Working Example</strong> to create a new sequence.</div>';
      }
    } else if (wasActive) {
      state.lsrDraftDismissed = false;
      state.loginSequence = normalizeClientLoginSequence(state.savedSequences[0]);
      state.selectedLsrStepIndex = state.loginSequence.actions.length > 0 ? 0 : -1;
      state.lastLsrPlayResult = null;
      if (state.loginSequence.actions.length > 0) {
        renderSequenceBlueprintCanvas(state.loginSequence);
      }
    }

    persistSequencesToLocal();
    applyLsrStateToInputs();

    const msgHtml = `<div class="lsr-diag-banner-header">🗑️ Deleted login sequence <strong>${escapeHtml(deletedName)}</strong>.</div>`;
    if (inlineDiagnosticsEl) {
      inlineDiagnosticsEl.className = 'lsr-top-diagnostics-banner info';
      inlineDiagnosticsEl.innerHTML = msgHtml;
      inlineDiagnosticsEl.classList.remove('hidden');
    }
    if (topDiagnosticsEl) {
      topDiagnosticsEl.className = 'lsr-top-diagnostics-banner info';
      topDiagnosticsEl.innerHTML = msgHtml;
      topDiagnosticsEl.classList.remove('hidden');
    }
    showLsrPlayOutput(`🗑️ Deleted login sequence <strong>${escapeHtml(deletedName)}</strong>.`, 'info');
  }

  async function duplicateSequence(seq) {
    if (!seq) return;
    const baseName = String(seq.name || 'Sequence.lsr').replace(/\.lsr$/i, '');
    const copyPayload = buildLoginSequencePayload({
      includeSecrets: true,
      seqOverride: normalizeClientLoginSequence({
        ...seq,
        sequenceId: '',
        name: `${baseName}-copy.lsr`,
        updatedAt: new Date().toISOString()
      })
    });
    delete copyPayload.sequenceId;

    let savedCopy = normalizeClientLoginSequence(copyPayload);
    try {
      const res = await apiPost('/api/auth/sequences', copyPayload);
      savedCopy = normalizeClientLoginSequence({
        ...(res?.sequence || copyPayload),
        secrets: copyPayload.secrets,
        otpConfig: copyPayload.otpConfig
      });
    } catch {
      savedCopy.sequenceId = `local-${Date.now()}`;
    }

    state.savedSequences.unshift(savedCopy);
    activateSequenceForScan(savedCopy);
  }

  async function executePlayLsrSequence({ seqOverride = null, openModalOnPlay = false } = {}) {
    const activeSeq = seqOverride ? normalizeClientLoginSequence(seqOverride) : null;
    if (activeSeq) {
      state.loginSequence = activeSeq;
      applyLsrStateToInputs();
    }
    const payload = buildLoginSequencePayload({ includeSecrets: true, seqOverride: activeSeq });
    const firstNav = payload.actions.find(a => a.type === 'navigate' && a.url);
    const rawTarget = (openModalOnPlay ? null : inspectUrlEl?.value.trim())
      || payload.targetUrl
      || firstNav?.url
      || document.getElementById('adv-auth-login-url')?.value.trim()
      || document.getElementById('target-url')?.value.trim()
      || '';

    if (!rawTarget) {
      if (openModalOnPlay) openLsrModal(state.loginSequence);
      const errRes = {
        authenticated: false,
        error: 'Enter a Target URL or Login URL before playing the login sequence.',
        steps: []
      };
      renderLsrDiagnosticsBanner(errRes);
      showLsrPlayOutput('Enter a Target URL or Login URL before playing the login sequence.', 'error');
      return;
    }
    if (payload.actions.length === 0) {
      if (openModalOnPlay) openLsrModal(state.loginSequence);
      const errRes = {
        authenticated: false,
        error: 'Add at least one Login Action step before playing the sequence.',
        steps: []
      };
      renderLsrDiagnosticsBanner(errRes);
      showLsrPlayOutput('Add at least one Login Action step before playing the sequence.', 'error');
      return;
    }

    const targetUrl = normalizeTargetScheme(rawTarget);
    const allowPrivate = Boolean(document.getElementById('allow-private-toggle')?.checked);
    const sourceIp = document.getElementById('adv-source-ip')?.value.trim() || '';
    const reqTimeout = Number(document.getElementById('adv-timeout')?.value) || 10000;

    if (openModalOnPlay && backdrop && backdrop.classList.contains('hidden')) {
      openLsrModal(state.loginSequence);
    }

    if (btnPlay) {
      btnPlay.disabled = true;
      btnPlay.textContent = 'Playing...';
    }
    if (btnPlaySelectedLsr) btnPlaySelectedLsr.disabled = true;
    showLsrPlayOutput('⏳ Executing login sequence steps against target...', 'info');
    renderSequenceBlueprintCanvas(payload);

    try {
      const res = await apiPost('/api/auth/record-session', {
        targetUrl,
        allowPrivate,
        timeout: reqTimeout,
        ...(sourceIp ? { sourceIp } : {}),
        sequenceId: payload.sequenceId || state.loginSequence.sequenceId || '',
        loginSequence: payload,
        systemVariables: state.systemVariables,
        secrets: payload.secrets,
        otpConfig: payload.otpConfig,
        restrictions: payload.restrictions,
        sessionDetection: payload.sessionDetection
      });

      state.lastLsrPlayResult = res;
      if (res.sequenceId && !state.loginSequence.sequenceId) {
        state.loginSequence.sequenceId = res.sequenceId;
      }

      const recIdEl = document.getElementById('adv-recorded-session-id');
      if (recIdEl) {
        recIdEl.value = res.authenticated === true && res.sessionId ? res.sessionId : '';
      }
      renderRecordedSessionPreview(res);
      renderLsrDiagnosticsBanner(res);
      renderLsrActionsList();
      renderVisualPlaySnapshot(res, -1);

      const steps = Array.isArray(res.steps) ? res.steps : (Array.isArray(res.sequenceSteps) ? res.sequenceSteps : []);
      const stepsHtml = steps.map(st => {
        const extras = [];
        if (st.status) extras.push(`HTTP ${st.status}`);
        if (st.csrfDetected) extras.push('CSRF detected');
        if (st.otpGenerated) extras.push('OTP filled');
        if (st.tokenExtracted) extras.push('Token captured');
        if (Array.isArray(st.cookiesHarvested) && st.cookiesHarvested.length > 0) {
          extras.push(`Cookies: ${st.cookiesHarvested.join(', ')}`);
        }
        if (st.error) extras.push(`Error: ${st.error}`);
        return `<div class="lsr-play-step-row"><span>Step ${escapeHtml(st.step)}: <strong>${escapeHtml(st.label || st.action)}</strong></span> <code>${escapeHtml(extras.join(' · ') || 'OK')}</code></div>`;
      }).join('');

      const verdictHtml = res.authenticated
        ? `✅ <strong>Authenticated</strong> (Session ${escapeHtml(String(res.sessionId || '').slice(0, 8))} · ${escapeHtml(res.cookieCount || 0)} cookie(s) · CSRF: ${escapeHtml(res.csrfHeaderName || res.csrfFormField || 'None')})`
        : `⚠️ <strong>Login Sequence Incomplete</strong> (${escapeHtml(res.error || 'See diagnostics banner at top')})`;

      showLsrPlayOutput(`
        <div class="lsr-play-verdict">${verdictHtml}</div>
        <div class="lsr-play-steps-list">${stepsHtml}</div>
      `, res.authenticated ? 'success' : 'error');
    } catch (err) {
      const recIdEl = document.getElementById('adv-recorded-session-id');
      if (recIdEl) recIdEl.value = '';
      const failRes = buildSyntheticPlayResultFromSequence(payload, {
        errorText: err.message,
        markFirstStepFailed: true
      });
      state.lastLsrPlayResult = failRes;
      renderLsrDiagnosticsBanner(failRes);
      renderLsrActionsList();
      renderVisualPlaySnapshot(failRes, 0);
      showLsrPlayOutput(`✕ Replay failed: ${escapeHtml(err.message)}`, 'error');
    } finally {
      if (btnPlay) {
        btnPlay.disabled = false;
        btnPlay.textContent = '▶️ Play / Test Sequence';
      }
      if (btnPlaySelectedLsr) btnPlaySelectedLsr.disabled = false;
    }
  }

  // System Variables Panel Handlers
  function syncSysVarValueInputType(catSelect, valInput) {
    if (!catSelect || !valInput) return;
    valInput.type = isSecretVarCategory(catSelect.value) ? 'password' : 'text';
  }

  if (sysVarCategoryEl && sysVarValueEl) {
    sysVarCategoryEl.addEventListener('change', () => syncSysVarValueInputType(sysVarCategoryEl, sysVarValueEl));
    syncSysVarValueInputType(sysVarCategoryEl, sysVarValueEl);
  }
  if (modalSysVarCatEl && modalSysVarValEl) {
    modalSysVarCatEl.addEventListener('change', () => syncSysVarValueInputType(modalSysVarCatEl, modalSysVarValEl));
    syncSysVarValueInputType(modalSysVarCatEl, modalSysVarValEl);
  }

  async function handleSaveMainSysVar() {
    const name = sysVarNameEl?.value.trim() || '';
    const category = sysVarCategoryEl?.value || 'custom';
    const value = sysVarValueEl?.value ?? '';
    const res = await saveSystemVariable({ name, category, value });
    if (res.ok) {
      if (sysVarNameEl) sysVarNameEl.value = '';
      if (sysVarValueEl) sysVarValueEl.value = '';
      if (btnSaveSysVar) btnSaveSysVar.textContent = '+ Save System Variable';
    } else if (sysVarNameEl) {
      sysVarNameEl.focus();
    }
  }

  if (btnSaveSysVar) btnSaveSysVar.addEventListener('click', handleSaveMainSysVar);
  if (sysVarValueEl) {
    sysVarValueEl.addEventListener('keydown', e => {
      if (e.key === 'Enter') {
        e.preventDefault();
        handleSaveMainSysVar();
      }
    });
  }

  if (sysVarsListEl) {
    sysVarsListEl.addEventListener('click', async e => {
      const btn = e.target.closest('[data-sysvar-action]');
      if (!btn) return;
      const action = btn.getAttribute('data-sysvar-action');
      const name = btn.getAttribute('data-sysvar-name') || '';
      if (!name) return;

      if (action === 'edit') {
        const entry = state.systemVariables.find(v => v.name === name);
        if (!entry) return;
        if (sysVarNameEl) sysVarNameEl.value = entry.name;
        if (sysVarCategoryEl) sysVarCategoryEl.value = entry.category || 'custom';
        syncSysVarValueInputType(sysVarCategoryEl, sysVarValueEl);
        if (sysVarValueEl) {
          sysVarValueEl.value = entry.isSecret ? '' : (entry.value || '');
          sysVarValueEl.placeholder = entry.isSecret ? 'Enter new secret value to rotate' : 'Enter updated value';
          sysVarValueEl.focus();
        }
        if (btnSaveSysVar) btnSaveSysVar.textContent = '💾 Update System Variable';
        showSysVarsStatus(`Editing {{VAR:${entry.name}}} — enter new value and click Update System Variable.`, false);
        return;
      }

      if (action === 'delete') {
        await deleteSystemVariable(name);
      }
    });
  }

  if (btnToggleModalSysVar && modalSysVarForm) {
    btnToggleModalSysVar.addEventListener('click', () => {
      const willShow = modalSysVarForm.classList.contains('hidden');
      modalSysVarForm.classList.toggle('hidden', !willShow);
      if (willShow) modalSysVarNameEl?.focus();
    });
  }

  if (btnModalSaveSysVar) {
    btnModalSaveSysVar.addEventListener('click', async () => {
      const name = modalSysVarNameEl?.value.trim() || '';
      const category = modalSysVarCatEl?.value || 'custom';
      const value = modalSysVarValEl?.value ?? '';
      const res = await saveSystemVariable({ name, category, value });
      if (res.ok) {
        if (modalSysVarNameEl) modalSysVarNameEl.value = '';
        if (modalSysVarValEl) modalSysVarValEl.value = '';
        if (modalSysVarForm) modalSysVarForm.classList.add('hidden');
        showLsrPlayOutput(`🌐 Saved system variable <code>{{VAR:${escapeHtml(res.variable.name)}}}</code> across all .lsr sequences.`, 'success');
      } else {
        modalSysVarNameEl?.focus();
      }
    });
  }

  function bindSystemVarToSelectedStep(varName) {
    if (!varName) return;
    const token = `{{VAR:${varName}}}`;
    const sysVar = state.systemVariables.find(v => v.name === varName);
    const idx = state.selectedLsrStepIndex;
    const action = state.loginSequence.actions[idx];
    if (!action) {
      showLsrPlayOutput(`Select a step in Recorded Login Actions first to bind <code>${escapeHtml(token)}</code>.`, 'info');
      return;
    }

    if (action.type === 'change_input') {
      action.secretName = '';
      action.value = token;
      action.isSecret = Boolean(sysVar?.isSecret || action.isSecret);
    } else if (action.type === 'navigate') {
      action.url = token;
    } else if (action.type === 'custom_request') {
      const curPayload = typeof action.payload === 'string' ? action.payload : (action.payload ? JSON.stringify(action.payload) : '');
      action.payload = curPayload ? `${curPayload}${token}` : token;
    } else if (action.type === 'fill_otp') {
      action.secretName = varName;
    }
    action.label = formatLsrStepLabel(action);
    renderLsrActionsList();
    renderLsrActionProperties();
  }

  if (modalSysVarsBar) {
    modalSysVarsBar.addEventListener('click', e => {
      const chip = e.target.closest('[data-lsr-bind-var]');
      if (!chip) return;
      bindSystemVarToSelectedStep(chip.getAttribute('data-lsr-bind-var') || '');
    });
  }

  // Diagnostics Banner Jump-to-Step Handler (Modal + Inline)
  function handleJumpToStepClick(e) {
    const jumpBtn = e.target.closest('[data-lsr-jump-step]');
    if (!jumpBtn) return;
    const stepIdx = parseInt(jumpBtn.getAttribute('data-lsr-jump-step'), 10);
    if (!Number.isInteger(stepIdx) || stepIdx < 0) return;
    if (backdrop && backdrop.classList.contains('hidden')) {
      openLsrModal(state.loginSequence);
    }
    switchLsrSubTab('actions');
    const maxIdx = Math.max(0, (state.loginSequence.actions?.length || 1) - 1);
    state.selectedLsrStepIndex = Math.min(stepIdx, maxIdx);
    renderLsrActionsList();
    renderLsrActionProperties();
    if (state.lastLsrPlayResult) {
      renderVisualPlaySnapshot(state.lastLsrPlayResult, stepIdx);
    }
  }
  if (topDiagnosticsEl) topDiagnosticsEl.addEventListener('click', handleJumpToStepClick);
  if (inlineDiagnosticsEl) inlineDiagnosticsEl.addEventListener('click', handleJumpToStepClick);

  // Reuse Saved Sequence Bar Handlers
  if (reuseSelectEl) {
    reuseSelectEl.addEventListener('change', () => {
      const seq = getSelectedReuseSequence();
      if (seq) activateSequenceForScan(seq);
    });
  }
  if (btnUseSelectedLsr) {
    btnUseSelectedLsr.addEventListener('click', () => {
      const seq = getSelectedReuseSequence() || state.savedSequences[0] || null;
      if (seq) activateSequenceForScan(seq);
    });
  }
  if (btnPlaySelectedLsr) {
    btnPlaySelectedLsr.addEventListener('click', async () => {
      const seq = getSelectedReuseSequence() || state.loginSequence;
      await executePlayLsrSequence({ seqOverride: seq, openModalOnPlay: false });
    });
  }
  if (btnDuplicateSelectedLsr) {
    btnDuplicateSelectedLsr.addEventListener('click', async () => {
      const seq = getSelectedReuseSequence() || state.loginSequence;
      await duplicateSequence(seq);
    });
  }
  if (btnDeleteSelectedLsr) {
    btnDeleteSelectedLsr.addEventListener('click', async () => {
      const seq = getSelectedReuseSequence() || state.loginSequence;
      await deleteLoginSequence(seq);
    });
  }
  if (btnDeleteSeqModal) {
    btnDeleteSeqModal.addEventListener('click', async () => {
      await deleteLoginSequence(state.loginSequence);
    });
  }
  if (btnRefreshLsrList) {
    btnRefreshLsrList.addEventListener('click', async () => {
      await Promise.all([loadSystemVariables(), loadSavedLoginSequences()]);
    });
  }

  if (tabActionsBtn) tabActionsBtn.addEventListener('click', () => switchLsrSubTab('actions'));
  if (tabRestrictionsBtn) tabRestrictionsBtn.addEventListener('click', () => switchLsrSubTab('restrictions'));
  if (tabSessionBtn) tabSessionBtn.addEventListener('click', () => switchLsrSubTab('session'));

  if (btnOpenNew) {
    btnOpenNew.addEventListener('click', () => {
      syncLsrConfigFromInputs();
      openLsrModal();
    });
  }
  if (btnNewBlank) {
    btnNewBlank.addEventListener('click', () => {
      openLsrModal(null, { isNewBlank: true });
      if (visualCanvas) {
        visualCanvas.innerHTML = '<div class="empty-muted">✨ Blank sequence ready. Enter a Login URL above and click <strong>→ Load Page Forms</strong>, or click <strong>⚡ Load Working Example</strong> to load a complete 5-step + 2FA demo sequence.</div>';
      }
      showLsrPlayOutput('✨ Created new blank login sequence.', 'info');
    });
  }

  async function loadWorkingExampleSequence({ openModal = true, autoPlay = true } = {}) {
    const demoOrigin = (typeof window !== 'undefined' && window.location?.origin && window.location.origin.startsWith('http'))
      ? window.location.origin
      : 'http://127.0.0.1:4321';
    const demoLoginUrl = `${demoOrigin}/api/auth/demo-login`;

    await saveSystemVariable({ name: 'demo_user', category: 'username', value: 'auditor@infsalesgroup.com' });
    await saveSystemVariable({ name: 'demo_pass', category: 'password', value: 'DemoEnterprisePass2026!' });

    const exampleSeq = normalizeClientLoginSequence({
      sequenceId: '',
      name: 'DemoEnterpriseMFA.lsr',
      targetUrl: demoLoginUrl,
      updatedAt: new Date().toISOString(),
      secrets: [],
      otpConfig: {
        enabled: true,
        secret: 'JBSWY3DPEHPK3PXP',
        digits: 6,
        period: 30,
        algorithm: 'SHA1',
        inputSelector: 'otp_code'
      },
      actions: [
        { type: 'navigate', url: demoLoginUrl },
        { type: 'change_input', selectorType: 'id', selector: 'email', fieldName: 'email', value: '{{VAR:demo_user}}', isSecret: false },
        { type: 'change_input', selectorType: 'id', selector: 'password', fieldName: 'password', value: '{{VAR:demo_pass}}', isSecret: true },
        { type: 'fill_otp', selectorType: 'id', selector: 'otp_code', fieldName: 'otp_code' },
        { type: 'click_button', selectorType: 'text', selector: 'Log In', submitUrl: demoLoginUrl, method: 'POST', contentType: 'form' }
      ],
      restrictions: ['/logout', '/signout', '/logoff'],
      sessionDetection: {
        statusCodes: [401, 403],
        redirectPattern: '/login',
        loggedOutPattern: '',
        loggedInPattern: ''
      }
    });

    state.lsrDraftDismissed = false;
    let savedExample = exampleSeq;
    try {
      const saveRes = await apiPost('/api/auth/sequences', {
        ...exampleSeq,
        allowPrivate: true,
        systemVariables: state.systemVariables
      });
      savedExample = normalizeClientLoginSequence({
        ...(saveRes?.sequence || exampleSeq),
        secrets: exampleSeq.secrets,
        otpConfig: exampleSeq.otpConfig
      });
    } catch {
      savedExample.sequenceId = savedExample.sequenceId || `local-${Date.now()}`;
    }
    const existingExIdx = state.savedSequences.findIndex(s =>
      (s.sequenceId && s.sequenceId === savedExample.sequenceId) ||
      s.name === savedExample.name
    );
    if (existingExIdx >= 0) {
      state.savedSequences[existingExIdx] = savedExample;
    } else {
      state.savedSequences.unshift(savedExample);
    }
    persistSequencesToLocal();

    if (openModal) {
      openLsrModal(savedExample);
    } else {
      state.loginSequence = savedExample;
      state.selectedLsrStepIndex = 0;
      applyLsrStateToInputs();
    }
    if (inspectUrlEl) inspectUrlEl.value = demoLoginUrl;
    renderSequenceBlueprintCanvas(savedExample);

    if (autoPlay) {
      await executePlayLsrSequence({ seqOverride: savedExample, openModalOnPlay: openModal });
    }
  }

  if (btnLoadExampleModal) {
    btnLoadExampleModal.addEventListener('click', () => loadWorkingExampleSequence({ openModal: true, autoPlay: true }));
  }
  if (btnLoadExampleInline) {
    btnLoadExampleInline.addEventListener('click', () => loadWorkingExampleSequence({ openModal: true, autoPlay: true }));
  }
  if (btnClose) btnClose.addEventListener('click', closeLsrModal);
  if (backdrop) {
    backdrop.addEventListener('click', e => {
      if (e.target === backdrop) closeLsrModal();
    });
  }
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && backdrop && !backdrop.classList.contains('hidden')) {
      closeLsrModal();
    }
  });

  // Secrets Vault handlers
  function handleAddSecret() {
    const name = secretNameEl?.value.trim() || '';
    const value = secretValueEl?.value ?? '';
    if (!name || LSR_FORBIDDEN_KEYS.has(name) || /[^a-zA-Z0-9_.-]/.test(name)) {
      if (secretNameEl) secretNameEl.focus();
      return;
    }
    const existingIdx = state.loginSequence.secrets.findIndex(s => s.name === name);
    const entry = { name, value, description: '' };
    if (existingIdx >= 0) {
      state.loginSequence.secrets[existingIdx] = entry;
    } else {
      state.loginSequence.secrets.push(entry);
    }
    if (secretNameEl) secretNameEl.value = '';
    if (secretValueEl) secretValueEl.value = '';
    renderLsrSecretsChips();
    renderLsrActionProperties();
    renderLsrSequenceCards();
    if (state.lastInspectedPage) renderInspectedPageCanvas(state.lastInspectedPage);
  }

  if (btnAddSecret) btnAddSecret.addEventListener('click', handleAddSecret);
  if (secretValueEl) {
    secretValueEl.addEventListener('keydown', e => {
      if (e.key === 'Enter') {
        e.preventDefault();
        handleAddSecret();
      }
    });
  }
  if (secretsChipsEl) {
    secretsChipsEl.addEventListener('click', e => {
      const removeBtn = e.target.closest('[data-remove-lsr-secret]');
      if (!removeBtn) return;
      const idx = parseInt(removeBtn.getAttribute('data-remove-lsr-secret'), 10);
      if (Number.isInteger(idx) && idx >= 0 && idx < state.loginSequence.secrets.length) {
        state.loginSequence.secrets.splice(idx, 1);
        renderLsrSecretsChips();
        renderLsrActionProperties();
        renderLsrSequenceCards();
        if (state.lastInspectedPage) renderInspectedPageCanvas(state.lastInspectedPage);
      }
    });
  }

  // OTP Configuration handlers
  if (btnOpenOtp && otpPanel) {
    btnOpenOtp.addEventListener('click', () => {
      const willShow = otpPanel.classList.contains('hidden');
      otpPanel.classList.toggle('hidden', !willShow);
      btnOpenOtp.setAttribute('aria-expanded', willShow ? 'true' : 'false');
    });
  }

  if (btnTestOtp) {
    btnTestOtp.addEventListener('click', async () => {
      syncLsrConfigFromInputs();
      const otp = state.loginSequence.otpConfig;
      if (!otp.secret) {
        if (otpStatusEl) {
          otpStatusEl.textContent = 'Enter a Base32 TOTP secret key first';
          otpStatusEl.className = 'lsr-otp-status-pill error';
        }
        return;
      }
      btnTestOtp.disabled = true;
      btnTestOtp.textContent = 'Verifying...';
      try {
        const res = await apiPost('/api/auth/otp-preview', {
          secret: otp.secret,
          digits: otp.digits,
          period: otp.period,
          algorithm: otp.algorithm,
          inputSelector: otp.inputSelector
        });
        state.loginSequence.otpConfig.enabled = true;
        if (otpStatusEl) {
          otpStatusEl.dataset.livePreview = '1';
          otpStatusEl.textContent = `✓ Code: ${res.code} (${res.digits || otp.digits}d · ${res.remainingSeconds ?? otp.period}s left)`;
          otpStatusEl.className = 'lsr-otp-status-pill valid';
        }
        renderLsrSequenceCards();
      } catch (err) {
        if (otpStatusEl) {
          otpStatusEl.textContent = `✕ ${err.message}`;
          otpStatusEl.className = 'lsr-otp-status-pill error';
        }
      } finally {
        btnTestOtp.disabled = false;
        btnTestOtp.textContent = 'Verify & Preview TOTP';
      }
    });
  }

  // Saved Sequences Card List (Use, Play, Edit, Duplicate, Export, Delete) + Import
  if (seqCardsList) {
    seqCardsList.addEventListener('click', async e => {
      const actionBtn = e.target.closest('[data-lsr-card-action]');
      if (!actionBtn) return;
      const action = actionBtn.getAttribute('data-lsr-card-action');
      const idx = parseInt(actionBtn.getAttribute('data-lsr-seq-idx'), 10);
      const list = getDisplayedSequenceCards();
      const targetSeq = list[idx];
      if (!targetSeq) return;

      if (action === 'use') {
        activateSequenceForScan(targetSeq);
        return;
      }

      if (action === 'play') {
        await executePlayLsrSequence({ seqOverride: targetSeq, openModalOnPlay: true });
        return;
      }

      if (action === 'edit') {
        openLsrModal(targetSeq);
        return;
      }

      if (action === 'duplicate') {
        await duplicateSequence(targetSeq);
        return;
      }

      if (action === 'export') {
        const exportObj = normalizeClientLoginSequence(targetSeq);
        const maskedExport = {
          ...exportObj,
          secrets: exportObj.secrets.map(s => ({ ...s, value: '[SECRET]' })),
          otpConfig: {
            ...exportObj.otpConfig,
            secret: exportObj.otpConfig.secret ? '[SECRET]' : ''
          },
          actions: exportObj.actions.map(a =>
            a.type === 'change_input' && a.isSecret && !a.secretName && !/^\{\{VAR:[^}]+\}\}$/i.test(String(a.value || ''))
              ? { ...a, value: '[SECRET]' }
              : a
          )
        };
        triggerFileDownload(JSON.stringify(maskedExport, null, 2), 'application/json', exportObj.name || 'WrapperSequence.lsr');
        return;
      }

      if (action === 'delete') {
        await deleteLoginSequence(targetSeq);
      }
    });
  }

  if (btnImport && importFileInput) {
    btnImport.addEventListener('click', () => importFileInput.click());
    importFileInput.addEventListener('change', async () => {
      const file = importFileInput.files?.[0];
      if (!file) return;
      try {
        const text = await file.text();
        const parsed = JSON.parse(text);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          throw new Error('Invalid .lsr JSON file');
        }
        const imported = normalizeClientLoginSequence({
          ...parsed,
          name: parsed.name || file.name || 'ImportedSequence.lsr'
        });
        openLsrModal(imported);
        showLsrPlayOutput(`📂 Imported <strong>${escapeHtml(imported.name)}</strong> (${escapeHtml(imported.actions.length)} step(s)).`, 'success');
      } catch (err) {
        showInlineBanner('url-validation-banner', `Failed to import .lsr sequence: ${err.message}`, true);
      } finally {
        importFileInput.value = '';
      }
    });
  }

  // Page Inspection (POST /api/auth/inspect-page)
  async function handleInspectPage({ autoRecordNav = false } = {}) {
    const rawUrl = inspectUrlEl?.value.trim()
      || document.getElementById('adv-auth-login-url')?.value.trim()
      || document.getElementById('target-url')?.value.trim()
      || '';
    if (!rawUrl) {
      if (inspectUrlEl) inspectUrlEl.focus();
      showLsrPlayOutput('Enter a login URL in the address bar above before inspecting.', 'error');
      return;
    }

    const normalizedUrl = normalizeTargetScheme(rawUrl);
    if (inspectUrlEl) inspectUrlEl.value = normalizedUrl;

    const allowPrivate = Boolean(document.getElementById('allow-private-toggle')?.checked);
    const sourceIp = document.getElementById('adv-source-ip')?.value.trim() || '';

    if (btnInspectGo) btnInspectGo.disabled = true;
    if (btnRecord) btnRecord.disabled = true;
    if (visualCanvas) {
      visualCanvas.innerHTML = '<div class="empty-muted">⏳ Inspecting target login page forms, inputs, and CSRF tokens...</div>';
    }

    try {
      const data = await apiPost('/api/auth/inspect-page', {
        url: normalizedUrl,
        targetUrl: normalizedUrl,
        allowPrivate,
        ...(sourceIp ? { sourceIp } : {})
      });
      const resolvedPageUrl = data.pageUrl || normalizedUrl;
      state.loginSequence.targetUrl = resolvedPageUrl;
      state.lastLsrPlayResult = null;
      renderLsrDiagnosticsBanner(null, { includeInline: false });
      renderInspectedPageCanvas(data);

      // Update stale placeholder navigate step or auto-record navigate step when requested
      const firstAction = state.loginSequence.actions[0];
      if (firstAction && firstAction.type === 'navigate' && /wrapper\.infsalesgroup\.com/i.test(firstAction.url || '')) {
        firstAction.url = resolvedPageUrl;
        firstAction.label = formatLsrStepLabel(firstAction);
        renderLsrActionsList();
        renderLsrActionProperties();
      } else if (autoRecordNav || state.loginSequence.actions.length === 0) {
        const alreadyHasNav = state.loginSequence.actions.some(a => a.type === 'navigate' && a.url === resolvedPageUrl);
        if (!alreadyHasNav) {
          appendLsrStep({ type: 'navigate', url: resolvedPageUrl });
        }
      }
    } catch (err) {
      if (visualCanvas) {
        visualCanvas.innerHTML = `<div class="feedback-banner error">Failed to inspect page: ${escapeHtml(err.message)}</div>`;
      }
    } finally {
      if (btnInspectGo) btnInspectGo.disabled = false;
      if (btnRecord) btnRecord.disabled = false;
    }
  }

  if (btnInspectGo) btnInspectGo.addEventListener('click', () => handleInspectPage({ autoRecordNav: false }));
  if (btnRecord) btnRecord.addEventListener('click', () => handleInspectPage({ autoRecordNav: true }));
  if (inspectUrlEl) {
    inspectUrlEl.addEventListener('keydown', e => {
      if (e.key === 'Enter') {
        e.preventDefault();
        handleInspectPage({ autoRecordNav: false });
      }
    });
  }

  // Recording actions & Visual Replay Timeline interactions in #lsr-visual-canvas
  if (visualCanvas) {
    visualCanvas.addEventListener('click', e => {
      const backBtn = e.target.closest('#btn-lsr-back-to-inspector');
      if (backBtn && state.lastInspectedPage) {
        renderInspectedPageCanvas(state.lastInspectedPage);
        return;
      }

      const previewStepBtn = e.target.closest('[data-lsr-preview-step]');
      if (previewStepBtn) {
        const previewIdx = parseInt(previewStepBtn.getAttribute('data-lsr-preview-step'), 10);
        if (Number.isInteger(previewIdx)) {
          if (previewIdx < (state.loginSequence.actions?.length || 0)) {
            state.selectedLsrStepIndex = previewIdx;
            renderLsrActionsList();
            renderLsrActionProperties();
          }
          if (state.lastLsrPlayResult) {
            renderVisualPlaySnapshot(state.lastLsrPlayResult, previewIdx);
          } else {
            renderSequenceBlueprintCanvas(state.loginSequence);
          }
        }
        return;
      }

      const navBtn = e.target.closest('#btn-lsr-record-nav-here');
      if (navBtn && state.lastInspectedPage) {
        appendLsrStep({ type: 'navigate', url: state.lastInspectedPage.pageUrl || inspectUrlEl?.value.trim() || '' });
        return;
      }

      const recInputBtn = e.target.closest('[data-lsr-record-input]');
      if (recInputBtn && state.lastInspectedPage) {
        const idx = parseInt(recInputBtn.getAttribute('data-lsr-record-input'), 10);
        const inp = state.lastInspectedPage.inputs?.[idx];
        if (!inp) return;
        const inspectedUrl = state.lastInspectedPage.pageUrl || inspectUrlEl?.value.trim() || '';
        if (inspectedUrl) {
          const hasNav = state.loginSequence.actions.some(a => a.type === 'navigate');
          if (!hasNav) {
            state.loginSequence.actions.unshift({
              type: 'navigate',
              url: inspectedUrl,
              step: 1,
              label: formatLsrStepLabel({ type: 'navigate', url: inspectedUrl })
            });
          } else if (/wrapper\.infsalesgroup\.com/i.test(state.loginSequence.actions[0]?.url || '')) {
            state.loginSequence.actions[0].url = inspectedUrl;
            state.loginSequence.actions[0].label = formatLsrStepLabel(state.loginSequence.actions[0]);
          }
          state.loginSequence.targetUrl = inspectedUrl;
        }
        if (inp.isOtpCandidate) {
          appendLsrStep({
            type: 'fill_otp',
            selectorType: inp.selectorType || 'id',
            selector: inp.selectorValue || inp.id || inp.name || 'auto',
            fieldName: inp.name || inp.id || ''
          });
          return;
        }
        const secretSel = visualCanvas.querySelector(`[data-lsr-input-secret="${idx}"]`);
        const valInput = visualCanvas.querySelector(`[data-lsr-input-val="${idx}"]`);
        const selectedRef = secretSel?.value.trim() || '';
        const literalVal = valInput?.value ?? '';

        let secretName = '';
        let value = literalVal;
        let isSecret = Boolean(inp.isPassword);

        if (selectedRef.startsWith('VAR:')) {
          const varName = selectedRef.slice(4);
          const sysVar = state.systemVariables.find(v => v.name === varName);
          value = `{{VAR:${varName}}}`;
          isSecret = Boolean(sysVar?.isSecret || inp.isPassword);
        } else if (selectedRef) {
          secretName = selectedRef.startsWith('SECRET:') ? selectedRef.slice(7) : selectedRef;
          value = `{{SECRET:${secretName}}}`;
          isSecret = true;
        }

        appendLsrStep({
          type: 'change_input',
          selectorType: inp.selectorType || 'id',
          selector: inp.selectorValue || inp.id || inp.name || '',
          fieldName: inp.name || inp.id || '',
          value,
          secretName,
          isSecret
        });
        return;
      }

      const recBtnEl = e.target.closest('[data-lsr-record-button]');
      if (recBtnEl && state.lastInspectedPage) {
        const idx = parseInt(recBtnEl.getAttribute('data-lsr-record-button'), 10);
        const btn = state.lastInspectedPage.buttons?.[idx];
        if (!btn) return;
        const form = (state.lastInspectedPage.forms || []).find(f => f.formIndex === btn.formIndex) || state.lastInspectedPage.forms?.[0] || null;
        appendLsrStep({
          type: 'click_button',
          selectorType: btn.selectorType || 'text',
          selector: btn.selectorValue || btn.text || btn.id || btn.name || 'Submit',
          submitUrl: form?.actionUrl || '',
          method: form?.method || 'POST',
          contentType: form?.enctype?.includes('json') ? 'json' : (form ? 'form' : '')
        });
      }
    });
  }

  // Quick add & OTP step buttons
  document.querySelectorAll('[data-lsr-quick-add]').forEach(btn => {
    btn.addEventListener('click', () => {
      const type = btn.getAttribute('data-lsr-quick-add');
      appendLsrStep(createDefaultStepForType(type));
    });
  });

  if (btnAddOtpStep) {
    btnAddOtpStep.addEventListener('click', () => {
      appendLsrStep(createDefaultStepForType('fill_otp'));
    });
  }

  function deleteStepAtIndex(targetIdx) {
    const actions = state.loginSequence.actions;
    if (!Array.isArray(actions) || actions.length === 0) return;
    const idx = (Number.isInteger(targetIdx) && targetIdx >= 0 && targetIdx < actions.length)
      ? targetIdx
      : (state.selectedLsrStepIndex >= 0 && state.selectedLsrStepIndex < actions.length
          ? state.selectedLsrStepIndex
          : actions.length - 1);
    const [removed] = actions.splice(idx, 1);
    actions.forEach((act, i) => {
      act.step = i + 1;
      act.label = formatLsrStepLabel(act);
    });
    state.selectedLsrStepIndex = actions.length > 0 ? Math.min(idx, actions.length - 1) : -1;
    state.loginSequence.updatedAt = new Date().toISOString();
    renderLsrActionsList();
    renderLsrActionProperties();
    renderLsrSequenceCards();
    if (actions.length > 0 && !state.lastLsrPlayResult && !state.lastInspectedPage) {
      renderSequenceBlueprintCanvas(state.loginSequence);
    }
    if (removed) {
      showLsrPlayOutput(`🗑️ Removed Step ${escapeHtml(idx + 1)}: <strong>${escapeHtml(removed.label || removed.type)}</strong>.`, 'info');
    }
  }

  // Step selection & reordering
  if (actionsListEl) {
    actionsListEl.addEventListener('click', e => {
      const delStepBtn = e.target.closest('[data-lsr-delete-step]');
      if (delStepBtn) {
        e.stopPropagation();
        const delIdx = parseInt(delStepBtn.getAttribute('data-lsr-delete-step'), 10);
        if (Number.isInteger(delIdx)) {
          deleteStepAtIndex(delIdx);
        }
        return;
      }
      const item = e.target.closest('[data-lsr-step-idx]');
      if (!item) return;
      const idx = parseInt(item.getAttribute('data-lsr-step-idx'), 10);
      if (Number.isInteger(idx)) {
        state.selectedLsrStepIndex = idx;
        renderLsrActionsList();
        renderLsrActionProperties();
        if (state.lastLsrPlayResult) {
          renderVisualPlaySnapshot(state.lastLsrPlayResult, idx);
        } else {
          renderSequenceBlueprintCanvas(state.loginSequence);
        }
      }
    });
  }

  if (btnStepAdd) {
    btnStepAdd.addEventListener('click', () => {
      const nextType = state.loginSequence.actions.length === 0 ? 'navigate' : 'change_input';
      appendLsrStep(createDefaultStepForType(nextType));
    });
  }

  if (btnStepUp) {
    btnStepUp.addEventListener('click', () => {
      const idx = state.selectedLsrStepIndex;
      const actions = state.loginSequence.actions;
      if (idx <= 0 || idx >= actions.length) return;
      const [moved] = actions.splice(idx, 1);
      actions.splice(idx - 1, 0, moved);
      actions.forEach((act, i) => { act.step = i + 1; });
      state.selectedLsrStepIndex = idx - 1;
      renderLsrActionsList();
      renderLsrActionProperties();
    });
  }

  if (btnStepDown) {
    btnStepDown.addEventListener('click', () => {
      const idx = state.selectedLsrStepIndex;
      const actions = state.loginSequence.actions;
      if (idx < 0 || idx >= actions.length - 1) return;
      const [moved] = actions.splice(idx, 1);
      actions.splice(idx + 1, 0, moved);
      actions.forEach((act, i) => { act.step = i + 1; });
      state.selectedLsrStepIndex = idx + 1;
      renderLsrActionsList();
      renderLsrActionProperties();
    });
  }

  if (btnStepDelete) {
    btnStepDelete.addEventListener('click', () => {
      deleteStepAtIndex(state.selectedLsrStepIndex);
    });
  }

  // Action Properties live editor
  if (actionPropsEl) {
    actionPropsEl.addEventListener('click', e => {
      const insertVarBtn = e.target.closest('[data-lsr-insert-var]');
      if (!insertVarBtn) return;
      const varName = insertVarBtn.getAttribute('data-lsr-insert-var') || '';
      if (varName) bindSystemVarToSelectedStep(varName);
    });

    const updateSelectedFromProps = e => {
      const idx = state.selectedLsrStepIndex;
      const action = state.loginSequence.actions[idx];
      if (!action) return;

      const recIdEl = document.getElementById('adv-recorded-session-id');
      if (recIdEl) recIdEl.value = '';

      if (e.target.id === 'lsr-prop-type') {
        const next = createDefaultStepForType(e.target.value);
        state.loginSequence.actions[idx] = { ...next, step: idx + 1 };
        renderLsrActionsList();
        renderLsrActionProperties();
        return;
      }

      if (action.type === 'navigate') {
        const urlEl = document.getElementById('lsr-prop-url');
        if (urlEl) action.url = urlEl.value.trim();
      } else if (action.type === 'change_input') {
        const selTypeEl = document.getElementById('lsr-prop-selector-type');
        const selEl = document.getElementById('lsr-prop-selector');
        const secEl = document.getElementById('lsr-prop-secret-name');
        const valEl = document.getElementById('lsr-prop-value');
        const maskEl = document.getElementById('lsr-prop-is-secret');
        if (selTypeEl) action.selectorType = selTypeEl.value;
        if (selEl && (e.target === selEl || e.target === selTypeEl)) {
          action.selector = selEl.value.trim();
          const cleanSel = action.selector.replace(/^#/, '');
          const matchedInspectedInput = (state.lastInspectedPage?.inputs || []).find(
            inp => inp.id === cleanSel || inp.name === cleanSel || inp.selectorValue === action.selector
          );
          action.fieldName = matchedInspectedInput?.name || cleanSel;
        } else if (selEl && !action.selector) {
          action.selector = selEl.value.trim();
        }
        if (secEl && e.target === secEl) {
          const refVal = secEl.value.trim();
          if (refVal.startsWith('VAR:')) {
            const varName = refVal.slice(4);
            const sysVar = state.systemVariables.find(v => v.name === varName);
            action.secretName = '';
            action.value = `{{VAR:${varName}}}`;
            action.isSecret = Boolean(sysVar?.isSecret);
          } else if (refVal) {
            const secName = refVal.startsWith('SECRET:') ? refVal.slice(7) : refVal;
            action.secretName = secName;
            action.value = `{{SECRET:${secName}}}`;
            action.isSecret = true;
          } else {
            action.secretName = '';
          }
          if (valEl) {
            valEl.value = action.value;
            valEl.type = action.isSecret ? 'password' : 'text';
          }
          if (maskEl) maskEl.checked = Boolean(action.isSecret);
        }
        if (valEl && e.target === valEl) {
          action.value = valEl.value;
          delete valEl.dataset.preserveMasked;
        }
        if (maskEl && e.target === maskEl) {
          action.isSecret = maskEl.checked;
          if (valEl) valEl.type = action.isSecret ? 'password' : 'text';
        }
      } else if (action.type === 'fill_otp') {
        const selTypeEl = document.getElementById('lsr-prop-selector-type');
        const selEl = document.getElementById('lsr-prop-selector');
        if (selTypeEl) action.selectorType = selTypeEl.value;
        if (selEl) {
          action.selector = selEl.value.trim() || 'auto';
          action.fieldName = action.selector === 'auto' ? '' : action.selector.replace(/^#/, '');
        }
      } else if (action.type === 'click_button') {
        const selTypeEl = document.getElementById('lsr-prop-selector-type');
        const selEl = document.getElementById('lsr-prop-selector');
        const subUrlEl = document.getElementById('lsr-prop-submit-url');
        const ctEl = document.getElementById('lsr-prop-content-type');
        if (selTypeEl) action.selectorType = selTypeEl.value;
        if (selEl) action.selector = selEl.value.trim();
        if (subUrlEl) action.submitUrl = subUrlEl.value.trim();
        if (ctEl) action.contentType = ctEl.value;
      } else if (action.type === 'extract_token') {
        const srcEl = document.getElementById('lsr-prop-token-source');
        const keyEl = document.getElementById('lsr-prop-token-key');
        if (srcEl) action.source = srcEl.value;
        if (keyEl) {
          action.key = keyEl.value.trim();
          action.tokenJsonPath = action.source === 'json' ? action.key : '';
        }
      } else if (action.type === 'custom_request') {
        const mEl = document.getElementById('lsr-prop-method');
        const ctEl = document.getElementById('lsr-prop-content-type');
        const uEl = document.getElementById('lsr-prop-url');
        const pEl = document.getElementById('lsr-prop-payload');
        if (mEl) action.method = mEl.value;
        if (ctEl) action.contentType = ctEl.value;
        if (uEl) action.url = uEl.value.trim();
        if (pEl) action.payload = pEl.value;
      }

      action.label = formatLsrStepLabel(action);
      state.loginSequence.updatedAt = new Date().toISOString();
      if (state.lastLsrPlayResult && !state.lastLsrPlayResult.authenticated) {
        state.lastLsrPlayResult = null;
        renderLsrDiagnosticsBanner(null, { includeInline: false });
      }
      renderLsrActionsList();
      if (!state.lastLsrPlayResult && !state.lastInspectedPage) {
        renderSequenceBlueprintCanvas(state.loginSequence);
      } else if (state.lastLsrPlayResult) {
        renderVisualPlaySnapshot(state.lastLsrPlayResult, idx);
      }
    };

    actionPropsEl.addEventListener('input', updateSelectedFromProps);
    actionPropsEl.addEventListener('change', updateSelectedFromProps);
  }

  // Restrictions handlers
  function handleAddRestriction() {
    const val = restrictionInput?.value.trim() || '';
    if (!val) return;
    if (!state.loginSequence.restrictions.includes(val)) {
      state.loginSequence.restrictions.push(val);
    }
    if (restrictionInput) restrictionInput.value = '';
    renderLsrRestrictionsList();
  }
  if (btnAddRestriction) btnAddRestriction.addEventListener('click', handleAddRestriction);
  if (restrictionsListEl) {
    restrictionsListEl.addEventListener('click', e => {
      const btn = e.target.closest('[data-remove-lsr-restriction]');
      if (!btn) return;
      const idx = parseInt(btn.getAttribute('data-remove-lsr-restriction'), 10);
      if (Number.isInteger(idx) && idx >= 0 && idx < state.loginSequence.restrictions.length) {
        state.loginSequence.restrictions.splice(idx, 1);
        renderLsrRestrictionsList();
      }
    });
  }

  // Save Sequence (POST/PUT /api/auth/sequences + localStorage persistence)
  if (btnSave) {
    btnSave.addEventListener('click', async () => {
      const payload = buildLoginSequencePayload({ includeSecrets: true });
      const allowPrivate = Boolean(document.getElementById('allow-private-toggle')?.checked);
      const requestBody = {
        ...payload,
        allowPrivate,
        systemVariables: state.systemVariables
      };
      btnSave.disabled = true;
      btnSave.textContent = 'Saving...';
      try {
        let res = null;
        if (payload.sequenceId && !payload.sequenceId.startsWith('local-')) {
          try {
            const putResp = await fetch(`/api/auth/sequences/${encodeURIComponent(payload.sequenceId)}`, {
              method: 'PUT',
              headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
              body: JSON.stringify(requestBody)
            });
            if (putResp.ok) {
              res = await putResp.json();
            }
          } catch {
            res = null;
          }
        }
        if (!res) {
          res = await apiPost('/api/auth/sequences', requestBody);
        }
        const saved = normalizeClientLoginSequence({
          ...(res?.sequence || payload),
          secrets: payload.secrets,
          otpConfig: payload.otpConfig
        });
        state.lsrDraftDismissed = false;
        state.loginSequence = saved;
        const idx = state.savedSequences.findIndex(s =>
          (s.sequenceId && s.sequenceId === saved.sequenceId) ||
          (!s.sequenceId && s.name === saved.name)
        );
        if (idx >= 0) {
          state.savedSequences[idx] = saved;
        } else {
          state.savedSequences.unshift(saved);
        }
        persistSequencesToLocal();
        applyLsrStateToInputs();
        const recIdEl = document.getElementById('adv-recorded-session-id');
        if (recIdEl) recIdEl.value = '';
        if (!state.lastLsrPlayResult) {
          renderSequenceBlueprintCanvas(saved);
        }
        if (topDiagnosticsEl) {
          topDiagnosticsEl.className = 'lsr-top-diagnostics-banner success';
          topDiagnosticsEl.innerHTML = `<div class="lsr-diag-banner-header">💾 Saved sequence <strong>${escapeHtml(saved.name)}</strong> (${escapeHtml(saved.actions.length)} step(s)) — Ready to Play or Reuse in Scan.</div>`;
          topDiagnosticsEl.classList.remove('hidden');
        }
        showLsrPlayOutput(`💾 Saved sequence <strong>${escapeHtml(saved.name)}</strong> (${escapeHtml(saved.actions.length)} step(s)).`, 'success');
      } catch (err) {
        if (topDiagnosticsEl) {
          topDiagnosticsEl.className = 'lsr-top-diagnostics-banner error';
          topDiagnosticsEl.innerHTML = `<div class="lsr-diag-banner-header">❌ Could not save sequence: ${escapeHtml(err.message)}</div>`;
          topDiagnosticsEl.classList.remove('hidden');
        }
        showLsrPlayOutput(`✕ Save failed: ${escapeHtml(err.message)}`, 'error');
      } finally {
        btnSave.disabled = false;
        btnSave.textContent = '💾 Save';
      }
    });
  }

  // Play / Test Sequence (POST /api/auth/record-session)
  if (btnPlay) {
    btnPlay.addEventListener('click', () => executePlayLsrSequence({ openModalOnPlay: false }));
  }

  applyLsrStateToInputs();
}
