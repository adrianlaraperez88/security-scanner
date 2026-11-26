import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { URL, fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import pLimit from 'p-limit';

import { getScanners } from './registry.js';
import { PRESETS, getCheckInfo, getCheckMeta, scaffoldCheck } from './catalog.js';
import { PROFILES, DEVICE_PROFILE_ALIASES, getProfileChecks, selectScannersForStack, ACTIVE_FUZZING_CHECKS } from './profiles.js';
import { validateTargets, resolveAndValidateTarget, normalizeTargetInput, resolveBareIpTargets } from './validator.js';
import { listHistory, loadHistoryById, diffScans, saveHistory } from './history.js';
import { generateHtmlReport, groupFindings, sanitizeApiCommunication } from './html-report.js';
import { saveAutoReports, generateReport, generateMarkdownReport, generateCsvReport, generateSarifReport, summarizeCveAudit, mergeApiCommunication } from './report.js';
import { auditCveCoverage, confirmCveDatabaseCoverage, CVE_DB_PROVIDERS } from './cve-audit.js';
import { CveCatalogError } from './cve-catalog.js';
import {
  DEFAULT_LABS_DIR,
  listCveLabs,
  buildMarketComparisonMatrix,
  runCveLabBenchmark,
  scaffoldCveLab,
  CveLabError
} from './cve-lab-runner.js';
import { runLocalPcAudit } from './pc-local-auditor.js';
import { runDeclarativeTemplate, TemplateValidationError } from './template-loader.js';
import { AiAdvisorService } from './ai-advisor.js';
import { runSystemDoctor, diagnoseTarget } from './system-doctor.js';
import { validateCustomHeadersResult } from './headers.js';
import { normalizeScopeRules } from '../scan.js';
import { calculateRisk } from './severity.js';
import { fingerprint } from './fingerprint.js';
import { runTargetCrawlPipeline } from './crawler.js';
import { fetchWithRetry as baseFetch, createGovernedFetch } from './fetch.js';
import { GraphStore } from './graph-store.js';
import { TrafficStore, analyzePassiveExchange } from './traffic.js';
import { EvidenceStore } from './evidence.js';
import { runIntruderCampaign, runAutorizeMatrix } from './intruder.js';
import { runDecoderPipeline, smartInspectValue, inspectJwtToken, compareResponses } from './decoder-comparer.js';
import { LlmPool } from './llmpool.js';
import { LlmRecorder } from './llmrec.js';
import { SideQuestionService } from './sidequestion.js';
import { NoiseGovernor, NOISE_PROFILES } from './egress.js';
import { SkillRegistry } from './skills.js';
import { AgentEngine } from './agent-engine.js';
import { foldColdGraph } from './coldgraph.js';
import { FIELD_SPECS, AssetDslError } from './asset-dsl.js';
import { EnrichEngine, ingestScanOutput, buildFindingAssetTree } from './enrich.js';
import { createTrackedFetch } from './reproduction.js';
import { evaluateAssetGate, evaluateInterceptRules, scoreRisk, decideClosed, TargetPinStore } from './guard.js';
import { reviewReportSubmission, STRICT_VDP_RULES } from './submission-review.js';
import { runLlmPostureCheck, POSTURE_PROBES } from './posture-check.js';
import { buildComplianceSummary } from './compliance-proof.js';
import { parseOpenApiSpec, discoverAndImportOpenApi } from './openapi-importer.js';
import {
  AuthSessionManager,
  MAX_SYSTEM_VARIABLES,
  extractCsrfTokens,
  generateTotpCode,
  inspectLoginPageDom,
  normalizeLoginSequence,
  parseLsrSequence,
  exportLsrSequence,
  normalizeSystemVariables,
  exportSystemVariables
} from './auth-session.js';
import {
  detectRuntimeScaFindings,
  extractRuntimeScaFromResponse,
  sanitizeRuntimeSca,
  mergeRuntimeSca
} from './runtime-sca.js';
import { auditMenuAndFormAccessControl } from './rbac-matrix.js';
import { buildSbomAndCveDriftReport } from './sbom-monitor.js';
import { discoverWebsiteRealIp } from './real-ip-finder.js';
import { DEVICE_CATEGORIES, DEVICE_CATEGORY_ALIASES, normalizeDeviceCategory } from './device-scanner.js';
import {
  computeNextScheduleRunAt,
  mergeDeltaScanSummary,
  normalizeTargetSystem,
  cloneTargetSystemConfig,
  resolveChecksForTargetSystemRun,
  exportTargetSystem
} from './target-systems.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const UI_DIR = path.resolve(__dirname, '../ui');
const UI_COMPONENTS_DIR = path.resolve(UI_DIR, 'components');
const PKG_VERSION = (() => {
  try {
    const pkgPath = path.resolve(__dirname, '../package.json');
    return JSON.parse(fs.readFileSync(pkgPath, 'utf8')).version || '2.2.0';
  } catch {
    return '2.2.0';
  }
})();

const JEV_KEY_ALIASES = {
  q2_authorized: 'q2_no_destructive_side_effects',
  q3_non_destructive: 'q3_reversible',
  q4_rate_bounded: 'q4_within_rate_budget',
  q5_no_exfiltration: 'q5_no_credential_exfil',
  q6_evidence_only: 'q6_no_cross_tenant_impact',
  q7_rollback_safe: 'q7_valid_verification_intent'
};

function normalizeJevAnswers(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return raw;
  const normalized = { ...raw };
  for (const [alias, canonical] of Object.entries(JEV_KEY_ALIASES)) {
    if (!(canonical in normalized) && alias in normalized) {
      normalized[canonical] = normalized[alias];
    }
  }
  return normalized;
}

const MAX_RECORDED_SESSIONS = 50;
const MAX_SAVED_SEQUENCES = 50;
const MAX_TARGET_SYSTEMS = 200;
export const MAX_SCAN_TARGETS = 200;

/**
 * Stores a Target System in the registry map while capping size at 200 (evicting oldest).
 */
function storeTargetSystem(targetSystemsMap, sys) {
  if (!targetSystemsMap || typeof targetSystemsMap.set !== 'function' || !sys || !sys.id) {
    return;
  }
  if (targetSystemsMap.has(sys.id)) {
    targetSystemsMap.delete(sys.id);
  }
  targetSystemsMap.set(sys.id, sys);
  while (targetSystemsMap.size > MAX_TARGET_SYSTEMS) {
    const oldestKey = targetSystemsMap.keys().next().value;
    if (oldestKey === undefined) break;
    targetSystemsMap.delete(oldestKey);
  }
}

/**
 * Stores a recorded session in the registry map while capping size at 50 (evicting oldest).
 */
function storeRecordedSession(sessionMap, session) {
  if (!sessionMap || typeof sessionMap.set !== 'function' || !session || !session.sessionId) {
    return;
  }
  if (sessionMap.has(session.sessionId)) {
    sessionMap.delete(session.sessionId);
  }
  sessionMap.set(session.sessionId, session);
  while (sessionMap.size > MAX_RECORDED_SESSIONS) {
    const oldestKey = sessionMap.keys().next().value;
    if (oldestKey === undefined) break;
    sessionMap.delete(oldestKey);
  }
}

/**
 * Stores a saved login sequence in the registry map while capping size at 50 (evicting oldest).
 */
function storeSavedSequence(sequenceMap, seq) {
  if (!sequenceMap || typeof sequenceMap.set !== 'function' || !seq || !seq.sequenceId) {
    return;
  }
  const normName = String(seq.name || '').trim().toLowerCase();
  const normTarget = String(seq.targetUrl || '').trim().toLowerCase();
  if (normName) {
    for (const [existingId, existingSeq] of sequenceMap.entries()) {
      if (existingId === seq.sequenceId) continue;
      const exName = String(existingSeq?.name || '').trim().toLowerCase();
      const exTarget = String(existingSeq?.targetUrl || '').trim().toLowerCase();
      if (exName === normName && exTarget === normTarget) {
        mergeSavedSequenceSecrets(seq, existingSeq);
        sequenceMap.delete(existingId);
      }
    }
  }
  if (sequenceMap.has(seq.sequenceId)) {
    sequenceMap.delete(seq.sequenceId);
  }
  sequenceMap.set(seq.sequenceId, seq);
  while (sequenceMap.size > MAX_SAVED_SEQUENCES) {
    const oldestKey = sequenceMap.keys().next().value;
    if (oldestKey === undefined) break;
    sequenceMap.delete(oldestKey);
  }
}

/**
 * Stores normalized system variables in the registry map while preserving existing unmasked
 * secret values and enforcing `MAX_SYSTEM_VARIABLES` (100) LRU cap.
 */
function storeSystemVariables(systemVarsMap, incomingVars, { replaceAll = false } = {}) {
  if (!systemVarsMap || typeof systemVarsMap.set !== 'function') {
    return [];
  }
  const prevMap = new Map(systemVarsMap);
  if (replaceAll) {
    systemVarsMap.clear();
  }
  const normalized = normalizeSystemVariables(incomingVars);
  for (const item of normalized) {
    const prev = prevMap.get(item.name);
    let nextVal = item.value;
    let nextCategory = item.category;
    let nextDescription = item.description;
    if (prev) {
      const prevHasRealValue = Boolean(
        prev.value && prev.value !== '[SECRET]' && prev.value !== '[REDACTED]'
      );
      if (
        prevHasRealValue &&
        (nextVal === '[SECRET]' ||
          nextVal === '[REDACTED]' ||
          (nextVal === '' && (item.isSecret || prev.isSecret) && item.keepExistingSecret !== false))
      ) {
        nextVal = prev.value;
      }
      if (!nextDescription && prev.description) {
        nextDescription = prev.description;
      }
      if (nextCategory === 'custom' && prev.category && prev.category !== 'custom') {
        nextCategory = prev.category;
      }
    }
    const mergedItem = {
      ...item,
      value: nextVal,
      category: nextCategory,
      description: nextDescription
    };
    if (systemVarsMap.has(mergedItem.name)) {
      systemVarsMap.delete(mergedItem.name);
    }
    systemVarsMap.set(mergedItem.name, mergedItem);
    while (systemVarsMap.size > MAX_SYSTEM_VARIABLES) {
      const oldestKey = systemVarsMap.keys().next().value;
      if (oldestKey === undefined) break;
      systemVarsMap.delete(oldestKey);
    }
  }
  return Array.from(systemVarsMap.values());
}

function writeJsonFileSecure(filePath, data) {
  try {
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
    const payload = JSON.stringify(data, null, 2);
    const tmpPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
    try {
      fs.writeFileSync(tmpPath, payload, { encoding: 'utf8', mode: 0o600 });
      fs.renameSync(tmpPath, filePath);
    } catch {
      try {
        if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath);
      } catch {}
      fs.writeFileSync(filePath, payload, { encoding: 'utf8', mode: 0o600 });
    }
  } catch {
    // Non-fatal persistence error
  }
}

function loadPersistedSequences(historyDir, sequenceMap = null) {
  try {
    const filePath = path.join(historyDir, 'auth-sequences.json');
    if (!fs.existsSync(filePath)) return [];
    const raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    const list = Array.isArray(raw)
      ? raw
      : (raw && Array.isArray(raw.sequences) ? raw.sequences : []);
    const loaded = [];
    for (const item of list) {
      if (!item || typeof item !== 'object') continue;
      const norm = normalizeLoginSequence(item);
      loaded.push(norm);
      if (sequenceMap) {
        storeSavedSequence(sequenceMap, norm);
      }
    }
    return loaded;
  } catch {
    return [];
  }
}

function savePersistedSequences(historyDir, sequenceMap) {
  if (!historyDir || !sequenceMap) return;
  const filePath = path.join(historyDir, 'auth-sequences.json');
  const list = Array.from(sequenceMap.values()).map(s =>
    exportLsrSequence(s, { includeSecrets: true })
  );
  writeJsonFileSecure(filePath, list);
}

function loadPersistedSystemVariables(historyDir, systemVarsMap = null) {
  try {
    const filePath = path.join(historyDir, 'system-variables.json');
    if (!fs.existsSync(filePath)) return [];
    const raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    const list = Array.isArray(raw)
      ? raw
      : (raw && Array.isArray(raw.variables) ? raw.variables : raw);
    const normalized = normalizeSystemVariables(list);
    if (systemVarsMap) {
      storeSystemVariables(systemVarsMap, normalized);
    }
    return normalized;
  } catch {
    return [];
  }
}

function savePersistedSystemVariables(historyDir, systemVarsMap) {
  if (!historyDir || !systemVarsMap) return;
  const filePath = path.join(historyDir, 'system-variables.json');
  const list = exportSystemVariables(Array.from(systemVarsMap.values()), { includeSecrets: true });
  writeJsonFileSecure(filePath, list);
}

function loadPersistedTargetSystems(historyDir, targetSystemsMap = null) {
  try {
    const filePath = path.join(historyDir, 'target-systems.json');
    if (!fs.existsSync(filePath)) return [];
    const raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    const list = Array.isArray(raw)
      ? raw
      : (raw && Array.isArray(raw.systems) ? raw.systems : []);
    const loaded = [];
    for (const item of list) {
      if (!item || typeof item !== 'object') continue;
      try {
        const norm = normalizeTargetSystem(item);
        loaded.push(norm);
        if (targetSystemsMap) {
          storeTargetSystem(targetSystemsMap, norm);
        }
      } catch {}
    }
    return loaded;
  } catch {
    return [];
  }
}

function savePersistedTargetSystems(historyDir, targetSystemsMap) {
  if (!historyDir || !targetSystemsMap) return;
  const filePath = path.join(historyDir, 'target-systems.json');
  const list = Array.from(targetSystemsMap.values()).map(s =>
    exportTargetSystem(s, { includeSecrets: true })
  );
  writeJsonFileSecure(filePath, list);
}

/**
 * Preserves existing unmasked secrets from a previously saved login sequence
 * when an updated sequence contains redaction placeholders ('[SECRET]' or '[REDACTED]').
 */
function mergeSavedSequenceSecrets(seq, savedSeq) {
  if (!seq || !savedSeq || typeof savedSeq !== 'object') return seq;

  if (
    seq.otpConfig &&
    (seq.otpConfig.secret === '[REDACTED]' ||
      (!seq.otpConfig.secret && !seq.otpConfig.secretName && !seq.otpConfig.variableName)) &&
    savedSeq.otpConfig?.secret &&
    savedSeq.otpConfig.secret !== '[REDACTED]'
  ) {
    seq.otpConfig.secret = savedSeq.otpConfig.secret;
    if (savedSeq.otpConfig.enabled !== undefined && seq.otpConfig.enabled === false) {
      seq.otpConfig.enabled = Boolean(savedSeq.otpConfig.enabled);
    }
  }

  if (Array.isArray(savedSeq.secrets) && savedSeq.secrets.length > 0) {
    const prevSecretMap = new Map();
    for (const s of savedSeq.secrets) {
      if (s && typeof s.name === 'string' && s.value && s.value !== '[SECRET]' && s.value !== '[REDACTED]') {
        prevSecretMap.set(s.name, s);
      }
    }
    if (Array.isArray(seq.secrets) && seq.secrets.length > 0) {
      for (const s of seq.secrets) {
        if (s && (s.value === '[SECRET]' || s.value === '[REDACTED]') && prevSecretMap.has(s.name)) {
          s.value = prevSecretMap.get(s.name).value;
        }
      }
    } else if (prevSecretMap.size > 0) {
      seq.secrets = Array.from(prevSecretMap.values()).map(s => ({ ...s }));
    }
  }

  if (Array.isArray(seq.actions) && Array.isArray(savedSeq.actions)) {
    for (let i = 0; i < seq.actions.length; i++) {
      const act = seq.actions[i];
      if (!act || act.type !== 'change_input' || (act.value !== '[REDACTED]' && act.value !== '[SECRET]')) continue;
      const prevAct = savedSeq.actions.find(a => a && a.id === act.id) || savedSeq.actions[i];
      if (
        prevAct &&
        prevAct.type === 'change_input' &&
        prevAct.value &&
        prevAct.value !== '[REDACTED]' &&
        prevAct.value !== '[SECRET]'
      ) {
        act.value = prevAct.value;
      }
    }
  }

  return seq;
}

function buildVariableLookupMap({ systemVariables = null, secrets = null } = {}) {
  const map = new Map();
  if (systemVariables) {
    for (const v of normalizeSystemVariables(systemVariables)) {
      if (v.name && v.value && v.value !== '[SECRET]' && v.value !== '[REDACTED]') {
        map.set(v.name, v.value);
      }
    }
  }
  if (Array.isArray(secrets)) {
    for (const s of secrets) {
      if (s && typeof s.name === 'string' && s.name.trim() && s.value && s.value !== '[SECRET]' && s.value !== '[REDACTED]') {
        map.set(s.name.trim(), String(s.value));
      }
    }
  } else if (secrets instanceof Map) {
    for (const [k, v] of secrets.entries()) {
      if (typeof k === 'string' && k.trim() && v && v !== '[SECRET]' && v !== '[REDACTED]') {
        map.set(k.trim(), String(v));
      }
    }
  } else if (secrets && typeof secrets === 'object') {
    for (const [k, v] of Object.entries(secrets)) {
      if (k && v && v !== '[SECRET]' && v !== '[REDACTED]') {
        map.set(k.trim(), String(v));
      }
    }
  }
  return map;
}

function resolveUrlPlaceholders(rawUrl, { systemVariables = null, secrets = null } = {}) {
  const str = typeof rawUrl === 'string' ? rawUrl.trim() : '';
  if (!str || !/\{\{(?:VAR|SECRET):[^}]{1,128}\}\}/i.test(str)) {
    return { resolvedUrl: str, hadPlaceholder: false, unresolved: [] };
  }
  const lookup = buildVariableLookupMap({ systemVariables, secrets });
  const unresolved = [];
  const resolvedUrl = str.replace(/\{\{(?:VAR|SECRET):([^}]{1,128})\}\}/gi, (match, rawName) => {
    const key = String(rawName || '').trim();
    if (key && lookup.has(key)) {
      return lookup.get(key);
    }
    unresolved.push(key || match);
    return match;
  }).trim();
  return { resolvedUrl, hadPlaceholder: true, unresolved };
}

/**
 * Validates and normalizes an optional deviceCategory input (returns 400-ready error on invalid strings).
 */
function parseValidatedDeviceCategory(rawCategory) {
  if (rawCategory === undefined || rawCategory === null || rawCategory === '') {
    return { valid: true, category: 'all' };
  }
  if (typeof rawCategory !== 'string') {
    return { valid: false, error: 'Invalid deviceCategory: must be a string' };
  }
  const trimmed = rawCategory.trim().toLowerCase();
  if (!trimmed) {
    return { valid: true, category: 'all' };
  }
  const underscored = trimmed.replace(/-/g, '_');
  if (!Object.hasOwn(DEVICE_CATEGORY_ALIASES, trimmed) && !Object.hasOwn(DEVICE_CATEGORIES, underscored)) {
    return {
      valid: false,
      error: `Invalid deviceCategory "${rawCategory}". Expected all, smart_tv, ip_camera, pc_workstation, or a supported category.`
    };
  }
  return { valid: true, category: normalizeDeviceCategory(trimmed) };
}

/**
 * Validates a URL against SSRF rules (`validateTargets`) and scope/deny rules (`evaluateAssetGate`).
 */
function validateAndGateUrl(rawUrl, { allowPrivate = false, scopeRules = [], normalizeBare = false } = {}) {
  const candidate = normalizeBare ? normalizeTargetInput(rawUrl) : String(rawUrl || '').trim();
  const validation = validateTargets([candidate], { allowPrivate });
  if (!validation.valid) {
    return {
      ok: false,
      status: 400,
      payload: {
        error: validation.errors.join('; '),
        errors: validation.errors
      }
    };
  }
  const validatedUrl = validation.targets[0];
  const gate = evaluateAssetGate(validatedUrl, { rules: scopeRules });
  if (!gate.allowed) {
    return {
      ok: false,
      status: 403,
      payload: {
        error: gate.reason,
        code: gate.code || 'TARGET_RULE_BLOCKED'
      }
    };
  }
  return { ok: true, url: validatedUrl };
}

/**
 * Resolves a validated target URL via DNS (or sourceIp) and blocks DNS rebinding / private IP SSRF
 * or post-DNS asset gate violations before any outbound request is dispatched.
 */
async function prevalidateResolvedTarget(
  validatedUrl,
  {
    allowPrivate = false,
    scopeRules = [],
    dnsResolver = null,
    targetPinStore = null,
    sourceIp = null,
    sourceIpMap = null
  } = {}
) {
  const preDns = await resolveAndValidateTarget(validatedUrl, {
    resolver: dnsResolver,
    ...(targetPinStore ? { targetPinStore } : {}),
    allowPrivate,
    ...(sourceIp ? { sourceIp } : {}),
    ...(sourceIpMap ? { sourceIpMap } : {})
  });
  if (!preDns.valid && preDns.code === 'INVALID_SOURCE_IP') {
    return { ok: false, status: 400, payload: { error: preDns.reason, code: preDns.code } };
  }
  if (!preDns.valid && preDns.code === 'DNS_REBIND_OR_PRIVATE_IP') {
    return { ok: false, status: 403, payload: { error: preDns.reason, code: preDns.code } };
  }
  if (preDns.valid && Array.isArray(preDns.resolvedIps) && preDns.resolvedIps.length > 0 && scopeRules.length) {
    const postDnsGate = evaluateAssetGate(
      { url: validatedUrl, hostname: preDns.hostname, resolvedIps: preDns.resolvedIps },
      { rules: scopeRules }
    );
    if (!postDnsGate.allowed) {
      return {
        ok: false,
        status: 403,
        payload: { error: postDnsGate.reason, code: postDnsGate.code || 'TARGET_RULE_BLOCKED' }
      };
    }
  }
  return { ok: true, preDns };
}

/**
 * Validates all URLs inside a normalized login sequence's actions (`navigate.url`,
 * `click_button.submitUrl`, `custom_request.url`) against SSRF, scope rules, and DNS pinning.
 */
async function validateSequenceActionUrls(
  seq,
  {
    allowPrivate = false,
    scopeRules = [],
    dnsResolver = null,
    targetPinStore = null,
    baseUrl = null,
    sourceIp = null,
    sourceIpMap = null,
    checkDns = true,
    systemVariables = null,
    secrets = null
  } = {}
) {
  if (!seq || !Array.isArray(seq.actions)) return { ok: true };
  const effectiveSecrets = secrets ?? seq.secrets ?? null;
  let effectiveBase = baseUrl || seq.targetUrl || null;
  if (effectiveBase) {
    effectiveBase = resolveUrlPlaceholders(effectiveBase, {
      systemVariables,
      secrets: effectiveSecrets
    }).resolvedUrl;
  }

  for (const act of seq.actions) {
    if (!act || typeof act !== 'object') continue;
    const rawActUrl =
      act.type === 'navigate'
        ? act.url
        : act.type === 'click_button'
          ? act.submitUrl
          : act.type === 'custom_request'
            ? act.url
            : '';
    const rawTrimmed = typeof rawActUrl === 'string' ? rawActUrl.trim() : '';
    if (!rawTrimmed) continue;

    const resolvedActInfo = resolveUrlPlaceholders(rawTrimmed, {
      systemVariables,
      secrets: effectiveSecrets
    });
    const trimmed = resolvedActInfo.resolvedUrl;
    if (!trimmed) continue;
    if (!checkDns && /\{\{(?:VAR|SECRET):[^}]+\}\}/i.test(rawTrimmed) && !/^https?:\/\//i.test(trimmed)) {
      continue;
    }

    const hasExplicitSchemeOrAuthority =
      trimmed.startsWith('//') || /^[a-zA-Z][a-zA-Z0-9+.-]*:/i.test(trimmed);

    let urlToValidate = null;
    if (hasExplicitSchemeOrAuthority) {
      urlToValidate = trimmed;
    } else if (effectiveBase) {
      try {
        urlToValidate = new URL(trimmed, effectiveBase).toString();
      } catch {
        return {
          ok: false,
          status: 400,
          payload: { error: `Invalid login sequence URL "${rawTrimmed}" at step ${act.step || ''}`.trim() }
        };
      }
    }

    if (urlToValidate) {
      const gated = validateAndGateUrl(urlToValidate, {
        allowPrivate,
        scopeRules,
        normalizeBare: false
      });
      if (!gated.ok) return gated;

      if (checkDns) {
        const dnsCheck = await prevalidateResolvedTarget(gated.url, {
          allowPrivate,
          scopeRules,
          dnsResolver,
          targetPinStore,
          sourceIp,
          sourceIpMap
        });
        if (!dnsCheck.ok) return dnsCheck;
      }

      if (!effectiveBase && act.type === 'navigate') {
        effectiveBase = gated.url;
      }
    }
  }

  return { ok: true };
}

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.ico': 'image/x-icon'
};

/**
 * Apply hardened security headers on every response.
 */
function applySecurityHeaders(res) {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
  );
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
}

/**
 * Validate Origin and Host headers against DNS rebinding & CSRF attacks.
 */
function isOriginAndHostAllowed(req) {
  const origin = req.headers['origin'];
  if (origin) {
    try {
      const parsedOrigin = new URL(origin);
      const originHost = parsedOrigin.hostname.toLowerCase();
      if (
        originHost !== 'localhost' &&
        originHost !== '127.0.0.1' &&
        originHost !== '[::1]' &&
        originHost !== '::1'
      ) {
        return false;
      }
    } catch {
      return false;
    }
  }

  const host = req.headers['host'];
  if (!host || typeof host !== 'string') {
    return false;
  }

  if (!/^(\[::1\]|localhost|127\.0\.0\.1)(:\d+)?$/i.test(host.trim())) {
    return false;
  }

  return true;
}

/**
 * Shared JSON body parser enforcing a strict byte limit and Content-Type checks.
 */
function parseBodyWithLimit(req, res, { maxBytes = 65536, optional = false } = {}) {
  return new Promise(resolve => {
    let settled = false;

    const finish = (statusCode, data) => {
      if (settled || res.headersSent) return;
      settled = true;
      if (statusCode !== null) {
        sendJson(res, statusCode, data);
        resolve(null);
      } else {
        resolve(data);
      }
    };

    const contentType = String(req.headers['content-type'] || '').toLowerCase();
    const isJsonContentType = contentType.includes('application/json');

    if (!optional && !isJsonContentType) {
      finish(415, { error: 'Content-Type must be application/json' });
      return;
    }

    let size = 0;
    const chunks = [];

    req.on('data', chunk => {
      if (settled || res.headersSent) return;
      size += chunk.length;
      if (size > maxBytes) {
        res.setHeader('Connection', 'close');
        finish(413, { error: 'Payload too large (max 64KB)' });
        if (typeof res.once === 'function') {
          res.once('finish', () => {
            if (typeof req.destroy === 'function' && !req.destroyed) req.destroy();
          });
        }
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      if (settled || res.headersSent) return;
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw.trim()) {
        finish(null, {});
        return;
      }
      if (optional && contentType && !isJsonContentType) {
        finish(415, { error: 'Content-Type must be application/json' });
        return;
      }
      try {
        const parsed = JSON.parse(raw);
        finish(null, parsed);
      } catch (err) {
        finish(400, { error: `Invalid JSON body: ${err.message}` });
      }
    });

    req.on('error', () => {
      if (settled || res.headersSent) return;
      finish(400, { error: 'Stream read error' });
    });
  });
}

/**
 * Parse JSON body with strict 64KB limit.
 */
function parseJsonBody(req, res, maxBytes = 65536) {
  return parseBodyWithLimit(req, res, { maxBytes, optional: false });
}

const readJsonBody = parseJsonBody;

/**
 * Parses an optional JSON body: enforces 64KB 413 limit with or without Content-Type,
 * and rejects non-JSON Content-Type when a non-empty body is supplied.
 */
function parseOptionalJsonBody(req, res, maxBytes = 65536) {
  return parseBodyWithLimit(req, res, { maxBytes, optional: true });
}

function sendJson(res, status, data) {
  if (res.headersSent) return;
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body)
  });
  res.end(body);
}

function capApiCommunicationInput(value, depth = 0) {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return value.slice(0, 512);
  if (depth > 4) return undefined;
  if (Array.isArray(value)) {
    return value.slice(0, 50).map(item => capApiCommunicationInput(item, depth + 1));
  }
  if (typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value).slice(0, 30)) {
      out[k] = capApiCommunicationInput(v, depth + 1);
    }
    return out;
  }
  return value;
}

/**
 * Broadcast an event to all connected SSE clients and record it in job events.
 */
function broadcastJobEvent(job, evt) {
  const eventPayload = {
    ...evt,
    timestamp: new Date().toISOString(),
    progress: job.progress,
    phase: job.phase
  };
  job.events.push(eventPayload);

  const eventName = eventPayload.type || 'message';
  const sseData = `event: ${eventName}\ndata: ${JSON.stringify(eventPayload)}\n\n`;

  for (const client of job.clients) {
    try {
      client.write(sseData);
    } catch {
      job.clients.delete(client);
    }
  }
}

/**
 * Executes a security scan job asynchronously with real-time SSE progress reporting.
 */
async function executeScanJob(job, ctx = {}) {
  let activeGovernedFetch = null;
  try {
    job.progress = 5;
    job.phase = 'starting';
    broadcastJobEvent(job, {
      type: 'start',
      message: `Starting scan for target(s): ${job.targets.join(', ')}`
    });

    const allowPrivate = Boolean(job.allowPrivate);
    const enrichEngine = ctx.enrichEngine || new EnrichEngine({ allowPrivate });
    const activeGovernor = job.noiseProfile
      ? new NoiseGovernor({ profile: job.noiseProfile })
      : (typeof ctx.getNoiseGovernor === 'function' ? ctx.getNoiseGovernor() : ctx.noiseGovernor);
    const activeScopeRules = typeof ctx.getScopeRules === 'function' ? ctx.getScopeRules() : ctx.scopeRules;
    const targetPinStore = ctx.targetPinStore || new TargetPinStore({ allowPrivate });
    const customHeaders = job.headers && typeof job.headers === 'object' ? job.headers : {};
    const authHeaders = job.auth ? { Authorization: job.auth } : {};
    const governedFetch = createGovernedFetch({
      ...(activeGovernor ? { governor: activeGovernor } : {}),
      ...(Array.isArray(activeScopeRules) && activeScopeRules.length ? { scopeRules: activeScopeRules } : {}),
      ...(ctx.trafficStore ? { trafficStore: ctx.trafficStore, taskId: `scan_${job.id}` } : {}),
      ...(ctx.dnsResolver ? { dnsResolver: ctx.dnsResolver } : {}),
      ...(job.sourceIp ? { sourceIp: job.sourceIp } : {}),
      ...(job.sourceIpMap ? { sourceIpMap: job.sourceIpMap } : {}),
      ...(ctx.fetcher ? { fetcher: ctx.fetcher } : {}),
      enforceDnsValidation: true,
      allowPrivate,
      targetPinStore,
      retries: 2,
      timeout: job.timeout
    });
    activeGovernedFetch = governedFetch;
    let fetchWithRetry = (url, opts = {}, ...rest) => {
      const safeOpts = opts && typeof opts === 'object' ? opts : {};
      return governedFetch(
        url,
        {
          ...safeOpts,
          headers: { ...customHeaders, ...authHeaders, ...(safeOpts.headers || {}) }
        },
        ...rest
      );
    };
    const copyFetchMeta = (src, dst) => {
      dst.governance = src.governance;
      dst.tlsAlpnProbe = src.tlsAlpnProbe;
      dst.sourceIp = src.sourceIp;
      dst.sourceIpMap = src.sourceIpMap;
      dst.resolveCache = src.resolveCache;
      dst.targetPinStore = src.targetPinStore;
      dst.hasCustomFetcher = src.hasCustomFetcher;
      if (src.isDefaultFetch !== undefined) {
        dst.isDefaultFetch = src.isDefaultFetch;
      }
      return dst;
    };
    copyFetchMeta(governedFetch, fetchWithRetry);

    let activeAuthManager = null;
    if (job.authSessionConfig) {
      const cfg = { ...job.authSessionConfig };
      if (cfg.sequenceId && !cfg.loginSequence && ctx.savedSequences?.has(cfg.sequenceId)) {
        cfg.loginSequence = ctx.savedSequences.get(cfg.sequenceId);
      }
      const mergedJobVarsMap = new Map();
      if (ctx.systemVariables) {
        storeSystemVariables(mergedJobVarsMap, Array.from(ctx.systemVariables.values()));
      }
      if (cfg.systemVariables) {
        storeSystemVariables(mergedJobVarsMap, cfg.systemVariables);
      }
      const mergedJobSystemVars = Array.from(mergedJobVarsMap.values());

      let authManager;
      if (cfg.recordedSessionId && ctx.recordedSessions?.has(cfg.recordedSessionId)) {
        authManager = AuthSessionManager.fromRecordedSession(
          ctx.recordedSessions.get(cfg.recordedSessionId)
        );
        if (cfg.loginSequence) {
          authManager.loginSequence = normalizeLoginSequence(cfg.loginSequence, authManager.targetUrl || job.targets[0]);
        }
        if (mergedJobSystemVars.length > 0) {
          for (const item of normalizeSystemVariables(mergedJobSystemVars)) {
            const prev = authManager.systemVariables.get(item.name);
            if (prev && prev.value && (item.value === '[SECRET]' || item.value === '[REDACTED]')) {
              continue;
            }
            authManager.systemVariables.set(item.name, item);
          }
        }
      } else {
        authManager = new AuthSessionManager({
          targetUrl: job.targets[0],
          ...cfg,
          systemVariables: mergedJobSystemVars
        });
      }

      if (
        !authManager.getRecordedSession().authenticated &&
        (authManager.username || authManager.loginPayload || authManager.loginUrl || authManager.loginSequence?.actions?.length)
      ) {
        broadcastJobEvent(job, {
          type: 'auth_session',
          status: 'authenticating',
          message: 'Logging in and recording authenticated session...'
        });
        await authManager.executeLoginMacro(fetchWithRetry);
      }

      activeAuthManager = authManager;
      storeRecordedSession(ctx.recordedSessions, authManager.exportRecordedSession());
      if (authManager.loginSequence?.actions?.length > 0 && ctx.savedSequences) {
        storeSavedSequence(ctx.savedSequences, authManager.loginSequence);
        if (!ctx.inMemory && ctx.historyDir) {
          savePersistedSequences(ctx.historyDir, ctx.savedSequences);
        }
      }
      fetchWithRetry = copyFetchMeta(fetchWithRetry, authManager.wrapFetch(fetchWithRetry));
      job.authSession = authManager.getRecordedSession({ includeSecrets: false });
      broadcastJobEvent(job, {
        type: 'auth_session',
        status: 'ready',
        authSession: job.authSession,
        message: `Authenticated session active (${job.authSession.cookieCount} cookie(s), JWT: ${job.authSession.hasBearerToken ? 'yes' : 'no'})`
      });
    }

    const scanners = await getScanners();

    const allResults = [];
    const stacks = [];
    const allDiscoveredMenus = [];
    const allDiscoveredForms = [];
    const allDiscoveredPages = [];
    const allRbacMatrices = [];
    let totalPagesFound = 0;

    const targetLimit = pLimit(Math.max(1, Math.min(job.concurrency, 10)));

    const schemesByHost = new Map();
    for (const jt of job.targets) {
      try {
        const u = new URL(jt);
        const hostKey = String(u.hostname || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
        if (!hostKey) continue;
        if (!schemesByHost.has(hostKey)) schemesByHost.set(hostKey, new Set());
        schemesByHost.get(hostKey).add(u.protocol.toLowerCase());
      } catch {}
    }

    const targetPromises = job.targets.map(initialTarget =>
      targetLimit(async () => {
        let siblingSchemes = [];
        try {
          const u = new URL(initialTarget);
          const hostKey = String(u.hostname || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
          siblingSchemes = Array.from(schemesByHost.get(hostKey) || []);
        } catch {}

        // 1. Tech Stack Fingerprinting
        job.phase = 'fingerprinting';
        job.progress = Math.min(job.progress + 5, 20);
        broadcastJobEvent(job, {
          type: 'fingerprinting',
          target: initialTarget,
          message: `Fingerprinting tech stack for ${initialTarget}...`
        });

        const seenBundleUrls = new Set();
        const seenConfigUrls = new Set();
        const budgetState = { bytes: 0 };
        const fp = await fingerprint(initialTarget, fetchWithRetry, {
          seenBundleUrls,
          seenConfigUrls,
          budgetState,
          deviceMode: Boolean(job.deviceMode),
          deviceCategory: job.deviceCategory || 'all',
          allowPrivate,
          ...(typeof ctx.tcpProbe === 'function' ? { tcpProbe: ctx.tcpProbe } : {}),
          ...(typeof ctx.portProbe === 'function' ? { portProbe: ctx.portProbe } : {}),
          ...(typeof ctx.rtspProbe === 'function' ? { rtspProbe: ctx.rtspProbe } : {}),
          ...(typeof ctx.udpProbe === 'function' ? { udpProbe: ctx.udpProbe } : {}),
          ...(typeof ctx.tlsProbe === 'function' ? { tlsProbe: ctx.tlsProbe } : {}),
          ...(ctx.multiPort !== undefined ? { multiPort: ctx.multiPort } : {}),
        });
        const safeFpApiComm = fp.apiCommunication ? sanitizeApiCommunication(fp.apiCommunication) : null;
        if (safeFpApiComm) fp.apiCommunication = safeFpApiComm;
        const safeFpRuntimeSca = fp.runtimeSca ? sanitizeRuntimeSca(fp.runtimeSca) : null;
        if (safeFpRuntimeSca) fp.runtimeSca = safeFpRuntimeSca;
        const isDeviceBasePortClosed = Boolean(
          fp.deviceInfo?.basePortClosed &&
          (fp.deviceInfo?.detected || job.deviceMode)
        );
        const effectiveProfileForSelection =
          String(job.profile || 'smart').toLowerCase() === 'smart' && isDeviceBasePortClosed
            ? 'device'
            : job.profile;
        let { activeScanners, skippedScanners } = selectScannersForStack(scanners, {
          profile: effectiveProfileForSelection,
          fp,
          techOverride: job.techOverride,
          forceAll: job.forceAll
        });
        if (Array.isArray(job.checks) && job.checks.length > 0) {
          const wantedLower = new Set(job.checks.map(c => String(c).trim().toLowerCase()).filter(Boolean));
          const matchesCheckOrCve = (s) => {
            if (wantedLower.has(String(s.name || '').toLowerCase())) return true;
            const cveList = Array.isArray(s.meta?.cveIds) ? s.meta.cveIds : [];
            return cveList.some(cve => wantedLower.has(String(cve).toLowerCase()));
          };
          activeScanners = scanners.filter(matchesCheckOrCve);
          skippedScanners = scanners.filter(s => !matchesCheckOrCve(s));
        }
        if (
          isDeviceBasePortClosed &&
          !fp.deviceInfo.activeHttpOrigin &&
          !fp.deviceInfo.activeHttpsOrigin
        ) {
          const nonHttpOnly = [];
          const skippedHttpOnly = [];
          for (const s of activeScanners) {
            if (s.name === 'device-security') nonHttpOnly.push(s);
            else skippedHttpOnly.push(s);
          }
          activeScanners = nonHttpOnly;
          skippedScanners = [...skippedScanners, ...skippedHttpOnly];
        }

        stacks.push({
          target: initialTarget,
          primary: fp.primary,
          confidence: fp.confidence,
          summary: fp.summary,
          stack: fp.stack,
          detectedTags: fp.detectedTags,
          recommendedProfile: fp.recommendedProfile,
          categories: fp.categories,
          apiCommunication: safeFpApiComm,
          runtimeSca: safeFpRuntimeSca,
          deviceInfo: fp.deviceInfo || null,
          activeChecksCount: activeScanners.length,
          skippedChecksCount: skippedScanners.length,
          skippedChecks: skippedScanners.map(s => s.name)
        });

        broadcastJobEvent(job, {
          type: 'fingerprint',
          target: initialTarget,
          primary: fp.primary,
          confidence: fp.confidence,
          summary: fp.summary,
          stack: fp.stack,
          detectedTags: fp.detectedTags,
          recommendedProfile: fp.recommendedProfile,
          categories: fp.categories,
          apiCommunication: safeFpApiComm,
          runtimeSca: safeFpRuntimeSca,
          deviceInfo: fp.deviceInfo || null,
          activeChecksCount: activeScanners.length,
          skippedChecksCount: skippedScanners.length,
          skippedChecks: skippedScanners.map(s => s.name),
          message: `Detected stack: ${
            fp.summary ||
            (fp.stack && fp.stack.length
              ? fp.stack.map(s => `${s.tech} (${s.score})`).join(', ')
              : 'Generic Web Application')
          } (${activeScanners.length} checks active, ${skippedScanners.length} skipped)`
        });

        // 2. Autonomous Web Crawling
        job.phase = 'crawling';
        job.progress = Math.min(job.progress + 10, 35);
        broadcastJobEvent(job, {
          type: 'crawling',
          target: initialTarget,
          message: isDeviceBasePortClosed
            ? `Standard HTTP port closed on ${initialTarget}; skipping web crawl and routing to device ports...`
            : `Discovering pages on ${initialTarget} (max depth: ${job.maxDepth})...`
        });

        const normalizedInitialTarget = String(initialTarget || '').replace(/\/+$/, '');
        const { discoveredUrls, discoveredMenus, discoveredForms } = await runTargetCrawlPipeline(
          initialTarget,
          fetchWithRetry,
          {
            maxDepth: job.maxDepth,
            authManager: activeAuthManager,
            fp,
            activeScanners,
            activeFuzzingChecks: ACTIVE_FUZZING_CHECKS,
            isDeviceBasePortClosed,
            seenBundleUrls,
            seenConfigUrls,
            budgetState,
            onCrawlDepth: ({ depth, pending, pagesFound }) => {
              broadcastJobEvent(job, {
                type: 'crawl_depth',
                target: initialTarget,
                depth,
                pending,
                pagesFound,
                message: `Depth ${depth}: Analyzing ${pending} pages for links, menus & forms...`
              });
            }
          }
        );

        allDiscoveredMenus.push(...discoveredMenus);
        allDiscoveredForms.push(...discoveredForms);
        for (const u of discoveredUrls) {
          if (!allDiscoveredPages.includes(u)) allDiscoveredPages.push(u);
        }
        totalPagesFound += discoveredUrls.length;

        let targetRbacFindings = [];
        if (
          activeAuthManager?.getRecordedSession()?.authenticated === true &&
          (discoveredMenus.length > 0 || discoveredForms.length > 0)
        ) {
          try {
            const targetRbac = await auditMenuAndFormAccessControl({
              discoveredMenus,
              discoveredForms,
              unauthFetch: governedFetch,
              authManager: activeAuthManager,
              maxProbes: 12
            });
            allRbacMatrices.push(targetRbac);
            if (Array.isArray(targetRbac.findings) && targetRbac.findings.length > 0) {
              targetRbacFindings = targetRbac.findings.map(rf => {
                const meta = getCheckMeta(rf.checkId || 'bola-mass-assignment');
                return enrichEngine.enrichFinding(
                  {
                    target: rf.url || initialTarget,
                    ...rf,
                    meta
                  },
                  { allowPrivate }
                );
              });
            }
          } catch {
            // Non-fatal RBAC matrix probe error
          }
        }

        broadcastJobEvent(job, {
          type: 'crawl_complete',
          target: initialTarget,
          pagesFound: discoveredUrls.length,
          pages: discoveredUrls,
          menusFound: discoveredMenus.length,
          formsFound: discoveredForms.length,
          menus: discoveredMenus,
          forms: discoveredForms,
          message: `Crawl complete. Found ${discoveredUrls.length} unique pages, ${discoveredMenus.length} menu/submenu items, and ${discoveredForms.length} forms on ${initialTarget}`
        });

        // 3. Run active scanners across discovered pages
        job.phase = 'scanning';

        const pageScannersMap = new Map();
        let targetPlanned = 0;
        for (const page of discoveredUrls) {
          const isRoot = (page.replace(/\/+$/, '') === normalizedInitialTarget || discoveredUrls.length === 1);
          const checksForPage = isRoot
            ? activeScanners
            : activeScanners.filter(s => ACTIVE_FUZZING_CHECKS.has(s.name));
          pageScannersMap.set(page, checksForPage);
          targetPlanned += checksForPage.length;
        }

        const totalChecks = Math.max(1, targetPlanned);
        let completedChecks = 0;

        broadcastJobEvent(job, {
          type: 'scanning',
          target: initialTarget,
          checkCount: activeScanners.length,
          pageCount: discoveredUrls.length,
          plannedChecks: totalChecks,
          message: `Running checks against ${discoveredUrls.length} discovered pages (${totalChecks} total checks planned)...`
        });

        const pageLimit = pLimit(3);
        const scannerOptions = {
          allowPrivate,
          deviceMode: Boolean(job.deviceMode),
          deviceCategory: job.deviceCategory || 'all',
          siblingSchemes,
          ...(typeof ctx.tcpProbe === 'function' ? { tcpProbe: ctx.tcpProbe } : {}),
          ...(typeof ctx.portProbe === 'function' ? { portProbe: ctx.portProbe } : {}),
          ...(typeof ctx.rtspProbe === 'function' ? { rtspProbe: ctx.rtspProbe } : {}),
          ...(typeof ctx.udpProbe === 'function' ? { udpProbe: ctx.udpProbe } : {}),
          ...(typeof ctx.tlsProbe === 'function' ? { tlsProbe: ctx.tlsProbe } : {}),
          ...(typeof ctx.tlsConnect === 'function' ? { tlsConnect: ctx.tlsConnect } : {}),
          ...(ctx.multiPort !== undefined ? { multiPort: ctx.multiPort } : {}),
          ...(fp.deviceInfo?.detected ? {
            cachedDeviceScan: {
              isQuickFingerprint: true,
              deviceProfile: fp.deviceInfo,
              host: fp.deviceInfo.host,
              openPorts: Array.isArray(fp.deviceInfo.openPorts) ? fp.deviceInfo.openPorts : [],
              ...(Array.isArray(fp.deviceInfo.openServices) ? { openServices: fp.deviceInfo.openServices } : {}),
              deviceCategory: job.deviceCategory || 'all'
            }
          } : {}),
          ...(Array.isArray(activeScopeRules) && activeScopeRules.length ? { scopeRules: activeScopeRules } : {}),
          ...(activeGovernor ? { governor: activeGovernor } : {}),
          ...(ctx.dnsResolver ? { dnsResolver: ctx.dnsResolver } : {}),
          ...(discoveredForms.length > 0 ? { discoveredForms } : {}),
          ...(discoveredUrls.length > 0 ? { verificationUrls: discoveredUrls.slice(0, 3) } : {}),
          targetPinStore
        };

        const pageResultsNested = await Promise.all(
          discoveredUrls.map(page =>
            pageLimit(async () => {
              const targetPageResults = [];
              const scannersForPage = pageScannersMap.get(page) || [];

              for (const scanner of scannersForPage) {
                let targetForCheck = page;
                if (isDeviceBasePortClosed && scanner.name !== 'device-security') {
                  if (scanner.name === 'ssl-tls' && fp.deviceInfo.activeHttpsOrigin) {
                    targetForCheck = fp.deviceInfo.activeHttpsOrigin;
                  } else if (fp.deviceInfo.activeHttpOrigin) {
                    targetForCheck = fp.deviceInfo.activeHttpOrigin;
                  } else if (fp.deviceInfo.activeHttpsOrigin) {
                    targetForCheck = fp.deviceInfo.activeHttpsOrigin;
                  }
                }
                try {
                  const trackedFetch = createTrackedFetch(fetchWithRetry);
                  const res = await scanner.run(targetForCheck, trackedFetch, scannerOptions);
                  const meta = res.meta || scanner.meta || getCheckMeta(scanner.name);
                  const finding = enrichEngine.enrichFinding({
                    target: targetForCheck,
                    checkId: scanner.name,
                    ...res,
                    meta
                  }, { allowPrivate, capturedTraces: trackedFetch.getTraces() });

                  if (
                    finding.status !== 'SAFE' &&
                    finding.status !== 'ERROR' &&
                    finding.trafficId &&
                    ctx.evidenceStore &&
                    typeof ctx.evidenceStore.captureSnapshotFromExchange === 'function' &&
                    typeof ctx.evidenceStore.bindEvidence === 'function'
                  ) {
                    try {
                      const snap = ctx.evidenceStore.captureSnapshotFromExchange(finding.trafficId, {
                        taskId: job.taskId || null
                      });
                      if (snap?.id) {
                        const firstQuote = Array.isArray(finding.evidenceQuotes) && finding.evidenceQuotes.length > 0
                          ? finding.evidenceQuotes[0]
                          : '';
                        const findingIdsToBind = new Set([
                          `${finding.checkId}::${finding.target}`,
                          `${finding.checkId}::${initialTarget}`,
                          `${finding.checkId}::${normalizedInitialTarget}`
                        ]);
                        for (const fid of findingIdsToBind) {
                          ctx.evidenceStore.bindEvidence({
                            findingId: fid,
                            snapshotId: snap.id,
                            role: 'proof',
                            quote: firstQuote
                          });
                        }
                      }
                    } catch {
                      // Non-fatal evidence binding error
                    }
                  }

                  targetPageResults.push(finding);

                  completedChecks++;
                  const progressPct = 35 + Math.round((completedChecks / totalChecks) * 55);
                  job.progress = Math.min(progressPct, 92);

                  broadcastJobEvent(job, {
                    type: 'check',
                    target: targetForCheck,
                    checkId: scanner.name,
                    status: finding.status,
                    severity: finding.severity,
                    name: finding.name || scanner.name,
                    title: meta?.title || finding.name || scanner.name,
                    fix: finding.fix || meta?.defaultFix || null,
                    reason: finding.reason || null,
                    ...(finding.detail ? { detail: finding.detail } : {}),
                    ...(finding.path ? { path: finding.path } : {}),
                    ...(finding.device ? { device: finding.device } : {}),
                    ...(finding.deviceCategory ? { deviceCategory: finding.deviceCategory } : {}),
                    ...(Array.isArray(finding.openPorts) ? { openPorts: finding.openPorts } : {}),
                    ...(Array.isArray(finding.files) ? { files: finding.files } : {}),
                    ...(Array.isArray(finding.findings) ? { findings: finding.findings } : {}),
                    ...(Array.isArray(finding.missing) ? { missing: finding.missing } : {}),
                    ...(Array.isArray(finding.present) ? { present: finding.present } : {}),
                    ...(Array.isArray(finding.evidenceQuotes) ? { evidenceQuotes: finding.evidenceQuotes } : {}),
                    ...(finding.reproVerified !== undefined ? { reproVerified: finding.reproVerified } : {}),
                    ...(finding.poeLevel !== undefined ? { poeLevel: finding.poeLevel } : {}),
                    ...(finding.trafficId !== undefined ? { trafficId: finding.trafficId } : {}),
                    cwe: finding.cwe,
                    owasp: finding.owasp,
                    cvssScore: finding.cvssScore,
                    cveIds: finding.cveIds,
                    ...(finding.reproduction ? { reproduction: finding.reproduction } : {})
                  });
                } catch (err) {
                  const meta = scanner.meta || getCheckMeta(scanner.name);
                  const errorFinding = enrichEngine.enrichFinding({
                    target: targetForCheck,
                    checkId: scanner.name,
                    name: scanner.name,
                    status: 'ERROR',
                    severity: 'LOW',
                    reason: err.message,
                    meta
                  }, { allowPrivate });
                  targetPageResults.push(errorFinding);
                  completedChecks++;
                  const progressPct = 35 + Math.round((completedChecks / totalChecks) * 55);
                  job.progress = Math.min(progressPct, 92);

                  broadcastJobEvent(job, {
                    type: 'check',
                    target: targetForCheck,
                    checkId: scanner.name,
                    status: errorFinding.status,
                    severity: errorFinding.severity,
                    name: errorFinding.name || scanner.name,
                    title: meta?.title || errorFinding.name || scanner.name,
                    fix: errorFinding.fix || meta?.defaultFix || null,
                    reason: errorFinding.reason || err.message || null,
                    cwe: errorFinding.cwe,
                    owasp: errorFinding.owasp,
                    cvssScore: errorFinding.cvssScore,
                    cveIds: errorFinding.cveIds
                  });
                }
              }
              return targetPageResults;
            })
          )
        );

        return [...pageResultsNested.flat(), ...targetRbacFindings];
      })
    );

    const nestedResults = await Promise.all(targetPromises);
    nestedResults.forEach(list => allResults.push(...list));

    const rbacMatrix = allRbacMatrices.length === 1
      ? allRbacMatrices[0]
      : allRbacMatrices.length > 1
        ? {
            summary: allRbacMatrices.reduce(
              (acc, m) => {
                acc.totalEvaluated += m.summary?.totalEvaluated || 0;
                acc.enforcedCount += m.summary?.enforcedCount || 0;
                acc.unauthenticatedBflaCount += m.summary?.unauthenticatedBflaCount || 0;
                acc.lowPrivilegeBflaCount += m.summary?.lowPrivilegeBflaCount || 0;
                acc.skippedCount += m.summary?.skippedCount || 0;
                if (m.summary?.status === 'VULNERABLE') acc.status = 'VULNERABLE';
                return acc;
              },
              {
                totalEvaluated: 0,
                enforcedCount: 0,
                unauthenticatedBflaCount: 0,
                lowPrivilegeBflaCount: 0,
                skippedCount: 0,
                status: 'SAFE'
              }
            ),
            menuMatrix: allDiscoveredMenus,
            formMatrix: allDiscoveredForms,
            findings: allRbacMatrices.flatMap(m => m.findings || [])
          }
        : null;

    // 5. Finalizing results and calculating risk
    job.phase = 'finalizing';
    job.progress = 96;
    broadcastJobEvent(job, {
      type: 'finalizing',
      message: 'Calculating security grade and compiling executive summary...'
    });

    const risk = calculateRisk(allResults);
    const groupedResults = groupFindings(allResults);
    const apiCommunication = mergeApiCommunication(stacks, allResults);
    const runtimeSca = mergeRuntimeSca(stacks, allResults);
    for (const s of stacks) {
      if (s && typeof s === 'object') {
        const targetFindings = allResults.filter(r => r && r.target && s.target && r.target.startsWith(s.target));
        const mergedTargetApi = mergeApiCommunication([s], targetFindings);
        if (mergedTargetApi) {
          s.apiCommunication = mergedTargetApi;
        }
        const mergedTargetSca = mergeRuntimeSca([s], targetFindings);
        if (mergedTargetSca) {
          s.runtimeSca = mergedTargetSca;
        }
      }
    }

    let cveCoverage = null;
    try {
      const detectedTagSet = new Set();
      for (const s of stacks) {
        if (Array.isArray(s?.detectedTags)) {
          for (const t of s.detectedTags) {
            if (typeof t === 'string' && t.trim()) detectedTagSet.add(t.trim().toLowerCase());
          }
        }
      }
      if (Array.isArray(job.techOverride)) {
        for (const t of job.techOverride) {
          if (typeof t === 'string' && t.trim()) detectedTagSet.add(t.trim().toLowerCase());
        }
      }
      const cveAudit = await auditCveCoverage({ scanners, techTags: Array.from(detectedTagSet) });
      cveCoverage = summarizeCveAudit(cveAudit);
    } catch {}

    let historyFile = null;
    let htmlReportFile = null;
    let jsonReportFile = null;
    if (!job.noHistory) {
      historyFile = saveHistory(job.targets, allResults, risk, stacks);
      if (historyFile && (apiCommunication || runtimeSca || cveCoverage || allDiscoveredMenus.length || allDiscoveredForms.length || allDiscoveredPages.length)) {
        try {
          const histRaw = JSON.parse(fs.readFileSync(historyFile, 'utf8'));
          if (apiCommunication) histRaw.apiCommunication = apiCommunication;
          if (runtimeSca) histRaw.runtimeSca = runtimeSca;
          if (cveCoverage) histRaw.cveCoverage = cveCoverage;
          histRaw.discoveredMenus = allDiscoveredMenus;
          histRaw.discoveredForms = allDiscoveredForms;
          histRaw.discoveredPages = allDiscoveredPages;
          histRaw.pagesCount = totalPagesFound;
          if (rbacMatrix) histRaw.rbacMatrix = rbacMatrix;
          fs.writeFileSync(historyFile, JSON.stringify(histRaw, null, 2));
        } catch {}
      }
      try {
        const autoReports = saveAutoReports(job.targets, allResults, risk, stacks, {
          cveCoverage,
          ...(apiCommunication ? { apiCommunication } : {}),
          ...(runtimeSca ? { runtimeSca } : {})
        });
        htmlReportFile = autoReports.htmlPath;
        jsonReportFile = autoReports.jsonPath;
      } catch {}
    }

    let ingestedTask = null;
    if (ctx.graphStore && typeof ctx.graphStore.ingestStaticScanResult === 'function') {
      try {
        ingestedTask = ctx.graphStore.ingestStaticScanResult({
          taskId: `scan_${job.id}`,
          title: `Scan: ${job.targets.join(', ')}`,
          targets: job.targets,
          results: allResults,
          risk,
          stacks,
          allow_private: allowPrivate,
          allowPrivate
        });
      } catch {}
    }

    let agentSummary = null;
    if (job.agent && ctx.graphStore && ctx.agentEngine) {
      try {
        job.phase = 'agent';
        broadcastJobEvent(job, {
          type: 'agent',
          message: `Running Agentic Verification loop for ${job.targets[0]}...`
        });
        const primaryTarget = job.targets[0];
        const agentTask = ctx.graphStore.createTask({
          title: `Agentic Verification: ${primaryTarget}`,
          target: primaryTarget,
          goal: job.goal || `Discover and verify security findings on ${primaryTarget}`,
          mode: 'auto',
          noise_profile: activeGovernor ? activeGovernor.profile : (job.noiseProfile || 'balanced'),
          scope: Array.isArray(activeScopeRules) ? activeScopeRules : undefined,
          allow_private: allowPrivate,
          allowPrivate,
        });
        if (typeof ctx.setTaskAllowPrivate === 'function') {
          ctx.setTaskAllowPrivate(agentTask.id, allowPrivate);
        }
        agentSummary = await ctx.agentEngine.runTaskLoop(agentTask.id, {
          maxRounds: Number(job.maxAgentRounds || 5),
          debounceMs: 0,
          allowPrivate,
          ...(typeof ctx.getScopeRules === 'function'
            ? { getScopeRules: ctx.getScopeRules }
            : Array.isArray(activeScopeRules)
              ? { scopeRules: [...activeScopeRules] }
              : {}),
        });
      } catch {}
    }

    const completedAtIso = new Date().toISOString();
    let targetSystemSummary = null;
    if (job.targetSystemId && ctx.targetSystems?.has(job.targetSystemId)) {
      const sys = ctx.targetSystems.get(job.targetSystemId);
      sys.lastScanSummary = mergeDeltaScanSummary(
        sys.lastScanSummary,
        {
          scanId: job.id,
          results: allResults,
          risk,
          historyFile,
          completedAt: completedAtIso
        },
        job.scanMode || 'full_profile',
        job.checks || []
      );
      sys.updatedAt = completedAtIso;
      targetSystemSummary = sys.lastScanSummary;
      if (!ctx.inMemory && ctx.historyDir) {
        savePersistedTargetSystems(ctx.historyDir, ctx.targetSystems);
      }
    }

    job.status = 'completed';
    job.progress = 100;
    job.phase = 'completed';
    job.result = {
      scanId: job.id,
      targetSystemId: job.targetSystemId || null,
      scanMode: job.scanMode || 'full_profile',
      ...(targetSystemSummary ? { targetSystemSummary } : {}),
      results: allResults,
      groupedResults,
      risk,
      historyFile,
      htmlReportFile,
      jsonReportFile,
      stacks,
      apiCommunication: apiCommunication || null,
      runtimeSca: runtimeSca || null,
      ...(cveCoverage ? { cveCoverage } : {}),
      ...(job.authSession ? { authSession: job.authSession } : {}),
      taskId: ingestedTask?.taskId || null,
      ...(agentSummary ? { agentSummary } : {}),
      pagesCount: totalPagesFound,
      discoveredMenus: allDiscoveredMenus,
      discoveredForms: allDiscoveredForms,
      discoveredPages: allDiscoveredPages,
      ...(rbacMatrix ? { rbacMatrix } : {}),
      completedAt: completedAtIso
    };

    broadcastJobEvent(job, {
      type: 'complete',
      status: 'completed',
      result: job.result,
      runtimeSca: runtimeSca || null,
      message: `Scan complete! Grade: ${risk.grade} (${risk.level} Risk, Score ${risk.score})`
    });

    for (const client of job.clients) {
      try {
        client.end();
      } catch {}
    }
    job.clients.clear();
  } catch (err) {
    job.status = 'failed';
    job.phase = 'failed';
    job.error = err.message;

    broadcastJobEvent(job, {
      type: 'error',
      status: 'failed',
      error: err.message,
      message: `Scan failed: ${err.message}`
    });

    for (const client of job.clients) {
      try {
        client.end();
      } catch {}
    }
    job.clients.clear();
  } finally {
    try {
      activeGovernedFetch?.destroyAgents?.();
    } catch {}
  }
}

/**
 * Serves static files strictly confined within the `ui/` folder.
 */
function serveStaticFile(req, res, pathname) {
  let decodedPath;
  try {
    decodedPath = decodeURIComponent(pathname);
  } catch {
    sendJson(res, 400, { error: 'Malformed URL path' });
    return;
  }

  if (decodedPath.includes('..') || decodedPath.includes('\0')) {
    sendJson(res, 403, { error: 'Access denied' });
    return;
  }

  let filePath;
  if (decodedPath.startsWith('/components/')) {
    const compName = decodedPath.slice('/components/'.length);
    if (!/^[a-z0-9-]+\.js$/.test(compName)) {
      sendJson(res, 403, { error: 'Access denied' });
      return;
    }
    filePath = path.resolve(UI_COMPONENTS_DIR, compName);
    if (!filePath.startsWith(UI_COMPONENTS_DIR + path.sep)) {
      sendJson(res, 403, { error: 'Access denied' });
      return;
    }
  } else {
    let cleanPath = decodedPath;
    if (cleanPath === '/' || cleanPath === '') {
      cleanPath = '/index.html';
    }

    // Sanitize path and prevent directory traversal
    const normalized = path.normalize(cleanPath).replace(/^(\.\.[/\\])+/, '');
    filePath = path.resolve(UI_DIR, '.' + normalized);

    if (!filePath.startsWith(UI_DIR + path.sep) && filePath !== path.join(UI_DIR, 'index.html')) {
      sendJson(res, 403, { error: 'Access denied' });
      return;
    }
  }

  if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
    sendJson(res, 404, { error: 'File not found' });
    return;
  }

  const ext = path.extname(filePath).toLowerCase();
  const mime = MIME_TYPES[ext] || 'application/octet-stream';
  const fileContent = fs.readFileSync(filePath);

  res.writeHead(200, {
    'Content-Type': mime,
    'Content-Length': fileContent.length,
    'Cache-Control': 'no-cache'
  });
  res.end(fileContent);
}

/**
 * Creates the HTTP Server with all security controls and API endpoints.
 */
export function createAppServer(options = {}) {
  const jobs = new Map();
  const MAX_JOBS = 100;
  const recordedSessions = new Map();
  const savedSequences = new Map();
  const systemVariables = new Map();
  const targetSystems = new Map();
  let cveLabBenchmarkInFlight = false;
  let pcLocalAuditInFlight = false;

  const historyDir = options.historyDir || path.join(process.cwd(), '.secscan-history');
  const useInMemory = Boolean(options.inMemory);

  if (!useInMemory) {
    loadPersistedSequences(historyDir, savedSequences);
    loadPersistedSystemVariables(historyDir, systemVariables);
    loadPersistedTargetSystems(historyDir, targetSystems);
  }
  if (Array.isArray(options.savedSequences)) {
    for (const item of options.savedSequences) {
      if (item && typeof item === 'object') {
        storeSavedSequence(savedSequences, normalizeLoginSequence(item));
      }
    }
  }
  if (options.systemVariables) {
    storeSystemVariables(systemVariables, options.systemVariables);
  }
  if (Array.isArray(options.targetSystems)) {
    for (const item of options.targetSystems) {
      if (item && typeof item === 'object') {
        try {
          storeTargetSystem(targetSystems, normalizeTargetSystem(item));
        } catch {}
      }
    }
  }

  const ownsGraphStore = !options.graphStore;
  const graphStore = options.graphStore || new GraphStore({
    dbPath: options.graphDbPath || (useInMemory ? ':memory:' : path.join(historyDir, 'secscan-graph.sqlite'))
  });

  const ownsTrafficStore = !options.trafficStore;
  const trafficStore = options.trafficStore || new TrafficStore({
    dbPath: options.trafficDbPath || (useInMemory ? ':memory:' : path.join(historyDir, 'secscan-traffic.sqlite')),
    blobDir: options.trafficBlobDir !== undefined ? options.trafficBlobDir : (useInMemory ? null : path.join(historyDir, 'traffic-blobs'))
  });

  const ownsEvidenceStore = !options.evidenceStore;
  const evidenceStore = options.evidenceStore || new EvidenceStore({
    dbPath: options.evidenceDbPath || (useInMemory ? ':memory:' : path.join(historyDir, 'secscan-evidence.sqlite')),
    blobDir: options.evidenceBlobDir !== undefined ? options.evidenceBlobDir : (useInMemory ? null : path.join(historyDir, 'evidence-blobs')),
    trafficStore
  });

  const llmRecorder = options.llmRecorder || new LlmRecorder();
  const llmPool = options.llmPool || new LlmPool({ recorder: llmRecorder, autoDiscoverEnv: true });
  const aiAdvisor = options.aiAdvisor || new AiAdvisorService({ llmPool });
  const sideQuestionService = options.sideQuestionService || new SideQuestionService({ llmPool });
  let noiseGovernor = options.noiseGovernor || new NoiseGovernor({ profile: options.noiseProfile || 'balanced' });
  const skillRegistry = options.skillRegistry || new SkillRegistry();
  const defaultAllowPrivate = Boolean(options.allowPrivate);
  let scopeRules = Array.isArray(options.scopeRules) ? normalizeScopeRules(options.scopeRules) : [];
  let interceptRules = Array.isArray(options.interceptRules) ? [...options.interceptRules] : [];
  const agentDnsResolver = options.dnsResolver ?? options.retestOptions?.dnsResolver ?? null;
  const agentEngine = options.agentEngine || new AgentEngine({
    graphStore,
    llmPool,
    trafficStore,
    evidenceStore,
    skillRegistry,
    getScopeRules: () => scopeRules,
    ...(agentDnsResolver ? { dnsResolver: agentDnsResolver } : {}),
    ...(options.agentOptions || {})
  });
  const enrichEngine = new EnrichEngine({ allowPrivate: defaultAllowPrivate });
  const taskAllowPrivateMap = new Map();
  const withTaskAllowPrivate = (task) => {
    if (!task) return task;
    const flag = Boolean(task.allowPrivate || task.allow_private || taskAllowPrivateMap.get(task.id));
    return {
      ...task,
      allowPrivate: flag,
      allow_private: flag
    };
  };

  function pruneJobs() {
    if (jobs.size <= MAX_JOBS) return;

    // Evict oldest completed or failed jobs first
    for (const [id, job] of jobs.entries()) {
      if (job.status === 'completed' || job.status === 'failed') {
        jobs.delete(id);
        if (jobs.size <= MAX_JOBS) return;
      }
    }

    // If still over cap, evict oldest jobs
    for (const [id] of jobs.entries()) {
      jobs.delete(id);
      if (jobs.size <= MAX_JOBS) return;
    }
  }

  function buildExecutionContext() {
    return {
      graphStore,
      trafficStore,
      evidenceStore,
      agentEngine,
      recordedSessions,
      savedSequences,
      systemVariables,
      targetSystems,
      historyDir,
      inMemory: useInMemory,
      setTaskAllowPrivate: (taskId, flag) => taskAllowPrivateMap.set(taskId, Boolean(flag)),
      dnsResolver: options.dnsResolver ?? null,
      fetcher: options.fetcher ?? null,
      ...(typeof options.tcpProbe === 'function' ? { tcpProbe: options.tcpProbe } : {}),
      ...(typeof options.portProbe === 'function' ? { portProbe: options.portProbe } : {}),
      ...(typeof options.rtspProbe === 'function' ? { rtspProbe: options.rtspProbe } : {}),
      ...(typeof options.udpProbe === 'function' ? { udpProbe: options.udpProbe } : {}),
      ...(typeof options.tlsProbe === 'function' ? { tlsProbe: options.tlsProbe } : {}),
      ...(typeof options.tlsConnect === 'function' ? { tlsConnect: options.tlsConnect } : {}),
      ...(options.multiPort !== undefined ? { multiPort: options.multiPort } : {}),
      getNoiseGovernor: () => noiseGovernor,
      getScopeRules: () => scopeRules
    };
  }

  async function validateTargetSystemUrls(sys, { checkDns = false } = {}) {
    const allowPrivate = Boolean(sys.allowPrivate);
    const dnsResolver = options.dnsResolver ?? options.retestOptions?.dnsResolver ?? null;
    const rawTargets = Array.isArray(sys.targets) && sys.targets.length > 0 ? sys.targets : [sys.targetUrl];
    const validatedTargets = [];
    for (const rawT of rawTargets) {
      const gated = validateAndGateUrl(rawT, {
        allowPrivate,
        scopeRules,
        normalizeBare: true
      });
      if (!gated.ok) return gated;
      if (checkDns) {
        const dnsCheck = await prevalidateResolvedTarget(gated.url, {
          allowPrivate,
          scopeRules,
          dnsResolver,
          sourceIp: sys.sourceIp || null
        });
        if (!dnsCheck.ok) return dnsCheck;
      }
      if (!validatedTargets.includes(gated.url)) {
        validatedTargets.push(gated.url);
      }
    }
    sys.targets = validatedTargets;
    sys.targetUrl = validatedTargets[0];

    if (sys.loginUrl) {
      const loginGated = validateAndGateUrl(sys.loginUrl, {
        allowPrivate,
        scopeRules,
        normalizeBare: false
      });
      if (!loginGated.ok) return loginGated;
      sys.loginUrl = loginGated.url;
    }

    const hdrValidation = validateCustomHeadersResult(sys.customHeaders);
    if (!hdrValidation.valid) {
      return {
        ok: false,
        status: 400,
        payload: { error: hdrValidation.error }
      };
    }
    sys.customHeaders = hdrValidation.headers;

    if (sys.sequenceId && savedSequences.has(sys.sequenceId) && !sys.sequenceName) {
      sys.sequenceName = savedSequences.get(sys.sequenceId)?.name || sys.sequenceId;
    }

    return { ok: true, system: sys };
  }

  async function launchTargetSystemScan(sys, { runMode = 'full_profile', checks = [] } = {}) {
    const activeRunningJobs = Array.from(jobs.values()).filter(j => j.status === 'running');
    if (activeRunningJobs.length >= 3) {
      return {
        ok: false,
        status: 429,
        payload: {
          error: 'Maximum concurrent scans reached (3). Please wait for an existing scan to finish.'
        }
      };
    }

    const urlValidation = await validateTargetSystemUrls(sys, { checkDns: true });
    if (!urlValidation.ok) return urlValidation;

    let authSessionConfig = null;
    const savedSeq = sys.sequenceId && savedSequences.has(sys.sequenceId)
      ? normalizeLoginSequence(savedSequences.get(sys.sequenceId))
      : null;
    const hasAuthConfig = Boolean(
      sys.sequenceId ||
      savedSeq ||
      sys.recordedSessionId ||
      sys.loginUrl ||
      sys.username
    );
    if (hasAuthConfig) {
      const effectiveVars = Array.from(systemVariables.values());
      authSessionConfig = {
        targetUrl: sys.targetUrl,
        ...(sys.recordedSessionId ? { recordedSessionId: sys.recordedSessionId } : {}),
        ...(sys.sequenceId ? { sequenceId: sys.sequenceId } : {}),
        ...(savedSeq ? { loginSequence: savedSeq } : {}),
        ...(sys.loginUrl ? { loginUrl: sys.loginUrl } : {}),
        ...(sys.username ? { username: sys.username } : {}),
        ...(effectiveVars.length > 0 ? { systemVariables: effectiveVars } : {})
      };
    }

    const effectiveProfile = typeof sys.profile === 'string' && sys.profile.trim() ? sys.profile.trim() : 'smart';
    const isDeviceProfile = effectiveProfile.toLowerCase() === 'device' || DEVICE_PROFILE_ALIASES.has(effectiveProfile.toLowerCase());
    const parsedCat = parseValidatedDeviceCategory(sys.deviceCategory || 'all');
    const effectiveDeviceCat = parsedCat.valid ? parsedCat.category : 'all';
    const effectiveDeviceMode = Boolean(sys.deviceMode) || isDeviceProfile || effectiveDeviceCat !== 'all';

    const scanId = crypto.randomUUID();
    const job = {
      id: scanId,
      status: 'running',
      progress: 0,
      phase: 'initializing',
      targetSystemId: sys.id,
      scanMode: runMode === 'open_issues_only' ? 'open_issues_only' : 'full_profile',
      targets: [...sys.targets],
      profile: effectiveProfile,
      deviceMode: effectiveDeviceMode,
      deviceCategory: effectiveDeviceCat,
      forceAll: Boolean(sys.forceAll),
      allowPrivate: Boolean(sys.allowPrivate),
      noiseProfile: sys.noiseProfile && Object.hasOwn(NOISE_PROFILES, sys.noiseProfile) ? sys.noiseProfile : null,
      agent: Boolean(sys.agentMode),
      goal: sys.goal || null,
      maxDepth: Number.isFinite(Number(sys.maxDepth)) ? Math.max(0, Math.min(Math.floor(Number(sys.maxDepth)), 5)) : 3,
      concurrency: Math.max(1, Math.min(Number(sys.concurrency) || 5, 10)),
      timeout: Math.max(1000, Math.min(Number(sys.timeout) || 10000, 60000)),
      auth: sys.authHeader || null,
      headers: sys.customHeaders || {},
      techOverride: Array.isArray(sys.techOverride) ? [...sys.techOverride] : null,
      noHistory: false,
      sourceIp: sys.sourceIp || null,
      sourceIpMap: null,
      checks: Array.isArray(checks) && checks.length > 0 ? [...checks] : null,
      authSessionConfig,
      authSession: null,
      createdAt: new Date().toISOString(),
      events: [],
      clients: new Set(),
      result: null,
      error: null
    };

    pruneJobs();
    jobs.set(scanId, job);
    executeScanJob(job, buildExecutionContext());

    return { ok: true, job };
  }

  async function runDueScheduledTargetSystems() {
    const triggered = [];
    const nowMs = Date.now();
    for (const sys of targetSystems.values()) {
      if (!sys?.schedule?.enabled || !sys.schedule.nextRunAt) continue;
      const dueMs = Date.parse(sys.schedule.nextRunAt);
      if (Number.isNaN(dueMs) || dueMs > nowMs) continue;

      const activeRunningCount = Array.from(jobs.values()).filter(j => j.status === 'running').length;
      if (activeRunningCount >= 3) break;

      const nowDate = new Date();
      sys.schedule.lastTriggeredAt = nowDate.toISOString();
      sys.schedule.nextRunAt = computeNextScheduleRunAt(sys.schedule, nowDate);
      sys.updatedAt = nowDate.toISOString();
      if (!useInMemory) {
        savePersistedTargetSystems(historyDir, targetSystems);
      }

      const runMode = sys.schedule.mode === 'full_profile' ? 'full_profile' : 'open_issues_only';
      const { checks, fallbackToFullProfile } = resolveChecksForTargetSystemRun(sys, runMode);
      const launched = await launchTargetSystemScan(sys, { runMode, checks });
      if (launched.ok) {
        triggered.push({
          scanId: launched.job.id,
          targetSystemId: sys.id,
          targetSystemName: sys.name,
          mode: runMode,
          checks,
          fallbackToFullProfile
        });
      }
    }
    return triggered;
  }

  const scheduleIntervalMs = Math.max(1000, Number(options.schedulePollIntervalMs) || 15000);
  const scheduleTimer = options.enableScheduler === false
    ? null
    : setInterval(() => {
        runDueScheduledTargetSystems().catch(() => {});
      }, scheduleIntervalMs);
  if (scheduleTimer && typeof scheduleTimer.unref === 'function') {
    scheduleTimer.unref();
  }

  const server = http.createServer(async (req, res) => {
    applySecurityHeaders(res);

    // ── Host & Origin validation on ALL requests ────────────────────────────
    if (!isOriginAndHostAllowed(req)) {
      sendJson(res, 403, { error: 'Forbidden: Invalid Origin or Host header' });
      return;
    }

    const rawPathOnly = String(req.url || '').split('?')[0];
    if (/(?:^|[\\/])\.\.(?:[\\/]|$)|%2e%2e/i.test(rawPathOnly)) {
      sendJson(res, 403, { error: 'Access denied' });
      return;
    }

    let parsedUrl;
    try {
      parsedUrl = new URL(req.url, `http://${req.headers.host || '127.0.0.1'}`);
    } catch {
      sendJson(res, 400, { error: 'Malformed request URL' });
      return;
    }

    const pathname = parsedUrl.pathname;
    const method = req.method ? req.method.toUpperCase() : 'GET';

    // ── API: GET /api/meta ───────────────────────────────────────────────────
    if (method === 'GET' && pathname === '/api/meta') {
      try {
        const scanners = await getScanners();
        const checks = scanners.map(s => ({
          id: s.name,
          tags: s.tags,
          meta: s.meta || getCheckInfo(s.name)
        }));
        const categorySet = new Set();
        for (const c of checks) {
          if (c.meta?.category) categorySet.add(c.meta.category);
        }
        const categories = Array.from(categorySet).sort((a, b) => a.localeCompare(b));
        let cveCoverageSummary = null;
        try {
          const audit = await auditCveCoverage({ scanners });
          cveCoverageSummary = summarizeCveAudit(audit);
        } catch {}

        sendJson(res, 200, {
          version: PKG_VERSION,
          totalChecks: checks.length,
          categories,
          cveCoverageSummary,
          cveDbProviders: Object.values(CVE_DB_PROVIDERS),
          allowPrivate: defaultAllowPrivate,
          presets: PRESETS,
          profiles: PROFILES,
          deviceCategories: DEVICE_CATEGORIES,
          ai: llmPool.getPoolStatus(),
          checks
        });
      } catch (err) {
        sendJson(res, 500, { error: `Failed to load metadata: ${err.message}` });
      }
      return;
    }

    // ── API: GET /api/cves/coverage, POST /api/cves/audit & POST /api/cves/confirm-db ─
    if (method === 'GET' && pathname === '/api/cves/coverage') {
      try {
        const techParam = parsedUrl.searchParams.get('tech') || '';
        const techTags = techParam
          .split(',')
          .map(s => s.trim())
          .filter(Boolean);
        const feedParam = (parsedUrl.searchParams.get('feed') || '').toLowerCase().trim();
        const providerParam = (parsedUrl.searchParams.get('provider') || parsedUrl.searchParams.get('db') || '').trim();
        const dbUrlParam = (parsedUrl.searchParams.get('dbUrl') || parsedUrl.searchParams.get('feedUrl') || '').trim();
        const packagesParam = (parsedUrl.searchParams.get('packages') || parsedUrl.searchParams.get('pkg') || '').trim();
        const includeFeed =
          feedParam === '1' ||
          feedParam === 'true' ||
          feedParam === 'yes' ||
          Boolean(providerParam || dbUrlParam);
        const audit = await auditCveCoverage({
          techTags,
          ...(packagesParam ? { packages: packagesParam } : {}),
          ...(providerParam ? { provider: providerParam } : {}),
          includeFeed,
          allowPrivate: defaultAllowPrivate,
          ...(scopeRules.length ? { scopeRules } : {}),
          ...(agentDnsResolver ? { dnsResolver: agentDnsResolver } : {}),
          ...((dbUrlParam || options.cveFeedUrl) ? { feedUrl: dbUrlParam || options.cveFeedUrl } : {}),
          ...(options.fetcher ? { fetchImpl: options.fetcher } : {})
        });
        sendJson(res, 200, audit);
      } catch (err) {
        sendJson(res, 500, { error: `Failed to audit CVE coverage: ${err.message}` });
      }
      return;
    }

    if (method === 'POST' && (pathname === '/api/cves/audit' || pathname === '/api/cves/confirm-db')) {
      const body = await parseOptionalJsonBody(req, res);
      if (!body) return;
      if (typeof body !== 'object' || Array.isArray(body)) {
        sendJson(res, 400, { error: 'Request body must be a JSON object' });
        return;
      }
      if (body.advisories !== undefined && body.advisories !== null && !Array.isArray(body.advisories)) {
        sendJson(res, 400, { error: 'advisories must be an array' });
        return;
      }
      const isConfirmRoute = pathname === '/api/cves/confirm-db';
      if (
        body.techTags !== undefined &&
        body.techTags !== null &&
        !Array.isArray(body.techTags) &&
        !(isConfirmRoute && typeof body.techTags === 'string')
      ) {
        sendJson(res, 400, { error: 'techTags must be an array' });
        return;
      }
      try {
        const provider = body.provider || body.dbProvider || null;
        const dbUrl = body.dbUrl || body.feedUrl || options.cveFeedUrl || null;
        const auditFn = isConfirmRoute ? confirmCveDatabaseCoverage : auditCveCoverage;
        const audit = await auditFn({
          advisories: body.advisories ?? null,
          externalPayload: body.externalPayload ?? null,
          techTags: body.techTags ?? [],
          packages: body.packages ?? [],
          ...(provider ? { provider } : {}),
          includeFeed: body.includeFeed !== undefined ? Boolean(body.includeFeed) : Boolean(isConfirmRoute && (provider || dbUrl)),
          allowPrivate: defaultAllowPrivate,
          ...(scopeRules.length ? { scopeRules } : {}),
          ...(agentDnsResolver ? { dnsResolver: agentDnsResolver } : {}),
          ...(dbUrl ? { feedUrl: dbUrl } : {}),
          ...(options.fetcher ? { fetchImpl: options.fetcher } : {})
        });
        sendJson(res, 200, audit);
      } catch (err) {
        const status = err instanceof CveCatalogError || err.name === 'CveCatalogError' ? 400 : 500;
        sendJson(res, status, { error: err.message });
      }
      return;
    }

    // ── API: GET /api/cves/labs & POST /api/cves/labs/run ────────────────────
    if (method === 'GET' && pathname === '/api/cves/labs') {
      try {
        sendJson(res, 200, {
          labs: listCveLabs(),
          marketComparison: buildMarketComparisonMatrix()
        });
      } catch (err) {
        const status = (err instanceof CveLabError || err?.name === 'CveLabError')
          ? (Number.isInteger(err.statusCode) && err.statusCode >= 400 && err.statusCode < 600 ? err.statusCode : 400)
          : 500;
        sendJson(res, status, { error: err.message });
      }
      return;
    }

    if (method === 'POST' && pathname === '/api/cves/labs/run') {
      if (cveLabBenchmarkInFlight) {
        sendJson(res, 429, { error: 'A CVE lab benchmark is already in progress. Please wait for it to complete.' });
        return;
      }
      const body = await parseOptionalJsonBody(req, res);
      if (!body) return;
      if (typeof body !== 'object' || Array.isArray(body)) {
        sendJson(res, 400, { error: 'Request body must be a JSON object' });
        return;
      }
      if (
        body.cveIds !== undefined &&
        body.cveIds !== null &&
        typeof body.cveIds !== 'string' &&
        !Array.isArray(body.cveIds)
      ) {
        sendJson(res, 400, { error: 'cveIds must be an array or comma-separated string' });
        return;
      }
      if (cveLabBenchmarkInFlight) {
        sendJson(res, 429, { error: 'A CVE lab benchmark is already in progress. Please wait for it to complete.' });
        return;
      }
      cveLabBenchmarkInFlight = true;
      try {
        const report = await runCveLabBenchmark({
          cveIds: body.cveIds ?? null,
          mode: body.mode || 'emulated'
        });
        sendJson(res, 200, report);
      } catch (err) {
        const status = (err instanceof CveLabError || err?.name === 'CveLabError')
          ? (Number.isInteger(err.statusCode) && err.statusCode >= 400 && err.statusCode < 600 ? err.statusCode : 400)
          : 500;
        sendJson(res, status, { error: err.message });
      } finally {
        cveLabBenchmarkInFlight = false;
      }
      return;
    }

    // ── API: POST /api/cves/labs/scaffold ────────────────────────────────────
    if (method === 'POST' && pathname === '/api/cves/labs/scaffold') {
      const body = await parseJsonBody(req, res);
      if (!body) return;
      if (typeof body !== 'object' || Array.isArray(body)) {
        sendJson(res, 400, { error: 'Request body must be a JSON object' });
        return;
      }
      try {
        // SECURITY: Always enforce DEFAULT_LABS_DIR; never accept untrusted labsDir from HTTP body
        const created = scaffoldCveLab(body.cveId, {
          ...(body.title ? { title: body.title } : {}),
          ...(body.ecosystem ? { ecosystem: body.ecosystem } : {}),
          ...(body.checkId ? { checkId: body.checkId } : {}),
          ...(body.profile ? { profile: body.profile } : {}),
          ...(body.cwe ? { cwe: body.cwe } : {}),
          ...(body.cvssScore !== undefined ? { cvssScore: body.cvssScore } : {}),
          ...(body.defaultPort !== undefined ? { defaultPort: body.defaultPort } : {}),
          overwrite: false,
          labsDir: DEFAULT_LABS_DIR
        });
        sendJson(res, 201, created);
      } catch (err) {
        const status = (err instanceof CveLabError || err?.name === 'CveLabError')
          ? (Number.isInteger(err.statusCode) && err.statusCode >= 400 && err.statusCode < 600 ? err.statusCode : 400)
          : 500;
        sendJson(res, status, { error: err.message });
      }
      return;
    }

    // ── API: GET /api/system/pc-audit ────────────────────────────────────────
    if (method === 'GET' && pathname === '/api/system/pc-audit') {
      if (pcLocalAuditInFlight) {
        sendJson(res, 429, { error: 'A local PC security audit is already in progress.' });
        return;
      }
      pcLocalAuditInFlight = true;
      try {
        const report = await runLocalPcAudit();
        sendJson(res, 200, report);
      } catch (err) {
        sendJson(res, 500, { error: `Local PC audit failed: ${err.message}` });
      } finally {
        pcLocalAuditInFlight = false;
      }
      return;
    }

    // ── API: POST /api/templates/run ─────────────────────────────────────────
    if (method === 'POST' && pathname === '/api/templates/run') {
      const body = await parseJsonBody(req, res);
      if (!body) return;
      if (typeof body !== 'object' || Array.isArray(body)) {
        sendJson(res, 400, { error: 'Request body must be a JSON object' });
        return;
      }
      if (!body.template || (typeof body.template !== 'string' && typeof body.template !== 'object')) {
        sendJson(res, 400, { error: 'template (YAML/JSON string or object) is required' });
        return;
      }
      const rawTargetUrl = body.targetUrl ?? body.target ?? '';
      const effectiveAllowPrivate =
        body.allowPrivate !== undefined ? Boolean(body.allowPrivate) : defaultAllowPrivate;
      const gated = validateAndGateUrl(rawTargetUrl, {
        allowPrivate: effectiveAllowPrivate,
        scopeRules
      });
      if (!gated.ok) {
        sendJson(res, gated.status, gated.payload);
        return;
      }

      const governedFetch = createGovernedFetch({
        ...(scopeRules.length ? { scopeRules } : {}),
        ...(agentDnsResolver ? { dnsResolver: agentDnsResolver } : {}),
        ...(options.fetcher ? { fetcher: options.fetcher } : {}),
        enforceDnsValidation: true,
        allowPrivate: effectiveAllowPrivate,
        retries: 0,
        timeout: 10000
      });

      try {
        const trackedFetch = createTrackedFetch(governedFetch);
        const rawFinding = await runDeclarativeTemplate(body.template, gated.url, trackedFetch, {
          allowPrivate: effectiveAllowPrivate
        });
        const finding = enrichEngine.enrichFinding(rawFinding, {
          allowPrivate: effectiveAllowPrivate,
          capturedTraces: trackedFetch.getTraces()
        });
        sendJson(res, 200, { finding });
      } catch (err) {
        const isValidationErr =
          err instanceof TemplateValidationError || err?.name === 'TemplateValidationError';
        const isGovErr = Boolean(
          err?.isGovernanceBlock ||
          err?.code === 'SSRF_POLICY_BLOCKED' ||
          err?.code === 'TARGET_RULE_BLOCKED' ||
          err?.code === 'DNS_REBIND_OR_PRIVATE_IP'
        );
        const status = isValidationErr ? 400 : isGovErr ? 403 : 400;
        sendJson(res, status, { error: err.message });
      } finally {
        try {
          governedFetch.destroyAgents?.();
        } catch {}
      }
      return;
    }

    // ── API: POST /api/fingerprint ───────────────────────────────────────────
    if (method === 'POST' && pathname === '/api/fingerprint') {
      const body = await parseJsonBody(req, res);
      if (!body) return;

      const { target, auth = null, timeout = 10000, deviceMode = false, deviceCategory = 'all' } = body;
      const parsedCat = parseValidatedDeviceCategory(deviceCategory);
      if (!parsedCat.valid) {
        sendJson(res, 400, { error: parsedCat.error });
        return;
      }
      const effectiveDeviceMode = Boolean(deviceMode) || parsedCat.category !== 'all';
      const allowPrivate = body.allowPrivate !== undefined ? Boolean(body.allowPrivate) : defaultAllowPrivate;
      const dnsResolver = options.dnsResolver ?? options.retestOptions?.dnsResolver ?? null;
      const fetchTimeout = Math.max(1000, Math.min(Number(timeout) || 10000, 60000));
      const rawInputs = typeof target === 'string' && normalizeTargetInput(target) ? [target] : [];
      const bareResolved = await resolveBareIpTargets(rawInputs, {
        allowPrivate,
        ...(scopeRules.length ? { scopeRules } : {}),
        ...(options.fetcher ? { fetcher: options.fetcher } : {}),
        ...(typeof options.tcpProbe === 'function' ? { tcpProbe: options.tcpProbe } : {}),
        timeoutMs: Math.min(fetchTimeout, 3500),
        ...(dnsResolver ? { dnsResolver } : {})
      });
      const validation = validateTargets(bareResolved.targets, { allowPrivate });
      if (!validation.valid) {
        sendJson(res, 400, {
          error: validation.errors.join('; '),
          errors: validation.errors
        });
        return;
      }

      const targetUrl = validation.targets[0];
      const targetPinStore = new TargetPinStore({ allowPrivate });
      for (const candidateUrl of validation.targets) {
        const gate = evaluateAssetGate(candidateUrl, { rules: scopeRules });
        if (!gate.allowed) {
          sendJson(res, 403, { error: gate.reason, code: gate.code || 'TARGET_RULE_BLOCKED' });
          return;
        }
        const preDns = await resolveAndValidateTarget(candidateUrl, {
          resolver: dnsResolver,
          targetPinStore,
          allowPrivate
        });
        if (!preDns.valid && preDns.code === 'DNS_REBIND_OR_PRIVATE_IP') {
          sendJson(res, 403, { error: preDns.reason, code: preDns.code });
          return;
        }
      }

      const authHeaders = auth ? { Authorization: String(auth).trim() } : {};
      const governedFetch = createGovernedFetch({
        ...(scopeRules.length ? { scopeRules } : {}),
        ...(dnsResolver ? { dnsResolver } : {}),
        ...(options.fetcher ? { fetcher: options.fetcher } : {}),
        enforceDnsValidation: true,
        allowPrivate,
        targetPinStore,
        retries: 2,
        timeout: fetchTimeout
      });
      const fetchWithRetry = (url, opts = {}, ...rest) => {
        const safeOpts = opts && typeof opts === 'object' ? opts : {};
        return governedFetch(
          url,
          {
            ...safeOpts,
            headers: { ...authHeaders, ...(safeOpts.headers || {}) }
          },
          ...rest
        );
      };
      fetchWithRetry.governance = governedFetch.governance;
      fetchWithRetry.tlsAlpnProbe = governedFetch.tlsAlpnProbe;
      fetchWithRetry.sourceIp = governedFetch.sourceIp;
      fetchWithRetry.sourceIpMap = governedFetch.sourceIpMap;
      fetchWithRetry.resolveCache = governedFetch.resolveCache;
      fetchWithRetry.targetPinStore = governedFetch.targetPinStore;
      fetchWithRetry.hasCustomFetcher = governedFetch.hasCustomFetcher;
      if (governedFetch.isDefaultFetch !== undefined) {
        fetchWithRetry.isDefaultFetch = governedFetch.isDefaultFetch;
      }

      try {
        const fp = await fingerprint(targetUrl, fetchWithRetry, {
          deviceMode: effectiveDeviceMode,
          deviceCategory: parsedCat.category,
          allowPrivate,
          ...(typeof options.tcpProbe === 'function' ? { tcpProbe: options.tcpProbe } : {}),
          ...(typeof options.portProbe === 'function' ? { portProbe: options.portProbe } : {}),
          ...(typeof options.rtspProbe === 'function' ? { rtspProbe: options.rtspProbe } : {}),
          ...(typeof options.udpProbe === 'function' ? { udpProbe: options.udpProbe } : {}),
          ...(typeof options.tlsProbe === 'function' ? { tlsProbe: options.tlsProbe } : {}),
          ...(options.multiPort !== undefined ? { multiPort: options.multiPort } : {}),
        });
        if (fp.runtimeSca) {
          fp.runtimeSca = sanitizeRuntimeSca(fp.runtimeSca);
        }
        const scanners = await getScanners();
        const isDeviceBasePortClosed = Boolean(
          fp.deviceInfo?.basePortClosed &&
          (fp.deviceInfo?.detected || effectiveDeviceMode)
        );
        const selectionProfile = isDeviceBasePortClosed
          ? (fp.recommendedProfile || 'device')
          : (effectiveDeviceMode ? 'device' : 'smart');
        const selection = selectScannersForStack(scanners, { profile: selectionProfile, fp });
        if (
          isDeviceBasePortClosed &&
          !fp.deviceInfo?.activeHttpOrigin &&
          !fp.deviceInfo?.activeHttpsOrigin
        ) {
          const skippedHttpChecks = selection.activeScanners.filter(s => s.name !== 'device-security');
          if (skippedHttpChecks.length > 0) {
            selection.activeScanners = selection.activeScanners.filter(s => s.name === 'device-security');
            selection.skippedScanners = [...selection.skippedScanners, ...skippedHttpChecks];
          }
        }

        sendJson(res, 200, {
          target: targetUrl,
          targets: validation.targets,
          fingerprint: fp,
          runtimeSca: fp.runtimeSca || null,
          deviceInfo: fp.deviceInfo || null,
          recommendedProfile: fp.recommendedProfile || 'smart',
          activeChecksCount: selection.activeScanners.length,
          skippedChecksCount: selection.skippedScanners.length,
          activeChecks: selection.activeScanners.map(s => ({
            id: s.name,
            title: s.meta?.title || s.name,
            category: s.meta?.category || 'General'
          })),
          skippedChecks: selection.skippedScanners.map(s => ({
            id: s.name,
            title: s.meta?.title || s.name,
            tags: s.tags
          }))
        });
      } catch (err) {
        sendJson(res, 500, { error: `Fingerprint failed: ${err.message}` });
      } finally {
        try {
          governedFetch.destroyAgents?.();
        } catch {}
      }
      return;
    }

    // ── API: POST /api/real-ip ───────────────────────────────────────────────
    if (method === 'POST' && pathname === '/api/real-ip') {
      const body = await parseJsonBody(req, res);
      if (!body) return;

      const rawTarget = typeof body.target === 'string' ? body.target.trim() : '';
      if (!rawTarget) {
        sendJson(res, 400, { error: 'Target URL or domain is required.' });
        return;
      }

      const allowPrivate = body.allowPrivate !== undefined ? Boolean(body.allowPrivate) : defaultAllowPrivate;
      const normalizedTarget = typeof body.target === 'string' ? normalizeTargetInput(body.target) : '';
      if (!normalizedTarget) {
        sendJson(res, 400, { error: 'Target URL or domain is required.' });
        return;
      }

      const dnsResolver = options.dnsResolver ?? options.retestOptions?.dnsResolver ?? null;
      const bareResolved = await resolveBareIpTargets([body.target], {
        allowPrivate,
        ...(scopeRules.length ? { scopeRules } : {}),
        ...(options.fetcher ? { fetcher: options.fetcher } : {}),
        ...(typeof options.tcpProbe === 'function' ? { tcpProbe: options.tcpProbe } : {}),
        timeoutMs: Math.min(Math.max(1000, Number(body.timeout) || 3500), 3500),
        ...(dnsResolver ? { dnsResolver } : {})
      });
      const validation = validateTargets(bareResolved.targets, { allowPrivate });
      if (!validation.valid) {
        sendJson(res, 400, {
          error: validation.errors.join('; '),
          errors: validation.errors
        });
        return;
      }

      const targetUrl = validation.targets[0];
      const gate = evaluateAssetGate(targetUrl, { rules: scopeRules });
      if (!gate.allowed) {
        sendJson(res, 403, { error: gate.reason, code: gate.code || 'TARGET_RULE_BLOCKED' });
        return;
      }

      try {
        const report = await discoverWebsiteRealIp(targetUrl, {
          allowPrivate,
          rules: scopeRules,
          ...(dnsResolver ? { dnsResolver } : {}),
          ...(options.fetcher ? { fetchFn: options.fetcher } : {}),
          verifyCandidates: body.verifyCandidates !== false,
          timeoutMs: Math.max(1000, Math.min(Number(body.timeout) || 6000, 20000))
        });
        sendJson(res, 200, report);
      } catch (err) {
        const status = err.code === 'SSRF_POLICY_BLOCKED' || err.code === 'TARGET_RULE_BLOCKED' ? 403 : 400;
        sendJson(res, status, { error: `Real IP discovery failed: ${err.message}`, code: err.code || 'REAL_IP_ERROR' });
      }
      return;
    }

    // ── API: POST /api/scan ──────────────────────────────────────────────────
    if (method === 'POST' && pathname === '/api/scan') {
      const body = await parseJsonBody(req, res);
      if (!body) return;

      const {
        target,
        targets,
        profile = 'smart',
        maxDepth = 3,
        concurrency = 5,
        timeout = 10000,
        auth = null,
        headers = null,
        techOverride = null,
        forceAll = false,
        noHistory = false,
        agent = false,
        agentMode = false,
        goal = null,
        sourceIp = null,
        sourceIpMap = null,
        authSession = null,
        recordedSessionId = null,
        sequenceId = null,
        loginSequence = null,
        secrets = null,
        otpConfig = null,
        restrictions = null,
        sessionDetection = null,
        loginUrl = null,
        username = null,
        password = null,
        loginType = null,
        loginContentType = null,
        deviceMode = false,
        deviceCategory = 'all',
      } = body;
      const parsedCat = parseValidatedDeviceCategory(deviceCategory);
      if (!parsedCat.valid) {
        sendJson(res, 400, { error: parsedCat.error });
        return;
      }
      const effectiveProfile = typeof profile === 'string' && profile.trim() ? profile.trim() : 'smart';
      const isDeviceProfile = effectiveProfile.toLowerCase() === 'device' || DEVICE_PROFILE_ALIASES.has(effectiveProfile.toLowerCase());
      const effectiveDeviceMode = Boolean(deviceMode) || isDeviceProfile || parsedCat.category !== 'all';
      // SECURITY BOUNDARY (T2.1): Never auto-enable allowPrivate from profile or deviceMode.
      const allowPrivate = body.allowPrivate !== undefined ? Boolean(body.allowPrivate) : defaultAllowPrivate;
      const cleanSourceIp = typeof sourceIp === 'string' && sourceIp.trim() ? sourceIp.trim() : null;
      const cleanSourceIpMap = sourceIpMap && (typeof sourceIpMap === 'object' || typeof sourceIpMap === 'string')
        ? sourceIpMap
        : null;

      const headerValidation = validateCustomHeadersResult(headers);
      if (!headerValidation.valid) {
        sendJson(res, 400, { error: headerValidation.error });
        return;
      }
      const validatedCustomHeaders = headerValidation.headers;

      let requestedNoiseProfile = null;
      if (body.noiseProfile !== undefined && body.noiseProfile !== null && body.noiseProfile !== '') {
        const normNoise = String(body.noiseProfile).trim().toLowerCase();
        if (!Object.hasOwn(NOISE_PROFILES, normNoise)) {
          sendJson(res, 400, {
            error: `Invalid noiseProfile "${body.noiseProfile}". Expected off, quiet, balanced, or aggressive.`
          });
          return;
        }
        requestedNoiseProfile = normNoise;
      }

      const rawDepth = maxDepth !== undefined && maxDepth !== null && maxDepth !== ''
        ? Number(maxDepth)
        : 3;
      if (!Number.isFinite(rawDepth)) {
        sendJson(res, 400, { error: 'Invalid maxDepth: must be a finite number' });
        return;
      }
      const effectiveMaxDepth = Math.max(0, Math.min(Math.floor(rawDepth), 5));

      const dnsResolver = options.dnsResolver ?? options.retestOptions?.dnsResolver ?? null;
      if (Array.isArray(targets) && targets.length > MAX_SCAN_TARGETS) {
        sendJson(res, 400, {
          error: `Too many targets (${targets.length}). Maximum allowed per scan is ${MAX_SCAN_TARGETS}.`
        });
        return;
      }
      const rawInputTargets = Array.isArray(targets)
        ? targets.filter(t => (typeof t === 'string' ? Boolean(normalizeTargetInput(t)) : Boolean(t)))
        : typeof target === 'string' && normalizeTargetInput(target)
        ? [target]
        : [];
      if (rawInputTargets.length > MAX_SCAN_TARGETS) {
        sendJson(res, 400, {
          error: `Too many targets (${rawInputTargets.length}). Maximum allowed per scan is ${MAX_SCAN_TARGETS}.`
        });
        return;
      }
      if (rawInputTargets.length === 0) {
        sendJson(res, 400, {
          error: 'No target URLs provided',
          errors: ['No target URLs provided']
        });
        return;
      }

      // Concurrency check (max 3 concurrent scans) — enforced BEFORE any network probing or DNS resolution
      const activeRunningJobsEarly = Array.from(jobs.values()).filter(
        j => j.status === 'running'
      );
      if (activeRunningJobsEarly.length >= 3) {
        sendJson(res, 429, {
          error: 'Maximum concurrent scans reached (3). Please wait for an existing scan to finish.'
        });
        return;
      }

      const bareResolved = await resolveBareIpTargets(rawInputTargets, {
        allowPrivate,
        ...(scopeRules.length ? { scopeRules } : {}),
        ...(options.fetcher ? { fetcher: options.fetcher } : {}),
        ...(typeof options.tcpProbe === 'function' ? { tcpProbe: options.tcpProbe } : {}),
        timeoutMs: Math.min(Math.max(1000, Number(timeout) || 10000), 3500),
        ...(cleanSourceIp ? { sourceIp: cleanSourceIp } : {}),
        ...(cleanSourceIpMap ? { sourceIpMap: cleanSourceIpMap } : {}),
        ...(dnsResolver ? { dnsResolver } : {})
      });
      const validation = validateTargets(bareResolved.targets, { allowPrivate });
      if (!validation.valid) {
        sendJson(res, 400, {
          error: validation.errors.join('; '),
          errors: validation.errors
        });
        return;
      }

      for (const validatedTarget of validation.targets) {
        const gate = evaluateAssetGate(validatedTarget, { rules: scopeRules });
        if (!gate.allowed) {
          sendJson(res, 403, { error: gate.reason, code: gate.code || 'TARGET_RULE_BLOCKED' });
          return;
        }
        const preDns = await resolveAndValidateTarget(validatedTarget, {
          resolver: dnsResolver,
          allowPrivate,
          ...(cleanSourceIp ? { sourceIp: cleanSourceIp } : {}),
          ...(cleanSourceIpMap ? { sourceIpMap: cleanSourceIpMap } : {})
        });
        if (!preDns.valid && preDns.code === 'INVALID_SOURCE_IP') {
          sendJson(res, 400, { error: preDns.reason, code: preDns.code });
          return;
        }
        if (!preDns.valid && preDns.code === 'DNS_REBIND_OR_PRIVATE_IP') {
          sendJson(res, 403, { error: preDns.reason, code: preDns.code });
          return;
        }
        if (preDns.valid && Array.isArray(preDns.resolvedIps) && preDns.resolvedIps.length > 0 && scopeRules.length) {
          const postDnsGate = evaluateAssetGate(
            { url: validatedTarget, hostname: preDns.hostname, resolvedIps: preDns.resolvedIps },
            { rules: scopeRules }
          );
          if (!postDnsGate.allowed) {
            sendJson(res, 403, { error: postDnsGate.reason, code: postDnsGate.code || 'TARGET_RULE_BLOCKED' });
            return;
          }
        }
      }

      const hasAuthSessionObj = Boolean(authSession && typeof authSession === 'object' && !Array.isArray(authSession));
      const rawSystemVariables = body.systemVariables ?? (hasAuthSessionObj ? authSession.systemVariables : null);
      const scanVarsMap = new Map(systemVariables);
      if (rawSystemVariables) {
        storeSystemVariables(scanVarsMap, rawSystemVariables);
      }
      const effectiveSecrets = secrets ?? (hasAuthSessionObj ? authSession.secrets : null);

      if (loginUrl !== null && loginUrl !== undefined && typeof loginUrl !== 'string') {
        sendJson(res, 400, { error: 'Invalid loginUrl: must be a URL string' });
        return;
      }
      const effectiveLoginUrl = typeof loginUrl === 'string' && loginUrl.trim()
        ? loginUrl.trim()
        : (hasAuthSessionObj && typeof authSession.loginUrl === 'string' && authSession.loginUrl.trim()
          ? authSession.loginUrl.trim()
          : null);
      let validatedLoginUrl = null;
      if (effectiveLoginUrl) {
        const resolvedLoginInfo = resolveUrlPlaceholders(effectiveLoginUrl, {
          systemVariables: Array.from(scanVarsMap.values()),
          secrets: effectiveSecrets
        });
        const loginCheck = validateAndGateUrl(resolvedLoginInfo.resolvedUrl, { allowPrivate, scopeRules, normalizeBare: false });
        if (!loginCheck.ok) {
          sendJson(res, loginCheck.status, loginCheck.payload);
          return;
        }
        validatedLoginUrl = loginCheck.url;
      }
      let validatedAuthTargetUrl = null;
      if (hasAuthSessionObj && typeof authSession.targetUrl === 'string' && authSession.targetUrl.trim()) {
        const resolvedAuthTarget = resolveUrlPlaceholders(authSession.targetUrl, {
          systemVariables: Array.from(scanVarsMap.values()),
          secrets: effectiveSecrets
        });
        const authTargetCheck = validateAndGateUrl(resolvedAuthTarget.resolvedUrl, { allowPrivate, scopeRules, normalizeBare: false });
        if (!authTargetCheck.ok) {
          sendJson(res, authTargetCheck.status, authTargetCheck.payload);
          return;
        }
        validatedAuthTargetUrl = authTargetCheck.url;
      }

      const cleanRecordedSessionId = typeof recordedSessionId === 'string' && recordedSessionId.trim()
        ? recordedSessionId.trim()
        : (hasAuthSessionObj && typeof authSession.recordedSessionId === 'string' && authSession.recordedSessionId.trim()
          ? authSession.recordedSessionId.trim()
          : null);
      const rawSequenceId = sequenceId ?? (hasAuthSessionObj ? authSession.sequenceId : null);
      const cleanSequenceId = typeof rawSequenceId === 'string' && rawSequenceId.trim()
        ? rawSequenceId.trim()
        : null;
      const rawLoginSequence = loginSequence ?? (hasAuthSessionObj ? authSession.loginSequence : null);
      const effectiveOtpConfig = otpConfig ?? (hasAuthSessionObj ? authSession.otpConfig : null);
      const effectiveRestrictions = restrictions ?? (hasAuthSessionObj ? authSession.restrictions : null);
      const effectiveSessionDetection = sessionDetection ?? (hasAuthSessionObj ? authSession.sessionDetection : null);

      const savedSeqForScan = cleanSequenceId && savedSequences.has(cleanSequenceId)
        ? savedSequences.get(cleanSequenceId)
        : null;
      let validatedLoginSequence = null;
      if (rawLoginSequence !== null && rawLoginSequence !== undefined) {
        try {
          const parsedSeq = parseLsrSequence(rawLoginSequence);
          const matchingSaved = savedSeqForScan ||
            (parsedSeq.sequenceId && savedSequences.has(parsedSeq.sequenceId)
              ? savedSequences.get(parsedSeq.sequenceId)
              : null);
          validatedLoginSequence = mergeSavedSequenceSecrets(parsedSeq, matchingSaved);
        } catch (err) {
          sendJson(res, 400, { error: err.message });
          return;
        }
      } else if (savedSeqForScan) {
        validatedLoginSequence = normalizeLoginSequence(savedSeqForScan);
      }

      const effectiveScanSystemVariables = Array.from(scanVarsMap.values());
      if (validatedLoginSequence) {
        let resolvedSeqBaseUrl = null;
        if (validatedLoginSequence.targetUrl) {
          const resolvedSeqTarget = resolveUrlPlaceholders(validatedLoginSequence.targetUrl, {
            systemVariables: effectiveScanSystemVariables,
            secrets: effectiveSecrets ?? validatedLoginSequence.secrets
          });
          const seqTargetCheck = validateAndGateUrl(resolvedSeqTarget.resolvedUrl, {
            allowPrivate,
            scopeRules,
            normalizeBare: true
          });
          if (!seqTargetCheck.ok) {
            sendJson(res, seqTargetCheck.status, seqTargetCheck.payload);
            return;
          }
          const seqTargetDns = await prevalidateResolvedTarget(seqTargetCheck.url, {
            allowPrivate,
            scopeRules,
            dnsResolver,
            sourceIp: cleanSourceIp,
            sourceIpMap: cleanSourceIpMap
          });
          if (!seqTargetDns.ok) {
            sendJson(res, seqTargetDns.status, seqTargetDns.payload);
            return;
          }
          resolvedSeqBaseUrl = seqTargetCheck.url;
          if (!resolvedSeqTarget.hadPlaceholder) {
            validatedLoginSequence.targetUrl = seqTargetCheck.url;
          }
        }
        const seqActionsCheck = await validateSequenceActionUrls(validatedLoginSequence, {
          allowPrivate,
          scopeRules,
          dnsResolver,
          baseUrl: resolvedSeqBaseUrl || validatedAuthTargetUrl || validation.targets[0] || null,
          sourceIp: cleanSourceIp,
          sourceIpMap: cleanSourceIpMap,
          systemVariables: effectiveScanSystemVariables,
          secrets: effectiveSecrets ?? validatedLoginSequence.secrets
        });
        if (!seqActionsCheck.ok) {
          sendJson(res, seqActionsCheck.status, seqActionsCheck.payload);
          return;
        }
      }

      const effectiveLoginContentType = loginContentType ?? loginType ?? (hasAuthSessionObj ? (authSession.loginContentType ?? authSession.loginType ?? null) : null);
      const hasAuthSessionConfig = Boolean(
        authSession ||
        cleanRecordedSessionId ||
        cleanSequenceId ||
        validatedLoginSequence?.actions?.length ||
        validatedLoginUrl ||
        (username !== null && username !== undefined && String(username) !== '') ||
        (password !== null && password !== undefined && String(password) !== '') ||
        (Array.isArray(effectiveRestrictions) && effectiveRestrictions.length > 0) ||
        (effectiveOtpConfig && typeof effectiveOtpConfig === 'object' && !Array.isArray(effectiveOtpConfig)) ||
        (effectiveSecrets && (Array.isArray(effectiveSecrets) ? effectiveSecrets.length > 0 : (typeof effectiveSecrets === 'object' && Object.keys(effectiveSecrets).length > 0)))
      );
      const authSessionConfig = hasAuthSessionConfig
        ? {
            ...(hasAuthSessionObj ? authSession : {}),
            ...(validatedAuthTargetUrl ? { targetUrl: validatedAuthTargetUrl } : {}),
            ...(cleanRecordedSessionId ? { recordedSessionId: cleanRecordedSessionId } : {}),
            ...(cleanSequenceId ? { sequenceId: cleanSequenceId } : {}),
            ...(validatedLoginSequence ? { loginSequence: validatedLoginSequence } : {}),
            ...(effectiveSecrets !== null && effectiveSecrets !== undefined ? { secrets: effectiveSecrets } : {}),
            ...(effectiveScanSystemVariables.length > 0 ? { systemVariables: effectiveScanSystemVariables } : {}),
            ...(effectiveOtpConfig !== null && effectiveOtpConfig !== undefined ? { otpConfig: effectiveOtpConfig } : {}),
            ...(effectiveRestrictions !== null && effectiveRestrictions !== undefined ? { restrictions: effectiveRestrictions } : {}),
            ...(effectiveSessionDetection !== null && effectiveSessionDetection !== undefined ? { sessionDetection: effectiveSessionDetection } : {}),
            ...(validatedLoginUrl ? { loginUrl: validatedLoginUrl } : {}),
            ...(username !== null && username !== undefined ? { username: String(username) } : {}),
            ...(password !== null && password !== undefined ? { password: String(password) } : {}),
            ...(loginType !== null && loginType !== undefined ? { loginType: String(loginType) } : {}),
            ...(effectiveLoginContentType !== null && effectiveLoginContentType !== undefined
              ? { loginContentType: String(effectiveLoginContentType) }
              : {})
          }
        : null;

      // Concurrency check (max 3 concurrent scans)
      const activeRunningJobs = Array.from(jobs.values()).filter(
        j => j.status === 'running'
      );
      if (activeRunningJobs.length >= 3) {
        sendJson(res, 429, {
          error: 'Maximum concurrent scans reached (3). Please wait for an existing scan to finish.'
        });
        return;
      }

      let resolvedTargetSystemId = typeof body.targetSystemId === 'string' && body.targetSystemId.trim()
        ? body.targetSystemId.trim()
        : null;
      const resolvedScanMode = body.scanMode === 'open_issues_only' ? 'open_issues_only' : 'full_profile';

      if (body.saveAsTargetSystem && !resolvedTargetSystemId) {
        try {
          const saveOpts = typeof body.saveAsTargetSystem === 'object' && !Array.isArray(body.saveAsTargetSystem)
            ? body.saveAsTargetSystem
            : {};
          const newSys = normalizeTargetSystem({
            ...body,
            ...saveOpts,
            targetUrl: validation.targets[0],
            targets: validation.targets,
            profile: effectiveProfile,
            deviceMode: effectiveDeviceMode,
            deviceCategory: parsedCat.category,
            allowPrivate,
            noiseProfile: requestedNoiseProfile || 'balanced',
            maxDepth: effectiveMaxDepth,
            sequenceId: cleanSequenceId,
            sequenceName: savedSeqForScan?.name || saveOpts.sequenceName || null,
            recordedSessionId: cleanRecordedSessionId,
            loginUrl: validatedLoginUrl,
            username: username !== null && username !== undefined ? String(username) : null,
            authHeader: typeof auth === 'string' && auth.trim() ? auth.trim() : null,
            customHeaders: validatedCustomHeaders
          });
          storeTargetSystem(targetSystems, newSys);
          if (!useInMemory) {
            savePersistedTargetSystems(historyDir, targetSystems);
          }
          resolvedTargetSystemId = newSys.id;
        } catch {}
      }

      const scanId = crypto.randomUUID();
      const job = {
        id: scanId,
        status: 'running',
        progress: 0,
        phase: 'initializing',
        targetSystemId: resolvedTargetSystemId,
        scanMode: resolvedScanMode,
        targets: validation.targets,
        profile: effectiveProfile,
        deviceMode: effectiveDeviceMode,
        deviceCategory: parsedCat.category,
        forceAll: Boolean(forceAll),
        allowPrivate,
        noiseProfile: requestedNoiseProfile,
        agent: Boolean(agent || agentMode),
        goal: typeof goal === 'string' && goal.trim() ? goal.trim() : null,
        maxDepth: effectiveMaxDepth,
        concurrency: Math.max(1, Math.min(Number(concurrency) || 5, 10)),
        timeout: Math.max(1000, Math.min(Number(timeout) || 10000, 60000)),
        auth: typeof auth === 'string' && auth.trim() ? auth.trim() : null,
        headers: validatedCustomHeaders,
        techOverride: Array.isArray(techOverride)
          ? techOverride
          : typeof techOverride === 'string' && techOverride.trim()
          ? techOverride.split(',').map(s => s.trim()).filter(Boolean)
          : null,
        noHistory: Boolean(noHistory),
        sourceIp: cleanSourceIp,
        sourceIpMap: cleanSourceIpMap,
        checks: Array.isArray(body.checks)
          ? body.checks.map(s => String(s).trim()).filter(Boolean)
          : typeof body.checks === 'string' && body.checks.trim()
            ? body.checks.split(',').map(s => s.trim()).filter(Boolean)
            : null,
        authSessionConfig,
        authSession: null,
        createdAt: new Date().toISOString(),
        events: [],
        clients: new Set(),
        result: null,
        error: null
      };

      pruneJobs();
      jobs.set(scanId, job);

      // Launch async scan
      executeScanJob(job, buildExecutionContext());

      sendJson(res, 202, {
        scanId,
        targets: validation.targets,
        profile: job.profile,
        deviceMode: job.deviceMode,
        deviceCategory: job.deviceCategory,
        allowPrivate,
        ...(resolvedTargetSystemId ? { targetSystemId: resolvedTargetSystemId } : {}),
        scanMode: resolvedScanMode
      });
      return;
    }

    // ── API: GET /api/scan/:id/stream (SSE) ──────────────────────────────────
    const streamMatch = pathname.match(/^\/api\/scan\/([a-zA-Z0-9_-]+)\/stream$/);
    if (method === 'GET' && streamMatch) {
      const scanId = streamMatch[1];
      const job = jobs.get(scanId);

      if (!job) {
        sendJson(res, 404, { error: 'Scan job not found' });
        return;
      }

      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache, no-transform',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no'
      });

      // Stream buffered prior events
      for (const evt of job.events) {
        const eventName = evt.type || 'message';
        res.write(`event: ${eventName}\ndata: ${JSON.stringify(evt)}\n\n`);
      }

      if (job.status === 'completed' || job.status === 'failed') {
        res.end();
      } else {
        job.clients.add(res);
        req.on('close', () => {
          job.clients.delete(res);
        });
      }
      return;
    }

    // ── API: GET /api/scan/:id ───────────────────────────────────────────────
    const scanMatch = pathname.match(/^\/api\/scan\/([a-zA-Z0-9_-]+)$/);
    if (method === 'GET' && scanMatch) {
      const scanId = scanMatch[1];
      const job = jobs.get(scanId);

      if (!job) {
        sendJson(res, 404, { error: 'Scan job not found' });
        return;
      }

      sendJson(res, 200, {
        id: job.id,
        status: job.status,
        progress: job.progress,
        phase: job.phase,
        targets: job.targets,
        result: job.result,
        error: job.error
      });
      return;
    }

    // ── API: GET /api/history ────────────────────────────────────────────────
    if (method === 'GET' && pathname === '/api/history') {
      try {
        const history = listHistory();
        sendJson(res, 200, { history });
      } catch (err) {
        sendJson(res, 500, { error: `Failed to retrieve history: ${err.message}` });
      }
      return;
    }

    // ── API: GET /api/history/:id ────────────────────────────────────────────
    const historyMatch = pathname.match(/^\/api\/history\/([a-zA-Z0-9._-]+\.json)$/);
    if (method === 'GET' && historyMatch) {
      const historyId = historyMatch[1];
      const record = loadHistoryById(historyId);

      if (!record) {
        sendJson(res, 404, { error: 'History record not found' });
        return;
      }

      // Enrich results with plain-English metadata
      if (Array.isArray(record.results)) {
        record.results = record.results.map(r => ({
          ...r,
          meta: r.meta || getCheckInfo(r.checkId || r.name)
        }));
      }
      if (!record.apiCommunication) {
        const mergedApi = mergeApiCommunication(record.stacks, record.results);
        if (mergedApi) record.apiCommunication = mergedApi;
      }
      if (!record.runtimeSca) {
        const mergedSca = mergeRuntimeSca(record.stacks, record.results);
        if (mergedSca) record.runtimeSca = mergedSca;
      }

      sendJson(res, 200, { record });
      return;
    }

    // ── API: POST /api/diff ──────────────────────────────────────────────────
    if (method === 'POST' && pathname === '/api/diff') {
      const body = await parseJsonBody(req, res);
      if (!body) return;

      const { previousId, currentId, currentResults } = body;
      if (!previousId) {
        sendJson(res, 400, { error: 'previousId is required' });
        return;
      }

      const prevRecord = loadHistoryById(previousId);
      if (!prevRecord) {
        sendJson(res, 404, { error: `Previous history record "${previousId}" not found` });
        return;
      }

      let currFindings = null;
      if (currentId) {
        const currRecord = loadHistoryById(currentId);
        if (!currRecord) {
          sendJson(res, 404, { error: `Current history record "${currentId}" not found` });
          return;
        }
        currFindings = currRecord.results;
      } else if (currentResults) {
        currFindings = Array.isArray(currentResults)
          ? currentResults
          : currentResults.results || [];
      } else {
        sendJson(res, 400, { error: 'Either currentId or currentResults must be provided' });
        return;
      }

      const diff = diffScans(prevRecord, currFindings);
      sendJson(res, 200, { diff });
      return;
    }

    // ── API: POST /api/report/html ───────────────────────────────────────────
    if (method === 'POST' && pathname === '/api/report/html') {
      const body = await parseJsonBody(req, res);
      if (!body) return;

      let { historyId, results, risk, stacks, cveCoverage, apiCommunication, runtimeSca } = body;

      if (historyId) {
        const record = loadHistoryById(historyId);
        if (!record) {
          sendJson(res, 404, { error: `History record "${historyId}" not found` });
          return;
        }
        results = record.results;
        risk = record.risk;
        if (!stacks && record.stacks) {
          stacks = record.stacks;
        }
        if (!cveCoverage && record.cveCoverage) {
          cveCoverage = record.cveCoverage;
        }
        if (!apiCommunication && record.apiCommunication) {
          apiCommunication = record.apiCommunication;
        }
        if (!runtimeSca && record.runtimeSca) {
          runtimeSca = record.runtimeSca;
        }
      }

      if (!Array.isArray(results)) {
        sendJson(res, 400, { error: 'A valid results array or historyId is required' });
        return;
      }

      try {
        const computedRisk = risk || calculateRisk(results);
        const resolvedApi = mergeApiCommunication(stacks, results, apiCommunication);
        const resolvedSca = mergeRuntimeSca(stacks, results, runtimeSca);
        const reportOpts = (cveCoverage || resolvedApi || resolvedSca)
          ? {
              ...(cveCoverage ? { cveCoverage } : {}),
              ...(resolvedApi ? { apiCommunication: resolvedApi } : {}),
              ...(resolvedSca ? { runtimeSca: resolvedSca } : {})
            }
          : null;
        const html = generateHtmlReport(results, computedRisk, stacks, reportOpts);
        sendJson(res, 200, { html });
      } catch (err) {
        sendJson(res, 500, { error: 'Failed to generate HTML report: ' + err.message });
      }
      return;
    }

    // ── API: POST /api/checks/scaffold ───────────────────────────────────────
    if (method === 'POST' && pathname === '/api/checks/scaffold') {
      const body = await parseJsonBody(req, res);
      if (!body) return;

      const {
        name,
        title,
        category,
        plainExplanation,
        whyItMatters,
        defaultFix,
        tags,
        cveIds,
        cwe,
        owasp,
        cvssScore,
        dryRun
      } = body;

      if (!name || typeof name !== 'string') {
        sendJson(res, 400, { error: 'Check name string is required' });
        return;
      }

      try {
        const result = scaffoldCheck(name, {
          title,
          category,
          plainExplanation,
          whyItMatters,
          defaultFix,
          tags,
          cveIds,
          cwe,
          owasp,
          cvssScore,
          dryRun: Boolean(dryRun)
        });
        sendJson(res, 200, result);
      } catch (err) {
        sendJson(res, 400, { error: err.message });
      }
      return;
    }

    // ── API: GET /api/scan/:id/export ────────────────────────────────────────
    const scanExportMatch = pathname.match(/^\/api\/scan\/([a-zA-Z0-9._-]+)\/export$/);
    if (method === 'GET' && scanExportMatch) {
      const exportId = scanExportMatch[1];
      const format = (parsedUrl.searchParams.get('format') || 'json').toLowerCase();

      let exportData = null;
      const job = jobs.get(exportId);
      if (job && job.result) {
        exportData = {
          targets: job.targets,
          results: job.result.results || [],
          risk: job.result.risk || calculateRisk(job.result.results || []),
          stacks: job.result.stacks || null,
          apiCommunication: job.result.apiCommunication || mergeApiCommunication(job.result.stacks, job.result.results) || null,
          runtimeSca: job.result.runtimeSca || mergeRuntimeSca(job.result.stacks, job.result.results) || null,
          cveCoverage: job.result.cveCoverage || null
        };
      } else {
        const hist = loadHistoryById(exportId);
        if (hist) {
          exportData = {
            targets: hist.targets || [],
            results: hist.results || [],
            risk: hist.risk || calculateRisk(hist.results || []),
            stacks: hist.stacks || null,
            apiCommunication: hist.apiCommunication || mergeApiCommunication(hist.stacks, hist.results) || null,
            runtimeSca: hist.runtimeSca || mergeRuntimeSca(hist.stacks, hist.results) || null,
            cveCoverage: hist.cveCoverage || null
          };
        } else {
          const task = graphStore.getTask(exportId);
          if (task) {
            const findingNodes = graphStore.listNodes(task.id, { node_type: 'finding' });
            const taskResults = findingNodes.map(n => ({
              ...(n.data && typeof n.data === 'object' ? n.data : {}),
              checkId: n.data?.checkId || n.title,
              name: n.title,
              status: n.status === 'verified' || n.status === 'confirmed' ? 'VULNERABLE' : 'SUSPICIOUS',
              severity: n.severity || 'MEDIUM',
              reason: n.summary || ''
            }));
            const taskAssets = graphStore.queryAssets({ taskId: task.id, limit: 1000 }).items;
            exportData = {
              targets: task.target ? [task.target] : [],
              results: taskResults,
              risk: calculateRisk(taskResults),
              stacks: null,
              cveCoverage: null,
              assets: taskAssets
            };
          }
        }
      }

      if (!exportData) {
        sendJson(res, 404, { error: 'Scan or history record not found' });
        return;
      }

      const safeFileId = exportId.replace(/[^a-zA-Z0-9._-]/g, '_');
      if (format === 'markdown' || format === 'md') {
        const md = generateMarkdownReport(exportData);
        const buf = Buffer.from(md, 'utf8');
        res.writeHead(200, {
          'Content-Type': 'text/markdown; charset=utf-8',
          'Content-Length': buf.length,
          'Content-Disposition': `attachment; filename="security-report-${safeFileId}.md"`
        });
        res.end(buf);
        return;
      }

      if (format === 'csv') {
        const csvStr = generateCsvReport(exportData);
        const buf = Buffer.from(csvStr, 'utf8');
        res.writeHead(200, {
          'Content-Type': 'text/csv; charset=utf-8',
          'Content-Length': buf.length,
          'Content-Disposition': `attachment; filename="security-report-${safeFileId}.csv"`
        });
        res.end(buf);
        return;
      }

      if (format === 'html') {
        const htmlOpts = (exportData.cveCoverage || exportData.apiCommunication || exportData.runtimeSca)
          ? {
              ...(exportData.cveCoverage ? { cveCoverage: exportData.cveCoverage } : {}),
              ...(exportData.apiCommunication ? { apiCommunication: exportData.apiCommunication } : {}),
              ...(exportData.runtimeSca ? { runtimeSca: exportData.runtimeSca } : {})
            }
          : null;
        const htmlStr = generateHtmlReport(
          exportData.results,
          exportData.risk,
          exportData.stacks,
          htmlOpts
        );
        const buf = Buffer.from(htmlStr, 'utf8');
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Length': buf.length,
          'Content-Disposition': `attachment; filename="security-report-${safeFileId}.html"`
        });
        res.end(buf);
        return;
      }

      if (format === 'sarif') {
        const sarifObj = generateSarifReport(exportData, { version: PKG_VERSION });
        const buf = Buffer.from(JSON.stringify(sarifObj, null, 2), 'utf8');
        res.writeHead(200, {
          'Content-Type': 'application/sarif+json; charset=utf-8',
          'Content-Length': buf.length,
          'Content-Disposition': `attachment; filename="security-report-${safeFileId}.sarif"`
        });
        res.end(buf);
        return;
      }

      if (format === 'json') {
        const jsonOpts = (exportData.cveCoverage || exportData.apiCommunication || exportData.runtimeSca)
          ? {
              ...(exportData.cveCoverage ? { cveCoverage: exportData.cveCoverage } : {}),
              ...(exportData.apiCommunication ? { apiCommunication: exportData.apiCommunication } : {}),
              ...(exportData.runtimeSca ? { runtimeSca: exportData.runtimeSca } : {})
            }
          : null;
        const report = generateReport(
          exportData.results,
          exportData.risk,
          exportData.stacks,
          jsonOpts
        );
        sendJson(res, 200, report);
        return;
      }

      sendJson(res, 400, { error: 'Unsupported export format. Expected markdown, csv, html, sarif, or json.' });
      return;
    }

    // ── API: Tasks & Agent Sessions ──────────────────────────────────────────
    if (method === 'GET' && pathname === '/api/tasks') {
      const status = parsedUrl.searchParams.get('status') || undefined;
      const mode = parsedUrl.searchParams.get('mode') || undefined;
      const tasks = graphStore.listTasks({
        ...(status ? { status } : {}),
        ...(mode ? { mode } : {})
      }).map(withTaskAllowPrivate);
      sendJson(res, 200, { tasks });
      return;
    }

    if (method === 'POST' && pathname === '/api/tasks') {
      const body = await parseJsonBody(req, res);
      if (!body) return;

      const allowPrivate =
        body.allowPrivate !== undefined || body.allow_private !== undefined
          ? Boolean(body.allowPrivate ?? body.allow_private)
          : defaultAllowPrivate;
      const rawTargetInput = typeof body.target === 'string' ? body.target.trim() : '';
      const rawTarget = rawTargetInput ? normalizeTargetInput(rawTargetInput) : '';
      const rawTitle = typeof body.title === 'string' ? body.title.trim() : '';
      if (!rawTarget && !rawTitle) {
        sendJson(res, 400, { error: 'target or title is required' });
        return;
      }

      let validatedTarget = rawTarget;
      if (rawTargetInput) {
        const validation = validateTargets([rawTarget], { allowPrivate });
        if (!validation.valid) {
          sendJson(res, 400, {
            error: validation.errors.join('; '),
            errors: validation.errors
          });
          return;
        }
        validatedTarget = validation.targets[0];
        const gate = evaluateAssetGate(validatedTarget, { rules: scopeRules });
        if (!gate.allowed) {
          sendJson(res, 403, { error: gate.reason, code: gate.code || 'TARGET_RULE_BLOCKED' });
          return;
        }

        const dnsResolver = options.dnsResolver ?? options.retestOptions?.dnsResolver ?? null;
        const taskSourceIp = typeof body.sourceIp === 'string' && body.sourceIp.trim() ? body.sourceIp.trim() : null;
        const taskSourceIpMap = body.sourceIpMap && (typeof body.sourceIpMap === 'object' || typeof body.sourceIpMap === 'string')
          ? body.sourceIpMap
          : null;
        const preDns = await resolveAndValidateTarget(validatedTarget, {
          resolver: dnsResolver,
          allowPrivate,
          ...(taskSourceIp ? { sourceIp: taskSourceIp } : {}),
          ...(taskSourceIpMap ? { sourceIpMap: taskSourceIpMap } : {})
        });
        if (!preDns.valid && preDns.code === 'INVALID_SOURCE_IP') {
          sendJson(res, 400, { error: preDns.reason, code: preDns.code });
          return;
        }
        if (!preDns.valid && preDns.code === 'DNS_REBIND_OR_PRIVATE_IP') {
          sendJson(res, 403, { error: preDns.reason, code: preDns.code });
          return;
        }
        if (preDns.valid && Array.isArray(preDns.resolvedIps) && preDns.resolvedIps.length > 0) {
          const postDnsGate = evaluateAssetGate(
            { url: validatedTarget, hostname: preDns.hostname, resolvedIps: preDns.resolvedIps },
            { rules: scopeRules }
          );
          if (!postDnsGate.allowed) {
            sendJson(res, 403, { error: postDnsGate.reason, code: postDnsGate.code || 'TARGET_RULE_BLOCKED' });
            return;
          }
        }
      }

      const profileIds = body.llm_profile_ids ?? body.llmProfileIds;
      const llmRotate = body.llm_rotate ?? body.llmRotate;

      try {
        const task = graphStore.createTask({
          title: rawTitle || `Task: ${validatedTarget}`,
          target: validatedTarget || null,
          goal: body.goal || '',
          mode: body.mode || 'auto',
          noise_profile: body.noise_profile || body.noiseProfile || noiseGovernor.profile || 'balanced',
          llm_profile_ids: Array.isArray(profileIds) ? profileIds : [],
          llm_rotate: Boolean(llmRotate),
          allow_private: allowPrivate,
          allowPrivate,
          scope: Array.isArray(body.scope) ? body.scope : undefined,
          constraints: Array.isArray(body.constraints) ? body.constraints : undefined
        });
        taskAllowPrivateMap.set(task.id, allowPrivate);

        if (Array.isArray(profileIds) || llmRotate !== undefined) {
          llmPool.configureTaskChain(task.id, {
            ...(Array.isArray(profileIds) ? { profileIds } : {}),
            ...(llmRotate !== undefined ? { llmRotate: Boolean(llmRotate) } : {})
          });
        }

        await agentEngine.decomposeGoals(task);

        if (body.autoRun === true || body.runLoop === true) {
          agentEngine.runTaskLoop(task.id, {
            maxRounds: Number(body.maxRounds || 5),
            allowPrivate,
            getScopeRules: () => scopeRules,
            scopeRules: [...scopeRules]
          }).catch(() => {});
        }

        const graph = graphStore.getExplorationGraph(task.id);
        sendJson(res, 201, { task: withTaskAllowPrivate(graphStore.getTask(task.id)), graph });
      } catch (err) {
        sendJson(res, 400, { error: err.message });
      }
      return;
    }

    const taskMatch = pathname.match(/^\/api\/tasks\/([^/]+)$/);
    if (method === 'GET' && taskMatch) {
      const taskId = decodeURIComponent(taskMatch[1]);
      const task = graphStore.getTask(taskId);
      if (!task) {
        sendJson(res, 404, { error: 'Task not found' });
        return;
      }
      const sinceSeq = Number(parsedUrl.searchParams.get('sinceSeq') || 0);
      sendJson(res, 200, {
        task: withTaskAllowPrivate(task),
        graph: graphStore.getExplorationGraph(taskId),
        activity: graphStore.listActivity(taskId, { sinceSeq }),
        coverage: graphStore.buildCoverageLedger(taskId),
        llmChain: llmPool.getTaskChain(taskId)
      });
      return;
    }

    const taskLlmMatch = pathname.match(/^\/api\/tasks\/([^/]+)\/llm$/);
    if (method === 'PUT' && taskLlmMatch) {
      const taskId = decodeURIComponent(taskLlmMatch[1]);
      const task = graphStore.getTask(taskId);
      if (!task) {
        sendJson(res, 404, { error: 'Task not found' });
        return;
      }
      const body = await parseJsonBody(req, res);
      if (!body) return;

      const profileIds = body.profileIds ?? body.llm_profile_ids ?? body.llmProfileIds;
      const llmRotate = body.llmRotate ?? body.llm_rotate;
      const llmChain = llmPool.configureTaskChain(taskId, {
        ...(Array.isArray(profileIds) ? { profileIds } : {}),
        ...(llmRotate !== undefined ? { llmRotate: Boolean(llmRotate) } : {})
      });
      const updatedTask = graphStore.updateTask(taskId, {
        ...(Array.isArray(profileIds) ? { llm_profile_ids: profileIds } : {}),
        ...(llmRotate !== undefined ? { llm_rotate: Boolean(llmRotate) } : {})
      });
      sendJson(res, 200, { task: updatedTask, llmChain });
      return;
    }

    const taskPlanMatch = pathname.match(/^\/api\/tasks\/([^/]+)\/plan$/);
    if (method === 'POST' && taskPlanMatch) {
      const taskId = decodeURIComponent(taskPlanMatch[1]);
      const task = graphStore.getTask(taskId);
      if (!task) {
        sendJson(res, 404, { error: 'Task not found' });
        return;
      }
      const body = await parseOptionalJsonBody(req, res);
      if (!body) return;

      try {
        const plan = await agentEngine.planNextRound(taskId, {
          force: body.force !== undefined ? Boolean(body.force) : true
        });
        sendJson(res, 200, { plan, graph: graphStore.getExplorationGraph(taskId) });
      } catch (err) {
        sendJson(res, 500, { error: `Plan round failed: ${err.message}` });
      }
      return;
    }

    const taskSideQMatch = pathname.match(/^\/api\/tasks\/([^/]+)\/sidequestion$/);
    if (method === 'POST' && taskSideQMatch) {
      const taskId = decodeURIComponent(taskSideQMatch[1]);
      const task = graphStore.getTask(taskId);
      if (!task) {
        sendJson(res, 404, { error: 'Task not found' });
        return;
      }
      const body = await parseJsonBody(req, res);
      if (!body) return;
      if (!body.question || typeof body.question !== 'string' || !body.question.trim()) {
        sendJson(res, 400, { error: 'question is required' });
        return;
      }

      const graph = graphStore.getExplorationGraph(taskId);
      const contextSnapshot = body.contextSnapshot || {
        task: { id: task.id, title: task.title, target: task.target, goal: task.goal, status: task.status },
        nodes: graph.nodes,
        edges: graph.edges,
        activity: graphStore.listActivity(taskId, { limit: 30 }),
        coverage: graphStore.buildCoverageLedger(taskId)
      };

      try {
        const result = await sideQuestionService.askSideQuestion({
          taskId,
          question: body.question,
          contextSnapshot,
          llmPool
        });
        sendJson(res, 200, result);
      } catch (err) {
        const status = /No enabled LLM profile|No healthy LLM/i.test(err.message) ? 503 : 500;
        sendJson(res, status, { error: err.message });
      }
      return;
    }

    const intentSteerMatch = pathname.match(/^\/api\/tasks\/([^/]+)\/intents\/([^/]+)\/steer$/);
    if (method === 'POST' && intentSteerMatch) {
      const taskId = decodeURIComponent(intentSteerMatch[1]);
      const nodeId = decodeURIComponent(intentSteerMatch[2]);
      const task = graphStore.getTask(taskId);
      if (!task) {
        sendJson(res, 404, { error: 'Task not found' });
        return;
      }
      const node = graphStore.getNode(nodeId);
      if (!node || node.task_id !== taskId) {
        sendJson(res, 404, { error: 'Intent node not found' });
        return;
      }
      const body = await parseJsonBody(req, res);
      if (!body) return;
      if (!body.instruction || typeof body.instruction !== 'string') {
        sendJson(res, 400, { error: 'instruction is required' });
        return;
      }
      const active = agentEngine.steerWork(nodeId, body.instruction);
      if (!active) {
        graphStore.appendActivity(taskId, {
          actor: 'operator',
          eventType: 'steer',
          nodeId,
          summary: body.instruction.slice(0, 160)
        });
      }
      sendJson(res, 200, { ok: true, active, taskId, nodeId, instruction: body.instruction });
      return;
    }

    const intentCancelMatch = pathname.match(/^\/api\/tasks\/([^/]+)\/intents\/([^/]+)\/cancel$/);
    if (method === 'POST' && intentCancelMatch) {
      const taskId = decodeURIComponent(intentCancelMatch[1]);
      const nodeId = decodeURIComponent(intentCancelMatch[2]);
      const task = graphStore.getTask(taskId);
      if (!task) {
        sendJson(res, 404, { error: 'Task not found' });
        return;
      }
      const node = graphStore.getNode(nodeId);
      if (!node || node.task_id !== taskId) {
        sendJson(res, 404, { error: 'Intent node not found' });
        return;
      }
      const result = agentEngine.killWork(taskId, nodeId);
      sendJson(res, 200, { ok: true, ...result, graph: graphStore.getExplorationGraph(taskId) });
      return;
    }

    // ── API: Dual-Graph & Asset DSL ──────────────────────────────────────────
    const explorationGraphMatch = pathname.match(/^\/api\/graph\/exploration\/([^/]+)$/);
    if (method === 'GET' && explorationGraphMatch) {
      const taskId = decodeURIComponent(explorationGraphMatch[1]);
      const task = graphStore.getTask(taskId);
      if (!task) {
        sendJson(res, 404, { error: 'Task not found' });
        return;
      }
      const graph = graphStore.getExplorationGraph(taskId);
      if (parsedUrl.searchParams.get('fold') === 'true') {
        const currentRound = Number(parsedUrl.searchParams.get('round') || 1);
        const folded = foldColdGraph(graph, { graphStore, currentRound });
        sendJson(res, 200, {
          taskId,
          nodes: folded.nodes,
          edges: folded.edges,
          digests: folded.digests,
          foldedCount: folded.foldedCount,
          folded: true
        });
        return;
      }
      sendJson(res, 200, { taskId, ...graph, folded: false });
      return;
    }

    if (method === 'GET' && pathname === '/api/graph/coverage') {
      const taskId = parsedUrl.searchParams.get('taskId') || null;
      const companyId = parsedUrl.searchParams.get('companyId') || null;
      const coverageGraph = graphStore.getCoverageGraph({ taskId, companyId });
      sendJson(res, 200, coverageGraph);
      return;
    }

    const lineageMatch = pathname.match(/^\/api\/graph\/lineage\/([^/]+)\/([^/]+)$/);
    if (method === 'GET' && lineageMatch) {
      const taskId = decodeURIComponent(lineageMatch[1]);
      const findingId = decodeURIComponent(lineageMatch[2]);
      const task = graphStore.getTask(taskId);
      if (!task) {
        sendJson(res, 404, { error: 'Task not found' });
        return;
      }
      const lineage = graphStore.getFindingLineage(taskId, findingId);
      if (!lineage || !lineage.finding) {
        sendJson(res, 404, { error: 'Finding node not found' });
        return;
      }
      sendJson(res, 200, { taskId, findingId, ...lineage });
      return;
    }

    if (method === 'GET' && pathname === '/api/assets') {
      const dsl = parsedUrl.searchParams.get('dsl') || '';
      const taskId = parsedUrl.searchParams.get('taskId') || null;
      const assetType = parsedUrl.searchParams.get('type') || null;
      const inScopeOnly = parsedUrl.searchParams.get('inScope') === 'true';
      const limit = Number(parsedUrl.searchParams.get('limit') || 200);
      const offset = Number(parsedUrl.searchParams.get('offset') || 0);

      try {
        const result = graphStore.queryAssets({ dsl, taskId, assetType, inScopeOnly, limit, offset });
        sendJson(res, 200, { ...result, fields: FIELD_SPECS });
      } catch (err) {
        const status = err instanceof AssetDslError || err.name === 'AssetDslError' ? 400 : 500;
        sendJson(res, status, { error: err.message, fields: FIELD_SPECS });
      }
      return;
    }

    if (method === 'POST' && pathname === '/api/assets/ingest') {
      const body = await parseJsonBody(req, res);
      if (!body) return;
      const format = body.format || body.tool;
      const rawInput = body.rawInput !== undefined ? body.rawInput : body.output;
      if (!format || rawInput === undefined) {
        sendJson(res, 400, { error: 'format and rawInput are required' });
        return;
      }
      try {
        const parsed = ingestScanOutput(format, rawInput);
        const taskId = body.taskId || null;
        const upsertedAssets = [];
        for (const asset of parsed.assets) {
          const saved = graphStore.upsertAsset(asset, { taskId });
          if (saved) upsertedAssets.push(saved);
        }
        sendJson(res, 200, {
          format,
          assets: upsertedAssets,
          facts: parsed.facts,
          findings: parsed.findings,
          counts: {
            assets: upsertedAssets.length,
            facts: parsed.facts.length,
            findings: parsed.findings.length
          }
        });
      } catch (err) {
        sendJson(res, 400, { error: err.message });
      }
      return;
    }

    // ── API: Findings, S1 Evidence Receipts, Retests & Asset Tree ────────────
    if (method === 'GET' && pathname === '/api/findings/asset-tree') {
      const taskId = parsedUrl.searchParams.get('taskId') || null;
      const scanId = parsedUrl.searchParams.get('scanId') || null;
      const historyId = parsedUrl.searchParams.get('historyId') || null;

      let findings = [];
      let assets = [];

      if (scanId && jobs.get(scanId)?.result?.results) {
        findings = jobs.get(scanId).result.results;
        const tId = jobs.get(scanId).result.taskId;
        assets = tId ? graphStore.queryAssets({ taskId: tId, limit: 1000 }).items : [];
      } else if (historyId) {
        const record = loadHistoryById(historyId);
        if (!record) {
          sendJson(res, 404, { error: 'History record not found' });
          return;
        }
        findings = Array.isArray(record.results) ? record.results : [];
      } else if (taskId) {
        const nodes = graphStore.listNodes(taskId, { node_type: 'finding' });
        findings = nodes.map(n => ({
          id: n.id,
          ...(n.data && typeof n.data === 'object' ? n.data : {}),
          name: n.title,
          severity: n.severity || 'MEDIUM',
          status: n.status === 'verified' || n.status === 'confirmed' ? 'VULNERABLE' : 'SUSPICIOUS'
        }));
        assets = graphStore.queryAssets({ taskId, limit: 1000 }).items;
      } else {
        const tasks = graphStore.listTasks();
        for (const t of tasks) {
          const nodes = graphStore.listNodes(t.id, { node_type: 'finding' });
          for (const n of nodes) {
            findings.push({
              id: n.id,
              ...(n.data && typeof n.data === 'object' ? n.data : {}),
              name: n.title,
              severity: n.severity || 'MEDIUM',
              status: n.status === 'verified' || n.status === 'confirmed' ? 'VULNERABLE' : 'SUSPICIOUS'
            });
          }
        }
        assets = graphStore.queryAssets({ limit: 1000 }).items;
      }

      sendJson(res, 200, buildFindingAssetTree(findings, assets));
      return;
    }

    const findingEvidenceMatch = pathname.match(/^\/api\/findings\/([^/]+)\/evidence$/);
    if (method === 'GET' && findingEvidenceMatch) {
      const findingId = decodeURIComponent(findingEvidenceMatch[1]);
      sendJson(res, 200, evidenceStore.getFindingEvidence(findingId));
      return;
    }

    if (method === 'POST' && findingEvidenceMatch) {
      const findingId = decodeURIComponent(findingEvidenceMatch[1]);
      const body = await parseJsonBody(req, res);
      if (!body) return;

      try {
        let snapshot = null;
        if (body.exchangeId) {
          snapshot = evidenceStore.captureSnapshotFromExchange(body.exchangeId, {
            taskId: body.taskId || null
          });
        } else if (body.snapshotId) {
          snapshot = evidenceStore.getSnapshot(body.snapshotId);
          if (!snapshot) {
            sendJson(res, 404, { error: `Snapshot not found: ${body.snapshotId}` });
            return;
          }
        } else {
          if (!body.url) {
            sendJson(res, 400, { error: 'exchangeId, snapshotId, or raw snapshot url is required' });
            return;
          }
          snapshot = evidenceStore.createSnapshot({
            taskId: body.taskId || null,
            method: body.method || 'GET',
            url: body.url,
            statusCode: body.statusCode ?? body.status ?? 200,
            reqHeaders: body.reqHeaders || {},
            resHeaders: body.resHeaders || {},
            reqBody: body.reqBody || '',
            resBody: body.resBody ?? body.responseBody ?? ''
          });
        }

        const binding = evidenceStore.bindEvidence({
          findingId,
          snapshotId: snapshot.id,
          role: body.role || 'proof',
          quote: body.quote || '',
          note: body.note || ''
        });

        let verification = null;
        if (body.verify !== false) {
          verification = evidenceStore.verifyFindingReceipts(findingId, {
            poeLevel: body.poeLevel ?? 3,
            evidenceQuotes: Array.isArray(body.evidenceQuotes)
              ? body.evidenceQuotes
              : (body.quote ? [body.quote] : [])
          });
        }

        sendJson(res, 200, {
          binding,
          snapshot,
          verification,
          evidence: evidenceStore.getFindingEvidence(findingId)
        });
      } catch (err) {
        sendJson(res, 400, { error: err.message });
      }
      return;
    }

    const findingVerifyMatch = pathname.match(/^\/api\/findings\/([^/]+)\/verify$/);
    if (method === 'POST' && findingVerifyMatch) {
      const findingId = decodeURIComponent(findingVerifyMatch[1]);
      const body = await parseOptionalJsonBody(req, res);
      if (!body) return;

      try {
        const assessment = evidenceStore.verifyFindingReceipts(findingId, {
          poeLevel: body.poeLevel ?? 3,
          evidenceQuotes: Array.isArray(body.evidenceQuotes) ? body.evidenceQuotes : []
        });
        sendJson(res, 200, {
          assessment,
          evidence: evidenceStore.getFindingEvidence(findingId)
        });
      } catch (err) {
        sendJson(res, 400, { error: err.message });
      }
      return;
    }

    const findingRetestMatch = pathname.match(/^\/api\/findings\/([^/]+)\/retest$/);
    if (method === 'POST' && findingRetestMatch) {
      const findingId = decodeURIComponent(findingRetestMatch[1]);
      const body = await parseOptionalJsonBody(req, res);
      if (!body) return;

      try {
        const allowPrivate = body.allowPrivate !== undefined ? Boolean(body.allowPrivate) : defaultAllowPrivate;
        const targetPinStore = new TargetPinStore({ allowPrivate });
        const dnsResolver = options.retestOptions?.dnsResolver ?? options.dnsResolver ?? null;
        const validateUrl =
          options.retestOptions?.validateUrl ||
          ((u, vOpts = {}) =>
            resolveAndValidateTarget(u, {
              resolver: vOpts.resolver ?? dnsResolver,
              targetPinStore: vOpts.targetPinStore ?? targetPinStore,
              allowPrivate: vOpts.allowPrivate ?? allowPrivate
            }));
        const retest = await evidenceStore.retestFinding(findingId, {
          ...(options.retestOptions || {}),
          dnsResolver,
          targetPinStore,
          allowPrivate,
          validateUrl,
          guard: scopeRules.length ? scopeRules : null,
          ...(Array.isArray(body.evidenceQuotes) ? { evidenceQuotes: body.evidenceQuotes } : {})
        });
        sendJson(res, 200, {
          retest,
          evidence: evidenceStore.getFindingEvidence(findingId)
        });
      } catch (err) {
        const msg = err.message || '';
        const status = /No bound proof snapshot/i.test(msg)
          ? 404
          : /blocked by/i.test(msg)
            ? 403
            : 400;
        sendJson(res, status, { error: msg });
      }
      return;
    }

    // ── API: Traffic Store, Rewrite Rules & RFC-9110 Replay ──────────────────
    if (method === 'GET' && pathname === '/api/traffic') {
      const taskId = parsedUrl.searchParams.get('taskId') || undefined;
      const host = parsedUrl.searchParams.get('host') || undefined;
      const methodFilter = parsedUrl.searchParams.get('method') || undefined;
      const statusParam = parsedUrl.searchParams.get('status');
      let status;
      if (statusParam !== null && statusParam.trim() !== '') {
        const trimmedStatus = statusParam.trim();
        if (/^[1-5]xx$/i.test(trimmedStatus)) {
          status = trimmedStatus.toLowerCase();
        } else if (/^\d+$/.test(trimmedStatus)) {
          status = Number(trimmedStatus);
        } else {
          sendJson(res, 400, { error: `Invalid status filter "${statusParam}". Expected numeric status or 1xx-5xx.` });
          return;
        }
      }
      const search = parsedUrl.searchParams.get('search') || undefined;
      const source = parsedUrl.searchParams.get('source') || undefined;
      const limit = Number(parsedUrl.searchParams.get('limit') || 100);
      const offset = Number(parsedUrl.searchParams.get('offset') || 0);

      const exchanges = trafficStore.queryExchanges({
        taskId,
        host,
        method: methodFilter,
        status,
        search,
        source,
        limit,
        offset
      });
      const total = typeof exchanges.total === 'number' ? exchanges.total : exchanges.length;
      sendJson(res, 200, { exchanges, items: exchanges, total });
      return;
    }

    if (method === 'GET' && pathname === '/api/traffic/hosts') {
      const taskId = parsedUrl.searchParams.get('taskId') || undefined;
      const hosts = trafficStore.listHosts({ taskId });
      sendJson(res, 200, { hosts });
      return;
    }

    if (method === 'GET' && pathname === '/api/traffic/rewrite-rules') {
      const rules = trafficStore.listRewriteRules();
      sendJson(res, 200, { rules });
      return;
    }

    if (method === 'POST' && pathname === '/api/traffic/rewrite-rules') {
      const body = await parseJsonBody(req, res);
      if (!body) return;
      try {
        const rule = trafficStore.addRewriteRule(body);
        sendJson(res, 201, { rule });
      } catch (err) {
        sendJson(res, 400, { error: err.message });
      }
      return;
    }

    const rewriteDeleteMatch = pathname.match(/^\/api\/traffic\/rewrite-rules\/([^/]+)$/);
    if (method === 'DELETE' && rewriteDeleteMatch) {
      const ruleId = decodeURIComponent(rewriteDeleteMatch[1]);
      const deleted = trafficStore.deleteRewriteRule(ruleId);
      if (!deleted) {
        sendJson(res, 404, { error: 'Rewrite rule not found' });
        return;
      }
      sendJson(res, 200, { deleted: true, id: ruleId });
      return;
    }

    if (method === 'POST' && pathname === '/api/traffic/ingest') {
      const body = await parseJsonBody(req, res);
      if (!body) return;
      try {
        const recorded = trafficStore.recordExternal(body);
        const list = Array.isArray(recorded) ? recorded : [recorded];
        const count = list.length;
        const passiveFindings = [];
        if (body.passiveScan !== false) {
          for (const ex of list) {
            const findings = analyzePassiveExchange(ex);
            for (const f of findings) {
              passiveFindings.push({ exchangeId: ex.id, url: ex.url, ...f });
            }
          }
        }
        sendJson(res, 201, { recorded, count, ingested: count, passiveFindings });
      } catch (err) {
        sendJson(res, 400, { error: err.message });
      }
      return;
    }

    if (method === 'GET' && pathname === '/api/traffic/export.har') {
      const host = parsedUrl.searchParams.get('host') || '';
      const taskId = parsedUrl.searchParams.get('taskId') || '';
      const limit = Number(parsedUrl.searchParams.get('limit') || 200);
      const har = trafficStore.exportHar({ host, taskId, limit });
      res.writeHead(200, {
        ...SECURITY_HEADERS,
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Disposition': 'attachment; filename="secscan-traffic.har"'
      });
      res.end(JSON.stringify(har, null, 2));
      return;
    }

    if (method === 'GET' && pathname === '/api/traffic/templates') {
      const host = parsedUrl.searchParams.get('host') || '';
      const taskId = parsedUrl.searchParams.get('taskId') || '';
      const limit = Number(parsedUrl.searchParams.get('limit') || 100);
      const templates = trafficStore.listUrlTemplates({ host, taskId, limit });
      sendJson(res, 200, { templates, count: templates.length });
      return;
    }

    const trafficStreamMatch = pathname.match(/^\/api\/traffic\/([^/]+)\/stream-messages$/);
    if (trafficStreamMatch) {
      const exchangeId = decodeURIComponent(trafficStreamMatch[1]);
      if (method === 'GET') {
        const messages = trafficStore.listStreamMessages(exchangeId);
        sendJson(res, 200, { exchangeId, messages, count: messages.length });
        return;
      }
      if (method === 'POST') {
        const body = await parseJsonBody(req, res);
        if (!body) return;
        const msg = trafficStore.recordStreamMessage({
          exchangeId,
          direction: body.direction || 's2c',
          seq: Number(body.seq ?? 0),
          payload: String(body.payload ?? '')
        });
        sendJson(res, 201, { message: msg });
        return;
      }
    }

    const trafficPassiveMatch = pathname.match(/^\/api\/traffic\/([^/]+)\/passive$/);
    if (method === 'GET' && trafficPassiveMatch) {
      const exchangeId = decodeURIComponent(trafficPassiveMatch[1]);
      const findings = trafficStore.analyzeExchangePassive(exchangeId);
      sendJson(res, 200, { exchangeId, findings, count: findings.length });
      return;
    }

    const trafficReplayMatch = pathname.match(/^\/api\/traffic\/([^/]+)\/replay$/);
    if (method === 'POST' && trafficReplayMatch) {
      const exchangeId = decodeURIComponent(trafficReplayMatch[1]);
      const body = await parseOptionalJsonBody(req, res);
      if (!body) return;
      try {
        let replayOverrides = { ...body };
        let rewriteInfo = { applied: false, taintedSensitive: false, appliedRules: [] };
        const original = trafficStore.getExchange(exchangeId, { includeBodies: true });
        if (original && body.applyRewrites !== false) {
          const rewritten = trafficStore.applyRewrites(
            {
              method: body.method || original.method,
              url: body.url || original.url,
              headers: { ...(original.reqHeaders || {}), ...(body.headers || body.reqHeaders || {}) },
              body: body.body ?? body.reqBody ?? original.reqBody ?? ''
            },
            'request'
          );
          if (rewritten.rewriteApplied) {
            replayOverrides = {
              ...replayOverrides,
              method: rewritten.method,
              url: rewritten.url,
              headers: rewritten.headers,
              body: rewritten.body
            };
            rewriteInfo = {
              applied: true,
              taintedSensitive: Boolean(rewritten.taintedSensitive),
              appliedRules: rewritten.appliedRules || []
            };
          }
        }
        const allowPrivate = body.allowPrivate !== undefined ? Boolean(body.allowPrivate) : defaultAllowPrivate;
        const targetPinStore = new TargetPinStore({ allowPrivate });
        const dnsResolver = options.retestOptions?.dnsResolver ?? options.dnsResolver ?? null;
        const validateUrl =
          options.retestOptions?.validateUrl ||
          ((u, vOpts = {}) =>
            resolveAndValidateTarget(u, {
              resolver: vOpts.resolver ?? dnsResolver,
              targetPinStore: vOpts.targetPinStore ?? targetPinStore,
              allowPrivate: vOpts.allowPrivate ?? allowPrivate
            }));
        const followRedirects = body.followRedirects !== undefined
          ? Boolean(body.followRedirects)
          : options.retestOptions?.followRedirects !== undefined
            ? Boolean(options.retestOptions.followRedirects)
            : Number(options.retestOptions?.maxRedirects) === 0;
        const result = await trafficStore.replayRequest(exchangeId, replayOverrides, {
          ...(options.retestOptions || {}),
          followRedirects,
          dnsResolver,
          targetPinStore,
          allowPrivate,
          validateUrl,
          guard: scopeRules.length ? scopeRules : null
        });
        sendJson(res, 200, { ...result, rewrite: rewriteInfo });
      } catch (err) {
        const msg = err.message || '';
        const status = /Exchange not found/i.test(msg)
          ? 404
          : /Maximum redirect limit/i.test(msg)
            ? 400
            : /blocked by/i.test(msg)
              ? 403
              : 400;
        sendJson(res, status, { error: msg });
      }
      return;
    }

    const trafficGetMatch = pathname.match(/^\/api\/traffic\/([^/]+)$/);
    if (method === 'GET' && trafficGetMatch) {
      const exchangeId = decodeURIComponent(trafficGetMatch[1]);
      const exchange = trafficStore.getExchange(exchangeId, { includeBodies: true });
      if (!exchange) {
        sendJson(res, 404, { error: 'Traffic exchange not found' });
        return;
      }
      sendJson(res, 200, { exchange });
      return;
    }

    // ── API: Multi-LLM Pool, Guardrails, Noise Governor & Skills ─────────────
    if (method === 'GET' && pathname === '/api/llm/pool') {
      sendJson(res, 200, {
        ...llmPool.getPoolStatus(),
        usage: llmRecorder.getUsageSummary()
      });
      return;
    }

    if (method === 'POST' && pathname === '/api/llm/profiles') {
      const body = await parseJsonBody(req, res);
      if (!body) return;
      if (!body.id && typeof body.name === 'string' && body.name.trim()) {
        body.id = body.name.trim().toLowerCase().replace(/[^a-z0-9_-]+/g, '-');
      }
      if (!body.id) {
        sendJson(res, 400, { error: 'LLM profile id is required' });
        return;
      }
      try {
        llmPool.upsertProfile(body);
        const status = llmPool.getPoolStatus();
        const profile = status.profiles.find(p => p.id === String(body.id)) || null;
        sendJson(res, 200, { ...status, profile });
      } catch (err) {
        sendJson(res, 400, { error: err.message });
      }
      return;
    }

    const llmProfileResetMatch = pathname.match(/^\/api\/llm\/profiles\/([^/]+)\/reset$/);
    if (method === 'POST' && llmProfileResetMatch) {
      const profileId = decodeURIComponent(llmProfileResetMatch[1]);
      if (!llmPool.getProfile(profileId)) {
        sendJson(res, 404, { error: 'LLM profile not found' });
        return;
      }
      llmPool.resetBreaker(profileId);
      sendJson(res, 200, { reset: true, id: profileId, ...llmPool.getPoolStatus() });
      return;
    }

    const llmProfileMatch = pathname.match(/^\/api\/llm\/profiles\/([^/]+)$/);
    if (method === 'DELETE' && llmProfileMatch) {
      const profileId = decodeURIComponent(llmProfileMatch[1]);
      if (!llmPool.getProfile(profileId)) {
        sendJson(res, 404, { error: 'LLM profile not found' });
        return;
      }
      llmPool.removeProfile(profileId);
      sendJson(res, 200, { deleted: true, id: profileId, ...llmPool.getPoolStatus() });
      return;
    }

    if (method === 'GET' && pathname === '/api/guard/settings') {
      sendJson(res, 200, {
        noise: noiseGovernor.snapshot(),
        noiseProfile: noiseGovernor.profile,
        scopeRules,
        interceptRules,
        skills: typeof skillRegistry.listSkills === 'function' ? skillRegistry.listSkills() : []
      });
      return;
    }

    if (method === 'PUT' && pathname === '/api/guard/settings') {
      const body = await parseJsonBody(req, res);
      if (!body) return;

      try {
        if (typeof body !== 'object' || Array.isArray(body)) {
          sendJson(res, 400, { error: 'Request body must be a JSON object' });
          return;
        }

        const requestedProfile = body.noiseProfile ?? body.profile ?? body.noise?.profile;
        let nextGovernor = noiseGovernor;
        if (requestedProfile !== undefined) {
          if (typeof requestedProfile !== 'string' && typeof requestedProfile !== 'number') {
            sendJson(res, 400, {
              error: `Invalid noiseProfile "${requestedProfile}". Expected off, quiet, balanced, or aggressive.`
            });
            return;
          }
          const normalizedProfile = String(requestedProfile).trim().toLowerCase();
          if (!Object.hasOwn(NOISE_PROFILES, normalizedProfile)) {
            sendJson(res, 400, {
              error: `Invalid noiseProfile "${requestedProfile}". Expected off, quiet, balanced, or aggressive.`
            });
            return;
          }
          if (
            body.noiseConfig !== undefined &&
            (typeof body.noiseConfig !== 'object' || body.noiseConfig === null || Array.isArray(body.noiseConfig))
          ) {
            sendJson(res, 400, { error: 'noiseConfig must be a JSON object' });
            return;
          }
          nextGovernor = new NoiseGovernor({
            profile: normalizedProfile,
            ...(body.noiseConfig && typeof body.noiseConfig === 'object' ? body.noiseConfig : {})
          });
        }

        let nextScopeRules = scopeRules;
        if (body.scopeRules !== undefined) {
          if (!Array.isArray(body.scopeRules)) {
            sendJson(res, 400, { error: 'scopeRules must be an array' });
            return;
          }
          nextScopeRules = normalizeScopeRules(body.scopeRules);
        }

        let nextInterceptRules = interceptRules;
        if (body.interceptRules !== undefined) {
          if (!Array.isArray(body.interceptRules)) {
            sendJson(res, 400, { error: 'interceptRules must be an array' });
            return;
          }
          nextInterceptRules = body.interceptRules;
        }

        noiseGovernor = nextGovernor;
        scopeRules = nextScopeRules;
        interceptRules = nextInterceptRules;

        sendJson(res, 200, {
          noise: noiseGovernor.snapshot(),
          noiseProfile: noiseGovernor.profile,
          scopeRules,
          interceptRules
        });
      } catch (err) {
        sendJson(res, 400, { error: err?.message || 'Invalid guard settings payload' });
      }
      return;
    }

    if (method === 'POST' && pathname === '/api/guard/evaluate') {
      const body = await parseJsonBody(req, res);
      if (!body) return;

      const mode = body.mode ? String(body.mode).trim().toLowerCase() : null;
      const hasTarget = body.target !== undefined || body.url !== undefined;
      const hasRisk = body.toolName !== undefined || body.tool !== undefined || body.method !== undefined;
      const hasJev = body.jevAnswers !== undefined || body.answers !== undefined || body.q1_in_scope !== undefined;
      const hasIntercept = body.command !== undefined;
      const applicableCount = [hasTarget, hasRisk, hasJev, hasIntercept].filter(Boolean).length;

      const evalRules = Array.isArray(body.rules) ? normalizeScopeRules(body.rules) : scopeRules;
      const includeBuiltinDeny = body.includeBuiltinDeny !== undefined ? Boolean(body.includeBuiltinDeny) : true;

      if (mode === 'all' || (!mode && applicableCount >= 2)) {
        const gateResult = hasTarget
          ? evaluateAssetGate(body.target ?? body.url, { rules: evalRules, includeBuiltinDeny })
          : { allowed: true, matchedRule: null, code: 'TARGET_SKIPPED', reason: 'No target provided' };

        const toolName = body.toolName || body.tool || body.method || 'http';
        const riskResult = scoreRisk(toolName, body.input || body);

        const rawJev = body.jevAnswers ?? body.answers ?? (body.q1_in_scope !== undefined ? body : null);
        const jevResult = hasJev || mode === 'all'
          ? decideClosed(normalizeJevAnswers(rawJev))
          : null;

        const interceptResult = hasIntercept
          ? evaluateInterceptRules(body.command ?? body, Array.isArray(body.rules) ? body.rules : interceptRules)
          : null;

        const allowed = Boolean(
          gateResult.allowed &&
          (jevResult ? jevResult.approved : true) &&
          (interceptResult ? interceptResult.allowed : true)
        );

        sendJson(res, 200, {
          mode: 'all',
          allowed,
          gate: gateResult,
          risk: riskResult,
          ...(jevResult ? { jev: jevResult } : {}),
          ...(interceptResult ? { intercept: interceptResult } : {})
        });
        return;
      }

      if (mode === 'asset' || (!mode && hasTarget)) {
        const targetInput = body.target ?? body.url;
        const result = evaluateAssetGate(targetInput, {
          rules: evalRules,
          includeBuiltinDeny
        });
        sendJson(res, 200, { mode: 'asset', result, ...result });
        return;
      }

      if (mode === 'jev' || (!mode && hasJev)) {
        const answers = normalizeJevAnswers(body.jevAnswers || body.answers || body);
        const result = decideClosed(answers);
        sendJson(res, 200, { mode: 'jev', result, ...result });
        return;
      }

      if (mode === 'intercept' || (!mode && hasIntercept)) {
        const rules = Array.isArray(body.rules) ? body.rules : interceptRules;
        const result = evaluateInterceptRules(body.command ?? body, rules);
        sendJson(res, 200, { mode: 'intercept', result, ...result });
        return;
      }

      if (mode === 'risk' || (!mode && hasRisk)) {
        const toolName = body.toolName || body.tool || body.method || 'http';
        const result = scoreRisk(toolName, body.input || body);
        sendJson(res, 200, { mode: 'risk', result, ...result });
        return;
      }

      sendJson(res, 400, {
        error: mode
          ? `Unsupported guard mode "${body.mode}". Expected asset, risk, jev, intercept, or all.`
          : 'Provide target/url (asset gate), toolName/method (risk), command (intercept), or jevAnswers (closed-world JEV).'
      });
      return;
    }

    // ── API: System Doctor & Target Connectivity Triage ──────────────────────
    if ((method === 'GET' || method === 'POST') && pathname === '/api/system/doctor') {
      try {
        const report = await runSystemDoctor({
          allowPrivate: defaultAllowPrivate,
          llmPool,
          historyDir,
          probeWrites: method === 'POST'
        });
        sendJson(res, 200, report);
      } catch (err) {
        sendJson(res, 500, { error: `System doctor failed: ${err.message}` });
      }
      return;
    }

    if (method === 'POST' && pathname === '/api/system/diagnose-target') {
      const body = await parseJsonBody(req, res);
      if (!body) return;
      const normalizedTarget = typeof body.target === 'string' ? normalizeTargetInput(body.target) : '';
      if (!normalizedTarget) {
        sendJson(res, 400, { error: 'target URL string is required' });
        return;
      }
      try {
        const diag = await diagnoseTarget(normalizedTarget, {
          allowPrivate: body.allowPrivate ?? defaultAllowPrivate,
          dnsResolver: agentDnsResolver,
          scopeRules,
          ...(options.fetcher ? { fetcher: options.fetcher } : {})
        });
        sendJson(res, 200, diag);
      } catch (err) {
        sendJson(res, 500, { error: `Target diagnostics failed: ${err.message}` });
      }
      return;
    }

    // ── API: AI Remediation & Audience Summary ───────────────────────────────
    if (method === 'POST' && pathname === '/api/ai/remediate') {
      const body = await parseJsonBody(req, res);
      if (!body) return;
      if (!body.finding || typeof body.finding !== 'object' || Array.isArray(body.finding)) {
        sendJson(res, 400, { error: 'finding object is required' });
        return;
      }
      let resolvedStack = body.stack || null;
      let resolvedApiComm =
        (body.apiCommunication && typeof body.apiCommunication === 'object' && !Array.isArray(body.apiCommunication)
          ? body.apiCommunication
          : null) ||
        body.finding.apiCommunication ||
        (resolvedStack && typeof resolvedStack === 'object' ? resolvedStack.apiCommunication : null) ||
        null;

      if (body.scanId && typeof body.scanId === 'string' && body.scanId.trim()) {
        const sid = body.scanId.trim();
        const job = jobs.get(sid);
        if (job && job.result) {
          if (!resolvedStack && job.result.stacks) resolvedStack = job.result.stacks;
          if (!resolvedApiComm) {
            resolvedApiComm = job.result.apiCommunication || mergeApiCommunication(job.result.stacks, job.result.results);
          }
        } else {
          const hist = loadHistoryById(sid);
          if (hist) {
            if (!resolvedStack && hist.stacks) resolvedStack = hist.stacks;
            if (!resolvedApiComm) {
              resolvedApiComm = hist.apiCommunication || mergeApiCommunication(hist.stacks, hist.results);
            }
          }
        }
      }

      const findingForAdvisor = resolvedApiComm && !body.finding.apiCommunication
        ? { ...body.finding, apiCommunication: resolvedApiComm }
        : body.finding;

      try {
        const solution = await aiAdvisor.generateFixSolution(findingForAdvisor, {
          audience: body.audience !== undefined ? body.audience : 'pro',
          stack: resolvedStack,
          ...(resolvedApiComm ? { apiCommunication: resolvedApiComm } : {})
        });
        sendJson(res, 200, solution);
      } catch (err) {
        const status = err.code === 'INVALID_AUDIENCE' ? 400 : 500;
        sendJson(res, status, { error: err.message, ...(err.code ? { code: err.code } : {}) });
      }
      return;
    }

    if (method === 'POST' && pathname === '/api/ai/summary') {
      const body = await parseJsonBody(req, res);
      if (!body) return;
      let scanData = null;
      if (body.scanId !== undefined && body.scanId !== null && String(body.scanId).trim()) {
        if (typeof body.scanId !== 'string') {
          sendJson(res, 400, { error: 'scanId must be a string' });
          return;
        }
        const sid = body.scanId.trim();
        const job = jobs.get(sid);
        if (job && job.result) {
          const apiComm =
            job.result.apiCommunication ||
            mergeApiCommunication(job.result.stacks, job.result.results) ||
            (body.apiCommunication && typeof body.apiCommunication === 'object' ? body.apiCommunication : null);
          scanData = {
            targets: job.targets,
            results: job.result.results || [],
            risk: job.result.risk,
            stacks: job.result.stacks || null,
            cveCoverage: job.result.cveCoverage || null,
            ...(apiComm ? { apiCommunication: apiComm } : {})
          };
        } else {
          const hist = loadHistoryById(sid);
          if (hist) {
            const apiComm =
              hist.apiCommunication ||
              mergeApiCommunication(hist.stacks, hist.results) ||
              (body.apiCommunication && typeof body.apiCommunication === 'object' ? body.apiCommunication : null);
            scanData = {
              ...hist,
              ...(apiComm ? { apiCommunication: apiComm } : {})
            };
          } else {
            sendJson(res, 404, { error: `Scan or history record "${sid}" not found` });
            return;
          }
        }
      } else if (body.scanResult && typeof body.scanResult === 'object' && !Array.isArray(body.scanResult)) {
        const apiComm =
          body.scanResult.apiCommunication ||
          (body.apiCommunication && typeof body.apiCommunication === 'object' ? body.apiCommunication : null) ||
          mergeApiCommunication(body.scanResult.stacks, body.scanResult.results);
        scanData = {
          ...body.scanResult,
          ...(apiComm ? { apiCommunication: apiComm } : {})
        };
      } else {
        sendJson(res, 400, { error: 'scanResult object or scanId string is required' });
        return;
      }

      try {
        const summary = await aiAdvisor.summarizeScanForAudience(scanData, {
          audience: body.audience !== undefined ? body.audience : 'beginner'
        });
        sendJson(res, 200, summary);
      } catch (err) {
        const status = err.code === 'INVALID_AUDIENCE' ? 400 : 500;
        sendJson(res, status, { error: err.message, ...(err.code ? { code: err.code } : {}) });
      }
      return;
    }

    if (method === 'POST' && pathname === '/api/ai/analyze-api') {
      const body = await parseJsonBody(req, res);
      if (!body) return;
      if (typeof body !== 'object' || Array.isArray(body)) {
        sendJson(res, 400, { error: 'Request body must be a JSON object' });
        return;
      }

      let apiData = null;
      let resolvedTarget = typeof body.target === 'string' && body.target.trim()
        ? body.target.trim().slice(0, 2048)
        : null;

      if (body.scanId !== undefined && body.scanId !== null && String(body.scanId).trim()) {
        if (typeof body.scanId !== 'string') {
          sendJson(res, 400, { error: 'scanId must be a string' });
          return;
        }
        const sid = body.scanId.trim();
        const job = jobs.get(sid);
        if (job && job.result) {
          apiData =
            job.result.apiCommunication ||
            mergeApiCommunication(job.result.stacks, job.result.results) ||
            { usesApi: false };
          if (!resolvedTarget && Array.isArray(job.targets) && job.targets[0]) {
            resolvedTarget = job.targets[0];
          }
        } else {
          const hist = loadHistoryById(sid);
          if (hist) {
            apiData =
              hist.apiCommunication ||
              mergeApiCommunication(hist.stacks, hist.results) ||
              { usesApi: false };
            if (!resolvedTarget && Array.isArray(hist.targets) && hist.targets[0]) {
              resolvedTarget = hist.targets[0];
            }
          } else {
            sendJson(res, 404, { error: `Scan or history record "${sid}" not found` });
            return;
          }
        }
      } else if (body.apiCommunication !== undefined && body.apiCommunication !== null) {
        if (typeof body.apiCommunication !== 'object' || Array.isArray(body.apiCommunication)) {
          sendJson(res, 400, { error: 'apiCommunication must be a JSON object' });
          return;
        }
        apiData = capApiCommunicationInput(body.apiCommunication);
      } else if (resolvedTarget) {
        apiData = { usesApi: false };
      } else {
        sendJson(res, 400, { error: 'apiCommunication object, scanId, or target URL is required' });
        return;
      }

      try {
        const analysis = await aiAdvisor.analyzeApiCommunication(apiData, {
          target: resolvedTarget,
          audience: body.audience !== undefined ? body.audience : 'beginner'
        });
        sendJson(res, 200, analysis);
      } catch (err) {
        const status = err.code === 'INVALID_AUDIENCE' ? 400 : 500;
        sendJson(res, status, { error: err.message, ...(err.code ? { code: err.code } : {}) });
      }
      return;
    }

    // ── API: POST /api/reports/review (SecScan 7-Gate VDP Report Reviewer) ─────
    if (method === 'POST' && pathname === '/api/reports/review') {
      const body = await parseJsonBody(req, res);
      if (!body) return;
      if (typeof body !== 'object' || Array.isArray(body)) {
        sendJson(res, 400, { error: 'Request body must be a JSON object' });
        return;
      }

      let reportInput = body.report ?? body.finding ?? body.scanResult ?? null;
      if (!reportInput && typeof body.scanId === 'string' && body.scanId.trim()) {
        const sid = body.scanId.trim();
        const job = jobs.get(sid);
        if (job && job.result) {
          reportInput = job.result;
        } else {
          const hist = loadHistoryById(sid);
          if (hist) {
            reportInput = hist;
          } else {
            sendJson(res, 404, { error: `Scan or history record "${sid}" not found` });
            return;
          }
        }
      }

      if (!reportInput) {
        sendJson(res, 400, { error: 'report, finding, scanResult, or scanId is required' });
        return;
      }

      try {
        const review = await reviewReportSubmission(reportInput, {
          rules: body.rules && typeof body.rules === 'object' ? body.rules : STRICT_VDP_RULES,
          subjectModel: body.subjectModel || null,
          reviewerModel: body.reviewerModel || 'deterministic-v1',
          allowSelfReview: Boolean(body.allowSelfReview),
          runBattery: body.runBattery !== false
        });
        sendJson(res, 200, review);
      } catch (err) {
        const status = err.exitCode === 3 ? 422 : 400;
        sendJson(res, status, { error: err.message, ...(err.exitCode ? { exitCode: err.exitCode } : {}) });
      }
      return;
    }

    // ── API: POST /api/llm/posture-check (SecScan 9-Probe Fenceline Posture) ───
    if (method === 'POST' && pathname === '/api/llm/posture-check') {
      const body = await parseOptionalJsonBody(req, res);
      if (!body) return;
      if (typeof body !== 'object' || Array.isArray(body)) {
        sendJson(res, 400, { error: 'Request body must be a JSON object' });
        return;
      }

      try {
        const mockResponses = body.mockResponses && typeof body.mockResponses === 'object'
          ? body.mockResponses
          : null;
        const summary = await runLlmPostureCheck({
          model: typeof body.model === 'string' && body.model.trim() ? body.model.trim() : 'configured-pool',
          llmPool,
          ...(mockResponses
            ? {
                callFn: async (probe) => mockResponses[probe.id] ?? ''
              }
            : {})
        });
        sendJson(res, 200, summary);
      } catch (err) {
        sendJson(res, 400, { error: err.message });
      }
      return;
    }

    // ── API: POST /api/intruder/run (Burp Intruder §marker§ Engine) ──────────
    if (method === 'POST' && pathname === '/api/intruder/run') {
      const body = await parseJsonBody(req, res);
      if (!body || typeof body !== 'object' || Array.isArray(body)) {
        if (body !== null) sendJson(res, 400, { error: 'Request body must be a JSON object' });
        return;
      }
      try {
        const allowPrivate = body.allowPrivate !== undefined ? Boolean(body.allowPrivate) : defaultAllowPrivate;
        const dnsResolver = options.dnsResolver ?? options.retestOptions?.dnsResolver ?? null;
        const result = await runIntruderCampaign(body, {
          allowPrivate,
          sourceIp: body.sourceIp || null,
          scopeRules,
          trafficStore,
          ...(dnsResolver ? { dnsResolver } : {}),
          ...(options.fetcher ? { fetchWithRetry: options.fetcher } : {})
        });
        sendJson(res, 200, result);
      } catch (err) {
        const status = err?.isGovernanceBlock ? 403 : 400;
        sendJson(res, status, { error: err.message });
      }
      return;
    }

    // ── API: POST /api/autorize/run (Burp Autorize 3-Context Authz Matrix) ───
    if (method === 'POST' && pathname === '/api/autorize/run') {
      const body = await parseJsonBody(req, res);
      if (!body || typeof body !== 'object' || Array.isArray(body)) {
        if (body !== null) sendJson(res, 400, { error: 'Request body must be a JSON object' });
        return;
      }
      try {
        const allowPrivate = body.allowPrivate !== undefined ? Boolean(body.allowPrivate) : defaultAllowPrivate;
        const dnsResolver = options.dnsResolver ?? options.retestOptions?.dnsResolver ?? null;
        const result = await runAutorizeMatrix(body, {
          allowPrivate,
          sourceIp: body.sourceIp || null,
          scopeRules,
          trafficStore,
          ...(dnsResolver ? { dnsResolver } : {}),
          ...(options.fetcher ? { fetchWithRetry: options.fetcher } : {})
        });
        sendJson(res, 200, result);
      } catch (err) {
        const status = err?.isGovernanceBlock ? 403 : 400;
        sendJson(res, status, { error: err.message });
      }
      return;
    }

    // ── API: POST /api/tools/decode (Burp Decoder & Smart JWT Inspector) ─────
    if (method === 'POST' && pathname === '/api/tools/decode') {
      const body = await parseJsonBody(req, res);
      if (!body || typeof body !== 'object' || Array.isArray(body)) {
        if (body !== null) sendJson(res, 400, { error: 'Request body must be a JSON object' });
        return;
      }
      try {
        const input = String(body.input ?? '');
        const mode = String(body.mode || 'smart').toLowerCase();
        if (mode === 'jwt') {
          sendJson(res, 200, { mode: 'jwt', ...inspectJwtToken(input) });
          return;
        }
        if (mode === 'pipeline' || Array.isArray(body.steps)) {
          const steps = Array.isArray(body.steps)
            ? body.steps
            : body.operation
              ? [body.operation]
              : [];
          sendJson(res, 200, { mode: 'pipeline', ...runDecoderPipeline(input, steps) });
          return;
        }
        sendJson(res, 200, { mode: 'smart', ...smartInspectValue(input, { maxDepth: body.maxDepth }) });
      } catch (err) {
        sendJson(res, 400, { error: err.message });
      }
      return;
    }

    // ── API: POST /api/tools/compare (Burp Response Comparer) ────────────────
    if (method === 'POST' && pathname === '/api/tools/compare') {
      const body = await parseJsonBody(req, res);
      if (!body || typeof body !== 'object' || Array.isArray(body)) {
        if (body !== null) sendJson(res, 400, { error: 'Request body must be a JSON object' });
        return;
      }
      try {
        let left = body.left ?? '';
        let right = body.right ?? '';
        if (typeof body.leftTrafficId === 'string' && body.leftTrafficId.trim()) {
          const exL = trafficStore.getExchange(body.leftTrafficId.trim(), { includeBodies: true });
          if (!exL) {
            sendJson(res, 404, { error: `Left exchange "${body.leftTrafficId}" not found` });
            return;
          }
          left = { status: exL.statusCode, headers: exL.resHeaders, body: exL.resBody || '' };
        }
        if (typeof body.rightTrafficId === 'string' && body.rightTrafficId.trim()) {
          const exR = trafficStore.getExchange(body.rightTrafficId.trim(), { includeBodies: true });
          if (!exR) {
            sendJson(res, 404, { error: `Right exchange "${body.rightTrafficId}" not found` });
            return;
          }
          right = { status: exR.statusCode, headers: exR.resHeaders, body: exR.resBody || '' };
        }
        const diff = compareResponses(left, right, { maxDiffLines: body.maxDiffLines });
        sendJson(res, 200, diff);
      } catch (err) {
        sendJson(res, 400, { error: err.message });
      }
      return;
    }

    // ── API: GET|POST /api/compliance/summary (6-Framework Compliance Matrix) ─
    if ((method === 'GET' || method === 'POST') && pathname === '/api/compliance/summary') {
      let findings = [];
      if (method === 'POST') {
        const body = await parseOptionalJsonBody(req, res);
        if (!body) return;
        findings = Array.isArray(body.findings) ? body.findings : [];
      } else {
        const scanId = parsedUrl.searchParams.get('scanId') || '';
        if (scanId && jobs.has(scanId)) {
          const job = jobs.get(scanId);
          const targets = job?.result?.targets || [];
          for (const t of targets) {
            if (Array.isArray(t.results)) findings.push(...t.results);
          }
        }
      }
      sendJson(res, 200, buildComplianceSummary(findings));
      return;
    }

    // ── API: POST /api/openapi/import (OpenAPI 2.0/3.x Schema Importer) ──────
    if (method === 'POST' && pathname === '/api/openapi/import') {
      const body = await parseJsonBody(req, res);
      if (!body || typeof body !== 'object' || Array.isArray(body)) {
        if (body !== null) sendJson(res, 400, { error: 'Request body must be a JSON object' });
        return;
      }
      try {
        if (body.spec) {
          const imported = parseOpenApiSpec(body.spec, body.baseUrl || 'https://example.com', {
            maxEndpoints: body.maxEndpoints
          });
          sendJson(res, 200, { discovered: true, ...imported });
          return;
        }
        if (typeof body.targetUrl === 'string' && body.targetUrl.trim()) {
          const allowPrivate = body.allowPrivate !== undefined ? Boolean(body.allowPrivate) : defaultAllowPrivate;
          const targetCheck = validateAndGateUrl(body.targetUrl, { allowPrivate, scopeRules, normalizeBare: true });
          if (!targetCheck.ok) {
            sendJson(res, targetCheck.status, targetCheck.payload);
            return;
          }
          const dnsResolver = options.dnsResolver ?? options.retestOptions?.dnsResolver ?? null;
          const governed = options.fetcher || createGovernedFetch({
            allowPrivate,
            sourceIp: body.sourceIp || null,
            scopeRules,
            trafficStore,
            enforceDnsValidation: true,
            ...(dnsResolver ? { dnsResolver } : {})
          });
          const discovered = await discoverAndImportOpenApi(targetCheck.url, governed, {
            maxEndpoints: body.maxEndpoints
          });
          sendJson(res, 200, discovered);
          return;
        }
        sendJson(res, 400, { error: 'Provide either "spec" (OpenAPI JSON) or "targetUrl" to discover' });
      } catch (err) {
        const status = err?.isGovernanceBlock ? 403 : 400;
        sendJson(res, status, { error: err.message });
      }
      return;
    }

    // ── API: GET|POST /api/auth/demo-login (Built-in Demo MFA Login Portal) ──
    if (pathname === '/api/auth/demo-login' && (method === 'GET' || method === 'POST')) {
      const renderDemoLoginHtml = (errorBanner = '') => `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SecScan Demo Enterprise SSO &amp; MFA Portal</title>
</head>
<body>
  <h1>SecScan Demo Enterprise SSO &amp; 2FA Portal</h1>
  ${errorBanner ? `<div class="alert-danger" role="alert">${errorBanner}</div>` : ''}
  <form id="demo-enterprise-login-form" action="/api/auth/demo-login" method="POST">
    <input type="hidden" name="_token" value="csrf_demo_enterprise_token_2026">
    <label for="email">Enterprise Email / Username</label>
    <input type="email" id="email" name="email" placeholder="auditor@infsalesgroup.com" value="auditor@infsalesgroup.com">
    <label for="password">Enterprise Password</label>
    <input type="password" id="password" name="password" placeholder="Enter password or bind {{VAR:demo_pass}}">
    <label for="otp_code">2FA Authenticator Code (TOTP)</label>
    <input type="text" id="otp_code" name="otp_code" autocomplete="one-time-code" placeholder="6-digit TOTP code">
    <button type="submit" id="btn-demo-login">Log In</button>
  </form>
</body>
</html>`;

      if (method === 'GET') {
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Set-Cookie': 'XSRF-TOKEN=csrf_demo_enterprise_token_2026; Path=/'
        });
        res.end(renderDemoLoginHtml());
        return;
      }

      const chunks = [];
      for await (const chunk of req) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      }
      const rawBody = Buffer.concat(chunks).toString('utf8');
      let passwordVal = '';
      let emailVal = '';
      if (rawBody.trim().startsWith('{')) {
        try {
          const parsed = JSON.parse(rawBody);
          passwordVal = String(parsed.password || '');
          emailVal = String(parsed.email || parsed.username || '');
        } catch {}
      } else {
        const params = new URLSearchParams(rawBody);
        passwordVal = String(params.get('password') || '');
        emailVal = String(params.get('email') || params.get('username') || '');
      }

      if (!passwordVal || /wrong|invalid|oldpass/i.test(passwordVal)) {
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Set-Cookie': 'XSRF-TOKEN=csrf_demo_enterprise_token_2026; Path=/'
        });
        res.end(
          renderDemoLoginHtml(
            !passwordVal
              ? 'Password field was empty — bind {{VAR:demo_pass}} in System Variables and replay.'
              : 'Invalid username or password for Demo Enterprise Portal — rotate {{VAR:demo_pass}} in System Variables.'
          )
        );
        return;
      }

      const demoJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdWRpdG9yQGluZnNhbGVzZ3JvdXAuY29tIiwiaXNzIjoic2Vjc2Nhbi1kZW1vIiwiZXhwIjoxOTk5OTk5OTk5fQ.demo_sig';
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'X-Auth-Token': demoJwt,
        'Set-Cookie': [
          'SECSCAN_DEMO_SESSION=authenticated_demo_session_2026; Path=/; HttpOnly; SameSite=Lax',
          'XSRF-TOKEN=csrf_demo_enterprise_token_2026; Path=/'
        ]
      });
      res.end(
        JSON.stringify({
          ok: true,
          authenticated: true,
          user: emailVal || 'auditor@infsalesgroup.com',
          access_token: demoJwt,
          initScript: `<script>localStorage.setItem('demo_access_token', '${demoJwt}');</script>`
        })
      );
      return;
    }

    const resolveSelfDemoUrl = (candidateUrl) => {
      const str = typeof candidateUrl === 'string' ? candidateUrl.trim() : '';
      if (!str) return { url: str, isSelfDemo: false };
      const hostHdr = String(req.headers?.host || '127.0.0.1:4321').trim();
      const selfOrigin = `http://${hostHdr}`;
      if (str === '/api/auth/demo-login' || str.startsWith('/api/auth/demo-login?')) {
        return { url: `${selfOrigin}${str}`, isSelfDemo: true };
      }
      try {
        const parsed = new URL(str);
        if (
          parsed.pathname === '/api/auth/demo-login' &&
          (parsed.host === hostHdr ||
            ((parsed.hostname === '127.0.0.1' || parsed.hostname === 'localhost') &&
              String(parsed.port || '80') === String(server.address()?.port || hostHdr.split(':')[1] || '4321')))
        ) {
          return { url: parsed.toString(), isSelfDemo: true };
        }
      } catch {}
      return { url: str, isSelfDemo: false };
    };

    // ── API: POST /api/auth/inspect-page (DOM Form & Input Inspector) ───────
    if (method === 'POST' && pathname === '/api/auth/inspect-page') {
      const body = await parseJsonBody(req, res);
      if (!body || typeof body !== 'object' || Array.isArray(body)) {
        if (body !== null) sendJson(res, 400, { error: 'Request body must be a JSON object' });
        return;
      }
      let governed = null;
      try {
        const rawUrlCandidate = body.targetUrl ?? body.url ?? body.loginUrl;
        const rawUrl = typeof rawUrlCandidate === 'string' ? rawUrlCandidate.trim() : '';
        if (!rawUrl) {
          sendJson(res, 400, { error: 'Provide a "targetUrl", "url", or "loginUrl" to inspect' });
          return;
        }
        const headerValidation = validateCustomHeadersResult(body.headers);
        if (!headerValidation.valid) {
          sendJson(res, 400, { error: headerValidation.error });
          return;
        }
        const inspectVarsMap = new Map(systemVariables);
        if (body.systemVariables) {
          storeSystemVariables(inspectVarsMap, body.systemVariables);
        }
        const resolvedInspectRaw = resolveUrlPlaceholders(rawUrl, {
          systemVariables: Array.from(inspectVarsMap.values()),
          secrets: body.secrets ?? null
        }).resolvedUrl;
        const demoCheck = resolveSelfDemoUrl(resolvedInspectRaw);
        const resolvedInspectUrl = demoCheck.url;
        const allowPrivate = demoCheck.isSelfDemo
          ? true
          : (body.allowPrivate !== undefined ? Boolean(body.allowPrivate) : defaultAllowPrivate);
        const targetCheck = validateAndGateUrl(resolvedInspectUrl, { allowPrivate, scopeRules, normalizeBare: true });
        if (!targetCheck.ok) {
          sendJson(res, targetCheck.status, targetCheck.payload);
          return;
        }
        const dnsResolver = options.dnsResolver ?? options.retestOptions?.dnsResolver ?? null;
        const targetPinStore = new TargetPinStore({ allowPrivate });
        const cleanSourceIp = typeof body.sourceIp === 'string' && body.sourceIp.trim() ? body.sourceIp.trim() : null;
        const dnsCheck = await prevalidateResolvedTarget(targetCheck.url, {
          allowPrivate,
          scopeRules,
          dnsResolver,
          targetPinStore,
          sourceIp: cleanSourceIp
        });
        if (!dnsCheck.ok) {
          sendJson(res, dnsCheck.status, dnsCheck.payload);
          return;
        }
        governed = options.fetcher || createGovernedFetch({
          allowPrivate,
          sourceIp: cleanSourceIp,
          scopeRules,
          trafficStore,
          targetPinStore,
          enforceDnsValidation: true,
          ...(dnsResolver ? { dnsResolver } : {})
        });
        const customHdrs = headerValidation.headers || {};
        const fetchRes = Object.keys(customHdrs).length > 0
          ? await governed(targetCheck.url, { headers: customHdrs })
          : await governed(targetCheck.url);
        const domInfo = inspectLoginPageDom(fetchRes?.text || '', fetchRes?.url || targetCheck.url);
        sendJson(res, 200, {
          ok: true,
          status: Number(fetchRes?.status || 0),
          ...domInfo
        });
      } catch (err) {
        const status = Boolean(
          err?.isGovernanceBlock ||
          err?.code === 'SSRF_POLICY_BLOCKED' ||
          err?.code === 'TARGET_RULE_BLOCKED' ||
          err?.code === 'DNS_REBIND_OR_PRIVATE_IP'
        ) ? 403 : 400;
        sendJson(res, status, { error: err.message });
      } finally {
        try {
          governed?.destroyAgents?.();
        } catch {}
      }
      return;
    }

    // ── API: POST /api/auth/otp-preview (RFC 6238 TOTP Live Preview) ────────
    if (method === 'POST' && pathname === '/api/auth/otp-preview') {
      const body = await parseJsonBody(req, res);
      if (!body || typeof body !== 'object' || Array.isArray(body)) {
        if (body !== null) sendJson(res, 400, { error: 'Request body must be a JSON object' });
        return;
      }
      try {
        const cfg = (body.otpConfig && typeof body.otpConfig === 'object' && !Array.isArray(body.otpConfig))
          ? { ...body.otpConfig }
          : { ...body };
        const savedSeq = (typeof body.sequenceId === 'string' && savedSequences.has(body.sequenceId.trim()))
          ? savedSequences.get(body.sequenceId.trim())
          : null;
        if (savedSeq?.otpConfig) {
          if (!cfg.secret || cfg.secret === '[REDACTED]' || cfg.secret === '[SECRET]') {
            if (savedSeq.otpConfig.secret && savedSeq.otpConfig.secret !== '[REDACTED]' && savedSeq.otpConfig.secret !== '[SECRET]') {
              cfg.secret = savedSeq.otpConfig.secret;
            }
          }
          if (!cfg.secretName && savedSeq.otpConfig.secretName) {
            cfg.secretName = savedSeq.otpConfig.secretName;
          }
          if (!cfg.variableName && savedSeq.otpConfig.variableName) {
            cfg.variableName = savedSeq.otpConfig.variableName;
          }
        }

        const otpVarsMap = new Map(systemVariables);
        if (body.systemVariables) {
          storeSystemVariables(otpVarsMap, body.systemVariables);
        }
        const combinedSecrets = [
          ...(Array.isArray(savedSeq?.secrets) ? savedSeq.secrets : []),
          ...(Array.isArray(body.secrets) ? body.secrets : [])
        ];
        const varLookup = buildVariableLookupMap({
          systemVariables: Array.from(otpVarsMap.values()),
          secrets: combinedSecrets.length > 0 ? combinedSecrets : body.secrets
        });

        const rawSecret = typeof cfg.secret === 'string' ? cfg.secret.trim() : '';
        const explicitVarName = String(cfg.secretName || cfg.variableName || '').trim();
        if (rawSecret && /\{\{(?:VAR|SECRET):([^}]{1,128})\}\}/i.test(rawSecret)) {
          let missingVar = '';
          const resolvedSecret = rawSecret.replace(/\{\{(?:VAR|SECRET):([^}]{1,128})\}\}/gi, (_m, rawName) => {
            const key = String(rawName || '').trim();
            if (key && varLookup.has(key)) {
              return varLookup.get(key);
            }
            if (!missingVar) missingVar = key || '(empty)';
            return '';
          }).trim();
          if (missingVar) {
            throw new Error(`TOTP secret variable '${missingVar}' is missing or empty in System Variables / Secrets vault`);
          }
          cfg.secret = resolvedSecret;
        } else if ((!rawSecret || rawSecret === '[REDACTED]' || rawSecret === '[SECRET]') && explicitVarName) {
          if (!varLookup.has(explicitVarName)) {
            throw new Error(`TOTP secret variable '${explicitVarName}' is missing or empty in System Variables / Secrets vault`);
          }
          cfg.secret = varLookup.get(explicitVarName);
        } else if (rawSecret && varLookup.has(rawSecret)) {
          cfg.secret = varLookup.get(rawSecret);
        }

        const totp = generateTotpCode(cfg);
        sendJson(res, 200, {
          valid: true,
          code: totp.code,
          digits: totp.digits,
          period: totp.period,
          algorithm: totp.algorithm,
          remainingSeconds: totp.remainingSeconds,
          secretMasked: '[CONFIGURED]'
        });
      } catch (err) {
        sendJson(res, 400, { valid: false, error: err.message });
      }
      return;
    }

    // ── API: GET|POST|PUT|DELETE /api/auth/variables (System Variables) ─────
    if (method === 'GET' && pathname === '/api/auth/variables') {
      const variables = exportSystemVariables(Array.from(systemVariables.values()), {
        includeSecrets: false
      });
      sendJson(res, 200, { variables });
      return;
    }

    if (method === 'POST' && pathname === '/api/auth/variables') {
      const body = await parseJsonBody(req, res);
      if (!body || typeof body !== 'object' || Array.isArray(body)) {
        if (body !== null) sendJson(res, 400, { error: 'Request body must be a JSON object' });
        return;
      }
      let rawList = [];
      if (body.variables !== undefined) {
        rawList = body.variables;
      } else if (body.variable && typeof body.variable === 'object' && !Array.isArray(body.variable)) {
        rawList = [body.variable];
      } else if (typeof body.name === 'string') {
        rawList = [body];
      }
      const normalizedCheck = normalizeSystemVariables(rawList);
      if (normalizedCheck.length === 0) {
        sendJson(res, 400, { error: 'At least one valid system variable with a non-empty name is required' });
        return;
      }
      storeSystemVariables(systemVariables, rawList, { replaceAll: Boolean(body.replaceAll) });
      if (!useInMemory) {
        savePersistedSystemVariables(historyDir, systemVariables);
      }
      const variables = exportSystemVariables(Array.from(systemVariables.values()), {
        includeSecrets: false
      });
      sendJson(res, 200, { saved: true, variables });
      return;
    }

    const authVariableItemMatch = pathname.match(/^\/api\/auth\/variables\/([^/]+)$/);
    if (authVariableItemMatch && (method === 'PUT' || method === 'DELETE')) {
      let targetName;
      try {
        targetName = decodeURIComponent(authVariableItemMatch[1]).trim();
      } catch {
        sendJson(res, 400, { error: 'Invalid system variable name' });
        return;
      }
      if (!targetName || targetName === '__proto__' || targetName === 'constructor' || targetName === 'prototype') {
        sendJson(res, 400, { error: 'Invalid system variable name' });
        return;
      }

      if (method === 'PUT') {
        const body = await parseJsonBody(req, res);
        if (!body || typeof body !== 'object' || Array.isArray(body)) {
          if (body !== null) sendJson(res, 400, { error: 'Request body must be a JSON object' });
          return;
        }
        const rawEntry = (body.variable && typeof body.variable === 'object' && !Array.isArray(body.variable))
          ? body.variable
          : body;
        const entry = { ...rawEntry, name: targetName };
        const normalizedCheck = normalizeSystemVariables([entry]);
        if (normalizedCheck.length === 0) {
          sendJson(res, 400, { error: 'Invalid system variable payload' });
          return;
        }
        storeSystemVariables(systemVariables, [entry]);
        if (!useInMemory) {
          savePersistedSystemVariables(historyDir, systemVariables);
        }
        const variables = exportSystemVariables(Array.from(systemVariables.values()), {
          includeSecrets: false
        });
        const variable = variables.find(v => v.name === targetName) || null;
        sendJson(res, 200, {
          updated: true,
          saved: true,
          name: targetName,
          variable,
          variables
        });
        return;
      }

      if (method === 'DELETE') {
        if (!systemVariables.has(targetName)) {
          sendJson(res, 404, { error: 'System variable not found' });
          return;
        }
        systemVariables.delete(targetName);
        if (!useInMemory) {
          savePersistedSystemVariables(historyDir, systemVariables);
        }
        const variables = exportSystemVariables(Array.from(systemVariables.values()), {
          includeSecrets: false
        });
        sendJson(res, 200, { deleted: true, name: targetName, variables });
        return;
      }
    }

    // ── API: GET|POST /api/auth/sequences & GET|PUT|DELETE /api/auth/sequences/:id ──
    if (method === 'GET' && pathname === '/api/auth/sequences') {
      const sequences = Array.from(savedSequences.values()).map(s =>
        exportLsrSequence(s, { includeSecrets: false })
      );
      sendJson(res, 200, { sequences });
      return;
    }

    if (method === 'POST' && pathname === '/api/auth/sequences') {
      const body = await parseJsonBody(req, res);
      if (!body || typeof body !== 'object' || Array.isArray(body)) {
        if (body !== null) sendJson(res, 400, { error: 'Request body must be a JSON object' });
        return;
      }
      try {
        const dnsResolver = options.dnsResolver ?? options.retestOptions?.dnsResolver ?? null;
        const seqInput = body.sequence !== undefined ? body.sequence : body;
        const seq = parseLsrSequence(seqInput);
        if (!seq.targetUrl && typeof body.targetUrl === 'string' && body.targetUrl.trim()) {
          seq.targetUrl = body.targetUrl.trim();
        }
        if (savedSequences.has(seq.sequenceId)) {
          mergeSavedSequenceSecrets(seq, savedSequences.get(seq.sequenceId));
        }
        const seqVarsMap = new Map(systemVariables);
        if (body.systemVariables) {
          storeSystemVariables(seqVarsMap, body.systemVariables);
        }
        const effectiveSeqVars = Array.from(seqVarsMap.values());
        const firstActionUrl = Array.isArray(seq.actions)
          ? (seq.actions.find(a => a && typeof a.url === 'string' && a.url.trim())?.url || '')
          : '';
        const isDemoSeq =
          resolveSelfDemoUrl(seq.targetUrl || '').isSelfDemo ||
          resolveSelfDemoUrl(firstActionUrl).isSelfDemo;
        const allowPrivate = isDemoSeq
          ? true
          : (body.allowPrivate !== undefined ? Boolean(body.allowPrivate) : defaultAllowPrivate);
        if (seq.targetUrl) {
          const demoTarget = resolveSelfDemoUrl(seq.targetUrl);
          if (demoTarget.isSelfDemo) seq.targetUrl = demoTarget.url;
        }
        if (Array.isArray(seq.actions)) {
          for (const act of seq.actions) {
            if (act?.url) {
              const d = resolveSelfDemoUrl(act.url);
              if (d.isSelfDemo) act.url = d.url;
            }
            if (act?.submitUrl) {
              const d = resolveSelfDemoUrl(act.submitUrl);
              if (d.isSelfDemo) act.submitUrl = d.url;
            }
          }
        }
        let resolvedBaseUrl = null;
        if (seq.targetUrl) {
          const resolvedTargetInfo = resolveUrlPlaceholders(seq.targetUrl, {
            systemVariables: effectiveSeqVars,
            secrets: seq.secrets
          });
          if (resolvedTargetInfo.resolvedUrl && (!resolvedTargetInfo.hadPlaceholder || /^https?:\/\//i.test(resolvedTargetInfo.resolvedUrl))) {
            const targetCheck = validateAndGateUrl(resolvedTargetInfo.resolvedUrl, {
              allowPrivate,
              scopeRules,
              normalizeBare: true
            });
            if (!targetCheck.ok) {
              sendJson(res, targetCheck.status, targetCheck.payload);
              return;
            }
            const dnsCheck = await prevalidateResolvedTarget(targetCheck.url, {
              allowPrivate,
              scopeRules,
              dnsResolver
            });
            if (!dnsCheck.ok) {
              sendJson(res, dnsCheck.status, dnsCheck.payload);
              return;
            }
            resolvedBaseUrl = targetCheck.url;
            if (!resolvedTargetInfo.hadPlaceholder) {
              seq.targetUrl = targetCheck.url;
            }
          }
        }
        const actionsCheck = await validateSequenceActionUrls(seq, {
          allowPrivate,
          scopeRules,
          dnsResolver,
          baseUrl: resolvedBaseUrl || seq.targetUrl || null,
          systemVariables: effectiveSeqVars,
          secrets: seq.secrets
        });
        if (!actionsCheck.ok) {
          sendJson(res, actionsCheck.status, actionsCheck.payload);
          return;
        }
        storeSavedSequence(savedSequences, seq);
        if (!useInMemory) {
          savePersistedSequences(historyDir, savedSequences);
        }
        const exported = exportLsrSequence(seq, { includeSecrets: false });
        sendJson(res, 200, {
          saved: true,
          sequenceId: seq.sequenceId,
          sequence: exported,
          lsrExport: exported
        });
      } catch (err) {
        const status = err?.isGovernanceBlock ? 403 : 400;
        sendJson(res, status, { error: err.message });
      }
      return;
    }

    const authSequenceItemMatch = pathname.match(/^\/api\/auth\/sequences\/([^/]+)$/);
    if (authSequenceItemMatch && (method === 'GET' || method === 'PUT' || method === 'DELETE')) {
      let sequenceId;
      try {
        sequenceId = decodeURIComponent(authSequenceItemMatch[1]).trim();
      } catch {
        sendJson(res, 400, { error: 'Invalid sequence ID' });
        return;
      }
      if (!sequenceId) {
        sendJson(res, 400, { error: 'Invalid sequence ID' });
        return;
      }

      if (method === 'GET') {
        if (!savedSequences.has(sequenceId)) {
          sendJson(res, 404, { error: 'Saved login sequence not found' });
          return;
        }
        const exported = exportLsrSequence(savedSequences.get(sequenceId), { includeSecrets: false });
        sendJson(res, 200, { sequence: exported, lsrExport: exported });
        return;
      }

      if (method === 'PUT') {
        const body = await parseJsonBody(req, res);
        if (!body || typeof body !== 'object' || Array.isArray(body)) {
          if (body !== null) sendJson(res, 400, { error: 'Request body must be a JSON object' });
          return;
        }
        try {
          const dnsResolver = options.dnsResolver ?? options.retestOptions?.dnsResolver ?? null;
          const seqInput = body.sequence !== undefined ? body.sequence : body;
          const seq = parseLsrSequence(seqInput);
          seq.sequenceId = sequenceId;
          if (!seq.targetUrl && typeof body.targetUrl === 'string' && body.targetUrl.trim()) {
            seq.targetUrl = body.targetUrl.trim();
          }
          if (savedSequences.has(sequenceId)) {
            mergeSavedSequenceSecrets(seq, savedSequences.get(sequenceId));
          }
          const seqVarsMap = new Map(systemVariables);
          if (body.systemVariables) {
            storeSystemVariables(seqVarsMap, body.systemVariables);
          }
          const effectiveSeqVars = Array.from(seqVarsMap.values());
          const firstActionUrl = Array.isArray(seq.actions)
            ? (seq.actions.find(a => a && typeof a.url === 'string' && a.url.trim())?.url || '')
            : '';
          const isDemoSeq =
            resolveSelfDemoUrl(seq.targetUrl || '').isSelfDemo ||
            resolveSelfDemoUrl(firstActionUrl).isSelfDemo;
          const allowPrivate = isDemoSeq
            ? true
            : (body.allowPrivate !== undefined ? Boolean(body.allowPrivate) : defaultAllowPrivate);
          if (seq.targetUrl) {
            const demoTarget = resolveSelfDemoUrl(seq.targetUrl);
            if (demoTarget.isSelfDemo) seq.targetUrl = demoTarget.url;
          }
          if (Array.isArray(seq.actions)) {
            for (const act of seq.actions) {
              if (act?.url) {
                const d = resolveSelfDemoUrl(act.url);
                if (d.isSelfDemo) act.url = d.url;
              }
              if (act?.submitUrl) {
                const d = resolveSelfDemoUrl(act.submitUrl);
                if (d.isSelfDemo) act.submitUrl = d.url;
              }
            }
          }
          let resolvedBaseUrl = null;
          if (seq.targetUrl) {
            const resolvedTargetInfo = resolveUrlPlaceholders(seq.targetUrl, {
              systemVariables: effectiveSeqVars,
              secrets: seq.secrets
            });
            if (resolvedTargetInfo.resolvedUrl && (!resolvedTargetInfo.hadPlaceholder || /^https?:\/\//i.test(resolvedTargetInfo.resolvedUrl))) {
              const targetCheck = validateAndGateUrl(resolvedTargetInfo.resolvedUrl, {
                allowPrivate,
                scopeRules,
                normalizeBare: true
              });
              if (!targetCheck.ok) {
                sendJson(res, targetCheck.status, targetCheck.payload);
                return;
              }
              const dnsCheck = await prevalidateResolvedTarget(targetCheck.url, {
                allowPrivate,
                scopeRules,
                dnsResolver
              });
              if (!dnsCheck.ok) {
                sendJson(res, dnsCheck.status, dnsCheck.payload);
                return;
              }
              resolvedBaseUrl = targetCheck.url;
              if (!resolvedTargetInfo.hadPlaceholder) {
                seq.targetUrl = targetCheck.url;
              }
            }
          }
          const actionsCheck = await validateSequenceActionUrls(seq, {
            allowPrivate,
            scopeRules,
            dnsResolver,
            baseUrl: resolvedBaseUrl || seq.targetUrl || null,
            systemVariables: effectiveSeqVars,
            secrets: seq.secrets
          });
          if (!actionsCheck.ok) {
            sendJson(res, actionsCheck.status, actionsCheck.payload);
            return;
          }
          storeSavedSequence(savedSequences, seq);
          if (!useInMemory) {
            savePersistedSequences(historyDir, savedSequences);
          }
          const exported = exportLsrSequence(seq, { includeSecrets: false });
          sendJson(res, 200, {
            saved: true,
            updated: true,
            sequenceId: seq.sequenceId,
            sequence: exported,
            lsrExport: exported
          });
        } catch (err) {
          const status = err?.isGovernanceBlock ? 403 : 400;
          sendJson(res, status, { error: err.message });
        }
        return;
      }

      if (method === 'DELETE') {
        let keyToDelete = savedSequences.has(sequenceId) ? sequenceId : null;
        if (!keyToDelete) {
          for (const [k, v] of savedSequences.entries()) {
            if (v && (v.sequenceId === sequenceId || v.name === sequenceId)) {
              keyToDelete = k;
              break;
            }
          }
        }
        if (!keyToDelete) {
          sendJson(res, 404, { error: 'Saved login sequence not found' });
          return;
        }
        savedSequences.delete(keyToDelete);
        if (!useInMemory) {
          savePersistedSequences(historyDir, savedSequences);
        }
        sendJson(res, 200, { deleted: true, sequenceId: keyToDelete });
        return;
      }
    }

    // ── API: POST /api/auth/macro-test & POST /api/auth/record-session ──────
    if (method === 'POST' && (pathname === '/api/auth/macro-test' || pathname === '/api/auth/record-session')) {
      const body = await parseJsonBody(req, res);
      if (!body || typeof body !== 'object' || Array.isArray(body)) {
        if (body !== null) sendJson(res, 400, { error: 'Request body must be a JSON object' });
        return;
      }
      let governed = null;
      try {
        if (
          typeof body.html === 'string' &&
          !body.loginUrl &&
          !body.targetUrl &&
          !body.username &&
          !body.loginSequence &&
          !body.sequenceId
        ) {
          sendJson(res, 200, extractCsrfTokens(body.html, body.headers || {}));
          return;
        }
        const allowPrivate = body.allowPrivate !== undefined ? Boolean(body.allowPrivate) : defaultAllowPrivate;
        const dnsResolver = options.dnsResolver ?? options.retestOptions?.dnsResolver ?? null;
        const targetPinStore = new TargetPinStore({ allowPrivate });
        const cleanSourceIp = typeof body.sourceIp === 'string' && body.sourceIp.trim() ? body.sourceIp.trim() : null;

        const cleanSequenceId = typeof body.sequenceId === 'string' && body.sequenceId.trim()
          ? body.sequenceId.trim()
          : null;
        const savedSeq = cleanSequenceId && savedSequences.has(cleanSequenceId)
          ? savedSequences.get(cleanSequenceId)
          : null;

        let resolvedSequence = null;
        if (body.loginSequence !== undefined && body.loginSequence !== null) {
          const parsedSeq = parseLsrSequence(body.loginSequence);
          const matchingSaved = savedSeq ||
            (parsedSeq.sequenceId && savedSequences.has(parsedSeq.sequenceId)
              ? savedSequences.get(parsedSeq.sequenceId)
              : null);
          resolvedSequence = mergeSavedSequenceSecrets(parsedSeq, matchingSaved);
        } else if (savedSeq) {
          resolvedSequence = normalizeLoginSequence(savedSeq);
        }

        const mergedVarsMap = new Map(systemVariables);
        if (resolvedSequence?.systemVariables) {
          storeSystemVariables(mergedVarsMap, resolvedSequence.systemVariables);
        }
        if (body.systemVariables !== undefined && body.systemVariables !== null) {
          storeSystemVariables(mergedVarsMap, body.systemVariables);
        }
        const mergedSystemVars = Array.from(mergedVarsMap.values());
        const effectiveSecretsForLookup = body.secrets ?? resolvedSequence?.secrets ?? null;

        let rawTargetUrl = typeof body.targetUrl === 'string' && body.targetUrl.trim()
          ? body.targetUrl.trim()
          : '';
        if (!rawTargetUrl && resolvedSequence) {
          if (typeof resolvedSequence.targetUrl === 'string' && resolvedSequence.targetUrl.trim()) {
            rawTargetUrl = resolvedSequence.targetUrl.trim();
          } else if (Array.isArray(resolvedSequence.actions)) {
            const firstNav =
              resolvedSequence.actions.find(a => a.type === 'navigate' && typeof a.url === 'string' && a.url.trim()) ||
              resolvedSequence.actions.find(a => a.type === 'custom_request' && typeof a.url === 'string' && a.url.trim());
            if (firstNav?.url) {
              rawTargetUrl = firstNav.url.trim();
            }
          }
        }

        if (rawTargetUrl) {
          const demoTarget = resolveSelfDemoUrl(rawTargetUrl);
          if (demoTarget.isSelfDemo) {
            rawTargetUrl = demoTarget.url;
          }
        }
        if (resolvedSequence && Array.isArray(resolvedSequence.actions)) {
          for (const act of resolvedSequence.actions) {
            if (act?.url) {
              const d = resolveSelfDemoUrl(act.url);
              if (d.isSelfDemo) act.url = d.url;
            }
            if (act?.submitUrl) {
              const d = resolveSelfDemoUrl(act.submitUrl);
              if (d.isSelfDemo) act.submitUrl = d.url;
            }
          }
          if (resolvedSequence.targetUrl) {
            const dt = resolveSelfDemoUrl(resolvedSequence.targetUrl);
            if (dt.isSelfDemo) resolvedSequence.targetUrl = dt.url;
          }
        }
        const isSelfDemoPlay =
          resolveSelfDemoUrl(rawTargetUrl).isSelfDemo ||
          resolveSelfDemoUrl(resolvedSequence?.targetUrl || '').isSelfDemo;
        const effectiveAllowPrivate = isSelfDemoPlay ? true : allowPrivate;

        let normalizedTargetUrl = null;
        if (rawTargetUrl) {
          const resolvedTargetInfo = resolveUrlPlaceholders(rawTargetUrl, {
            systemVariables: mergedSystemVars,
            secrets: effectiveSecretsForLookup
          });
          const targetCheck = validateAndGateUrl(resolvedTargetInfo.resolvedUrl, {
            allowPrivate: effectiveAllowPrivate,
            scopeRules,
            normalizeBare: true
          });
          if (!targetCheck.ok) {
            sendJson(res, targetCheck.status, targetCheck.payload);
            return;
          }
          const targetDns = await prevalidateResolvedTarget(targetCheck.url, {
            allowPrivate: effectiveAllowPrivate,
            scopeRules,
            dnsResolver,
            targetPinStore,
            sourceIp: cleanSourceIp
          });
          if (!targetDns.ok) {
            sendJson(res, targetDns.status, targetDns.payload);
            return;
          }
          normalizedTargetUrl = targetCheck.url;
        }

        let normalizedLoginUrl = null;
        if (typeof body.loginUrl === 'string' && body.loginUrl.trim()) {
          const resolvedLoginInfo = resolveUrlPlaceholders(body.loginUrl.trim(), {
            systemVariables: mergedSystemVars,
            secrets: effectiveSecretsForLookup
          });
          const demoLogin = resolveSelfDemoUrl(resolvedLoginInfo.resolvedUrl);
          const loginCheck = validateAndGateUrl(demoLogin.url, {
            allowPrivate: demoLogin.isSelfDemo ? true : effectiveAllowPrivate,
            scopeRules,
            normalizeBare: true
          });
          if (!loginCheck.ok) {
            sendJson(res, loginCheck.status, loginCheck.payload);
            return;
          }
          const loginDns = await prevalidateResolvedTarget(loginCheck.url, {
            allowPrivate: demoLogin.isSelfDemo ? true : effectiveAllowPrivate,
            scopeRules,
            dnsResolver,
            targetPinStore,
            sourceIp: cleanSourceIp
          });
          if (!loginDns.ok) {
            sendJson(res, loginDns.status, loginDns.payload);
            return;
          }
          normalizedLoginUrl = loginCheck.url;
        }

        if (resolvedSequence) {
          let resolvedSeqBaseUrl = null;
          if (resolvedSequence.targetUrl) {
            const resolvedSeqTarget = resolveUrlPlaceholders(resolvedSequence.targetUrl, {
              systemVariables: mergedSystemVars,
              secrets: effectiveSecretsForLookup
            });
            const seqTargetCheck = validateAndGateUrl(resolvedSeqTarget.resolvedUrl, {
              allowPrivate: effectiveAllowPrivate,
              scopeRules,
              normalizeBare: true
            });
            if (!seqTargetCheck.ok) {
              sendJson(res, seqTargetCheck.status, seqTargetCheck.payload);
              return;
            }
            const seqTargetDns = await prevalidateResolvedTarget(seqTargetCheck.url, {
              allowPrivate: effectiveAllowPrivate,
              scopeRules,
              dnsResolver,
              targetPinStore,
              sourceIp: cleanSourceIp
            });
            if (!seqTargetDns.ok) {
              sendJson(res, seqTargetDns.status, seqTargetDns.payload);
              return;
            }
            resolvedSeqBaseUrl = seqTargetCheck.url;
            if (!resolvedSeqTarget.hadPlaceholder) {
              resolvedSequence.targetUrl = seqTargetCheck.url;
            }
            if (!normalizedTargetUrl) normalizedTargetUrl = seqTargetCheck.url;
          } else if (normalizedTargetUrl) {
            resolvedSequence.targetUrl = normalizedTargetUrl;
          }

          const seqActionsCheck = await validateSequenceActionUrls(resolvedSequence, {
            allowPrivate: effectiveAllowPrivate,
            scopeRules,
            dnsResolver,
            targetPinStore,
            baseUrl: resolvedSeqBaseUrl || normalizedTargetUrl || normalizedLoginUrl || null,
            sourceIp: cleanSourceIp,
            systemVariables: mergedSystemVars,
            secrets: effectiveSecretsForLookup
          });
          if (!seqActionsCheck.ok) {
            sendJson(res, seqActionsCheck.status, seqActionsCheck.payload);
            return;
          }
        }

        if (!normalizedTargetUrl && !normalizedLoginUrl && !(resolvedSequence && resolvedSequence.actions.length > 0)) {
          sendJson(res, 400, { error: 'Provide "loginUrl", "targetUrl", or "loginSequence" (or "html" for CSRF extraction)' });
          return;
        }

        const effectiveRecordTimeout = Math.max(2000, Math.min(Number(body.timeout) || 15000, 45000));
        governed = options.fetcher || createGovernedFetch({
          allowPrivate: effectiveAllowPrivate,
          sourceIp: cleanSourceIp,
          scopeRules,
          trafficStore,
          targetPinStore,
          enforceDnsValidation: true,
          retries: 1,
          timeout: effectiveRecordTimeout,
          ...(dnsResolver ? { dnsResolver } : {})
        });
        const mgr = new AuthSessionManager({
          ...body,
          ...(normalizedTargetUrl ? { targetUrl: normalizedTargetUrl } : {}),
          ...(normalizedLoginUrl ? { loginUrl: normalizedLoginUrl } : {}),
          ...(resolvedSequence ? { loginSequence: resolvedSequence } : {}),
          ...(body.secrets !== undefined ? { secrets: body.secrets } : {}),
          systemVariables: mergedSystemVars,
          ...(body.otpConfig !== undefined ? { otpConfig: body.otpConfig } : {}),
          ...(body.restrictions !== undefined ? { restrictions: body.restrictions } : {}),
          ...(body.sessionDetection !== undefined ? { sessionDetection: body.sessionDetection } : {})
        });
        const outcome = await mgr.executeLoginMacro(governed);
        storeRecordedSession(recordedSessions, mgr.exportRecordedSession());
        if (mgr.loginSequence?.actions?.length > 0 && body.saveSequence !== false) {
          storeSavedSequence(savedSequences, mgr.loginSequence);
          if (!useInMemory) {
            savePersistedSequences(historyDir, savedSequences);
          }
        }
        const safeSession = mgr.getRecordedSession({ includeSecrets: false });
        const includeArtifactValues = body.includeArtifactValues === true;
        const responsePayload = {
          ...outcome,
          ...safeSession,
          ...(includeArtifactValues
            ? { authArtifacts: mgr.getRecordedSession({ includeSecrets: true }).authArtifacts }
            : {})
        };
        sendJson(res, 200, responsePayload);
      } catch (err) {
        const status = Boolean(
          err?.isGovernanceBlock ||
          err?.code === 'SSRF_POLICY_BLOCKED' ||
          err?.code === 'TARGET_RULE_BLOCKED' ||
          err?.code === 'DNS_REBIND_OR_PRIVATE_IP'
        ) ? 403 : 400;
        sendJson(res, status, { error: err.message });
      } finally {
        try {
          governed?.destroyAgents?.();
        } catch {}
      }
      return;
    }

    // ── API: POST /api/sca/analyze (Runtime Software Composition Analysis) ──
    if (method === 'POST' && pathname === '/api/sca/analyze') {
      const body = await parseJsonBody(req, res);
      if (!body || typeof body !== 'object' || Array.isArray(body)) {
        if (body !== null) sendJson(res, 400, { error: 'Request body must be a JSON object' });
        return;
      }
      let governedFetch = null;
      try {
        const rawTargetCandidate = body.target ?? body.targetUrl;
        const rawTarget = typeof rawTargetCandidate === 'string' ? rawTargetCandidate.trim() : '';
        if (typeof body.html === 'string' && !rawTarget) {
          const runtimeSca = extractRuntimeScaFromResponse({
            html: body.html,
            headers: (body.headers && typeof body.headers === 'object' && !Array.isArray(body.headers)) ? body.headers : {},
            pageUrl: ''
          });
          sendJson(res, 200, { runtimeSca });
          return;
        }
        if (!rawTarget) {
          sendJson(res, 400, { error: 'Provide "target" / "targetUrl" or "html" for Runtime SCA analysis' });
          return;
        }
        const allowPrivate = body.allowPrivate !== undefined ? Boolean(body.allowPrivate) : defaultAllowPrivate;
        const targetCheck = validateAndGateUrl(rawTarget, { allowPrivate, scopeRules, normalizeBare: true });
        if (!targetCheck.ok) {
          sendJson(res, targetCheck.status, targetCheck.payload);
          return;
        }
        const dnsResolver = options.dnsResolver ?? options.retestOptions?.dnsResolver ?? null;
        const targetPinStore = new TargetPinStore({ allowPrivate });
        const cleanSourceIp = typeof body.sourceIp === 'string' && body.sourceIp.trim() ? body.sourceIp.trim() : null;
        const dnsCheck = await prevalidateResolvedTarget(targetCheck.url, {
          allowPrivate,
          scopeRules,
          dnsResolver,
          targetPinStore,
          sourceIp: cleanSourceIp
        });
        if (!dnsCheck.ok) {
          sendJson(res, dnsCheck.status, dnsCheck.payload);
          return;
        }
        governedFetch = options.fetcher || createGovernedFetch({
          allowPrivate,
          sourceIp: cleanSourceIp,
          scopeRules,
          trafficStore,
          targetPinStore,
          enforceDnsValidation: true,
          ...(dnsResolver ? { dnsResolver } : {})
        });
        const runtimeSca = await detectRuntimeScaFindings(targetCheck.url, governedFetch);
        sendJson(res, 200, { target: targetCheck.url, runtimeSca });
      } catch (err) {
        const status = Boolean(
          err?.isGovernanceBlock ||
          err?.code === 'SSRF_POLICY_BLOCKED' ||
          err?.code === 'TARGET_RULE_BLOCKED' ||
          err?.code === 'DNS_REBIND_OR_PRIVATE_IP'
        ) ? 403 : 400;
        sendJson(res, status, { error: err.message });
      } finally {
        try {
          governedFetch?.destroyAgents?.();
        } catch {}
      }
      return;
    }

    // ── API: GET /api/asm/sbom (Zero-Touch Runtime SCA SBOM & CVE Drift) ────
    if (method === 'GET' && pathname === '/api/asm/sbom') {
      try {
        const records = [];
        try {
          const histList = listHistory();
          if (Array.isArray(histList)) {
            for (const item of histList) {
              if (!item?.id) continue;
              const rec = loadHistoryById(item.id);
              if (rec) records.push(rec);
            }
          }
        } catch {
          // Ignore disk history errors in memory-only mode
        }
        for (const job of jobs.values()) {
          if (job?.status === 'completed' && job.result) {
            records.push({
              id: job.id,
              timestamp: job.result.completedAt || new Date().toISOString(),
              targets: job.targets,
              stacks: job.result.stacks,
              runtimeSca: job.result.runtimeSca,
              results: job.result.results
            });
          }
        }
        const report = buildSbomAndCveDriftReport(records);
        sendJson(res, 200, report);
      } catch (err) {
        sendJson(res, 500, { error: `Failed to generate SBOM drift report: ${err.message}` });
      }
      return;
    }

    // ── API: POST /api/asm/rbac-audit (Multi-Role RBAC & BFLA Matrix Audit) ──
    if (method === 'POST' && pathname === '/api/asm/rbac-audit') {
      const body = await parseJsonBody(req, res);
      if (!body || typeof body !== 'object' || Array.isArray(body)) {
        if (body !== null) sendJson(res, 400, { error: 'Request body must be a JSON object' });
        return;
      }
      let governedFetch = null;
      try {
        const allowPrivate = body.allowPrivate !== undefined ? Boolean(body.allowPrivate) : defaultAllowPrivate;
        let validatedSecondaryHeaders = null;
        if (body.secondaryAuthHeaders !== undefined && body.secondaryAuthHeaders !== null) {
          if (typeof body.secondaryAuthHeaders !== 'object' || Array.isArray(body.secondaryAuthHeaders)) {
            sendJson(res, 400, { error: 'secondaryAuthHeaders must be a header object' });
            return;
          }
          const hdrValidation = validateCustomHeadersResult(body.secondaryAuthHeaders);
          if (!hdrValidation.valid) {
            sendJson(res, 400, { error: hdrValidation.error });
            return;
          }
          validatedSecondaryHeaders = hdrValidation.headers;
        }

        let menus = null;
        let forms = null;

        if (Array.isArray(body.discoveredMenus) || Array.isArray(body.discoveredForms)) {
          menus = Array.isArray(body.discoveredMenus)
            ? body.discoveredMenus.filter(m => m && typeof m === 'object').map(m => ({ ...m }))
            : [];
          forms = Array.isArray(body.discoveredForms)
            ? body.discoveredForms.filter(f => f && typeof f === 'object').map(f => ({ ...f }))
            : [];
        } else if (typeof body.scanId === 'string' && body.scanId.trim()) {
          const job = jobs.get(body.scanId.trim());
          if (!job || !job.result) {
            sendJson(res, 404, { error: 'Scan job not found or not yet completed' });
            return;
          }
          menus = Array.isArray(job.result.discoveredMenus) ? job.result.discoveredMenus : [];
          forms = Array.isArray(job.result.discoveredForms) ? job.result.discoveredForms : [];
        } else if (typeof body.historyId === 'string' && body.historyId.trim()) {
          const hid = body.historyId.trim();
          if (!/^[a-zA-Z0-9._-]+\.json$/.test(hid)) {
            sendJson(res, 400, { error: 'Invalid historyId format' });
            return;
          }
          const record = loadHistoryById(hid);
          if (!record) {
            sendJson(res, 404, { error: 'History record not found' });
            return;
          }
          menus = Array.isArray(record.discoveredMenus) ? record.discoveredMenus : [];
          forms = Array.isArray(record.discoveredForms) ? record.discoveredForms : [];
        } else {
          sendJson(res, 400, {
            error: 'Provide "discoveredMenus"/"discoveredForms", "scanId", or "historyId" for RBAC audit'
          });
          return;
        }

        const dnsResolver = options.dnsResolver ?? options.retestOptions?.dnsResolver ?? null;
        const targetPinStore = new TargetPinStore({ allowPrivate });
        const cleanSourceIp = typeof body.sourceIp === 'string' && body.sourceIp.trim() ? body.sourceIp.trim() : null;

        const candidateUrls = new Set();
        for (const m of menus) {
          if (typeof m?.url === 'string' && m.url.trim()) candidateUrls.add(m.url.trim());
        }
        for (const f of forms) {
          const u = typeof f?.actionUrl === 'string' && f.actionUrl.trim()
            ? f.actionUrl.trim()
            : (typeof f?.pageUrl === 'string' && f.pageUrl.trim() ? f.pageUrl.trim() : '');
          if (u) candidateUrls.add(u);
        }

        for (const rawUrl of candidateUrls) {
          const urlCheck = validateAndGateUrl(rawUrl, { allowPrivate, scopeRules, normalizeBare: false });
          if (!urlCheck.ok) {
            sendJson(res, urlCheck.status, urlCheck.payload);
            return;
          }
          const dnsCheck = await prevalidateResolvedTarget(urlCheck.url, {
            allowPrivate,
            scopeRules,
            dnsResolver,
            targetPinStore,
            sourceIp: cleanSourceIp
          });
          if (!dnsCheck.ok) {
            sendJson(res, dnsCheck.status, dnsCheck.payload);
            return;
          }
        }

        governedFetch = options.fetcher || createGovernedFetch({
          allowPrivate,
          sourceIp: cleanSourceIp,
          scopeRules,
          trafficStore,
          targetPinStore,
          enforceDnsValidation: true,
          ...(dnsResolver ? { dnsResolver } : {})
        });

        const maxProbes = Number.isFinite(Number(body.maxProbes))
          ? Math.max(1, Math.min(50, Math.floor(Number(body.maxProbes))))
          : 12;

        const rbacMatrix = await auditMenuAndFormAccessControl({
          discoveredMenus: menus,
          discoveredForms: forms,
          unauthFetch: governedFetch,
          secondaryAuthHeaders: validatedSecondaryHeaders,
          maxProbes
        });

        sendJson(res, 200, { rbacMatrix });
      } catch (err) {
        const status = Boolean(
          err?.isGovernanceBlock ||
          err?.code === 'SSRF_POLICY_BLOCKED' ||
          err?.code === 'TARGET_RULE_BLOCKED' ||
          err?.code === 'DNS_REBIND_OR_PRIVATE_IP'
        ) ? 403 : 400;
        sendJson(res, status, { error: err.message });
      } finally {
        try {
          governedFetch?.destroyAgents?.();
        } catch {}
      }
      return;
    }

    // ── API: GET /api/auth/sessions (List Recorded Sessions) ────────────────
    if (method === 'GET' && pathname === '/api/auth/sessions') {
      const includeArtifactsParam = (parsedUrl.searchParams.get('includeArtifactValues') || '').trim().toLowerCase();
      const includeArtifactValues = includeArtifactsParam === '1' || includeArtifactsParam === 'true';
      const rawOriginFilter = (parsedUrl.searchParams.get('origin') || parsedUrl.searchParams.get('targetUrl') || '').trim();
      let filterOrigin = '';
      if (rawOriginFilter) {
        try {
          filterOrigin = new URL(rawOriginFilter).origin.toLowerCase();
        } catch {
          filterOrigin = rawOriginFilter.toLowerCase();
        }
      }

      const sessions = [];
      for (const s of recordedSessions.values()) {
        const mgr = AuthSessionManager.fromRecordedSession(s);
        const safeSession = mgr.getRecordedSession({ includeSecrets: false });
        if (filterOrigin) {
          const candidates = [safeSession.targetUrl, safeSession.loginUrl, safeSession.postLoginUrl].filter(Boolean);
          const matchesOrigin = candidates.some(u => {
            try {
              return new URL(u).origin.toLowerCase() === filterOrigin;
            } catch {
              return String(u).toLowerCase().includes(filterOrigin);
            }
          });
          if (!matchesOrigin) continue;
        }
        if (includeArtifactValues) {
          safeSession.authArtifacts = mgr.getRecordedSession({ includeSecrets: true }).authArtifacts;
        }
        sessions.push(safeSession);
      }
      sendJson(res, 200, { sessions });
      return;
    }

    // ── API: DELETE /api/auth/sessions/:id (Delete Recorded Session) ────────
    const authSessionDeleteMatch = pathname.match(/^\/api\/auth\/sessions\/([^/]+)$/);
    if (method === 'DELETE' && authSessionDeleteMatch) {
      let sessionId;
      try {
        sessionId = decodeURIComponent(authSessionDeleteMatch[1]);
      } catch {
        sendJson(res, 400, { error: 'Invalid session ID' });
        return;
      }
      if (!recordedSessions.has(sessionId)) {
        sendJson(res, 404, { error: 'Recorded session not found' });
        return;
      }
      recordedSessions.delete(sessionId);
      sendJson(res, 200, { deleted: true, sessionId });
      return;
    }

    // ── API: Target Systems Registry, Clone & Delta Re-Scan ─────────────────
    if (method === 'GET' && pathname === '/api/target-systems') {
      const systems = Array.from(targetSystems.values()).map(s =>
        exportTargetSystem(s, { includeSecrets: false })
      );
      sendJson(res, 200, { systems });
      return;
    }

    if (method === 'POST' && pathname === '/api/target-systems') {
      const body = await parseJsonBody(req, res);
      if (!body || typeof body !== 'object' || Array.isArray(body)) {
        if (body !== null) sendJson(res, 400, { error: 'Request body must be a JSON object' });
        return;
      }
      try {
        const allowPrivate = body.allowPrivate !== undefined ? Boolean(body.allowPrivate) : defaultAllowPrivate;
        const sys = normalizeTargetSystem({ ...body, allowPrivate });
        const validated = await validateTargetSystemUrls(sys, { checkDns: false });
        if (!validated.ok) {
          sendJson(res, validated.status, validated.payload);
          return;
        }
        storeTargetSystem(targetSystems, sys);
        if (!useInMemory) {
          savePersistedTargetSystems(historyDir, targetSystems);
        }
        sendJson(res, 201, { system: exportTargetSystem(sys, { includeSecrets: false }) });
      } catch (err) {
        const status = err?.statusCode || (err?.isGovernanceBlock ? 403 : 400);
        sendJson(res, status, { error: err.message });
      }
      return;
    }

    const targetSystemCloneMatch = pathname.match(/^\/api\/target-systems\/([^/]+)\/clone$/);
    if (method === 'POST' && targetSystemCloneMatch) {
      let sysId;
      try {
        sysId = decodeURIComponent(targetSystemCloneMatch[1]).trim();
      } catch {
        sendJson(res, 400, { error: 'Invalid target system ID' });
        return;
      }
      if (!sysId || !targetSystems.has(sysId)) {
        sendJson(res, 404, { error: 'Target system not found' });
        return;
      }
      const body = await parseOptionalJsonBody(req, res);
      if (!body) return;
      if (typeof body !== 'object' || Array.isArray(body)) {
        sendJson(res, 400, { error: 'Request body must be a JSON object' });
        return;
      }
      try {
        const source = targetSystems.get(sysId);
        const cloned = cloneTargetSystemConfig(source, body);
        const validated = await validateTargetSystemUrls(cloned, { checkDns: false });
        if (!validated.ok) {
          sendJson(res, validated.status, validated.payload);
          return;
        }
        storeTargetSystem(targetSystems, cloned);
        if (!useInMemory) {
          savePersistedTargetSystems(historyDir, targetSystems);
        }
        sendJson(res, 201, {
          system: exportTargetSystem(cloned, { includeSecrets: false }),
          clonedFromId: source.id
        });
      } catch (err) {
        const status = err?.statusCode || (err?.isGovernanceBlock ? 403 : 400);
        sendJson(res, status, { error: err.message });
      }
      return;
    }

    const targetSystemRunMatch = pathname.match(/^\/api\/target-systems\/([^/]+)\/run$/);
    if (method === 'POST' && targetSystemRunMatch) {
      let sysId;
      try {
        sysId = decodeURIComponent(targetSystemRunMatch[1]).trim();
      } catch {
        sendJson(res, 400, { error: 'Invalid target system ID' });
        return;
      }
      if (!sysId || !targetSystems.has(sysId)) {
        sendJson(res, 404, { error: 'Target system not found' });
        return;
      }
      const body = await parseOptionalJsonBody(req, res);
      if (!body) return;
      if (typeof body !== 'object' || Array.isArray(body)) {
        sendJson(res, 400, { error: 'Request body must be a JSON object' });
        return;
      }
      const sys = targetSystems.get(sysId);
      const runMode = body.mode === 'open_issues_only' ? 'open_issues_only' : 'full_profile';
      const { checks, fallbackToFullProfile } = resolveChecksForTargetSystemRun(sys, runMode, body.checks);

      const launched = await launchTargetSystemScan(sys, { runMode, checks });
      if (!launched.ok) {
        sendJson(res, launched.status, launched.payload);
        return;
      }

      const nowDate = new Date();
      if (sys.schedule) {
        sys.schedule.lastTriggeredAt = nowDate.toISOString();
        if (sys.schedule.enabled) {
          sys.schedule.nextRunAt = computeNextScheduleRunAt(sys.schedule, nowDate);
        }
      }
      sys.updatedAt = nowDate.toISOString();
      if (!useInMemory) {
        savePersistedTargetSystems(historyDir, targetSystems);
      }

      sendJson(res, 202, {
        scanId: launched.job.id,
        status: 'running',
        targetSystemId: sys.id,
        targetSystemName: sys.name,
        mode: runMode,
        checks,
        checksCount: checks.length,
        fallbackToFullProfile,
        targets: launched.job.targets
      });
      return;
    }

    const targetSystemItemMatch = pathname.match(/^\/api\/target-systems\/([^/]+)$/);
    if (targetSystemItemMatch && (method === 'GET' || method === 'PUT' || method === 'DELETE')) {
      let sysId;
      try {
        sysId = decodeURIComponent(targetSystemItemMatch[1]).trim();
      } catch {
        sendJson(res, 400, { error: 'Invalid target system ID' });
        return;
      }
      if (!sysId || !targetSystems.has(sysId)) {
        sendJson(res, 404, { error: 'Target system not found' });
        return;
      }

      if (method === 'GET') {
        sendJson(res, 200, { system: exportTargetSystem(targetSystems.get(sysId), { includeSecrets: false }) });
        return;
      }

      if (method === 'PUT') {
        const body = await parseJsonBody(req, res);
        if (!body || typeof body !== 'object' || Array.isArray(body)) {
          if (body !== null) sendJson(res, 400, { error: 'Request body must be a JSON object' });
          return;
        }
        try {
          const existing = targetSystems.get(sysId);
          const updated = normalizeTargetSystem(body, existing);
          const validated = await validateTargetSystemUrls(updated, { checkDns: false });
          if (!validated.ok) {
            sendJson(res, validated.status, validated.payload);
            return;
          }
          if (updated.sequenceId && savedSequences.has(updated.sequenceId) && (body.sequenceId !== undefined || !updated.sequenceName)) {
            updated.sequenceName = savedSequences.get(updated.sequenceId)?.name || updated.sequenceName;
          }
          storeTargetSystem(targetSystems, updated);
          if (!useInMemory) {
            savePersistedTargetSystems(historyDir, targetSystems);
          }
          sendJson(res, 200, { system: exportTargetSystem(updated, { includeSecrets: false }) });
        } catch (err) {
          const status = err?.statusCode || (err?.isGovernanceBlock ? 403 : 400);
          sendJson(res, status, { error: err.message });
        }
        return;
      }

      if (method === 'DELETE') {
        targetSystems.delete(sysId);
        if (!useInMemory) {
          savePersistedTargetSystems(historyDir, targetSystems);
        }
        sendJson(res, 200, { deleted: true, id: sysId });
        return;
      }
    }

    // ── Static Assets (UI) ──────────────────────────────────────────────────
    if (method === 'GET') {
      serveStaticFile(req, res, pathname);
      return;
    }

    sendJson(res, 405, { error: 'Method Not Allowed' });
  });

  server.context = {
    jobs,
    recordedSessions,
    savedSequences,
    systemVariables,
    targetSystems,
    runDueScheduledTargetSystems,
    graphStore,
    trafficStore,
    evidenceStore,
    llmPool,
    llmRecorder,
    aiAdvisor,
    sideQuestionService,
    getNoiseGovernor: () => noiseGovernor,
    skillRegistry,
    agentEngine,
    getScopeRules: () => scopeRules,
    getInterceptRules: () => interceptRules
  };

  server.on('close', () => {
    if (scheduleTimer) clearInterval(scheduleTimer);
    if (ownsEvidenceStore) evidenceStore.close();
    if (ownsTrafficStore) trafficStore.close();
    if (ownsGraphStore) graphStore.close();
  });

  return server;
}

/**
 * Starts the server and listens on the configured host & port.
 */
export function startServer(options = {}) {
  const { port = 4321, host = '127.0.0.1' } = options;
  const server = createAppServer(options);

  return new Promise((resolve, reject) => {
    server.on('error', reject);
    server.listen(port, host, () => {
      const address = server.address();
      const actualPort = typeof address === 'object' && address ? address.port : port;
      const formattedHost = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
      const url = `http://${formattedHost}:${actualPort}`;
      console.log(`🚀 Security Scanner UI Server running at ${url}`);
      resolve({ server, port: actualPort, host, url });
    });
  });
}

// Automatically start if executed directly via `node core/server.js`
if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  const port = parseInt(process.env.PORT || '4321', 10);
  const host = process.env.HOST || '127.0.0.1';
  startServer({ port, host }).catch(err => {
    console.error('Failed to start server:', err);
    process.exit(1);
  });
}
