import crypto from 'node:crypto';
import path from 'node:path';

export const SCHEDULE_INTERVAL_MINUTES = {
  manual: 0,
  hourly: 60,
  every_6h: 360,
  daily: 1440,
  weekly: 10080
};

export const VALID_ENVIRONMENTS = ['production', 'staging', 'development', 'qa', 'custom'];
export const VALID_SCHEDULE_MODES = ['open_issues_only', 'full_profile'];

const VALID_NOISE_PROFILES = new Set(['balanced', 'quiet', 'aggressive', 'off']);
const VALID_AUTH_METHODS = new Set(['none', 'lsr', 'bearer', 'cookie', 'form']);
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const SENSITIVE_HEADER_NAMES = new Set(['authorization', 'cookie', 'x-api-key', 'proxy-authorization']);

const SEVERITY_RANK = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0,
  NONE: 0
};

function resolveFindingCheckId(r) {
  if (!r || typeof r !== 'object') return '';
  return String(r.checkId || r.check || r.id || r.meta?.id || r.name || '').trim();
}

/**
 * Computes the next scheduled ISO timestamp from a schedule configuration object.
 *
 * @param {object} schedule
 * @param {Date} [now=new Date()]
 * @returns {string|null}
 */
export function computeNextScheduleRunAt(schedule, now = new Date()) {
  if (!schedule || !schedule.enabled) return null;
  const baseDate = now instanceof Date && !Number.isNaN(now.getTime()) ? now : new Date();
  const intervalKey = String(schedule.interval || '').trim().toLowerCase();

  let intervalMinutes;
  if (
    intervalKey &&
    intervalKey !== 'custom' &&
    Object.hasOwn(SCHEDULE_INTERVAL_MINUTES, intervalKey) &&
    SCHEDULE_INTERVAL_MINUTES[intervalKey] > 0
  ) {
    intervalMinutes = SCHEDULE_INTERVAL_MINUTES[intervalKey];
  } else {
    const rawMin = Number(schedule.intervalMinutes);
    intervalMinutes = Number.isFinite(rawMin) && rawMin >= 1
      ? Math.max(1, Math.min(Math.floor(rawMin), 43200))
      : 60;
  }

  return new Date(baseDate.getTime() + intervalMinutes * 60_000).toISOString();
}

/**
 * Extracts deduplicated unfixed (`VULNERABLE` or `SUSPICIOUS`) checks from scan results.
 *
 * @param {Array<object>} [results=[]]
 * @returns {{
 *   unfixedCheckIds: string[],
 *   unfixedChecks: Array<{ id: string, name: string, status: string, severity: string, category: string }>,
 *   vulnerableCount: number,
 *   suspiciousCount: number
 * }}
 */
export function extractUnfixedChecksFromResults(results = []) {
  const list = Array.isArray(results) ? results : [];
  const byId = new Map();
  let vulnerableCount = 0;
  let suspiciousCount = 0;

  for (const r of list) {
    if (!r || typeof r !== 'object') continue;
    const status = String(r.status || '').trim().toUpperCase();
    if (status === 'VULNERABLE') vulnerableCount++;
    else if (status === 'SUSPICIOUS') suspiciousCount++;
    else continue;

    const checkId = resolveFindingCheckId(r);
    if (!checkId || FORBIDDEN_KEYS.has(checkId)) continue;

    const severity = String(r.severity || 'MEDIUM').trim().toUpperCase();
    const name = String(r.title || r.meta?.title || r.name || checkId).trim().slice(0, 160);
    const category = String(r.category || r.meta?.category || 'General').trim().slice(0, 80);

    if (!byId.has(checkId)) {
      byId.set(checkId, {
        id: checkId,
        name,
        status,
        severity,
        category
      });
    } else {
      const prev = byId.get(checkId);
      if (status === 'VULNERABLE' && prev.status !== 'VULNERABLE') {
        prev.status = 'VULNERABLE';
      }
      if ((SEVERITY_RANK[severity] ?? 0) > (SEVERITY_RANK[prev.severity] ?? 0)) {
        prev.severity = severity;
      }
    }
  }

  const unfixedChecks = Array.from(byId.values());
  return {
    unfixedCheckIds: unfixedChecks.map(c => c.id),
    unfixedChecks,
    vulnerableCount,
    suspiciousCount
  };
}

/**
 * Merges a completed scan job result into a Target System's `lastScanSummary`,
 * tracking open vs. newly fixed check IDs across `full_profile` and `open_issues_only` runs.
 *
 * @param {object|null} existingSummary
 * @param {object} scanJobResult
 * @param {'full_profile'|'open_issues_only'} [runMode='full_profile']
 * @param {string[]} [executedCheckIds=[]]
 * @returns {object}
 */
export function mergeDeltaScanSummary(
  existingSummary,
  scanJobResult,
  runMode = 'full_profile',
  executedCheckIds = []
) {
  const effectiveMode = runMode === 'open_issues_only' ? 'open_issues_only' : 'full_profile';
  const rawResults = Array.isArray(scanJobResult?.results) ? scanJobResult.results : [];
  const extracted = extractUnfixedChecksFromResults(rawResults);
  const freshById = new Map(extracted.unfixedChecks.map(c => [c.id, c]));

  const prevChecks = Array.isArray(existingSummary?.unfixedChecks)
    ? existingSummary.unfixedChecks.filter(c => c && typeof c.id === 'string' && c.id.trim())
    : [];

  const testedSet = new Set();
  if (Array.isArray(executedCheckIds)) {
    for (const id of executedCheckIds) {
      const clean = String(id || '').trim();
      if (clean) testedSet.add(clean);
    }
  }
  for (const r of rawResults) {
    const cid = resolveFindingCheckId(r);
    if (cid) testedSet.add(cid);
  }

  const fixedCheckIds = [];
  let mergedUnfixedChecks = [];

  if (effectiveMode === 'open_issues_only' && prevChecks.length > 0) {
    const seenIds = new Set();
    for (const prev of prevChecks) {
      const cid = String(prev.id).trim();
      if (!cid || seenIds.has(cid)) continue;
      if (testedSet.has(cid)) {
        if (freshById.has(cid)) {
          mergedUnfixedChecks.push(freshById.get(cid));
          seenIds.add(cid);
        } else {
          fixedCheckIds.push(cid);
        }
      } else {
        mergedUnfixedChecks.push({
          id: cid,
          name: String(prev.name || cid).slice(0, 160),
          status: String(prev.status || 'VULNERABLE').toUpperCase(),
          severity: String(prev.severity || 'MEDIUM').toUpperCase(),
          category: String(prev.category || 'General').slice(0, 80)
        });
        seenIds.add(cid);
      }
    }
    for (const [cid, item] of freshById.entries()) {
      if (!seenIds.has(cid)) {
        mergedUnfixedChecks.push(item);
        seenIds.add(cid);
      }
    }
  } else {
    if (prevChecks.length > 0) {
      for (const prev of prevChecks) {
        const cid = String(prev.id).trim();
        if (cid && !freshById.has(cid)) {
          fixedCheckIds.push(cid);
        }
      }
    }
    mergedUnfixedChecks = extracted.unfixedChecks;
  }

  const historyId =
    scanJobResult?.historyId ||
    (typeof scanJobResult?.historyFile === 'string' && scanJobResult.historyFile.trim()
      ? path.basename(scanJobResult.historyFile.trim(), '.json')
      : null);

  return {
    lastScanId: scanJobResult?.scanId || null,
    lastHistoryId: historyId,
    lastRunAt: scanJobResult?.completedAt || new Date().toISOString(),
    lastMode: effectiveMode,
    lastGrade: scanJobResult?.risk?.grade || existingSummary?.lastGrade || null,
    lastRiskLevel: scanJobResult?.risk?.level || existingSummary?.lastRiskLevel || null,
    lastScore: scanJobResult?.risk?.score ?? existingSummary?.lastScore ?? null,
    lastVulnerableCount: mergedUnfixedChecks.filter(c => c.status === 'VULNERABLE').length,
    lastSuspiciousCount: mergedUnfixedChecks.filter(c => c.status === 'SUSPICIOUS').length,
    fixedInLastRunCount: fixedCheckIds.length,
    fixedInLastRunCheckIds: fixedCheckIds,
    unfixedCheckIds: mergedUnfixedChecks.map(c => c.id),
    unfixedChecks: mergedUnfixedChecks
  };
}

function sanitizeCustomHeadersMap(rawHeaders, existingHeaders = null) {
  const out = {};
  if (!rawHeaders || typeof rawHeaders !== 'object' || Array.isArray(rawHeaders)) {
    return existingHeaders && typeof existingHeaders === 'object' ? { ...existingHeaders } : out;
  }
  const entries = Object.entries(rawHeaders).slice(0, 25);
  for (const [rawK, rawV] of entries) {
    const key = String(rawK || '').replace(/[\r\n]+/g, '').trim().slice(0, 120);
    if (!key || FORBIDDEN_KEYS.has(key) || FORBIDDEN_KEYS.has(key.toLowerCase())) continue;
    const val = String(rawV ?? '').replace(/[\r\n]+/g, '').trim().slice(0, 2048);
    if (
      (val === '[REDACTED]' || val === '[SECRET]') &&
      existingHeaders &&
      typeof existingHeaders === 'object' &&
      typeof existingHeaders[key] === 'string' &&
      existingHeaders[key] !== '[REDACTED]' &&
      existingHeaders[key] !== '[SECRET]'
    ) {
      out[key] = existingHeaders[key];
    } else {
      out[key] = val;
    }
  }
  return out;
}

function normalizeCheckIdsList(rawChecks) {
  if (!rawChecks) return [];
  const rawList = Array.isArray(rawChecks)
    ? rawChecks
    : typeof rawChecks === 'string'
      ? rawChecks.split(',')
      : [];
  const seen = new Set();
  const out = [];
  for (const item of rawList) {
    const clean = String(item || '').trim();
    if (!clean || FORBIDDEN_KEYS.has(clean) || seen.has(clean)) continue;
    seen.add(clean);
    out.push(clean);
    if (out.length >= 200) break;
  }
  return out;
}

/**
 * Validates and normalizes a Target System configuration object.
 *
 * @param {object} [input={}]
 * @param {object|null} [existing=null]
 * @returns {object}
 */
export function normalizeTargetSystem(input = {}, existing = null) {
  const src = input && typeof input === 'object' && !Array.isArray(input) ? input : {};
  const prev = existing && typeof existing === 'object' && !Array.isArray(existing) ? existing : null;

  const id = prev?.id
    ? String(prev.id)
    : (typeof src.id === 'string' && /^[a-zA-Z0-9_-]{3,80}$/.test(src.id.trim())
        ? src.id.trim()
        : `ts_${crypto.randomUUID()}`);

  const rawEnv = String(src.environment ?? prev?.environment ?? 'production').trim().toLowerCase();
  const environment = VALID_ENVIRONMENTS.includes(rawEnv) ? rawEnv : 'production';

  const rawPrimaryUrl = String(
    src.targetUrl ??
    src.target ??
    (Array.isArray(src.targets) && src.targets.length > 0 ? src.targets[0] : undefined) ??
    prev?.targetUrl ??
    ''
  ).trim();

  if (!rawPrimaryUrl) {
    const err = new Error('Target System requires a non-empty targetUrl');
    err.statusCode = 400;
    throw err;
  }

  const targetsSet = new Set([rawPrimaryUrl]);
  const incomingTargets = Array.isArray(src.targets)
    ? src.targets
    : (src.targetUrl === undefined && src.target === undefined && Array.isArray(prev?.targets) ? prev.targets : []);
  for (const t of incomingTargets) {
    if (typeof t === 'string' && t.trim()) {
      targetsSet.add(t.trim());
      if (targetsSet.size >= 25) break;
    }
  }
  const targets = Array.from(targetsSet);
  const targetUrl = targets[0];

  let derivedDefaultName = targetUrl;
  try {
    const parsed = new URL(targetUrl.includes('://') ? targetUrl : `https://${targetUrl}`);
    derivedDefaultName = `${parsed.hostname}${parsed.pathname && parsed.pathname !== '/' ? parsed.pathname : ''} (${environment})`;
  } catch {
    derivedDefaultName = `${targetUrl} (${environment})`;
  }

  const rawName = String(src.name ?? prev?.name ?? '').trim();
  const name = (rawName || derivedDefaultName).slice(0, 140);
  const description = String(src.description ?? prev?.description ?? '').trim().slice(0, 500);

  const profile = String(src.profile ?? prev?.profile ?? 'smart').trim() || 'smart';
  const rawMaxDepth = Number(src.maxDepth ?? prev?.maxDepth ?? 3);
  const maxDepth = Number.isFinite(rawMaxDepth) ? Math.max(0, Math.min(Math.floor(rawMaxDepth), 5)) : 3;
  const rawConcurrency = Number(src.concurrency ?? prev?.concurrency ?? 5);
  const concurrency = Number.isFinite(rawConcurrency) ? Math.max(1, Math.min(Math.floor(rawConcurrency), 10)) : 5;
  const rawTimeout = Number(src.timeout ?? prev?.timeout ?? 10000);
  const timeout = Number.isFinite(rawTimeout) ? Math.max(1000, Math.min(Math.floor(rawTimeout), 60000)) : 10000;

  const rawNoise = String(src.noiseProfile ?? prev?.noiseProfile ?? 'balanced').trim().toLowerCase();
  const noiseProfile = VALID_NOISE_PROFILES.has(rawNoise) ? rawNoise : 'balanced';

  const allowPrivate = src.allowPrivate !== undefined
    ? Boolean(src.allowPrivate)
    : Boolean(prev?.allowPrivate);
  const deviceMode = src.deviceMode !== undefined
    ? Boolean(src.deviceMode)
    : Boolean(prev?.deviceMode);
  const deviceCategory = String(src.deviceCategory ?? prev?.deviceCategory ?? 'all').trim() || 'all';
  const rawSourceIp = src.sourceIp !== undefined ? src.sourceIp : prev?.sourceIp;
  const sourceIp = typeof rawSourceIp === 'string' && rawSourceIp.trim() ? rawSourceIp.trim() : null;

  let techOverride = null;
  const rawTech = src.techOverride !== undefined ? src.techOverride : prev?.techOverride;
  if (Array.isArray(rawTech)) {
    const cleanTech = rawTech.map(t => String(t || '').trim()).filter(Boolean);
    if (cleanTech.length > 0) techOverride = cleanTech;
  } else if (typeof rawTech === 'string' && rawTech.trim()) {
    techOverride = rawTech.split(',').map(t => t.trim()).filter(Boolean);
  }

  const forceAll = src.forceAll !== undefined ? Boolean(src.forceAll) : Boolean(prev?.forceAll);
  const agentMode = src.agentMode !== undefined
    ? Boolean(src.agentMode)
    : (src.agent !== undefined ? Boolean(src.agent) : Boolean(prev?.agentMode));
  const rawGoal = src.goal !== undefined ? src.goal : prev?.goal;
  const goal = typeof rawGoal === 'string' && rawGoal.trim() ? rawGoal.trim().slice(0, 300) : null;

  const checks = src.checks !== undefined
    ? normalizeCheckIdsList(src.checks)
    : normalizeCheckIdsList(prev?.checks);

  // Auth configuration (never store plaintext passwords)
  const rawSeqId = src.sequenceId !== undefined ? src.sequenceId : prev?.sequenceId;
  const sequenceId = typeof rawSeqId === 'string' && rawSeqId.trim() ? rawSeqId.trim() : null;
  const rawSeqName = src.sequenceName !== undefined ? src.sequenceName : prev?.sequenceName;
  const sequenceName = typeof rawSeqName === 'string' && rawSeqName.trim() ? rawSeqName.trim() : null;
  const rawRecId = src.recordedSessionId !== undefined ? src.recordedSessionId : prev?.recordedSessionId;
  const recordedSessionId = typeof rawRecId === 'string' && rawRecId.trim() ? rawRecId.trim() : null;
  const rawLoginUrl = src.loginUrl !== undefined ? src.loginUrl : prev?.loginUrl;
  const loginUrl = typeof rawLoginUrl === 'string' && rawLoginUrl.trim() ? rawLoginUrl.trim() : null;
  const rawUsername = src.username !== undefined ? src.username : prev?.username;
  const username = typeof rawUsername === 'string' && rawUsername.trim() ? rawUsername.trim().slice(0, 120) : null;

  let authHeader = null;
  const rawAuthHeader = src.authHeader !== undefined
    ? src.authHeader
    : (src.auth !== undefined ? src.auth : prev?.authHeader);
  if (typeof rawAuthHeader === 'string' && rawAuthHeader.trim()) {
    const trimmedAuth = rawAuthHeader.replace(/[\r\n]+/g, '').trim();
    if ((trimmedAuth === '[REDACTED]' || trimmedAuth === '[SECRET]') && prev?.authHeader) {
      authHeader = prev.authHeader;
    } else if (trimmedAuth !== '[REDACTED]' && trimmedAuth !== '[SECRET]') {
      authHeader = trimmedAuth;
    }
  }

  const customHeaders = src.customHeaders !== undefined || src.headers !== undefined
    ? sanitizeCustomHeadersMap(src.customHeaders ?? src.headers, prev?.customHeaders)
    : sanitizeCustomHeadersMap(prev?.customHeaders);

  const rawAuthMethod = String(src.authMethod ?? prev?.authMethod ?? '').trim().toLowerCase();
  let authMethod = VALID_AUTH_METHODS.has(rawAuthMethod) ? rawAuthMethod : 'none';
  if (sequenceId && (authMethod === 'none' || !src.authMethod)) {
    authMethod = 'lsr';
  } else if (!sequenceId && authHeader && authMethod === 'none') {
    authMethod = 'bearer';
  }

  // Schedule configuration
  const rawSched = src.schedule && typeof src.schedule === 'object' && !Array.isArray(src.schedule)
    ? src.schedule
    : {};
  const prevSched = prev?.schedule && typeof prev.schedule === 'object' ? prev.schedule : {};

  const rawInterval = String(rawSched.interval ?? src.scheduleInterval ?? prevSched.interval ?? 'manual')
    .trim()
    .toLowerCase();
  const interval = (Object.hasOwn(SCHEDULE_INTERVAL_MINUTES, rawInterval) || rawInterval === 'custom')
    ? rawInterval
    : 'manual';

  let enabled;
  if (interval === 'manual') {
    enabled = false;
  } else if (rawSched.enabled !== undefined) {
    enabled = Boolean(rawSched.enabled);
  } else if (src.scheduleEnabled !== undefined) {
    enabled = Boolean(src.scheduleEnabled);
  } else if (rawSched.interval !== undefined || src.scheduleInterval !== undefined) {
    enabled = true;
  } else {
    enabled = Boolean(prevSched.enabled);
  }

  let intervalMinutes = 0;
  if (interval !== 'manual') {
    if (interval !== 'custom' && SCHEDULE_INTERVAL_MINUTES[interval] > 0) {
      intervalMinutes = SCHEDULE_INTERVAL_MINUTES[interval];
    } else {
      const rawMin = Number(rawSched.intervalMinutes ?? src.scheduleIntervalMinutes ?? prevSched.intervalMinutes ?? 60);
      intervalMinutes = Number.isFinite(rawMin) && rawMin >= 1
        ? Math.max(1, Math.min(Math.floor(rawMin), 43200))
        : 60;
    }
  }

  const rawMode = String(rawSched.mode ?? src.scheduleMode ?? prevSched.mode ?? 'open_issues_only')
    .trim()
    .toLowerCase();
  const mode = VALID_SCHEDULE_MODES.includes(rawMode) ? rawMode : 'open_issues_only';

  const intervalChanged = prevSched.interval !== interval || prevSched.intervalMinutes !== intervalMinutes;
  let nextRunAt = null;
  if (enabled) {
    if (typeof rawSched.nextRunAt === 'string' && rawSched.nextRunAt.trim() && !Number.isNaN(Date.parse(rawSched.nextRunAt))) {
      nextRunAt = new Date(rawSched.nextRunAt).toISOString();
    } else if (
      !intervalChanged &&
      prevSched.enabled &&
      typeof prevSched.nextRunAt === 'string' &&
      Date.parse(prevSched.nextRunAt) > Date.now()
    ) {
      nextRunAt = prevSched.nextRunAt;
    } else {
      nextRunAt = computeNextScheduleRunAt({ enabled, interval, intervalMinutes });
    }
  }

  const lastTriggeredAt = rawSched.lastTriggeredAt !== undefined
    ? rawSched.lastTriggeredAt
    : (prevSched.lastTriggeredAt ?? null);

  const schedule = {
    enabled,
    interval,
    intervalMinutes,
    mode,
    nextRunAt,
    lastTriggeredAt
  };

  let lastScanSummary = prev?.lastScanSummary || null;
  if (src.lastScanSummary && typeof src.lastScanSummary === 'object' && !Array.isArray(src.lastScanSummary)) {
    const rawSum = src.lastScanSummary;
    const unfixedChecks = Array.isArray(rawSum.unfixedChecks)
      ? rawSum.unfixedChecks
          .filter(c => c && typeof c.id === 'string' && c.id.trim())
          .map(c => ({
            id: String(c.id).trim(),
            name: String(c.name || c.id).slice(0, 160),
            status: String(c.status || 'VULNERABLE').toUpperCase(),
            severity: String(c.severity || 'MEDIUM').toUpperCase(),
            category: String(c.category || 'General').slice(0, 80)
          }))
      : [];
    const unfixedCheckIds = unfixedChecks.length > 0
      ? unfixedChecks.map(c => c.id)
      : normalizeCheckIdsList(rawSum.unfixedCheckIds);
    lastScanSummary = {
      lastScanId: rawSum.lastScanId || null,
      lastHistoryId: rawSum.lastHistoryId || null,
      lastRunAt: rawSum.lastRunAt || null,
      lastMode: rawSum.lastMode || 'full_profile',
      lastGrade: rawSum.lastGrade || null,
      lastRiskLevel: rawSum.lastRiskLevel || null,
      lastScore: rawSum.lastScore ?? null,
      lastVulnerableCount: Number(rawSum.lastVulnerableCount ?? unfixedChecks.filter(c => c.status === 'VULNERABLE').length) || 0,
      lastSuspiciousCount: Number(rawSum.lastSuspiciousCount ?? unfixedChecks.filter(c => c.status === 'SUSPICIOUS').length) || 0,
      fixedInLastRunCount: Number(rawSum.fixedInLastRunCount) || 0,
      fixedInLastRunCheckIds: normalizeCheckIdsList(rawSum.fixedInLastRunCheckIds),
      unfixedCheckIds,
      unfixedChecks
    };
  }

  const nowIso = new Date().toISOString();
  const createdAt = (typeof prev?.createdAt === 'string' && prev.createdAt)
    ? prev.createdAt
    : (typeof src.createdAt === 'string' && !Number.isNaN(Date.parse(src.createdAt))
        ? new Date(src.createdAt).toISOString()
        : nowIso);
  const updatedAt = nowIso;

  return {
    id,
    name,
    description,
    environment,
    targetUrl,
    targets,
    profile,
    maxDepth,
    concurrency,
    timeout,
    noiseProfile,
    allowPrivate,
    deviceMode,
    deviceCategory,
    sourceIp,
    techOverride,
    forceAll,
    agentMode,
    goal,
    checks,
    authMethod,
    sequenceId,
    sequenceName,
    recordedSessionId,
    loginUrl,
    username,
    authHeader,
    customHeaders,
    schedule,
    lastScanSummary,
    createdAt,
    updatedAt
  };
}

/**
 * Clones a saved Target System configuration into a new Target System with a fresh ID,
 * applying optional overrides (`name`, `targetUrl`, `environment`, `sequenceId`, etc.).
 *
 * @param {object} sourceSystem
 * @param {object} [overrides={}]
 * @returns {object}
 */
export function cloneTargetSystemConfig(sourceSystem, overrides = {}) {
  if (!sourceSystem || typeof sourceSystem !== 'object') {
    const err = new Error('Source Target System is required for cloning');
    err.statusCode = 400;
    throw err;
  }
  const ov = overrides && typeof overrides === 'object' && !Array.isArray(overrides) ? overrides : {};

  const newTargetUrl = ov.targetUrl || ov.target || (Array.isArray(ov.targets) && ov.targets[0]) || sourceSystem.targetUrl;
  const newTargets = Array.isArray(ov.targets) && ov.targets.length > 0
    ? ov.targets
    : (ov.targetUrl || ov.target ? [newTargetUrl] : [...(sourceSystem.targets || [sourceSystem.targetUrl])]);

  let clonedChecks = ov.checks !== undefined
    ? normalizeCheckIdsList(ov.checks)
    : [...(sourceSystem.checks || [])];
  if (ov.copyUnfixedChecks === true && Array.isArray(sourceSystem.lastScanSummary?.unfixedCheckIds)) {
    clonedChecks = normalizeCheckIdsList([...clonedChecks, ...sourceSystem.lastScanSummary.unfixedCheckIds]);
  }

  const ovSched = ov.schedule && typeof ov.schedule === 'object' ? ov.schedule : {};
  const clonedSchedule = {
    ...(sourceSystem.schedule || {}),
    ...ovSched,
    enabled: ovSched.enabled !== undefined ? Boolean(ovSched.enabled) : false,
    lastTriggeredAt: null,
    nextRunAt: null
  };

  return normalizeTargetSystem({
    ...sourceSystem,
    ...ov,
    id: `ts_${crypto.randomUUID()}`,
    name: typeof ov.name === 'string' && ov.name.trim()
      ? ov.name.trim()
      : `${sourceSystem.name || 'Target System'} (Clone)`,
    targetUrl: newTargetUrl,
    targets: newTargets,
    checks: clonedChecks,
    customHeaders: ov.customHeaders !== undefined || ov.headers !== undefined
      ? sanitizeCustomHeadersMap(ov.customHeaders ?? ov.headers, sourceSystem.customHeaders)
      : { ...(sourceSystem.customHeaders || {}) },
    schedule: clonedSchedule,
    lastScanSummary: ov.preserveLastScanSummary === true ? sourceSystem.lastScanSummary : null,
    createdAt: new Date().toISOString()
  });
}

/**
 * Resolves the list of check IDs to execute for a Target System scan run.
 *
 * @param {object} system
 * @param {'full_profile'|'open_issues_only'} [runMode='full_profile']
 * @param {string[]|null} [overrideChecks=null]
 * @returns {{ checks: string[], mode: 'full_profile'|'open_issues_only', fallbackToFullProfile: boolean }}
 */
export function resolveChecksForTargetSystemRun(system, runMode = 'full_profile', overrideChecks = null) {
  const effectiveMode = runMode === 'open_issues_only' ? 'open_issues_only' : 'full_profile';
  const explicitList = normalizeCheckIdsList(overrideChecks);
  if (explicitList.length > 0) {
    return {
      checks: explicitList,
      mode: effectiveMode,
      fallbackToFullProfile: false
    };
  }

  if (effectiveMode === 'open_issues_only') {
    const unfixedIds = normalizeCheckIdsList(system?.lastScanSummary?.unfixedCheckIds);
    if (unfixedIds.length > 0) {
      return {
        checks: unfixedIds,
        mode: 'open_issues_only',
        fallbackToFullProfile: false
      };
    }
    const pinnedIds = normalizeCheckIdsList(system?.checks);
    if (pinnedIds.length > 0) {
      return {
        checks: pinnedIds,
        mode: 'open_issues_only',
        fallbackToFullProfile: false
      };
    }
    return {
      checks: [],
      mode: 'open_issues_only',
      fallbackToFullProfile: true
    };
  }

  return {
    checks: normalizeCheckIdsList(system?.checks),
    mode: 'full_profile',
    fallbackToFullProfile: false
  };
}

/**
 * Exports a Target System object for API responses or persistence, masking secret headers
 * when `includeSecrets` is `false`.
 *
 * @param {object} system
 * @param {{ includeSecrets?: boolean }} [options={}]
 * @returns {object}
 */
export function exportTargetSystem(system, { includeSecrets = false } = {}) {
  if (!system || typeof system !== 'object') return null;
  const maskedHeaders = {};
  if (system.customHeaders && typeof system.customHeaders === 'object') {
    for (const [k, v] of Object.entries(system.customHeaders)) {
      if (!includeSecrets && SENSITIVE_HEADER_NAMES.has(k.toLowerCase()) && v) {
        maskedHeaders[k] = '[REDACTED]';
      } else {
        maskedHeaders[k] = v;
      }
    }
  }

  return {
    ...system,
    targets: Array.isArray(system.targets) ? [...system.targets] : [system.targetUrl],
    checks: Array.isArray(system.checks) ? [...system.checks] : [],
    techOverride: Array.isArray(system.techOverride) ? [...system.techOverride] : null,
    hasAuthHeader: Boolean(system.authHeader),
    authHeader: includeSecrets ? (system.authHeader || null) : (system.authHeader ? '[REDACTED]' : null),
    customHeaders: maskedHeaders,
    schedule: system.schedule ? { ...system.schedule } : null,
    lastScanSummary: system.lastScanSummary
      ? {
          ...system.lastScanSummary,
          unfixedCheckIds: [...(system.lastScanSummary.unfixedCheckIds || [])],
          unfixedChecks: (system.lastScanSummary.unfixedChecks || []).map(c => ({ ...c })),
          fixedInLastRunCheckIds: [...(system.lastScanSummary.fixedInLastRunCheckIds || [])]
        }
      : null
  };
}
