/**
 * Multi-Provider LLM Failover Pool, Circuit Breaker, Equal-Rank Group Rotation,
 * Context-Window Pre-Filtering, and Per-Task Round-Robin Worker Rotation (`llmRotate`).
 */

import {
  HARD_FAILURE_STATUSES,
  SOFT_FAILURE_STATUSES,
  LlmProviderError,
  buildProviderRequest,
  callProvider,
  isQuotaExhaustedMessage,
  maskSecret,
} from './llm-provider.js';

export const COOLDOWN_LADDER_MS = Object.freeze([60_000, 300_000, 1_800_000]);

/**
 * Fast character/token heuristic (~ceil(chars / 3.8) plus tool schema overhead).
 *
 * @param {string|Array<object>|object} messagesOrText
 * @returns {number}
 */
export function estimateTokens(messagesOrText) {
  if (!messagesOrText) return 0;

  if (typeof messagesOrText === 'string') {
    return Math.ceil(messagesOrText.length / 3.8);
  }

  let totalChars = 0;
  let toolSchemaOverheadTokens = 0;

  const accumulateMessage = (msg) => {
    if (!msg) return;
    if (typeof msg === 'string') {
      totalChars += msg.length;
      return;
    }
    if (typeof msg.role === 'string') {
      totalChars += msg.role.length + 4;
    }
    if (typeof msg.content === 'string') {
      totalChars += msg.content.length;
    } else if (msg.content !== undefined && msg.content !== null) {
      totalChars += JSON.stringify(msg.content).length;
    }
    if (msg.tool_calls || msg.toolCalls) {
      totalChars += JSON.stringify(msg.tool_calls || msg.toolCalls).length;
    }
  };

  if (Array.isArray(messagesOrText)) {
    for (const item of messagesOrText) {
      accumulateMessage(item);
    }
    return Math.ceil(totalChars / 3.8);
  }

  if (typeof messagesOrText === 'object') {
    if (typeof messagesOrText.system === 'string') {
      totalChars += messagesOrText.system.length;
    }
    if (typeof messagesOrText.instructions === 'string') {
      totalChars += messagesOrText.instructions.length;
    }
    if (typeof messagesOrText.prompt === 'string') {
      totalChars += messagesOrText.prompt.length;
    }
    if (typeof messagesOrText.text === 'string') {
      totalChars += messagesOrText.text.length;
    }
    if (Array.isArray(messagesOrText.messages)) {
      for (const m of messagesOrText.messages) {
        accumulateMessage(m);
      }
    }
    if (Array.isArray(messagesOrText.input)) {
      for (const m of messagesOrText.input) {
        accumulateMessage(m);
      }
    }
    if (Array.isArray(messagesOrText.tools) && messagesOrText.tools.length > 0) {
      for (const tool of messagesOrText.tools) {
        const schemaChars = JSON.stringify(tool).length;
        totalChars += schemaChars;
        toolSchemaOverheadTokens += 12;
      }
    }
    if (
      totalChars === 0 &&
      !messagesOrText.messages &&
      !messagesOrText.system &&
      !messagesOrText.tools
    ) {
      totalChars += JSON.stringify(messagesOrText).length;
    }
  }

  return Math.ceil(totalChars / 3.8) + toolSchemaOverheadTokens;
}

function envValue(env, key) {
  const v = env && typeof env === 'object' ? env[key] : undefined;
  return typeof v === 'string' && v.trim() ? v.trim() : '';
}

function areHeadersEqual(a, b) {
  const entriesA = a && typeof a === 'object' ? Object.entries(a).filter(([, v]) => v !== undefined) : [];
  const entriesB = b && typeof b === 'object' ? Object.entries(b).filter(([, v]) => v !== undefined) : [];
  if (entriesA.length !== entriesB.length) return false;
  const mapA = new Map(entriesA.map(([k, v]) => [String(k).toLowerCase(), String(v)]));
  for (const [k, v] of entriesB) {
    const key = String(k).toLowerCase();
    if (!mapA.has(key) || mapA.get(key) !== String(v)) return false;
  }
  return true;
}

/**
 * Registers default LLM profiles discovered from environment variables.
 * Reads `env` only (never mutates it) and never throws. Existing profile ids are not overwritten.
 *
 * @param {LlmPool} pool
 * @param {Record<string, string|undefined>} [env]
 * @returns {string[]} ids of profiles registered
 */
export function bootstrapDefaultLlmProfiles(pool, env = process.env) {
  const added = [];
  if (!pool || typeof pool.addProfile !== 'function') return added;
  const specs = [];
  const geminiKey = envValue(env, 'GEMINI_API_KEY');
  if (geminiKey) {
    specs.push({
      id: 'gemini',
      provider: 'gemini',
      model: envValue(env, 'SECSCAN_GEMINI_MODEL') || 'gemini-2.5-flash',
      apiKey: geminiKey,
      contextWindow: 1_000_000,
      rank: 1,
      autoDiscovered: true,
      source: 'env',
    });
  }
  const anthropicKey = envValue(env, 'ANTHROPIC_API_KEY');
  if (anthropicKey) {
    specs.push({
      id: 'anthropic',
      provider: 'anthropic',
      model: envValue(env, 'SECSCAN_ANTHROPIC_MODEL') || 'claude-sonnet-4-20250514',
      apiKey: anthropicKey,
      contextWindow: 200_000,
      rank: 2,
      autoDiscovered: true,
      source: 'env',
    });
  }
  const openaiKey = envValue(env, 'OPENAI_API_KEY');
  if (openaiKey) {
    specs.push({
      id: 'openai',
      provider: 'openai',
      model: envValue(env, 'SECSCAN_OPENAI_MODEL') || 'gpt-4o-mini',
      apiKey: openaiKey,
      contextWindow: 128_000,
      rank: 3,
      autoDiscovered: true,
      source: 'env',
    });
  }
  const ollamaHost = envValue(env, 'OLLAMA_HOST');
  const ollamaModel = envValue(env, 'SECSCAN_OLLAMA_MODEL');
  if (ollamaHost || ollamaModel) {
    let baseUrl = ollamaHost;
    if (baseUrl && !/^https?:\/\//i.test(baseUrl)) baseUrl = `http://${baseUrl}`;
    specs.push({
      id: 'ollama',
      provider: 'ollama',
      model: ollamaModel || 'llama3.1',
      baseUrl: baseUrl || '',
      apiKey: '',
      contextWindow: 32_000,
      rank: 4,
      autoDiscovered: true,
      source: 'env',
    });
  }
  for (const spec of specs) {
    try {
      if (pool.getProfile(spec.id)) continue;
      pool.addProfile(spec);
      added.push(spec.id);
    } catch {
      // never throw during env bootstrap
    }
  }
  return added;
}

/**
 * Multi-Provider LLM Failover Pool with Circuit Breaker and Per-Intent Worker Rotation.
 */
export class LlmPool {
  /**
   * @param {object|Array<object>} [options]
   */
  constructor(options = {}) {
    const opts = Array.isArray(options) ? { profiles: options } : options || {};
    this.nowFn = typeof opts.nowFn === 'function' ? opts.nowFn : () => Date.now();
    this.softTripThreshold = Number(opts.softTripThreshold ?? 3);
    this.fetcher = opts.fetcher || globalThis.fetch;
    this.timeoutMs = Number(opts.timeoutMs ?? 60_000);
    this.recorder = opts.recorder || null;

    /** @type {Map<string, object>} */
    this.profiles = new Map();
    /** @type {Map<string, { consecutiveFailures: number, tripCount: number, cooldownUntil: number, lastError: string|null, lastStatus: number|null }>} */
    this.breakers = new Map();
    /** @type {Map<number, number>} */
    this.rankCursors = new Map();
    /** @type {Map<string, { taskId: string, profileIds: string[], llmRotate: boolean, rotationCursor: number, intentPins: Map<string, string>, excludedProfiles: Set<string>, taskStreaks: Map<string, number> }>} */
    this.taskChains = new Map();

    if (Array.isArray(opts.profiles)) {
      for (const p of opts.profiles) {
        this.addProfile(p);
      }
    }

    if (opts.autoDiscoverEnv === true) {
      bootstrapDefaultLlmProfiles(this, opts.env || process.env);
    }
  }

  /**
   * Registers or updates an LLM profile in the pool.
   *
   * @param {object} profile
   * @returns {object}
   */
  addProfile(profile) {
    if (!profile || !profile.id) {
      throw new Error('LLM profile requires a non-empty `id`');
    }
    const id = String(profile.id);
    const existing = this.profiles.get(id) || null;

    const nextProvider = (profile.provider || existing?.provider || 'openai').toLowerCase();
    const nextBaseUrl =
      profile.baseUrl !== undefined
        ? String(profile.baseUrl || '').trim()
        : String(existing?.baseUrl || '').trim();
    const nextHeaders =
      profile.headers !== undefined
        ? (profile.headers ? { ...profile.headers } : undefined)
        : (existing?.headers ? { ...existing.headers } : undefined);

    const rawIncomingKey = profile.apiKey;
    const isMaskedPlaceholder =
      typeof rawIncomingKey === 'string' && rawIncomingKey.trim().startsWith('__masked__:');
    const hasNewKey =
      typeof rawIncomingKey === 'string' &&
      rawIncomingKey.trim().length > 0 &&
      !isMaskedPlaceholder;

    let nextApiKey = hasNewKey ? rawIncomingKey : '';
    if (existing && existing.apiKey && !hasNewKey) {
      const providerChanged = nextProvider !== existing.provider;
      const baseUrlChanged = nextBaseUrl !== String(existing.baseUrl || '').trim();
      const headersChanged =
        profile.headers !== undefined && !areHeadersEqual(existing.headers, profile.headers);
      if (providerChanged || baseUrlChanged || headersChanged) {
        throw new Error(
          'Cannot modify provider, baseUrl, or headers on an existing profile without providing apiKey'
        );
      }
      nextApiKey = existing.apiKey;
    }

    const autoDiscovered =
      profile.autoDiscovered !== undefined
        ? Boolean(profile.autoDiscovered)
        : Boolean(existing?.autoDiscovered);
    const source =
      profile.source !== undefined
        ? String(profile.source)
        : (existing?.source || (autoDiscovered ? 'env' : 'manual'));

    const normalized = {
      id,
      name: profile.name || existing?.name || id,
      provider: nextProvider,
      model: profile.model || existing?.model || 'gpt-4o',
      baseUrl: nextBaseUrl,
      apiKey: nextApiKey,
      contextWindow: Number(profile.contextWindow ?? existing?.contextWindow ?? 128_000),
      maxOutputTokens: Number(
        profile.maxOutputTokens ?? profile.maxTokens ?? existing?.maxOutputTokens ?? 4096
      ),
      rank: Number(profile.rank ?? existing?.rank ?? 1),
      enabled:
        profile.enabled !== undefined
          ? Boolean(profile.enabled)
          : (existing ? existing.enabled : true),
      headers: nextHeaders,
      maxTokensField:
        profile.maxTokensField !== undefined ? profile.maxTokensField : existing?.maxTokensField,
      autoDiscovered,
      source,
    };
    this.profiles.set(normalized.id, normalized);
    if (!this.breakers.has(normalized.id)) {
      this.breakers.set(normalized.id, {
        consecutiveFailures: 0,
        tripCount: 0,
        cooldownUntil: 0,
        lastError: null,
        lastStatus: null,
      });
    }
    return normalized;
  }

  upsertProfile(profile) {
    return this.addProfile(profile);
  }

  removeProfile(profileId) {
    this.profiles.delete(profileId);
    this.breakers.delete(profileId);
  }

  getProfile(profileId) {
    return this.profiles.get(profileId) || null;
  }

  /** Internal: raw profiles (including secrets). Never return these from public APIs. */
  _listRawProfiles({ enabledOnly = false } = {}) {
    const list = [...this.profiles.values()];
    const filtered = enabledOnly ? list.filter((p) => p.enabled !== false) : list;
    return filtered.sort((a, b) => a.rank - b.rank);
  }

  /** Public listing: apiKey is never exposed (masked, plus `hasApiKey`). */
  listProfiles(options = {}) {
    return this._listRawProfiles(options).map((p) => ({
      ...p,
      apiKey: maskSecret(p.apiKey),
      hasApiKey: Boolean(p.apiKey),
      autoDiscovered: Boolean(p.autoDiscovered),
      source: p.source || (p.autoDiscovered ? 'env' : 'manual'),
      headers: p.headers ? { ...p.headers } : undefined,
    }));
  }

  _getBreaker(profileId) {
    if (!this.breakers.has(profileId)) {
      this.breakers.set(profileId, {
        consecutiveFailures: 0,
        tripCount: 0,
        cooldownUntil: 0,
        lastError: null,
        lastStatus: null,
      });
    }
    return this.breakers.get(profileId);
  }

  /**
   * Returns true if the profile's circuit breaker is currently open (in cooldown).
   *
   * @param {string} profileId
   * @param {number} [now]
   * @returns {boolean}
   */
  isProfileTripped(profileId, now = this.nowFn()) {
    const breaker = this.breakers.get(profileId);
    if (!breaker) return false;
    return breaker.cooldownUntil > now;
  }

  /**
   * Records a failed call against a profile's circuit breaker.
   * - Hard failure (401, 402, 403, 404): trips immediately on 1st failure.
   * - Soft failure (408, 409, 425, 429, 500, 502, 503, 504 or network timeout): trips after 3 consecutive failures.
   *
   * @param {string} profileId
   * @param {Error|object} error
   * @returns {object} updated breaker state
   */
  recordFailure(profileId, error = {}) {
    const breaker = this._getBreaker(profileId);
    const rawStatus = Number(error?.status ?? 0);
    const msg = error?.rawBody || error?.message || '';
    const effectiveStatus =
      error?.effectiveStatus !== undefined && error?.effectiveStatus !== null
        ? Number(error.effectiveStatus)
        : isQuotaExhaustedMessage(rawStatus, msg)
          ? 402
          : rawStatus;

    const isHard =
      error?.isHardFailure === true || HARD_FAILURE_STATUSES.has(effectiveStatus);
    const isSoft =
      !isHard &&
      (error?.isSoftFailure === true ||
        SOFT_FAILURE_STATUSES.has(effectiveStatus) ||
        effectiveStatus === 0 ||
        effectiveStatus >= 500);

    breaker.consecutiveFailures += 1;
    breaker.lastStatus = effectiveStatus;
    breaker.lastError = error?.message || `HTTP ${effectiveStatus}`;

    const shouldTrip =
      isHard ||
      (isSoft &&
        breaker.consecutiveFailures >= this.softTripThreshold &&
        breaker.consecutiveFailures % this.softTripThreshold === 0);

    if (shouldTrip) {
      breaker.tripCount += 1;
      const ladderIdx = Math.min(breaker.tripCount - 1, COOLDOWN_LADDER_MS.length - 1);
      const cooldownMs = COOLDOWN_LADDER_MS[ladderIdx];
      breaker.cooldownUntil = this.nowFn() + cooldownMs;
    }

    return {
      ...breaker,
      state: this.isProfileTripped(profileId) ? 'tripped' : 'healthy',
    };
  }

  /**
   * Records a successful call against a profile, resetting its failure streak and trip state.
   *
   * @param {string} profileId
   */
  recordSuccess(profileId) {
    const breaker = this._getBreaker(profileId);
    breaker.consecutiveFailures = 0;
    breaker.tripCount = 0;
    breaker.cooldownUntil = 0;
    breaker.lastError = null;
    breaker.lastStatus = 200;
  }

  /**
   * Clears circuit breaker trip state for a specific profile (or all profiles if omitted).
   *
   * @param {string} [profileId]
   */
  resetBreaker(profileId) {
    if (profileId === undefined || profileId === null) {
      for (const id of this.breakers.keys()) {
        this.resetBreaker(id);
      }
      return;
    }
    this.breakers.set(String(profileId), {
      consecutiveFailures: 0,
      tripCount: 0,
      cooldownUntil: 0,
      lastError: null,
      lastStatus: null,
    });
  }

  /**
   * Configures a task's LLM profile chain and worker round-robin rotation flag.
   * Omitting `llmRotate` on update preserves its existing boolean value (matching ARTEX PUT /api/tasks/{id}/llm).
   *
   * @param {string} taskId
   * @param {{ profileIds?: string[], llmRotate?: boolean }} [options]
   * @returns {object}
   */
  configureTaskChain(taskId, options = {}) {
    if (!taskId) {
      throw new Error('configureTaskChain requires a non-empty `taskId`');
    }
    const key = String(taskId);
    const existing = this.taskChains.get(key);

    const profileIds = Array.isArray(options.profileIds)
      ? options.profileIds.map(String)
      : existing
        ? [...existing.profileIds]
        : this._listRawProfiles({ enabledOnly: true }).map((p) => p.id);

    const llmRotate =
      options.llmRotate !== undefined
        ? Boolean(options.llmRotate)
        : existing
          ? existing.llmRotate
          : false;

    const entry = {
      taskId: key,
      profileIds,
      llmRotate,
      rotationCursor: existing ? existing.rotationCursor : 0,
      intentPins: existing ? existing.intentPins : new Map(),
      excludedProfiles: existing ? existing.excludedProfiles : new Set(),
      taskStreaks: existing ? existing.taskStreaks : new Map(),
    };

    this.taskChains.set(key, entry);
    return this.getTaskChain(key);
  }

  /**
   * Returns the task's configured LLM failover chain and rotation state.
   *
   * @param {string} taskId
   * @returns {{ taskId: string, profileIds: string[], llmRotate: boolean, rotationCursor: number, activePrimaryId: string|null }}
   */
  getTaskChain(taskId) {
    const key = String(taskId || '');
    const chain = this.taskChains.get(key);
    if (!chain) {
      const defaultIds = this._listRawProfiles({ enabledOnly: true }).map((p) => p.id);
      const primary = this._findHealthyPrimary(defaultIds);
      return {
        taskId: key,
        profileIds: defaultIds,
        llmRotate: false,
        rotationCursor: 0,
        activePrimaryId: primary?.id || defaultIds[0] || null,
      };
    }
    const primary = this._findHealthyPrimary(chain.profileIds, chain.excludedProfiles);
    return {
      taskId: chain.taskId,
      profileIds: [...chain.profileIds],
      llmRotate: chain.llmRotate,
      rotationCursor: chain.rotationCursor,
      activePrimaryId: primary?.id || chain.profileIds[0] || null,
    };
  }

  /**
   * Resets breaker state and task chain exclusions/pins for a task.
   *
   * @param {string} taskId
   */
  resetTaskChain(taskId) {
    const key = String(taskId || '');
    const chain = this.taskChains.get(key);
    if (chain) {
      chain.rotationCursor = 0;
      chain.intentPins.clear();
      chain.excludedProfiles.clear();
      chain.taskStreaks.clear();
      for (const pid of chain.profileIds) {
        this.resetBreaker(pid);
      }
    }
  }

  _isProfileHealthy(profileId, excludedSet = null, now = this.nowFn()) {
    const profile = this.profiles.get(profileId);
    if (!profile || profile.enabled === false) return false;
    if (excludedSet && excludedSet.has(profileId)) return false;
    return !this.isProfileTripped(profileId, now);
  }

  _findHealthyPrimary(profileIds = [], excludedSet = null) {
    const now = this.nowFn();
    for (const pid of profileIds) {
      if (this._isProfileHealthy(pid, excludedSet, now)) {
        return this.profiles.get(pid);
      }
    }
    // Fallback to first enabled profile in the list if all are tripped
    for (const pid of profileIds) {
      const p = this.profiles.get(pid);
      if (p && p.enabled !== false) return p;
    }
    return null;
  }

  /**
   * Selects the profile for a task role/intent according to ARTEX worker round-robin rotation rules:
   * - When `llmRotate: true` and `role === 'worker'`, assigns successive worker intents A, B, A, B
   *   across the task's `profileIds` regardless of completion order.
   * - Pins each `intentId` to its assigned profile; if that profile's circuit breaker is open/excluded,
   *   falls back to the task's current healthy primary profile while keeping the rotation cursor advancing
   *   across the full list.
   * - Planner and non-worker roles continue using the task's primary ordered chain.
   *
   * @param {string} taskId
   * @param {{ role?: string, intentId?: string|null }} [options]
   * @returns {object|null}
   */
  nextRotatedProfile(taskId, { role = 'worker', intentId = null } = {}) {
    const key = taskId ? String(taskId) : '';
    let chain = key ? this.taskChains.get(key) : null;
    if (!chain) {
      const defaultIds = this._listRawProfiles({ enabledOnly: true }).map((p) => p.id);
      if (defaultIds.length === 0) return null;
      if (key) {
        this.configureTaskChain(key, { profileIds: defaultIds, llmRotate: false });
        chain = this.taskChains.get(key);
      } else {
        return this._findHealthyPrimary(defaultIds);
      }
    }

    const validIds = chain.profileIds.filter((id) => {
      const p = this.profiles.get(id);
      return p && p.enabled !== false;
    });
    if (validIds.length === 0) return null;

    const healthyPrimary = this._findHealthyPrimary(validIds, chain.excludedProfiles);

    // Planner and non-worker roles (or when llmRotate is false) always use the primary ordered chain
    if (role !== 'worker' || !chain.llmRotate) {
      if (!healthyPrimary) return null;
      return {
        ...healthyPrimary,
        profileId: healthyPrimary.id,
        assignedProfileId: healthyPrimary.id,
        fallbackUsed: false,
      };
    }

    // Worker role with llmRotate === true
    let assignedId;
    const intentKey =
      intentId !== null && intentId !== undefined && String(intentId) !== ''
        ? String(intentId)
        : null;

    if (intentKey && chain.intentPins.has(intentKey)) {
      assignedId = chain.intentPins.get(intentKey);
    } else {
      const cursor = chain.rotationCursor;
      assignedId = validIds[cursor % validIds.length];
      chain.rotationCursor = cursor + 1;
      if (intentKey) {
        chain.intentPins.set(intentKey, assignedId);
      }
    }

    if (this._isProfileHealthy(assignedId, chain.excludedProfiles)) {
      const assignedProfile = this.profiles.get(assignedId);
      return {
        ...assignedProfile,
        profileId: assignedProfile.id,
        assignedProfileId: assignedId,
        fallbackUsed: false,
      };
    }

    // Pinned/assigned profile is tripped or excluded: fall back to current healthy primary profile
    const fallbackProfile = healthyPrimary || this.profiles.get(assignedId);
    if (!fallbackProfile) return null;
    return {
      ...fallbackProfile,
      profileId: fallbackProfile.id,
      assignedProfileId: assignedId,
      fallbackUsed: fallbackProfile.id !== assignedId,
    };
  }

  /**
   * Builds an ordered list of candidate profiles applying equal-rank round-robin rotation.
   *
   * @param {object} [options]
   * @returns {Array<object>}
   */
  _buildCandidateChain({ taskId = null, role = 'planner', intentId = null, advanceRotation = true } = {}) {
    const now = this.nowFn();
    const candidates = [];
    const seen = new Set();

    const addCandidate = (profile) => {
      if (!profile || profile.enabled === false || seen.has(profile.id)) return;
      seen.add(profile.id);
      candidates.push(profile);
    };

    if (taskId && this.taskChains.has(String(taskId))) {
      const chain = this.taskChains.get(String(taskId));
      const primarySelection = this.nextRotatedProfile(taskId, { role, intentId });
      if (primarySelection) {
        const prof = this.profiles.get(primarySelection.id);
        if (prof && !this.isProfileTripped(prof.id, now)) {
          addCandidate(prof);
        }
      }
      for (const pid of chain.profileIds) {
        const prof = this.profiles.get(pid);
        if (prof && !this.isProfileTripped(prof.id, now) && !chain.excludedProfiles.has(pid)) {
          addCandidate(prof);
        }
      }
      // If all profiles in the task chain were tripped, allow trying the chain profiles in order
      if (candidates.length === 0) {
        for (const pid of chain.profileIds) {
          addCandidate(this.profiles.get(pid));
        }
      }
      return candidates;
    }

    // Global pool ordering with Equal-Rank Group Rotation
    const enabled = this._listRawProfiles({ enabledOnly: true });
    const rankGroups = new Map();
    for (const p of enabled) {
      if (!rankGroups.has(p.rank)) {
        rankGroups.set(p.rank, []);
      }
      rankGroups.get(p.rank).push(p);
    }

    const sortedRanks = [...rankGroups.keys()].sort((a, b) => a - b);
    const rotatedAll = [];

    for (const rank of sortedRanks) {
      const group = rankGroups.get(rank);
      if (group.length > 1) {
        const cursor = this.rankCursors.get(rank) || 0;
        const offset = cursor % group.length;
        if (advanceRotation) {
          this.rankCursors.set(rank, cursor + 1);
        }
        const rotated = [...group.slice(offset), ...group.slice(0, offset)];
        rotatedAll.push(...rotated);
      } else {
        rotatedAll.push(...group);
      }
    }

    for (const p of rotatedAll) {
      if (!this.isProfileTripped(p.id, now)) {
        addCandidate(p);
      }
    }

    // If every profile is currently tripped, fall back to the one with earliest cooldown expiry
    if (candidates.length === 0 && rotatedAll.length > 0) {
      const byExpiry = [...rotatedAll].sort((a, b) => {
        const ba = this.breakers.get(a.id)?.cooldownUntil || 0;
        const bb = this.breakers.get(b.id)?.cooldownUntil || 0;
        return ba - bb;
      });
      for (const p of byExpiry) {
        addCandidate(p);
      }
    }

    return candidates;
  }

  /**
   * Filters candidate profiles by contextWindow >= estimateTokens(request) + maxOutputTokens,
   * preserving the last fallback profile if all candidates would otherwise be filtered out.
   *
   * @param {Array<object>} candidates
   * @param {object} request
   * @returns {Array<object>}
   */
  filterByContextWindow(candidates = [], request = {}) {
    if (candidates.length <= 1) return candidates;
    const estInput = estimateTokens(request);
    const fitting = [];

    for (let i = 0; i < candidates.length; i++) {
      const profile = candidates[i];
      const maxOut = Number(
        request?.maxTokens ?? request?.maxOutputTokens ?? profile.maxOutputTokens ?? 0
      );
      const requiredTokens = estInput + maxOut;
      const windowSize = Number(profile.contextWindow ?? 0);

      if (windowSize <= 0 || windowSize >= requiredTokens) {
        fitting.push(profile);
      }
    }

    // Never filter out the last fallback profile if no earlier profile fit
    return fitting.length > 0 ? fitting : [candidates[candidates.length - 1]];
  }

  /**
   * Executes a completion request with context-window pre-filtering, equal-rank / worker round-robin
   * selection, circuit breaker tracking, automatic pre-commit failover, and optional LlmRecorder logging.
   *
   * @param {object} request
   * @param {{ taskId?: string|null, role?: string, intentId?: string|null, recorder?: object|null, fetcher?: Function }} [options]
   * @returns {Promise<object>}
   */
  async complete(
    request = {},
    { taskId = null, role = 'planner', intentId = null, recorder = null, fetcher } = {}
  ) {
    const rawCandidates = this._buildCandidateChain({
      taskId,
      role,
      intentId,
      advanceRotation: true,
    });

    if (rawCandidates.length === 0) {
      throw new LlmProviderError('No enabled LLM profiles available in pool', {
        status: 503,
        effectiveStatus: 503,
        code: 'NO_PROFILES_AVAILABLE',
        isHardFailure: false,
        isSoftFailure: true,
      });
    }

    const candidates = this.filterByContextWindow(rawCandidates, request);
    const activeRecorder = recorder || this.recorder;
    const activeFetcher = fetcher || this.fetcher;
    const failovers = [];
    let lastError = null;

    for (const profile of candidates) {
      const startMs = Date.now();
      const builtReq = buildProviderRequest(profile, request);

      try {
        const result = await callProvider(profile, request, {
          fetcher: activeFetcher,
          timeoutMs: request.timeoutMs ?? this.timeoutMs,
        });
        const durationMs = Math.max(0, Date.now() - startMs);

        this.recordSuccess(profile.id);

        if (activeRecorder && typeof activeRecorder.recordCall === 'function') {
          activeRecorder.recordCall({
            taskId,
            role,
            intentId,
            profileId: profile.id,
            provider: profile.provider,
            model: result.model || profile.model,
            inputTokens: result.usage?.inputTokens ?? 0,
            outputTokens: result.usage?.outputTokens ?? 0,
            durationMs,
            status: 200,
            requestPayload: {
              url: builtReq.url,
              method: builtReq.method,
              headers: builtReq.headers,
              body: builtReq.body,
            },
            responsePayload: result,
          });
        }

        return {
          ...result,
          profileId: profile.id,
          failovers,
        };
      } catch (err) {
        const durationMs = Math.max(0, Date.now() - startMs);
        this.recordFailure(profile.id, err);
        lastError = err;

        const effectiveStatus = err?.effectiveStatus ?? err?.status ?? 500;

        if (activeRecorder && typeof activeRecorder.recordCall === 'function') {
          activeRecorder.recordCall({
            taskId,
            role,
            intentId,
            profileId: profile.id,
            provider: profile.provider,
            model: profile.model,
            inputTokens: estimateTokens(request),
            outputTokens: 0,
            durationMs,
            status: effectiveStatus,
            requestPayload: {
              url: builtReq.url,
              method: builtReq.method,
              headers: builtReq.headers,
              body: builtReq.body,
            },
            responsePayload: {
              error: err?.message || 'Provider call failed',
              status: err?.status ?? 0,
              effectiveStatus,
              code: err?.code,
            },
          });
        }

        failovers.push({
          profileId: profile.id,
          provider: profile.provider,
          model: profile.model,
          status: err?.status ?? 0,
          effectiveStatus,
          code: err?.code || 'LLM_PROVIDER_ERROR',
          message: err?.message || 'Provider call failed',
        });
      }
    }

    if (lastError) {
      lastError.failovers = failovers;
      throw lastError;
    }

    throw new LlmProviderError('All candidate LLM profiles failed', {
      status: 503,
      effectiveStatus: 503,
      code: 'ALL_PROFILES_FAILED',
    });
  }

  /**
   * Returns a sanitized snapshot of all profiles (with `apiKey` masked via `maskSecret`),
   * circuit breaker states (`healthy | tripped`, `cooldownUntil`, `consecutiveFailures`, `tripCount`),
   * and rotation cursors.
   *
   * @returns {{ profiles: Array<object>, breakers: Record<string, object>, rotationCursors: object }}
   */
  getPoolStatus() {
    const now = this.nowFn();
    const profiles = [];
    const breakers = {};

    for (const profile of this._listRawProfiles()) {
      const b = this._getBreaker(profile.id);
      const tripped = this.isProfileTripped(profile.id, now);
      const state = tripped ? 'tripped' : 'healthy';

      const breakerInfo = {
        state,
        status: state,
        cooldownUntil: b.cooldownUntil,
        consecutiveFailures: b.consecutiveFailures,
        tripCount: b.tripCount,
        lastError: b.lastError,
        lastStatus: b.lastStatus,
      };

      breakers[profile.id] = breakerInfo;

      profiles.push({
        id: profile.id,
        name: profile.name,
        provider: profile.provider,
        model: profile.model,
        baseUrl: profile.baseUrl,
        apiKey: maskSecret(profile.apiKey),
        hasApiKey: Boolean(profile.apiKey),
        autoDiscovered: Boolean(profile.autoDiscovered),
        source: profile.source || (profile.autoDiscovered ? 'env' : 'manual'),
        contextWindow: profile.contextWindow,
        maxOutputTokens: profile.maxOutputTokens,
        rank: profile.rank,
        enabled: profile.enabled,
        state,
        cooldownUntil: b.cooldownUntil,
        consecutiveFailures: b.consecutiveFailures,
        tripCount: b.tripCount,
        breaker: breakerInfo,
      });
    }

    const taskCursors = {};
    for (const [tid, chain] of this.taskChains.entries()) {
      taskCursors[tid] = {
        rotationCursor: chain.rotationCursor,
        llmRotate: chain.llmRotate,
        profileIds: [...chain.profileIds],
      };
    }

    return {
      profiles,
      breakers,
      rotationCursors: {
        equalRank: Object.fromEntries(this.rankCursors),
        tasks: taskCursors,
      },
    };
  }
}
