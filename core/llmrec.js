/**
 * LLM Call Recorder & Token/Cost Metering Ledger (`LlmRecorder`).
 * Sanitizes all Authorization and API-key headers/fields before storing wire capture payloads.
 */

import { maskSecret } from './llm-provider.js';

const SENSITIVE_KEY_RE = /^(authorization|proxy-authorization|x-api-key|x-goog-api-key|x-auth-token|api[-_]?key|secret|token|password|access[-_]?token)$/i;
const BEARER_PREFIX_RE = /^Bearer\s+(.+)$/i;
const INLINE_BEARER_RE = /\bBearer\s+([A-Za-z0-9._\-]{6,})\b/gi;
const INLINE_SK_KEY_RE = /\b(sk-(?:ant-|proj-)?[A-Za-z0-9._\-]{6,})\b/g;

// Default per-1M token pricing (USD) when explicit pricing is not supplied
const DEFAULT_PRICING_PER_1M = {
  anthropic: { input: 3.0, output: 15.0 },
  openai: { input: 2.5, output: 10.0 },
  'openai-responses': { input: 2.5, output: 10.0 },
  gemini: { input: 0.15, output: 0.6 },
  'gemini-2.5-flash': { input: 0.15, output: 0.6 },
  'gemini-2.5-pro': { input: 1.25, output: 10.0 },
  'gemini-2.0-flash': { input: 0.1, output: 0.4 },
  ollama: { input: 0.0, output: 0.0 },
};

function sanitizeStringValue(str) {
  if (typeof str !== 'string' || !str) return str;
  let out = str.replace(INLINE_BEARER_RE, (full, token) => {
    if (token === 'ollama' || token.startsWith('__masked__:')) return full;
    return `Bearer ${maskSecret(token)}`;
  });
  out = out.replace(INLINE_SK_KEY_RE, (match) => maskSecret(match));
  return out;
}

/**
 * Deeply clones and redacts any Authorization headers, x-api-key headers, or API key fields
 * inside request/response capture payloads.
 *
 * @param {any} value
 * @returns {any}
 */
export function sanitizePayload(value) {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') {
    return sanitizeStringValue(value);
  }
  if (typeof value !== 'object') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => sanitizePayload(item));
  }

  const out = {};
  for (const [k, v] of Object.entries(value)) {
    if (SENSITIVE_KEY_RE.test(k)) {
      if (typeof v === 'string') {
        const trimmed = v.trim();
        const bearerMatch = trimmed.match(BEARER_PREFIX_RE);
        if (bearerMatch) {
          const token = bearerMatch[1].trim();
          out[k] =
            token === 'ollama' || token.startsWith('__masked__:')
              ? `Bearer ${token}`
              : `Bearer ${maskSecret(token)}`;
        } else if (trimmed.startsWith('__masked__:')) {
          out[k] = trimmed;
        } else {
          out[k] = maskSecret(trimmed);
        }
      } else {
        out[k] = '';
      }
    } else {
      out[k] = sanitizePayload(v);
    }
  }
  return out;
}

/**
 * Tracks token usage, latency, cost ledger, and sanitized wire payloads per task, profile, and role.
 */
export class LlmRecorder {
  /**
   * @param {{ maxRecords?: number, pricingPer1M?: Record<string, { input: number, output: number }> }} [options]
   */
  constructor({ maxRecords = 5000, pricingPer1M = {} } = {}) {
    this.maxRecords = Number(maxRecords) > 0 ? Number(maxRecords) : 5000;
    this.pricingPer1M = { ...DEFAULT_PRICING_PER_1M, ...pricingPer1M };
    /** @type {Array<object>} */
    this.records = [];
    this._seq = 0;
  }

  _computeCostUsd(provider, inputTokens, outputTokens, customRates = null, model = '') {
    const normModel = String(model || '').trim().toLowerCase();
    const normProvider = String(provider || '').trim().toLowerCase();
    const rates =
      customRates ||
      this.pricingPer1M[normModel] ||
      this.pricingPer1M[normProvider] ||
      { input: 0, output: 0 };
    const inCost = (Math.max(0, Number(inputTokens) || 0) / 1_000_000) * (rates.input || 0);
    const outCost = (Math.max(0, Number(outputTokens) || 0) / 1_000_000) * (rates.output || 0);
    return Number((inCost + outCost).toFixed(8));
  }

  /**
   * Records an LLM call with sanitized request/response payloads and token/cost accounting.
   *
   * @param {object} entry
   * @returns {object}
   */
  recordCall({
    taskId = null,
    role = 'planner',
    intentId = null,
    profileId = 'default',
    provider = 'openai',
    model = '',
    inputTokens = 0,
    outputTokens = 0,
    durationMs = 0,
    status = 200,
    requestPayload = null,
    responsePayload = null,
    costUsd = null,
  } = {}) {
    this._seq += 1;
    const inTok = Math.max(0, Number(inputTokens) || 0);
    const outTok = Math.max(0, Number(outputTokens) || 0);
    const totalTokens = inTok + outTok;
    const dur = Math.max(0, Number(durationMs) || 0);
    const computedCost =
      costUsd !== null && costUsd !== undefined
        ? Number(costUsd)
        : this._computeCostUsd(provider, inTok, outTok, null, model);

    const record = {
      id: `llmrec_${this._seq}`,
      seq: this._seq,
      taskId: taskId ? String(taskId) : null,
      role: String(role || 'planner'),
      intentId: intentId ? String(intentId) : null,
      profileId: String(profileId || 'default'),
      provider: String(provider || 'openai').toLowerCase(),
      model: String(model || ''),
      inputTokens: inTok,
      outputTokens: outTok,
      totalTokens,
      durationMs: dur,
      status: Number(status ?? 200),
      costUsd: computedCost,
      requestPayload: sanitizePayload(requestPayload),
      responsePayload: sanitizePayload(responsePayload),
      timestamp: new Date().toISOString(),
    };

    this.records.push(record);
    if (this.records.length > this.maxRecords) {
      this.records.shift();
    }

    return record;
  }

  /**
   * Aggregates token usage, latency, and cost metrics across all calls (or filtered by `taskId`).
   *
   * @param {{ taskId?: string|null }} [filter]
   * @returns {object}
   */
  getUsageSummary({ taskId = null } = {}) {
    const targetTask = taskId ? String(taskId) : null;
    const matching = targetTask
      ? this.records.filter((r) => r.taskId === targetTask)
      : this.records;

    let totalCalls = 0;
    let inputTokens = 0;
    let outputTokens = 0;
    let totalTokens = 0;
    let totalDurationMs = 0;
    let totalCostUsd = 0;

    const byRole = {};
    const byProfile = {};
    const byTask = {};

    const addBucket = (map, key, rec, extra = {}) => {
      if (!map[key]) {
        map[key] = {
          calls: 0,
          inputTokens: 0,
          outputTokens: 0,
          totalTokens: 0,
          durationMs: 0,
          costUsd: 0,
          ...extra,
        };
      }
      const b = map[key];
      b.calls += 1;
      b.inputTokens += rec.inputTokens;
      b.outputTokens += rec.outputTokens;
      b.totalTokens += rec.totalTokens;
      b.durationMs += rec.durationMs;
      b.costUsd = Number((b.costUsd + rec.costUsd).toFixed(8));
    };

    for (const rec of matching) {
      totalCalls += 1;
      inputTokens += rec.inputTokens;
      outputTokens += rec.outputTokens;
      totalTokens += rec.totalTokens;
      totalDurationMs += rec.durationMs;
      totalCostUsd = Number((totalCostUsd + rec.costUsd).toFixed(8));

      addBucket(byRole, rec.role, rec);
      addBucket(byProfile, rec.profileId, rec, {
        provider: rec.provider,
        model: rec.model,
      });
      if (rec.taskId) {
        addBucket(byTask, rec.taskId, rec);
      }
    }

    return {
      taskId: targetTask,
      totalCalls,
      inputTokens,
      outputTokens,
      totalTokens,
      totalDurationMs,
      avgDurationMs: totalCalls > 0 ? Math.round(totalDurationMs / totalCalls) : 0,
      totalCostUsd,
      byRole,
      byProfile,
      byTask,
    };
  }

  /**
   * Lists recorded LLM call records (most recent up to `limit`), optionally filtered by `taskId`.
   *
   * @param {{ taskId?: string|null, limit?: number }} [options]
   * @returns {Array<object>}
   */
  listRecords({ taskId = null, limit = 50 } = {}) {
    const targetTask = taskId ? String(taskId) : null;
    const matching = targetTask
      ? this.records.filter((r) => r.taskId === targetTask)
      : this.records;
    const cap = Math.max(1, Number(limit) || 50);
    return matching.slice(-cap).map((r) => ({ ...r }));
  }

  clear() {
    this.records = [];
  }
}
