/**
 * `/btw` Snapshot-Forked Ephemeral Read-Only Side Question Service (`SideQuestionService`).
 * Performs 4-stage context budget compression on a deep-cloned snapshot without mutating
 * active task state or exploration graphs, and executes with strictly zero tools (`tools: []`).
 */

import { estimateTokens } from './llmpool.js';

export const STAGE_1_MAX_OUTPUT_CHARS = 512;
export const STAGE_3_MAX_ACTIVITIES = 5;

const READ_ONLY_SYSTEM_PROMPT = [
  'You are answering an operator `/btw` side question using a read-only forked snapshot of an active security verification task.',
  'STRICT GUARDRAILS:',
  '1. This session is strictly READ-ONLY. Zero tools or target probes are enabled (`tools: []`).',
  '2. Answer concisely and accurately using only the facts, findings, intents, and goals in the provided snapshot.',
  '3. Never claim to have executed new probes or modified task state.',
].join('\n');

function deepClone(obj) {
  if (obj === null || obj === undefined || typeof obj !== 'object') {
    return obj;
  }
  if (typeof structuredClone === 'function') {
    try {
      return structuredClone(obj);
    } catch {
      // Fallback to JSON clone if non-cloneable properties exist
    }
  }
  return JSON.parse(JSON.stringify(obj));
}

function truncateStr(val, maxChars = STAGE_1_MAX_OUTPUT_CHARS) {
  if (typeof val !== 'string') return val;
  if (val.length <= maxChars) return val;
  return val.slice(0, maxChars);
}

function truncateObjectOutputs(item, maxChars = STAGE_1_MAX_OUTPUT_CHARS) {
  if (!item) return item;
  if (typeof item === 'string') {
    return truncateStr(item, maxChars);
  }
  if (typeof item !== 'object') return item;

  const bodyFields = [
    'output',
    'rawOutput',
    'toolOutput',
    'body',
    'httpBody',
    'responseBody',
    'requestBody',
    'content',
    'text',
    'detail',
  ];
  for (const field of bodyFields) {
    if (typeof item[field] === 'string' && item[field].length > maxChars) {
      item[field] = truncateStr(item[field], maxChars);
    }
  }
  return item;
}

function isLowPriorityHint(hint) {
  if (!hint) return true;
  if (typeof hint === 'string') return false;
  if (hint.lowPriority === true) return true;
  if (hint.state === 'consumed' || hint.status === 'consumed' || hint.status === 'dismissed') {
    return true;
  }
  if (typeof hint.priority === 'string') {
    const p = hint.priority.toLowerCase();
    return p === 'low' || p === 'minor' || p === 'trivial';
  }
  if (typeof hint.priority === 'number') {
    return hint.priority < 5;
  }
  return false;
}

function isCompletedColdFact(fact) {
  if (!fact || typeof fact !== 'object') return false;
  if (fact.cold === true || fact.isCold === true) return true;
  if (typeof fact.coldSinceRound === 'number' || typeof fact.cold_since_round === 'number') {
    return true;
  }
  const status = String(fact.status || fact.state || '').toLowerCase();
  if (status === 'cold' || status === 'completed' || status === 'folded' || status === 'archived') {
    return true;
  }
  if (fact.completed === true) return true;
  return false;
}

function foldColdFacts(factsArray) {
  if (!Array.isArray(factsArray) || factsArray.length === 0) {
    return { keptFacts: [], digestLine: null };
  }
  const cold = [];
  const hot = [];
  for (const f of factsArray) {
    if (isCompletedColdFact(f)) {
      cold.push(f);
    } else {
      hot.push(f);
    }
  }
  if (cold.length === 0) {
    return { keptFacts: hot, digestLine: null };
  }
  const summaries = cold
    .map((f) => f.summary || f.title || f.text || f.id || 'fact')
    .join('; ')
    .replace(/[\r\n]+/g, ' ')
    .trim();
  const digestLine = `Cold facts digest (${cold.length} completed): ${summaries}`;
  return { keptFacts: hot, digestLine };
}

function isVerifiedOrCandidateFinding(finding) {
  if (!finding) return false;
  if (typeof finding === 'string') return true;
  const status = String(
    finding.status || finding.state || finding.verificationStatus || 'candidate'
  ).toLowerCase();
  if (status === 'dismissed' || status === 'rejected' || status === 'false_positive') {
    return false;
  }
  return true;
}

/**
 * Applies the 4-stage context budget compression pipeline to a deep-cloned snapshot:
 * - Stage 0: Full snapshot (goals, active intents, findings, recent facts, tool outputs).
 * - Stage 1: Truncate raw tool outputs / HTTP bodies to 512 chars.
 * - Stage 2: Drop low-priority hints and fold completed cold facts into a 1-line digest summary.
 * - Stage 3: Keep only task goal, verified/candidate findings, and last 5 activity summaries.
 *
 * @param {object} contextSnapshot
 * @param {{ maxContextTokens?: number, question?: string, targetStage?: number|null }} [options]
 * @returns {{ snapshot: object, stage: number, estimatedTokens: number }}
 */
export function compressContextSnapshot(
  contextSnapshot = {},
  { maxContextTokens = 16000, question = '', targetStage = null } = {}
) {
  const cloned = deepClone(contextSnapshot || {});
  // Strip any tools if present in the snapshot
  if ('tools' in cloned) {
    delete cloned.tools;
  }

  const measure = (snap) => {
    const serialized = JSON.stringify(snap);
    return estimateTokens(serialized) + estimateTokens(question) + estimateTokens(READ_ONLY_SYSTEM_PROMPT);
  };

  let stage = 0;
  let tokens = measure(cloned);

  const shouldAdvance = (nextStage) => {
    if (targetStage !== null && targetStage !== undefined) {
      return nextStage <= targetStage;
    }
    return tokens > maxContextTokens;
  };

  // Stage 1: Truncate raw tool outputs / HTTP bodies to 512 chars
  if (shouldAdvance(1)) {
    stage = 1;
    if (Array.isArray(cloned.toolOutputs)) {
      cloned.toolOutputs = cloned.toolOutputs.map((t) =>
        truncateObjectOutputs(t, STAGE_1_MAX_OUTPUT_CHARS)
      );
    }
    if (Array.isArray(cloned.recentFacts)) {
      cloned.recentFacts = cloned.recentFacts.map((f) =>
        truncateObjectOutputs(f, STAGE_1_MAX_OUTPUT_CHARS)
      );
    }
    if (Array.isArray(cloned.facts)) {
      cloned.facts = cloned.facts.map((f) =>
        truncateObjectOutputs(f, STAGE_1_MAX_OUTPUT_CHARS)
      );
    }
    if (Array.isArray(cloned.activeIntents)) {
      cloned.activeIntents = cloned.activeIntents.map((i) =>
        truncateObjectOutputs(i, STAGE_1_MAX_OUTPUT_CHARS)
      );
    }
    if (Array.isArray(cloned.intents)) {
      cloned.intents = cloned.intents.map((i) =>
        truncateObjectOutputs(i, STAGE_1_MAX_OUTPUT_CHARS)
      );
    }
    if (typeof cloned.httpBody === 'string') {
      cloned.httpBody = truncateStr(cloned.httpBody, STAGE_1_MAX_OUTPUT_CHARS);
    }
    if (typeof cloned.rawOutput === 'string') {
      cloned.rawOutput = truncateStr(cloned.rawOutput, STAGE_1_MAX_OUTPUT_CHARS);
    }
    tokens = measure(cloned);
  }

  // Stage 2: Drop low-priority hints and fold completed cold facts into a 1-line digest summary
  if (shouldAdvance(2)) {
    stage = 2;
    if (Array.isArray(cloned.hints)) {
      cloned.hints = cloned.hints.filter((h) => !isLowPriorityHint(h));
    }

    const digestParts = [];
    if (Array.isArray(cloned.recentFacts)) {
      const { keptFacts, digestLine } = foldColdFacts(cloned.recentFacts);
      cloned.recentFacts = keptFacts;
      if (digestLine) digestParts.push(digestLine);
    }
    if (Array.isArray(cloned.facts)) {
      const { keptFacts, digestLine } = foldColdFacts(cloned.facts);
      cloned.facts = keptFacts;
      if (digestLine) digestParts.push(digestLine);
    }
    if (digestParts.length > 0) {
      cloned.coldFactsDigest = digestParts.join(' | ');
    }
    tokens = measure(cloned);
  }

  // Stage 3: Keep only task goal, verified/candidate findings, and last 5 activity summaries
  if (shouldAdvance(3)) {
    stage = 3;
    const rawFindings = Array.isArray(cloned.findings) ? cloned.findings : [];
    const keptFindings = rawFindings
      .filter((f) => isVerifiedOrCandidateFinding(f))
      .map((f) => {
        if (typeof f !== 'object' || !f) return f;
        return {
          id: f.id,
          title: f.title || f.name || f.summary || '',
          severity: f.severity,
          status: f.status || f.state || 'candidate',
          summary: truncateStr(f.summary || f.detail || '', 256),
        };
      });

    const rawActivity = Array.isArray(cloned.activity)
      ? cloned.activity
      : Array.isArray(cloned.activities)
        ? cloned.activities
        : [];
    const last5Activity = rawActivity.slice(-STAGE_3_MAX_ACTIVITIES).map((a) => {
      if (typeof a === 'string') return truncateStr(a, 200);
      return {
        seq: a?.seq ?? a?.id,
        summary: truncateStr(a?.summary || a?.title || a?.event_type || '', 200),
      };
    });

    const minimal = {};
    if (cloned.goal !== undefined) minimal.goal = cloned.goal;
    if (cloned.goals !== undefined) minimal.goals = cloned.goals;
    minimal.findings = keptFindings;
    minimal.activity = last5Activity;

    for (const key of Object.keys(cloned)) {
      delete cloned[key];
    }
    Object.assign(cloned, minimal);
    tokens = measure(cloned);
  }

  return {
    snapshot: cloned,
    stage,
    estimatedTokens: tokens,
  };
}

/**
 * Ephemeral read-only `/btw` side question handler.
 */
export class SideQuestionService {
  /**
   * @param {{ llmPool?: object, maxContextTokens?: number, fetcher?: Function }} [options]
   */
  constructor({ llmPool = null, maxContextTokens = 16000, fetcher = null } = {}) {
    this.llmPool = llmPool;
    this.maxContextTokens = Number(maxContextTokens) || 16000;
    this.fetcher = fetcher;
  }

  /**
   * Compresses a cloned context snapshot without mutating the source snapshot.
   *
   * @param {object} contextSnapshot
   * @param {{ maxContextTokens?: number, question?: string, targetStage?: number|null }} [options]
   * @returns {{ snapshot: object, stage: number, estimatedTokens: number }}
   */
  compressSnapshot(contextSnapshot, options = {}) {
    return compressContextSnapshot(contextSnapshot, {
      maxContextTokens: options.maxContextTokens ?? this.maxContextTokens,
      question: options.question || '',
      targetStage: options.targetStage ?? null,
    });
  }

  /**
   * Answers an operator `/btw` side question against a deep-cloned, budget-compressed snapshot
   * with strictly zero tools enabled (`tools: []`).
   *
   * @param {{ taskId?: string|null, question: string, contextSnapshot?: object, llmPool?: object, maxContextTokens?: number, fetcher?: Function, targetStage?: number|null }} params
   * @returns {Promise<{ answer: string, compressionStage: number, stage: number, estimatedTokens: number, compressedSnapshot: object, tools: Array<never>, profileId: string|null, usage: object }>}
   */
  async askSideQuestion({
    taskId = null,
    question = '',
    contextSnapshot = {},
    llmPool = null,
    maxContextTokens = this.maxContextTokens,
    fetcher = this.fetcher,
    targetStage = null,
  } = {}) {
    if (!question || typeof question !== 'string' || !question.trim()) {
      throw new Error('askSideQuestion requires a non-empty `question` string');
    }

    const pool = llmPool || this.llmPool;
    if (!pool || typeof pool.complete !== 'function') {
      throw new Error('askSideQuestion requires an `llmPool` instance with `.complete()`');
    }

    const { snapshot: compressedSnapshot, stage, estimatedTokens } = compressContextSnapshot(
      contextSnapshot,
      {
        maxContextTokens,
        question,
        targetStage,
      }
    );

    const userContent = [
      '=== TASK CONTEXT SNAPSHOT (READ-ONLY) ===',
      JSON.stringify(compressedSnapshot, null, 2),
      '',
      '=== OPERATOR SIDE QUESTION (/btw) ===',
      question.trim(),
    ].join('\n');

    // Strictly zero tools enabled (`tools: []`) so `/btw` queries can never mutate task state or probe targets
    const request = {
      system: READ_ONLY_SYSTEM_PROMPT,
      messages: [{ role: 'user', content: userContent }],
      tools: [],
      temperature: 0.1,
    };

    const result = await pool.complete(request, {
      taskId,
      role: 'sidequestion',
      fetcher: fetcher || undefined,
    });

    return {
      answer: result.text || '',
      text: result.text || '',
      compressionStage: stage,
      stage,
      estimatedTokens,
      compressedSnapshot,
      tools: [],
      profileId: result.profileId || null,
      usage: result.usage || { inputTokens: 0, outputTokens: 0, totalTokens: 0 },
    };
  }
}
