/**
 * Hierarchical budgets (task-level BudgetLedger + per-intent IntentMeter) with the
 * SecScan `BudgetWrapupBlocks` pre-tool gate.
 *
 * When the remaining budget enters the wrap-up reserve window, exploratory tools are
 * blocked and only graph write-back tools may run, so that findings/facts/coverage
 * discovered so far are always persisted before the budget is exhausted.
 */

export const WRAPUP_BLOCKED_TOOLS = new Set([
  'http_probe',
  'run_check',
  'spawn_intent',
  'crawl_page',
  'fuzz_endpoint',
  'replay_request',
  'mcp_call',
]);

export const WRITEBACK_ALLOWED_TOOLS = new Set([
  'insert_assets',
  'record_fact',
  'report_finding',
  'record_coverage',
  'prove_goal',
  'complete_intent',
]);

export const WRAPUP_BLOCK_REASON =
  'Budget wrap-up active: only write-back tools (insert_assets, record_fact, report_finding, record_coverage) are permitted';

function posNum(v, fallback) {
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

/**
 * Computes the wrap-up reserve for a (maxTokens, maxTurns) envelope.
 */
export function computeWrapupReserve({
  maxTokens,
  maxTurns: _maxTurns,
  wrapupReservePct = 0.05,
  minWrapupTokens = 20_000,
  minWrapupTurns = 2,
} = {}) {
  const reserveTokens = Math.max(
    Math.ceil(maxTokens * wrapupReservePct),
    Math.min(minWrapupTokens, Math.floor(maxTokens * 0.25))
  );
  return { reserveTokens, reserveTurns: minWrapupTurns };
}

/**
 * Evaluates the gate for a tool given wrap-up state. Shared by ledger/meter.
 */
function gateDecision(toolName, wrapup) {
  const name = String(toolName || '');
  if (!wrapup) return { allowed: true, wrapup: false };
  if (WRITEBACK_ALLOWED_TOOLS.has(name)) return { allowed: true, wrapup: true };
  return { allowed: false, wrapup: true, reason: WRAPUP_BLOCK_REASON };
}

/**
 * Per-intent meter (one per worker run).
 */
export class IntentMeter {
  constructor({
    intentId = null,
    maxTokens = 40_000,
    maxTurns = 12,
    wrapupReservePct = 0.05,
    minWrapupTokens = 20_000,
    minWrapupTurns = 2,
  } = {}) {
    this.intentId = intentId;
    this.maxTokens = posNum(maxTokens, 40_000);
    this.maxTurns = posNum(maxTurns, 12);
    const { reserveTokens, reserveTurns } = computeWrapupReserve({
      maxTokens: this.maxTokens,
      maxTurns: this.maxTurns,
      wrapupReservePct,
      minWrapupTokens,
      minWrapupTurns,
    });
    this.reserveTokens = reserveTokens;
    this.reserveTurns = reserveTurns;
    this.tokensUsed = 0;
    this.turnsUsed = 0;
  }

  record({ tokens = 0, turns = 0 } = {}) {
    this.tokensUsed += posNum(tokens, 0);
    this.turnsUsed += posNum(turns, 0);
    return this;
  }

  get remainingTokens() {
    return Math.max(0, this.maxTokens - this.tokensUsed);
  }

  get remainingTurns() {
    return Math.max(0, this.maxTurns - this.turnsUsed);
  }

  isWrapupActive() {
    return this.remainingTokens <= this.reserveTokens || this.remainingTurns <= this.reserveTurns;
  }

  isExhausted() {
    return this.remainingTokens <= 0 || this.remainingTurns <= 0;
  }

  checkToolGate(toolName) {
    return gateDecision(toolName, this.isWrapupActive());
  }

  snapshot() {
    return {
      intentId: this.intentId,
      maxTokens: this.maxTokens,
      maxTurns: this.maxTurns,
      tokensUsed: this.tokensUsed,
      turnsUsed: this.turnsUsed,
      reserveTokens: this.reserveTokens,
      reserveTurns: this.reserveTurns,
      wrapup: this.isWrapupActive(),
    };
  }
}

/**
 * Task-level budget ledger.
 */
export class BudgetLedger {
  constructor({
    maxTokens = 200_000,
    maxTurns = 40,
    wrapupReservePct = 0.05,
    minWrapupTokens = 20_000,
    minWrapupTurns = 2,
  } = {}) {
    this.maxTokens = posNum(maxTokens, 200_000);
    this.maxTurns = posNum(maxTurns, 40);
    this.wrapupReservePct = wrapupReservePct;
    this.minWrapupTokens = minWrapupTokens;
    this.minWrapupTurns = minWrapupTurns;
    const { reserveTokens, reserveTurns } = computeWrapupReserve({
      maxTokens: this.maxTokens,
      maxTurns: this.maxTurns,
      wrapupReservePct,
      minWrapupTokens,
      minWrapupTurns,
    });
    this.reserveTokens = reserveTokens;
    this.reserveTurns = reserveTurns;
    this.tokensUsed = 0;
    this.turnsUsed = 0;
    /** @type {Map<string, {tokens:number, turns:number}>} */
    this.completedIntents = new Map();
  }

  /** Create a per-intent meter scaled to the remaining task budget. */
  createIntentMeter(intentId, { maxTokens, maxTurns } = {}) {
    return new IntentMeter({
      intentId,
      maxTokens: maxTokens ?? Math.max(1, Math.min(40_000, this.remainingTokens)),
      maxTurns: maxTurns ?? Math.max(1, Math.min(12, this.remainingTurns)),
      wrapupReservePct: this.wrapupReservePct,
      minWrapupTokens: this.minWrapupTokens,
      minWrapupTurns: this.minWrapupTurns,
    });
  }

  record({ tokens = 0, turns = 0 } = {}) {
    this.tokensUsed += posNum(tokens, 0);
    this.turnsUsed += posNum(turns, 0);
    return this;
  }

  get remainingTokens() {
    return Math.max(0, this.maxTokens - this.tokensUsed);
  }

  get remainingTurns() {
    return Math.max(0, this.maxTurns - this.turnsUsed);
  }

  isWrapupActive() {
    return this.remainingTokens <= this.reserveTokens || this.remainingTurns <= this.reserveTurns;
  }

  isExhausted() {
    return this.remainingTokens <= 0 || this.remainingTurns <= 0;
  }

  /**
   * SecScan BudgetWrapupBlocks pre-tool gate: consults task budget and (optionally) intent meter.
   */
  checkToolGate(toolName, { intentMeter = null } = {}) {
    const wrapup = this.isWrapupActive() || Boolean(intentMeter && intentMeter.isWrapupActive());
    return gateDecision(toolName, wrapup);
  }

  recordIntentConsumption({ intentId, tokens = 0, turns = 0 } = {}) {
    const key = String(intentId ?? `intent_${this.completedIntents.size + 1}`);
    this.completedIntents.set(key, { tokens: posNum(tokens, 0), turns: posNum(turns, 0) });
    return this.completedIntents.size;
  }

  averageIntentCost() {
    const n = this.completedIntents.size;
    if (n === 0) return null;
    let t = 0;
    let u = 0;
    for (const v of this.completedIntents.values()) {
      t += v.tokens;
      u += v.turns;
    }
    return { avgTokens: t / n, avgTurns: u / n, samples: n };
  }

  /**
   * Estimates how many more worker intents the remaining budget (minus wrap-up reserve) can fund.
   */
  estimateRemainingWorkerCapacity() {
    const avg = this.averageIntentCost();
    const avgTokens = Math.max(1, avg?.avgTokens || 20_000);
    const avgTurns = Math.max(1, avg?.avgTurns || 6);
    const usableTokens = Math.max(0, this.remainingTokens - this.reserveTokens);
    const usableTurns = Math.max(0, this.remainingTurns - this.reserveTurns);
    const byTokens = Math.floor(usableTokens / avgTokens);
    const byTurns = Math.floor(usableTurns / avgTurns);
    return {
      avgTokens,
      avgTurns,
      samples: avg?.samples ?? 0,
      remainingWorkers: Math.max(0, Math.min(byTokens, byTurns)),
    };
  }

  snapshot() {
    return {
      maxTokens: this.maxTokens,
      maxTurns: this.maxTurns,
      tokensUsed: this.tokensUsed,
      turnsUsed: this.turnsUsed,
      reserveTokens: this.reserveTokens,
      reserveTurns: this.reserveTurns,
      wrapup: this.isWrapupActive(),
      capacity: this.estimateRemainingWorkerCapacity(),
    };
  }
}
