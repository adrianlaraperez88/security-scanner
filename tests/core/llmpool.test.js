import test from 'node:test';
import assert from 'node:assert/strict';

import {
  PROVIDERS,
  LlmProviderError,
  buildProviderRequest,
  callProvider,
  isQuotaExhaustedMessage,
  maskSecret,
  parseProviderResponse,
} from '../../core/llm-provider.js';
import { COOLDOWN_LADDER_MS, LlmPool, estimateTokens, bootstrapDefaultLlmProfiles } from '../../core/llmpool.js';
import { LlmRecorder, sanitizePayload } from '../../core/llmrec.js';
import { SideQuestionService, compressContextSnapshot } from '../../core/sidequestion.js';

test('llm-provider: PROVIDERS constant and maskSecret redaction', () => {
  assert.deepEqual(PROVIDERS, ['anthropic', 'openai', 'openai-responses', 'ollama', 'gemini']);
  assert.equal(maskSecret(''), '');
  assert.equal(maskSecret(null), '');
  assert.equal(maskSecret(undefined), '');
  assert.equal(maskSecret('sk-ant-api03-supersecret1234'), '__masked__:1234');
});

test('llm-provider: buildProviderRequest & parseProviderResponse for all 4 wire formats', () => {
  const sampleTools = [
    {
      name: 'http_probe',
      description: 'Send HTTP probe',
      parameters: {
        type: 'object',
        properties: { url: { type: 'string' } },
        required: ['url'],
      },
    },
  ];
  const sampleMessages = [{ role: 'user', content: 'Verify target auth boundary' }];

  // 1. Anthropic wire format
  const anthropicReq = buildProviderRequest(
    {
      provider: 'anthropic',
      model: 'claude-sonnet-4-5',
      baseUrl: 'https://api.anthropic.com',
      apiKey: 'sk-ant-secret9999',
      maxOutputTokens: 2048,
    },
    {
      system: 'System security prompt',
      messages: sampleMessages,
      tools: sampleTools,
      temperature: 0.2,
    }
  );
  assert.equal(anthropicReq.url, 'https://api.anthropic.com/v1/messages');
  assert.equal(anthropicReq.method, 'POST');
  assert.equal(anthropicReq.headers['x-api-key'], 'sk-ant-secret9999');
  assert.equal(anthropicReq.headers['anthropic-version'], '2023-06-01');
  assert.equal(anthropicReq.body.system, 'System security prompt');
  assert.equal(anthropicReq.body.max_tokens, 2048);
  assert.equal(anthropicReq.body.tools[0].name, 'http_probe');
  assert.ok(anthropicReq.body.tools[0].input_schema);

  const anthropicParsed = parseProviderResponse('anthropic', {
    model: 'claude-sonnet-4-5',
    stop_reason: 'tool_use',
    content: [
      { type: 'text', text: 'Checking endpoint...' },
      {
        type: 'tool_use',
        id: 'toolu_01',
        name: 'http_probe',
        input: { url: 'https://example.com/api' },
      },
    ],
    usage: { input_tokens: 120, output_tokens: 45 },
  });
  assert.equal(anthropicParsed.text, 'Checking endpoint...');
  assert.equal(anthropicParsed.toolCalls.length, 1);
  assert.deepEqual(anthropicParsed.toolCalls[0], {
    id: 'toolu_01',
    name: 'http_probe',
    arguments: { url: 'https://example.com/api' },
  });
  assert.deepEqual(anthropicParsed.usage, {
    inputTokens: 120,
    outputTokens: 45,
    totalTokens: 165,
  });

  // 2. OpenAI chat completions wire format
  const openaiReq = buildProviderRequest(
    {
      provider: 'openai',
      model: 'gpt-4o',
      baseUrl: 'https://api.openai.com',
      apiKey: 'sk-openai-abcd',
    },
    {
      system: 'OpenAI system prompt',
      messages: sampleMessages,
      tools: sampleTools,
    }
  );
  assert.equal(openaiReq.url, 'https://api.openai.com/v1/chat/completions');
  assert.equal(openaiReq.headers.Authorization, 'Bearer sk-openai-abcd');
  assert.equal(openaiReq.body.messages[0].role, 'system');
  assert.equal(openaiReq.body.messages[1].role, 'user');
  assert.equal(openaiReq.body.tools[0].type, 'function');
  assert.equal(openaiReq.body.tools[0].function.name, 'http_probe');

  const openaiParsed = parseProviderResponse('openai', {
    model: 'gpt-4o',
    choices: [
      {
        finish_reason: 'tool_calls',
        message: {
          content: 'Running probe',
          tool_calls: [
            {
              id: 'call_99',
              type: 'function',
              function: {
                name: 'http_probe',
                arguments: '{"url":"https://example.com/login"}',
              },
            },
          ],
        },
      },
    ],
    usage: { prompt_tokens: 200, completion_tokens: 50, total_tokens: 250 },
  });
  assert.equal(openaiParsed.text, 'Running probe');
  assert.deepEqual(openaiParsed.toolCalls[0], {
    id: 'call_99',
    name: 'http_probe',
    arguments: { url: 'https://example.com/login' },
  });
  assert.equal(openaiParsed.usage.totalTokens, 250);

  // 3. OpenAI Responses API (/v1/responses) wire format
  const responsesReq = buildProviderRequest(
    {
      provider: 'openai-responses',
      model: 'gpt-4.1',
      baseUrl: 'https://api.openai.com',
      apiKey: 'sk-resp-7777',
    },
    {
      system: 'Responses system instructions',
      messages: sampleMessages,
      tools: sampleTools,
    }
  );
  assert.equal(responsesReq.url, 'https://api.openai.com/v1/responses');
  assert.equal(responsesReq.headers.Authorization, 'Bearer sk-resp-7777');
  assert.equal(responsesReq.body.instructions, 'Responses system instructions');
  assert.equal(responsesReq.body.input.length, 1);
  assert.equal(responsesReq.body.tools[0].type, 'function');
  assert.equal(responsesReq.body.tools[0].name, 'http_probe');

  const responsesParsed = parseProviderResponse('openai-responses', {
    model: 'gpt-4.1',
    status: 'completed',
    output: [
      {
        type: 'message',
        content: [{ type: 'output_text', text: 'Responses output text' }],
      },
      {
        type: 'function_call',
        call_id: 'fc_1',
        name: 'http_probe',
        arguments: '{"url":"https://example.com/v2"}',
      },
    ],
    usage: { input_tokens: 80, output_tokens: 20, total_tokens: 100 },
  });
  assert.equal(responsesParsed.text, 'Responses output text');
  assert.deepEqual(responsesParsed.toolCalls[0], {
    id: 'fc_1',
    name: 'http_probe',
    arguments: { url: 'https://example.com/v2' },
  });

  // 4. Ollama local wire format (uses placeholder 'ollama' when apiKey is empty/unset)
  const ollamaReq = buildProviderRequest(
    {
      provider: 'ollama',
      model: 'qwen2.5-coder:32b',
      baseUrl: 'http://127.0.0.1:11434',
      apiKey: '',
    },
    {
      system: 'Local ollama system',
      messages: sampleMessages,
    }
  );
  assert.equal(ollamaReq.url, 'http://127.0.0.1:11434/v1/chat/completions');
  assert.equal(ollamaReq.headers.Authorization, 'Bearer ollama');

  const ollamaNativeReq = buildProviderRequest(
    {
      provider: 'ollama',
      model: 'llama3.2',
      baseUrl: 'http://127.0.0.1:11434/api/chat',
    },
    { messages: sampleMessages }
  );
  assert.equal(ollamaNativeReq.url, 'http://127.0.0.1:11434/api/chat');
  assert.equal(ollamaNativeReq.headers.Authorization, 'Bearer ollama');
});

test('llm-provider: isQuotaExhaustedMessage rewrites HTTP 429 quota errors to effectiveStatus 402 hard trip', async () => {
  assert.equal(isQuotaExhaustedMessage(402, ''), true);
  assert.equal(
    isQuotaExhaustedMessage(
      429,
      '{"error":{"code":"insufficient_quota","message":"You exceeded your current quota"}}'
    ),
    true
  );
  assert.equal(
    isQuotaExhaustedMessage(429, 'Your credit balance is too low to access the Anthropic API.'),
    true
  );
  assert.equal(isQuotaExhaustedMessage(429, 'billing_hard_limit_reached'), true);
  assert.equal(isQuotaExhaustedMessage(429, 'Account out of credits'), true);
  // Transient RPM rate limit must remain false (not a hard quota trip)
  assert.equal(
    isQuotaExhaustedMessage(429, 'Rate limit reached for requests per minute (RPM). Try again in 2s'),
    false
  );
  assert.equal(isQuotaExhaustedMessage(500, 'insufficient_quota'), false);

  // Verify callProvider throws LlmProviderError with effectiveStatus = 402 and isHardFailure = true
  await assert.rejects(
    async () => {
      await callProvider(
        { provider: 'openai', model: 'gpt-4o', apiKey: 'sk-test-1111' },
        { messages: [{ role: 'user', content: 'hi' }] },
        {
          fetcher: async () => ({
            ok: false,
            status: 429,
            text: async () =>
              JSON.stringify({
                error: {
                  code: 'insufficient_quota',
                  message: 'You exceeded your current quota, please check your plan and billing details.',
                },
              }),
          }),
        }
      );
    },
    (err) => {
      assert.ok(err instanceof LlmProviderError);
      assert.equal(err.status, 429);
      assert.equal(err.effectiveStatus, 402);
      assert.equal(err.isHardFailure, true);
      assert.equal(err.isSoftFailure, false);
      return true;
    }
  );
});

test('llmpool: circuit breaker 1-strike hard trip vs 3-strike soft trip and 1m -> 5m -> 30m cooldown ladder', () => {
  assert.deepEqual(COOLDOWN_LADDER_MS, [60_000, 300_000, 1_800_000]);

  let now = 1_000_000;
  const pool = new LlmPool({
    nowFn: () => now,
    profiles: [
      { id: 'hard-prof', provider: 'openai', model: 'gpt-4o', apiKey: 'sk-hard-1111' },
      { id: 'soft-prof', provider: 'anthropic', model: 'claude-sonnet-4-5', apiKey: 'sk-soft-2222' },
    ],
  });

  // 1. Hard failure (401/402/403/404 or 429 quota) trips immediately on 1st strike
  pool.recordFailure('hard-prof', { status: 429, rawBody: 'credit balance is too low' });
  let status = pool.getPoolStatus();
  assert.equal(status.breakers['hard-prof'].state, 'tripped');
  assert.equal(status.breakers['hard-prof'].tripCount, 1);
  assert.equal(status.breakers['hard-prof'].cooldownUntil, now + 60_000); // 1m

  // Advance past 1m cooldown; trigger 2nd hard failure -> 5m cooldown
  now += 61_000;
  assert.equal(pool.isProfileTripped('hard-prof'), false);
  pool.recordFailure('hard-prof', { status: 401, message: 'Unauthorized key' });
  status = pool.getPoolStatus();
  assert.equal(status.breakers['hard-prof'].state, 'tripped');
  assert.equal(status.breakers['hard-prof'].tripCount, 2);
  assert.equal(status.breakers['hard-prof'].cooldownUntil, now + 300_000); // 5m

  // Advance past 5m cooldown; trigger 3rd hard failure -> 30m cooldown
  now += 301_000;
  pool.recordFailure('hard-prof', { status: 403, message: 'Forbidden' });
  status = pool.getPoolStatus();
  assert.equal(status.breakers['hard-prof'].tripCount, 3);
  assert.equal(status.breakers['hard-prof'].cooldownUntil, now + 1_800_000); // 30m

  // 2. Soft failure (429 transient RPM / 503 / 502) requires 3 consecutive strikes to trip
  pool.recordFailure('soft-prof', { status: 503, message: 'Service unavailable' });
  assert.equal(pool.isProfileTripped('soft-prof'), false);
  pool.recordFailure('soft-prof', { status: 429, message: 'Rate limit RPM exceeded' });
  assert.equal(pool.isProfileTripped('soft-prof'), false);
  pool.recordFailure('soft-prof', { status: 502, message: 'Bad gateway' });
  assert.equal(pool.isProfileTripped('soft-prof'), true);
  status = pool.getPoolStatus();
  assert.equal(status.breakers['soft-prof'].consecutiveFailures, 3);
  assert.equal(status.breakers['soft-prof'].tripCount, 1);
  assert.equal(status.breakers['soft-prof'].cooldownUntil, now + 60_000);

  // resetBreaker clears trip state
  pool.resetBreaker('hard-prof');
  assert.equal(pool.isProfileTripped('hard-prof'), false);
  assert.equal(pool.getPoolStatus().breakers['hard-prof'].tripCount, 0);
});

test('llmpool: context-window pre-filtering and last-fallback preservation', async () => {
  const calledProfiles = [];
  const pool = new LlmPool({
    profiles: [
      {
        id: 'small-ctx',
        provider: 'openai',
        model: 'gpt-4o-mini',
        apiKey: 'sk-small-1111',
        contextWindow: 500,
        maxOutputTokens: 200,
        rank: 1,
      },
      {
        id: 'large-ctx',
        provider: 'openai',
        model: 'gpt-4o',
        apiKey: 'sk-large-2222',
        contextWindow: 128_000,
        maxOutputTokens: 4096,
        rank: 2,
      },
    ],
    fetcher: async (url, init) => {
      const body = JSON.parse(init.body);
      calledProfiles.push(body.model);
      return {
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            model: body.model,
            choices: [{ finish_reason: 'stop', message: { content: 'Handled by large window' } }],
            usage: { prompt_tokens: 1200, completion_tokens: 20, total_tokens: 1220 },
          }),
      };
    },
  });

  // Request with ~1,500 tokens exceeds small-ctx (contextWindow: 500) -> skips small-ctx and selects large-ctx
  const bigPrompt = 'A'.repeat(5000);
  assert.ok(estimateTokens(bigPrompt) > 1000);

  const res = await pool.complete({
    messages: [{ role: 'user', content: bigPrompt }],
    maxTokens: 200,
  });
  assert.equal(res.profileId, 'large-ctx');
  assert.deepEqual(calledProfiles, ['gpt-4o']);

  // If all profiles have a smaller contextWindow than required, preserves the last fallback profile
  const tinyPool = new LlmPool({
    profiles: [
      { id: 'tiny-1', provider: 'openai', model: 'm1', contextWindow: 100, maxOutputTokens: 50, rank: 1 },
      { id: 'tiny-2', provider: 'openai', model: 'm2', contextWindow: 200, maxOutputTokens: 50, rank: 2 },
    ],
  });
  const filtered = tinyPool.filterByContextWindow(tinyPool.listProfiles(), {
    messages: [{ role: 'user', content: bigPrompt }],
  });
  assert.equal(filtered.length, 1);
  assert.equal(filtered[0].id, 'tiny-2');
});

test('llmpool: worker round-robin rotation (A, B, A, B), intent pinning, tripped fallback, and preserving llmRotate on update', async () => {
  let now = 5_000_000;
  const pool = new LlmPool({
    nowFn: () => now,
    profiles: [
      { id: 'prof-A', provider: 'openai', model: 'gpt-4o', apiKey: 'sk-aaaa-1111', rank: 1 },
      { id: 'prof-B', provider: 'anthropic', model: 'claude-sonnet-4-5', apiKey: 'sk-bbbb-2222', rank: 2 },
    ],
  });

  // Configure task chain with llmRotate: true
  pool.configureTaskChain('task-rot', {
    profileIds: ['prof-A', 'prof-B'],
    llmRotate: true,
  });
  assert.equal(pool.getTaskChain('task-rot').llmRotate, true);

  // Updating profileIds while omitting llmRotate MUST preserve llmRotate: true
  pool.configureTaskChain('task-rot', {
    profileIds: ['prof-A', 'prof-B'],
  });
  assert.equal(pool.getTaskChain('task-rot').llmRotate, true);

  // Planner role always uses the primary ordered chain head ('prof-A') without advancing worker rotation cursor
  const plannerProf1 = pool.nextRotatedProfile('task-rot', { role: 'planner' });
  const plannerProf2 = pool.nextRotatedProfile('task-rot', { role: 'planner' });
  assert.equal(plannerProf1.id, 'prof-A');
  assert.equal(plannerProf2.id, 'prof-A');
  assert.equal(pool.getTaskChain('task-rot').rotationCursor, 0);

  // Concurrent worker intents rotate A, B, A, B in strict round-robin order
  const w1 = pool.nextRotatedProfile('task-rot', { role: 'worker', intentId: 'intent-1' });
  const w2 = pool.nextRotatedProfile('task-rot', { role: 'worker', intentId: 'intent-2' });
  const w3 = pool.nextRotatedProfile('task-rot', { role: 'worker', intentId: 'intent-3' });
  const w4 = pool.nextRotatedProfile('task-rot', { role: 'worker', intentId: 'intent-4' });
  assert.deepEqual([w1.id, w2.id, w3.id, w4.id], ['prof-A', 'prof-B', 'prof-A', 'prof-B']);

  // Calling nextRotatedProfile again for an already-pinned intentId returns its pinned profile without advancing cursor
  const cursorBefore = pool.getTaskChain('task-rot').rotationCursor;
  const w2Again = pool.nextRotatedProfile('task-rot', { role: 'worker', intentId: 'intent-2' });
  assert.equal(w2Again.id, 'prof-B');
  assert.equal(pool.getTaskChain('task-rot').rotationCursor, cursorBefore);

  // Trip prof-B's circuit breaker -> new intent assigned to prof-B slot falls back to healthy primary prof-A
  // while keeping the rotation cursor advancing across the full list
  pool.recordFailure('prof-B', { status: 402, message: 'insufficient_quota' });
  assert.equal(pool.isProfileTripped('prof-B'), true);

  const w5 = pool.nextRotatedProfile('task-rot', { role: 'worker', intentId: 'intent-5' }); // cursor 4 -> prof-A
  const w6 = pool.nextRotatedProfile('task-rot', { role: 'worker', intentId: 'intent-6' }); // cursor 5 -> assigned prof-B, falls back to prof-A
  assert.equal(w5.id, 'prof-A');
  assert.equal(w5.fallbackUsed, false);
  assert.equal(w6.id, 'prof-A');
  assert.equal(w6.assignedProfileId, 'prof-B');
  assert.equal(w6.fallbackUsed, true);
  assert.equal(pool.getTaskChain('task-rot').rotationCursor, 6);

  // resetTaskChain clears breaker state and rotation pins
  pool.resetTaskChain('task-rot');
  assert.equal(pool.isProfileTripped('prof-B'), false);
  assert.equal(pool.getTaskChain('task-rot').rotationCursor, 0);
});

test('llmpool & llmrec: pre-commit failover and strict secret redaction in getPoolStatus() & LlmRecorder', async () => {
  const rawKeyA = 'sk-proj-RAW_SECRET_KEY_AAAA_1111';
  const rawKeyB = 'sk-ant-RAW_SECRET_KEY_BBBB_2222';
  const recorder = new LlmRecorder();

  const pool = new LlmPool({
    recorder,
    profiles: [
      { id: 'primary', provider: 'openai', model: 'gpt-4o', apiKey: rawKeyA, rank: 1 },
      { id: 'backup', provider: 'anthropic', model: 'claude-sonnet-4-5', apiKey: rawKeyB, rank: 1 },
    ],
    fetcher: async (url) => {
      if (url.includes('openai.com')) {
        return {
          ok: false,
          status: 429,
          text: async () =>
            JSON.stringify({
              error: { code: 'insufficient_quota', message: 'Quota exceeded for primary key' },
            }),
        };
      }
      return {
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            model: 'claude-sonnet-4-5',
            stop_reason: 'end_turn',
            content: [{ type: 'text', text: 'Failover succeeded on backup' }],
            usage: { input_tokens: 40, output_tokens: 12 },
          }),
      };
    },
  });

  const result = await pool.complete(
    {
      system: 'Verify target',
      messages: [{ role: 'user', content: 'Run check' }],
    },
    { taskId: 'task-failover', role: 'planner' }
  );

  assert.equal(result.profileId, 'backup');
  assert.equal(result.text, 'Failover succeeded on backup');
  assert.equal(result.failovers.length, 1);
  assert.equal(result.failovers[0].profileId, 'primary');
  assert.equal(result.failovers[0].effectiveStatus, 402);

  // Verify getPoolStatus() masks all API keys and never leaks rawKeyA or rawKeyB
  const poolStatus = pool.getPoolStatus();
  const statusJson = JSON.stringify(poolStatus);
  assert.equal(statusJson.includes(rawKeyA), false);
  assert.equal(statusJson.includes(rawKeyB), false);
  assert.equal(poolStatus.profiles[0].apiKey, '__masked__:1111');
  assert.equal(poolStatus.profiles[1].apiKey, '__masked__:2222');

  // Verify LlmRecorder records both calls and redacts Authorization and x-api-key headers
  const records = recorder.listRecords({ taskId: 'task-failover' });
  assert.equal(records.length, 2);
  const recordsJson = JSON.stringify(records);
  assert.equal(recordsJson.includes(rawKeyA), false);
  assert.equal(recordsJson.includes(rawKeyB), false);
  assert.equal(records[0].requestPayload.headers.Authorization, 'Bearer __masked__:1111');
  assert.equal(records[1].requestPayload.headers['x-api-key'], '__masked__:2222');

  const summary = recorder.getUsageSummary({ taskId: 'task-failover' });
  assert.equal(summary.totalCalls, 2);
  assert.equal(summary.outputTokens, 12);
  assert.ok(summary.byProfile.backup);
});

test('sidequestion: 4-stage context budget compression, snapshot clone isolation, and zero write tools (tools: [])', async () => {
  const originalSnapshot = {
    goal: 'Verify authentication bypass on api.example.com',
    goals: [{ id: 'g1', text: 'Check JWT signature validation', status: 'open' }],
    activeIntents: [
      {
        id: 'i1',
        summary: 'Probe /api/admin with alg:none JWT',
        rawOutput: 'X'.repeat(1200),
      },
    ],
    findings: [
      {
        id: 'f1',
        title: 'Admin endpoint accepts unsigned JWT',
        severity: 'CRITICAL',
        status: 'verified',
        summary: '200 OK returned with forged alg:none token',
      },
      {
        id: 'f2',
        title: 'Dismissed noise finding',
        severity: 'LOW',
        status: 'dismissed',
        summary: 'False positive',
      },
    ],
    recentFacts: [
      {
        id: 'fact-hot',
        summary: 'Target uses RS256 in normal login flow',
        cold: false,
        httpBody: 'H'.repeat(1000),
      },
      {
        id: 'fact-cold-1',
        summary: 'Port 443 open with nginx 1.24',
        cold: true,
        status: 'completed',
      },
      {
        id: 'fact-cold-2',
        summary: 'Static assets served from CDN',
        cold: true,
        status: 'completed',
      },
    ],
    toolOutputs: [
      { id: 'to-1', tool: 'http_probe', output: 'T'.repeat(2000) },
      'R'.repeat(1500),
    ],
    hints: [
      { id: 'h-low', text: 'Check robots.txt later', priority: 'low' },
      { id: 'h-high', text: 'Focus on /api/v2/admin token parser', priority: 'high' },
    ],
    activity: [
      { seq: 1, summary: 'Task started' },
      { seq: 2, summary: 'Fingerprinted Next.js + Express' },
      { seq: 3, summary: 'Crawled 14 endpoints' },
      { seq: 4, summary: 'Dispatched intent i1' },
      { seq: 5, summary: 'Recorded fact-hot' },
      { seq: 6, summary: 'Verified finding f1' },
      { seq: 7, summary: 'Updated coverage ledger' },
    ],
    tools: [{ name: 'dangerous_write_tool' }],
  };

  const originalCopy = JSON.stringify(originalSnapshot);

  // Stage 0: Full snapshot when budget is generous
  const s0 = compressContextSnapshot(originalSnapshot, { maxContextTokens: 50_000 });
  assert.equal(s0.stage, 0);
  assert.equal(s0.snapshot.toolOutputs[0].output.length, 2000);
  assert.equal('tools' in s0.snapshot, false);

  // Stage 1: Truncates raw tool outputs / HTTP bodies to 512 chars
  const s1 = compressContextSnapshot(originalSnapshot, {
    maxContextTokens: s0.estimatedTokens - 10,
  });
  assert.ok(s1.stage >= 1);
  const s1Forced = compressContextSnapshot(originalSnapshot, { targetStage: 1 });
  assert.equal(s1Forced.stage, 1);
  assert.equal(s1Forced.snapshot.toolOutputs[0].output.length, 512);
  assert.equal(s1Forced.snapshot.toolOutputs[1].length, 512);
  assert.equal(s1Forced.snapshot.recentFacts[0].httpBody.length, 512);
  assert.equal(s1Forced.snapshot.activeIntents[0].rawOutput.length, 512);

  // Stage 2: Drops low-priority hints and folds completed cold facts into a 1-line digest summary
  const s2Forced = compressContextSnapshot(originalSnapshot, { targetStage: 2 });
  assert.equal(s2Forced.stage, 2);
  assert.equal(s2Forced.snapshot.hints.length, 1);
  assert.equal(s2Forced.snapshot.hints[0].id, 'h-high');
  assert.equal(s2Forced.snapshot.recentFacts.length, 1);
  assert.equal(s2Forced.snapshot.recentFacts[0].id, 'fact-hot');
  assert.ok(s2Forced.snapshot.coldFactsDigest.includes('Cold facts digest (2 completed)'));
  assert.equal(s2Forced.snapshot.coldFactsDigest.includes('\n'), false);

  // Stage 3: Keeps only task goal, verified/candidate findings, and last 5 activity summaries
  const s3 = compressContextSnapshot(originalSnapshot, { maxContextTokens: 200 });
  assert.equal(s3.stage, 3);
  assert.equal(s3.snapshot.goal, originalSnapshot.goal);
  assert.equal(s3.snapshot.findings.length, 1);
  assert.equal(s3.snapshot.findings[0].id, 'f1');
  assert.equal(s3.snapshot.activity.length, 5);
  assert.equal(s3.snapshot.activity[0].seq, 3);
  assert.equal(s3.snapshot.activity[4].seq, 7);
  assert.equal(s3.snapshot.toolOutputs, undefined);
  assert.equal(s3.snapshot.recentFacts, undefined);
  assert.equal(s3.snapshot.activeIntents, undefined);

  // Ensure originalSnapshot was NEVER mutated across any stage
  assert.equal(JSON.stringify(originalSnapshot), originalCopy);

  // Verify askSideQuestion sends strictly zero tools (`tools: []`)
  let capturedWireBody = null;
  const pool = new LlmPool({
    profiles: [{ id: 'sq-prof', provider: 'openai', model: 'gpt-4o', apiKey: 'sk-sq-1234' }],
    fetcher: async (url, init) => {
      capturedWireBody = JSON.parse(init.body);
      return {
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            model: 'gpt-4o',
            choices: [
              {
                finish_reason: 'stop',
                message: { content: 'Finding f1 confirms unsigned JWT acceptance on /api/admin.' },
              },
            ],
            usage: { prompt_tokens: 95, completion_tokens: 18, total_tokens: 113 },
          }),
      };
    },
  });

  const service = new SideQuestionService({ llmPool: pool });
  const answer = await service.askSideQuestion({
    taskId: 'task-1',
    question: 'What is the current status of JWT verification?',
    contextSnapshot: originalSnapshot,
    maxContextTokens: 200,
  });

  assert.equal(answer.compressionStage, 3);
  assert.deepEqual(answer.tools, []);
  assert.equal(
    answer.answer,
    'Finding f1 confirms unsigned JWT acceptance on /api/admin.'
  );
  assert.equal(capturedWireBody.tools, undefined);
  assert.equal(JSON.stringify(originalSnapshot), originalCopy);
});

test('llm-provider: gemini request/response/tool-call translation uses header key, never URL', () => {
  const built = buildProviderRequest(
    { provider: 'gemini', model: 'gemini-2.5-flash', apiKey: 'AIza-secret-9876' },
    {
      system: 'sys A',
      messages: [
        { role: 'system', content: 'sys B' },
        { role: 'user', content: 'hi' },
        { role: 'assistant', content: 'yo' },
      ],
      tools: [
        {
          name: 'http_probe',
          description: 'probe',
          parameters: { type: 'object', additionalProperties: false, properties: { url: { type: 'string' } } },
        },
      ],
      temperature: 0.2,
      maxTokens: 256,
    }
  );
  assert.equal(
    built.url,
    'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent'
  );
  assert.ok(!built.url.includes('?') && !built.url.includes('AIza-secret'));
  assert.equal(built.headers['x-goog-api-key'], 'AIza-secret-9876');
  assert.equal(built.headers['Content-Type'], 'application/json');
  assert.deepEqual(built.body.systemInstruction, { parts: [{ text: 'sys A\n\nsys B' }] });
  assert.deepEqual(built.body.contents, [
    { role: 'user', parts: [{ text: 'hi' }] },
    { role: 'model', parts: [{ text: 'yo' }] },
  ]);
  assert.deepEqual(built.body.generationConfig, { maxOutputTokens: 256, temperature: 0.2 });
  assert.equal(built.body.tools[0].functionDeclarations[0].name, 'http_probe');
  assert.equal(built.body.tools[0].functionDeclarations[0].parameters.additionalProperties, undefined);

  const custom = buildProviderRequest(
    { provider: 'gemini', model: 'm/x', baseUrl: 'https://proxy.local/v1beta/', apiKey: 'k' },
    {}
  );
  assert.equal(custom.url, 'https://proxy.local/v1beta/models/m%2Fx:generateContent');

  const parsed = parseProviderResponse('gemini', {
    candidates: [
      {
        content: {
          parts: [{ text: 'hello ' }, { text: 'world' }, { functionCall: { name: 'http_probe', args: { url: 'http://x' } } }],
        },
        finishReason: 'STOP',
      },
    ],
    usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 5, totalTokenCount: 15 },
  });
  assert.equal(parsed.text, 'hello world');
  assert.equal(parsed.toolCalls.length, 1);
  assert.equal(parsed.toolCalls[0].name, 'http_probe');
  assert.deepEqual(parsed.toolCalls[0].arguments, { url: 'http://x' });
  assert.deepEqual(parsed.usage, { inputTokens: 10, outputTokens: 5, totalTokens: 15 });
  assert.equal(parsed.stopReason, 'tool_use');
  assert.ok(parsed.raw);
});

test('llmpool: bootstrapDefaultLlmProfiles env discovery and key redaction', () => {
  const empty = new LlmPool();
  assert.equal(empty.listProfiles().length, 0);
  assert.deepEqual(bootstrapDefaultLlmProfiles(empty, {}), []);

  const env = Object.freeze({
    GEMINI_API_KEY: 'g-key-1111',
    ANTHROPIC_API_KEY: 'a-key-2222',
    OPENAI_API_KEY: 'o-key-3333',
    SECSCAN_OPENAI_MODEL: 'gpt-4.1',
  });
  const pool = new LlmPool({ autoDiscoverEnv: true, env });
  const byId = Object.fromEntries(pool.listProfiles().map((p) => [p.id, p]));
  assert.equal(byId.gemini.model, 'gemini-2.5-flash');
  assert.equal(byId.anthropic.model, 'claude-sonnet-4-20250514');
  assert.equal(byId.openai.model, 'gpt-4.1');
  assert.equal(byId.ollama, undefined);
  assert.equal(byId.gemini.hasApiKey, true);
  assert.equal(byId.gemini.apiKey, '__masked__:1111');

  const status = JSON.stringify(pool.getPoolStatus()) + JSON.stringify(pool.listProfiles());
  for (const raw of ['g-key-1111', 'a-key-2222', 'o-key-3333']) {
    assert.ok(!status.includes(raw));
  }
  // internal chain still carries real keys
  assert.equal(pool._buildCandidateChain({})[0].apiKey, 'g-key-1111');

  const p2 = new LlmPool();
  bootstrapDefaultLlmProfiles(p2, { OLLAMA_HOST: '10.0.0.5:11434', SECSCAN_GEMINI_MODEL: 'x' });
  assert.deepEqual(p2.listProfiles().map((p) => p.id), ['ollama']);
  assert.equal(p2.getProfile('ollama').model, 'llama3.1');
  assert.equal(p2.getProfile('ollama').baseUrl, 'http://10.0.0.5:11434');
});

test('CANDIDATE-7: callProvider keeps abort timer active during res.text() body read and caps oversized bodies', async () => {
  await assert.rejects(
    async () => {
      await callProvider(
        { provider: 'openai', model: 'gpt-4o', apiKey: 'sk-slow-1111' },
        { messages: [{ role: 'user', content: 'hi' }] },
        {
          timeoutMs: 40,
          fetcher: async () => ({
            ok: true,
            status: 200,
            text: () => new Promise((resolve) => setTimeout(() => resolve('{"choices":[]}'), 200)),
          }),
        }
      );
    },
    (err) => {
      assert.ok(err instanceof LlmProviderError);
      assert.equal(err.status, 408);
      assert.equal(err.effectiveStatus, 408);
      assert.equal(err.code, 'ETIMEDOUT');
      return true;
    }
  );

  // Oversized ReadableStream body is rejected without buffering infinitely
  const bigStream = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(600));
      controller.enqueue(new Uint8Array(600));
      controller.close();
    },
  });
  await assert.rejects(
    async () => {
      await callProvider(
        { provider: 'openai', model: 'gpt-4o', apiKey: 'sk-big-1111' },
        { messages: [{ role: 'user', content: 'hi' }] },
        {
          maxResponseBytes: 1024,
          fetcher: async () => ({
            ok: true,
            status: 200,
            body: bigStream,
          }),
        }
      );
    },
    (err) => {
      assert.ok(err instanceof LlmProviderError);
      assert.equal(err.code, 'RESPONSE_TOO_LARGE');
      return true;
    }
  );

  // Oversized res.text() mock is also rejected
  await assert.rejects(
    async () => {
      await callProvider(
        { provider: 'openai', model: 'gpt-4o', apiKey: 'sk-big-2222' },
        { messages: [{ role: 'user', content: 'hi' }] },
        {
          maxResponseBytes: 512,
          fetcher: async () => ({
            ok: true,
            status: 200,
            text: async () => 'x'.repeat(1024),
          }),
        }
      );
    },
    (err) => {
      assert.ok(err instanceof LlmProviderError);
      assert.equal(err.code, 'RESPONSE_TOO_LARGE');
      return true;
    }
  );
});

test('CANDIDATE-12: gemini pricing, env autoDiscovered flags, and safe upsert key preservation vs anti-exfiltration guard', () => {
  // 1. LlmRecorder meters Gemini token cost > 0
  const rec = new LlmRecorder();
  const flashCall = rec.recordCall({
    provider: 'gemini',
    model: 'gemini-2.5-flash',
    inputTokens: 1_000_000,
    outputTokens: 500_000,
  });
  assert.ok(flashCall.costUsd > 0, `Expected non-zero Gemini costUsd, got ${flashCall.costUsd}`);
  const proCall = rec.recordCall({
    provider: 'gemini',
    model: 'gemini-2.5-pro',
    inputTokens: 1_000_000,
    outputTokens: 1_000_000,
  });
  assert.ok(proCall.costUsd > flashCall.costUsd);

  // 2. Env-discovered profiles expose autoDiscovered:true & source:'env' in listProfiles() & getPoolStatus()
  const pool = new LlmPool({
    autoDiscoverEnv: true,
    env: { GEMINI_API_KEY: 'AIza-env-secret-9999' },
  });
  const listed = pool.listProfiles().find((p) => p.id === 'gemini');
  const statusProf = pool.getPoolStatus().profiles.find((p) => p.id === 'gemini');
  assert.equal(listed.autoDiscovered, true);
  assert.equal(listed.source, 'env');
  assert.equal(statusProf.autoDiscovered, true);
  assert.equal(statusProf.source, 'env');

  // 3. Updating model/name/enabled with omitted/blank apiKey preserves env key when provider/baseUrl/headers are unchanged
  pool.upsertProfile({
    id: 'gemini',
    provider: 'gemini',
    model: 'gemini-2.5-pro',
    enabled: true,
  });
  assert.equal(pool.getProfile('gemini').model, 'gemini-2.5-pro');
  assert.equal(pool.getProfile('gemini').apiKey, 'AIza-env-secret-9999');
  assert.equal(pool.getProfile('gemini').autoDiscovered, true);

  // 4. Changing baseUrl, provider, or custom headers with blank/omitted apiKey MUST throw (anti-exfiltration)
  assert.throws(() => {
    pool.upsertProfile({
      id: 'gemini',
      provider: 'gemini',
      model: 'gemini-2.5-pro',
      baseUrl: 'https://evil.example/collect',
    });
  }, /without providing apiKey/);

  assert.throws(() => {
    pool.upsertProfile({
      id: 'gemini',
      provider: 'openai',
      model: 'gpt-4o',
      apiKey: '',
    });
  }, /without providing apiKey/);

  assert.throws(() => {
    pool.upsertProfile({
      id: 'gemini',
      provider: 'gemini',
      model: 'gemini-2.5-pro',
      headers: { 'X-Steal': '1' },
    });
  }, /without providing apiKey/);
});
