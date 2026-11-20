/**
 * Multi-Provider LLM Wire Adapter (`anthropic`, `openai`, `openai-responses`, `ollama`).
 * Implements ARTEX quota-aware HTTP status classification (429 -> 402 hard trip on billing/quota exhaustion),
 * secret masking, request formatting, and response normalization.
 */

export const PROVIDERS = Object.freeze([
  'anthropic',
  'openai',
  'openai-responses',
  'ollama',
  'gemini',
]);

const GEMINI_UNSUPPORTED_SCHEMA_KEYS = new Set(['$schema', 'additionalProperties', '$id', '$ref', 'definitions', '$defs']);

function sanitizeGeminiSchema(schema) {
  if (Array.isArray(schema)) return schema.map(sanitizeGeminiSchema);
  if (!schema || typeof schema !== 'object') return schema;
  const out = {};
  for (const [k, v] of Object.entries(schema)) {
    if (GEMINI_UNSUPPORTED_SCHEMA_KEYS.has(k)) continue;
    out[k] = sanitizeGeminiSchema(v);
  }
  return out;
}

function normalizeGeminiTools(tools = []) {
  const declarations = tools.map((t) => {
    const fn = t.function || t;
    const params =
      fn.parameters ||
      fn.input_schema ||
      fn.inputSchema ||
      t.parameters ||
      t.input_schema ||
      t.inputSchema ||
      { type: 'object', properties: {} };
    return {
      name: fn.name || t.name || 'tool',
      description: fn.description || t.description || '',
      parameters: sanitizeGeminiSchema(params),
    };
  });
  return [{ functionDeclarations: declarations }];
}

export const HARD_FAILURE_STATUSES = new Set([401, 402, 403, 404]);
export const SOFT_FAILURE_STATUSES = new Set([408, 409, 425, 429, 500, 502, 503, 504]);

const QUOTA_EXHAUSTED_PATTERNS = [
  /insufficient_quota/i,
  /credit balance is too low/i,
  /billing_hard_limit_reached/i,
  /quota exceeded/i,
  /exceeded your current quota/i,
  /out of credits/i,
  /insufficient credits/i,
  /billing_not_active/i,
  /monthly_spend_limit/i,
];

/**
 * Masks an API key or secret so raw credentials are never exposed in status responses or logs.
 * Returns '' if empty, or '__masked__:' + secret.slice(-4).
 *
 * @param {string} secret
 * @returns {string}
 */
export function maskSecret(secret) {
  if (!secret || typeof secret !== 'string') return '';
  const trimmed = secret.trim();
  if (!trimmed) return '';
  return '__masked__:' + trimmed.slice(-4);
}

/**
 * Detects billing/credit/quota exhaustion patterns on HTTP 429 or 402 responses
 * so the circuit breaker can normalize effectiveStatus to 402 (immediate hard trip)
 * rather than retrying a depleted key.
 *
 * @param {number|string} status
 * @param {string} [bodyText='']
 * @returns {boolean}
 */
export function isQuotaExhaustedMessage(status, bodyText = '') {
  if (typeof status === 'string' && bodyText === '') {
    return QUOTA_EXHAUSTED_PATTERNS.some((re) => re.test(status));
  }
  const numStatus = Number(status);
  if (numStatus === 402) return true;
  if (numStatus !== 429) return false;
  const text = typeof bodyText === 'string' ? bodyText : JSON.stringify(bodyText ?? '');
  return QUOTA_EXHAUSTED_PATTERNS.some((re) => re.test(text));
}

/**
 * Structured error thrown by `callProvider` on non-2xx HTTP responses or transport failures.
 */
export class LlmProviderError extends Error {
  constructor(
    message,
    {
      status = 0,
      effectiveStatus = null,
      code = 'LLM_PROVIDER_ERROR',
      isHardFailure = null,
      isSoftFailure = null,
      retryAfterMs = null,
      provider = null,
      rawBody = '',
    } = {}
  ) {
    super(message);
    this.name = 'LlmProviderError';
    this.status = status;
    this.effectiveStatus =
      effectiveStatus !== null
        ? effectiveStatus
        : isQuotaExhaustedMessage(status, rawBody || message)
          ? 402
          : status;
    this.code = code;
    this.isHardFailure =
      isHardFailure !== null ? Boolean(isHardFailure) : HARD_FAILURE_STATUSES.has(this.effectiveStatus);
    this.isSoftFailure =
      isSoftFailure !== null
        ? Boolean(isSoftFailure)
        : !this.isHardFailure &&
          (SOFT_FAILURE_STATUSES.has(this.effectiveStatus) ||
            this.effectiveStatus === 0 ||
            this.effectiveStatus >= 500);
    this.retryAfterMs = retryAfterMs;
    this.provider = provider;
    this.rawBody = rawBody;
  }
}

function safeJsonParse(value, fallback = {}) {
  if (value && typeof value === 'object') return value;
  if (typeof value !== 'string' || !value.trim()) return fallback;
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function parseRetryAfterMs(headerVal) {
  if (!headerVal) return null;
  const num = Number(headerVal);
  if (Number.isFinite(num) && num >= 0) {
    return Math.round(num * 1000);
  }
  const dateMs = Date.parse(headerVal);
  if (Number.isFinite(dateMs)) {
    return Math.max(0, dateMs - Date.now());
  }
  return null;
}

function normalizeAnthropicTools(tools = []) {
  return tools.map((t) => {
    const fn = t.function || t;
    return {
      name: fn.name || t.name || 'tool',
      description: fn.description || t.description || '',
      input_schema: fn.input_schema ||
        fn.inputSchema ||
        fn.parameters ||
        t.input_schema ||
        t.inputSchema ||
        t.parameters || { type: 'object', properties: {} },
    };
  });
}

function normalizeOpenAiTools(tools = []) {
  return tools.map((t) => {
    if (t.type === 'function' && t.function) return t;
    const fn = t.function || t;
    return {
      type: 'function',
      function: {
        name: fn.name || t.name || 'tool',
        description: fn.description || t.description || '',
        parameters: fn.parameters ||
          fn.input_schema ||
          fn.inputSchema ||
          t.parameters ||
          t.input_schema ||
          t.inputSchema || { type: 'object', properties: {} },
      },
    };
  });
}

function normalizeOpenAiResponsesTools(tools = []) {
  return tools.map((t) => {
    const fn = t.function || t;
    return {
      type: 'function',
      name: fn.name || t.name || 'tool',
      description: fn.description || t.description || '',
      parameters: fn.parameters ||
        fn.input_schema ||
        fn.inputSchema ||
        t.parameters ||
        t.input_schema ||
        t.inputSchema || { type: 'object', properties: {} },
    };
  });
}

/**
 * Builds the provider-specific URL, HTTP headers, and JSON body for any supported wire protocol.
 *
 * @param {object} profile
 * @param {object} request
 * @returns {{ url: string, method: string, headers: Record<string, string>, body: object, bodyText: string, provider: string }}
 */
export function buildProviderRequest(
  profile = {},
  { messages = [], system = '', tools = [], temperature, maxTokens, stream = false } = {}
) {
  const provider = (profile.provider || 'openai').toLowerCase();
  if (!PROVIDERS.includes(provider)) {
    throw new LlmProviderError(`Unsupported LLM provider: ${provider}`, {
      status: 400,
      effectiveStatus: 400,
      code: 'UNSUPPORTED_PROVIDER',
      isHardFailure: true,
      isSoftFailure: false,
      provider,
    });
  }

  const rawMessages = Array.isArray(messages) ? messages : [];
  const extractedSystems = [];
  if (system && typeof system === 'string' && system.trim()) {
    extractedSystems.push(system.trim());
  }
  const nonSystemMessages = [];
  for (const m of rawMessages) {
    if (!m) continue;
    if (m.role === 'system') {
      if (typeof m.content === 'string' && m.content.trim()) {
        extractedSystems.push(m.content.trim());
      }
    } else {
      nonSystemMessages.push({ role: m.role || 'user', content: m.content ?? '' });
    }
  }
  const combinedSystem = extractedSystems.join('\n\n');
  const resolvedMaxTokens = maxTokens ?? profile.maxOutputTokens ?? profile.maxTokens;

  if (provider === 'anthropic') {
    const base = (profile.baseUrl || 'https://api.anthropic.com').replace(/\/+$/, '');
    const url = base.endsWith('/v1/messages')
      ? base
      : base.endsWith('/v1')
        ? `${base}/messages`
        : `${base}/v1/messages`;

    const headers = {
      'Content-Type': 'application/json',
      'x-api-key': profile.apiKey || '',
      'anthropic-version': profile.anthropicVersion || '2023-06-01',
      ...(profile.headers || {}),
    };

    const body = {
      model: profile.model || 'claude-sonnet-4-5',
      max_tokens: resolvedMaxTokens || 4096,
      messages: nonSystemMessages.length > 0 ? nonSystemMessages : [{ role: 'user', content: '' }],
      stream: Boolean(stream),
    };
    if (combinedSystem) {
      body.system = combinedSystem;
    }
    if (Array.isArray(tools) && tools.length > 0) {
      body.tools = normalizeAnthropicTools(tools);
    }
    if (temperature !== undefined) {
      body.temperature = temperature;
    }

    return {
      url,
      method: 'POST',
      headers,
      body,
      bodyText: JSON.stringify(body),
      provider,
    };
  }

  if (provider === 'gemini') {
    const model = profile.model || 'gemini-2.5-flash';
    const base = (profile.baseUrl || 'https://generativelanguage.googleapis.com/v1beta').replace(/\/+$/, '');
    let url;
    if (/:(stream)?generateContent$/i.test(base)) {
      url = base;
    } else if (base.endsWith('/models')) {
      url = `${base}/${encodeURIComponent(model)}:generateContent`;
    } else if (/\/v1(beta)?$/.test(base)) {
      url = `${base}/models/${encodeURIComponent(model)}:generateContent`;
    } else {
      url = `${base}/v1beta/models/${encodeURIComponent(model)}:generateContent`;
    }

    // API key goes in a header only; never in the URL query string (avoids leaking into logs).
    const headers = {
      'Content-Type': 'application/json',
      'x-goog-api-key': profile.apiKey || '',
      ...(profile.headers || {}),
    };

    const contents = nonSystemMessages.map((m) => ({
      role: m.role === 'assistant' || m.role === 'model' ? 'model' : 'user',
      parts: [
        {
          text: typeof m.content === 'string' ? m.content : JSON.stringify(m.content ?? ''),
        },
      ],
    }));

    const body = {
      contents: contents.length > 0 ? contents : [{ role: 'user', parts: [{ text: '' }] }],
    };
    if (combinedSystem) {
      body.systemInstruction = { parts: [{ text: combinedSystem }] };
    }
    const generationConfig = {
      ...(resolvedMaxTokens ? { maxOutputTokens: resolvedMaxTokens } : {}),
      ...(temperature !== undefined ? { temperature } : {}),
    };
    if (Object.keys(generationConfig).length > 0) {
      body.generationConfig = generationConfig;
    }
    if (Array.isArray(tools) && tools.length > 0) {
      body.tools = normalizeGeminiTools(tools);
    }

    return {
      url,
      method: 'POST',
      headers,
      body,
      bodyText: JSON.stringify(body),
      provider,
    };
  }

  if (provider === 'openai-responses') {
    const base = (profile.baseUrl || 'https://api.openai.com').replace(/\/+$/, '');
    const url = base.endsWith('/v1/responses') || base.endsWith('/responses')
      ? base
      : base.endsWith('/v1')
        ? `${base}/responses`
        : `${base}/v1/responses`;

    const headers = {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${profile.apiKey || ''}`,
      ...(profile.headers || {}),
    };

    const body = {
      model: profile.model || 'gpt-4o',
      input: nonSystemMessages.map((m) => ({
        role: m.role,
        content: m.content,
      })),
      stream: Boolean(stream),
    };
    if (combinedSystem) {
      body.instructions = combinedSystem;
    }
    if (Array.isArray(tools) && tools.length > 0) {
      body.tools = normalizeOpenAiResponsesTools(tools);
    }
    if (resolvedMaxTokens !== undefined) {
      body.max_output_tokens = resolvedMaxTokens;
    }
    if (temperature !== undefined) {
      body.temperature = temperature;
    }

    return {
      url,
      method: 'POST',
      headers,
      body,
      bodyText: JSON.stringify(body),
      provider,
    };
  }

  if (provider === 'ollama') {
    const base = (profile.baseUrl || 'http://127.0.0.1:11434').replace(/\/+$/, '');
    let url;
    if (base.endsWith('/v1/chat/completions') || base.endsWith('/api/chat')) {
      url = base;
    } else if (base.endsWith('/v1')) {
      url = `${base}/chat/completions`;
    } else if (base.endsWith('/api')) {
      url = `${base}/chat`;
    } else {
      url = `${base}/v1/chat/completions`;
    }

    // Never leak cloud API keys to local Ollama servers: default to placeholder 'ollama' when unset
    const bearerToken =
      profile.apiKey && typeof profile.apiKey === 'string' && profile.apiKey.trim()
        ? profile.apiKey.trim()
        : 'ollama';

    const headers = {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${bearerToken}`,
      ...(profile.headers || {}),
    };

    const wireMessages = [];
    if (combinedSystem) {
      wireMessages.push({ role: 'system', content: combinedSystem });
    }
    wireMessages.push(...nonSystemMessages);

    const body = {
      model: profile.model || 'llama3.1',
      messages: wireMessages,
      stream: Boolean(stream),
    };
    if (Array.isArray(tools) && tools.length > 0) {
      body.tools = normalizeOpenAiTools(tools);
    }
    if (resolvedMaxTokens !== undefined) {
      body.max_tokens = resolvedMaxTokens;
    }
    if (temperature !== undefined) {
      body.temperature = temperature;
    }

    return {
      url,
      method: 'POST',
      headers,
      body,
      bodyText: JSON.stringify(body),
      provider,
    };
  }

  // Default: 'openai' (/v1/chat/completions)
  const base = (profile.baseUrl || 'https://api.openai.com').replace(/\/+$/, '');
  const url = base.endsWith('/chat/completions')
    ? base
    : base.endsWith('/v1')
      ? `${base}/chat/completions`
      : `${base}/v1/chat/completions`;

  const headers = {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${profile.apiKey || ''}`,
    ...(profile.headers || {}),
  };

  const wireMessages = [];
  if (combinedSystem) {
    wireMessages.push({ role: 'system', content: combinedSystem });
  }
  wireMessages.push(...nonSystemMessages);

  const body = {
    model: profile.model || 'gpt-4o',
    messages: wireMessages,
    stream: Boolean(stream),
  };
  if (Array.isArray(tools) && tools.length > 0) {
    body.tools = normalizeOpenAiTools(tools);
  }
  if (resolvedMaxTokens !== undefined) {
    const tokenField = profile.maxTokensField || 'max_tokens';
    body[tokenField] = resolvedMaxTokens;
  }
  if (temperature !== undefined) {
    body.temperature = temperature;
  }

  return {
    url,
    method: 'POST',
    headers,
    body,
    bodyText: JSON.stringify(body),
    provider,
  };
}

/**
 * Normalizes raw provider JSON payload into a unified completion result.
 *
 * @param {string} provider
 * @param {object|string} rawJson
 * @returns {{ text: string, toolCalls: Array<{ id: string, name: string, arguments: object }>, usage: { inputTokens: number, outputTokens: number, totalTokens: number }, model: string, provider: string, finishReason: string }}
 */
export function parseProviderResponse(provider, rawJson) {
  const normProvider = (provider || 'openai').toLowerCase();
  const raw = typeof rawJson === 'string' ? safeJsonParse(rawJson, {}) : rawJson || {};

  if (normProvider === 'anthropic') {
    const contentBlocks = Array.isArray(raw.content) ? raw.content : [];
    const textParts = [];
    const toolCalls = [];

    for (const block of contentBlocks) {
      if (!block) continue;
      if (block.type === 'text' && typeof block.text === 'string') {
        textParts.push(block.text);
      } else if (block.type === 'tool_use') {
        toolCalls.push({
          id: block.id || `tool_${toolCalls.length + 1}`,
          name: block.name || '',
          arguments: safeJsonParse(block.input, {}),
        });
      }
    }

    const inputTokens = Number(raw.usage?.input_tokens ?? raw.usage?.inputTokens ?? 0);
    const outputTokens = Number(raw.usage?.output_tokens ?? raw.usage?.outputTokens ?? 0);
    const totalTokens = Number(raw.usage?.total_tokens ?? inputTokens + outputTokens);

    return {
      text: textParts.join(''),
      toolCalls,
      usage: { inputTokens, outputTokens, totalTokens },
      model: raw.model || '',
      provider: normProvider,
      finishReason: raw.stop_reason || raw.finishReason || 'end_turn',
    };
  }

  if (normProvider === 'gemini') {
    const candidate = Array.isArray(raw.candidates) ? raw.candidates[0] : null;
    const parts = Array.isArray(candidate?.content?.parts) ? candidate.content.parts : [];
    const textParts = [];
    const toolCalls = [];
    for (const part of parts) {
      if (!part) continue;
      if (typeof part.text === 'string' && !part.thought) {
        textParts.push(part.text);
      } else if (part.functionCall) {
        toolCalls.push({
          id: part.functionCall.id || `call_${toolCalls.length + 1}`,
          name: part.functionCall.name || '',
          arguments: safeJsonParse(part.functionCall.args, {}),
        });
      }
    }
    const um = raw.usageMetadata || {};
    const inputTokens = Number(um.promptTokenCount ?? 0);
    const outputTokens = Number(um.candidatesTokenCount ?? 0);
    const totalTokens = Number(um.totalTokenCount ?? inputTokens + outputTokens);
    const finishReason = candidate?.finishReason || 'STOP';
    return {
      text: textParts.join(''),
      toolCalls,
      usage: { inputTokens, outputTokens, totalTokens },
      model: raw.modelVersion || raw.model || '',
      provider: normProvider,
      finishReason,
      stopReason: toolCalls.length > 0 ? 'tool_use' : finishReason,
      raw,
    };
  }

  if (normProvider === 'openai-responses') {
    const textParts = [];
    const toolCalls = [];

    if (typeof raw.output_text === 'string' && raw.output_text) {
      textParts.push(raw.output_text);
    }

    const outputItems = Array.isArray(raw.output) ? raw.output : [];
    for (const item of outputItems) {
      if (!item) continue;
      if (item.type === 'message' && Array.isArray(item.content)) {
        for (const c of item.content) {
          if (
            (c.type === 'output_text' || c.type === 'text') &&
            typeof c.text === 'string' &&
            textParts.length === 0
          ) {
            textParts.push(c.text);
          }
        }
      } else if (
        (item.type === 'output_text' || item.type === 'text') &&
        typeof item.text === 'string' &&
        textParts.length === 0
      ) {
        textParts.push(item.text);
      } else if (item.type === 'function_call' || item.type === 'tool_call') {
        toolCalls.push({
          id: item.call_id || item.id || `call_${toolCalls.length + 1}`,
          name: item.name || item.function?.name || '',
          arguments: safeJsonParse(item.arguments ?? item.function?.arguments, {}),
        });
      }
    }

    const inputTokens = Number(raw.usage?.input_tokens ?? raw.usage?.prompt_tokens ?? 0);
    const outputTokens = Number(raw.usage?.output_tokens ?? raw.usage?.completion_tokens ?? 0);
    const totalTokens = Number(raw.usage?.total_tokens ?? inputTokens + outputTokens);

    return {
      text: textParts.join(''),
      toolCalls,
      usage: { inputTokens, outputTokens, totalTokens },
      model: raw.model || '',
      provider: normProvider,
      finishReason: raw.status || raw.finish_reason || 'completed',
    };
  }

  // 'openai' and 'ollama' (/v1/chat/completions or /api/chat)
  const choice = Array.isArray(raw.choices) ? raw.choices[0] : null;
  const msg = choice?.message || raw.message || {};

  let text = '';
  if (typeof msg.content === 'string') {
    text = msg.content;
  } else if (Array.isArray(msg.content)) {
    text = msg.content.map((c) => (typeof c === 'string' ? c : c?.text || '')).join('');
  } else if (typeof raw.response === 'string') {
    text = raw.response;
  }

  const rawToolCalls = Array.isArray(msg.tool_calls) ? msg.tool_calls : [];
  const toolCalls = rawToolCalls.map((tc, idx) => ({
    id: tc.id || `call_${idx + 1}`,
    name: tc.function?.name || tc.name || '',
    arguments: safeJsonParse(tc.function?.arguments ?? tc.arguments, {}),
  }));

  const inputTokens = Number(
    raw.usage?.prompt_tokens ??
      raw.usage?.input_tokens ??
      raw.usage?.inputTokens ??
      raw.prompt_eval_count ??
      0
  );
  const outputTokens = Number(
    raw.usage?.completion_tokens ??
      raw.usage?.output_tokens ??
      raw.usage?.outputTokens ??
      raw.eval_count ??
      0
  );
  const totalTokens = Number(raw.usage?.total_tokens ?? inputTokens + outputTokens);

  return {
    text,
    toolCalls,
    usage: { inputTokens, outputTokens, totalTokens },
    model: raw.model || '',
    provider: normProvider,
    finishReason: choice?.finish_reason || raw.done_reason || 'stop',
  };
}

export const MAX_LLM_RESPONSE_BYTES = 2 * 1024 * 1024;

async function readResponseBodyWithLimit(res, signal, maxBytes = MAX_LLM_RESPONSE_BYTES) {
  if (signal?.aborted) {
    const err = new Error('The operation was aborted');
    err.name = 'AbortError';
    throw err;
  }

  const readUnbounded = async () => {
    if (res?.body && typeof res.body.getReader === 'function') {
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let totalBytes = 0;
      let out = '';
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (value) {
            totalBytes += value.byteLength ?? value.length ?? 0;
            if (totalBytes > maxBytes) {
              try { await reader.cancel(); } catch {}
              const err = new Error(`LLM response body exceeded ${maxBytes} bytes limit`);
              err.code = 'RESPONSE_TOO_LARGE';
              throw err;
            }
            out += decoder.decode(value, { stream: true });
          }
        }
        out += decoder.decode();
        return out;
      } finally {
        try { reader.releaseLock(); } catch {}
      }
    }

    let text = '';
    if (typeof res?.text === 'function') {
      text = String((await res.text()) ?? '');
    } else if (typeof res?.json === 'function') {
      const j = await res.json();
      text = JSON.stringify(j);
    } else if (res?.body !== undefined) {
      text = typeof res.body === 'string' ? res.body : JSON.stringify(res.body);
    }

    if (Buffer.byteLength(text, 'utf8') > maxBytes) {
      const err = new Error(`LLM response body exceeded ${maxBytes} bytes limit`);
      err.code = 'RESPONSE_TOO_LARGE';
      throw err;
    }
    return text;
  };

  if (!signal || typeof signal.addEventListener !== 'function') {
    return await readUnbounded();
  }

  let onAbort;
  const abortPromise = new Promise((_, reject) => {
    onAbort = () => {
      const err = new Error('The operation was aborted');
      err.name = 'AbortError';
      reject(err);
    };
    signal.addEventListener('abort', onAbort, { once: true });
  });

  try {
    return await Promise.race([readUnbounded(), abortPromise]);
  } finally {
    if (onAbort) {
      signal.removeEventListener('abort', onAbort);
    }
  }
}

/**
 * Executes an HTTP completion request against the given provider profile.
 * Throws `LlmProviderError` on non-2xx responses or transport timeouts.
 *
 * @param {object} profile
 * @param {object} request
 * @param {object} [options]
 * @returns {Promise<{ text: string, toolCalls: Array<object>, usage: object, model: string, provider: string, finishReason: string }>}
 */
export async function callProvider(
  profile,
  request = {},
  { fetcher = globalThis.fetch, timeoutMs = 60000, maxResponseBytes = MAX_LLM_RESPONSE_BYTES } = {}
) {
  const built = buildProviderRequest(profile, request);
  const controller = new AbortController();
  const timer = timeoutMs > 0 ? setTimeout(() => controller.abort(), timeoutMs) : null;

  let res;
  let bodyText = '';
  try {
    res = await fetcher(built.url, {
      method: built.method,
      headers: built.headers,
      body: built.bodyText,
      signal: controller.signal,
    });
    bodyText = await readResponseBodyWithLimit(res, controller.signal, maxResponseBytes);
  } catch (err) {
    if (err instanceof LlmProviderError) throw err;
    if (err?.code === 'RESPONSE_TOO_LARGE') {
      throw new LlmProviderError(err.message, {
        status: 502,
        effectiveStatus: 502,
        code: 'RESPONSE_TOO_LARGE',
        isHardFailure: false,
        isSoftFailure: true,
        provider: built.provider,
      });
    }
    const isAbort =
      controller.signal.aborted ||
      err?.name === 'AbortError' ||
      err?.code === 'ABORT_ERR' ||
      err?.code === 20;
    const status = isAbort ? 408 : 0;
    throw new LlmProviderError(err?.message || (isAbort ? 'LLM request timed out' : 'LLM transport failure'), {
      status,
      effectiveStatus: isAbort ? 408 : 503,
      code: isAbort ? 'ETIMEDOUT' : err?.code || 'NETWORK_ERROR',
      isHardFailure: false,
      isSoftFailure: true,
      provider: built.provider,
    });
  } finally {
    if (timer) clearTimeout(timer);
  }

  const status = Number(res.status ?? (res.ok ? 200 : 500));
  const ok = res.ok !== undefined ? Boolean(res.ok) : status >= 200 && status < 300;

  if (!ok) {
    const quotaExhausted = isQuotaExhaustedMessage(status, bodyText);
    const effectiveStatus = quotaExhausted ? 402 : status;
    const parsedErr = safeJsonParse(bodyText, null);
    const errObj = parsedErr?.error || parsedErr;
    const code =
      (typeof errObj?.code === 'string' && errObj.code) ||
      (typeof errObj?.type === 'string' && errObj.type) ||
      (quotaExhausted ? 'insufficient_quota' : `HTTP_${status}`);
    const message =
      (typeof errObj?.message === 'string' && errObj.message) ||
      bodyText ||
      `LLM provider returned HTTP ${status}`;
    const retryAfterHeader =
      typeof res.headers?.get === 'function'
        ? res.headers.get('retry-after')
        : res.headers?.['retry-after'] ?? res.headers?.['Retry-After'];

    throw new LlmProviderError(message, {
      status,
      effectiveStatus,
      code,
      isHardFailure: HARD_FAILURE_STATUSES.has(effectiveStatus),
      isSoftFailure:
        !HARD_FAILURE_STATUSES.has(effectiveStatus) &&
        (SOFT_FAILURE_STATUSES.has(effectiveStatus) || effectiveStatus >= 500),
      retryAfterMs: parseRetryAfterMs(retryAfterHeader),
      provider: built.provider,
      rawBody: bodyText,
    });
  }

  const parsedJson = safeJsonParse(bodyText, {});
  const normalized = parseProviderResponse(built.provider, parsedJson);
  if (!normalized.model && profile.model) {
    normalized.model = profile.model;
  }
  return normalized;
}
