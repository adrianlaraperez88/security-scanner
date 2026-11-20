import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mockFetch, mockFetchError } from '../helpers/mock-fetch.js';
import run from '../../checks/ai-llm-exposure.js';

const BASE = 'https://example.com';

test('ai-llm-exposure: CRITICAL on /api/tags Ollama exposure', async () => {
  const fetch = async (url) => {
    if (url === `${BASE}/api/tags`) {
      return {
        status: 200,
        headers: {},
        text: '{"models":[{"name":"llama3:latest","digest":"sha256:123456"}]}'
      };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  };

  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'CRITICAL');
  assert.ok(r.findings.some(f => f.name === 'exposed ollama api endpoint' && f.severity === 'CRITICAL'));
});

test('ai-llm-exposure: CRITICAL on sk-proj- and sk-ant- key leaks with masking', async () => {
  const openAiKey = ['sk', 'proj', '1234567890abcdefghijklmnopQRSTUVWXYZ'].join('-');
  const anthropicKey = ['sk', 'ant', '9876543210abcdefghijklmnopQRSTUVWXYZ'].join('-');

  const fetch = async (url) => {
    if (url === BASE) {
      return {
        status: 200,
        headers: {},
        text: `<html><script>const k1="${openAiKey}"; const k2="${anthropicKey}";</script></html>`
      };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  };

  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'CRITICAL');

  const openAiFinding = r.findings.find(f => f.name === 'leaked openai api key');
  const anthropicFinding = r.findings.find(f => f.name === 'leaked anthropic api key');
  assert.ok(openAiFinding);
  assert.ok(anthropicFinding);
  assert.ok(openAiFinding.reason.includes(`${openAiKey.slice(0, 14)}...`));
  assert.ok(!openAiFinding.reason.includes(openAiKey));
  assert.ok(anthropicFinding.reason.includes(`${anthropicKey.slice(0, 14)}...`));
  assert.ok(!anthropicFinding.reason.includes(anthropicKey));
});

test('ai-llm-exposure: HIGH on /.claude/settings.json and /v1/models', async () => {
  const fetch = async (url) => {
    if (url === `${BASE}/.claude/settings.json`) {
      return {
        status: 200,
        headers: {},
        text: '{"mcpServers":{"filesystem":{"command":"npx"}},"permissions":{"allow":["Read"]}}'
      };
    }
    if (url === `${BASE}/v1/models`) {
      return {
        status: 200,
        headers: {},
        text: '{"object":"list","data":[{"id":"gpt-4o"}]}'
      };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  };

  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'HIGH');
  assert.ok(r.findings.some(f => f.name === 'exposed claude settings and mcp servers' && f.severity === 'HIGH'));
  assert.ok(r.findings.some(f => f.name === 'unauthenticated openai-compatible models endpoint' && f.severity === 'HIGH'));
});

test('ai-llm-exposure: MEDIUM on /.cursorrules exposure', async () => {
  const fetch = async (url) => {
    if (url === `${BASE}/.cursorrules`) {
      return {
        status: 200,
        headers: {},
        text: 'You are an expert TypeScript developer. Always follow these cursor rules.'
      };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  };

  const r = await run(BASE, fetch);
  assert.equal(r.status, 'VULNERABLE');
  assert.equal(r.severity, 'MEDIUM');
  assert.ok(r.findings.some(f => f.name === 'exposed cursor rules' && f.severity === 'MEDIUM'));
});

test('ai-llm-exposure: SAFE when clean', async () => {
  const fetch = mockFetch({ status: 404, text: 'Not Found' });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SAFE');
  assert.equal(r.severity, 'NONE');
});

test('ai-llm-exposure: ERROR when all requests fail', async () => {
  const r = await run(BASE, mockFetchError('connection refused'));
  assert.equal(r.status, 'ERROR');
  assert.equal(r.severity, 'NONE');
});
