import {
  isHtmlOrScript,
  isRedirectedToDifferentPath,
  isFrameworkRouteErrorResponse,
  parseJsonObject,
  extractVerbatimSnippet,
  confirmReproducible
} from '../core/check-verify.js';

export const tags = ['all'];

const AI_ENDPOINTS = [
  {
    path: '/.cursorrules',
    name: 'exposed cursor rules',
    severity: 'MEDIUM',
    status: 'VULNERABLE',
    reason: 'Exposed .cursorrules file reveals internal system prompts, development instructions, or configuration.',
    validate: (res) => {
      const text = typeof res?.text === 'string' ? res.text : '';
      if (!text || isHtmlOrScript(res, text) || text.trim().startsWith('{')) return false;
      const lower = text.toLowerCase();
      return (lower.includes('you are') && (lower.includes('rules') || lower.includes('always') || lower.includes('cursor'))) ||
             (lower.includes('cursor') && lower.includes('rules') && lower.includes('always'));
    },
    signalDesc: 'Plaintext .cursorrules directives'
  },
  {
    path: '/.claude/settings.json',
    name: 'exposed claude settings and mcp servers',
    severity: 'HIGH',
    status: 'VULNERABLE',
    reason: 'Exposed .claude/settings.json file reveals MCP server configurations and tool permissions.',
    validate: (res) => {
      const text = typeof res?.text === 'string' ? res.text : '';
      if (!text || isHtmlOrScript(res, text)) return false;
      const json = parseJsonObject(text);
      return Boolean(json && !Array.isArray(json) && (json.permissions || json.mcpServers || json.enabledMcpjsonServers));
    },
    signalDesc: 'JSON permissions/mcpServers schema'
  },
  {
    path: '/.well-known/ai-plugin.json',
    name: 'exposed ai plugin manifest',
    severity: 'LOW',
    status: 'SUSPICIOUS',
    reason: 'Exposed AI plugin manifest reveals API schema specifications and model integration metadata.',
    validate: (res) => {
      const text = typeof res?.text === 'string' ? res.text : '';
      if (!text || isHtmlOrScript(res, text)) return false;
      const json = parseJsonObject(text);
      return Boolean(json && !Array.isArray(json) && json.schema_version && json.name_for_model);
    },
    signalDesc: 'AI plugin manifest JSON'
  },
  {
    path: '/api/tags',
    name: 'exposed ollama api endpoint',
    severity: 'CRITICAL',
    status: 'VULNERABLE',
    reason: 'Unauthenticated Ollama API endpoint (/api/tags) is publicly exposed, allowing arbitrary model enumeration or execution.',
    validate: (res) => {
      const text = typeof res?.text === 'string' ? res.text : '';
      if (!text || isHtmlOrScript(res, text)) return false;
      const json = parseJsonObject(text);
      return Boolean(json && !Array.isArray(json) && Array.isArray(json.models));
    },
    signalDesc: 'Ollama JSON models[] array'
  },
  {
    path: '/v1/models',
    name: 'unauthenticated openai-compatible models endpoint',
    severity: 'HIGH',
    status: 'VULNERABLE',
    reason: 'Unauthenticated OpenAI-compatible API proxy endpoint (/v1/models) is publicly accessible.',
    validate: (res) => {
      const text = typeof res?.text === 'string' ? res.text : '';
      if (!text || isHtmlOrScript(res, text)) return false;
      const json = parseJsonObject(text);
      return Boolean(json && !Array.isArray(json) && json.object === 'list' && Array.isArray(json.data));
    },
    signalDesc: 'OpenAI-compatible models list JSON'
  }
];

export default async function run(target, fetchWithRetry) {
  const base = target.replace(/\/+$/, '');
  const found = [];
  let networkSuccess = false;

  // 1. Check homepage for leaked AI API keys
  try {
    const homeRes = await fetchWithRetry(target);
    networkSuccess = true;
    const text = homeRes?.text || '';

    const openAiMatch = /sk-proj-[a-zA-Z0-9_-]{20,}/.exec(text);
    if (openAiMatch) {
      const masked = `${openAiMatch[0].slice(0, 14)}...`;
      found.push({
        name         : 'leaked openai api key',
        path         : '/',
        url          : target,
        method       : 'GET',
        status       : homeRes?.status ?? 200,
        severity     : 'CRITICAL',
        statusTag    : 'VULNERABLE',
        matchedSignal: `OpenAI key prefix ${masked}`,
        reproducible : true,
        preview      : `OpenAI key prefix ${masked}`,
        reason       : `Exposed OpenAI project API key (${masked}) found in page content.`,
        ...(homeRes?.trafficId !== undefined ? { trafficId: homeRes.trafficId } : {})
      });
    }

    const anthropicMatch = /sk-ant-[a-zA-Z0-9_-]{20,}/.exec(text);
    if (anthropicMatch) {
      const masked = `${anthropicMatch[0].slice(0, 14)}...`;
      found.push({
        name         : 'leaked anthropic api key',
        path         : '/',
        url          : target,
        method       : 'GET',
        status       : homeRes?.status ?? 200,
        severity     : 'CRITICAL',
        statusTag    : 'VULNERABLE',
        matchedSignal: `Anthropic key prefix ${masked}`,
        reproducible : true,
        preview      : `Anthropic key prefix ${masked}`,
        reason       : `Exposed Anthropic API key (${masked}) found in page content.`,
        ...(homeRes?.trafficId !== undefined ? { trafficId: homeRes.trafficId } : {})
      });
    }
  } catch { /* homepage request failed */ }

  // 2. Probe AI / Agent configuration & MCP endpoints with confirmation
  for (const check of AI_ENDPOINTS) {
    try {
      const url = `${base}${check.path}`;
      const res = await fetchWithRetry(url, { followRedirects: false });
      networkSuccess = true;

      if (
        res?.status !== 200 ||
        isRedirectedToDifferentPath(res, url) ||
        isFrameworkRouteErrorResponse(res, res?.text) ||
        !check.validate(res)
      ) {
        continue;
      }

      const { confirmed, res: cRes } = await confirmReproducible(
        url,
        fetchWithRetry,
        { followRedirects: false },
        (r) => r?.status === 200 && !isRedirectedToDifferentPath(r, url) && check.validate(r)
      );
      if (!confirmed) continue;

      const finalRes = cRes || res;
      const preview = extractVerbatimSnippet(finalRes.text || res.text || '', /models|mcpServers|permissions|schema_version|object|you are/i)
        || check.signalDesc;

      found.push({
        name         : check.name,
        path         : check.path,
        url,
        method       : 'GET',
        status       : 200,
        severity     : check.severity,
        statusTag    : check.status,
        matchedSignal: check.signalDesc,
        reproducible : true,
        preview,
        reason       : check.reason,
        ...(finalRes?.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {})
      });
    } catch { /* probe failed */ }
  }

  if (!networkSuccess) {
    return { name: 'ai & llm exposure', status: 'ERROR', severity: 'NONE', reason: 'Target unreachable' };
  }

  if (found.length === 0) {
    return { name: 'ai & llm exposure', status: 'SAFE', severity: 'NONE' };
  }

  const maxSev = found.some(f => f.severity === 'CRITICAL') ? 'CRITICAL'
               : found.some(f => f.severity === 'HIGH')     ? 'HIGH'
               : found.some(f => f.severity === 'MEDIUM')   ? 'MEDIUM'
               : 'LOW';
  const primary = found[0];
  const evidenceQuotes = found.map(f => f.preview).filter(q => typeof q === 'string' && q.length >= 8).slice(0, 5);

  return {
    name          : 'ai & llm exposure',
    status        : found.some(f => f.statusTag === 'VULNERABLE') ? 'VULNERABLE' : 'SUSPICIOUS',
    severity      : maxSev,
    path          : primary.path,
    detail        : `Confirmed ${found.length} AI/LLM exposure(s): ${found.map(f => f.path).join(', ')}`,
    findings      : found.map(f => ({ name: f.name, severity: f.severity, path: f.path, url: f.url, status: f.status, matchedSignal: f.matchedSignal, preview: f.preview, reason: f.reason })),
    files         : found,
    reproVerified : true,
    poeLevel      : evidenceQuotes.length > 0 ? 3 : 2,
    ...(evidenceQuotes.length > 0 ? { evidenceQuotes } : {}),
    ...(primary.trafficId !== undefined ? { trafficId: primary.trafficId } : {}),
    fix           : 'Restrict public access to AI development files (.cursorrules, .claude), protect AI API endpoints (/v1/models, /api/tags) behind authentication, and immediately revoke any leaked API keys.'
  };
}
