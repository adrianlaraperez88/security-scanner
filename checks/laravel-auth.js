import { redactSecretsInText } from '../core/ai-advisor.js';
import {
  isHtmlOrScript,
  isRedirectedToDifferentPath,
  parseJsonObject,
  extractVerbatimSnippet,
  confirmReproducible
} from '../core/check-verify.js';

export const tags = ['laravel'];

const ERROR_KEYS = new Set(['error', 'errors', 'exception', 'fault']);

function hasApiErrorPayload(json) {
  if (!json || typeof json !== 'object' || Array.isArray(json)) return false;
  if (json.success === false || json.ok === false || json.authenticated === false) return true;
  for (const key of Object.keys(json)) {
    if (ERROR_KEYS.has(key.toLowerCase()) && json[key]) return true;
  }
  const msg = typeof json.message === 'string' ? json.message.toLowerCase() : '';
  return /\b(unauthenticated|unauthorized|forbidden|invalid credentials|validation|disabled|not allowed|failed|incorrect)\b/.test(msg);
}

function isExposedUserJson(res) {
  if (!res || res.status !== 200) return null;
  const text = typeof res.text === 'string' ? res.text : '';
  if (!text || isHtmlOrScript(res, text)) return null;

  const parsed = parseJsonObject(text);
  if (!parsed || hasApiErrorPayload(parsed)) return null;

  const candidate = Array.isArray(parsed)
    ? parsed[0]
    : (parsed.data && typeof parsed.data === 'object' && !Array.isArray(parsed.data)
        ? parsed.data
        : (parsed.user && typeof parsed.user === 'object' ? parsed.user : parsed));

  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) return null;

  const hasEmail = typeof candidate.email === 'string' && /@/.test(candidate.email);
  const hasSecretToken = ['api_token', 'remember_token', 'password', 'password_hash', 'access_token']
    .some(k => typeof candidate[k] === 'string' && candidate[k].length > 0);
  const hasIdentityPair =
    (candidate.id !== undefined && candidate.id !== null) &&
    (typeof candidate.name === 'string' || typeof candidate.username === 'string' || typeof candidate.email === 'string');

  if (!hasEmail && !hasSecretToken && !hasIdentityPair) return null;

  const matchedSignal = hasEmail ? 'JSON email identity field'
    : hasSecretToken ? 'JSON token/credential field'
    : 'JSON user id+name identity';
  return { matchedSignal, snippet: extractVerbatimSnippet(text, hasEmail ? '"email"' : '"id"') || text.slice(0, 120) };
}

function isOpenRegistrationJson(res) {
  if (!res || (res.status !== 200 && res.status !== 201)) return null;
  const text = typeof res.text === 'string' ? res.text : '';
  if (!text || isHtmlOrScript(res, text)) return null;

  const parsed = parseJsonObject(text);
  if (!parsed || Array.isArray(parsed) || hasApiErrorPayload(parsed)) return null;

  const hasCreatedArtifact = Boolean(
    parsed.token ||
    parsed.access_token ||
    parsed.user ||
    parsed.data?.id ||
    parsed.id !== undefined ||
    parsed.success === true ||
    parsed.created === true ||
    /registered|created successfully/i.test(String(parsed.message || ''))
  );
  if (!hasCreatedArtifact) return null;

  return {
    matchedSignal: `HTTP ${res.status} JSON registration succeeded`,
    snippet: extractVerbatimSnippet(text, '"token"') || extractVerbatimSnippet(text, '"user"') || text.slice(0, 120)
  };
}

function isOpenLoginBypassJson(res) {
  if (!res || res.status !== 200) return null;
  const text = typeof res.text === 'string' ? res.text : '';
  if (!text || isHtmlOrScript(res, text)) return null;

  const parsed = parseJsonObject(text);
  if (!parsed || Array.isArray(parsed) || hasApiErrorPayload(parsed)) return null;

  const hasAuthGrant = Boolean(
    parsed.token ||
    parsed.access_token ||
    parsed.jwt ||
    parsed.bearer ||
    parsed.session_id ||
    parsed.authenticated === true ||
    parsed.success === true
  );
  if (!hasAuthGrant) return null;

  return {
    matchedSignal: 'HTTP 200 JSON auth token issued for bad credentials',
    snippet: extractVerbatimSnippet(text, '"token"') || extractVerbatimSnippet(text, '"access_token"') || text.slice(0, 120)
  };
}

/**
 * Checks common Laravel API authentication endpoints for reproducible security issues:
 *  - /api/user, /api/me: unauthenticated JSON user identity disclosure
 *  - /api/register: open JSON registration accepting unauthenticated signup
 *  - /api/login: authentication bypass returning 200 auth token on bad credentials
 */
const ENDPOINTS = [
  {
    path   : '/api/user',
    method : 'GET',
    issue  : '/api/user returns user data without authentication',
    severity: 'CRITICAL',
    validate: isExposedUserJson
  },
  {
    path   : '/api/me',
    method : 'GET',
    issue  : '/api/me returns user data without authentication',
    severity: 'CRITICAL',
    validate: isExposedUserJson
  },
  {
    path   : '/api/register',
    method : 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body   : JSON.stringify({ name: 'test', email: 'probe@example.com', password: 'P@ssword1!' }),
    issue  : '/api/register accepts unauthenticated registration',
    severity: 'MEDIUM',
    validate: isOpenRegistrationJson
  },
  {
    path   : '/api/login',
    method : 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body   : JSON.stringify({ email: 'probe@example.com', password: 'wrongpassword' }),
    issue  : '/api/login returned authenticated token (HTTP 200) on invalid credentials',
    severity: 'HIGH',
    validate: isOpenLoginBypassJson
  },
];

export default async function run(target, fetchWithRetry) {
  const findings = [];
  let networkSuccess = false;
  let lastError = null;

  for (const ep of ENDPOINTS) {
    try {
      const url = `${target}${ep.path}`;
      const fetchOpts = {
        method : ep.method,
        headers: ep.headers ?? { 'Accept': 'application/json' },
        body   : ep.body ?? undefined,
        followRedirects: false
      };
      const res = await fetchWithRetry(url, fetchOpts);
      networkSuccess = true;

      if (isRedirectedToDifferentPath(res, url)) continue;
      const match = ep.validate(res);
      if (!match) continue;

      const { confirmed, res: confirmRes } = await confirmReproducible(
        url,
        fetchWithRetry,
        fetchOpts,
        (r) => !isRedirectedToDifferentPath(r, url) && Boolean(ep.validate(r))
      );
      if (!confirmed) continue;

      const rawSnippet = redactSecretsInText(String(match.snippet || '').replace(/[\r\n\t]+/g, ' ').trim().slice(0, 120));
      findings.push({
        issue        : ep.issue,
        path         : ep.path,
        url,
        method       : ep.method,
        status       : confirmRes?.status ?? res?.status,
        severity     : ep.severity,
        matchedSignal: match.matchedSignal,
        reproducible : true,
        preview      : rawSnippet,
        detail       : `${ep.issue} (confirmed HTTP ${confirmRes?.status ?? res?.status}, ${match.matchedSignal})`,
        ...(confirmRes?.trafficId ?? res?.trafficId !== undefined ? { trafficId: confirmRes?.trafficId ?? res?.trafficId } : {})
      });
    } catch (err) {
      lastError = err;
    }
  }

  if (!findings.length) {
    if (!networkSuccess && lastError) {
      return { name: 'laravel auth routes', status: 'ERROR', severity: 'LOW', reason: lastError.message };
    }
    return { name: 'laravel auth routes', status: 'SAFE', severity: 'NONE' };
  }

  const maxSev = findings.some(f => f.severity === 'CRITICAL') ? 'CRITICAL'
               : findings.some(f => f.severity === 'HIGH')     ? 'HIGH'
               : 'MEDIUM';
  const primary = findings[0];
  const evidenceQuotes = findings.map(f => f.preview).filter(q => typeof q === 'string' && q.length >= 8).slice(0, 5);

  return {
    name          : 'laravel auth routes',
    status        : 'VULNERABLE',
    severity      : maxSev,
    path          : primary.path,
    detail        : `Confirmed reproducible auth exposure: ${findings.map(f => `${f.method} ${f.path} (HTTP ${f.status})`).join(', ')}`,
    findings,
    files         : findings.map(f => ({
      path         : f.path,
      url          : f.url,
      method       : f.method,
      status       : f.status,
      severity     : f.severity,
      matchedSignal: f.matchedSignal,
      reproducible : true,
      preview      : f.preview
    })),
    reproVerified : true,
    poeLevel      : evidenceQuotes.length > 0 ? 3 : 2,
    ...(evidenceQuotes.length > 0 ? { evidenceQuotes } : {}),
    ...(primary.trafficId !== undefined ? { trafficId: primary.trafficId } : {}),
    fix           : 'Ensure all sensitive API routes (/api/user, /api/me) are protected by authentication middleware (e.g., Sanctum/Passport). Disable public user registration (/api/register) if not needed and apply strict rate limiting to auth endpoints.'
  };
}
