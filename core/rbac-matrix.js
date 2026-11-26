import pLimit from 'p-limit';
import { isLogoutOrDestructiveUrl } from './auth-session.js';

/**
 * Guardrail pattern matching logout, session-destruction, or destructive state-changing URLs
 * that must never be probed during RBAC / BFLA access-control matrix verification.
 */
export const DESTRUCTIVE_OR_LOGOUT_URL_RE =
  /(?:^|[\/?&_=-])(?:log[-_]?out|sign[-_]?out|log[-_]?off|kill[-_]?session|destroy[-_]?session|delete|remove|drop|truncate|purge|reset)(?:[\/?&#_=-]|$)/i;

const LOGIN_REDIRECT_RE =
  /(?:^|[\/?&_=-])(?:log[-_]?in|sign[-_]?in|auth|authenticate|sso|oauth|session|user\/login|site\/login|admin\/login|wp-login)(?:[\/?&#_=-]|$)/i;

const PASSWORD_INPUT_RE =
  /<input\b[^>]*\btype\s*=\s*["']?password["']?[^>]*>|LoginForm\[password\]|\bname\s*=\s*["']?(?:password|pass|passwd|user_pass|LoginForm\[password\])["']?/i;

const LOGIN_PROMPT_RE =
  /(?:please\s+(?:log\s*in|sign\s*in)|sign\s+in\s+to\s+start\s+your\s+session|authentication\s+required|you\s+must\s+be\s+logged\s+in|access\s+denied|unauthorized|forbidden|session\s+expired)/i;

const AUTH_DASHBOARD_MARKER_RE =
  /(?:log\s*out|sign\s*out|dashboard|my\s+account|admin\s+panel|welcome\s*,)/i;

const BADGE_BY_STATUS = Object.freeze({
  enforced: '🔒 Auth Enforced',
  bfla_unauthenticated: '🚨 Unprotected (BFLA)',
  bfla_low_privilege: '⚠️ Low-Priv Accessible',
  skipped: '⏭️ Skipped'
});

function getHeaderMap(headers) {
  const out = Object.create(null);
  if (!headers) return out;
  if (typeof headers.entries === 'function') {
    for (const [k, v] of headers.entries()) {
      out[String(k).toLowerCase()] = String(v ?? '');
    }
    return out;
  }
  if (typeof headers === 'object') {
    for (const [k, v] of Object.entries(headers)) {
      out[String(k).toLowerCase()] = Array.isArray(v) ? v.join('; ') : String(v ?? '');
    }
  }
  return out;
}

/**
 * Checks whether a URL or item descriptor matches a logout or destructive operation.
 *
 * @param {string} rawUrl
 * @param {object} [item={}]
 * @returns {boolean}
 */
export function isDestructiveOrLogoutEndpoint(rawUrl, item = {}) {
  if (!rawUrl || typeof rawUrl !== 'string') return true;
  if (item && (item.kind === 'logout' || item.kind === 'external_app')) {
    return true;
  }

  const label = String(item?.label || item?.formName || '').trim();
  const trigger = String(item?.trigger || '').trim();
  if (
    /^(?:log\s*out|sign\s*out|log\s*off)$/i.test(label) ||
    DESTRUCTIVE_OR_LOGOUT_URL_RE.test(trigger)
  ) {
    return true;
  }

  const candidate = rawUrl.trim();
  if (!candidate) return true;
  if (isLogoutOrDestructiveUrl(candidate) || DESTRUCTIVE_OR_LOGOUT_URL_RE.test(candidate)) {
    return true;
  }

  try {
    const decoded = decodeURIComponent(candidate);
    if (isLogoutOrDestructiveUrl(decoded) || DESTRUCTIVE_OR_LOGOUT_URL_RE.test(decoded)) {
      return true;
    }
  } catch {
    // Ignore malformed percent-encoding
  }

  try {
    const parsed = new URL(candidate);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return true;
    }
    const pathAndQuery = `${parsed.pathname || ''}${parsed.search || ''}`;
    if (isLogoutOrDestructiveUrl(pathAndQuery) || DESTRUCTIVE_OR_LOGOUT_URL_RE.test(pathAndQuery)) {
      return true;
    }
    try {
      const decodedPQ = decodeURIComponent(pathAndQuery);
      if (isLogoutOrDestructiveUrl(decodedPQ) || DESTRUCTIVE_OR_LOGOUT_URL_RE.test(decodedPQ)) {
        return true;
      }
    } catch {
      // Ignore malformed percent-encoding
    }
  } catch {
    return true;
  }

  return false;
}

function isAuthManagerSessionExpired(authManager, res) {
  if (!authManager || !res) return false;
  try {
    if (typeof authManager.isSessionExpired === 'function' && authManager.isSessionExpired(res)) {
      return true;
    }
    if (typeof authManager.isSessionExpiredResponse === 'function' && authManager.isSessionExpiredResponse(res)) {
      return true;
    }
  } catch {
    // Ignore session detector error
  }
  return false;
}

function isHtmlOrJsonContent(res, headersMap, bodyText) {
  const ct = String(headersMap['content-type'] || '').toLowerCase();
  const trimmed = String(bodyText || '').trim();
  if (!trimmed) return false;

  if (ct) {
    if (
      ct.includes('text/html') ||
      ct.includes('application/xhtml+xml') ||
      ct.includes('application/json') ||
      ct.includes('+json')
    ) {
      return true;
    }
    if (ct.includes('text/plain') && (/^[<{[]/.test(trimmed) || trimmed.length > 0)) {
      return true;
    }
    return false;
  }

  // Fallback when content-type header is omitted in lightweight mocks
  return trimmed.length > 0;
}

function isLoginPageOrPrompt(bodyText) {
  const text = String(bodyText || '').slice(0, 262144);
  if (!text.trim()) return false;
  if (PASSWORD_INPUT_RE.test(text)) {
    return true;
  }
  if (LOGIN_PROMPT_RE.test(text) && !AUTH_DASHBOARD_MARKER_RE.test(text)) {
    return true;
  }
  return false;
}

function classifyAccessProbeResponse(res, authManager) {
  if (!res || typeof res !== 'object' || res.isGovernanceBlock) {
    return { enforced: false, unprotected: false, status: null };
  }

  const status = Number(res.status ?? 0);
  if (!Number.isFinite(status) || status <= 0) {
    return { enforced: false, unprotected: false, status: null };
  }

  const headersMap = getHeaderMap(res.headers);
  const bodyText = typeof res.text === 'string' ? res.text : '';
  const sessionExpired = isAuthManagerSessionExpired(authManager, res);

  // Explicit auth rejection status codes or session-loss detector match
  if (status === 401 || status === 403 || status === 404 || sessionExpired) {
    return { enforced: true, unprotected: false, status };
  }

  // HTTP 3xx redirect (e.g. redirecting to login/auth URL or front-controller gate)
  if (status === 301 || status === 302 || status === 303 || status === 307 || status === 308) {
    const location = String(headersMap.location || '');
    if (!location || LOGIN_REDIRECT_RE.test(location) || status >= 300) {
      return { enforced: true, unprotected: false, status };
    }
  }

  if (status === 200) {
    if (isLoginPageOrPrompt(bodyText)) {
      return { enforced: true, unprotected: false, status };
    }
    if (isHtmlOrJsonContent(res, headersMap, bodyText) && !sessionExpired) {
      return { enforced: false, unprotected: true, status };
    }
  }

  return { enforced: true, unprotected: false, status };
}

function hasValidSecondaryAuthHeaders(secondaryAuthHeaders) {
  if (!secondaryAuthHeaders || typeof secondaryAuthHeaders !== 'object' || Array.isArray(secondaryAuthHeaders)) {
    return false;
  }
  return Object.entries(secondaryAuthHeaders).some(
    ([k, v]) => Boolean(k && typeof v === 'string' && v.trim())
  );
}

function extractUrlPath(rawUrl) {
  try {
    const u = new URL(rawUrl);
    return `${u.pathname || '/'}${u.search || ''}`;
  } catch {
    return String(rawUrl || '/');
  }
}

/**
 * Passively and safely audits discovered authenticated navigation menu items and HTML/SPA forms
 * for Broken Function Level Authorization (BFLA / CWE-285) by re-probing read-only GET endpoints
 * without session credentials (and optionally with low-privilege `secondaryAuthHeaders`).
 *
 * @param {{
 *   discoveredMenus?: Array<object>,
 *   discoveredForms?: Array<object>,
 *   unauthFetch?: Function,
 *   authManager?: object | null,
 *   secondaryAuthHeaders?: Record<string, string> | null,
 *   maxProbes?: number,
 *   concurrency?: number
 * }} [options={}]
 */
export async function auditMenuAndFormAccessControl(options = {}) {
  const {
    discoveredMenus = [],
    discoveredForms = [],
    unauthFetch = null,
    authManager = null,
    secondaryAuthHeaders = null,
    maxProbes = 12,
    concurrency = 3
  } = options || {};

  const menus = Array.isArray(discoveredMenus) ? discoveredMenus : [];
  const forms = Array.isArray(discoveredForms) ? discoveredForms : [];

  const effectiveMaxProbes = Number.isFinite(Number(maxProbes)) && Number(maxProbes) >= 0
    ? Math.floor(Number(maxProbes))
    : 12;
  const effectiveConcurrency = Number.isFinite(Number(concurrency)) && Number(concurrency) > 0
    ? Math.max(1, Math.min(10, Math.floor(Number(concurrency))))
    : 3;

  const probeUrls = [];
  const probeUrlSet = new Set();
  const itemBindings = [];

  const registerItem = (item, kindLabel) => {
    if (!item || typeof item !== 'object') return;
    const rawUrl = kindLabel === 'menu'
      ? String(item.url || '').trim()
      : String(item.actionUrl || item.pageUrl || '').trim();

    const isRestrictedByAuthMgr = Boolean(
      rawUrl &&
      authManager &&
      typeof authManager.isRestrictedUrl === 'function' &&
      authManager.isRestrictedUrl(rawUrl)
    );

    if (
      typeof unauthFetch !== 'function' ||
      !rawUrl ||
      isDestructiveOrLogoutEndpoint(rawUrl, item) ||
      isRestrictedByAuthMgr
    ) {
      item.accessControlStatus = 'skipped';
      item.accessControlBadge = BADGE_BY_STATUS.skipped;
      item.unauthStatus = null;
      return;
    }

    let normalizedUrl;
    try {
      const parsed = new URL(rawUrl);
      parsed.hash = '';
      normalizedUrl = parsed.toString();
    } catch {
      item.accessControlStatus = 'skipped';
      item.accessControlBadge = BADGE_BY_STATUS.skipped;
      item.unauthStatus = null;
      return;
    }

    if (!probeUrlSet.has(normalizedUrl)) {
      if (probeUrls.length >= effectiveMaxProbes) {
        item.accessControlStatus = 'skipped';
        item.accessControlBadge = BADGE_BY_STATUS.skipped;
        item.unauthStatus = null;
        return;
      }
      probeUrlSet.add(normalizedUrl);
      probeUrls.push(normalizedUrl);
    }

    itemBindings.push({ item, kindLabel, url: normalizedUrl });
  };

  for (const menu of menus) {
    registerItem(menu, 'menu');
  }
  for (const form of forms) {
    registerItem(form, 'form');
  }

  const probeResultsByUrl = new Map();
  const useSecondaryRole = hasValidSecondaryAuthHeaders(secondaryAuthHeaders);

  if (typeof unauthFetch === 'function' && probeUrls.length > 0) {
    const limit = pLimit(effectiveConcurrency);
    await Promise.all(
      probeUrls.map(url =>
        limit(async () => {
          try {
            const unauthRes = await unauthFetch(url, {
              method: 'GET',
              headers: { Cookie: '', Authorization: '' },
              followRedirects: false,
              redirect: 'manual'
            });

            const unauthEval = classifyAccessProbeResponse(unauthRes, authManager);
            if (unauthEval.status === null) {
              probeResultsByUrl.set(url, {
                accessControlStatus: 'skipped',
                unauthStatus: null,
                lowPrivStatus: null
              });
              return;
            }

            if (unauthEval.unprotected) {
              probeResultsByUrl.set(url, {
                accessControlStatus: 'bfla_unauthenticated',
                unauthStatus: unauthEval.status,
                lowPrivStatus: null
              });
              return;
            }

            // Endpoint enforced against unauthenticated access; optionally test low-privilege role
            if (useSecondaryRole) {
              try {
                const lowPrivRes = await unauthFetch(url, {
                  method: 'GET',
                  headers: { ...secondaryAuthHeaders },
                  followRedirects: false,
                  redirect: 'manual'
                });
                const lowPrivEval = classifyAccessProbeResponse(lowPrivRes, authManager);
                if (lowPrivEval.unprotected) {
                  probeResultsByUrl.set(url, {
                    accessControlStatus: 'bfla_low_privilege',
                    unauthStatus: unauthEval.status,
                    lowPrivStatus: lowPrivEval.status
                  });
                  return;
                }
              } catch {
                // Ignore secondary probe failure and keep enforced
              }
            }

            probeResultsByUrl.set(url, {
              accessControlStatus: 'enforced',
              unauthStatus: unauthEval.status,
              lowPrivStatus: null
            });
          } catch {
            probeResultsByUrl.set(url, {
              accessControlStatus: 'skipped',
              unauthStatus: null,
              lowPrivStatus: null
            });
          }
        })
      )
    );
  }

  const findings = [];
  const seenFindingKeys = new Set();

  for (const { item, kindLabel, url } of itemBindings) {
    const outcome = probeResultsByUrl.get(url) || {
      accessControlStatus: 'skipped',
      unauthStatus: null,
      lowPrivStatus: null
    };

    item.accessControlStatus = outcome.accessControlStatus;
    item.accessControlBadge = BADGE_BY_STATUS[outcome.accessControlStatus] || BADGE_BY_STATUS.skipped;
    item.unauthStatus = outcome.unauthStatus;
    if (outcome.lowPrivStatus !== null && outcome.lowPrivStatus !== undefined) {
      item.lowPrivStatus = outcome.lowPrivStatus;
    }

    if (
      outcome.accessControlStatus === 'bfla_unauthenticated' ||
      outcome.accessControlStatus === 'bfla_low_privilege'
    ) {
      const displayLabel = kindLabel === 'menu'
        ? `Menu "${item.parentMenu ? `${item.parentMenu} -> ` : ''}${item.label || url}"`
        : `Form "${item.formName || item.formId || url}"`;
      const pathStr = extractUrlPath(url);
      const findingKey = `${url}::${outcome.accessControlStatus}`;
      if (!seenFindingKeys.has(findingKey)) {
        seenFindingKeys.add(findingKey);
        const isLowPriv = outcome.accessControlStatus === 'bfla_low_privilege';
        findings.push({
          name: 'Broken Function Level Authorization (BFLA) on Menu/Form Endpoint',
          checkId: 'bola-mass-assignment',
          status: 'VULNERABLE',
          severity: 'HIGH',
          cwe: 'CWE-285',
          owasp: 'A01:2021-Broken Access Control',
          cvssScore: 8.6,
          accessControlStatus: outcome.accessControlStatus,
          path: pathStr,
          url,
          detail: isLowPriv
            ? `${displayLabel} (${pathStr}) blocks anonymous requests (HTTP ${outcome.unauthStatus}) but returns HTTP ${outcome.lowPrivStatus || 200} content to a low-privilege user session (vertical BFLA).`
            : `${displayLabel} (${pathStr}) was discovered during authenticated crawling but returned HTTP ${outcome.unauthStatus || 200} content when probed without session cookies or Authorization headers (unauthenticated BFLA).`,
          fix: 'Enforce server-side authentication and role-based access control (RBAC) middleware on all administrative menu views, SPA templates, and form action endpoints. Deny unauthenticated and unauthorized low-privilege requests with HTTP 401/403.'
        });
      }
    }
  }

  let enforcedCount = 0;
  let unauthenticatedBflaCount = 0;
  let lowPrivilegeBflaCount = 0;
  let skippedCount = 0;

  for (const item of [...menus, ...forms]) {
    if (!item || typeof item !== 'object') continue;
    switch (item.accessControlStatus) {
      case 'enforced':
        enforcedCount += 1;
        break;
      case 'bfla_unauthenticated':
        unauthenticatedBflaCount += 1;
        break;
      case 'bfla_low_privilege':
        lowPrivilegeBflaCount += 1;
        break;
      default:
        skippedCount += 1;
        break;
    }
  }

  const totalEvaluated = enforcedCount + unauthenticatedBflaCount + lowPrivilegeBflaCount;
  const status = (unauthenticatedBflaCount > 0 || lowPrivilegeBflaCount > 0)
    ? 'VULNERABLE'
    : 'SAFE';

  return {
    summary: {
      totalEvaluated,
      enforcedCount,
      unauthenticatedBflaCount,
      lowPrivilegeBflaCount,
      skippedCount,
      status
    },
    menuMatrix: menus,
    formMatrix: forms,
    findings
  };
}
