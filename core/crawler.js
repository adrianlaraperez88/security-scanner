import pLimit from 'p-limit';
import {
  DEFAULT_MAX_HTML_BYTES,
  filterSafeSameOriginApiRoutes,
  inspectApiCommunication,
  isSafeReadOnlyApiRoute,
  stripSensitiveQueryParamsForProbe
} from './api-discovery.js';
import { TaskQueue, LOGOUT_URL_RE } from './queue.js';
import { isCsrfFieldName, buildAuthenticatedSeedUrls } from './auth-session.js';
import { ACTIVE_FUZZING_CHECKS } from './profiles.js';

const FORBIDDEN_FIELD_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const IGNORED_INPUT_TYPES = new Set(['submit', 'button', 'reset', 'image', 'file']);
const DEFAULT_MAX_SCRIPT_BYTES = 512 * 1024;
const DESTRUCTIVE_ENDPOINT_RE = /(?:^|[\/?&_=-])(?:delete|remove|destroy|drop|truncate|purge|reset|logout|sign[-_]?out|log[-_]?off|kill)(?:[\/?&#_=-]|(?=[A-Z])|$)/i;
const AJAX_CONFIG_KEYS = new Set([
  'url', 'method', 'type', 'headers', 'timeout', 'data', 'params', 'body',
  'responsetype', 'withcredentials', 'cache', 'async', 'contenttype', 'datatype',
  'processdata', 'crossdomain', 'beforesend', 'success', 'error', 'complete',
  'signal', 'canceltoken', 'xsrfcookiename', 'xsrfheadername', 'transformrequest',
  'transformresponse', 'validateStatus', 'maxredirects'
]);
const JS_RESERVED_WORDS = new Set([
  'return', 'function', 'async', 'await', 'var', 'let', 'const', 'if', 'else',
  'for', 'while', 'do', 'switch', 'case', 'break', 'continue', 'try', 'catch',
  'finally', 'throw', 'new', 'typeof', 'instanceof', 'void', 'delete', 'in', 'of',
  'true', 'false', 'null', 'undefined', 'this', 'super', 'class', 'extends'
]);

const VENDOR_SCRIPT_NAME_RE = /(?:^|[\/_-])(?:jquery(?:-ui|\.mask|\.min|\.slim)?|bootstrap(?:\.bundle)?|angular(?:-sanitize|-route|-animate|-cookies|-touch|-resource|-messages|-aria|\.min)?|ng-(?:infinite-scroll|csv|table|file-upload)|textangular(?:-rangy|-sanitize)?|raphael(?:-min)?|morris(?:\.min)?|multiselectcomponent|lodash|moment|fontawesome|chart(?:\.min)?|d3(?:\.min)?|select2|sweetalert|toastr|datatables|popper|axios|vue|react(?:-dom)?|polyfills|vendor|runtime|manifest)(?:\.[a-z0-9_-]+)*\.m?js(?:[?#]|$)/i;

function decodeBasicHtmlEntities(value = '') {
  return String(value ?? '')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&quot;/gi, '"')
    .replace(/&#0*39;|&apos;/gi, "'")
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>');
}

function cleanTextLabel(rawHtml = '') {
  return decodeBasicHtmlEntities(
    String(rawHtml || '')
      .replace(/<!--[\s\S]*?-->/g, ' ')
      .replace(/<(?:i|svg|img)\b[^>]*>[\s\S]*?<\/(?:i|svg)>|<(?:i|img|br|hr)\b[^>]*\/?>/gi, ' ')
      .replace(/<[^>]*>/g, ' ')
  )
    .replace(/\s+/g, ' ')
    .trim();
}

function parseHtmlAttributes(attrText = '') {
  const attrs = Object.create(null);
  const attrRe = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*(?:=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  let m;
  while ((m = attrRe.exec(attrText)) !== null) {
    const key = m[1].toLowerCase();
    if (FORBIDDEN_FIELD_KEYS.has(key)) continue;
    const rawVal = m[2] ?? m[3] ?? m[4] ?? '';
    attrs[key] = decodeBasicHtmlEntities(rawVal);
  }
  return attrs;
}

export function getSampleFieldValue(field) {
  const existing = typeof field?.value === 'string' ? field.value.trim() : '';
  if (existing) return existing;
  const name = String(field?.name || '');
  const type = String(field?.type || '').toLowerCase();
  if (type === 'number' || /id|num|count|page|status|type/i.test(name)) {
    return '1';
  }
  if (type === 'email') {
    return 'test@example.com';
  }
  return 'test';
}

/**
 * Infers the application base directory (e.g. `/broadbandAdmin/` or `/`) from inline
 * config (`environment = { baseUrl: '/broadbandAdmin/' }`), `<base href="...">`, or the page URL.
 *
 * @param {string} html
 * @param {URL} baseObj
 * @returns {string}
 */
export function inferAppBasePath(html = '', baseObj = null) {
  if (typeof html === 'string' && html) {
    const baseTagMatch = html.match(/<base\b[^>]*\bhref\s*=\s*["']([^"']+)["']/i);
    if (baseTagMatch?.[1]) {
      try {
        const parsed = new URL(baseTagMatch[1], baseObj || 'http://localhost');
        if (!baseObj || parsed.origin === baseObj.origin) {
          const p = parsed.pathname || '/';
          return p.endsWith('/') ? p : `${p}/`;
        }
      } catch {}
    }

    const envBaseMatch =
      html.match(/\bbaseUrl\s*:\s*["'](\/[a-zA-Z0-9_.\-\/]*?)["']/i) ||
      html.match(/\badminPath\s*=\s*["'](\/[a-zA-Z0-9_.\-\/]*?)["']/i);
    if (envBaseMatch?.[1]) {
      const p = envBaseMatch[1].trim();
      return p.endsWith('/') ? p : `${p}/`;
    }
  }

  const pathname = baseObj?.pathname || '/';
  const idxMatch = pathname.match(/^(\/[a-zA-Z0-9_.\-\/]+?)\/index(?:-test)?\.php(?:\/|$)/i);
  if (idxMatch?.[1]) {
    return `${idxMatch[1].replace(/\/+$/, '')}/`;
  }
  return '/';
}

function resolveSameOriginUrl(rawLink, baseObj, { allowLogout = false, appBasePath = null } = {}) {
  if (!baseObj) return null;
  const cleaned = decodeBasicHtmlEntities(rawLink).trim();
  if (!cleaned || cleaned.startsWith('#')) return null;
  if (/^(?:data|mailto|javascript|tel|blob|about):/i.test(cleaned)) return null;

  try {
    let resolveBase = baseObj.href;
    if (/^index\.php(?:[\/?#]|$)/i.test(cleaned)) {
      if (appBasePath && appBasePath.startsWith('/')) {
        const normPrefix = appBasePath.endsWith('/') ? appBasePath : `${appBasePath}/`;
        resolveBase = `${baseObj.origin}${normPrefix}index.php`;
      } else if (/\/index\.php\//i.test(baseObj.pathname || '')) {
        const idx = baseObj.pathname.toLowerCase().indexOf('/index.php/');
        if (idx !== -1) {
          resolveBase = `${baseObj.origin}${baseObj.pathname.slice(0, idx + '/index.php'.length)}`;
        }
      }
    }
    const resolvedObj = new URL(cleaned, resolveBase);
    resolvedObj.hash = '';
    if (!['http:', 'https:'].includes(resolvedObj.protocol)) return null;
    if (resolvedObj.origin !== baseObj.origin) return null;
    if (!allowLogout && LOGOUT_URL_RE.test((resolvedObj.pathname || '') + (resolvedObj.search || ''))) {
      return null;
    }
    return resolvedObj.href;
  } catch {
    return null;
  }
}

function extractSelectDefaultValue(selectInnerHtml = '') {
  const optionRe = /<option\b([^>]*)>([\s\S]*?)<\/option>/gi;
  let firstVal = '';
  let m;
  while ((m = optionRe.exec(selectInnerHtml)) !== null) {
    const attrs = parseHtmlAttributes(m[1]);
    const textVal = decodeBasicHtmlEntities(String(m[2] || '').replace(/<[^>]*>/g, '').trim());
    const val = attrs.value !== undefined ? attrs.value : textVal;
    if ('selected' in attrs && val) {
      return val;
    }
    if (!firstVal && val) {
      firstVal = val;
    }
  }
  return firstVal;
}

/**
 * Parses AngularJS `$routeProvider.when(...)`, UI-Router `$stateProvider.state(...)`,
 * and front-controller (`index.php/<controller>/<action>`) routes from inline or external JS text.
 *
 * @param {string} scriptText
 * @param {string} pageUrl
 * @param {string} [explicitAppBasePath]
 * @returns {{ routeMap: Map<string, { routeKey: string, routePath: string, templateUrl: string, controller: string }>, links: string[] }}
 */
export function parseSpaRoutesFromScript(scriptText = '', pageUrl = '', explicitAppBasePath = '') {
  const routeMap = new Map();
  const linksSet = new Set();
  if (typeof scriptText !== 'string' || !scriptText || !pageUrl) {
    return { routeMap, links: [] };
  }

  let baseObj;
  try {
    baseObj = new URL(pageUrl);
  } catch {
    return { routeMap, links: [] };
  }

  const appBasePath = explicitAppBasePath || inferAppBasePath(scriptText, baseObj);
  const normBase = appBasePath.endsWith('/') ? appBasePath : `${appBasePath}/`;

  // Strip JS comments so commented-out routes or dead code are not extracted
  const uncommented = scriptText
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:\\])\/\/[^\r\n]*/g, '$1 ');

  const resolveScriptPath = (rawPath) => {
    const cleaned = String(rawPath || '').trim().replace(/^['"]+|['"]+$/g, '');
    if (!cleaned) return null;
    if (/^https?:\/\//i.test(cleaned)) {
      return resolveSameOriginUrl(cleaned, baseObj, { appBasePath: normBase });
    }
    const rel = cleaned.startsWith('/') ? cleaned : `${normBase}${cleaned}`;
    return resolveSameOriginUrl(rel, baseObj, { appBasePath: normBase });
  };

  // 1. Parse AngularJS $routeProvider.when('/slug', { templateUrl: ..., controller: ... })
  const whenRe = /\.\s*when\(\s*["']([^"']{1,128})["']\s*,\s*\{([\s\S]{1,800}?)\}\s*\)/g;
  let m;
  while ((m = whenRe.exec(uncommented)) !== null) {
    const rawRoute = m[1].trim();
    const cfgBody = m[2] || '';
    const routeKey = rawRoute.replace(/^\/+/, '');
    if (!routeKey) continue;

    const tplMatch = cfgBody.match(/\btemplateUrl\s*:\s*(?:[a-zA-Z0-9_.$]+\s*\+\s*)?["']([^"']{1,256})["']/);
    const ctrlMatch = cfgBody.match(/\bcontroller\s*:\s*["']([^"']{1,128})["']/);
    const rawTpl = tplMatch?.[1] ? tplMatch[1].trim() : '';
    const controller = ctrlMatch?.[1] ? ctrlMatch[1].trim() : '';
    const resolvedTpl = rawTpl ? resolveScriptPath(rawTpl) : null;

    if (resolvedTpl) {
      linksSet.add(resolvedTpl);
      const entry = {
        routeKey,
        routePath: rawRoute.startsWith('/') ? rawRoute : `/${rawRoute}`,
        templateUrl: resolvedTpl,
        controller
      };
      routeMap.set(routeKey, entry);
      routeMap.set(routeKey.toLowerCase(), entry);
      routeMap.set(entry.routePath, entry);
      routeMap.set(entry.routePath.toLowerCase(), entry);
    }
  }

  // 2. Parse UI-Router $stateProvider.state('name', { url: '...', templateUrl: '...' })
  const stateRe = /\.\s*state\(\s*["']([^"']{1,128})["']\s*,\s*\{([\s\S]{1,800}?)\}\s*\)/g;
  while ((m = stateRe.exec(uncommented)) !== null) {
    const stateName = m[1].trim();
    const cfgBody = m[2] || '';
    const urlMatch = cfgBody.match(/\burl\s*:\s*["']([^"']{1,128})["']/);
    const tplMatch = cfgBody.match(/\btemplateUrl\s*:\s*(?:[a-zA-Z0-9_.$]+\s*\+\s*)?["']([^"']{1,256})["']/);
    const ctrlMatch = cfgBody.match(/\bcontroller\s*:\s*["']([^"']{1,128})["']/);
    const rawTpl = tplMatch?.[1] ? tplMatch[1].trim() : '';
    const resolvedTpl = rawTpl ? resolveScriptPath(rawTpl) : null;
    if (resolvedTpl) {
      linksSet.add(resolvedTpl);
      const routeKey = (urlMatch?.[1] || stateName).replace(/^\/+/, '');
      const entry = {
        routeKey,
        routePath: `/${routeKey}`,
        templateUrl: resolvedTpl,
        controller: ctrlMatch?.[1] ? ctrlMatch[1].trim() : ''
      };
      routeMap.set(stateName, entry);
      routeMap.set(stateName.toLowerCase(), entry);
      if (routeKey) {
        routeMap.set(routeKey, entry);
        routeMap.set(routeKey.toLowerCase(), entry);
      }
    }
  }

  // 3. Extract front-controller routes (index.php/controller/action or ?r=controller/action) in JS services/controllers
  const fcScriptRe = /["']((?:\/[a-zA-Z0-9_.-]+)*\/?index\.php(?:\/[a-zA-Z0-9_\/-]+|\?r=[a-zA-Z0-9_\/-]+)[^"'<>\\\s#]*)["']/gi;
  while ((m = fcScriptRe.exec(uncommented)) !== null) {
    const candidate = m[1];
    if (!candidate) continue;
    const cleaned = candidate.replace(/\/+$/, '');
    if (/index\.php$/i.test(cleaned)) continue;
    const resolved = resolveScriptPath(cleaned);
    if (resolved) {
      linksSet.add(resolved);
    }
  }

  // 4. Parse Laravel Wayfinder / Inertia.js route definitions: <Ident>.definition={methods:[...],url:"/..."}
  const wayfinderByIdent = new Map();
  const wayfinderDefRe = /\b([A-Za-z0-9_$]{1,32})\.definition\s*=\s*\{\s*methods\s*:\s*\[([^\]]{1,200})\]\s*,\s*url\s*:\s*["'`]([^"'`]{1,256})["'`]\s*\}/g;
  while ((m = wayfinderDefRe.exec(uncommented)) !== null) {
    const ident = m[1].trim();
    const methodsRaw = m[2] || '';
    const rawUrl = m[3].trim();
    if (!ident || !rawUrl || !rawUrl.startsWith('/')) continue;

    // Skip template routes containing required or locale parameters (e.g. /{locale?}/..., /api/em/{symbol})
    if (rawUrl.includes('{') || rawUrl.includes('}')) continue;

    const methods = [...methodsRaw.matchAll(/["'`]([a-zA-Z]+)["'`]/g)].map(mm => mm[1].toLowerCase());
    const isLogoutRoute = LOGOUT_URL_RE.test(rawUrl);
    const resolvedUrl = resolveSameOriginUrl(rawUrl, baseObj, { allowLogout: true, appBasePath: normBase });
    if (!resolvedUrl) continue;

    wayfinderByIdent.set(ident, {
      ident,
      methods,
      rawUrl,
      resolvedUrl,
      isLogoutRoute
    });

    const isLoginEndpoint = /^\/(?:login|signin|sign-in)(?:\/|$)/i.test(rawUrl);
    if (!isLogoutRoute && !isLoginEndpoint && methods.includes('get') && rawUrl !== '/' && !rawUrl.endsWith('.txt')) {
      linksSet.add(resolvedUrl);
      const routeKey = rawUrl.replace(/^\/+/, '');
      if (routeKey && !rawUrl.startsWith('/api/')) {
        const prettyLabel = routeKey
          .split('/')
          .filter(Boolean)
          .map(seg => seg.replace(/[-_]+/g, ' ').replace(/\b[a-z]/g, c => c.toUpperCase()))
          .join(' / ');
        const entry = {
          routeKey,
          routePath: rawUrl,
          templateUrl: resolvedUrl,
          controller: `Wayfinder (${ident})`,
          parentMenu: 'SPA Router (Wayfinder / Inertia)',
          label: prettyLabel || routeKey,
          kind: 'spa_route',
          trigger: `Wayfinder(${ident}): ${rawUrl}`
        };
        routeMap.set(routeKey, entry);
        routeMap.set(routeKey.toLowerCase(), entry);
        routeMap.set(rawUrl, entry);
        routeMap.set(rawUrl.toLowerCase(), entry);
      }
    }
  }

  // 5. Parse Vue / React / Inertia Sidebar & Dropdown Submenu structures ({ title: "...", href: ..., items: [...] })
  const jsMenus = [];
  const seenJsMenuKeys = new Set();
  const resolveJsHrefExpr = (rawExpr = '') => {
    const expr = String(rawExpr || '').trim();
    if (!expr) return null;

    // Quoted URL string: '/zero-dte/live' or 'https://github.com/...'
    const strMatch = expr.match(/^["'`]([^"'`]+)["'`]$/);
    if (strMatch?.[1]) {
      const lit = strMatch[1].trim();
      if (/^https?:\/\//i.test(lit)) {
        try {
          const u = new URL(lit);
          if (u.origin !== baseObj.origin) {
            return {
              resolvedUrl: u.href,
              routePath: u.pathname,
              controller: null,
              trigger: `href: ${u.href}`,
              isExternalOrigin: true,
              isLogout: false
            };
          }
        } catch {}
      }
      const resolved = resolveSameOriginUrl(lit, baseObj, { allowLogout: true, appBasePath: normBase });
      if (!resolved) return null;
      return {
        resolvedUrl: resolved,
        routePath: lit,
        controller: null,
        trigger: `href: ${lit}`,
        isExternalOrigin: false,
        isLogout: LOGOUT_URL_RE.test(lit)
      };
    }

    // Wayfinder function call: G(), J(), Y(), kc(), Mc(), q(), cc() or Vue unref E(q)(), E(cc)()
    const callMatch = expr.match(/^(?:[A-Za-z0-9_$]+\s*\(\s*)?([A-Za-z0-9_$]{1,32})\s*\)?\s*\(\s*\)/);
    if (callMatch?.[1] && wayfinderByIdent.has(callMatch[1])) {
      const wf = wayfinderByIdent.get(callMatch[1]);
      return {
        resolvedUrl: wf.resolvedUrl,
        routePath: wf.rawUrl,
        controller: `Wayfinder (${wf.ident})`,
        trigger: `${wf.ident}() -> ${wf.rawUrl}`,
        isExternalOrigin: false,
        isLogout: wf.isLogoutRoute
      };
    }
    return null;
  };

  const pushJsMenu = ({ parentMenu, label, kind, hrefInfo }) => {
    if (!label || !hrefInfo?.resolvedUrl) return;
    const effectiveKind = hrefInfo.isLogout
      ? 'logout'
      : hrefInfo.isExternalOrigin
        ? 'external_app'
        : (kind || 'menu');
    const key = `${(parentMenu || 'App Sidebar').toLowerCase()}::${label.toLowerCase()}::${hrefInfo.resolvedUrl.toLowerCase()}`;
    if (seenJsMenuKeys.has(key)) return;
    seenJsMenuKeys.add(key);

    if (effectiveKind !== 'logout' && effectiveKind !== 'external_app') {
      linksSet.add(hrefInfo.resolvedUrl);
    }

    // Remove redundant generic SPA Router entry when covered by an explicit sidebar menu or submenu
    if (hrefInfo.routePath) {
      const cleanK = hrefInfo.routePath.replace(/^\/+/, '');
      if (effectiveKind === 'menu' || effectiveKind === 'submenu') {
        routeMap.delete(cleanK);
        routeMap.delete(cleanK.toLowerCase());
        routeMap.delete(hrefInfo.routePath);
        routeMap.delete(hrefInfo.routePath.toLowerCase());
      }
    }

    jsMenus.push({
      parentMenu: parentMenu || 'App Sidebar',
      label,
      kind: effectiveKind,
      trigger: hrefInfo.trigger,
      routeKey: hrefInfo.routePath ? hrefInfo.routePath.replace(/^\/+/, '') : null,
      controller: hrefInfo.controller || null,
      url: hrefInfo.resolvedUrl,
      pageUrl: baseObj.href
    });
  };

  const consumedSubmenuSpans = [];
  const parentWithItemsRe = /\{\s*title\s*:\s*["'`]([^"'`]{1,80})["'`]\s*,\s*href\s*:\s*([^,}]{1,120})(?:,[^{}\[\]]*)?,\s*items\s*:\s*\[([^\]]{1,2000})\]\s*\}/g;
  while ((m = parentWithItemsRe.exec(uncommented)) !== null) {
    consumedSubmenuSpans.push([m.index, m.index + m[0].length]);
    const parentTitle = m[1].trim();
    const parentHref = resolveJsHrefExpr(m[2]);
    const itemsBlock = m[3] || '';
    if (parentHref) {
      pushJsMenu({
        parentMenu: 'App Sidebar',
        label: parentTitle,
        kind: 'menu',
        hrefInfo: parentHref
      });
    }
    const childItemRe = /\{\s*title\s*:\s*["'`]([^"'`]{1,80})["'`]\s*,\s*href\s*:\s*([^,}]{1,120})\s*\}/g;
    let cm;
    while ((cm = childItemRe.exec(itemsBlock)) !== null) {
      const childTitle = cm[1].trim();
      const childHref = resolveJsHrefExpr(cm[2]);
      if (childHref) {
        pushJsMenu({
          parentMenu: parentTitle,
          label: childTitle,
          kind: 'submenu',
          hrefInfo: childHref
        });
      }
    }
  }

  const singleNavItemRe = /\{\s*title\s*:\s*["'`]([^"'`]{1,80})["'`]\s*,\s*href\s*:\s*([^,}]{1,160})(?:,[^{}\[\]]*)?\}/g;
  while ((m = singleNavItemRe.exec(uncommented)) !== null) {
    const idx = m.index;
    if (consumedSubmenuSpans.some(([s, e]) => idx >= s && idx < e)) continue;
    // Skip Inertia layout breadcrumbs ({ layout: { breadcrumbs: [{ title: ..., href: ... }] } })
    const prefixSlice = uncommented.slice(Math.max(0, idx - 40), idx);
    if (/breadcrumbs\s*:\s*\[\s*$/i.test(prefixSlice)) continue;

    const itemTitle = m[1].trim();
    const itemHref = resolveJsHrefExpr(m[2]);
    if (itemHref) {
      pushJsMenu({
        parentMenu: 'App Sidebar',
        label: itemTitle,
        kind: 'menu',
        hrefInfo: itemHref
      });
    }
  }

  // Also include Wayfinder logout route in menus if present
  for (const wf of wayfinderByIdent.values()) {
    if (wf.isLogoutRoute) {
      pushJsMenu({
        parentMenu: 'Account Menu',
        label: 'Log out',
        kind: 'logout',
        hrefInfo: {
          resolvedUrl: wf.resolvedUrl,
          routePath: wf.rawUrl,
          controller: `Wayfinder (${wf.ident})`,
          trigger: `${wf.ident}() -> ${wf.rawUrl}`,
          isExternalOrigin: false,
          isLogout: true
        }
      });
    }
  }

  return {
    routeMap,
    links: [...linksSet],
    menus: jsMenus
  };
}

function extractBalancedBlock(text, openIdx, openChar = '{', closeChar = '}') {
  if (typeof text !== 'string' || openIdx < 0 || openIdx >= text.length || text[openIdx] !== openChar) {
    return null;
  }
  const maxEnd = Math.min(text.length, openIdx + 16384);
  let depth = 0;
  let quote = null;
  for (let i = openIdx; i < maxEnd; i++) {
    const ch = text[i];
    if (quote) {
      if (ch === '\\') {
        i++;
        continue;
      }
      if (ch === quote) {
        quote = null;
      }
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      quote = ch;
      continue;
    }
    if (ch === openChar) {
      depth++;
    } else if (ch === closeChar) {
      depth--;
      if (depth === 0) {
        return {
          content: text.slice(openIdx + 1, i),
          endIdx: i
        };
      }
    }
  }
  return null;
}

function splitTopLevelItems(innerText = '', delimiter = ',') {
  const items = [];
  if (typeof innerText !== 'string' || !innerText.trim()) return items;
  let braceDepth = 0;
  let bracketDepth = 0;
  let parenDepth = 0;
  let quote = null;
  let start = 0;

  for (let i = 0; i < innerText.length; i++) {
    const ch = innerText[i];
    if (quote) {
      if (ch === '\\') {
        i++;
        continue;
      }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      quote = ch;
      continue;
    }
    if (ch === '{') braceDepth++;
    else if (ch === '}') braceDepth = Math.max(0, braceDepth - 1);
    else if (ch === '[') bracketDepth++;
    else if (ch === ']') bracketDepth = Math.max(0, bracketDepth - 1);
    else if (ch === '(') parenDepth++;
    else if (ch === ')') parenDepth = Math.max(0, parenDepth - 1);
    else if (ch === delimiter && braceDepth === 0 && bracketDepth === 0 && parenDepth === 0) {
      items.push(innerText.slice(start, i).trim());
      start = i + 1;
    }
  }
  const tail = innerText.slice(start).trim();
  if (tail) items.push(tail);
  return items;
}

function isForbiddenFieldName(name) {
  const clean = String(name || '').trim();
  if (!clean) return true;
  return FORBIDDEN_FIELD_KEYS.has(clean) || FORBIDDEN_FIELD_KEYS.has(clean.toLowerCase());
}

function extractFieldsFromObjectLiteral(objInnerText = '', { excludeConfigKeys = false } = {}) {
  const entries = splitTopLevelItems(objInnerText, ',');
  const fields = [];
  const seen = new Set();

  for (const entry of entries) {
    if (!entry || entry.startsWith('...')) continue;
    const colonIdx = (() => {
      let quote = null;
      for (let i = 0; i < entry.length; i++) {
        const ch = entry[i];
        if (quote) {
          if (ch === '\\') {
            i++;
            continue;
          }
          if (ch === quote) quote = null;
          continue;
        }
        if (ch === '"' || ch === "'" || ch === '`') {
          quote = ch;
          continue;
        }
        if (ch === ':') return i;
        if (ch === '(' || ch === '{' || ch === '[') break;
      }
      return -1;
    })();

    let key = '';
    if (colonIdx !== -1) {
      const rawKey = entry.slice(0, colonIdx).trim();
      const keyMatch = rawKey.match(/^(?:["']([a-zA-Z_$][a-zA-Z0-9_$\-\[\].]{0,63})["']|([a-zA-Z_$][a-zA-Z0-9_$]{0,63}))$/);
      key = (keyMatch?.[1] || keyMatch?.[2] || '').trim();
    } else {
      const shortMatch = entry.match(/^([a-zA-Z_$][a-zA-Z0-9_$]{0,63})$/);
      if (shortMatch?.[1] && !JS_RESERVED_WORDS.has(shortMatch[1])) {
        key = shortMatch[1].trim();
      }
    }

    if (!key || isForbiddenFieldName(key) || seen.has(key)) continue;
    if (excludeConfigKeys && AJAX_CONFIG_KEYS.has(key.toLowerCase())) continue;
    seen.add(key);
    fields.push({ name: key, type: 'text', value: '' });
  }

  return fields;
}

function extractNamedSubObjectFields(containerInnerText = '', propNames = [], varFieldsMap = new Map()) {
  if (!containerInnerText || !Array.isArray(propNames) || propNames.length === 0) return [];
  const propPattern = propNames.map(p => p.replace(/[^a-zA-Z0-9_$]/g, '')).filter(Boolean).join('|');
  if (!propPattern) return [];
  const re = new RegExp(
    `(?:^|[,{\\s])(?:["']?(?:${propPattern})["']?)\\s*:\\s*(?:JSON\\.stringify\\s*\\(\\s*|\\$\\.param\\s*\\(\\s*|jQuery\\.param\\s*\\(\\s*|new\\s+URLSearchParams\\s*\\(\\s*)?(\\{|([a-zA-Z_$][a-zA-Z0-9_$]*))`,
    'i'
  );
  const m = re.exec(containerInnerText);
  if (!m) return [];
  if (m[1] === '{') {
    const braceIdx = m.index + m[0].lastIndexOf('{');
    const block = extractBalancedBlock(containerInnerText, braceIdx, '{', '}');
    if (block) {
      return extractFieldsFromObjectLiteral(block.content);
    }
  } else if (m[2] && varFieldsMap.has(m[2])) {
    return varFieldsMap.get(m[2]).map(f => ({ ...f }));
  }
  return [];
}

function extractFieldsFromArgExpression(argExpr = '', varFieldsMap = new Map(), { excludeConfigKeys = false } = {}) {
  const trimmed = String(argExpr || '').trim();
  if (!trimmed) return [];

  const braceIdx = trimmed.indexOf('{');
  if (braceIdx !== -1) {
    const prefix = trimmed.slice(0, braceIdx).trim();
    if (!prefix || /^(?:JSON\.stringify|(?:\$|jQuery)\.param|new\s+URLSearchParams|Object\.assign)\s*\($/i.test(prefix)) {
      const block = extractBalancedBlock(trimmed, braceIdx, '{', '}');
      if (block) {
        return extractFieldsFromObjectLiteral(block.content, { excludeConfigKeys });
      }
    }
  }

  const varMatch = trimmed.match(/^(?:JSON\.stringify\s*\(\s*|(?:\$|jQuery)\.param\s*\(\s*|new\s+URLSearchParams\s*\(\s*)?([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\)?$/);
  if (varMatch?.[1]) {
    const varName = varMatch[1];
    if (varFieldsMap.has(varName)) {
      return varFieldsMap.get(varName).map(f => ({ ...f }));
    }
  }

  return [];
}

/**
 * Extracts non-destructive AJAX/REST endpoint descriptors (`$http.post/put/patch/get`,
 * `axios.post/put/patch/get`, `fetch(url, { method, body })`, `$.ajax({ url, type/method, data })`)
 * from application scripts (`adminService.js`, `*Controller.js`, `app.js`).
 *
 * @param {string} [scriptText='']
 * @param {string} [pageUrl='']
 * @param {string} [explicitAppBasePath='']
 * @returns {Array<{
 *   formName: string,
 *   formId: string,
 *   formType: 'ajax_endpoint',
 *   contentType: 'json' | 'form' | 'query',
 *   pageUrl: string,
 *   actionUrl: string,
 *   method: string,
 *   fields: Array<{ name: string, type: string, value: string }>,
 *   hiddenFields: Record<string, string>,
 *   csrfField: null
 * }>}
 */
export function extractAjaxFormsFromScript(scriptText = '', pageUrl = '', explicitAppBasePath = '') {
  if (typeof scriptText !== 'string' || !scriptText || !pageUrl) return [];
  let baseObj;
  try {
    baseObj = new URL(pageUrl);
  } catch {
    return [];
  }
  if (!['http:', 'https:'].includes(baseObj.protocol)) return [];

  const appBasePath = explicitAppBasePath || inferAppBasePath(scriptText, baseObj);
  const normBase = appBasePath.endsWith('/') ? appBasePath : `${appBasePath}/`;

  const uncommented = scriptText
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:\\])\/\/[^\r\n]*/g, '$1 ');

  const resolveScriptPath = (rawPath) => {
    const cleaned = String(rawPath || '').trim().replace(/^['"`]+|['"`]+$/g, '');
    if (!cleaned) return null;
    if (/^https?:\/\//i.test(cleaned)) {
      return resolveSameOriginUrl(cleaned, baseObj, { appBasePath: normBase });
    }
    const rel = cleaned.startsWith('/') ? cleaned : `${normBase}${cleaned}`;
    return resolveSameOriginUrl(rel, baseObj, { appBasePath: normBase });
  };

  // 1. Collect local string variables and payload object variables
  const varStringMap = new Map();
  const varStrRe = /\b(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:([a-zA-Z_$][a-zA-Z0-9_.$]*)\s*\+\s*)?["']([^"'\r\n]{1,256})["']/g;
  let vm;
  while ((vm = varStrRe.exec(uncommented)) !== null) {
    const varName = vm[1];
    const prefixVar = vm[2] || '';
    const literal = vm[3] || '';
    if (!varName || !literal) continue;
    if (prefixVar && varStringMap.has(prefixVar)) {
      const p = varStringMap.get(prefixVar);
      varStringMap.set(varName, `${p.replace(/\/+$/, '')}/${literal.replace(/^\/+/, '')}`);
    } else {
      varStringMap.set(varName, literal);
    }
  }

  const varFieldsMap = new Map();
  const varObjRe = /\b(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*\{/g;
  while ((vm = varObjRe.exec(uncommented)) !== null) {
    const varName = vm[1];
    const openBraceIdx = vm.index + vm[0].length - 1;
    const block = extractBalancedBlock(uncommented, openBraceIdx, '{', '}');
    if (block) {
      const extracted = extractFieldsFromObjectLiteral(block.content);
      if (extracted.length > 0) {
        varFieldsMap.set(varName, extracted);
      }
    }
  }

  const propAssignRe = /\b([a-zA-Z_$][a-zA-Z0-9_$]*)\s*(?:\.\s*([a-zA-Z_$][a-zA-Z0-9_$]*)|\[\s*["']([a-zA-Z_$][a-zA-Z0-9_$\-\[\].]{1,63})["']\s*\])\s*=(?!=)/g;
  const ignoredAssignTargets = new Set(['this', '$scope', '$rootScope', 'window', 'document', 'location', 'module', 'exports', 'console']);
  while ((vm = propAssignRe.exec(uncommented)) !== null) {
    const objName = vm[1];
    const propName = (vm[2] || vm[3] || '').trim();
    if (!objName || ignoredAssignTargets.has(objName) || !propName || isForbiddenFieldName(propName)) continue;
    const list = varFieldsMap.get(objName) || [];
    if (!list.some(f => f.name === propName)) {
      list.push({ name: propName, type: 'text', value: '' });
      varFieldsMap.set(objName, list);
    }
  }

  const resolveUrlExpression = (rawExpr) => {
    const expr = String(rawExpr || '').trim();
    if (!expr) return { resolvedUrl: null, queryFields: [] };

    const queryFields = [];
    const seenQ = new Set();
    const qParamRe = /[?&]([a-zA-Z_$][a-zA-Z0-9_$\-\[\].]{0,63})=/g;
    let qm;
    while ((qm = qParamRe.exec(expr)) !== null) {
      const qName = qm[1];
      if (qName && !isForbiddenFieldName(qName) && !seenQ.has(qName)) {
        seenQ.add(qName);
        queryFields.push({ name: qName, type: 'text', value: '' });
      }
    }

    let candidatePath = '';
    if (/^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(expr)) {
      candidatePath = varStringMap.get(expr) || '';
    } else if (expr.startsWith('`') && expr.endsWith('`')) {
      const inner = expr.slice(1, -1);
      candidatePath = inner
        .replace(/^\$\{\s*([a-zA-Z_$][a-zA-Z0-9_.$]*)\s*\}/, (_m, vName) => varStringMap.get(vName) || '')
        .replace(/\$\{[^}]+\}/g, '1');
    } else {
      const parts = splitTopLevelItems(expr, '+');
      let built = '';
      for (let i = 0; i < parts.length; i++) {
        const part = parts[i].trim();
        const litMatch = part.match(/^["']([^"']*)["']$/);
        if (litMatch) {
          built += litMatch[1];
        } else if (i === 0 && varStringMap.has(part)) {
          built += varStringMap.get(part);
        } else if (i > 0 && /[=\/]$/.test(built)) {
          built += '1';
        }
      }
      candidatePath = built;
    }

    if (!candidatePath) return { resolvedUrl: null, queryFields };
    const resolvedUrl = resolveScriptPath(candidatePath);
    if (!resolvedUrl) return { resolvedUrl: null, queryFields };

    try {
      const parsed = new URL(resolvedUrl);
      const pathAndQuery = `${parsed.pathname || ''}${parsed.search || ''}`;
      if (DESTRUCTIVE_ENDPOINT_RE.test(pathAndQuery) || LOGOUT_URL_RE.test(pathAndQuery)) {
        return { resolvedUrl: null, queryFields };
      }
      for (const key of parsed.searchParams.keys()) {
        if (key && !isForbiddenFieldName(key) && !seenQ.has(key)) {
          seenQ.add(key);
          queryFields.push({ name: key, type: 'text', value: parsed.searchParams.get(key) || '' });
        }
      }
    } catch {
      return { resolvedUrl: null, queryFields };
    }

    return { resolvedUrl, queryFields };
  };

  const forms = [];
  const seenForms = new Set();

  const addAjaxForm = ({ index = 0, resolvedUrl, method, fields, queryFields = [], contentType = null }) => {
    if (!resolvedUrl) return;
    const upperMethod = String(method || 'GET').trim().toUpperCase();
    if (!['GET', 'POST', 'PUT', 'PATCH'].includes(upperMethod)) return;

    const mergedFields = [];
    const seenFieldNames = new Set();
    for (const f of [...(Array.isArray(fields) ? fields : []), ...(Array.isArray(queryFields) ? queryFields : [])]) {
      const name = String(f?.name || '').trim();
      if (!name || isForbiddenFieldName(name) || seenFieldNames.has(name)) continue;
      seenFieldNames.add(name);
      mergedFields.push({
        name,
        type: f?.type || 'text',
        value: typeof f?.value === 'string' ? f.value : ''
      });
    }

    if (mergedFields.length === 0) {
      if (upperMethod === 'GET') {
        return;
      }
      mergedFields.push({ name: 'id', type: 'text', value: '' });
    }

    let shortPath = '/';
    try {
      const u = new URL(resolvedUrl);
      const segs = (u.pathname || '/').split('/').filter(Boolean);
      shortPath = segs.slice(-2).join('/') || '/';
    } catch {}

    const effectiveContentType = contentType || (upperMethod === 'GET' ? 'query' : 'json');
    const dedupKey = `${upperMethod}::${resolvedUrl}::${mergedFields.map(f => f.name).join(',')}`;
    if (seenForms.has(dedupKey)) return;
    seenForms.add(dedupKey);

    forms.push({
      _order: index,
      formName: `AJAX ${upperMethod} (${shortPath})`,
      formId: '',
      formType: 'ajax_endpoint',
      contentType: effectiveContentType,
      pageUrl: baseObj.href,
      actionUrl: resolvedUrl,
      method: upperMethod,
      fields: mergedFields,
      hiddenFields: {},
      csrfField: null
    });
  };

  // 2. Match $http.post/put/patch/get, axios.post/put/patch/get, $.post/get, jQuery.post/get
  const dotCallRe = /(?:\$http|axios|http|\$|jQuery)\s*\.\s*(post|put|patch|get)\s*\(/gi;
  let cm;
  while ((cm = dotCallRe.exec(uncommented)) !== null) {
    const method = cm[1].toUpperCase();
    const openParenIdx = cm.index + cm[0].length - 1;
    const callBlock = extractBalancedBlock(uncommented, openParenIdx, '(', ')');
    if (!callBlock) continue;
    const args = splitTopLevelItems(callBlock.content, ',');
    if (args.length === 0) continue;

    const { resolvedUrl, queryFields } = resolveUrlExpression(args[0]);
    if (!resolvedUrl) continue;

    let fields = [];
    let contentType = method === 'GET' ? 'query' : 'json';
    if (args[1]) {
      if (method === 'GET') {
        fields = extractNamedSubObjectFields(args[1], ['params', 'data'], varFieldsMap);
        if (fields.length === 0) {
          fields = extractFieldsFromArgExpression(args[1], varFieldsMap, { excludeConfigKeys: true });
        }
      } else {
        if (/(?:\$|jQuery)\.param|new\s+URLSearchParams/i.test(args[1])) {
          contentType = 'form';
        }
        fields = extractFieldsFromArgExpression(args[1], varFieldsMap, { excludeConfigKeys: false });
        if (fields.length === 0) {
          fields = extractNamedSubObjectFields(args[1], ['data', 'params', 'body'], varFieldsMap);
        }
      }
    }
    if (args[2] && method !== 'GET') {
      if (/application\/x-www-form-urlencoded/i.test(args[2])) {
        contentType = 'form';
      }
      const extraParams = extractNamedSubObjectFields(args[2], ['params'], varFieldsMap);
      if (extraParams.length > 0) {
        fields.push(...extraParams);
      }
    }

    addAjaxForm({ index: cm.index, resolvedUrl, method, fields, queryFields, contentType });
  }

  // 3. Match $.ajax({...}), jQuery.ajax({...}), $http({...}), axios({...})
  const objCallRe = /(?:\$http|axios|(?:\$|jQuery)\s*\.\s*ajax)\s*\(\s*\{/g;
  while ((cm = objCallRe.exec(uncommented)) !== null) {
    const openBraceIdx = cm.index + cm[0].length - 1;
    const cfgBlock = extractBalancedBlock(uncommented, openBraceIdx, '{', '}');
    if (!cfgBlock) continue;

    const cfgEntries = splitTopLevelItems(cfgBlock.content, ',');
    let urlExpr = '';
    let method = '';
    let hasDataProp = false;
    let explicitContentType = null;

    for (const entry of cfgEntries) {
      const mProp = entry.match(/^["']?([a-zA-Z_$][a-zA-Z0-9_$]*)["']?\s*:\s*([\s\S]+)$/);
      if (!mProp) continue;
      const propKey = mProp[1].toLowerCase();
      const propVal = mProp[2].trim();
      if (propKey === 'url') {
        urlExpr = propVal;
      } else if (propKey === 'method' || propKey === 'type') {
        const mLit = propVal.match(/^["']([a-zA-Z]+)["']$/);
        if (mLit) method = mLit[1].toUpperCase();
      } else if (propKey === 'data' || propKey === 'body') {
        hasDataProp = true;
      } else if (propKey === 'contenttype' || propKey === 'headers') {
        if (/application\/x-www-form-urlencoded/i.test(propVal)) {
          explicitContentType = 'form';
        } else if (/application\/json/i.test(propVal)) {
          explicitContentType = 'json';
        }
      }
    }

    if (!urlExpr) continue;
    const effectiveMethod = method || (hasDataProp ? 'POST' : 'GET');
    if (!['GET', 'POST', 'PUT', 'PATCH'].includes(effectiveMethod)) continue;

    const { resolvedUrl, queryFields } = resolveUrlExpression(urlExpr);
    if (!resolvedUrl) continue;

    const isJqueryAjax = /(?:\$|jQuery)\s*\.\s*ajax/.test(cm[0]);
    const defaultCt = effectiveMethod === 'GET'
      ? 'query'
      : (explicitContentType || (isJqueryAjax && !/JSON\.stringify/i.test(cfgBlock.content) ? 'json' : 'json'));
    const fields = extractNamedSubObjectFields(cfgBlock.content, ['data', 'params', 'body'], varFieldsMap);

    addAjaxForm({
      index: cm.index,
      resolvedUrl,
      method: effectiveMethod,
      fields,
      queryFields,
      contentType: defaultCt
    });
  }

  // 4. Match fetch(url, { method, body })
  const fetchCallRe = /\b(?:window\.)?fetch\s*\(/g;
  while ((cm = fetchCallRe.exec(uncommented)) !== null) {
    const openParenIdx = cm.index + cm[0].length - 1;
    const callBlock = extractBalancedBlock(uncommented, openParenIdx, '(', ')');
    if (!callBlock) continue;
    const args = splitTopLevelItems(callBlock.content, ',');
    if (args.length === 0) continue;

    const { resolvedUrl, queryFields } = resolveUrlExpression(args[0]);
    if (!resolvedUrl) continue;

    let method = 'GET';
    let fields = [];
    let contentType = null;

    if (args[1]) {
      const mMethod = args[1].match(/\bmethod\s*:\s*["']([a-zA-Z]+)["']/i);
      if (mMethod?.[1]) {
        method = mMethod[1].toUpperCase();
      } else if (/\bbody\s*:/i.test(args[1])) {
        method = 'POST';
      }
      if (!['GET', 'POST', 'PUT', 'PATCH'].includes(method)) continue;

      if (/application\/x-www-form-urlencoded|new\s+URLSearchParams/i.test(args[1])) {
        contentType = 'form';
      }
      fields = extractNamedSubObjectFields(args[1], ['body', 'data', 'params'], varFieldsMap);
    }

    addAjaxForm({
      index: cm.index,
      resolvedUrl,
      method,
      fields,
      queryFields,
      contentType: contentType || (method === 'GET' ? 'query' : 'json')
    });
  }

  return forms
    .sort((a, b) => a._order - b._order)
    .map(({ _order, ...rest }) => rest);
}

function resolveOpenApiRef(spec, node, depth = 0) {
  if (!node || typeof node !== 'object' || depth > 6) return node;
  if (typeof node.$ref !== 'string' || !node.$ref.startsWith('#/')) return node;
  const parts = node.$ref.slice(2).split('/');
  let cur = spec;
  for (const rawPart of parts) {
    const part = rawPart.replace(/~1/g, '/').replace(/~0/g, '~');
    if (isForbiddenFieldName(part) || !cur || typeof cur !== 'object' || !Object.hasOwn(cur, part)) {
      return null;
    }
    cur = cur[part];
  }
  return resolveOpenApiRef(spec, cur, depth + 1);
}

function collectOpenApiSchemaProperties(spec, rawSchema, depth = 0) {
  const props = new Map();
  if (!rawSchema || typeof rawSchema !== 'object' || depth > 5) return props;
  const schema = resolveOpenApiRef(spec, rawSchema, depth);
  if (!schema || typeof schema !== 'object') return props;

  if (schema.properties && typeof schema.properties === 'object') {
    for (const [propName, propVal] of Object.entries(schema.properties)) {
      if (!propName || isForbiddenFieldName(propName)) continue;
      props.set(propName, resolveOpenApiRef(spec, propVal, depth + 1) || {});
    }
  }

  for (const combiner of ['allOf', 'oneOf', 'anyOf']) {
    if (Array.isArray(schema[combiner])) {
      for (const sub of schema[combiner]) {
        const subProps = collectOpenApiSchemaProperties(spec, sub, depth + 1);
        for (const [k, v] of subProps.entries()) {
          if (!props.has(k)) props.set(k, v);
        }
      }
    }
  }

  return props;
}

/**
 * Synthesizes active fuzzing form descriptors from an OpenAPI v3 or Swagger v2 specification.
 *
 * @param {object|string} openApiSpec
 * @param {string} baseUrl
 * @returns {Array<{
 *   formName: string,
 *   formId: string,
 *   formType: 'openapi_operation',
 *   contentType: 'json' | 'form' | 'query',
 *   pageUrl: string,
 *   actionUrl: string,
 *   method: string,
 *   fields: Array<{ name: string, type: string, value: string }>,
 *   hiddenFields: Record<string, string>,
 *   csrfField: null
 * }>}
 */
export function synthesizeFormsFromOpenApi(openApiSpec, baseUrl) {
  if (!openApiSpec || !baseUrl) return [];
  let spec = openApiSpec;
  if (typeof openApiSpec === 'string') {
    try {
      spec = JSON.parse(openApiSpec);
    } catch {
      return [];
    }
  }
  if (!spec || typeof spec !== 'object' || !spec.paths || typeof spec.paths !== 'object') {
    return [];
  }

  let baseObj;
  try {
    baseObj = new URL(baseUrl);
  } catch {
    return [];
  }
  if (!['http:', 'https:'].includes(baseObj.protocol)) return [];

  let apiBasePrefix = '';
  if (typeof spec.basePath === 'string' && spec.basePath.trim() && spec.basePath.trim() !== '/') {
    apiBasePrefix = spec.basePath.trim().replace(/\/+$/, '');
  } else if (Array.isArray(spec.servers) && typeof spec.servers[0]?.url === 'string') {
    const srvUrl = spec.servers[0].url.trim();
    if (srvUrl.startsWith('/')) {
      apiBasePrefix = srvUrl.replace(/\/+$/, '');
    } else if (/^https?:\/\//i.test(srvUrl)) {
      try {
        const srvObj = new URL(srvUrl);
        if (srvObj.origin === baseObj.origin && srvObj.pathname && srvObj.pathname !== '/') {
          apiBasePrefix = srvObj.pathname.replace(/\/+$/, '');
        }
      } catch {}
    }
  }

  const ALLOWED_METHODS = ['get', 'post', 'put', 'patch'];
  const forms = [];
  const seenKeys = new Set();

  for (const [rawPath, pathItem] of Object.entries(spec.paths)) {
    if (!rawPath || typeof pathItem !== 'object' || !pathItem) continue;
    if (DESTRUCTIVE_ENDPOINT_RE.test(rawPath) || LOGOUT_URL_RE.test(rawPath)) continue;

    const concretePath = rawPath.replace(/\{[^}]+\}/g, '1');
    const fullRelPath = apiBasePrefix && !concretePath.startsWith(apiBasePrefix)
      ? `${apiBasePrefix}${concretePath.startsWith('/') ? '' : '/'}${concretePath}`
      : concretePath;
    const resolvedActionUrl = resolveSameOriginUrl(fullRelPath, baseObj);
    if (!resolvedActionUrl) continue;

    const pathLevelParams = Array.isArray(pathItem.parameters) ? pathItem.parameters : [];

    for (const methodLower of ALLOWED_METHODS) {
      const op = pathItem[methodLower];
      if (!op || typeof op !== 'object') continue;
      if (op.operationId && DESTRUCTIVE_ENDPOINT_RE.test(String(op.operationId))) continue;

      const upperMethod = methodLower.toUpperCase();
      const fields = [];
      const seenFields = new Set();
      let hasJsonBody = false;
      let hasFormBody = false;

      const addField = (rawName, schemaOrParam = {}) => {
        const name = String(rawName || '').trim();
        if (!name || isForbiddenFieldName(name) || seenFields.has(name)) return;
        seenFields.add(name);

        const rawType = String(schemaOrParam?.type || schemaOrParam?.schema?.type || '').toLowerCase();
        const rawFormat = String(schemaOrParam?.format || schemaOrParam?.schema?.format || '').toLowerCase();
        const type = rawType === 'integer' || rawType === 'number'
          ? 'number'
          : rawFormat === 'email'
            ? 'email'
            : 'text';

        const rawDefault =
          schemaOrParam?.default ??
          schemaOrParam?.example ??
          schemaOrParam?.schema?.default ??
          schemaOrParam?.schema?.example ??
          (Array.isArray(schemaOrParam?.enum) ? schemaOrParam.enum[0] : undefined) ??
          (Array.isArray(schemaOrParam?.schema?.enum) ? schemaOrParam.schema.enum[0] : undefined);
        const value = (typeof rawDefault === 'string' || typeof rawDefault === 'number' || typeof rawDefault === 'boolean')
          ? String(rawDefault)
          : '';

        fields.push({ name, type, value });
      };

      const allParams = [
        ...pathLevelParams,
        ...(Array.isArray(op.parameters) ? op.parameters : [])
      ];

      for (const rawParam of allParams) {
        const param = resolveOpenApiRef(spec, rawParam);
        if (!param || typeof param !== 'object') continue;
        const loc = String(param.in || '').toLowerCase();
        if (loc === 'query') {
          addField(param.name, param);
        } else if (loc === 'formdata') {
          hasFormBody = true;
          addField(param.name, param);
        } else if (loc === 'body' && param.schema) {
          hasJsonBody = true;
          const bodyProps = collectOpenApiSchemaProperties(spec, param.schema);
          for (const [propName, propSchema] of bodyProps.entries()) {
            addField(propName, propSchema);
          }
        }
      }

      if (op.requestBody) {
        const reqBody = resolveOpenApiRef(spec, op.requestBody);
        const content = reqBody?.content && typeof reqBody.content === 'object' ? reqBody.content : {};
        for (const [mime, mediaObj] of Object.entries(content)) {
          if (!mediaObj || typeof mediaObj !== 'object') continue;
          const lowMime = mime.toLowerCase();
          if (lowMime.includes('json')) {
            hasJsonBody = true;
            const props = collectOpenApiSchemaProperties(spec, mediaObj.schema);
            for (const [propName, propSchema] of props.entries()) {
              addField(propName, propSchema);
            }
          } else if (lowMime.includes('x-www-form-urlencoded') || lowMime.includes('multipart/form-data')) {
            hasFormBody = true;
            const props = collectOpenApiSchemaProperties(spec, mediaObj.schema);
            for (const [propName, propSchema] of props.entries()) {
              addField(propName, propSchema);
            }
          }
        }
      }

      if (fields.length === 0) continue;

      const contentType = upperMethod === 'GET'
        ? 'query'
        : hasJsonBody
          ? 'json'
          : hasFormBody
            ? 'form'
            : 'json';

      const dedupKey = `${upperMethod}::${resolvedActionUrl}::${fields.map(f => f.name).join(',')}`;
      if (seenKeys.has(dedupKey)) continue;
      seenKeys.add(dedupKey);

      forms.push({
        formName: String(op.operationId || op.summary || `OpenAPI ${upperMethod} (${rawPath})`).trim(),
        formId: String(op.operationId || '').trim(),
        formType: 'openapi_operation',
        contentType,
        pageUrl: baseObj.href,
        actionUrl: resolvedActionUrl,
        method: upperMethod,
        fields,
        hiddenFields: {},
        csrfField: null
      });
    }
  }

  return forms;
}

function extractClickRouteKey(attrValue = '') {
  const raw = String(attrValue || '').trim();
  if (!raw) return null;
  // Matches selectPage('configuration', $event), go('orders'), navigate('/users'), etc.
  const fnMatch = raw.match(/\b(?:selectPage|openPage|loadPage|changePage|setPage|goTo|go|navigate|selectTab|setTab|openMenu|loadView)\s*\(\s*["']([^"']{1,128})["']/i);
  if (fnMatch?.[1]) {
    return fnMatch[1].trim();
  }
  const locMatch = raw.match(/(?:window\.)?location(?:\.href)?\s*=\s*["']([^"']{1,256})["']/i);
  if (locMatch?.[1]) {
    return locMatch[1].trim();
  }
  const pageAssignMatch = raw.match(/\bpage\s*=\s*["']([^"']{1,128})["']/i);
  if (pageAssignMatch?.[1]) {
    return pageAssignMatch[1].trim();
  }
  return null;
}

/**
 * Extracts structured navigation menus, dropdown submenus, and SPA route items from HTML.
 *
 * @param {string} html
 * @param {string} pageUrl
 * @param {{ routeMap?: Map<string, object>, appBasePath?: string }} [options={}]
 * @returns {Array<{
 *   parentMenu: string,
 *   label: string,
 *   kind: 'menu' | 'submenu' | 'spa_route' | 'external_app' | 'logout',
 *   trigger: string,
 *   routeKey: string | null,
 *   controller: string | null,
 *   url: string | null,
 *   pageUrl: string
 * }>}
 */
export function extractMenusFromHtml(html = '', pageUrl = '', options = {}) {
  if (typeof html !== 'string' || !html || !pageUrl) return [];
  let baseObj;
  try {
    baseObj = new URL(pageUrl);
  } catch {
    return [];
  }

  const appBasePath = options.appBasePath || inferAppBasePath(html, baseObj);
  const normBase = appBasePath.endsWith('/') ? appBasePath : `${appBasePath}/`;
  const routeMap = options.routeMap instanceof Map ? options.routeMap : new Map();

  // Strip HTML comments so commented-out dead menu items are not extracted
  const cleanHtml = html.replace(/<!--[\s\S]*?-->/g, '');

  const menus = [];
  const seenKeys = new Set();
  const seenTargetKeys = new Set();
  const matchedRouteKeys = new Set();

  const resolveMenuTarget = (attrs) => {
    const rawHref = (attrs.href || attrs['ng-href'] || attrs['data-href'] || attrs['data-url'] || '').trim();
    const ngClick = (attrs['ng-click'] || attrs.onclick || '').trim();
    const uiSref = (attrs['ui-sref'] || attrs.routerlink || attrs['ng-reflect-router-link'] || '').trim();

    let routeKey = extractClickRouteKey(ngClick) || (uiSref ? uiSref.replace(/^\//, '') : null);
    let trigger = '';
    let resolvedUrl = null;
    let controller = null;

    if (routeKey) {
      trigger = ngClick ? `ng-click: ${ngClick.replace(/\s+/g, ' ')}` : `route: ${routeKey}`;
      const cleanKey = routeKey.replace(/^\/+/, '');
      const mapped =
        routeMap.get(cleanKey) ||
        routeMap.get(cleanKey.toLowerCase()) ||
        routeMap.get(`/${cleanKey}`) ||
        routeMap.get(`/${cleanKey.toLowerCase()}`);
      if (mapped) {
        resolvedUrl = mapped.templateUrl;
        controller = mapped.controller || null;
        matchedRouteKeys.add(mapped.routeKey.toLowerCase());
      } else if (/^https?:\/\//i.test(routeKey) || routeKey.startsWith('/')) {
        resolvedUrl = resolveSameOriginUrl(routeKey, baseObj, { allowLogout: true, appBasePath: normBase });
      } else if (/\/index\.php(?:\/|\?|$)/i.test(baseObj.pathname || '') || normBase !== '/') {
        resolvedUrl = `${baseObj.origin}${normBase}index.php/${cleanKey}`;
      } else {
        resolvedUrl = `${baseObj.origin}/${cleanKey}`;
      }
    } else if (rawHref && rawHref !== '#' && !/^javascript:/i.test(rawHref)) {
      trigger = `href: ${rawHref}`;
      const cleanHrefKey = rawHref.replace(/^\/+/, '');
      const mapped =
        routeMap.get(rawHref) ||
        routeMap.get(rawHref.toLowerCase()) ||
        routeMap.get(cleanHrefKey) ||
        routeMap.get(cleanHrefKey.toLowerCase());
      if (mapped) {
        resolvedUrl = mapped.templateUrl;
        controller = mapped.controller || null;
        routeKey = mapped.routeKey;
        matchedRouteKeys.add(mapped.routeKey.toLowerCase());
      } else {
        resolvedUrl = resolveSameOriginUrl(rawHref, baseObj, { allowLogout: true, appBasePath: normBase });
      }
    }

    return {
      rawHref,
      ngClick,
      routeKey,
      trigger,
      resolvedUrl,
      controller
    };
  };

  const addMenuItem = ({ parentMenu, label, kind, trigger, routeKey, controller, url }) => {
    const cleanLabel = String(label || '').trim();
    if (!cleanLabel || cleanLabel.length > 120) return;
    if (!url && !routeKey && !trigger) return;

    let effectiveKind = kind || 'menu';
    if (LOGOUT_URL_RE.test(url || '') || LOGOUT_URL_RE.test(trigger || '') || /^log\s*out|sign\s*out$/i.test(cleanLabel)) {
      effectiveKind = 'logout';
    } else if (url && normBase !== '/') {
      try {
        const uObj = new URL(url);
        if (!uObj.pathname.toLowerCase().startsWith(normBase.toLowerCase())) {
          effectiveKind = 'external_app';
        }
      } catch {}
    }

    const targetKey = `${cleanLabel.toLowerCase()}::${(url || routeKey || trigger).toLowerCase()}`;
    const dedupKey = `${(parentMenu || 'Main Menu').toLowerCase()}::${targetKey}`;
    if (seenKeys.has(dedupKey) || (parentMenu === 'Page Actions' && seenTargetKeys.has(targetKey))) return;
    seenKeys.add(dedupKey);
    seenTargetKeys.add(targetKey);

    menus.push({
      parentMenu: parentMenu || 'Main Menu',
      label: cleanLabel,
      kind: effectiveKind,
      trigger: trigger || (url ? `href: ${url}` : ''),
      routeKey: routeKey || null,
      controller: controller || null,
      url: url || null,
      pageUrl: baseObj.href
    });
  };

  // Extract navigation regions (<nav>, <ul class="nav...">, <aside>)
  const navBlocks = [];
  const navTagRe = /<nav\b[^>]*>([\s\S]*?)<\/nav>|<aside\b[^>]*>([\s\S]*?)<\/aside>/gi;
  let nm;
  while ((nm = navTagRe.exec(cleanHtml)) !== null) {
    navBlocks.push(nm[1] || nm[2] || '');
  }
  if (navBlocks.length === 0) {
    const ulNavRe = /<ul\b[^>]*\bclass\s*=\s*["'][^"']*\b(?:nav|navbar-nav|menu|sidebar-menu|main-menu|metismenu)\b[^"']*["'][^>]*>([\s\S]*?)<\/ul>/gi;
    while ((nm = ulNavRe.exec(cleanHtml)) !== null) {
      navBlocks.push(nm[0]);
    }
  }

  for (const block of navBlocks) {
    const consumedRanges = [];

    // 1. Find dropdown / submenu groups: <a ...>Parent Label</a> ... <ul class="dropdown-menu|submenu...">...</ul>
    const dropdownGroupRe = /<a\b([^>]*)>((?:(?!<\/a>)[\s\S])*)<\/a>\s*<ul\b([^>]*\bclass\s*=\s*["'][^"']*\b(?:dropdown-menu|submenu|sub-menu|treeview-menu|nav-second-level)\b[^"']*["'][^>]*)>([\s\S]*?)<\/ul>/gi;
    let dm;
    while ((dm = dropdownGroupRe.exec(block)) !== null) {
      consumedRanges.push([dm.index, dm.index + dm[0].length]);
      const parentLabel = cleanTextLabel(dm[2]) || 'Dropdown Menu';
      const subMenuHtml = dm[4] || '';

      const subLinkRe = /<(a|button)\b([^>]*)>([\s\S]*?)<\/\1>/gi;
      let sm;
      while ((sm = subLinkRe.exec(subMenuHtml)) !== null) {
        const subAttrs = parseHtmlAttributes(sm[2] || '');
        const subLabel = cleanTextLabel(sm[3]);
        if (!subLabel) continue;
        const targetInfo = resolveMenuTarget(subAttrs);
        addMenuItem({
          parentMenu: parentLabel,
          label: subLabel,
          kind: 'submenu',
          trigger: targetInfo.trigger,
          routeKey: targetInfo.routeKey,
          controller: targetInfo.controller,
          url: targetInfo.resolvedUrl
        });
      }
    }

    // 2. Find top-level links outside dropdown groups
    const topLinkRe = /<(a|button)\b([^>]*)>([\s\S]*?)<\/\1>/gi;
    let tm;
    while ((tm = topLinkRe.exec(block)) !== null) {
      const idx = tm.index;
      if (consumedRanges.some(([s, e]) => idx >= s && idx < e)) continue;
      const attrs = parseHtmlAttributes(tm[2] || '');
      const cls = String(attrs.class || '').toLowerCase();
      const toggle = String(attrs['data-toggle'] || attrs['data-bs-toggle'] || '').toLowerCase();
      if (cls.includes('dropdown-toggle') || toggle === 'dropdown') continue;

      const label = cleanTextLabel(tm[3]);
      if (!label) continue;
      const targetInfo = resolveMenuTarget(attrs);
      addMenuItem({
        parentMenu: 'Main Menu',
        label,
        kind: 'menu',
        trigger: targetInfo.trigger,
        routeKey: targetInfo.routeKey,
        controller: targetInfo.controller,
        url: targetInfo.resolvedUrl
      });
    }
  }

  // 3. Also scan any ng-click="selectPage(...)" links outside <nav> if not already captured
  const standaloneNgClickRe = /<(a|button)\b([^>]*\bng-click\s*=\s*["'][^"']+["'][^>]*)>([\s\S]*?)<\/\1>/gi;
  let ngm;
  while ((ngm = standaloneNgClickRe.exec(cleanHtml)) !== null) {
    const attrs = parseHtmlAttributes(ngm[2] || '');
    const routeKey = extractClickRouteKey(attrs['ng-click'] || '');
    if (!routeKey) continue;
    const label = cleanTextLabel(ngm[3]) || routeKey;
    const targetInfo = resolveMenuTarget(attrs);
    addMenuItem({
      parentMenu: 'Page Actions',
      label,
      kind: 'menu',
      trigger: targetInfo.trigger,
      routeKey: targetInfo.routeKey,
      controller: targetInfo.controller,
      url: targetInfo.resolvedUrl
    });
  }

  // 4. Add any SPA $routeProvider routes from routeMap that were not linked in visible HTML menus
  const addedSpaRoutes = new Set();
  for (const entry of routeMap.values()) {
    if (!entry || !entry.routeKey || !entry.templateUrl) continue;
    const keyLower = entry.routeKey.toLowerCase();
    if (matchedRouteKeys.has(keyLower) || addedSpaRoutes.has(keyLower)) continue;
    addedSpaRoutes.add(keyLower);
    addMenuItem({
      parentMenu: entry.parentMenu || 'SPA Router ($routeProvider)',
      label: entry.label || entry.routeKey,
      kind: entry.kind || 'spa_route',
      trigger: entry.trigger || `$routeProvider.when('${entry.routePath}')`,
      routeKey: entry.routeKey,
      controller: entry.controller || null,
      url: entry.templateUrl
    });
  }

  return menus;
}

function deriveControlFieldName(attrs) {
  const rawName = (attrs.name || '').trim();
  if (rawName && !FORBIDDEN_FIELD_KEYS.has(rawName)) return rawName;

  const ngModel = (attrs['ng-model'] || attrs['v-model'] || attrs.formcontrolname || '').trim();
  if (ngModel) {
    const cleanModel = ngModel.replace(/^\$scope\./, '').trim();
    const parts = cleanModel.split('.').filter(Boolean);
    const shortName = parts.length > 1 ? parts[parts.length - 1] : cleanModel;
    if (shortName && !FORBIDDEN_FIELD_KEYS.has(shortName) && /^[a-zA-Z0-9_\-\[\].]+$/.test(shortName)) {
      return shortName;
    }
  }

  const rawId = (attrs.id || '').trim();
  if (rawId && !FORBIDDEN_FIELD_KEYS.has(rawId)) return rawId;
  return '';
}

function deriveFormDisplayName(formAttrs, formBody, actionUrl, pageUrl, index, precedingHtml = '') {
  const legendMatch =
    formBody.match(/<(?:legend|h[1-4])\b[^>]*>([\s\S]*?)<\/(?:legend|h[1-4])>/i) ||
    precedingHtml.match(/<h[1-4]\b[^>]*>([\s\S]*?)<\/h[1-4]>(?:(?!<h[1-4]\b)[\s\S])*$/i);
  if (legendMatch?.[1]) {
    const text = cleanTextLabel(legendMatch[1]);
    if (text && text.length <= 80) return text;
  }
  if (formAttrs.id) return formAttrs.id;
  if (formAttrs.name) return formAttrs.name;
  if (formAttrs['ng-submit']) return `ng-submit: ${formAttrs['ng-submit'].trim()}`;
  try {
    const u = new URL(actionUrl || pageUrl);
    const segs = (u.pathname || '/').split('/').filter(Boolean);
    const tail = segs.slice(-2).join('/') || '/';
    return `Form #${index + 1} (${tail})`;
  } catch {
    return `Form #${index + 1}`;
  }
}

/**
 * Extracts same-origin links, front-controller routes, navigation menus/submenus,
 * and HTML/SPA forms (with synthesized parameterized query URLs for active checks)
 * from an HTML document.
 *
 * @param {string} html
 * @param {string} pageUrl
 * @param {{ routeMap?: Map<string, object>, extraLinks?: string[], appBasePath?: string }} [options={}]
 * @returns {{
 *   links: string[],
 *   rawLinks: string[],
 *   menus: Array<object>,
 *   forms: Array<{
 *     formName: string,
 *     formId: string,
 *     formType: 'html_form' | 'spa_view_controls',
 *     pageUrl: string,
 *     actionUrl: string,
 *     method: string,
 *     fields: Array<{ name: string, type: string, value: string, ngModel?: string }>,
 *     hiddenFields: Record<string, string>,
 *     csrfField: string | null
 *   }>
 * }}
 */
export function extractLinksAndFormsFromHtml(html, pageUrl, options = {}) {
  if (typeof html !== 'string' || !html) {
    return { links: [], rawLinks: [], menus: [], forms: [] };
  }

  let baseObj = null;
  try {
    baseObj = new URL(pageUrl);
  } catch {
    return { links: [], rawLinks: [], menus: [], forms: [] };
  }
  if (!['http:', 'https:'].includes(baseObj.protocol)) {
    return { links: [], rawLinks: [], menus: [], forms: [] };
  }

  const appBasePath = options.appBasePath || inferAppBasePath(html, baseObj);
  const inlineRoutes = parseSpaRoutesFromScript(html, pageUrl, appBasePath);
  const mergedRouteMap = new Map(inlineRoutes.routeMap);
  if (options.routeMap instanceof Map) {
    for (const [k, v] of options.routeMap.entries()) {
      mergedRouteMap.set(k, v);
    }
  }

  const rawLinks = [];
  const rawSeen = new Set();
  const rawCandidates = [...inlineRoutes.links];
  if (Array.isArray(options.extraLinks)) {
    rawCandidates.push(...options.extraLinks);
  }

  // 1. Extract href, src, action, data-url, data-href attributes (preserving query strings, stripping #fragment)
  const attrRegex = /\b(?:href|src|action|data-url|data-href)\s*=\s*["']([^"'>\s#]+)(?:#[^"'>\s]*)?["']/gi;
  let match;
  while ((match = attrRegex.exec(html)) !== null) {
    if (match[1]) {
      const decoded = decodeBasicHtmlEntities(match[1]).trim();
      if (decoded && !/^(?:data|mailto|javascript|tel):/i.test(decoded)) {
        if (!rawSeen.has(decoded)) {
          rawSeen.add(decoded);
          rawLinks.push(decoded);
        }
        rawCandidates.push(decoded);
      }
    }
  }

  // 2. Extract quoted front-controller routes in HTML or inline scripts
  const fcAbsRegex = /["']((?:\/[a-zA-Z0-9_.-]+)*\/index\.php(?:\/[a-zA-Z0-9_\/-]+|\?r=[a-zA-Z0-9_\/-]+)[^"'<>\\\s#]*)["']/gi;
  while ((match = fcAbsRegex.exec(html)) !== null) {
    if (match[1]) rawCandidates.push(match[1]);
  }

  const fcRelRegex = /["'](index\.php(?:\/[a-zA-Z0-9_\/-]+|\?r=[a-zA-Z0-9_\/-]+)[^"'<>\\\s#]*)["']/gi;
  while ((match = fcRelRegex.exec(html)) !== null) {
    if (match[1]) rawCandidates.push(match[1]);
  }

  // 3. Extract structured menus & submenus (and resolve their ng-click / $routeProvider targets)
  const menus = extractMenusFromHtml(html, pageUrl, {
    routeMap: mergedRouteMap,
    appBasePath
  });
  for (const menuItem of menus) {
    if (menuItem.url && menuItem.kind !== 'logout' && menuItem.kind !== 'external_app') {
      rawCandidates.push(menuItem.url);
    }
  }

  const normAppBase = appBasePath.endsWith('/') ? appBasePath : `${appBasePath}/`;
  const cleanLinksSet = new Set();
  for (const raw of rawCandidates) {
    const cleanRaw = String(raw || '').trim();
    const mappedRoute =
      mergedRouteMap.get(cleanRaw) ||
      mergedRouteMap.get(cleanRaw.toLowerCase()) ||
      mergedRouteMap.get(cleanRaw.replace(/^\/+/, '')) ||
      mergedRouteMap.get(cleanRaw.replace(/^\/+/, '').toLowerCase());
    if (mappedRoute?.templateUrl) {
      cleanLinksSet.add(mappedRoute.templateUrl);
      continue;
    }

    const resolved = resolveSameOriginUrl(raw, baseObj, { appBasePath });
    if (resolved) {
      if (normAppBase !== '/') {
        try {
          const rObj = new URL(resolved);
          if (!rObj.pathname.toLowerCase().startsWith(normAppBase.toLowerCase())) {
            continue;
          }
        } catch {}
      }
      cleanLinksSet.add(resolved);
    }
  }

  // 4. Parse <form> blocks and synthesize parameterized URLs + form descriptors
  const cleanHtmlForForms = html.replace(/<!--[\s\S]*?-->/g, '');
  const forms = [];
  const formRanges = [];
  const formRegex = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let formMatch;
  while ((formMatch = formRegex.exec(cleanHtmlForForms)) !== null) {
    formRanges.push([formMatch.index, formMatch.index + formMatch[0].length]);
    const formAttrs = parseHtmlAttributes(formMatch[1] || '');
    const formBody = formMatch[2] || '';

    const rawAction = (formAttrs.action || '').trim();
    if (/^(?:data|mailto|javascript|tel):/i.test(rawAction)) {
      continue;
    }

    let actionUrl = null;
    if (!rawAction || rawAction === '#') {
      const pageClean = new URL(baseObj.href);
      pageClean.hash = '';
      if (!LOGOUT_URL_RE.test((pageClean.pathname || '') + (pageClean.search || ''))) {
        actionUrl = pageClean.href;
      }
    } else {
      actionUrl = resolveSameOriginUrl(rawAction, baseObj, { appBasePath });
    }
    if (!actionUrl) continue;

    const rawMethod = (formAttrs.method || (formAttrs['ng-submit'] ? 'POST' : 'GET')).trim().toUpperCase();
    const method = rawMethod === 'POST' ? 'POST' : 'GET';

    const hiddenFields = Object.create(null);
    const fields = [];
    const fieldIndexByName = new Map();

    const controlRegex = /<(textarea|select)\b([^>]*)>([\s\S]*?)<\/\1>|<input\b([^>]*)\/?>/gi;
    let ctrlMatch;
    while ((ctrlMatch = controlRegex.exec(formBody)) !== null) {
      const tag = ctrlMatch[1] ? ctrlMatch[1].toLowerCase() : 'input';
      const attrStr = ctrlMatch[1] ? ctrlMatch[2] : ctrlMatch[4];
      const innerHtml = ctrlMatch[1] ? (ctrlMatch[3] || '') : '';
      const attrs = parseHtmlAttributes(attrStr || '');

      const name = deriveControlFieldName(attrs);
      if (!name || FORBIDDEN_FIELD_KEYS.has(name)) continue;
      const ngModel = (attrs['ng-model'] || attrs['v-model'] || '').trim() || undefined;

      if (tag === 'input') {
        const type = (attrs.type || 'text').trim().toLowerCase();
        if (IGNORED_INPUT_TYPES.has(type)) continue;
        const value = attrs.value ?? '';
        if (type === 'hidden') {
          hiddenFields[name] = value;
        } else if (!fieldIndexByName.has(name)) {
          fieldIndexByName.set(name, fields.length);
          fields.push({ name, type, value, ...(ngModel ? { ngModel } : {}) });
        } else {
          const existingIdx = fieldIndexByName.get(name);
          if (!fields[existingIdx].value && value) {
            fields[existingIdx].value = value;
          }
        }
      } else if (tag === 'textarea') {
        const value = decodeBasicHtmlEntities(innerHtml.trim());
        if (!fieldIndexByName.has(name)) {
          fieldIndexByName.set(name, fields.length);
          fields.push({ name, type: 'textarea', value, ...(ngModel ? { ngModel } : {}) });
        }
      } else if (tag === 'select') {
        const value = extractSelectDefaultValue(innerHtml);
        if (!fieldIndexByName.has(name)) {
          fieldIndexByName.set(name, fields.length);
          fields.push({ name, type: 'select', value, ...(ngModel ? { ngModel } : {}) });
        }
      }
    }

    if (fields.length > 0) {
      cleanLinksSet.add(actionUrl);
      try {
        const synthUrlObj = new URL(actionUrl);
        for (const field of fields.slice(0, 12)) {
          synthUrlObj.searchParams.set(field.name, getSampleFieldValue(field));
        }
        cleanLinksSet.add(synthUrlObj.toString());
      } catch {
        // Ignore synthesis failure
      }

      const csrfField = Object.keys(hiddenFields).find(k => isCsrfFieldName(k)) || null;
      const formId = (formAttrs.id || formAttrs.name || '').trim();
      const precedingHtml = cleanHtmlForForms.slice(Math.max(0, formMatch.index - 300), formMatch.index);
      const formName = deriveFormDisplayName(formAttrs, formBody, actionUrl, baseObj.href, forms.length, precedingHtml);

      forms.push({
        formName,
        formId,
        formType: 'html_form',
        pageUrl: baseObj.href,
        actionUrl,
        method,
        fields,
        hiddenFields: { ...hiddenFields },
        csrfField
      });
    }
  }

  // 5. Also capture standalone SPA view controls (<input ng-model="..."> / <select> / <textarea>) outside <form> tags
  const standaloneFields = [];
  const standaloneSeen = new Set();
  const controlRegexAll = /<(textarea|select)\b([^>]*)>([\s\S]*?)<\/\1>|<input\b([^>]*)\/?>/gi;
  let sMatch;
  while ((sMatch = controlRegexAll.exec(cleanHtmlForForms)) !== null) {
    const idx = sMatch.index;
    if (formRanges.some(([s, e]) => idx >= s && idx < e)) continue;
    const tag = sMatch[1] ? sMatch[1].toLowerCase() : 'input';
    const attrStr = sMatch[1] ? sMatch[2] : sMatch[4];
    const innerHtml = sMatch[1] ? (sMatch[3] || '') : '';
    const attrs = parseHtmlAttributes(attrStr || '');

    if (tag === 'input') {
      const type = (attrs.type || 'text').trim().toLowerCase();
      if (IGNORED_INPUT_TYPES.has(type) || type === 'hidden') continue;
    }

    const name = deriveControlFieldName(attrs);
    if (!name || FORBIDDEN_FIELD_KEYS.has(name) || standaloneSeen.has(name)) continue;
    standaloneSeen.add(name);
    const ngModel = (attrs['ng-model'] || attrs['v-model'] || '').trim() || undefined;
    const type = tag === 'input' ? (attrs.type || 'text').trim().toLowerCase() : tag;
    const value = tag === 'select'
      ? extractSelectDefaultValue(innerHtml)
      : tag === 'textarea'
        ? decodeBasicHtmlEntities(innerHtml.trim())
        : (attrs.value ?? '');
    standaloneFields.push({ name, type, value, ...(ngModel ? { ngModel } : {}) });
  }

  if (standaloneFields.length > 0 && !LOGOUT_URL_RE.test((baseObj.pathname || '') + (baseObj.search || ''))) {
    try {
      const synthUrlObj = new URL(baseObj.href);
      synthUrlObj.hash = '';
      for (const field of standaloneFields.slice(0, 10)) {
        synthUrlObj.searchParams.set(field.name, getSampleFieldValue(field));
      }
      cleanLinksSet.add(synthUrlObj.toString());
    } catch {}

    const headingMatch = cleanHtmlForForms.match(/<h[1-4]\b[^>]*>([\s\S]*?)<\/h[1-4]>/i);
    const viewTitle = headingMatch?.[1] ? cleanTextLabel(headingMatch[1]) : '';
    const pathTail = (baseObj.pathname || '/').split('/').filter(Boolean).slice(-2).join('/') || '/';

    forms.push({
      formName: viewTitle ? `${viewTitle} (${pathTail})` : `View Controls (${pathTail})`,
      formId: '',
      formType: 'spa_view_controls',
      pageUrl: baseObj.href,
      actionUrl: baseObj.href,
      method: 'GET',
      fields: standaloneFields,
      hiddenFields: {},
      csrfField: null
    });
  }

  return {
    links: [...cleanLinksSet],
    rawLinks,
    menus,
    forms
  };
}

function extractAppScriptCandidates(html = '', baseObj = null) {
  if (typeof html !== 'string' || !html || !baseObj) return [];
  const scripts = [];
  const seen = new Set();

  const pushCandidate = (rawSrc) => {
    const cleaned = decodeBasicHtmlEntities(rawSrc || '').trim();
    if (!cleaned || /^(?:data|javascript):/i.test(cleaned)) return;
    let resolved;
    try {
      resolved = new URL(cleaned, baseObj.href);
    } catch {
      return;
    }
    if (resolved.origin !== baseObj.origin) return;
    if (!/\.m?js(?:[?#]|$)/i.test(resolved.pathname || '')) return;
    if (VENDOR_SCRIPT_NAME_RE.test(resolved.pathname || '')) return;
    if (seen.has(resolved.href)) return;
    seen.add(resolved.href);
    scripts.push(resolved.href);
  };

  const scriptSrcRe = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi;
  let m;
  while ((m = scriptSrcRe.exec(html)) !== null) {
    pushCandidate(m[1]);
  }

  const modulePreloadRe = /<link\b[^>]*\brel\s*=\s*["']modulepreload["'][^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*>|<link\b[^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*\brel\s*=\s*["']modulepreload["'][^>]*>/gi;
  while ((m = modulePreloadRe.exec(html)) !== null) {
    pushCandidate(m[1] || m[2]);
  }

  // Prioritize app.js / app-<hash>.js, wayfinder-<hash>.js, router, menuController, adminService first
  scripts.sort((a, b) => {
    const score = (u) => {
      const lower = u.toLowerCase();
      if (/(?:^|\/)(?:app|wayfinder|routes?|router|menucontroller|adminservice|main)(?:-[a-z0-9_-]{4,16})?\.m?js(?:[?#]|$)/i.test(lower)) return 0;
      if (/controller|service|dashboard|sidebar|nav/i.test(lower)) return 1;
      return 2;
    };
    return score(a) - score(b);
  });

  return scripts;
}

/**
 * Lightweight link, menu/submenu, SPA router, and form extractor.
 */
export async function crawlPage(url, fetchWithRetry, options = {}) {
  const includeResponse = Boolean(options?.includeResponse);
  try {
    const res = await fetchWithRetry(url, {
      sameOriginRedirects: true,
      maxBytes: options?.maxBytes || DEFAULT_MAX_HTML_BYTES
    });
    if (!res || res.status !== 200) {
      return includeResponse ? { links: [], menus: [], forms: [], response: res || null } : [];
    }

    const html = typeof res?.text === 'string' ? res.text : '';
    if (!html) {
      return includeResponse ? { links: [], menus: [], forms: [], response: res } : [];
    }

    const effectivePageUrl = (typeof res?.url === 'string' && /^https?:\/\//i.test(res.url))
      ? res.url
      : url;

    let baseObj = null;
    try {
      baseObj = new URL(effectivePageUrl);
    } catch {
      baseObj = null;
    }

    const appBasePath = baseObj ? inferAppBasePath(html, baseObj) : '/';
    const sharedRouteMap = options?.routeMap instanceof Map ? options.routeMap : new Map();
    const extraLinks = [];
    const scriptMenus = [];
    const ajaxForms = [];

    // When crawling in full mode (includeResponse: true), inspect same-origin app scripts (e.g. app.js, menuController.js)
    // to resolve AngularJS $routeProvider / SPA menu routes, hidden templateUrl views, and AJAX endpoints.
    if (includeResponse && baseObj && options?.discoverAppScripts !== false) {
      const seenScripts = options?.seenAppScriptUrls instanceof Set ? options.seenAppScriptUrls : new Set();
      const maxAppScripts = Number.isFinite(Number(options?.maxAppScripts))
        ? Math.max(0, Math.floor(Number(options.maxAppScripts)))
        : 6;
      const appScripts = extractAppScriptCandidates(html, baseObj);
      const scriptsToFetch = [];

      for (const scriptUrl of appScripts) {
        if (scriptsToFetch.length >= maxAppScripts) break;
        if (seenScripts.has(scriptUrl)) continue;
        seenScripts.add(scriptUrl);
        scriptsToFetch.push(scriptUrl);
      }

      if (scriptsToFetch.length > 0) {
        const scriptLimit = pLimit(3);
        const scriptResults = await Promise.all(
          scriptsToFetch.map(scriptUrl =>
            scriptLimit(async () => {
              try {
                const sRes = await fetchWithRetry(scriptUrl, {
                  sameOriginRedirects: true,
                  maxBytes: options?.maxScriptBytes || options?.maxBytes || DEFAULT_MAX_SCRIPT_BYTES
                });
                if (sRes && sRes.status === 200 && typeof sRes.text === 'string' && sRes.text) {
                  return {
                    spaRoutes: parseSpaRoutesFromScript(sRes.text, effectivePageUrl, appBasePath),
                    ajaxForms: extractAjaxFormsFromScript(sRes.text, effectivePageUrl, appBasePath)
                  };
                }
              } catch {
                // Ignore individual script fetch error
              }
              return null;
            })
          )
        );
        for (const item of scriptResults) {
          if (!item) continue;
          if (item.spaRoutes) {
            for (const [k, v] of item.spaRoutes.routeMap.entries()) {
              sharedRouteMap.set(k, v);
            }
            extraLinks.push(...item.spaRoutes.links);
            if (Array.isArray(item.spaRoutes.menus) && item.spaRoutes.menus.length > 0) {
              scriptMenus.push(...item.spaRoutes.menus);
            }
          }
          if (Array.isArray(item.ajaxForms) && item.ajaxForms.length > 0) {
            ajaxForms.push(...item.ajaxForms);
          }
        }
      }
    }

    const extracted = extractLinksAndFormsFromHtml(html, effectivePageUrl, {
      routeMap: sharedRouteMap,
      extraLinks,
      appBasePath
    });

    if (scriptMenus.length > 0) {
      const seenMenuKeys = new Set(
        extracted.menus.map(
          m => `${(m.parentMenu || 'Main Menu').toLowerCase()}::${(m.label || '').toLowerCase()}::${(m.url || m.routeKey || m.trigger || '').toLowerCase()}`
        )
      );
      for (const sm of scriptMenus) {
        if (!sm || !sm.label) continue;
        const key = `${(sm.parentMenu || 'Main Menu').toLowerCase()}::${sm.label.toLowerCase()}::${(sm.url || sm.routeKey || sm.trigger || '').toLowerCase()}`;
        if (seenMenuKeys.has(key)) continue;
        seenMenuKeys.add(key);
        extracted.menus.push(sm);
      }
    }

    if (ajaxForms.length > 0) {
      const seenFormKeys = new Set(
        extracted.forms.map(
          f => `${(f.method || 'GET').toUpperCase()}::${f.actionUrl}::${(f.fields || []).map(fld => fld.name).join(',')}`
        )
      );
      for (const af of ajaxForms) {
        if (!af || !af.actionUrl) continue;
        const key = `${(af.method || 'GET').toUpperCase()}::${af.actionUrl}::${(af.fields || []).map(fld => fld.name).join(',')}`;
        if (seenFormKeys.has(key)) continue;
        seenFormKeys.add(key);
        extracted.forms.push(af);
      }
    }

    return includeResponse
      ? {
          links: extracted.links,
          menus: extracted.menus,
          forms: extracted.forms,
          response: res
        }
      : extracted.rawLinks;

  } catch (e) {
    return includeResponse ? { links: [], menus: [], forms: [], response: null } : [];
  }
}

/**
 * Discovers safe, read-only same-origin API routes referenced by a crawled page's HTML,
 * client-side JS bundles, or runtime config files so callers can enqueue them into TaskQueue.
 *
 * @param {string} url
 * @param {string|null|undefined} html
 * @param {Function} fetchWithRetry
 * @param {object} [options={}]
 * @returns {Promise<string[]>}
 */
export async function discoverApiRoutesFromPage(url, html, fetchWithRetry, options = {}) {
  try {
    const baseObj = new URL(url);
    if (!['http:', 'https:'].includes(baseObj.protocol)) return [];

    const rootResponse = options.rootResponse
      ?? (typeof html === 'string'
        ? { status: 200, headers: options.headers || {}, text: html }
        : undefined);

    const inspection = await inspectApiCommunication(baseObj.href, fetchWithRetry, {
      maxBundles: options.maxBundles ?? 3,
      maxConfigProbes: options.maxConfigProbes ?? 3,
      ...options,
      ...(rootResponse ? { rootResponse } : {})
    });

    const maxRoutes = Number.isFinite(Number(options.maxRoutes)) && Number(options.maxRoutes) > 0
      ? Math.floor(Number(options.maxRoutes))
      : 20;

    const routes = [];
    const seen = new Set();
    for (const ep of inspection?.sameOriginEndpoints || []) {
      if (!isSafeReadOnlyApiRoute(ep)) continue;
      const cleanEp = stripSensitiveQueryParamsForProbe(ep);
      if (!cleanEp) continue;
      let resolved;
      try {
        resolved = new URL(cleanEp, baseObj.href);
      } catch {
        continue;
      }
      if (resolved.origin !== baseObj.origin) continue;
      if (!['http:', 'https:'].includes(resolved.protocol)) continue;
      const route = `${resolved.pathname}${resolved.search}`;
      if (!isSafeReadOnlyApiRoute(route)) continue;
      if (!seen.has(route)) {
        seen.add(route);
        routes.push(route);
        if (routes.length >= maxRoutes) break;
      }
    }
    return routes;
  } catch {
    return [];
  }
}

/**
 * Shared target crawling, menu/submenu discovery, form discovery, API route discovery,
 * and post-login seeding pipeline used by both the CLI (`scan.js`) and Web UI server (`core/server.js`).
 *
 * @param {string} initialTarget
 * @param {Function} fetchWithRetry
 * @param {object} [options={}]
 * @returns {Promise<{
 *   discoveredUrls: string[],
 *   discoveredMenus: Array<object>,
 *   discoveredForms: Array<object>
 * }>}
 */
export async function runTargetCrawlPipeline(initialTarget, fetchWithRetry, options = {}) {
  const {
    maxDepth = 3,
    authManager = null,
    fp = null,
    activeScanners = [],
    activeFuzzingChecks = null,
    isDeviceBasePortClosed = false,
    isBareIpHttpsSniRestricted = false,
    seenBundleUrls,
    seenConfigUrls,
    budgetState,
    onCrawlDepth = null,
    crawlConcurrency = 4
  } = options;

  const queue = new TaskQueue(initialTarget, {
    shouldEnqueue: (candidateUrl) =>
      !(authManager && typeof authManager.isRestrictedUrl === 'function' && authManager.isRestrictedUrl(candidateUrl))
  });
  const sharedRouteMap = new Map();
  const seenAppScriptUrls = new Set();

  const discoveredMenus = [];
  const seenMenuKeys = new Set();
  const recordDiscoveredMenus = (menusList) => {
    if (!Array.isArray(menusList)) return;
    for (const m of menusList) {
      if (!m || !m.label) continue;
      const key = `${(m.parentMenu || 'Main Menu').toLowerCase()}::${m.label.toLowerCase()}::${(m.url || m.routeKey || m.trigger || '').toLowerCase()}`;
      if (seenMenuKeys.has(key)) continue;
      seenMenuKeys.add(key);
      discoveredMenus.push({
        target: initialTarget,
        ...m
      });
    }
  };

  const discoveredForms = [];
  const seenFormKeys = new Set();
  const recordDiscoveredForms = (formsList) => {
    if (!Array.isArray(formsList)) return;
    for (const form of formsList) {
      if (!form || !form.actionUrl) continue;
      const key = `${form.method || 'GET'}::${form.actionUrl}::${(form.fields || []).map(f => f.name).join(',')}`;
      if (seenFormKeys.has(key)) continue;
      seenFormKeys.add(key);
      discoveredForms.push({
        target: initialTarget,
        ...form
      });
    }
  };

  if (authManager) {
    const authSeeds = buildAuthenticatedSeedUrls(initialTarget, authManager);
    queue.push(authSeeds, initialTarget);
    if (authManager.postLoginHtml) {
      const postLoginBase = authManager.postLoginUrl || initialTarget;
      const extractedPostLogin = extractLinksAndFormsFromHtml(authManager.postLoginHtml, postLoginBase, {
        routeMap: sharedRouteMap
      });
      queue.push(extractedPostLogin.links, postLoginBase);
      recordDiscoveredMenus(extractedPostLogin.menus);
      recordDiscoveredForms(extractedPostLogin.forms);
    }
  }

  let depth = 0;
  const MAX_API_ROUTES_PER_TARGET = 12;
  let apiRoutesEnqueued = 0;
  const enqueueApiRoutes = (routes) => {
    if (apiRoutesEnqueued >= MAX_API_ROUTES_PER_TARGET) return;
    const safeSlice = filterSafeSameOriginApiRoutes(
      routes,
      initialTarget,
      MAX_API_ROUTES_PER_TARGET - apiRoutesEnqueued
    );
    if (safeSlice.length > 0) {
      apiRoutesEnqueued += safeSlice.length;
      queue.push(safeSlice, initialTarget);
    }
  };

  const normalizedInitialTarget = String(initialTarget || '').replace(/\/+$/, '');
  const effectiveConcurrency = Number.isFinite(Number(crawlConcurrency)) && Number(crawlConcurrency) > 0
    ? Math.max(1, Math.min(10, Math.floor(Number(crawlConcurrency))))
    : 4;
  const crawlLimit = pLimit(effectiveConcurrency);

  while (!isDeviceBasePortClosed && !isBareIpHttpsSniRestricted && depth < maxDepth && !queue.isEmpty()) {
    const currentBatch = queue.pending.splice(0, queue.pending.length);
    if (typeof onCrawlDepth === 'function') {
      try {
        onCrawlDepth({
          depth,
          pending: currentBatch.length,
          pagesFound: queue.totalFound
        });
      } catch {}
    }

    const currentDepth = depth;
    await Promise.all(
      currentBatch.map(p =>
        crawlLimit(async () => {
          try {
            const normP = p.replace(/\/+$/, '');
            const isSeedPage =
              normP === normalizedInitialTarget ||
              Boolean(authManager?.postLoginUrl && normP === String(authManager.postLoginUrl).replace(/\/+$/, ''));
            if ((currentDepth === 0 || isSeedPage) && fp?.apiCommunication?.sameOriginEndpoints?.length) {
              enqueueApiRoutes(fp.apiCommunication.sameOriginEndpoints);
            }
            const crawlRes = await crawlPage(p, fetchWithRetry, {
              includeResponse: true,
              routeMap: sharedRouteMap,
              seenAppScriptUrls,
              discoverAppScripts: currentDepth <= 1 || isSeedPage
            });
            const pageBaseUrl = (typeof crawlRes.response?.url === 'string' && /^https?:\/\//i.test(crawlRes.response.url))
              ? crawlRes.response.url
              : p;
            queue.push(crawlRes.links, pageBaseUrl);
            recordDiscoveredMenus(crawlRes.menus);
            recordDiscoveredForms(crawlRes.forms);
            if (apiRoutesEnqueued < MAX_API_ROUTES_PER_TARGET && crawlRes.response?.status === 200) {
              const apiRoutes = await discoverApiRoutesFromPage(p, crawlRes.response.text || '', fetchWithRetry, {
                rootResponse: crawlRes.response,
                maxRoutes: MAX_API_ROUTES_PER_TARGET - apiRoutesEnqueued,
                maxBundles: isSeedPage ? 2 : 1,
                maxConfigProbes: isSeedPage && !fp?.apiCommunication ? 2 : 0,
                seenBundleUrls,
                seenConfigUrls,
                budgetState
              });
              enqueueApiRoutes(apiRoutes);
            }
          } catch {
            // Non-fatal crawl failure on single page
          }
        })
      )
    );
    depth++;
  }

  // If maxDepth stopped before inspecting newly discovered menu/submenu views, sample up to 8 menu views for forms
  if (!isDeviceBasePortClosed && !isBareIpHttpsSniRestricted && discoveredMenus.length > 0 && queue.pending.length > 0) {
    const menuViewSamples = queue.pending.splice(0, 8);
    await Promise.all(
      menuViewSamples.map(viewUrl =>
        crawlLimit(async () => {
          try {
            const viewRes = await crawlPage(viewUrl, fetchWithRetry, {
              includeResponse: true,
              routeMap: sharedRouteMap,
              seenAppScriptUrls,
              discoverAppScripts: false
            });
            const viewBaseUrl = (typeof viewRes.response?.url === 'string' && /^https?:\/\//i.test(viewRes.response.url))
              ? viewRes.response.url
              : viewUrl;
            queue.push(viewRes.links, viewBaseUrl);
            recordDiscoveredMenus(viewRes.menus);
            recordDiscoveredForms(viewRes.forms);
          } catch {}
        })
      )
    );
  }

  const discoveredUrls = Array.from(queue.seen);
  const discoveredUrlNormSet = new Set(discoveredUrls.map(u => String(u).replace(/\/+$/, '')));
  const fuzzCheckSet = activeFuzzingChecks instanceof Set ? activeFuzzingChecks : ACTIVE_FUZZING_CHECKS;
  const activeFuzzCheckNames = (Array.isArray(activeScanners) ? activeScanners : [])
    .filter(s => s && fuzzCheckSet.has(s.name))
    .map(s => s.name);

  for (const m of discoveredMenus) {
    m.auditStatus = m.kind === 'logout'
      ? 'logout_protected'
      : m.kind === 'external_app'
        ? 'external_app'
        : (m.url && discoveredUrlNormSet.has(String(m.url).replace(/\/+$/, '')))
          ? 'crawled'
          : 'discovered';
  }

  for (const f of discoveredForms) {
    const checksForForm = [...activeFuzzCheckNames];
    if (f.method === 'POST' && checksForForm.length > 0 && !checksForForm.includes('post-form-fuzz')) {
      checksForForm.push('post-form-fuzz');
    }
    f.hiddenFieldNames = Object.keys(f.hiddenFields || {});
    f.checksRun = checksForForm;
    f.tested = true;
  }

  return {
    discoveredUrls,
    discoveredMenus,
    discoveredForms
  };
}
