import {
  DEFAULT_MAX_HTML_BYTES,
  inspectApiCommunication,
  isSafeReadOnlyApiRoute,
  stripSensitiveQueryParamsForProbe
} from './api-discovery.js';

const LOGOUT_URL_RE = /(?:^|[\/?&=])(?:log[-_]?out|sign[-_]?out|log[-_]?off|kill[-_]?session|destroy[-_]?session)(?:[\/?&#=]|$)/i;
const FORBIDDEN_FIELD_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const IGNORED_INPUT_TYPES = new Set(['submit', 'button', 'reset', 'image', 'file']);
const CSRF_FIELD_RE = /(?:^|[_.\-\[])(?:csrf|xsrf|yii_csrf_token|requestverificationtoken|authenticity_token|antiforgery|_token)(?:$|[_.\-\]])/i;

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

function getSampleFieldValue(field) {
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
    // Skip dynamic concatenation prefixes ending with a trailing slash and no action if desired, or resolve valid paths
    const cleaned = candidate.replace(/\/+$/, '');
    if (/index\.php$/i.test(cleaned)) continue;
    const resolved = resolveScriptPath(cleaned);
    if (resolved) {
      linksSet.add(resolved);
    }
  }

  return {
    routeMap,
    links: [...linksSet]
  };
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
      parentMenu: 'SPA Router ($routeProvider)',
      label: entry.routeKey,
      kind: 'spa_route',
      trigger: `$routeProvider.when('${entry.routePath}')`,
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

      const csrfField = Object.keys(hiddenFields).find(k => CSRF_FIELD_RE.test(k)) || null;
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
  const scriptSrcRe = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi;
  let m;
  while ((m = scriptSrcRe.exec(html)) !== null) {
    const rawSrc = decodeBasicHtmlEntities(m[1] || '').trim();
    if (!rawSrc || /^(?:data|javascript):/i.test(rawSrc)) continue;
    let resolved;
    try {
      resolved = new URL(rawSrc, baseObj.href);
    } catch {
      continue;
    }
    if (resolved.origin !== baseObj.origin) continue;
    if (VENDOR_SCRIPT_NAME_RE.test(resolved.pathname || '')) continue;
    if (seen.has(resolved.href)) continue;
    seen.add(resolved.href);
    scripts.push(resolved.href);
  }

  // Prioritize app.js, router, menuController, adminService first
  scripts.sort((a, b) => {
    const score = (u) => {
      const lower = u.toLowerCase();
      if (/(?:^|\/)(?:app|routes?|router|menucontroller|adminservice|main)\.js(?:[?#]|$)/i.test(lower)) return 0;
      if (/controller|service/i.test(lower)) return 1;
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

    // When crawling in full mode (includeResponse: true), inspect same-origin app scripts (e.g. app.js, menuController.js)
    // to resolve AngularJS $routeProvider / SPA menu routes and hidden templateUrl views.
    if (includeResponse && baseObj && options?.discoverAppScripts !== false) {
      const seenScripts = options?.seenAppScriptUrls instanceof Set ? options.seenAppScriptUrls : new Set();
      const maxAppScripts = Number.isFinite(Number(options?.maxAppScripts))
        ? Math.max(0, Math.floor(Number(options.maxAppScripts)))
        : 6;
      const appScripts = extractAppScriptCandidates(html, baseObj);
      let fetchedScripts = 0;

      for (const scriptUrl of appScripts) {
        if (fetchedScripts >= maxAppScripts) break;
        if (seenScripts.has(scriptUrl)) continue;
        seenScripts.add(scriptUrl);
        fetchedScripts++;
        try {
          const sRes = await fetchWithRetry(scriptUrl, {
            sameOriginRedirects: true,
            maxBytes: options?.maxBytes || DEFAULT_MAX_HTML_BYTES
          });
          if (sRes && sRes.status === 200 && typeof sRes.text === 'string' && sRes.text) {
            const parsedScript = parseSpaRoutesFromScript(sRes.text, effectivePageUrl, appBasePath);
            for (const [k, v] of parsedScript.routeMap.entries()) {
              sharedRouteMap.set(k, v);
            }
            extraLinks.push(...parsedScript.links);
          }
        } catch {
          // Ignore individual script fetch error
        }
      }
    }

    const extracted = extractLinksAndFormsFromHtml(html, effectivePageUrl, {
      routeMap: sharedRouteMap,
      extraLinks,
      appBasePath
    });

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
