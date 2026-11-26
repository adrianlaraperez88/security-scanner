import net from 'node:net';
import { DEFAULT_MAX_HTML_BYTES, inspectApiCommunication } from './api-discovery.js';
import { detectRuntimeScaFindings } from './runtime-sca.js';
import { scanDeviceTarget, probeSingleTcpPort, normalizeDeviceCategory } from './device-scanner.js';
import { detectOperatingSystemFromSignals } from './os-scanner.js';
import { normalizeTargetInput, validateTargetUrl, resolveAndValidateTarget, isPrivateOrReservedIP } from './validator.js';
import { fetchWithRetry as defaultCoreFetch, runAssetGateCheck } from './fetch.js';

function isPrivateOrLanHost(hostname) {
  if (typeof hostname !== 'string') return false;
  const clean = hostname.trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
  if (!clean) return false;
  if (clean === 'localhost' || clean.endsWith('.local') || clean.endsWith('.localhost')) {
    return true;
  }
  if (net.isIP(clean) !== 0) {
    return isPrivateOrReservedIP(clean);
  }
  return false;
}

/**
 * Priority Tier definition for technologies.
 * Frameworks are given the highest weight, followed by frontend UI, languages/runtimes, and finally server/infrastructure.
 */
export const TECH_PRIORITY = {
  // Tier 1: Frameworks, CMS & Smart Devices (Priority 10)
  'laravel': 10,
  'wordpress': 10,
  'django': 10,
  'rails': 10,
  'spring': 10,
  'express': 10,
  'nextjs': 10,
  'drupal': 10,
  'magento': 10,
  'codeigniter': 10,
  'joomla': 10,
  'symfony': 10,
  'yii': 10,
  'yii1': 10,
  'yii2': 10,
  'aspnet': 10,
  'flask': 10,
  'fastapi': 10,
  'device': 10,

  // Tier 2: Frontend UI & Frameworks (Priority 5)
  'react': 5,
  'vue': 5,
  'angular': 5,

  // Tier 3: Languages & Runtimes (Priority 3)
  'php': 3,
  'python': 3,
  'node': 3,
  'java': 3,

  // Tier 4: Server, CDN & Caching (Priority 1)
  'tomcat': 10,
  'nginx': 1,
  'apache': 1,
  'cloudflare': 1,
  'varnish': 1
};

export const CATEGORY_MAP = {
  laravel: 'frameworks',
  wordpress: 'frameworks',
  django: 'frameworks',
  rails: 'frameworks',
  spring: 'frameworks',
  express: 'frameworks',
  nextjs: 'frameworks',
  drupal: 'frameworks',
  magento: 'frameworks',
  codeigniter: 'frameworks',
  joomla: 'frameworks',
  symfony: 'frameworks',
  yii: 'frameworks',
  yii1: 'frameworks',
  yii2: 'frameworks',
  aspnet: 'frameworks',
  flask: 'frameworks',
  fastapi: 'frameworks',

  react: 'frontend',
  vue: 'frontend',
  angular: 'frontend',

  php: 'runtimes',
  python: 'runtimes',
  node: 'runtimes',
  java: 'runtimes',

  nginx: 'servers',
  apache: 'servers',
  tomcat: 'servers',
  cloudflare: 'servers',
  varnish: 'servers',
  device: 'servers'
};

export const TECH_DISPLAY_NAMES = {
  laravel: 'Laravel',
  wordpress: 'WordPress',
  django: 'Django',
  rails: 'Rails',
  spring: 'Spring Boot',
  express: 'Express',
  nextjs: 'Next.js',
  drupal: 'Drupal',
  magento: 'Magento',
  codeigniter: 'CodeIgniter',
  joomla: 'Joomla',
  symfony: 'Symfony',
  yii: 'Yii Framework',
  yii1: 'Yii 1.x',
  yii2: 'Yii 2.x',
  aspnet: 'ASP.NET',
  flask: 'Flask',
  fastapi: 'FastAPI',
  react: 'React',
  vue: 'Vue',
  angular: 'Angular',
  php: 'PHP',
  python: 'Python',
  node: 'Node.js',
  java: 'Java',
  nginx: 'Nginx',
  apache: 'Apache',
  tomcat: 'Apache Tomcat',
  cloudflare: 'Cloudflare',
  varnish: 'Varnish',
  device: 'Smart TV, Camera, PC & IoT Device'
};

/**
 * Returns ecosystem tags associated with a canonical device category.
 *
 * @param {string | null | undefined} category
 * @returns {string[]}
 */
export function getDeviceCategoryTags(category) {
  switch (category) {
    case 'smart_tv':
      return ['device', 'tv', 'smart-tv', 'iot'];
    case 'ip_camera':
      return ['device', 'camera', 'ip-camera', 'iot'];
    case 'pc_workstation':
      return ['device', 'pc', 'workstation', 'server'];
    case 'router_gateway':
      return ['device', 'router', 'iot'];
    case 'printer':
      return ['device', 'printer', 'iot'];
    case 'nas_media_server':
      return ['device', 'nas', 'iot'];
    default:
      return ['device', 'iot'];
  }
}

/**
 * Expands detected stack items into comprehensive ecosystem tags.
 *
 * @param {Array<{tech: string}|string>} stackItems
 * @returns {string[]}
 */
export function inferEcosystemTags(stackItems = []) {
  const tags = new Set();
  for (const item of stackItems) {
    const tech = typeof item === 'string' ? item : item?.tech;
    if (tech) tags.add(tech);
  }

  if (tags.has('yii1') || tags.has('yii2')) {
    tags.add('yii');
  }

  const phpFrameworks = ['laravel', 'wordpress', 'drupal', 'magento', 'codeigniter', 'joomla', 'symfony', 'yii', 'yii1', 'yii2'];
  if (phpFrameworks.some(f => tags.has(f))) {
    tags.add('php');
  }

  if (tags.has('nextjs')) {
    tags.add('react');
    tags.add('node');
    tags.add('frontend');
  }

  if (tags.has('express')) {
    tags.add('node');
  }

  const frontendFrameworks = ['react', 'vue', 'angular'];
  if (frontendFrameworks.some(f => tags.has(f))) {
    tags.add('frontend');
  }

  const pythonFrameworks = ['django', 'flask', 'fastapi'];
  if (pythonFrameworks.some(f => tags.has(f))) {
    tags.add('python');
  }

  if (tags.has('spring') || tags.has('tomcat')) {
    tags.add('java');
  }

  if (tags.has('smart_tv') || tags.has('smart-tv') || tags.has('tv')) {
    tags.add('device');
    tags.add('tv');
    tags.add('smart-tv');
    tags.add('iot');
  }

  if (tags.has('ip_camera') || tags.has('ip-camera') || tags.has('camera') || tags.has('nvr')) {
    tags.add('device');
    tags.add('camera');
    tags.add('ip-camera');
    tags.add('iot');
  }

  if (tags.has('pc_workstation') || tags.has('pc-workstation') || tags.has('pc') || tags.has('workstation') || tags.has('server')) {
    tags.add('device');
    tags.add('pc');
    tags.add('workstation');
    tags.add('server');
  }

  if (tags.has('device') || tags.has('iot') || tags.has('router') || tags.has('printer') || tags.has('nas')) {
    tags.add('device');
    if (
      !tags.has('camera') &&
      !tags.has('pc') &&
      !tags.has('workstation') &&
      !tags.has('server') &&
      !tags.has('tv')
    ) {
      tags.add('iot');
    }
  }

  return Array.from(tags);
}

/**
 * Recommends the optimal scanner profile for a detected primary tech and tags.
 *
 * @param {string} primary
 * @param {string[]} [detectedTags=[]]
 * @returns {string}
 */
export function recommendProfileForStack(primary, detectedTags = []) {
  const candidate = (p) => {
    switch (p) {
      case 'laravel': return 'laravel';
      case 'wordpress': return 'wordpress';
      case 'drupal': return 'drupal';
      case 'magento': return 'magento';
      case 'symfony': return 'symfony';
      case 'yii':
      case 'yii1':
      case 'yii2': return 'yii';
      case 'codeigniter': return 'codeigniter';
      case 'php':
      case 'joomla': return 'php';
      case 'nextjs': return 'modern';
      case 'express':
      case 'node': return 'node';
      case 'django':
      case 'flask':
      case 'fastapi':
      case 'python': return 'python';
      case 'spring':
      case 'tomcat':
      case 'java': return 'spring';
      case 'react':
      case 'vue':
      case 'angular': return 'frontend';
      case 'nginx': return 'nginx';
      case 'apache': return 'apache';
      case 'device':
      case 'tv':
      case 'smart-tv':
      case 'smart_tv':
      case 'camera':
      case 'ip-camera':
      case 'ip_camera':
      case 'nvr':
      case 'pc':
      case 'workstation':
      case 'server':
      case 'pc-workstation':
      case 'pc_workstation':
      case 'iot': return 'device';
      default: return null;
    }
  };

  const fromPrimary = candidate(primary);
  if (fromPrimary) return fromPrimary;

  const tags = new Set(Array.isArray(detectedTags) ? detectedTags : []);
  const priorityOrder = [
    'device', 'tv', 'smart-tv', 'smart_tv', 'camera', 'ip-camera', 'ip_camera', 'nvr',
    'pc', 'workstation', 'server', 'pc-workstation', 'pc_workstation', 'iot',
    'laravel', 'wordpress', 'drupal', 'magento', 'symfony', 'yii1', 'yii2', 'yii', 'codeigniter',
    'joomla', 'nextjs', 'express', 'django', 'flask', 'fastapi', 'spring',
    'tomcat', 'react', 'vue', 'angular', 'php', 'node', 'python', 'java', 'nginx', 'apache'
  ];
  for (const tag of priorityOrder) {
    if (tags.has(tag)) {
      const rec = candidate(tag);
      if (rec) return rec;
    }
  }

  return 'smart';
}

export async function fingerprint(target, fetchWithRetry, options = {}) {
  const normalizedTarget = (typeof target === 'string' ? normalizeTargetInput(target) : null) || String(target || '').trim();
  let parsedUrl = null;
  try {
    parsedUrl = new URL(normalizedTarget);
  } catch {
    parsedUrl = null;
  }

  const hostname = parsedUrl ? parsedUrl.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '') : '';
  const isLiteralIp = Boolean(hostname && net.isIP(hostname) !== 0);
  const isPrivateLanTarget = isPrivateOrLanHost(hostname);
  const explicitPort = parsedUrl?.port ? Number(parsedUrl.port) : null;
  const basePort = explicitPort || (parsedUrl?.protocol === 'https:' ? 443 : 80);

  const boundGovernance = fetchWithRetry?.governance || null;
  const allowPrivate = Boolean(boundGovernance?.allowPrivate ?? options.allowPrivate);
  const deviceMode = Boolean(options.deviceMode);
  const deviceCategory = normalizeDeviceCategory(options.deviceCategory);

  const hasCustomProbe = typeof options.tcpProbe === 'function' || typeof options.portProbe === 'function';
  const isLiveNetworkFetcher =
    fetchWithRetry === defaultCoreFetch ||
    Boolean(fetchWithRetry?.isDefaultFetch) ||
    (Boolean(boundGovernance) && !fetchWithRetry?.hasCustomFetcher);

  const deviceScanOptions = {
    ...options,
    allowPrivate,
    deviceMode,
    deviceCategory,
    quickFingerprint: true,
    ...(!isLiveNetworkFetcher && !hasCustomProbe && options.multiPort === undefined ? { multiPort: false } : {})
  };

  const buildDeviceOnlyResult = (dp) => ({
    primary: 'device',
    confidence: 10,
    stack: [{ tech: 'device', score: 10, rank: 100 }],
    detectedTags: getDeviceCategoryTags(dp.category),
    recommendedProfile: 'device',
    categories: { frameworks: [], frontend: [], runtimes: [], servers: ['device'] },
    summary: dp.summary || 'Smart TV, Camera, PC & IoT Device',
    apiCommunication: null,
    runtimeSca: null,
    deviceInfo: dp,
    osInfo: detectOperatingSystemFromSignals({
      deviceInfo: dp,
      openPorts: dp?.openPorts,
      openServices: dp?.openServices
    })
  });

  // Fast TCP pre-check on basePort when scanning literal IPs/device targets (or when tcpProbe is supplied)
  // so closed/filtered ports 80/443 never stall root fetchWithRetry for 30s+.
  // For non-literal hostnames with live/governed fetchers, enforce DNS SSRF validation BEFORE any socket probe.
  let basePortClosedPrecheck = false;
  let dnsGovernanceBlocked = false;
  let pinnedPrecheckHost = hostname;
  if (parsedUrl && validateTargetUrl(normalizedTarget, { allowPrivate }).valid) {
    const preDnsGate = runAssetGateCheck(normalizedTarget, {
      guard: boundGovernance?.guard,
      scopeRules: boundGovernance?.scopeRules,
      alwaysBuiltin: true
    });
    if (preDnsGate && preDnsGate.allowed === false) {
      dnsGovernanceBlocked = true;
    } else {
      const customProbe = typeof options.tcpProbe === 'function'
        ? options.tcpProbe
        : (typeof options.portProbe === 'function' ? options.portProbe : null);
      const shouldCheckDnsBeforePrecheck =
        !isLiteralIp && (isLiveNetworkFetcher || Boolean(boundGovernance?.dnsResolver));
      if (shouldCheckDnsBeforePrecheck) {
        const activeDnsResolver = boundGovernance ? boundGovernance.dnsResolver : (options.dnsResolver ?? null);
        const dnsCheck = await resolveAndValidateTarget(normalizedTarget, {
          allowPrivate,
          resolver: activeDnsResolver,
          resolveCache: boundGovernance?.resolveCache ?? null,
          targetPinStore: boundGovernance?.targetPinStore ?? null,
          sourceIp: boundGovernance?.sourceIp ?? null,
          sourceIpMap: boundGovernance?.sourceIpMap ?? null
        });
        if (!dnsCheck.valid) {
          dnsGovernanceBlocked = true;
        } else {
          if ((boundGovernance?.guard || boundGovernance?.scopeRules) && Array.isArray(dnsCheck.resolvedIps) && dnsCheck.resolvedIps.length > 0) {
            const postDnsGate = runAssetGateCheck(
              { url: normalizedTarget, hostname, resolvedIps: dnsCheck.resolvedIps },
              { guard: boundGovernance?.guard, scopeRules: boundGovernance?.scopeRules }
            );
            if (postDnsGate && postDnsGate.allowed === false) {
              dnsGovernanceBlocked = true;
            }
          }
          if (!dnsGovernanceBlocked && dnsCheck.primaryIp) {
            pinnedPrecheckHost = dnsCheck.primaryIp;
          }
        }
      }

      if (!dnsGovernanceBlocked && (deviceMode || isPrivateLanTarget || options.multiPort === true)) {
        if (customProbe) {
          try {
            const pre = await customProbe(hostname, basePort, { timeoutMs: Math.min(Number(options.portTimeoutMs) || 700, 1200) });
            const isOpen = typeof pre === 'boolean' ? pre : Boolean(pre && pre.open);
            if (!isOpen) basePortClosedPrecheck = true;
          } catch {}
        } else if (isLiveNetworkFetcher) {
          try {
            const pre = await probeSingleTcpPort(pinnedPrecheckHost, basePort, { timeoutMs: Math.min(Number(options.portTimeoutMs) || 700, 1200) });
            if (!pre.open) basePortClosedPrecheck = true;
          } catch {}
        }
      }
    }
  }

  if (dnsGovernanceBlocked) {
    return {
      primary: 'unknown',
      confidence: 0,
      stack: [],
      detectedTags: [],
      recommendedProfile: 'smart',
      categories: { frameworks: [], frontend: [], runtimes: [], servers: [] },
      summary: 'Unreachable or Unknown',
      apiCommunication: null,
      runtimeSca: null
    };
  }

  if (basePortClosedPrecheck) {
    if (options.deviceDiscovery !== false && (deviceMode || isPrivateLanTarget || options.multiPort === true)) {
      try {
        const devRes = await scanDeviceTarget(normalizedTarget, fetchWithRetry, deviceScanOptions);
        if (devRes?.ok && devRes.deviceProfile?.detected) {
          return buildDeviceOnlyResult(devRes.deviceProfile);
        }
      } catch {
        // Ignore device fallback error
      }
    }
    return {
      primary: 'unknown',
      confidence: 0,
      stack: [],
      detectedTags: [],
      recommendedProfile: 'smart',
      categories: { frameworks: [], frontend: [], runtimes: [], servers: [] },
      summary: 'Unreachable or Unknown',
      apiCommunication: null,
      runtimeSca: null,
      deviceInfo: {
        detected: false,
        host: hostname,
        basePortClosed: true,
        openPorts: [],
        openServices: [],
        activeHttpOrigin: null,
        activeHttpsOrigin: null
      }
    };
  }

  let res;
  const fastTimeout = Number.isFinite(Number(options.rootTimeoutMs ?? options.probeTimeoutMs)) && Number(options.rootTimeoutMs ?? options.probeTimeoutMs) > 0
    ? Number(options.rootTimeoutMs ?? options.probeTimeoutMs)
    : ((deviceMode || isPrivateLanTarget) ? 2000 : 10000);

  try {
    res = await fetchWithRetry(
      normalizedTarget,
      {
        maxBytes: DEFAULT_MAX_HTML_BYTES,
        retries: 0,
        failFast: true,
        ...((deviceMode || isPrivateLanTarget) ? { timeout: fastTimeout } : {}), ...(allowPrivate ? { allowPrivate } : {})
      },
      0,
      fastTimeout
    );
  } catch (e) {
    // When base HTTP/HTTPS port (e.g. port 80 on a Smart TV or IoT device like 192.168.68.53) is closed,
    // fall back to multi-port device discovery if permitted (never when blocked by governance/SSRF policy).
    const isGovBlock =
      dnsGovernanceBlocked ||
      Boolean(e?.isGovernanceBlock) ||
      e?.code === 'SSRF_POLICY_BLOCKED' ||
      e?.code === 'DNS_REBIND_OR_PRIVATE_IP' ||
      e?.code === 'TARGET_RULE_BLOCKED';
    if (!isGovBlock && options.deviceDiscovery !== false && (deviceMode || isPrivateLanTarget || options.multiPort === true)) {
      try {
        const devRes = await scanDeviceTarget(normalizedTarget, fetchWithRetry, deviceScanOptions);
        if (devRes?.ok && devRes.deviceProfile?.detected) {
          return buildDeviceOnlyResult(devRes.deviceProfile);
        }
      } catch {
        // Ignore device fallback error
      }
    }

    return {
      primary: 'unknown',
      confidence: 0,
      stack: [],
      detectedTags: [],
      recommendedProfile: 'smart',
      categories: { frameworks: [], frontend: [], runtimes: [], servers: [] },
      summary: 'Unreachable or Unknown',
      apiCommunication: null,
      runtimeSca: null
    };
  }

  const base = normalizedTarget.replace(/\/+$/, '');
  const html = (res.text || '').toLowerCase();
  const rawHeaders = res.headers || {};
  const h = {};
  for (const [k, v] of Object.entries(rawHeaders)) {
    h[k.toLowerCase()] = Array.isArray(v) ? v.join('; ') : String(v);
  }

  // ── Header signals (most reliable) ────────────────────────────────────────
  const powered   = (h['x-powered-by'] || '').toLowerCase();
  const server    = (h['server'] || '').toLowerCase();
  const setCookie = (h['set-cookie'] || '').toLowerCase();
  const via       = (h['via'] || '').toLowerCase();
  const generator = (h['x-generator'] || '').toLowerCase();
  const runtime   = (h['x-runtime'] || '').toLowerCase();   // Rails
  const cfRay     = (h['cf-ray'] || '');
  const xVarnish  = (h['x-varnish'] || '');
  const xCache    = (h['x-cache'] || '').toLowerCase();

  const stack = [];
  const boost = (tech, score) => {
    const existing = stack.find(s => s.tech === tech);
    if (existing) {
      existing.score += score;
    } else {
      stack.push({ tech, score });
    }
  };

  // ── Laravel ──────────────────────────────────────────────────────────────
  let laravel = 0;
  if (setCookie.includes('laravel_session')) laravel += 5;
  if (setCookie.includes('xsrf-token'))      laravel += 4;
  if (html.includes('csrf-token') && !html.includes('name="csrf-param"')) laravel += 3;
  if (html.includes('name="_token"'))        laravel += 3;
  if (html.includes('livewire/livewire.js') || html.includes('wire:initial-data') || html.includes('wire:click')) laravel += 4;
  if (html.includes('inertia') || html.includes('data-page=')) laravel += 3;
  if (html.includes('laravel'))              laravel += 2;
  if (html.includes('illuminate'))           laravel += 1;
  if (laravel) boost('laravel', laravel);

  // ── Yii 1.x & Yii 2.x ─────────────────────────────────────────────────────
  let yii1 = 0;
  if (setCookie.includes('yii_csrf_token') || html.includes('yii_csrf_token')) yii1 += 6;
  if (
    html.includes('jquery.yiiactiveform') ||
    html.includes('jquery.yiigridview') ||
    html.includes('jquery.yiilistview') ||
    html.includes('yiiactiveform')
  ) {
    yii1 += 5;
  }
  if (
    html.includes('cexception') ||
    html.includes('cdbexception') ||
    html.includes('chttpexception') ||
    html.includes('cactiveform') ||
    html.includes('cwebapplication')
  ) {
    yii1 += 5;
  }
  if (html.includes('loginform[') && (html.includes('loginform_username') || html.includes('name="yt0"'))) {
    yii1 += 5;
  } else if (html.includes('name="yt0"') && html.includes('value="login"')) {
    yii1 += 3;
  }
  if (yii1) {
    boost('yii1', yii1);
    boost('yii', yii1);
  }

  let yii2 = 0;
  if (
    setCookie.includes('_csrf-frontend') ||
    setCookie.includes('_csrf-backend') ||
    html.includes('_csrf-frontend') ||
    html.includes('_csrf-backend')
  ) {
    yii2 += 6;
  }
  if (
    setCookie.includes('_identity-frontend') ||
    setCookie.includes('_identity-backend') ||
    setCookie.includes('_identity=')
  ) {
    yii2 += 5;
  }
  if (
    html.includes('yii.activeform.js') ||
    html.includes('yii.gridview.js') ||
    html.includes('yii.validation.js') ||
    html.includes('yii.captcha.js') ||
    html.includes('.yiiactiveform(')
  ) {
    yii2 += 5;
  }
  if (
    Boolean(h['x-debug-tag'] || h['x-debug-link'] || h['x-debug-duration']) ||
    html.includes('yii-debug-toolbar')
  ) {
    yii2 += 6;
  }
  if (html.includes('name="csrf-param"') && (html.includes('content="_csrf') || html.includes("content='_csrf"))) {
    yii2 += 5;
  }
  if (html.includes('loginform[') && html.includes('loginform-username')) {
    yii2 += 5;
  }
  if (html.includes('yii\\base\\') || html.includes('yii\\web\\') || html.includes('yii\\db\\')) {
    yii2 += 5;
  }
  if (yii2) {
    boost('yii2', yii2);
    boost('yii', yii2);
  }

  if (!yii1 && !yii2) {
    let yiiGeneric = 0;
    if (powered.includes('yii') || generator.includes('yii')) yiiGeneric += 5;
    if (html.includes('powered by yii framework') || html.includes('yiiframework.com')) yiiGeneric += 5;
    if (yiiGeneric) boost('yii', yiiGeneric);
  }

  // ── PHP ───────────────────────────────────────────────────────────────────
  let php = 0;
  if (powered.includes('php'))                                              php += 5;
  if (/\.php(?:\/|\?|$)/i.test(normalizedTarget) || /\.php(?:\/|\?|$)/i.test(res?.url || '')) php += 5;
  if (setCookie.includes('phpsessid'))                                      php += 5;
  if (setCookie.includes('yii_csrf_token') || html.includes('yii_csrf_token')) php += 5;
  if (html.includes('loginform[') || html.includes('yiiactiveform'))        php += 4;
  if (html.includes('.php'))                                                php += 1;
  if (php) boost('php', php);

  // ── WordPress ─────────────────────────────────────────────────────────────
  let wp = 0;
  if (html.includes('wp-content/themes/') || html.includes('wp-content/plugins/')) wp += 5;
  if (generator.includes('wordpress') || html.includes('<meta name="generator" content="wordpress')) wp += 5;
  if (html.includes('wp-content'))      wp += 3;
  if (html.includes('wp-json'))         wp += 3;
  if (html.includes('wp-includes'))     wp += 2;
  if (html.includes('wp-block-library') || html.includes('window._wpemojisettings')) wp += 3;
  if (setCookie.includes('wordpress_')) wp += 3;
  if (html.includes('xmlrpc.php'))      wp += 2;
  if (wp) boost('wordpress', wp);

  // ── Express / Node.js ────────────────────────────────────────────────────
  let express = 0;
  if (powered.includes('express'))       express += 5;
  if (setCookie.includes('connect.sid')) express += 4;
  if (powered.includes('node'))          express += 2;
  if (express) boost('express', express);

  // ── Django ────────────────────────────────────────────────────────────────
  let django = 0;
  if (html.includes('csrfmiddlewaretoken') || html.includes('name="csrfmiddlewaretoken"')) django += 5;
  if (setCookie.includes('csrftoken'))                                    django += 5;
  if (setCookie.includes('sessionid') && !setCookie.includes('laravel')) django += 3;
  if (html.includes('/static/admin/'))                                    django += 3;
  if (html.includes('django'))                                            django += 2;
  if (django) boost('django', django);

  // ── Rails ─────────────────────────────────────────────────────────────────
  let rails = 0;
  if (runtime && /^\d+\.\d+$/.test(runtime)) rails += 4;
  if (setCookie.includes('_session_id'))       rails += 4;
  if (html.includes('csrf-param') && html.includes('authenticity_token')) rails += 4;
  if (h['x-request-id'] && runtime)           rails += 2;
  if (rails) boost('rails', rails);

  // ── Spring Boot ────────────────────────────────────────────────────────────
  let spring = 0;
  if (setCookie.includes('jsessionid'))   spring += 5;
  if (h['x-application-context'])         spring += 3;
  if (html.includes('whitelabel error page') || html.includes('this application has no explicit mapping for /error')) spring += 5;
  if (html.includes('spring'))            spring += 1;
  if (spring) boost('spring', spring);

  // ── ASP.NET ────────────────────────────────────────────────────────────────
  let aspnet = 0;
  if (powered.includes('asp.net'))              aspnet += 5;
  if (h['x-aspnet-version'])                    aspnet += 4;
  if (setCookie.includes('asp.net_sessionid'))  aspnet += 4;
  if (setCookie.includes('__requestverificationtoken')) aspnet += 4;
  if (html.includes('__viewstate') || html.includes('__eventvalidation')) aspnet += 4;
  if (html.includes('.aspx'))                   aspnet += 1;
  if (aspnet) boost('aspnet', aspnet);

  // ── Drupal ───────────────────────────────────
  let drupal = 0;
  if (generator.includes('drupal') || html.includes('<meta name="generator" content="drupal')) drupal += 5;
  if (h['x-drupal-cache'])                             drupal += 4;
  if (h['x-drupal-dynamic-cache'])                     drupal += 4;
  if (html.includes('drupalsettings') || html.includes('data-drupal-')) drupal += 4;
  if (html.includes('/sites/default/files'))           drupal += 3;
  if (html.includes('drupal'))                         drupal += 2;
  if (drupal) boost('drupal', drupal);

  // ── Magento ────────────────────────────────────────────────────────────────
  let magento = 0;
  if (h['x-magento-cache-id'])           magento += 5;
  if (h['x-magento-tags'])               magento += 4;
  if (h['x-magento-vary'])               magento += 3;
  if (html.includes('mage.cookies'))     magento += 3;
  if (html.includes('mage_'))            magento += 2;
  if (html.includes('magento'))          magento += 2;
  if (html.includes('/pub/static/'))     magento += 1;
  if (magento) boost('magento', magento);

  // ── CodeIgniter ───────────────────────────────────────────────────────────
  let codeigniter = 0;
  if (setCookie.includes('ci_session'))                         codeigniter += 5;
  if (html.includes('a php error was encountered'))             codeigniter += 4;
  if (html.includes('codeigniter'))                             codeigniter += 3;
  if (html.includes('/index.php/welcome'))                      codeigniter += 3;
  if (html.includes('ci_csrf_token'))                           codeigniter += 2;
  if (codeigniter) boost('codeigniter', codeigniter);

  // ── Joomla ────────────────────────────────────────────────────────────────
  let joomla = 0;
  if (html.includes('/components/com_'))    joomla += 3;
  if (setCookie.includes('joomla_session')) joomla += 3;
  if (html.includes('joomla'))              joomla += 1;
  if (joomla) boost('joomla', joomla);

  // ── Symfony ────────────────────────────────────────────────────────────────
  let symfony = 0;
  if (html.includes('sf-toolbar') || html.includes('sfminitoolbar')) symfony += 5;
  if (setCookie.includes('symfony') || setCookie.includes('sf_redirect')) symfony += 4;
  if (html.includes('/_wdt/') || html.includes('/_profiler/')) symfony += 4;
  if (symfony) boost('symfony', symfony);

  // ── Angular ────────────────────────────────────────────────
  let angular = 0;
  if (html.includes('ng-version'))                   angular += 5;
  if (html.includes('ng-server-context'))            angular += 5;
  if (html.includes('ng-component') || html.includes('_nghost-') || html.includes('_ngcontent-')) angular += 3;
  if (html.includes('<app-root'))                    angular += 3;
  if (/\bng-app\b/.test(html))                       angular += 3;
  if (/main(?:[.-][a-z0-9]+)?\.m?js\b/i.test(html) && /polyfills(?:[.-][a-z0-9]+)?\.m?js\b/i.test(html)) angular += 3;
  if (html.includes('@angular/common/http') || html.includes('providehttpclient') || html.includes('httpclient')) angular += 2;
  if (angular) boost('angular', angular);

  // ── React ─────────────────────────────────────────────────────────────────
  let react = 0;
  if (html.includes('data-reactroot'))              react += 4;
  if (html.includes('react-dom'))                   react += 3;
  if (html.includes('__next_data__'))               react += 2;
  if (react) boost('react', react);

  // ── Vue ───────────────────────────────────────────────────────────────────
  let vue = 0;
  if (html.includes('data-v-'))                     vue += 4;
  if (html.includes('vue.js') || html.includes('vue.runtime')) vue += 3;
  if (html.includes('__vue_app__'))                 vue += 2;
  if (vue) boost('vue', vue);

  // ── Next.js ───────────────────────────────────────────────────────────────
  let nextjs = 0;
  if (html.includes('__next_data__'))  nextjs += 4;
  if (html.includes('/_next/static'))  nextjs += 3;
  if (h['x-nextjs-page'])              nextjs += 3;
  if (nextjs) {
    boost('nextjs', nextjs);
    if (!react) boost('react', 3);
  }

  // ── Flask ──────────────────────────────────────────────────────────────────
  let flask = 0;
  if (server.includes('werkzeug')) flask += 5;
  if (html.includes('werkzeug'))   flask += 4;
  if (flask) boost('flask', flask);

  // ── FastAPI ────────────────────────────────────────────────────────────────
  let fastapi = 0;
  if (server.includes('uvicorn') || server.includes('hypercorn') || server.includes('starlette')) fastapi += 4;
  if (html.includes('swagger-ui') && (html.includes('/openapi.json') || html.includes('fastapi'))) fastapi += 4;
  if (fastapi) boost('fastapi', fastapi);

  // ── Python ─────────────────────────────────────────────────────────────────
  let python = 0;
  if (server.includes('python') || server.includes('gunicorn') || server.includes('uwsgi') || server.includes('daphne') || server.includes('wsgiserver')) python += 4;
  if (powered.includes('python')) python += 4;
  if (python) boost('python', python);

  // ── Node.js ────────────────────────────────────────────────────────────────
  let node = 0;
  if (powered.includes('express') || powered.includes('next.js') || powered.includes('nestjs') || powered.includes('fastify') || powered.includes('koa')) node += 4;
  if (setCookie.includes('connect.sid')) node += 3;
  if (node) boost('node', node);

  // ── Java ───────────────────────────────────────────────────────────────────
  const servletEngine = (h['servlet-engine'] || '').toLowerCase();
  const xJavaVersion = (h['x-java-version'] || '').toLowerCase();
  const javaHeaderText = [server, powered, servletEngine, xJavaVersion].filter(Boolean).join(' ');
  let java = 0;
  if (setCookie.includes('jsessionid')) java += 4;
  if (
    javaHeaderText.includes('coyote') ||
    javaHeaderText.includes('tomcat') ||
    javaHeaderText.includes('jetty') ||
    javaHeaderText.includes('wildfly') ||
    javaHeaderText.includes('undertow') ||
    javaHeaderText.includes('netty') ||
    javaHeaderText.includes('weblogic') ||
    javaHeaderText.includes('openjdk') ||
    javaHeaderText.includes('java/') ||
    Boolean(xJavaVersion)
  ) {
    java += 4;
  }
  if (java) boost('java', java);

  // ── Nginx ─────────────────────────────────────────────────────────────────
  let nginx = 0;
  if (server.includes('nginx')) nginx += 3;
  if (nginx) boost('nginx', nginx);

  // ── Apache ────────────────────────────────────────────────────────────────
  let apache = 0;
  if (server.includes('apache') && !server.includes('tomcat') && !server.includes('coyote')) apache += 3;
  if (apache) boost('apache', apache);

  // ── Tomcat ────────────────────────────────────────────────────────────────
  let tomcat = 0;
  if (server.includes('apache tomcat') || server.includes('tomcat')) tomcat += 6;
  if (servletEngine.includes('tomcat')) tomcat += 5;
  if (html.includes('apache tomcat')) tomcat += 3;
  if (tomcat) boost('tomcat', tomcat);

  // ── Cloudflare ────────────────────────────────────────────────────────────
  let cloudflare = 0;
  if (cfRay)                         cloudflare += 4;
  if (server.includes('cloudflare')) cloudflare += 3;
  if (cloudflare) boost('cloudflare', cloudflare);

  // ── Varnish ───────────────────────────────────────────────────────────────
  let varnish = 0;
  if (xVarnish)                varnish += 4;
  if (xCache.includes('hit'))  varnish += 1;
  if (via.includes('varnish')) varnish += 2;
  if (varnish) boost('varnish', varnish);

  // ── Smart TV, IP Camera, PC/Workstation & IoT Devices ─────────────────────
  let deviceScore = 0;
  let customDeviceSummary = null;
  if (html.includes('"samsung smarttv"') || html.includes('"tokenauthsupport"') || html.includes('"frametvsupport"')) {
    deviceScore += 8;
    customDeviceSummary = 'Samsung Smart TV (Tizen)';
  } else if (html.includes('"cast_build_revision"') || html.includes('"ssdp_udn"') || html.includes('"hotspot_bssid"')) {
    deviceScore += 8;
    customDeviceSummary = 'Google TV / Android TV / Chromecast';
  } else if (html.includes('<device-info>') && (html.includes('<wifi-mac>') || html.includes('<vendor-name>roku') || html.includes('<serial-number>'))) {
    deviceScore += 8;
    customDeviceSummary = 'Roku TV / Roku Streaming Device';
  } else if (html.includes('urn:schemas-upnp-org:device:') || html.includes('urn:samsung.com:device:') || html.includes('urn:dial-multiscreen-org:')) {
    deviceScore += 7;
    customDeviceSummary = 'UPnP / DLNA Media Device';
  } else if (server.includes('airtunes') || server.includes('airplay')) {
    deviceScore += 7;
    customDeviceSummary = 'Apple AirPlay / AirTunes Receiver';
  } else if (server.includes('tizen') || server.includes('webos')) {
    deviceScore += 7;
    customDeviceSummary = server.includes('tizen') ? 'Samsung Smart TV (Tizen)' : 'LG webOS Smart TV';
  } else if (html.includes('"statusprm"') && html.includes('"statusfwr"')) {
    deviceScore += 7;
    customDeviceSummary = 'Tasmota Smart Home IoT Device';
  } else if (
    server.includes('app-webs') ||
    server.includes('dnvrs-webs') ||
    server.includes('dvrdvs-webs') ||
    server.includes('hikvision') ||
    html.includes('doc/page/login.asp') ||
    html.includes('rpc2_login') ||
    html.includes('/axis-cgi/') ||
    html.includes('onvif')
  ) {
    deviceScore += 7;
    customDeviceSummary = 'IP Camera / NVR Surveillance Appliance';
  } else if (server.includes('cups') || html.includes('<title>home - cups') || html.includes('<title>printers - cups') || html.includes('cups.org')) {
    deviceScore += 6;
    customDeviceSummary = 'CUPS / IPP Print Server';
  } else if (html.includes('ollama is running')) {
    deviceScore += 7;
    customDeviceSummary = 'Ollama Local LLM Server';
  }
  if (deviceScore) boost('device', deviceScore);

  // ── Client-Side API Communication & Bundle Inspection ────────────────────
  const initialSeenBundleUrls = options.seenBundleUrls instanceof Set
    ? new Set(options.seenBundleUrls)
    : undefined;
  let apiCommunication = null;
  if (options.apiDiscovery !== false && !deviceMode && !deviceScore) {
    try {
      apiCommunication = await inspectApiCommunication(base, fetchWithRetry, {
        rootResponse: res,
        maxBundles: 3,
        maxConfigProbes: 3,
        ...(options.seenBundleUrls instanceof Set ? { seenBundleUrls: options.seenBundleUrls } : {}),
        ...(options.seenConfigUrls instanceof Set ? { seenConfigUrls: options.seenConfigUrls } : {}),
        ...(options.budgetState && typeof options.budgetState === 'object' ? { budgetState: options.budgetState } : {})
      });
      if (apiCommunication) {
        const hasAngularClient = Array.isArray(apiCommunication.clients)
          && apiCommunication.clients.includes('Angular HttpClient');
        const hasAngularBundleFramework = Array.isArray(apiCommunication.frameworks)
          && apiCommunication.frameworks.includes('angular');
        if (hasAngularClient || hasAngularBundleFramework) {
          boost('angular', hasAngularClient ? 4 : 3);
        }
      }
    } catch {
      apiCommunication = null;
    }
  }

  let runtimeSca = null;
  if (options.scaDiscovery !== false && !deviceMode && !deviceScore) {
    try {
      const scaSeen = initialSeenBundleUrls instanceof Set ? initialSeenBundleUrls : options.seenBundleUrls;
      runtimeSca = await detectRuntimeScaFindings(base, fetchWithRetry, {
        rootResponse: res,
        seenBundleUrls: scaSeen,
        maxBundles: 2
      });
      if (scaSeen instanceof Set && options.seenBundleUrls instanceof Set && scaSeen !== options.seenBundleUrls) {
        for (const u of scaSeen) options.seenBundleUrls.add(u);
      }
    } catch {
      runtimeSca = null;
    }
  }

  // ── Lightweight Secondary Fallback Probes (When Homepage Signal is Ambiguous) ──
  const hasHighTier = stack.some(item => (TECH_PRIORITY[item.tech] ?? 1) >= 5 && item.score > 0);

  if (options.deepProbe !== false && !hasHighTier && !deviceMode && !deviceScore && Number(res?.status) !== 401) {

    // Probe 1: /robots.txt
    try {
      const robotsRes = await fetchWithRetry(`${base}/robots.txt`);
      if (robotsRes && robotsRes.status === 200 && typeof robotsRes.text === 'string') {
        const robotsText = robotsRes.text;
        const robotsLower = robotsText.toLowerCase();
        if (robotsLower.includes('user-agent:') || robotsLower.includes('disallow:')) {
          if (/disallow:\s*\/wp-(admin|includes|content)/i.test(robotsText)) boost('wordpress', 5);
          if (/disallow:\s*\/administrator\b/i.test(robotsText)) boost('joomla', 4);
          if (/disallow:\s*\/(core|sites\/default|user\/login)/i.test(robotsText) && robotsLower.includes('drupal')) boost('drupal', 4);
          if (/disallow:\s*\/(downloader|app\/etc|pkginfo)\b/i.test(robotsText)) boost('magento', 4);
          if (/disallow:\s*\/_next\//i.test(robotsText)) boost('nextjs', 4);
        }
      }
    } catch {
      // Ignore probe errors
    }

    // Probe 2: 404 Error Page Signature
    try {
      const probeRes = await fetchWithRetry(`${base}/_secscan_fp_probe_404`);
      if (probeRes) {
        const pHeaders = {};
        for (const [k, v] of Object.entries(probeRes.headers || {})) {
          pHeaders[k.toLowerCase()] = v;
        }
        const pText = (probeRes.text || '').toLowerCase();
        const rawCookie = pHeaders['set-cookie'];
        const pCookie = (Array.isArray(rawCookie) ? rawCookie.join(';') : (rawCookie || '')).toLowerCase();

        if (pText.includes('using the urlconf defined in') || (pText.includes('page not found (404)') && pText.includes('django'))) {
          boost('django', 5);
        }
        if (pText.includes('whitelabel error page') || pText.includes('explicit mapping for /error')) {
          boost('spring', 5);
        }
        if (pText.includes('cannot get /_secscan_fp_probe_404')) {
          boost('express', 5);
        }
        if (pText.includes('next_not_found') || pText.includes('__next')) {
          boost('nextjs', 4);
        }
        if (pCookie.includes('laravel_session') || pCookie.includes('xsrf-token')) {
          boost('laravel', 5);
        }
        if (pCookie.includes('yii_csrf_token') || pText.includes('chttpexception') || pText.includes('cexception') || pText.includes('unable to resolve the request')) {
          boost('yii1', 5);
          boost('yii', 5);
        }
        if (pCookie.includes('_csrf-frontend') || pCookie.includes('_csrf-backend') || pText.includes('yii\\web\\notfoundhttpexception') || pText.includes('yii-debug-toolbar')) {
          boost('yii2', 5);
          boost('yii', 5);
        }
      }
    } catch {
      // Ignore probe errors
    }

    // Probe 3: /requirements.txt (Python / Django / FastAPI fallback)
    try {
      const reqRes = await fetchWithRetry(`${base}/requirements.txt`);
      if (reqRes && reqRes.status === 200 && typeof reqRes.text === 'string') {
        const reqLower = reqRes.text.toLowerCase();
        if (!reqLower.includes('<html') && !reqLower.includes('<!doctype')) {
          if (/\bdjango\s*[=<>~!]/i.test(reqRes.text)) boost('django', 5);
          if (/\bfastapi\s*[=<>~!]/i.test(reqRes.text)) boost('fastapi', 5);
          if (/\bflask\s*[=<>~!]/i.test(reqRes.text)) boost('flask', 5);
          if (/\b(starlette|uvicorn|gunicorn)\s*[=<>~!]/i.test(reqRes.text)) boost('python', 4);
        }
      }
    } catch {
      // Ignore probe errors
    }
  }

  // ── Smart Priority-Weighted Ranking Sorting ──────────────────────────────
  const rankedStack = stack
    .map(item => {
      const priority = TECH_PRIORITY[item.tech] ?? 1;
      return {
        tech: item.tech,
        score: item.score,
        rank: item.score * priority
      };
    })
    .filter(item => item.score > 0)
    .sort((a, b) => b.rank - a.rank);

  const hasStrongWebStack = rankedStack.some(item => item.tech !== 'device' && (TECH_PRIORITY[item.tech] ?? 1) >= 3 && item.score > 0);
  const rootStatus = Number(res?.status || 0);
  const isGenericOrAuth = rootStatus === 401 || rootStatus === 403 || rootStatus === 404 || !hasStrongWebStack || deviceScore > 0;

  let deviceInfo = null;
  if (options.deviceDiscovery !== false && (deviceMode || (isPrivateLanTarget && isGenericOrAuth))) {
    try {
      const devRes = await scanDeviceTarget(normalizedTarget, fetchWithRetry, deviceScanOptions);
      if (devRes?.ok && devRes.deviceProfile?.detected) {
        deviceInfo = devRes.deviceProfile;
      }
    } catch {
      deviceInfo = null;
    }
  }

  let primary = rankedStack[0]?.tech || 'unknown';
  let confidence = rankedStack[0]?.score || 0;
  let detectedTags = inferEcosystemTags(rankedStack);
  let recommendedProfile = recommendProfileForStack(primary, detectedTags);

  const allowDevicePromotion = Boolean(
    deviceInfo &&
    (deviceMode || isPrivateLanTarget || deviceInfo.category !== 'device_web')
  );
  if (deviceInfo && allowDevicePromotion) {
    const devTags = getDeviceCategoryTags(deviceInfo.category);
    detectedTags = Array.from(new Set([...detectedTags, ...devTags]));
    if (!rankedStack.some(s => s.tech === 'device')) {
      rankedStack.push({ tech: 'device', score: 10, rank: 100 });
      rankedStack.sort((a, b) => b.rank - a.rank);
    }
    if (deviceMode || !hasStrongWebStack) {
      primary = 'device';
      confidence = Math.max(confidence, 10);
      recommendedProfile = 'device';
    }
  }

  const categories = {
    frameworks: [],
    frontend: [],
    runtimes: [],
    servers: []
  };

  for (const tag of detectedTags) {
    const cat = CATEGORY_MAP[tag];
    if (cat && !categories[cat].includes(tag)) {
      categories[cat].push(tag);
    }
  }

  const allTechs = [
    ...categories.frameworks,
    ...categories.frontend,
    ...categories.runtimes,
    ...categories.servers
  ];

  const summary = deviceInfo && allowDevicePromotion && (deviceMode || !hasStrongWebStack)
    ? (deviceInfo.summary || customDeviceSummary || 'Smart TV, Camera, PC & IoT Device')
    : customDeviceSummary && primary === 'device'
      ? customDeviceSummary
      : allTechs.length === 0
        ? 'Generic Web Application'
        : allTechs.map(t => TECH_DISPLAY_NAMES[t] || (t.charAt(0).toUpperCase() + t.slice(1))).join(', ');

  const osInfo = detectOperatingSystemFromSignals({
    headers: rawHeaders,
    html: res.text || '',
    deviceInfo,
    openPorts: deviceInfo?.openPorts,
    openServices: deviceInfo?.openServices
  });

  return {
    primary,
    confidence,
    stack: rankedStack,
    detectedTags,
    recommendedProfile,
    categories,
    summary,
    apiCommunication,
    runtimeSca,
    osInfo,
    ...(deviceInfo ? { deviceInfo } : {})
  };
}
