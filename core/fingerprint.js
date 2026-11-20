import { DEFAULT_MAX_HTML_BYTES, inspectApiCommunication } from './api-discovery.js';

/**
 * Priority Tier definition for technologies.
 * Frameworks are given the highest weight, followed by frontend UI, languages/runtimes, and finally server/infrastructure.
 */
export const TECH_PRIORITY = {
  // Tier 1: Frameworks & CMS (Priority 10)
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
  'aspnet': 10,
  'flask': 10,
  'fastapi': 10,

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
  varnish: 'servers'
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
  varnish: 'Varnish'
};

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

  const phpFrameworks = ['laravel', 'wordpress', 'drupal', 'magento', 'codeigniter', 'joomla', 'symfony'];
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
      default: return null;
    }
  };

  const fromPrimary = candidate(primary);
  if (fromPrimary) return fromPrimary;

  const tags = new Set(Array.isArray(detectedTags) ? detectedTags : []);
  const priorityOrder = [
    'laravel', 'wordpress', 'drupal', 'magento', 'symfony', 'codeigniter',
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
  let res;

  try {
    res = await fetchWithRetry(target, { maxBytes: DEFAULT_MAX_HTML_BYTES });
  } catch (e) {
    return {
      primary: 'unknown',
      confidence: 0,
      stack: [],
      detectedTags: [],
      recommendedProfile: 'smart',
      categories: { frameworks: [], frontend: [], runtimes: [], servers: [] },
      summary: 'Unreachable or Unknown',
      apiCommunication: null
    };
  }

  const base = target.replace(/\/+$/, '');
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
  if (html.includes('csrf-token'))           laravel += 3;
  if (html.includes('name="_token"'))        laravel += 3;
  if (html.includes('livewire/livewire.js') || html.includes('wire:initial-data') || html.includes('wire:click')) laravel += 4;
  if (html.includes('inertia') || html.includes('data-page=')) laravel += 3;
  if (html.includes('laravel'))              laravel += 2;
  if (html.includes('illuminate'))           laravel += 1;
  if (laravel) boost('laravel', laravel);

  // ── PHP ───────────────────────────────────────────────────────────────────
  let php = 0;
  if (powered.includes('php'))  php += 5;
  if (html.includes('.php'))    php += 1;
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

  // ── Client-Side API Communication & Bundle Inspection ────────────────────
  let apiCommunication = null;
  if (options.apiDiscovery !== false) {
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

  // ── Lightweight Secondary Fallback Probes (When Homepage Signal is Ambiguous) ──
  const hasHighTier = stack.some(item => (TECH_PRIORITY[item.tech] ?? 1) >= 5 && item.score > 0);

  if (options.deepProbe !== false && !hasHighTier) {

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

  const primary = rankedStack[0]?.tech || 'unknown';
  const confidence = rankedStack[0]?.score || 0;
  const detectedTags = inferEcosystemTags(rankedStack);
  const recommendedProfile = recommendProfileForStack(primary, detectedTags);

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

  const summary = allTechs.length === 0
    ? 'Generic Web Application'
    : allTechs.map(t => TECH_DISPLAY_NAMES[t] || (t.charAt(0).toUpperCase() + t.slice(1))).join(', ');

  return {
    primary,
    confidence,
    stack: rankedStack,
    detectedTags,
    recommendedProfile,
    categories,
    summary,
    apiCommunication
  };
}
