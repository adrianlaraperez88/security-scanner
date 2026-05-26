/**
 * Priority Tier definition for technologies.
 * Frameworks are given the highest weight, followed by frontend UI, languages/runtimes, and finally server/infrastructure.
 */
const TECH_PRIORITY = {
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

  // Tier 2: Frontend UI & Frameworks (Priority 5)
  'react': 5,
  'vue': 5,
  'angular': 5,

  // Tier 3: Languages & Runtimes (Priority 3)
  'php': 3,

  // Tier 4: Server, CDN & Caching (Priority 1)
  'nginx': 1,
  'apache': 1,
  'cloudflare': 1,
  'varnish': 1
};

export async function fingerprint(target, fetchWithRetry) {
  let res;

  try {
    res = await fetchWithRetry(target);
  } catch (e) {
    return { primary: 'unknown', confidence: 0, stack: [] };
  }

  const html = res.text.toLowerCase();
  const h    = res.headers || {};

  // ── Header signals (most reliable) ────────────────────────────────────────
  const powered   = (h['x-powered-by']    || '').toLowerCase();
  const server    = (h['server']           || '').toLowerCase();
  const setCookie = (h['set-cookie']       || '').toLowerCase();
  const via       = (h['via']              || '').toLowerCase();
  const generator = (h['x-generator']     || '').toLowerCase();
  const runtime   = (h['x-runtime']       || '').toLowerCase();   // Rails
  const cfRay     = (h['cf-ray']          || '');
  const xVarnish  = (h['x-varnish']       || '');
  const xCache    = (h['x-cache']         || '').toLowerCase();

  const stack = [];

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
  if (laravel) stack.push({ tech: 'laravel', score: laravel });

  // ── PHP ───────────────────────────────────────────────────────────────────
  let php = 0;
  if (powered.includes('php'))  php += 5;
  if (html.includes('.php'))    php += 1;
  if (php) stack.push({ tech: 'php', score: php });

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
  if (wp) stack.push({ tech: 'wordpress', score: wp });

  // ── Express / Node.js ────────────────────────────────────────────────────
  let express = 0;
  if (powered.includes('express'))       express += 5;
  if (setCookie.includes('connect.sid')) express += 4;
  if (powered.includes('node'))          express += 2;
  if (express) stack.push({ tech: 'express', score: express });

  // ── Django ────────────────────────────────────────────────────────────────
  let django = 0;
  if (html.includes('csrfmiddlewaretoken') || html.includes('name="csrfmiddlewaretoken"')) django += 5;
  if (setCookie.includes('csrftoken'))                                    django += 5;
  if (setCookie.includes('sessionid') && !setCookie.includes('laravel')) django += 3;
  if (html.includes('/static/admin/'))                                    django += 3;
  if (html.includes('django'))                                            django += 2;
  if (django) stack.push({ tech: 'django', score: django });

  // ── Rails ─────────────────────────────────────────────────────────────────
  let rails = 0;
  if (runtime && /^\d+\.\d+$/.test(runtime)) rails += 4;
  if (setCookie.includes('_session_id'))       rails += 4;
  if (html.includes('csrf-param') && html.includes('authenticity_token')) rails += 4;
  if (h['x-request-id'] && runtime)           rails += 2;
  if (rails) stack.push({ tech: 'rails', score: rails });

  // ── Spring Boot ────────────────────────────────────────────────────────────
  let spring = 0;
  if (setCookie.includes('jsessionid'))   spring += 5;
  if (h['x-application-context'])         spring += 3;
  if (html.includes('whitelabel error page') || html.includes('this application has no explicit mapping for /error')) spring += 5;
  if (html.includes('spring'))            spring += 1;
  if (spring) stack.push({ tech: 'spring', score: spring });

  // ── ASP.NET ────────────────────────────────────────────────────────────────
  let aspnet = 0;
  if (powered.includes('asp.net'))              aspnet += 5;
  if (h['x-aspnet-version'])                    aspnet += 4;
  if (setCookie.includes('asp.net_sessionid'))  aspnet += 4;
  if (setCookie.includes('__requestverificationtoken')) aspnet += 4;
  if (html.includes('__viewstate') || html.includes('__eventvalidation')) aspnet += 4;
  if (html.includes('.aspx'))                   aspnet += 1;
  if (aspnet) stack.push({ tech: 'aspnet', score: aspnet });

  // ── Drupal ───────────────────────────────────
  let drupal = 0;
  if (generator.includes('drupal') || html.includes('<meta name="generator" content="drupal')) drupal += 5;
  if (h['x-drupal-cache'])                             drupal += 4;
  if (h['x-drupal-dynamic-cache'])                     drupal += 4;
  if (html.includes('drupalsettings') || html.includes('data-drupal-')) drupal += 4;
  if (html.includes('/sites/default/files'))           drupal += 3;
  if (html.includes('drupal'))                         drupal += 2;
  if (drupal) stack.push({ tech: 'drupal', score: drupal });

  // ── Magento ────────────────────────────────────────────────────────────────
  let magento = 0;
  if (h['x-magento-cache-id'])           magento += 5;
  if (h['x-magento-tags'])               magento += 4;
  if (h['x-magento-vary'])               magento += 3;
  if (html.includes('mage.cookies'))     magento += 3;
  if (html.includes('mage_'))            magento += 2;
  if (html.includes('magento'))          magento += 2;
  if (html.includes('/pub/static/'))     magento += 1;
  if (magento) stack.push({ tech: 'magento', score: magento });

  // ── CodeIgniter ───────────────────────────────────────────────────────────
  let codeigniter = 0;
  if (setCookie.includes('ci_session'))                         codeigniter += 5;
  if (html.includes('a php error was encountered'))             codeigniter += 4;
  if (html.includes('codeigniter'))                             codeigniter += 3;
  if (html.includes('/index.php/welcome'))                      codeigniter += 3;
  if (html.includes('ci_csrf_token'))                           codeigniter += 2;
  if (codeigniter) stack.push({ tech: 'codeigniter', score: codeigniter });

  // ── Joomla ────────────────────────────────────────────────────────────────
  let joomla = 0;
  if (html.includes('/components/com_'))    joomla += 3;
  if (setCookie.includes('joomla_session')) joomla += 3;
  if (html.includes('joomla'))              joomla += 1;
  if (joomla) stack.push({ tech: 'joomla', score: joomla });

  // ── Symfony ────────────────────────────────────────────────────────────────
  let symfony = 0;
  if (html.includes('sf-toolbar') || html.includes('sfminitoolbar')) symfony += 5;
  if (setCookie.includes('symfony') || setCookie.includes('sf_redirect')) symfony += 4;
  if (html.includes('/_wdt/') || html.includes('/_profiler/')) symfony += 4;
  if (symfony) stack.push({ tech: 'symfony', score: symfony });

  // ── Angular ────────────────────────────────────────────────
  let angular = 0;
  if (html.includes('ng-version'))                   angular += 5;
  if (html.includes('ng-component'))                 angular += 3;
  if (html.includes('<app-root'))                    angular += 3;
  if (html.includes('polyfills.js') && html.includes('main.js')) angular += 2;
  if (angular) stack.push({ tech: 'angular', score: angular });

  // ── React ─────────────────────────────────────────────────────────────────
  let react = 0;
  if (html.includes('data-reactroot'))              react += 4;
  if (html.includes('react-dom'))                   react += 3;
  if (html.includes('__next_data__'))               react += 2;
  if (react) stack.push({ tech: 'react', score: react });

  // ── Vue ───────────────────────────────────────────────────────────────────
  let vue = 0;
  if (html.includes('data-v-'))                     vue += 4;
  if (html.includes('vue.js') || html.includes('vue.runtime')) vue += 3;
  if (html.includes('__vue_app__'))                 vue += 2;
  if (vue) stack.push({ tech: 'vue', score: vue });

  // ── Next.js ───────────────────────────────────────────────────────────────
  let nextjs = 0;
  if (html.includes('__next_data__'))  nextjs += 4;
  if (html.includes('/_next/static'))  nextjs += 3;
  if (h['x-nextjs-page'])              nextjs += 3;
  if (nextjs) {
    stack.push({ tech: 'nextjs', score: nextjs });
    if (!react) stack.push({ tech: 'react', score: 3 });
  }

  // ── Nginx ─────────────────────────────────────────────────────────────────
  let nginx = 0;
  if (server.includes('nginx')) nginx += 3;
  if (nginx) stack.push({ tech: 'nginx', score: nginx });

  // ── Apache ────────────────────────────────────────────────────────────────
  let apache = 0;
  if (server.includes('apache')) apache += 3;
  if (apache) stack.push({ tech: 'apache', score: apache });

  // ── Cloudflare ────────────────────────────────────────────────────────────
  let cloudflare = 0;
  if (cfRay)                         cloudflare += 4;
  if (server.includes('cloudflare')) cloudflare += 3;
  if (cloudflare) stack.push({ tech: 'cloudflare', score: cloudflare });

  // ── Varnish ───────────────────────────────────────────────────────────────
  let varnish = 0;
  if (xVarnish)                varnish += 4;
  if (xCache.includes('hit'))  varnish += 1;
  if (via.includes('varnish')) varnish += 2;
  if (varnish) stack.push({ tech: 'varnish', score: varnish });

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

  return {
    primary   : rankedStack[0]?.tech || 'unknown',
    confidence: rankedStack[0]?.score || 0,
    stack: rankedStack
  };
}