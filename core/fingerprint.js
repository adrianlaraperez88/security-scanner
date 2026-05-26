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
  if (setCookie.includes('laravel_session')) laravel += 4;
  if (html.includes('csrf-token'))           laravel += 2;
  if (html.includes('laravel'))              laravel += 2;
  if (html.includes('illuminate'))           laravel += 1;
  if (laravel) stack.push({ tech: 'laravel', score: laravel });

  // ── PHP ───────────────────────────────────────────────────────────────────
  let php = 0;
  if (powered.includes('php'))  php += 4;
  if (html.includes('.php'))    php += 1;
  if (php) stack.push({ tech: 'php', score: php });

  // ── WordPress ─────────────────────────────────────────────────────────────
  let wp = 0;
  if (html.includes('wp-content'))      wp += 3;
  if (html.includes('wp-json'))         wp += 2;
  if (html.includes('wp-includes'))     wp += 2;
  if (setCookie.includes('wordpress_')) wp += 2;
  if (wp) stack.push({ tech: 'wordpress', score: wp });

  // ── Express / Node.js ────────────────────────────────────────────────────
  let express = 0;
  if (powered.includes('express'))       express += 4;
  if (setCookie.includes('connect.sid')) express += 3;
  if (powered.includes('node'))          express += 2;
  if (express) stack.push({ tech: 'express', score: express });

  // ── Django ────────────────────────────────────────────────────────────────
  let django = 0;
  if (setCookie.includes('csrftoken'))                                    django += 4;
  if (setCookie.includes('sessionid') && !setCookie.includes('laravel')) django += 2;
  if (html.includes('django'))                                            django += 2;
  if (django) stack.push({ tech: 'django', score: django });

  // ── Rails ─────────────────────────────────────────────────────────────────
  let rails = 0;
  if (runtime && /^\d+\.\d+$/.test(runtime)) rails += 3;
  if (setCookie.includes('_session_id'))       rails += 3;
  if (h['x-request-id'] && runtime)           rails += 1;
  if (rails) stack.push({ tech: 'rails', score: rails });

  // ── Spring Boot ────────────────────────────────────────────────────────────
  let spring = 0;
  if (setCookie.includes('jsessionid'))   spring += 4;
  if (h['x-application-context'])         spring += 3;
  if (html.includes('spring'))            spring += 1;
  if (spring) stack.push({ tech: 'spring', score: spring });

  // ── ASP.NET ────────────────────────────────────────────────────────────────
  let aspnet = 0;
  if (powered.includes('asp.net'))              aspnet += 4;
  if (h['x-aspnet-version'])                    aspnet += 3;
  if (setCookie.includes('asp.net_sessionid'))  aspnet += 3;
  if (html.includes('.aspx'))                   aspnet += 1;
  if (aspnet) stack.push({ tech: 'aspnet', score: aspnet });

  // ── Drupal (improved — HTTP headers are the most reliable signal) ─────────
  let drupal = 0;
  if (generator.includes('drupal'))                    drupal += 5;  // X-Generator: Drupal 10 (...)
  if (h['x-drupal-cache'])                             drupal += 4;  // X-Drupal-Cache: MISS
  if (h['x-drupal-dynamic-cache'])                     drupal += 4;  // X-Drupal-Dynamic-Cache: MISS
  if (html.includes('drupal'))                         drupal += 2;
  if (html.includes('/sites/default/files'))           drupal += 2;
  if (html.includes('drupal-'))                        drupal += 1;  // class="drupal-*"
  if (drupal) stack.push({ tech: 'drupal', score: drupal });

  // ── Magento ────────────────────────────────────────────────────────────────
  let magento = 0;
  if (h['x-magento-cache-id'])           magento += 5;  // Strongest Magento signal
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
  if (html.includes('a php error was encountered'))             codeigniter += 4;  // classic CI error page
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

  // ── Angular (including 18+) ────────────────────────────────────────────────
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
  if (html.includes('__next_data__'))               react += 2; // Next.js is React
  if (react) stack.push({ tech: 'react', score: react });

  // ── Vue ───────────────────────────────────────────────────────────────────
  let vue = 0;
  if (html.includes('data-v-'))                     vue += 4; // Scoped CSS
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
    if (!react) stack.push({ tech: 'react', score: 3 }); // Ensure React is tagged
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

  stack.sort((a, b) => b.score - a.score);

  return {
    primary   : stack[0]?.tech || 'unknown',
    confidence: stack[0]?.score || 0,
    stack
  };
}