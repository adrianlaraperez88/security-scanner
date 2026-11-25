import http from 'node:http';
import zlib from 'node:zlib';

export const HARDENED_SECURITY_HEADERS = {
  'Content-Security-Policy': "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
};

function readBody(req) {
  return new Promise(resolve => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', () => resolve(''));
  });
}

function sendRouteResponse(res, spec, activeTimers) {
  const status = spec.status ?? 200;
  const headers = { ...(spec.headers || {}) };
  let payload = spec.body ?? '';

  if (typeof payload === 'object' && !Buffer.isBuffer(payload)) {
    payload = JSON.stringify(payload);
    if (!Object.keys(headers).some(k => k.toLowerCase() === 'content-type')) {
      headers['Content-Type'] = 'application/json; charset=utf-8';
    }
  } else if (typeof payload === 'string') {
    if (!Object.keys(headers).some(k => k.toLowerCase() === 'content-type')) {
      headers['Content-Type'] = payload.trimStart().startsWith('<')
        ? 'text/html; charset=utf-8'
        : 'text/plain; charset=utf-8';
    }
  }

  let bodyBuf = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload), 'utf8');
  if (spec.gzip) {
    bodyBuf = zlib.gzipSync(bodyBuf);
    headers['Content-Encoding'] = 'gzip';
  }
  headers['Content-Length'] = bodyBuf.length;

  const finalize = () => {
    if (res.writableEnded || res.destroyed) return;
    res.writeHead(status, headers);
    res.end(bodyBuf);
  };

  if (spec.hang) {
    // Keep socket open until closed/aborted by client or server teardown
    return;
  }

  if (spec.delayMs && spec.delayMs > 0) {
    const timer = setTimeout(() => {
      activeTimers.delete(timer);
      finalize();
    }, spec.delayMs);
    activeTimers.add(timer);
    res.on('close', () => {
      clearTimeout(timer);
      activeTimers.delete(timer);
    });
    return;
  }

  finalize();
}

/**
 * Starts a programmable `node:http` mock target bound strictly to `127.0.0.1:0`.
 *
 * @param {object} [options]
 * @param {object|Function} [options.routes] Map of path -> response spec/fn, or dynamic handler(reqInfo, req, res)
 * @param {object} [options.defaultHeaders]
 * @param {object} [options.defaultResponse]
 * @param {boolean} [options.logRequests=true]
 */
export async function startMockTarget(options = {}) {
  const requests = [];
  const activeTimers = new Set();
  let routes = options.routes || {};
  const defaultHeaders = options.defaultHeaders || {};
  const defaultResponse = options.defaultResponse || { status: 404, body: 'Not Found' };
  const logRequests = options.logRequests !== false;

  const server = http.createServer(async (req, res) => {
    const rawUrl = req.url || '/';
    const parsedUrl = new URL(rawUrl, 'http://127.0.0.1');
    const pathname = parsedUrl.pathname;
    const body = await readBody(req);

    const reqInfo = {
      method: (req.method || 'GET').toUpperCase(),
      url: rawUrl,
      pathname,
      search: parsedUrl.search,
      searchParams: parsedUrl.searchParams,
      headers: { ...req.headers },
      body,
      timestamp: Date.now()
    };

    if (logRequests) {
      requests.push(reqInfo);
    }

    if (typeof routes === 'function') {
      const handled = await routes(reqInfo, req, res, {
        send: spec => sendRouteResponse(res, { ...spec, headers: { ...defaultHeaders, ...(spec.headers || {}) } }, activeTimers)
      });
      if (handled !== false && (res.headersSent || res.writableEnded)) {
        return;
      }
      if (handled && typeof handled === 'object') {
        sendRouteResponse(
          res,
          { ...handled, headers: { ...defaultHeaders, ...(handled.headers || {}) } },
          activeTimers
        );
        return;
      }
      sendRouteResponse(
        res,
        { ...defaultResponse, headers: { ...defaultHeaders, ...(defaultResponse.headers || {}) } },
        activeTimers
      );
      return;
    }

    let decodedPathname = pathname;
    try {
      decodedPathname = decodeURIComponent(pathname);
    } catch {
      decodedPathname = pathname;
    }
    const methodKey = `${reqInfo.method} ${pathname}`;
    const decodedMethodKey = `${reqInfo.method} ${decodedPathname}`;
    const fullKey = `${reqInfo.method} ${rawUrl}`;
    const match =
      routes[fullKey] ??
      routes[methodKey] ??
      routes[decodedMethodKey] ??
      routes[rawUrl] ??
      routes[pathname] ??
      routes[decodedPathname] ??
      null;

    let spec = null;
    if (typeof match === 'function') {
      spec = await match(reqInfo, req, res);
      if (res.headersSent || res.writableEnded) return;
    } else if (match && typeof match === 'object') {
      spec = match;
    }

    const chosen = spec || defaultResponse;
    sendRouteResponse(
      res,
      {
        ...chosen,
        headers: { ...defaultHeaders, ...(chosen.headers || {}) }
      },
      activeTimers
    );
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });

  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  const baseUrl = `http://127.0.0.1:${port}`;

  return {
    server,
    port,
    host: '127.0.0.1',
    baseUrl,
    requests,
    resetRequests() {
      requests.length = 0;
    },
    setRoutes(nextRoutes) {
      routes = nextRoutes;
    },
    async close() {
      for (const t of activeTimers) {
        clearTimeout(t);
      }
      activeTimers.clear();
      server.closeAllConnections?.();
      await new Promise(resolve => server.close(() => resolve()));
    }
  };
}

export async function withMockTarget(options, fn) {
  const target = await startMockTarget(options);
  try {
    return await fn(target);
  } finally {
    await target.close();
  }
}

/**
 * Builds deterministic preset configurations for clean-hardened targets,
 * all 8 M3 CVE ecosystems, NGINX HTTP/2, and multi-stack scenarios.
 *
 * @param {string} preset
 * @param {string} [variant='vulnerable']
 */
export function buildStackPresetConfig(preset, variant = 'vulnerable') {
  const key = String(preset || '').toLowerCase();
  const v = String(variant || 'vulnerable').toLowerCase();

  if (key === 'clean-hardened') {
    return {
      defaultHeaders: { ...HARDENED_SECURITY_HEADERS },
      defaultResponse: { status: 404, body: 'Not Found' },
      routes: {
        '/': {
          status: 200,
          headers: { 'Content-Type': 'text/html; charset=utf-8' },
          body: '<!DOCTYPE html><html><head><title>Hardened App</title></head><body><h1>Welcome</h1></body></html>'
        },
        '/robots.txt': {
          status: 200,
          headers: { 'Content-Type': 'text/plain; charset=utf-8' },
          body: 'User-agent: *\nDisallow: /private/\n'
        }
      }
    };
  }

  if (key === 'nginx') {
    const serverBanner =
      v === 'patched'
        ? 'nginx/1.30.7'
        : v === 'backport'
          ? 'nginx/1.24.0 (Ubuntu)'
          : v === 'suppressed'
            ? 'nginx'
            : 'nginx/1.28.0';
    return {
      defaultHeaders: {
        ...HARDENED_SECURITY_HEADERS,
        'X-RateLimit-Limit': '1000',
        'X-RateLimit-Remaining': '999',
        Server: serverBanner,
        'Alt-Svc': 'h2=":443"; ma=86400'
      },
      defaultResponse: { status: 404, body: '404 Not Found' },
      routes: {
        '/': {
          status: 200,
          body: '<!DOCTYPE html><html><body><h1>Edge Proxy</h1></body></html>'
        }
      }
    };
  }

  if (key === 'nextjs') {
    if (v === 'patched') {
      return {
        defaultHeaders: {
          ...HARDENED_SECURITY_HEADERS,
          'X-Powered-By': 'Next.js',
          'X-Nextjs-Version': '15.5.7'
        },
        defaultResponse: { status: 404, body: 'Not Found' },
        routes: {
          '/': {
            status: 200,
            body: '<!DOCTYPE html><html><head><script src="/_next/static/chunks/main.js"></script></head><body><script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"ok":true}},"page":"/","buildId":"prod-patched"}</script></body></html>'
          },
          '/admin': { status: 403, body: 'Forbidden' },
          '/dashboard': { status: 403, body: 'Forbidden' }
        }
      };
    }

    return {
      defaultHeaders: {
        'X-Powered-By': 'Next.js',
        'X-Nextjs-Version': '15.1.0',
        Vary: 'RSC, Next-Router-State-Tree, Next-Router-Prefetch, Next-Url'
      },
      defaultResponse: { status: 404, body: 'Not Found' },
      routes: async reqInfo => {
        const p = reqInfo.pathname;
        // CVE-2025-29927 middleware bypass
        if (p === '/admin' || p === '/dashboard') {
          if (reqInfo.headers['x-middleware-subrequest']) {
            return {
              status: 200,
              body: '<html><body><h1>Admin Panel</h1><p>Internal users: admin@internal.local</p></body></html>'
            };
          }
          return { status: 403, body: 'Forbidden' };
        }
        // CVE-2024-46982 cache poisoning on __nextDataReq / x-now-route-matches
        if (reqInfo.headers['x-now-route-matches'] || reqInfo.searchParams.has('__nextDataReq')) {
          return {
            status: 200,
            headers: {
              'Content-Type': 'application/json; charset=utf-8',
              'Cache-Control': 'public, max-age=3600',
              'x-nextjs-cache': 'HIT'
            },
            body: { pageProps: { user: 'cached-session' }, __N_SSP: true }
          };
        }
        // CVE-2025-55182 React Server Components / Server Actions
        if (reqInfo.method === 'POST' && reqInfo.headers['next-action']) {
          const reflectedHost = reqInfo.headers['x-forwarded-host'] || reqInfo.headers['host'] || '127.0.0.1';
          return {
            status: 200,
            headers: {
              'Content-Type': 'text/x-component; charset=utf-8',
              'X-Action-Redirect': `http://${reflectedHost}/dashboard`
            },
            body: '0:["$@1",["development",null]]\n1:{"ok":true,"react":"19.1.0"}\n'
          };
        }
        if (p === '/package.json') {
          return {
            status: 200,
            body: {
              name: 'nextjs-vuln-app',
              version: '1.0.0',
              dependencies: { next: '15.1.0', react: '19.1.0', 'react-dom': '19.1.0' }
            }
          };
        }
        if (p === '/_next/static/chunks/main.js.map') {
          return {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
            body: { version: 3, sources: ['webpack:///./pages/index.js'], names: [] }
          };
        }
        if (p === '/_buildManifest.js') {
          return {
            status: 200,
            headers: { 'Content-Type': 'application/javascript' },
            body: 'self.__BUILD_MANIFEST={sortedPages:["/","/admin","/dashboard"]};'
          };
        }
        if (p === '/') {
          return {
            status: 200,
            headers: { 'Content-Type': 'text/html; charset=utf-8' },
            body: '<!DOCTYPE html><html><head><script src="/_next/static/chunks/main.js"></script></head><body><div id="__next">App</div><script>self.__next_f.push([1,"0:{\"react\":\"19.1.0\"}"])</script><script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"NEXT_PUBLIC_API_KEY":"pk_live_mock_secret"}},"page":"/","buildId":"dev-15.1.0"}</script></body></html>'
          };
        }
        return null;
      }
    };
  }

  if (key === 'spring') {
    if (v === 'patched' || v === 'mitigated' || v === 'arm64') {
      const isArm = v === 'mitigated' || v === 'arm64';
      return {
        defaultHeaders: {
          ...HARDENED_SECURITY_HEADERS,
          'Set-Cookie': 'JSESSIONID=SAFE123; Path=/; HttpOnly; SameSite=Strict',
          ...(isArm ? { 'X-Os-Arch': 'aarch64', 'X-Java-Version': '21.0.13' } : { 'X-Java-Version': '21.0.14' })
        },
        defaultResponse: { status: 404, body: 'Not Found' },
        routes: {
          '/': {
            status: 200,
            body: '<!DOCTYPE html><html><body><h1>Spring Boot Patched</h1></body></html>'
          },
          '/actuator/info': {
            status: 200,
            body: {
              java: { version: isArm ? '21.0.13' : '21.0.14', vendor: { name: 'Eclipse Adoptium' } },
              os: { name: 'Linux', arch: isArm ? 'aarch64' : 'amd64' },
              springBoot: { version: '3.4.5' },
              springFramework: { version: '6.2.6' }
            }
          },
          '/actuator/health': { status: 200, body: { status: 'UP' } },
          '/actuator/env': { status: 404, body: { error: 'Not Found' } },
          '/actuator/heapdump': { status: 404, body: { error: 'Not Found' } },
          '/actuator/mappings': { status: 404, body: { error: 'Not Found' } }
        }
      };
    }

    return {
      defaultHeaders: {
        'Set-Cookie': 'JSESSIONID=SPRINGVULN123; Path=/',
        'X-Application-Context': 'billing:prod:8080',
        Server: 'Apache-Coyote/1.1 OpenJDK/21.0.13 (x86-64)',
        'X-Java-Version': '21.0.13',
        'X-Os-Arch': 'amd64'
      },
      defaultResponse: { status: 404, body: 'Whitelabel Error Page\nThis application has no explicit mapping for /error' },
      routes: async reqInfo => {
        const p = reqInfo.pathname;
        // Static path traversal probe (CVE-2024-38816 / CVE-2024-38819)
        if (reqInfo.url.includes('..%2f') || reqInfo.url.includes('%2e%2e') || p.includes('/etc/passwd')) {
          return { status: 200, body: 'root:x:0:0:root:/root:/bin/bash\n' };
        }
        // Open redirect via UriComponentsBuilder (CVE-2024-22262)
        const targetRedirect = reqInfo.searchParams.get('url') || reqInfo.searchParams.get('redirect');
        if (targetRedirect) {
          if (/[\r\n\u0000-\u001f\u007f]/.test(targetRedirect)) {
            return { status: 400, body: 'Bad Request' };
          }
          return { status: 302, headers: { Location: targetRedirect }, body: '' };
        }
        if (p === '/') {
          return {
            status: 200,
            headers: { 'Content-Type': 'text/html; charset=utf-8' },
            body: '<!DOCTYPE html><html><body><h1>Spring Boot Billing API</h1></body></html>'
          };
        }
        if (p === '/error') {
          return {
            status: 500,
            body: '<html><body><h1>Whitelabel Error Page</h1><p>This application has no explicit mapping for /error</p></body></html>'
          };
        }
        if (p === '/actuator/info') {
          return {
            status: 200,
            body: {
              app: { name: 'billing-service', version: '1.0.0' },
              java: { version: '21.0.13', vendor: { name: 'Eclipse Adoptium' } },
              os: { name: 'Linux', arch: 'amd64' },
              springBoot: { version: '3.3.3' },
              springFramework: { version: '6.1.12' }
            }
          };
        }
        if (p === '/actuator/env') {
          return {
            status: 200,
            body: {
              activeProfiles: ['prod'],
              propertySources: [
                {
                  name: 'systemProperties',
                  properties: {
                    'java.runtime.version': { value: '21.0.13+7' },
                    'os.arch': { value: 'amd64' },
                    'java.class.path': { value: '/app/libs/spring-boot-3.3.3.jar:/app/libs/spring-webmvc-6.1.12.jar' }
                  }
                }
              ]
            }
          };
        }
        if (p === '/actuator/health') {
          return { status: 200, body: { status: 'UP' } };
        }
        if (p === '/actuator/mappings') {
          return { status: 200, body: { contexts: { application: { mappings: { dispatcherServlets: {} } } } } };
        }
        if (p === '/actuator/heapdump') {
          return { status: 200, headers: { 'Content-Type': 'application/octet-stream' }, body: 'JAVA PROFILE 1.0.2' };
        }
        if (p === '/v3/api-docs') {
          return { status: 200, body: { openapi: '3.0.1', info: { title: 'Billing API', version: '3.3.3' } } };
        }
        return null;
      }
    };
  }

  if (key === 'tomcat') {
    if (v === 'patched') {
      return {
        defaultHeaders: { ...HARDENED_SECURITY_HEADERS, Server: 'Apache Tomcat/10.1.41' },
        defaultResponse: { status: 404, body: 'Not Found' },
        routes: {
          '/': { status: 200, body: '<!DOCTYPE html><html><body><h1>Tomcat Patched</h1></body></html>' },
          'OPTIONS /': { status: 200, headers: { Allow: 'GET, HEAD, POST, OPTIONS' }, body: '' }
        }
      };
    }
    if (v === 'backport') {
      return {
        defaultHeaders: { ...HARDENED_SECURITY_HEADERS, Server: 'Apache Tomcat/9.0.70 (Debian)' },
        defaultResponse: { status: 404, body: 'Not Found' },
        routes: {
          '/': { status: 200, body: '<!DOCTYPE html><html><body><h1>Tomcat Debian Backport</h1></body></html>' },
          'OPTIONS /': { status: 200, headers: { Allow: 'GET, HEAD, POST, OPTIONS' }, body: '' }
        }
      };
    }
    return {
      defaultHeaders: {
        Server: 'Apache Tomcat/10.1.30',
        'Set-Cookie': 'JSESSIONID=TOMCATVULN; Path=/',
        'Alt-Svc': 'h2=":443"; ma=86400'
      },
      defaultResponse: {
        status: 404,
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
        body: '<!doctype html><html lang="en"><head><title>HTTP Status 404 – Not Found</title></head><body><h1>HTTP Status 404 – Not Found</h1><hr class="line" /><h3>Apache Tomcat/10.1.30</h3></body></html>'
      },
      routes: {
        '/': {
          status: 200,
          body: '<!DOCTYPE html><html><head><title>Apache Tomcat/10.1.30</title></head><body><h1>Apache Tomcat/10.1.30</h1></body></html>'
        },
        'OPTIONS /': {
          status: 200,
          headers: { Allow: 'GET, HEAD, POST, PUT, DELETE, OPTIONS' },
          body: ''
        }
      }
    };
  }

  if (key === 'apache') {
    const serverHeader =
      v === 'patched'
        ? 'Apache/2.4.63 (Unix)'
        : v === 'backport'
          ? 'Apache/2.4.52 (Ubuntu)'
          : v === 'suppressed'
            ? 'Apache'
            : 'Apache/2.4.58 (Unix) OpenSSL/3.0.13';
    const extraHeaders =
      v === 'vulnerable'
        ? { 'Alt-Svc': 'h2=":443"; ma=86400', Via: '1.1 backend-proxy' }
        : { ...HARDENED_SECURITY_HEADERS };
    return {
      defaultHeaders: {
        ...extraHeaders,
        Server: serverHeader
      },
      defaultResponse: { status: 404, body: 'Not Found' },
      routes: {
        '/': {
          status: 200,
          body: `<!DOCTYPE html><html><body><h1>${serverHeader}</h1></body></html>`
        }
      }
    };
  }

  if (key === 'wordpress') {
    if (v === 'patched') {
      return {
        defaultHeaders: { ...HARDENED_SECURITY_HEADERS, 'X-Generator': 'WordPress 6.7.2' },
        defaultResponse: { status: 404, body: 'Not Found' },
        routes: {
          '/': {
            status: 200,
            body: '<!DOCTYPE html><html><head><meta name="generator" content="WordPress 6.7.2" /></head><body><link rel="stylesheet" href="/wp-content/themes/twentytwentyfive/style.css"></body></html>'
          },
          '/wp-content/plugins/really-simple-ssl/readme.txt': { status: 200, body: '=== Really Simple Security ===\nStable tag: 9.1.2\n' },
          '/wp-json/wp/v2/users': { status: 401, body: { code: 'rest_forbidden' } },
          'POST /xmlrpc.php': { status: 403, body: 'Forbidden' }
        }
      };
    }

    return {
      defaultHeaders: {
        'X-Generator': 'WordPress 6.4.2'
      },
      defaultResponse: { status: 404, body: 'Not Found' },
      routes: {
        '/': {
          status: 200,
          body: '<!DOCTYPE html><html><head><meta name="generator" content="WordPress 6.4.2" /><script src="/wp-includes/js/jquery/jquery.min.js?ver=6.4.2"></script><link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css"></head><body><h1>WordPress Blog</h1></body></html>'
        },
        '/readme.html': {
          status: 200,
          body: '<html><head><title>WordPress &rsaquo; ReadMe</title></head><body><h1>WordPress</h1><p>Version 6.4.2</p></body></html>'
        },
        '/wp-content/plugins/really-simple-ssl/readme.txt': {
          status: 200,
          body: '=== Really Simple SSL ===\nRequires at least: 5.8\nStable tag: 9.0.0\n'
        },
        '/wp-json/reallysimplessl/v1/': {
          status: 200,
          body: { namespace: 'reallysimplessl/v1', routes: {} }
        },
        '/wp-json/wp/v2/users': {
          status: 200,
          body: [{ id: 1, name: 'admin', slug: 'admin' }]
        },
        'POST /xmlrpc.php': {
          status: 200,
          headers: { 'Content-Type': 'text/xml; charset=utf-8' },
          body: '<?xml version="1.0"?><methodResponse><params><param><value><array><data><value><string>system.listMethods</string></value></data></array></value></param></params></methodResponse>'
        },
        '/wp-login.php': {
          status: 200,
          body: '<html><body><form name="loginform" id="loginform" action="/wp-login.php" method="post"><input type="text" name="log" id="user_login" /><input type="password" name="pwd" id="user_pass" /><input type="submit" name="wp-submit" id="wp-submit" value="Log In" /></form></body></html>'
        }
      }
    };
  }

  if (key === 'python') {
    if (v === 'patched') {
      return {
        defaultHeaders: { ...HARDENED_SECURITY_HEADERS, Server: 'uvicorn' },
        defaultResponse: { status: 404, body: 'Not Found' },
        routes: {
          '/': {
            status: 200,
            body: '<!DOCTYPE html><html><body><input type="hidden" name="csrfmiddlewaretoken" value="safe123"></body></html>'
          }
        }
      };
    }

    return {
      defaultHeaders: {
        Server: 'WSGIServer/0.2 CPython/3.11.6 uvicorn',
        'Set-Cookie': 'csrftoken=pycsrftoken123; Path=/; sessionid=pysession123; Path=/'
      },
      defaultResponse: {
        status: 404,
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
        body: '<!DOCTYPE html><html><head><title>Page not found at /</title></head><body><h1>Page not found (404)</h1><p>Using the URLconf defined in <code>app.urls</code>, Django tried these URL patterns...</p><p>Django Version: 4.2.15</p><p>You\'re seeing this error because you have <code>DEBUG = True</code> in your Django settings file.</p></body></html>'
      },
      routes: {
        '/': {
          status: 200,
          body: '<!DOCTYPE html><html><head><link rel="stylesheet" href="/static/admin/css/base.css"></head><body><form><input type="hidden" name="csrfmiddlewaretoken" value="tok123"></form></body></html>'
        },
        '/requirements.txt': {
          status: 200,
          body: 'Django==4.2.15\nstarlette==0.38.6\nfastapi==0.112.0\nuvicorn==0.30.0\n'
        },
        '/openapi.json': {
          status: 200,
          body: {
            openapi: '3.1.0',
            info: { title: 'FastAPI Service', version: '0.112.0' },
            paths: { '/items': { get: { summary: 'List Items' } } }
          }
        },
        '/docs': {
          status: 200,
          body: '<!DOCTYPE html><html><head><title>FastAPI - Swagger UI</title></head><body><div id="swagger-ui"></div></body></html>'
        }
      }
    };
  }

  if (key === 'node') {
    if (v === 'patched') {
      return {
        defaultHeaders: { ...HARDENED_SECURITY_HEADERS },
        defaultResponse: { status: 404, body: 'Not Found' },
        routes: {
          '/': {
            status: 200,
            body: '<!DOCTYPE html><html><body><h1>Node API Patched</h1></body></html>'
          }
        }
      };
    }

    return {
      defaultHeaders: {
        'X-Powered-By': 'Express',
        'Set-Cookie': 'connect.sid=s%3Amocksid; Path=/'
      },
      defaultResponse: { status: 404, body: 'Cannot GET /missing' },
      routes: {
        '/': {
          status: 200,
          body: '<!DOCTYPE html><html><body><h1>Express Node Service</h1></body></html>'
        },
        '/package.json': {
          status: 200,
          body: {
            name: 'vuln-express-api',
            version: '1.0.0',
            dependencies: {
              express: '4.18.2',
              ws: '8.16.0',
              axios: '1.7.2'
            }
          }
        },
        '/node_modules/express/package.json': {
          status: 200,
          body: { name: 'express', version: '4.18.2' }
        },
        '/package-lock.json': {
          status: 200,
          body: {
            name: 'vuln-express-api',
            lockfileVersion: 3,
            packages: {
              'node_modules/express': { version: '4.18.2' },
              'node_modules/ws': { version: '8.16.0' },
              'node_modules/axios': { version: '1.7.2' }
            }
          }
        }
      }
    };
  }

  if (key === 'php') {
    if (v === 'patched') {
      return {
        defaultHeaders: {
          ...HARDENED_SECURITY_HEADERS,
          'X-Powered-By': 'PHP/8.4.28'
        },
        defaultResponse: { status: 404, body: 'Not Found' },
        routes: {
          '/': { status: 200, body: '<!DOCTYPE html><html><body><h1>PHP 8.4 Patched</h1></body></html>' }
        }
      };
    }
    if (v === 'backport') {
      return {
        defaultHeaders: {
          ...HARDENED_SECURITY_HEADERS,
          'X-Powered-By': 'PHP/8.2.20-1~deb12u1'
        },
        defaultResponse: { status: 404, body: 'Not Found' },
        routes: {
          '/': { status: 200, body: '<!DOCTYPE html><html><body><h1>PHP Debian Backport</h1></body></html>' }
        }
      };
    }

    return {
      defaultHeaders: {
        'X-Powered-By': 'PHP/8.2.20',
        'Set-Cookie': 'laravel_session=laravelsess123; Path=/; XSRF-TOKEN=xsrf123; Path=/; symfony=sym123; Path=/'
      },
      defaultResponse: { status: 404, body: 'Not Found' },
      routes: async reqInfo => {
        const p = reqInfo.pathname;
        if (p === '/') {
          return {
            status: 200,
            body: '<!DOCTYPE html><html><body><h1>PHP Laravel Symfony App</h1></body></html>'
          };
        }
        if (p === '/composer.json') {
          return {
            status: 200,
            body: {
              require: {
                php: '^8.2',
                'laravel/framework': 'v11.30.0',
                'symfony/http-foundation': 'v6.4.10'
              }
            }
          };
        }
        if (p === '/composer.lock') {
          return {
            status: 200,
            body: {
              packages: [
                { name: 'laravel/framework', version: 'v11.30.0' },
                { name: 'symfony/http-foundation', version: 'v6.4.10' }
              ]
            }
          };
        }
        if (p === '/_profiler' || p === '/_profiler/') {
          return {
            status: 200,
            body: '<html><head><title>Symfony Profiler</title></head><body><h1>Symfony Profiler</h1></body></html>'
          };
        }
        if (p === '/cgi-bin/php') {
          if (reqInfo.search.includes('%ADd') || reqInfo.search.includes('allow_url_include')) {
            return {
              status: 200,
              headers: { 'X-Powered-By': 'PHP/8.2.20', 'Content-Type': 'text/html' },
              body: '<html><body><title>phpinfo()</title><table><tr><td>allow_url_include</td><td>On</td></tr></table></body></html>'
            };
          }
          return { status: 200, body: 'PHP CGI Ready' };
        }
        return null;
      }
    };
  }

  if (key === 'multi-stack-enterprise') {
    const springCfg = buildStackPresetConfig('spring', 'vulnerable');
    return {
      defaultHeaders: {
        Server: 'nginx/1.28.0',
        'Alt-Svc': 'h2=":443"; ma=86400',
        'Set-Cookie': 'JSESSIONID=ENT123; Path=/',
        'X-Java-Version': '21.0.13',
        'X-Os-Arch': 'amd64'
      },
      defaultResponse: { status: 404, body: 'Not Found' },
      routes: async (reqInfo, req, res) => {
        if (reqInfo.pathname === '/.env') {
          return {
            status: 200,
            headers: { 'Content-Type': 'text/plain; charset=utf-8' },
            body: 'APP_ENV=production\nAPP_KEY=base64:enterprise_secret_key_12345\nDB_PASSWORD=super_secret_db_pw\n'
          };
        }
        return springCfg.routes(reqInfo, req, res);
      }
    };
  }

  if (key === 'modern-saas') {
    const nextCfg = buildStackPresetConfig('nextjs', 'vulnerable');
    const nodeCfg = buildStackPresetConfig('node', 'vulnerable');
    return {
      defaultHeaders: {
        'X-Powered-By': 'Next.js, Express',
        'X-Nextjs-Version': '15.1.0',
        Vary: 'RSC, Next-Router-State-Tree, Next-Router-Prefetch, Next-Url'
      },
      defaultResponse: { status: 404, body: 'Not Found' },
      routes: async (reqInfo, req, res) => {
        const origin = reqInfo.headers['origin'];
        const corsHeaders = origin
          ? {
              'Access-Control-Allow-Origin': origin,
              'Access-Control-Allow-Credentials': 'true'
            }
          : {};
        if (reqInfo.pathname === '/package.json') {
          const r = nodeCfg.routes['/package.json'];
          return { ...r, headers: { ...corsHeaders, ...(r.headers || {}) } };
        }
        if (reqInfo.pathname === '/node_modules/express/package.json') {
          const r = nodeCfg.routes['/node_modules/express/package.json'];
          return { ...r, headers: { ...corsHeaders, ...(r.headers || {}) } };
        }
        const resSpec = await nextCfg.routes(reqInfo, req, res);
        if (!resSpec) return null;
        return {
          ...resSpec,
          headers: { ...corsHeaders, ...(resSpec.headers || {}) }
        };
      }
    };
  }

  if (key === 'legacy-cms-php') {
    const wpCfg = buildStackPresetConfig('wordpress', 'vulnerable');
    const phpCfg = buildStackPresetConfig('php', 'vulnerable');
    return {
      defaultHeaders: {
        Server: 'Apache/2.4.58 (Unix) OpenSSL/3.0.13',
        'X-Powered-By': 'PHP/8.2.20',
        'X-Generator': 'WordPress 6.4.2'
      },
      defaultResponse: { status: 404, body: 'Not Found' },
      routes: async (reqInfo, req, res) => {
        const routeKey = `${reqInfo.method} ${reqInfo.pathname}`;
        const wpMatch = wpCfg.routes[routeKey] || wpCfg.routes[reqInfo.pathname];
        if (wpMatch) return wpMatch;
        return phpCfg.routes(reqInfo, req, res);
      }
    };
  }

  if (key === 'ssrf-redirect-trap') {
    return {
      defaultHeaders: { ...HARDENED_SECURITY_HEADERS },
      defaultResponse: { status: 404, body: 'Not Found' },
      routes: {
        '/': {
          status: 200,
          body: '<!DOCTYPE html><html><body><a href="/trap-meta">Metadata</a><a href="/trap-gov">Gov</a></body></html>'
        },
        '/trap-meta': {
          status: 302,
          headers: { Location: 'http://169.254.169.254/latest/meta-data/' },
          body: ''
        },
        '/trap-gov': {
          status: 302,
          headers: { Location: 'http://portal.example.gov/secret' },
          body: ''
        }
      }
    };
  }

  throw new Error(`Unknown stack preset: ${preset}`);
}

export async function createStackTarget(preset, variant = 'vulnerable', overrides = {}) {
  const config = buildStackPresetConfig(preset, variant);
  return startMockTarget({
    ...config,
    ...overrides,
    defaultHeaders: {
      ...(config.defaultHeaders || {}),
      ...(overrides.defaultHeaders || {})
    }
  });
}
