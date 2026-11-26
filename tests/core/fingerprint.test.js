import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {
  fingerprint,
  inferEcosystemTags,
  recommendProfileForStack
} from '../../core/fingerprint.js';
import { selectScannersForStack, getProfileChecks } from '../../core/profiles.js';
import { getScanners } from '../../core/registry.js';
import { fetchWithRetry, createGovernedFetch } from '../../core/fetch.js';
import { createTrackedFetch } from '../../core/reproduction.js';

test('Fingerprint: accurately identifies WordPress even with PHP/Nginx headers', async () => {
  const mockFetch = async () => ({
    status: 200,
    headers: {
      'server': 'nginx/1.18.0',
      'x-powered-by': 'PHP/7.4.3',
      'x-generator': 'WordPress 6.4.2'
    },
    text: `
      <html>
        <head>
          <link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">
        </head>
        <body>
          <h1>WordPress Test</h1>
        </body>
      </html>
    `
  });

  const res = await fingerprint('https://wp.example.com', mockFetch);
  assert.equal(res.primary, 'wordpress');
  assert.ok(res.confidence >= 5);
  assert.ok(res.stack.some(t => t.tech === 'php'));
  assert.ok(res.stack.some(t => t.tech === 'nginx'));
});

test('Fingerprint: identifies Laravel through CSRF token and Livewire signals', async () => {
  const mockFetch = async () => ({
    status: 200,
    headers: {
      'set-cookie': 'laravel_session=abc; XSRF-TOKEN=xyz',
      'server': 'Apache'
    },
    text: `
      <html>
        <head>
          <meta name="csrf-token" content="csrf-value">
        </head>
        <body>
          <form><input type="hidden" name="_token" value="csrf"></form>
          <div wire:id="123" wire:initial-data="{}">Livewire component</div>
        </body>
      </html>
    `
  });

  const res = await fingerprint('https://laravel.example.com', mockFetch);
  assert.equal(res.primary, 'laravel');
  assert.ok(res.stack.some(t => t.tech === 'laravel'));
});

test('Fingerprint: identifies Symfony through toolbar and cookies', async () => {
  const mockFetch = async () => ({
    status: 200,
    headers: {
      'set-cookie': 'symfony=xyz',
      'server': 'nginx'
    },
    text: `
      <html>
        <body>
          <div id="sf-toolbar">Symfony Debug Toolbar</div>
        </body>
      </html>
    `
  });

  const res = await fingerprint('https://symfony.example.com', mockFetch);
  assert.equal(res.primary, 'symfony');
});

test('Fingerprint: identifies Django through csrfmiddlewaretoken', async () => {
  const mockFetch = async () => ({
    status: 200,
    headers: {
      'set-cookie': 'csrftoken=abc; sessionid=def'
    },
    text: `
      <html>
        <body>
          <input type="hidden" name="csrfmiddlewaretoken" value="token">
        </body>
      </html>
    `
  });

  const res = await fingerprint('https://django.example.com', mockFetch);
  assert.equal(res.primary, 'django');
});

test('Fingerprint: identifies Spring Boot through Whitelabel page text', async () => {
  const mockFetch = async () => ({
    status: 500,
    headers: {},
    text: `
      <html>
        <body>
          <h1>Whitelabel Error Page</h1>
          <p>This application has no explicit mapping for /error</p>
        </body>
      </html>
    `
  });

  const res = await fingerprint('https://spring.example.com', mockFetch);
  assert.equal(res.primary, 'spring');
});

test('Fingerprint: identifies ASP.NET through ViewState and RequestVerificationToken', async () => {
  const mockFetch = async () => ({
    status: 200,
    headers: {
      'x-aspnet-version': '4.0.30319'
    },
    text: `
      <html>
        <body>
          <input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="foo">
        </body>
      </html>
    `
  });

  const res = await fingerprint('https://dotnet.example.com', mockFetch);
  assert.equal(res.primary, 'aspnet');
});

test('inferEcosystemTags: expands frameworks into parent ecosystem/runtime tags', () => {
  // laravel / wordpress -> php
  const laravelTags = inferEcosystemTags([{ tech: 'laravel' }]);
  assert.ok(laravelTags.includes('laravel'));
  assert.ok(laravelTags.includes('php'));

  const wpTags = inferEcosystemTags(['wordpress']);
  assert.ok(wpTags.includes('wordpress'));
  assert.ok(wpTags.includes('php'));

  // nextjs -> react, node, frontend
  const nextTags = inferEcosystemTags([{ tech: 'nextjs' }]);
  assert.ok(nextTags.includes('nextjs'));
  assert.ok(nextTags.includes('react'));
  assert.ok(nextTags.includes('node'));
  assert.ok(nextTags.includes('frontend'));

  // django / flask / fastapi -> python
  for (const fw of ['django', 'flask', 'fastapi']) {
    const pyTags = inferEcosystemTags([{ tech: fw }]);
    assert.ok(pyTags.includes(fw));
    assert.ok(pyTags.includes('python'));
  }

  // spring -> java
  const springTags = inferEcosystemTags([{ tech: 'spring' }]);
  assert.ok(springTags.includes('spring'));
  assert.ok(springTags.includes('java'));
});

test('recommendProfileForStack: returns expected profile recommendations for detected stacks', () => {
  assert.equal(recommendProfileForStack('laravel', ['laravel', 'php']), 'laravel');
  assert.equal(recommendProfileForStack('wordpress', ['wordpress', 'php']), 'wordpress');
  assert.equal(recommendProfileForStack('nextjs', ['nextjs', 'react', 'node', 'frontend']), 'modern');
  assert.equal(recommendProfileForStack('django', ['django', 'python']), 'python');
  assert.equal(recommendProfileForStack('spring', ['spring', 'java']), 'spring');
  assert.equal(recommendProfileForStack('unknown', []), 'smart');
});

test('Fingerprint: secondary fallback /robots.txt probe detects WordPress and Next.js behind generic CDN headers', async () => {
  const wpFetch = async (url) => {
    if (url.endsWith('/robots.txt')) {
      return {
        status: 200,
        headers: {},
        text: 'User-agent: *\nDisallow: /wp-admin/\nAllow: /wp-admin/admin-ajax.php'
      };
    }
    return {
      status: 200,
      headers: { 'server': 'cloudflare', 'cf-ray': '123456-IAD' },
      text: '<html><body>Welcome</body></html>'
    };
  };

  const wpFp = await fingerprint('https://hidden-wp.example.com', wpFetch);
  assert.equal(wpFp.primary, 'wordpress');
  assert.ok(wpFp.detectedTags.includes('wordpress'));
  assert.ok(wpFp.detectedTags.includes('php'));
  assert.equal(wpFp.recommendedProfile, 'wordpress');

  const nextFetch = async (url) => {
    if (url.endsWith('/robots.txt')) {
      return {
        status: 200,
        headers: {},
        text: 'User-agent: *\nDisallow: /_next/static/'
      };
    }
    return {
      status: 200,
      headers: { 'server': 'nginx' },
      text: '<html><body>Landing Page</body></html>'
    };
  };

  const nextFp = await fingerprint('https://hidden-next.example.com', nextFetch);
  assert.equal(nextFp.primary, 'nextjs');
  assert.ok(nextFp.detectedTags.includes('nextjs'));
  assert.ok(nextFp.detectedTags.includes('react'));
  assert.ok(nextFp.detectedTags.includes('node'));
  assert.equal(nextFp.recommendedProfile, 'modern');
});

test('Fingerprint: secondary fallback /_secscan_fp_probe_404 detects Django, Spring, and Express', async () => {
  const make404Fetch = (probeText) => async (url) => {
    if (url.endsWith('/_secscan_fp_probe_404')) {
      return {
        status: 404,
        headers: {},
        text: probeText
      };
    }
    return {
      status: 200,
      headers: { 'server': 'nginx', 'cf-ray': '99999-SJC' },
      text: '<html><body>Generic Homepage</body></html>'
    };
  };

  const djangoFp = await fingerprint(
    'https://hidden-django.example.com',
    make404Fetch('Page not found (404) - Using the URLconf defined in myproject.urls, Django tried these URL patterns')
  );
  assert.equal(djangoFp.primary, 'django');
  assert.ok(djangoFp.detectedTags.includes('python'));
  assert.equal(djangoFp.recommendedProfile, 'python');

  const springFp = await fingerprint(
    'https://hidden-spring.example.com',
    make404Fetch('<html><body><h1>Whitelabel Error Page</h1><p>This application has no explicit mapping for /error</p></body></html>')
  );
  assert.equal(springFp.primary, 'spring');
  assert.ok(springFp.detectedTags.includes('java'));
  assert.equal(springFp.recommendedProfile, 'spring');

  const expressFp = await fingerprint(
    'https://hidden-express.example.com',
    make404Fetch('<!DOCTYPE html><html><body><pre>Cannot GET /_secscan_fp_probe_404</pre></body></html>')
  );
  assert.equal(expressFp.primary, 'express');
  assert.ok(expressFp.detectedTags.includes('node'));
  assert.equal(expressFp.recommendedProfile, 'node');
});

test('selectScannersForStack: filters real scanners accurately for Next.js, WordPress, and explicit profiles', async () => {
  const scanners = await getScanners();

  // 1. Next.js stack: selects Next.js/Frontend/Node + universal checks, skips irrelevant CMS/PHP/Python/Spring checks
  const nextSelection = selectScannersForStack(scanners, {
    profile: 'smart',
    fp: {
      primary: 'nextjs',
      detectedTags: ['nextjs', 'react', 'node', 'frontend']
    }
  });
  const nextActiveNames = new Set(nextSelection.activeScanners.map(s => s.name));
  const nextSkippedNames = new Set(nextSelection.skippedScanners.map(s => s.name));

  assert.ok(nextActiveNames.has('nextjs-checks'));
  assert.ok(nextActiveNames.has('frontend-checks'));
  assert.ok(nextActiveNames.has('node-checks'));
  assert.ok(nextActiveNames.has('ssl-tls'));
  assert.ok(nextActiveNames.has('security-headers'));

  for (const skipped of ['wp-checks', 'laravel-debug', 'magento-checks', 'drupal-checks', 'python-checks', 'spring-checks']) {
    assert.ok(nextSkippedNames.has(skipped), `Expected ${skipped} to be skipped on Next.js stack`);
    assert.ok(!nextActiveNames.has(skipped), `Expected ${skipped} not to be active on Next.js stack`);
  }

  // 2. WordPress stack: selects WordPress/PHP + universal checks, skips Next.js/Node/Python/Spring/Laravel/Magento checks
  const wpSelection = selectScannersForStack(scanners, {
    profile: 'smart',
    fp: {
      primary: 'wordpress',
      detectedTags: ['wordpress', 'php']
    }
  });
  const wpActiveNames = new Set(wpSelection.activeScanners.map(s => s.name));
  const wpSkippedNames = new Set(wpSelection.skippedScanners.map(s => s.name));

  assert.ok(wpActiveNames.has('wp-checks'));
  assert.ok(wpActiveNames.has('php-version'));
  assert.ok(wpActiveNames.has('php-config'));
  assert.ok(wpActiveNames.has('php-backup'));

  for (const skipped of ['nextjs-checks', 'node-checks', 'python-checks', 'spring-checks', 'laravel-debug', 'magento-checks']) {
    assert.ok(wpSkippedNames.has(skipped), `Expected ${skipped} to be skipped on WordPress stack`);
    assert.ok(!wpActiveNames.has(skipped), `Expected ${skipped} not to be active on WordPress stack`);
  }

  // 3. Explicit --profile wordpress or --profile spring runs profile checks even when fp.stack is empty (unknown)
  const explicitWp = selectScannersForStack(scanners, {
    profile: 'wordpress',
    fp: { primary: 'unknown', stack: [], detectedTags: [] }
  });
  const explicitWpNames = new Set(explicitWp.activeScanners.map(s => s.name));
  assert.ok(explicitWpNames.has('wp-checks'));
  assert.ok(explicitWpNames.has('ssl-tls'));

  const explicitSpring = selectScannersForStack(scanners, {
    profile: 'spring',
    fp: { primary: 'unknown', stack: [], detectedTags: [] }
  });
  const explicitSpringNames = new Set(explicitSpring.activeScanners.map(s => s.name));
  assert.ok(explicitSpringNames.has('spring-checks'));
  assert.ok(explicitSpringNames.has('cve-2026-114938'));
  assert.ok(explicitSpringNames.has('ssl-tls'));
});

test('Fingerprint: detects Java runtimes via Undertow/Netty/WebLogic/OpenJDK/X-Java-Version and recommends nginx profile for standalone NGINX', async () => {
  const javaCases = [
    { 'server': 'Undertow/2.3' },
    { 'x-powered-by': 'Netty' },
    { 'servlet-engine': 'WebLogic Server 14.1.1' },
    { 'server': 'OpenJDK/21.0.13' },
    { 'server': 'Java/17.0.21' },
    { 'x-java-version': '21.0.13' }
  ];

  for (const headers of javaCases) {
    const res = await fingerprint('https://java.example.com', async () => ({
      status: 200,
      headers,
      text: '<html><body>Java Service</body></html>'
    }), { deepProbe: false });
    assert.ok(res.detectedTags.includes('java'), `Expected java tag for headers ${JSON.stringify(headers)}`);
    assert.equal(res.recommendedProfile, 'spring');
  }

  const nginxOnly = await fingerprint('https://nginx.example.com', async () => ({
    status: 200,
    headers: { 'server': 'nginx/1.31.0' },
    text: '<html><body>Welcome to nginx!</body></html>'
  }), { deepProbe: false });
  assert.equal(nginxOnly.primary, 'nginx');
  assert.equal(nginxOnly.recommendedProfile, 'nginx');
  assert.equal(recommendProfileForStack('wordpress', ['wordpress', 'php', 'nginx']), 'wordpress');
  assert.equal(recommendProfileForStack('nginx', ['nginx']), 'nginx');
});

test('selectScannersForStack: selects CVE-2026-123007/123633 for nginx, CVE-2026-114938 for spring/java, and skips them on unrelated stacks', async () => {
  const scanners = await getScanners();

  // NGINX stack -> selects NGINX HTTP/2 CVEs, skips Java4Shell
  const nginxSel = selectScannersForStack(scanners, {
    profile: 'smart',
    fp: { primary: 'nginx', detectedTags: ['nginx'] }
  });
  const nginxActive = new Set(nginxSel.activeScanners.map(s => s.name));
  const nginxSkipped = new Set(nginxSel.skippedScanners.map(s => s.name));
  assert.ok(nginxActive.has('cve-2026-123007'));
  assert.ok(nginxActive.has('cve-2026-123633'));
  assert.ok(nginxSkipped.has('cve-2026-114938'));

  // Explicit nginx profile -> includes both NGINX HTTP/2 CVEs
  const explicitNginx = selectScannersForStack(scanners, {
    profile: 'nginx',
    fp: { primary: 'unknown', stack: [], detectedTags: [] }
  });
  const explicitNginxNames = new Set(explicitNginx.activeScanners.map(s => s.name));
  assert.ok(explicitNginxNames.has('cve-2026-123007'));
  assert.ok(explicitNginxNames.has('cve-2026-123633'));

  // Spring / Java stack -> selects Java4Shell, skips NGINX HTTP/2 CVEs
  for (const fp of [
    { primary: 'spring', detectedTags: ['spring', 'java'] },
    { primary: 'java', detectedTags: ['java'] }
  ]) {
    const javaSel = selectScannersForStack(scanners, { profile: 'smart', fp });
    const javaActive = new Set(javaSel.activeScanners.map(s => s.name));
    const javaSkipped = new Set(javaSel.skippedScanners.map(s => s.name));
    assert.ok(javaActive.has('cve-2026-114938'));
    assert.ok(javaSkipped.has('cve-2026-123007'));
    assert.ok(javaSkipped.has('cve-2026-123633'));
  }

  // Irrelevant stack (WordPress without nginx) -> skips all three CVE checks
  const wpSel = selectScannersForStack(scanners, {
    profile: 'smart',
    fp: { primary: 'wordpress', detectedTags: ['wordpress', 'php'] }
  });
  const wpSkipped = new Set(wpSel.skippedScanners.map(s => s.name));
  assert.ok(wpSkipped.has('cve-2026-123007'));
  assert.ok(wpSkipped.has('cve-2026-123633'));
  assert.ok(wpSkipped.has('cve-2026-114938'));
});

test('Fingerprint: detects Apache, Tomcat, Python (/requirements.txt & uvicorn), Express, and PHP/Laravel/Symfony stacks accurately', async () => {
  // 1. Standalone Apache HTTP Server -> apache tag & apache profile
  const apacheFp = await fingerprint('https://apache.example.com', async () => ({
    status: 200,
    headers: { server: 'Apache/2.4.58 (Unix) OpenSSL/3.0.13' },
    text: '<html><body><h1>It works!</h1></body></html>'
  }), { deepProbe: false });
  assert.equal(apacheFp.primary, 'apache');
  assert.ok(apacheFp.detectedTags.includes('apache'));
  assert.equal(apacheFp.recommendedProfile, 'apache');
  assert.equal(recommendProfileForStack('apache', ['apache']), 'apache');
  assert.equal(recommendProfileForStack('wordpress', ['wordpress', 'php', 'apache']), 'wordpress');

  // 2. Apache Tomcat -> tomcat + java tags (does NOT falsely tag apache httpd), maps to spring profile
  const tomcatFp = await fingerprint('https://tomcat.example.com', async () => ({
    status: 200,
    headers: {
      server: 'Apache Tomcat/10.1.30',
      'set-cookie': 'JSESSIONID=TOMCATVULN; Path=/'
    },
    text: '<html><head><title>Apache Tomcat/10.1.30</title></head><body><h1>Apache Tomcat/10.1.30</h1></body></html>'
  }), { deepProbe: false });
  assert.equal(tomcatFp.primary, 'tomcat');
  assert.ok(tomcatFp.detectedTags.includes('tomcat'));
  assert.ok(tomcatFp.detectedTags.includes('java'));
  assert.ok(!tomcatFp.detectedTags.includes('apache'));
  assert.equal(tomcatFp.recommendedProfile, 'spring');

  // 3. FastAPI / Starlette / Django via /requirements.txt fallback probe and uvicorn header
  const reqTxtFp = await fingerprint('https://py-hidden.example.com', async (url) => {
    if (url.endsWith('/requirements.txt')) {
      return {
        status: 200,
        headers: { 'content-type': 'text/plain' },
        text: 'Django==4.2.15\nstarlette==0.38.6\nfastapi==0.112.0\nuvicorn==0.30.0\n'
      };
    }
    return {
      status: 200,
      headers: { server: 'nginx/1.25.0' },
      text: '<html><body>API Service</body></html>'
    };
  });
  assert.ok(['django', 'fastapi'].includes(reqTxtFp.primary));
  assert.ok(reqTxtFp.detectedTags.includes('python'));
  assert.equal(reqTxtFp.recommendedProfile, 'python');

  const uvicornFp = await fingerprint('https://uvicorn.example.com', async () => ({
    status: 200,
    headers: { server: 'WSGIServer/0.2 CPython/3.11.6 uvicorn' },
    text: '<html><body>FastAPI</body></html>'
  }), { deepProbe: false });
  assert.ok(uvicornFp.detectedTags.includes('fastapi'));
  assert.ok(uvicornFp.detectedTags.includes('python'));
  assert.equal(uvicornFp.recommendedProfile, 'python');

  // 4. Express -> node tag & node profile
  const expressFp = await fingerprint('https://express.example.com', async () => ({
    status: 200,
    headers: { 'x-powered-by': 'Express' },
    text: '<html><body>Express API</body></html>'
  }), { deepProbe: false });
  assert.equal(expressFp.primary, 'express');
  assert.ok(expressFp.detectedTags.includes('node'));
  assert.equal(expressFp.recommendedProfile, 'node');

  // 5. PHP / Laravel / Symfony
  const phpFp = await fingerprint('https://php.example.com', async () => ({
    status: 200,
    headers: { 'x-powered-by': 'PHP/8.2.20' },
    text: '<html><body>PHP App</body></html>'
  }), { deepProbe: false });
  assert.equal(phpFp.primary, 'php');
  assert.ok(phpFp.detectedTags.includes('php'));
  assert.equal(phpFp.recommendedProfile, 'php');
});

test('selectScannersForStack: selects all 8 ecosystem CVE checks for matching stacks under smart and explicit profiles', async () => {
  const scanners = await getScanners();

  const stackExpectations = [
    {
      label: 'tomcat',
      fp: { primary: 'tomcat', detectedTags: ['tomcat', 'java'] },
      expected: ['cve-tomcat', 'cve-2026-114938'],
      excluded: ['cve-apache-httpd', 'cve-wordpress-ecosystem', 'cve-python-web']
    },
    {
      label: 'apache',
      fp: { primary: 'apache', detectedTags: ['apache'] },
      expected: ['cve-apache-httpd'],
      excluded: ['cve-tomcat', 'cve-nextjs-react', 'cve-php-ecosystem']
    },
    {
      label: 'nextjs',
      fp: { primary: 'nextjs', detectedTags: ['nextjs', 'react', 'node', 'frontend'] },
      expected: ['cve-nextjs-react', 'cve-node-express'],
      excluded: ['cve-wordpress-ecosystem', 'cve-spring-framework', 'cve-apache-httpd']
    },
    {
      label: 'spring',
      fp: { primary: 'spring', detectedTags: ['spring', 'java'] },
      expected: ['cve-spring-framework', 'cve-2026-114938'],
      excluded: ['cve-node-express', 'cve-php-ecosystem']
    },
    {
      label: 'python',
      fp: { primary: 'django', detectedTags: ['django', 'fastapi', 'python'] },
      expected: ['cve-python-web'],
      excluded: ['cve-node-express', 'cve-wordpress-ecosystem', 'cve-tomcat']
    },
    {
      label: 'node',
      fp: { primary: 'express', detectedTags: ['express', 'node'] },
      expected: ['cve-node-express'],
      excluded: ['cve-python-web', 'cve-php-ecosystem', 'cve-apache-httpd']
    },
    {
      label: 'php',
      fp: { primary: 'php', detectedTags: ['php', 'laravel', 'symfony'] },
      expected: ['cve-php-ecosystem', 'cve-2024-4577'],
      excluded: ['cve-nextjs-react', 'cve-python-web', 'cve-spring-framework']
    },
    {
      label: 'wordpress',
      fp: { primary: 'wordpress', detectedTags: ['wordpress', 'php'] },
      expected: ['cve-wordpress-ecosystem', 'cve-php-ecosystem', 'cve-2024-4577'],
      excluded: ['cve-nextjs-react', 'cve-tomcat', 'cve-node-express']
    }
  ];

  for (const spec of stackExpectations) {
    const sel = selectScannersForStack(scanners, { profile: 'smart', fp: spec.fp });
    const active = new Set(sel.activeScanners.map(s => s.name));
    const skipped = new Set(sel.skippedScanners.map(s => s.name));
    for (const c of spec.expected) {
      assert.ok(active.has(c), `${spec.label} under smart should include ${c}`);
    }
    for (const c of spec.excluded) {
      assert.ok(skipped.has(c), `${spec.label} under smart should skip ${c}`);
    }
  }

  // Explicit apache profile includes cve-apache-httpd
  const explicitApache = selectScannersForStack(scanners, {
    profile: 'apache',
    fp: { primary: 'unknown', stack: [], detectedTags: [] }
  });
  const apacheNames = new Set(explicitApache.activeScanners.map(s => s.name));
  assert.ok(apacheNames.has('cve-apache-httpd'));
  assert.ok(apacheNames.has('ssl-tls'));
});

test('Fingerprint: detects Angular via ng-server-context, hashed main/polyfills bundles, ng-app, and HttpClient bundle signals with apiCommunication', async () => {
  // 1. Modern Angular SSR + hashed bundles + HttpClient + /assets/config.json
  const ngFetch = async (url) => {
    if (url === 'https://ng.example.com') {
      return {
        status: 200,
        headers: { 'content-type': 'text/html', server: 'nginx/1.26.0' },
        text: `
          <!doctype html>
          <html>
            <head>
              <script src="/polyfills-FFHMD2TL.js" type="module"></script>
              <script src="/main-6X7K2L3M.js" type="module"></script>
            </head>
            <body>
              <app-root ng-server-context="ssr"></app-root>
            </body>
          </html>
        `
      };
    }
    if (url === 'https://ng.example.com/main-6X7K2L3M.js') {
      return {
        status: 200,
        headers: { 'content-type': 'application/javascript' },
        text: 'import { HttpClient, provideHttpClient } from "@angular/common/http"; http.get("/api/orders"); fetch("https://api.ng-backend.example/v1/items");'
      };
    }
    if (url === 'https://ng.example.com/assets/config.json') {
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        text: '{"apiUrl":"https://api.ng-backend.example"}'
      };
    }
    return { status: 404, headers: {}, text: '' };
  };

  const ngRes = await fingerprint('https://ng.example.com', ngFetch);
  assert.equal(ngRes.primary, 'angular');
  assert.ok(ngRes.detectedTags.includes('angular'));
  assert.ok(ngRes.detectedTags.includes('frontend'));
  assert.equal(ngRes.recommendedProfile, 'frontend');
  assert.ok(ngRes.apiCommunication);
  assert.equal(ngRes.apiCommunication.usesApi, true);
  assert.equal(ngRes.apiCommunication.architecture, 'ssr_hybrid_api');
  assert.ok(ngRes.apiCommunication.clients.includes('Angular HttpClient'));
  assert.ok(ngRes.apiCommunication.sameOriginEndpoints.includes('/api/orders'));
  assert.ok(ngRes.apiCommunication.externalApiOrigins.includes('https://api.ng-backend.example'));

  // 2. AngularJS / ng-app + bundle-only HttpClient without ng-version in HTML
  const ngAppRes = await fingerprint('https://ng-bundle.example.com', async (url) => {
    if (url === 'https://ng-bundle.example.com') {
      return {
        status: 200,
        headers: { 'content-type': 'text/html' },
        text: '<html ng-app="app"><body><script src="/main.js"></script></body></html>'
      };
    }
    if (url === 'https://ng-bundle.example.com/main.js') {
      return {
        status: 200,
        headers: { 'content-type': 'application/javascript' },
        text: 'provideHttpClient(); this.http.get("/api/dashboard");'
      };
    }
    throw new Error('Mock probe error should remain non-fatal');
  }, { deepProbe: false });

  assert.equal(ngAppRes.primary, 'angular');
  assert.equal(ngAppRes.recommendedProfile, 'frontend');
  assert.ok(ngAppRes.apiCommunication);
  assert.ok(ngAppRes.apiCommunication.sameOriginEndpoints.includes('/api/dashboard'));
});

test('Fingerprint: fast TCP pre-check avoids stall when port 80 is closed and classifies quoted Samsung Smart TV target', async () => {
  let rootFetched = false;
  const tvFetch = async (url) => {
    if (url === 'http://192.168.68.53' || url === 'http://192.168.68.53/') {
      rootFetched = true;
      throw new Error('Should have been skipped by TCP pre-check');
    }
    if (url === 'http://192.168.68.53:8001/api/v2/') {
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        text: JSON.stringify({
          device: {
            type: 'Samsung SmartTV',
            OS: 'Tizen',
            modelName: 'UN55TU7000FXZA',
            name: 'Living Room TV',
            tokenAuthSupport: 'false'
          }
        })
      };
    }
    return { status: 404, headers: {}, text: '' };
  };

  const t0 = Date.now();
  const fp = await fingerprint('"192.168.68.53\\"', tvFetch, {
    allowPrivate: true,
    deviceMode: true,
    tcpProbe: async (_h, port) => ({ port, open: port === 8001 || port === 8002 || port === 8080 || port === 9197 })
  });
  const elapsed = Date.now() - t0;

  assert.ok(elapsed < 500, `Expected < 500ms, got ${elapsed}ms`);
  assert.equal(rootFetched, false);
  assert.equal(fp.primary, 'device');
  assert.equal(fp.recommendedProfile, 'device');
  assert.ok(fp.detectedTags.includes('tv'));
  assert.ok(fp.deviceInfo);
  assert.equal(fp.deviceInfo.category, 'smart_tv');
  assert.equal(fp.deviceInfo.modelName, 'UN55TU7000FXZA');
});

test('Fingerprint: invokes scanDeviceTarget on 401/generic root response for IP Camera and PC/Workstation targets', async () => {
  // 1. IP Camera returning 401 Basic Auth on port 80
  const camFp = await fingerprint('http://192.168.1.90', async (url) => {
    if (url === 'http://192.168.1.90' || url === 'http://192.168.1.90/') {
      return {
        status: 401,
        headers: { server: 'App-webs/', 'www-authenticate': 'Basic realm="Hikvision Camera"' },
        text: 'Unauthorized'
      };
    }
    if (url === 'http://192.168.1.90/ISAPI/System/deviceInfo') {
      return {
        status: 200,
        headers: { 'content-type': 'application/xml' },
        text: '<DeviceInfo><model>DS-2CD2143</model></DeviceInfo>'
      };
    }
    return { status: 404, headers: {}, text: '' };
  }, {
    allowPrivate: true,
    tcpProbe: async (_h, p) => ({ port: p, open: p === 80 || p === 554 })
  });
  assert.equal(camFp.primary, 'device');
  assert.equal(camFp.recommendedProfile, 'device');
  assert.ok(camFp.detectedTags.includes('camera'));
  assert.ok(!camFp.detectedTags.includes('tv'));
  assert.equal(camFp.deviceInfo.category, 'ip_camera');

  // 2. PC/Workstation with generic port 80 + SMB 445 / SSH 22 / CUPS 631
  const pcFp = await fingerprint('http://192.168.1.101', async (url) => {
    if (url === 'http://192.168.1.101' || url === 'http://192.168.1.101/') {
      return { status: 200, headers: {}, text: '<html><body>Host Status</body></html>' };
    }
    return { status: 404, headers: {}, text: '' };
  }, {
    allowPrivate: true,
    deviceMode: true,
    tcpProbe: async (_h, p) => ({ port: p, open: p === 80 || p === 22 || p === 445 || p === 631 })
  });
  assert.equal(pcFp.primary, 'device');
  assert.equal(pcFp.recommendedProfile, 'device');
  assert.ok(pcFp.detectedTags.includes('pc'));
  assert.ok(pcFp.detectedTags.includes('workstation'));
  assert.ok(pcFp.detectedTags.includes('server'));
  assert.equal(pcFp.deviceInfo.category, 'pc_workstation');

  // 3. Mock fetch with deviceMode: true and NO tcpProbe must NEVER open OS sockets
  const mockOnlyFp = await fingerprint('https://example.com', async () => ({
    status: 200,
    headers: { server: 'nginx' },
    text: '<html><body>Hello</body></html>'
  }), { deviceMode: true });
  assert.ok(mockOnlyFp.primary);
});

test('inferEcosystemTags, recommendProfileForStack, and getProfileChecks support Smart TV, IP Camera, and PC/Workstation aliases', () => {
  const camTags = inferEcosystemTags(['ip_camera']);
  assert.ok(camTags.includes('device'));
  assert.ok(camTags.includes('camera'));
  assert.ok(camTags.includes('ip-camera'));
  assert.ok(!camTags.includes('tv'));

  const pcTags = inferEcosystemTags(['pc_workstation']);
  assert.ok(pcTags.includes('device'));
  assert.ok(pcTags.includes('pc'));
  assert.ok(pcTags.includes('workstation'));
  assert.ok(pcTags.includes('server'));
  assert.ok(!pcTags.includes('tv'));

  for (const alias of ['smart_tv', 'camera', 'ip-camera', 'nvr', 'pc', 'workstation', 'server', 'pc_workstation']) {
    assert.equal(recommendProfileForStack(alias, []), 'device');
  }
  for (const profAlias of ['tv', 'smart-tv', 'smart_tv', 'camera', 'ip-camera', 'ip_camera', 'nvr', 'pc', 'workstation', 'server', 'pc-workstation', 'pc_workstation', 'lan']) {
    assert.deepEqual(getProfileChecks(profAlias), getProfileChecks('device'));
  }
});

test('Fingerprint regression (Bug 2): ordinary PHP/Nginx HTML mentioning "cups " does NOT hijack primary to device', async () => {
  const fp = await fingerprint('https://coffee.example.com', async () => ({
    status: 200,
    headers: { server: 'nginx', 'x-powered-by': 'PHP/8.2.20' },
    text: '<html><head><title>Coffee Shop</title></head><body><h1>Buy 2 cups and get 1 free!</h1></body></html>'
  }), { deepProbe: false });
  assert.equal(fp.primary, 'php');
  assert.notEqual(fp.primary, 'device');
  assert.equal(fp.recommendedProfile, 'php');
});

test('Fingerprint regression (Bugs 4 & 7): pre-DNS SSRF blocks TCP pre-check and createTrackedFetch(fetchWithRetry) detects loopback Smart TV without multiPort: true', async () => {
  // Bug 4: DNS resolving to 127.0.0.1 with allowPrivate: false must NOT fire tcpProbe or fetchWithRetry
  let tcpCalled = 0;
  let fetchCalled = 0;
  const governed = createGovernedFetch({
    allowPrivate: false,
    dnsResolver: async () => ['127.0.0.1']
  });
  const trackedGoverned = Object.assign(async (...args) => {
    fetchCalled++;
    return governed(...args);
  }, {
    governance: governed.governance,
    hasCustomFetcher: governed.hasCustomFetcher,
    isDefaultFetch: governed.isDefaultFetch
  });
  const blockedFp = await fingerprint('http://rebind-fp.example', trackedGoverned, {
    deviceMode: true,
    tcpProbe: async () => { tcpCalled++; return { open: false }; }
  });
  assert.equal(tcpCalled, 0);
  assert.equal(fetchCalled, 0);
  assert.equal(blockedFp.primary, 'unknown');

  // Bug 7: createTrackedFetch(fetchWithRetry) with explicit ports & NO multiPort: true succeeds on loopback server
  const tvServer = http.createServer((req, res) => {
    if (req.url === '/api/v2/') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ device: { type: 'Samsung SmartTV', OS: 'Tizen', modelName: 'QN55Q80C', tokenAuthSupport: 'false' } }));
      return;
    }
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
  });
  await new Promise(resolve => tvServer.listen(0, '127.0.0.1', resolve));
  const tvPort = tvServer.address().port;

  // Find a guaranteed closed port on 127.0.0.1 to simulate closed port 80
  const closedSrv = http.createServer();
  await new Promise(resolve => closedSrv.listen(0, '127.0.0.1', resolve));
  const closedPort = closedSrv.address().port;
  await new Promise(resolve => closedSrv.close(resolve));

  try {
    const tracked = createTrackedFetch(fetchWithRetry);
    const fp = await fingerprint(`"http://127.0.0.1:${closedPort}\\"`, tracked, {
      allowPrivate: true,
      deviceMode: true,
      ports: [closedPort, tvPort],
      portTimeoutMs: 250,
      probeTimeoutMs: 500
    });
    assert.equal(fp.primary, 'device');
    assert.equal(fp.deviceInfo?.category, 'smart_tv');
    assert.equal(fp.deviceInfo?.vendor, 'Samsung');
  } finally {
    tvServer.closeAllConnections?.();
    await new Promise(resolve => tvServer.close(resolve));
  }
});

test('FINDING-2 regression: fingerprint evaluates built-in, custom, and post-DNS asset gate before DNS lookup or TCP probe', async () => {
  // 1. Built-in deny TLD (.gov) must block before dnsResolver, tcpProbe, or fetchWithRetry
  let dnsCalls = 0;
  let tcpCalls = 0;
  let fetchCalls = 0;
  const builtinGov = createGovernedFetch({
    allowPrivate: false,
    dnsResolver: async () => {
      dnsCalls++;
      return ['93.184.216.34'];
    }
  });
  const trackedGov = Object.assign(async (...args) => {
    fetchCalls++;
    return builtinGov(...args);
  }, {
    governance: builtinGov.governance,
    hasCustomFetcher: builtinGov.hasCustomFetcher,
    isDefaultFetch: builtinGov.isDefaultFetch
  });

  const govRes = await fingerprint('https://agency.gov', trackedGov, {
    deviceMode: true,
    tcpProbe: async () => {
      tcpCalls++;
      return { open: true };
    }
  });
  assert.equal(govRes.primary, 'unknown');
  assert.equal(dnsCalls, 0);
  assert.equal(tcpCalls, 0);
  assert.equal(fetchCalls, 0);

  // 2. Custom exact_domain deny rule must block before dnsResolver, tcpProbe, or fetchWithRetry
  const customDenied = createGovernedFetch({
    allowPrivate: false,
    scopeRules: [{ ruleType: 'exact_domain', pattern: 'denied.example.com', isAllowed: false }],
    dnsResolver: async () => {
      dnsCalls++;
      return ['93.184.216.34'];
    }
  });
  const trackedCustom = Object.assign(async (...args) => {
    fetchCalls++;
    return customDenied(...args);
  }, {
    governance: customDenied.governance,
    hasCustomFetcher: customDenied.hasCustomFetcher,
    isDefaultFetch: customDenied.isDefaultFetch
  });

  const customRes = await fingerprint('https://denied.example.com', trackedCustom, {
    deviceMode: true,
    tcpProbe: async () => {
      tcpCalls++;
      return { open: true };
    }
  });
  assert.equal(customRes.primary, 'unknown');
  assert.equal(dnsCalls, 0);
  assert.equal(tcpCalls, 0);
  assert.equal(fetchCalls, 0);

  // 3. Post-DNS CIDR deny rule must block before tcpProbe or fetchWithRetry
  let postDnsChecks = 0;
  const cidrDenied = createGovernedFetch({
    allowPrivate: false,
    scopeRules: [{ ruleType: 'cidr', pattern: '198.51.100.0/24', isAllowed: false }],
    dnsResolver: async () => {
      postDnsChecks++;
      return ['198.51.100.42'];
    }
  });
  const trackedCidr = Object.assign(async (...args) => {
    fetchCalls++;
    return cidrDenied(...args);
  }, {
    governance: cidrDenied.governance,
    hasCustomFetcher: cidrDenied.hasCustomFetcher,
    isDefaultFetch: cidrDenied.isDefaultFetch
  });

  const cidrRes = await fingerprint('https://masked-cidr.example.com', trackedCidr, {
    deviceMode: true,
    tcpProbe: async () => {
      tcpCalls++;
      return { open: true };
    }
  });
  assert.equal(cidrRes.primary, 'unknown');
  assert.equal(postDnsChecks, 1);
  assert.equal(tcpCalls, 0);
  assert.equal(fetchCalls, 0);
});

test('Fingerprint (R3 scoping): bare public IP without deviceMode does NOT trigger multi-port device discovery or hijack profile to device', async () => {
  // 1. Public IP returning Cloudflare 403 generic response without deviceMode (even with allowPrivate: true)
  let tcpProbedPorts = [];
  const cfPublicFp = await fingerprint('http://104.21.43.139', async () => ({
    status: 403,
    headers: { server: 'cloudflare', 'cf-ray': '8abc123456-MIA' },
    text: '<html><title>Direct IP access not allowed | Cloudflare</title></html>'
  }), {
    allowPrivate: true,
    deepProbe: false,
    apiDiscovery: false,
    tcpProbe: async (_h, port) => {
      tcpProbedPorts.push(port);
      return { port, open: [80, 443, 8080, 8443].includes(port) };
    }
  });
  assert.deepEqual(tcpProbedPorts, []);
  assert.equal(cfPublicFp.primary, 'cloudflare');
  assert.notEqual(cfPublicFp.primary, 'device');
  assert.notEqual(cfPublicFp.recommendedProfile, 'device');
  assert.equal(cfPublicFp.deviceInfo, undefined);

  // 2. Public IP with unreachable HTTP (fetch error) and deviceMode: false must NOT fall back to scanDeviceTarget
  let fallbackTcpCalled = 0;
  const downPublicFp = await fingerprint('http://104.21.43.139', async () => {
    const err = new Error('connect ECONNREFUSED 104.21.43.139:80');
    err.code = 'ECONNREFUSED';
    throw err;
  }, {
    allowPrivate: false,
    tcpProbe: async () => {
      fallbackTcpCalled++;
      return { open: true };
    }
  });
  assert.equal(fallbackTcpCalled, 0);
  assert.equal(downPublicFp.primary, 'unknown');
  assert.equal(downPublicFp.recommendedProfile, 'smart');

  // 3. Public host with multiPort: true and deviceMode: false returning only 8080/8443 device_web must NOT overwrite primary/recommendedProfile
  const publicDeviceWebFp = await fingerprint('http://104.21.43.139', async () => ({
    status: 403,
    headers: { server: 'cloudflare' },
    text: '<html><body>Forbidden</body></html>'
  }), {
    deviceMode: false,
    multiPort: true,
    deepProbe: false,
    apiDiscovery: false,
    tcpProbe: async (_h, port) => ({ port, open: port === 80 || port === 8080 || port === 8443 })
  });
  assert.notEqual(publicDeviceWebFp.primary, 'device');
  assert.notEqual(publicDeviceWebFp.recommendedProfile, 'device');

  // 4. Same public IP WITH explicit deviceMode: true + deviceCategory: 'ip_camera' DOES run device discovery
  const explicitCamPublicFp = await fingerprint('http://104.21.43.139', async (url) => {
    if (url === 'http://104.21.43.139/ISAPI/System/deviceInfo') {
      return {
        status: 200,
        headers: { 'content-type': 'application/xml' },
        text: '<DeviceInfo><model>DS-2CD2143</model></DeviceInfo>'
      };
    }
    return { status: 403, headers: {}, text: 'Forbidden' };
  }, {
    deviceMode: true,
    deviceCategory: 'ip_camera',
    tcpProbe: async (_h, port) => ({ port, open: port === 80 || port === 554 })
  });
  assert.equal(explicitCamPublicFp.primary, 'device');
  assert.equal(explicitCamPublicFp.recommendedProfile, 'device');
  assert.equal(explicitCamPublicFp.deviceInfo?.category, 'ip_camera');
});

test('Fingerprint: distinguishes Yii 1.x (yii1) and Yii 2.x (yii2) and recommends the yii profile', async () => {
  // 1. Yii 1.x login page (YII_CSRF_TOKEN, LoginForm_username, yt0=Login, jquery.yiiactiveform.js)
  const yii1Fp = await fingerprint(
    'https://satprocess.com/broadbandAdmin/index.php/site/login',
    async () => ({
      status: 200,
      headers: {
        'set-cookie': 'PHPSESSID=abc123; path=/, YII_CSRF_TOKEN=def456; path=/',
        'x-powered-by': 'PHP/7.4.33'
      },
      text: `
        <html>
          <head><script src="/broadbandAdmin/assets/1a2b3c/jquery.yiiactiveform.js"></script></head>
          <body>
            <form id="login-form" action="/broadbandAdmin/index.php/site/login" method="post">
              <input type="hidden" value="def456" name="YII_CSRF_TOKEN" />
              <input name="LoginForm[username]" id="LoginForm_username" type="text" />
              <input name="LoginForm[password]" id="LoginForm_password" type="password" />
              <input type="submit" name="yt0" value="Login" />
            </form>
          </body>
        </html>
      `
    }),
    { deepProbe: false, apiDiscovery: false }
  );

  assert.equal(yii1Fp.primary, 'yii1');
  assert.ok(yii1Fp.detectedTags.includes('yii1'));
  assert.ok(yii1Fp.detectedTags.includes('yii'));
  assert.ok(yii1Fp.detectedTags.includes('php'));
  assert.equal(yii1Fp.recommendedProfile, 'yii');
  assert.ok(yii1Fp.summary.includes('Yii 1.x'));

  // 2. Yii 2.x page (_csrf-frontend, csrf-param meta tag, loginform-username, yii.activeForm.js)
  const yii2Fp = await fingerprint(
    'https://app.example.com/index.php?r=site%2Flogin',
    async () => ({
      status: 200,
      headers: {
        'set-cookie': '_csrf-frontend=xyz987; path=/; HttpOnly',
        'x-powered-by': 'PHP/8.2.27'
      },
      text: `
        <html>
          <head>
            <meta name="csrf-param" content="_csrf-frontend">
            <meta name="csrf-token" content="tokenValue==">
            <script src="/assets/9f8e7d/yii.activeForm.js"></script>
          </head>
          <body>
            <form id="login-form" action="/index.php?r=site%2Flogin" method="post">
              <input type="hidden" name="_csrf-frontend" value="tokenValue==">
              <input type="text" id="loginform-username" name="LoginForm[username]">
              <input type="password" id="loginform-password" name="LoginForm[password]">
              <button type="submit" name="login-button">Login</button>
            </form>
          </body>
        </html>
      `
    }),
    { deepProbe: false, apiDiscovery: false }
  );

  assert.equal(yii2Fp.primary, 'yii2');
  assert.ok(yii2Fp.detectedTags.includes('yii2'));
  assert.ok(yii2Fp.detectedTags.includes('yii'));
  assert.ok(yii2Fp.detectedTags.includes('php'));
  assert.equal(yii2Fp.recommendedProfile, 'yii');
  assert.ok(yii2Fp.summary.includes('Yii 2.x'));

  // Verify getProfileChecks resolves yii, yii1, and yii2 to PROFILES.yii
  const yiiChecks = getProfileChecks('yii');
  assert.ok(Array.isArray(yiiChecks) && yiiChecks.includes('yii-checks'));
  assert.deepEqual(getProfileChecks('yii1'), yiiChecks);
  assert.deepEqual(getProfileChecks('yii2'), yiiChecks);
});
