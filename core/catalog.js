import fs from 'node:fs';
import path from 'node:path';
import { PROFILES } from './profiles.js';

/**
 * Rich security check metadata list for regular-person friendly explanations.
 */
const METADATA_ENTRIES = [
  {
    id: 'admin-panels',
    title: 'Administrative Panels Exposure',
    category: 'Access Control',
    plainExplanation: 'Scans for publicly exposed administrative dashboards and login panels (e.g., /admin, /administrator, /cpanel).',
    whyItMatters: 'Exposed admin interfaces attract automated brute-force attacks and credential stuffing.',
    defaultFix: 'Restrict access by IP whitelist, VPN, or require multi-factor authentication (MFA).',
    aliases: ['admin panels', 'admin panel', 'admin panel exposure']
  },
  {
    id: 'api-communication',
    title: 'Client-Side API Communication & Endpoint Discovery',
    category: 'API Security',
    plainExplanation: 'Inspects Single Page Application (SPA) HTML, JavaScript bundles (Angular, React, Vue, Next.js), runtime configuration files (/assets/config.json, /config.json, /env.js), and CSP connect-src directives to map client-to-API communication, discover backend REST/GraphQL/WebSocket endpoints, and detect unauthenticated API data exposure or insecure API configurations.',
    whyItMatters: 'Modern SPAs communicate directly with same-origin or external backend APIs via Angular HttpClient, Fetch, Axios, or GraphQL. Hardcoded development/localhost API URLs, plaintext HTTP API endpoints on HTTPS pages, exposed runtime config files, or unauthenticated JSON API endpoints can leak sensitive customer data, credentials, and internal service topology.',
    defaultFix: 'Use environment-specific production builds (e.g., Angular environment.prod.ts without dev proxy.conf.json localhost URLs), enforce HTTPS for all API origins, require authentication on sensitive REST/GraphQL endpoints, remove secrets from public /assets/config.json files, and restrict allowed API origins via Content-Security-Policy connect-src and strict CORS policies.',
    aliases: [
      'api communication',
      'api-communication',
      'client-side api communication',
      'client-side api communication & endpoint discovery',
      'spa api communication',
      'spa api discovery'
    ]
  },
  {
    id: 'api-endpoints',
    title: 'Sensitive API Endpoints',
    category: 'API Security',
    plainExplanation: 'Discovers exposed internal API endpoints, debug endpoints, and Swagger/OpenAPI documentation.',
    whyItMatters: 'Publicly readable API endpoints can leak system architectures, internal schemas, and unprotected administrative actions.',
    defaultFix: 'Enforce authentication and role-based access control on all internal endpoints and disable debug routes in production.',
    aliases: ['api endpoints', 'api endpoint exposure', 'api docs exposure']
  },
  {
    id: 'clickjacking',
    title: 'Clickjacking Protection',
    category: 'HTTP Headers',
    plainExplanation: 'Checks if your web pages can be embedded in an iframe on third-party websites.',
    whyItMatters: 'Attackers can trick users into clicking invisible buttons or submitting forms on your site while thinking they are on another site.',
    defaultFix: 'Add the "X-Frame-Options: DENY" or "Content-Security-Policy: frame-ancestors \'none\'" HTTP header.',
    aliases: ['clickjacking', 'iframe clickjacking']
  },
  {
    id: 'codeigniter-checks',
    title: 'CodeIgniter Framework Security',
    category: 'Framework Security',
    plainExplanation: 'Checks for known CodeIgniter vulnerabilities, exposed writable logs, and system folders.',
    whyItMatters: 'Outdated CodeIgniter versions and exposed application logs can lead to remote code execution and credential leakage.',
    defaultFix: 'Upgrade CodeIgniter to the latest release and ensure application/system folders are outside the web root.',
    aliases: ['codeigniter security', 'codeigniter', 'codeigniter-checks', 'codeigniter exposure']
  },
  {
    id: 'cookie-security',
    title: 'Cookie Security Attributes',
    category: 'Authentication & Session',
    plainExplanation: 'Verifies that cookies have Secure, HttpOnly, and SameSite flags configured.',
    whyItMatters: 'Cookies missing HttpOnly can be stolen via XSS, and cookies missing Secure can be intercepted over unencrypted networks.',
    defaultFix: 'Set "Secure; HttpOnly; SameSite=Lax" (or SameSite=Strict) on all session and sensitive cookies.',
    aliases: ['cookie security', 'insecure cookies']
  },
  {
    id: 'cors',
    title: 'CORS Configuration',
    category: 'API Security',
    plainExplanation: 'Checks for overly permissive Cross-Origin Resource Sharing (CORS) policies like wildcard origins with credentials.',
    whyItMatters: 'Permissive CORS allows malicious third-party websites to read sensitive user data from your API via cross-origin requests.',
    defaultFix: 'Specify explicit trusted origins in the "Access-Control-Allow-Origin" header and avoid reflecting arbitrary origins with credentials.',
    aliases: ['cors', 'cors configuration', 'cross-origin resource sharing', 'cors misconfiguration']
  },
  {
    id: 'cve-2024-4577',
    title: 'PHP CGI Argument Injection (CVE-2024-4577)',
    category: 'Known Vulnerabilities',
    plainExplanation: 'Tests for critical Windows PHP CGI argument injection vulnerability allowing remote code execution.',
    whyItMatters: 'Attackers can execute arbitrary command-line code on the server without authentication.',
    defaultFix: 'Update PHP to patched versions (8.3.8+, 8.2.20+, 8.1.29+) and rewrite URL query strings to disallow argument injection.',
    aliases: ['php cgi rce (cve-2024-4577)', 'php-cgi rce (cve-2024-4577)', 'cve-2024-4577', 'php-cgi-rce']
  },
  {
    id: 'cve-2026-114938',
    title: 'Java4Shell Base64 Decoder Heap Overflow (CVE-2026-114938)',
    category: 'Known Vulnerabilities',
    plainExplanation: 'Passively inspects HTTP headers and Spring Boot Actuator endpoints (/actuator/info, /actuator/env) for Java runtime versions and CPU architectures affected by the Java4Shell Base64 AVX-512 heap overflow (CVE-2026-114938).',
    whyItMatters: 'Affected Java runtimes on x86-64 CPUs with AVX-512 VBMI suffer a heap buffer overflow in the Base64 intrinsic decoder, allowing unauthenticated attackers to crash the JVM or potentially achieve remote code execution.',
    defaultFix: 'Upgrade Java to patched releases (8u513+, 17.0.21.1+ / 17.0.22+, 21.0.13.1+ / 21.0.14+, 25.0.5.1+, or 27.0.1.1+). As an immediate workaround on affected x86-64 hosts, add -XX:-UseBASE64Intrinsics or -XX:UseAVX=2 to JVM flags and restrict public access to Actuator endpoints.',
    aliases: ['java4shell (cve-2026-114938)', 'java4shell', 'cve-2026-114938']
  },
  {
    id: 'cve-2026-123007',
    title: 'NGINX HTTP/2 Flow-Control Heap Overflow (CVE-2026-123007)',
    category: 'Known Vulnerabilities',
    plainExplanation: 'Passively checks whether an NGINX endpoint exposes HTTP/2 on a version affected by the ngx_http_v2_module flow-control heap buffer overflow (CVE-2026-123007).',
    whyItMatters: 'Unauthenticated clients sending crafted HTTP/2 flow-control sequences to affected NGINX versions can trigger a heap overflow causing worker crashes or potential remote code execution.',
    defaultFix: 'Upgrade NGINX OSS to 1.30.7+ (stable) or 1.31.9+ (mainline), or NGINX Plus to R37 build 37.0.8.1+ or 37.3.0.1+. As an immediate mitigation, disable HTTP/2 (http2 off; / remove listen ... http2).',
    aliases: ['nginx http/2 heap overflow (cve-2026-123007)', 'cve-2026-123007']
  },
  {
    id: 'cve-2026-123633',
    title: 'NGINX HTTP/2 Upstream Proxy UAF (CVE-2026-123633)',
    category: 'Known Vulnerabilities',
    plainExplanation: 'Passively checks whether an NGINX reverse proxy exposes HTTP/2 on a version affected by the ngx_http_v2_module upstream proxy use-after-free vulnerability (CVE-2026-123633).',
    whyItMatters: 'When NGINX terminates HTTP/2 and proxies requests upstream, affected versions can suffer a use-after-free memory corruption bug leading to worker crashes or potential remote code execution.',
    defaultFix: 'Upgrade NGINX OSS to 1.30.7+ (stable) or 1.31.9+ (mainline), or NGINX Plus to 37.0.7.1+, 37.2.0.1+, or 37.3.0.1+. As an immediate mitigation, disable HTTP/2 (http2 off; / remove listen ... http2).',
    aliases: ['nginx http/2 upstream uaf (cve-2026-123633)', 'cve-2026-123633']
  },
  {
    id: 'cve-2026-123634',
    title: 'NGINX Resolver & Upstream Proxy UAF Advisory (CVE-2026-123634)',
    category: 'Known Vulnerabilities',
    plainExplanation: 'Passively checks unmasked NGINX version banners alongside upstream proxy signals for potential exposure to the resolver + variable proxy_pass + mirror/SSI use-after-free (CVE-2026-123634).',
    whyItMatters: 'Unpatched NGINX OSS (<= 1.30.6 / <= 1.31.8) or NGINX Plus (< 37.0.8.1 / < 37.3.0.1) using resolver with variable proxy_pass and mirror or SSI can suffer worker heap corruption or RCE.',
    defaultFix: 'Upgrade NGINX OSS to 1.30.7+ (stable) or 1.31.9+ (mainline), or NGINX Plus to 37.0.8.1+ or 37.3.0.1+, and verify nginx.conf resolver/mirror/SSI usage.',
    aliases: [
      'nginx resolver & upstream proxy uaf advisory (cve-2026-123634)',
      'cve-2026-123634'
    ]
  },
  {
    id: 'cve-jdk-advisories',
    title: 'JDK & Java Security Advisories (CVE-2026-91403, CVE-2026-114820, CVE-2026-114939, CVE-2026-114940, CVE-2026-22016, CVE-2026-34282, CVE-2026-47063, CVE-2026-91398, CVE-2026-91453)',
    category: 'Known Vulnerabilities',
    plainExplanation: 'Passively inspects HTTP headers and Spring Boot Actuator endpoints (/actuator/info, /actuator/env) for Java runtime versions affected by 2026 Oracle CPU/CSPU and OpenJDK advisories across all CPU architectures including ARM64 and Java 8/11.',
    whyItMatters: 'Unpatched JDK releases suffer compromised eMudhra CA truststore certificates (CVE-2026-91403, CVE-2026-114820), JAXP XPath XXE (CVE-2026-22016), TLS close-notify DoS (CVE-2026-34282), JAR signature bypass (CVE-2026-47063), Kerberos/TLS client auth flaws (CVE-2026-114939, CVE-2026-114940), and networking/httpserver flaws.',
    defaultFix: 'Upgrade JDK/JRE to the Nov 17, 2026 patched baselines (8u513+, 11.0.33.1+, 17.0.21.1+, 21.0.13.1+, 25.0.5.1+, or 27.0.1.1+) and restrict public access to /actuator/info and /actuator/env.',
    aliases: [
      'jdk & java security advisories (cve-2026-91403, cve-2026-114820, cve-2026-114939, cve-2026-114940, cve-2026-22016, cve-2026-34282, cve-2026-47063, cve-2026-91398, cve-2026-91453)',
      'jdk security advisory (cve-2026-91403)',
      'jdk security advisory (cve-2026-114820)',
      'jdk security advisory (cve-2026-114939)',
      'jdk security advisory (cve-2026-114940)',
      'jdk security advisory (cve-2026-22016)',
      'jdk security advisory (cve-2026-34282)',
      'jdk security advisory (cve-2026-47063)',
      'jdk security advisory (cve-2026-91398)',
      'jdk security advisory (cve-2026-91453)',
      'jdk unconfirmed version advisory (cve-2026-91403)',
      'jdk unconfirmed version advisory (cve-2026-114820)',
      'jdk unconfirmed version advisory (cve-2026-114939)',
      'jdk unconfirmed version advisory (cve-2026-114940)',
      'jdk unconfirmed version advisory (cve-2026-22016)',
      'jdk unconfirmed version advisory (cve-2026-34282)',
      'jdk unconfirmed version advisory (cve-2026-47063)',
      'jdk unconfirmed version advisory (cve-2026-91398)',
      'jdk unconfirmed version advisory (cve-2026-91453)',
      'cve-jdk-advisories'
    ]
  },
  {
    id: 'cve-nginx-http3',
    title: 'NGINX HTTP/3 Security Advisories (CVE-2026-121810, CVE-2026-95101, CVE-2026-90439)',
    category: 'Known Vulnerabilities',
    plainExplanation: 'Passively checks NGINX Server banners and same-origin Alt-Svc: h3 HTTP/3 advertisements for vulnerabilities in ngx_http_v3_module including HTTP/3 UAF (CVE-2026-121810), request body injection (CVE-2026-95101), and OpenSSL QUIC heap overflow (CVE-2026-90439).',
    whyItMatters: 'Affected NGINX servers advertising HTTP/3 over QUIC can suffer remote worker crashes, heap memory corruption, or HTTP/3 request smuggling.',
    defaultFix: 'Upgrade NGINX OSS to 1.30.7+ (stable) or 1.31.9+ (mainline), or NGINX Plus to 37.0.8.1+ or 37.3.0.1+, and ensure OpenSSL >= 3.5.1 is used for HTTP/3.',
    aliases: [
      'nginx http/3 security advisories (cve-2026-121810, cve-2026-95101, cve-2026-90439)',
      'nginx http/3 vulnerability (cve-2026-121810)',
      'nginx http/3 vulnerability (cve-2026-95101)',
      'nginx http/3 advisory (cve-2026-90439)',
      'nginx http/3 distro backport check (cve-2026-121810)',
      'nginx http/3 distro backport check (cve-2026-95101)',
      'nginx http/3 distro backport check (cve-2026-90439)',
      'nginx http/3 suppressed version advisory',
      'cve-nginx-http3'
    ]
  },
  {
    id: 'cve-nginx-tls',
    title: 'NGINX TLS 1.3 Security Advisories (CVE-2026-118899, CVE-2026-97629, CVE-2025-23419)',
    category: 'Known Vulnerabilities',
    plainExplanation: 'Passively inspects TLS 1.3 protocol negotiation alongside NGINX Server banners for TLS 1.3 request body infinite-loop DoS (CVE-2026-118899), session ticket forgery/mTLS bypass (CVE-2026-97629), and SNI session resumption client-cert bypass (CVE-2025-23419).',
    whyItMatters: 'Affected NGINX servers negotiating TLS 1.3 can be stalled by infinite-loop worker DoS or suffer session ticket forgery and mutual TLS client-certificate authentication bypasses.',
    defaultFix: 'Upgrade NGINX OSS to 1.30.7+ (stable) or 1.31.9+ (mainline), or NGINX Plus to 37.0.8.1+ or 37.3.0.1+, and configure explicit ssl_session_ticket_key rotation when using shared session caches.',
    aliases: [
      'nginx tls 1.3 security advisories (cve-2026-118899, cve-2026-97629, cve-2025-23419)',
      'nginx tls 1.3 vulnerability (cve-2026-118899)',
      'nginx tls 1.3 advisory (cve-2026-97629)',
      'nginx tls 1.3 advisory (cve-2025-23419)',
      'nginx tls 1.3 distro backport check (cve-2026-118899)',
      'nginx tls 1.3 distro backport check (cve-2026-97629)',
      'nginx tls 1.3 distro backport check (cve-2025-23419)',
      'nginx tls 1.3 suppressed version advisory',
      'cve-nginx-tls'
    ]
  },
  {
    id: 'cve-apache-httpd',
    title: 'Apache HTTP Server CVEs (CVE-2024-38476, CVE-2024-38477, CVE-2024-39573, CVE-2024-27316)',
    category: 'Known Vulnerabilities',
    plainExplanation: 'Passively inspects Apache HTTP Server Server banners and HTTP/2 signals (ALPN/Alt-Svc) for vulnerabilities including mod_proxy backend handler confusion (CVE-2024-38476), mod_proxy null pointer crash (CVE-2024-38477), mod_rewrite SSRF (CVE-2024-39573), and HTTP/2 CONTINUATION flood DoS (CVE-2024-27316).',
    whyItMatters: 'Unpatched upstream Apache HTTP Server versions before 2.4.62 can allow source code disclosure, SSRF, request smuggling/handler confusion, and denial of service via HTTP/2 header floods.',
    defaultFix: 'Upgrade Apache HTTP Server to 2.4.62+ (or 2.4.63+), or apply distribution vendor security updates. Set "ServerTokens Prod" to suppress detailed version banners.',
    aliases: [
      'apache http server cves (cve-2024-38476, cve-2024-38477, cve-2024-39573, cve-2024-27316)',
      'apache http server distro backport check (cve-2024-38476)',
      'apache http server distro backport check (cve-2024-38477)',
      'apache http server distro backport check (cve-2024-39573)',
      'apache http server distro backport check (cve-2024-27316)',
      'apache http server vulnerability (cve-2024-38476)',
      'apache http server vulnerability (cve-2024-38477)',
      'apache http server vulnerability (cve-2024-39573)',
      'apache http server vulnerability (cve-2024-27316)',
      'cve-apache-httpd'
    ]
  },
  {
    id: 'cve-nextjs-react',
    title: 'Next.js & React Server Components CVEs (CVE-2025-55182, CVE-2024-34351, CVE-2024-46982)',
    category: 'Known Vulnerabilities',
    plainExplanation: 'Checks Next.js and React Server Components (RSC) endpoints non-destructively for React2Shell RSC exposure (CVE-2025-55182), Server Actions host-header SSRF/redirect reflection (CVE-2024-34351), and SSR cache poisoning (CVE-2024-46982).',
    whyItMatters: 'Affected React 19 RSC and Next.js releases allow unauthenticated remote code execution via Flight protocol deserialization, forged Server Action redirects/SSRF via X-Forwarded-Host, or poisoning public caches with private SSR data.',
    defaultFix: 'Upgrade Next.js to 15.0.5+, 15.1.9+, 15.2.6+, 15.3.6+, 15.4.8+, 15.5.7+, or 16.0.7+ (and >= 14.2.10 on 14.x), and upgrade React to 19.0.1+, 19.1.2+, or 19.2.1+. Strip untrusted X-Forwarded-Host and x-now-route-matches headers at your reverse proxy and block public access to package.json.',
    aliases: [
      'next.js & react server components cves (cve-2025-55182, cve-2024-34351, cve-2024-46982)',
      'next.js cache poisoning via x-now-route-matches (cve-2024-46982)',
      'next.js cache poisoning indicator (cve-2024-46982)',
      'next.js server actions host-header ssrf / redirect reflection (cve-2024-34351)',
      'next.js server actions redirect reflection (cve-2024-34351)',
      'react server components / next.js flight protocol exposure (cve-2025-55182)',
      'vulnerable next.js version for rsc cve-2025-55182',
      'vulnerable next.js version for cve-2024-34351',
      'vulnerable next.js version for cve-2024-46982',
      'vulnerable react 19 version in rsc payload (cve-2025-55182)',
      'next.js version in exposed package.json (cve-2025-55182)',
      'react version in exposed package.json (cve-2025-55182)',
      'cve-nextjs-react'
    ]
  },
  {
    id: 'cve-node-express',
    title: 'Node.js & Express Ecosystem CVEs (CVE-2024-29041, CVE-2024-43796, CVE-2024-37890, CVE-2025-27152)',
    category: 'Known Vulnerabilities',
    plainExplanation: 'Inspects exposed /package.json, /package-lock.json, and /node_modules/express/package.json manifests for vulnerable versions of express (CVE-2024-29041, CVE-2024-43796), ws (CVE-2024-37890), and axios (CVE-2025-27152).',
    whyItMatters: 'Vulnerable Express versions allow open redirects or XSS via response.redirect(), vulnerable ws versions crash on excessive HTTP headers (DoS), and vulnerable axios versions leak credentials or allow SSRF when handling absolute URLs.',
    defaultFix: 'Upgrade express to 4.21.2+ (or 5.0.0+), ws to 8.17.1+ (or 7.5.10+), and axios to 1.8.2+. Block public HTTP access to package.json, package-lock.json, and node_modules/.',
    aliases: [
      'node.js & express ecosystem cves (cve-2024-29041, cve-2024-43796, cve-2024-37890, cve-2025-27152)',
      'express open redirect in response.redirect (cve-2024-29041)',
      'express xss via response.redirect (cve-2024-43796)',
      'express wildcard version exposure (cve-2024-43796)',
      'ws websocket server header count dos (cve-2024-37890)',
      'ws wildcard version exposure (cve-2024-37890)',
      'axios ssrf & credential leakage on absolute urls (cve-2025-27152)',
      'axios wildcard version exposure (cve-2025-27152)',
      'cve-node-express'
    ]
  },
  {
    id: 'cve-php-ecosystem',
    title: 'PHP, Laravel & Symfony Ecosystem CVEs (CVE-2025-1217, CVE-2025-27515, CVE-2024-50342 & Nov 2026 PHP CVEs)',
    category: 'Known Vulnerabilities',
    plainExplanation: 'Passively inspects X-Powered-By / Server PHP banners and exposed /composer.json and /composer.lock manifests for PHP core/FPM/CGI/session/stream CVEs (including CVE-2025-1217 and 12 November 2026 advisories), Laravel file validation bypass (CVE-2025-27515), and Symfony HttpFoundation Request parsing vulnerabilities (CVE-2024-50342).',
    whyItMatters: 'Vulnerable PHP, Laravel, and Symfony versions can allow unauthenticated FastCGI request smuggling RCE, session deserialization/UAF RCE, uriparser integer overflows, cleartext TLS downgrades, HTTP DoS, uploaded file validation bypasses, and FPM status XSS.',
    defaultFix: 'Upgrade PHP to 8.2.36+, 8.3.37+, 8.4.28+, 8.5.13+, or 8.6.0+ (or apply vendor distro security updates), upgrade laravel/framework to 11.44.1+ or 12.1.1+, and upgrade symfony/http-foundation to 6.4.14+ or 7.1.7+. Remove composer.json/composer.lock from public web roots and set expose_php = Off.',
    aliases: [
      'php, laravel & symfony ecosystem cves (cve-2025-1217, cve-2025-27515, cve-2024-50342)',
      'php, laravel & symfony ecosystem cves (cve-2025-1217, cve-2025-27515, cve-2024-50342 & nov 2026 php cves)',
      'php distro backport check (cve-2025-1217)',
      'php http header parsing vulnerability (cve-2025-1217)',
      'php ecosystem vulnerability (cve-2026-129289)',
      'php distro backport check (cve-2026-129289)',
      'php ecosystem vulnerability (cve-2026-129182)',
      'php distro backport check (cve-2026-129182)',
      'php ecosystem vulnerability (cve-2026-129474)',
      'php distro backport check (cve-2026-129474)',
      'php ecosystem vulnerability (cve-2026-129496)',
      'php distro backport check (cve-2026-129496)',
      'php ecosystem vulnerability (cve-2026-129481)',
      'php distro backport check (cve-2026-129481)',
      'php ecosystem vulnerability (cve-2026-126714)',
      'php distro backport check (cve-2026-126714)',
      'php ecosystem vulnerability (cve-2026-115560)',
      'php distro backport check (cve-2026-115560)',
      'php ecosystem vulnerability (cve-2026-48841)',
      'php distro backport check (cve-2026-48841)',
      'php ecosystem vulnerability (cve-2026-127960)',
      'php distro backport check (cve-2026-127960)',
      'php ecosystem vulnerability (cve-2026-128064)',
      'php distro backport check (cve-2026-128064)',
      'php ecosystem vulnerability (cve-2026-129538)',
      'php distro backport check (cve-2026-129538)',
      'php ecosystem vulnerability (cve-2026-129292)',
      'php distro backport check (cve-2026-129292)',
      'laravel file validation bypass (cve-2025-27515)',
      'symfony httpfoundation request url parsing flaw (cve-2024-50342)',
      'yii 2 __wakeup() behavior attachment rce (cve-2024-58136)',
      'yii 2 unsafe object deserialization (cve-2024-4991)',
      'yii 1.1 predictable prng / eol vulnerability (cve-2021-3692)',
      'cve-php-ecosystem'
    ]
  },
  {
    id: 'cve-python-web',
    title: 'Python Web Ecosystem CVEs (CVE-2024-45230, CVE-2024-53907, CVE-2025-26699, CVE-2024-47874, CVE-2024-56326)',
    category: 'Known Vulnerabilities',
    plainExplanation: 'Inspects exposed /requirements.txt, /openapi.json, response headers, and Python/Django debug error pages for vulnerable Django releases (CVE-2024-45230, CVE-2024-53907, CVE-2025-26699), Starlette/FastAPI multipart DoS versions (CVE-2024-47874), and Jinja2 sandboxed format string bypass versions (CVE-2024-56326).',
    whyItMatters: 'Affected Django versions suffer SQL injection via JSONField HasKey lookups and denial-of-service in urlize/wrap filters, affected Starlette/FastAPI versions allow unauthenticated memory exhaustion via crafted multipart form uploads, and affected Jinja2 versions (< 3.1.5) allow sandboxed format string execution bypass.',
    defaultFix: 'Upgrade Django to 4.2.19+, 5.0.12+, or 5.1.6+; upgrade Starlette to 0.40.0+, FastAPI to 0.115.0+, and Jinja2 to 3.1.5+. Disable DEBUG = True in production and ensure requirements.txt is not publicly served.',
    aliases: [
      'python web ecosystem cves (cve-2024-45230, cve-2024-53907, cve-2025-26699, cve-2024-47874, cve-2024-56326)',
      'python web ecosystem cves (cve-2024-45230, cve-2024-53907, cve-2025-26699, cve-2024-47874)',
      'django sql injection via jsonfield haskey (cve-2024-53907)',
      'django urlize/urlizetrunc dos (cve-2024-45230)',
      'django wordwrap dos (cve-2025-26699)',
      'starlette multipart form memory exhaustion dos (cve-2024-47874)',
      'fastapi / starlette multipart form memory exhaustion dos (cve-2024-47874)',
      'starlette multipart dos header version (cve-2024-47874)',
      'jinja2 sandboxed environment format string execution bypass (cve-2024-56326)',
      'cve-python-web'
    ]
  },
  {
    id: 'cve-spring-framework',
    title: 'Spring Boot & Spring Framework CVEs (CVE-2024-38816, CVE-2024-38819, CVE-2025-22235, CVE-2024-22262)',
    category: 'Known Vulnerabilities',
    plainExplanation: 'Inspects Spring Boot Actuator metadata (/actuator/info, /actuator/env) and runs strictly non-destructive probes for static resource path traversal (CVE-2024-38816, CVE-2024-38819), EndpointRequest security matcher bypass (CVE-2025-22235), and UriComponentsBuilder open redirect (CVE-2024-22262).',
    whyItMatters: 'Vulnerable Spring WebMvc/WebFlux and Spring Boot versions can expose arbitrary server files through static routing, bypass security matchers for disabled actuator endpoints, or permit SSRF and open redirects due to URL parsing discrepancies.',
    defaultFix: 'Upgrade Spring Boot to 3.3.10+ / 3.4.5+ and Spring Framework to 6.1.14+ / 6.2.6+. Disable public exposure of /actuator/info and /actuator/env, and enforce strict allowlist validation on external redirect URLs.',
    aliases: [
      'spring boot & spring framework cves (cve-2024-38816, cve-2024-38819, cve-2025-22235, cve-2024-22262)',
      'spring webmvc/webflux path traversal (cve-2024-38816)',
      'spring webmvc/webflux path traversal (cve-2024-38819)',
      'spring uricomponentsbuilder open redirect / ssrf (cve-2024-22262)',
      'spring boot endpointrequest matcher bypass (cve-2025-22235)',
      'spring boot / framework path traversal version (cve-2024-38816)',
      'spring boot / framework path traversal version (cve-2024-38819)',
      'spring framework path traversal version (cve-2024-38816)',
      'spring framework path traversal version (cve-2024-38819)',
      'spring framework uricomponentsbuilder redirect version (cve-2024-22262)',
      'cve-spring-framework'
    ]
  },
  {
    id: 'cve-tomcat',
    title: 'Apache Tomcat CVEs (CVE-2025-24813, CVE-2024-50379, CVE-2025-31650)',
    category: 'Known Vulnerabilities',
    plainExplanation: 'Passively inspects Server headers, default Tomcat error pages, Alt-Svc HTTP/2 indicators, and OPTIONS Allow methods for Apache Tomcat versions affected by partial-PUT deserialization RCE (CVE-2025-24813), case-insensitive PUT race RCE (CVE-2024-50379), and HTTP/2 memory leak DoS (CVE-2025-31650).',
    whyItMatters: 'Vulnerable Apache Tomcat releases with DefaultServlet write/PUT support enabled or HTTP/2 active can suffer unauthenticated remote code execution via uploaded/deserialized files or denial of service via memory exhaustion.',
    defaultFix: 'Upgrade Apache Tomcat to 9.0.105+, 10.1.41+, or 11.0.7+ (or apply vendor distro patches). Keep DefaultServlet readonly=true, disable HTTP PUT unless required, and suppress Tomcat version details from Server and error pages.',
    aliases: [
      'apache tomcat cves (cve-2025-24813, cve-2024-50379, cve-2025-31650)',
      'apache tomcat distro backport check (cve-2025-24813)',
      'apache tomcat distro backport check (cve-2024-50379)',
      'apache tomcat distro backport check (cve-2025-31650)',
      'apache tomcat vulnerability (cve-2025-24813)',
      'apache tomcat vulnerability (cve-2024-50379)',
      'apache tomcat vulnerability (cve-2025-31650)',
      'cve-tomcat'
    ]
  },
  {
    id: 'cve-wordpress-ecosystem',
    title: 'WordPress Core & Plugin CVEs (CVE-2024-10924, CVE-2024-4439, CVE-2024-6307)',
    category: 'Known Vulnerabilities',
    plainExplanation: 'Passively checks WordPress generator headers/meta tags, /readme.html, Really Simple Security / Really Simple SSL plugin readme.txt, and /wp-json/reallysimplessl/v1/ for authentication bypass (CVE-2024-10924) and WordPress core stored XSS CVEs (CVE-2024-4439, CVE-2024-6307).',
    whyItMatters: 'Really Simple Security (< 9.1.2) suffers a critical unauthenticated authentication bypass allowing administrator account takeover, while outdated WordPress core releases (< 6.5.5 / < 6.6.2) allow stored XSS.',
    defaultFix: 'Upgrade Really Simple Security / Really Simple SSL to 9.1.2+ immediately and upgrade WordPress core to 6.7.2+ (minimum 6.6.2+). Remove /readme.html and disable WordPress version generator headers and meta tags.',
    aliases: [
      'wordpress core & plugin cves (cve-2024-10924, cve-2024-4439, cve-2024-6307)',
      'really simple security authentication bypass (cve-2024-10924)',
      'exposed really simple security rest namespace (cve-2024-10924)',
      'wordpress core avatar block stored xss (cve-2024-4439)',
      'wordpress core views block stored xss (cve-2024-6307)',
      'cve-wordpress-ecosystem'
    ]
  },
  {
    id: 'directory-listing',
    title: 'Directory Indexing / Listing',
    category: 'Information Disclosure',
    plainExplanation: 'Checks if web server directories without index files display automatic file listings.',
    whyItMatters: 'Allows attackers to browse internal folder contents, discover forgotten backups, uploaded files, and source code.',
    defaultFix: 'Disable directory browsing in web server configuration (e.g., "Options -Indexes" in Apache, "autoindex off" in Nginx).',
    aliases: ['directory listing', 'directory indexing']
  },
  {
    id: 'drupal-checks',
    title: 'Drupal CMS Security',
    category: 'CMS Security',
    plainExplanation: 'Audits Drupal installations for end-of-life versions, exposed CHANGELOG files, and administrative routes.',
    whyItMatters: 'Unsupported Drupal versions contain known critical vulnerabilities that can lead to complete site takeover.',
    defaultFix: 'Upgrade to an actively supported Drupal release and restrict access to CHANGELOG.txt and admin paths.',
    aliases: ['drupal security', 'drupal', 'drupal-checks', 'drupal exposure']
  },
  {
    id: 'env',
    title: 'Environment File Exposure (.env)',
    category: 'Secrets & Exposure',
    plainExplanation: 'Checks if environment configuration files (.env, .env.backup, etc.) are downloadable from the web.',
    whyItMatters: '.env files usually contain database passwords, API secrets, JWT keys, and payment gateway tokens.',
    defaultFix: 'Block web server access to all dotfiles (e.g. location ~ /\\. { deny all; }) and store sensitive configs outside web roots.',
    aliases: ['.env exposure', 'env exposure', 'env file exposure', 'env', '.env']
  },
  {
    id: 'frontend-checks',
    title: 'Frontend Source Maps & Dev Artifacts',
    category: 'Information Disclosure',
    plainExplanation: 'Checks for exposed production JavaScript source maps (.js.map), debug modes, and hardcoded API tokens.',
    whyItMatters: 'Source maps reconstruct original client-side source code, revealing internal endpoints, comments, and architectural flaws.',
    defaultFix: 'Do not deploy .map files to public production servers; generate source maps only for internal error tracking.',
    aliases: ['frontend security', 'frontend-checks', 'source maps']
  },
  {
    id: 'git',
    title: 'Git Repository Exposure (.git)',
    category: 'Secrets & Exposure',
    plainExplanation: 'Checks if the .git folder or .git/HEAD is publicly accessible on the web server.',
    whyItMatters: 'Exposed Git folders allow attackers to download your entire source code repository, history, and embedded secrets.',
    defaultFix: 'Configure your web server to strictly block access to the .git directory or exclude .git during deployment.',
    aliases: ['.git exposure', 'git exposure', 'git', '.git']
  },
  {
    id: 'graphql',
    title: 'GraphQL Introspection & Security',
    category: 'API Security',
    plainExplanation: 'Checks if GraphQL schema introspection is enabled in production environments.',
    whyItMatters: 'Introspection exposes your entire GraphQL schema, types, queries, and mutations to any unauthenticated caller.',
    defaultFix: 'Disable GraphQL schema introspection in production deployments.',
    aliases: ['graphql introspection', 'graphql security', 'graphql']
  },
  {
    id: 'http-methods',
    title: 'Dangerous HTTP Methods',
    category: 'HTTP Headers',
    plainExplanation: 'Tests whether dangerous or unnecessary HTTP verbs (PUT, DELETE, TRACE, OPTIONS) are accepted.',
    whyItMatters: 'TRACE enables Cross-Site Tracing (XST) attacks; improperly configured PUT/DELETE allows unauthorized file modification.',
    defaultFix: 'Disable TRACE and restrict HTTP methods to only GET, POST, and HEAD for public web pages.',
    aliases: ['dangerous http methods', 'http methods']
  },
  {
    id: 'http-redirect',
    title: 'HTTP to HTTPS Redirection',
    category: 'Network & Transport',
    plainExplanation: 'Verifies that unencrypted HTTP connections are automatically redirected to secure HTTPS.',
    whyItMatters: 'Unencrypted HTTP traffic can be intercepted, read, or modified by attackers on public networks.',
    defaultFix: 'Configure a permanent (301) redirect from HTTP to HTTPS across all web server hosts.',
    aliases: ['http to https redirect', 'http-redirect', 'https redirect']
  },
  {
    id: 'ignition',
    title: 'Laravel Ignition Debug RCE',
    category: 'Framework Security',
    plainExplanation: 'Detects exposed Laravel Ignition error page endpoints susceptible to known remote code execution exploits.',
    whyItMatters: 'Ignition debug routes in production can allow an attacker to run arbitrary PHP code on the server.',
    defaultFix: 'Set APP_DEBUG=false in production and ensure ignition package is only in require-dev.',
    aliases: ['laravel ignition rce', 'ignition', 'ignition rce', 'ignition rce (cve-2021-3129)']
  },
  {
    id: 'jwt-security',
    title: 'JSON Web Token (JWT) Security',
    category: 'Authentication & Session',
    plainExplanation: 'Audits JWT implementations for "none" algorithm flaws, weak secret keys, and exposed token endpoints.',
    whyItMatters: 'Vulnerable JWT implementations allow attackers to forge tokens and impersonate administrators.',
    defaultFix: 'Use strong cryptographic algorithms (RS256 or high-entropy HS256) and strictly reject tokens with "alg": "none".',
    aliases: ['jwt security', 'jwt', 'jwt-security']
  },
  {
    id: 'laravel-auth',
    title: 'Laravel Auth Routes & CSRF',
    category: 'Framework Security',
    plainExplanation: 'Checks Laravel login, registration, and password reset endpoints for missing CSRF protection and brute-force defenses.',
    whyItMatters: 'Unprotected authentication routes enable credential brute-forcing and cross-site request forgery.',
    defaultFix: 'Enable RateLimiter on authentication routes and ensure VerifyCsrfToken middleware is active.',
    aliases: ['laravel auth endpoints', 'laravel auth routes', 'laravel-auth']
  },
  {
    id: 'laravel-debug',
    title: 'Laravel Debug Mode Exposure',
    category: 'Framework Security',
    plainExplanation: 'Checks if Laravel debug mode (APP_DEBUG=true) is accidentally enabled in production.',
    whyItMatters: 'Debug mode displays detailed stack traces, database queries, and environment secrets when errors occur.',
    defaultFix: 'Set APP_DEBUG=false in your production .env file.',
    aliases: ['laravel debug mode', 'laravel debug', 'laravel debug exposure', 'laravel-debug']
  },
  {
    id: 'laravel-env-manipulation',
    title: 'Laravel Environment Manipulation',
    category: 'Framework Security',
    plainExplanation: 'Tests for parameter injection vulnerability attempting to switch application environment to local or debug.',
    whyItMatters: 'Allows attackers to manipulate framework runtime behavior and trigger verbose error responses.',
    defaultFix: 'Ensure framework dependencies are up-to-date and disallow CLI argument reflection in HTTP contexts.',
    aliases: ['laravel env manipulation', 'laravel env manipulation (cve-2024-52301)', 'laravel-env-manipulation']
  },
  {
    id: 'laravel-livewire',
    title: 'Laravel Livewire Security',
    category: 'Framework Security',
    plainExplanation: 'Audits Livewire endpoints (/livewire/update, /livewire/upload-file) for authorization bypasses and missing validation.',
    whyItMatters: 'Exposed Livewire component endpoints can allow unauthorized state modification or file upload vulnerabilities.',
    defaultFix: 'Ensure all Livewire components enforce authorization checks inside render/mount and validate all component properties.',
    aliases: ['laravel livewire security', 'laravel-livewire', 'livewire', 'livewire exposure (cve-2025-54068)', 'livewire exposure (cve-2024-47823)']
  },
  {
    id: 'laravel-storage',
    title: 'Laravel Storage & Log Exposure',
    category: 'Framework Security',
    plainExplanation: 'Checks if Laravel storage/logs, framework caches, or session files are accessible over HTTP.',
    whyItMatters: 'Storage logs contain user data, API errors, session identifiers, and sensitive system details.',
    defaultFix: 'Ensure only the "public" directory is served as the web root, not the project root directory.',
    aliases: ['laravel storage exposure', 'laravel storage', 'laravel-storage', 'laravel log exposure']
  },
  {
    id: 'laravel-telescope',
    title: 'Laravel Telescope Exposure',
    category: 'Framework Security',
    plainExplanation: 'Checks if Laravel Telescope debugging dashboard (/telescope) is publicly accessible.',
    whyItMatters: 'Telescope records all requests, SQL queries, mail messages, and user sessions in real-time.',
    defaultFix: 'Restrict Telescope access with Telescope::auth gate or disable it completely in production.',
    aliases: ['laravel telescope exposure', 'laravel telescope', 'laravel-telescope', 'telescope/horizon exposure', 'laravel telescope exposed', 'laravel horizon exposed']
  },
  {
    id: 'magento-checks',
    title: 'Magento / Adobe Commerce Security',
    category: 'CMS Security',
    plainExplanation: 'Checks for accessible Magento admin URLs, downloader tools, and config files like local.xml.',
    whyItMatters: 'Exposed local.xml files leak database credentials and encryption keys for customer passwords.',
    defaultFix: 'Block web access to /app, /downloader, and /var directories in web server configuration.',
    aliases: ['magento security', 'magento', 'magento-checks', 'magento exposure']
  },
  {
    id: 'magento-cosmicsting',
    title: 'Magento CosmicSting (CVE-2024-34102)',
    category: 'Known Vulnerabilities',
    plainExplanation: 'Checks for critical XML External Entity (XXE) injection vulnerability in Adobe Commerce and Magento.',
    whyItMatters: 'Allows unauthenticated attackers to read arbitrary files from the server, including secret encryption keys.',
    defaultFix: 'Apply Adobe security patch APSB24-40 immediately or upgrade Magento to 2.4.7-p1+.',
    aliases: ['magento cosmicsting (cve-2024-34102)', 'magento cosmicsting', 'cosmicsting']
  },
  {
    id: 'node-checks',
    title: 'Node.js & Express Security',
    category: 'Framework Security',
    plainExplanation: 'Scans for exposed package.json, node_modules directories, and X-Powered-By: Express headers.',
    whyItMatters: 'Exposed package.json reveals exact dependency versions, making it easy for attackers to target known CVEs.',
    defaultFix: 'Remove X-Powered-By with app.disable("x-powered-by") and ensure node_modules is outside web root.',
    aliases: ['node.js security', 'node security', 'node', 'node-checks']
  },
  {
    id: 'open-redirect',
    title: 'Open Redirect Vulnerability',
    category: 'Input Validation',
    plainExplanation: 'Tests if redirect parameters (e.g. ?url=, ?redirect=) accept arbitrary external websites.',
    whyItMatters: 'Attackers craft believable phishing links using your trusted domain that redirect victims to malicious sites.',
    defaultFix: 'Validate target URLs against a strict whitelist of internal relative paths or approved domains.',
    aliases: ['open redirect', 'open-redirect']
  },
  {
    id: 'php-backup',
    title: 'PHP Backup & Old Files',
    category: 'Information Disclosure',
    plainExplanation: 'Scans for forgotten backup files such as index.php.bak, config.php.old, or index.php~.',
    whyItMatters: 'Web servers often do not execute PHP for .bak or .old extensions, dumping raw PHP source code and credentials.',
    defaultFix: 'Never store backup or temporary files inside the web server document root; delete backup files after deployment.',
    aliases: ['php backup files', 'php-backup', 'backup files']
  },
  {
    id: 'php-cgi-exposure',
    title: 'PHP-FPM & CGI Status Exposure',
    category: 'Framework Security',
    plainExplanation: 'Checks for accessible /fpm-ping, /php-status, or cgi-bin PHP binaries.',
    whyItMatters: 'FPM status pages leak active client IPs, query strings, and script paths; exposed CGI binaries allow command execution.',
    defaultFix: 'Restrict /status and /ping endpoints in Nginx/Apache to localhost (127.0.0.1) only.',
    aliases: ['php cgi & fpm exposure', 'php-cgi/fpm exposure', 'php-cgi-exposure', 'php fpm status']
  },
  {
    id: 'php-config',
    title: 'Insecure PHP Configuration',
    category: 'Framework Security',
    plainExplanation: 'Checks for unsafe PHP directives such as allow_url_include, display_errors, or register_globals.',
    whyItMatters: 'Insecure PHP configurations enable Remote File Inclusion (RFI) and information disclosure.',
    defaultFix: 'Turn off display_errors, disable allow_url_include, and harden php.ini.',
    aliases: ['php configuration', 'php config exposure', 'php-config']
  },
  {
    id: 'php-errors',
    title: 'PHP Error & Exception Disclosure',
    category: 'Information Disclosure',
    plainExplanation: 'Checks if the web server displays verbose PHP warning, notice, or fatal error messages.',
    whyItMatters: 'Error messages display filesystem paths, line numbers, and database query structures to visitors.',
    defaultFix: 'Set display_errors = Off and log_errors = On in php.ini.',
    aliases: ['php errors', 'php error disclosure', 'php error exposure', 'php-errors']
  },
  {
    id: 'php-info',
    title: 'PHPInfo Page Exposure',
    category: 'Information Disclosure',
    plainExplanation: 'Checks for public phpinfo.php, info.php, or test.php files.',
    whyItMatters: 'phpinfo() outputs complete server environment variables, PHP modules, OS versions, and database usernames.',
    defaultFix: 'Delete any phpinfo() script files from public production servers.',
    aliases: ['phpinfo exposure', 'php info exposure', 'phpinfo', 'php-info']
  },
  {
    id: 'php-lfi',
    title: 'PHP Local File Inclusion (LFI)',
    category: 'Injection & Input',
    plainExplanation: 'Tests for directory traversal vulnerabilities in file inclusion parameters (e.g. ?page=../../etc/passwd).',
    whyItMatters: 'LFI allows attackers to read sensitive files from the server OS or execute code via log poisoning.',
    defaultFix: 'Use a strict whitelist of allowed file keys rather than passing user input directly to require/include.',
    aliases: ['php local file inclusion', 'local file inclusion (lfi)', 'php-lfi', 'lfi']
  },
  {
    id: 'php-version',
    title: 'PHP Version Disclosure & EOL',
    category: 'Information Disclosure',
    plainExplanation: 'Checks if PHP version is disclosed via X-Powered-By headers and whether that version is end-of-life.',
    whyItMatters: 'EOL versions no longer receive security fixes; disclosing the exact version makes targeting known exploits trivial.',
    defaultFix: 'Set expose_php = Off in php.ini and upgrade PHP to an actively supported version (8.2+).',
    aliases: ['php version disclosure', 'php-version', 'php version', 'php version (eol)']
  },
  {
    id: 'phpunit-rce',
    title: 'PHPUnit Eval-Stdin RCE',
    category: 'Known Vulnerabilities',
    plainExplanation: 'Checks for exposed /vendor/phpunit/.../eval-stdin.php test runner endpoint (CVE-2017-9841).',
    whyItMatters: 'This endpoint executes arbitrary PHP code sent via POST without authentication.',
    defaultFix: 'Remove the /vendor directory from public web access and install test dependencies with --no-dev in production.',
    aliases: ['phpunit rce exposure', 'phpunit-rce', 'phpunit rce', 'phpunit rce (cve-2017-9841)']
  },
  {
    id: 'python-checks',
    title: 'Python (Django & Flask) Security',
    category: 'Framework Security',
    plainExplanation: 'Checks for exposed requirements.txt, Django debug mode, and Werkzeug/Flask interactive debugger.',
    whyItMatters: 'Werkzeug interactive debugger allows unauthenticated remote code execution via interactive console.',
    defaultFix: 'Set DEBUG = False in Django and disable debug mode in Flask before deploying to production.',
    aliases: ['python security', 'python-checks', 'django debug', 'flask debug']
  },
  {
    id: 'rate-limit',
    title: 'Rate Limiting & Abuse Prevention',
    category: 'API Security',
    plainExplanation: 'Tests whether rapid bursts of requests trigger HTTP 429 Too Many Requests or rate-limit headers.',
    whyItMatters: 'Endpoints without rate limiting are vulnerable to denial of service, credential stuffing, and scraping.',
    defaultFix: 'Implement rate limiting at the reverse proxy (e.g. Nginx limit_req) or application layer.',
    aliases: ['rate limiting', 'rate-limit', 'rate limit']
  },
  {
    id: 'robots-sitemap',
    title: 'Robots.txt & Sitemap Disclosure',
    category: 'Information Disclosure',
    plainExplanation: 'Analyzes robots.txt and sitemap.xml for disallow rules pointing to sensitive hidden directories.',
    whyItMatters: 'Attackers read robots.txt to discover hidden admin panels, staging areas, and private endpoints.',
    defaultFix: 'Do not rely on robots.txt for security; enforce authentication on all sensitive endpoints.',
    aliases: ['robots & sitemap', 'robots and sitemap', 'robots-sitemap', 'robots.txt disclosure']
  },
  {
    id: 'security-headers',
    title: 'HTTP Security Headers',
    category: 'HTTP Headers',
    plainExplanation: 'Checks for critical defensive headers: HSTS, X-Content-Type-Options, X-Frame-Options, CSP, etc.',
    whyItMatters: 'Missing security headers leaves users exposed to clickjacking, MIME sniffing, and cross-site scripting.',
    defaultFix: 'Configure your web server to supply HSTS, CSP, X-Content-Type-Options: nosniff, and Referrer-Policy headers.',
    aliases: ['security headers', 'security-headers', 'missing security headers']
  },
  {
    id: 'sensitive-files',
    title: 'Sensitive Files & Configurations',
    category: 'Secrets & Exposure',
    plainExplanation: 'Scans for exposed database dumps, configuration backups, credentials, and docker-compose files.',
    whyItMatters: 'Leaked configuration and database dump files grant instant access to sensitive databases.',
    defaultFix: 'Store backups, SQL dumps, and configuration files outside the web root directory.',
    aliases: ['sensitive files', 'sensitive-files']
  },
  {
    id: 'server-disclosure',
    title: 'Server Software Disclosure',
    category: 'Information Disclosure',
    plainExplanation: 'Checks if Server header reveals software names and exact version numbers (e.g., Apache/2.4.41).',
    whyItMatters: 'Detailed version information allows attackers to look up specific CVE exploits for that exact version.',
    defaultFix: 'Set ServerTokens Prod in Apache or server_tokens off in Nginx.',
    aliases: ['server disclosure', 'server-disclosure', 'server banner', 'server version disclosure']
  },
  {
    id: 'sql-errors',
    title: 'Database Error Disclosure',
    category: 'Injection & Input',
    plainExplanation: 'Tests if query strings trigger verbose database error messages (MySQL, PostgreSQL, SQLite, MSSQL).',
    whyItMatters: 'Database error messages reveal schema structures and confirm the presence of SQL injection vulnerabilities.',
    defaultFix: 'Disable detailed database error output in production and use generic error messages.',
    aliases: ['sql errors', 'sql-errors', 'database errors', 'sql error disclosure']
  },
  {
    id: 'sqli',
    title: 'SQL Injection (SQLi)',
    category: 'Injection & Input',
    plainExplanation: 'Tests input fields and parameters for SQL syntax manipulation and time-based delays.',
    whyItMatters: 'SQL injection allows attackers to bypass authentication, read, modify, or delete the entire database.',
    defaultFix: 'Use parameterized queries / prepared statements for all database interactions; avoid string concatenation.',
    aliases: ['sql injection', 'sqli']
  },
  {
    id: 'ssl-tls',
    title: 'SSL / TLS Certificate & Encryption',
    category: 'Network & Transport',
    plainExplanation: 'Verifies SSL certificate validity, expiration, hostname matching, and secure TLS protocol versions.',
    whyItMatters: 'Expired or untrusted certificates cause browser warnings and leave traffic vulnerable to interception.',
    defaultFix: 'Renew your SSL certificate, enable auto-renewal via Let\'s Encrypt, and disable obsolete TLS 1.0/1.1.',
    aliases: ['ssl & tls configuration', 'ssl-tls', 'ssl / tls', 'ssl', 'ssl/tls check']
  },
  {
    id: 'system-health',
    title: 'System & Operational Health Exposure',
    category: 'Network & Transport',
    plainExplanation: 'Scans for exposed operational telemetry (/metrics, /prometheus, /server-status, /actuator/health), server 5xx errors, slow response latency, uncompressed payloads, and expiring TLS certificates.',
    whyItMatters: 'Publicly accessible operational metrics, server status, and detailed component health dumps reveal internal architectures, infrastructure utilization, and sensitive service names to unauthorized actors.',
    defaultFix: 'Restrict operational and telemetry endpoints to authorized monitoring networks or require authentication. Enable gzip/brotli compression, resolve backend server errors, and renew SSL/TLS certificates before expiration.',
    aliases: ['system-health', 'system & operational health exposure', 'system health']
  },
  {
    id: 'device-security',
    title: 'Smart TV, IP Camera, PC/Workstation & Network Device Security Exposure',
    category: 'Infrastructure & Network',
    plainExplanation: 'Performs non-intrusive discovery and security auditing across Smart TVs (Samsung Tizen, LG webOS, Roku ECP, Google TV / Android TV / Chromecast, Sony Bravia, Vizio SmartCast, Philips JointSpace, Apple AirPlay, DIAL), IP Cameras / NVRs (RTSP 554/8554, ONVIF SOAP, Hikvision ISAPI, Dahua, Axis, Xiongmai, UniFi Protect, unauthenticated snapshots), PCs / Workstations / Local Servers (Windows SMB/NetBIOS/MSRPC/RDP/WinRM/WSDAPI, macOS/Linux SSH/VNC/CUPS/NFS/AFP/rsync/mDNS, Docker TCP 2375, Ollama 11434, local dev servers, open shares), routers, printers, NAS, and IoT appliances.',
    whyItMatters: 'Local network devices and workstations often expose unauthenticated REST/WebSocket control APIs, live RTSP/MJPEG camera feeds, cleartext admin UIs, unauthenticated Docker/Ollama/dev servers, or remote file-sharing and shell services (SMB 445, RDP 3389, WinRM 5985, ADB 5555, Telnet 23) that allow LAN attackers to hijack screens, view surveillance feeds, access files, or execute arbitrary commands.',
    defaultFix: 'Segment Smart TVs, IP cameras/NVRs, and IoT appliances onto isolated VLANs with client isolation enabled. Require authentication and HTTPS/TLS on camera and appliance admin interfaces, enforce RTSP Digest auth, disable unused UPnP/DLNA/ADB/Telnet services, bind local dev servers, Docker, and Ollama to 127.0.0.1, and restrict SMB/RDP/WinRM/SSH/VNC/NFS via host firewalls.',
    aliases: [
      'device-security',
      'device security',
      'smart tv, iot & network device security exposure',
      'smart tv, ip camera, pc/workstation & network device security exposure',
      'smart tv & iot device security',
      'tv security',
      'iot device security',
      'ip camera security',
      'pc security',
      'workstation security',
      'lan device security'
    ]
  },
  {
    id: 'os-security',
    title: 'Universal Operating System, Edge Appliance & Market CVE Security Audit',
    category: 'Known Vulnerabilities',
    plainExplanation: 'Passively inspects HTTP headers, service banners, and open OS/appliance/runtime ports across Windows Server & Workstation, Linux distributions (Ubuntu, Debian, CentOS, RHEL, AlmaLinux, Rocky, Alpine), macOS / Apple Darwin / AirPlay, BSD / Firewall OS (FreeBSD, OpenBSD, pfSense, OPNsense), Edge VPN/Firewall/Router/NAS appliances (Palo Alto PAN-OS, Fortinet FortiOS, Ivanti Connect Secure, Citrix NetScaler, Cisco IOS XE, MikroTik RouterOS, QNAP QTS), and AI/Cloud runtimes (Ollama, Anyscale Ray) for End-of-Life OS releases and high-impact CVEs.',
    whyItMatters: 'End-of-Life operating systems and unpatched OS daemons or edge appliances (OpenSSH regreSSHion CVE-2024-6387, CUPS CVE-2024-47176, Apple AirPlay AirBorne CVE-2025-24252, Windows HTTP.sys/TCP-IP/RDP/SMBGhost, PAN-OS GlobalProtect, FortiOS SSL VPN, Ivanti Connect Secure, CitrixBleed, Cisco IOS XE, MikroTik RouterOS, QNAP QTS, Ollama Probllama, and Anyscale Ray ShadowRay) allow unauthenticated remote attackers to achieve root/SYSTEM remote code execution, session hijacking, or full network compromise.',
    defaultFix: 'Upgrade End-of-Life operating systems to actively supported LTS releases, upgrade OpenSSH to 9.9p2+ (or apply vendor backport security updates), restrict or disable CUPS (631), AirPlay (5000/7000), SMB (445), and RDP (3389) on untrusted networks, apply emergency patches for PAN-OS, FortiOS, Ivanti, Citrix NetScaler, Cisco IOS XE, MikroTik RouterOS, and QNAP QTS appliances, and upgrade Ollama to 0.1.34+ and Ray to 2.8.1+ while binding AI runtimes to localhost.',
    aliases: [
      'os-security',
      'os security',
      'operating system security',
      'universal operating system, edge appliance & market cve security audit'
    ]
  },
  {
    id: 'symfony-checks',
    title: 'Symfony Framework Security',
    category: 'Framework Security',
    plainExplanation: 'Checks for exposed Symfony WebProfiler toolbar (_profiler), debug routes, and config files.',
    whyItMatters: 'Symfony WebProfiler exposes all request data, database credentials, and session tokens.',
    defaultFix: 'Ensure APP_ENV=prod and remove web-profiler-bundle from production environments.',
    aliases: ['symfony security', 'symfony', 'symfony-checks', 'symfony misconfiguration']
  },
  {
    id: 'yii-checks',
    title: 'Yii 1.x & Yii 2.x Framework Security',
    category: 'Framework Security',
    plainExplanation: 'Audits Yii 1.x and Yii 2.x applications for exposed Gii code generators (/gii, ?r=gii), Yii 2 Debug module toolbars (/debug, X-Debug-Tag), YII_DEBUG stack trace disclosures (CException, CDbException), and accessible protected/runtime logs.',
    whyItMatters: 'Exposed Yii Gii code generators allow remote code generation and arbitrary PHP file creation (RCE). Exposed Yii 2 Debug panels and YII_DEBUG stack traces leak database credentials, session tokens, SQL queries, and application secrets.',
    defaultFix: 'Disable Gii and Debug modules in production (set YII_DEBUG to false and YII_ENV to prod), restrict Gii/Debug allowedIPs strictly to localhost, and block web server access to protected/, runtime/, and config/ directories.',
    aliases: ['yii security', 'yii', 'yii1', 'yii2', 'yii-checks', 'yii 1.x & yii 2.x framework security', 'yii misconfiguration']
  },
  {
    id: 'wp-checks',
    title: 'WordPress CMS Security',
    category: 'CMS Security',
    plainExplanation: 'Audits WordPress installations for exposed user enumeration endpoints, wp-config backups, and debug logs.',
    whyItMatters: 'User enumeration allows attackers to compile username lists for brute-force attacks against wp-login.php.',
    defaultFix: 'Block access to wp-config.php backups, disable author query enumeration, and protect wp-login.php.',
    aliases: ['wordpress security', 'wp-checks', 'wordpress', 'wordpress checks']
  },
  {
    id: 'xss',
    title: 'Cross-Site Scripting (XSS)',
    category: 'Injection & Input',
    plainExplanation: 'Tests if user inputs in query parameters are reflected unsanitized in the HTML page body.',
    whyItMatters: 'XSS allows attackers to execute malicious JavaScript in victims\' browsers, stealing cookies and session tokens.',
    defaultFix: 'Sanitize and HTML-encode all user input before outputting it into web pages, and deploy a strong CSP.',
    aliases: ['cross-site scripting', 'reflected xss', 'xss']
  },

  // ── 2025–2026 Modern Scanners ──────────────────────────────────────────────
  {
    id: 'nextjs-checks',
    title: 'Next.js & React Security',
    category: 'Framework Security',
    plainExplanation: 'Audits Next.js applications for Server Actions exposures, source maps, SSR data leaks, and dev headers.',
    whyItMatters: 'Next.js Server Actions can inadvertently expose internal server functions, while hydration state may leak sensitive user secrets.',
    defaultFix: 'Enforce authentication in Server Actions, omit source maps in production, and never expose server secrets in NEXT_PUBLIC_ env vars.',
    aliases: ['nextjs security', 'nextjs', 'nextjs-checks', 'next.js security']
  },
  {
    id: 'ai-llm-exposure',
    title: 'AI & LLM Endpoint Exposure',
    category: 'AI & Machine Learning',
    plainExplanation: 'Checks for publicly exposed AI/LLM API routes (e.g., /api/chat, /api/generate, /v1/chat/completions) and vector DB endpoints.',
    whyItMatters: 'Unprotected AI endpoints invite costly token theft, denial-of-wallet attacks, and prompt injection exploits.',
    defaultFix: 'Enforce strict authentication, user-level rate limiting, and input validation on all AI endpoints.',
    aliases: ['ai & llm exposure', 'ai llm exposure', 'ai-llm-exposure', 'ai & llm endpoints']
  },
  {
    id: 'sri-supply-chain',
    title: 'Supply Chain & Subresource Integrity (SRI)',
    category: 'Supply Chain Security',
    plainExplanation: 'Checks whether external CDN scripts and stylesheets utilize Subresource Integrity (integrity and crossorigin attributes).',
    whyItMatters: 'If a third-party CDN is compromised, scripts without SRI hashes can inject malicious code directly into your visitors\' browsers.',
    defaultFix: 'Include cryptographic integrity hashes (e.g., integrity="sha384-...") on all external script and link tags.',
    aliases: ['supply chain & sri', 'supply chain and sri', 'sri-supply-chain', 'sri']
  },
  {
    id: 'spring-checks',
    title: 'Spring Boot Framework Security',
    category: 'Framework Security',
    plainExplanation: 'Checks for exposed Spring Boot Actuator endpoints (/actuator, /actuator/env, /actuator/heapdump) and Whitelabel error pages.',
    whyItMatters: 'Exposed Actuator endpoints can leak environment variables, database credentials, and heap dumps containing cleartext passwords.',
    defaultFix: 'Restrict Actuator endpoints using Spring Security or set management.endpoints.web.exposure.include=health,info.',
    aliases: ['spring boot security', 'spring boot', 'spring-checks', 'spring']
  },
  {
    id: 'origin-source-ip',
    title: 'Direct Source-IP / Origin-IP HTTP Exposure & CDN/WAF Bypass',
    category: 'Infrastructure & Network',
    plainExplanation: 'Verifies whether the target connects via a resolved or configured Source/Origin IP and checks if direct Source-IP HTTP/HTTPS requests bypass CDN/WAF edge protections or leak internal default virtual-host / origin server metadata.',
    whyItMatters: 'When an origin server accepts direct HTTP/HTTPS connections on its Source IP outside the CDN/WAF IP allowlist, attackers can bypass edge WAF rules, rate limits, and bot protections by connecting directly to the Source IP.',
    defaultFix: 'Restrict origin firewall ingress on ports 80/443 to trusted CDN/WAF IP ranges only, configure a default-deny catch-all virtual host (ssl_reject_handshake on; return 444;), and enforce Authenticated Origin Pulls (mTLS).',
    aliases: ['origin-source-ip', 'source ip exposure', 'origin ip bypass', 'direct source-ip / origin-ip http exposure & cdn/waf bypass']
  },
  {
    id: 'php-session-upload-progress',
    title: 'PHP session.upload_progress LFI-to-RCE & Serializer Mismatch (CVE-2026-109618 / CVE-2026-109619)',
    category: 'Known Vulnerabilities',
    plainExplanation: 'Passively and safely inspects PHP targets for the php2shell (CVE-2026-109618 / CVE-2026-109619) session.upload_progress multipart PHPSESSID fixation, raw filename session injection, var_destroy UAF, and FPM PS(serializer) handler mismatch conditions.',
    whyItMatters: 'In PHP 5.4.0 through 8.5.11, the rfc1867 session.upload_progress handler accepts PHPSESSID from multipart POST form data ignoring session.use_only_cookies and writes raw filenames into session files, enabling LFI-to-RCE and deserialization RCE.',
    defaultFix: 'Upgrade PHP to 8.2.35+, 8.3.36+, 8.4.27+, or 8.5.12+ (or 8.2.36+ / 8.3.37+ / 8.4.28+ / 8.5.13+), set session.upload_progress.enabled = Off, session.use_only_cookies = On, and enforce session.serialize_handler = php_serialize.',
    aliases: ['php-session-upload-progress', 'php2shell', 'php session.upload_progress lfi-to-rce & serializer mismatch (cve-2026-109618 / cve-2026-109619)']
  },
  {
    id: 'api-security-spectrum',
    title: 'API Trust-Boundary Confusion, OAuth2/PKCE & REST Differential Spectrum',
    category: 'API & Authentication',
    plainExplanation: 'Inspects API and authentication surfaces for X-Forwarded-For / X-Real-IP rate-limit and IP trust-boundary confusion, OAuth2/OIDC missing PKCE or deprecated grant types, and REST differential exposures.',
    whyItMatters: 'Trusting unverified X-Forwarded-For headers allows attackers to spoof 127.0.0.1 to bypass IP allowlists and rate limiters, while OAuth2 endpoints lacking S256 PKCE enable authorization-code interception.',
    defaultFix: 'Configure reverse proxies and middleware to trust X-Forwarded-For only from verified proxy CIDRs, enforce S256 PKCE on OAuth2/OIDC endpoints, and disable implicit/password grant types.',
    aliases: ['api-security-spectrum', 'api trust-boundary confusion, oauth2/pkce & rest differential spectrum', 'api security spectrum']
  },
  {
    id: 'subdomain-takeover',
    title: 'Subdomain Takeover & Dangling CNAME Cloud Resource Detection',
    category: 'Infrastructure & Network',
    plainExplanation: 'Inspects DNS CNAME chains and HTTP response signatures for dangling DNS records pointing to unclaimed third-party cloud platforms (GitHub Pages, AWS S3, Heroku, Fastly, Azure, Shopify, Vercel, Netlify, Pantheon, Zendesk, Surge.sh, Fly.io).',
    whyItMatters: 'A dangling CNAME pointing to a deprovisioned external cloud service lets an attacker claim the resource name and serve arbitrary content or steal cookies under your domain.',
    defaultFix: 'Remove dangling CNAME, A, and AAAA DNS records before deprovisioning cloud buckets or PaaS applications.',
    aliases: ['subdomain-takeover', 'subdomain takeover', 'subdomain takeover & dangling cname cloud resource detection']
  },
  {
    id: 'iis-shortname',
    title: 'Microsoft IIS 8.3 Shortname (~1) Enumeration & ASP.NET Diagnostic Exposure',
    category: 'Server & Configuration',
    plainExplanation: 'Performs a safe status/error differential probe for Windows NTFS 8.3 tilde (~1) shortname enumeration on Microsoft IIS servers and checks for exposed ASP.NET trace.axd and elmah.axd diagnostic handlers.',
    whyItMatters: 'IIS 8.3 shortname disclosure allows attackers to brute-force hidden backup and configuration files, while exposed trace.axd or elmah.axd pages leak session cookies and full HTTP request logs.',
    defaultFix: 'Disable NTFS 8.3 shortname creation (fsutil 8dot3name set 1), block tilde (~) in IIS Request Filtering, and disable trace.axd and public elmah.axd access in web.config.',
    aliases: ['iis-shortname', 'iis shortname', 'microsoft iis 8.3 shortname (~1) enumeration & asp.net diagnostic exposure']
  },
  {
    id: 'ssti-check',
    title: 'Server-Side Template Injection (SSTI — Jinja2, Twig, Freemarker, EL, ERB, EJS)',
    category: 'Injection & Input',
    plainExplanation: 'Tests URL query parameters with non-destructive arithmetic template expressions across Jinja2/Twig/Pebble ({{7919*13}}), Freemarker/Spring EL/Thymeleaf (${7919*13}), and ERB/EJS (<%= 7919*13 %>), verifying that the server evaluates the expression to 102947 without reflecting the un-evaluated formula.',
    whyItMatters: 'When user input is concatenated directly into a server-side template string before rendering, attackers can execute arbitrary template expressions and achieve remote code execution (RCE).',
    defaultFix: 'Never pass user-supplied strings as template source code. Always pass user data as named context variables into pre-compiled static templates.',
    aliases: ['ssti-check', 'ssti', 'server-side template injection', 'server-side template injection (ssti — jinja2, twig, freemarker, el, erb, ejs)']
  },
  {
    id: 'cache-poisoning',
    title: 'Web Cache Poisoning & Unkeyed Header Reflection (X-Forwarded-Host / X-Original-URL)',
    category: 'HTTP Headers',
    plainExplanation: 'Probes an isolated cache-busted URL (?secscan_cb=<nonce>) with unkeyed forwarding headers (X-Forwarded-Host, X-Host, X-Original-URL) and performs a clean follow-up request to verify whether the reflected header is stored in a shared HTTP cache.',
    whyItMatters: 'If a reverse proxy or CDN caches a response containing an unkeyed header value, an attacker can poison the shared cache and serve malicious scripts or redirects to all visitors.',
    defaultFix: 'Include X-Forwarded-Host / X-Forwarded-Scheme in the cache key (Vary header), or configure the web server and framework to ignore unauthenticated X-Forwarded-Host and X-Original-URL headers.',
    aliases: ['cache-poisoning', 'web cache poisoning', 'web cache poisoning & unkeyed header reflection (x-forwarded-host / x-original-url)']
  },
  {
    id: 'http-desync-smuggling',
    title: 'HTTP/1.1 & HTTP/2 Request Smuggling / Desync Normalization Surface',
    category: 'Infrastructure & Network',
    plainExplanation: 'Safely inspects reverse-proxy / origin HTTP framing behavior for ambiguous Transfer-Encoding obfuscation (TE.TE / CL.TE) and HTTP/2-to-HTTP/1.1 downgrade desynchronization indicators without poisoning shared connections.',
    whyItMatters: 'When a front-end proxy and back-end server disagree on message boundaries, attackers can smuggle requests across user sessions.',
    defaultFix: 'Configure the front-end proxy and origin server to reject requests containing both Content-Length and Transfer-Encoding (RFC 9112 §6.3) and reject malformed Transfer-Encoding values.',
    aliases: ['http-desync-smuggling', 'request smuggling', 'http/1.1 & http/2 request smuggling / desync normalization surface']
  },
  {
    id: 'bola-mass-assignment',
    title: 'API BOLA / IDOR & Mass Assignment Privilege Attribute Exposure',
    category: 'API & Authentication',
    plainExplanation: 'Inspects REST API object endpoints (/api/users/1) against a non-existent canary route to detect unauthenticated Broken Object Level Authorization (BOLA/IDOR) and checks whether privilege-escalation fields (role, isAdmin, is_superuser) are exposed.',
    whyItMatters: 'Broken Object Level Authorization (OWASP API1:2023) allows attackers to read or modify other users’ records by enumerating IDs, while Mass Assignment allows binding privileged fields like role or isAdmin.',
    defaultFix: 'Enforce object-level ownership checks on every record lookup, use non-sequential UUIDs, and restrict request body deserialization to explicit allowlisted DTO fields.',
    aliases: ['bola-mass-assignment', 'bola', 'idor', 'api bola / idor & mass assignment privilege attribute exposure']
  },
  {
    id: 'dom-xss-sinks',
    title: 'DOM-Based XSS Source-to-Sink & Unsafe postMessage Listener Analysis',
    category: 'Injection & Input',
    plainExplanation: 'Inspects client-side JavaScript in HTML responses for direct untrusted DOM source-to-sink dataflows (location.hash / location.search flowing into innerHTML / document.write / eval) and window.addEventListener("message") handlers lacking event.origin validation.',
    whyItMatters: 'DOM-based XSS executes entirely in the victim’s browser when client-side scripts pass attacker-controlled URL fragments or cross-window postMessage data directly into HTML/script execution sinks.',
    defaultFix: 'Use textContent / innerText instead of innerHTML or document.write, sanitize dynamic HTML with DOMPurify, and always validate event.origin inside postMessage handlers.',
    aliases: ['dom-xss-sinks', 'dom xss', 'dom-based xss source-to-sink & unsafe postmessage listener analysis']
  },
  {
    id: 'xxe-injection',
    title: 'XML External Entity (XXE) & Unsafe XML/SOAP Entity Expansion',
    category: 'Injection & Input',
    plainExplanation: 'Safely tests XML-accepting endpoints with a benign internal DTD entity declaration (<!ENTITY secscanxxe "secscan_xxe_eval_9412">) to verify whether custom DOCTYPE entities are expanded or whether raw XML parser exceptions are disclosed.',
    whyItMatters: 'XML parsers that permit DOCTYPE declarations and entity resolution allow attackers to read arbitrary local files, probe internal networks via SSRF, or trigger denial-of-service.',
    defaultFix: 'Disable DOCTYPE declarations (disallow-doctype-decl = true) and external entities in your XML parser.',
    aliases: ['xxe-injection', 'xxe', 'xml external entity (xxe) & unsafe xml/soap entity expansion']
  },
  {
    id: 'crlf-header-injection',
    title: 'HTTP Response Splitting & CRLF Header Injection',
    category: 'Injection & Input',
    plainExplanation: 'Probes redirect and query parameters with URL-encoded CR/LF sequences (%0d%0aX-SecScan-Crlf: crlf9812injected) and verifies whether an actual X-SecScan-Crlf HTTP header is injected into the response headers.',
    whyItMatters: 'When user input containing CR and LF characters is copied into an HTTP response header without newline stripping, attackers can inject arbitrary headers, set malicious cookies, or split the HTTP response body.',
    defaultFix: 'Strip or reject CR (\\r, %0d) and LF (\\n, %0a) characters before writing any user-derived value into HTTP response headers.',
    aliases: ['crlf-header-injection', 'crlf injection', 'http response splitting & crlf header injection']
  },
  {
    id: 'ssrf-surface',
    title: 'Server-Side Request Forgery (SSRF) URL Parameter & Backend Fetcher Surface',
    category: 'Injection & Input',
    plainExplanation: 'Tests URL/webhook/callback query parameters (?url=, ?webhook=, ?uri=) with a non-routable RFC 2606 domain (http://secscan-ssrf-probe.invalid/) to detect whether the backend server attempts an outbound HTTP fetch and leaks HTTP client connection errors.',
    whyItMatters: 'Unvalidated server-side URL fetchers allow attackers to pivot into internal VPC networks, query cloud instance metadata services (169.254.169.254), and scan internal ports.',
    defaultFix: 'Validate user-supplied URLs against a strict domain allowlist, connect directly to the validated IP (PinnedDialer), and block all RFC1918, loopback, link-local, and cloud metadata IP ranges.',
    aliases: ['ssrf-surface', 'ssrf', 'server-side request forgery (ssrf) url parameter & backend fetcher surface']
  },
  {
    id: 'runtime-sca',
    title: 'Runtime SCA & Technology Dependency Versions',
    category: 'Supply Chain Security',
    plainExplanation: 'Passively inspects HTML script/link tags, framework attributes (ng-version, meta generator), JavaScript bundle banners (Moment.js, Lodash, jQuery, Bootstrap, AngularJS, Angular, React, Vue.js, Next.js, DOMPurify, Axios, Handlebars), and server response headers to compare identified dependency versions against branch-level and overall latest releases and known CVEs.',
    whyItMatters: 'Outdated or End-of-Life (EOL) third-party libraries and server runtimes expose web applications to publicly documented Cross-Site Scripting (XSS), Prototype Pollution, Regular Expression Denial of Service (ReDoS), SSRF, and Remote Code Execution vulnerabilities.',
    defaultFix: 'Upgrade outdated third-party libraries and runtime dependencies to their latest patched releases, and migrate away from End-of-Life frameworks such as AngularJS 1.x or Moment.js.',
    aliases: [
      'runtime-sca',
      'runtime sca',
      'runtime sca & technology dependency versions',
      'software composition analysis',
      'technology dependency versions'
    ]
  }
];

/**
 * Deterministic CWE, OWASP Top 10 (2021), CVSS v3.1 Base Score, CVE, and reference mapping
 * for all 64 built-in checks plus common vulnerability archetypes.
 */
export const CWE_OWASP_MAP = {
  'admin-panels': {
    cwe: 'CWE-284',
    owasp: 'A01:2021-Broken Access Control',
    cvssScore: 5.3,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/284.html',
      'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'
    ]
  },
  'ai-llm-exposure': {
    cwe: 'CWE-306',
    owasp: 'A01:2021-Broken Access Control',
    cvssScore: 7.5,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/306.html',
      'https://genai.owasp.org/'
    ]
  },
  'api-communication': {
    cwe: 'CWE-200',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 5.3,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/200.html',
      'https://owasp.org/API-Security/',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    ]
  },
  'api-endpoints': {
    cwe: 'CWE-200',
    owasp: 'A01:2021-Broken Access Control',
    cvssScore: 5.3,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/200.html',
      'https://owasp.org/API-Security/'
    ]
  },
  'clickjacking': {
    cwe: 'CWE-1021',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 4.3,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/1021.html',
      'https://owasp.org/www-community/attacks/Clickjacking'
    ]
  },
  'codeigniter-checks': {
    cwe: 'CWE-16',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 7.5,
    cveIds: ['CVE-2025-54418'],
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2025-54418',
      'https://cwe.mitre.org/data/definitions/16.html',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    ]
  },
  'cookie-security': {
    cwe: 'CWE-614',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 5.3,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/614.html',
      'https://owasp.org/www-community/controls/SecureCookieAttribute'
    ]
  },
  'cors': {
    cwe: 'CWE-942',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 7.5,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/942.html',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    ]
  },
  'cve-2024-4577': {
    cwe: 'CWE-78',
    owasp: 'A03:2021-Injection',
    cvssScore: 9.8,
    cveIds: ['CVE-2024-4577'],
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2024-4577',
      'https://cwe.mitre.org/data/definitions/78.html'
    ]
  },
  'cve-2026-114938': {
    cwe: 'CWE-122',
    owasp: 'A06:2021-Vulnerable and Outdated Components',
    cvssScore: 9.2,
    cveIds: ['CVE-2026-114938'],
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2026-114938',
      'https://cwe.mitre.org/data/definitions/122.html',
      'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/'
    ]
  },
  'cve-2026-123007': {
    cwe: 'CWE-191',
    owasp: 'A06:2021-Vulnerable and Outdated Components',
    cvssScore: 9.2,
    cveIds: ['CVE-2026-123007'],
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2026-123007',
      'https://cwe.mitre.org/data/definitions/191.html',
      'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/'
    ]
  },
  'cve-2026-123633': {
    cwe: 'CWE-416',
    owasp: 'A06:2021-Vulnerable and Outdated Components',
    cvssScore: 9.2,
    cveIds: ['CVE-2026-123633'],
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2026-123633',
      'https://cwe.mitre.org/data/definitions/416.html',
      'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/'
    ]
  },
  'cve-2026-123634': {
    cwe: 'CWE-416',
    owasp: 'A06:2021-Vulnerable and Outdated Components',
    cvssScore: 9.2,
    cveIds: ['CVE-2026-123634'],
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2026-123634',
      'https://cwe.mitre.org/data/definitions/416.html',
      'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/'
    ]
  },
  'cve-jdk-advisories': {
    cwe: 'CWE-295',
    owasp: 'A06:2021-Vulnerable and Outdated Components',
    cvssScore: 9.1,
    cveIds: [
      'CVE-2026-91403',
      'CVE-2026-114820',
      'CVE-2026-114939',
      'CVE-2026-114940',
      'CVE-2026-22016',
      'CVE-2026-34282',
      'CVE-2026-47063',
      'CVE-2026-91398',
      'CVE-2026-91453'
    ],
    references: [
      'https://openjdk.org/groups/vulnerability/advisories/2026-11-17',
      'https://www.oracle.com/security-alerts/cpuoct2026.html',
      'https://nvd.nist.gov/vuln/detail/CVE-2026-91403',
      'https://nvd.nist.gov/vuln/detail/CVE-2026-114820',
      'https://nvd.nist.gov/vuln/detail/CVE-2026-22016'
    ]
  },
  'cve-nginx-http3': {
    cwe: 'CWE-416',
    owasp: 'A06:2021-Vulnerable and Outdated Components',
    cvssScore: 9.2,
    cveIds: ['CVE-2026-121810', 'CVE-2026-95101', 'CVE-2026-90439'],
    references: [
      'https://nginx.org/en/security_advisories.html',
      'https://nvd.nist.gov/vuln/detail/CVE-2026-121810',
      'https://nvd.nist.gov/vuln/detail/CVE-2026-95101',
      'https://nvd.nist.gov/vuln/detail/CVE-2026-90439'
    ]
  },
  'cve-nginx-tls': {
    cwe: 'CWE-835',
    owasp: 'A06:2021-Vulnerable and Outdated Components',
    cvssScore: 8.3,
    cveIds: ['CVE-2026-118899', 'CVE-2026-97629', 'CVE-2025-23419'],
    references: [
      'https://nginx.org/en/security_advisories.html',
      'https://nvd.nist.gov/vuln/detail/CVE-2026-118899',
      'https://nvd.nist.gov/vuln/detail/CVE-2026-97629',
      'https://nvd.nist.gov/vuln/detail/CVE-2025-23419'
    ]
  },
  'cve-apache-httpd': {
    cwe: 'CWE-20',
    owasp: 'A06:2021-Vulnerable and Outdated Components',
    cvssScore: 9.1,
    cveIds: ['CVE-2024-38476', 'CVE-2024-38477', 'CVE-2024-39573', 'CVE-2024-27316'],
    references: [
      'https://cwe.mitre.org/data/definitions/20.html',
      'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-38476',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-38477',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-39573',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-27316'
    ]
  },
  'cve-nextjs-react': {
    cwe: 'CWE-94',
    owasp: 'A03:2021-Injection',
    cvssScore: 9.1,
    cveIds: ['CVE-2025-55182', 'CVE-2024-34351', 'CVE-2024-46982'],
    references: [
      'https://cwe.mitre.org/data/definitions/94.html',
      'https://owasp.org/Top10/A03_2021-Injection/',
      'https://nvd.nist.gov/vuln/detail/CVE-2025-55182',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-34351',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-46982'
    ]
  },
  'cve-node-express': {
    cwe: 'CWE-79',
    owasp: 'A06:2021-Vulnerable and Outdated Components',
    cvssScore: 7.5,
    cveIds: ['CVE-2024-29041', 'CVE-2024-43796', 'CVE-2024-37890', 'CVE-2025-27152'],
    references: [
      'https://cwe.mitre.org/data/definitions/79.html',
      'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-29041',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-43796',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-37890',
      'https://nvd.nist.gov/vuln/detail/CVE-2025-27152'
    ]
  },
  'cve-php-ecosystem': {
    cwe: 'CWE-20',
    owasp: 'A06:2021-Vulnerable and Outdated Components',
    cvssScore: 9.8,
    cveIds: [
      'CVE-2025-1217',
      'CVE-2025-27515',
      'CVE-2024-50342',
      'CVE-2026-129289',
      'CVE-2026-129182',
      'CVE-2026-129474',
      'CVE-2026-129496',
      'CVE-2026-129481',
      'CVE-2026-126714',
      'CVE-2026-115560',
      'CVE-2026-48841',
      'CVE-2026-127960',
      'CVE-2026-128064',
      'CVE-2026-129538',
      'CVE-2026-129292',
      'CVE-2026-109618',
      'CVE-2026-109619'
    ],
    references: [
      'https://cwe.mitre.org/data/definitions/20.html',
      'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
      'https://www.php.net/ChangeLog-8.php',
      'https://nvd.nist.gov/vuln/detail/CVE-2025-1217',
      'https://nvd.nist.gov/vuln/detail/CVE-2025-27515',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-50342',
      'https://nvd.nist.gov/vuln/detail/CVE-2026-129289',
      'https://nvd.nist.gov/vuln/detail/CVE-2026-48841',
      'https://nvd.nist.gov/vuln/detail/CVE-2026-109618',
      'https://nvd.nist.gov/vuln/detail/CVE-2026-109619'
    ]
  },
  'origin-source-ip': {
    cwe: 'CWE-284',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 7.5,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/284.html',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    ]
  },
  'php-session-upload-progress': {
    cwe: 'CWE-384',
    owasp: 'A07:2021-Identification and Authentication Failures',
    cvssScore: 9.8,
    cveIds: ['CVE-2026-109618', 'CVE-2026-109619'],
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2026-109618',
      'https://nvd.nist.gov/vuln/detail/CVE-2026-109619',
      'https://github.com/php/php-src/pull/22113',
      'https://www.php.net/ChangeLog-8.php'
    ]
  },
  'api-security-spectrum': {
    cwe: 'CWE-290',
    owasp: 'A07:2021-Identification and Authentication Failures',
    cvssScore: 7.5,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/290.html',
      'https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/'
    ]
  },
  'subdomain-takeover': {
    cwe: 'CWE-284',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 8.2,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/284.html',
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover'
    ]
  },
  'iis-shortname': {
    cwe: 'CWE-200',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 6.5,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/200.html',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    ]
  },
  'cve-python-web': {
    cwe: 'CWE-89',
    owasp: 'A03:2021-Injection',
    cvssScore: 8.8,
    cveIds: ['CVE-2024-45230', 'CVE-2024-53907', 'CVE-2025-26699', 'CVE-2024-47874', 'CVE-2024-56326'],
    references: [
      'https://cwe.mitre.org/data/definitions/89.html',
      'https://owasp.org/Top10/A03_2021-Injection/',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-45230',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-53907',
      'https://nvd.nist.gov/vuln/detail/CVE-2025-26699',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-47874',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-56326'
    ]
  },
  'cve-spring-framework': {
    cwe: 'CWE-22',
    owasp: 'A01:2021-Broken Access Control',
    cvssScore: 7.5,
    cveIds: ['CVE-2024-38816', 'CVE-2024-38819', 'CVE-2025-22235', 'CVE-2024-22262'],
    references: [
      'https://cwe.mitre.org/data/definitions/22.html',
      'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-38816',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-38819',
      'https://nvd.nist.gov/vuln/detail/CVE-2025-22235',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-22262'
    ]
  },
  'cve-tomcat': {
    cwe: 'CWE-502',
    owasp: 'A08:2021-Software and Data Integrity Failures',
    cvssScore: 9.8,
    cveIds: ['CVE-2025-24813', 'CVE-2024-50379', 'CVE-2025-31650'],
    references: [
      'https://cwe.mitre.org/data/definitions/502.html',
      'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
      'https://nvd.nist.gov/vuln/detail/CVE-2025-24813',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-50379',
      'https://nvd.nist.gov/vuln/detail/CVE-2025-31650'
    ]
  },
  'cve-wordpress-ecosystem': {
    cwe: 'CWE-287',
    owasp: 'A07:2021-Identification and Authentication Failures',
    cvssScore: 9.8,
    cveIds: ['CVE-2024-10924', 'CVE-2024-4439', 'CVE-2024-6307'],
    references: [
      'https://cwe.mitre.org/data/definitions/287.html',
      'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-10924',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-4439',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-6307'
    ]
  },
  'directory-listing': {
    cwe: 'CWE-548',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 5.3,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/548.html',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    ]
  },
  'drupal-checks': {
    cwe: 'CWE-1104',
    owasp: 'A06:2021-Vulnerable and Outdated Components',
    cvssScore: 7.5,
    cveIds: ['CVE-2025-13081', 'CVE-2024-55638'],
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2025-13081',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-55638',
      'https://cwe.mitre.org/data/definitions/1104.html',
      'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/'
    ]
  },
  'env': {
    cwe: 'CWE-200',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 9.1,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/200.html',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    ]
  },
  'frontend-checks': {
    cwe: 'CWE-540',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 5.3,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/540.html',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    ]
  },
  'git': {
    cwe: 'CWE-527',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 7.5,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/527.html',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    ]
  },
  'graphql': {
    cwe: 'CWE-200',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 5.3,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/200.html',
      'https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html'
    ]
  },
  'http-methods': {
    cwe: 'CWE-749',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 5.3,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/749.html',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    ]
  },
  'http-redirect': {
    cwe: 'CWE-319',
    owasp: 'A02:2021-Cryptographic Failures',
    cvssScore: 5.3,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/319.html',
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'
    ]
  },
  'ignition': {
    cwe: 'CWE-94',
    owasp: 'A06:2021-Vulnerable and Outdated Components',
    cvssScore: 9.8,
    cveIds: ['CVE-2021-3129'],
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2021-3129',
      'https://cwe.mitre.org/data/definitions/94.html'
    ]
  },
  'jwt-security': {
    cwe: 'CWE-347',
    owasp: 'A07:2021-Identification and Authentication Failures',
    cvssScore: 9.1,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/347.html',
      'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/'
    ]
  },
  'laravel-auth': {
    cwe: 'CWE-352',
    owasp: 'A07:2021-Identification and Authentication Failures',
    cvssScore: 7.5,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/352.html',
      'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/'
    ]
  },
  'laravel-debug': {
    cwe: 'CWE-215',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 7.5,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/215.html',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    ]
  },
  'laravel-env-manipulation': {
    cwe: 'CWE-88',
    owasp: 'A03:2021-Injection',
    cvssScore: 7.5,
    cveIds: ['CVE-2024-52301'],
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2024-52301',
      'https://cwe.mitre.org/data/definitions/88.html'
    ]
  },
  'laravel-livewire': {
    cwe: 'CWE-285',
    owasp: 'A01:2021-Broken Access Control',
    cvssScore: 7.5,
    cveIds: ['CVE-2025-54068', 'CVE-2024-47823'],
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2025-54068',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-47823',
      'https://cwe.mitre.org/data/definitions/285.html',
      'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'
    ]
  },
  'laravel-storage': {
    cwe: 'CWE-532',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 7.5,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/532.html',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    ]
  },
  'laravel-telescope': {
    cwe: 'CWE-200',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 7.5,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/200.html',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    ]
  },
  'magento-checks': {
    cwe: 'CWE-200',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 7.5,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/200.html',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    ]
  },
  'magento-cosmicsting': {
    cwe: 'CWE-611',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 9.8,
    cveIds: ['CVE-2024-34102'],
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2024-34102',
      'https://cwe.mitre.org/data/definitions/611.html'
    ]
  },
  'nextjs-checks': {
    cwe: 'CWE-285',
    owasp: 'A01:2021-Broken Access Control',
    cvssScore: 9.1,
    cveIds: ['CVE-2025-29927'],
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2025-29927',
      'https://cwe.mitre.org/data/definitions/285.html'
    ]
  },
  'node-checks': {
    cwe: 'CWE-200',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 5.3,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/200.html',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    ]
  },
  'open-redirect': {
    cwe: 'CWE-601',
    owasp: 'A01:2021-Broken Access Control',
    cvssScore: 6.1,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/601.html',
      'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'
    ]
  },
  'php-backup': {
    cwe: 'CWE-530',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 7.5,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/530.html',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    ]
  },
  'php-cgi-exposure': {
    cwe: 'CWE-200',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 7.5,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/200.html',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    ]
  },
  'php-config': {
    cwe: 'CWE-16',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 5.3,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/16.html',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    ]
  },
  'php-errors': {
    cwe: 'CWE-209',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 5.3,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/209.html',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    ]
  },
  'php-info': {
    cwe: 'CWE-200',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 5.3,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/200.html',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    ]
  },
  'php-lfi': {
    cwe: 'CWE-22',
    owasp: 'A01:2021-Broken Access Control',
    cvssScore: 9.1,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/22.html',
      'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'
    ]
  },
  'php-version': {
    cwe: 'CWE-1104',
    owasp: 'A06:2021-Vulnerable and Outdated Components',
    cvssScore: 5.3,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/1104.html',
      'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/'
    ]
  },
  'phpunit-rce': {
    cwe: 'CWE-94',
    owasp: 'A06:2021-Vulnerable and Outdated Components',
    cvssScore: 9.8,
    cveIds: ['CVE-2017-9841'],
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2017-9841',
      'https://cwe.mitre.org/data/definitions/94.html'
    ]
  },
  'python-checks': {
    cwe: 'CWE-489',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 9.1,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/489.html',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    ]
  },
  'rate-limit': {
    cwe: 'CWE-770',
    owasp: 'A04:2021-Insecure Design',
    cvssScore: 5.3,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/770.html',
      'https://owasp.org/Top10/A04_2021-Insecure_Design/'
    ]
  },
  'robots-sitemap': {
    cwe: 'CWE-200',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 3.1,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/200.html',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    ]
  },
  'security-headers': {
    cwe: 'CWE-693',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 5.3,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/693.html',
      'https://owasp.org/www-project-secure-headers/'
    ]
  },
  'sensitive-files': {
    cwe: 'CWE-538',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 7.5,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/538.html',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    ]
  },
  'server-disclosure': {
    cwe: 'CWE-200',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 3.1,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/200.html',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    ]
  },
  'spring-checks': {
    cwe: 'CWE-215',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 7.5,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/215.html',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    ]
  },
  'sql-errors': {
    cwe: 'CWE-209',
    owasp: 'A03:2021-Injection',
    cvssScore: 5.3,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/209.html',
      'https://owasp.org/Top10/A03_2021-Injection/'
    ]
  },
  'sqli': {
    cwe: 'CWE-89',
    owasp: 'A03:2021-Injection',
    cvssScore: 9.8,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/89.html',
      'https://owasp.org/Top10/A03_2021-Injection/'
    ]
  },
  'sri-supply-chain': {
    cwe: 'CWE-829',
    owasp: 'A08:2021-Software and Data Integrity Failures',
    cvssScore: 5.3,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/829.html',
      'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/'
    ]
  },
  'ssl-tls': {
    cwe: 'CWE-295',
    owasp: 'A02:2021-Cryptographic Failures',
    cvssScore: 7.5,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/295.html',
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'
    ]
  },
  'system-health': {
    cwe: 'CWE-200',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 5.3,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/200.html',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    ]
  },
  'device-security': {
    cwe: 'CWE-200',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 7.5,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/200.html',
      'https://owasp.org/www-project-internet-of-things/'
    ]
  },
  'os-security': {
    cwe: 'CWE-1104',
    owasp: 'A06:2021-Vulnerable and Outdated Components',
    cvssScore: 9.8,
    cveIds: [
      'CVE-2024-6387',
      'CVE-2025-26465',
      'CVE-2025-26466',
      'CVE-2024-7589',
      'CVE-2024-47176',
      'CVE-2024-38063',
      'CVE-2024-38077',
      'CVE-2022-21907',
      'CVE-2020-0796',
      'CVE-2025-24252',
      'CVE-2024-3400',
      'CVE-2024-0012',
      'CVE-2024-21762',
      'CVE-2024-55591',
      'CVE-2024-21887',
      'CVE-2025-0282',
      'CVE-2023-4966',
      'CVE-2023-20198',
      'CVE-2023-30799',
      'CVE-2024-27130',
      'CVE-2024-37032',
      'CVE-2023-48022'
    ],
    references: [
      'https://cwe.mitre.org/data/definitions/1104.html',
      'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-6387',
      'https://nvd.nist.gov/vuln/detail/CVE-2025-26465',
      'https://nvd.nist.gov/vuln/detail/CVE-2025-26466',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-7589',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-47176',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-38063',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-38077',
      'https://nvd.nist.gov/vuln/detail/CVE-2022-21907',
      'https://nvd.nist.gov/vuln/detail/CVE-2020-0796',
      'https://nvd.nist.gov/vuln/detail/CVE-2025-24252',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-3400',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-0012',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-21762',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-55591',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-21887',
      'https://nvd.nist.gov/vuln/detail/CVE-2025-0282',
      'https://nvd.nist.gov/vuln/detail/CVE-2023-4966',
      'https://nvd.nist.gov/vuln/detail/CVE-2023-20198',
      'https://nvd.nist.gov/vuln/detail/CVE-2023-30799',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-27130',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-37032',
      'https://nvd.nist.gov/vuln/detail/CVE-2023-48022'
    ]
  },
  'symfony-checks': {
    cwe: 'CWE-215',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 7.5,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/215.html',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    ]
  },
  'yii-checks': {
    cwe: 'CWE-215',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 9.8,
    cveIds: ['CVE-2024-58136', 'CVE-2024-4991', 'CVE-2023-47129', 'CVE-2021-3692'],
    references: [
      'https://www.yiiframework.com/doc/guide/2.0/en/security-best-practices',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-58136',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-4991',
      'https://nvd.nist.gov/vuln/detail/CVE-2023-47129',
      'https://nvd.nist.gov/vuln/detail/CVE-2021-3692',
      'https://cwe.mitre.org/data/definitions/215.html'
    ]
  },
  'wp-checks': {
    cwe: 'CWE-200',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 5.3,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/200.html',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    ]
  },
  'xss': {
    cwe: 'CWE-79',
    owasp: 'A03:2021-Injection',
    cvssScore: 7.5,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/79.html',
      'https://owasp.org/Top10/A03_2021-Injection/'
    ]
  },
  'ssti-check': {
    cwe: 'CWE-1336',
    owasp: 'A03:2021-Injection',
    cvssScore: 9.8,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/1336.html',
      'https://portswigger.net/web-security/server-side-template-injection'
    ]
  },
  'cache-poisoning': {
    cwe: 'CWE-444',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 8.2,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/444.html',
      'https://portswigger.net/web-security/web-cache-poisoning'
    ]
  },
  'http-desync-smuggling': {
    cwe: 'CWE-444',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 8.6,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/444.html',
      'https://portswigger.net/web-security/request-smuggling'
    ]
  },
  'bola-mass-assignment': {
    cwe: 'CWE-639',
    owasp: 'A01:2021-Broken Access Control',
    cvssScore: 8.6,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/639.html',
      'https://cwe.mitre.org/data/definitions/915.html'
    ]
  },
  'dom-xss-sinks': {
    cwe: 'CWE-79',
    owasp: 'A03:2021-Injection',
    cvssScore: 7.5,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/79.html',
      'https://portswigger.net/web-security/cross-site-scripting/dom-based'
    ]
  },
  'xxe-injection': {
    cwe: 'CWE-611',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 8.6,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/611.html',
      'https://portswigger.net/web-security/xxe'
    ]
  },
  'crlf-header-injection': {
    cwe: 'CWE-113',
    owasp: 'A03:2021-Injection',
    cvssScore: 7.5,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/113.html',
      'https://owasp.org/www-community/vulnerabilities/CRLF_Injection'
    ]
  },
  'ssrf-surface': {
    cwe: 'CWE-918',
    owasp: 'A10:2021-Server-Side Request Forgery',
    cvssScore: 8.6,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/918.html',
      'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/'
    ]
  },
  'runtime-sca': {
    cwe: 'CWE-1395',
    owasp: 'A06:2021-Vulnerable and Outdated Components',
    cvssScore: 7.5,
    cveIds: [],
    references: [
      'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
      'https://cwe.mitre.org/data/definitions/1395.html'
    ]
  },
  'rce': {
    cwe: 'CWE-94',
    owasp: 'A03:2021-Injection',
    cvssScore: 9.8,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/94.html',
      'https://owasp.org/Top10/A03_2021-Injection/'
    ]
  },
  'ssrf': {
    cwe: 'CWE-918',
    owasp: 'A10:2021-Server-Side Request Forgery',
    cvssScore: 9.1,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/918.html',
      'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/'
    ]
  },
  'default': {
    cwe: 'CWE-16',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 5.3,
    cveIds: [],
    references: [
      'https://cwe.mitre.org/data/definitions/16.html',
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    ]
  }
};

function resolveCweOwaspFallback(id) {
  if (Object.hasOwn(CWE_OWASP_MAP, id)) {
    return CWE_OWASP_MAP[id];
  }
  const lower = String(id || '').toLowerCase();
  if (lower.includes('xss')) return CWE_OWASP_MAP['xss'];
  if (lower.includes('sql')) return CWE_OWASP_MAP['sqli'];
  if (lower.includes('lfi') || lower.includes('traversal')) return CWE_OWASP_MAP['php-lfi'];
  if (lower.includes('ssrf')) return CWE_OWASP_MAP['ssrf'];
  if (lower.includes('rce') || lower.includes('cmd') || lower.includes('exec')) return CWE_OWASP_MAP['rce'];
  if (lower.includes('redirect')) return CWE_OWASP_MAP['open-redirect'];
  if (lower.includes('jwt') || lower.includes('auth')) return CWE_OWASP_MAP['jwt-security'];
  if (lower.includes('ssl') || lower.includes('tls')) return CWE_OWASP_MAP['ssl-tls'];
  return CWE_OWASP_MAP['default'];
}

/**
 * Builds CHECK_CATALOG keyed by filename stem, lowercased name, and known aliases.
 */
export const CHECK_CATALOG = {};

for (const entry of METADATA_ENTRIES) {
  const enrichment = resolveCweOwaspFallback(entry.id);
  const meta = {
    id: entry.id,
    title: entry.title,
    category: entry.category,
    plainExplanation: entry.plainExplanation,
    whyItMatters: entry.whyItMatters,
    defaultFix: entry.defaultFix,
    remediation: entry.defaultFix,
    cwe: enrichment.cwe,
    owasp: enrichment.owasp,
    cvssScore: enrichment.cvssScore,
    cveIds: [...(enrichment.cveIds || [])],
    references: [...(enrichment.references || [])]
  };

  CHECK_CATALOG[entry.id] = meta;
  CHECK_CATALOG[entry.id.replace(/-/g, ' ')] = meta;

  if (Array.isArray(entry.aliases)) {
    for (const alias of entry.aliases) {
      CHECK_CATALOG[alias.toLowerCase()] = meta;
    }
  }
}

/**
 * Formats a raw identifier into Title Case.
 */
function formatTitle(str) {
  return String(str)
    .replace(/^\./, '')
    .replace(/[-_.]+/g, ' ')
    .replace(/\b\w/g, c => c.toUpperCase())
    .trim();
}

/**
 * Fallback metadata generator for custom or unknown checks.
 */
function createFallbackMeta(nameOrId) {
  const clean = String(nameOrId || '').trim();
  const id = clean.toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/^-+|-+$/g, '') || 'custom-check';
  const title = formatTitle(clean) || 'Custom Security Check';
  const enrichment = resolveCweOwaspFallback(id);
  const defaultFix = 'Review configuration and restrict access according to the principle of least privilege.';

  return {
    id,
    title,
    category: 'General Security',
    plainExplanation: `Verifies security configurations and safeguards for ${title}.`,
    whyItMatters: 'Ensures the application adheres to defensive security best practices and prevents unauthorized access.',
    defaultFix,
    remediation: defaultFix,
    cwe: enrichment.cwe,
    owasp: enrichment.owasp,
    cvssScore: enrichment.cvssScore,
    cveIds: [...(enrichment.cveIds || [])],
    references: [...(enrichment.references || [])]
  };
}

/**
 * Looks up rich metadata by check ID, filename stem, or result name with smart fallback.
 *
 * @param {string} nameOrId
 * @returns {{ id: string, title: string, category: string, plainExplanation: string, whyItMatters: string, defaultFix: string, remediation: string, cwe: string, owasp: string, cvssScore: number, cveIds: string[], references: string[] }}
 */
export function getCheckInfo(nameOrId) {
  if (!nameOrId || typeof nameOrId !== 'string') {
    return createFallbackMeta(nameOrId);
  }

  const raw = nameOrId.trim();
  const lower = raw.toLowerCase();

  // 1. Direct lookup in catalog
  if (Object.hasOwn(CHECK_CATALOG, raw)) return CHECK_CATALOG[raw];
  if (Object.hasOwn(CHECK_CATALOG, lower)) return CHECK_CATALOG[lower];

  // 2. Normalized variants
  const noDot = lower.replace(/^\./, '');
  if (Object.hasOwn(CHECK_CATALOG, noDot)) return CHECK_CATALOG[noDot];

  const withHyphens = noDot.replace(/\s+/g, '-');
  if (Object.hasOwn(CHECK_CATALOG, withHyphens)) return CHECK_CATALOG[withHyphens];

  const withSpaces = noDot.replace(/[-_]+/g, ' ');
  if (Object.hasOwn(CHECK_CATALOG, withSpaces)) return CHECK_CATALOG[withSpaces];

  // 3. Match by id or title in catalog values
  const found = Object.values(CHECK_CATALOG).find(c =>
    c.id === withHyphens ||
    c.title.toLowerCase() === lower ||
    c.title.toLowerCase() === withSpaces
  );
  if (found) return found;

  // 4. Smart fallback for custom checks
  return createFallbackMeta(raw);
}

/**
 * Alias of getCheckInfo returning full enriched metadata (including CWE, OWASP, CVSS, remediation, references).
 *
 * @param {string} nameOrId
 */
export function getCheckMeta(nameOrId) {
  return getCheckInfo(nameOrId);
}

/**
 * Groups all canonical catalog checks by category.
 *
 * @returns {Record<string, Array<object>>}
 */
export function getCatalogByCategory() {
  const byCategory = {};
  const seenIds = new Set();

  for (const entry of METADATA_ENTRIES) {
    if (seenIds.has(entry.id)) continue;
    seenIds.add(entry.id);
    const meta = CHECK_CATALOG[entry.id];
    const cat = meta.category || 'General Security';
    if (!byCategory[cat]) {
      byCategory[cat] = [];
    }
    byCategory[cat].push(meta);
  }

  return byCategory;
}

const cloneProfileChecks = (id) => (
  Array.isArray(PROFILES[id]?.checks) ? [...PROFILES[id].checks] : null
);

/**
 * Scan presets designed for regular users in the web UI and CLI.
 * Check lists are derived directly from PROFILES as the single source of truth.
 */
export const PRESETS = [
  {
    id: 'smart',
    name: 'Smart Auto-Detect (Recommended)',
    tagline: 'Detects your site tech stack first & runs the right checks',
    description: 'Automatically fingerprints the target website (Laravel, WordPress, Next.js, Node, Python, Spring, etc.) and runs universal web checks plus only the checks that match your stack.',
    checks: cloneProfileChecks('smart')
  },
  {
    id: 'quick',
    name: 'Quick Health Check',
    tagline: 'Fast 10-second check of SSL, headers & exposed secrets',
    description: 'Scans essential baseline defenses including SSL certificates, basic security headers, and common configuration file leaks in under 10 seconds.',
    checks: cloneProfileChecks('quick')
  },
  {
    id: 'full',
    name: 'Full Website Audit',
    tagline: 'Complete security check across all technologies',
    description: 'Comprehensive evaluation executing all available security scanners against the target system.',
    checks: cloneProfileChecks('full')
  },
  {
    id: 'modern',
    name: 'Modern Web & AI App',
    tagline: 'React, Next.js, Node.js, AI/LLM endpoints & supply chain',
    description: 'Tailored for contemporary JavaScript frameworks, Next.js server actions, AI/LLM endpoint exposures, and SRI supply chain security.',
    checks: cloneProfileChecks('modern')
  },
  {
    id: 'cms',
    name: 'CMS & E-Commerce',
    tagline: 'WordPress, Laravel, Magento, Drupal & PHP security',
    description: 'Deep audit for content management platforms and frameworks including WordPress, Laravel, Magento/Adobe Commerce, Drupal, and CodeIgniter.',
    checks: cloneProfileChecks('cms')
  },
  {
    id: 'api',
    name: 'API & Backend Service',
    tagline: 'CORS, JWT, Rate Limiting, GraphQL & Auth',
    description: 'Specialized for REST and GraphQL endpoints testing access controls, token security, rate limiting, and HTTP verb manipulation.',
    checks: cloneProfileChecks('api')
  },
  {
    id: 'device',
    name: 'Smart TV, Camera, PC & LAN Device',
    tagline: 'Smart TVs, IP Cameras / NVRs, PCs / Workstations / Dev Servers, Routers & IoT',
    description: 'Non-intrusive multi-port device discovery and security audit for Smart TVs, IP cameras / NVRs (RTSP, ONVIF, Hikvision, Dahua, Axis), PCs / workstations / local servers (SMB, RDP, WinRM, SSH, VNC, CUPS, Docker, Ollama, dev servers), routers, printers, NAS, and smart home IoT hubs.',
    checks: cloneProfileChecks('device')
  }
];

/**
 * Generates scanner code and corresponding test code templates for a new check.
 *
 * @param {string} name
 * @param {object} [options={}]
 * @returns {{ checkFilename: string, checkCode: string, testFilename: string, testCode: string }}
 */
export function generateCheckTemplate(name, options = {}) {
  const cleanName = String(name).toLowerCase().trim();

  if (!/^[a-z0-9-]{2,40}$/.test(cleanName)) {
    throw new Error(`Invalid check name "${name}". Name must match /^[a-z0-9-]{2,40}$/ (2-40 lowercase letters, numbers, and hyphens).`);
  }

  const title = options.title || formatTitle(cleanName);
  const category = options.category || 'General Security';
  const plainExplanation = options.plainExplanation || `Checks for security issues related to ${title}.`;
  const whyItMatters = options.whyItMatters || 'Helps protect the target application against common security exposures and misconfigurations.';
  const defaultFix = options.defaultFix || 'Apply recommended security hardening and restrict access to authorized users only.';
  const tags = Array.isArray(options.tags) && options.tags.length ? options.tags : ['all'];

  const safeCommentTitle = String(title).replace(/[\r\n]+/g, ' ').replace(/\/\*|\*\//g, '');

  const cveIds = Array.isArray(options.cveIds)
    ? options.cveIds.map(id => String(id || '').trim().toUpperCase()).filter(id => /^CVE-\d{4}-\d{4,}$/.test(id))
    : [];
  const cwe = typeof options.cwe === 'string' && options.cwe.trim() ? options.cwe.trim() : null;
  const owasp = typeof options.owasp === 'string' && options.owasp.trim() ? options.owasp.trim() : null;
  const cvssScore = Number.isFinite(Number(options.cvssScore)) ? Number(options.cvssScore) : null;

  const extraMetaLines = [];
  if (cveIds.length > 0) extraMetaLines.push(`  cveIds: ${JSON.stringify(cveIds)},`);
  if (cwe) extraMetaLines.push(`  cwe: ${JSON.stringify(cwe)},`);
  if (owasp) extraMetaLines.push(`  owasp: ${JSON.stringify(owasp)},`);
  if (cvssScore !== null) extraMetaLines.push(`  cvssScore: ${JSON.stringify(cvssScore)},`);
  const extraMetaBlock = extraMetaLines.length > 0 ? `\n${extraMetaLines.join('\n')}` : '';

  const checkFilename = `${cleanName}.js`;
  const testFilename = `${cleanName}.test.js`;

  const checkCode = `export const tags = ${JSON.stringify(tags)};

export const meta = {
  id: ${JSON.stringify(cleanName)},
  title: ${JSON.stringify(title)},
  category: ${JSON.stringify(category)},${extraMetaBlock}
  plainExplanation: ${JSON.stringify(plainExplanation)},
  whyItMatters: ${JSON.stringify(whyItMatters)},
  defaultFix: ${JSON.stringify(defaultFix)}
};

/**
 * ${safeCommentTitle} scanner
 */
export default async function run(target, fetchWithRetry) {
  try {
    const res = await fetchWithRetry(\`\${target}/\`);

    // TODO: Add detection logic here
    // Example:
    // if (res.status === 200 && res.text.includes('vulnerable-signal')) {
    //   return {
    //     name: ${JSON.stringify(cleanName)},
    //     status: 'VULNERABLE',
    //     severity: 'HIGH',
    //     fix: ${JSON.stringify(defaultFix)}
    //   };
    // }

    return {
      name: ${JSON.stringify(cleanName)},
      status: 'SAFE',
      severity: 'NONE'
    };
  } catch (e) {
    return {
      name: ${JSON.stringify(cleanName)},
      status: 'ERROR',
      severity: 'LOW',
      reason: e.message
    };
  }
}
`;

  const testCode = `import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mockFetch, mockFetchError } from '../helpers/mock-fetch.js';
import run from '../../checks/${checkFilename}';

const BASE = 'https://example.com';

test(${JSON.stringify(`${cleanName}: SAFE on normal response`)}, async () => {
  const fetch = mockFetch({ status: 200, text: 'OK' });
  const r = await run(BASE, fetch);
  assert.equal(r.status, 'SAFE');
  assert.equal(r.severity, 'NONE');
});

test(${JSON.stringify(`${cleanName}: ERROR on fetch failure`)}, async () => {
  const r = await run(BASE, mockFetchError('connection failure'));
  assert.equal(r.status, 'ERROR');
  assert.equal(r.severity, 'LOW');
});
`;

  return {
    checkFilename,
    checkCode,
    testFilename,
    testCode
  };
}

/**
 * Scaffolds a new scanner check file and test file.
 *
 * @param {string} name
 * @param {object} [options={}]
 * @returns {{ created: boolean, dryRun: boolean, checkFilename: string, testFilename: string, checkPath: string, testPath: string, checkCode: string, testCode: string }}
 */
export function scaffoldCheck(name, options = {}) {
  const cleanName = String(name).toLowerCase().trim();

  if (!/^[a-z0-9-]{2,40}$/.test(cleanName)) {
    throw new Error(`Invalid check name "${name}". Name must match /^[a-z0-9-]{2,40}$/ (2-40 lowercase letters, numbers, and hyphens).`);
  }

  const { checkFilename, checkCode, testFilename, testCode } = generateCheckTemplate(cleanName, options);

  const checkPath = path.join(process.cwd(), 'checks', checkFilename);
  const testPath = path.join(process.cwd(), 'tests', 'checks', testFilename);

  if (fs.existsSync(checkPath)) {
    throw new Error(`Check file already exists: ${checkPath}`);
  }
  if (fs.existsSync(testPath)) {
    throw new Error(`Test file already exists: ${testPath}`);
  }

  if (options.dryRun) {
    return {
      created: false,
      dryRun: true,
      checkFilename,
      testFilename,
      checkPath,
      testPath,
      checkCode,
      testCode
    };
  }

  const checkDir = path.dirname(checkPath);
  if (!fs.existsSync(checkDir)) fs.mkdirSync(checkDir, { recursive: true });

  const testDir = path.dirname(testPath);
  if (!fs.existsSync(testDir)) fs.mkdirSync(testDir, { recursive: true });

  fs.writeFileSync(checkPath, checkCode, 'utf8');
  fs.writeFileSync(testPath, testCode, 'utf8');

  return {
    created: true,
    dryRun: false,
    checkFilename,
    testFilename,
    checkPath,
    testPath,
    checkCode,
    testCode
  };
}
