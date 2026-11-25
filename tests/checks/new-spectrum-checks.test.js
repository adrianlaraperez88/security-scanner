import { test } from 'node:test';
import assert from 'node:assert/strict';
import { run as runOriginSourceIp, meta as originMeta, tags as originTags } from '../../checks/origin-source-ip.js';
import { run as runPhpUploadProgress, meta as phpUploadMeta } from '../../checks/php-session-upload-progress.js';
import { run as runApiSpectrum, meta as apiSpectrumMeta } from '../../checks/api-security-spectrum.js';
import { run as runSubdomainTakeover, meta as takeoverMeta, tags as takeoverTags } from '../../checks/subdomain-takeover.js';
import { run as runIisShortname, meta as iisMeta } from '../../checks/iis-shortname.js';
import { selectScannersForStack } from '../../core/profiles.js';
import { EnrichEngine } from '../../core/enrich.js';
import { createTrackedFetch } from '../../core/reproduction.js';

const BASE = 'https://app.example.com';

test('origin-source-ip: detects X-Origin-IP leak and CDN/WAF bypass via direct Source IP, and stays SAFE on normal responses', async () => {
  assert.equal(originMeta.id, 'origin-source-ip');

  // 1. Origin IP header leak
  const leakRes = await runOriginSourceIp(BASE, async () => ({
    status: 200,
    headers: { 'server': 'cloudflare', 'cf-ray': '8abc123', 'x-origin-ip': '198.51.100.42' },
    text: '<html>OK</html>',
    resolvedIp: '203.0.113.10',
    dialedAddress: '203.0.113.10:443'
  }));
  assert.equal(leakRes.status, 'SUSPICIOUS');
  assert.equal(leakRes.severity, 'MEDIUM');
  assert.ok(leakRes.findings.some(f => f.type === 'origin_ip_header_disclosure'));

  // 2. CDN/WAF 403 on edge vs 200 OK on direct Source IP probe
  let callCount = 0;
  const bypassRes = await runOriginSourceIp(BASE, async () => {
    callCount++;
    if (callCount === 1) {
      return {
        status: 403,
        headers: { 'server': 'cloudflare', 'cf-ray': '8abc999' },
        text: 'Attention Required! | Cloudflare',
        resolvedIp: '203.0.113.55',
        sourceIp: '203.0.113.55'
      };
    }
    return {
      status: 200,
      headers: { 'server': 'nginx/1.30.7' },
      text: '<html><body>Origin Admin Dashboard</body></html>',
      resolvedIp: '203.0.113.55',
      sourceIp: '203.0.113.55'
    };
  });
  assert.equal(bypassRes.status, 'VULNERABLE');
  assert.equal(bypassRes.severity, 'HIGH');
  assert.equal(bypassRes.sourceIp, '203.0.113.55');

  // 3. SAFE on normal site
  const safeRes = await runOriginSourceIp(BASE, async () => ({
    status: 200,
    headers: { 'server': 'nginx' },
    text: '<html>Healthy</html>',
    resolvedIp: '203.0.113.10'
  }));
  assert.equal(safeRes.status, 'SAFE');
});

test('php-session-upload-progress: detects CVE-2026-109618 / CVE-2026-109619 (php2shell) on affected PHP versions and stays SAFE on PHP 8.2.35+ / 8.5.12+', async () => {
  assert.deepEqual(phpUploadMeta.cveIds, ['CVE-2026-109618', 'CVE-2026-109619']);

  // 1. Vulnerable PHP 8.2.34 with PHPSESSID cookie
  const vulnRes = await runPhpUploadProgress(BASE, async () => ({
    status: 200,
    headers: {
      'x-powered-by': 'PHP/8.2.34',
      'set-cookie': 'PHPSESSID=a1b2c3d4e5f6g7h8; path=/; HttpOnly'
    },
    text: '<html>App</html>'
  }));
  assert.equal(vulnRes.status, 'VULNERABLE');
  assert.equal(vulnRes.severity, 'CRITICAL');
  assert.deepEqual(vulnRes.cveIds, ['CVE-2026-109618', 'CVE-2026-109619']);

  // 2. Patched PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 -> SAFE
  for (const patched of ['PHP/8.2.35', 'PHP/8.3.36', 'PHP/8.4.27', 'PHP/8.5.12', 'PHP/8.6.0']) {
    const safeRes = await runPhpUploadProgress(BASE, async () => ({
      status: 200,
      headers: { 'x-powered-by': patched },
      text: '<html>Patched</html>'
    }));
    assert.equal(safeRes.status, 'SAFE', `Expected SAFE for ${patched}`);
  }
});

test('api-security-spectrum: detects X-Forwarded-For IP trust-boundary bypass and OIDC missing S256 PKCE, and ignores 404/catch-all routes', async () => {
  assert.equal(apiSpectrumMeta.id, 'api-security-spectrum');

  // 1. X-Forwarded-For: 127.0.0.1 bypasses HTTP 429 rate limit
  const xffRes = await runApiSpectrum(BASE, async (_url, opts = {}) => {
    if (opts.headers?.['X-Forwarded-For'] === '127.0.0.1') {
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        text: '{"status":"authenticated_by_ip","role":"internal"}'
      };
    }
    return {
      status: 429,
      headers: { 'content-type': 'application/json', 'x-ratelimit-remaining': '0' },
      text: '{"error":"Rate limit exceeded"}'
    };
  });
  assert.equal(xffRes.status, 'VULNERABLE');
  assert.equal(xffRes.severity, 'HIGH');
  assert.ok(xffRes.findings.some(f => f.type === 'ip_trust_boundary_bypass'));

  // 2. OIDC configuration without S256 PKCE and with implicit grant
  const oidcRes = await runApiSpectrum(BASE, async (url) => {
    if (url.endsWith('/.well-known/openid-configuration')) {
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        text: JSON.stringify({
          issuer: BASE,
          authorization_endpoint: `${BASE}/oauth/authorize`,
          code_challenge_methods_supported: ['plain'],
          grant_types_supported: ['authorization_code', 'implicit']
        })
      };
    }
    return { status: 404, headers: {}, text: 'Not Found' };
  });
  assert.equal(oidcRes.status, 'SUSPICIOUS');
  assert.ok(oidcRes.findings.some(f => f.type === 'oauth_missing_s256_pkce'));
  assert.ok(oidcRes.findings.some(f => f.type === 'oauth_legacy_grant_types'));
});

test('subdomain-takeover: requires both CNAME/provider match and unclaimed signature, and passes verifyFindingBeforeReport on HTTP 404 takeover proofs', async () => {
  assert.equal(takeoverMeta.id, 'subdomain-takeover');

  const fetchMock = async () => ({
    status: 404,
    headers: { 'server': 'GitHub.com', 'content-type': 'text/html' },
    text: "<html><body><h1>404</h1><p>There isn't a GitHub Pages site here.</p></body></html>"
  });
  fetchMock.governance = {
    dnsResolver: {
      resolveCname: async () => ['abandoned-org.github.io']
    }
  };

  const tracked = createTrackedFetch(fetchMock);
  const rawFinding = await runSubdomainTakeover('https://docs.example.com', tracked);
  assert.equal(rawFinding.status, 'VULNERABLE');
  assert.equal(rawFinding.severity, 'HIGH');

  // Verify EnrichEngine + verifyFindingBeforeReport keeps the 404 subdomain-takeover finding VULNERABLE
  const enrich = new EnrichEngine();
  const enriched = enrich.enrichFinding(
    { target: 'https://docs.example.com', checkId: 'subdomain-takeover', ...rawFinding, meta: takeoverMeta },
    { capturedTraces: tracked.getTraces() }
  );
  assert.equal(enriched.status, 'VULNERABLE');
  assert.ok(enriched.reproduction?.curl?.includes('https://docs.example.com'));

  // Generic 404 page without matching provider signature is SAFE
  const generic404Fetch = async () => ({
    status: 404,
    headers: { 'server': 'caddy', 'content-type': 'application/json' },
    text: '{"message":"The route could not be found."}'
  });
  generic404Fetch.governance = { dnsResolver: async () => ['93.184.216.34'] };
  const safeRes = await runSubdomainTakeover('https://fearlessbull.com', generic404Fetch);
  assert.equal(safeRes.status, 'SAFE');
});

test('iis-shortname: detects IIS 8.3 (~1) differential and trace.axd on IIS servers, and skips non-IIS targets cleanly', async () => {
  assert.equal(iisMeta.id, 'iis-shortname');

  // 1. Non-IIS target (Caddy/Laravel) -> immediately SAFE without extra probes
  let probes = 0;
  const nonIisRes = await runIisShortname('https://fearlessbull.com', async () => {
    probes++;
    return { status: 200, headers: { 'server': 'Caddy' }, text: 'Laravel' };
  });
  assert.equal(nonIisRes.status, 'SAFE');
  assert.equal(probes, 1);

  // 2. IIS server with 8.3 shortname differential (404 on /*~1*/.aspx vs 400 on non-existent shortname)
  const iisFetch = createTrackedFetch(async (url) => {
    if (url.endsWith('/*~1*/.aspx')) {
      return { status: 404, headers: { 'server': 'Microsoft-IIS/10.0' }, text: 'HTTP Error 404.0 - Not Found (0x80070002)' };
    }
    if (url.includes('secscan_no83_zz9~1')) {
      return { status: 400, headers: { 'server': 'Microsoft-IIS/10.0' }, text: 'Bad Request' };
    }
    return { status: 200, headers: { 'server': 'Microsoft-IIS/10.0', 'x-aspnet-version': '4.0.30319' }, text: 'IIS Home' };
  });

  const iisFinding = await runIisShortname(BASE, iisFetch);
  assert.equal(iisFinding.status, 'SUSPICIOUS');
  assert.ok(iisFinding.findings.some(f => f.type === 'iis_83_shortname_enumeration'));

  const enrich = new EnrichEngine();
  const enriched = enrich.enrichFinding(
    { target: BASE, checkId: 'iis-shortname', ...iisFinding, meta: iisMeta },
    { capturedTraces: iisFetch.getTraces() }
  );
  assert.equal(enriched.status, 'SUSPICIOUS');
});

test('origin-source-ip: runs in smart profile, inspects expanded leak headers, and classifies CDN edge vs direct origin vhost', async () => {
  assert.deepEqual(originTags, ['all']);
  assert.deepEqual(takeoverTags, ['all']);

  // selectScannersForStack includes both ['all'] and legacy ['universal'] in smart mode
  const sel = selectScannersForStack(
    [
      { name: 'origin-source-ip', tags: originTags },
      { name: 'legacy-universal', tags: ['universal'] },
      { name: 'wordpress-only', tags: ['wordpress'] }
    ],
    { profile: 'smart', fp: { detectedTags: ['cloudflare'] } }
  );
  assert.ok(sel.activeScanners.some(s => s.name === 'origin-source-ip'));
  assert.ok(sel.activeScanners.some(s => s.name === 'legacy-universal'));
  assert.ok(!sel.activeScanners.some(s => s.name === 'wordpress-only'));

  // 1. Cloudflare edge IP (104.21.43.139) with Error 1003 "Direct IP access not allowed" -> SAFE with CDN attribution
  const cfEdgeRes = await runOriginSourceIp('https://104.21.43.139/', async () => ({
    status: 403,
    headers: { server: 'cloudflare', 'cf-ray': '9999-DFW' },
    text: '<html><title>Direct IP access not allowed | Cloudflare</title><body>Error 1003: Direct IP access not allowed</body></html>'
  }));
  assert.equal(cfEdgeRes.status, 'SAFE');
  assert.equal(cfEdgeRes.isCdnEdge, true);
  assert.equal(cfEdgeRes.cdnProvider, 'Cloudflare');
  assert.equal(cfEdgeRes.directIpBlocked, true);
  assert.equal(cfEdgeRes.resolvedIp, '104.21.43.139');
  assert.match(cfEdgeRes.detail, /Cloudflare CDN\/WAF edge/i);

  // 2. Cloudflare CIDR IP even without cf-ray header still classifies via classifyCdnIp -> SAFE
  const cfCidrOnly = await runOriginSourceIp('http://104.21.43.139/', async () => ({
    status: 400,
    headers: {},
    text: 'Direct IP access not allowed'
  }));
  assert.equal(cfCidrOnly.status, 'SAFE');
  assert.equal(cfCidrOnly.isCdnEdge, true);
  assert.equal(cfCidrOnly.cdnProvider, 'Cloudflare');
  assert.equal(cfCidrOnly.directIpBlocked, true);

  // 3. Expanded origin leak headers (x-server-ip, x-forwarded-server, x-host-ip) trigger SUSPICIOUS even on CDN IP
  for (const hdr of ['x-server-ip', 'x-forwarded-server', 'x-host-ip']) {
    const leakHdrRes = await runOriginSourceIp('https://104.21.43.139/', async () => ({
      status: 403,
      headers: { server: 'cloudflare', 'cf-ray': '1111-DFW', [hdr]: '198.51.100.77' },
      text: 'Direct IP access not allowed'
    }));
    assert.equal(leakHdrRes.status, 'SUSPICIOUS', `Expected SUSPICIOUS for ${hdr}`);
    assert.equal(leakHdrRes.severity, 'MEDIUM');
    assert.ok(leakHdrRes.findings.some(f => f.type === 'origin_ip_header_disclosure'));
  }

  // 4. Non-CDN public IP serving default server vhost -> SUSPICIOUS (MEDIUM, poeLevel: 3) and passes verifyFindingBeforeReport
  const nginxTracked = createTrackedFetch(async () => ({
    status: 200,
    headers: { server: 'nginx/1.24.0' },
    text: '<html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1></body></html>'
  }));
  const nginxRes = await runOriginSourceIp('http://198.51.100.50/', nginxTracked);
  assert.equal(nginxRes.status, 'SUSPICIOUS');
  assert.equal(nginxRes.severity, 'MEDIUM');
  assert.equal(nginxRes.poeLevel, 3);
  assert.ok(nginxRes.evidenceQuotes.includes('Welcome to nginx!'));
  assert.ok(nginxRes.findings.some(f => f.type === 'direct_ip_default_vhost_exposure'));

  const enrichEngine = new EnrichEngine();
  const enrichedNginx = enrichEngine.enrichFinding(
    { target: 'http://198.51.100.50/', checkId: 'origin-source-ip', ...nginxRes, meta: originMeta },
    { capturedTraces: nginxTracked.getTraces() }
  );
  assert.equal(enrichedNginx.status, 'SUSPICIOUS');
  assert.equal(enrichedNginx.poeLevel, 3);

  // 5. Non-CDN public IP serving live app without default vhost leak -> SAFE with direct-origin attribution
  const originSafeRes = await runOriginSourceIp('https://198.51.100.50/', async () => ({
    status: 200,
    headers: { server: 'Caddy' },
    text: '<html><body>Production API Gateway</body></html>'
  }));
  assert.equal(originSafeRes.status, 'SAFE');
  assert.equal(originSafeRes.isCdnEdge, false);
  assert.equal(originSafeRes.resolvedIp, '198.51.100.50');
  assert.match(originSafeRes.detail, /origin\/standalone server/i);
});
