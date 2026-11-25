import { URL } from 'node:url';
import { isFrameworkRouteErrorResponse } from '../core/check-verify.js';

export const tags = ['iis', 'aspnet', 'windows'];

export const meta = {
  id: 'iis-shortname',
  title: 'Microsoft IIS 8.3 Shortname (~1) Enumeration & ASP.NET Diagnostic Exposure',
  category: 'Server & Configuration',
  plainExplanation:
    'Performs a safe status/error differential probe for Windows NTFS 8.3 tilde (~1) shortname enumeration on Microsoft IIS servers and checks for exposed ASP.NET trace.axd and elmah.axd diagnostic handlers.',
  whyItMatters:
    'IIS 8.3 shortname disclosure allows attackers to brute-force hidden backup files, admin scripts, and configuration files 6 characters at a time. Exposed trace.axd or elmah.axd pages leak session cookies, viewstate secrets, and full HTTP request logs.',
  defaultFix:
    'Disable NTFS 8.3 shortname creation on Windows volumes (fsutil 8dot3name set 1), block requests containing tilde (~) characters in IIS Request Filtering, and set <trace enabled="false" /> and restrict elmah.axd in web.config.',
  cwe: 'CWE-200',
  owasp: 'A05:2021-Security Misconfiguration',
  cvssScore: 6.5,
  references: [
    'https://cwe.mitre.org/data/definitions/200.html',
    'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
  ]
};

const GOVERNANCE_ERROR_CODES = new Set([
  'SSRF_POLICY_BLOCKED',
  'TARGET_RULE_BLOCKED',
  'TARGET_OUT_OF_SCOPE',
  'DNS_REBIND_OR_PRIVATE_IP'
]);

function isGovernanceBlock(err) {
  if (!err) return false;
  if (err.isGovernanceBlock === true || GOVERNANCE_ERROR_CODES.has(err.code)) return true;
  const msg = String(err.message || '');
  return (
    msg.startsWith('Redirect blocked by SSRF policy') ||
    msg.startsWith('Request blocked by SSRF policy') ||
    msg.startsWith('[SECSCAN platform control')
  );
}

function getHeader(headers, key) {
  if (!headers || typeof headers !== 'object') return '';
  const lower = key.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (String(k).toLowerCase() === lower) {
      return String(v ?? '');
    }
  }
  return '';
}

function isIisOrAspNetResponse(res) {
  if (!res || typeof res !== 'object') return false;
  const server = getHeader(res.headers, 'server');
  const poweredBy = getHeader(res.headers, 'x-powered-by');
  const aspNetVer = getHeader(res.headers, 'x-aspnet-version');
  const aspNetMvc = getHeader(res.headers, 'x-aspnetmvc-version');
  const setCookie = getHeader(res.headers, 'set-cookie');
  return (
    /\bMicrosoft-IIS\b/i.test(server) ||
    /\bASP\.NET\b/i.test(poweredBy) ||
    Boolean(aspNetVer) ||
    Boolean(aspNetMvc) ||
    /\bASP\.NET_SessionId=/i.test(setCookie)
  );
}

export async function run(targetInput, fetchWithRetry) {
  const target = Array.isArray(targetInput) ? targetInput[0] : targetInput;
  if (!target || typeof target !== 'string') {
    return {
      name: meta.title,
      checkId: meta.id,
      target: String(target || ''),
      status: 'SAFE',
      detail: 'No valid target URL provided.'
    };
  }

  let parsed;
  try {
    parsed = new URL(target);
  } catch {
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      status: 'SAFE',
      detail: 'Invalid target URL.'
    };
  }

  let baseRes;
  try {
    baseRes = await fetchWithRetry(target, { followRedirects: false });
  } catch (err) {
    if (isGovernanceBlock(err)) throw err;
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      status: 'ERROR',
      detail: `Baseline probe failed: ${err.message}`
    };
  }

  // Only run active IIS/ASP.NET probes if target fingerprints as IIS or ASP.NET
  if (!isIisOrAspNetResponse(baseRes)) {
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      status: 'SAFE',
      detail: 'Target does not fingerprint as Microsoft IIS or ASP.NET.'
    };
  }

  const findings = [];
  const evidenceQuotes = [];
  const trafficIds = [];
  if (baseRes?.trafficId) trafficIds.push(baseRes.trafficId);

  // 1. Check ASP.NET diagnostic handlers (/trace.axd and /elmah.axd) with strict signature verification
  const diagProbes = [
    {
      path: '/trace.axd',
      sigRe: /(?:Application Trace|Requests to this Application|Trace\.axd|ASP\.NET Trace)/i,
      title: 'ASP.NET Application Trace (/trace.axd) exposed publicly'
    },
    {
      path: '/elmah.axd',
      sigRe: /(?:Error Log for\b|ELMAH - Error Logging Modules and Handlers|Powered by ELMAH)/i,
      title: 'ASP.NET ELMAH Error Log (/elmah.axd) exposed publicly'
    }
  ];

  for (const probe of diagProbes) {
    const probeUrl = new URL(probe.path, parsed.origin).href;
    try {
      const res = await fetchWithRetry(probeUrl, { followRedirects: false });
      if (res?.trafficId) trafficIds.push(res.trafficId);
      const body = String(res?.text || '');
      const match = body.match(probe.sigRe);
      if (res && res.status === 200 && !isFrameworkRouteErrorResponse(res) && match) {
        const quote = match[0].length >= 8 ? match[0] : `ASP.NET ${match[0]}`;
        findings.push({
          type: 'aspnet_diagnostic_exposure',
          severity: 'HIGH',
          path: probe.path,
          url: probeUrl,
          status: res.status,
          issue: `${probe.title} at ${probeUrl} (matched "${match[0]}").`,
          matchedSignal: quote
        });
        evidenceQuotes.push(quote);
      }
    } catch (err) {
      if (isGovernanceBlock(err)) throw err;
    }
  }

  // 2. IIS 8.3 tilde (~1) shortname differential check:
  //    Compare wildcard shortname match `/*~1*/.aspx` against guaranteed non-existent `/secscan_no83_zz9~1*/.aspx`
  const matchProbeUrl = new URL('/*~1*/.aspx', parsed.origin).href;
  const missProbeUrl = new URL('/secscan_no83_zz9~1*/.aspx', parsed.origin).href;
  try {
    const [matchRes, missRes] = await Promise.all([
      fetchWithRetry(matchProbeUrl, { followRedirects: false }),
      fetchWithRetry(missProbeUrl, { followRedirects: false })
    ]);
    if (matchRes?.trafficId) trafficIds.push(matchRes.trafficId);

    const matchBody = String(matchRes?.text || '');
    const missBody = String(missRes?.text || '');
    const hasIisErrorCodeDiff =
      matchRes &&
      missRes &&
      matchRes.status === 404 &&
      missRes.status === 400 &&
      /Microsoft-IIS/i.test(getHeader(matchRes.headers, 'server'));
    const hasSubstatusDiff =
      matchRes &&
      missRes &&
      /0x80070002|HTTP Error 404\.0/i.test(matchBody) &&
      !/0x80070002|HTTP Error 404\.0/i.test(missBody);

    if (hasIisErrorCodeDiff || hasSubstatusDiff) {
      const serverHdr = getHeader(matchRes.headers, 'server') || 'Microsoft-IIS';
      const quote = `Server: ${serverHdr}`;
      findings.push({
        type: 'iis_83_shortname_enumeration',
        severity: 'MEDIUM',
        path: '/*~1*/.aspx',
        url: matchProbeUrl,
        status: matchRes.status,
        issue: `IIS 8.3 shortname (~1) differential confirmed: /*~1*/.aspx returned HTTP ${matchRes.status} while non-existent shortname returned HTTP ${missRes.status}.`,
        matchedSignal: quote
      });
      evidenceQuotes.push(quote);
    }
  } catch (err) {
    if (isGovernanceBlock(err)) throw err;
  }

  if (findings.length === 0) {
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      status: 'SAFE',
      detail: 'No IIS 8.3 shortname enumeration differential or ASP.NET diagnostic exposure detected.'
    };
  }

  const hasHigh = findings.some(f => f.severity === 'HIGH');
  const primary = findings[0];
  return {
    name: meta.title,
    checkId: meta.id,
    target,
    url: primary.url || target,
    status: hasHigh ? 'VULNERABLE' : 'SUSPICIOUS',
    severity: hasHigh ? 'HIGH' : 'MEDIUM',
    findings,
    evidenceQuotes: Array.from(new Set(evidenceQuotes)).filter(q => q.length >= 8).slice(0, 5),
    poeLevel: 3,
    ...(trafficIds.length > 0 ? { trafficId: trafficIds[trafficIds.length - 1], trafficIds } : {}),
    detail: findings.map(f => f.issue).join(' ')
  };
}
