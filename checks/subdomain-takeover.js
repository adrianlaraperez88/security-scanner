import dnsPromises from 'node:dns/promises';
import net from 'node:net';
import { URL } from 'node:url';

export const tags = ['all'];

export const meta = {
  id: 'subdomain-takeover',
  title: 'Subdomain Takeover & Dangling CNAME Cloud Resource Detection',
  category: 'Infrastructure & Network',
  plainExplanation:
    'Inspects DNS CNAME chains and HTTP response signatures for dangling DNS records pointing to unclaimed third-party cloud platforms (GitHub Pages, AWS S3, Heroku, Fastly, Azure, Shopify, Vercel, Netlify, Pantheon, Zendesk, Surge.sh, Fly.io).',
  whyItMatters:
    'A dangling CNAME pointing to a deprovisioned external cloud service lets an attacker register the unclaimed resource name and serve arbitrary content, steal session cookies, or issue valid TLS certificates under your domain.',
  defaultFix:
    'Remove dangling CNAME, A, and AAAA DNS records before deprovisioning cloud buckets or PaaS applications, or immediately claim the target resource in your organization cloud account.',
  cwe: 'CWE-284',
  owasp: 'A05:2021-Security Misconfiguration',
  cvssScore: 8.2,
  references: [
    'https://cwe.mitre.org/data/definitions/284.html',
    'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover'
  ]
};

/**
 * Verified provider takeover signatures (adapted from SecScan `bbot-recon` `baddns`).
 * To eliminate false positives, a finding is only reported when BOTH:
 * 1. The target's CNAME (or provider response header) matches the cloud provider domain pattern, AND
 * 2. The HTTP response body contains the exact unclaimed provider error signature.
 */
export const TAKEOVER_FINGERPRINTS = [
  {
    provider: 'GitHub Pages',
    cnameRe: /(?:^|\.)github\.io$/i,
    headerMarkerRe: /GitHub\.com/i,
    bodySignatures: ["There isn't a GitHub Pages site here.", 'For root URLs (like http://example.com/) you must provide an index.html file']
  },
  {
    provider: 'AWS S3',
    cnameRe: /(?:^|\.)s3(?:-[a-z0-9-]+|\.[a-z0-9-]+)?\.amazonaws\.com$/i,
    headerMarkerRe: /AmazonS3/i,
    bodySignatures: ['NoSuchBucket', 'The specified bucket does not exist']
  },
  {
    provider: 'Heroku',
    cnameRe: /(?:^|\.)(?:herokuapp|herokussl|herokudns)\.com$/i,
    headerMarkerRe: /heroku/i,
    bodySignatures: ['No such app', 'there is no app configured at that hostname']
  },
  {
    provider: 'Fastly',
    cnameRe: /(?:^|\.)fastly(?:lb)?\.net$/i,
    headerMarkerRe: /Fastly/i,
    bodySignatures: ['Fastly error: unknown domain:']
  },
  {
    provider: 'Microsoft Azure',
    cnameRe: /(?:^|\.)(?:azurewebsites\.net|cloudapp\.net|azurefd\.net|blob\.core\.windows\.net|trafficmanager\.net)$/i,
    headerMarkerRe: /Windows-Azure|Microsoft-Azure/i,
    bodySignatures: ['404 Web Site not found', 'Error 404 - Web app not found']
  },
  {
    provider: 'Shopify',
    cnameRe: /(?:^|\.)myshopify\.com$/i,
    headerMarkerRe: /shopify/i,
    bodySignatures: ['Sorry, this shop is currently unavailable.', 'Only one step left! To finish setting up your new web address']
  },
  {
    provider: 'Surge.sh',
    cnameRe: /(?:^|\.)surge\.sh$/i,
    headerMarkerRe: /Surge/i,
    bodySignatures: ['project not found']
  },
  {
    provider: 'Pantheon',
    cnameRe: /(?:^|\.)pantheonsite\.io$/i,
    headerMarkerRe: /pantheon/i,
    bodySignatures: ['404 error unknown site!', 'The gods are wise, but do not know of the site which you seek.']
  },
  {
    provider: 'Zendesk',
    cnameRe: /(?:^|\.)zendesk\.com$/i,
    headerMarkerRe: /zendesk/i,
    bodySignatures: ['Help Center Closed', 'this help center no longer exists']
  },
  {
    provider: 'Vercel',
    cnameRe: /(?:^|\.)(?:vercel\.app|now\.sh|vercel-dns\.com)$/i,
    headerMarkerRe: /Vercel/i,
    bodySignatures: ['The deployment could not be found on Vercel.', 'DEPLOYMENT_NOT_FOUND']
  },
  {
    provider: 'Netlify',
    cnameRe: /(?:^|\.)(?:netlify\.app|netlify\.com)$/i,
    headerMarkerRe: /Netlify/i,
    bodySignatures: ['Not Found - Request ID:']
  },
  {
    provider: 'Fly.io',
    cnameRe: /(?:^|\.)fly\.dev$/i,
    headerMarkerRe: /Fly/i,
    bodySignatures: ['404 Not Found: app not found']
  }
];

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

async function resolveCnamesSafe(hostname, fetchWithRetry) {
  const customResolver = fetchWithRetry?.governance?.dnsResolver;
  if (customResolver && typeof customResolver.resolveCname === 'function') {
    try {
      const cnames = await customResolver.resolveCname(hostname);
      return Array.isArray(cnames) ? cnames.map(c => String(c).toLowerCase().replace(/\.+$/, '')) : [];
    } catch {
      return [];
    }
  }
  // If running with an offline mock fetch or custom function dnsResolver without resolveCname, skip live OS DNS
  if (!fetchWithRetry?.governance || typeof customResolver === 'function') {
    return [];
  }
  let timer = null;
  try {
    const cnames = await Promise.race([
      dnsPromises.resolveCname(hostname),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('CNAME lookup timeout')), 1500);
        if (typeof timer.unref === 'function') timer.unref();
      })
    ]);
    return Array.isArray(cnames) ? cnames.map(c => String(c).toLowerCase().replace(/\.+$/, '')) : [];
  } catch {
    return [];
  } finally {
    if (timer) clearTimeout(timer);
  }
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
      detail: 'Target URL could not be parsed.'
    };
  }

  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
  if (!hostname || net.isIP(hostname) !== 0) {
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      status: 'SAFE',
      detail: 'Target is an IP literal; subdomain CNAME takeover does not apply.'
    };
  }

  let res;
  try {
    res = await fetchWithRetry(target, { followRedirects: false });
  } catch (err) {
    if (isGovernanceBlock(err)) throw err;
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      status: 'ERROR',
      detail: `Target request failed: ${err.message}`
    };
  }

  const body = String(res?.text || '');
  const candidateFingerprints = TAKEOVER_FINGERPRINTS.filter(fp =>
    fp.bodySignatures.some(sig => body.includes(sig))
  );
  if (candidateFingerprints.length === 0) {
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      status: 'SAFE',
      detail: 'No dangling CNAME or unclaimed cloud provider takeover signature detected.'
    };
  }

  const cnames = await resolveCnamesSafe(hostname, fetchWithRetry);
  const headerCorpus = Object.entries(res?.headers || {})
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n');

  for (const fp of candidateFingerprints) {
    const matchedCname = cnames.find(c => fp.cnameRe.test(c)) || null;
    const matchedHeader = fp.headerMarkerRe ? fp.headerMarkerRe.test(headerCorpus) : false;
    const matchedSig = fp.bodySignatures.find(sig => body.includes(sig)) || null;

    if (matchedSig && (matchedCname || matchedHeader)) {
      const isConfirmedCname = Boolean(matchedCname);
      return {
        name: meta.title,
        checkId: meta.id,
        target,
        url: target,
        status: isConfirmedCname ? 'VULNERABLE' : 'SUSPICIOUS',
        severity: isConfirmedCname ? 'HIGH' : 'MEDIUM',
        findings: [
          {
            provider: fp.provider,
            hostname,
            cname: matchedCname,
            url: target,
            status: res.status,
            matchedSignal: matchedSig,
            issue: `Subdomain "${hostname}"${matchedCname ? ` points via CNAME to "${matchedCname}" and` : ''} returned unclaimed ${fp.provider} signature: "${matchedSig}".`
          }
        ],
        evidenceQuotes: [matchedSig],
        poeLevel: 3,
        ...(res?.trafficId ? { trafficId: res.trafficId } : {}),
        reproduction: {
          method: 'GET',
          url: target,
          responseStatus: res.status,
          observedSignal: `HTTP ${res.status} — matched ${JSON.stringify(matchedSig)}`
        },
        detail: `Subdomain "${hostname}" is vulnerable to ${fp.provider} subdomain takeover (${matchedCname ? `CNAME -> ${matchedCname}, ` : ''}matched "${matchedSig}").`
      };
    }
  }

  return {
    name: meta.title,
    checkId: meta.id,
    target,
    status: 'SAFE',
    detail: 'No dangling CNAME or unclaimed cloud provider takeover signature detected.'
  };
}
