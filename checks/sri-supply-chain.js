export const tags = ['react', 'angular', 'vue', 'nextjs', 'all'];

const COMPROMISED_DOMAINS = ['polyfill.io', 'bootcss.com', 'bootcdn.net', 'staticfile.org'];

export default async function run(target, fetchWithRetry) {
  let res;
  try {
    res = await fetchWithRetry(target);
  } catch {
    return { name: 'supply chain & sri', status: 'ERROR', severity: 'NONE', reason: 'Target unreachable' };
  }

  const html = res?.text || '';
  const found = [];

  let targetHost = '';
  try {
    targetHost = new URL(target).hostname.toLowerCase();
  } catch {
    targetHost = '';
  }

  // Parse <script ...> tags
  const scriptRegex = /<script\b([^>]*)>/gi;
  let match;
  const compromisedScripts = [];
  const missingSriScripts = [];

  while ((match = scriptRegex.exec(html)) !== null) {
    const attrs = match[1];
    const srcMatch = attrs.match(/\bsrc=["']([^"']+)["']/i);
    if (!srcMatch) continue; // inline script

    const src = srcMatch[1].trim();
    const srcLower = src.toLowerCase();

    // Check 1: Known Compromised / High-Risk Supply-Chain Domains
    if (COMPROMISED_DOMAINS.some(d => srcLower.includes(d))) {
      compromisedScripts.push(src);
    }

    // Check 2: External Third-Party Scripts Missing SRI
    let isExternal = false;
    if (src.startsWith('http://') || src.startsWith('https://') || src.startsWith('//')) {
      try {
        const fullUrl = src.startsWith('//') ? `https:${src}` : src;
        const scriptUrl = new URL(fullUrl);
        if (scriptUrl.hostname && scriptUrl.hostname.toLowerCase() !== targetHost) {
          isExternal = true;
        }
      } catch { /* malformed url */ }
    }

    if (isExternal) {
      const hasSri = /integrity=["']sha/i.test(attrs);
      if (!hasSri) {
        missingSriScripts.push(src);
      }
    }
  }

  if (compromisedScripts.length > 0) {
    found.push({
      name: 'compromised cdn script domain',
      severity: 'CRITICAL',
      status: 'VULNERABLE',
      reason: `Found ${compromisedScripts.length} script(s) loading from known compromised supply-chain CDN domain(s): ${compromisedScripts.join(', ')}.`
    });
  }

  if (missingSriScripts.length > 0) {
    const count = missingSriScripts.length;
    const severity = count >= 3 ? 'MEDIUM' : 'LOW';
    found.push({
      name: 'external scripts missing sri',
      severity,
      status: 'SUSPICIOUS',
      reason: `${count} external third-party script(s) loaded without Subresource Integrity (SRI) integrity="sha..." attribute.`
    });
  }

  if (found.length === 0) {
    return { name: 'supply chain & sri', status: 'SAFE', severity: 'NONE' };
  }

  const maxSev = found.some(f => f.severity === 'CRITICAL') ? 'CRITICAL'
               : found.some(f => f.severity === 'HIGH')     ? 'HIGH'
               : found.some(f => f.severity === 'MEDIUM')   ? 'MEDIUM'
               : 'LOW';

  const evidenceQuotes = [
    ...compromisedScripts.map(s => `Compromised CDN script: ${s}`),
    ...missingSriScripts.slice(0, 3).map(s => `Script without SRI: ${s}`)
  ].filter(q => q.length >= 8).slice(0, 5);

  return {
    name    : 'supply chain & sri',
    status  : found.some(f => f.status === 'VULNERABLE') ? 'VULNERABLE' : 'SUSPICIOUS',
    severity: maxSev,
    path    : '/',
    detail  : found.map(f => f.reason).join(' '),
    findings: found.map(f => ({ name: f.name, severity: f.severity, reason: f.reason })),
    ...(evidenceQuotes.length > 0 ? { evidenceQuotes } : {}),
    ...(res?.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
    fix     : 'Remove any scripts referencing compromised CDN domains (polyfill.io, bootcss.com, bootcdn.net, staticfile.org). For all external third-party scripts, enforce Subresource Integrity (SRI) using integrity="sha384-..." and crossorigin="anonymous".'
  };
}
