export const tags = ['react', 'angular', 'vue', 'nextjs', 'all'];

/**
 * Specialized checks for modern frontend frameworks.
 * Frontend apps often leak source code via .map files and 
 * sensitive environment variables via hardcoded constants.
 */
export default async function run(target, fetchWithRetry) {
  const found = [];
  let mainResponse;

  try {
    mainResponse = await fetchWithRetry(target);
  } catch {
    return { name: 'frontend security', status: 'ERROR', severity: 'NONE', reason: 'Target unreachable' };
  }

  const html = mainResponse.text;
  const lowHtml = html.toLowerCase();

  // 1. Source Map Detection
  // Extract external script paths
  const scriptRegex = /<script\b[^>]*src=["']([^"']+\.js)/gi;
  const scriptPaths = [];
  let match;
  while ((match = scriptRegex.exec(html)) !== null) {
    let path = match[1];
    if (path.startsWith('http')) continue; // Skip external CDNs for maps check
    scriptPaths.push(path);
  }

  // Probe for .map files for the first 3 internal scripts (usually main bundles)
  for (const path of scriptPaths.slice(0, 3)) {
    try {
      const mapPath = path.startsWith('/') ? path : `/${path}`;
      const res = await fetchWithRetry(`${target}${mapPath}.map`);
      if (res.status === 200 && res.text.includes('"sources"')) {
        found.push({
          name: 'exposed source maps',
          severity: 'HIGH',
          reason: `A source map was found at ${path}.map, allowing attackers to reconstruct your original source code.`,
          status: 'VULNERABLE'
        });
        break; // One finding is enough
      }
    } catch { /* ignore */ }
  }

  // 2. Development Mode Detection
  if (lowHtml.includes('react devtools') || lowHtml.includes('vue-devtools')) {
    found.push({
      name: 'development build detected',
      severity: 'LOW',
      reason: 'The application appears to be running a development build of React or Vue, which contains extra debugging information.',
      status: 'SUSPICIOUS'
    });
  }

  // 3. Potential Credential Exposure (Shallow scan of HTML)
  const secretPatterns = [
    { name: 'Generic API Key', regex: /api[-_]?key["']?\s*:\s*["'][a-zA-Z0-9_\-]{20,}/gi },
    { name: 'Firebase Project ID', regex: /["']?projectId["']?\s*:\s*["'][a-z0-9\-]{10,}/gi },
  ];

  for (const pattern of secretPatterns) {
    if (pattern.regex.test(html)) {
      found.push({
        name: `potential ${pattern.name.toLowerCase()} exposure`,
        severity: 'MEDIUM',
        reason: `A potential ${pattern.name} was found hardcoded in the root HTML.`,
        status: 'SUSPICIOUS'
      });
    }
  }

  if (found.length === 0) {
    return { name: 'frontend security', status: 'SAFE', severity: 'NONE' };
  }

  const maxSev = found.some(f => f.severity === 'HIGH')   ? 'HIGH'
               : found.some(f => f.severity === 'MEDIUM') ? 'MEDIUM'
               : 'LOW';

  return {
    name    : 'frontend security',
    status  : found.some(f => f.status === 'VULNERABLE') ? 'VULNERABLE' : 'SUSPICIOUS',
    severity: maxSev,
    findings: found.map(f => ({ name: f.name, severity: f.severity, reason: f.reason })),
    fix     : 'Disable source map generation in your production build (e.g., GEN_SOURCE_MAP=false for CRA). Ensure you are using production builds of React/Vue/Angular, and never hardcode secrets in client-side code.'
  };
}
