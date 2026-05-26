export const tags = ['wordpress'];

/**
 * WordPress-specific checks:
 *  1. xmlrpc.php  — if enabled, allows brute-force amplification and DDoS
 *  2. User enumeration — /wp-json/wp/v2/users leaks usernames
 *  3. wp-login.php — check if the admin login page is publicly accessible
 */
export default async function run(target, fetchWithRetry) {
  const findings = [];

  // ── 1. xmlrpc.php ─────────────────────────────────────────────────────────
  try {
    const res = await fetchWithRetry(`${target}/xmlrpc.php`, {
      method  : 'POST',
      headers : { 'Content-Type': 'text/xml' },
      body    : '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params/></methodCall>'
    });

    if (res.status === 200 && res.text.includes('<methodResponse>')) {
      findings.push({ issue: 'xmlrpc.php enabled (brute-force amplification)', severity: 'MEDIUM' });
    }
  } catch { /* unreachable */ }

  // ── 2. User enumeration via REST API ──────────────────────────────────────
  try {
    const res = await fetchWithRetry(`${target}/wp-json/wp/v2/users`);

    if (res.status === 200 && res.text.includes('"slug"')) {
      findings.push({ issue: 'User enumeration via /wp-json/wp/v2/users', severity: 'MEDIUM' });
    }
  } catch { /* unreachable */ }

  // ── 3. wp-login.php publicly accessible ───────────────────────────────────
  try {
    const res  = await fetchWithRetry(`${target}/wp-login.php`);
    const html = res.text.toLowerCase();

    if (res.status === 200 && (html.includes('log in') || html.includes('login'))) {
      findings.push({ issue: 'wp-login.php is publicly accessible', severity: 'LOW' });
    }
  } catch { /* unreachable */ }

  if (findings.length === 0) {
    return { name: 'wordpress checks', status: 'SAFE', severity: 'NONE' };
  }

  const maxSev = findings.some(f => f.severity === 'HIGH')   ? 'HIGH'
               : findings.some(f => f.severity === 'MEDIUM') ? 'MEDIUM'
               : 'LOW';

  return {
    name     : 'wordpress checks',
    status   : 'VULNERABLE',
    severity : maxSev,
    findings,
    fix      : "Disable XML-RPC by adding 'add_filter(\"xmlrpc_enabled\", \"__return_false\");' to functions.php. Restrict the REST API users endpoint and protect 'wp-login.php' with IP whitelisting or a security plugin."
  };
}
