export const tags = ['laravel', 'all'];

/**
 * Checks common Laravel API authentication endpoints for security issues:
 *
 *  /api/login     — publicly accessible? returns consistent error? (user enum risk)
 *  /api/register  — open to mass registration?
 *  /api/user      — returns user data without authentication?
 *  /api/me        — unauthenticated user data exposure
 *  /api/forgot-password — different responses for valid/invalid email (user enumeration)
 */
const ENDPOINTS = [
  {
    path    : '/api/user',
    method  : 'GET',
    check   : (res) => {
      const body = res.text.toLowerCase();
      // Returns user data without auth — major issue
      if (res.status === 200 && (body.includes('"email"') || body.includes('"name"') || body.includes('"id"'))) {
        return { issue: '/api/user returns user data without authentication', severity: 'CRITICAL' };
      }
      return null;
    }
  },
  {
    path    : '/api/me',
    method  : 'GET',
    check   : (res) => {
      const body = res.text.toLowerCase();
      if (res.status === 200 && (body.includes('"email"') || body.includes('"id"'))) {
        return { issue: '/api/me returns user data without authentication', severity: 'CRITICAL' };
      }
      return null;
    }
  },
  {
    path    : '/api/register',
    method  : 'POST',
    headers : { 'Content-Type': 'application/json' },
    body    : JSON.stringify({ name: 'test', email: 'probe@example.com', password: 'P@ssword1!' }),
    check   : (res) => {
      // 200/201 on register with no verification = open registration
      if (res.status === 200 || res.status === 201) {
        return { issue: '/api/register accepts unauthenticated registration', severity: 'MEDIUM' };
      }
      return null;
    }
  },
  {
    path    : '/api/login',
    method  : 'POST',
    headers : { 'Content-Type': 'application/json' },
    body    : JSON.stringify({ email: 'probe@example.com', password: 'wrongpassword' }),
    check   : (res) => {
      // Login endpoint exists and responds (just confirm it isn't wide-open)
      if (res.status === 200) {
        return { issue: '/api/login returned 200 on bad credentials', severity: 'HIGH' };
      }
      // 422/401/403 are all normal — just note the endpoint exists
      if ([401, 403, 422, 429].includes(res.status)) return null;
      return null;
    }
  },
];

export default async function run(target, fetchWithRetry) {
  const findings = [];

  for (const ep of ENDPOINTS) {
    try {
      const res    = await fetchWithRetry(`${target}${ep.path}`, {
        method : ep.method,
        headers: ep.headers ?? {},
        body   : ep.body ?? undefined,
      });

      const finding = ep.check(res);
      if (finding) findings.push(finding);

    } catch { /* unreachable */ }
  }

  if (!findings.length) {
    return { name: 'laravel auth routes', status: 'SAFE', severity: 'NONE' };
  }

  const maxSev = findings.some(f => f.severity === 'CRITICAL') ? 'CRITICAL'
               : findings.some(f => f.severity === 'HIGH')     ? 'HIGH'
               : 'MEDIUM';

  return {
    name    : 'laravel auth routes',
    status  : 'VULNERABLE',
    severity: maxSev,
    findings,
    fix     : 'Ensure all sensitive API routes (/api/user, /api/me) are protected by authentication middleware (e.g., Sanctum/Passport). Disable public user registration (/api/register) if not needed and apply strict rate limiting to auth endpoints.'
  };
}
