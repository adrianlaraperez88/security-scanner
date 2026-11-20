import { Fuzzer } from '../core/fuzzer.js';

export const tags = ['all'];

export default async function run(target, fetchWithRetry, options = {}) {
  const fuzzer = new Fuzzer(fetchWithRetry);
  const payload = `<script>alert('xss-probe-${Math.random().toString(36).substring(7)}')</script>`;

  let detail;
  try {
    detail = await fuzzer.fuzzDetailed(target, payload, 'XSS_REFLECTED', options);
  } catch (err) {
    return {
      name: 'reflected xss',
      status: 'ERROR',
      severity: 'NONE',
      reason: err?.message || 'Invalid target URL'
    };
  }

  if (detail.governanceError) {
    return {
      name: 'reflected xss',
      status: 'ERROR',
      severity: 'NONE',
      reason: detail.governanceError.message || 'Blocked by governance policy'
    };
  }

  const findings = detail.findings;

  if (findings.length === 0) {
    if (detail.attempted > 0 && !detail.networkSuccess) {
      return {
        name: 'reflected xss',
        status: 'ERROR',
        severity: 'NONE',
        reason: detail.lastError?.message || 'Target unreachable'
      };
    }
    return { name: 'reflected xss', status: 'SAFE', severity: 'NONE' };
  }

  return {
    name    : 'reflected xss',
    status  : 'VULNERABLE',
    severity: 'HIGH',
    detail  : `${findings.length} parameter(s) vulnerable`,
    findings: findings.map(f => ({ parameter: f.parameter, url: f.url })),
    fix     : 'Always HTML-encode user input before rendering it in the browser. Use modern templating engines with auto-escaping (like Blade, Twig, or EJS) and implement a robust Content-Security-Policy (CSP).'
  };
}
