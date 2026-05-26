import { Fuzzer } from '../core/fuzzer.js';

export const tags = ['all'];

export default async function run(target, fetchWithRetry) {
  const fuzzer = new Fuzzer(fetchWithRetry);
  const payload = `<script>alert('xss-probe-${Math.random().toString(36).substring(7)}')</script>`;
  
  const findings = await fuzzer.fuzz(target, payload, 'XSS_REFLECTED');

  if (findings.length === 0) {
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
