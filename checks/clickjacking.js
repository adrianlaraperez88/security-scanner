import { URL } from 'node:url';
import { getHeader, confirmReproducible } from '../core/check-verify.js';

export const tags = ['all'];

function analyzeHeaders(headers) {
  const xfo = getHeader(headers, 'x-frame-options').toLowerCase().trim();
  const csp = getHeader(headers, 'content-security-policy').toLowerCase();

  const hasXfo = xfo === 'deny' || xfo === 'sameorigin';
  const xfoAllowFrom = xfo.startsWith('allow-from');
  const hasCspFrameAnc = csp.includes('frame-ancestors');
  const issues = [];

  if (!hasXfo && !hasCspFrameAnc) {
    issues.push({ issue: 'No X-Frame-Options or CSP frame-ancestors — iframe embedding possible', severity: 'MEDIUM' });
  } else if (xfoAllowFrom) {
    issues.push({ issue: 'X-Frame-Options: ALLOW-FROM is deprecated and ignored by most browsers', severity: 'LOW' });
  }

  if (hasXfo && !hasCspFrameAnc) {
    issues.push({ issue: 'X-Frame-Options set but no CSP frame-ancestors — modern browsers may ignore XFO', severity: 'LOW' });
  }

  return { issues, xfo, csp };
}

export default async function run(target, fetchWithRetry) {
  try {
    const res = await fetchWithRetry(target);
    const { issues, xfo } = analyzeHeaders(res?.headers);

    if (issues.length === 0) {
      return { name: 'clickjacking protection', status: 'SAFE', severity: 'NONE' };
    }

    const { confirmed, res: cRes } = await confirmReproducible(
      target,
      fetchWithRetry,
      {},
      (r) => analyzeHeaders(r?.headers).issues.length > 0
    );
    if (!confirmed) {
      return { name: 'clickjacking protection', status: 'SAFE', severity: 'NONE' };
    }

    let reqPath = '/';
    try {
      const u = new URL(target);
      reqPath = `${u.pathname || '/'}${u.search || ''}`;
    } catch { /* keep '/' */ }

    const finalRes = cRes || res;
    const status = finalRes?.status ?? 200;
    const maxSev = issues.some(i => i.severity === 'MEDIUM') ? 'MEDIUM' : 'LOW';
    const quote = `HTTP ${status} on ${reqPath}: ${issues[0].issue} (XFO=${xfo || 'missing'})`;

    return {
      name          : 'clickjacking protection',
      status        : 'SUSPICIOUS',
      severity      : maxSev,
      path          : reqPath,
      observedStatus: status,
      issues,
      detail        : issues.map(i => i.issue).join('; '),
      reproVerified : true,
      poeLevel      : 3,
      evidenceQuotes: [quote],
      ...(finalRes?.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {}),
      fix           : "Add 'X-Frame-Options: DENY' (or SAMEORIGIN) and 'Content-Security-Policy: frame-ancestors none' (or 'self') headers to prevent unauthorized embedding in iframes."
    };

  } catch (e) {
    return { name: 'clickjacking protection', status: 'ERROR', severity: 'LOW', reason: e.message };
  }
}
