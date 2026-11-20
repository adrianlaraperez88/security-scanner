import { extractVerbatimSnippet, confirmReproducible } from '../core/check-verify.js';

export const tags = ['php', 'laravel', 'wordpress', 'drupal', 'magento', 'symfony', 'codeigniter', 'joomla'];

// Patterns requiring PHP runtime error context rather than generic prose words like "warning:" or "stack trace"
const PHP_ERROR_PATTERNS = [
  { label: 'fatal error', re: /\b(?:fatal error|uncaught\s+(?:error|exception|[a-z0-9_\\]+exception)):\s+[^\r\n<]{3,200}/i },
  { label: 'warning:', re: /\b(?:php\s+)?warning:\s+[^\r\n<]{3,200}\s+in\s+[^\r\n<]+\.php(?:\s+on\s+line\s+\d+|\b)/i },
  { label: 'parse error', re: /\b(?:php\s+)?parse error:\s+[^\r\n<]{3,200}/i },
  { label: 'undefined index', re: /\b(?:undefined\s+(?:index|variable|array key|offset)|call to undefined function)\b/i },
  { label: 'stack trace', re: /(?:stack trace:\s*#0\s+[^\r\n<]+|class=["']xdebug-error\b)/i }
];

function matchPhpErrors(rawText) {
  if (typeof rawText !== 'string' || !rawText) return [];
  return PHP_ERROR_PATTERNS.filter(p => p.re.test(rawText));
}

export default async function run(target, fetchWithRetry) {
  try {
    const res = await fetchWithRetry(target);
    const rawText = typeof res?.text === 'string' ? res.text : '';
    const hits = matchPhpErrors(rawText);

    if (hits.length === 0) {
      return { name: 'php error exposure', status: 'SAFE', severity: 'NONE' };
    }

    const { confirmed, res: confirmRes } = await confirmReproducible(
      target,
      fetchWithRetry,
      {},
      (r) => matchPhpErrors(r?.text).length > 0
    );
    if (!confirmed) {
      return { name: 'php error exposure', status: 'SAFE', severity: 'NONE' };
    }

    const finalRes = confirmRes || res;
    const finalText = typeof finalRes?.text === 'string' ? finalRes.text : rawText;
    const primary = hits[0];
    const snippet = extractVerbatimSnippet(finalText, primary.re) || primary.label;
    let path = '/';
    try {
      const u = new URL(target);
      path = `${u.pathname || '/'}${u.search || ''}`;
    } catch { /* default / */ }

    return {
      name          : 'php error exposure',
      status        : 'SUSPICIOUS',
      severity      : hits.length > 2 ? 'MEDIUM' : 'LOW',
      path,
      url           : target,
      detail        : `PHP runtime error output detected on ${path} (${hits.map(h => h.label).join(', ')})`,
      files         : [{
        path,
        url          : target,
        method       : 'GET',
        status       : finalRes?.status ?? 200,
        matchedSignal: primary.label,
        reproducible : true,
        preview      : snippet
      }],
      reproVerified : true,
      poeLevel      : snippet.length >= 8 ? 3 : 2,
      ...(snippet.length >= 8 ? { evidenceQuotes: [snippet] } : {}),
      ...(finalRes?.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {}),
      fix           : "Disable error display in production by setting 'display_errors = Off' and 'log_errors = On' in your php.ini or application config."
    };

  } catch (e) {
    return {
      name: 'php error exposure',
      status: 'ERROR',
      severity: 'LOW',
      reason: e?.message || 'Target unreachable'
    };
  }
}