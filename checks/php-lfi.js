import {
  isRedirectedToDifferentPath,
  isFrameworkRouteErrorResponse,
  extractVerbatimSnippet,
  confirmReproducible
} from '../core/check-verify.js';

export const tags = ['php', 'laravel', 'wordpress', 'drupal', 'magento', 'symfony', 'codeigniter', 'joomla'];

/**
 * Passive Local File Inclusion (LFI) probe.
 *
 * Appends path traversal payloads to common query parameters and checks
 * whether /etc/passwd (Linux) or win.ini (Windows) is returned in the response.
 */
const PARAMS = [
  'page', 'file', 'include', 'path', 'template',
  'load', 'view', 'doc', 'document', 'name', 'pg', 'p'
];

const PAYLOADS = [
  '../../../../../../etc/passwd',
  '../../../../etc/passwd',
  '/etc/passwd',
  '../../../../../../windows/win.ini',
];

// Confirmation signals
const LINUX_SIGNAL   = 'root:x:0:0:';
const WINDOWS_SIGNAL = '[extensions]';

function buildLfiProbeUrl(target, param, payload) {
  const encoded = encodeURIComponent(payload);
  try {
    const u = new URL(target);
    const sep = u.search ? '&' : '?';
    const nextSearch = `${u.search || ''}${sep}${param}=${encoded}`;
    u.search = nextSearch;
    return { testUrl: u.href, path: `${u.pathname || '/'}${u.search}` };
  } catch {
    const sep = String(target).includes('?') ? '&' : '?';
    const testUrl = `${target}${sep}${param}=${encoded}`;
    return { testUrl, path: `${sep}${param}=${encoded}` };
  }
}

export default async function run(target, fetchWithRetry) {
  let baselineText = '';
  try {
    const baseRes = await fetchWithRetry(target);
    baselineText = typeof baseRes?.text === 'string' ? baseRes.text : '';
  } catch { /* baseline best-effort */ }

  for (const param of PARAMS) {
    for (const payload of PAYLOADS) {
      const { testUrl, path } = buildLfiProbeUrl(target, param, payload);

      try {
        const res  = await fetchWithRetry(testUrl);
        if (res?.status !== 200 || isRedirectedToDifferentPath(res, testUrl) || isFrameworkRouteErrorResponse(res, res?.text)) {
          continue;
        }
        const body = typeof res?.text === 'string' ? res.text : '';

        const matchedLinux = body.includes(LINUX_SIGNAL) && !baselineText.includes(LINUX_SIGNAL);
        const matchedWin = body.includes(WINDOWS_SIGNAL) && !baselineText.includes(WINDOWS_SIGNAL);
        if (!matchedLinux && !matchedWin) continue;

        const signal = matchedLinux ? LINUX_SIGNAL : WINDOWS_SIGNAL;
        const fileLabel = matchedLinux ? '/etc/passwd' : 'win.ini';

        const { confirmed, res: confirmRes } = await confirmReproducible(
          testUrl,
          fetchWithRetry,
          {},
          (r) => typeof r?.text === 'string' && r.text.includes(signal)
        );
        if (!confirmed) continue;

        const finalRes = confirmRes || res;
        const finalBody = typeof finalRes?.text === 'string' ? finalRes.text : body;
        const snippet = extractVerbatimSnippet(finalBody, signal) || signal;
        const trafficId = finalRes?.trafficId ?? res?.trafficId;

        return {
          name          : 'local file inclusion (LFI)',
          status        : 'VULNERABLE',
          severity      : 'CRITICAL',
          path,
          url           : testUrl,
          detail        : `${fileLabel} content returned via ?${param}=${payload}`,
          fix           : 'CRITICAL: Sanitize all user input used in file operations. Use a whitelist of allowed files and avoid passing user-supplied variables directly to include() or require() functions.',
          param,
          payload,
          files         : [{
            path,
            url          : testUrl,
            method       : 'GET',
            status       : finalRes?.status ?? 200,
            matchedSignal: signal,
            reproducible : true,
            preview      : snippet
          }],
          reproVerified : true,
          poeLevel      : snippet.length >= 8 ? 3 : 2,
          ...(snippet.length >= 8 ? { evidenceQuotes: [snippet] } : {}),
          ...(trafficId !== undefined ? { trafficId } : {})
        };

      } catch { /* fetch failed — skip this combination */ }
    }
  }

  return { name: 'local file inclusion (LFI)', status: 'SAFE', severity: 'NONE' };
}
