export const tags = ['php', 'all'];

/**
 * Passive Local File Inclusion (LFI) probe.
 *
 * Appends path traversal payloads to common query parameters and checks
 * whether /etc/passwd (Linux) or win.ini (Windows) is returned in the response.
 *
 * This is PASSIVE detection only — we read existing parameters, we never
 * upload files, modify data, or execute code.
 *
 * Common in PHP apps that use include()/require() with user-supplied input:
 *   include($_GET['page'] . '.php');
 *   require($_GET['file']);
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

export default async function run(target, fetchWithRetry) {
  for (const param of PARAMS) {
    for (const payload of PAYLOADS) {
      const testUrl = `${target}?${param}=${encodeURIComponent(payload)}`;

      try {
        const res  = await fetchWithRetry(testUrl);
        const body = res.text;

        if (body.includes(LINUX_SIGNAL)) {
          return {
            name    : 'local file inclusion (LFI)',
            status  : 'VULNERABLE',
            severity: 'CRITICAL',
            detail  : `/etc/passwd content returned via ?${param}=${payload}`,
            fix     : 'CRITICAL: Sanitize all user input used in file operations. Use a whitelist of allowed files and avoid passing user-supplied variables directly to include() or require() functions.',
            param,
            payload
          };
        }

        if (body.includes(WINDOWS_SIGNAL)) {
          return {
            name    : 'local file inclusion (LFI)',
            status  : 'VULNERABLE',
            severity: 'CRITICAL',
            detail  : `win.ini content returned via ?${param}=${payload}`,
            fix     : 'CRITICAL: Sanitize all user input used in file operations. Use a whitelist of allowed files and avoid passing user-supplied variables directly to include() or require() functions.',
            param,
            payload
          };
        }

      } catch { /* fetch failed — skip this combination */ }
    }
  }

  return { name: 'local file inclusion (LFI)', status: 'SAFE', severity: 'NONE' };
}
