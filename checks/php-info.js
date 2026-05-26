export const tags = ['php', 'all'];

const PATHS = [
  '/phpinfo.php',
  '/info.php',
  '/test.php',
  '/php.php',
  '/phptest.php',
];

export default async function run(target, fetchWithRetry) {
  let fetchErrors = 0;

  for (const p of PATHS) {
    try {
      const res  = await fetchWithRetry(`${target}${p}`);
      const html = res.text.toLowerCase();

      if (res.status === 200 && html.includes('php version') && html.includes('configuration')) {
        return {
          name     : 'php info exposure',
          status   : 'VULNERABLE',
          severity : 'HIGH',
          path     : p,
          fix      : "Delete any files that call 'phpinfo()' from your production server, as they leak detailed environment and configuration data."
        };
      }

    } catch {
      fetchErrors++;
    }
  }

  if (fetchErrors === PATHS.length) {
    return { name: 'php info exposure', status: 'ERROR', severity: 'LOW', reason: 'All paths unreachable' };
  }

  return { name: 'php info exposure', status: 'SAFE', severity: 'NONE' };
}