export const tags = ['laravel', 'php', 'all'];

const PATHS = [
  '/.env',
  '/.env.backup',
  '/.env.dev',
  '/.env.prod',
  '/.env.local',
  '/.env.example',
  '/.env.staging',
];

// Patterns that strongly indicate a real .env file (not a redirect page)
const SENSITIVE = ['APP_KEY', 'DB_PASSWORD', 'DB_HOST', 'DB_USERNAME', 'SECRET_KEY', 'AWS_SECRET'];

export default async function run(target, fetchWithRetry) {
  let fetchErrors = 0;

  for (const p of PATHS) {
    try {
      const res = await fetchWithRetry(`${target}${p}`);

      // A 403 on a sensitive path is worth flagging as suspicious
      if (res.status === 403) {
        return {
          name     : 'env file exposure',
          status   : 'SUSPICIOUS',
          severity : 'MEDIUM',
          path     : p,
          detail   : 'Path exists but access is forbidden (403)',
          fix      : 'Ensure the .env file is moved out of the web root or permanently blocked in the web server configuration.'
        };
      }

      if (res.status === 200 && SENSITIVE.some(k => res.text.includes(k))) {
        return {
          name     : 'env file exposure',
          status   : 'VULNERABLE',
          severity : 'CRITICAL',
          path     : p,
          fix      : 'CRITICAL: Move the .env file out of the web root IMMEDIATELY and rotate all exposed credentials (DB passwords, APP_KEY, etc.).'
        };
      }

    } catch {
      fetchErrors++;
    }
  }

  if (fetchErrors === PATHS.length) {
    return { name: 'env file exposure', status: 'ERROR', severity: 'LOW', reason: 'All paths unreachable' };
  }

  return { name: 'env file exposure', status: 'SAFE', severity: 'NONE' };
}