import { redactSecretsInText } from '../core/ai-advisor.js';
import { isHtmlOrScript, isRedirectedToDifferentPath, confirmReproducible } from '../core/check-verify.js';

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

const CANARY_DOTFILE_PATH = '/.secscan_dotfile_probe';

// Patterns that strongly indicate a real .env assignment with a value
const SENSITIVE = ['APP_KEY', 'DB_PASSWORD', 'DB_HOST', 'DB_USERNAME', 'SECRET_KEY', 'AWS_SECRET'];
const ENV_ASSIGNMENT_RE = /^\s*(?:APP_KEY|DB_PASSWORD|DB_HOST|DB_USERNAME|SECRET_KEY|AWS_SECRET[A-Z0-9_]*)\s*=\s*\S+/m;

function isPlaceholderExampleOnly(pathStr, text) {
  if (pathStr !== '/.env.example') return false;
  const lines = String(text || '').split(/\r?\n/);
  const assignments = lines.filter(l => ENV_ASSIGNMENT_RE.test(l));
  if (assignments.length === 0) return true;
  return assignments.every(line => {
    const val = line.slice(line.indexOf('=') + 1).trim().replace(/^['"]|['"]$/g, '').toLowerCase();
    return !val || /^(?:null|false|example|changeme|your[_-]|secret_?here|<.+>|\*+)$/.test(val);
  });
}

export default async function run(target, fetchWithRetry) {
  let fetchErrors = 0;
  let blanketDotfile403Checked = false;
  let isBlanketDotfile403 = false;
  const fetchOpts = { followRedirects: false };

  for (const p of PATHS) {
    try {
      const targetUrl = `${target}${p}`;
      const res = await fetchWithRetry(targetUrl, fetchOpts);
      if (isRedirectedToDifferentPath(res, targetUrl)) continue;

      // A consistent 403 on a sensitive path indicates access control on an explicit route/file
      // only if a random non-existent dotfile does NOT also return 403 via a blanket dotfile deny rule.
      if (res.status === 403) {
        if (!blanketDotfile403Checked) {
          blanketDotfile403Checked = true;
          try {
            const canaryRes = await fetchWithRetry(`${target}${CANARY_DOTFILE_PATH}`, fetchOpts);
            isBlanketDotfile403 = canaryRes?.status === 403;
          } catch {
            isBlanketDotfile403 = false;
          }
        }
        if (isBlanketDotfile403) {
          continue;
        }

        const { confirmed, res: confirmRes } = await confirmReproducible(
          targetUrl,
          fetchWithRetry,
          fetchOpts,
          (r) => r?.status === 403 && !isRedirectedToDifferentPath(r, targetUrl)
        );
        if (!confirmed) continue;

        const trafficId = confirmRes?.trafficId ?? res?.trafficId;
        const quote = `HTTP 403 Forbidden on ${p}`;
        return {
          name          : 'env file exposure',
          status        : 'SUSPICIOUS',
          severity      : 'MEDIUM',
          path          : p,
          observedStatus: 403,
          detail        : `Path ${p} consistently returned HTTP 403 Forbidden while non-existent dotfiles return 404 (verify the .env file is moved outside the public web root)`,
          files         : [{
            path         : p,
            url          : targetUrl,
            method       : 'GET',
            status       : 403,
            matchedSignal: 'HTTP 403 Forbidden',
            reproducible : true,
            preview      : quote
          }],
          evidenceQuotes: [quote],
          poeLevel      : 2,
          reproVerified : true,
          ...(trafficId !== undefined ? { trafficId } : {}),
          fix           : 'Ensure the .env file is moved out of the web root or permanently blocked in the web server configuration.'
        };
      }

      const text = typeof res?.text === 'string' ? res.text : '';
      const matchedKey = SENSITIVE.find(k => text.includes(k));
      if (
        res.status === 200 &&
        text &&
        !isHtmlOrScript(res, text) &&
        ENV_ASSIGNMENT_RE.test(text) &&
        matchedKey &&
        !isPlaceholderExampleOnly(p, text)
      ) {
        // Confirm reproducibility before marking CRITICAL VULNERABLE
        const { confirmed, res: confirmRes } = await confirmReproducible(
          targetUrl,
          fetchWithRetry,
          fetchOpts,
          (r) => {
            const cText = typeof r?.text === 'string' ? r.text : '';
            return (
              r?.status === 200 &&
              !isRedirectedToDifferentPath(r, targetUrl) &&
              Boolean(cText) &&
              !isHtmlOrScript(r, cText) &&
              ENV_ASSIGNMENT_RE.test(cText)
            );
          }
        );
        if (!confirmed) continue;

        const matchLine = text.match(ENV_ASSIGNMENT_RE)?.[0] || matchedKey;
        const safeQuote = redactSecretsInText(matchLine.replace(/[\r\n\t]+/g, ' ').trim().slice(0, 120));
        const trafficId = confirmRes?.trafficId ?? res?.trafficId;
        return {
          name          : 'env file exposure',
          status        : 'VULNERABLE',
          severity      : 'CRITICAL',
          path          : p,
          observedStatus: 200,
          detail        : `Confirmed reproducible .env exposure at ${p} (HTTP 200, matched ${matchedKey}=<redacted>)`,
          files         : [{
            path         : p,
            url          : targetUrl,
            method       : 'GET',
            status       : 200,
            matchedSignal: `${matchedKey}=<redacted>`,
            reproducible : true,
            preview      : safeQuote
          }],
          reproVerified : true,
          poeLevel      : safeQuote.length >= 8 ? 3 : 2,
          ...(safeQuote.length >= 8 ? { evidenceQuotes: [safeQuote] } : {}),
          ...(trafficId !== undefined ? { trafficId } : {}),
          fix           : 'CRITICAL: Move the .env file out of the web root IMMEDIATELY and rotate all exposed credentials (DB passwords, APP_KEY, etc.).'
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