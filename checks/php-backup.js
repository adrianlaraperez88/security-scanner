import { redactSecretsInText } from '../core/ai-advisor.js';
import {
  isHtmlOrScript,
  isRedirectedToDifferentPath,
  isFrameworkRouteErrorResponse,
  extractVerbatimSnippet,
  confirmReproducible
} from '../core/check-verify.js';

export const tags = ['php', 'laravel', 'wordpress', 'drupal', 'magento', 'symfony', 'codeigniter', 'joomla'];

const BACKUP_FILES = [
  { path: '/index.php.bak',         type: 'php', signals: ['<?php'] },
  { path: '/index.php.old',         type: 'php', signals: ['<?php'] },
  { path: '/index.php~',            type: 'php', signals: ['<?php'] },
  { path: '/config.php.bak',        type: 'php', signals: ['<?php', 'DB_'] },
  { path: '/config.php.old',        type: 'php', signals: ['<?php', 'DB_'] },
  { path: '/config.php~',           type: 'php', signals: ['<?php', 'DB_'] },
  { path: '/configuration.php.bak', type: 'php', signals: ['<?php', 'JConfig'] },
  { path: '/database.php.bak',      type: 'php', signals: ['<?php'] },
  { path: '/.env.bak',              type: 'env' },
  { path: '/.env.old',              type: 'env' },
  { path: '/.env~',                 type: 'env' },
  { path: '/wp-config.php.bak',     type: 'php', signals: ['<?php', 'DB_NAME', 'DB_PASSWORD'] },
  { path: '/settings.php.bak',      type: 'php', signals: ['<?php', '$databases'] },
  { path: '/app.php.bak',           type: 'php', signals: ['<?php'] },
];

const ENV_ASSIGN_RE = /^\s*(?:APP_KEY|DB_PASSWORD|DB_HOST|DB_USERNAME|SECRET_KEY|AWS_SECRET[A-Z0-9_]*)\s*=\s*\S+/m;

function validateBackupResponse(file, res, reqUrl) {
  if (res?.status !== 200 || (reqUrl && isRedirectedToDifferentPath(res, reqUrl))) return null;
  const text = typeof res.text === 'string' ? res.text : '';
  if (!text || isHtmlOrScript(res, text) || isFrameworkRouteErrorResponse(res, text)) return null;

  if (file.type === 'env') {
    const m = ENV_ASSIGN_RE.exec(text);
    return m ? `Env assignment (${m[0].split('=')[0].trim()})` : null;
  }

  if (text.includes('<?php') || text.includes('<?=')) {
    const hit = file.signals.find(s => text.includes(s)) || '<?php';
    return `PHP source code (${hit})`;
  }
  return null;
}

export default async function run(target, fetchWithRetry) {
  const found = [];

  for (const file of BACKUP_FILES) {
    try {
      const url = `${target}${file.path}`;
      const res = await fetchWithRetry(url, { followRedirects: false });
      const signal = validateBackupResponse(file, res, url);
      if (!signal) continue;

      const { confirmed, res: cRes } = await confirmReproducible(
        url,
        fetchWithRetry,
        { followRedirects: false },
        (r) => Boolean(validateBackupResponse(file, r, url))
      );
      if (!confirmed) continue;

      const finalRes = cRes || res;
      const preview = redactSecretsInText(
        extractVerbatimSnippet(finalRes.text || res.text || '', file.type === 'env' ? ENV_ASSIGN_RE : '<?php') || signal
      );
      found.push({
        path         : file.path,
        url,
        method       : 'GET',
        status       : 200,
        severity     : 'HIGH',
        matchedSignal: signal,
        reproducible : true,
        preview,
        detail       : 'Backup file served as plaintext — exposes PHP source or credentials',
        ...(finalRes?.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {})
      });
    } catch { /* path unreachable */ }
  }

  if (!found.length) {
    return { name: 'php backup files', status: 'SAFE', severity: 'NONE' };
  }

  const primary = found[0];
  const evidenceQuotes = found.map(f => f.preview).filter(q => typeof q === 'string' && q.length >= 8).slice(0, 5);

  return {
    name          : 'php backup files',
    status        : 'VULNERABLE',
    severity      : 'HIGH',
    path          : primary.path,
    files         : found,
    detail        : `Confirmed ${found.length} plaintext backup file(s): ${found.map(f => f.path).join(', ')}`,
    reproVerified : true,
    poeLevel      : evidenceQuotes.length > 0 ? 3 : 2,
    ...(evidenceQuotes.length > 0 ? { evidenceQuotes } : {}),
    ...(primary.trafficId !== undefined ? { trafficId: primary.trafficId } : {}),
    fix           : 'Remove all backup files (.bak, .old, ~, .swp) from the web server and ensure your deployment process excludes these artifacts from production.'
  };
}
