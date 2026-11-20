import { redactSecretsInText } from '../core/ai-advisor.js';
import {
  isHtmlOrScript,
  isRedirectedToDifferentPath,
  isFrameworkRouteErrorResponse,
  extractVerbatimSnippet,
  confirmReproducible
} from '../core/check-verify.js';

export const tags = ['php', 'laravel', 'wordpress', 'drupal', 'magento', 'symfony', 'codeigniter', 'joomla'];

const CONFIG_FILES = [
  { path: '/config.php',                      type: 'php', severity: 'HIGH' },
  { path: '/configuration.php',               type: 'php', severity: 'HIGH' },
  { path: '/config/database.php',             type: 'php', severity: 'HIGH' },
  { path: '/includes/config.php',             type: 'php', severity: 'HIGH' },
  { path: '/include/config.php',              type: 'php', severity: 'HIGH' },
  { path: '/db.php',                          type: 'php', severity: 'HIGH' },
  { path: '/app/config/parameters.yml',       type: 'yaml', severity: 'CRITICAL', note: 'Symfony parameters file — contains DB credentials and app secret', keys: ['database_host:', 'database_password:', 'secret:'] },
  { path: '/config/packages/doctrine.yaml',   type: 'yaml', severity: 'MEDIUM', keys: ['doctrine:', 'dbal:'] },
  { path: '/app/etc/local.xml',               type: 'xml', severity: 'CRITICAL', note: 'Magento 1 config — DB credentials in plaintext XML', keys: ['<connection>', '<password>'] },
  { path: '/app/etc/env.php',                 type: 'php', severity: 'CRITICAL', note: 'Magento 2 config — credentials and encryption key' },
  { path: '/sites/default/settings.php',      type: 'php', severity: 'HIGH' },
  { path: '/config/app.php',                  type: 'php', severity: 'HIGH' },
  { path: '/application/config/database.php', type: 'php', severity: 'HIGH' },
];

function validateConfigResponse(file, res, reqUrl) {
  if (res?.status !== 200 || (reqUrl && isRedirectedToDifferentPath(res, reqUrl))) return null;
  const text = typeof res.text === 'string' ? res.text : '';
  if (!text || isHtmlOrScript(res, text) || isFrameworkRouteErrorResponse(res, text)) return null;

  if (file.type === 'php') {
    if (text.includes('<?php') && /password|secret|db_|database|\$db|\$databases|crypt/i.test(text)) {
      return 'PHP source configuration array';
    }
    return null;
  }
  if (file.type === 'yaml') {
    const matched = file.keys.filter(k => text.includes(k));
    return matched.length >= 2 ? `YAML keys (${matched.join(', ')})` : null;
  }
  if (file.type === 'xml') {
    return file.keys.every(k => text.includes(k)) ? 'XML <connection><password> config' : null;
  }
  return null;
}

export default async function run(target, fetchWithRetry) {
  const found = [];

  for (const file of CONFIG_FILES) {
    try {
      const url = `${target}${file.path}`;
      const res = await fetchWithRetry(url, { followRedirects: false });
      const signal = validateConfigResponse(file, res, url);
      if (!signal) continue;

      const { confirmed, res: cRes } = await confirmReproducible(
        url,
        fetchWithRetry,
        { followRedirects: false },
        (r) => Boolean(validateConfigResponse(file, r, url))
      );
      if (!confirmed) continue;

      const finalRes = cRes || res;
      const preview = redactSecretsInText(
        extractVerbatimSnippet(finalRes.text || res.text || '', /<\?php|database_password:|database_host:|<connection>|doctrine:/i) || signal
      );
      found.push({
        path         : file.path,
        url,
        method       : 'GET',
        status       : 200,
        severity     : file.severity,
        matchedSignal: signal,
        reproducible : true,
        preview,
        detail       : file.note ?? 'Config file with credentials exposed as source text',
        ...(finalRes?.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {})
      });
    } catch { /* path unreachable */ }
  }

  if (!found.length) {
    return { name: 'php config exposure', status: 'SAFE', severity: 'NONE' };
  }

  const maxSev = found.some(f => f.severity === 'CRITICAL') ? 'CRITICAL' : 'HIGH';
  const primary = found[0];
  const evidenceQuotes = found.map(f => f.preview).filter(q => typeof q === 'string' && q.length >= 8).slice(0, 5);

  return {
    name          : 'php config exposure',
    status        : 'VULNERABLE',
    severity      : maxSev,
    path          : primary.path,
    files         : found,
    detail        : `Confirmed ${found.length} exposed config file(s): ${found.map(f => f.path).join(', ')}`,
    reproVerified : true,
    poeLevel      : evidenceQuotes.length > 0 ? 3 : 2,
    ...(evidenceQuotes.length > 0 ? { evidenceQuotes } : {}),
    ...(primary.trafficId !== undefined ? { trafficId: primary.trafficId } : {}),
    fix           : 'IMMEDIATELY move configuration files out of the web root or deny all public access via server configuration. Rotate all database passwords and API keys found in these files.'
  };
}
