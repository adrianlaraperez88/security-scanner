import {
  isHtmlOrScript,
  isRedirectedToDifferentPath,
  isFrameworkRouteErrorResponse,
  extractVerbatimSnippet,
  confirmReproducible
} from '../core/check-verify.js';

export const tags = ['magento'];

const CHECKS = [
  {
    path    : '/app/etc/local.xml',
    severity: 'CRITICAL',
    detail  : 'Magento 1 config — DB credentials in plaintext XML',
    validate: (res) => {
      const text = typeof res?.text === 'string' ? res.text : '';
      return !isHtmlOrScript(res, text) && text.includes('<connection>') && (text.includes('<password>') || text.includes('<host>'));
    },
    signalDesc: 'Magento local.xml DB credentials'
  },
  {
    path    : '/app/etc/env.php',
    severity: 'CRITICAL',
    detail  : 'Magento 2 config — credentials and encryption key',
    validate: (res) => {
      const text = typeof res?.text === 'string' ? res.text : '';
      return !isHtmlOrScript(res, text) && text.includes('<?php') && text.includes("'crypt'") && text.includes("'db'");
    },
    signalDesc: 'Magento env.php crypt/db array'
  },
  {
    path    : '/downloader/',
    severity: 'HIGH',
    detail  : 'Magento Connect installer/admin panel accessible',
    validate: (res) => {
      const lower = (typeof res?.text === 'string' ? res.text : '').toLowerCase();
      return lower.includes('magento connect');
    },
    signalDesc: 'Magento Connect panel'
  },
  {
    path    : '/admin/dashboard',
    severity: 'HIGH',
    detail  : 'Magento admin panel accessible at /admin/dashboard',
    validate: (res) => {
      const lower = (typeof res?.text === 'string' ? res.text : '').toLowerCase();
      return lower.includes('magento') && lower.includes('dashboard');
    },
    signalDesc: 'Magento admin dashboard'
  },
  {
    path    : '/backend/',
    severity: 'HIGH',
    detail  : 'Magento admin panel accessible at /backend/',
    validate: (res) => {
      const lower = (typeof res?.text === 'string' ? res.text : '').toLowerCase();
      return lower.includes('magento') && (lower.includes('dashboard') || lower.includes('adminhtml'));
    },
    signalDesc: 'Magento backend adminhtml'
  },
  {
    path    : '/magento_version',
    severity: 'MEDIUM',
    detail  : 'Magento version disclosed — enables targeted CVE exploitation',
    validate: (res) => {
      const text = typeof res?.text === 'string' ? res.text : '';
      return !isHtmlOrScript(res, text) && /\bMagento\/\d+\.\d+/i.test(text);
    },
    signalDesc: 'Magento version banner'
  },
  {
    path    : '/pub/health_check.php',
    severity: 'LOW',
    detail  : 'Magento health check accessible — leaks environment status',
    validate: (res) => {
      const text = typeof res?.text === 'string' ? res.text.trim() : '';
      return !isHtmlOrScript(res, text) && (text === '' || text.toLowerCase() === 'ok' || text.toLowerCase().includes('maintenance'));
    },
    signalDesc: 'Magento health check status'
  },
  {
    path    : '/var/log/system.log',
    severity: 'HIGH',
    detail  : 'Magento system log readable — may contain credentials or internal paths',
    validate: (res) => {
      const text = typeof res?.text === 'string' ? res.text : '';
      return !isHtmlOrScript(res, text) && /\[\d{4}-\d{2}-\d{2}|main\.(CRITICAL|ERROR|WARNING)/i.test(text);
    },
    signalDesc: 'Magento system.log entries'
  },
  {
    path    : '/var/log/exception.log',
    severity: 'HIGH',
    detail  : 'Magento exception log readable — stack traces expose internal paths',
    validate: (res) => {
      const text = typeof res?.text === 'string' ? res.text : '';
      return !isHtmlOrScript(res, text) && (text.includes('vendor/magento') || (text.includes('Stack trace:') && text.includes('#0 ')));
    },
    signalDesc: 'Magento exception.log stack traces'
  },
];

export default async function run(target, fetchWithRetry) {
  const found = [];

  for (const check of CHECKS) {
    try {
      const url = `${target}${check.path}`;
      const res = await fetchWithRetry(url, { followRedirects: false });
      if (
        res?.status !== 200 ||
        isRedirectedToDifferentPath(res, url) ||
        isFrameworkRouteErrorResponse(res, res?.text) ||
        !check.validate(res)
      ) {
        continue;
      }

      const { confirmed, res: cRes } = await confirmReproducible(
        url,
        fetchWithRetry,
        { followRedirects: false },
        (r) => r?.status === 200 && !isRedirectedToDifferentPath(r, url) && check.validate(r)
      );
      if (!confirmed) continue;

      const finalRes = cRes || res;
      const preview = extractVerbatimSnippet(finalRes.text || res.text || '', /Magento|<connection>|'crypt'|CRITICAL|ERROR|Stack trace|ok/i)
        || check.signalDesc;
      found.push({
        path         : check.path,
        url,
        method       : 'GET',
        status       : 200,
        severity     : check.severity,
        matchedSignal: check.signalDesc,
        reproducible : true,
        preview,
        detail       : check.detail,
        ...(finalRes?.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {})
      });
    } catch { /* unreachable */ }
  }

  if (!found.length) {
    return { name: 'magento exposure', status: 'SAFE', severity: 'NONE' };
  }

  const maxSev = found.some(f => f.severity === 'CRITICAL') ? 'CRITICAL'
               : found.some(f => f.severity === 'HIGH')     ? 'HIGH'
               : 'MEDIUM';
  const primary = found[0];
  const evidenceQuotes = found.map(f => f.preview).filter(q => typeof q === 'string' && q.length >= 8).slice(0, 5);

  return {
    name          : 'magento exposure',
    status        : 'VULNERABLE',
    severity      : maxSev,
    path          : primary.path,
    findings      : found,
    files         : found,
    detail        : `Confirmed ${found.length} Magento misconfiguration(s): ${found.map(f => f.path).join(', ')}`,
    reproVerified : true,
    poeLevel      : evidenceQuotes.length > 0 ? 3 : 2,
    ...(evidenceQuotes.length > 0 ? { evidenceQuotes } : {}),
    ...(primary.trafficId !== undefined ? { trafficId: primary.trafficId } : {}),
    fix           : "Secure your Magento installation by denying access to the 'app/etc/', 'var/log/', and 'downloader/' directories. Move the admin panel to a non-default URL and restrict it to trusted IPs."
  };
}
