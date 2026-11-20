import { redactSecretsInText } from '../core/ai-advisor.js';
import {
  getHeader,
  isHtmlOrScript,
  isRedirectedToDifferentPath,
  isFrameworkRouteErrorResponse,
  parseJsonObject,
  extractVerbatimSnippet,
  confirmReproducible
} from '../core/check-verify.js';

export const tags = ['node', 'express', 'nextjs'];

const CHECKS = [
  {
    path: '/package.json',
    name: 'node package metadata disclosure',
    severity: 'MEDIUM',
    reason: 'Reveals backend dependencies, engine versions, and build scripts.',
    validate: (res) => {
      const text = typeof res?.text === 'string' ? res.text : '';
      if (!text || isHtmlOrScript(res, text)) return false;
      const json = parseJsonObject(text);
      return Boolean(json && !Array.isArray(json) && (json.dependencies || json.devDependencies || json.scripts));
    },
    signalDesc: 'package.json JSON dependencies/scripts'
  },
  {
    path: '/package-lock.json',
    name: 'node lockfile disclosure',
    severity: 'HIGH',
    reason: 'Reveals exact dependency versions used in the backend.',
    validate: (res) => {
      const text = typeof res?.text === 'string' ? res.text : '';
      if (!text || isHtmlOrScript(res, text)) return false;
      const json = parseJsonObject(text);
      return Boolean(json && !Array.isArray(json) && json.lockfileVersion && (json.packages || json.dependencies));
    },
    signalDesc: 'package-lock.json JSON'
  },
  {
    path: '/npm-debug.log',
    name: 'npm debug log exposure',
    severity: 'MEDIUM',
    reason: 'Reveals installation errors and local path structures.',
    validate: (res) => {
      const text = typeof res?.text === 'string' ? res.text : '';
      return !isHtmlOrScript(res, text) && (text.includes('npm info ') || text.includes('npm ERR!'));
    },
    signalDesc: 'npm-debug.log entries'
  },
  {
    path: '/.npmrc',
    name: 'npm configuration exposure',
    severity: 'CRITICAL',
    reason: 'May contain sensitive registry tokens or private proxy credentials.',
    validate: (res) => {
      const text = typeof res?.text === 'string' ? res.text : '';
      return !isHtmlOrScript(res, text) && /^\s*(?:registry|\/\/[^=\s]+:_authToken|_auth|always-auth)\s*=/m.test(text);
    },
    signalDesc: '.npmrc registry/auth assignment'
  },
  {
    path: '/node_modules/express/package.json',
    name: 'node_modules directory exposure',
    severity: 'HIGH',
    reason: 'Indicates the entire node_modules directory is improperly exposed to the web.',
    validate: (res) => {
      const text = typeof res?.text === 'string' ? res.text : '';
      if (!text || isHtmlOrScript(res, text)) return false;
      const json = parseJsonObject(text);
      return Boolean(json && json.name === 'express' && typeof json.version === 'string');
    },
    signalDesc: 'express package.json'
  }
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
      const preview = redactSecretsInText(
        extractVerbatimSnippet(finalRes.text || res.text || '', /dependencies|lockfileVersion|npm ERR!|_auth|registry=|"name"\s*:\s*"express"/i) || check.signalDesc
      );
      found.push({
        name         : check.name,
        path         : check.path,
        url,
        method       : 'GET',
        status       : 200,
        statusTag    : 'VULNERABLE',
        severity     : check.severity,
        matchedSignal: check.signalDesc,
        reproducible : true,
        preview,
        reason       : check.reason,
        ...(finalRes?.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {})
      });
    } catch { /* ignore */ }
  }

  try {
    const probe = await fetchWithRetry(target);
    const powered = getHeader(probe?.headers, 'x-powered-by');
    if (powered.toLowerCase().includes('express')) {
      const quote = `X-Powered-By: ${powered}`;
      found.push({
        name         : 'express header disclosure',
        path         : '/',
        url          : target,
        method       : 'GET',
        status       : probe?.status ?? 200,
        statusTag    : 'SUSPICIOUS',
        severity     : 'LOW',
        matchedSignal: quote,
        reproducible : true,
        preview      : quote,
        reason       : 'The "X-Powered-By: Express" header is enabled, informing attackers of the underlying technology.',
        ...(probe?.trafficId !== undefined ? { trafficId: probe.trafficId } : {})
      });
    }
  } catch { /* ignore */ }

  if (found.length === 0) {
    return { name: 'node security', status: 'SAFE', severity: 'NONE' };
  }

  const maxSev = found.some(f => f.severity === 'CRITICAL') ? 'CRITICAL'
               : found.some(f => f.severity === 'HIGH')     ? 'HIGH'
               : found.some(f => f.severity === 'MEDIUM')   ? 'MEDIUM'
               : 'LOW';
  const primary = found[0];
  const evidenceQuotes = found.map(f => f.preview).filter(q => typeof q === 'string' && q.length >= 8).slice(0, 5);

  return {
    name          : 'node security',
    status        : found.some(f => f.statusTag === 'VULNERABLE') ? 'VULNERABLE' : 'SUSPICIOUS',
    severity      : maxSev,
    path          : primary.path,
    detail        : `Confirmed ${found.length} Node/Express issue(s): ${found.map(f => f.path).join(', ')}`,
    findings      : found.map(f => ({ name: f.name, severity: f.severity, path: f.path, url: f.url, status: f.status, matchedSignal: f.matchedSignal, preview: f.preview, reason: f.reason })),
    files         : found,
    reproVerified : true,
    poeLevel      : evidenceQuotes.length > 0 ? 3 : 2,
    ...(evidenceQuotes.length > 0 ? { evidenceQuotes } : {}),
    ...(primary.trafficId !== undefined ? { trafficId: primary.trafficId } : {}),
    fix           : 'Ensure package.json, lockfiles, and node_modules are not in the web root. Use "app.disable(\'x-powered-by\')" in Express to hide the framework identity.'
  };
}
