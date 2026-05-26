export const tags = ['node', 'express', 'all'];

/**
 * Specialized checks for Node.js and Express ecosystems.
 * Node apps often leak metadata through package files and debug logs.
 */
const CHECKS = [
  {
    path: '/package.json',
    name: 'node package metadata disclosure',
    severity: 'MEDIUM',
    reason: 'Reveals backend dependencies, engine versions, and build scripts.',
    signals: ['"dependencies"', '"scripts"', '"version"', '"devDependencies"']
  },
  {
    path: '/package-lock.json',
    name: 'node lockfile disclosure',
    severity: 'HIGH',
    reason: 'Reveals exact dependency versions used in the backend.',
    signals: ['"lockfileVersion"', '"packages"', '"dependencies"']
  },
  {
    path: '/npm-debug.log',
    name: 'npm debug log exposure',
    severity: 'MEDIUM',
    reason: 'Reveals installation errors and local path structures.',
    signals: ['npm info', 'npm ERR!', 'node -v']
  },
  {
    path: '/.npmrc',
    name: 'npm configuration exposure',
    severity: 'CRITICAL',
    reason: 'May contain sensitive registry tokens or private proxy credentials.',
    signals: ['registry=', '_auth=', 'always-auth=']
  },
  {
    path: '/node_modules/express/package.json',
    name: 'node_modules directory exposure',
    severity: 'HIGH',
    reason: 'Indicates the entire node_modules directory is improperly exposed to the web.',
    signals: ['"name": "express"', '"version"']
  }
];

export default async function run(target, fetchWithRetry) {
  const found = [];

  // 1. Static file/directory checks
  for (const check of CHECKS) {
    try {
      const res = await fetchWithRetry(`${target}${check.path}`);
      if (res.status === 200) {
        const isReal = check.signals.some(s => res.text.includes(s));
        if (isReal) {
          found.push({ ...check, status: 'VULNERABLE' });
        }
      }
    } catch { /* ignore */ }
  }

  // 2. Express Header Disclosure
  try {
    const probe = await fetchWithRetry(target);
    const powered = (probe.headers['x-powered-by'] || '').toLowerCase();
    
    if (powered.includes('express')) {
      found.push({
        name: 'express header disclosure',
        severity: 'LOW',
        reason: 'The "X-Powered-By: Express" header is enabled, informing attackers of the underlying technology.',
        status: 'SUSPICIOUS'
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

  return {
    name    : 'node security',
    status  : found.some(f => f.status === 'VULNERABLE') ? 'VULNERABLE' : 'SUSPICIOUS',
    severity: maxSev,
    findings: found.map(f => ({ name: f.name, severity: f.severity, reason: f.reason })),
    fix     : 'Ensure package.json, lockfiles, and node_modules are not in the web root. Use "app.disable(\'x-powered-by\')" in Express to hide the framework identity.'
  };
}
