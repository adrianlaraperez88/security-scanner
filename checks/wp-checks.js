import { URL } from 'node:url';
import {
  isHtmlOrScript,
  extractVerbatimSnippet,
  confirmReproducible
} from '../core/check-verify.js';

export const tags = ['wordpress'];

const GOVERNANCE_ERROR_CODES = new Set([
  'SSRF_POLICY_BLOCKED',
  'TARGET_RULE_BLOCKED',
  'TARGET_OUT_OF_SCOPE',
  'DNS_REBIND_OR_PRIVATE_IP'
]);

function isGovernanceBlockError(err) {
  if (!err) return false;
  if (err.isGovernanceBlock === true) return true;
  if (GOVERNANCE_ERROR_CODES.has(err.code)) return true;
  const msg = typeof err.message === 'string' ? err.message : '';
  return (
    msg.startsWith('Redirect blocked by SSRF policy') ||
    msg.startsWith('Request blocked by SSRF policy') ||
    msg.startsWith('[SECSCAN platform control')
  );
}

export default async function run(target, fetchWithRetry) {
  let baseUrl;
  try {
    baseUrl = new URL(String(target ?? '').trim());
  } catch {
    return { name: 'wordpress checks', status: 'ERROR', severity: 'NONE', reason: 'Invalid URL' };
  }

  const findings = [];
  let networkSuccess = false;
  let lastError = null;

  // 1. xmlrpc.php
  try {
    const xmlUrl = new URL('/xmlrpc.php', baseUrl.origin).href;
    const xmlOpts = {
      method  : 'POST',
      headers : { 'Content-Type': 'text/xml' },
      body    : '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params/></methodCall>'
    };
    const res = await fetchWithRetry(xmlUrl, xmlOpts);
    if (res?.isGovernanceBlock) {
      return { name: 'wordpress checks', status: 'ERROR', severity: 'NONE', reason: res.reason || res.error || 'Blocked by governance policy' };
    }
    networkSuccess = true;
    const text = typeof res?.text === 'string' ? res.text : '';
    if (res?.status === 200 && text.includes('<methodResponse>')) {
      const { confirmed, res: cRes } = await confirmReproducible(
        xmlUrl,
        fetchWithRetry,
        xmlOpts,
        (r) => r?.status === 200 && typeof r.text === 'string' && r.text.includes('<methodResponse>')
      );
      if (confirmed) {
        const finalRes = cRes || res;
        findings.push({
          issue        : 'xmlrpc.php enabled (brute-force amplification)',
          path         : '/xmlrpc.php',
          url          : xmlUrl,
          method       : 'POST',
          status       : 200,
          severity     : 'MEDIUM',
          matchedSignal: '<methodResponse>',
          reproducible : true,
          preview      : extractVerbatimSnippet(finalRes.text || text, '<methodResponse>') || '<methodResponse> XML-RPC response',
          ...(finalRes?.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {})
        });
      }
    }
  } catch (err) {
    if (isGovernanceBlockError(err)) {
      return { name: 'wordpress checks', status: 'ERROR', severity: 'NONE', reason: err.message };
    }
    lastError = err;
  }

  // 2. User enumeration via REST API
  try {
    const usersUrl = new URL('/wp-json/wp/v2/users', baseUrl.origin).href;
    const res = await fetchWithRetry(usersUrl);
    if (res?.isGovernanceBlock) {
      return { name: 'wordpress checks', status: 'ERROR', severity: 'NONE', reason: res.reason || res.error || 'Blocked by governance policy' };
    }
    networkSuccess = true;
    const text = typeof res?.text === 'string' ? res.text : '';
    if (res?.status === 200 && !isHtmlOrScript(res, text) && text.includes('"slug"')) {
      const { confirmed, res: cRes } = await confirmReproducible(
        usersUrl,
        fetchWithRetry,
        {},
        (r) => r?.status === 200 && !isHtmlOrScript(r, r.text) && typeof r.text === 'string' && r.text.includes('"slug"')
      );
      if (confirmed) {
        const finalRes = cRes || res;
        findings.push({
          issue        : 'User enumeration via /wp-json/wp/v2/users',
          path         : '/wp-json/wp/v2/users',
          url          : usersUrl,
          method       : 'GET',
          status       : 200,
          severity     : 'MEDIUM',
          matchedSignal: 'WP REST users "slug"',
          reproducible : true,
          preview      : extractVerbatimSnippet(finalRes.text || text, '"slug"') || '/wp-json/wp/v2/users exposed',
          ...(finalRes?.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {})
        });
      }
    }
  } catch (err) {
    if (isGovernanceBlockError(err)) {
      return { name: 'wordpress checks', status: 'ERROR', severity: 'NONE', reason: err.message };
    }
    lastError = err;
  }

  // 3. wp-login.php publicly accessible
  try {
    const loginUrl = new URL('/wp-login.php', baseUrl.origin).href;
    const res = await fetchWithRetry(loginUrl);
    if (res?.isGovernanceBlock) {
      return { name: 'wordpress checks', status: 'ERROR', severity: 'NONE', reason: res.reason || res.error || 'Blocked by governance policy' };
    }
    networkSuccess = true;
    const text = typeof res?.text === 'string' ? res.text : '';
    const html = text.toLowerCase();
    const hasWpLoginMarker =
      html.includes('user_login') ||
      html.includes('wp-submit') ||
      html.includes('loginform') ||
      (html.includes('name="log"') && html.includes('name="pwd"'));

    if (res?.status === 200 && hasWpLoginMarker) {
      const { confirmed, res: cRes } = await confirmReproducible(
        loginUrl,
        fetchWithRetry,
        {},
        (r) => r?.status === 200 && typeof r.text === 'string' && /user_login|wp-submit|loginform|name="log"/i.test(r.text)
      );
      if (confirmed) {
        const finalRes = cRes || res;
        findings.push({
          issue        : 'wp-login.php is publicly accessible',
          path         : '/wp-login.php',
          url          : loginUrl,
          method       : 'GET',
          status       : 200,
          severity     : 'LOW',
          matchedSignal: 'WordPress login form marker',
          reproducible : true,
          preview      : extractVerbatimSnippet(finalRes.text || text, /user_login|wp-submit|loginform|name="log"/i) || 'wp-login.php accessible',
          ...(finalRes?.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {})
        });
      }
    }
  } catch (err) {
    if (isGovernanceBlockError(err)) {
      return { name: 'wordpress checks', status: 'ERROR', severity: 'NONE', reason: err.message };
    }
    lastError = err;
  }

  if (findings.length === 0) {
    if (!networkSuccess) {
      return {
        name: 'wordpress checks',
        status: 'ERROR',
        severity: 'NONE',
        reason: lastError?.message || 'Target unreachable'
      };
    }
    return { name: 'wordpress checks', status: 'SAFE', severity: 'NONE' };
  }

  const maxSev = findings.some(f => f.severity === 'HIGH')   ? 'HIGH'
               : findings.some(f => f.severity === 'MEDIUM') ? 'MEDIUM'
               : 'LOW';
  const primary = findings[0];
  const evidenceQuotes = findings.map(f => f.preview).filter(q => typeof q === 'string' && q.length >= 8).slice(0, 5);

  return {
    name          : 'wordpress checks',
    status        : 'VULNERABLE',
    severity      : maxSev,
    path          : primary.path,
    detail        : `Confirmed ${findings.length} WordPress exposure(s): ${findings.map(f => f.path).join(', ')}`,
    findings,
    files         : findings,
    reproVerified : true,
    poeLevel      : evidenceQuotes.length > 0 ? 3 : 2,
    ...(evidenceQuotes.length > 0 ? { evidenceQuotes } : {}),
    ...(primary.trafficId !== undefined ? { trafficId: primary.trafficId } : {}),
    fix           : "Disable XML-RPC by adding 'add_filter(\"xmlrpc_enabled\", \"__return_false\");' to functions.php. Restrict the REST API users endpoint and protect 'wp-login.php' with IP whitelisting or a security plugin."
  };
}
