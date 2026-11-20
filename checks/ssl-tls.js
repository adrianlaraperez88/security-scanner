import tls from 'node:tls';
import net from 'node:net';
import { URL } from 'node:url';
import { validateTargetUrl, resolveAndValidateTarget } from '../core/validator.js';
import { runAssetGateCheck, mergeGovernedProbeOptions } from '../core/fetch.js';

export const tags = ['all'];

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

/**
 * Checks SSL/TLS certificate validity and connection protocol using governed
 * URL validation, scope rules, DNS resolution/pinning, and pinned TLS connections.
 */
function openPinnedTlsSocket({ host, port, servername, timeout = 10000, minVersion, maxVersion }) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let socket = null;
    let timer = null;

    const cleanup = () => {
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
      if (socket) {
        try { socket.setTimeout(0); } catch {}
        if (!socket.destroyed) socket.destroy();
      }
    };

    const fail = (err) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(err instanceof Error ? err : new Error(String(err)));
    };

    const succeed = (info) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(info);
    };

    try {
      const tlsOpts = {
        host,
        port,
        ...(servername ? { servername } : {}),
        rejectUnauthorized: false,
        ...(minVersion ? { minVersion } : {}),
        ...(maxVersion ? { maxVersion } : {})
      };

      socket = tls.connect(tlsOpts, () => {
        succeed({
          cert              : socket.getPeerCertificate(true),
          protocol          : socket.getProtocol(),
          authorized        : socket.authorized,
          authorizationError: socket.authorizationError
        });
      });

      timer = setTimeout(() => {
        fail(new Error('TLS connection timed out'));
      }, timeout);
      if (typeof timer.unref === 'function') {
        timer.unref();
      }

      socket.setTimeout(timeout, () => {
        fail(new Error('TLS connection timed out'));
      });

      socket.on('error', (e) => fail(e));
    } catch (e) {
      fail(e);
    }
  });
}

export default async function run(target, fetchWithRetry, options = {}) {
  const customTlsConnect = typeof options?.tlsConnect === 'function' ? options.tlsConnect : null;
  const boundGovernance = fetchWithRetry?.governance || null;
  const govOpts = mergeGovernedProbeOptions(boundGovernance, options);

  const allowPrivate = Boolean(govOpts.allowPrivate);
  const guard = govOpts.guard ?? null;
  const scopeRules = boundGovernance && boundGovernance.scopeRules === undefined
    ? null
    : (govOpts.scopeRules ?? null);
  const dnsResolver = govOpts.dnsResolver ?? govOpts.resolver ?? null;
  const targetPinStore = boundGovernance && boundGovernance.targetPinStore === undefined
    ? null
    : (govOpts.targetPinStore ?? null);
  const timeout = Number.isFinite(Number(govOpts.timeout)) && Number(govOpts.timeout) > 0
    ? Number(govOpts.timeout)
    : 10000;

  let parsed;
  try {
    parsed = new URL(String(target ?? '').trim());
  } catch {
    return { name: 'ssl/tls check', status: 'ERROR', severity: 'NONE', reason: 'Invalid URL' };
  }

  // ── Pre-network URL & scope governance ─────────────────────────────────────
  const urlCheck = validateTargetUrl(target, { allowPrivate });
  if (!urlCheck.valid) {
    return {
      name: 'ssl/tls check',
      status: 'ERROR',
      severity: 'NONE',
      reason: `Request blocked by SSRF policy: ${urlCheck.error}`
    };
  }

  const preDnsGate = runAssetGateCheck(target, { guard, scopeRules, alwaysBuiltin: true });
  if (preDnsGate && preDnsGate.allowed === false) {
    return {
      name: 'ssl/tls check',
      status: 'ERROR',
      severity: 'NONE',
      reason: preDnsGate.reason
    };
  }

  if (parsed.protocol !== 'https:') {
    return {
      name: 'ssl/tls check',
      status: 'SUSPICIOUS',
      severity: 'HIGH',
      detail: 'Server not using HTTPS at all',
      fix: "Enable HTTPS (TLS) immediately to encrypt all data in transit. You can use Let's Encrypt for a free, trusted certificate."
    };
  }

  // ── DNS resolution, TargetPinStore pinning & post-DNS gate ─────────────────
  const hasGovernance = Boolean(
    boundGovernance ||
    options?.guard ||
    options?.scopeRules ||
    options?.dnsResolver ||
    options?.resolver ||
    options?.targetPinStore ||
    options?.enforceDnsValidation ||
    options?.allowPrivate
  );

  let cleanHostname = String(parsed.hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
  let connectHost = cleanHostname;
  let resolvedIp = null;
  let resolvedIps = [];

  if (!customTlsConnect || hasGovernance) {
    const dnsRes = await resolveAndValidateTarget(target, {
      resolver: dnsResolver,
      targetPinStore,
      allowPrivate
    });

    if (!dnsRes.valid) {
      const msg = dnsRes.reason.startsWith('[SECSCAN platform control')
        ? dnsRes.reason
        : `[SECSCAN platform control, not target defense] ${dnsRes.reason}`;
      return {
        name: 'ssl/tls check',
        status: 'ERROR',
        severity: 'NONE',
        reason: msg
      };
    }

    if (Array.isArray(dnsRes.resolvedIps) && dnsRes.resolvedIps.length > 0) {
      const postDnsGate = runAssetGateCheck(
        {
          url: target,
          hostname: dnsRes.hostname,
          resolvedIps: dnsRes.resolvedIps
        },
        { guard, scopeRules, alwaysBuiltin: true }
      );
      if (postDnsGate && postDnsGate.allowed === false) {
        return {
          name: 'ssl/tls check',
          status: 'ERROR',
          severity: 'NONE',
          reason: postDnsGate.reason
        };
      }
      resolvedIps = dnsRes.resolvedIps;
      resolvedIp = dnsRes.resolvedIps[0];
      connectHost = resolvedIp;
    }

    cleanHostname = String(dnsRes.hostname || cleanHostname).toLowerCase().replace(/^\[|\]$/g, '');
  }

  const servername = net.isIP(cleanHostname) === 0 ? cleanHostname : undefined;
  const port = parseInt(parsed.port || '443', 10);

  const invokeTlsConnect = (tlsOptions = {}) => {
    if (customTlsConnect) {
      return customTlsConnect({
        url: parsed.toString(),
        host: connectHost,
        resolvedIp,
        resolvedIps,
        hostname: cleanHostname,
        port,
        ...(servername ? { servername } : {}),
        timeout,
        ...tlsOptions
      });
    }
    return openPinnedTlsSocket({
      host: connectHost,
      port,
      servername,
      timeout,
      ...tlsOptions
    });
  };

  const issues = [];
  let conn;

  try {
    conn = await invokeTlsConnect();
  } catch (e) {
    return { name: 'ssl/tls check', status: 'ERROR', severity: 'NONE', reason: e?.message || 'TLS connection failed' };
  }

  // ── 1. Certificate expiry ──────────────────────────────────────────────────
  const cert = conn?.cert;
  if (cert?.valid_to) {
    const expiry   = new Date(cert.valid_to);
    const daysLeft = Math.floor((expiry - Date.now()) / 86_400_000);

    if (daysLeft < 0) {
      issues.push({ issue: `Certificate EXPIRED ${Math.abs(daysLeft)} days ago`, severity: 'CRITICAL' });
    } else if (daysLeft < 7) {
      issues.push({ issue: `Certificate expires in ${daysLeft} days — URGENT`, severity: 'CRITICAL' });
    } else if (daysLeft < 30) {
      issues.push({ issue: `Certificate expires in ${daysLeft} days`, severity: 'HIGH' });
    }
  }

  // ── 2. Untrusted / self-signed certificate ─────────────────────────────────
  if (!conn?.authorized) {
    issues.push({ issue: `Untrusted certificate: ${conn?.authorizationError || 'unauthorized'}`, severity: 'HIGH' });
  }

  // ── 3. Weak TLS protocol ───────────────────────────────────────────────────
  if (conn?.protocol === 'TLSv1' || conn?.protocol === 'TLSv1.1') {
    issues.push({ issue: `Weak TLS protocol in use: ${conn.protocol}`, severity: 'HIGH' });
  }

  // ── 4. Test if server accepts old TLS 1.0 ─────────────────────────────────
  try {
    await invokeTlsConnect({ minVersion: 'TLSv1', maxVersion: 'TLSv1' });
    issues.push({ issue: 'Server accepts TLS 1.0 (deprecated, PCI-DSS non-compliant)', severity: 'MEDIUM' });
  } catch (err) {
    if (isGovernanceBlockError(err)) {
      return { name: 'ssl/tls check', status: 'ERROR', severity: 'NONE', reason: err.message };
    }
  }

  // ── 5. Test if server accepts TLS 1.1 ─────────────────────────────────────
  try {
    await invokeTlsConnect({ minVersion: 'TLSv1.1', maxVersion: 'TLSv1.1' });
    issues.push({ issue: 'Server accepts TLS 1.1 (deprecated)', severity: 'MEDIUM' });
  } catch (err) {
    if (isGovernanceBlockError(err)) {
      return { name: 'ssl/tls check', status: 'ERROR', severity: 'NONE', reason: err.message };
    }
  }

  if (issues.length === 0) {
    return {
      name    : 'ssl/tls check',
      status  : 'SAFE',
      severity: 'NONE',
      detail  : `${conn?.protocol || 'TLS'} | expires: ${cert?.valid_to ?? 'unknown'}`
    };
  }

  const maxSev = issues.some(i => i.severity === 'CRITICAL') ? 'CRITICAL'
               : issues.some(i => i.severity === 'HIGH')     ? 'HIGH'
               : 'MEDIUM';

  return {
    name    : 'ssl/tls check',
    status  : 'VULNERABLE',
    severity: maxSev,
    protocol: conn?.protocol,
    issues,
    fix     : "Renew expired or expiring certificates immediately. Disable deprecated protocols (TLS 1.0, 1.1) and enable support for TLS 1.2 or 1.3 in your web server configuration."
  };
}
