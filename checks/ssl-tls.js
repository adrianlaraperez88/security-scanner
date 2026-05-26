import tls from 'tls';
import { URL } from 'url';

export const tags = ['all'];

/**
 * Checks SSL/TLS certificate validity and connection protocol.
 * Uses node:tls directly to inspect the certificate without depending on
 * fetchWithRetry (which always follows redirects and can't inspect TLS metadata).
 */
function tlsConnect(hostname, port, options = {}) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host      : hostname,
      port      : port,
      servername: hostname,          // SNI
      rejectUnauthorized: false,     // Check cert ourselves
      ...options
    }, () => {
      const info = {
        cert             : socket.getPeerCertificate(true),
        protocol         : socket.getProtocol(),
        authorized       : socket.authorized,
        authorizationError: socket.authorizationError
      };
      socket.destroy();
      resolve(info);
    });

    socket.on('error', (e) => { socket.destroy(); reject(e); });
    socket.setTimeout(10000, () => { socket.destroy(); reject(new Error('TLS connection timed out')); });
  });
}

export default async function run(target) {
  let parsed;
  try { parsed = new URL(target); } catch {
    return { name: 'ssl/tls check', status: 'ERROR', severity: 'LOW', reason: 'Invalid URL' };
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

  const hostname = parsed.hostname;
  const port     = parseInt(parsed.port || '443', 10);
  const issues   = [];
  let conn;

  try {
    conn = await tlsConnect(hostname, port);
  } catch (e) {
    return { name: 'ssl/tls check', status: 'ERROR', severity: 'LOW', reason: e.message };
  }

  // ── 1. Certificate expiry ──────────────────────────────────────────────────
  const cert = conn.cert;
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
  if (!conn.authorized) {
    issues.push({ issue: `Untrusted certificate: ${conn.authorizationError}`, severity: 'HIGH' });
  }

  // ── 3. Weak TLS protocol ───────────────────────────────────────────────────
  if (conn.protocol === 'TLSv1' || conn.protocol === 'TLSv1.1') {
    issues.push({ issue: `Weak TLS protocol in use: ${conn.protocol}`, severity: 'HIGH' });
  }

  // ── 4. Test if server accepts old TLS 1.0 ─────────────────────────────────
  try {
    await tlsConnect(hostname, port, { minVersion: 'TLSv1', maxVersion: 'TLSv1' });
    issues.push({ issue: 'Server accepts TLS 1.0 (deprecated, PCI-DSS non-compliant)', severity: 'MEDIUM' });
  } catch { /* rejected — server requires TLS 1.2+ */ }

  // ── 5. Test if server accepts TLS 1.1 ─────────────────────────────────────
  try {
    await tlsConnect(hostname, port, { minVersion: 'TLSv1.1', maxVersion: 'TLSv1.1' });
    issues.push({ issue: 'Server accepts TLS 1.1 (deprecated)', severity: 'MEDIUM' });
  } catch { /* rejected — good */ }

  if (issues.length === 0) {
    return {
      name    : 'ssl/tls check',
      status  : 'SAFE',
      severity: 'NONE',
      detail  : `${conn.protocol} | expires: ${cert?.valid_to ?? 'unknown'}`
    };
  }

  const maxSev = issues.some(i => i.severity === 'CRITICAL') ? 'CRITICAL'
               : issues.some(i => i.severity === 'HIGH')     ? 'HIGH'
               : 'MEDIUM';

  return {
    name    : 'ssl/tls check',
    status  : 'VULNERABLE',
    severity: maxSev,
    protocol: conn.protocol,
    issues,
    fix     : "Renew expired or expiring certificates immediately. Disable deprecated protocols (TLS 1.0, 1.1) and enable support for TLS 1.2 or 1.3 in your web server configuration."
  };
}
