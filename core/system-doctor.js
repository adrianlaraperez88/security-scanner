import fs from 'node:fs';
import path from 'node:path';
import { URL } from 'node:url';
import dnsPromises from 'node:dns/promises';
import { getScanners } from './registry.js';
import { validateTargetUrl, resolveAndValidateTarget, isForbiddenMetadataHost } from './validator.js';
import { evaluateAssetGate, TargetPinStore } from './guard.js';
import { createGovernedFetch } from './fetch.js';

/**
 * Masks any embedded credentials (user:pass@) in proxy URL strings.
 *
 * @param {string} rawUrl
 * @returns {string|null}
 */
export function maskProxyUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') return null;
  const trimmed = rawUrl.trim();
  if (!trimmed) return null;

  try {
    const parsed = new URL(trimmed);
    if (parsed.username || parsed.password) {
      parsed.username = '***';
      parsed.password = '***';
      return parsed.toString();
    }
    return trimmed;
  } catch {
    return trimmed.replace(/:\/\/([^:@]+):([^@]+)@/, '://***:***@');
  }
}

function formatSafeStoragePath(resolvedPath) {
  const rel = path.relative(process.cwd(), resolvedPath);
  if (rel === '') return '.';
  if (!rel.startsWith('..') && !path.isAbsolute(rel)) {
    return rel.replace(/\\/g, '/');
  }
  return path.basename(resolvedPath) || 'storage';
}

function sanitizeFsError(err) {
  const code = String(err?.code || '').toUpperCase();
  if (code === 'EACCES' || code === 'EPERM') return 'Permission denied';
  if (code === 'EROFS') return 'Read-only filesystem';
  if (code === 'ENOENT') return 'Directory does not exist';
  if (code === 'ENOTDIR') return 'Path is not a directory';
  if (code === 'ENOSPC') return 'Insufficient disk space';
  if (code) return `Storage access error (${code.replace(/[^A-Z0-9_]/g, '')})`;
  return 'Storage access error';
}

/**
 * Inspects directory access. Non-mutating by default (`probeWrites = false`);
 * performs an active write/read/unlink probe only when `probeWrites` is `true`.
 */
function checkDirectoryAccess(dirPath, { probeWrites = false } = {}) {
  const resolved = path.resolve(process.cwd(), dirPath);
  const displayPath = formatSafeStoragePath(resolved);

  if (!probeWrites) {
    try {
      if (fs.existsSync(resolved)) {
        const st = fs.statSync(resolved);
        if (!st.isDirectory()) {
          return {
            path: displayPath,
            exists: true,
            readable: false,
            writable: false,
            error: 'Path is not a directory'
          };
        }
        let readable = false;
        let writable = false;
        try { fs.accessSync(resolved, fs.constants.R_OK); readable = true; } catch {}
        try { fs.accessSync(resolved, fs.constants.W_OK); writable = true; } catch {}
        return {
          path: displayPath,
          exists: true,
          readable,
          writable,
          ...(!readable || !writable
            ? { error: !writable ? 'Directory is not writable' : 'Directory is not readable' }
            : {})
        };
      }

      // Directory does not exist yet: check nearest existing ancestor without mutating disk
      let cur = path.dirname(resolved);
      while (cur && !fs.existsSync(cur)) {
        const parent = path.dirname(cur);
        if (parent === cur) break;
        cur = parent;
      }
      if (!cur || !fs.existsSync(cur)) {
        return {
          path: displayPath,
          exists: false,
          readable: false,
          writable: false,
          error: 'Parent directory does not exist'
        };
      }
      let readable = false;
      let writable = false;
      try { fs.accessSync(cur, fs.constants.R_OK); readable = true; } catch {}
      try { fs.accessSync(cur, fs.constants.W_OK); writable = true; } catch {}
      return {
        path: displayPath,
        exists: false,
        readable,
        writable,
        ...(!writable ? { error: 'Parent directory is not writable' } : {})
      };
    } catch (err) {
      return {
        path: displayPath,
        exists: false,
        readable: false,
        writable: false,
        error: sanitizeFsError(err)
      };
    }
  }

  try {
    if (!fs.existsSync(resolved)) {
      fs.mkdirSync(resolved, { recursive: true });
    }
    const probeFile = path.join(resolved, `.doctor-probe-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    fs.writeFileSync(probeFile, 'probe', 'utf8');
    const readBack = fs.readFileSync(probeFile, 'utf8');
    fs.unlinkSync(probeFile);

    return {
      path: displayPath,
      exists: true,
      readable: readBack === 'probe',
      writable: true
    };
  } catch (err) {
    return {
      path: displayPath,
      exists: fs.existsSync(resolved),
      readable: false,
      writable: false,
      error: sanitizeFsError(err)
    };
  }
}

/**
 * Inspects local environment, storage, proxy, LLM AI pools, and built-in security scanners.
 *
 * @param {object} [options={}]
 * @returns {Promise<object>}
 */
export async function runSystemDoctor({
  allowPrivate = false,
  llmPool = null,
  historyDir = '.secscan-history',
  reportsDir = 'reports',
  env = process.env,
  uiPort = 4321,
  probeWrites = false
} = {}) {
  const recommendations = [];

  // 1. Node.js runtime environment check
  const rawNodeVersion = process.version;
  const nodeMajor = parseInt(rawNodeVersion.replace(/^v/, '').split('.')[0], 10);
  const nodeOk = nodeMajor >= 22;
  if (!nodeOk) {
    recommendations.push(
      `Node.js version is ${rawNodeVersion}. Security Scanner recommends Node.js 22 or higher for native SQLite and security capabilities.`
    );
  }

  // 2. node:sqlite availability check
  let sqliteAvailable = false;
  try {
    const sqliteMod = await import('node:sqlite');
    sqliteAvailable = Boolean(sqliteMod.DatabaseSync);
  } catch {
    sqliteAvailable = false;
  }
  if (!sqliteAvailable) {
    recommendations.push(
      'node:sqlite module is unavailable. Node.js 22+ with built-in SQLite is required for knowledge graph and evidence history.'
    );
  }

  const environment = {
    nodeVersion: rawNodeVersion,
    nodeMajor,
    nodeOk,
    platform: process.platform,
    arch: process.arch,
    sqliteAvailable,
    uiPort: Number(uiPort) || 4321,
    allowPrivate: Boolean(allowPrivate)
  };

  // 3. Storage directories check (historyDir and reportsDir)
  const historyStorage = checkDirectoryAccess(historyDir, { probeWrites: Boolean(probeWrites) });
  const reportsStorage = checkDirectoryAccess(reportsDir, { probeWrites: Boolean(probeWrites) });

  if (!historyStorage.writable) {
    recommendations.push(
      `Scan history directory "${historyStorage.path}" is not writable: ${historyStorage.error || 'Access denied'}. History retention may fail.`
    );
  }
  if (!reportsStorage.writable) {
    recommendations.push(
      `Reports output directory "${reportsStorage.path}" is not writable: ${reportsStorage.error || 'Access denied'}. Report generation may fail.`
    );
  }

  const storage = {
    historyDir: historyStorage,
    reportsDir: reportsStorage
  };

  // 4. HTTP / HTTPS Proxy inspection (with credential masking)
  const httpProxy = env.HTTP_PROXY || env.http_proxy || null;
  const httpsProxy = env.HTTPS_PROXY || env.https_proxy || null;
  const noProxy = env.NO_PROXY || env.no_proxy || null;

  const proxy = {
    configured: Boolean(httpProxy || httpsProxy),
    httpProxy: maskProxyUrl(httpProxy),
    httpsProxy: maskProxyUrl(httpsProxy),
    noProxy: noProxy ? String(noProxy).trim() : null
  };

  // 5. LLM Pool / AI configuration inspection
  let activeProfilesCount = 0;
  let providers = [];
  let aiConfigured = false;

  if (llmPool) {
    const status = typeof llmPool.getPoolStatus === 'function'
      ? llmPool.getPoolStatus()
      : (typeof llmPool.getStatus === 'function' ? llmPool.getStatus() : null);
    let profs = [];
    if (status && Array.isArray(status.profiles)) {
      profs = status.profiles;
    } else if (typeof llmPool.listProfiles === 'function') {
      profs = llmPool.listProfiles();
    } else if (llmPool.profiles) {
      profs = llmPool.profiles instanceof Map
        ? [...llmPool.profiles.values()]
        : Object.values(llmPool.profiles);
    }
    const active = profs.filter(p => p && p.enabled !== false && !p.disabled);
    activeProfilesCount = active.length;
    providers = [...new Set(active.map(p => p.provider || p.name).filter(Boolean))];
    aiConfigured = activeProfilesCount > 0;
  } else {
    const knownKeys = ['GEMINI_API_KEY', 'ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'GROQ_API_KEY'];
    const activeKeys = knownKeys.filter(k => Boolean(env[k]));
    if (activeKeys.length > 0) {
      aiConfigured = true;
      providers = activeKeys.map(k => k.replace('_API_KEY', '').toLowerCase());
      activeProfilesCount = activeKeys.length;
    }
  }

  if (activeProfilesCount === 0) {
    recommendations.push(
      'No active LLM providers configured. Set GEMINI_API_KEY, ANTHROPIC_API_KEY, or OPENAI_API_KEY to enable AI-powered remediation advice.'
    );
  }

  const ai = {
    configured: aiConfigured,
    activeProfilesCount,
    providers
  };

  // 6. Built-in scanners verification
  let scanners = [];
  try {
    scanners = await getScanners();
  } catch (err) {
    recommendations.push(`Failed to load scanner plugins: ${err.message}`);
  }

  const checksCount = scanners.length;
  if (checksCount < 63) {
    recommendations.push(
      `Expected at least 63 scanner checks, but discovered ${checksCount}. Verify the checks/ directory.`
    );
  }

  const checks = {
    count: checksCount,
    available: checksCount > 0,
    scanners: scanners.map(s => s.name)
  };

  // 7. Overall health status rollup
  const ok = nodeOk &&
    sqliteAvailable &&
    historyStorage.writable &&
    reportsStorage.writable &&
    checksCount >= 63;

  return {
    ok,
    generatedAt: new Date().toISOString(),
    environment,
    storage,
    proxy,
    ai,
    checks,
    recommendations
  };
}

/**
 * Diagnostic triage for a target website or IP:
 * Determines whether connectivity issues originate from local PC/network,
 * the target website, or platform policy blocks.
 *
 * @param {string} targetUrl
 * @param {object} [options={}]
 * @returns {Promise<object>}
 */
export async function diagnoseTarget(targetUrl, {
  allowPrivate = false,
  timeoutMs = 6000,
  dnsResolver = null,
  scopeRules = null,
  fetcher = null
} = {}) {
  const permitPrivate = Boolean(allowPrivate);

  // ── Stage 1: URL validation & Cloud Metadata Block ─────────────────────────
  if (!targetUrl || typeof targetUrl !== 'string' || !targetUrl.trim()) {
    return {
      ok: false,
      targetUrl,
      stage: 'url_validation',
      issueOrigin: 'policy_block',
      reason: 'Target URL must be a non-empty string',
      recommendation: 'Provide a valid HTTP or HTTPS target URL.'
    };
  }

  let parsed;
  try {
    parsed = new URL(targetUrl.trim());
  } catch (e) {
    return {
      ok: false,
      targetUrl,
      stage: 'url_validation',
      issueOrigin: 'policy_block',
      reason: `Invalid URL format: "${targetUrl}"`,
      recommendation: 'Ensure the URL includes http:// or https:// and a valid hostname.'
    };
  }

  // Always block cloud metadata hostnames even if allowPrivate: true
  const rawHostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (isForbiddenMetadataHost(rawHostname)) {
    return {
      ok: false,
      targetUrl,
      stage: 'url_validation',
      issueOrigin: 'policy_block',
      reason: `Cloud metadata endpoint is strictly blocked: "${rawHostname}"`,
      recommendation: 'Target is a cloud provider instance metadata service (IMDS). Scanning cloud metadata endpoints is prohibited.'
    };
  }

  const urlCheck = validateTargetUrl(targetUrl, { allowPrivate: permitPrivate });
  if (!urlCheck.valid) {
    return {
      ok: false,
      targetUrl,
      stage: 'url_validation',
      issueOrigin: 'policy_block',
      reason: urlCheck.error,
      recommendation: 'Target URL violates security policy or contains forbidden characters/credentials.'
    };
  }

  // ── Stage 2: Asset gate scope and deny rule evaluation ─────────────────────
  const gateCheck = evaluateAssetGate(targetUrl, { rules: scopeRules, includeBuiltinDeny: true });
  if (gateCheck && gateCheck.allowed === false) {
    return {
      ok: false,
      targetUrl,
      stage: 'asset_gate',
      issueOrigin: 'policy_block',
      code: gateCheck.code || 'TARGET_RULE_BLOCKED',
      reason: gateCheck.reason,
      recommendation: 'Target matches a platform deny rule or is outside the configured asset scope.'
    };
  }

  // ── Stage 3: DNS Resolution and Local PC vs Target Domain Triage ───────────
  const targetPinStore = new TargetPinStore({ allowPrivate: permitPrivate });
  let resolvedIps = [];
  try {
    const dnsRes = await resolveAndValidateTarget(targetUrl, {
      resolver: dnsResolver,
      allowPrivate: permitPrivate,
      targetPinStore
    });

    if (!dnsRes.valid) {
      const reason = dnsRes.reason || 'DNS validation failed';

      // Check if blocked by platform control or SSRF policy
      if (
        reason.includes('SSRF') ||
        reason.includes('platform control') ||
        reason.includes('blocked by') ||
        reason.includes('private') ||
        reason.includes('reserved')
      ) {
        return {
          ok: false,
          targetUrl,
          stage: 'dns_resolution',
          issueOrigin: 'policy_block',
          reason,
          recommendation: 'DNS resolution revealed a private, loopback, or policy-denied IP address.'
        };
      }

      // DNS lookup failure triage: local PC vs target domain
      let isLocalPcIssue = false;
      try {
        // Test whether standard DNS works from local PC
        if (typeof dnsResolver === 'function') {
          // If custom resolver fails on reference localhost/test host
          await dnsResolver('localhost');
        } else {
          await dnsPromises.resolve4('localhost');
        }
      } catch {
        // Even localhost lookup failed -> local PC network/DNS offline
        isLocalPcIssue = true;
      }

      const issueOrigin = isLocalPcIssue ? 'local_pc' : 'target_website';
      const recommendation = isLocalPcIssue
        ? 'Local DNS resolution is failing. Check your local PC network interface, default gateway, and DNS configuration.'
        : `Target domain "${parsed.hostname}" could not be resolved. Ensure DNS A/AAAA records exist and the domain is registered.`;

      return {
        ok: false,
        targetUrl,
        stage: 'dns_resolution',
        issueOrigin,
        reason,
        recommendation
      };
    }

    resolvedIps = Array.isArray(dnsRes.resolvedIps) ? dnsRes.resolvedIps : [];
  } catch (err) {
    const msg = err.message || String(err);
    return {
      ok: false,
      targetUrl,
      stage: 'dns_resolution',
      issueOrigin: 'target_website',
      reason: `DNS resolution error: ${msg}`,
      recommendation: `Verify that "${parsed.hostname}" has valid DNS records configured.`
    };
  }

  // ── Stage 4: Governed HTTP GET Probe & Latency Measurement ─────────────────
  const start = Date.now();
  let durationMs = 0;
  const effectiveTimeout = Number.isFinite(Number(timeoutMs)) && Number(timeoutMs) > 0
    ? Number(timeoutMs)
    : 6000;

  try {
    const governedFetch = createGovernedFetch({
      enforceDnsValidation: true,
      targetPinStore,
      allowPrivate: permitPrivate,
      scopeRules,
      dnsResolver,
      retries: 0,
      timeout: effectiveTimeout,
      ...(typeof fetcher === 'function' ? { fetcher } : {})
    });
    const probeRes = await governedFetch(targetUrl, {}, 0, effectiveTimeout);

    durationMs = Date.now() - start;

    if (probeRes?.isGovernanceBlock) {
      return {
        ok: false,
        targetUrl,
        stage: 'http_probe',
        issueOrigin: 'policy_block',
        latencyMs: durationMs,
        resolvedIps,
        reason: probeRes.reason || probeRes.error || 'Blocked by governance policy during HTTP probe',
        recommendation: 'Target request blocked by platform security policy.'
      };
    }

    const statusCode = typeof probeRes?.status === 'number' ? probeRes.status : 200;

    // HTTP 5xx Server Error: target website failure
    if (statusCode >= 500) {
      return {
        ok: false,
        targetUrl,
        stage: 'http_probe',
        issueOrigin: 'target_website',
        status: statusCode,
        latencyMs: durationMs,
        resolvedIps,
        reason: `Target web server returned HTTP error status ${statusCode}`,
        recommendation: 'Target server is reachable, but the upstream application crashed or returned 5xx. Inspect application error logs.'
      };
    }

    // Normal response (HTTP 2xx, 3xx, 4xx)
    return {
      ok: true,
      targetUrl,
      stage: 'http_probe',
      issueOrigin: null,
      status: statusCode,
      latencyMs: durationMs,
      resolvedIps,
      reason: `Target is reachable and responded with HTTP ${statusCode} in ${durationMs}ms`,
      recommendation: null
    };
  } catch (err) {
    durationMs = Date.now() - start;
    const msg = String(err?.message || err || '');
    const code = err?.code || '';
    const errName = err?.name || '';

    // Governance block in fetch
    if (
      err?.isGovernanceBlock === true ||
      msg.includes('SSRF') ||
      msg.includes('governance') ||
      msg.includes('[SECSCAN platform control') ||
      code === 'SSRF_POLICY_BLOCKED' ||
      code === 'TARGET_RULE_BLOCKED' ||
      code === 'TARGET_OUT_OF_SCOPE' ||
      code === 'DNS_REBIND_OR_PRIVATE_IP'
    ) {
      return {
        ok: false,
        targetUrl,
        stage: 'http_probe',
        issueOrigin: 'policy_block',
        latencyMs: durationMs,
        resolvedIps,
        reason: msg,
        recommendation: 'Probe was blocked by security governance policies.'
      };
    }

    // Connection refused (ECONNREFUSED): port is closed or web service is down
    if (code === 'ECONNREFUSED' || msg.includes('ECONNREFUSED')) {
      const port = parsed.port || (parsed.protocol === 'https:' ? '443' : '80');
      return {
        ok: false,
        targetUrl,
        stage: 'http_probe',
        issueOrigin: 'target_website',
        latencyMs: durationMs,
        resolvedIps,
        reason: `Connection refused (ECONNREFUSED) on port ${port}`,
        recommendation: `Target host is reachable, but no service is listening on port ${port}. Verify web server process is started.`
      };
    }

    // Timeout (ETIMEDOUT / TimeoutError / AbortError)
    if (
      code === 'ETIMEDOUT' ||
      code === 'ABORT_ERR' ||
      code === 20 ||
      errName === 'AbortError' ||
      errName === 'TimeoutError' ||
      /aborted|timed?\s*out|timeouterror/i.test(msg) ||
      durationMs >= effectiveTimeout
    ) {
      return {
        ok: false,
        targetUrl,
        stage: 'http_probe',
        issueOrigin: 'target_website',
        latencyMs: durationMs,
        resolvedIps,
        reason: `HTTP probe timed out after ${durationMs}ms (threshold: ${effectiveTimeout}ms)`,
        recommendation: 'Target server dropped packets or response timed out. Verify target firewall, security groups, or server load.'
      };
    }

    // Network unreachable (local PC or gateway issue)
    if (code === 'ENETUNREACH' || code === 'EHOSTUNREACH' || msg.includes('network unreachable')) {
      return {
        ok: false,
        targetUrl,
        stage: 'http_probe',
        issueOrigin: 'local_pc',
        latencyMs: durationMs,
        resolvedIps,
        reason: `Network unreachable (${code || msg}) from local PC`,
        recommendation: 'Check your local network connection, VPN status, and default gateway routing.'
      };
    }

    // Generic HTTP probe failure
    return {
      ok: false,
      targetUrl,
      stage: 'http_probe',
      issueOrigin: 'target_website',
      latencyMs: durationMs,
      resolvedIps,
      reason: `HTTP connection failed: ${msg}`,
      recommendation: 'Check target server availability and connectivity.'
    };
  }
}
