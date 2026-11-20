import { URL } from 'node:url';
import {
  fetchWithRetry as defaultFetch,
  governedTlsAlpnProbe,
  mergeGovernedProbeOptions,
  runAssetGateCheck
} from '../core/fetch.js';
import { validateTargetUrl } from '../core/validator.js';
import {
  isHtmlOrScript,
  isRedirectedToDifferentPath,
  parseJsonObject
} from '../core/check-verify.js';

export const tags = ['all', 'ops', 'system'];

export const name = 'system-health';
export const cwe = 'CWE-200';
export const owasp = 'A05:2021-Security Misconfiguration';
export const cvssScore = 5.3;

export const meta = {
  id: 'system-health',
  title: 'System & Operational Health Exposure',
  category: 'Network & Transport',
  plainExplanation: 'Scans for exposed operational telemetry (/metrics, /prometheus, /server-status, /actuator/health), server 5xx errors, slow response latency, uncompressed payloads, and expiring TLS certificates.',
  whyItMatters: 'Publicly accessible operational metrics, server status, and detailed component health dumps reveal internal architectures, infrastructure utilization, and sensitive service names to unauthorized actors.',
  defaultFix: 'Restrict operational and telemetry endpoints to authorized monitoring networks or require authentication. Enable gzip/brotli compression, resolve backend server errors, and renew SSL/TLS certificates before expiration.',
  cwe: 'CWE-200',
  owasp: 'A05:2021-Security Misconfiguration',
  cvssScore: 5.3,
  cveIds: [],
  references: [
    'https://cwe.mitre.org/data/definitions/200.html',
    'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
  ]
};

const GOVERNANCE_ERROR_CODES = new Set([
  'SSRF_POLICY_BLOCKED',
  'TARGET_RULE_BLOCKED',
  'TARGET_OUT_OF_SCOPE',
  'DNS_REBIND_OR_PRIVATE_IP'
]);

function isGovernanceBlock(errOrRes) {
  if (!errOrRes) return false;
  if (errOrRes.isGovernanceBlock === true) return true;
  if (GOVERNANCE_ERROR_CODES.has(errOrRes.code)) return true;
  const msg = typeof errOrRes.message === 'string'
    ? errOrRes.message
    : (typeof errOrRes.reason === 'string' ? errOrRes.reason : '');
  return (
    msg.startsWith('Redirect blocked by SSRF policy') ||
    msg.startsWith('Request blocked by SSRF policy') ||
    msg.startsWith('[SECSCAN platform control') ||
    msg.includes('SSRF policy') ||
    msg.includes('Target blocked by deny rule') ||
    msg.includes('Target outside declared allow scope')
  );
}

function getHeader(headers, name) {
  if (!headers || typeof headers !== 'object') return '';
  const targetLower = String(name).toLowerCase();
  if (typeof headers.get === 'function') {
    return String(headers.get(name) ?? headers.get(targetLower) ?? '');
  }
  for (const [k, v] of Object.entries(headers)) {
    if (String(k).toLowerCase() === targetLower && v !== undefined && v !== null) {
      return Array.isArray(v) ? v.join(', ') : String(v);
    }
  }
  return '';
}

/**
 * Extracts a verbatim evidence quote >= 8 characters from text around a signal.
 */
function extractEvidenceQuote(text, signal) {
  if (typeof text !== 'string' || !signal) return signal ? String(signal) : '';
  const idx = text.indexOf(signal);
  if (idx === -1) {
    return signal.length >= 8 ? signal : signal.padEnd(8, ' ');
  }

  // Look for end of line or take up to 80 chars
  const lineEnd = text.indexOf('\n', idx);
  const end = lineEnd !== -1 ? lineEnd : text.length;
  let quote = text.slice(idx, Math.min(idx + 100, end)).trim();
  if (quote.length < 8) {
    quote = text.slice(idx, Math.min(text.length, idx + 16)).trim();
  }
  return quote.length >= 8 ? quote : signal;
}

const TELEMETRY_ENDPOINTS = [
  '/metrics',
  '/prometheus',
  '/server-status',
  '/nginx_status'
];

const TELEMETRY_SIGNALS = [
  '# HELP',
  '# TYPE',
  'process_cpu',
  'go_goroutines',
  'Active connections',
  'Apache Server Status',
  'Scoreboard'
];

const HEALTH_ENDPOINTS = [
  '/health',
  '/healthz',
  '/readyz',
  '/actuator/health'
];

const HEALTH_LEAK_SIGNALS = [
  '"components"',
  '"diskSpace"',
  '"db"',
  '"redis"'
];

/**
 * System & Operational Health Exposure scanner
 */
export default async function run(target, fetchWithRetry = defaultFetch, options = {}) {
  const boundGovernance = fetchWithRetry?.governance || null;
  const govOpts = mergeGovernedProbeOptions(boundGovernance, options);
  const allowPrivate = Boolean(govOpts.allowPrivate);
  const guard = govOpts.guard ?? null;
  const scopeRules = boundGovernance && boundGovernance.scopeRules === undefined
    ? null
    : (govOpts.scopeRules ?? null);

  let parsedUrl;
  try {
    parsedUrl = new URL(String(target ?? '').trim());
  } catch {
    return {
      name: 'system-health',
      status: 'ERROR',
      severity: 'NONE',
      reason: 'Invalid URL'
    };
  }

  // Pre-check URL validation & asset gate
  const urlCheck = validateTargetUrl(target, { allowPrivate });
  if (!urlCheck.valid) {
    return {
      name: 'system-health',
      status: 'ERROR',
      severity: 'NONE',
      reason: `Request blocked by SSRF policy: ${urlCheck.error}`
    };
  }

  const preDnsGate = runAssetGateCheck(target, { guard, scopeRules, alwaysBuiltin: true });
  if (preDnsGate && preDnsGate.allowed === false) {
    return {
      name: 'system-health',
      status: 'ERROR',
      severity: 'NONE',
      reason: preDnsGate.reason || 'Blocked by governance policy'
    };
  }

  const fetchFn = typeof fetchWithRetry === 'function' ? fetchWithRetry : defaultFetch;
  const fetchOpts = { ...options, allowPrivate };
  const issues = [];
  const allEvidenceQuotes = [];
  const origin = parsedUrl.origin;
  let mainTrafficId;

  // ── 1. Main target timing, 5xx status, TTFB, and HTTP compression ──────────
  try {
    const start = Date.now();
    const mainRes = await fetchFn(target, fetchOpts);
    mainTrafficId = mainRes?.trafficId;

    if (isGovernanceBlock(mainRes)) {
      return {
        name: 'system-health',
        status: 'ERROR',
        severity: 'NONE',
        reason: mainRes.reason || mainRes.error || 'Blocked by governance policy'
      };
    }

    const ttfb = (typeof mainRes.durationMs === 'number' && mainRes.durationMs > 0)
      ? mainRes.durationMs
      : (Date.now() - start);

    // 5xx error status check
    if (typeof mainRes.status === 'number' && mainRes.status >= 500) {
      issues.push({
        issue: `Main target returned HTTP server error ${mainRes.status}`,
        status: 'SUSPICIOUS',
        severity: 'HIGH',
        path: parsedUrl.pathname || '/',
        url: target,
        ...(mainRes?.trafficId !== undefined ? { trafficId: mainRes.trafficId } : {}),
        detail: `Server responded with HTTP ${mainRes.status} indicating backend unhealthiness or unhandled crash.`
      });
    }

    // Slow response TTFB (>= 3000ms)
    if (ttfb >= 3000) {
      issues.push({
        issue: `Slow response TTFB (${ttfb}ms >= 3000ms)`,
        status: 'SUSPICIOUS',
        severity: 'LOW',
        path: parsedUrl.pathname || '/',
        url: target,
        ...(mainRes?.trafficId !== undefined ? { trafficId: mainRes.trafficId } : {}),
        detail: `Initial server response time (${ttfb}ms) indicates a performance or latency bottleneck.`
      });
    }

    // Missing HTTP compression on text/html or application/json > 4096 bytes
    const contentType = (getHeader(mainRes.headers, 'content-type') || '').toLowerCase();
    const contentEncoding = (getHeader(mainRes.headers, 'content-encoding') || '').toLowerCase();
    const textLen = typeof mainRes.text === 'string' ? Buffer.byteLength(mainRes.text) : 0;
    const headerLen = Number(getHeader(mainRes.headers, 'content-length') || 0);
    const bodyBytes = Math.max(textLen, headerLen);

    if (
      (contentType.includes('text/html') || contentType.includes('application/json')) &&
      bodyBytes > 4096 &&
      !contentEncoding
    ) {
      issues.push({
        issue: 'Missing HTTP compression on large text/json response payload (>4KB)',
        status: 'SUSPICIOUS',
        severity: 'LOW',
        path: parsedUrl.pathname || '/',
        url: target,
        ...(mainRes?.trafficId !== undefined ? { trafficId: mainRes.trafficId } : {}),
        detail: `Response payload is ${bodyBytes} bytes without Content-Encoding (gzip/br/deflate) header.`
      });
    }
  } catch (err) {
    if (isGovernanceBlock(err)) {
      return {
        name: 'system-health',
        status: 'ERROR',
        severity: 'NONE',
        reason: err.message || 'Blocked by governance policy'
      };
    }
    // Network failure on main target
    return {
      name: 'system-health',
      status: 'ERROR',
      severity: 'NONE',
      reason: err.message || 'Target unreachable'
    };
  }

  // ── 2. Probe operational telemetry endpoints ───────────────────────────────
  const endpointsToProbe = [
    '/health',
    '/healthz',
    '/readyz',
    '/metrics',
    '/prometheus',
    '/server-status',
    '/nginx_status',
    '/actuator/health'
  ];

  for (const ep of endpointsToProbe) {
    try {
      const probeUrl = `${origin}${ep}`;
      const res = await fetchFn(probeUrl, fetchOpts);

      if (isGovernanceBlock(res)) {
        return {
          name: 'system-health',
          status: 'ERROR',
          severity: 'NONE',
          reason: res.reason || res.error || 'Blocked by governance policy'
        };
      }

      if (res?.status === 200 && !isRedirectedToDifferentPath(res, probeUrl) && typeof res.text === 'string') {
        const bodyText = res.text;

        // Check telemetry endpoints (/metrics, /prometheus, /server-status, /nginx_status)
        if (TELEMETRY_ENDPOINTS.includes(ep)) {
          const isApacheStatusHtml = ep === '/server-status' && bodyText.includes('Apache Server Status');
          if (!isApacheStatusHtml && isHtmlOrScript(res, bodyText)) {
            continue;
          }
          for (const sig of TELEMETRY_SIGNALS) {
            if (bodyText.includes(sig)) {
              const quote = extractEvidenceQuote(bodyText, sig);
              if (!allEvidenceQuotes.includes(quote)) {
                allEvidenceQuotes.push(quote);
              }
              issues.push({
                issue: `Operational telemetry exposed on ${ep}`,
                status: 'VULNERABLE',
                severity: 'MEDIUM',
                endpoint: ep,
                path: ep,
                url: probeUrl,
                method: 'GET',
                signal: sig,
                matchedSignal: sig,
                preview: quote,
                evidenceQuotes: [quote],
                ...(res?.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
                detail: `Telemetry endpoint ${ep} returned HTTP 200 with operational metrics signal "${sig}".`
              });
              break;
            }
          }
        }

        // Check health endpoints (/actuator/health, /health, /healthz, /readyz)
        if (HEALTH_ENDPOINTS.includes(ep)) {
          // Reject SPA HTML/JS catch-alls; health component dumps are JSON objects
          if (isHtmlOrScript(res, bodyText) || !parseJsonObject(bodyText)) {
            continue;
          }
          // Check for leaking internal component/DB/disk details
          let matchedLeakSignal = null;
          for (const leakSig of HEALTH_LEAK_SIGNALS) {
            if (bodyText.includes(leakSig)) {
              matchedLeakSignal = leakSig;
              break;
            }
          }

          if (matchedLeakSignal) {
            const quote = extractEvidenceQuote(bodyText, matchedLeakSignal);
            if (!allEvidenceQuotes.includes(quote)) {
              allEvidenceQuotes.push(quote);
            }
            issues.push({
              issue: `Internal health details and components exposed on ${ep}`,
              status: 'VULNERABLE',
              severity: 'MEDIUM',
              endpoint: ep,
              path: ep,
              url: probeUrl,
              method: 'GET',
              signal: matchedLeakSignal,
              matchedSignal: matchedLeakSignal,
              preview: quote,
              evidenceQuotes: [quote],
              ...(res?.trafficId !== undefined ? { trafficId: res.trafficId } : {}),
              detail: `Health endpoint ${ep} exposed sensitive component information matching "${matchedLeakSignal}".`
            });
          }
          // Note: bare {"status":"UP"} or {"status": "UP"} is NOT flagged as vulnerable!
        }
      }
    } catch (err) {
      if (isGovernanceBlock(err)) {
        return {
          name: 'system-health',
          status: 'ERROR',
          severity: 'NONE',
          reason: err.message || 'Blocked by governance policy'
        };
      }
      // Individual endpoint probe failed, continue to next
    }
  }

  // ── 3. TLS Certificate Check for HTTPS targets ─────────────────────────────
  if (parsedUrl.protocol === 'https:') {
    let daysRemaining = null;
    const extractDaysRemaining = (probeRes) => {
      if (!probeRes || typeof probeRes !== 'object') return null;
      if (probeRes.daysRemaining !== undefined && Number.isFinite(Number(probeRes.daysRemaining))) {
        return Number(probeRes.daysRemaining);
      }
      if (probeRes.cert?.valid_to) {
        const exp = new Date(probeRes.cert.valid_to).getTime();
        if (Number.isFinite(exp)) {
          return Math.floor((exp - Date.now()) / 86_400_000);
        }
      }
      return null;
    };

    if (options?.tlsProbe !== undefined) {
      if (typeof options.tlsProbe === 'function') {
        try {
          const hasGovernance = Boolean(
            boundGovernance ||
            options?.guard ||
            options?.scopeRules ||
            options?.dnsResolver ||
            options?.resolver ||
            options?.targetPinStore ||
            options?.enforceDnsValidation
          );
          let probeRes;
          if (typeof fetchWithRetry?.tlsAlpnProbe === 'function') {
            probeRes = await fetchWithRetry.tlsAlpnProbe(
              target,
              mergeGovernedProbeOptions(boundGovernance, { ...options, tlsProbe: options.tlsProbe })
            );
          } else if (hasGovernance) {
            probeRes = await governedTlsAlpnProbe(
              target,
              mergeGovernedProbeOptions(boundGovernance, { ...options, tlsProbe: options.tlsProbe })
            );
          } else {
            probeRes = await options.tlsProbe(target, options);
          }
          daysRemaining = extractDaysRemaining(probeRes);
        } catch (err) {
          if (isGovernanceBlock(err)) {
            return {
              name: 'system-health',
              status: 'ERROR',
              severity: 'NONE',
              reason: err.message || 'Blocked by governance policy'
            };
          }
        }
      } else if (options.tlsProbe && typeof options.tlsProbe === 'object') {
        daysRemaining = extractDaysRemaining(options.tlsProbe);
      }
    } else {
      // No options.tlsProbe mock supplied: governed TLS probe (asset gate + DNS pin + governor)
      try {
        const tlsOpts = mergeGovernedProbeOptions(boundGovernance, {
          ...options,
          timeout: options?.timeout ?? 5000
        });
        const probeRes = typeof fetchWithRetry?.tlsAlpnProbe === 'function'
          ? await fetchWithRetry.tlsAlpnProbe(target, tlsOpts)
          : await governedTlsAlpnProbe(target, tlsOpts);
        daysRemaining = extractDaysRemaining(probeRes);
      } catch (err) {
        if (isGovernanceBlock(err)) {
          return {
            name: 'system-health',
            status: 'ERROR',
            severity: 'NONE',
            reason: err.message || 'Blocked by governance policy'
          };
        }
        // In unit tests without mock or outside network, ignore raw socket failures
      }
    }

    if (daysRemaining !== null && Number.isFinite(daysRemaining)) {
      if (daysRemaining <= 0) {
        issues.push({
          issue: `TLS certificate expired (${Math.abs(daysRemaining)} days ago)`,
          status: 'VULNERABLE',
          severity: 'CRITICAL',
          daysRemaining,
          detail: 'SSL/TLS certificate has expired, resulting in browser security warnings and broken secure connections.'
        });
      } else if (daysRemaining <= 14) {
        issues.push({
          issue: `TLS certificate expiring soon (${daysRemaining} days remaining)`,
          status: 'SUSPICIOUS',
          severity: 'HIGH',
          daysRemaining,
          detail: `SSL/TLS certificate will expire in ${daysRemaining} days. Immediate renewal required.`
        });
      } else if (daysRemaining <= 30) {
        issues.push({
          issue: `TLS certificate expires in ${daysRemaining} days`,
          status: 'SUSPICIOUS',
          severity: 'MEDIUM',
          daysRemaining,
          detail: `SSL/TLS certificate expires in ${daysRemaining} days. Plan renewal.`
        });
      }
    }
  }

  // ── 4. Roll up overall status and severity ─────────────────────────────────
  if (issues.length === 0) {
    return {
      name: 'system-health',
      status: 'SAFE',
      severity: 'NONE',
      cwe: 'CWE-200',
      owasp: 'A05:2021-Security Misconfiguration',
      cvssScore: 5.3,
      issues: [],
      evidenceQuotes: []
    };
  }

  const hasVulnerable = issues.some(i => i.status === 'VULNERABLE');
  const overallStatus = hasVulnerable ? 'VULNERABLE' : 'SUSPICIOUS';

  let overallSeverity = 'LOW';
  if (issues.some(i => i.severity === 'CRITICAL')) {
    overallSeverity = 'CRITICAL';
  } else if (issues.some(i => i.severity === 'HIGH')) {
    overallSeverity = 'HIGH';
  } else if (issues.some(i => i.severity === 'MEDIUM')) {
    overallSeverity = 'MEDIUM';
  }

  const primaryIssue = issues.find(i => i.status === 'VULNERABLE' && i.endpoint) || issues.find(i => i.endpoint) || issues[0];
  const primaryPath = primaryIssue?.endpoint || primaryIssue?.path || (parsedUrl.pathname || '/');
  const primaryTrafficId = primaryIssue?.trafficId ?? mainTrafficId;

  return {
    name: 'system-health',
    status: overallStatus,
    severity: overallSeverity,
    path: primaryPath,
    detail: issues.map(i => i.issue).join('; '),
    cwe: 'CWE-200',
    owasp: 'A05:2021-Security Misconfiguration',
    cvssScore: 5.3,
    issues,
    evidenceQuotes: allEvidenceQuotes,
    ...(primaryTrafficId !== undefined ? { trafficId: primaryTrafficId } : {}),
    fix: meta.defaultFix
  };
}
