import { URL } from 'node:url';

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
 * The Fuzzer engine for Scanner 2.0.
 * Injects payloads into URL parameters and analyzes responses for signatures.
 */
export class Fuzzer {
  constructor(fetchWithRetry) {
    this.fetch = fetchWithRetry;
  }

  /**
   * Identifies query parameters in a URL, runs fuzzing probes, and returns detailed
   * execution metadata (findings, attempted count, networkSuccess, governanceError, lastError, baselineMs).
   */
  async fuzzDetailed(targetUrl, payload, signatureType = 'REFLECTED', options = {}) {
    const url = new URL(String(targetUrl ?? '').trim());
    const params = Array.from(url.searchParams.keys());
    const findings = [];

    if (params.length === 0) {
      return {
        findings,
        attempted: 0,
        networkSuccess: true,
        governanceError: null,
        lastError: null,
        baselineMs: null
      };
    }

    const delayThresholdMs = Number.isFinite(Number(options?.delayThresholdMs)) && Number(options.delayThresholdMs) > 0
      ? Number(options.delayThresholdMs)
      : 4500;

    let attempted = 0;
    let networkSuccess = false;
    let governanceError = null;
    let lastError = null;
    let baselineMs = null;

    if (signatureType === 'SQLI_TIME') {
      attempted += 1;
      const bStart = Date.now();
      try {
        const bRes = await this.fetch(url.href);
        if (bRes?.isGovernanceBlock) {
          const gErr = new Error(bRes.reason || bRes.error || 'Blocked by governance policy');
          gErr.isGovernanceBlock = true;
          return {
            findings: [],
            attempted,
            networkSuccess: false,
            governanceError: gErr,
            lastError: gErr,
            baselineMs: null
          };
        }
        baselineMs = Math.max(0, Date.now() - bStart);
        networkSuccess = true;
      } catch (err) {
        lastError = err;
        if (isGovernanceBlockError(err)) {
          return {
            findings: [],
            attempted,
            networkSuccess: false,
            governanceError: err,
            lastError: err,
            baselineMs: null
          };
        }
      }
    }

    for (const param of params) {
      const testUrl = new URL(url.href);
      testUrl.searchParams.set(param, payload);
      attempted += 1;

      const startTime = Date.now();
      try {
        const res = await this.fetch(testUrl.href);
        if (res?.isGovernanceBlock) {
          const gErr = new Error(res.reason || res.error || 'Blocked by governance policy');
          gErr.isGovernanceBlock = true;
          governanceError = gErr;
          lastError = gErr;
          break;
        }
        networkSuccess = true;
        const duration = Math.max(0, Date.now() - startTime);

        if (this.isVulnerable(res, payload, signatureType, duration, { baselineMs, delayThresholdMs })) {
          findings.push({
            parameter: param,
            payload,
            type: signatureType,
            url: testUrl.href,
            ...(res?.trafficId !== undefined ? { trafficId: res.trafficId } : {})
          });
        }
      } catch (err) {
        lastError = err;
        if (isGovernanceBlockError(err)) {
          governanceError = err;
          break;
        }
      }
    }

    return {
      findings,
      attempted,
      networkSuccess,
      governanceError,
      lastError,
      baselineMs
    };
  }

  /**
   * Identifies query parameters in a URL and generates test cases (returns Array of findings).
   */
  async fuzz(targetUrl, payload, signatureType = 'REFLECTED', options = {}) {
    const detail = await this.fuzzDetailed(targetUrl, payload, signatureType, options);
    return detail.findings;
  }

  /**
   * Internal logic to decide if a response matches a vulnerability signature.
   */
  isVulnerable(res, payload, type, duration, options = {}) {
    if (!res || typeof res !== 'object') return false;
    const body = typeof res.text === 'string' ? res.text : '';

    switch (type) {
      case 'XSS_REFLECTED': {
        const contentType = getHeader(res.headers, 'content-type').toLowerCase();
        if (contentType.includes('application/json') && !/^\s*</.test(body)) {
          return false;
        }
        return Boolean(payload) && body.includes(payload);
      }

      case 'SQLI_ERROR': {
        const sqlErrors = [
          'sql syntax', 'mysql_fetch', 'ora-00933', 'postgresql query failed',
          'sqlite3::exception', 'dynamic sql generation', 'unclosed quotation mark'
        ];
        const lowBody = body.toLowerCase();
        return sqlErrors.some(err => lowBody.includes(err));
      }

      case 'SQLI_TIME': {
        const baselineMs = options?.baselineMs;
        const delayThresholdMs = Number.isFinite(Number(options?.delayThresholdMs)) && Number(options.delayThresholdMs) > 0
          ? Number(options.delayThresholdMs)
          : 4500;
        if (typeof baselineMs !== 'number' || !Number.isFinite(baselineMs)) {
          return false;
        }
        return duration >= baselineMs + delayThresholdMs;
      }

      default:
        return false;
    }
  }
}
