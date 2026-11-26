import { URL } from 'node:url';
import { getSampleFieldValue } from './crawler.js';

const GOVERNANCE_ERROR_CODES = new Set([
  'SSRF_POLICY_BLOCKED',
  'TARGET_RULE_BLOCKED',
  'TARGET_OUT_OF_SCOPE',
  'DNS_REBIND_OR_PRIVATE_IP'
]);

export function isGovernanceBlockError(err) {
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

const SQL_ERRORS = [
  'sql syntax',
  'mysql_fetch',
  'ora-00933',
  'postgresql query failed',
  'sqlite3::exception',
  'dynamic sql generation',
  'unclosed quotation mark'
];

const FORBIDDEN_FORM_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function normalizeUrlForFormMatch(rawUrl) {
  try {
    const parsed = new URL(String(rawUrl ?? '').trim());
    const cleanPath = (parsed.pathname || '/').replace(/\/+$/, '') || '/';
    return `${parsed.origin}${cleanPath}`;
  } catch {
    return '';
  }
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

    const WRITE_FORM_METHODS = new Set(['POST', 'PUT', 'PATCH']);
    const rawForms = Array.isArray(options?.discoveredForms) ? options.discoveredForms : [];
    const matchingPostForms = [];
    if (rawForms.length > 0) {
      const normTarget = normalizeUrlForFormMatch(url.href);
      if (normTarget) {
        const seenFormKeys = new Set();
        for (const f of rawForms) {
          if (!f || typeof f !== 'object') continue;
          const fMethod = String(f.method || '').toUpperCase();
          if (!WRITE_FORM_METHODS.has(fMethod)) continue;
          if (!Array.isArray(f.fields) || f.fields.length === 0) continue;
          const normAction = normalizeUrlForFormMatch(f.actionUrl);
          if (!normAction) continue;
          const normPage = normalizeUrlForFormMatch(f.pageUrl);
          if (normAction === normTarget || normPage === normTarget) {
            const fieldNames = f.fields
              .map(field => (typeof field?.name === 'string' ? field.name.trim() : ''))
              .filter(Boolean);
            if (fieldNames.length === 0) continue;
            const dedupKey = `${fMethod}::${f.actionUrl}::${fieldNames.join(',')}`;
            if (!seenFormKeys.has(dedupKey)) {
              seenFormKeys.add(dedupKey);
              matchingPostForms.push(f);
            }
          }
        }
      }
    }

    if (params.length === 0 && matchingPostForms.length === 0) {
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

    if (params.length > 0 && signatureType === 'SQLI_TIME') {
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

    let sqliErrorBaselineFetched = false;
    let sqliErrorBaselineRes = null;

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
          let isBaselineFalsePositive = false;
          if (
            signatureType === 'SQLI_ERROR' &&
            Number(res?.status ?? 200) === 200 &&
            testUrl.href !== url.href
          ) {
            if (!sqliErrorBaselineFetched) {
              sqliErrorBaselineFetched = true;
              try {
                const bRes = await this.fetch(url.href);
                if (bRes?.isGovernanceBlock) {
                  const gErr = new Error(bRes.reason || bRes.error || 'Blocked by governance policy');
                  gErr.isGovernanceBlock = true;
                  governanceError = gErr;
                  lastError = gErr;
                  break;
                }
                sqliErrorBaselineRes = bRes;
              } catch (bErr) {
                if (isGovernanceBlockError(bErr)) {
                  governanceError = bErr;
                  lastError = bErr;
                  break;
                }
              }
            }

            if (
              sqliErrorBaselineRes &&
              Number(sqliErrorBaselineRes.status ?? 200) === 200 &&
              typeof sqliErrorBaselineRes.text === 'string' &&
              typeof res.text === 'string'
            ) {
              if (sqliErrorBaselineRes.text === res.text) {
                isBaselineFalsePositive = true;
              } else {
                const lowProbe = res.text.toLowerCase();
                const lowBase = sqliErrorBaselineRes.text.toLowerCase();
                const matchedInProbe = SQL_ERRORS.filter(sig => lowProbe.includes(sig));
                if (matchedInProbe.length > 0 && matchedInProbe.every(sig => lowBase.includes(sig))) {
                  isBaselineFalsePositive = true;
                }
              }
            }
          }

          if (!isBaselineFalsePositive) {
            findings.push({
              parameter: param,
              payload,
              type: signatureType,
              url: testUrl.href,
              ...(res?.trafficId !== undefined ? { trafficId: res.trafficId } : {})
            });
          }
        }
      } catch (err) {
        lastError = err;
        if (isGovernanceBlockError(err)) {
          governanceError = err;
          break;
        }
      }
    }

    if (!governanceError && matchingPostForms.length > 0) {
      const isReflectedCheck = signatureType === 'REFLECTED' || signatureType === 'XSS_REFLECTED';
      const sameOriginVerificationUrls = [];
      if (isReflectedCheck && Array.isArray(options?.verificationUrls) && options.verificationUrls.length > 0) {
        const seenVerify = new Set();
        for (const rawVerifyUrl of options.verificationUrls) {
          if (sameOriginVerificationUrls.length >= 3) break;
          if (typeof rawVerifyUrl !== 'string' || !rawVerifyUrl.trim()) continue;
          try {
            const parsedVerify = new URL(rawVerifyUrl.trim(), url.origin);
            if (!['http:', 'https:'].includes(parsedVerify.protocol)) continue;
            if (parsedVerify.origin !== url.origin) continue;
            const cleanHref = parsedVerify.href;
            if (seenVerify.has(cleanHref)) continue;
            seenVerify.add(cleanHref);
            sameOriginVerificationUrls.push(cleanHref);
          } catch {
            continue;
          }
        }
      }
      const storedVerifiedUrlsForPayload = new Set();

      for (const form of matchingPostForms.slice(0, 5)) {
        if (governanceError) break;
        const formMethod = String(form.method || 'POST').toUpperCase();
        const reqMethod = WRITE_FORM_METHODS.has(formMethod) ? formMethod : 'POST';
        const isJsonForm = String(form.contentType || '').toLowerCase() === 'json';
        const reqHeaders = {
          'Content-Type': isJsonForm ? 'application/json' : 'application/x-www-form-urlencoded'
        };
        const serializeFormBody = (paramsObj) => {
          if (isJsonForm) {
            return JSON.stringify(paramsObj);
          }
          return new URLSearchParams(
            Object.entries(paramsObj).map(([k, v]) => [k, String(v ?? '')])
          ).toString();
        };

        const defaultFormParams = Object.create(null);
        if (form.hiddenFields && typeof form.hiddenFields === 'object') {
          for (const [k, v] of Object.entries(form.hiddenFields)) {
            const key = String(k || '').trim();
            if (!key || FORBIDDEN_FORM_KEYS.has(key)) continue;
            defaultFormParams[key] = String(v ?? '');
          }
        }
        for (const f of form.fields) {
          const fName = typeof f?.name === 'string' ? f.name.trim() : '';
          if (!fName || FORBIDDEN_FORM_KEYS.has(fName)) continue;
          defaultFormParams[fName] = getSampleFieldValue(f);
        }

        const defaultBodyStr = serializeFormBody(defaultFormParams);

        let formBaselineMs = baselineMs;
        if (signatureType === 'SQLI_TIME') {
          attempted += 1;
          const bStart = Date.now();
          try {
            const bRes = await this.fetch(form.actionUrl, {
              method: reqMethod,
              headers: reqHeaders,
              body: defaultBodyStr
            });
            if (bRes?.isGovernanceBlock) {
              const gErr = new Error(bRes.reason || bRes.error || 'Blocked by governance policy');
              gErr.isGovernanceBlock = true;
              governanceError = gErr;
              lastError = gErr;
              break;
            }
            formBaselineMs = Math.max(0, Date.now() - bStart);
            if (baselineMs === null) baselineMs = formBaselineMs;
            networkSuccess = true;
          } catch (err) {
            lastError = err;
            if (isGovernanceBlockError(err)) {
              governanceError = err;
              break;
            }
          }
        }

        let postSqliErrorBaselineFetched = false;
        let postSqliErrorBaselineRes = null;

        for (const field of form.fields.slice(0, 10)) {
          const fieldName = typeof field?.name === 'string' ? field.name.trim() : '';
          if (!fieldName || FORBIDDEN_FORM_KEYS.has(fieldName)) continue;

          const probeParams = { ...defaultFormParams, [fieldName]: payload };
          const bodyStr = serializeFormBody(probeParams);

          attempted += 1;
          const startTime = Date.now();
          try {
            const res = await this.fetch(form.actionUrl, {
              method: reqMethod,
              headers: reqHeaders,
              body: bodyStr
            });
            if (res?.isGovernanceBlock) {
              const gErr = new Error(res.reason || res.error || 'Blocked by governance policy');
              gErr.isGovernanceBlock = true;
              governanceError = gErr;
              lastError = gErr;
              break;
            }
            networkSuccess = true;
            const duration = Math.max(0, Date.now() - startTime);

            if (this.isVulnerable(res, payload, signatureType, duration, { baselineMs: formBaselineMs, delayThresholdMs })) {
              let isBaselineFalsePositive = false;
              if (
                signatureType === 'SQLI_ERROR' &&
                Number(res?.status ?? 200) === 200 &&
                bodyStr !== defaultBodyStr
              ) {
                if (!postSqliErrorBaselineFetched) {
                  postSqliErrorBaselineFetched = true;
                  try {
                    const bRes = await this.fetch(form.actionUrl, {
                      method: reqMethod,
                      headers: reqHeaders,
                      body: defaultBodyStr
                    });
                    if (bRes?.isGovernanceBlock) {
                      const gErr = new Error(bRes.reason || bRes.error || 'Blocked by governance policy');
                      gErr.isGovernanceBlock = true;
                      governanceError = gErr;
                      lastError = gErr;
                      break;
                    }
                    postSqliErrorBaselineRes = bRes;
                  } catch (bErr) {
                    if (isGovernanceBlockError(bErr)) {
                      governanceError = bErr;
                      lastError = bErr;
                      break;
                    }
                  }
                }

                if (
                  postSqliErrorBaselineRes &&
                  Number(postSqliErrorBaselineRes.status ?? 200) === 200 &&
                  typeof postSqliErrorBaselineRes.text === 'string' &&
                  typeof res.text === 'string'
                ) {
                  if (postSqliErrorBaselineRes.text === res.text) {
                    isBaselineFalsePositive = true;
                  } else {
                    const lowProbe = res.text.toLowerCase();
                    const lowBase = postSqliErrorBaselineRes.text.toLowerCase();
                    const matchedInProbe = SQL_ERRORS.filter(sig => lowProbe.includes(sig));
                    if (matchedInProbe.length > 0 && matchedInProbe.every(sig => lowBase.includes(sig))) {
                      isBaselineFalsePositive = true;
                    }
                  }
                }
              }

              if (!isBaselineFalsePositive) {
                findings.push({
                  parameter: fieldName,
                  payload,
                  type: signatureType,
                  url: form.actionUrl,
                  method: reqMethod,
                  ...(res?.trafficId !== undefined ? { trafficId: res.trafficId } : {})
                });
              }
            } else if (isReflectedCheck && sameOriginVerificationUrls.length > 0) {
              for (const verifyUrl of sameOriginVerificationUrls) {
                if (storedVerifiedUrlsForPayload.has(verifyUrl)) continue;
                attempted += 1;
                try {
                  const vRes = await this.fetch(verifyUrl);
                  if (vRes?.isGovernanceBlock) {
                    const gErr = new Error(vRes.reason || vRes.error || 'Blocked by governance policy');
                    gErr.isGovernanceBlock = true;
                    governanceError = gErr;
                    lastError = gErr;
                    break;
                  }
                  networkSuccess = true;
                  if (this.isVulnerable(vRes, payload, 'REFLECTED', 0)) {
                    storedVerifiedUrlsForPayload.add(verifyUrl);
                    findings.push({
                      parameter: fieldName,
                      payload,
                      type: 'STORED_REFLECTED',
                      storedOnUrl: verifyUrl,
                      url: form.actionUrl,
                      method: reqMethod,
                      ...(vRes?.trafficId !== undefined
                        ? { trafficId: vRes.trafficId }
                        : res?.trafficId !== undefined
                          ? { trafficId: res.trafficId }
                          : {})
                    });
                    break;
                  }
                } catch (vErr) {
                  lastError = vErr;
                  if (isGovernanceBlockError(vErr)) {
                    governanceError = vErr;
                    break;
                  }
                }
              }
              if (governanceError) break;
            }
          } catch (err) {
            lastError = err;
            if (isGovernanceBlockError(err)) {
              governanceError = err;
              break;
            }
          }
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
      case 'REFLECTED':
      case 'XSS_REFLECTED': {
        const contentType = getHeader(res.headers, 'content-type').toLowerCase();
        if (contentType.includes('application/json') && !/^\s*</.test(body)) {
          return false;
        }
        return Boolean(payload) && body.includes(payload);
      }

      case 'SQLI_ERROR': {
        const lowBody = body.toLowerCase();
        return SQL_ERRORS.some(err => lowBody.includes(err));
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
