import {
  isHtmlOrScript,
  isRedirectedToDifferentPath,
  isFrameworkRouteErrorResponse,
  parseJsonObject,
  extractVerbatimSnippet,
  confirmReproducible
} from '../core/check-verify.js';

export const tags = ['laravel'];

const IGNITION_ENDPOINT = '/_ignition/execute-solution';
const IGNITION_CANARY_ENDPOINT = '/_ignition/secscan-canary-404';
const IGNITION_BODY = JSON.stringify({
  solution   : 'Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution',
  parameters : { variableName: 'test', viewFile: '/etc/passwd' }
});
const IGNITION_HEADERS = { 'Content-Type': 'application/json', 'Accept': 'application/json' };

function hasStrictIgnitionSignature(lowerText) {
  return (
    lowerText.includes('facade\\ignition') ||
    lowerText.includes('spatie\\laravelignition') ||
    lowerText.includes('spatie\\laravel-ignition') ||
    lowerText.includes('makeviewvariableoptionalsolution') ||
    lowerText.includes('executesolutioncontroller') ||
    lowerText.includes('runnablesolutionsenabled')
  );
}

function isConfirmedIgnitionRce(res, reqUrl) {
  if (!res) return false;
  const status = Number(res.status ?? 200);
  if (
    status === 404 ||
    status === 405 ||
    status === 403 ||
    status === 401 ||
    status === 410 ||
    status === 419 ||
    status === 429 ||
    (status >= 300 && status < 400)
  ) {
    return false;
  }
  if (reqUrl && isRedirectedToDifferentPath(res, reqUrl)) {
    return false;
  }

  const text = typeof res.text === 'string' ? res.text : '';
  if (isFrameworkRouteErrorResponse(res, text)) {
    return false;
  }

  const lower = text.toLowerCase();
  const isStrictFrameworkSignature = hasStrictIgnitionSignature(lower);

  if (isHtmlOrScript(res, text)) {
    return isStrictFrameworkSignature && (lower.includes('whoops') || lower.includes('stack trace') || lower.includes('exception'));
  }

  const json = parseJsonObject(text);
  if (json && !Array.isArray(json)) {
    const jsonMsg = String(json.message || json.exception || json.solution || '').toLowerCase();
    const jsonFile = String(json.file || '').toLowerCase();
    if (
      status === 200 &&
      (Object.keys(json).length === 0 || json.status === 'ok' || json.success === true)
    ) {
      return true;
    }
    if (
      isStrictFrameworkSignature ||
      jsonMsg.includes('facade\\ignition') ||
      jsonMsg.includes('spatie\\laravelignition') ||
      jsonMsg.includes('makeviewvariableoptionalsolution') ||
      jsonFile.includes('ignition') ||
      (status === 500 && jsonMsg.includes('ignition') && (json.exception || json.trace || json.file))
    ) {
      return true;
    }
    return false;
  }

  return isStrictFrameworkSignature;
}

function isSuspiciousIgnition500(res, reqUrl) {
  if (!res || res.status !== 500) return false;
  if (reqUrl && isRedirectedToDifferentPath(res, reqUrl)) return false;
  const text = typeof res.text === 'string' ? res.text : '';
  if (isFrameworkRouteErrorResponse(res, text)) return false;
  const lower = text.toLowerCase();
  return (
    hasStrictIgnitionSignature(lower) ||
    lower.includes('ignition') ||
    lower.includes('whoops')
  );
}

/**
 * Tests for Ignition debug page / CVE-2021-3129 (Laravel RCE via Ignition).
 */
export default async function run(target, fetchWithRetry) {
  const url = `${target}${IGNITION_ENDPOINT}`;
  const fetchOpts = { method: 'POST', headers: IGNITION_HEADERS, body: IGNITION_BODY, followRedirects: false };

  try {
    const res = await fetchWithRetry(url, fetchOpts);
    const text = typeof res?.text === 'string' ? res.text : '';

    if (isConfirmedIgnitionRce(res, url)) {
      const { confirmed, res: confirmRes } = await confirmReproducible(
        url,
        fetchWithRetry,
        fetchOpts,
        (r) => isConfirmedIgnitionRce(r, url)
      );
      if (!confirmed) {
        return { name: 'ignition RCE (CVE-2021-3129)', status: 'SAFE', severity: 'NONE' };
      }

      const finalRes = confirmRes || res;
      const finalText = typeof finalRes?.text === 'string' ? finalRes.text : text;

      // If matched purely on a generic 200 JSON (e.g. {} or {"status":"ok"}) without explicit Ignition class names,
      // probe a canary non-existent Ignition route to rule out catch-all 200 JSON endpoints.
      if (finalRes.status === 200 && !hasStrictIgnitionSignature(finalText.toLowerCase())) {
        try {
          const canaryUrl = `${target}${IGNITION_CANARY_ENDPOINT}`;
          const canaryRes = await fetchWithRetry(canaryUrl, fetchOpts);
          if (canaryRes && canaryRes.status === 200 && !isFrameworkRouteErrorResponse(canaryRes, canaryRes.text)) {
            return { name: 'ignition RCE (CVE-2021-3129)', status: 'SAFE', severity: 'NONE' };
          }
        } catch {
          // Canary failed or 404'd — proceed
        }
      }

      const snippet = extractVerbatimSnippet(finalText, /facade\\ignition|spatie\\laravelignition|MakeViewVariableOptionalSolution|exception/i)
        || `HTTP ${finalRes.status} Ignition response at ${IGNITION_ENDPOINT}`;
      const quotes = snippet.length >= 8 ? [snippet] : [];

      return {
        name          : 'ignition RCE (CVE-2021-3129)',
        status        : 'VULNERABLE',
        severity      : 'CRITICAL',
        path          : IGNITION_ENDPOINT,
        cve           : 'CVE-2021-3129',
        cveIds        : ['CVE-2021-3129'],
        detail        : `Confirmed reproducible Ignition solution execution endpoint at ${IGNITION_ENDPOINT} (HTTP ${finalRes.status})`,
        files         : [{
          path         : IGNITION_ENDPOINT,
          url,
          method       : 'POST',
          status       : finalRes.status,
          matchedSignal: 'Ignition exception/solution response',
          reproducible : true,
          preview      : snippet
        }],
        reproVerified : true,
        poeLevel      : quotes.length > 0 ? 3 : 2,
        ...(quotes.length > 0 ? { evidenceQuotes: quotes } : {}),
        ...(finalRes.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {}),
        fix           : "CRITICAL: Disable Laravel debug mode (APP_DEBUG=false) in your .env file immediately. Update 'facade/ignition' to a non-vulnerable version or uninstall it in production."
      };
    }

    if (isSuspiciousIgnition500(res, url)) {
      const { confirmed, res: confirmRes } = await confirmReproducible(
        url,
        fetchWithRetry,
        fetchOpts,
        (r) => isSuspiciousIgnition500(r, url)
      );
      if (!confirmed) {
        return { name: 'ignition RCE (CVE-2021-3129)', status: 'SAFE', severity: 'NONE' };
      }

      const finalRes = confirmRes || res;
      const snippet = extractVerbatimSnippet(text, /error|exception|ignition|whoops/i) || `HTTP 500 on POST ${IGNITION_ENDPOINT}`;
      return {
        name          : 'ignition RCE (CVE-2021-3129)',
        status        : 'SUSPICIOUS',
        severity      : 'HIGH',
        path          : IGNITION_ENDPOINT,
        cve           : 'CVE-2021-3129',
        cveIds        : ['CVE-2021-3129'],
        detail        : `POST ${IGNITION_ENDPOINT} consistently returned HTTP 500 — verify Ignition package is disabled/patched`,
        files         : [{
          path         : IGNITION_ENDPOINT,
          url,
          method       : 'POST',
          status       : 500,
          matchedSignal: 'HTTP 500 on /_ignition/execute-solution',
          reproducible : true,
          preview      : snippet
        }],
        reproVerified : true,
        poeLevel      : 2,
        ...(snippet.length >= 8 ? { evidenceQuotes: [snippet] } : {}),
        ...(finalRes.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {}),
        fix           : "Ensure 'APP_DEBUG=false' is set in production and that the '/_ignition' endpoints are blocked or removed from the production environment."
      };
    }

    return { name: 'ignition RCE (CVE-2021-3129)', status: 'SAFE', severity: 'NONE' };

  } catch (e) {
    return { name: 'ignition RCE (CVE-2021-3129)', status: 'ERROR', severity: 'LOW', reason: e.message };
  }
}
