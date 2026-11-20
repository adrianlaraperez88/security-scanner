import {
  isHtmlOrScript,
  isRedirectedToDifferentPath,
  isFrameworkRouteErrorResponse,
  parseJsonObject,
  extractVerbatimSnippet,
  confirmReproducible
} from '../core/check-verify.js';

export const tags = ['laravel'];

const LIVEWIRE_JS_PATHS = [
  '/livewire/livewire.js',
  '/vendor/livewire/livewire/dist/livewire.js',
];

const UPDATE_PAYLOAD = JSON.stringify({
  _token    : 'probe',
  components: [{ snapshot: '{}', updates: [], calls: [] }]
});
const UPDATE_HEADERS = { 'Content-Type': 'application/json', 'Accept': 'application/json' };

function extractLivewireVersion(text = '') {
  if (typeof text !== 'string' || !text) return null;
  const m =
    /Livewire\s+v?(\d+\.\d+\.\d+)/i.exec(text) ||
    /["']?version["']?\s*[:=]\s*["']v?(\d+\.\d+\.\d+)["']/i.exec(text);
  return m ? m[1] : null;
}

function isVulnerableLivewireVersion(version) {
  if (!version) return false;
  const parts = String(version).split('.').map(Number);
  if (parts.length < 3 || parts.some(n => !Number.isFinite(n))) return false;
  const [major, minor, patch] = parts;
  if (major === 3) {
    return minor < 6 || (minor === 6 && patch < 4);
  }
  if (major === 2) {
    return minor < 12 || (minor === 12 && patch < 7);
  }
  return major < 2;
}

function isLivewireUpdateJson(res, reqUrl) {
  if (!res || res.status !== 200 || isRedirectedToDifferentPath(res, reqUrl)) return false;
  const text = typeof res.text === 'string' ? res.text : '';
  if (!text || isHtmlOrScript(res, text)) return false;
  const json = parseJsonObject(text);
  if (!json || Array.isArray(json)) return false;
  return (
    Object.hasOwn(json, 'effects') ||
    Object.hasOwn(json, 'components') ||
    Object.hasOwn(json, 'assets') ||
    (typeof json.html === 'string' && Object.keys(json).length >= 1)
  );
}

function isLivewireUploadExposed(res, reqUrl) {
  if (!res || isRedirectedToDifferentPath(res, reqUrl)) return false;
  const text = typeof res.text === 'string' ? res.text : '';
  if (isFrameworkRouteErrorResponse(res, text)) return false;
  if (res.status === 422) {
    return !isHtmlOrScript(res, text);
  }
  if (res.status === 200 && text && !isHtmlOrScript(res, text)) {
    const json = parseJsonObject(text);
    return Boolean(json && !Array.isArray(json) && (Array.isArray(json.paths) || typeof json.path === 'string' || typeof json.signedUrl === 'string'));
  }
  return false;
}

export default async function run(target, fetchWithRetry) {
  let livewireDetected = false;
  let detectedVersion = null;
  let jsPathHit = null;
  let jsUrlHit = null;
  let jsTrafficId;

  for (const jsPath of LIVEWIRE_JS_PATHS) {
    try {
      const jsUrl = `${target}${jsPath}`;
      const res = await fetchWithRetry(jsUrl, { followRedirects: false });
      const text = typeof res?.text === 'string' ? res.text : '';
      if (res?.status === 200 && !isRedirectedToDifferentPath(res, jsUrl) && !isHtmlOrScript(res, text) && text.includes('Livewire')) {
        livewireDetected = true;
        detectedVersion = extractLivewireVersion(text);
        jsPathHit = jsPath;
        jsUrlHit = jsUrl;
        jsTrafficId = res.trafficId;
        break;
      }
      // Note: unit tests call mockFetchMap where livewire.js has no content-type header and doesn't start with <html
    } catch { /* skip */ }
  }

  if (!livewireDetected) {
    try {
      const home = await fetchWithRetry(target);
      const rawHome = typeof home?.text === 'string' ? home.text : '';
      const body = rawHome.toLowerCase();
      if (
        body.includes('/livewire/livewire.js') ||
        body.includes('window.livewire_token') ||
        body.includes('wire:snapshot') ||
        body.includes('wire:id') ||
        body.includes('data-livewire')
      ) {
        livewireDetected = true;
        if (!detectedVersion) {
          detectedVersion = extractLivewireVersion(rawHome);
        }
      }
    } catch { /* skip */ }
  }

  const hasVulnerableVersion = isVulnerableLivewireVersion(detectedVersion);

  // Probe POST /livewire/update (CVE-2025-54068)
  const updateUrl = `${target}/livewire/update`;
  const updateOpts = { method: 'POST', headers: UPDATE_HEADERS, body: UPDATE_PAYLOAD, followRedirects: false };
  let updateRes = null;
  try {
    updateRes = await fetchWithRetry(updateUrl, updateOpts);
  } catch { /* endpoint unreachable */ }

  if (isLivewireUpdateJson(updateRes, updateUrl)) {
    const { confirmed, res: confirmRes } = await confirmReproducible(
      updateUrl,
      fetchWithRetry,
      updateOpts,
      (r) => isLivewireUpdateJson(r, updateUrl)
    );
    if (confirmed) {
      const finalRes = confirmRes || updateRes;
      const snippet = extractVerbatimSnippet(finalRes.text || updateRes.text || '', /effects|components|"html"/i)
        || 'HTTP 200 Livewire JSON update response';
      return {
        name          : 'livewire exposure (CVE-2025-54068)',
        status        : 'VULNERABLE',
        severity      : 'CRITICAL',
        path          : '/livewire/update',
        detail        : 'Confirmed reproducible /livewire/update JSON response — verify Livewire >= 3.6.4 (CVE-2025-54068)',
        fix           : 'CRITICAL: Update Livewire to version 3.6.4 or higher immediately to patch the hydration RCE (CVE-2025-54068).',
        cve           : 'CVE-2025-54068',
        cveIds        : ['CVE-2025-54068'],
        paths         : ['/livewire/update'],
        files         : [{
          path         : '/livewire/update',
          url          : updateUrl,
          method       : 'POST',
          status       : 200,
          matchedSignal: 'Livewire JSON effects/components response',
          reproducible : true,
          preview      : snippet
        }],
        reproVerified : true,
        poeLevel      : 3,
        evidenceQuotes: [snippet],
        ...(finalRes.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {})
      };
    }
  }

  // HTTP 422 on /livewire/update with dummy _token: 'probe' means the request bypassed CSRF and reached payload validation.
  // HTTP 419 means Laravel CSRF protection properly rejected the unauthenticated probe, so only flag 419 if a vulnerable Livewire version (< 3.6.4) is disclosed.
  if (
    (updateRes?.status === 422 && !isHtmlOrScript(updateRes, updateRes.text)) ||
    (updateRes?.status === 419 && hasVulnerableVersion)
  ) {
    const statusTarget = updateRes.status;
    const { confirmed, res: confirmRes } = await confirmReproducible(
      updateUrl,
      fetchWithRetry,
      updateOpts,
      (r) => r?.status === statusTarget
    );
    if (confirmed) {
      const finalRes = confirmRes || updateRes;
      const quote = detectedVersion
        ? `Livewire ${detectedVersion} with HTTP ${statusTarget} on POST /livewire/update`
        : `HTTP ${statusTarget} on POST /livewire/update`;
      return {
        name          : 'livewire exposure (CVE-2025-54068)',
        status        : 'SUSPICIOUS',
        severity      : 'HIGH',
        path          : '/livewire/update',
        ...(detectedVersion ? { version: detectedVersion } : {}),
        detail        : detectedVersion
          ? `Vulnerable Livewire ${detectedVersion} (< 3.6.4) detected with active /livewire/update endpoint (HTTP ${statusTarget}, CVE-2025-54068)`
          : `/livewire/update accepted unauthenticated request without CSRF rejection (HTTP ${statusTarget}) — confirm Livewire version >= 3.6.4 (CVE-2025-54068)`,
        fix           : 'Update Livewire to version 3.6.4+ (v3) or 2.12.7+ (v2) and ensure CSRF protection is active on all Livewire endpoints.',
        cve           : 'CVE-2025-54068',
        cveIds        : ['CVE-2025-54068'],
        paths         : ['/livewire/update'],
        files         : [{
          path         : '/livewire/update',
          url          : updateUrl,
          method       : 'POST',
          status       : statusTarget,
          matchedSignal: `HTTP ${statusTarget} Livewire update route`,
          reproducible : true,
          preview      : quote
        }],
        reproVerified : true,
        poeLevel      : 2,
        evidenceQuotes: [quote],
        ...(finalRes.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {})
      };
    }
  }

  // Probe POST /livewire/upload-file (CVE-2024-47823)
  const uploadUrl = `${target}/livewire/upload-file`;
  const uploadOpts = { method: 'POST', headers: UPDATE_HEADERS, body: '{}', followRedirects: false };
  let uploadRes = null;
  try {
    uploadRes = await fetchWithRetry(uploadUrl, uploadOpts);
  } catch { /* endpoint unreachable */ }

  if (isLivewireUploadExposed(uploadRes, uploadUrl)) {
    const { confirmed, res: confirmRes } = await confirmReproducible(
      uploadUrl,
      fetchWithRetry,
      uploadOpts,
      (r) => isLivewireUploadExposed(r, uploadUrl)
    );
    if (confirmed) {
      const finalRes = confirmRes || uploadRes;
      const snippet = extractVerbatimSnippet(finalRes.text || uploadRes.text || '', /message|path|error/i)
        || `HTTP ${finalRes.status} on POST /livewire/upload-file`;
      return {
        name          : 'livewire exposure (CVE-2024-47823)',
        status        : 'SUSPICIOUS',
        severity      : 'HIGH',
        path          : '/livewire/upload-file',
        detail        : `/livewire/upload-file is consistently accessible without CSRF rejection (HTTP ${finalRes.status}) — verify Livewire version >= 3.5.2 (CVE-2024-47823)`,
        fix           : 'Update Livewire to version 3.5.2+ (v3) or 2.12.7+ (v2) to patch the file upload extension bypass (CVE-2024-47823).',
        cve           : 'CVE-2024-47823',
        cveIds        : ['CVE-2024-47823'],
        paths         : ['/livewire/upload-file'],
        files         : [{
          path         : '/livewire/upload-file',
          url          : uploadUrl,
          method       : 'POST',
          status       : finalRes.status,
          matchedSignal: `HTTP ${finalRes.status} Livewire upload endpoint`,
          reproducible : true,
          preview      : snippet
        }],
        reproVerified : true,
        poeLevel      : 2,
        evidenceQuotes: [snippet],
        ...(finalRes.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {})
      };
    }
  }

  if (livewireDetected && hasVulnerableVersion) {
    const evidencePath = jsPathHit || '/';
    const evidenceUrl = jsUrlHit || target;
    const quote = `Livewire v${detectedVersion} exposed at ${evidencePath}`;
    return {
      name          : 'livewire exposure (CVE-2025-54068)',
      status        : 'SUSPICIOUS',
      severity      : 'MEDIUM',
      path          : evidencePath,
      version       : detectedVersion,
      cve           : 'CVE-2025-54068',
      cveIds        : ['CVE-2025-54068'],
      detail        : `Vulnerable Livewire v${detectedVersion} (< 3.6.4) detected at ${evidencePath} (CVE-2025-54068 / CVE-2024-47823)`,
      files         : [{
        path         : evidencePath,
        url          : evidenceUrl,
        method       : 'GET',
        status       : 200,
        matchedSignal: quote,
        reproducible : true,
        preview      : quote
      }],
      reproVerified : true,
      poeLevel      : 2,
      evidenceQuotes: [quote],
      ...(jsTrafficId !== undefined ? { trafficId: jsTrafficId } : {}),
      fix           : 'Ensure Livewire is updated to at least v3.6.4 (for v3) or v2.12.7 (for v2) to protect against known RCE and upload vulnerabilities.'
    };
  }

  return { name: 'livewire exposure (CVE-2025-54068)', status: 'SAFE', severity: 'NONE' };
}
