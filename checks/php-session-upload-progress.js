import { isPhpVersionAffected, parsePhpVersion } from '../core/cve-utils.js';

export const tags = ['php', 'laravel', 'symfony', 'wordpress', 'drupal'];

const PHP2SHELL_RANGES = [
  '>=5.4.0 <8.2.35',
  '>=8.3.0 <8.3.36',
  '>=8.4.0 <8.4.27',
  '>=8.5.0 <8.5.12'
];

export const meta = {
  id: 'php-session-upload-progress',
  title: 'PHP session.upload_progress LFI-to-RCE & Serializer Mismatch (CVE-2026-109618 / CVE-2026-109619)',
  category: 'Known Vulnerabilities',
  plainExplanation:
    'Passively and safely inspects PHP targets for the php2shell (CVE-2026-109618 / CVE-2026-109619) session.upload_progress multipart PHPSESSID fixation, raw filename session injection, var_destroy UAF, and FPM PS(serializer) handler mismatch conditions.',
  whyItMatters:
    'In PHP 5.4.0 through 8.5.11, the rfc1867 session.upload_progress handler accepts PHPSESSID from multipart POST form data even when session.use_only_cookies=On and stores unsanitized filenames in the session file, while php_rshutdown_session_globals leaks PS(serializer) across FPM requests and var_destroy triggers a heap use-after-free during deserialization.',
  defaultFix:
    'Upgrade PHP to 8.2.35+, 8.3.36+, 8.4.27+, or 8.5.12+ (or 8.2.36+ / 8.3.37+ / 8.4.28+ / 8.5.13+ for the Nov 2026 CVE-2026-115560 fix). Set session.upload_progress.enabled = Off, session.use_only_cookies = On, session.use_strict_mode = On, and enforce a uniform session.serialize_handler = php_serialize.',
  cwe: 'CWE-384',
  owasp: 'A07:2021-Identification and Authentication Failures',
  cvssScore: 9.8,
  cveIds: ['CVE-2026-109618', 'CVE-2026-109619'],
  references: [
    'https://nvd.nist.gov/vuln/detail/CVE-2026-109618',
    'https://nvd.nist.gov/vuln/detail/CVE-2026-109619',
    'https://github.com/php/php-src/pull/22113',
    'https://www.php.net/ChangeLog-8.php'
  ]
};

const GOVERNANCE_ERROR_CODES = new Set([
  'SSRF_POLICY_BLOCKED',
  'TARGET_RULE_BLOCKED',
  'TARGET_OUT_OF_SCOPE',
  'DNS_REBIND_OR_PRIVATE_IP'
]);

const DISTRO_MARKER_RE = /(?:[~+]deb\d*|deb\d{1,2}u\d+|\bdebian\b|ubuntu|\bel[789]\b|\.el[789]\b|alpine|red\s*hat|redhat|centos|amzn|sles)/i;

function isGovernanceBlock(err) {
  if (!err) return false;
  if (err.isGovernanceBlock === true || GOVERNANCE_ERROR_CODES.has(err.code)) return true;
  const msg = String(err.message || '');
  return (
    msg.startsWith('Redirect blocked by SSRF policy') ||
    msg.startsWith('Request blocked by SSRF policy') ||
    msg.startsWith('[SECSCAN platform control')
  );
}

function getHeader(headers, key) {
  if (!headers || typeof headers !== 'object') return '';
  const lower = key.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (String(k).toLowerCase() === lower) {
      return String(v ?? '');
    }
  }
  return '';
}

export async function run(targetInput, fetchWithRetry) {
  const target = Array.isArray(targetInput) ? targetInput[0] : targetInput;
  if (!target || typeof target !== 'string') {
    return {
      name: meta.title,
      checkId: meta.id,
      target: String(target || ''),
      status: 'SAFE',
      detail: 'No valid target URL provided.'
    };
  }

  let res;
  try {
    res = await fetchWithRetry(target, { followRedirects: false });
  } catch (err) {
    if (isGovernanceBlock(err)) throw err;
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      status: 'ERROR',
      detail: `Target request failed: ${err.message}`
    };
  }

  if (!res || res.status === 404 || res.status === 405 || res.status === 410) {
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      status: 'SAFE',
      detail: 'No PHP session.upload_progress exposure detected.'
    };
  }

  const poweredBy = getHeader(res.headers, 'x-powered-by');
  const server = getHeader(res.headers, 'server');
  const setCookie = getHeader(res.headers, 'set-cookie');
  const body = String(res.text || '');

  const bannerSource = [poweredBy, server].filter(Boolean).join(' ');
  const parsedVer = parsePhpVersion(bannerSource);
  const phpVersionStr = parsedVer?.normalized || parsedVer?.version || null;
  const isDistroBuild = Boolean(parsedVer?.isDistroBackport) || DISTRO_MARKER_RE.test(bannerSource);

  // Check for explicit phpinfo / diagnostic configuration disclosure of session.upload_progress.enabled = On
  const uploadProgressEnabledMatch = body.match(
    /session\.upload_progress\.enabled\s*(?:<\/td>\s*<td[^>]*>\s*|=|=>|:)\s*(On|1|true)\b/i
  );
  const serializeHandlerMismatchMatch = body.match(
    /session\.serialize_handler\s*(?:<\/td>\s*<td[^>]*>\s*|=|=>|:)\s*(php)\s*(?:<\/td>\s*<td[^>]*>\s*)(php_serialize)\b/i
  );
  const useOnlyCookiesOffMatch = body.match(
    /session\.use_only_cookies\s*(?:<\/td>\s*<td[^>]*>\s*|=|=>|:)\s*(Off|0|false)\b/i
  );
  const hasPhpSessionCookie = /\bPHPSESSID=[A-Za-z0-9,-]{8,}/i.test(setCookie);

  const findings = [];
  const evidenceQuotes = [];

  if (parsedVer && parsedVer.hasPatch && isPhpVersionAffected(parsedVer, PHP2SHELL_RANGES)) {
    const versionQuote = poweredBy && poweredBy.toLowerCase().includes('php/')
      ? `X-Powered-By: ${poweredBy}`
      : `Server: ${server}`;
    evidenceQuotes.push(versionQuote);

    const hasActiveUploadProgressSignal = Boolean(
      uploadProgressEnabledMatch || serializeHandlerMismatchMatch || useOnlyCookiesOffMatch
    );

    if (uploadProgressEnabledMatch) {
      evidenceQuotes.push(uploadProgressEnabledMatch[0].replace(/\s+/g, ' ').trim());
    }
    if (serializeHandlerMismatchMatch) {
      evidenceQuotes.push(serializeHandlerMismatchMatch[0].replace(/\s+/g, ' ').trim());
    }

    findings.push({
      cveIds: ['CVE-2026-109618', 'CVE-2026-109619'],
      version: phpVersionStr,
      url: target,
      status: res.status,
      hasSessionCookie: hasPhpSessionCookie,
      uploadProgressConfirmed: Boolean(uploadProgressEnabledMatch),
      serializeHandlerMismatch: Boolean(serializeHandlerMismatchMatch),
      issue: `PHP ${phpVersionStr} is in the affected range for CVE-2026-109618 & CVE-2026-109619 (php2shell session.upload_progress PHPSESSID fixation, raw filename session injection, var_destroy UAF & FPM serializer leak)${hasActiveUploadProgressSignal ? ' with confirmed active session.upload_progress / serializer configuration exposure' : ''}${hasPhpSessionCookie ? ' and active PHPSESSID session handling' : ''}.`,
      matchedSignal: versionQuote
    });

    const isVulnerable = !isDistroBuild && (hasActiveUploadProgressSignal || hasPhpSessionCookie);
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      url: target,
      status: isVulnerable ? 'VULNERABLE' : 'SUSPICIOUS',
      severity: isVulnerable ? 'CRITICAL' : 'HIGH',
      cveIds: ['CVE-2026-109618', 'CVE-2026-109619'],
      findings,
      evidenceQuotes: Array.from(new Set(evidenceQuotes)).filter(q => q.length >= 8).slice(0, 5),
      poeLevel: 3,
      ...(res.trafficId ? { trafficId: res.trafficId } : {}),
      detail: findings[0].issue
    };
  }

  // Even without a PHP version header, if a diagnostic page explicitly exposes session.upload_progress.enabled = On
  // along with serialize_handler mismatch or use_only_cookies = Off:
  if (
    res.status === 200 &&
    uploadProgressEnabledMatch &&
    (serializeHandlerMismatchMatch || useOnlyCookiesOffMatch)
  ) {
    const quote = uploadProgressEnabledMatch[0].replace(/\s+/g, ' ').trim();
    evidenceQuotes.push(quote);
    findings.push({
      cveIds: ['CVE-2026-109618', 'CVE-2026-109619'],
      url: target,
      status: res.status,
      issue: `Target exposes active PHP session.upload_progress.enabled=On alongside ${serializeHandlerMismatchMatch ? 'mixed session.serialize_handler (php vs php_serialize)' : 'session.use_only_cookies=Off'} (CVE-2026-109618 / CVE-2026-109619 precondition).`,
      matchedSignal: quote
    });

    return {
      name: meta.title,
      checkId: meta.id,
      target,
      url: target,
      status: 'SUSPICIOUS',
      severity: 'HIGH',
      cveIds: ['CVE-2026-109618', 'CVE-2026-109619'],
      findings,
      evidenceQuotes: Array.from(new Set(evidenceQuotes)).filter(q => q.length >= 8).slice(0, 5),
      poeLevel: 3,
      ...(res.trafficId ? { trafficId: res.trafficId } : {}),
      detail: findings[0].issue
    };
  }

  return {
    name: meta.title,
    checkId: meta.id,
    target,
    status: 'SAFE',
    detail: 'No vulnerable PHP session.upload_progress (CVE-2026-109618 / CVE-2026-109619) exposure detected.'
  };
}
