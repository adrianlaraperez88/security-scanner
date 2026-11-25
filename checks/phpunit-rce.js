import { createHash } from 'crypto';
import {
  isHtmlOrScript,
  isRedirectedToDifferentPath,
  isFrameworkRouteErrorResponse,
  parseJsonObject,
  extractVerbatimSnippet,
  confirmReproducible
} from '../core/check-verify.js';

export const tags = ['php', 'laravel', 'wordpress', 'drupal', 'magento', 'symfony', 'codeigniter', 'joomla'];

const PHPUNIT_PATHS = [
  '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
  '/vendor/phpunit/src/Util/PHP/eval-stdin.php',
  '/vendor/phpunit/phpunit/Util/PHP/eval-stdin.php',
];

const TOKEN     = 'secscan_rce_probe_2025';
const EXPECTED  = createHash('md5').update(TOKEN).digest('hex');
const PHP_PROBE = ['<' + '?php', `echo md5('${TOKEN}');`, '?' + '>'].join(' ');

export default async function run(target, fetchWithRetry) {
  for (const p of PHPUNIT_PATHS) {
    const url = `${target}${p}`;

    try {
      const getRes = await fetchWithRetry(url, { followRedirects: false });
      if (getRes?.status !== 200 || isRedirectedToDifferentPath(getRes, url)) continue;

      const getText = typeof getRes.text === 'string' ? getRes.text : '';
      if (isFrameworkRouteErrorResponse(getRes, getText)) continue;
      const getWasHtml = isHtmlOrScript(getRes, getText);

      // Step 2: Test POST execution
      const postOpts = {
        method : 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body   : PHP_PROBE,
      };
      let postRes = null;
      let rceConfirmed = false;
      try {
        postRes = await fetchWithRetry(url, postOpts);
        if (typeof postRes?.text === 'string' && postRes.text.includes(EXPECTED)) {
          // Verify reproducibility of RCE execution
          const { confirmed, res: confirmPost } = await confirmReproducible(
            url,
            fetchWithRetry,
            postOpts,
            (r) => typeof r?.text === 'string' && r.text.includes(EXPECTED)
          );
          if (confirmed) {
            rceConfirmed = true;
            postRes = confirmPost || postRes;
          }
        }
      } catch { /* POST failed */ }

      if (rceConfirmed) {
        const quote = extractVerbatimSnippet(postRes?.text || '', EXPECTED) || EXPECTED;
        return {
          name          : 'phpunit RCE (CVE-2017-9841)',
          status        : 'VULNERABLE',
          severity      : 'CRITICAL',
          path          : p,
          cve           : 'CVE-2017-9841',
          cveIds        : ['CVE-2017-9841'],
          detail        : `Confirmed reproducible unauthenticated RCE via ${p}`,
          files         : [{
            path         : p,
            url,
            method       : 'POST',
            status       : postRes?.status ?? 200,
            matchedSignal: `MD5(${TOKEN})=${EXPECTED}`,
            reproducible : true,
            preview      : quote
          }],
          reproVerified : true,
          poeLevel      : 3,
          evidenceQuotes: [quote],
          ...(postRes?.trafficId !== undefined ? { trafficId: postRes.trafficId } : {}),
          fix           : "CRITICAL: Remove 'vendor/phpunit' from your production server immediately. Ensure your web root is set correctly (e.g., to the 'public' or 'www' folder) so the 'vendor' directory is not web-accessible."
        };
      }

      // Skip SPA/HTML or JSON API catch-all 200 responses that are not real eval-stdin.php
      if (getWasHtml || Boolean(parseJsonObject(getText))) continue;

      const { confirmed, res: confirmGet } = await confirmReproducible(
        url,
        fetchWithRetry,
        { followRedirects: false },
        (r) => r?.status === 200 && !isRedirectedToDifferentPath(r, url) && !isHtmlOrScript(r, r.text) && !parseJsonObject(r.text)
      );
      if (!confirmed) continue;

      try {
        const canaryRes = await fetchWithRetry(`${target}/vendor/phpunit/.secscan_canary_404.php`, { followRedirects: false });
        if (canaryRes?.status === 200 && !isHtmlOrScript(canaryRes, canaryRes.text)) {
          continue;
        }
      } catch { /* canary 404/unreachable -> proceed */ }

      const finalRes = confirmGet || getRes;
      const finalText = typeof finalRes?.text === 'string' ? finalRes.text : '';
      const verbatimQuote =
        finalText.trim().length >= 8
          ? (extractVerbatimSnippet(finalText, /\S+/) || finalText.replace(/\s+/g, ' ').trim().slice(0, 120))
          : null;
      const quote = (verbatimQuote && verbatimQuote.length >= 8)
        ? verbatimQuote
        : `HTTP 200 non-HTML response on ${p}`;
      return {
        name          : 'phpunit RCE (CVE-2017-9841)',
        status        : 'SUSPICIOUS',
        severity      : 'HIGH',
        path          : p,
        cve           : 'CVE-2017-9841',
        cveIds        : ['CVE-2017-9841'],
        detail        : `eval-stdin.php at ${p} returned HTTP 200 consistently without PHP probe execution — verify PHPUnit removal`,
        files         : [{
          path         : p,
          url,
          method       : 'GET',
          status       : 200,
          matchedSignal: 'Non-HTML HTTP 200 on eval-stdin.php',
          reproducible : true,
          preview      : quote
        }],
        reproVerified : true,
        poeLevel      : 2,
        evidenceQuotes: [quote],
        ...(finalRes?.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {}),
        fix           : "Remove 'vendor/phpunit' from your production server or deny access to the 'vendor' directory in your web server configuration."
      };

    } catch { /* path unreachable */ }
  }

  return { name: 'phpunit RCE (CVE-2017-9841)', status: 'SAFE', severity: 'NONE' };
}
