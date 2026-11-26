export const tags = ['yii', 'yii1', 'yii2'];

export const meta = {
  id: 'yii-checks',
  title: 'Yii 1.x & Yii 2.x Framework Security',
  category: 'Framework Security',
  cwe: 'CWE-215',
  owasp: 'A05:2021-Security Misconfiguration',
  cvssScore: 9.8,
  cveIds: ['CVE-2024-58136', 'CVE-2024-4991', 'CVE-2023-47129', 'CVE-2021-3692'],
  plainExplanation:
    'Audits Yii 1.x and Yii 2.x applications for exposed Gii code generators (/gii, ?r=gii), Yii 2 Debug module toolbars (/debug, X-Debug-Tag), YII_DEBUG stack trace disclosures (CException, CDbException), and accessible protected/runtime logs or configuration files.',
  whyItMatters:
    'Exposed Yii Gii code generators allow remote code generation and arbitrary PHP file creation (RCE). Exposed Yii 2 Debug panels and YII_DEBUG stack traces leak database credentials, session tokens, SQL queries, and application secrets.',
  defaultFix:
    'Disable Gii and Debug modules in production (set YII_DEBUG to false and YII_ENV to prod), restrict Gii/Debug allowedIPs strictly to localhost, and block web server access to protected/, runtime/, and config/ directories.',
  references: [
    'https://www.yiiframework.com/doc/guide/2.0/en/security-best-practices',
    'https://nvd.nist.gov/vuln/detail/CVE-2024-58136',
    'https://nvd.nist.gov/vuln/detail/CVE-2024-4991',
    'https://nvd.nist.gov/vuln/detail/CVE-2023-47129',
    'https://nvd.nist.gov/vuln/detail/CVE-2021-3692',
    'https://cwe.mitre.org/data/definitions/215.html'
  ]
};

/**
 * Derives candidate base URLs for a target (both origin root and application base directory
 * when the target is mounted under a subpath such as `/broadbandAdmin/index.php/site/login`).
 *
 * @param {string} target
 * @returns {string[]}
 */
function buildCandidateAppBases(target) {
  const clean = String(target || '').trim().replace(/\/+$/, '');
  if (!clean) return [];

  let parsed;
  try {
    parsed = new URL(clean);
  } catch {
    return [clean];
  }

  const origin = parsed.origin;
  const pathname = parsed.pathname || '/';
  const bases = [];
  const addBase = (b) => {
    const norm = String(b || '').replace(/\/+$/, '');
    if (norm && !bases.includes(norm)) bases.push(norm);
  };

  const idxMatch = pathname.match(/^(.*)\/index(?:-test)?\.php(?:\/.*)?$/i);
  if (idxMatch) {
    const appDir = (idxMatch[1] || '').replace(/\/+$/, '');
    addBase(`${origin}${appDir}`);
  } else if (pathname && pathname !== '/') {
    const stripped = pathname.replace(/(?:\/site)?\/(?:login|index|error|contact|about)\/?$/i, '');
    if (stripped && stripped !== '/') {
      addBase(`${origin}${stripped}`);
    }
  }

  addBase(origin);
  return bases;
}

function getHeaderMap(headers) {
  const out = {};
  if (!headers) return out;
  if (typeof headers.entries === 'function') {
    for (const [k, v] of headers.entries()) {
      out[String(k).toLowerCase()] = String(v);
    }
    return out;
  }
  if (typeof headers === 'object') {
    for (const [k, v] of Object.entries(headers)) {
      out[String(k).toLowerCase()] = Array.isArray(v) ? v.join('; ') : String(v ?? '');
    }
  }
  return out;
}

function isSpaHtmlFallback(text = '', headers = {}) {
  const h = getHeaderMap(headers);
  const ct = (h['content-type'] || '').toLowerCase();
  const lower = String(text || '').trimStart().slice(0, 512).toLowerCase();
  return (
    ct.includes('text/html') ||
    lower.startsWith('<!doctype html') ||
    lower.startsWith('<html')
  );
}

/**
 * Yii 1.x & Yii 2.x security scanner
 */
export default async function run(target, fetchWithRetry) {
  const bases = buildCandidateAppBases(target);
  const primaryBase = bases[0] || String(target || '').replace(/\/+$/, '');
  let anySuccess = false;
  let lastErr = null;

  const safeFetch = async (url) => {
    try {
      const res = await fetchWithRetry(url);
      if (res?.isGovernanceBlock) {
        const err = new Error(res.reason || res.error || 'Target blocked by governance policy');
        err.isGovernanceBlock = true;
        throw err;
      }
      anySuccess = true;
      return res;
    } catch (e) {
      if (e?.isGovernanceBlock) throw e;
      lastErr = e;
      return null;
    }
  };

  try {
    // 1. Inspect initial target response for passive Yii 1 / Yii 2 debug & stack trace exposures
    const rootRes = await safeFetch(target);
    if (rootRes) {
      const rootHeaders = getHeaderMap(rootRes.headers);
      const rootText = String(rootRes.text || '');

      // Check Yii 2 Debug headers on initial response
      if (rootHeaders['x-debug-tag'] || rootHeaders['x-debug-link']) {
        const debugTag = rootHeaders['x-debug-tag'] || '';
        const debugLink = rootHeaders['x-debug-link'] || '/debug/default/view';
        return {
          name: 'yii-checks',
          status: 'VULNERABLE',
          severity: 'HIGH',
          cwe: 'CWE-215',
          owasp: 'A05:2021-Security Misconfiguration',
          cvssScore: 7.5,
          detail: `Yii 2 Debug Module active in response headers (X-Debug-Tag: ${debugTag || 'present'}, X-Debug-Link: ${debugLink})`,
          path: debugLink,
          fix: meta.defaultFix
        };
      }

      // Check Yii 1 / Yii 2 verbose debug stack trace on initial page
      if (
        (/\b(?:CException|CDbException|CHttpException)\b/.test(rootText) && /Stack Trace|#0\s+[^\r\n]+\.php/i.test(rootText)) ||
        (/\byii\\(?:base|db|web)\\[A-Za-z]+Exception\b/.test(rootText) && /Stack trace:|in\s+[^\r\n]+\/vendor\/yiisoft\/yii2/i.test(rootText))
      ) {
        return {
          name: 'yii-checks',
          status: 'VULNERABLE',
          severity: 'HIGH',
          cwe: 'CWE-209',
          owasp: 'A05:2021-Security Misconfiguration',
          cvssScore: 7.5,
          detail: 'YII_DEBUG enabled — verbose Yii exception stack trace and file paths exposed',
          fix: meta.defaultFix
        };
      }

      if (rootText.includes('yii-debug-toolbar') || rootText.includes('id="yii-debug-toolbar"')) {
        return {
          name: 'yii-checks',
          status: 'VULNERABLE',
          severity: 'HIGH',
          cwe: 'CWE-215',
          owasp: 'A05:2021-Security Misconfiguration',
          cvssScore: 7.5,
          detail: 'Yii 2 Debug Toolbar (yii-debug-toolbar) embedded in HTML response',
          fix: meta.defaultFix
        };
      }
    }

    // 2. Check Yii 1 & Yii 2 Gii Code Generator exposure (/gii, /index.php/gii, /index.php?r=gii)
    const giiPaths = [
      '/gii',
      '/index.php/gii',
      '/index.php?r=gii'
    ];
    for (const base of bases) {
      for (const suffix of giiPaths) {
        const url = `${base}${suffix}`;
        const res = await safeFetch(url);
        if (!res || res.status !== 200 || typeof res.text !== 'string') continue;
        const text = res.text;
        const hasOpenGenerator =
          text.includes('Welcome to Yii Code Generator') ||
          (text.includes('Yii Code Generator') && (text.includes('Model Generator') || text.includes('Controller Generator') || text.includes('CRUD Generator')));
        if (hasOpenGenerator) {
          return {
            name: 'yii-checks',
            status: 'VULNERABLE',
            severity: 'CRITICAL',
            cwe: 'CWE-94',
            owasp: 'A05:2021-Security Misconfiguration',
            cvssScore: 9.8,
            detail: `Yii Gii Code Generator publicly accessible at ${suffix} — allows arbitrary PHP code generation`,
            path: suffix,
            fix: meta.defaultFix
          };
        }
        const hasGiiLogin =
          (text.includes('Yii Code Generator') || text.includes('Gii')) &&
          text.includes('Enter your password') &&
          /LoginForm\[password\]|gii-login/i.test(text);
        if (hasGiiLogin) {
          return {
            name: 'yii-checks',
            status: 'VULNERABLE',
            severity: 'HIGH',
            cwe: 'CWE-215',
            owasp: 'A05:2021-Security Misconfiguration',
            cvssScore: 7.5,
            detail: `Yii Gii Code Generator login page publicly reachable without IP filtering at ${suffix}`,
            path: suffix,
            fix: meta.defaultFix
          };
        }
      }
    }

    // 3. Check Yii 2 Debug Module dashboard exposure (/debug/default/index, /index.php?r=debug)
    const debugPaths = [
      '/debug/default/index',
      '/index.php/debug/default/index',
      '/index.php?r=debug/default/index'
    ];
    for (const base of bases) {
      for (const suffix of debugPaths) {
        const res = await safeFetch(`${base}${suffix}`);
        if (!res || res.status !== 200 || typeof res.text !== 'string') continue;
        const text = res.text;
        const h = getHeaderMap(res.headers);
        if (
          h['x-debug-tag'] ||
          text.includes('yii-debug-toolbar') ||
          (text.includes('Yii2 Debug') && text.includes('Profiling')) ||
          (text.includes('Yii Debugger') && text.includes('Database'))
        ) {
          return {
            name: 'yii-checks',
            status: 'VULNERABLE',
            severity: 'HIGH',
            cwe: 'CWE-215',
            owasp: 'A05:2021-Security Misconfiguration',
            cvssScore: 7.5,
            detail: `Yii 2 Debug Module dashboard exposed at ${suffix} (leaks request logs, DB queries, and configuration)`,
            path: suffix,
            fix: meta.defaultFix
          };
        }
      }
    }

    // 4. Check Yii 1 protected/runtime/application.log & Yii 2 runtime/logs/app.log exposure
    const logProbes = [
      { path: '/protected/runtime/application.log', label: 'Yii 1.x application log (/protected/runtime/application.log)' },
      { path: '/runtime/logs/app.log', label: 'Yii 2.x application log (/runtime/logs/app.log)' }
    ];
    for (const base of bases) {
      for (const probe of logProbes) {
        const res = await safeFetch(`${base}${probe.path}`);
        if (!res || res.status !== 200 || typeof res.text !== 'string') continue;
        if (isSpaHtmlFallback(res.text, res.headers)) continue;
        const text = res.text;
        if (
          /\[(?:error|warning|info|trace)\]\s*\[(?:exception\.|system\.|application|yii\\)/i.test(text) ||
          /\b(?:CException|CDbException|CHttpException|Stack trace:)\b/.test(text)
        ) {
          return {
            name: 'yii-checks',
            status: 'VULNERABLE',
            severity: 'HIGH',
            cwe: 'CWE-532',
            owasp: 'A05:2021-Security Misconfiguration',
            cvssScore: 7.5,
            detail: `Exposed ${probe.label} leaking stack traces and application logs`,
            path: probe.path,
            fix: meta.defaultFix
          };
        }
      }
    }

    // 5. Check Yii 1 /index-test.php functional test entrypoint exposure
    for (const base of bases) {
      const testRes = await safeFetch(`${base}/index-test.php`);
      if (!testRes || testRes.status !== 200 || typeof testRes.text !== 'string') continue;
      if (
        /\b(?:CException|CDbException|YII_DEBUG|CWebApplication)\b/.test(testRes.text) &&
        /Stack Trace|#0\s+[^\r\n]+\.php/i.test(testRes.text)
      ) {
        return {
          name: 'yii-checks',
          status: 'VULNERABLE',
          severity: 'MEDIUM',
          cwe: 'CWE-489',
          owasp: 'A05:2021-Security Misconfiguration',
          cvssScore: 5.3,
          detail: 'Yii 1.x test entrypoint (/index-test.php) is publicly accessible with debug traces enabled',
          path: '/index-test.php',
          fix: 'Remove index-test.php from production deployments.'
        };
      }
    }

    if (!anySuccess && lastErr) {
      return {
        name: 'yii-checks',
        status: 'ERROR',
        severity: 'LOW',
        reason: lastErr.message
      };
    }

    return {
      name: 'yii-checks',
      status: 'SAFE',
      severity: 'NONE'
    };
  } catch (e) {
    return {
      name: 'yii-checks',
      status: 'ERROR',
      severity: 'LOW',
      reason: e.message
    };
  }
}
