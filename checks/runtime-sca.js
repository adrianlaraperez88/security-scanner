import { detectRuntimeScaFindings } from '../core/runtime-sca.js';

export const tags = [
  'all',
  'frontend',
  'react',
  'angular',
  'vue',
  'nextjs',
  'php',
  'node',
  'python',
  'java'
];

export const name = 'runtime-sca';
export const cwe = 'CWE-1395';
export const owasp = 'A06:2021-Vulnerable and Outdated Components';
export const cvssScore = 7.5;

export const meta = {
  id: 'runtime-sca',
  title: 'Runtime SCA & Technology Dependency Versions',
  category: 'Supply Chain Security',
  plainExplanation:
    'Passively inspects HTML script/link tags, framework attributes (ng-version, meta generator), JavaScript bundle banners (Moment.js, Lodash, jQuery, Bootstrap, AngularJS, Angular, React, Vue.js, Next.js, DOMPurify, Axios, Handlebars), and server response headers to compare identified dependency versions against branch-level and overall latest releases and known CVEs.',
  whyItMatters:
    'Outdated or End-of-Life (EOL) third-party libraries and server runtimes expose web applications to publicly documented Cross-Site Scripting (XSS), Prototype Pollution, Regular Expression Denial of Service (ReDoS), SSRF, and Remote Code Execution vulnerabilities.',
  defaultFix:
    'Upgrade outdated third-party libraries and runtime dependencies to their latest patched releases, and migrate away from End-of-Life frameworks such as AngularJS 1.x or Moment.js.',
  cwe: 'CWE-1395',
  owasp: 'A06:2021-Vulnerable and Outdated Components',
  cvssScore: 7.5,
  cveIds: [],
  references: [
    'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
    'https://cwe.mitre.org/data/definitions/1395.html'
  ]
};

/**
 * Runtime SCA & Technology Dependency Versions scanner.
 */
export default async function run(target, fetchWithRetry, options = {}) {
  const sca = await detectRuntimeScaFindings(target, fetchWithRetry, options);

  if (!sca || !Array.isArray(sca.findings) || sca.findings.length === 0) {
    return {
      name: 'runtime-sca',
      status: 'SAFE',
      severity: 'NONE',
      runtimeSca: sca,
      scaFindings: []
    };
  }

  const outdatedFindings = sca.findings.filter(f => f && (f.isOutOfDate || f.status === 'Out of date'));

  if (outdatedFindings.length === 0) {
    return {
      name: 'runtime-sca',
      status: 'SAFE',
      severity: 'NONE',
      runtimeSca: sca,
      scaFindings: sca.findings,
      detail: sca.summary
    };
  }

  const vulnerableFindings = outdatedFindings.filter(
    f => f.isVulnerable || Number(f.highestCvss) >= 4.0
  );

  const subFindings = outdatedFindings.map(f => {
    const itemDetail = `${f.name} ${f.identifiedVersionDisplay} — Latest branch: ${f.latestBranchDisplay}, Overall latest: ${f.overallLatestDisplay}.${f.recommendedAction ? ` ${f.recommendedAction}` : ''}`;
    return {
      ...f,
      path: f.sources?.[0] || '/',
      detail: itemDetail,
      reason: itemDetail
    };
  });

  const evidenceQuotes = outdatedFindings.slice(0, 6).map(f => {
    const src = Array.isArray(f.sources) && f.sources.length > 0 ? ` [${f.sources[0]}]` : '';
    return `${f.name}: ${f.identifiedVersionDisplay} (Overall latest: ${f.overallLatestDisplay})${src}`;
  });

  const detailParts = outdatedFindings.map(
    f => `${f.name} ${f.identifiedVersionDisplay} [Overall latest: ${f.overallLatestVersion}]`
  );
  const detail = `Outdated runtime dependencies detected (${outdatedFindings.length}/${sca.findings.length}): ${detailParts.join('; ')}.`;

  const actionSet = new Set();
  for (const f of outdatedFindings) {
    if (f.recommendedAction) {
      actionSet.add(`${f.name}: ${f.recommendedAction}`);
    }
  }
  const fix = actionSet.size > 0
    ? Array.from(actionSet).join(' | ')
    : meta.defaultFix;

  if (vulnerableFindings.length > 0) {
    const highestCvss = Math.max(0.0, ...vulnerableFindings.map(f => Number(f.highestCvss) || 0.0));
    const severity = highestCvss >= 9.0
      ? 'CRITICAL'
      : highestCvss >= 7.0
      ? 'HIGH'
      : 'MEDIUM';
    const cveIds = Array.from(
      new Set(
        vulnerableFindings
          .flatMap(f => (Array.isArray(f.cveIds) ? f.cveIds : []))
          .filter(Boolean)
      )
    );

    return {
      name: 'runtime-sca',
      status: 'VULNERABLE',
      severity,
      cwe: meta.cwe,
      owasp: meta.owasp,
      cvssScore: highestCvss,
      cveIds,
      runtimeSca: sca,
      scaFindings: sca.findings,
      findings: subFindings,
      evidenceQuotes,
      detail,
      fix
    };
  }

  const maxOutdatedCvss = Math.max(0.0, ...outdatedFindings.map(f => Number(f.highestCvss) || 0.0));

  return {
    name: 'runtime-sca',
    status: 'SUSPICIOUS',
    severity: 'LOW',
    cwe: meta.cwe,
    owasp: meta.owasp,
    cvssScore: maxOutdatedCvss,
    cveIds: [],
    runtimeSca: sca,
    scaFindings: sca.findings,
    findings: subFindings,
    evidenceQuotes,
    detail,
    fix
  };
}
