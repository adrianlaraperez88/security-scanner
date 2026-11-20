import fs from 'fs';
import path from 'path';
import {
  generateHtmlReport,
  groupFindings,
  extractFindingCveIds,
  sanitizeApiCommunication,
  sanitizeFindingRecord,
  mergeApiCommunication
} from './html-report.js';
import { getCheckMeta } from './catalog.js';
import { buildFindingAssetTree } from './enrich.js';
import { buildReproductionContext, sanitizeHeadersForRepro } from './reproduction.js';
import { redactSecretsInText } from './ai-advisor.js';

export {
  groupFindings,
  generateHtmlReport,
  extractFindingCveIds,
  sanitizeApiCommunication,
  mergeApiCommunication
};

const REPORTS_DIR = 'reports';

const POE_LABELS = {
  0: 'L0 (None)',
  1: 'L1 (Signal / Heuristic / Timing)',
  2: 'L2 (Structural / Configuration)',
  3: 'L3 (Proof of Execution / Data Extracted)',
  4: 'L4 (Critical Impact Verified)'
};

/**
 * Generates ARTEX's Quality proof-strength descriptors for a finding.
 *
 * @param {object} finding
 * @returns {{
 *   poeLevel: number,
 *   poeLabel: string,
 *   verificationStatus: string,
 *   verificationNote: string,
 *   confidenceRationale: string,
 *   counterevidence: string,
 *   trafficCount: number,
 *   reportStale: boolean,
 *   bullets: string[]
 * }}
 */
export function assessReportQuality(finding = {}) {
  const f = finding && typeof finding === 'object' ? finding : {};
  const status = String(f.status || 'SAFE').toUpperCase();

  const bindings = Array.isArray(f.trafficBindings)
    ? f.trafficBindings
    : (Array.isArray(f.evidenceBindings)
        ? f.evidenceBindings
        : (Array.isArray(f.traffic_refs) ? f.traffic_refs : []));

  const trafficCount = Number.isFinite(f.trafficCount ?? f.traffic_count)
    ? Number(f.trafficCount ?? f.traffic_count)
    : bindings.length;

  let poeLevel;
  if (Number.isFinite(f.poeLevel ?? f.poe_level)) {
    poeLevel = Math.max(0, Math.min(4, Math.floor(Number(f.poeLevel ?? f.poe_level))));
  } else if (status === 'VULNERABLE') {
    poeLevel = trafficCount > 0 ? 3 : 2;
  } else if (status === 'SUSPICIOUS') {
    poeLevel = 1;
  } else {
    poeLevel = 0;
  }

  const poeLabel = POE_LABELS[poeLevel] || POE_LABELS[0];

  const verificationStatus = String(
    f.verificationStatus ||
    f.verification_status ||
    (poeLevel >= 3 && trafficCount > 0
      ? 'verified'
      : status === 'VULNERABLE' || status === 'SUSPICIOUS'
        ? 'unverified'
        : 'not_assessed')
  );

  const verificationNote = String(
    f.verificationNote ||
    f.verification_note ||
    (verificationStatus === 'verified'
      ? `Verified with ${trafficCount} bound traffic receipt(s) at ${poeLabel}`
      : trafficCount === 0
        ? 'No bound proof traffic exchange attached'
        : `PoE level L${poeLevel} recorded`)
  );

  const confidenceRationale = String(
    f.confidenceRationale ||
    f.confidence_rationale ||
    (status === 'VULNERABLE'
      ? `Deterministic check signature matched (${poeLabel})`
      : status === 'SUSPICIOUS'
        ? 'Heuristic anomaly detected requiring manual or receipt verification'
        : 'No vulnerability signature observed')
  );

  const counterevidence = String(f.counterevidence || '');

  const evVer = f.evidenceVersion ?? f.evidence_version;
  const repEvVer = f.reportEvidenceVersion ?? f.report_evidence_version;
  const hasReport = Boolean(f.report || f.detailedReport);
  const reportStale = Boolean(
    f.reportStale ||
    f.report_stale ||
    (hasReport && evVer !== undefined && repEvVer !== undefined && evVer !== repEvVer)
  );

  const bullets = [
    `PoE level: L${poeLevel} — ${poeLabel}`,
    `Verification: ${verificationStatus}`,
    trafficCount > 0
      ? `Proof: ${trafficCount} bound traffic exchange(s)`
      : 'Proof: no bound traffic evidence',
    `Verification note: ${verificationNote}`
  ];

  if (confidenceRationale) {
    bullets.push(`Confidence rationale: ${confidenceRationale}`);
  }
  if (counterevidence) {
    bullets.push(`Counterevidence: ${counterevidence}`);
  }
  if (reportStale) {
    bullets.push('Notice: The evidence has changed; the detailed report needs updating.');
  }

  return {
    poeLevel,
    poeLabel,
    verificationStatus,
    verificationNote,
    confidenceRationale,
    counterevidence,
    trafficCount,
    reportStale,
    bullets
  };
}

/**
 * Counts triple-backtick (```) and triple-tilde (~~~) code fences in markdown
 * and appends closing fences if unbalanced so untrusted finding payloads
 * can never break out of Markdown code blocks.
 *
 * @param {string} markdown
 * @returns {string}
 */
export function closeUnbalancedFences(markdown) {
  const text = String(markdown ?? '');
  if (!text) return '';

  const backtickMatches = text.match(/`{3,}/g) || [];
  const tildeMatches = text.match(/~{3,}/g) || [];

  let result = text;
  if (backtickMatches.length % 2 !== 0) {
    result += (result.endsWith('\n') ? '' : '\n') + '```';
  }
  if (tildeMatches.length % 2 !== 0) {
    result += (result.endsWith('\n') ? '' : '\n') + '~~~';
  }

  return result;
}

/**
 * Generates a Markdown verification section for a single finding.
 *
 * @param {object} finding
 * @returns {string}
 */
export function generateSingleFindingMarkdown(finding = {}) {
  const f = finding && typeof finding === 'object' ? finding : {};
  const meta = f.meta || getCheckMeta(f.checkId || f.name || f.id);
  const quality = assessReportQuality(f);

  const title = f.title || meta.title || f.name || 'Security Finding';
  const checkId = f.checkId || f.name || meta.id || 'unknown';
  const status = f.status || 'UNKNOWN';
  const severity = f.severity || 'NONE';
  const cwe = f.cwe || meta.cwe || 'CWE-16';
  const owasp = f.owasp || meta.owasp || 'A05:2021-Security Misconfiguration';
  const cvssScore = f.cvssScore ?? meta.cvssScore ?? 5.3;
  const cveIds = extractFindingCveIds(f, meta);
  const target = Array.isArray(f.pages) && f.pages.length > 0
    ? f.pages.join(', ')
    : (f.target || f.url || 'N/A');
  const pathStr = f.path || '';
  const detail = f.detail || f.reason || meta.plainExplanation || '';
  const remediation = f.remediation || f.fix || meta.remediation || meta.defaultFix || '';
  const references = Array.isArray(f.references) && f.references.length > 0
    ? f.references
    : (meta.references || []);

  const lines = [
    `### [${severity}] ${title} (\`${checkId}\`)`,
    '',
    `- **Status**: ${status}`,
    `- **Severity**: ${severity} (CVSS: ${cvssScore})`,
    `- **CWE**: ${cwe}`,
    `- **OWASP**: ${owasp}`,
    ...(cveIds.length > 0 ? [`- **CVE IDs**: ${cveIds.join(', ')}`] : []),
    `- **Target**: ${target}${pathStr ? ` (\`${pathStr}\`)` : ''}`,
    '',
    '#### Proof-Strength Quality',
    ...quality.bullets.map(b => `- ${b}`)
  ];

  if (detail) {
    lines.push('', '#### Finding Detail', closeUnbalancedFences(redactSecretsInText(String(detail))));
  }

  const exposedItems = Array.isArray(f.files) && f.files.length > 0
    ? f.files
    : (Array.isArray(f.findings) ? f.findings : []);
  if (exposedItems.length > 0) {
    lines.push('', '#### Matched Files & Exposed Paths');
    for (const fileItem of exposedItems.slice(0, 15)) {
      if (!fileItem || typeof fileItem !== 'object') continue;
      const fPath = closeUnbalancedFences(redactSecretsInText(String(fileItem.path || fileItem.url || fileItem.name || 'finding')));
      const fMeta = [
        fileItem.method ? String(fileItem.method) : '',
        fileItem.status ? `HTTP ${fileItem.status}` : '',
        fileItem.contentType ? `Content-Type: ${fileItem.contentType}` : '',
        fileItem.matchedSignal ? `Matched: ${redactSecretsInText(String(fileItem.matchedSignal))}` : '',
        fileItem.detail || fileItem.issue || fileItem.reason ? redactSecretsInText(String(fileItem.detail || fileItem.issue || fileItem.reason)) : '',
      ].filter(Boolean).join(', ');
      lines.push(`- \`${fPath}\`${fMeta ? ` (${closeUnbalancedFences(fMeta)})` : ''}`);
    }
  }

  if (Array.isArray(f.missing) && f.missing.length > 0) {
    lines.push('', '#### Missing Headers / Controls');
    lines.push(`- ${closeUnbalancedFences(f.missing.join(', '))}`);
  }

  if (Array.isArray(f.evidenceQuotes) && f.evidenceQuotes.length > 0) {
    lines.push('', '#### Verbatim Evidence Proof');
    for (const q of f.evidenceQuotes.slice(0, 5)) {
      lines.push(`- \`${closeUnbalancedFences(redactSecretsInText(String(q)))}\``);
    }
  }

  const repro = status !== 'SAFE' ? (f.reproduction || buildReproductionContext(f)) : null;
  if (repro) {
    lines.push('', '#### How to Reproduce & Verify Fix');
    lines.push(`- **Reproducible**: ${repro.reproducible || f.reproVerified ? 'Yes (Confirmed)' : 'Recorded trigger trace'}`);
    if (repro.observedSignal) {
      lines.push(`- **Observed Signal**: ${closeUnbalancedFences(redactSecretsInText(repro.observedSignal))}`);
    }
    if (Array.isArray(repro.steps) && repro.steps.length > 0) {
      lines.push('', ...repro.steps.map((s, idx) => `${idx + 1}. ${closeUnbalancedFences(redactSecretsInText(s))}`));
    }
    if (repro.curl) {
      lines.push('', '```bash', redactSecretsInText(repro.curl), '```');
    }
  }

  if (f.report || f.detailedReport) {
    const rawDetailed = String(f.report || f.detailedReport).slice(0, 8192);
    lines.push('', '#### Detailed Verification Report', closeUnbalancedFences(rawDetailed));
  }

  if (remediation) {
    lines.push('', '#### Remediation', closeUnbalancedFences(String(remediation)));
  }

  if (f.aiSolution && typeof f.aiSolution === 'object') {
    const ai = f.aiSolution;
    const modeLabel = ai.mode === 'ai'
      ? `AI (${ai.provider || 'llm'}/${ai.model || 'unknown'})`
      : 'Playbook';
    lines.push('', `#### AI Remediation Guidance (${modeLabel})`);
    if (ai.plainExplanation) {
      lines.push(`- **Summary**: ${closeUnbalancedFences(String(ai.plainExplanation))}`);
    }
    if (ai.rootCause) {
      lines.push(`- **Root Cause**: ${closeUnbalancedFences(String(ai.rootCause))}`);
    }
    if (Array.isArray(ai.solutionSteps) && ai.solutionSteps.length > 0) {
      lines.push('', ...ai.solutionSteps.map((s, idx) => `${idx + 1}. ${closeUnbalancedFences(String(s))}`));
    }
    if (ai.patchSnippet) {
      const lang = String(ai.patchLanguage || '').replace(/[^a-z0-9+#.-]/gi, '');
      const safeSnippet = closeUnbalancedFences(String(ai.patchSnippet));
      lines.push('', `\`\`\`${lang}`, safeSnippet, '```');
    }
    if (ai.verifyCommand) {
      lines.push('', `- **Verify Command**: \`${String(ai.verifyCommand).replace(/`/g, "'")}\``);
    }
  }

  if (references.length > 0) {
    lines.push('', '#### References', ...references.map(ref => `- ${ref}`));
  }

  return closeUnbalancedFences(lines.join('\n'));
}

/**
 * Produces a comprehensive Markdown verification report with Executive Summary,
 * Risk Grade, Asset Tree, Proof-Strength Quality bullets, CWE/OWASP tags,
 * and closeUnbalancedFences protection.
 *
 * @param {object|Array} scanData
 * @param {object} [riskArg=null]
 * @param {object} [stacksArg=null]
 * @returns {string}
 */
export function generateMarkdownReport(scanData, riskArg = null, stacksArg = null, optionsArg = null) {
  let results = [];
  let risk = riskArg;
  let stacks = stacksArg;
  let cveCoverage = optionsArg?.cveCoverage || null;
  let explicitApiComm = optionsArg?.apiCommunication || null;
  let assets = [];
  let targets = [];
  let generatedAt = new Date().toISOString();

  if (Array.isArray(scanData)) {
    results = scanData;
  } else if (scanData && typeof scanData === 'object') {
    results = Array.isArray(scanData.results)
      ? scanData.results
      : (Array.isArray(scanData.findings) ? scanData.findings : []);
    risk = scanData.risk || scanData.summary || riskArg || {};
    stacks = scanData.stacks || stacksArg || null;
    cveCoverage = scanData.cveCoverage || cveCoverage || null;
    explicitApiComm = scanData.apiCommunication || explicitApiComm || null;
    assets = Array.isArray(scanData.assets) ? scanData.assets : [];
    targets = Array.isArray(scanData.targets) ? scanData.targets : [];
    if (scanData.generatedAt) generatedAt = scanData.generatedAt;
  }

  const sanitizedResults = Array.isArray(results) ? results.map(sanitizeFindingRecord) : [];
  const sanitizedStacks = sanitizeStacksForReport(stacks);
  const apiCommunication = mergeApiCommunication(sanitizedStacks, sanitizedResults, explicitApiComm);

  const grouped = groupFindings(sanitizedResults).map(sanitizeFindingRecord);
  const vulns = grouped.filter(r => r.status === 'VULNERABLE');
  const suspicious = grouped.filter(r => r.status === 'SUSPICIOUS');
  const safe = grouped.filter(r => r.status === 'SAFE');
  const errors = grouped.filter(r => r.status === 'ERROR');

  const grade = risk?.grade || (vulns.length > 0 ? 'D' : suspicious.length > 0 ? 'B' : 'A+');
  const level = risk?.level || (vulns.length > 0 ? 'HIGH' : suspicious.length > 0 ? 'MEDIUM' : 'LOW');
  const score = risk?.score ?? 0;

  const tree = buildFindingAssetTree(sanitizedResults, assets);

  const lines = [
    '# Security Verification Report',
    '',
    `- **Generated At**: ${generatedAt}`,
    ...(targets.length > 0 ? [`- **Targets**: ${targets.join(', ')}`] : []),
    '',
    '## Executive Summary',
    '',
    `- **Risk Grade**: **${grade}**`,
    `- **Risk Level**: **${level}** (Score: ${score}/60)`,
    `- **Total Checks Grouped**: ${grouped.length} (${sanitizedResults.length} total executions)`,
    `- **Vulnerable**: ${vulns.length}`,
    `- **Suspicious**: ${suspicious.length}`,
    `- **Safe**: ${safe.length}`,
    `- **Errors**: ${errors.length}`,
    ...(risk?.summary ? ['', `> ${risk.summary}`] : []),
    '',
    '## Asset Tree & Finding Rollup',
    ''
  ];

  if (tree.roots.length === 0) {
    lines.push('- No host assets linked.');
  } else {
    for (const root of tree.roots) {
      lines.push(`- **${root.kind}: \`${root.value}\`** (Findings: ${root.counts.total}, CRITICAL: ${root.counts.CRITICAL}, HIGH: ${root.counts.HIGH}, MEDIUM: ${root.counts.MEDIUM}, LOW: ${root.counts.LOW})`);
      for (const sub of root.children) {
        lines.push(`  - Subdomain: \`${sub.value}\` (Findings: ${sub.counts.total})`);
        for (const svc of sub.children) {
          lines.push(`    - Service: \`${svc.value}\` (Findings: ${svc.counts.total})`);
          for (const ep of svc.children) {
            lines.push(`      - Endpoint: \`${ep.value}\` (${ep.findings.length} finding(s))`);
          }
        }
      }
    }
  }

  if (stacks && typeof stacks === 'object') {
    lines.push('', '## Detected Technology Stack', '');
    const stackEntries = Array.isArray(stacks)
      ? stacks.map((fp, i) => [fp?.target || `Target #${i + 1}`, fp])
      : Object.entries(stacks);
    for (const [tUrl, fp] of stackEntries) {
      if (!fp || typeof fp !== 'object') continue;
      lines.push(`- **${tUrl}**: ${fp.summary || 'Unknown'} (Profile: \`${fp.recommendedProfile || 'smart'}\`)`);
    }
  }

  if (apiCommunication) {
    const sanitizeMdInline = (val) =>
      closeUnbalancedFences(
        redactSecretsInText(String(val ?? ''))
          .replace(/[\r\n]+/g, ' ')
          .replace(/`/g, "'")
          .trim()
      );
    lines.push('', '## API Communication & Discovered Endpoints', '');
    lines.push(`- **Uses Client-Side API**: ${apiCommunication.usesApi ? 'Yes' : 'No'}`);
    lines.push(`- **Architecture**: \`${sanitizeMdInline(apiCommunication.architecture || 'traditional_web')}\``);
    if (apiCommunication.summary) {
      lines.push(`- **Summary**: ${closeUnbalancedFences(redactSecretsInText(apiCommunication.summary))}`);
    }
    if (apiCommunication.clients.length > 0) {
      lines.push(`- **API Clients**: ${apiCommunication.clients.map(c => `\`${sanitizeMdInline(c)}\``).join(', ')}`);
    }
    if (apiCommunication.protocols.length > 0) {
      lines.push(`- **Protocols**: ${apiCommunication.protocols.map(p => `\`${sanitizeMdInline(p)}\``).join(', ')}`);
    }
    if (apiCommunication.sameOriginEndpoints.length > 0) {
      lines.push(
        `- **Same-Origin Endpoints (${apiCommunication.sameOriginEndpoints.length})**: ${apiCommunication.sameOriginEndpoints.map(ep => `\`${sanitizeMdInline(ep)}\``).join(', ')}`
      );
    }
    if (apiCommunication.externalApiOrigins.length > 0) {
      lines.push(
        `- **External API Origins (${apiCommunication.externalApiOrigins.length})**: ${apiCommunication.externalApiOrigins.map(o => `\`${sanitizeMdInline(o)}\``).join(', ')}`
      );
    }
    if (apiCommunication.configFiles.length > 0) {
      lines.push(`- **Runtime Config Files**: ${apiCommunication.configFiles.map(cf => `\`${sanitizeMdInline(cf)}\``).join(', ')}`);
    }
    if (apiCommunication.issues.length > 0) {
      lines.push('- **Configuration & Exposure Issues**:');
      for (const iss of apiCommunication.issues) {
        lines.push(
          `  - **[${sanitizeMdInline(iss.severity || 'MEDIUM')}] ${sanitizeMdInline(iss.type)}**: ${closeUnbalancedFences(redactSecretsInText(iss.detail || ''))}`
        );
      }
    }
  }

  if (cveCoverage && typeof cveCoverage === 'object') {
    const covSummary = cveCoverage.summary && typeof cveCoverage.summary === 'object'
      ? cveCoverage.summary
      : cveCoverage;
    if (Number.isFinite(Number(covSummary.totalAdvisories))) {
      lines.push('', '## CVE Coverage Summary', '');
      lines.push(`- **Total Advisories**: ${covSummary.totalAdvisories}`);
      lines.push(`- **Covered**: ${covSummary.coveredCount ?? 0}`);
      if (covSummary.partialCount !== undefined) {
        lines.push(`- **Partial**: ${covSummary.partialCount}`);
      }
      lines.push(`- **Missing**: ${covSummary.missingCount ?? 0}`);
      lines.push(`- **Coverage**: ${covSummary.coveragePercent ?? 100}%`);
      if (covSummary.kevTotal !== undefined) {
        lines.push(`- **CISA KEV**: ${covSummary.kevCovered ?? 0}/${covSummary.kevTotal} covered (missing: ${covSummary.kevMissing ?? 0})`);
      }
      const tags = Array.isArray(cveCoverage.techTags)
        ? cveCoverage.techTags
        : (Array.isArray(cveCoverage.filter?.techTags) ? cveCoverage.filter.techTags : []);
      if (tags.length > 0) {
        lines.push(`- **Tech Filter**: ${tags.join(', ')}`);
      }
    }
  }

  lines.push('', '## Findings & Proof-Strength Attestation', '');

  const actionable = [...vulns, ...suspicious];
  const findingsToRender = actionable.length > 0 ? actionable : grouped;

  if (findingsToRender.length === 0) {
    lines.push('No findings recorded.');
  } else {
    for (const finding of findingsToRender) {
      lines.push(generateSingleFindingMarkdown(finding), '');
    }
  }

  return closeUnbalancedFences(lines.join('\n'));
}

/**
 * Neutralizes CSV formula injection and formats a single RFC-4180 CSV cell.
 * Cells starting with =, +, -, @, \t, or \r are prefixed with a single quote (').
 *
 * @param {unknown} value
 * @returns {string}
 */
export function formatCsvCell(value) {
  let str = String(value ?? '');
  if (/^[=+\-@\t\r]/.test(str)) {
    str = `'${str}`;
  }
  if (/[",\r\n]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

/**
 * Produces an RFC-4180 CSV report prefixed with UTF-8 BOM (\uFEFF) and
 * CSV formula-injection neutralization.
 *
 * @param {object|Array} scanData
 * @returns {string}
 */
export function generateCsvReport(scanData) {
  const results = Array.isArray(scanData)
    ? scanData
    : (Array.isArray(scanData?.results)
        ? scanData.results
        : (Array.isArray(scanData?.findings) ? scanData.findings : []));

  const headers = [
    'Check ID',
    'Title',
    'Status',
    'Severity',
    'CWE',
    'OWASP',
    'CVSS',
    'CVE IDs',
    'Target',
    'Path',
    'PoE Level',
    'Verification Status',
    'Detail',
    'Remediation',
    'How to Reproduce'
  ];

  const rows = [headers.map(formatCsvCell).join(',')];

  for (const r of results) {
    if (!r || typeof r !== 'object') continue;
    const meta = r.meta || getCheckMeta(r.checkId || r.name || r.id);
    const quality = assessReportQuality(r);

    const checkId = r.checkId || r.name || meta.id || 'unknown';
    const title = r.title || meta.title || checkId;
    const status = r.status || 'UNKNOWN';
    const severity = r.severity || 'NONE';
    const cwe = r.cwe || meta.cwe || 'CWE-16';
    const owasp = r.owasp || meta.owasp || 'A05:2021-Security Misconfiguration';
    const cvss = r.cvssScore ?? meta.cvssScore ?? 5.3;
    const cveIds = extractFindingCveIds(r, meta);
    const target = r.target || (Array.isArray(r.pages) && r.pages[0]) || '';
    const pathStr = r.path || (Array.isArray(r.files) && r.files[0]?.path) || '';
    const filesDetail = Array.isArray(r.files) && r.files.length > 0
      ? r.files.map(f => `${f.path || ''}${f.matchedSignal ? ` (${f.matchedSignal})` : ''}`).filter(Boolean).join('; ')
      : '';
    const detail = redactSecretsInText(r.detail || r.reason || filesDetail || '');
    const remediation = r.remediation || r.fix || meta.remediation || meta.defaultFix || '';
    const repro = status !== 'SAFE' ? (r.reproduction || buildReproductionContext(r)) : null;
    const reproSummary = repro
      ? [repro.summary, repro.curl ? `Cmd: ${repro.curl}` : '', repro.verifyFix ? `Verify: ${repro.verifyFix}` : ''].filter(Boolean).join(' | ')
      : '';

    const row = [
      checkId,
      title,
      status,
      severity,
      cwe,
      owasp,
      cvss,
      cveIds.join('; '),
      target,
      pathStr,
      `L${quality.poeLevel}`,
      quality.verificationStatus,
      detail,
      remediation,
      reproSummary
    ];

    rows.push(row.map(formatCsvCell).join(','));
  }

  return `\uFEFF${rows.join('\r\n')}\r\n`;
}

/**
 * Compacts a full `auditCveCoverage` output into a lightweight summary object
 * suitable for scan JSON/HTML/Markdown reports and `/api/meta`.
 *
 * @param {object|null} audit
 * @returns {object|null}
 */
export function summarizeCveAudit(audit) {
  if (!audit || typeof audit !== 'object') return null;
  const summary = audit.summary && typeof audit.summary === 'object' ? audit.summary : audit;
  if (!Number.isFinite(Number(summary.totalAdvisories))) return null;
  return {
    ...summary,
    techTags: Array.isArray(audit.filter?.techTags) ? [...audit.filter.techTags] : [],
    byEcosystem: audit.byEcosystem || {},
    missingCveIds: Array.isArray(audit.missing) ? audit.missing.map(m => m.cveId).filter(Boolean) : [],
    partialCveIds: Array.isArray(audit.partial) ? audit.partial.map(p => p.cveId).filter(Boolean) : [],
    coveredCveIds: Array.isArray(audit.covered) ? audit.covered.map(c => c.cveId).filter(Boolean) : [],
    generatedAt: audit.generatedAt || new Date().toISOString()
  };
}

function sanitizeStacksForReport(stacks) {
  if (!stacks) return undefined;
  if (Array.isArray(stacks)) {
    return stacks.map(s => (
      s && typeof s === 'object' && s.apiCommunication
        ? { ...s, apiCommunication: sanitizeApiCommunication(s.apiCommunication) }
        : s
    ));
  }
  if (typeof stacks === 'object') {
    if (stacks.apiCommunication && typeof stacks.apiCommunication === 'object') {
      return { ...stacks, apiCommunication: sanitizeApiCommunication(stacks.apiCommunication) };
    }
    const out = {};
    for (const [k, v] of Object.entries(stacks)) {
      out[k] = (v && typeof v === 'object' && v.apiCommunication)
        ? { ...v, apiCommunication: sanitizeApiCommunication(v.apiCommunication) }
        : v;
    }
    return out;
  }
  return stacks;
}

export function generateReport(results, risk = null, stacks = null, extra = null) {
  const sanitizedResults = Array.isArray(results) ? results.map(sanitizeFindingRecord) : [];
  const sanitizedStacks = sanitizeStacksForReport(stacks);
  const grouped    = groupFindings(sanitizedResults).map(sanitizeFindingRecord);
  const vulns      = grouped.filter(r => r.status === 'VULNERABLE');
  const suspicious = grouped.filter(r => r.status === 'SUSPICIOUS');
  const errors     = grouped.filter(r => r.status === 'ERROR');
  const cveCoverage = extra && typeof extra === 'object'
    ? (extra.cveCoverage ?? (extra.totalAdvisories !== undefined || extra.summary ? extra : null))
    : null;
  const explicitApi = extra && typeof extra === 'object' ? (extra.apiCommunication || null) : null;
  const apiCommunication = mergeApiCommunication(sanitizedStacks, sanitizedResults, explicitApi);

  return {
    generatedAt     : new Date().toISOString(),
    summary         : {
      ...(risk || {}),
      totalChecks     : grouped.length,
      totalExecutions : sanitizedResults.length,
      vulnerable      : vulns.length,
      suspicious      : suspicious.length,
      errors          : errors.length
    },
    stacks          : sanitizedStacks,
    ...(apiCommunication ? { apiCommunication } : {}),
    ...(cveCoverage ? { cveCoverage } : {}),
    groupedFindings : grouped,
    findings        : sanitizedResults
  };
}

/**
 * Alias of generateReport for JSON report generation.
 */
export const generateJsonReport = generateReport;

export function saveReport(report, stem = 'report') {
  const file = stem.endsWith('.json') ? stem : `${stem}.json`;
  fs.writeFileSync(file, JSON.stringify(report, null, 2));
  return file;
}

export function saveHtmlReport(results, risk, stem = 'report', stacks = null, options = null) {
  const file = stem.endsWith('.html') ? stem : `${stem}.html`;
  fs.writeFileSync(file, generateHtmlReport(results, risk, stacks, options));
  return file;
}

/**
 * Automatically saves both HTML and JSON reports into `./reports/` after a scan.
 */
export function saveAutoReports(targets, results, risk, stacks = null, options = null) {
  const dir = path.join(process.cwd(), REPORTS_DIR);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  const ts = new Date().toISOString().replace(/[:.]/g, '-').replace('T', '_').slice(0, 19);
  const safeHost = (Array.isArray(targets) && targets[0]
    ? (() => { try { return new URL(targets[0]).hostname.replace(/[^a-z0-9.-]/gi, '_'); } catch { return 'target'; } })()
    : 'target');

  const baseName = `${ts}_${safeHost}`;
  const htmlPath = path.join(dir, `${baseName}.html`);
  const jsonPath = path.join(dir, `${baseName}.json`);

  const reportObj = generateReport(results, risk, stacks, options);
  fs.writeFileSync(jsonPath, JSON.stringify(reportObj, null, 2));
  fs.writeFileSync(htmlPath, generateHtmlReport(results, risk, stacks, options));

  return { htmlPath, jsonPath, dir };
}

const SARIF_SENSITIVE_HEADER_RE = /^(x-goog-api-key|x-api-key|x-auth-token|x-access-token|x-csrf-token|authorization|proxy-authorization|cookie|set-cookie)$/i;

function sanitizeHeaderMapForSarif(headers) {
  const cleaned = sanitizeHeadersForRepro(headers, { keepDefaults: true });
  for (const key of Object.keys(cleaned)) {
    if (SARIF_SENSITIVE_HEADER_RE.test(key)) {
      cleaned[key] = '<REDACTED>';
    } else if (typeof cleaned[key] === 'string') {
      cleaned[key] = redactSecretsInText(cleaned[key]);
    }
  }
  return cleaned;
}

function redactSecretsDeep(value, depth = 0) {
  if (value === null || value === undefined || depth > 10) return value;
  if (typeof value === 'string') return redactSecretsInText(value);
  if (Array.isArray(value)) return value.map((item) => redactSecretsDeep(item, depth + 1));
  if (typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if ((k === 'requestHeaders' || k === 'headers') && v && typeof v === 'object' && !Array.isArray(v)) {
        out[k] = sanitizeHeaderMapForSarif(v);
      } else {
        out[k] = redactSecretsDeep(v, depth + 1);
      }
    }
    return out;
  }
  return value;
}

function sanitizeReproForSarif(repro) {
  if (!repro || typeof repro !== 'object') return null;
  return redactSecretsDeep(repro);
}

/**
 * Produces a SARIF v2.1.0 report object suitable for GitHub Code Scanning and CI/CD pipelines.
 *
 * @param {object|Array} scanData
 * @param {{ version?: string, includeSafe?: boolean }} [options={}]
 * @returns {object}
 */
export function generateSarifReport(scanData, options = {}) {
  const rawList = Array.isArray(scanData)
    ? scanData
    : (Array.isArray(scanData?.results)
        ? scanData.results
        : (Array.isArray(scanData?.findings) ? scanData.findings : []));
  const rawResults = rawList.map(sanitizeFindingRecord);

  const includeSafe = Boolean(options.includeSafe);
  const rules = [];
  const ruleIndexMap = new Map();
  const sarifResults = [];

  for (const f of rawResults) {
    if (!f || typeof f !== 'object') continue;
    const status = String(f.status || 'ERROR').toUpperCase();
    if (status === 'SAFE' && !includeSafe) continue;

    const meta = f.meta || getCheckMeta(f.checkId || f.name || f.id);
    const checkId = String(f.checkId || f.name || meta.id || 'unknown');
    const title = String(f.title || meta.title || f.name || checkId);
    const severity = String(f.severity || 'NONE').toUpperCase();
    const cwe = f.cwe || meta.cwe || 'CWE-16';
    const owasp = f.owasp || meta.owasp || 'A05:2021-Security Misconfiguration';
    const cvssScore = f.cvssScore ?? meta.cvssScore ?? 5.3;
    const cveIds = extractFindingCveIds(f, meta);
    const remediation = String(
      f.remediation || f.fix || meta.remediation || meta.defaultFix || 'Review configuration and apply security hardening.'
    );
    const references = Array.isArray(f.references) && f.references.length > 0
      ? f.references
      : (meta.references || []);
    const helpUri = references.find(r => typeof r === 'string' && /^https?:\/\//i.test(r))
      || 'https://owasp.org/www-project-top-ten/';

    const safeTitle = redactSecretsInText(title);
    const safeRemediation = redactSecretsInText(remediation);
    const safeFullDescription = redactSecretsInText(String(meta.plainExplanation || f.detail || f.reason || title));

    if (!ruleIndexMap.has(checkId)) {
      const tags = Array.from(new Set(['security', cwe, owasp, ...cveIds].filter(Boolean)));
      ruleIndexMap.set(checkId, rules.length);
      rules.push({
        id: checkId,
        name: safeTitle,
        shortDescription: { text: safeTitle },
        fullDescription: { text: safeFullDescription },
        helpUri,
        help: { text: safeRemediation },
        properties: {
          tags,
          'security-severity': String(cvssScore ?? 5.3),
        },
      });
    }

    const level = status === 'VULNERABLE'
      ? 'error'
      : status === 'SUSPICIOUS'
        ? 'warning'
        : status === 'SAFE'
          ? 'none'
          : 'note';

    const rawMsg = f.detail || f.reason || f.title || title;
    const safeMsg = redactSecretsInText(String(rawMsg));
    const rawUri = String(f.target || (Array.isArray(f.pages) && f.pages[0]) || 'about:blank');
    const uri = redactSecretsInText(rawUri);

    const rawRepro = status !== 'SAFE' ? (f.reproduction || buildReproductionContext(f)) : null;
    const safeRepro = sanitizeReproForSarif(rawRepro);
    const safeAiSolution = f.aiSolution
      ? (typeof f.aiSolution === 'object' ? redactSecretsDeep(f.aiSolution) : redactSecretsInText(String(f.aiSolution)))
      : null;

    const properties = {
      cwe,
      owasp,
      cvssScore,
      cveIds,
      status,
      severity,
      ...(safeRepro ? { reproduction: safeRepro } : {}),
      ...(safeAiSolution ? { aiSolution: safeAiSolution } : {}),
    };

    sarifResults.push({
      ruleId: checkId,
      ruleIndex: ruleIndexMap.get(checkId),
      level,
      ...(status === 'SAFE' ? { kind: 'pass' } : {}),
      message: { text: safeMsg },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri,
            },
          },
        },
      ],
      properties,
    });
  }

  const rawApiComm = (!Array.isArray(scanData) && scanData && typeof scanData === 'object')
    ? (scanData.apiCommunication || options.apiCommunication || null)
    : (options.apiCommunication || null);
  const stacksForSarif = (!Array.isArray(scanData) && scanData && typeof scanData === 'object')
    ? (scanData.stacks || null)
    : null;
  const apiCommunication = mergeApiCommunication(stacksForSarif, rawResults, rawApiComm);

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Security Scanner',
            informationUri: 'https://github.com/security-scanner/security-scanner',
            version: options.version || '2.2.0',
            rules,
          },
        },
        results: sarifResults,
        ...(apiCommunication ? { properties: { apiCommunication: redactSecretsDeep(apiCommunication) } } : {}),
      },
    ],
  };
}
