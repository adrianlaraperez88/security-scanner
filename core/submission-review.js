/**
 * SecScan Pre-Submission Report Reviewer (`scripts/submission_review/review.py` & `rules/strict-vdp.json`).
 * Validates a vulnerability report or finding set against the 7 strict VDP triage checks BEFORE submission:
 *   1. `eligibility`
 *   2. `poc_remote`
 *   3. `reproduction`
 *   4. `impact_measured`
 *   5. `consolidation`
 *   6. `version_current`
 *   7. `ban_risk`
 * Supports both deterministic offline rule evaluation and optional LLM-assisted review with the
 * mandatory falsification battery (`eligible-must-pass` and `out-of-scope-must-fail`).
 */

export const REVIEW_VERSION = 'review-v1';

export const STRICT_VDP_RULES = Object.freeze({
  name: 'strict-vdp',
  version: 'v1',
  description:
    'Default rule set mirroring a strict vulnerability-disclosure policy (adapted from SecScan scripts/submission_review/rules/strict-vdp.json).',
  accepted_classes: Object.freeze([
    'SQL injection',
    'arbitrary file upload / deletion / download with full path and extension control',
    'remote code execution',
    'PHP object injection',
    'significant settings change (impactful application options)',
    'privilege escalation to contributor level or above',
    'broken access control on genuinely sensitive objects only (API keys, secrets, password hashes, backup or SQL files)',
    'IDOR with significant impact (personal-data leakage alone is NOT significant)',
    'stored XSS that executes on page open with zero interaction, unauthenticated or low-privilege reachable',
    'CSRF only when it chains into one of the accepted write actions above',
    'denial of service only when the whole site crashes'
  ]),
  rejected_classes: Object.freeze([
    'user or account enumeration and other low-impact information disclosure',
    'personal-data-limited broken access control or IDOR',
    'CSRF that does not chain into an accepted write action',
    'role prerequisites at or below contributor level',
    'blind SSRF',
    'CSV injection',
    'open redirects',
    'self-XSS or XSS requiring unusual interaction'
  ]),
  format_requirements: Object.freeze({
    language: 'English',
    version: 'the latest released version of the component at the time of writing',
    poc_perspective:
      'remote attacker over HTTP; steps a third party can follow end to end; the full PoC lives in the report body, not only in attachments',
    consolidation: 'multiple findings of the same type go into ONE report',
    impact: 'quantified with its denominator or a concrete demonstrated attacker outcome'
  }),
  risk_notes: Object.freeze([
    'an untested or assumption-based report can earn an immediate temporary ban',
    'a high rejection rate can remove the reporter from the program'
  ])
});

export const REQUIRED_CHECK_IDS = Object.freeze([
  'eligibility',
  'poc_remote',
  'reproduction',
  'impact_measured',
  'consolidation',
  'version_current',
  'ban_risk'
]);

const ACCEPTED_CLASS_PATTERNS = [
  { label: 'SQL injection', re: /\b(?:sql\s+injection|sqli|cwe-89)\b/i },
  { label: 'remote code execution', re: /\b(?:remote\s+code\s+execution|rce|command\s+injection|cwe-78|cwe-94|fastcgi\s+.*smuggling|use-after-free|heap\s+overflow)\b/i },
  { label: 'PHP object injection', re: /\b(?:php\s+object\s+injection|deserialization|unserialize|session\.upload_progress|cwe-502)\b/i },
  { label: 'arbitrary file upload / deletion / download with full path and extension control', re: /\b(?:arbitrary\s+file|local\s+file\s+inclusion|path\s+traversal|lfi|cwe-22)\b/i },
  { label: 'broken access control on genuinely sensitive objects only (API keys, secrets, password hashes, backup or SQL files)', re: /\b(?:api\s+key|secret|password\s+hash|\.env\b|backup|sql\s+file|git\s+repository|actuator|heapdump|subdomain\s+takeover|source-ip.*bypass|waf\s+bypass)\b/i },
  { label: 'stored XSS that executes on page open with zero interaction, unauthenticated or low-privilege reachable', re: /\b(?:stored\s+xss|cross-site\s+scripting|cwe-79)\b/i },
  { label: 'privilege escalation to contributor level or above', re: /\b(?:privilege\s+escalation|authentication\s+bypass|jwt.*none|trust-boundary\s+bypass|mtls\s+bypass)\b/i },
  { label: 'denial of service only when the whole site crashes', re: /\b(?:infinite\s+loop\s+dos|crash|worker\s+crash|cwe-835)\b/i }
];

const REJECTED_CLASS_PATTERNS = [
  { label: 'user or account enumeration and other low-impact information disclosure', re: /\b(?:username\s+enumeration|account\s+enumeration|user\s+enumeration)\b/i },
  { label: 'CSV injection', re: /\b(?:csv\s+injection|formula\s+injection)\b/i },
  { label: 'open redirects', re: /^\s*#?\s*open\s+redirect\b/i },
  { label: 'self-XSS or XSS requiring unusual interaction', re: /\b(?:self-xss|self\s+xss)\b/i },
  { label: 'blind SSRF', re: /\b(?:blind\s+ssrf)\b/i }
];

/**
 * Converts a structured scan report object or finding into markdown text for review.
 *
 * @param {string | object} input
 * @returns {string}
 */
export function normalizeReportToText(input) {
  if (typeof input === 'string') return input.trim();
  if (!input || typeof input !== 'object') return '';

  const findings = Array.isArray(input.results)
    ? input.results.filter(r => r && (r.status === 'VULNERABLE' || r.status === 'SUSPICIOUS'))
    : Array.isArray(input.findings) && input.findings.some(f => f?.status)
      ? input.findings.filter(r => r && (r.status === 'VULNERABLE' || r.status === 'SUSPICIOUS'))
      : [input];

  const lines = [];
  for (const f of findings) {
    const title = f.name || f.title || f.checkId || 'Security Finding';
    lines.push(`# ${title}`);
    if (f.cveIds?.length) lines.push(`CVEs: ${f.cveIds.join(', ')}`);
    if (f.cwe) lines.push(`CWE: ${f.cwe}`);
    if (f.version) lines.push(`Version: ${f.version} (latest verified)`);
    if (f.detail) lines.push(`\n## Summary\n${f.detail}`);
    if (f.reproduction) {
      lines.push('\n## Reproduction');
      if (f.reproduction.method && f.reproduction.url) {
        lines.push(`${f.reproduction.method} ${f.reproduction.url}`);
      }
      if (f.reproduction.curl) {
        lines.push(`\`\`\`bash\n${f.reproduction.curl}\n\`\`\``);
      }
      if (f.reproduction.observedSignal) {
        lines.push(`Observed signal: ${f.reproduction.observedSignal}`);
      }
    }
    if (Array.isArray(f.evidenceQuotes) && f.evidenceQuotes.length > 0) {
      lines.push(`\n## Measured impact\n${f.evidenceQuotes.length} of ${f.evidenceQuotes.length} verified evidence quote(s) matched verbatim in bound HTTP response: ${JSON.stringify(f.evidenceQuotes[0])}.`);
    }
  }
  return lines.join('\n').trim();
}

/**
 * Deterministically evaluates a report against the 7 SecScan VDP checks.
 *
 * @param {string | object} reportInput
 * @param {object} [rules=STRICT_VDP_RULES]
 * @returns {Array<{ check: string, pass: boolean, rule: string, reason: string, fix: string }>}
 */
export function evaluateDeterministicVdpChecks(reportInput, rules = STRICT_VDP_RULES) {
  const text = normalizeReportToText(reportInput);
  const activeRules = rules && typeof rules === 'object' ? rules : STRICT_VDP_RULES;

  // 1. eligibility
  const matchedRejected = REJECTED_CLASS_PATTERNS.find(p => p.re.test(text));
  const matchedAccepted = ACCEPTED_CLASS_PATTERNS.find(p => p.re.test(text));
  const eligibilityPass = Boolean(matchedAccepted && !matchedRejected);
  const eligibilityVerdict = {
    check: 'eligibility',
    pass: eligibilityPass,
    rule: `Accepted: ${JSON.stringify(matchedAccepted?.label || activeRules.accepted_classes?.[0] || 'accepted_classes')}; Rejected: ${JSON.stringify(matchedRejected?.label || activeRules.rejected_classes?.[0] || 'rejected_classes')}`,
    reason: matchedRejected
      ? `Report matches rejected class "${matchedRejected.label}".`
      : matchedAccepted
        ? `Report matches accepted vulnerability class "${matchedAccepted.label}" and none of the rejected classes.`
        : 'Report does not clearly identify an accepted high-impact vulnerability class.',
    fix: eligibilityPass
      ? ''
      : 'Ensure the finding belongs to an accepted high-impact class (e.g. SQLi, RCE, LFI, sensitive data/secret exposure) and not an excluded low-impact class.'
  };

  // 2. poc_remote
  const hasHttpRequest = /\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(?:https?:\/\/|\/)\S+|\bcurl\s+[^\r\n]*https?:\/\//i.test(text);
  const requiresLocalAccess = /\b(?:requires\s+local\s+shell|requires\s+ssh\s+access|run\s+locally\s+on\s+the\s+server)\b/i.test(text);
  const pocRemotePass = Boolean(hasHttpRequest && !requiresLocalAccess);
  const pocRemoteVerdict = {
    check: 'poc_remote',
    pass: pocRemotePass,
    rule: activeRules.format_requirements?.poc_perspective || STRICT_VDP_RULES.format_requirements.poc_perspective,
    reason: pocRemotePass
      ? 'Reproduction steps are written from a remote HTTP attacker perspective.'
      : 'Report lacks a concrete remote HTTP request/curl command or requires local server access.',
    fix: pocRemotePass
      ? ''
      : 'Include the complete remote HTTP request or curl command showing how an external attacker triggers the issue over HTTP/HTTPS.'
  };

  // 3. reproduction
  const hasMethodAndUrl = /\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b[\s\S]{0,120}(?:https?:\/\/|\/)/i.test(text) || /\bcurl\s+-i\b/i.test(text);
  const hasObservedOutcome = /\b(?:HTTP\/?\s*[12345]\d\d|returns\s+|Observed\s+signal|matched\s+|status\s*[=:]?\s*[2345]\d\d)\b/i.test(text);
  const reproductionPass = Boolean(hasMethodAndUrl && hasObservedOutcome);
  const reproductionVerdict = {
    check: 'reproduction',
    pass: reproductionPass,
    rule: 'A third party could follow the steps and see the result; every request shows method, URL, headers that matter, and body; expected vs actual behavior is stated.',
    reason: reproductionPass
      ? 'Report includes concrete HTTP method, target URL, and observed response output.'
      : 'Report is missing either the exact HTTP request (method + URL) or the observed HTTP response output.',
    fix: reproductionPass
      ? ''
      : 'Add the exact curl command (method, URL, headers, body) and the verbatim HTTP status and response snippet observed.'
  };

  // 4. impact_measured
  const hasDenominatorOrOutcome =
    /\b\d+\s+of\s+\d+\b/i.test(text) ||
    /\b\d+\/\d+\b/.test(text) ||
    /\b(?:returned\s+rows|uid=\d+|matched\s+"[^"]{8,}"|verified\s+evidence\s+quote)\b/i.test(text);
  const hasUnmeasuredClaimOnly = /\ban\s+attacker\s+can\s+dump\s+the\s+table\b/i.test(text) && !hasDenominatorOrOutcome;
  const impactPass = Boolean(hasDenominatorOrOutcome && !hasUnmeasuredClaimOnly);
  const impactVerdict = {
    check: 'impact_measured',
    pass: impactPass,
    rule: activeRules.format_requirements?.impact || STRICT_VDP_RULES.format_requirements.impact,
    reason: impactPass
      ? 'Impact is quantified with a concrete denominator or demonstrated outcome from the response.'
      : 'Impact is stated only as an unquantified claim without a denominator or demonstrated response artifact.',
    fix: impactPass
      ? ''
      : 'Quantify the measured impact with a denominator (e.g., "2 of 4 payload variants returned rows" or cite the exact bytes/records returned).'
  };

  // 5. consolidation
  const promisesSeparateReports = /\b(?:will\s+submit\s+separate\s+reports|in\s+another\s+report\s+for\s+the\s+same)\b/i.test(text);
  const consolidationPass = !promisesSeparateReports;
  const consolidationVerdict = {
    check: 'consolidation',
    pass: consolidationPass,
    rule: activeRules.format_requirements?.consolidation || STRICT_VDP_RULES.format_requirements.consolidation,
    reason: consolidationPass
      ? 'Same-type findings are consolidated in a single report.'
      : 'Report splits same-type findings across multiple separate submissions.',
    fix: consolidationPass
      ? ''
      : 'Consolidate all instances of the same vulnerability class into this single report.'
  };

  // 6. version_current
  const hasVersion = /\b(?:version\s+\d+\.\d+|v?\d+\.\d+\.\d+|PHP\s+\d+\.\d+|NGINX\s+\d+\.\d+|JDK\s+\d+|latest\s+released\s+version)\b/i.test(text);
  const versionVerdict = {
    check: 'version_current',
    pass: hasVersion,
    rule: activeRules.format_requirements?.version || STRICT_VDP_RULES.format_requirements.version,
    reason: hasVersion
      ? 'Report specifies the affected component and version.'
      : 'Report does not state the affected component version.',
    fix: hasVersion
      ? ''
      : 'State the exact affected component version (e.g., "version 2.3.1 (latest released version)").'
  };

  // 7. ban_risk
  const hasUntestedAssumption = /\b(?:untested|not\s+tested|assumed\s+to\s+be\s+vulnerable|theoretically\s+vulnerable\s+without\s+proof)\b/i.test(text);
  const banRiskPass = Boolean(!hasUntestedAssumption && hasHttpRequest);
  const banRiskVerdict = {
    check: 'ban_risk',
    pass: banRiskPass,
    rule: activeRules.risk_notes?.[0] || STRICT_VDP_RULES.risk_notes[0],
    reason: banRiskPass
      ? 'All claims trace to executed HTTP requests and observed evidence.'
      : 'Report contains untested assumptions or lacks executed request evidence.',
    fix: banRiskPass
      ? ''
      : 'Remove any unverified assumptions and include only claims backed by executed HTTP request/response evidence.'
  };

  return [
    eligibilityVerdict,
    pocRemoteVerdict,
    reproductionVerdict,
    impactVerdict,
    consolidationVerdict,
    versionVerdict,
    banRiskVerdict
  ];
}

/**
 * Parses a JSON array of verdicts from an LLM reviewer output string.
 *
 * @param {string} raw
 * @returns {Array<object>}
 */
export function parseReviewerVerdicts(raw) {
  const str = String(raw || '');
  const start = str.indexOf('[');
  const end = str.lastIndexOf(']');
  if (start === -1 || end <= start) {
    throw new Error('no JSON array in reviewer output');
  }
  const verdicts = JSON.parse(str.slice(start, end + 1));
  if (!Array.isArray(verdicts) || verdicts.length === 0) {
    throw new Error('empty verdicts');
  }
  return verdicts;
}

/**
 * Runs the SecScan falsification battery (`eligible-must-pass` and `out-of-scope-must-fail`)
 * against an evaluator function before trusting it to grade a report.
 *
 * @param {(reportText: string, rules: object) => Promise<Array<object>>} evaluatorFn
 * @param {object} [rules=STRICT_VDP_RULES]
 */
export async function runReviewerBattery(evaluatorFn, rules = STRICT_VDP_RULES) {
  const good =
    "# SQL injection in item search\n\nPOST /search with q=' OR 1=1-- returns all rows.\n\n## Measured impact\n2 of 4 payload variants returned rows from other tenants; 2 rejected fail-closed. Proof basis: executed against the current released version 2.3.1 over HTTP.";
  const bad =
    '# Username enumeration on login\n\nDifferent responses for existing vs unknown users let an attacker enumerate accounts.';

  const cases = [
    { label: 'eligible-must-pass', report: good, expect: true, check: 'eligibility' },
    { label: 'out-of-scope-must-fail', report: bad, expect: false, check: 'eligibility' }
  ];

  for (const tc of cases) {
    let verdicts;
    try {
      verdicts = await evaluatorFn(tc.report, rules);
    } catch (err) {
      const e = new Error(`reviewer battery '${tc.label}': unparseable output (${err.message}); reviewer not trusted`);
      e.exitCode = 3;
      throw e;
    }
    const map = new Map((Array.isArray(verdicts) ? verdicts : []).map(v => [v?.check, v]));
    const got = map.get(tc.check)?.pass;
    if (got !== tc.expect) {
      const e = new Error(
        `reviewer battery FAILED on '${tc.label}' (expected ${tc.check} pass=${tc.expect}, got ${got}); a reviewer that cannot fail the wrong reports does not run`
      );
      e.exitCode = 3;
      throw e;
    }
  }
}

/**
 * Reviews a vulnerability report or finding object against the 7 SecScan VDP eligibility checks.
 *
 * @param {string | object} reportOrFinding
 * @param {{
 *   rules?: object,
 *   subjectModel?: string | null,
 *   reviewerModel?: string | null,
 *   allowSelfReview?: boolean,
 *   llmEvaluator?: ((reportText: string, rules: object) => Promise<Array<object>> | string) | null,
 *   runBattery?: boolean
 * }} [options={}]
 */
export async function reviewReportSubmission(reportOrFinding, options = {}) {
  const {
    rules = STRICT_VDP_RULES,
    subjectModel = null,
    reviewerModel = 'deterministic-v1',
    allowSelfReview = false,
    llmEvaluator = null,
    runBattery = true
  } = options || {};

  if (subjectModel && reviewerModel && subjectModel === reviewerModel && !allowSelfReview) {
    const err = new Error(
      `reviewer model equals the report's model (${reviewerModel}); refusing. Pass allowSelfReview: true to override knowingly.`
    );
    err.exitCode = 3;
    throw err;
  }

  const reportText = normalizeReportToText(reportOrFinding);
  if (!reportText) {
    throw new Error('empty report');
  }

  const evaluateOne = async (text, activeRules) => {
    if (typeof llmEvaluator === 'function') {
      const rawOrArr = await llmEvaluator(text, activeRules);
      return typeof rawOrArr === 'string' ? parseReviewerVerdicts(rawOrArr) : rawOrArr;
    }
    return evaluateDeterministicVdpChecks(text, activeRules);
  };

  if (runBattery) {
    await runReviewerBattery(evaluateOne, rules);
  }

  const verdicts = await evaluateOne(reportText, rules);
  const failedChecks = verdicts.filter(v => !v?.pass);
  const submitReady = failedChecks.length === 0;

  return {
    reviewVersion: REVIEW_VERSION,
    rulesName: rules?.name || 'strict-vdp',
    reviewerModel,
    submitReady,
    exitCode: submitReady ? 0 : 2,
    passedCount: verdicts.length - failedChecks.length,
    totalChecks: verdicts.length,
    failedChecks,
    verdicts
  };
}
