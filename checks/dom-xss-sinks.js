import { DOM_CANARY, verifyDomSinksInSandbox } from '../core/dom-sandbox-verifier.js';
import { extractVerbatimSnippet } from '../core/check-verify.js';

export const tags = ['all', 'react', 'angular', 'vue', 'nextjs', 'node', 'php', 'python', 'java'];

export const meta = {
  id: 'dom-xss-sinks',
  title: 'DOM-Based XSS Source-to-Sink & Unsafe postMessage Listener Analysis',
  category: 'Injection & Input',
  plainExplanation:
    'Inspects client-side JavaScript in HTML responses for direct untrusted DOM source-to-sink dataflows (location.hash / location.search / document.referrer / window.name flowing into innerHTML / document.write / eval) and window.addEventListener("message") handlers lacking event.origin validation.',
  whyItMatters:
    'DOM-based XSS executes entirely in the victim’s browser when client-side scripts pass attacker-controlled URL fragments or cross-window postMessage data directly into HTML/script execution sinks without sanitization or origin verification.',
  defaultFix:
    'Use textContent / innerText instead of innerHTML or document.write, sanitize dynamic HTML with DOMPurify, and always validate event.origin against an explicit allowlist inside window.addEventListener("message") handlers.',
  cwe: 'CWE-79',
  owasp: 'A03:2021-Injection',
  cvssScore: 7.5,
  cveIds: [],
  references: [
    'https://cwe.mitre.org/data/definitions/79.html',
    'https://portswigger.net/web-security/cross-site-scripting/dom-based'
  ]
};

const GOVERNANCE_ERROR_CODES = new Set([
  'SSRF_POLICY_BLOCKED',
  'TARGET_RULE_BLOCKED',
  'TARGET_OUT_OF_SCOPE',
  'DNS_REBIND_OR_PRIVATE_IP'
]);

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

// Direct DOM source-to-sink patterns (bounded, linear-time regexes)
const DIRECT_DOM_SINK_PATTERNS = [
  {
    name: 'innerHTML / outerHTML assigned from location.hash / search / href',
    severity: 'HIGH',
    re: /\.(?:innerHTML|outerHTML)\s*\+?=\s*[^;\r\n]{0,120}\b(?:location\.(?:hash|search|href)|document\.(?:URL|documentURI|referrer)|window\.name)\b/i
  },
  {
    name: 'document.write / writeln called with location.hash / search / href',
    severity: 'HIGH',
    re: /\bdocument\.write(?:ln)?\s*\(\s*[^)\r\n]{0,120}\b(?:location\.(?:hash|search|href)|document\.(?:URL|documentURI|referrer)|window\.name)\b/i
  },
  {
    name: 'eval / Function / setTimeout called with location.hash / search / window.name',
    severity: 'CRITICAL',
    re: /\b(?:eval|Function|setTimeout|setInterval)\s*\(\s*[^)\r\n]{0,120}\b(?:location\.(?:hash|search|href)|document\.(?:URL|referrer)|window\.name)\b/i
  }
];

const CRITICAL_SINKS = new Set(['eval', 'setTimeout', 'setInterval']);

function matchesStaticDirectPattern(finding, sink) {
  if (!finding || finding.type !== 'dom_source_to_sink') return false;
  const pat = String(finding.pattern || '');
  if (sink === 'innerHTML' || sink === 'outerHTML' || sink === 'insertAdjacentHTML') {
    return /innerhtml|outerhtml/i.test(pat);
  }
  if (sink === 'document.write' || sink === 'document.writeln') {
    return /document\.write/i.test(pat);
  }
  if (CRITICAL_SINKS.has(sink)) {
    return /eval|Function|setTimeout/i.test(pat);
  }
  return false;
}

function extractRuntimeQuote(body, primaryToken, fallbackToken) {
  const candidates = [
    extractVerbatimSnippet(body, primaryToken),
    fallbackToken ? extractVerbatimSnippet(body, fallbackToken) : null,
    extractVerbatimSnippet(body, /<script/i)
  ];
  for (const cand of candidates) {
    if (typeof cand === 'string' && cand.trim().length >= 8) {
      return cand.trim();
    }
  }
  return null;
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
      detail: 'No DOM XSS source-to-sink or unsafe postMessage handlers detected.'
    };
  }

  const body = String(res.text || '').slice(0, 262144);
  if (!/<script\b/i.test(body) && !body.includes('addEventListener') && !body.includes('innerHTML')) {
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      status: 'SAFE',
      detail: 'No client-side DOM sink patterns found.'
    };
  }

  const findings = [];
  const evidenceQuotes = [];

  for (const pat of DIRECT_DOM_SINK_PATTERNS) {
    const m = pat.re.exec(body);
    if (m) {
      const quote = m[0].replace(/\s+/g, ' ').trim();
      // Skip static single-line matches that explicitly wrap the source in HTML/URI encoders or DOMPurify
      // (the runtime DOM sandbox verifier below will still catch it if the sanitizer fails to strip <...>)
      if (/\b(?:encodeURIComponent|encodeURI|DOMPurify\.sanitize|sanitize(?:Html)?|escape(?:Html)?|htmlEscape|esc)\s*\(/i.test(quote) || /\.replace\s*\(\s*\/(?:\\?[<>]|\[[^\]]*[<>&][^\]]*\])/i.test(quote)) {
        continue;
      }
      evidenceQuotes.push(quote);
      findings.push({
        type: 'dom_source_to_sink',
        pattern: pat.name,
        severity: pat.severity,
        url: target,
        status: res.status,
        matchedSignal: quote,
        issue: `Client-side script passes untrusted DOM source directly into execution sink (${pat.name}): "${quote}".`
      });
    }
  }

  // Check for window.addEventListener('message', ...) without event.origin check
  const postMsgRegex = /addEventListener\s*\(\s*['"]message['"]\s*,\s*(?:function\s*\(\s*([a-zA-Z0-9_$]+)\s*\)|(?:\(\s*([a-zA-Z0-9_$]+)\s*\)|([a-zA-Z0-9_$]+))\s*=>)\s*\{([^}]{1,600})\}/gi;
  let pmMatch;
  while ((pmMatch = postMsgRegex.exec(body)) !== null) {
    const eventParam = pmMatch[1] || pmMatch[2] || pmMatch[3] || 'event';
    const handlerBody = pmMatch[4] || '';
    const checksOrigin = new RegExp(`\\b${eventParam.replace(/\$/g, '\\$')}\\.origin\\b`).test(handlerBody);
    const usesSink = /\b(?:innerHTML|outerHTML|document\.write|eval|location\.href|location\.assign|postMessage)\b/.test(handlerBody);
    if (!checksOrigin && usesSink) {
      const quote = pmMatch[0].replace(/\s+/g, ' ').trim().slice(0, 180);
      evidenceQuotes.push(quote);
      findings.push({
        type: 'unsafe_postmessage_listener',
        pattern: 'window.addEventListener("message") without origin check',
        severity: 'HIGH',
        url: target,
        status: res.status,
        matchedSignal: quote,
        issue: `postMessage listener processes "${eventParam}.data" into a DOM sink without validating "${eventParam}.origin".`
      });
    }
  }

  const sandboxResult = verifyDomSinksInSandbox(body);
  for (const call of sandboxResult.taintedSinkCalls) {
    if (call.sourceType === 'direct_dom') {
      const existing = findings.find(f => matchesStaticDirectPattern(f, call.sink));
      if (existing) {
        existing.runtimeVerified = true;
        existing.runtimeSink = call.sink;
        continue;
      }
      if (findings.some(f => f.type === 'dom_source_to_sink' && f.runtimeSink === call.sink)) {
        continue;
      }
      const quote = extractRuntimeQuote(body, call.sink, '<script');
      if (quote) evidenceQuotes.push(quote);
      findings.push({
        type: 'dom_source_to_sink',
        pattern: `Runtime-verified DOM source-to-${call.sink} flow`,
        severity: CRITICAL_SINKS.has(call.sink) ? 'CRITICAL' : 'HIGH',
        url: target,
        status: res.status,
        matchedSignal: quote || call.sink,
        runtimeVerified: true,
        runtimeSink: call.sink,
        issue: `Runtime sandbox verified untrusted DOM source (${DOM_CANARY}) reaching "${call.sink}" sink${quote ? `: "${quote}"` : ''}.`
      });
    } else if (call.sourceType === 'postmessage') {
      const existing =
        findings.find(f => f.type === 'unsafe_postmessage_listener' && !f.runtimeVerified) ||
        findings.find(f => f.type === 'unsafe_postmessage_listener');
      if (existing) {
        existing.runtimeVerified = true;
        existing.runtimeSink = call.sink;
        continue;
      }
      if (findings.some(f => f.type === 'unsafe_postmessage_listener' && f.runtimeSink === call.sink)) {
        continue;
      }
      const quote = extractRuntimeQuote(body, 'addEventListener', call.sink);
      if (quote) evidenceQuotes.push(quote);
      findings.push({
        type: 'unsafe_postmessage_listener',
        pattern: `Runtime-verified postMessage-to-${call.sink} listener`,
        severity: CRITICAL_SINKS.has(call.sink) ? 'CRITICAL' : 'HIGH',
        url: target,
        status: res.status,
        matchedSignal: quote || call.sink,
        runtimeVerified: true,
        runtimeSink: call.sink,
        issue: `Runtime sandbox verified untrusted postMessage event reaching "${call.sink}" sink without rejecting untrusted origin${quote ? `: "${quote}"` : ''}.`
      });
    }
  }

  if (findings.length > 0) {
    const hasDirectSink = findings.some(f => f.type === 'dom_source_to_sink');
    const hasRuntimeVerified = findings.some(f => f.runtimeVerified === true);
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      url: target,
      status: (hasDirectSink || hasRuntimeVerified) ? 'VULNERABLE' : 'SUSPICIOUS',
      severity: findings.some(f => f.severity === 'CRITICAL') ? 'CRITICAL' : 'HIGH',
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
    detail: 'No DOM-based XSS source-to-sink flows or unverified postMessage listeners detected.'
  };
}

export default run;
