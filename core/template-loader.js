import fs from 'node:fs';
import path from 'node:path';
import { resolveTargetUrl } from './cve-utils.js';
import {
  getHeader,
  extractVerbatimSnippet,
  isSoft404Response,
  verifyFindingBeforeReport
} from './check-verify.js';

export const MAX_TEMPLATE_FILE_BYTES = 256 * 1024;
export const MAX_REGEX_PATTERN_LEN = 512;

const VALID_TEMPLATE_ID_RE = /^[a-zA-Z0-9._-]{2,80}$/;
const VALID_SEVERITIES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'NONE']);
const VALID_METHODS = new Set(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']);

export class TemplateValidationError extends Error {
  constructor(message, statusCode = 400) {
    super(message);
    this.name = 'TemplateValidationError';
    this.statusCode = statusCode;
  }
}

/**
 * Linear-time O(n) static analyzer that detects nested quantifiers (e.g., `(a+)+`, `([a-z]*)*`, `(.*)+`)
 * or oversized regex patterns (`> 512` chars) to block ReDoS in custom templates.
 *
 * @param {string} patternStr
 * @returns {boolean}
 */
export function hasNestedQuantifiers(patternStr) {
  if (typeof patternStr !== 'string') return false;
  if (patternStr.length > MAX_REGEX_PATTERN_LEN) return true;

  const groupStack = [];
  let escaped = false;
  let inCharClass = false;

  for (let i = 0; i < patternStr.length; i++) {
    const ch = patternStr[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === '\\') {
      escaped = true;
      continue;
    }
    if (ch === '[') {
      inCharClass = true;
      continue;
    }
    if (ch === ']' && inCharClass) {
      inCharClass = false;
      continue;
    }
    if (inCharClass) continue;

    if (ch === '(') {
      groupStack.push({ hasInnerQuantifier: false, hasAlternation: false });
      continue;
    }

    if (ch === '|' && groupStack.length > 0) {
      groupStack[groupStack.length - 1].hasAlternation = true;
      continue;
    }

    if (ch === ')') {
      const group = groupStack.pop();
      const next = patternStr[i + 1] || '';
      const isGroupQuantified = next === '+' || next === '*' || next === '{';
      if ((group?.hasInnerQuantifier || group?.hasAlternation) && isGroupQuantified) {
        return true;
      }
      if (groupStack.length > 0) {
        if (group?.hasInnerQuantifier || isGroupQuantified) {
          groupStack[groupStack.length - 1].hasInnerQuantifier = true;
        }
        if (group?.hasAlternation) {
          groupStack[groupStack.length - 1].hasAlternation = true;
        }
      }
      continue;
    }

    if (ch === '+' || ch === '*' || (ch === '{' && /^\{\d+,\d*\}/.test(patternStr.slice(i, i + 12)))) {
      if (groupStack.length > 0) {
        groupStack[groupStack.length - 1].hasInnerQuantifier = true;
      }
    }
  }

  return false;
}

function unquoteYamlScalar(raw) {
  const trimmed = String(raw ?? '').trim();
  if (!trimmed) return '';
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return trimmed
      .slice(1, -1)
      .replace(/\\n/g, '\n')
      .replace(/\\r/g, '\r')
      .replace(/\\t/g, '\t')
      .replace(/\\"/g, '"')
      .replace(/\\\\/g, '\\');
  }
  if (/^(?:true|false)$/i.test(trimmed)) return trimmed.toLowerCase() === 'true';
  if (/^-?\d+(?:\.\d+)?$/.test(trimmed)) return Number(trimmed);
  if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
    const inner = trimmed.slice(1, -1).trim();
    if (!inner) return [];
    return inner.split(',').map(item => unquoteYamlScalar(item));
  }
  return trimmed;
}

/**
 * Lightweight zero-dependency Nuclei-style YAML subset parser for declarative HTTP CVE templates.
 * Also supports JSON strings directly.
 *
 * @param {string|object} rawInput
 * @param {'auto'|'yaml'|'json'} [formatHint='auto']
 * @returns {object}
 */
export function parseDeclarativeTemplate(rawInput, formatHint = 'auto') {
  if (rawInput && typeof rawInput === 'object' && !Array.isArray(rawInput)) {
    return structuredClone(rawInput);
  }
  if (typeof rawInput !== 'string') {
    throw new TemplateValidationError('Template input must be a YAML/JSON string or object');
  }
  if (Buffer.byteLength(rawInput, 'utf8') > MAX_TEMPLATE_FILE_BYTES) {
    throw new TemplateValidationError(`Template exceeds maximum size (${MAX_TEMPLATE_FILE_BYTES} bytes)`);
  }

  const trimmed = rawInput.trim();
  if (!trimmed) {
    throw new TemplateValidationError('Template content is empty');
  }

  if (formatHint === 'json' || trimmed.startsWith('{')) {
    try {
      const parsed = JSON.parse(trimmed);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new TemplateValidationError('JSON template must be a root object');
      }
      return parsed;
    } catch (err) {
      if (err instanceof TemplateValidationError) throw err;
      throw new TemplateValidationError(`Invalid JSON template: ${err.message}`);
    }
  }

  // Parse structured YAML subset for declarative CVE templates
  const lines = trimmed.split(/\r?\n/);
  const tpl = {
    id: '',
    info: {
      name: '',
      severity: 'MEDIUM',
      description: '',
      remediation: '',
      classification: {}
    },
    http: []
  };

  let topSection = null;
  let infoSubsection = null;
  let currentReq = null;
  let reqListTarget = null;
  let currentMatcher = null;
  let matcherListKey = null;

  for (const rawLine of lines) {
    const commentStripped = rawLine.replace(/^\s*#.*$/, '');
    if (!commentStripped.trim()) continue;

    const indent = rawLine.match(/^(\s*)/)[1].length;
    const line = rawLine.trim();

    if (indent === 0) {
      currentReq = null;
      currentMatcher = null;
      reqListTarget = null;
      matcherListKey = null;
      infoSubsection = null;

      const kv = line.match(/^([a-zA-Z0-9_-]+)\s*:\s*(.*)$/);
      if (!kv) continue;
      const key = kv[1];
      const val = kv[2].trim();

      if (key === 'id') {
        tpl.id = String(unquoteYamlScalar(val));
      } else if (key === 'info') {
        topSection = 'info';
      } else if (key === 'http' || key === 'requests') {
        topSection = 'http';
      }
      continue;
    }

    if (topSection === 'info') {
      const kv = line.match(/^([a-zA-Z0-9_-]+)\s*:\s*(.*)$/);
      if (!kv) continue;
      const key = kv[1];
      const val = kv[2].trim();

      if (indent <= 2) {
        if (key === 'classification') {
          infoSubsection = 'classification';
        } else {
          infoSubsection = null;
          tpl.info[key] = unquoteYamlScalar(val);
        }
      } else if (infoSubsection === 'classification') {
        tpl.info.classification[key] = unquoteYamlScalar(val);
      }
      continue;
    }

    if (topSection === 'http') {
      // New HTTP request item at indent 2 (or 0-4 with `- method:` or `- raw:` or `- path:`)
      if (indent <= 4 && line.startsWith('- ') && !reqListTarget && !currentMatcher) {
        currentReq = {
          method: 'GET',
          path: [],
          headers: {},
          body: '',
          'matchers-condition': 'or',
          matchers: []
        };
        tpl.http.push(currentReq);
        const rest = line.slice(2).trim();
        const kv = rest.match(/^([a-zA-Z0-9_-]+)\s*:\s*(.*)$/);
        if (kv) {
          const k = kv[1];
          const v = kv[2].trim();
          if (k === 'method') currentReq.method = String(unquoteYamlScalar(v)).toUpperCase();
          else if (k === 'path') {
            if (v) currentReq.path = [].concat(unquoteYamlScalar(v));
            else reqListTarget = 'path';
          }
        }
        continue;
      }

      if (!currentReq) {
        currentReq = {
          method: 'GET',
          path: [],
          headers: {},
          body: '',
          'matchers-condition': 'or',
          matchers: []
        };
        tpl.http.push(currentReq);
      }

      // Inside matchers block
      if (reqListTarget === 'matchers') {
        if (line.startsWith('- ')) {
          const rest = line.slice(2).trim();
          const kv = rest.match(/^([a-zA-Z0-9_-]+)\s*:\s*(.*)$/);
          if (kv && (kv[1] === 'type' || kv[1] === 'part' || kv[1] === 'negative' || kv[1] === 'condition' || kv[1] === 'status' || kv[1] === 'words' || kv[1] === 'regex')) {
            currentMatcher = {
              type: 'word',
              part: 'body',
              condition: 'or',
              negative: false
            };
            currentReq.matchers.push(currentMatcher);
            matcherListKey = null;
            const k = kv[1];
            const v = kv[2].trim();
            if (v) {
              currentMatcher[k] = unquoteYamlScalar(v);
            } else {
              currentMatcher[k] = [];
              matcherListKey = k;
            }
            continue;
          }
          if (currentMatcher && matcherListKey) {
            if (!Array.isArray(currentMatcher[matcherListKey])) {
              currentMatcher[matcherListKey] = [];
            }
            currentMatcher[matcherListKey].push(unquoteYamlScalar(rest));
            continue;
          }
        }

        if (currentMatcher) {
          const kv = line.match(/^([a-zA-Z0-9_-]+)\s*:\s*(.*)$/);
          if (kv) {
            const k = kv[1];
            const v = kv[2].trim();
            if (k === 'matchers-condition') {
              currentReq['matchers-condition'] = String(unquoteYamlScalar(v)).toLowerCase();
              currentMatcher = null;
              matcherListKey = null;
              continue;
            }
            if (v) {
              currentMatcher[k] = unquoteYamlScalar(v);
              matcherListKey = null;
            } else {
              currentMatcher[k] = [];
              matcherListKey = k;
            }
            continue;
          }
        }
      }

      if (line.startsWith('- ') && reqListTarget === 'path') {
        currentReq.path.push(String(unquoteYamlScalar(line.slice(2))));
        continue;
      }

      if (reqListTarget === 'headers') {
        const hkv = line.match(/^([A-Za-z0-9_-]+)\s*:\s*(.+)$/);
        if (hkv && !['path', 'matchers', 'matchers-condition', 'body', 'method'].includes(hkv[1])) {
          currentReq.headers[hkv[1]] = String(unquoteYamlScalar(hkv[2]));
          continue;
        }
      }

      const kv = line.match(/^([a-zA-Z0-9_-]+)\s*:\s*(.*)$/);
      if (kv) {
        const k = kv[1];
        const v = kv[2].trim();
        if (k === 'method') {
          currentReq.method = String(unquoteYamlScalar(v)).toUpperCase();
          reqListTarget = null;
        } else if (k === 'path') {
          if (v) {
            currentReq.path = [].concat(unquoteYamlScalar(v)).map(String);
            reqListTarget = null;
          } else {
            reqListTarget = 'path';
          }
        } else if (k === 'headers') {
          reqListTarget = 'headers';
        } else if (k === 'body') {
          currentReq.body = String(unquoteYamlScalar(v));
          reqListTarget = null;
        } else if (k === 'matchers-condition') {
          currentReq['matchers-condition'] = String(unquoteYamlScalar(v)).toLowerCase();
        } else if (k === 'matchers') {
          reqListTarget = 'matchers';
          currentMatcher = null;
          matcherListKey = null;
        }
      }
    }
  }

  return tpl;
}

/**
 * Validates a parsed declarative template for ID hygiene, same-origin path containment
 * (blocking SSRF to external URLs), and ReDoS-safe regular expressions.
 *
 * @param {object} tpl
 * @returns {object}
 */
export function validateDeclarativeTemplate(tpl) {
  if (!tpl || typeof tpl !== 'object' || Array.isArray(tpl)) {
    throw new TemplateValidationError('Template must be a non-null object');
  }

  const id = String(tpl.id || '').trim();
  if (!VALID_TEMPLATE_ID_RE.test(id)) {
    throw new TemplateValidationError(`Invalid template id "${id}". Expected 2-80 alphanumeric/._- characters.`);
  }

  const info = tpl.info && typeof tpl.info === 'object' ? tpl.info : null;
  if (!info || typeof info.name !== 'string' || !info.name.trim()) {
    throw new TemplateValidationError(`Template "${id}" is missing info.name`);
  }

  const rawSeverity = String(info.severity || 'MEDIUM').trim().toUpperCase();
  const severity = rawSeverity === 'INFO' ? 'LOW' : rawSeverity;
  if (!VALID_SEVERITIES.has(rawSeverity)) {
    throw new TemplateValidationError(`Template "${id}" has unsupported info.severity "${info.severity}"`);
  }

  const rawRequests = Array.isArray(tpl.http)
    ? tpl.http
    : Array.isArray(tpl.requests)
      ? tpl.requests
      : [];
  if (rawRequests.length === 0) {
    throw new TemplateValidationError(`Template "${id}" must define at least one http/requests block`);
  }

  const normalizedRequests = [];
  for (const req of rawRequests) {
    if (!req || typeof req !== 'object') {
      throw new TemplateValidationError(`Template "${id}" contains an invalid request entry`);
    }
    const method = String(req.method || 'GET').trim().toUpperCase();
    if (!VALID_METHODS.has(method)) {
      throw new TemplateValidationError(`Template "${id}" uses unsupported HTTP method "${method}"`);
    }

    const pathField = req.path !== undefined ? req.path : req.paths;
    const rawPaths = Array.isArray(pathField) ? pathField : (typeof pathField === 'string' ? [pathField] : []);
    if (rawPaths.length === 0) {
      throw new TemplateValidationError(`Template "${id}" request is missing path[]`);
    }

    const relativePaths = [];
    for (const p of rawPaths) {
      const pStr = String(p || '').trim();
      let rel = pStr;
      if (pStr.startsWith('{{BaseURL}}')) {
        rel = pStr.slice('{{BaseURL}}'.length) || '/';
      } else if (pStr.startsWith('{{RootURL}}')) {
        rel = pStr.slice('{{RootURL}}'.length) || '/';
      } else if (!pStr.startsWith('/')) {
        throw new TemplateValidationError(
          `Template "${id}" path "${pStr}" must start with {{BaseURL}}, {{RootURL}}, or / (external URLs are blocked)`
        );
      }

      if (!rel.startsWith('/') || rel.startsWith('//') || rel.includes('://')) {
        throw new TemplateValidationError(
          `Template "${id}" path "${pStr}" attempts to escape target origin (SSRF blocked)`
        );
      }
      relativePaths.push(rel);
    }

    const matchers = Array.isArray(req.matchers) ? req.matchers : [];
    if (matchers.length === 0) {
      throw new TemplateValidationError(`Template "${id}" request must define at least one matcher`);
    }

    const normalizedMatchers = [];
    for (const m of matchers) {
      if (!m || typeof m !== 'object') {
        throw new TemplateValidationError(`Template "${id}" contains an invalid matcher object`);
      }
      const type = String(m.type || 'word').trim().toLowerCase();
      if (!['status', 'word', 'regex', 'header'].includes(type)) {
        throw new TemplateValidationError(`Template "${id}" uses unsupported matcher type "${type}"`);
      }

      if (type === 'regex') {
        const patterns = Array.isArray(m.regex) ? m.regex : (typeof m.regex === 'string' ? [m.regex] : []);
        if (patterns.length === 0) {
          throw new TemplateValidationError(`Template "${id}" regex matcher is missing regex patterns`);
        }
        for (const pat of patterns) {
          const patStr = String(pat || '');
          if (hasNestedQuantifiers(patStr)) {
            throw new TemplateValidationError(
              `Template "${id}" regex pattern "${patStr.slice(0, 60)}" rejected due to nested quantifiers or length > ${MAX_REGEX_PATTERN_LEN} (ReDoS guard)`
            );
          }
          try {
            new RegExp(patStr, 'i');
          } catch (err) {
            throw new TemplateValidationError(`Template "${id}" has invalid regex "${patStr}": ${err.message}`);
          }
        }
      }

      normalizedMatchers.push({
        type,
        part: String(m.part || (type === 'header' ? 'header' : 'body')).toLowerCase(),
        condition: String(m.condition || 'or').toLowerCase() === 'and' ? 'and' : 'or',
        negative: Boolean(m.negative),
        status: Array.isArray(m.status) ? m.status.map(Number) : (m.status !== undefined ? [Number(m.status)] : []),
        words: Array.isArray(m.words) ? m.words.map(String) : (typeof m.words === 'string' ? [m.words] : []),
        regex: Array.isArray(m.regex) ? m.regex.map(String) : (typeof m.regex === 'string' ? [m.regex] : [])
      });
    }

    normalizedRequests.push({
      method,
      paths: relativePaths,
      headers: req.headers && typeof req.headers === 'object' && !Array.isArray(req.headers) ? { ...req.headers } : {},
      body: req.body !== undefined && req.body !== null ? String(req.body) : undefined,
      matchersCondition: String(req['matchers-condition'] || req.matchersCondition || 'or').toLowerCase() === 'and' ? 'and' : 'or',
      matchers: normalizedMatchers
    });
  }

  const classification = info.classification && typeof info.classification === 'object' ? info.classification : {};
  const rawCve =
    classification['cve-id'] ??
    classification.cveId ??
    classification.cveIds ??
    info.cveIds ??
    info.cve ??
    null;
  const cveIds = Array.isArray(rawCve)
    ? rawCve.map(c => String(c).toUpperCase()).filter(Boolean)
    : (typeof rawCve === 'string' && rawCve.trim() ? [rawCve.trim().toUpperCase()] : []);
  const rawCwe = classification['cwe-id'] || classification.cweId || info.cwe || 'CWE-200';
  const cwe = Array.isArray(rawCwe) ? String(rawCwe[0] || 'CWE-200').toUpperCase() : String(rawCwe).toUpperCase();
  const cvssScore = Number.isFinite(Number(classification['cvss-score'] ?? classification.cvssScore ?? info.cvssScore))
    ? Number(classification['cvss-score'] ?? classification.cvssScore ?? info.cvssScore)
    : (severity === 'CRITICAL' ? 9.1 : severity === 'HIGH' ? 7.5 : severity === 'MEDIUM' ? 5.3 : 3.1);

  return {
    id,
    info: {
      name: info.name.trim(),
      severity,
      description: String(info.description || info.name || '').trim(),
      remediation: String(info.remediation || 'Apply vendor security patches and restrict access to sensitive endpoints.').trim(),
      cwe,
      cvssScore,
      cveIds
    },
    requests: normalizedRequests
  };
}

/**
 * Loads and validates declarative `.yaml`, `.yml`, or `.json` CVE templates from a file or directory.
 *
 * @param {string} fileOrDirPath
 * @returns {Array<object>}
 */
export function loadTemplatesFromPath(fileOrDirPath) {
  if (typeof fileOrDirPath !== 'string' || !fileOrDirPath.trim()) {
    throw new TemplateValidationError('Template file or directory path is required');
  }
  const resolved = path.resolve(fileOrDirPath.trim());
  if (!fs.existsSync(resolved)) {
    throw new TemplateValidationError(`Template path not found: ${fileOrDirPath}`, 404);
  }

  const stat = fs.statSync(resolved);
  const files = [];
  if (stat.isFile()) {
    files.push(resolved);
  } else if (stat.isDirectory()) {
    for (const entry of fs.readdirSync(resolved, { withFileTypes: true })) {
      if (entry.isFile() && /\.(?:ya?ml|json)$/i.test(entry.name)) {
        files.push(path.join(resolved, entry.name));
      }
    }
    files.sort();
  }

  const templates = [];
  for (const f of files) {
    const raw = fs.readFileSync(f, 'utf8');
    const formatHint = f.toLowerCase().endsWith('.json') ? 'json' : 'yaml';
    const parsed = parseDeclarativeTemplate(raw, formatHint);
    templates.push(validateDeclarativeTemplate(parsed));
  }
  return templates;
}

function serializeHeadersForMatch(headers) {
  if (!headers || typeof headers !== 'object') return '';
  if (typeof headers.entries === 'function') {
    const lines = [];
    for (const [k, v] of headers.entries()) {
      lines.push(`${k}: ${v}`);
    }
    return lines.join('\n');
  }
  return Object.entries(headers)
    .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join('; ') : String(v ?? '')}`)
    .join('\n');
}

function evaluateSingleMatcher(matcher, res) {
  const status = Number(res?.status ?? 0);
  const bodyText = typeof res?.text === 'string' ? res.text : '';
  const headerText = serializeHeadersForMatch(res?.headers);
  const rawCorpus =
    matcher.part === 'header' || matcher.type === 'header'
      ? headerText
      : matcher.part === 'all'
        ? `${headerText}\n${bodyText}`
        : bodyText;
  const targetCorpus = rawCorpus.slice(0, 65536);

  let rawMatched = false;
  let quote = null;

  if (matcher.type === 'status') {
    rawMatched = matcher.status.includes(status);
  } else if (matcher.type === 'word' || matcher.type === 'header') {
    const matches = [];
    for (const w of matcher.words) {
      const has = targetCorpus.toLowerCase().includes(w.toLowerCase());
      matches.push(has);
      if (has && !quote) {
        quote = extractVerbatimSnippet(targetCorpus, w) || (w.length >= 8 ? w : null);
      }
    }
    rawMatched =
      matcher.condition === 'and'
        ? matches.length > 0 && matches.every(Boolean)
        : matches.some(Boolean);
  } else if (matcher.type === 'regex') {
    const matches = [];
    for (const pat of matcher.regex) {
      const re = new RegExp(pat, 'i');
      const m = re.exec(targetCorpus);
      const has = Boolean(m);
      matches.push(has);
      if (m && !quote) {
        quote = extractVerbatimSnippet(targetCorpus, re) || (m[0].length >= 8 ? m[0] : null);
      }
    }
    rawMatched =
      matcher.condition === 'and'
        ? matches.length > 0 && matches.every(Boolean)
        : matches.some(Boolean);
  }

  const finalMatched = matcher.negative ? !rawMatched : rawMatched;
  return { matched: finalMatched, quote: finalMatched ? quote : null };
}

/**
 * Executes a validated declarative template against `targetUrl`, automatically wrapping
 * responses in SecScan's Soft-404 shingle filter (`isSoft404Response`) and Pre-Report Gate (`verifyFindingBeforeReport`).
 *
 * @param {object|string} templateOrRaw
 * @param {string} targetUrl
 * @param {Function} fetchWithRetry
 * @param {object} [options={}]
 * @returns {Promise<object>}
 */
export async function runDeclarativeTemplate(templateOrRaw, targetUrl, fetchWithRetry, options = {}) {
  const parsed = typeof templateOrRaw === 'string'
    ? parseDeclarativeTemplate(templateOrRaw)
    : templateOrRaw;
  const tpl = validateDeclarativeTemplate(parsed);

  let baseline404Res = options.baseline404Res || null;
  if (!baseline404Res && options.enableSoft404Filter !== false) {
    const canaryUrl = resolveTargetUrl(targetUrl, '/.secscan_tpl_404_canary');
    if (canaryUrl) {
      try {
        baseline404Res = await fetchWithRetry(canaryUrl, { followRedirects: false });
      } catch {
        baseline404Res = null;
      }
    }
  }

  for (const reqBlock of tpl.requests) {
    for (const relPath of reqBlock.paths) {
      const fullUrl = resolveTargetUrl(targetUrl, relPath);
      if (!fullUrl) continue;

      let res;
      try {
        res = await fetchWithRetry(fullUrl, {
          method: reqBlock.method,
          headers: reqBlock.headers,
          ...(reqBlock.body !== undefined ? { body: reqBlock.body } : {}),
          followRedirects: false
        });
      } catch (err) {
        if (err?.isGovernanceBlock) throw err;
        continue;
      }

      if (!res) continue;

      // Soft-404 suppression: skip HTTP 200 responses that match the target's soft-404 page
      const expects404 = reqBlock.matchers.some(m => m.type === 'status' && m.status.includes(404));
      if (!expects404 && isSoft404Response(res, baseline404Res)) {
        continue;
      }

      const evalResults = reqBlock.matchers.map(m => evaluateSingleMatcher(m, res));
      const allPassed =
        reqBlock.matchersCondition === 'and'
          ? evalResults.every(r => r.matched)
          : evalResults.some(r => r.matched);

      if (!allPassed) continue;

      const quotes = evalResults
        .map(r => r.quote)
        .filter(q => typeof q === 'string' && q.trim().length >= 8);
      if (quotes.length === 0) {
        const ctHeader = getHeader(res.headers, 'content-type');
        if (ctHeader && `Content-Type: ${ctHeader}`.length >= 8) {
          quotes.push(`Content-Type: ${ctHeader}`);
        } else if (typeof res.text === 'string' && res.text.trim().length >= 8) {
          quotes.push(res.text.trim().slice(0, 80));
        }
      }

      const candidateFinding = {
        checkId: tpl.id,
        name: tpl.info.name,
        target: targetUrl,
        url: fullUrl,
        path: relPath,
        method: reqBlock.method,
        status: 'VULNERABLE',
        severity: tpl.info.severity,
        cwe: tpl.info.cwe,
        owasp: 'A06:2021-Vulnerable and Outdated Components',
        cvssScore: tpl.info.cvssScore,
        ...(tpl.info.cveIds.length > 0 ? { cve: tpl.info.cveIds[0], cveIds: tpl.info.cveIds } : { cveIds: [] }),
        detail: `${tpl.info.description} (matched declarative template ${tpl.id} on ${reqBlock.method} ${relPath})`,
        fix: tpl.info.remediation,
        poeLevel: quotes.length > 0 ? 3 : 2,
        reproVerified: true,
        ...(quotes.length > 0 ? { evidenceQuotes: quotes } : {}),
        ...(res.trafficId !== undefined ? { trafficId: res.trafficId } : {})
      };

      return verifyFindingBeforeReport(candidateFinding, options);
    }
  }

  return verifyFindingBeforeReport(
    {
      checkId: tpl.id,
      name: tpl.info.name,
      target: targetUrl,
      status: 'SAFE',
      severity: 'NONE',
      cveIds: [],
      detail: `Template ${tpl.id} did not match any vulnerable conditions`
    },
    options
  );
}
