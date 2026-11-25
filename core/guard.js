import crypto from 'node:crypto';
import net from 'node:net';
import { URL } from 'node:url';
import { voidsExemption, expandIPv6 } from './validator.js';

export const PLATFORM_CONTROL_PREFIX = '[SECSCAN platform control, not target defense]';

/**
 * Built-in high-risk TLD deny rules (.gov, .mil, .edu, .gov.cn, .edu.cn).
 */
export const BUILTIN_DENY_RULES = Object.freeze([
  Object.freeze({
    id: 'builtin-deny-gov',
    ruleType: 'fuzzy_domain',
    pattern: '.gov',
    isAllowed: false,
    action: 'deny',
    note: 'Built-in government TLD deny rule (.gov)'
  }),
  Object.freeze({
    id: 'builtin-deny-mil',
    ruleType: 'fuzzy_domain',
    pattern: '.mil',
    isAllowed: false,
    action: 'deny',
    note: 'Built-in military TLD deny rule (.mil)'
  }),
  Object.freeze({
    id: 'builtin-deny-edu',
    ruleType: 'fuzzy_domain',
    pattern: '.edu',
    isAllowed: false,
    action: 'deny',
    note: 'Built-in education TLD deny rule (.edu)'
  }),
  Object.freeze({
    id: 'builtin-deny-gov-cn',
    ruleType: 'fuzzy_domain',
    pattern: '.gov.cn',
    isAllowed: false,
    action: 'deny',
    note: 'Built-in government TLD deny rule (.gov.cn)'
  }),
  Object.freeze({
    id: 'builtin-deny-edu-cn',
    ruleType: 'fuzzy_domain',
    pattern: '.edu.cn',
    isAllowed: false,
    action: 'deny',
    note: 'Built-in education TLD deny rule (.edu.cn)'
  })
]);

/**
 * Converts an IPv4 or IPv6 literal string into `{ version: 4|6, value: BigInt, bits: 32|128 }`, or null.
 *
 * @param {string} rawIp
 * @returns {{ version: 4|6, value: bigint, bits: 32|128 } | null}
 */
export function parseIpToBigInt(rawIp) {
  if (typeof rawIp !== 'string' || !rawIp.trim()) return null;
  const clean = rawIp.trim().replace(/^\[|\]$/g, '').toLowerCase();

  const ipv4Match = clean.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const [o1, o2, o3, o4] = ipv4Match.slice(1).map(Number);
    if ([o1, o2, o3, o4].some(o => o > 255)) return null;
    const value =
      (BigInt(o1) << 24n) |
      (BigInt(o2) << 16n) |
      (BigInt(o3) << 8n) |
      BigInt(o4);
    return { version: 4, value, bits: 32 };
  }

  if (clean.includes(':')) {
    const words = expandIPv6(clean);
    if (!words) return null;
    let value = 0n;
    for (const w of words) {
      value = (value << 16n) | BigInt(w);
    }
    return { version: 6, value, bits: 128 };
  }

  return null;
}

/**
 * Checks whether an IPv4 or IPv6 address matches a CIDR block (e.g., 10.0.0.0/8 or 2001:db8::/32).
 *
 * @param {string} ipStr
 * @param {string} cidrStr
 * @returns {boolean}
 */
export function ipMatchesCidr(ipStr, cidrStr) {
  if (typeof ipStr !== 'string' || typeof cidrStr !== 'string') return false;
  const trimmedCidr = cidrStr.trim();
  const slashIdx = trimmedCidr.indexOf('/');
  if (slashIdx === -1) {
    const ipParsed = parseIpToBigInt(ipStr);
    const netParsed = parseIpToBigInt(trimmedCidr);
    return Boolean(ipParsed && netParsed && ipParsed.version === netParsed.version && ipParsed.value === netParsed.value);
  }

  const netPart = trimmedCidr.slice(0, slashIdx).trim();
  const prefixStr = trimmedCidr.slice(slashIdx + 1).trim();
  if (!/^\d+$/.test(prefixStr)) return false;

  const prefixLen = Number(prefixStr);
  const ipParsed = parseIpToBigInt(ipStr);
  const netParsed = parseIpToBigInt(netPart);
  if (!ipParsed || !netParsed || ipParsed.version !== netParsed.version) {
    return false;
  }

  const totalBits = ipParsed.bits;
  if (prefixLen < 0 || prefixLen > totalBits) return false;
  if (prefixLen === 0) return true;

  const shift = BigInt(totalBits - prefixLen);
  const mask = ((1n << BigInt(prefixLen)) - 1n) << shift;
  return (ipParsed.value & mask) === (netParsed.value & mask);
}

/**
 * Normalizes a target input (URL string, host string, IP string, or object) into
 * `{ url, hostname, ips, path }` for scope and deny evaluation.
 */
function normalizeTargetForGate(targetInput) {
  let rawUrl = '';
  let hostname = '';
  let pathStr = '';
  const ips = new Set();

  if (typeof targetInput === 'string') {
    const trimmed = targetInput.trim();
    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) {
      rawUrl = trimmed;
      try {
        const parsed = new URL(trimmed);
        hostname = parsed.hostname.toLowerCase().replace(/\.+$/, '').replace(/^\[|\]$/g, '');
        pathStr = `${parsed.pathname || '/'}${parsed.search || ''}`;
        rawUrl = parsed.toString().replace(/\/+$/, '');
      } catch {
        hostname = trimmed.toLowerCase();
      }
    } else {
      // Could be IPv6 in brackets [2001:db8::1]:8080, IPv4:port, or domain/path
      const slashIdx = trimmed.indexOf('/');
      const authority = slashIdx === -1 ? trimmed : trimmed.slice(0, slashIdx);
      pathStr = slashIdx === -1 ? '/' : trimmed.slice(slashIdx);

      if (authority.startsWith('[')) {
        const closeIdx = authority.indexOf(']');
        hostname = closeIdx !== -1 ? authority.slice(1, closeIdx).toLowerCase() : authority.toLowerCase();
      } else if (authority.split(':').length > 2) {
        // Unbracketed IPv6 literal
        hostname = authority.toLowerCase();
      } else {
        hostname = authority.replace(/:\d+$/, '').toLowerCase().replace(/\.+$/, '');
      }
      rawUrl = `http://${authority}${slashIdx === -1 ? '' : pathStr}`;
    }
  } else if (targetInput && typeof targetInput === 'object') {
    if (typeof targetInput.url === 'string' && targetInput.url.trim()) {
      const fromUrl = normalizeTargetForGate(targetInput.url);
      rawUrl = fromUrl.url;
      hostname = fromUrl.hostname;
      pathStr = fromUrl.path;
      for (const ip of fromUrl.ips) ips.add(ip);
    }
    const explicitHost = targetInput.hostname || targetInput.host || targetInput.domain;
    if (typeof explicitHost === 'string' && explicitHost.trim()) {
      hostname = explicitHost.trim().toLowerCase().replace(/\.+$/, '').replace(/^\[|\]$/g, '');
    }
    if (typeof targetInput.ip === 'string' && targetInput.ip.trim()) {
      ips.add(targetInput.ip.trim().replace(/^\[|\]$/g, '').toLowerCase());
    }
    if (Array.isArray(targetInput.resolvedIps)) {
      for (const rIp of targetInput.resolvedIps) {
        if (typeof rIp === 'string' && rIp.trim()) {
          ips.add(rIp.trim().replace(/^\[|\]$/g, '').toLowerCase());
        }
      }
    }
    if (!rawUrl && hostname) {
      rawUrl = `http://${hostname.includes(':') ? `[${hostname}]` : hostname}`;
    }
  }

  if (hostname && net.isIP(hostname) !== 0) {
    ips.add(hostname);
  }

  return {
    url: rawUrl,
    hostname,
    path: pathStr,
    ips: Array.from(ips)
  };
}

/**
 * Converts a wildcard glob pattern (containing `*`) into a RegExp.
 */
function globToRegExp(globPattern) {
  const escaped = globPattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`, 'i');
}

/**
 * Checks whether a single scope/deny rule matches the normalized target.
 */
function matchesAssetRule(target, rule) {
  if (!rule || rule.enabled === false) return false;
  const rawType = String(rule.ruleType || rule.rule_type || rule.kind || rule.type || 'exact_domain').toLowerCase();
  const rawPattern = String(rule.pattern || rule.value || '').trim();
  if (!rawPattern) return false;

  const patLower = rawPattern.toLowerCase();
  const { url, hostname, ips } = target;

  switch (rawType) {
    case 'exact_domain':
    case 'domain': {
      const cleanPat = patLower.replace(/^\.+|\.+$/g, '');
      return Boolean(hostname && hostname === cleanPat);
    }

    case 'fuzzy_domain':
    case 'wildcard_domain':
    case 'suffix_domain': {
      if (!hostname) return false;
      // Handle explicit glob patterns like api-*.example.com
      if (patLower.includes('*') && !patLower.startsWith('*.')) {
        return globToRegExp(patLower).test(hostname);
      }
      const cleanPat = patLower.replace(/^\*\./, '').replace(/^\.+|\.+$/g, '');
      if (!cleanPat) return false;
      // Match exact domain, subdomain suffix (.cleanPat), or multi-part TLD segment (.gov.uk if pattern is .gov)
      if (hostname === cleanPat || hostname.endsWith(`.${cleanPat}`)) {
        return true;
      }
      // If rule is a TLD rule like .gov, .mil, .edu, also block gov.<ccTLD> (e.g. agency.gov.uk)
      if (rawPattern.startsWith('.') && !cleanPat.includes('.')) {
        if (hostname.includes(`.${cleanPat}.`)) {
          return true;
        }
      }
      return false;
    }

    case 'exact_ip':
    case 'ip': {
      const targetBig = parseIpToBigInt(rawPattern);
      for (const candidateIp of ips) {
        if (candidateIp === patLower.replace(/^\[|\]$/g, '')) return true;
        const candBig = parseIpToBigInt(candidateIp);
        if (targetBig && candBig && targetBig.version === candBig.version && targetBig.value === candBig.value) {
          return true;
        }
      }
      return false;
    }

    case 'fuzzy_ip': {
      for (const candidateIp of ips) {
        if (patLower.includes('*')) {
          if (globToRegExp(patLower).test(candidateIp)) return true;
        } else if (candidateIp.startsWith(patLower)) {
          return true;
        }
      }
      return false;
    }

    case 'cidr': {
      for (const candidateIp of ips) {
        if (ipMatchesCidr(candidateIp, rawPattern)) {
          return true;
        }
      }
      return false;
    }

    case 'exact_url': {
      if (!url) return false;
      const normCandidate = url.replace(/\/+$/, '').toLowerCase();
      const normPattern = rawPattern.replace(/\/+$/, '').toLowerCase();
      return normCandidate === normPattern;
    }

    case 'fuzzy_url': {
      if (!url) return false;
      const urlLower = url.toLowerCase();
      if (patLower.includes('*')) {
        return globToRegExp(patLower).test(urlLower);
      }
      return urlLower.startsWith(patLower) || urlLower.includes(patLower);
    }

    default:
      return false;
  }
}

/**
 * Determines whether a scope rule is a deny/block rule (`false`) or an allow rule (`true`).
 */
function isRuleAllow(rule) {
  if (typeof rule.isAllowed === 'boolean') return rule.isAllowed;
  if (typeof rule.is_allowed === 'boolean') return rule.is_allowed;
  if (typeof rule.is_allowed === 'number') return rule.is_allowed !== 0;
  const action = String(rule.action || rule.constraint_type || rule.constraintType || '').toLowerCase();
  if (action === 'deny' || action === 'block') return false;
  if (action === 'allow') return true;
  return true;
}

/**
 * Evaluates a target against built-in and custom Scope/Deny asset rules.
 *
 * Precedence:
 * 1. Block-first: If any deny rule matches, immediately reject with `[SECSCAN platform control, not target defense]`.
 * 2. Allow-whitelist: If at least one allow rule is present in `rules`, the target must match at least one allow rule.
 *
 * @param {string | object} targetInput
 * @param {{ rules?: Array<object>, includeBuiltinDeny?: boolean }} [options]
 * @returns {{ allowed: boolean, matchedRule: object | null, code?: string, reason: string }}
 */
export function evaluateAssetGate(
  targetInput,
  { rules = [], includeBuiltinDeny = true } = {}
) {
  const target = normalizeTargetForGate(targetInput);
  const customRules = Array.isArray(rules) ? rules.filter(r => r && r.enabled !== false) : [];
  const denyRules = [
    ...(includeBuiltinDeny ? BUILTIN_DENY_RULES : []),
    ...customRules.filter(r => !isRuleAllow(r))
  ];
  const allowRules = customRules.filter(r => isRuleAllow(r));

  // 1. Block-first evaluation
  for (const denyRule of denyRules) {
    if (matchesAssetRule(target, denyRule)) {
      const ruleType = denyRule.ruleType || denyRule.rule_type || denyRule.kind || 'rule';
      return {
        allowed: false,
        matchedRule: denyRule,
        code: 'TARGET_RULE_BLOCKED',
        reason: `${PLATFORM_CONTROL_PREFIX} Target blocked by deny rule: ${denyRule.pattern} (${ruleType})`
      };
    }
  }

  // 2. Allow-whitelist evaluation (when at least one allow rule is declared)
  if (allowRules.length > 0) {
    for (const allowRule of allowRules) {
      if (matchesAssetRule(target, allowRule)) {
        return {
          allowed: true,
          matchedRule: allowRule,
          code: 'TARGET_ALLOWED',
          reason: `Target matched allow rule: ${allowRule.pattern}`
        };
      }
    }

    return {
      allowed: false,
      matchedRule: null,
      code: 'TARGET_OUT_OF_SCOPE',
      reason: `${PLATFORM_CONTROL_PREFIX} Target outside declared allow scope`
    };
  }

  return {
    allowed: true,
    matchedRule: null,
    code: 'TARGET_ALLOWED',
    reason: 'Target allowed (no restrictive allow scope declared)'
  };
}

/**
 * Tracks pinned DNS IPs per hostname for a scan/task and rejects DNS rebinding
 * (when a subsequent resolution switches from a public IP to a voidsExemption(ip) address
 * or deviates from pinned IPs).
 */
export class TargetPinStore {
  constructor({ allowPrivate = false, strictSubset = true } = {}) {
    this.allowPrivate = Boolean(allowPrivate);
    this.strictSubset = Boolean(strictSubset);
    this.pins = new Map();
    this._versionSeq = 0;
  }

  _normalizeHost(hostname) {
    return String(hostname || '')
      .trim()
      .toLowerCase()
      .replace(/\.+$/, '')
      .replace(/^\[|\]$/g, '');
  }

  /**
   * Explicitly pins a set of IP addresses for a hostname.
   */
  pin(hostname, ips = []) {
    const key = this._normalizeHost(hostname);
    const normIps = Array.from(
      new Set((Array.isArray(ips) ? ips : [ips]).map(ip => String(ip).trim().replace(/^\[|\]$/g, '')))
    ).filter(Boolean);

    const existing = this.pins.get(key);
    const record = {
      hostname: key,
      pinnedIps: new Set(normIps),
      hadPublicIp: normIps.some(ip => !voidsExemption(ip)),
      firstSeenAt: existing ? existing.firstSeenAt : Date.now(),
      updatedAt: Date.now(),
      version: ++this._versionSeq
    };
    this.pins.set(key, record);
    return {
      hostname: key,
      pinnedIps: Array.from(record.pinnedIps),
      version: record.version
    };
  }

  /**
   * Verifies a newly resolved IP set against existing pins for `hostname`, or records a new pin.
   * Rejects if any resolved IP is private/reserved (`voidsExemption(ip)`) or rebinds after pinning.
   */
  verifyOrPin(hostname, resolvedIps = [], { allowPrivate } = {}) {
    const key = this._normalizeHost(hostname);
    const permitPrivate = allowPrivate !== undefined ? Boolean(allowPrivate) : this.allowPrivate;
    const normIps = Array.from(
      new Set((Array.isArray(resolvedIps) ? resolvedIps : [resolvedIps]).map(ip => String(ip).trim().replace(/^\[|\]$/g, '')))
    ).filter(Boolean);

    if (!key || normIps.length === 0) {
      return {
        valid: false,
        allowed: false,
        code: 'DNS_RESOLUTION_FAILED',
        reason: `${PLATFORM_CONTROL_PREFIX} No valid resolved IPs to pin for "${key}"`
      };
    }

    const existing = this.pins.get(key);

    // Check if any resolved IP falls into private/loopback/metadata/reserved space
    if (!permitPrivate) {
      for (const ip of normIps) {
        if (voidsExemption(ip)) {
          const isRebind = Boolean(existing && existing.hadPublicIp);
          return {
            valid: false,
            allowed: false,
            rebindDetected: isRebind,
            code: 'DNS_REBIND_OR_PRIVATE_IP',
            reason: isRebind
              ? `${PLATFORM_CONTROL_PREFIX} DNS rebinding detected for "${key}": previously pinned to [${Array.from(existing.pinnedIps).join(', ')}], now resolved to private/reserved IP "${ip}"`
              : `${PLATFORM_CONTROL_PREFIX} DNS resolution for "${key}" returned private/reserved IP "${ip}"`
          };
        }
      }
    }

    if (existing) {
      // Even if permitPrivate was passed on a subsequent call, never allow a public pin to switch to a voidsExemption IP
      if (existing.hadPublicIp) {
        for (const ip of normIps) {
          if (voidsExemption(ip)) {
            return {
              valid: false,
              allowed: false,
              rebindDetected: true,
              code: 'DNS_REBIND_OR_PRIVATE_IP',
              reason: `${PLATFORM_CONTROL_PREFIX} DNS rebinding detected for "${key}": switched from public IP [${Array.from(existing.pinnedIps).join(', ')}] to internal IP "${ip}"`
            };
          }
        }
      }

      if (this.strictSubset) {
        const unpinned = normIps.filter(ip => !existing.pinnedIps.has(ip));
        if (unpinned.length > 0) {
          return {
            valid: false,
            allowed: false,
            rebindDetected: true,
            code: 'DNS_REBIND_OR_PRIVATE_IP',
            reason: `${PLATFORM_CONTROL_PREFIX} DNS pin mismatch for "${key}": resolved [${normIps.join(', ')}] not in pinned set [${Array.from(existing.pinnedIps).join(', ')}]`
          };
        }
      }

      return {
        valid: true,
        allowed: true,
        hostname: key,
        pinnedIps: Array.from(existing.pinnedIps),
        newlyPinned: false
      };
    }

    // First resolution for this hostname: pin it
    const record = {
      hostname: key,
      pinnedIps: new Set(normIps),
      hadPublicIp: normIps.some(ip => !voidsExemption(ip)),
      firstSeenAt: Date.now(),
      updatedAt: Date.now(),
      version: ++this._versionSeq
    };
    this.pins.set(key, record);

    return {
      valid: true,
      allowed: true,
      hostname: key,
      pinnedIps: Array.from(record.pinnedIps),
      newlyPinned: true
    };
  }

  getPin(hostname) {
    const key = this._normalizeHost(hostname);
    const rec = this.pins.get(key);
    if (!rec) return null;
    return {
      hostname: rec.hostname,
      pinnedIps: Array.from(rec.pinnedIps),
      hadPublicIp: rec.hadPublicIp,
      firstSeenAt: rec.firstSeenAt,
      updatedAt: rec.updatedAt,
      version: rec.version
    };
  }

  listPins() {
    return Array.from(this.pins.keys()).map(k => this.getPin(k));
  }

  clear(hostname) {
    if (hostname !== undefined) {
      this.pins.delete(this._normalizeHost(hostname));
    } else {
      this.pins.clear();
    }
  }
}

/**
 * Hardcoded interpreter, shell, launcher, and privilege-escalation binaries that
 * can NEVER be auto-approved by prefix/allow intercept rules.
 */
export const ALWAYS_ALLOW_DENYLIST = new Set([
  'sh',
  'bash',
  'zsh',
  'dash',
  'ksh',
  'csh',
  'pwsh',
  'powershell',
  'cmd',
  'python',
  'python3',
  'node',
  'deno',
  'bun',
  'perl',
  'ruby',
  'php',
  'lua',
  'awk',
  'sed',
  'find',
  'xargs',
  'env',
  'sudo',
  'su',
  'curl',
  'wget',
  'nc',
  'ncat',
  'socat',
  'ssh',
  'scp'
]);

/**
 * Extracts and normalizes a binary basename from a path/token (stripping directory paths and .exe/.cmd extensions).
 */
export function normalizeBinaryName(rawBin) {
  if (typeof rawBin !== 'string' || !rawBin.trim()) return '';
  const base = rawBin
    .trim()
    .replace(/^['"]|['"]$/g, '')
    .split(/[\\/]/)
    .pop()
    .toLowerCase()
    .replace(/\.(exe|cmd|bat|ps1|sh)$/i, '');
  return base;
}

/**
 * Checks if a binary name (including versioned interpreters like python3.11) is in ALWAYS_ALLOW_DENYLIST.
 */
export function isBinaryDenylisted(rawBin) {
  const norm = normalizeBinaryName(rawBin);
  if (!norm) return false;
  if (ALWAYS_ALLOW_DENYLIST.has(norm)) return true;
  // Strip trailing version numbers (e.g., python3.11 -> python3 / python, php8.2 -> php)
  const strippedMinor = norm.replace(/\.\d+.*$/, '');
  if (ALWAYS_ALLOW_DENYLIST.has(strippedMinor)) return true;
  const strippedAllDigits = norm.replace(/\d+(\.\d+)*$/, '');
  if (strippedAllDigits && ALWAYS_ALLOW_DENYLIST.has(strippedAllDigits)) return true;
  return false;
}

/**
 * Parses a single simple command into an `argv` array while strictly rejecting:
 * - shell chaining (`;`, `&&`, `||`, `|`, `&`)
 * - command/parameter substitution (`` ` ``, `$(`, `${`)
 * - input/output redirection (`>`, `<`)
 * - subshells / brace expansion (`(`, `)`, `{`, `}`)
 * - newlines / control characters (`\n`, `\r`, `\0`)
 * - leading environment variable assignments (`FOO=bar cmd`)
 *
 * @param {string} cmdStr
 * @returns {{ valid: boolean, argv: string[], binary?: string, rawBinary?: string, prefix?: string, isDenylisted?: boolean, reason?: string }}
 */
export function parseSimpleCommand(cmdStr) {
  if (typeof cmdStr !== 'string' || !cmdStr.trim()) {
    return {
      valid: false,
      argv: [],
      reason: 'Command must be a non-empty string'
    };
  }

  if (/[\r\n\0]/.test(cmdStr)) {
    return {
      valid: false,
      argv: [],
      reason: 'Newlines or control characters are not allowed in simple commands'
    };
  }

  const argv = [];
  let current = '';
  let hasTokenChars = false;
  let inSingle = false;
  let inDouble = false;

  for (let i = 0; i < cmdStr.length; i++) {
    const ch = cmdStr[i];
    const next = cmdStr[i + 1] || '';

    if (inSingle) {
      if (ch === "'") {
        inSingle = false;
      } else {
        current += ch;
      }
      continue;
    }

    if (inDouble) {
      if (ch === '"') {
        inDouble = false;
        continue;
      }
      if (ch === '`') {
        return {
          valid: false,
          argv: [],
          reason: 'Backtick command substitution is not allowed'
        };
      }
      if (ch === '$' && (next === '(' || next === '{' || /[A-Za-z0-9_@*#?$!-]/.test(next))) {
        return {
          valid: false,
          argv: [],
          reason: 'Command or parameter expansion ($() / ${} / $VAR) is not allowed'
        };
      }
      if (ch === '\\') {
        if (i + 1 >= cmdStr.length) {
          return { valid: false, argv: [], reason: 'Trailing backslash escape in command' };
        }
        current += cmdStr[++i];
        continue;
      }
      current += ch;
      continue;
    }

    // Outside quotes
    if (/\s/.test(ch)) {
      if (hasTokenChars) {
        argv.push(current);
        current = '';
        hasTokenChars = false;
      }
      continue;
    }

    if (ch === "'") {
      inSingle = true;
      hasTokenChars = true;
      continue;
    }

    if (ch === '"') {
      inDouble = true;
      hasTokenChars = true;
      continue;
    }

    // Reject shell chaining and background operators: ; | & && ||
    if (ch === ';' || ch === '|' || ch === '&') {
      const op = (ch === '&' && next === '&') ? '&&' : (ch === '|' && next === '|') ? '||' : ch;
      return {
        valid: false,
        argv: [],
        reason: `Shell chaining or pipeline operator "${op}" is not allowed`
      };
    }

    // Reject redirection operators: > < >> <<
    if (ch === '>' || ch === '<') {
      return {
        valid: false,
        argv: [],
        reason: `Shell redirection operator "${ch}" is not allowed`
      };
    }

    // Reject command/process/parameter expansion and subshells/braces: ` $( ${ ( ) { }
    if (ch === '`') {
      return {
        valid: false,
        argv: [],
        reason: 'Backtick command substitution is not allowed'
      };
    }
    if (ch === '$') {
      return {
        valid: false,
        argv: [],
        reason: 'Shell expansion ($) is not allowed in simple commands'
      };
    }
    if (ch === '(' || ch === ')' || ch === '{' || ch === '}') {
      return {
        valid: false,
        argv: [],
        reason: `Subshell or brace token "${ch}" is not allowed`
      };
    }

    if (ch === '\\') {
      if (i + 1 >= cmdStr.length) {
        return { valid: false, argv: [], reason: 'Trailing backslash in command' };
      }
      current += cmdStr[++i];
      hasTokenChars = true;
      continue;
    }

    current += ch;
    hasTokenChars = true;
  }

  if (inSingle || inDouble) {
    return {
      valid: false,
      argv: [],
      reason: 'Unclosed quote in command string'
    };
  }

  if (hasTokenChars) {
    argv.push(current);
  }

  if (argv.length === 0) {
    return {
      valid: false,
      argv: [],
      reason: 'Empty command'
    };
  }

  // Reject leading environment variable assignments (e.g., FOO=bar cmd or LD_PRELOAD=/tmp/x.so cmd)
  if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(argv[0])) {
    return {
      valid: false,
      argv: [],
      reason: `Environment variable assignment "${argv[0]}" is not allowed in simple commands`
    };
  }

  const binary = normalizeBinaryName(argv[0]);
  const isDenylisted = isBinaryDenylisted(argv[0]);

  // Compute canonical prefix (up to 2 tokens for multi-subcommand CLI tools like git, npm, docker)
  const multiSubcommandTools = new Set(['git', 'npm', 'pnpm', 'yarn', 'docker', 'kubectl', 'cargo', 'go']);
  let prefix = binary;
  if (multiSubcommandTools.has(binary) && argv.length > 1 && !argv[1].startsWith('-')) {
    prefix = `${binary} ${argv[1]}`;
  }

  return {
    valid: true,
    argv,
    binary,
    rawBinary: argv[0],
    prefix,
    isDenylisted
  };
}

/**
 * Built-in destructive command intercept rules.
 */
export const BUILTIN_INTERCEPT_RULES = Object.freeze([
  Object.freeze({
    id: 'builtin-deny-rm-rf-root',
    name: 'Block destructive rm -rf',
    matchType: 'regex',
    pattern: '\\brm\\s+(-[a-zA-Z]*r[a-zA-Z]*f|--recursive)\\b',
    action: 'deny',
    priority: 1000,
    message: `${PLATFORM_CONTROL_PREFIX} Destructive file deletion command blocked`
  }),
  Object.freeze({
    id: 'builtin-deny-mkfs-dd',
    name: 'Block disk formatting and raw device writes',
    matchType: 'regex',
    pattern: '\\b(mkfs(\\.[a-z0-9]+)?|dd\\s+if=|shutdown|reboot|init\\s+0)\\b',
    action: 'deny',
    priority: 1000,
    message: `${PLATFORM_CONTROL_PREFIX} Destructive system command blocked`
  }),
  Object.freeze({
    id: 'builtin-deny-sql-drop',
    name: 'Block destructive database DDL/flush operations',
    matchType: 'regex',
    pattern: '\\b(DROP\\s+(TABLE|DATABASE|SCHEMA)|TRUNCATE\\s+TABLE|FLUSHALL|dropDatabase)\\b',
    action: 'deny',
    priority: 1000,
    message: `${PLATFORM_CONTROL_PREFIX} Destructive database command blocked`
  })
]);

/**
 * Evaluates a command string or tool action against intercept rules (`string`, `regex`, `argv`),
 * enforcing `ALWAYS_ALLOW_DENYLIST` so interpreter/launcher binaries can never be auto-approved.
 *
 * @param {string | object} commandOrAction
 * @param {Array<object>} [rules=[]]
 * @param {{ includeBuiltin?: boolean }} [options]
 * @returns {{ allowed: boolean, action: 'allow'|'deny'|'ask', decision: 'allow'|'deny'|'ask', denylisted?: boolean, matchedRule: object | null, reason: string }}
 */
export function evaluateInterceptRules(
  commandOrAction,
  rules = [],
  { includeBuiltin = true } = {}
) {
  const commandStr = typeof commandOrAction === 'string'
    ? commandOrAction.trim()
    : String(
        commandOrAction?.command ||
        commandOrAction?.cmd ||
        commandOrAction?.input ||
        commandOrAction?.toolName ||
        commandOrAction?.tool ||
        ''
      ).trim();

  const parsedCmd = parseSimpleCommand(commandStr);
  const firstToken = commandStr.split(/\s+/)[0] || '';
  const detectedBinary = parsedCmd.valid ? parsedCmd.binary : normalizeBinaryName(firstToken);
  const cmdIsDenylisted = parsedCmd.valid
    ? Boolean(parsedCmd.isDenylisted)
    : isBinaryDenylisted(firstToken);

  const activeRules = [
    ...(includeBuiltin ? BUILTIN_INTERCEPT_RULES : []),
    ...(Array.isArray(rules) ? rules.filter(r => r && r.enabled !== false) : [])
  ];

  // Sort so deny rules and higher priority rules run first
  const sortedRules = [...activeRules].sort((a, b) => {
    const aDeny = (a.action === 'deny' || a.action === 'block' || a.isAllowed === false) ? 1 : 0;
    const bDeny = (b.action === 'deny' || b.action === 'block' || b.isAllowed === false) ? 1 : 0;
    if (aDeny !== bDeny) return bDeny - aDeny;
    return (b.priority ?? 0) - (a.priority ?? 0);
  });

  for (const rule of sortedRules) {
    const matchType = String(rule.matchType || rule.match_type || rule.type || 'string').toLowerCase();
    const pattern = String(rule.pattern || rule.match || rule.prefix || '').trim();
    if (!pattern) continue;

    const rawAction = String(
      rule.action || (rule.isAllowed === false ? 'deny' : rule.isAllowed === true ? 'allow' : 'allow')
    ).toLowerCase();
    const normAction = rawAction === 'block' ? 'deny' : rawAction;

    let matched = false;

    if (matchType === 'argv') {
      if (parsedCmd.valid) {
        const patParsed = parseSimpleCommand(pattern);
        const patTokens = patParsed.valid ? patParsed.argv : pattern.split(/\s+/).filter(Boolean);
        if (patTokens.length > 0 && parsedCmd.argv.length >= patTokens.length) {
          const binMatches = parsedCmd.binary === normalizeBinaryName(patTokens[0]);
          const argsMatch = patTokens.slice(1).every((tok, idx) => parsedCmd.argv[idx + 1] === tok);
          matched = binMatches && argsMatch;
        }
      }
    } else if (matchType === 'regex') {
      try {
        const re = new RegExp(pattern, rule.flags || 'i');
        matched = re.test(commandStr);
      } catch {
        matched = false;
      }
    } else if (normAction === 'allow') {
      // 'string' allow rules require strict token-boundary argv prefix matching (never .includes or unanchored prefix)
      if (parsedCmd.valid) {
        const patternCmd = parseSimpleCommand(pattern);
        if (
          patternCmd.valid &&
          patternCmd.argv.length > 0 &&
          parsedCmd.argv.length >= patternCmd.argv.length &&
          normalizeBinaryName(parsedCmd.binary) === normalizeBinaryName(patternCmd.binary)
        ) {
          matched = patternCmd.argv.every((tok, idx) => parsedCmd.argv[idx] === tok);
        }
      }
    } else {
      // 'string' prefix or substring match for deny/ask rules
      matched = commandStr === pattern || commandStr.startsWith(pattern) || commandStr.includes(pattern);
    }

    if (!matched) continue;

    if (normAction === 'deny') {
      return {
        allowed: false,
        action: 'deny',
        decision: 'deny',
        denylisted: cmdIsDenylisted,
        matchedRule: rule,
        reason: rule.message || rule.reason || `${PLATFORM_CONTROL_PREFIX} Blocked by intercept rule: ${rule.name || pattern}`
      };
    }

    if (normAction === 'ask') {
      return {
        allowed: false,
        action: 'ask',
        decision: 'ask',
        denylisted: cmdIsDenylisted,
        matchedRule: rule,
        reason: rule.message || rule.reason || `Manual approval required by rule: ${rule.name || pattern}`
      };
    }

    if (normAction === 'allow') {
      // Enforce ALWAYS_ALLOW_DENYLIST: interpreter/launcher binaries can NEVER be auto-approved
      const patFirstToken = pattern.split(/\s+/)[0] || '';
      if (
        cmdIsDenylisted ||
        isBinaryDenylisted(patFirstToken) ||
        (parsedCmd.valid && ALWAYS_ALLOW_DENYLIST.has(normalizeBinaryName(parsedCmd.binary)))
      ) {
        return {
          allowed: false,
          action: 'ask',
          decision: 'ask',
          denylisted: true,
          binary: detectedBinary || normalizeBinaryName(patFirstToken),
          matchedRule: rule,
          reason: `${PLATFORM_CONTROL_PREFIX} Binary "${detectedBinary || normalizeBinaryName(patFirstToken)}" is in ALWAYS_ALLOW_DENYLIST and cannot be auto-approved`
        };
      }

      // Also refuse auto-approval if the command contains shell chaining/injection
      if (!parsedCmd.valid) {
        return {
          allowed: false,
          action: 'ask',
          decision: 'ask',
          denylisted: false,
          matchedRule: rule,
          reason: `${PLATFORM_CONTROL_PREFIX} Command cannot be auto-approved because it is not a simple command: ${parsedCmd.reason}`
        };
      }

      return {
        allowed: true,
        action: 'allow',
        decision: 'allow',
        denylisted: false,
        matchedRule: rule,
        reason: rule.message || `Allowed by rule: ${rule.name || pattern}`
      };
    }
  }

  return {
    allowed: false,
    action: 'ask',
    decision: 'ask',
    denylisted: cmdIsDenylisted,
    matchedRule: null,
    reason: 'No matching intercept rule (default ask)'
  };
}

/**
 * Computes a deterministic 0–100 risk score based on HTTP method (`GET`/`HEAD` low,
 * `POST`/`PUT`/`DELETE` medium/high), state-mutating parameters, or command class.
 *
 * @param {string | object} toolName
 * @param {object | string} [input={}]
 * @returns {{ score: number, level: 'low'|'medium'|'high', reasons: string[] }}
 */
export function scoreRisk(toolName, input = {}) {
  let tool = '';
  let params = {};

  if (typeof toolName === 'object' && toolName !== null) {
    params = toolName;
    tool = String(toolName.toolName || toolName.tool || toolName.method || 'http');
  } else {
    tool = String(toolName || 'http');
    if (typeof input === 'string') {
      params = { command: input };
    } else if (input && typeof input === 'object') {
      params = input;
    }
  }

  const toolUpper = tool.trim().toUpperCase();
  const httpMethods = new Set(['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE', 'TRACE', 'CONNECT']);
  const method = String(
    params.method || (httpMethods.has(toolUpper) ? toolUpper : '') || ''
  ).toUpperCase();

  const urlOrPath = String(params.url || params.path || params.endpoint || params.target || '');
  const command = String(params.command || params.cmd || '');
  const bodyStr = typeof params.body === 'string'
    ? params.body
    : params.body
      ? JSON.stringify(params.body)
      : '';
  const queryAndParams = JSON.stringify(params.params || params.query || params.arguments || {});
  const combinedInspect = `${urlOrPath} ${bodyStr} ${queryAndParams}`;

  let score = 0;
  const reasons = [];

  // 1. Base score by HTTP method or tool class
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
    score += 10;
    reasons.push(`Read-only HTTP method (${method})`);
  } else if (method === 'POST') {
    score += 40;
    reasons.push('State-changing HTTP method (POST)');
  } else if (method === 'PUT' || method === 'PATCH') {
    score += 50;
    reasons.push(`State-mutating HTTP method (${method})`);
  } else if (method === 'DELETE') {
    score += 75;
    reasons.push('Destructive HTTP method (DELETE)');
  } else if (command || /^(bash|sh|exec|shell|command|run_command)$/i.test(tool)) {
    score += 20;
    reasons.push('Command execution tool');
  } else {
    score += 15;
    reasons.push(`Tool invocation (${tool})`);
  }

  // 2. State-mutating / destructive URL paths or parameters
  if (/\b(delete|drop|destroy|truncate|wipe|purge|flush|factory[-_]?reset|remove|kill|format|shutdown)\b/i.test(combinedInspect)) {
    score += 30;
    reasons.push('Destructive or state-wiping target parameter/path');
  }

  if (/\b(password|passwd|secret|api[-_]?key|private[-_]?key|role|is[_-]?admin|privilege|permission|grant|sudo|exec|eval|cmd)\b/i.test(combinedInspect)) {
    score += 20;
    reasons.push('Privilege or credential-mutating parameter detected');
  }

  // 3. Command class analysis
  if (command) {
    if (/\b(rm\s+-[a-zA-Z]*r|mkfs|dd\s+if=|shutdown|reboot|init\s+0|iptables\s+-F|chmod\s+777|DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+TABLE|FLUSHALL)\b/i.test(command)) {
      score += 65;
      reasons.push('Destructive system or database command class');
    }
    if (/\b(sudo|su\b|passwd|useradd|usermod|chown|crontab|nc\s+-e|bash\s+-i|socat)\b/i.test(command) || /\|\s*(sh|bash|zsh|pwsh|python|perl|ruby|php)\b/i.test(command)) {
      score += 45;
      reasons.push('Privilege escalation or remote shell command class');
    }
    if (/(\/etc\/shadow|\/etc\/passwd|\.env\b|id_rsa|\.aws\/credentials|\.ssh\/)/i.test(command)) {
      score += 35;
      reasons.push('Sensitive credential or secret file access');
    }
    const parsed = parseSimpleCommand(command);
    if (!parsed.valid) {
      score += 20;
      reasons.push(`Complex/chained shell syntax (${parsed.reason})`);
    } else if (parsed.isDenylisted) {
      score += 20;
      reasons.push(`Denylisted interpreter/launcher binary (${parsed.binary})`);
    }
  }

  score = Math.max(0, Math.min(100, score));
  const level = score >= 70 ? 'high' : score >= 30 ? 'medium' : 'low';

  const report = {
    score,
    level,
    reasons
  };

  Object.defineProperty(report, 'valueOf', {
    value() {
      return this.score;
    },
    enumerable: false
  });
  Object.defineProperty(report, Symbol.toPrimitive, {
    value(hint) {
      return hint === 'string' ? String(this.score) : this.score;
    },
    enumerable: false
  });

  return report;
}

/**
 * The 8 closed-world JEV safety invariant questions.
 */
export const JEV_QUESTIONS = Object.freeze([
  'q1_in_scope',
  'q2_no_destructive_side_effects',
  'q3_reversible',
  'q4_within_rate_budget',
  'q5_no_credential_exfil',
  'q6_no_cross_tenant_impact',
  'q7_valid_verification_intent',
  'q8_least_privilege'
]);

/**
 * Implements SecScan's closed-world 8-question boolean precedence (`q1_in_scope` .. `q8_least_privilege`).
 * Strictly fails closed (`{ approved: false, reason, failedChecks }`) on missing/non-boolean fields
 * or any failed invariant.
 *
 * @param {object} jevAnswers
 * @returns {{ approved: boolean, decision: 'allow'|'deny', reason: string, failedChecks: string[], missingChecks: string[] }}
 */
export function decideClosed(jevAnswers) {
  if (!jevAnswers || typeof jevAnswers !== 'object' || Array.isArray(jevAnswers)) {
    return {
      approved: false,
      decision: 'deny',
      reason: 'Closed-world judge failed closed: JEV answers must be a non-null object',
      failedChecks: [...JEV_QUESTIONS],
      missingChecks: [...JEV_QUESTIONS]
    };
  }

  const failedChecks = [];
  const missingChecks = [];

  for (const q of JEV_QUESTIONS) {
    if (!(q in jevAnswers) || typeof jevAnswers[q] !== 'boolean') {
      missingChecks.push(q);
      failedChecks.push(q);
    } else if (jevAnswers[q] !== true) {
      failedChecks.push(q);
    }
  }

  if (failedChecks.length > 0) {
    const reason = missingChecks.length > 0
      ? `Closed-world judge failed closed: missing or non-boolean invariant(s): ${missingChecks.join(', ')}`
      : `Closed-world judge rejected action: failed invariant(s): ${failedChecks.join(', ')}`;
    return {
      approved: false,
      decision: 'deny',
      reason,
      failedChecks,
      missingChecks
    };
  }

  return {
    approved: true,
    decision: 'allow',
    reason: 'All 8 JEV closed-world safety invariants verified',
    failedChecks: [],
    missingChecks: []
  };
}

/**
 * Detects WAF / CDN vendor from normalized lowercase HTTP response headers and optional body text.
 */
function detectWafVendor(normHeaders, bodyText = '') {
  const server = String(normHeaders['server'] || '').toLowerCase();
  const via = String(normHeaders['via'] || '').toLowerCase();
  const xCdn = String(normHeaders['x-cdn'] || '').toLowerCase();

  // Cloudflare
  if (
    normHeaders['cf-ray'] ||
    normHeaders['cf-mitigated'] ||
    normHeaders['cf-chl-bypass'] ||
    server.includes('cloudflare')
  ) {
    return 'cloudflare';
  }

  // Akamai
  if (
    normHeaders['x-akamai-transformed'] ||
    normHeaders['akamai-grn'] ||
    normHeaders['x-akamai-request-id'] ||
    normHeaders['x-akamai-session-info'] ||
    server.includes('akamaighost') ||
    server.includes('akamai')
  ) {
    return 'akamai';
  }

  // AWS WAF / CloudFront
  if (
    normHeaders['x-amzn-waf-action'] ||
    normHeaders['x-amzn-errortype'] ||
    normHeaders['x-amz-cf-id'] ||
    normHeaders['x-amz-cf-pop'] ||
    server.includes('awselb') ||
    server.includes('cloudfront') ||
    via.includes('cloudfront')
  ) {
    return 'aws-waf';
  }

  // Imperva / Incapsula
  if (normHeaders['x-iinfo'] || xCdn.includes('incapsula') || xCdn.includes('imperva')) {
    return 'imperva';
  }

  // ModSecurity / Sucuri / DataDome / Fastly
  if (normHeaders['x-sucuri-id'] || normHeaders['x-sucuri-block']) return 'sucuri';
  if (normHeaders['x-datadome'] || normHeaders['x-datadome-cid']) return 'datadome';
  if (normHeaders['x-waf-event-info'] || server.includes('mod_security')) return 'modsecurity';

  if (/cloudflare/i.test(bodyText)) return 'cloudflare';
  if (/akamai|reference\s+#\d+\.\w+/i.test(bodyText)) return 'akamai';
  if (/aws\s*waf|request\s+blocked\s+by\s+aws/i.test(bodyText)) return 'aws-waf';

  return null;
}

/**
 * Observer G5 attribution: distinguishes `[SECSCAN platform control, not target defense]`
 * vs target WAF / rate-limit (`429`, `403` with Cloudflare/Akamai/AWS WAF headers) vs network timeout.
 *
 * @param {{ status?: number, headers?: object, error?: Error | string, body?: string }} [input={}]
 * @returns {{
 *   category: 'platform_control'|'rate_limit'|'waf_block'|'target_forbidden'|'network_timeout'|'network_error'|'ok',
 *   source: 'platform'|'target_defense'|'network'|'target',
 *   isPlatformBlock: boolean,
 *   isTargetDefense: boolean,
 *   isRateLimit: boolean,
 *   isWaf: boolean,
 *   isTimeout: boolean,
 *   vendor: string | null,
 *   retryAfter?: string | null,
 *   reason: string
 * }}
 */
export function attributeTargetFailure({ status, headers = {}, error, body = '' } = {}) {
  const normHeaders = {};
  if (headers && typeof headers.entries === 'function') {
    for (const [k, v] of headers.entries()) {
      normHeaders[String(k).toLowerCase()] = String(v);
    }
  } else if (headers && typeof headers === 'object') {
    for (const [k, v] of Object.entries(headers)) {
      normHeaders[String(k).toLowerCase()] = String(v);
    }
  }

  const errMsg = typeof error === 'string' ? error : (error?.message || '');
  const errCode = (typeof error === 'object' && error !== null) ? error.code : '';

  // 1. Platform control block (local scope/deny/SSRF/DNS pin policy)
  if (
    errMsg.includes(PLATFORM_CONTROL_PREFIX) ||
    /\[[A-Z0-9_]+ platform control, not target defense\]/i.test(errMsg) ||
    errMsg.includes('blocked by SSRF policy') ||
    errMsg.includes('Target blocked by deny rule') ||
    errMsg.includes('Target outside declared allow scope') ||
    errCode === 'TARGET_RULE_BLOCKED' ||
    errCode === 'TARGET_OUT_OF_SCOPE' ||
    errCode === 'DNS_REBIND_OR_PRIVATE_IP'
  ) {
    return {
      category: 'platform_control',
      source: 'platform',
      isPlatformBlock: true,
      isTargetDefense: false,
      isRateLimit: false,
      isWaf: false,
      isTimeout: false,
      vendor: null,
      reason: errMsg.startsWith('[SECSCAN platform control')
        ? errMsg
        : `${PLATFORM_CONTROL_PREFIX} ${errMsg || 'Blocked by local platform security control'}`
    };
  }

  const vendor = detectWafVendor(normHeaders, body);

  // 2. Target Rate-Limit (HTTP 429 or 503 with Retry-After / rate-limit headers)
  if (
    status === 429 ||
    (status === 503 && normHeaders['retry-after'] !== undefined) ||
    normHeaders['x-ratelimit-remaining'] === '0' ||
    /rate[-_\s]?limit|too many requests/i.test(errMsg)
  ) {
    return {
      category: 'rate_limit',
      source: 'target_defense',
      isPlatformBlock: false,
      isTargetDefense: true,
      isRateLimit: true,
      isWaf: Boolean(vendor),
      isTimeout: false,
      vendor,
      retryAfter: normHeaders['retry-after'] || null,
      reason: `Target rate-limit triggered (HTTP ${status || 429}${vendor ? `, vendor: ${vendor}` : ''})`
    };
  }

  // 3. Target WAF / Forbidden block (HTTP 403 / 406 / 503 with WAF vendor or challenge markers)
  if (status === 403 || status === 406 || (status === 503 && vendor)) {
    const isWaf = Boolean(
      vendor ||
      normHeaders['cf-mitigated'] ||
      /waf|firewall|captcha|challenge|access denied/i.test(body || errMsg)
    );
    return {
      category: isWaf ? 'waf_block' : 'target_forbidden',
      source: 'target_defense',
      isPlatformBlock: false,
      isTargetDefense: true,
      isRateLimit: false,
      isWaf,
      isTimeout: false,
      vendor,
      reason: isWaf
        ? `Target WAF blocked probe (HTTP ${status}${vendor ? `, vendor: ${vendor}` : ''})`
        : `Target returned HTTP ${status} Forbidden`
    };
  }

  // 4. Network or request timeout
  if (
    error?.name === 'AbortError' ||
    error?.name === 'TimeoutError' ||
    errCode === 'ETIMEDOUT' ||
    errCode === 'ECONNABORTED' ||
    errCode === 'UND_ERR_CONNECT_TIMEOUT' ||
    status === 408 ||
    status === 504 ||
    /timeout|timed\s*out|aborted/i.test(errMsg)
  ) {
    return {
      category: 'network_timeout',
      source: 'network',
      isPlatformBlock: false,
      isTargetDefense: false,
      isRateLimit: false,
      isWaf: false,
      isTimeout: true,
      vendor: null,
      reason: `Network or request timeout: ${errMsg || `HTTP ${status}`}`
    };
  }

  // 5. Generic network error
  if (error) {
    return {
      category: 'network_error',
      source: 'network',
      isPlatformBlock: false,
      isTargetDefense: false,
      isRateLimit: false,
      isWaf: false,
      isTimeout: false,
      vendor: null,
      reason: `Network error: ${errMsg}`
    };
  }

  return {
    category: 'ok',
    source: 'target',
    isPlatformBlock: false,
    isTargetDefense: false,
    isRateLimit: false,
    isWaf: false,
    isTimeout: false,
    vendor,
    reason: `HTTP ${status || 200}`
  };
}

/**
 * Neutralizes any forged `[[SECSCAN_DATA ...]]` or `[[/SECSCAN_DATA ...]]` envelope tags
 * inside untrusted content, especially any closing tag matching `nonce`.
 *
 * @param {string} content
 * @param {string} [nonce]
 * @returns {string}
 */
export function stripForgedEnvelopes(content, nonce) {
  const raw = String(content ?? '');
  let sanitized = raw;

  if (typeof nonce === 'string' && nonce.trim()) {
    const escapedNonce = nonce.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const exactCloseRe = new RegExp(`\\[\\[\\s*\\/\\s*SECSCAN_DATA[^\\]]*nonce\\s*=\\s*${escapedNonce}[^\\]]*\\]\\]`, 'gi');
    const exactOpenRe = new RegExp(`\\[\\[\\s*SECSCAN_DATA[^\\]]*nonce\\s*=\\s*${escapedNonce}[^\\]]*\\]\\]`, 'gi');
    sanitized = sanitized
      .replace(exactCloseRe, '[[/secscan-data-forged-stripped]]')
      .replace(exactOpenRe, '[[secscan-data-forged-stripped]]');
  }

  // Also neutralize any generic SECSCAN_DATA opening or closing markers inside untrusted content
  sanitized = sanitized
    .replace(/\[\[\s*\/\s*SECSCAN_DATA([^\]]*)\]\]/gi, '[[/secscan-data-forged-stripped$1]]')
    .replace(/\[\[\s*SECSCAN_DATA([^\]]*)\]\]/gi, '[[secscan-data-forged-stripped$1]]');

  return sanitized;
}

/**
 * Wraps untrusted target response data in a nonce-tagged envelope:
 * `[[SECSCAN_DATA nonce=<8-hex> field=<field>]]\n...\n[[/SECSCAN_DATA nonce=<8-hex>]]`
 * using `crypto.randomBytes(4).toString('hex')` and neutralizing any forged inner tags.
 *
 * @param {string} field
 * @param {string} content
 * @param {{ nonce?: string }} [options]
 * @returns {string}
 */
export function wrapDataEnvelope(field, content, { nonce } = {}) {
  const actualNonce = (typeof nonce === 'string' && /^[a-f0-9]{8}$/i.test(nonce.trim()))
    ? nonce.trim().toLowerCase()
    : crypto.randomBytes(4).toString('hex');

  const safeField = String(field || 'response').replace(/[^a-zA-Z0-9_.:/-]/g, '_');
  const cleanBody = stripForgedEnvelopes(content, actualNonce);

  return `[[SECSCAN_DATA nonce=${actualNonce} field=${safeField}]]\n${cleanBody}\n[[/SECSCAN_DATA nonce=${actualNonce}]]`;
}
