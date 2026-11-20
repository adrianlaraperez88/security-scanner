import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import { URL } from 'node:url';
import { resolveAndValidateTarget, voidsExemption } from './validator.js';

export const NOTIFY_CHANNELS = [
  'webhook',
  'slack',
  'telegram',
  'dingtalk',
  'feishu',
  'wecom',
  'email'
];

export const SECRET_KEYS = [
  'secret',
  'token',
  'botToken',
  'password',
  'apiKey',
  'webhookKey',
  'smtpPass',
  'authToken',
  'signingSecret'
];

export const DESTINATION_KEYS = [
  'url',
  'webhookUrl',
  'baseUrl',
  'base_url',
  'endpoint',
  'host',
  'smtpHost',
  'port',
  'smtpPort',
  'chatId',
  'chat_id',
  'to'
];

const SECRET_KEY_SET = new Set(SECRET_KEYS.map(k => k.toLowerCase()));
const URL_KEY_SET = new Set(['url', 'webhookurl', 'baseurl', 'base_url', 'endpoint']);
const DESTINATION_KEY_SET = new Set(DESTINATION_KEYS.map(k => k.toLowerCase()));

const SENSITIVE_QUERY_PARAMS = new Set([
  'access_token',
  'token',
  'key',
  'secret',
  'api_key',
  'apikey',
  'webhookkey',
  'webhook_key',
  'password',
  'sig',
  'signature',
  'auth'
]);

const SEVERITY_RANK = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  NONE: 0
};

/**
 * Security error thrown when notification configuration or dispatch violates
 * credential-exfiltration or SSRF guardrails.
 */
export class NotifySecurityError extends Error {
  constructor(message) {
    super(message);
    this.name = 'NotifySecurityError';
    this.code = 'NOTIFY_SECURITY_ERROR';
  }
}

/**
 * Masks a single secret value as '__masked__:' + last 6 chars.
 *
 * @param {string} val
 * @returns {string}
 */
export function maskSecretValue(val) {
  if (typeof val !== 'string' || !val) return val;
  if (val.startsWith('__masked__:')) return val;
  return `__masked__:${val.slice(-6)}`;
}

/**
 * Masks sensitive query parameters (e.g. access_token, key, token, secret) inside a URL.
 *
 * @param {string} rawUrl
 * @returns {string}
 */
export function maskWebhookUrl(rawUrl) {
  if (typeof rawUrl !== 'string' || !rawUrl.trim()) return rawUrl;
  try {
    const parsed = new URL(rawUrl);
    let modified = false;
    const params = new URLSearchParams(parsed.search);
    const maskedEntries = [];

    for (const [k, v] of params.entries()) {
      if (SENSITIVE_QUERY_PARAMS.has(k.toLowerCase()) && v && !v.startsWith('__masked__:')) {
        maskedEntries.push([k, maskSecretValue(v)]);
        modified = true;
      } else {
        maskedEntries.push([k, v]);
      }
    }

    if (!modified) return rawUrl;

    const queryStr = maskedEntries
      .map(([k, v]) => `${encodeURIComponent(k)}=${v.startsWith('__masked__:') ? v : encodeURIComponent(v)}`)
      .join('&');
    return `${parsed.origin}${parsed.pathname}${queryStr ? `?${queryStr}` : ''}${parsed.hash || ''}`;
  } catch {
    return rawUrl.replace(
      /([?&](?:access_token|token|key|secret|api_key|apiKey|webhookKey|sig)=)([^&#\s]+)/gi,
      (_, prefix, val) => `${prefix}${maskSecretValue(val)}`
    );
  }
}

/**
 * Strips query parameters whose values are masked so base destination comparison works.
 */
function normalizeUrlDestination(rawUrl) {
  if (typeof rawUrl !== 'string' || !rawUrl.trim()) return '';
  try {
    const u = new URL(rawUrl.trim());
    return `${u.origin.toLowerCase()}${u.pathname}`;
  } catch {
    return rawUrl.trim().split('?')[0].toLowerCase();
  }
}

/**
 * Masks any secret fields (secret, token, botToken, password, apiKey, webhookKey)
 * as '__masked__:' + val.slice(-6) and masks sensitive query tokens in webhook URLs.
 *
 * @param {object} config
 * @returns {object}
 */
export function maskConfig(config) {
  if (!config || typeof config !== 'object') return config;
  if (Array.isArray(config)) return config.map(item => maskConfig(item));

  const out = {};

  for (const [key, value] of Object.entries(config)) {
    const lowerKey = key.toLowerCase();
    if (value && typeof value === 'object') {
      out[key] = maskConfig(value);
    } else if (SECRET_KEY_SET.has(lowerKey) && typeof value === 'string' && value.length > 0) {
      out[key] = maskSecretValue(value);
    } else if (URL_KEY_SET.has(lowerKey) && typeof value === 'string' && value.length > 0) {
      out[key] = maskWebhookUrl(value);
    } else {
      out[key] = value;
    }
  }

  return out;
}

function isPlainObject(val) {
  return Boolean(val) && typeof val === 'object' && !Array.isArray(val);
}

function buildLowerKeyMap(obj) {
  const map = new Map();
  if (!isPlainObject(obj)) return map;
  for (const [key, value] of Object.entries(obj)) {
    map.set(key.toLowerCase(), { key, value });
  }
  return map;
}

function walkConfigUpdateArray(existingArr, incomingArr, state) {
  return incomingArr.map((item, idx) => {
    const oldItem = idx < existingArr.length ? existingArr[idx] : undefined;
    if (isPlainObject(item)) {
      return walkConfigUpdateObject(isPlainObject(oldItem) ? oldItem : {}, item, state);
    }
    if (Array.isArray(item)) {
      return walkConfigUpdateArray(Array.isArray(oldItem) ? oldItem : [], item, state);
    }
    return item;
  });
}

function walkConfigUpdateObject(existingObj, incomingObj, state) {
  const existingMap = buildLowerKeyMap(existingObj);
  const merged = isPlainObject(existingObj) ? { ...existingObj } : {};

  for (const [k, v] of Object.entries(incomingObj)) {
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;

    const lowerKey = k.toLowerCase();
    const existingEntry = existingMap.get(lowerKey);
    const oldVal = existingEntry ? existingEntry.value : undefined;

    if (typeof v === 'string' && v.includes('__masked__:')) {
      if (SECRET_KEY_SET.has(lowerKey) || URL_KEY_SET.has(lowerKey)) {
        state.retainsMaskedSecret = true;
      }
    }

    if (DESTINATION_KEY_SET.has(lowerKey) && v !== undefined) {
      if (URL_KEY_SET.has(lowerKey)) {
        const normNew = typeof v === 'string' ? normalizeUrlDestination(v) : String(v ?? '');
        const normOld = typeof oldVal === 'string' ? normalizeUrlDestination(oldVal) : String(oldVal ?? '');
        if (normNew !== normOld) {
          state.destinationChanged = true;
        }
      } else {
        const newStr = isPlainObject(v) || Array.isArray(v) ? JSON.stringify(v) : String(v ?? '');
        const oldStr = isPlainObject(oldVal) || Array.isArray(oldVal) ? JSON.stringify(oldVal) : String(oldVal ?? '');
        if (newStr !== oldStr) {
          state.destinationChanged = true;
        }
      }
    }

    if (existingEntry && existingEntry.key !== k) {
      delete merged[existingEntry.key];
    }

    if (isPlainObject(v)) {
      merged[k] = walkConfigUpdateObject(isPlainObject(oldVal) ? oldVal : {}, v, state);
    } else if (Array.isArray(v)) {
      merged[k] = walkConfigUpdateArray(Array.isArray(oldVal) ? oldVal : [], v, state);
    } else if (SECRET_KEY_SET.has(lowerKey) && typeof v === 'string' && v.startsWith('__masked__:')) {
      merged[k] = typeof oldVal === 'string' && oldVal.length > 0 ? oldVal : v;
    } else if (
      URL_KEY_SET.has(lowerKey) &&
      typeof v === 'string' &&
      v.includes('__masked__:') &&
      typeof oldVal === 'string' &&
      normalizeUrlDestination(v) === normalizeUrlDestination(oldVal)
    ) {
      merged[k] = oldVal;
    } else {
      merged[k] = v;
    }
  }

  return merged;
}

/**
 * Prevents credential-exfiltration via config updates:
 * - If incomingConfig retains a '__masked__:' placeholder for any secret field
 *   WHILE changing any destination endpoint (url, webhookUrl, endpoint, host, smtpHost, chatId, to),
 *   throws NotifySecurityError.
 * - Otherwise restores the existing secret when '__masked__:' is unchanged.
 *
 * @param {object} existingConfig
 * @param {object} incomingConfig
 * @returns {object}
 */
export function prepareConfigUpdate(existingConfig = {}, incomingConfig = {}) {
  const existing = isPlainObject(existingConfig) ? existingConfig : {};
  const incoming = isPlainObject(incomingConfig) ? incomingConfig : {};
  const state = {
    retainsMaskedSecret: false,
    destinationChanged: false
  };

  const merged = walkConfigUpdateObject(existing, incoming, state);

  if (state.retainsMaskedSecret && state.destinationChanged) {
    throw new NotifySecurityError(
      'Cannot change notification destination while retaining masked secret — re-enter credentials'
    );
  }

  return merged;
}

/**
 * Generates DingTalk HMAC-SHA256 webhook signature.
 * String-to-sign: `${timestamp}\n${secret}` signed with `secret` as HMAC key.
 *
 * @param {number|string} timestamp
 * @param {string} secret
 * @returns {string} Base64 signature
 */
export function signDingTalk(timestamp, secret) {
  const stringToSign = `${timestamp}\n${secret}`;
  return crypto.createHmac('sha256', String(secret)).update(stringToSign, 'utf8').digest('base64');
}

/**
 * Generates Feishu (Lark) HMAC-SHA256 bot signature.
 * In Feishu's custom bot spec, `${timestamp}\n${secret}` is used as the HMAC key over an empty message.
 *
 * @param {number|string} timestamp
 * @param {string} secret
 * @returns {string} Base64 signature
 */
export function signFeishu(timestamp, secret) {
  const stringToSign = `${timestamp}\n${secret}`;
  return crypto.createHmac('sha256', stringToSign).update('', 'utf8').digest('base64');
}

function escapeTelegramHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function truncateUtf8Bytes(str, maxBytes = 4096) {
  const text = String(str ?? '');
  if (Buffer.byteLength(text, 'utf8') <= maxBytes) return text;
  const buf = Buffer.from(text, 'utf8');
  let slice = buf.subarray(0, Math.max(0, maxBytes - 3)).toString('utf8');
  // Strip replacement character at boundary if multi-byte char was split
  slice = slice.replace(/\uFFFD+$/, '');
  return `${slice}...`;
}

// ── Slack-style block builder ─────────────────────────────────────────────────
function buildSlackPayload(results, risk, targets, packMeta = null) {
  const safeResults = Array.isArray(results) ? results : [];
  const safeRisk = risk && typeof risk === 'object' ? risk : { level: 'LOW', score: 0 };
  const safeTargets = Array.isArray(targets) ? targets : [];

  const vulns      = safeResults.filter(r => r && r.status === 'VULNERABLE');
  const suspicious = safeResults.filter(r => r && r.status === 'SUSPICIOUS');
  const riskEmoji  = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🟢' }[safeRisk.level] ?? '⚪';

  const header = `${riskEmoji} *Security Scan — ${safeRisk.level || 'LOW'} Risk (${safeRisk.score ?? 0} pts)*`;
  const targetLine = `*Targets:* ${safeTargets.join(', ') || 'N/A'}`;

  let body = '';

  if (vulns.length) {
    body += `\n*🚨 Vulnerable (${vulns.length}):*\n`;
    body += vulns.map(v => `  • \`${v.name}\` [${v.severity}]${v.path ? ' → ' + v.path : ''}`).join('\n');
  }

  if (suspicious.length) {
    body += `\n*⚠️ Suspicious (${suspicious.length}):*\n`;
    body += suspicious.map(s => `  • \`${s.name}\` [${s.severity}]${s.detail ? ' → ' + s.detail : ''}`).join('\n');
  }

  if (!vulns.length && !suspicious.length) {
    body = '\n✅ All checks passed — no findings detected.';
  }

  if (packMeta && packMeta.totalPacks > 1) {
    body += `\n_(Pack ${packMeta.packIndex + 1}/${packMeta.totalPacks}: showing ${packMeta.kept} item(s), remaining ${packMeta.remaining} in next message)_`;
  }

  return {
    text: `${header}\n${targetLine}${body}`,
    blocks: [
      {
        type: 'section',
        text: { type: 'mrkdwn', text: `${header}\n${targetLine}` }
      },
      ...(body ? [{
        type: 'section',
        text: { type: 'mrkdwn', text: body }
      }] : []),
      {
        type: 'context',
        elements: [{
          type: 'mrkdwn',
          text: `Security Scanner v2.2 · ${new Date().toISOString()}`
        }]
      }
    ]
  };
}

/**
 * Splits findings into batches of maxItemsPerPack (packItemCount) and formats
 * channel-specific payloads across all 7 supported notification channels.
 *
 * @param {'webhook'|'slack'|'telegram'|'dingtalk'|'feishu'|'wecom'|'email'|string} channel
 * @param {object} event
 * @param {object} [options={}]
 * @param {number} [options.maxItemsPerPack=5]
 * @param {string} [options.secret]
 * @param {number|string} [options.timestamp]
 * @returns {Array<object>}
 */
export function formatChannelPayloads(channel, event = {}, options = {}) {
  const ch = String(channel || 'webhook').trim().toLowerCase();
  if (!NOTIFY_CHANNELS.includes(ch)) {
    throw new Error(`Unsupported notification channel: "${channel}"`);
  }

  const maxItemsPerPack = Number(options.maxItemsPerPack) > 0
    ? Math.floor(Number(options.maxItemsPerPack))
    : 5;

  const rawFindings = Array.isArray(event.findings)
    ? event.findings
    : (Array.isArray(event.results) ? event.results : []);
  const actionable = rawFindings.filter(f => f && (f.status === 'VULNERABLE' || f.status === 'SUSPICIOUS'));
  const itemsToPack = actionable.length > 0 ? actionable : rawFindings.filter(Boolean);

  const risk = event.risk || event.summary || { level: 'LOW', score: 0, grade: 'A+' };
  const targets = Array.isArray(event.targets)
    ? event.targets
    : (event.target ? [event.target] : []);
  const title = event.title || `Security Scan — ${risk.level || 'LOW'} Risk (Grade ${risk.grade || 'A+'})`;
  const secret = options.secret ?? event.secret ?? event.config?.secret ?? '';
  const ts = options.timestamp ?? event.timestamp ?? Date.now();

  const batches = [];
  if (itemsToPack.length === 0) {
    batches.push([]);
  } else {
    for (let i = 0; i < itemsToPack.length; i += maxItemsPerPack) {
      batches.push(itemsToPack.slice(i, i + maxItemsPerPack));
    }
  }

  const totalPacks = batches.length;
  const totalItems = itemsToPack.length;
  let itemsShownSoFar = 0;

  return batches.map((batch, packIndex) => {
    itemsShownSoFar += batch.length;
    const remaining = Math.max(0, totalItems - itemsShownSoFar);
    const packMeta = {
      packIndex,
      totalPacks,
      kept: batch.length,
      packItemCount: batch.length,
      totalItems,
      remaining
    };

    const continuationNote = totalPacks > 1
      ? `(this message shows ${batch.length} item(s) [pack ${packIndex + 1}/${totalPacks}], remaining ${remaining} will continue in the next message)`
      : '';

    const itemLines = batch.map(
      f => `- [${f.severity || 'INFO'}] ${f.name || f.checkId || f.title || 'finding'}${f.target ? ` (${f.target})` : ''}${f.path ? ` -> ${f.path}` : ''}`
    );
    const bodyText = itemLines.length > 0
      ? itemLines.join('\n')
      : 'All checks passed — no findings detected.';

    if (ch === 'slack') {
      const slackPayload = buildSlackPayload(batch, risk, targets, packMeta);
      return {
        channel: 'slack',
        ...packMeta,
        ...slackPayload
      };
    }

    if (ch === 'webhook') {
      return {
        channel: 'webhook',
        ...packMeta,
        scanner: 'security-scanner/2.2',
        timestamp: new Date(typeof ts === 'number' ? ts : Date.now()).toISOString(),
        title,
        targets,
        risk,
        summary: {
          vulnerable: batch.filter(r => r.status === 'VULNERABLE').length,
          suspicious: batch.filter(r => r.status === 'SUSPICIOUS').length,
          total: batch.length
        },
        findings: batch,
        text: `${title}\n${bodyText}${continuationNote ? `\n${continuationNote}` : ''}`
      };
    }

    if (ch === 'telegram') {
      const htmlLines = [
        `<b>${escapeTelegramHtml(title)}</b>`,
        targets.length ? `Targets: <code>${escapeTelegramHtml(targets.join(', '))}</code>` : '',
        ...batch.map(f =>
          `• <b>[${escapeTelegramHtml(f.severity || 'INFO')}]</b> <code>${escapeTelegramHtml(f.name || f.checkId || 'check')}</code> ${escapeTelegramHtml(f.path || f.detail || '')}`
        ),
        continuationNote ? `<i>${escapeTelegramHtml(continuationNote)}</i>` : ''
      ].filter(Boolean);

      return {
        channel: 'telegram',
        ...packMeta,
        parse_mode: 'HTML',
        text: htmlLines.join('\n').slice(0, 4096)
      };
    }

    if (ch === 'dingtalk') {
      const numericTs = typeof ts === 'number' ? ts : Date.now();
      const sign = secret ? signDingTalk(numericTs, secret) : undefined;
      const signedQuery = sign
        ? `timestamp=${numericTs}&sign=${encodeURIComponent(sign)}`
        : undefined;
      const markdownText = [
        `### ${title}`,
        targets.length ? `**Targets**: ${targets.join(', ')}` : '',
        bodyText,
        continuationNote ? `> ${continuationNote}` : ''
      ].filter(Boolean).join('\n\n');

      return {
        channel: 'dingtalk',
        ...packMeta,
        msgtype: 'markdown',
        markdown: {
          title,
          text: truncateUtf8Bytes(markdownText, 20000)
        },
        timestamp: numericTs,
        ...(sign ? { sign, signedQuery } : {})
      };
    }

    if (ch === 'feishu') {
      // Feishu timestamps are seconds-based strings (or raw timestamp if already in seconds)
      const secTs = typeof ts === 'number' && ts > 1e11 ? Math.floor(ts / 1000) : ts;
      const sign = secret ? signFeishu(secTs, secret) : undefined;
      const colorTemplate = {
        CRITICAL: 'red',
        HIGH: 'orange',
        MEDIUM: 'yellow',
        LOW: 'blue'
      }[risk.level] || 'grey';

      return {
        channel: 'feishu',
        ...packMeta,
        msg_type: 'interactive',
        timestamp: String(secTs),
        ...(sign ? { sign } : {}),
        card: {
          header: {
            title: { tag: 'plain_text', content: title },
            template: colorTemplate
          },
          elements: [
            {
              tag: 'markdown',
              content: [
                targets.length ? `**Targets**: ${targets.join(', ')}` : '',
                bodyText,
                continuationNote
              ].filter(Boolean).join('\n')
            }
          ]
        }
      };
    }

    if (ch === 'wecom') {
      const mdContent = truncateUtf8Bytes(
        [
          `**${title}**`,
          targets.length ? `Targets: \`${targets.join(', ')}\`` : '',
          bodyText,
          continuationNote
        ].filter(Boolean).join('\n'),
        4096
      );

      return {
        channel: 'wecom',
        ...packMeta,
        msgtype: 'markdown',
        markdown: {
          content: mdContent
        }
      };
    }

    // email
    return {
      channel: 'email',
      ...packMeta,
      subject: totalPacks > 1 ? `${title} [${packIndex + 1}/${totalPacks}]` : title,
      text: `${title}\n\n${bodyText}${continuationNote ? `\n\n${continuationNote}` : ''}`,
      html: `<h2>${escapeTelegramHtml(title)}</h2><pre>${escapeTelegramHtml(bodyText)}</pre>${continuationNote ? `<p><em>${escapeTelegramHtml(continuationNote)}</em></p>` : ''}`
    };
  });
}

function isLoopbackIp(ip) {
  const clean = String(ip || '').trim().replace(/^\[|\]$/g, '').toLowerCase();
  return (
    clean === '::1' ||
    clean === '::ffff:127.0.0.1' ||
    /^127\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(clean)
  );
}

/**
 * Validates an outbound notification URL with strict syntax, credential, backslash,
 * and DNS-rebinding SSRF protections.
 */
async function validateOutboundNotifyUrl(rawUrl, { allowLocalhost = false, dnsLookup = null } = {}) {
  if (typeof rawUrl !== 'string' || !rawUrl.trim()) {
    return { valid: false, error: 'Target URL must be a non-empty string' };
  }

  const trimmed = rawUrl.trim();
  const preQueryHash = trimmed.split(/[?#]/)[0];
  if (preQueryHash.includes('\\')) {
    return { valid: false, error: 'Backslash characters in URL authority or path are blocked' };
  }

  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { valid: false, error: `Invalid URL format: "${rawUrl}"` };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      valid: false,
      error: `Protocol "${parsed.protocol}" is not supported; only http: and https: are permitted`
    };
  }

  const rawAuthority = trimmed.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, '').split(/[/?#]/)[0];
  if (parsed.username || parsed.password || rawAuthority.includes('@')) {
    return {
      valid: false,
      error: 'URLs containing credentials (username or password) are not allowed'
    };
  }

  const rawHostNoPort = rawAuthority.replace(/:\d*$/, '').replace(/^\[|\]$/g, '').toLowerCase();
  const parsedHostClean = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  const isLocalhostHostname =
    (parsedHostClean === 'localhost' || parsedHostClean === '127.0.0.1' || parsedHostClean === '::1') &&
    rawHostNoPort === parsedHostClean;

  const allowPrivate = Boolean(allowLocalhost && isLocalhostHostname);
  const resolver = dnsLookup || ((host, opts) => dns.lookup(host, opts));

  const resolved = await resolveAndValidateTarget(trimmed, {
    resolver,
    allowPrivate
  });

  if (!resolved.valid) {
    return {
      valid: false,
      error: resolved.reason || resolved.error || 'Blocked by SSRF policy'
    };
  }

  if (allowPrivate && Array.isArray(resolved.resolvedIps)) {
    for (const ip of resolved.resolvedIps) {
      if (voidsExemption(ip) && !isLoopbackIp(ip)) {
        return {
          valid: false,
          error: `Localhost destination resolved to non-loopback internal IP (${ip})`
        };
      }
    }
  }

  return resolved;
}

/**
 * Multi-channel notification manager with severity/type filtering and
 * dispatch-time SSRF + DNS validation.
 */
export class NotificationManager {
  /**
   * @param {object} [options={}]
   * @param {Array<object>} [options.channels=[]]
   * @param {object} [options.filter={}]
   * @param {Function} [options.fetch]
   * @param {Function|object} [options.dnsLookup]
   * @param {Function|object} [options.resolver]
   * @param {boolean} [options.allowLocalhost=false]
   * @param { number } [options.maxItemsPerPack=5]
   */
  constructor(options = {}) {
    this.channels = Array.isArray(options.channels) ? [...options.channels] : [];
    this.filter = options.filter && typeof options.filter === 'object' ? options.filter : {};
    this.fetchImpl = typeof options.fetch === 'function'
      ? options.fetch
      : ((...args) => globalThis.fetch(...args));
    this.dnsLookup = options.dnsLookup || options.resolver || ((host, opts) => dns.lookup(host, opts));
    this.allowLocalhost = Boolean(options.allowLocalhost);
    this.maxItemsPerPack = Number(options.maxItemsPerPack) > 0 ? Number(options.maxItemsPerPack) : 5;
  }

  /**
   * Adds or updates a channel configuration.
   */
  addChannel(config) {
    if (!config || typeof config !== 'object') {
      throw new Error('Channel configuration must be an object');
    }
    const ch = String(config.channel || config.type || 'webhook').toLowerCase();
    if (!NOTIFY_CHANNELS.includes(ch)) {
      throw new Error(`Unsupported channel type: "${ch}"`);
    }
    this.channels.push({ ...config, channel: ch, enabled: config.enabled !== false });
  }

  /**
   * Filters an event by minSeverity, event type, and vulnerability class rules.
   *
   * @param {object} event
   * @param {object} [filterConfig=this.filter]
   * @returns {{ matched: boolean, findings: Array<object>, reason?: string }}
   */
  filterEvent(event = {}, filterConfig = this.filter) {
    const fCfg = filterConfig && typeof filterConfig === 'object' ? filterConfig : {};
    const minSevName = String(fCfg.minSeverity || fCfg.min_severity || 'LOW').toUpperCase();
    const minRank = Object.hasOwn(SEVERITY_RANK, minSevName) ? SEVERITY_RANK[minSevName] : 0;

    if (Array.isArray(fCfg.eventTypes) && fCfg.eventTypes.length > 0 && event.type) {
      if (!fCfg.eventTypes.includes(event.type)) {
        return { matched: false, findings: [], reason: `Event type "${event.type}" excluded by filter` };
      }
    }

    const rawFindings = Array.isArray(event.findings)
      ? event.findings
      : (Array.isArray(event.results) ? event.results : []);

    const includeClasses = Array.isArray(fCfg.vulnclassInclude || fCfg.vulnclass_include)
      ? (fCfg.vulnclassInclude || fCfg.vulnclass_include).map(s => String(s).toLowerCase())
      : null;
    const excludeClasses = Array.isArray(fCfg.vulnclassExclude || fCfg.vulnclass_exclude)
      ? (fCfg.vulnclassExclude || fCfg.vulnclass_exclude).map(s => String(s).toLowerCase())
      : null;

    const filteredFindings = rawFindings.filter(f => {
      if (!f || typeof f !== 'object') return false;
      const sev = String(f.severity || 'NONE').toUpperCase();
      const rank = Object.hasOwn(SEVERITY_RANK, sev) ? SEVERITY_RANK[sev] : 0;
      if (rank < minRank) return false;

      const checkName = String(f.checkId || f.name || f.cwe || '').toLowerCase();
      if (includeClasses && includeClasses.length > 0) {
        if (!includeClasses.some(cls => checkName.includes(cls))) return false;
      }
      if (excludeClasses && excludeClasses.length > 0) {
        if (excludeClasses.some(cls => checkName.includes(cls))) return false;
      }
      return true;
    });

    if (rawFindings.length > 0 && filteredFindings.length === 0) {
      return {
        matched: false,
        findings: [],
        reason: `No findings met minimum severity "${minSevName}" or class filters`
      };
    }

    // If event has no findings array but has a top-level severity/risk level
    if (rawFindings.length === 0 && (event.severity || event.risk?.level)) {
      const topSev = String(event.severity || event.risk?.level || 'LOW').toUpperCase();
      const topRank = Object.hasOwn(SEVERITY_RANK, topSev) ? SEVERITY_RANK[topSev] : 0;
      if (topRank < minRank) {
        return {
          matched: false,
          findings: [],
          reason: `Event severity "${topSev}" is below minimum "${minSevName}"`
        };
      }
    }

    return {
      matched: true,
      findings: filteredFindings
    };
  }

  /**
   * Validates an outbound webhook URL against SSRF policy and DNS resolution checks.
   *
   * @param {string} rawUrl
   * @param {object} [options={}]
   */
  async validateDestination(rawUrl, options = {}) {
    const allowLocal = options.allowLocalhost ?? this.allowLocalhost;
    const lookupFn = options.dnsLookup || options.resolver || this.dnsLookup;
    const validation = await validateOutboundNotifyUrl(rawUrl, {
      allowLocalhost: Boolean(allowLocal),
      dnsLookup: lookupFn
    });

    if (!validation.valid) {
      throw new NotifySecurityError(`Notification destination blocked by SSRF policy: ${validation.error}`);
    }

    return validation;
  }

  /**
   * Dispatches an event across all enabled channels after filtering and SSRF validation.
   *
   * @param {object} event
   * @returns {Promise<{ dispatched: Array<object>, skipped: Array<object>, errors: Array<object> }>}
   */
  async dispatch(event = {}) {
    const dispatched = [];
    const skipped = [];
    const errors = [];

    for (const chCfg of this.channels) {
      if (!chCfg || chCfg.enabled === false) {
        skipped.push({ channel: chCfg?.channel || 'unknown', reason: 'Channel disabled' });
        continue;
      }

      const channelName = String(chCfg.channel || chCfg.type || 'webhook').toLowerCase();
      const filterRes = this.filterEvent(event, chCfg.filter || this.filter);
      if (!filterRes.matched) {
        skipped.push({ channel: channelName, reason: filterRes.reason });
        continue;
      }

      const filteredEvent = {
        ...event,
        findings: filterRes.findings.length > 0 ? filterRes.findings : (event.findings || event.results || [])
      };

      const payloads = formatChannelPayloads(channelName, filteredEvent, {
        maxItemsPerPack: chCfg.maxItemsPerPack || this.maxItemsPerPack,
        secret: chCfg.secret,
        timestamp: event.timestamp
      });

      if (channelName === 'email') {
        if (typeof chCfg.sendEmail === 'function') {
          try {
            for (const pack of payloads) {
              await chCfg.sendEmail(pack, chCfg);
            }
            dispatched.push({ channel: 'email', packsSent: payloads.length });
          } catch (err) {
            errors.push({ channel: 'email', error: err.message });
          }
        } else {
          dispatched.push({ channel: 'email', packsSent: payloads.length, simulated: true, payloads });
        }
        continue;
      }

      const rawEndpoint = chCfg.url || chCfg.webhookUrl || chCfg.endpoint || '';
      try {
        await this.validateDestination(rawEndpoint, chCfg);

        for (const pack of payloads) {
          let targetUrl = rawEndpoint;
          if (channelName === 'dingtalk' && pack.signedQuery) {
            const sep = targetUrl.includes('?') ? '&' : '?';
            targetUrl = `${targetUrl}${sep}${pack.signedQuery}`;
          }

          const res = await this.fetchImpl(targetUrl, {
            method: chCfg.method || 'POST',
            redirect: 'manual',
            headers: {
              'Content-Type': 'application/json',
              ...(chCfg.headers || {})
            },
            body: JSON.stringify(pack)
          });

          if (res && ((res.status >= 300 && res.status < 400) || res.type === 'opaqueredirect')) {
            throw new NotifySecurityError(
              `Notification destination rejected HTTP ${res.status || 'redirect'} redirect by SSRF policy`
            );
          }

          if (res && res.ok === false) {
            throw new Error(`HTTP ${res.status}`);
          }
        }

        dispatched.push({
          channel: channelName,
          url: maskWebhookUrl(rawEndpoint),
          packsSent: payloads.length
        });
      } catch (err) {
        if (err instanceof NotifySecurityError) {
          throw err;
        }
        errors.push({
          channel: channelName,
          url: maskWebhookUrl(rawEndpoint),
          error: err.message
        });
      }
    }

    return { dispatched, skipped, errors };
  }

  /**
   * Alias of dispatch(event).
   */
  async notify(event) {
    return this.dispatch(event);
  }
}

// ── Legacy / Backward-Compatible Webhook Sender ───────────────────────────────
/**
 * Sends a Slack/JSON webhook notification after a scan completes.
 * Supports:
 *   1. sendWebhook(webhookUrl, results, risk, targets, fetchImpl, options)
 *   2. sendWebhook(webhookUrl, reportData, fetchImpl, options)
 */
export async function sendWebhook(
  webhookUrl,
  resultsOrReport,
  riskOrFetch,
  targetsOrOptions,
  maybeFetchOrOptions,
  maybeOptions
) {
  if (!webhookUrl) return;

  let results = [];
  let risk = { level: 'LOW', score: 0 };
  let targets = [];
  let fetchImpl = globalThis.fetch;
  let options = {};

  if (typeof riskOrFetch === 'function') {
    fetchImpl = riskOrFetch;
    if (Array.isArray(resultsOrReport)) {
      results = resultsOrReport;
    } else if (resultsOrReport && typeof resultsOrReport === 'object') {
      results = resultsOrReport.results || resultsOrReport.findings || [];
      risk = resultsOrReport.risk || resultsOrReport.summary || { level: 'LOW', score: 0 };
      targets = resultsOrReport.targets || [];
    }
    if (targetsOrOptions && typeof targetsOrOptions === 'object' && !Array.isArray(targetsOrOptions)) {
      options = targetsOrOptions;
    }
  } else if (!Array.isArray(resultsOrReport) && resultsOrReport && typeof resultsOrReport === 'object') {
    results = resultsOrReport.results || resultsOrReport.findings || [];
    const looksLikeOptions =
      riskOrFetch &&
      typeof riskOrFetch === 'object' &&
      ('dnsLookup' in riskOrFetch || 'resolver' in riskOrFetch || 'fetch' in riskOrFetch || 'allowLocalhost' in riskOrFetch);
    if (looksLikeOptions) {
      options = riskOrFetch;
      risk = resultsOrReport.risk || resultsOrReport.summary || { level: 'LOW', score: 0 };
      targets = resultsOrReport.targets || [];
    } else {
      risk = resultsOrReport.risk || resultsOrReport.summary || riskOrFetch || { level: 'LOW', score: 0 };
      targets = resultsOrReport.targets || (Array.isArray(targetsOrOptions) ? targetsOrOptions : []);
    }
    if (typeof maybeFetchOrOptions === 'function') {
      fetchImpl = maybeFetchOrOptions;
      if (maybeOptions && typeof maybeOptions === 'object') options = maybeOptions;
    } else if (maybeFetchOrOptions && typeof maybeFetchOrOptions === 'object') {
      options = maybeFetchOrOptions;
    }
  } else {
    results = Array.isArray(resultsOrReport) ? resultsOrReport : [];
    risk = riskOrFetch || { level: 'LOW', score: 0 };
    targets = Array.isArray(targetsOrOptions) ? targetsOrOptions : [];
    if (typeof maybeFetchOrOptions === 'function') {
      fetchImpl = maybeFetchOrOptions;
      if (maybeOptions && typeof maybeOptions === 'object') options = maybeOptions;
    } else if (maybeFetchOrOptions && typeof maybeFetchOrOptions === 'object') {
      options = maybeFetchOrOptions;
    }
  }

  if (typeof options.fetch === 'function' && fetchImpl === globalThis.fetch) {
    fetchImpl = options.fetch;
  }

  const validation = await validateOutboundNotifyUrl(webhookUrl, {
    allowLocalhost: Boolean(options.allowLocalhost),
    dnsLookup: options.dnsLookup ?? options.resolver
  });
  if (!validation.valid) {
    console.warn(`⚠️  Webhook blocked by SSRF policy: ${validation.error}`);
    return { ok: false, blocked: true, error: validation.error };
  }

  const payload = buildSlackPayload(results, risk, targets);

  const controller = new AbortController();
  const timer      = setTimeout(() => controller.abort(), 10000);
  try {
    const res = await fetchImpl(webhookUrl, {
      method   : 'POST',
      redirect : 'manual',
      headers  : { 'Content-Type': 'application/json' },
      body     : JSON.stringify(payload),
      signal   : controller.signal,
    });

    if (res && ((res.status >= 300 && res.status < 400) || res.type === 'opaqueredirect')) {
      const msg = `Webhook blocked HTTP ${res.status || 'redirect'} redirect by SSRF policy`;
      console.warn(`⚠️  ${msg}`);
      return { ok: false, blocked: true, status: res.status, error: msg };
    }

    if (!res.ok) {
      const errText = typeof res.text === 'function' ? await res.text() : '';
      console.warn(`⚠️  Webhook returned ${res.status}: ${errText}`);
      return { ok: false, status: res.status };
    } else {
      console.log(`📣  Notification sent → ${maskWebhookUrl(webhookUrl)}`);
      return { ok: true, status: res.status, payload };
    }
  } catch (e) {
    console.warn(`⚠️  Webhook failed: ${e.message}`);
    return { ok: false, error: e.message };
  } finally {
    clearTimeout(timer);
  }
}
