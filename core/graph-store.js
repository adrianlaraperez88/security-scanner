/**
 * Embedded Dual-Graph Store (Global Asset Graph + Per-Task Exploration Graph)
 * Backed by Node 24 built-in `node:sqlite` (DatabaseSync) with parameterized prepared statements.
 * Ported from ARTEX db/ subsystem (`assets.go`, `task_scope.go`, `exploration.go`, `coverage_ledger.go`, `lessons.go`).
 */

import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { isIP } from 'node:net';
import { compileAssetDsl, FIELD_SPECS, AssetDslError } from './asset-dsl.js';

export { compileAssetDsl, FIELD_SPECS, AssetDslError };

const MULTI_PART_TLDS = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'net.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn',
  'co.nz', 'org.nz', 'govt.nz',
  'co.za', 'org.za', 'gov.za',
  'co.in', 'net.in', 'org.in', 'gov.in',
  'com.mx', 'com.sg', 'com.tw', 'com.hk', 'co.kr',
]);

const VALID_ASSET_TYPES = new Set([
  'root_domain',
  'ip',
  'subdomain',
  'app',
  'service',
  'endpoint',
]);

const VALID_NODE_TYPES = new Set([
  'begin',
  'goal',
  'intent',
  'fact',
  'finding',
  'hint',
  'digest',
]);

const VALID_EDGE_TYPES = new Set([
  'spawns',
  'derived_from',
  'yields',
  'proves',
  'covers',
]);

/**
 * Expand an IPv6 address into 8 full 16-bit integer groups.
 * Returns null if invalid.
 */
function parseIpv6Groups(ipStr) {
  let addr = String(ipStr || '').trim().toLowerCase();
  if (addr.startsWith('[') && addr.endsWith(']')) {
    addr = addr.slice(1, -1);
  }
  const zoneIdx = addr.indexOf('%');
  if (zoneIdx !== -1) {
    addr = addr.slice(0, zoneIdx);
  }
  if (isIP(addr) !== 6) return null;

  // Handle embedded IPv4 tail (e.g. ::ffff:192.168.1.1)
  if (addr.includes('.')) {
    const lastColon = addr.lastIndexOf(':');
    const ipv4Part = addr.slice(lastColon + 1);
    const octets = ipv4Part.split('.').map(Number);
    if (octets.length !== 4 || octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) {
      return null;
    }
    const hi = ((octets[0] << 8) | octets[1]).toString(16);
    const lo = ((octets[2] << 8) | octets[3]).toString(16);
    addr = `${addr.slice(0, lastColon)}:${hi}:${lo}`;
  }

  const dblParts = addr.split('::');
  if (dblParts.length > 2) return null;

  const left = dblParts[0] ? dblParts[0].split(':') : [];
  const right = dblParts.length === 2 && dblParts[1] ? dblParts[1].split(':') : [];
  const missing = 8 - (left.length + right.length);
  if (dblParts.length === 1 && left.length !== 8) return null;
  if (missing < 0) return null;

  const full = [...left, ...Array(dblParts.length === 2 ? missing : 0).fill('0'), ...right];
  if (full.length !== 8) return null;

  return full.map((h) => parseInt(h || '0', 16));
}

/**
 * Compute C-segment network for an IPv4 (/24) or IPv6 (/48) literal.
 */
export function computeCSegment(ipStr) {
  if (!ipStr || typeof ipStr !== 'string') return null;
  let cleaned = ipStr.trim();
  if (cleaned.startsWith('[') && cleaned.endsWith(']')) {
    cleaned = cleaned.slice(1, -1);
  }
  const ver = isIP(cleaned);
  if (ver === 4) {
    const parts = cleaned.split('.');
    if (parts.length === 4) {
      return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
    }
    return null;
  }
  if (ver === 6) {
    const groups = parseIpv6Groups(cleaned);
    if (!groups) return null;
    const g0 = groups[0].toString(16);
    const g1 = groups[1].toString(16);
    const g2 = groups[2].toString(16);
    if (groups[0] === 0 && groups[1] === 0 && groups[2] === 0) {
      return '::/48';
    }
    if (groups[1] === 0 && groups[2] === 0) {
      return `${g0}::/48`;
    }
    if (groups[2] === 0) {
      return `${g0}:${g1}::/48`;
    }
    return `${g0}:${g1}:${g2}::/48`;
  }
  return null;
}

/**
 * Extract apex / root domain from a hostname.
 * Returns null if hostname is an IP literal or empty.
 */
export function extractRootDomain(hostname) {
  if (!hostname || typeof hostname !== 'string') return null;
  let host = hostname.trim().toLowerCase();
  if (host.startsWith('*.')) host = host.slice(2);
  if (host.startsWith('.')) host = host.slice(1);
  if (host.endsWith('.')) host = host.slice(0, -1);

  if (!host.startsWith('[') && host.includes(':') && isIP(host) === 0) {
    host = host.split(':')[0];
  }
  if (host.startsWith('[') && host.includes(']')) {
    host = host.slice(1, host.indexOf(']'));
  }
  if (!host || isIP(host) !== 0) return null;

  const labels = host.split('.').filter(Boolean);
  if (labels.length <= 2) {
    return labels.join('.');
  }
  const lastTwo = `${labels[labels.length - 2]}.${labels[labels.length - 1]}`;
  if (MULTI_PART_TLDS.has(lastTwo) && labels.length >= 3) {
    return labels.slice(-3).join('.');
  }
  return labels.slice(-2).join('.');
}

function ipv4ToBigInt(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return null;
  }
  return (
    (BigInt(parts[0]) << 24n) |
    (BigInt(parts[1]) << 16n) |
    (BigInt(parts[2]) << 8n) |
    BigInt(parts[3])
  );
}

function ipv6ToBigInt(ip) {
  const groups = parseIpv6Groups(ip);
  if (!groups) return null;
  let res = 0n;
  for (const g of groups) {
    res = (res << 16n) | BigInt(g);
  }
  return res;
}

function ipMatchesCidr(ipStr, cidrStr) {
  if (!ipStr || !cidrStr || !cidrStr.includes('/')) return false;
  const [netAddr, prefixStr] = cidrStr.trim().split('/');
  const prefix = Number(prefixStr);
  if (!Number.isInteger(prefix)) return false;

  const ipVer = isIP(ipStr.trim());
  const netVer = isIP(netAddr.trim());
  if (ipVer === 0 || ipVer !== netVer) return false;

  if (ipVer === 4) {
    if (prefix < 0 || prefix > 32) return false;
    const ipVal = ipv4ToBigInt(ipStr.trim());
    const netVal = ipv4ToBigInt(netAddr.trim());
    if (ipVal === null || netVal === null) return false;
    if (prefix === 0) return true;
    const mask = ((1n << 32n) - 1n) ^ ((1n << BigInt(32 - prefix)) - 1n);
    return (ipVal & mask) === (netVal & mask);
  }

  if (ipVer === 6) {
    if (prefix < 0 || prefix > 128) return false;
    const ipVal = ipv6ToBigInt(ipStr.trim());
    const netVal = ipv6ToBigInt(netAddr.trim());
    if (ipVal === null || netVal === null) return false;
    if (prefix === 0) return true;
    const mask = ((1n << 128n) - 1n) ^ ((1n << BigInt(128 - prefix)) - 1n);
    return (ipVal & mask) === (netVal & mask);
  }

  return false;
}

function cidrContainsCidr(outerCidr, innerIpOrCidr) {
  if (!outerCidr || !innerIpOrCidr) return false;
  if (!outerCidr.includes('/')) {
    return outerCidr.trim().toLowerCase() === innerIpOrCidr.trim().toLowerCase();
  }
  if (!innerIpOrCidr.includes('/')) {
    return ipMatchesCidr(innerIpOrCidr, outerCidr);
  }
  const [outerNet, outerPrefixStr] = outerCidr.trim().split('/');
  const [innerNet, innerPrefixStr] = innerIpOrCidr.trim().split('/');
  const outerPrefix = Number(outerPrefixStr);
  const innerPrefix = Number(innerPrefixStr);
  if (!Number.isInteger(outerPrefix) || !Number.isInteger(innerPrefix)) return false;
  if (outerPrefix > innerPrefix) return false;
  return ipMatchesCidr(innerNet, outerCidr);
}

function matchWildcardGlob(pattern, text, { maxPatternLen = 2048 } = {}) {
  const pat = String(pattern || '').toLowerCase();
  const str = String(text || '').toLowerCase();
  if (!pat || pat.length > maxPatternLen) return false;
  let pi = 0;
  let si = 0;
  let starIdx = -1;
  let matchIdx = 0;
  while (si < str.length) {
    if (pi < pat.length && pat[pi] === str[si]) {
      pi++;
      si++;
    } else if (pi < pat.length && pat[pi] === '*') {
      starIdx = pi;
      matchIdx = si;
      pi++;
    } else if (starIdx !== -1) {
      pi = starIdx + 1;
      matchIdx++;
      si = matchIdx;
    } else {
      return false;
    }
  }
  while (pi < pat.length && pat[pi] === '*') {
    pi++;
  }
  return pi === pat.length;
}

function domainMatchesRoot(candidateHost, rootPattern) {
  if (!candidateHost || !rootPattern) return false;
  let host = String(candidateHost).trim().toLowerCase().replace(/\.+$/, '');
  const rawPat = String(rootPattern).trim().toLowerCase();
  let pat = rawPat;
  if (pat.startsWith('*.')) pat = pat.slice(2);
  if (pat.startsWith('.')) pat = pat.slice(1);
  pat = pat.replace(/\.+$/, '');
  if (host.startsWith('*.')) host = host.slice(2);
  if (!host || !pat) return false;
  if (pat.includes('*')) {
    return matchWildcardGlob(pat, host);
  }
  if (host === pat || host.endsWith(`.${pat}`)) return true;
  if (rawPat.startsWith('.') && !pat.includes('.') && host.includes(`.${pat}.`)) {
    return true;
  }
  return false;
}

function safeJsonParse(str, fallback = {}) {
  if (str == null || str === '') return fallback;
  if (typeof str === 'object') return str;
  try {
    return JSON.parse(str);
  } catch {
    return fallback;
  }
}

function parseUrlComponents(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') return null;
  try {
    const u = new URL(rawUrl);
    u.username = '';
    u.password = '';
    const protocol = u.protocol.replace(/:$/, '').toLowerCase();
    let host = u.hostname.toLowerCase();
    if (host.startsWith('[') && host.endsWith(']')) {
      host = host.slice(1, -1);
    }
    const port = u.port ? Number(u.port) : (protocol === 'https' ? 443 : protocol === 'http' ? 80 : null);
    const pathPart = `${u.pathname || '/'}${u.search || ''}`;
    let normalizedUrl = u.toString();
    if (normalizedUrl.endsWith('/') && u.pathname === '/' && !u.search && !u.hash) {
      normalizedUrl = normalizedUrl.slice(0, -1);
    }
    return {
      url: normalizedUrl,
      protocol,
      host,
      port,
      path: pathPart,
      service: protocol,
    };
  } catch {
    return null;
  }
}

function inferCheckCategory(checkName = '', meta = {}) {
  const text = `${checkName} ${meta?.category || ''} ${meta?.title || ''}`.toLowerCase();
  if (/sql|xss|ssti|crlf|inject|command|proto|xxe|graphql|open-redirect/.test(text)) return 'injection';
  if (/auth|jwt|csrf|cors|cookie|session|oauth|saml|idor|bola/.test(text)) return 'auth';
  if (/env|git|backup|sourcemap|source-map|actuators|swagger|openapi|debug|expose|leak|secret|ai|llm|mcp| bucket|s3/.test(text)) return 'exposure';
  if (/header|csp|hsts|tls|ssl|config|method|clickjack|sri|cache|host-header/.test(text)) return 'config';
  return 'recon';
}

export class GraphStore {
  constructor({ dbPath = ':memory:' } = {}) {
    this.dbPath = dbPath || ':memory:';
    if (this.dbPath !== ':memory:') {
      const dir = path.dirname(this.dbPath);
      if (dir && dir !== '.') {
        fs.mkdirSync(dir, { recursive: true });
      }
    }
    this.db = new DatabaseSync(this.dbPath);
    this._closed = false;
    this._txDepth = 0;
    this._initSchema();
  }

  _initSchema() {
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA busy_timeout = 5000;
      PRAGMA foreign_keys = ON;

      -- Global Asset Graph
      CREATE TABLE IF NOT EXISTS companies (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        created_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS company_scope (
        id TEXT PRIMARY KEY,
        company_id TEXT NOT NULL,
        rule_type TEXT NOT NULL,
        pattern TEXT NOT NULL,
        is_allowed INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS assets (
        id TEXT PRIMARY KEY,
        company_id TEXT,
        asset_type TEXT NOT NULL CHECK(asset_type IN ('root_domain','ip','subdomain','app','service','endpoint')),
        key TEXT NOT NULL,
        host TEXT,
        ip TEXT,
        port INTEGER,
        protocol TEXT,
        service TEXT,
        url TEXT,
        path TEXT,
        title TEXT,
        status_code INTEGER,
        c_segment TEXT,
        source TEXT,
        confidence REAL DEFAULT 1.0,
        verified INTEGER NOT NULL DEFAULT 0,
        parent_asset_id TEXT,
        metadata_json TEXT DEFAULT '{}',
        first_seen_at INTEGER NOT NULL,
        last_seen_at INTEGER NOT NULL,
        UNIQUE(asset_type, key)
      );

      CREATE INDEX IF NOT EXISTS idx_assets_host ON assets(host);
      CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip);
      CREATE INDEX IF NOT EXISTS idx_assets_parent ON assets(parent_asset_id);
      CREATE INDEX IF NOT EXISTS idx_assets_c_segment ON assets(c_segment);

      CREATE TABLE IF NOT EXISTS task_asset_links (
        task_id TEXT NOT NULL,
        asset_id TEXT NOT NULL,
        relation TEXT NOT NULL DEFAULT 'discovered',
        created_at INTEGER NOT NULL,
        PRIMARY KEY (task_id, asset_id, relation)
      );

      CREATE TABLE IF NOT EXISTS task_scope (
        id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        rule_type TEXT NOT NULL,
        pattern TEXT NOT NULL,
        is_allowed INTEGER NOT NULL DEFAULT 1,
        source TEXT NOT NULL DEFAULT 'declared',
        created_at INTEGER NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_task_scope_task ON task_scope(task_id);

      -- Per-Task Exploration Graph
      CREATE TABLE IF NOT EXISTS tasks (
        id TEXT PRIMARY KEY,
        title TEXT,
        target TEXT,
        goal TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        mode TEXT NOT NULL DEFAULT 'auto',
        noise_profile TEXT NOT NULL DEFAULT 'balanced',
        llm_profile_ids_json TEXT NOT NULL DEFAULT '[]',
        llm_rotate INTEGER NOT NULL DEFAULT 0,
        allow_private INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS explorations (
        id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        round_no INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'open',
        summary TEXT,
        created_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS exploration_nodes (
        id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        node_type TEXT NOT NULL CHECK(node_type IN ('begin','goal','intent','fact','finding','hint','digest')),
        title TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        severity TEXT,
        poe_level INTEGER DEFAULT 0,
        confidence REAL DEFAULT 1.0,
        summary TEXT,
        data_json TEXT DEFAULT '{}',
        claim_owner TEXT,
        unclaim_token TEXT,
        claim_expires_at INTEGER,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_exp_nodes_task ON exploration_nodes(task_id, node_type, status);

      CREATE TABLE IF NOT EXISTS exploration_edges (
        id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        from_node_id TEXT NOT NULL,
        to_node_id TEXT NOT NULL,
        edge_type TEXT NOT NULL CHECK(edge_type IN ('spawns','derived_from','yields','proves','covers')),
        label TEXT,
        created_at INTEGER NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_exp_edges_task ON exploration_edges(task_id, from_node_id, to_node_id);

      CREATE TABLE IF NOT EXISTS exploration_anchors (
        id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        node_id TEXT NOT NULL,
        asset_id TEXT NOT NULL,
        relation TEXT NOT NULL DEFAULT 'targets',
        created_at INTEGER NOT NULL,
        UNIQUE(task_id, node_id, asset_id, relation)
      );

      CREATE INDEX IF NOT EXISTS idx_exp_anchors_task ON exploration_anchors(task_id, node_id, asset_id);

      CREATE TABLE IF NOT EXISTS task_constraints (
        id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        constraint_type TEXT NOT NULL CHECK(constraint_type IN ('allow','deny')),
        rule_type TEXT NOT NULL,
        pattern TEXT NOT NULL,
        note TEXT,
        created_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS activity (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id TEXT NOT NULL,
        actor TEXT,
        event_type TEXT NOT NULL,
        node_id TEXT,
        summary TEXT,
        payload_json TEXT DEFAULT '{}',
        created_at INTEGER NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_activity_task_seq ON activity(task_id, seq);

      CREATE TABLE IF NOT EXISTS coverage_ledger (
        id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        asset_id TEXT NOT NULL,
        check_category TEXT NOT NULL,
        intent_node_id TEXT,
        status TEXT NOT NULL DEFAULT 'tested',
        notes TEXT,
        updated_at INTEGER NOT NULL,
        UNIQUE(task_id, asset_id, check_category)
      );

      CREATE TABLE IF NOT EXISTS rsi_lessons (
        id TEXT PRIMARY KEY,
        fingerprint_sha256 TEXT NOT NULL UNIQUE,
        category TEXT NOT NULL,
        title TEXT NOT NULL,
        lesson TEXT NOT NULL,
        evidence_node_id TEXT,
        verified INTEGER NOT NULL DEFAULT 0,
        hit_count INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL
      );
    `);

    const taskCols = this.db.prepare('PRAGMA table_info(tasks)').all();
    if (!taskCols.some((c) => c.name === 'allow_private')) {
      this.db.exec('ALTER TABLE tasks ADD COLUMN allow_private INTEGER NOT NULL DEFAULT 0;');
    }
  }

  _inTransaction(fn) {
    if (this._txDepth > 0) {
      this._txDepth++;
      try {
        return fn();
      } finally {
        this._txDepth--;
      }
    }
    this._txDepth = 1;
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const result = fn();
      this.db.exec('COMMIT');
      return result;
    } catch (err) {
      try {
        this.db.exec('ROLLBACK');
      } catch {}
      throw err;
    } finally {
      this._txDepth = 0;
    }
  }

  // ── Row Hydrators ──────────────────────────────────────────────────────────

  _hydrateTask(row) {
    if (!row) return null;
    const llmProfileIds = safeJsonParse(row.llm_profile_ids_json, []);
    const llmRotate = Boolean(row.llm_rotate);
    const allowPrivate = Boolean(row.allow_private);
    return {
      ...row,
      noiseProfile: row.noise_profile,
      llmProfileIds,
      llm_profile_ids: llmProfileIds,
      llmRotate,
      llm_rotate: row.llm_rotate,
      allowPrivate,
      allow_private: allowPrivate,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  _hydrateAsset(row) {
    if (!row) return null;
    const metadata = safeJsonParse(row.metadata_json, {});
    return {
      ...row,
      type: row.asset_type,
      assetType: row.asset_type,
      companyId: row.company_id,
      statusCode: row.status_code,
      cSegment: row.c_segment,
      parentAssetId: row.parent_asset_id,
      verified: Boolean(row.verified),
      metadata,
      firstSeenAt: row.first_seen_at,
      lastSeenAt: row.last_seen_at,
    };
  }

  _hydrateNode(row) {
    if (!row) return null;
    const data = safeJsonParse(row.data_json, {});
    return {
      ...row,
      taskId: row.task_id,
      nodeType: row.node_type,
      type: row.node_type,
      poeLevel: row.poe_level,
      data,
      claimOwner: row.claim_owner,
      unclaimToken: row.unclaim_token,
      claimExpiresAt: row.claim_expires_at,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  _hydrateEdge(row) {
    if (!row) return null;
    return {
      ...row,
      taskId: row.task_id,
      fromNodeId: row.from_node_id,
      toNodeId: row.to_node_id,
      edgeType: row.edge_type,
      from: row.from_node_id,
      to: row.to_node_id,
      type: row.edge_type,
      createdAt: row.created_at,
    };
  }

  _hydrateAnchor(row) {
    if (!row) return null;
    return {
      ...row,
      taskId: row.task_id,
      nodeId: row.node_id,
      assetId: row.asset_id,
      createdAt: row.created_at,
    };
  }

  // ── Companies & Company Scope ──────────────────────────────────────────────

  upsertCompany({ id, name, createdAt = Date.now() } = {}) {
    if (!name) throw new Error('Company name is required');
    const companyId = id || `comp_${crypto.randomUUID()}`;
    this.db
      .prepare(
        `INSERT INTO companies (id, name, created_at)
         VALUES (?, ?, ?)
         ON CONFLICT(name) DO UPDATE SET name = excluded.name`
      )
      .run(companyId, String(name).trim(), createdAt);
    return this.db.prepare('SELECT * FROM companies WHERE name = ?').get(String(name).trim());
  }

  setCompanyScope(companyId, rules = []) {
    return this._inTransaction(() => {
      this.db.prepare('DELETE FROM company_scope WHERE company_id = ?').run(companyId);
      const stmt = this.db.prepare(
        `INSERT INTO company_scope (id, company_id, rule_type, pattern, is_allowed, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`
      );
      const now = Date.now();
      for (const r of rules) {
        const id = r.id || `cscope_${crypto.randomUUID()}`;
        const ruleType = r.rule_type || r.ruleType || r.kind || r.type || 'domain';
        const pattern = String(r.pattern ?? r.value ?? r.domain ?? r.net ?? '').trim();
        const isAllowed = (r.is_allowed ?? r.isAllowed ?? r.allowed ?? true) ? 1 : 0;
        stmt.run(id, companyId, ruleType, pattern, isAllowed, r.created_at || now);
      }
      return this.getCompanyScope(companyId);
    });
  }

  getCompanyScope(companyId) {
    const rows = this.db
      .prepare('SELECT * FROM company_scope WHERE company_id = ? ORDER BY created_at ASC, id ASC')
      .all(companyId);
    return rows.map((r) => ({
      ...r,
      companyId: r.company_id,
      ruleType: r.rule_type,
      isAllowed: Boolean(r.is_allowed),
    }));
  }

  // ── Tasks, Scope & Constraints ─────────────────────────────────────────────

  createTask(task = {}) {
    const now = Date.now();
    const id = task.id || `task_${crypto.randomUUID()}`;
    const title = task.title ?? (task.target ? `Task: ${task.target}` : 'Verification Task');
    const target = task.target ?? null;
    const goal = task.goal ?? '';
    const status = task.status ?? 'pending';
    const mode = task.mode ?? 'auto';
    const noiseProfile = task.noise_profile ?? task.noiseProfile ?? 'balanced';
    const rawProfiles = task.llm_profile_ids ?? task.llmProfileIds ?? safeJsonParse(task.llm_profile_ids_json, []);
    const llmProfileIdsJson = typeof rawProfiles === 'string' ? rawProfiles : JSON.stringify(rawProfiles);
    const llmRotate = (task.llm_rotate ?? task.llmRotate ?? false) ? 1 : 0;
    const allowPrivate = (task.allow_private ?? task.allowPrivate ?? false) ? 1 : 0;
    const createdAt = task.created_at ?? task.createdAt ?? now;
    const updatedAt = task.updated_at ?? task.updatedAt ?? createdAt;

    this.db
      .prepare(
        `INSERT INTO tasks (
          id, title, target, goal, status, mode, noise_profile,
          llm_profile_ids_json, llm_rotate, allow_private, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        id,
        title,
        target,
        goal,
        status,
        mode,
        noiseProfile,
        llmProfileIdsJson,
        llmRotate,
        allowPrivate,
        createdAt,
        updatedAt
      );

    // Ensure an initial exploration round exists for this task
    this.db
      .prepare(
        `INSERT OR IGNORE INTO explorations (id, task_id, round_no, status, summary, created_at)
         VALUES (?, ?, 0, 'open', ?, ?)`
      )
      .run(`exp_${id}`, id, goal || title, createdAt);

    if (Array.isArray(task.scope) && task.scope.length > 0) {
      this.setTaskScope(id, task.scope);
    }
    if (Array.isArray(task.constraints) && task.constraints.length > 0) {
      this.setTaskConstraints(id, task.constraints);
    }

    return this.getTask(id);
  }

  getTask(taskId) {
    if (!taskId) return null;
    const row = this.db.prepare('SELECT * FROM tasks WHERE id = ?').get(taskId);
    return this._hydrateTask(row);
  }

  listTasks(filter = {}) {
    const clauses = ['1=1'];
    const params = [];
    if (filter.status) {
      clauses.push('status = ?');
      params.push(filter.status);
    }
    if (filter.mode) {
      clauses.push('mode = ?');
      params.push(filter.mode);
    }
    if (filter.target) {
      clauses.push('LOWER(target) LIKE LOWER(?)');
      params.push(`%${filter.target}%`);
    }
    const limit = Number(filter.limit) > 0 ? Number(filter.limit) : 200;
    params.push(limit);

    const rows = this.db
      .prepare(`SELECT * FROM tasks WHERE ${clauses.join(' AND ')} ORDER BY created_at DESC, id DESC LIMIT ?`)
      .all(...params);
    return rows.map((r) => this._hydrateTask(r));
  }

  updateTask(taskId, patch = {}) {
    const existing = this.getTask(taskId);
    if (!existing) return null;

    const now = patch.updated_at ?? patch.updatedAt ?? Date.now();
    const title = patch.title !== undefined ? patch.title : existing.title;
    const target = patch.target !== undefined ? patch.target : existing.target;
    const goal = patch.goal !== undefined ? patch.goal : existing.goal;
    const status = patch.status !== undefined ? patch.status : existing.status;
    const mode = patch.mode !== undefined ? patch.mode : existing.mode;
    const noiseProfile =
      patch.noise_profile !== undefined
        ? patch.noise_profile
        : patch.noiseProfile !== undefined
          ? patch.noiseProfile
          : existing.noise_profile;

    let llmProfileIdsJson = existing.llm_profile_ids_json;
    if (patch.llm_profile_ids_json !== undefined) {
      llmProfileIdsJson = patch.llm_profile_ids_json;
    } else if (patch.llm_profile_ids !== undefined || patch.llmProfileIds !== undefined) {
      const arr = patch.llm_profile_ids ?? patch.llmProfileIds;
      llmProfileIdsJson = typeof arr === 'string' ? arr : JSON.stringify(arr);
    }

    let llmRotate = existing.llm_rotate;
    if (patch.llm_rotate !== undefined || patch.llmRotate !== undefined) {
      llmRotate = (patch.llm_rotate ?? patch.llmRotate) ? 1 : 0;
    }

    let allowPrivate = existing.allow_private ? 1 : 0;
    if (patch.allow_private !== undefined || patch.allowPrivate !== undefined) {
      allowPrivate = (patch.allow_private ?? patch.allowPrivate) ? 1 : 0;
    }

    this.db
      .prepare(
        `UPDATE tasks
         SET title = ?, target = ?, goal = ?, status = ?, mode = ?,
             noise_profile = ?, llm_profile_ids_json = ?, llm_rotate = ?, allow_private = ?, updated_at = ?
         WHERE id = ?`
      )
      .run(
        title,
        target,
        goal,
        status,
        mode,
        noiseProfile,
        llmProfileIdsJson,
        llmRotate,
        allowPrivate,
        now,
        taskId
      );

    return this.getTask(taskId);
  }

  setTaskScope(taskId, rules = []) {
    return this._inTransaction(() => {
      this.db.prepare('DELETE FROM task_scope WHERE task_id = ?').run(taskId);
      const stmt = this.db.prepare(
        `INSERT INTO task_scope (id, task_id, rule_type, pattern, is_allowed, source, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      );
      const now = Date.now();
      for (const r of rules) {
        const id = r.id || `scope_${crypto.randomUUID()}`;
        const ruleType = String(r.rule_type || r.ruleType || r.kind || r.type || 'domain').toLowerCase();
        const pattern = String(r.pattern ?? r.value ?? r.domain ?? r.net ?? '').trim();
        let isAllowed = 1;
        if (r.is_allowed !== undefined) isAllowed = r.is_allowed ? 1 : 0;
        else if (r.isAllowed !== undefined) isAllowed = r.isAllowed ? 1 : 0;
        else if (r.allowed !== undefined) isAllowed = r.allowed ? 1 : 0;
        else if (r.action === 'deny' || r.constraint_type === 'deny') isAllowed = 0;

        const source = String(r.source || 'declared').toLowerCase();
        stmt.run(id, taskId, ruleType, pattern, isAllowed, source, r.created_at || now);
      }
      return this.getTaskScope(taskId);
    });
  }

  getTaskScope(taskId) {
    const rows = this.db
      .prepare('SELECT * FROM task_scope WHERE task_id = ? ORDER BY created_at ASC, id ASC')
      .all(taskId);
    return rows.map((r) => ({
      ...r,
      taskId: r.task_id,
      ruleType: r.rule_type,
      isAllowed: Boolean(r.is_allowed),
      createdAt: r.created_at,
    }));
  }

  setTaskConstraints(taskId, constraints = []) {
    return this._inTransaction(() => {
      this.db.prepare('DELETE FROM task_constraints WHERE task_id = ?').run(taskId);
      const stmt = this.db.prepare(
        `INSERT INTO task_constraints (id, task_id, constraint_type, rule_type, pattern, note, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      );
      const now = Date.now();
      for (const c of constraints) {
        const id = c.id || `cstr_${crypto.randomUUID()}`;
        let constraintType = c.constraint_type || c.constraintType || c.action || 'deny';
        if (c.is_allowed !== undefined) constraintType = c.is_allowed ? 'allow' : 'deny';
        if (c.isAllowed !== undefined) constraintType = c.isAllowed ? 'allow' : 'deny';
        const ruleType = c.rule_type || c.ruleType || c.type || 'domain';
        const pattern = String(c.pattern ?? c.value ?? '').trim();
        const note = c.note ?? c.reason ?? null;
        stmt.run(id, taskId, constraintType, ruleType, pattern, note, c.created_at || now);
      }
      return this.getTaskConstraints(taskId);
    });
  }

  getTaskConstraints(taskId) {
    const rows = this.db
      .prepare('SELECT * FROM task_constraints WHERE task_id = ? ORDER BY created_at ASC, id ASC')
      .all(taskId);
    return rows.map((r) => ({
      ...r,
      taskId: r.task_id,
      constraintType: r.constraint_type,
      ruleType: r.rule_type,
      createdAt: r.created_at,
    }));
  }

  // ── Global Asset Graph ─────────────────────────────────────────────────────

  /**
   * Automatic parent host asset derivation (`endpoint`/`service`/`app` -> `subdomain`/`ip` -> `root_domain`).
   */
  linkHostAssets(assetInput, { taskId = null } = {}) {
    const assetType = String(
      assetInput.asset_type || assetInput.assetType || assetInput.type || assetInput.kind || ''
    ).toLowerCase();
    const host = assetInput.host ? String(assetInput.host).trim().toLowerCase() : null;
    const ip = assetInput.ip ? String(assetInput.ip).trim() : null;
    const companyId = assetInput.company_id || assetInput.companyId || null;
    const source = assetInput.source || 'derived';

    if (assetType === 'root_domain' || assetType === 'ip') {
      return null;
    }

    if (assetType === 'subdomain') {
      if (host && isIP(host) === 0) {
        const rootDomain = extractRootDomain(host);
        if (rootDomain && rootDomain !== host) {
          const rootAsset = this.upsertAsset(
            {
              asset_type: 'root_domain',
              key: rootDomain,
              host: rootDomain,
              company_id: companyId,
              source,
            },
            { taskId, _skipParentLink: true }
          );
          return rootAsset.id;
        }
      }
      return null;
    }

    // For 'endpoint', 'service', 'app'
    let parentId = null;
    if (host && isIP(host) === 0) {
      const rootDomain = extractRootDomain(host);
      let rootAsset = null;
      if (rootDomain) {
        rootAsset = this.upsertAsset(
          {
            asset_type: 'root_domain',
            key: rootDomain,
            host: rootDomain,
            company_id: companyId,
            source,
          },
          { taskId, _skipParentLink: true }
        );
      }
      if (rootDomain && host !== rootDomain) {
        const subAsset = this.upsertAsset(
          {
            asset_type: 'subdomain',
            key: host,
            host,
            parent_asset_id: rootAsset ? rootAsset.id : null,
            company_id: companyId,
            source,
          },
          { taskId, _skipParentLink: true }
        );
        parentId = subAsset.id;
      } else if (rootAsset) {
        parentId = rootAsset.id;
      }

      if (ip && isIP(ip) !== 0) {
        this.upsertAsset(
          {
            asset_type: 'ip',
            key: ip,
            host: ip,
            ip,
            company_id: companyId,
            source,
          },
          { taskId, _skipParentLink: true }
        );
      }
      return parentId;
    }

    const effectiveIp = (host && isIP(host) !== 0) ? host : (ip && isIP(ip) !== 0 ? ip : null);
    if (effectiveIp) {
      const ipAsset = this.upsertAsset(
        {
          asset_type: 'ip',
          key: effectiveIp,
          host: effectiveIp,
          ip: effectiveIp,
          company_id: companyId,
          source,
        },
        { taskId, _skipParentLink: true }
      );
      return ipAsset.id;
    }

    return null;
  }

  upsertAsset(asset = {}, { taskId = null, relation = 'discovered', _skipParentLink = false } = {}) {
    const now = Date.now();
    let assetType = String(
      asset.asset_type || asset.assetType || asset.type || asset.kind || ''
    ).trim().toLowerCase();

    let parsedUrl = null;
    if (asset.url) {
      parsedUrl = parseUrlComponents(asset.url);
    } else if (asset.key && (String(asset.key).startsWith('http://') || String(asset.key).startsWith('https://'))) {
      parsedUrl = parseUrlComponents(String(asset.key));
    }

    if (!assetType) {
      if (parsedUrl) {
        assetType = parsedUrl.path && parsedUrl.path !== '/' ? 'endpoint' : 'service';
      } else if (asset.ip && !asset.host && !asset.domain) {
        assetType = 'ip';
      } else if (asset.host || asset.domain || asset.key) {
        const h = String(asset.host || asset.domain || asset.key).trim().toLowerCase();
        if (isIP(h) !== 0) {
          assetType = 'ip';
        } else {
          const root = extractRootDomain(h);
          assetType = root && root !== h ? 'subdomain' : 'root_domain';
        }
      } else {
        assetType = 'endpoint';
      }
    }

    if (assetType === 'domain') {
      const h = String(asset.host || asset.domain || asset.key || '').trim().toLowerCase();
      const root = extractRootDomain(h);
      assetType = root && root !== h ? 'subdomain' : 'root_domain';
    }

    if (!VALID_ASSET_TYPES.has(assetType)) {
      throw new Error(`Invalid asset_type "${assetType}". Must be one of: ${Array.from(VALID_ASSET_TYPES).join(', ')}`);
    }

    let host = asset.host ?? asset.domain ?? (parsedUrl ? parsedUrl.host : null);
    if (host) {
      host = String(host).trim().toLowerCase();
      if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
    }

    const valueStr = asset.value ? String(asset.value).trim() : '';
    let ip = asset.ip ?? (assetType === 'ip' ? (asset.key || (valueStr && isIP(valueStr) !== 0 ? valueStr : null) || host) : null);
    if (!ip && host && isIP(host) !== 0) {
      ip = host;
    }
    if (ip) {
      ip = String(ip).trim();
    }

    let url = parsedUrl ? parsedUrl.url : (asset.url ? String(asset.url).trim() : null);
    let port = asset.port !== undefined && asset.port !== null ? Number(asset.port) : (parsedUrl ? parsedUrl.port : null);
    let protocol = asset.protocol ?? (parsedUrl ? parsedUrl.protocol : null);
    let service = asset.service ?? asset.service_name ?? (parsedUrl ? parsedUrl.service : null);
    let pathVal = asset.path ?? (parsedUrl ? parsedUrl.path : null);
    const title = asset.title ?? asset.page_title ?? null;
    const statusCode =
      asset.status_code !== undefined && asset.status_code !== null
        ? Number(asset.status_code)
        : asset.statusCode !== undefined && asset.statusCode !== null
          ? Number(asset.statusCode)
          : asset.status !== undefined && typeof asset.status === 'number'
            ? Number(asset.status)
            : null;

    let key = asset.key ? String(asset.key).trim() : '';
    if (!key) {
      if (assetType === 'root_domain' || assetType === 'subdomain') {
        key = host || '';
      } else if (assetType === 'ip') {
        key = ip || host || '';
      } else if (assetType === 'endpoint') {
        key = url || `${host || ip || ''}${pathVal || '/'}`;
      } else if (assetType === 'service') {
        key = url || `${protocol || 'tcp'}://${host || ip || ''}${port ? `:${port}` : ''}`;
      } else if (assetType === 'app') {
        key = String(asset.name || asset.bundle_id || title || url || host || '');
      }
    }
    if (!key) {
      throw new Error(`Asset key could not be derived for asset_type "${assetType}"`);
    }
    if ((assetType === 'root_domain' || assetType === 'subdomain') && !host) {
      host = key.toLowerCase();
      key = host;
    }
    if (assetType === 'ip' && !ip) {
      ip = key;
      if (!host) host = ip;
    }

    const cSegment =
      asset.c_segment ??
      asset.cSegment ??
      (ip ? computeCSegment(ip) : null);

    let parentAssetId = asset.parent_asset_id ?? asset.parentAssetId ?? null;
    if (!_skipParentLink) {
      const derivedParentId = this.linkHostAssets(
        {
          asset_type: assetType,
          host,
          ip,
          company_id: asset.company_id ?? asset.companyId ?? null,
          source: asset.source || 'derived',
        },
        { taskId }
      );
      if (!parentAssetId && derivedParentId) {
        parentAssetId = derivedParentId;
      }
    }

    const companyId = asset.company_id ?? asset.companyId ?? null;
    const source = asset.source ?? 'scanner';
    const confidence = asset.confidence !== undefined && asset.confidence !== null ? Number(asset.confidence) : 1.0;
    const verified = (asset.verified ?? false) ? 1 : 0;
    const incomingMeta = safeJsonParse(asset.metadata ?? asset.metadata_json, {});

    const existing = this.db
      .prepare('SELECT * FROM assets WHERE asset_type = ? AND key = ?')
      .get(assetType, key);

    let assetId;
    if (existing) {
      assetId = existing.id;
      const mergedMeta = {
        ...safeJsonParse(existing.metadata_json, {}),
        ...incomingMeta,
      };
      this.db
        .prepare(
          `UPDATE assets
           SET company_id = COALESCE(?, company_id),
               host = COALESCE(?, host),
               ip = COALESCE(?, ip),
               port = COALESCE(?, port),
               protocol = COALESCE(?, protocol),
               service = COALESCE(?, service),
               url = COALESCE(?, url),
               path = COALESCE(?, path),
               title = COALESCE(?, title),
               status_code = COALESCE(?, status_code),
               c_segment = COALESCE(?, c_segment),
               source = COALESCE(?, source),
               confidence = COALESCE(?, confidence),
               verified = CASE WHEN ? = 1 THEN 1 ELSE verified END,
               parent_asset_id = COALESCE(?, parent_asset_id),
               metadata_json = ?,
               last_seen_at = ?
           WHERE id = ?`
        )
        .run(
          companyId,
          host,
          ip,
          port,
          protocol,
          service,
          url,
          pathVal,
          title,
          statusCode,
          cSegment,
          source,
          confidence,
          verified,
          parentAssetId,
          JSON.stringify(mergedMeta),
          asset.last_seen_at ?? now,
          assetId
        );
    } else {
      assetId = asset.id || `asset_${crypto.randomUUID()}`;
      const firstSeen = asset.first_seen_at ?? asset.firstSeenAt ?? now;
      const lastSeen = asset.last_seen_at ?? asset.lastSeenAt ?? firstSeen;
      this.db
        .prepare(
          `INSERT INTO assets (
            id, company_id, asset_type, key, host, ip, port, protocol, service,
            url, path, title, status_code, c_segment, source, confidence, verified,
            parent_asset_id, metadata_json, first_seen_at, last_seen_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          assetId,
          companyId,
          assetType,
          key,
          host,
          ip,
          port,
          protocol,
          service,
          url,
          pathVal,
          title,
          statusCode,
          cSegment,
          source,
          confidence,
          verified,
          parentAssetId,
          JSON.stringify(incomingMeta),
          firstSeen,
          lastSeen
        );
    }

    if (taskId) {
      this.db
        .prepare(
          `INSERT INTO task_asset_links (task_id, asset_id, relation, created_at)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(task_id, asset_id, relation) DO NOTHING`
        )
        .run(taskId, assetId, relation, now);
    }

    return this.getAsset(assetId);
  }

  getAsset(assetId) {
    if (!assetId) return null;
    const row = this.db.prepare('SELECT * FROM assets WHERE id = ?').get(assetId);
    return this._hydrateAsset(row);
  }

  /**
   * Port of ARTEX `declaredScopeFilter` in `db/task_scope.go`:
   * Filters `task_scope` rules so that `source === 'auto'` rows only count if they
   * fall under a declared (`source !== 'auto'`) domain or IP/CIDR root rule, and
   * evaluates block-first deny rules + allow-whitelist rules against assets.
   */
  declaredScopeFilter(taskId) {
    const scopeRules = taskId ? this.getTaskScope(taskId) : [];
    const constraints = taskId ? this.getTaskConstraints(taskId) : [];

    const declaredAllowRules = scopeRules.filter((r) => r.isAllowed && r.source !== 'auto');
    const autoAllowRules = scopeRules.filter((r) => r.isAllowed && r.source === 'auto');
    const denyRules = [
      ...scopeRules.filter((r) => !r.isAllowed),
      ...constraints
        .filter((c) => c.constraint_type === 'deny')
        .map((c) => ({ rule_type: c.rule_type, pattern: c.pattern, isAllowed: false, source: 'declared' })),
    ];
    const constraintAllows = constraints
      .filter((c) => c.constraint_type === 'allow')
      .map((c) => ({ rule_type: c.rule_type, pattern: c.pattern, isAllowed: true, source: 'declared' }));

    const allDeclaredRoots = [...declaredAllowRules, ...constraintAllows];

    // An auto rule is only kept if it falls under a declared root_domain/subdomain/domain or ip/cidr root
    const validAutoRules = autoAllowRules.filter((autoRule) => {
      return allDeclaredRoots.some((root) => {
        const rType = String(root.rule_type || '').toLowerCase();
        const aType = String(autoRule.rule_type || '').toLowerCase();
        if (['domain', 'root_domain', 'subdomain', 'fuzzy_domain'].includes(rType)) {
          if (['domain', 'root_domain', 'subdomain', 'fuzzy_domain', 'exact_domain'].includes(aType)) {
            return domainMatchesRoot(autoRule.pattern, root.pattern);
          }
        }
        if (['ip', 'exact_ip', 'cidr', 'c_segment'].includes(rType)) {
          if (['ip', 'exact_ip', 'cidr', 'c_segment'].includes(aType)) {
            return cidrContainsCidr(root.pattern, autoRule.pattern);
          }
        }
        return false;
      });
    });

    const effectiveAllowRules = [...allDeclaredRoots, ...validAutoRules];

    const matchesRule = (asset, rule) => {
      const ruleType = String(rule.rule_type || rule.ruleType || 'domain').toLowerCase();
      const pat = String(rule.pattern || '').trim();
      if (!pat) return false;
      const lowerPat = pat.toLowerCase();

      const assetHost = String(asset.host || (asset.asset_type === 'root_domain' || asset.asset_type === 'subdomain' ? asset.key : '') || '').toLowerCase();
      const assetIp = String(asset.ip || (asset.asset_type === 'ip' ? asset.key : '') || '').trim();
      const assetUrl = String(asset.url || '').toLowerCase();
      const assetKey = String(asset.key || '').toLowerCase();

      if (ruleType === 'root_domain' || ruleType === 'domain' || ruleType === 'fuzzy_domain') {
        return domainMatchesRoot(assetHost || assetKey, lowerPat);
      }
      if (ruleType === 'subdomain' || ruleType === 'exact_domain') {
        const cleanPat = lowerPat.startsWith('*.') ? lowerPat.slice(2) : lowerPat;
        if (lowerPat.startsWith('*.')) {
          return domainMatchesRoot(assetHost || assetKey, cleanPat);
        }
        return (assetHost || assetKey) === cleanPat;
      }
      if (ruleType === 'ip' || ruleType === 'exact_ip') {
        if (pat.includes('/')) {
          return ipMatchesCidr(assetIp, pat);
        }
        return assetIp.toLowerCase() === lowerPat || assetHost === lowerPat;
      }
      if (ruleType === 'cidr' || ruleType === 'c_segment') {
        if (asset.c_segment && String(asset.c_segment).toLowerCase() === lowerPat) {
          return true;
        }
        return ipMatchesCidr(assetIp, pat);
      }
      if (ruleType === 'company') {
        return String(asset.company_id || '').toLowerCase() === lowerPat;
      }
      if (ruleType === 'url' || ruleType === 'fuzzy_url' || ruleType === 'exact_url' || ruleType === 'path') {
        if (ruleType === 'exact_url') {
          return assetUrl === lowerPat || assetKey === lowerPat;
        }
        if (lowerPat.includes('*')) {
          return matchWildcardGlob(lowerPat, assetUrl || assetKey);
        }
        return assetUrl.startsWith(lowerPat) || assetUrl.includes(lowerPat) || String(asset.path || '').toLowerCase().startsWith(lowerPat);
      }
      return domainMatchesRoot(assetHost || assetKey, lowerPat) || assetKey.includes(lowerPat);
    };

    const matchesAsset = (asset) => {
      // 1. Block-first deny rules
      for (const deny of denyRules) {
        if (matchesRule(asset, deny)) {
          return false;
        }
      }
      // 2. If allow rules exist (or auto rules were declared without any valid root), enforce allow-whitelist
      if (effectiveAllowRules.length > 0) {
        return effectiveAllowRules.some((allow) => matchesRule(asset, allow));
      }
      // If task has only unanchored auto rules and no declared roots, nothing is in declared scope
      if (autoAllowRules.length > 0 && allDeclaredRoots.length === 0) {
        return false;
      }
      return true;
    };

    return {
      taskId,
      declaredAllowRules: allDeclaredRoots,
      validAutoRules,
      effectiveAllowRules,
      denyRules,
      hasScopeRules: scopeRules.length > 0 || constraints.length > 0,
      matchesAsset,
    };
  }

  queryAssets({ dsl = '', taskId = null, assetType = null, inScopeOnly = false, limit = 200, offset = 0 } = {}) {
    const compiled = compileAssetDsl(dsl);
    const clauses = [compiled.whereSql || '1=1'];
    const params = [...compiled.params];

    if (assetType) {
      clauses.push('LOWER(assets.asset_type) = LOWER(?)');
      params.push(String(assetType).trim());
    }

    // If taskId is provided and inScopeOnly is false, restrict to assets linked to taskId
    if (taskId && !inScopeOnly) {
      clauses.push('EXISTS (SELECT 1 FROM task_asset_links tal WHERE tal.asset_id = assets.id AND tal.task_id = ?)');
      params.push(taskId);
    }

    const sql = `SELECT assets.* FROM assets WHERE ${clauses.join(' AND ')} ORDER BY assets.last_seen_at DESC, assets.id ASC`;
    const allRows = this.db.prepare(sql).all(...params).map((r) => this._hydrateAsset(r));

    let filtered = allRows;
    if (inScopeOnly && taskId) {
      const scopeEval = this.declaredScopeFilter(taskId);
      if (scopeEval.hasScopeRules) {
        filtered = allRows.filter((a) => scopeEval.matchesAsset(a));
      } else {
        // Fallback when no scope rules exist yet: assets linked to taskId
        const linkedIds = new Set(
          this.db
            .prepare('SELECT asset_id FROM task_asset_links WHERE task_id = ?')
            .all(taskId)
            .map((r) => r.asset_id)
        );
        filtered = allRows.filter((a) => linkedIds.has(a.id));
      }
    }

    const safeOffset = Math.max(0, Number(offset) || 0);
    const safeLimit = Number(limit) > 0 ? Number(limit) : 200;
    const items = filtered.slice(safeOffset, safeOffset + safeLimit);

    return {
      items,
      total: filtered.length,
    };
  }

  getCoverageGraph({ taskId = null, companyId = null } = {}) {
    const clauses = ['1=1'];
    const params = [];
    if (companyId) {
      clauses.push('assets.company_id = ?');
      params.push(companyId);
    }
    if (taskId) {
      const hasLinks = this.db
        .prepare('SELECT 1 FROM task_asset_links WHERE task_id = ? LIMIT 1')
        .get(taskId);
      if (hasLinks) {
        clauses.push('EXISTS (SELECT 1 FROM task_asset_links tal WHERE tal.asset_id = assets.id AND tal.task_id = ?)');
        params.push(taskId);
      }
    }

    const assetRows = this.db
      .prepare(`SELECT assets.* FROM assets WHERE ${clauses.join(' AND ')} ORDER BY assets.first_seen_at ASC, assets.id ASC`)
      .all(...params)
      .map((r) => this._hydrateAsset(r));

    const scopeEval = taskId ? this.declaredScopeFilter(taskId) : null;

    // Pre-aggregate anchor counts and finding counts per asset
    const anchorQuery = taskId
      ? this.db
          .prepare(
            `SELECT ea.asset_id,
                    COUNT(DISTINCT ea.id) AS anchor_count,
                    SUM(CASE WHEN en.node_type = 'finding' THEN 1 ELSE 0 END) AS finding_count,
                    SUM(CASE WHEN en.node_type = 'fact' THEN 1 ELSE 0 END) AS fact_count,
                    SUM(CASE WHEN en.node_type = 'intent' THEN 1 ELSE 0 END) AS intent_count
             FROM exploration_anchors ea
             JOIN exploration_nodes en ON en.id = ea.node_id
             WHERE ea.task_id = ?
             GROUP BY ea.asset_id`
          )
          .all(taskId)
      : this.db
          .prepare(
            `SELECT ea.asset_id,
                    COUNT(DISTINCT ea.id) AS anchor_count,
                    SUM(CASE WHEN en.node_type = 'finding' THEN 1 ELSE 0 END) AS finding_count,
                    SUM(CASE WHEN en.node_type = 'fact' THEN 1 ELSE 0 END) AS fact_count,
                    SUM(CASE WHEN en.node_type = 'intent' THEN 1 ELSE 0 END) AS intent_count
             FROM exploration_anchors ea
             JOIN exploration_nodes en ON en.id = ea.node_id
             GROUP BY ea.asset_id`
          )
          .all();

    const countsByAsset = new Map();
    for (const row of anchorQuery) {
      countsByAsset.set(row.asset_id, {
        anchorCount: Number(row.anchor_count) || 0,
        findingCount: Number(row.finding_count) || 0,
        factCount: Number(row.fact_count) || 0,
        intentCount: Number(row.intent_count) || 0,
      });
    }

    const ledgerCoveredIds = new Set(
      (taskId
        ? this.db.prepare('SELECT DISTINCT asset_id FROM coverage_ledger WHERE task_id = ?').all(taskId)
        : this.db.prepare('SELECT DISTINCT asset_id FROM coverage_ledger').all()
      ).map((r) => r.asset_id)
    );

    const assetIdSet = new Set(assetRows.map((a) => a.id));
    const nodes = [];
    const edges = [];
    const byType = {};
    let totalFindings = 0;
    let totalAnchors = 0;
    let testedAssets = 0;

    for (const asset of assetRows) {
      const c = countsByAsset.get(asset.id) || {
        anchorCount: 0,
        findingCount: 0,
        factCount: 0,
        intentCount: 0,
      };
      const tested = c.anchorCount > 0 || ledgerCoveredIds.has(asset.id);
      const inScope = scopeEval ? scopeEval.matchesAsset(asset) : true;

      if (tested) testedAssets++;
      totalFindings += c.findingCount;
      totalAnchors += c.anchorCount;

      if (!byType[asset.asset_type]) {
        byType[asset.asset_type] = { total: 0, tested: 0, findings: 0 };
      }
      byType[asset.asset_type].total++;
      if (tested) byType[asset.asset_type].tested++;
      byType[asset.asset_type].findings += c.findingCount;

      nodes.push({
        ...asset,
        findingCount: c.findingCount,
        finding_count: c.findingCount,
        anchorCount: c.anchorCount,
        anchor_count: c.anchorCount,
        factCount: c.factCount,
        intentCount: c.intentCount,
        tested,
        inScope,
        in_scope: inScope,
      });

      if (asset.parent_asset_id && assetIdSet.has(asset.parent_asset_id)) {
        edges.push({
          id: `cov_edge_${asset.parent_asset_id}_${asset.id}`,
          from: asset.parent_asset_id,
          to: asset.id,
          fromAssetId: asset.parent_asset_id,
          toAssetId: asset.id,
          type: 'contains',
        });
      }
    }

    const totalAssets = nodes.length;
    const coveragePct = totalAssets > 0 ? Math.round((testedAssets / totalAssets) * 10000) / 100 : 0;

    return {
      nodes,
      edges,
      stats: {
        totalAssets,
        testedAssets,
        untestedAssets: totalAssets - testedAssets,
        totalFindings,
        totalAnchors,
        coveragePct,
        byType,
      },
    };
  }

  // ── Exploration Graph & Lease Fencing ──────────────────────────────────────

  addNode(node = {}) {
    const now = Date.now();
    const id = node.id || `node_${crypto.randomUUID()}`;
    const taskId = node.task_id || node.taskId;
    if (!taskId) {
      throw new Error('taskId is required for addNode');
    }
    const nodeType = String(node.node_type || node.nodeType || node.type || 'fact').toLowerCase();
    if (!VALID_NODE_TYPES.has(nodeType)) {
      throw new Error(`Invalid node_type "${nodeType}". Must be one of: ${Array.from(VALID_NODE_TYPES).join(', ')}`);
    }

    const defaultStatusMap = {
      begin: 'open',
      goal: 'open',
      intent: 'pending',
      fact: 'confirmed',
      finding: 'confirmed',
      hint: 'active',
      digest: 'active',
    };
    const status = node.status ?? defaultStatusMap[nodeType] ?? 'pending';
    const title = node.title ?? node.name ?? nodeType;
    const severity = node.severity ?? null;
    const poeLevel = node.poe_level ?? node.poeLevel ?? 0;
    const confidence = node.confidence !== undefined && node.confidence !== null ? Number(node.confidence) : 1.0;
    const summary = node.summary ?? '';
    const rawData = node.data ?? safeJsonParse(node.data_json, {});
    const dataJson = typeof rawData === 'string' ? rawData : JSON.stringify(rawData);
    const claimOwner = node.claim_owner ?? node.claimOwner ?? null;
    const unclaimToken = node.unclaim_token ?? node.unclaimToken ?? null;
    const claimExpiresAt = node.claim_expires_at ?? node.claimExpiresAt ?? null;
    const createdAt = node.created_at ?? node.createdAt ?? now;
    const updatedAt = node.updated_at ?? node.updatedAt ?? createdAt;

    this.db
      .prepare(
        `INSERT INTO exploration_nodes (
          id, task_id, node_type, title, status, severity, poe_level, confidence,
          summary, data_json, claim_owner, unclaim_token, claim_expires_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        id,
        taskId,
        nodeType,
        title,
        status,
        severity,
        poeLevel,
        confidence,
        summary,
        dataJson,
        claimOwner,
        unclaimToken,
        claimExpiresAt,
        createdAt,
        updatedAt
      );

    const assetIds = node.assetIds || node.asset_ids || (node.assetId || node.asset_id ? [node.assetId || node.asset_id] : []);
    for (const assetId of assetIds) {
      this.anchorNodeToAsset({ taskId, nodeId: id, assetId, relation: node.anchorRelation || 'targets' });
    }

    return this.getNode(id);
  }

  updateNode(nodeId, patch = {}) {
    const existing = this.getNode(nodeId);
    if (!existing) return null;

    const now = patch.updated_at ?? patch.updatedAt ?? Date.now();
    const title = patch.title !== undefined ? patch.title : existing.title;
    const status = patch.status !== undefined ? patch.status : existing.status;
    const severity = patch.severity !== undefined ? patch.severity : existing.severity;
    const poeLevel =
      patch.poe_level !== undefined
        ? patch.poe_level
        : patch.poeLevel !== undefined
          ? patch.poeLevel
          : existing.poe_level;
    const confidence = patch.confidence !== undefined ? Number(patch.confidence) : existing.confidence;
    const summary = patch.summary !== undefined ? patch.summary : existing.summary;

    let dataJson = existing.data_json;
    if (patch.data_json !== undefined) {
      dataJson = typeof patch.data_json === 'string' ? patch.data_json : JSON.stringify(patch.data_json);
    } else if (patch.data !== undefined) {
      dataJson = typeof patch.data === 'string' ? patch.data : JSON.stringify({ ...existing.data, ...patch.data });
    }

    const claimOwner =
      patch.claim_owner !== undefined
        ? patch.claim_owner
        : patch.claimOwner !== undefined
          ? patch.claimOwner
          : existing.claim_owner;
    const unclaimToken =
      patch.unclaim_token !== undefined
        ? patch.unclaim_token
        : patch.unclaimToken !== undefined
          ? patch.unclaimToken
          : existing.unclaim_token;
    const claimExpiresAt =
      patch.claim_expires_at !== undefined
        ? patch.claim_expires_at
        : patch.claimExpiresAt !== undefined
          ? patch.claimExpiresAt
          : existing.claim_expires_at;

    this.db
      .prepare(
        `UPDATE exploration_nodes
         SET title = ?, status = ?, severity = ?, poe_level = ?, confidence = ?,
             summary = ?, data_json = ?, claim_owner = ?, unclaim_token = ?,
             claim_expires_at = ?, updated_at = ?
         WHERE id = ?`
      )
      .run(
        title,
        status,
        severity,
        poeLevel,
        confidence,
        summary,
        dataJson,
        claimOwner,
        unclaimToken,
        claimExpiresAt,
        now,
        nodeId
      );

    return this.getNode(nodeId);
  }

  getNode(nodeId) {
    if (!nodeId) return null;
    const row = this.db.prepare('SELECT * FROM exploration_nodes WHERE id = ?').get(nodeId);
    return this._hydrateNode(row);
  }

  listNodes(taskId, filter = {}) {
    const clauses = ['task_id = ?'];
    const params = [taskId];

    const nodeType = filter.node_type ?? filter.nodeType ?? filter.type;
    if (nodeType) {
      if (Array.isArray(nodeType)) {
        clauses.push(`node_type IN (${nodeType.map(() => '?').join(', ')})`);
        params.push(...nodeType);
      } else {
        clauses.push('node_type = ?');
        params.push(nodeType);
      }
    }

    if (filter.status) {
      if (Array.isArray(filter.status)) {
        clauses.push(`status IN (${filter.status.map(() => '?').join(', ')})`);
        params.push(...filter.status);
      } else {
        clauses.push('status = ?');
        params.push(filter.status);
      }
    }

    if (filter.severity) {
      clauses.push('UPPER(severity) = UPPER(?)');
      params.push(filter.severity);
    }

    const rows = this.db
      .prepare(`SELECT * FROM exploration_nodes WHERE ${clauses.join(' AND ')} ORDER BY created_at ASC, id ASC`)
      .all(...params);
    return rows.map((r) => this._hydrateNode(r));
  }

  addEdge(edge = {}) {
    const now = Date.now();
    const id = edge.id || `edge_${crypto.randomUUID()}`;
    const fromNodeId = edge.from_node_id || edge.fromNodeId || edge.from || edge.src_id;
    const toNodeId = edge.to_node_id || edge.toNodeId || edge.to || edge.dst_id;
    if (!fromNodeId || !toNodeId) {
      throw new Error('fromNodeId and toNodeId are required for addEdge');
    }
    let taskId = edge.task_id || edge.taskId;
    if (!taskId) {
      const srcNode = this.getNode(fromNodeId);
      taskId = srcNode ? srcNode.task_id : null;
    }
    if (!taskId) {
      throw new Error('taskId is required for addEdge');
    }

    const edgeType = String(edge.edge_type || edge.edgeType || edge.type || edge.rel || 'spawns').toLowerCase();
    if (!VALID_EDGE_TYPES.has(edgeType)) {
      throw new Error(`Invalid edge_type "${edgeType}". Must be one of: ${Array.from(VALID_EDGE_TYPES).join(', ')}`);
    }
    const label = edge.label ?? null;
    const createdAt = edge.created_at ?? edge.createdAt ?? now;

    this.db
      .prepare(
        `INSERT INTO exploration_edges (id, task_id, from_node_id, to_node_id, edge_type, label, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .run(id, taskId, fromNodeId, toNodeId, edgeType, label, createdAt);

    const row = this.db.prepare('SELECT * FROM exploration_edges WHERE id = ?').get(id);
    return this._hydrateEdge(row);
  }

  listEdges(taskId) {
    const rows = this.db
      .prepare('SELECT * FROM exploration_edges WHERE task_id = ? ORDER BY created_at ASC, id ASC')
      .all(taskId);
    return rows.map((r) => this._hydrateEdge(r));
  }

  anchorNodeToAsset({ taskId, nodeId, assetId, relation = 'targets' } = {}) {
    if (!nodeId || !assetId) {
      throw new Error('nodeId and assetId are required for anchorNodeToAsset');
    }
    let resolvedTaskId = taskId;
    if (!resolvedTaskId) {
      const node = this.getNode(nodeId);
      resolvedTaskId = node ? node.task_id : null;
    }
    if (!resolvedTaskId) {
      throw new Error('taskId could not be resolved for anchorNodeToAsset');
    }

    const id = `anchor_${crypto.randomUUID()}`;
    const now = Date.now();
    this.db
      .prepare(
        `INSERT INTO exploration_anchors (id, task_id, node_id, asset_id, relation, created_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(task_id, node_id, asset_id, relation)
         DO UPDATE SET created_at = excluded.created_at`
      )
      .run(id, resolvedTaskId, nodeId, assetId, relation, now);

    const row = this.db
      .prepare(
        `SELECT * FROM exploration_anchors
         WHERE task_id = ? AND node_id = ? AND asset_id = ? AND relation = ?`
      )
      .get(resolvedTaskId, nodeId, assetId, relation);
    return this._hydrateAnchor(row);
  }

  getNodeAnchors(taskId, { nodeId = null, assetId = null } = {}) {
    const clauses = ['ea.task_id = ?'];
    const params = [taskId];
    if (nodeId) {
      clauses.push('ea.node_id = ?');
      params.push(nodeId);
    }
    if (assetId) {
      clauses.push('ea.asset_id = ?');
      params.push(assetId);
    }

    const rows = this.db
      .prepare(
        `SELECT ea.*, a.asset_type, a.key AS asset_key, a.host AS asset_host, a.url AS asset_url, a.ip AS asset_ip
         FROM exploration_anchors ea
         LEFT JOIN assets a ON a.id = ea.asset_id
         WHERE ${clauses.join(' AND ')}
         ORDER BY ea.created_at ASC, ea.id ASC`
      )
      .all(...params);

    return rows.map((r) => ({
      ...this._hydrateAnchor(r),
      assetType: r.asset_type,
      assetKey: r.asset_key,
      assetHost: r.asset_host,
      assetUrl: r.asset_url,
      assetIp: r.asset_ip,
    }));
  }

  getExplorationGraph(taskId) {
    return {
      task: this.getTask(taskId),
      nodes: this.listNodes(taskId),
      edges: this.listEdges(taskId),
      anchors: this.getNodeAnchors(taskId),
    };
  }

  /**
   * Trace ancestor chain (`begin -> goal -> intent -> fact -> finding`) and bound assets for a finding node.
   */
  getFindingLineage(taskId, findingNodeId) {
    const finding = this.getNode(findingNodeId);
    if (!finding || (taskId && finding.task_id !== taskId)) {
      return { finding: null, chain: [], nodes: [], edges: [], assets: [], anchors: [] };
    }
    const effectiveTaskId = taskId || finding.task_id;
    const allNodes = this.listNodes(effectiveTaskId);
    const allEdges = this.listEdges(effectiveTaskId);
    const nodeMap = new Map(allNodes.map((n) => [n.id, n]));

    // Build incoming edges map (to_node_id -> edges) and outgoing proving edges (finding --proves--> goal)
    const incomingByTarget = new Map();
    const provesGoals = new Set();
    for (const e of allEdges) {
      if (!incomingByTarget.has(e.to_node_id)) {
        incomingByTarget.set(e.to_node_id, []);
      }
      incomingByTarget.get(e.to_node_id).push(e);
      if (e.from_node_id === findingNodeId && e.edge_type === 'proves') {
        provesGoals.add(e.to_node_id);
      }
    }

    const visitedIds = new Set([findingNodeId, ...provesGoals]);
    const queue = [findingNodeId, ...provesGoals];
    const lineageEdges = [];
    const seenEdgeIds = new Set();

    while (queue.length > 0) {
      const currId = queue.shift();
      const inc = incomingByTarget.get(currId) || [];
      for (const edge of inc) {
        if (!seenEdgeIds.has(edge.id)) {
          seenEdgeIds.add(edge.id);
          lineageEdges.push(edge);
        }
        if (!visitedIds.has(edge.from_node_id) && nodeMap.has(edge.from_node_id)) {
          visitedIds.add(edge.from_node_id);
          queue.push(edge.from_node_id);
        }
      }
    }

    for (const e of allEdges) {
      if (e.from_node_id === findingNodeId && e.edge_type === 'proves' && !seenEdgeIds.has(e.id)) {
        seenEdgeIds.add(e.id);
        lineageEdges.push(e);
      }
    }

    const typeRank = {
      begin: 0,
      goal: 1,
      intent: 2,
      fact: 3,
      hint: 3,
      digest: 3,
      finding: 4,
    };

    const chain = Array.from(visitedIds)
      .map((id) => nodeMap.get(id))
      .filter(Boolean)
      .sort((a, b) => {
        const ra = typeRank[a.node_type] ?? 99;
        const rb = typeRank[b.node_type] ?? 99;
        if (ra !== rb) return ra - rb;
        return a.created_at - b.created_at;
      });

    const allAnchors = this.getNodeAnchors(effectiveTaskId);
    const lineageAnchors = allAnchors.filter((a) => visitedIds.has(a.node_id));
    const assetIds = Array.from(new Set(lineageAnchors.map((a) => a.asset_id)));
    const assets = assetIds.map((aid) => this.getAsset(aid)).filter(Boolean);

    return {
      finding,
      chain,
      nodes: chain,
      edges: lineageEdges,
      assets,
      anchors: lineageAnchors,
    };
  }

  /**
   * Atomic Intent Lease Fencing (15s heartbeat / 90s expiry)
   */
  claimIntentToken(nodeId, owner, { ttlMs = 90000, now = Date.now() } = {}) {
    if (!nodeId || !owner) {
      throw new Error('nodeId and owner are required for claimIntentToken');
    }
    return this._inTransaction(() => {
      const unclaimToken = crypto.randomBytes(16).toString('hex');
      const expiresAt = now + ttlMs;

      const result = this.db
        .prepare(
          `UPDATE exploration_nodes
           SET status = 'running',
               claim_owner = ?,
               unclaim_token = ?,
               claim_expires_at = ?,
               updated_at = ?
           WHERE id = ?
             AND node_type = 'intent'
             AND (
               status IN ('pending', 'open')
               OR (status = 'running' AND claim_expires_at IS NOT NULL AND claim_expires_at <= ?)
             )`
        )
        .run(owner, unclaimToken, expiresAt, now, nodeId, now);

      const node = this.getNode(nodeId);
      if (result.changes === 0) {
        return {
          claimed: false,
          unclaimToken: null,
          node,
        };
      }

      return {
        claimed: true,
        unclaimToken,
        node,
      };
    });
  }

  heartbeatIntentClaim(nodeId, unclaimToken, { ttlMs = 90000, now = Date.now() } = {}) {
    if (!nodeId || !unclaimToken) return false;
    const expiresAt = now + ttlMs;
    const res = this.db
      .prepare(
        `UPDATE exploration_nodes
         SET claim_expires_at = ?, updated_at = ?
         WHERE id = ?
           AND node_type = 'intent'
           AND status = 'running'
           AND unclaim_token = ?`
      )
      .run(expiresAt, now, nodeId, unclaimToken);
    return res.changes > 0;
  }

  settleIntentClaim(nodeId, unclaimToken, { status = 'completed', summary, data, now = Date.now() } = {}) {
    if (!nodeId || !unclaimToken) return false;
    return this._inTransaction(() => {
      const current = this.db
        .prepare(
          `SELECT * FROM exploration_nodes
           WHERE id = ? AND node_type = 'intent' AND status = 'running' AND unclaim_token = ?`
        )
        .get(nodeId, unclaimToken);

      if (!current) {
        return false;
      }

      const nextSummary = summary !== undefined ? summary : current.summary;
      let nextDataJson = current.data_json;
      if (data !== undefined) {
        nextDataJson =
          typeof data === 'string'
            ? data
            : JSON.stringify({ ...safeJsonParse(current.data_json, {}), ...data });
      }

      const res = this.db
        .prepare(
          `UPDATE exploration_nodes
           SET status = ?,
               summary = ?,
               data_json = ?,
               claim_expires_at = NULL,
               updated_at = ?
           WHERE id = ? AND unclaim_token = ?`
        )
        .run(status, nextSummary, nextDataJson, now, nodeId, unclaimToken);

      return res.changes > 0;
    });
  }

  resetExpiredIntents(taskId = null, { now = Date.now() } = {}) {
    return this._inTransaction(() => {
      const rows = taskId
        ? this.db
            .prepare(
              `SELECT id FROM exploration_nodes
               WHERE task_id = ?
                 AND node_type = 'intent'
                 AND status = 'running'
                 AND claim_expires_at IS NOT NULL
                 AND claim_expires_at <= ?`
            )
            .all(taskId, now)
        : this.db
            .prepare(
              `SELECT id FROM exploration_nodes
               WHERE node_type = 'intent'
                 AND status = 'running'
                 AND claim_expires_at IS NOT NULL
                 AND claim_expires_at <= ?`
            )
            .all(now);

      const updateStmt = this.db.prepare(
        `UPDATE exploration_nodes
         SET status = 'pending',
             claim_owner = NULL,
             unclaim_token = ?,
             claim_expires_at = NULL,
             updated_at = ?
         WHERE id = ?`
      );

      for (const r of rows) {
        const rotatedToken = crypto.randomBytes(16).toString('hex');
        updateStmt.run(rotatedToken, now, r.id);
      }

      return rows.length;
    });
  }

  /**
   * Exclusive Cascade Delete (port of ARTEX `CancelIntent` in `db/exploration.go`).
   * Cancels/removes `intentNodeId` and cascades deletion ONLY to descendant nodes
   * exclusively reachable from `intentNodeId` (preserving shared facts/findings
   * reachable from other intents or protected begin/goal nodes).
   */
  cancelIntent(taskId, intentNodeId) {
    return this._inTransaction(() => {
      const targetIntent = this.getNode(intentNodeId);
      if (!targetIntent || (taskId && targetIntent.task_id !== taskId)) {
        return { cancelled: false, deletedNodeIds: [], deletedCount: 0 };
      }
      const effectiveTaskId = taskId || targetIntent.task_id;

      const allNodes = this.listNodes(effectiveTaskId);
      const allEdges = this.listEdges(effectiveTaskId);

      const protectedIds = new Set();
      for (const n of allNodes) {
        if (n.node_type === 'begin' || n.node_type === 'goal' || (n.node_type === 'fact' && n.status === 'origin')) {
          protectedIds.add(n.id);
        }
      }

      // parentsOf: dst -> Set of all incoming src nodes
      // downOf: src -> Set of downward dst nodes along spawns / derived_from / yields
      const parentsOf = new Map();
      const downOf = new Map();

      for (const e of allEdges) {
        if (!parentsOf.has(e.to_node_id)) {
          parentsOf.set(e.to_node_id, new Set());
        }
        parentsOf.get(e.to_node_id).add(e.from_node_id);

        if (e.edge_type === 'spawns' || e.edge_type === 'derived_from' || e.edge_type === 'yields') {
          if (!downOf.has(e.from_node_id)) {
            downOf.set(e.from_node_id, new Set());
          }
          downOf.get(e.from_node_id).add(e.to_node_id);
        }
      }

      const del = new Set([intentNodeId]);
      let changed = true;
      while (changed) {
        changed = false;
        for (const srcId of Array.from(del)) {
          const children = downOf.get(srcId);
          if (!children) continue;
          for (const dstId of children) {
            if (del.has(dstId) || protectedIds.has(dstId)) continue;
            const parents = parentsOf.get(dstId) || new Set();
            let exclusive = parents.size > 0;
            for (const pId of parents) {
              if (!del.has(pId)) {
                exclusive = false;
                break;
              }
            }
            if (exclusive) {
              del.add(dstId);
              changed = true;
            }
          }
        }
      }

      const deletedNodeIds = Array.from(del);
      const placeholders = deletedNodeIds.map(() => '?').join(', ');

      this.db
        .prepare(
          `DELETE FROM exploration_edges
           WHERE task_id = ?
             AND (from_node_id IN (${placeholders}) OR to_node_id IN (${placeholders}))`
        )
        .run(effectiveTaskId, ...deletedNodeIds, ...deletedNodeIds);

      this.db
        .prepare(`DELETE FROM exploration_anchors WHERE task_id = ? AND node_id IN (${placeholders})`)
        .run(effectiveTaskId, ...deletedNodeIds);

      this.db
        .prepare(`DELETE FROM exploration_nodes WHERE task_id = ? AND id IN (${placeholders})`)
        .run(effectiveTaskId, ...deletedNodeIds);

      return {
        cancelled: true,
        deletedNodeIds,
        deletedCount: deletedNodeIds.length,
      };
    });
  }

  // ── Coverage Ledger, Activity & RSI Lessons ────────────────────────────────

  recordCoverage({ taskId, assetId, checkCategory, intentNodeId = null, status = 'tested', notes = '' } = {}) {
    if (!taskId || !assetId || !checkCategory) {
      throw new Error('taskId, assetId, and checkCategory are required for recordCoverage');
    }
    const now = Date.now();
    const id = `cov_${crypto.randomUUID()}`;
    const normCategory = String(checkCategory).trim().toLowerCase();

    this.db
      .prepare(
        `INSERT INTO coverage_ledger (id, task_id, asset_id, check_category, intent_node_id, status, notes, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(task_id, asset_id, check_category)
         DO UPDATE SET
           intent_node_id = COALESCE(excluded.intent_node_id, coverage_ledger.intent_node_id),
           status = excluded.status,
           notes = excluded.notes,
           updated_at = excluded.updated_at`
      )
      .run(id, taskId, assetId, normCategory, intentNodeId, status, notes, now);

    const row = this.db
      .prepare('SELECT * FROM coverage_ledger WHERE task_id = ? AND asset_id = ? AND check_category = ?')
      .get(taskId, assetId, normCategory);

    return {
      ...row,
      taskId: row.task_id,
      assetId: row.asset_id,
      checkCategory: row.check_category,
      intentNodeId: row.intent_node_id,
      updatedAt: row.updated_at,
    };
  }

  buildCoverageLedger(taskId, { requiredCategories = ['recon', 'auth', 'injection', 'config', 'exposure'] } = {}) {
    const entries = this.db
      .prepare('SELECT * FROM coverage_ledger WHERE task_id = ? ORDER BY asset_id ASC, check_category ASC')
      .all(taskId)
      .map((r) => ({
        ...r,
        taskId: r.task_id,
        assetId: r.asset_id,
        checkCategory: r.check_category,
        intentNodeId: r.intent_node_id,
        updatedAt: r.updated_at,
      }));

    const inScopeAssets = this.queryAssets({ taskId, inScopeOnly: true, limit: 10000 }).items;
    const entryMap = new Map();
    for (const e of entries) {
      entryMap.set(`${e.asset_id}::${String(e.check_category).toLowerCase()}`, e);
    }

    const completedStatuses = new Set([
      'tested',
      'completed',
      'verified',
      'reported',
      'no_issue_found',
      'ruled_out',
      'not_applicable',
      'pass',
      'safe',
      'done',
    ]);

    const gaps = [];
    const normRequired = requiredCategories.map((c) => String(c).trim().toLowerCase());

    for (const asset of inScopeAssets) {
      for (const category of normRequired) {
        const entry = entryMap.get(`${asset.id}::${category}`);
        if (!entry || !completedStatuses.has(String(entry.status).toLowerCase())) {
          gaps.push({
            taskId,
            assetId: asset.id,
            assetKey: asset.key,
            assetType: asset.asset_type,
            checkCategory: category,
            status: entry ? entry.status : 'missing',
            reason: entry ? `Category "${category}" has incomplete status "${entry.status}"` : `Missing verification coverage for "${category}"`,
          });
        }
      }
    }

    const totalRequired = inScopeAssets.length * normRequired.length;
    const coveredCount = Math.max(0, totalRequired - gaps.length);
    const coveragePct =
      totalRequired > 0 ? Math.round((coveredCount / totalRequired) * 10000) / 100 : 100;

    return {
      entries,
      gaps,
      coveragePct,
      totalAssets: inScopeAssets.length,
      totalRequired,
      coveredCount,
      requiredCategories: normRequired,
    };
  }

  appendActivity(taskId, event = {}) {
    if (!taskId) throw new Error('taskId is required for appendActivity');
    const now = event.created_at ?? event.createdAt ?? Date.now();
    const actor = event.actor ?? 'system';
    const eventType = event.event_type ?? event.eventType ?? event.type ?? 'info';
    const nodeId = event.node_id ?? event.nodeId ?? null;
    const summary = event.summary ?? event.message ?? '';
    const rawPayload = event.payload ?? safeJsonParse(event.payload_json, {});
    const payloadJson = typeof rawPayload === 'string' ? rawPayload : JSON.stringify(rawPayload);

    const res = this.db
      .prepare(
        `INSERT INTO activity (task_id, actor, event_type, node_id, summary, payload_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .run(taskId, actor, eventType, nodeId, summary, payloadJson, now);

    const row = this.db.prepare('SELECT * FROM activity WHERE seq = ?').get(res.lastInsertRowid);
    return {
      ...row,
      taskId: row.task_id,
      eventType: row.event_type,
      nodeId: row.node_id,
      payload: safeJsonParse(row.payload_json, {}),
      createdAt: row.created_at,
    };
  }

  listActivity(taskId, { sinceSeq = 0, limit = 200 } = {}) {
    const safeLimit = Number(limit) > 0 ? Number(limit) : 200;
    const rows = this.db
      .prepare(
        `SELECT * FROM activity
         WHERE task_id = ? AND seq > ?
         ORDER BY seq ASC
         LIMIT ?`
      )
      .all(taskId, Number(sinceSeq) || 0, safeLimit);

    return rows.map((r) => ({
      ...r,
      taskId: r.task_id,
      eventType: r.event_type,
      nodeId: r.node_id,
      payload: safeJsonParse(r.payload_json, {}),
      createdAt: r.created_at,
    }));
  }

  recordLesson({ category, title, lesson, evidenceNodeId = null, verified = false } = {}) {
    if (!category || !title || !lesson) {
      throw new Error('category, title, and lesson are required for recordLesson');
    }
    const normCategory = String(category).trim();
    const normTitle = String(title).trim();
    const normLesson = String(lesson).trim();
    const fingerprint = crypto
      .createHash('sha256')
      .update(`${normCategory.toLowerCase()}||${normTitle.toLowerCase()}||${normLesson.toLowerCase()}`)
      .digest('hex');

    const hasEvidence = Boolean(evidenceNodeId && String(evidenceNodeId).trim() !== '');
    const effectiveVerified = Boolean(verified) && hasEvidence ? 1 : 0;
    const now = Date.now();

    const existing = this.db
      .prepare('SELECT * FROM rsi_lessons WHERE fingerprint_sha256 = ?')
      .get(fingerprint);

    if (existing) {
      const nextVerified = existing.verified === 1 || effectiveVerified === 1 ? 1 : 0;
      const nextEvidenceId = hasEvidence ? String(evidenceNodeId).trim() : existing.evidence_node_id;
      this.db
        .prepare(
          `UPDATE rsi_lessons
           SET hit_count = hit_count + 1,
               evidence_node_id = ?,
               verified = ?
           WHERE id = ?`
        )
        .run(nextEvidenceId, nextVerified, existing.id);
    } else {
      const id = `lesson_${crypto.randomUUID()}`;
      this.db
        .prepare(
          `INSERT INTO rsi_lessons (
            id, fingerprint_sha256, category, title, lesson, evidence_node_id, verified, hit_count, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)`
        )
        .run(
          id,
          fingerprint,
          normCategory,
          normTitle,
          normLesson,
          hasEvidence ? String(evidenceNodeId).trim() : null,
          effectiveVerified,
          now
        );
    }

    const row = this.db
      .prepare('SELECT * FROM rsi_lessons WHERE fingerprint_sha256 = ?')
      .get(fingerprint);

    return {
      ...row,
      fingerprintSha256: row.fingerprint_sha256,
      evidenceNodeId: row.evidence_node_id,
      verified: Boolean(row.verified),
      hitCount: row.hit_count,
      createdAt: row.created_at,
    };
  }

  listVerifiedLessons({ category = null, limit = 100 } = {}) {
    const clauses = ["verified = 1", "evidence_node_id IS NOT NULL", "evidence_node_id != ''"];
    const params = [];
    if (category) {
      clauses.push('LOWER(category) = LOWER(?)');
      params.push(String(category).trim());
    }
    params.push(Number(limit) > 0 ? Number(limit) : 100);

    const rows = this.db
      .prepare(
        `SELECT * FROM rsi_lessons
         WHERE ${clauses.join(' AND ')}
         ORDER BY hit_count DESC, created_at DESC
         LIMIT ?`
      )
      .all(...params);

    return rows.map((row) => ({
      ...row,
      fingerprintSha256: row.fingerprint_sha256,
      evidenceNodeId: row.evidence_node_id,
      verified: Boolean(row.verified),
      hitCount: row.hit_count,
      createdAt: row.created_at,
    }));
  }

  // ── Snapshot & Static Scan Ingestion ───────────────────────────────────────

  ingestStaticScanResult(scanReport = {}) {
    return this._inTransaction(() => {
      const targets = Array.isArray(scanReport.targets)
        ? scanReport.targets
        : scanReport.target
          ? [scanReport.target]
          : ['https://example.com'];
      const primaryTarget = targets[0] || 'https://example.com';
      const taskTitle = scanReport.title || `Static Scan: ${primaryTarget}`;
      const taskGoal = scanReport.goal || `Static verification scan of ${primaryTarget}`;
      const allowPrivate = Boolean(scanReport.allow_private ?? scanReport.allowPrivate ?? false);

      let task = scanReport.taskId ? this.getTask(scanReport.taskId) : null;
      if (task) {
        this.db.prepare('DELETE FROM exploration_anchors WHERE task_id = ?').run(task.id);
        this.db.prepare('DELETE FROM exploration_edges WHERE task_id = ?').run(task.id);
        this.db.prepare('DELETE FROM exploration_nodes WHERE task_id = ?').run(task.id);
        this.db.prepare('DELETE FROM coverage_ledger WHERE task_id = ?').run(task.id);
        this.db.prepare('DELETE FROM task_asset_links WHERE task_id = ?').run(task.id);
        this.db.prepare('DELETE FROM task_scope WHERE task_id = ?').run(task.id);
        task = this.updateTask(task.id, {
          title: taskTitle,
          target: primaryTarget,
          goal: taskGoal,
          status: 'completed',
          mode: 'static',
          allow_private: allowPrivate,
        });
      } else {
        task = this.createTask({
          id: scanReport.taskId,
          title: taskTitle,
          target: primaryTarget,
          goal: taskGoal,
          status: 'completed',
          mode: 'static',
          allow_private: allowPrivate,
        });
      }

      const scopeRules = [];
      const upsertedAssets = [];
      const targetAssetByUrl = new Map();

      for (const t of targets) {
        const parsed = parseUrlComponents(t);
        const host = parsed ? parsed.host : String(t).trim().toLowerCase();
        const rootDomain = extractRootDomain(host);
        if (rootDomain) {
          scopeRules.push({ rule_type: 'root_domain', pattern: rootDomain, is_allowed: true, source: 'declared' });
        } else if (host) {
          scopeRules.push({ rule_type: isIP(host) ? 'ip' : 'domain', pattern: host, is_allowed: true, source: 'declared' });
        }

        const stackInfo =
          (scanReport.stacks && scanReport.stacks[t]) ||
          scanReport.fingerprint ||
          {};
        const targetAsset = this.upsertAsset(
          {
            asset_type: parsed && parsed.path && parsed.path !== '/' ? 'endpoint' : 'service',
            url: parsed ? parsed.url : t,
            host,
            port: parsed ? parsed.port : null,
            protocol: parsed ? parsed.protocol : null,
            service: parsed ? parsed.service : 'http',
            path: parsed ? parsed.path : '/',
            source: 'static_scan',
            metadata: { fingerprint: stackInfo, risk: scanReport.risk || null },
          },
          { taskId: task.id }
        );
        upsertedAssets.push(targetAsset);
        targetAssetByUrl.set(t, targetAsset);
        if (parsed?.url) targetAssetByUrl.set(parsed.url, targetAsset);
      }

      if (scopeRules.length > 0) {
        this.setTaskScope(task.id, scopeRules);
      }

      const primaryAsset = upsertedAssets[0];

      const beginNode = this.addNode({
        taskId: task.id,
        nodeType: 'begin',
        title: 'Scan Start',
        status: 'open',
        summary: `Initialized static scan for ${primaryTarget}`,
      });

      const goalNode = this.addNode({
        taskId: task.id,
        nodeType: 'goal',
        title: task.goal,
        status: 'met',
        summary: `Complete static security checks on ${primaryTarget}`,
      });
      this.addEdge({ taskId: task.id, fromNodeId: beginNode.id, toNodeId: goalNode.id, edgeType: 'spawns' });

      const intentNode = this.addNode({
        taskId: task.id,
        nodeType: 'intent',
        title: 'Execute Static Check Suite',
        status: 'completed',
        summary: `Run static verification checks against ${targets.join(', ')}`,
        assetIds: primaryAsset ? [primaryAsset.id] : [],
      });
      this.addEdge({ taskId: task.id, fromNodeId: goalNode.id, toNodeId: intentNode.id, edgeType: 'spawns' });

      const recordedCoverageStatus = new Map();
      const recordStaticCoverage = (assetId, checkCategory, status, notes) => {
        const key = `${assetId}::${String(checkCategory).toLowerCase()}`;
        const prev = recordedCoverageStatus.get(key);
        if (prev === 'tested' && status === 'error') {
          return;
        }
        recordedCoverageStatus.set(key, status);
        this.recordCoverage({
          taskId: task.id,
          assetId,
          checkCategory,
          intentNodeId: intentNode.id,
          status,
          notes,
        });
      };

      if (scanReport.fingerprint || scanReport.stacks) {
        const fpData = scanReport.fingerprint || scanReport.stacks;
        const fpNode = this.addNode({
          taskId: task.id,
          nodeType: 'fact',
          title: 'Technology Stack Fingerprint',
          status: 'confirmed',
          summary: fpData.summary || 'Detected target stack and headers',
          data: fpData,
          assetIds: primaryAsset ? [primaryAsset.id] : [],
        });
        this.addEdge({ taskId: task.id, fromNodeId: intentNode.id, toNodeId: fpNode.id, edgeType: 'yields' });
        if (primaryAsset) {
          recordStaticCoverage(primaryAsset.id, 'recon', 'tested', 'Technology stack fingerprinting complete');
        }
      }

      const results = Array.isArray(scanReport.results)
        ? scanReport.results
        : Array.isArray(scanReport.findings)
          ? scanReport.findings
          : [];

      const endpointAssetCache = new Map();
      const createdFindings = [];
      let safeCount = 0;
      let errorCount = 0;

      for (const res of results) {
        const targetUrl = res.target || primaryTarget;
        const checkName = res.name || res.checkId || 'security-check';
        const category = inferCheckCategory(checkName, res.meta);
        const statusUpper = String(res.status || 'VULNERABLE').toUpperCase();
        const isActionable = statusUpper === 'VULNERABLE' || statusUpper === 'SUSPICIOUS';

        let endpointAsset = null;
        if (!res.path && !isActionable && targetAssetByUrl.has(targetUrl)) {
          endpointAsset = targetAssetByUrl.get(targetUrl);
        } else {
          const epCacheKey = `${targetUrl}::${res.path || ''}`;
          if (endpointAssetCache.has(epCacheKey)) {
            endpointAsset = endpointAssetCache.get(epCacheKey);
          } else {
            endpointAsset = this.upsertAsset(
              {
                asset_type: 'endpoint',
                url: targetUrl,
                path: res.path || undefined,
                source: 'static_scan',
              },
              { taskId: task.id }
            );
            endpointAssetCache.set(epCacheKey, endpointAsset);
          }
        }

        recordStaticCoverage(
          endpointAsset.id,
          category,
          statusUpper === 'ERROR' ? 'error' : 'tested',
          `Executed ${checkName} (${statusUpper})`
        );

        if (isActionable) {
          const factNode = this.addNode({
            taskId: task.id,
            nodeType: 'fact',
            title: `Observation: ${checkName}`,
            status: 'confirmed',
            summary: res.reason || res.detail || `${checkName} triggered on ${targetUrl}`,
            data: { checkId: res.checkId, target: targetUrl, path: res.path },
            assetIds: [endpointAsset.id],
          });
          this.addEdge({ taskId: task.id, fromNodeId: intentNode.id, toNodeId: factNode.id, edgeType: 'yields' });

          const findingNode = this.addNode({
            taskId: task.id,
            nodeType: 'finding',
            title: checkName,
            status: 'confirmed',
            severity: res.severity || (statusUpper === 'VULNERABLE' ? 'HIGH' : 'MEDIUM'),
            poeLevel: statusUpper === 'VULNERABLE' ? 3 : 2,
            confidence: statusUpper === 'VULNERABLE' ? 0.95 : 0.7,
            summary: res.reason || res.detail || `${checkName} (${statusUpper})`,
            data: res,
            assetIds: [endpointAsset.id],
          });
          this.addEdge({ taskId: task.id, fromNodeId: factNode.id, toNodeId: findingNode.id, edgeType: 'yields' });
          this.addEdge({ taskId: task.id, fromNodeId: findingNode.id, toNodeId: goalNode.id, edgeType: 'proves' });
          createdFindings.push(findingNode);
        } else if (statusUpper === 'ERROR') {
          errorCount += 1;
        } else {
          safeCount += 1;
        }
      }

      if (results.length > 0 && createdFindings.length === 0) {
        const summaryFact = this.addNode({
          taskId: task.id,
          nodeType: 'fact',
          title: `Static Checks Summary: ${safeCount} passed, ${errorCount} errored`,
          status: 'confirmed',
          summary: `Completed ${results.length} static checks with 0 findings (${safeCount} safe, ${errorCount} errored)`,
          data: { totalResults: results.length, findings: 0, safeCount, errorCount },
          assetIds: primaryAsset ? [primaryAsset.id] : [],
        });
        this.addEdge({ taskId: task.id, fromNodeId: intentNode.id, toNodeId: summaryFact.id, edgeType: 'yields' });
      }

      this.updateNode(intentNode.id, {
        data: {
          totalResults: results.length,
          findings: createdFindings.length,
          safeCount,
          errorCount,
        },
      });

      this.appendActivity(task.id, {
        actor: 'scanner',
        eventType: 'static_scan_ingested',
        nodeId: intentNode.id,
        summary: `Ingested static scan for ${primaryTarget} (${createdFindings.length} findings)`,
        payload: {
          risk: scanReport.risk || null,
          totalResults: results.length,
          findings: createdFindings.length,
          safeCount,
          errorCount,
        },
      });

      return {
        taskId: task.id,
        task,
        findings: createdFindings,
        ...this.getExplorationGraph(task.id),
      };
    });
  }

  exportSnapshot(taskId = null) {
    const tasks = taskId
      ? this.db.prepare('SELECT * FROM tasks WHERE id = ?').all(taskId)
      : this.db.prepare('SELECT * FROM tasks').all();
    const explorations = taskId
      ? this.db.prepare('SELECT * FROM explorations WHERE task_id = ?').all(taskId)
      : this.db.prepare('SELECT * FROM explorations').all();
    const explorationNodes = taskId
      ? this.db.prepare('SELECT * FROM exploration_nodes WHERE task_id = ?').all(taskId)
      : this.db.prepare('SELECT * FROM exploration_nodes').all();
    const explorationEdges = taskId
      ? this.db.prepare('SELECT * FROM exploration_edges WHERE task_id = ?').all(taskId)
      : this.db.prepare('SELECT * FROM exploration_edges').all();
    const explorationAnchors = taskId
      ? this.db.prepare('SELECT * FROM exploration_anchors WHERE task_id = ?').all(taskId)
      : this.db.prepare('SELECT * FROM exploration_anchors').all();
    const taskConstraints = taskId
      ? this.db.prepare('SELECT * FROM task_constraints WHERE task_id = ?').all(taskId)
      : this.db.prepare('SELECT * FROM task_constraints').all();
    const taskScope = taskId
      ? this.db.prepare('SELECT * FROM task_scope WHERE task_id = ?').all(taskId)
      : this.db.prepare('SELECT * FROM task_scope').all();
    const taskAssetLinks = taskId
      ? this.db.prepare('SELECT * FROM task_asset_links WHERE task_id = ?').all(taskId)
      : this.db.prepare('SELECT * FROM task_asset_links').all();
    const assets = taskId
      ? this.db
          .prepare(
            `SELECT * FROM assets
             WHERE id IN (SELECT asset_id FROM task_asset_links WHERE task_id = ?)
                OR id IN (SELECT asset_id FROM exploration_anchors WHERE task_id = ?)`
          )
          .all(taskId, taskId)
      : this.db.prepare('SELECT * FROM assets').all();
    const activity = taskId
      ? this.db.prepare('SELECT * FROM activity WHERE task_id = ? ORDER BY seq ASC').all(taskId)
      : this.db.prepare('SELECT * FROM activity ORDER BY seq ASC').all();
    const coverageLedger = taskId
      ? this.db.prepare('SELECT * FROM coverage_ledger WHERE task_id = ?').all(taskId)
      : this.db.prepare('SELECT * FROM coverage_ledger').all();
    const companies = this.db.prepare('SELECT * FROM companies').all();
    const companyScope = this.db.prepare('SELECT * FROM company_scope').all();
    const rsiLessons = this.db.prepare('SELECT * FROM rsi_lessons').all();

    return {
      version: 1,
      exportedAt: Date.now(),
      taskId,
      companies,
      companyScope,
      assets,
      taskAssetLinks,
      taskScope,
      tasks,
      explorations,
      explorationNodes,
      explorationEdges,
      explorationAnchors,
      taskConstraints,
      activity,
      coverageLedger,
      rsiLessons,
    };
  }

  importSnapshot(snapshot = {}) {
    return this._inTransaction(() => {
      const insertCompany = this.db.prepare(
        'INSERT OR REPLACE INTO companies (id, name, created_at) VALUES (?, ?, ?)'
      );
      for (const c of snapshot.companies || []) {
        insertCompany.run(c.id, c.name, c.created_at);
      }

      const insertCompanyScope = this.db.prepare(
        'INSERT OR REPLACE INTO company_scope (id, company_id, rule_type, pattern, is_allowed, created_at) VALUES (?, ?, ?, ?, ?, ?)'
      );
      for (const cs of snapshot.companyScope || []) {
        insertCompanyScope.run(cs.id, cs.company_id, cs.rule_type, cs.pattern, cs.is_allowed, cs.created_at);
      }

      const insertAsset = this.db.prepare(
        `INSERT OR REPLACE INTO assets (
          id, company_id, asset_type, key, host, ip, port, protocol, service,
          url, path, title, status_code, c_segment, source, confidence, verified,
          parent_asset_id, metadata_json, first_seen_at, last_seen_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      );
      for (const a of snapshot.assets || []) {
        insertAsset.run(
          a.id,
          a.company_id ?? null,
          a.asset_type,
          a.key,
          a.host ?? null,
          a.ip ?? null,
          a.port ?? null,
          a.protocol ?? null,
          a.service ?? null,
          a.url ?? null,
          a.path ?? null,
          a.title ?? null,
          a.status_code ?? null,
          a.c_segment ?? null,
          a.source ?? null,
          a.confidence ?? 1.0,
          a.verified ? 1 : 0,
          a.parent_asset_id ?? null,
          a.metadata_json ?? '{}',
          a.first_seen_at ?? Date.now(),
          a.last_seen_at ?? Date.now()
        );
      }

      const insertTask = this.db.prepare(
        `INSERT OR REPLACE INTO tasks (
          id, title, target, goal, status, mode, noise_profile,
          llm_profile_ids_json, llm_rotate, allow_private, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      );
      for (const t of snapshot.tasks || []) {
        insertTask.run(
          t.id,
          t.title,
          t.target,
          t.goal,
          t.status,
          t.mode,
          t.noise_profile,
          t.llm_profile_ids_json ?? '[]',
          t.llm_rotate ? 1 : 0,
          (t.allow_private ?? t.allowPrivate ?? 0) ? 1 : 0,
          t.created_at,
          t.updated_at
        );
      }

      const insertLink = this.db.prepare(
        'INSERT OR REPLACE INTO task_asset_links (task_id, asset_id, relation, created_at) VALUES (?, ?, ?, ?)'
      );
      for (const l of snapshot.taskAssetLinks || []) {
        insertLink.run(l.task_id, l.asset_id, l.relation, l.created_at);
      }

      const insertScope = this.db.prepare(
        'INSERT OR REPLACE INTO task_scope (id, task_id, rule_type, pattern, is_allowed, source, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
      );
      for (const s of snapshot.taskScope || []) {
        insertScope.run(s.id, s.task_id, s.rule_type, s.pattern, s.is_allowed, s.source || 'declared', s.created_at);
      }

      const insertExp = this.db.prepare(
        'INSERT OR REPLACE INTO explorations (id, task_id, round_no, status, summary, created_at) VALUES (?, ?, ?, ?, ?, ?)'
      );
      for (const e of snapshot.explorations || []) {
        insertExp.run(e.id, e.task_id, e.round_no, e.status, e.summary, e.created_at);
      }

      const insertNode = this.db.prepare(
        `INSERT OR REPLACE INTO exploration_nodes (
          id, task_id, node_type, title, status, severity, poe_level, confidence,
          summary, data_json, claim_owner, unclaim_token, claim_expires_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      );
      for (const n of snapshot.explorationNodes || []) {
        insertNode.run(
          n.id,
          n.task_id,
          n.node_type,
          n.title,
          n.status,
          n.severity ?? null,
          n.poe_level ?? 0,
          n.confidence ?? 1.0,
          n.summary ?? '',
          n.data_json ?? '{}',
          n.claim_owner ?? null,
          n.unclaim_token ?? null,
          n.claim_expires_at ?? null,
          n.created_at,
          n.updated_at
        );
      }

      const insertEdge = this.db.prepare(
        'INSERT OR REPLACE INTO exploration_edges (id, task_id, from_node_id, to_node_id, edge_type, label, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
      );
      for (const e of snapshot.explorationEdges || []) {
        insertEdge.run(e.id, e.task_id, e.from_node_id, e.to_node_id, e.edge_type, e.label ?? null, e.created_at);
      }

      const insertAnchor = this.db.prepare(
        'INSERT OR REPLACE INTO exploration_anchors (id, task_id, node_id, asset_id, relation, created_at) VALUES (?, ?, ?, ?, ?, ?)'
      );
      for (const a of snapshot.explorationAnchors || []) {
        insertAnchor.run(a.id, a.task_id, a.node_id, a.asset_id, a.relation, a.created_at);
      }

      const insertConstraint = this.db.prepare(
        'INSERT OR REPLACE INTO task_constraints (id, task_id, constraint_type, rule_type, pattern, note, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
      );
      for (const c of snapshot.taskConstraints || []) {
        insertConstraint.run(c.id, c.task_id, c.constraint_type, c.rule_type, c.pattern, c.note ?? null, c.created_at);
      }

      const insertCoverage = this.db.prepare(
        'INSERT OR REPLACE INTO coverage_ledger (id, task_id, asset_id, check_category, intent_node_id, status, notes, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
      );
      for (const cl of snapshot.coverageLedger || []) {
        insertCoverage.run(cl.id, cl.task_id, cl.asset_id, cl.check_category, cl.intent_node_id ?? null, cl.status, cl.notes ?? '', cl.updated_at);
      }

      const insertLesson = this.db.prepare(
        'INSERT OR REPLACE INTO rsi_lessons (id, fingerprint_sha256, category, title, lesson, evidence_node_id, verified, hit_count, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
      );
      for (const l of snapshot.rsiLessons || []) {
        insertLesson.run(l.id, l.fingerprint_sha256, l.category, l.title, l.lesson, l.evidence_node_id ?? null, l.verified ? 1 : 0, l.hit_count ?? 1, l.created_at);
      }

      const activityRows = Array.isArray(snapshot.activity)
        ? [...snapshot.activity].sort((a, b) => Number(a.seq ?? 0) - Number(b.seq ?? 0))
        : [];
      if (Array.isArray(snapshot.activity)) {
        const activityTaskIds = new Set(activityRows.map((a) => a.task_id).filter(Boolean));
        if (snapshot.taskId) {
          activityTaskIds.add(snapshot.taskId);
        }
        const delActivity = this.db.prepare('DELETE FROM activity WHERE task_id = ?');
        for (const tid of activityTaskIds) {
          delActivity.run(tid);
        }

        const checkSeq = this.db.prepare('SELECT 1 FROM activity WHERE seq = ?');
        const insertActivityWithSeq = this.db.prepare(
          `INSERT INTO activity (seq, task_id, actor, event_type, node_id, summary, payload_json, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
        );
        const insertActivityAutoSeq = this.db.prepare(
          `INSERT INTO activity (task_id, actor, event_type, node_id, summary, payload_json, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`
        );
        for (const a of activityRows) {
          if (!a.task_id) continue;
          const actor = a.actor ?? 'system';
          const eventType = a.event_type ?? 'info';
          const nodeId = a.node_id ?? null;
          const summary = a.summary ?? '';
          const payloadJson = a.payload_json ?? (a.payload ? JSON.stringify(a.payload) : '{}');
          const createdAt = a.created_at ?? Date.now();
          const hasValidSeq = Number.isInteger(Number(a.seq)) && Number(a.seq) > 0;
          if (hasValidSeq && !checkSeq.get(Number(a.seq))) {
            insertActivityWithSeq.run(Number(a.seq), a.task_id, actor, eventType, nodeId, summary, payloadJson, createdAt);
          } else {
            insertActivityAutoSeq.run(a.task_id, actor, eventType, nodeId, summary, payloadJson, createdAt);
          }
        }
      }

      return {
        imported: true,
        counts: {
          tasks: (snapshot.tasks || []).length,
          assets: (snapshot.assets || []).length,
          nodes: (snapshot.explorationNodes || []).length,
          edges: (snapshot.explorationEdges || []).length,
          activity: activityRows.length,
        },
      };
    });
  }

  close() {
    if (!this._closed && this.db) {
      this._closed = true;
      try {
        this.db.close();
      } catch {}
    }
  }
}

export function createGraphStore(options = {}) {
  return new GraphStore(options);
}
