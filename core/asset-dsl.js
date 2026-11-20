/**
 * Asset Query DSL Tokenizer, Recursive-Descent AST Parser & SQLite Compiler
 * Ported from ARTEX db/asset_dsl.go for Node.js ESM + node:sqlite.
 */

export class AssetDslError extends Error {
  constructor(message, position = 0) {
    super(message);
    this.name = 'AssetDslError';
    this.position = typeof position === 'number' ? position : 0;
  }
}

const VALID_OPERATORS = ['=', '==', '!=', '>', '>=', '<', '<='];

/**
 * Canonical 19 ARTEX Asset DSL fields + `asset` / `key`.
 * Column expressions are strictly static whitelist expressions (never interpolated from user input).
 */
export const FIELD_SPECS = Object.freeze({
  domain: Object.freeze({
    name: 'domain',
    column: "COALESCE(assets.host, assets.key, '')",
    kind: 'string',
    exactOnly: false,
    operators: VALID_OPERATORS,
    description: 'Domain or hostname of the asset',
  }),
  host: Object.freeze({
    name: 'host',
    column: "COALESCE(assets.host, '')",
    kind: 'string',
    exactOnly: false,
    operators: VALID_OPERATORS,
    description: 'Hostname or IP literal of the asset',
  }),
  ip: Object.freeze({
    name: 'ip',
    column: "COALESCE(assets.ip, '')",
    kind: 'string',
    exactOnly: true,
    operators: VALID_OPERATORS,
    description: 'IPv4 or IPv6 address',
  }),
  port: Object.freeze({
    name: 'port',
    column: 'assets.port',
    kind: 'number',
    exactOnly: true,
    operators: VALID_OPERATORS,
    description: 'Network port number (1-65535)',
  }),
  service: Object.freeze({
    name: 'service',
    column: "COALESCE(assets.service, '')",
    kind: 'string',
    exactOnly: false,
    operators: VALID_OPERATORS,
    description: 'Service name or fingerprint (e.g., http, https, ssh, nginx)',
  }),
  protocol: Object.freeze({
    name: 'protocol',
    column: "COALESCE(assets.protocol, '')",
    kind: 'string',
    exactOnly: true,
    operators: VALID_OPERATORS,
    description: 'Transport or application protocol (e.g., tcp, http, https)',
  }),
  url: Object.freeze({
    name: 'url',
    column: "COALESCE(assets.url, '')",
    kind: 'string',
    exactOnly: false,
    operators: VALID_OPERATORS,
    description: 'Full normalized URL of service or endpoint',
  }),
  path: Object.freeze({
    name: 'path',
    column: "COALESCE(assets.path, '')",
    kind: 'string',
    exactOnly: false,
    operators: VALID_OPERATORS,
    description: 'URL path component',
  }),
  title: Object.freeze({
    name: 'title',
    column: "COALESCE(assets.title, '')",
    kind: 'string',
    exactOnly: false,
    operators: VALID_OPERATORS,
    description: 'HTTP page title or banner',
  }),
  status: Object.freeze({
    name: 'status',
    column: 'assets.status_code',
    kind: 'number',
    exactOnly: true,
    operators: VALID_OPERATORS,
    description: 'HTTP response status code',
  }),
  source: Object.freeze({
    name: 'source',
    column: "COALESCE(assets.source, '')",
    kind: 'string',
    exactOnly: false,
    operators: VALID_OPERATORS,
    description: 'Discovery source (e.g., scanner, crawl, dns, manual)',
  }),
  company: Object.freeze({
    name: 'company',
    column: "COALESCE(assets.company_id, '')",
    kind: 'company',
    exactOnly: false,
    operators: VALID_OPERATORS,
    description: 'Company ID or company name',
  }),
  c_segment: Object.freeze({
    name: 'c_segment',
    column: "COALESCE(assets.c_segment, '')",
    kind: 'string',
    exactOnly: true,
    operators: VALID_OPERATORS,
    description: 'Network C-segment (/24 for IPv4, /48 for IPv6)',
  }),
  type: Object.freeze({
    name: 'type',
    column: "COALESCE(assets.asset_type, '')",
    kind: 'string',
    exactOnly: true,
    operators: VALID_OPERATORS,
    description: 'Asset type (root_domain, ip, subdomain, app, service, endpoint)',
  }),
  scope: Object.freeze({
    name: 'scope',
    column: "COALESCE(json_extract(assets.metadata_json, '$.scope'), 'in')",
    kind: 'scope',
    exactOnly: true,
    operators: VALID_OPERATORS,
    description: 'Scope status (in, out, true, false)',
  }),
  confidence: Object.freeze({
    name: 'confidence',
    column: 'assets.confidence',
    kind: 'confidence',
    exactOnly: false,
    operators: VALID_OPERATORS,
    description: 'Asset confidence score or level',
  }),
  verified: Object.freeze({
    name: 'verified',
    column: 'assets.verified',
    kind: 'boolean',
    exactOnly: true,
    operators: ['=', '==', '!='],
    description: 'Whether asset is verified (true/false/1/0)',
  }),
  severity: Object.freeze({
    name: 'severity',
    column: 'severity',
    kind: 'severity',
    exactOnly: true,
    operators: VALID_OPERATORS,
    description: 'Severity of findings anchored to the asset (CRITICAL, HIGH, MEDIUM, LOW, INFO)',
  }),
  finding: Object.freeze({
    name: 'finding',
    column: 'finding',
    kind: 'finding',
    exactOnly: false,
    operators: VALID_OPERATORS,
    description: 'Title, summary, or existence of findings anchored to the asset',
  }),
  asset: Object.freeze({
    name: 'asset',
    column: "COALESCE(assets.key, '')",
    kind: 'string',
    exactOnly: false,
    operators: VALID_OPERATORS,
    description: 'Canonical asset key',
  }),
  key: Object.freeze({
    name: 'key',
    column: "COALESCE(assets.key, '')",
    kind: 'string',
    exactOnly: false,
    operators: VALID_OPERATORS,
    description: 'Canonical asset key',
  }),
});

const FIELD_ALIASES = Object.freeze({
  asset_type: 'type',
  kind: 'type',
  status_code: 'status',
  company_id: 'company',
  root_domain: 'domain',
  service_name: 'service',
  page_title: 'title',
});

const BARE_SEARCH_COLUMNS = Object.freeze([
  "COALESCE(assets.key, '')",
  "COALESCE(assets.host, '')",
  "COALESCE(assets.ip, '')",
  "COALESCE(assets.url, '')",
  "COALESCE(assets.path, '')",
  "COALESCE(assets.title, '')",
  "COALESCE(assets.service, '')",
  "COALESCE(assets.protocol, '')",
  "COALESCE(assets.c_segment, '')",
  "COALESCE(assets.source, '')",
  "COALESCE(assets.asset_type, '')",
]);

const SEVERITY_RANK = Object.freeze({
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0,
  NONE: 0,
});

function isWhitespace(ch) {
  return ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r';
}

function isIdentStart(ch) {
  return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch === '_';
}

function isIdentChar(ch) {
  return isIdentStart(ch) || (ch >= '0' && ch <= '9');
}

function isOperatorStart(s, i) {
  const ch = s[i];
  const next = s[i + 1];
  if (ch === '=' || ch === '>' || ch === '<') return true;
  if (ch === '!' && next === '=') return true;
  return false;
}

function readOperator(s, i) {
  const two = s.slice(i, i + 2);
  if (two === '==' || two === '!=' || two === '>=' || two === '<=') {
    return { op: two, end: i + 2 };
  }
  const one = s[i];
  if (one === '=' || one === '>' || one === '<') {
    return { op: one, end: i + 1 };
  }
  return null;
}

function readQuotedString(s, startPos) {
  const quote = s[startPos];
  let i = startPos + 1;
  let out = '';
  while (i < s.length) {
    const ch = s[i];
    if (ch === '\\') {
      if (i + 1 >= s.length) {
        throw new AssetDslError('Unterminated escape sequence in quoted string', startPos);
      }
      out += s[i + 1];
      i += 2;
      continue;
    }
    if (ch === quote) {
      return { value: out, end: i + 1 };
    }
    out += ch;
    i++;
  }
  throw new AssetDslError(`Unterminated quoted string starting with ${quote}`, startPos);
}

function isTokenBoundary(s, i) {
  const ch = s[i];
  if (!ch || isWhitespace(ch) || ch === '(' || ch === ')' || ch === '"' || ch === "'") {
    return true;
  }
  if (s.slice(i, i + 2) === '&&' || s.slice(i, i + 2) === '||') {
    return true;
  }
  return false;
}

function readUnquotedValue(s, startPos) {
  let i = startPos;
  if (i < s.length && (s[i] === '"' || s[i] === "'")) {
    return readQuotedString(s, i);
  }
  while (i < s.length && !isTokenBoundary(s, i)) {
    if (isOperatorStart(s, i) || s[i] === '!') {
      break;
    }
    i++;
  }
  return { value: s.slice(startPos, i), end: i };
}

/**
 * Tokenize an Asset DSL query string into structured tokens.
 */
export function tokenizeAssetDsl(query) {
  const s = String(query ?? '');
  const tokens = [];
  let i = 0;

  while (i < s.length) {
    while (i < s.length && isWhitespace(s[i])) {
      i++;
    }
    if (i >= s.length) break;

    const pos = i;
    const ch = s[i];
    const two = s.slice(i, i + 2);

    if (ch === '(') {
      tokens.push({ type: 'LPAREN', value: '(', position: pos });
      i++;
      continue;
    }
    if (ch === ')') {
      tokens.push({ type: 'RPAREN', value: ')', position: pos });
      i++;
      continue;
    }
    if (two === '&&') {
      tokens.push({ type: 'AND', value: '&&', position: pos });
      i += 2;
      continue;
    }
    if (two === '||') {
      tokens.push({ type: 'OR', value: '||', position: pos });
      i += 2;
      continue;
    }
    if (isOperatorStart(s, i)) {
      throw new AssetDslError(`Unexpected operator at position ${pos}`, pos);
    }
    if (ch === '!' && s[i + 1] !== '=') {
      throw new AssetDslError(`Unexpected '!' operator at position ${pos}`, pos);
    }

    if (ch === '"' || ch === "'") {
      const { value, end } = readQuotedString(s, i);
      tokens.push({ type: 'BARE', value, position: pos });
      i = end;
      continue;
    }

    // Check if this starts with a simple identifier that might be a keyword (AND/OR) or a field comparison
    if (isIdentStart(ch)) {
      let identEnd = i;
      while (identEnd < s.length && isIdentChar(s[identEnd])) {
        identEnd++;
      }
      const ident = s.slice(i, identEnd);
      const upper = ident.toUpperCase();

      // Check if the identifier is immediately followed by an operator (possibly after whitespace)
      let afterIdent = identEnd;
      while (afterIdent < s.length && isWhitespace(s[afterIdent])) {
        afterIdent++;
      }
      const opMatch = readOperator(s, afterIdent);
      // Only treat as field comparison if identEnded cleanly at whitespace or operator
      if (opMatch && (identEnd === afterIdent || isTokenBoundary(s, identEnd))) {
        if (upper === 'AND' || upper === 'OR') {
          throw new AssetDslError(`Boolean keyword "${ident}" cannot be used as a field name`, pos);
        }
        let valStart = opMatch.end;
        while (valStart < s.length && isWhitespace(s[valStart])) {
          valStart++;
        }
        if (valStart >= s.length) {
          throw new AssetDslError(`Missing value after "${ident} ${opMatch.op}"`, opMatch.end);
        }
        const { value, end } = readUnquotedValue(s, valStart);
        if (value === '' && s[valStart] !== '"' && s[valStart] !== "'") {
          throw new AssetDslError(`Missing value for field "${ident}" after operator "${opMatch.op}"`, valStart);
        }
        tokens.push({
          type: 'FIELD',
          field: ident.toLowerCase(),
          op: opMatch.op,
          value,
          position: pos,
          valuePosition: valStart,
        });
        i = end;
        continue;
      }

      // Check if ident is a standalone AND / OR keyword
      if ((upper === 'AND' || upper === 'OR') && isTokenBoundary(s, identEnd)) {
        tokens.push({ type: upper, value: ident, position: pos });
        i = identEnd;
        continue;
      }
    }

    // Otherwise read a bare search token (e.g., hostname, IP, URL, word)
    let bareEnd = i;
    while (bareEnd < s.length && !isTokenBoundary(s, bareEnd)) {
      if (isOperatorStart(s, bareEnd)) {
        // Distinguish URL query strings like https://example.com/a?b=c vs invalid field op
        const prefix = s.slice(i, bareEnd);
        if (!prefix.includes('://') && !prefix.includes('/')) {
          throw new AssetDslError(`Invalid field name "${prefix}" before operator`, pos);
        }
      }
      bareEnd++;
    }
    const bareValue = s.slice(i, bareEnd);
    if (!bareValue) {
      throw new AssetDslError(`Unexpected character "${s[i]}" at position ${pos}`, pos);
    }
    tokens.push({ type: 'BARE', value: bareValue, position: pos });
    i = bareEnd;
  }

  tokens.push({ type: 'EOF', value: '', position: s.length });
  return tokens;
}

function resolveFieldSpec(rawField, position) {
  const key = String(rawField || '').toLowerCase();
  const canonical = FIELD_ALIASES[key] || key;
  const spec = FIELD_SPECS[canonical];
  if (!spec) {
    throw new AssetDslError(
      `Unknown asset DSL field "${rawField}". Valid fields: ${Object.keys(FIELD_SPECS).join(', ')}`,
      position
    );
  }
  return spec;
}

/**
 * Parse a DSL query into a boolean AST.
 * Grammar (AND binds tighter than OR):
 *   expr     -> or_expr
 *   or_expr  -> and_expr ( ('OR' | '||') and_expr )*
 *   and_expr -> atom ( ('AND' | '&&')? atom )*
 *   atom     -> FIELD | BARE | '(' expr ')'
 */
export function parseAssetDsl(query) {
  if (query == null || String(query).trim() === '') {
    return null;
  }
  const tokens = tokenizeAssetDsl(query);
  let pos = 0;

  const peek = () => tokens[pos] || { type: 'EOF', position: String(query).length };
  const consume = () => tokens[pos++];

  function parseOr() {
    let left = parseAnd();
    const children = [left];
    while (peek().type === 'OR') {
      const opTok = consume();
      if (peek().type === 'EOF' || peek().type === 'RPAREN' || peek().type === 'OR' || peek().type === 'AND') {
        throw new AssetDslError(`Expected expression after "${opTok.value}"`, opTok.position);
      }
      children.push(parseAnd());
    }
    if (children.length === 1) return children[0];
    return { type: 'or', children };
  }

  function parseAnd() {
    let left = parseAtom();
    const children = [left];
    while (true) {
      const next = peek();
      if (next.type === 'AND') {
        const opTok = consume();
        if (peek().type === 'EOF' || peek().type === 'RPAREN' || peek().type === 'OR' || peek().type === 'AND') {
          throw new AssetDslError(`Expected expression after "${opTok.value}"`, opTok.position);
        }
        children.push(parseAtom());
      } else if (next.type === 'FIELD' || next.type === 'BARE' || next.type === 'LPAREN') {
        // Implicit AND between adjacent terms
        children.push(parseAtom());
      } else {
        break;
      }
    }
    if (children.length === 1) return children[0];
    return { type: 'and', children };
  }

  function parseAtom() {
    const t = peek();
    if (t.type === 'FIELD') {
      consume();
      const spec = resolveFieldSpec(t.field, t.position);
      if (!spec.operators.includes(t.op)) {
        throw new AssetDslError(`Field "${spec.name}" does not support operator "${t.op}"`, t.position);
      }
      return {
        type: 'comparison',
        field: spec.name,
        op: t.op,
        value: t.value,
        position: t.position,
        valuePosition: t.valuePosition,
      };
    }
    if (t.type === 'BARE') {
      consume();
      return {
        type: 'bare',
        value: t.value,
        position: t.position,
      };
    }
    if (t.type === 'LPAREN') {
      const openTok = consume();
      if (peek().type === 'RPAREN') {
        throw new AssetDslError('Empty parentheses "()" in DSL expression', openTok.position);
      }
      const inner = parseOr();
      if (peek().type !== 'RPAREN') {
        throw new AssetDslError('Missing closing parenthesis ")"', openTok.position);
      }
      consume();
      return inner;
    }
    if (t.type === 'EOF') {
      throw new AssetDslError('Unexpected end of DSL expression', t.position);
    }
    throw new AssetDslError(`Unexpected token "${t.value || t.type}"`, t.position);
  }

  const ast = parseOr();
  if (peek().type !== 'EOF') {
    const extra = peek();
    throw new AssetDslError(`Unexpected token "${extra.value || extra.type}"`, extra.position);
  }
  return ast;
}

function toLikePattern(rawVal, exactOnly = false) {
  const str = String(rawVal);
  if (str.includes('*')) {
    return str.replace(/\*/g, '%');
  }
  if (str.includes('%')) {
    return str;
  }
  return exactOnly ? str : `%${str}%`;
}

function compileAstNode(node, params) {
  if (!node) {
    return '1=1';
  }
  if (node.type === 'and') {
    const parts = node.children.map((c) => `(${compileAstNode(c, params)})`);
    return parts.join(' AND ');
  }
  if (node.type === 'or') {
    const parts = node.children.map((c) => `(${compileAstNode(c, params)})`);
    return parts.join(' OR ');
  }
  if (node.type === 'bare') {
    const pattern = `%${node.value}%`;
    const clauses = BARE_SEARCH_COLUMNS.map((col) => {
      params.push(pattern);
      return `LOWER(${col}) LIKE LOWER(?)`;
    });
    return `(${clauses.join(' OR ')})`;
  }
  if (node.type === 'comparison') {
    const spec = resolveFieldSpec(node.field, node.position);
    const op = node.op;
    const rawValue = node.value;

    // 1. Numeric fields (port, status)
    if (spec.kind === 'number') {
      const num = Number(rawValue);
      if (!Number.isFinite(num) || rawValue.trim() === '' || !/^-?\d+(\.\d+)?$/.test(rawValue.trim())) {
        throw new AssetDslError(
          `Field "${spec.name}" requires a numeric value, got "${rawValue}"`,
          node.valuePosition ?? node.position
        );
      }
      const sqlOp = op === '==' ? '=' : op;
      params.push(num);
      return `${spec.column} ${sqlOp} ?`;
    }

    // 2. Boolean fields (verified)
    if (spec.kind === 'boolean') {
      const lower = String(rawValue).toLowerCase().trim();
      let boolInt;
      if (lower === 'true' || lower === '1' || lower === 'yes') {
        boolInt = 1;
      } else if (lower === 'false' || lower === '0' || lower === 'no') {
        boolInt = 0;
      } else {
        throw new AssetDslError(
          `Field "${spec.name}" requires a boolean value (true/false/1/0), got "${rawValue}"`,
          node.valuePosition ?? node.position
        );
      }
      const sqlOp = op === '!=' ? '!=' : '=';
      params.push(boolInt);
      return `COALESCE(${spec.column}, 0) ${sqlOp} ?`;
    }

    // 3. Confidence (supports numeric or string comparison)
    if (spec.kind === 'confidence') {
      const trimmed = String(rawValue).trim();
      const isNumeric = /^-?\d+(\.\d+)?$/.test(trimmed);
      if (isNumeric) {
        const sqlOp = op === '==' ? '=' : op;
        params.push(Number(trimmed));
        return `CAST(COALESCE(${spec.column}, 0) AS REAL) ${sqlOp} ?`;
      }
      if (op !== '=' && op !== '==' && op !== '!=') {
        throw new AssetDslError(
          `Field "confidence" requires a numeric value for operator "${op}", got "${rawValue}"`,
          node.valuePosition ?? node.position
        );
      }
      params.push(trimmed);
      if (op === '!=') {
        return `LOWER(CAST(COALESCE(${spec.column}, '') AS TEXT)) != LOWER(?)`;
      }
      return `LOWER(CAST(COALESCE(${spec.column}, '') AS TEXT)) = LOWER(?)`;
    }

    // 4. Company (matches company_id or companies.name)
    if (spec.kind === 'company') {
      if (op === '==') {
        params.push(rawValue, rawValue);
        return `(LOWER(COALESCE(assets.company_id, '')) = LOWER(?) OR EXISTS (SELECT 1 FROM companies c WHERE c.id = assets.company_id AND LOWER(c.name) = LOWER(?)))`;
      }
      const pat = toLikePattern(rawValue, false);
      if (op === '!=') {
        params.push(rawValue, pat);
        return `(LOWER(COALESCE(assets.company_id, '')) != LOWER(?) AND NOT EXISTS (SELECT 1 FROM companies c WHERE c.id = assets.company_id AND LOWER(c.name) LIKE LOWER(?)))`;
      }
      params.push(pat, pat);
      return `(LOWER(COALESCE(assets.company_id, '')) LIKE LOWER(?) OR EXISTS (SELECT 1 FROM companies c WHERE c.id = assets.company_id AND LOWER(c.name) LIKE LOWER(?)))`;
    }

    // 5. Scope
    if (spec.kind === 'scope') {
      const lower = String(rawValue).toLowerCase().trim();
      const inVals = new Set(['in', 'true', '1', 'allowed', 'in_scope']);
      const outVals = new Set(['out', 'false', '0', 'denied', 'out_of_scope']);
      let wantIn = inVals.has(lower);
      if (!wantIn && !outVals.has(lower)) {
        params.push(rawValue);
        const sqlOp = op === '!=' ? '!=' : '=';
        return `LOWER(${spec.column}) ${sqlOp} LOWER(?)`;
      }
      if (op === '!=') wantIn = !wantIn;
      params.push(wantIn ? 'out' : 'in');
      return wantIn
        ? `LOWER(${spec.column}) != LOWER(?)`
        : `LOWER(${spec.column}) != LOWER(?)`;
    }

    // 6. Severity (checks anchored finding nodes or metadata_json.$.severity)
    if (spec.kind === 'severity') {
      const upper = String(rawValue).toUpperCase().trim();
      if (op === '=' || op === '==') {
        params.push(upper, upper);
        return `(EXISTS (SELECT 1 FROM exploration_anchors ea JOIN exploration_nodes en ON en.id = ea.node_id WHERE ea.asset_id = assets.id AND en.node_type = 'finding' AND UPPER(COALESCE(en.severity, '')) = ?) OR UPPER(COALESCE(json_extract(assets.metadata_json, '$.severity'), '')) = ?)`;
      }
      if (op === '!=') {
        params.push(upper, upper);
        return `(NOT EXISTS (SELECT 1 FROM exploration_anchors ea JOIN exploration_nodes en ON en.id = ea.node_id WHERE ea.asset_id = assets.id AND en.node_type = 'finding' AND UPPER(COALESCE(en.severity, '')) = ?) AND UPPER(COALESCE(json_extract(assets.metadata_json, '$.severity'), '')) != ?)`;
      }
      const rank = SEVERITY_RANK[upper];
      if (rank === undefined) {
        throw new AssetDslError(
          `Unknown severity level "${rawValue}". Expected CRITICAL, HIGH, MEDIUM, LOW, or INFO`,
          node.valuePosition ?? node.position
        );
      }
      params.push(rank);
      return `EXISTS (SELECT 1 FROM exploration_anchors ea JOIN exploration_nodes en ON en.id = ea.node_id WHERE ea.asset_id = assets.id AND en.node_type = 'finding' AND (CASE UPPER(COALESCE(en.severity, '')) WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END) ${op} ?)`;
    }

    // 7. Finding (checks anchored finding nodes or metadata_json.$.finding)
    if (spec.kind === 'finding') {
      const lower = String(rawValue).toLowerCase().trim();
      if ((lower === 'true' || lower === '1') && (op === '=' || op === '==')) {
        return `EXISTS (SELECT 1 FROM exploration_anchors ea JOIN exploration_nodes en ON en.id = ea.node_id WHERE ea.asset_id = assets.id AND en.node_type = 'finding')`;
      }
      if ((lower === 'false' || lower === '0') && (op === '=' || op === '==')) {
        return `NOT EXISTS (SELECT 1 FROM exploration_anchors ea JOIN exploration_nodes en ON en.id = ea.node_id WHERE ea.asset_id = assets.id AND en.node_type = 'finding')`;
      }
      const pat = op === '==' ? rawValue : toLikePattern(rawValue, false);
      const cmp = op === '==' ? '=' : 'LIKE';
      params.push(pat, pat, pat);
      const clause = `(EXISTS (SELECT 1 FROM exploration_anchors ea JOIN exploration_nodes en ON en.id = ea.node_id WHERE ea.asset_id = assets.id AND en.node_type = 'finding' AND (LOWER(COALESCE(en.title, '')) ${cmp} LOWER(?) OR LOWER(COALESCE(en.summary, '')) ${cmp} LOWER(?))) OR LOWER(COALESCE(json_extract(assets.metadata_json, '$.finding'), '')) ${cmp} LOWER(?))`;
      return op === '!=' ? `NOT ${clause}` : clause;
    }

    // 8. Standard string fields
    const col = spec.column;
    if (op === '==') {
      params.push(rawValue);
      return `LOWER(${col}) = LOWER(?)`;
    }
    if (op === '=') {
      if (rawValue.includes('*') || rawValue.includes('%')) {
        params.push(toLikePattern(rawValue, false));
        return `LOWER(${col}) LIKE LOWER(?)`;
      }
      if (spec.exactOnly) {
        params.push(rawValue);
        return `LOWER(${col}) = LOWER(?)`;
      }
      params.push(`%${rawValue}%`);
      return `LOWER(${col}) LIKE LOWER(?)`;
    }
    if (op === '!=') {
      if (rawValue.includes('*') || rawValue.includes('%')) {
        params.push(toLikePattern(rawValue, false));
        return `LOWER(${col}) NOT LIKE LOWER(?)`;
      }
      if (spec.exactOnly) {
        params.push(rawValue);
        return `LOWER(${col}) != LOWER(?)`;
      }
      params.push(`%${rawValue}%`);
      return `LOWER(${col}) NOT LIKE LOWER(?)`;
    }
    if (op === '>' || op === '>=' || op === '<' || op === '<=') {
      params.push(rawValue);
      return `LOWER(${col}) ${op} LOWER(?)`;
    }
  }

  throw new AssetDslError(`Unsupported AST node type "${node.type}"`, node.position || 0);
}

/**
 * Compile an Asset DSL query string into a parameterized SQLite WHERE clause.
 *
 * @param {string} query
 * @returns {{ whereSql: string, params: Array<string|number>, ast: object|null }}
 */
export function compileAssetDsl(query) {
  const ast = parseAssetDsl(query);
  if (!ast) {
    return { whereSql: '1=1', params: [], ast: null };
  }
  const params = [];
  const whereSql = compileAstNode(ast, params);
  return { whereSql, params, ast };
}
