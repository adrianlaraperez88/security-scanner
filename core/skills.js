/**
 * Modular skill registry. Skills are `skills/<name>/SKILL.md` documents with YAML
 * frontmatter (`name`, `description`, `tags`, `mcps`, `checks`) and a markdown body.
 * Loading a skill unlocks its declared MCP tools / check runners for the worker.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const VALID_SKILL_NAME_RE = /^[a-z0-9][a-z0-9_-]*$/;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const DEFAULT_SKILLS_DIR = path.resolve(__dirname, '..', 'skills');

export class SkillError extends Error {
  constructor(message, code = 'SKILL_ERROR') {
    super(message);
    this.name = 'SkillError';
    this.code = code;
  }
}

function stripQuotes(s) {
  const t = String(s).trim();
  if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) {
    return t.slice(1, -1);
  }
  return t;
}

function parseInlineList(v) {
  const inner = v.trim().slice(1, -1);
  if (!inner.trim()) return [];
  return inner
    .split(',')
    .map((x) => stripQuotes(x))
    .filter(Boolean);
}

/**
 * Parse a SKILL.md document into `{ name, description, tags, mcps, checks, body, frontmatter }`.
 */
export function parseSkillMarkdown(rawContent) {
  const text = String(rawContent ?? '').replace(/^\uFEFF/, '').replace(/\r\n/g, '\n');
  const fm = {};
  let body = text;
  const m = /^---\n([\s\S]*?)\n---\n?/.exec(text);
  if (m) {
    body = text.slice(m[0].length);
    const lines = m[1].split('\n');
    let currentKey = null;
    for (const line of lines) {
      if (!line.trim() || line.trim().startsWith('#')) continue;
      const listItem = /^\s+-\s+(.*)$/.exec(line);
      if (listItem && currentKey) {
        if (!Array.isArray(fm[currentKey])) fm[currentKey] = [];
        fm[currentKey].push(stripQuotes(listItem[1]));
        continue;
      }
      const kv = /^([A-Za-z0-9_-]+)\s*:\s*(.*)$/.exec(line);
      if (!kv) continue;
      currentKey = kv[1];
      const val = kv[2].trim();
      if (val === '') fm[currentKey] = [];
      else if (val.startsWith('[') && val.endsWith(']')) fm[currentKey] = parseInlineList(val);
      else fm[currentKey] = stripQuotes(val);
    }
  }
  const asList = (v) => (Array.isArray(v) ? v.map(String) : v ? [String(v)] : []);
  const description = Array.isArray(fm.description) ? '' : String(fm.description ?? '');
  return {
    name: Array.isArray(fm.name) ? '' : String(fm.name ?? ''),
    description,
    tags: asList(fm.tags),
    mcps: asList(fm.mcps),
    checks: asList(fm.checks),
    body: body.trim(),
    frontmatter: fm,
  };
}

export class SkillRegistry {
  constructor({ skillsDir = DEFAULT_SKILLS_DIR } = {}) {
    this.skillsDir = path.resolve(skillsDir);
    /** @type {Map<string, number>} */
    this.skillUsage = new Map();
    /** @type {Array<{topic: string, reason: string, at: number}>} */
    this.skillGaps = [];
    this._cache = new Map();
  }

  _resolveSkillPath(name) {
    if (typeof name !== 'string' || !VALID_SKILL_NAME_RE.test(name)) {
      throw new SkillError(`Invalid skill name "${String(name).slice(0, 64)}"`, 'INVALID_SKILL_NAME');
    }
    const file = path.resolve(this.skillsDir, name, 'SKILL.md');
    const rel = path.relative(this.skillsDir, file);
    if (rel.startsWith('..') || path.isAbsolute(rel)) {
      throw new SkillError('Skill path escapes skills directory', 'INVALID_SKILL_NAME');
    }
    return file;
  }

  /** Names of every valid skill directory that has a SKILL.md. */
  listSkills() {
    let entries = [];
    try {
      entries = fs.readdirSync(this.skillsDir, { withFileTypes: true });
    } catch {
      return [];
    }
    const out = [];
    for (const e of entries) {
      if (!e.isDirectory() || !VALID_SKILL_NAME_RE.test(e.name)) continue;
      try {
        const skill = this.readSkill(e.name);
        out.push({ name: skill.name, description: skill.description, tags: skill.tags });
      } catch {
        /* skip unreadable skills */
      }
    }
    return out.sort((a, b) => a.name.localeCompare(b.name));
  }

  /** Read without recording usage. */
  readSkill(name) {
    const file = this._resolveSkillPath(name);
    if (this._cache.has(name)) return this._cache.get(name);
    let raw;
    try {
      raw = fs.readFileSync(file, 'utf8');
    } catch {
      throw new SkillError(`Skill "${name}" not found`, 'SKILL_NOT_FOUND');
    }
    const parsed = parseSkillMarkdown(raw);
    const skill = { ...parsed, name: parsed.name || name, dirName: name };
    this._cache.set(name, skill);
    return skill;
  }

  /**
   * Load a skill and record usage. Returns the skill plus the `unlocked` MCP tools / checks.
   */
  loadSkill(name) {
    const skill = this.readSkill(name);
    this.skillUsage.set(name, (this.skillUsage.get(name) || 0) + 1);
    return {
      ...skill,
      unlocked: { mcps: [...skill.mcps], checks: [...skill.checks] },
    };
  }

  recordSkillGap(topic, reason = '') {
    const entry = { topic: String(topic || '').slice(0, 200), reason: String(reason || '').slice(0, 500), at: Date.now() };
    this.skillGaps.push(entry);
    return entry;
  }

  getUsage() {
    return Object.fromEntries(this.skillUsage);
  }

  getGaps() {
    return [...this.skillGaps];
  }
}
