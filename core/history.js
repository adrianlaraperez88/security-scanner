import fs   from 'fs';
import path  from 'path';
import { groupFindings } from './html-report.js';
import { calculateRisk } from './severity.js';

const HISTORY_DIR = '.secscan-history';

function safeHostname(target) {
  try {
    return new URL(target).hostname.replace(/[^a-z0-9.-]/gi, '_');
  } catch {
    return 'unknown';
  }
}

function historyPath(target, timestamp) {
  const dir  = path.join(process.cwd(), HISTORY_DIR);
  const ts   = timestamp.replace(/[:.]/g, '-').replace('T', '_').slice(0, 19);
  const host = safeHostname(target);
  return path.join(dir, `${ts}_${host}.json`);
}

// ── Save ───────────────────────────────────────────────────────────────────────
export function saveHistory(targets, results, risk, stacks = null) {
  const dir = path.join(process.cwd(), HISTORY_DIR);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  const timestamp = new Date().toISOString();
  const record    = {
    timestamp,
    targets,
    risk,
    results,
    ...(stacks ? { stacks } : {})
  };

  // One file per unique target hostname group
  const key       = targets.map(safeHostname).join('_');
  const ts        = timestamp.replace(/[:.]/g, '-').replace('T', '_').slice(0, 19);
  const filePath  = path.join(dir, `${ts}_${key}.json`);

  fs.writeFileSync(filePath, JSON.stringify(record, null, 2));
  return filePath;
}

// ── Load last scan for given targets ─────────────────────────────────────────
export function loadLastHistory(targets) {
  const dir = path.join(process.cwd(), HISTORY_DIR);
  if (!fs.existsSync(dir)) return null;

  const key   = targets.map(safeHostname).join('_');
  const files = fs.readdirSync(dir)
    .filter(f => f.endsWith(`_${key}.json`) && f.endsWith('.json'))
    .sort()
    .reverse();

  if (!files.length) return null;

  try {
    const raw = fs.readFileSync(path.join(dir, files[0]), 'utf8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

// ── List scan history (newest first) ─────────────────────────────────────────
export function listHistory() {
  const dir = path.join(process.cwd(), HISTORY_DIR);
  if (!fs.existsSync(dir)) return [];

  try {
    const files = fs.readdirSync(dir).filter(f => f.endsWith('.json'));
    const list = [];

    for (const file of files) {
      try {
        const filePath = path.join(dir, file);
        const raw = fs.readFileSync(filePath, 'utf8');
        const record = JSON.parse(raw);
        const results = Array.isArray(record.results) ? record.results : [];
        const grouped = groupFindings(results);

        const vulnerable = grouped.filter(r => r.status === 'VULNERABLE').length;
        const suspicious = grouped.filter(r => r.status === 'SUSPICIOUS').length;
        const normalizedRisk = results.length > 0 ? calculateRisk(results) : (record.risk || null);

        list.push({
          id: file,
          timestamp: record.timestamp || file.slice(0, 19).replace(/_/g, 'T'),
          targets: Array.isArray(record.targets) ? record.targets : [],
          risk: normalizedRisk,
          count: grouped.length,
          vulnerable,
          suspicious
        });
      } catch {
        // Skip unparseable files
      }
    }

    list.sort((a, b) => {
      const timeA = new Date(a.timestamp).getTime() || 0;
      const timeB = new Date(b.timestamp).getTime() || 0;
      if (timeB !== timeA) return timeB - timeA;
      return b.id.localeCompare(a.id);
    });

    return list;
  } catch {
    return [];
  }
}

// ── Load scan history by ID ──────────────────────────────────────────────────
export function loadHistoryById(id) {
  if (typeof id !== 'string' || !/^[a-zA-Z0-9._-]+\.json$/.test(id)) {
    return null;
  }

  const dir = path.join(process.cwd(), HISTORY_DIR);
  const resolvedDir = path.resolve(dir);
  const resolvedPath = path.resolve(dir, id);

  if (!resolvedPath.startsWith(resolvedDir + path.sep)) {
    return null;
  }

  if (!fs.existsSync(resolvedPath)) {
    return null;
  }

  try {
    const raw = fs.readFileSync(resolvedPath, 'utf8');
    const record = JSON.parse(raw);
    if (record && Array.isArray(record.results) && record.results.length > 0) {
      record.risk = calculateRisk(record.results);
    }
    return record;
  } catch {
    return null;
  }
}

// ── Diff two result sets ──────────────────────────────────────────────────────
export function diffScans(previous, current) {
  const prevMap = new Map(
    previous.results.map(r => [`${r.target}::${r.name}`, r])
  );
  const currMap = new Map(
    current.map(r => [`${r.target}::${r.name}`, r])
  );

  const newFindings     = [];
  const fixedFindings   = [];
  const changedFindings = [];
  const unchanged       = [];

  // Check current against previous
  for (const [key, curr] of currMap) {
    const prev = prevMap.get(key);
    if (!prev) {
      if (curr.status !== 'SAFE' && curr.status !== 'ERROR') {
        newFindings.push(curr);          // brand-new finding
      }
      continue;
    }

    if (prev.status !== curr.status || prev.severity !== curr.severity) {
      if (curr.status === 'SAFE' && prev.status !== 'SAFE') {
        fixedFindings.push({ prev, curr });
      } else {
        changedFindings.push({ prev, curr });
      }
    } else {
      unchanged.push(curr);
    }
  }

  // Checks that existed before but are gone now
  for (const [key, prev] of prevMap) {
    if (!currMap.has(key) && prev.status !== 'SAFE') {
      fixedFindings.push({ prev, curr: null });
    }
  }

  return { newFindings, fixedFindings, changedFindings, unchanged, previous };
}
