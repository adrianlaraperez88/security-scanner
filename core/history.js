import fs   from 'fs';
import path  from 'path';

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
export function saveHistory(targets, results, risk) {
  const dir = path.join(process.cwd(), HISTORY_DIR);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  const timestamp = new Date().toISOString();
  const record    = { timestamp, targets, risk, results };

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
