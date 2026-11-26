import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getCheckInfo } from './catalog.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

let cachedCheckNames = null;
let cachedScanners = null;

function cloneScannerDescriptor(s) {
  return {
    name: s.name,
    run: s.run,
    tags: [...s.tags],
    meta: {
      ...s.meta,
      cveIds: [...(s.meta.cveIds || [])],
      references: [...(s.meta.references || [])]
    }
  };
}

export function getAvailableCheckNames() {
  if (cachedCheckNames) {
    return [...cachedCheckNames];
  }
  const dir = path.join(__dirname, '../checks');
  cachedCheckNames = fs.readdirSync(dir)
    .filter(f => f.endsWith('.js'))
    .map(f => f.replace(/\.js$/, ''))
    .sort();
  return [...cachedCheckNames];
}

export async function getScanners(options = {}) {
  const rawOnly = options?.onlyChecks;
  const onlySet = rawOnly
    ? new Set(
        Array.from(rawOnly)
          .map(name => String(name || '').trim().toLowerCase().replace(/\.js$/, ''))
          .filter(Boolean)
      )
    : null;

  if (cachedScanners) {
    const source = onlySet
      ? cachedScanners.filter(s => onlySet.has(s.name.toLowerCase()))
      : cachedScanners;
    return source.map(cloneScannerDescriptor);
  }

  let files = getAvailableCheckNames().map(name => `${name}.js`);
  if (onlySet) {
    files = files.filter(f => onlySet.has(f.replace(/\.js$/, '').toLowerCase()));
  }

  const scanners = [];

  for (const file of files) {
    try {
      const mod = await import(`../checks/${file}`);

      const run = typeof mod.default === 'function'
        ? mod.default
        : Object.values(mod).find(v => typeof v === 'function');

      if (!run) continue;

      const baseName = file.replace('.js', '');
      const defaultMeta = getCheckInfo(baseName);
      const rawMeta = mod.meta ? { ...defaultMeta, ...mod.meta } : { ...defaultMeta };
      const meta = {
        ...rawMeta,
        id: rawMeta.id || baseName,
        remediation: mod.meta?.remediation ?? mod.meta?.defaultFix ?? rawMeta.remediation ?? rawMeta.defaultFix,
        cveIds: Array.isArray(rawMeta.cveIds) ? [...rawMeta.cveIds] : [...(defaultMeta.cveIds || [])],
        references: Array.isArray(rawMeta.references) ? [...rawMeta.references] : [...(defaultMeta.references || [])]
      };

      const tags = Array.isArray(mod.tags) && mod.tags.length > 0 ? [...mod.tags] : ['all'];

      scanners.push({
        name: baseName,
        run,
        tags,
        meta
      });
    } catch (err) {
      console.warn(`⚠️  Failed to load scanner "${file}": ${err.message}`);
    }
  }

  if (!onlySet) {
    cachedScanners = scanners;
  }

  return scanners.map(cloneScannerDescriptor);
}
