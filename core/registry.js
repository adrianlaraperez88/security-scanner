import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getCheckInfo } from './catalog.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export async function getScanners() {
  const dir = path.join(__dirname, '../checks');
  const files = fs.readdirSync(dir).filter(f => f.endsWith('.js')).sort();

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

  return scanners;
}
