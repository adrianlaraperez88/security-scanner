import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export async function getScanners() {
  const dir = path.join(__dirname, '../checks');
  const files = fs.readdirSync(dir).filter(f => f.endsWith('.js'));

  const scanners = [];

  for (const file of files) {
    const mod = await import(`../checks/${file}`);

    const run =
      mod.default ||
      Object.values(mod).find(v => typeof v === 'function');

    if (!run) continue;

    scanners.push({
      name: file.replace('.js', ''),
      run,
      tags: mod.tags || ['all']
    });
  }

  return scanners;
}