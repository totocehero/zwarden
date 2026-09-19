/**
 * Checks the extension's size budget: `dist/` must stay under 300 KB (excluding
 * source maps). Exits non-zero otherwise, so it can act as a CI guard rail. See
 * the README: this is the project's central promise.
 */

import { readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const BUDGET = 300 * 1024;
const DIST = new URL('../dist', import.meta.url).pathname;

function* files(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      yield* files(path);
    } else if (!entry.name.endsWith('.map')) {
      yield path;
    }
  }
}

let total = 0;
const rows = [];
try {
  for (const path of files(DIST)) {
    const size = statSync(path).size;
    total += size;
    rows.push([size, path.slice(DIST.length + 1)]);
  }
} catch {
  console.error('dist/ not found — run `npm run build` first.');
  process.exit(1);
}

rows.sort((a, b) => b[0] - a[0]);
for (const [size, name] of rows) {
  console.log(`${String(Math.round(size / 1024)).padStart(6)} KB  ${name}`);
}

const kb = Math.round(total / 1024);
const budget = Math.round(BUDGET / 1024);
if (total > BUDGET) {
  console.error(`\nTOTAL: ${kb} KB — budget of ${budget} KB EXCEEDED`);
  process.exit(1);
}
console.log(`\nTOTAL: ${kb} KB / budget ${budget} KB`);
