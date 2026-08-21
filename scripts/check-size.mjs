/**
 * Vérifie le budget de poids de l'extension : `dist/` doit rester sous
 * 300 Ko (hors sourcemaps). Échoue en sortie non nulle sinon, pour servir de
 * garde-fou en CI. Voir le README : c'est la promesse centrale du projet.
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
const lignes = [];
try {
  for (const path of files(DIST)) {
    const size = statSync(path).size;
    total += size;
    lignes.push([size, path.slice(DIST.length + 1)]);
  }
} catch {
  console.error('dist/ introuvable — lancer `npm run build` d’abord.');
  process.exit(1);
}

lignes.sort((a, b) => b[0] - a[0]);
for (const [size, name] of lignes) {
  console.log(`${String(Math.round(size / 1024)).padStart(6)} Ko  ${name}`);
}

const ko = Math.round(total / 1024);
const budget = Math.round(BUDGET / 1024);
if (total > BUDGET) {
  console.error(`\nTOTAL : ${ko} Ko — budget de ${budget} Ko DÉPASSÉ`);
  process.exit(1);
}
console.log(`\nTOTAL : ${ko} Ko / budget ${budget} Ko`);
