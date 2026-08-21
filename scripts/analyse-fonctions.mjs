/**
 * Mesure la longueur des fonctions exportées et signale les dépassements.
 * Analyse purement lexicale : suffisante pour repérer les fonctions à découper.
 *
 * Usage : node scripts/analyse-fonctions.mjs [seuil]
 */

import { readFileSync } from 'node:fs';
import { globSync } from 'node:fs';

const SEUIL = Number(process.argv[2] ?? 40);

const fichiers = globSync('src/**/*.ts');

const SIGNATURE =
  /^\s*(?:export\s+)?(?:async\s+)?(?:function\s+(\w+)|(?:private\s+|public\s+|static\s+|readonly\s+)*(?:async\s+)?(\w+)\s*\()/;

const IGNORES = new Set(['if', 'for', 'while', 'switch', 'catch', 'return', 'constructor']);

const resultats = [];

for (const fichier of fichiers) {
  const lignes = readFileSync(fichier, 'utf8').split('\n');

  for (let i = 0; i < lignes.length; i++) {
    const correspondance = SIGNATURE.exec(lignes[i]);
    if (!correspondance) continue;

    const nom = correspondance[1] ?? correspondance[2];
    if (!nom || IGNORES.has(nom)) continue;
    if (!lignes[i].includes('(')) continue;

    // Compte les lignes de corps jusqu'à l'accolade fermante de même niveau.
    let profondeur = 0;
    let début = -1;
    let corps = 0;

    for (let j = i; j < lignes.length; j++) {
      const ligne = lignes[j];
      const sansCommentaire = ligne.replace(/\/\/.*$/, '');

      for (const caractère of sansCommentaire) {
        if (caractère === '{') {
          if (début === -1) début = j;
          profondeur++;
        } else if (caractère === '}') {
          profondeur--;
        }
      }

      if (début !== -1) {
        const nu = ligne.trim();
        if (nu && !nu.startsWith('*') && !nu.startsWith('//') && !nu.startsWith('/*')) {
          corps++;
        }
      }

      if (début !== -1 && profondeur === 0) {
        resultats.push({ fichier, nom, lignes: corps, début: i + 1 });
        break;
      }
    }
  }
}

resultats.sort((a, b) => b.lignes - a.lignes);

const longueur = (n) => String(n).padStart(4);

console.log(`Seuil d'alerte : ${SEUIL} lignes de corps\n`);
console.log(`${'fonction'.padEnd(28)}${'lignes'.padStart(7)}  fichier`);
console.log('-'.repeat(78));

let dépassements = 0;
for (const r of resultats) {
  const alerte = r.lignes > SEUIL;
  if (alerte) dépassements++;
  const marque = alerte ? ' <-- à découper' : '';
  console.log(
    `${r.nom.padEnd(28)}${longueur(r.lignes)}   ${r.fichier.replace(/\\/g, '/')}:${r.début}${marque}`,
  );
}

const total = resultats.reduce((s, r) => s + r.lignes, 0);
console.log('-'.repeat(78));
console.log(
  `${resultats.length} fonctions, ${total} lignes de corps, ` +
    `moyenne ${(total / resultats.length).toFixed(1)}, ${dépassements} au-dessus du seuil`,
);
