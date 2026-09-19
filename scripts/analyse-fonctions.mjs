/**
 * Mesure la longueur des fonctions et signale les dépassements.
 *
 * Analyse purement lexicale : suffisante pour repérer les fonctions à découper.
 *
 * ## Ce qui est compté, et pourquoi pas tout
 *
 * Le seuil vise la **complexité** : trop de décisions au même endroit. Or une
 * ligne de balisage JSX n'est pas une décision — elle est linéaire, sans
 * branche, et se relit de haut en bas. Compter les deux ensemble condamnait un
 * formulaire déclaratif de cent quarante lignes au même titre qu'une fonction
 * de cent quarante lignes de logique, ce qui rendait l'avertissement inutile
 * là où il aurait dû servir.
 *
 * Les deux nombres sont donc affichés — logique, puis total — et seule la
 * logique déclenche l'alerte.
 *
 * ## Ce que ce script ne sait pas distinguer
 *
 * Trois formes gonflent le compte « logique » sans être de la logique, et il
 * faut le savoir avant de découper quoi que ce soit sur la foi d'un chiffre :
 *
 * - la **liste de propriétés** d'un composant, destructurée puis typée — une
 *   cinquantaine de lignes pour un composant à seize propriétés, sans une seule
 *   décision ;
 * - le **littéral d'objet** que rend un crochet dont les méthodes sont courtes :
 *   le script mesure l'objet entier comme une fonction unique ;
 * - les **membres d'un type** déclarés dans le corps.
 *
 * Un dépassement se lit donc, il ne s'obéit pas.
 *
 * Usage : node scripts/analyse-fonctions.mjs [seuil]
 */

import { readFileSync } from 'node:fs';
import { globSync } from 'node:fs';

const SEUIL = Number(process.argv[2] ?? 40);

const fichiers = globSync('src/**/*.{ts,tsx}');

const SIGNATURE =
  /^\s*(?:export\s+)?(?:async\s+)?(?:function\s+(\w+)|(?:private\s+|public\s+|static\s+|readonly\s+)*(?:async\s+)?(\w+)\s*\()/;

const IGNORES = new Set(['if', 'for', 'while', 'switch', 'catch', 'return', 'constructor']);

/**
 * Écarte ce qui ressemble à une signature sans en être une.
 *
 * Le second motif de SIGNATURE — `nom(` en début de ligne — vise les méthodes de
 * classe, mais attrape aussi tout appel de fonction (`setBusy('…');`) et toute
 * fonction fléchée passée en attribut JSX (`onSubmit={(e) => {`). Les deux
 * produisaient des mesures absurdes : une ligne d'appel se voyait attribuer le
 * corps de la fonction qui l'entoure, et un attribut JSX celui du composant.
 *
 * Deux marques suffisent à les écarter : un appel se termine par `;`, un
 * attribut JSX contient `={`.
 */
function estFausseSignature(ligne) {
  const nu = ligne.trim();
  return nu.endsWith(';') || nu.includes('={');
}

/**
 * Reconnaît une ligne de balisage JSX.
 *
 * Trois formes : une balise (`<div`, `</ul>`, `/>`), un attribut (`value={…}`,
 * `class="…"`), ou une ponctuation de fermeture d'expression (`)}`, `>`).
 * Heuristique, comme tout le reste de ce script — elle peut se tromper sur une
 * ligne tordue, jamais assez pour changer un ordre de grandeur.
 */
function estBalisage(ligne) {
  const nu = ligne.trim();
  if (nu === '') return false;
  if (/^<|^\/>|^<\/|^\)\}|^>$|^\{' '\}$/.test(nu)) return true;
  return /^[\w-]+=(?:\{|")/.test(nu);
}

const resultats = [];

for (const fichier of fichiers) {
  const lignes = readFileSync(fichier, 'utf8').split('\n');

  for (let i = 0; i < lignes.length; i++) {
    const correspondance = SIGNATURE.exec(lignes[i]);
    if (!correspondance) continue;

    const nom = correspondance[1] ?? correspondance[2];
    if (!nom || IGNORES.has(nom)) continue;
    if (!lignes[i].includes('(')) continue;
    if (estFausseSignature(lignes[i])) continue;

    // Compte les lignes de corps jusqu'à l'accolade fermante de même niveau.
    let profondeur = 0;
    let début = -1;
    let corps = 0;
    let logique = 0;

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
          if (!estBalisage(ligne)) logique++;
        }
      }

      if (début !== -1 && profondeur === 0) {
        resultats.push({ fichier, nom, logique, lignes: corps, début: i + 1 });
        break;
      }
    }
  }
}

resultats.sort((a, b) => b.logique - a.logique);

const longueur = (n) => String(n).padStart(4);

console.log(`Seuil d'alerte : ${SEUIL} lignes de logique (le balisage JSX ne compte pas)\n`);
console.log(`${'fonction'.padEnd(28)}${'logique'.padStart(8)}${'total'.padStart(7)}  fichier`);
console.log('-'.repeat(78));

let dépassements = 0;
for (const r of resultats) {
  const alerte = r.logique > SEUIL;
  if (alerte) dépassements++;
  const marque = alerte ? ' <-- à découper' : '';
  console.log(
    `${r.nom.padEnd(28)}${longueur(r.logique)}${longueur(r.lignes)}   ` +
      `${r.fichier.replace(/\\/g, '/')}:${r.début}${marque}`,
  );
}

const total = resultats.reduce((s, r) => s + r.logique, 0);
console.log('-'.repeat(78));
console.log(
  `${resultats.length} fonctions, ${total} lignes de logique, ` +
    `moyenne ${(total / resultats.length).toFixed(1)}, ${dépassements} au-dessus du seuil`,
);
