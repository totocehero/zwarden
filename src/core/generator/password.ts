/**
 * @file Générateur de mots de passe.
 *
 * ## Deux pièges, et comment ils sont évités
 *
 * **Le biais du modulo.** `octet % alphabet.length` semble innocent : il ne
 * l'est pas. Avec un alphabet de 62 caractères, les 256 valeurs d'un octet se
 * répartissent en 4 tours complets plus un reste de 8 — les 8 premiers
 * caractères de l'alphabet sortent 5 fois sur 256, les autres 4 fois. Le
 * générateur perd de l'entropie sans jamais échouer visiblement. On tire donc
 * à nouveau (`rejection sampling`) au lieu de replier le reste.
 *
 * **La garantie de composition.** Cocher « chiffres » sans en obtenir un est
 * une déception fréquente, et surtout un mot de passe refusé par le site
 * après coup. Un caractère de chaque classe demandée est donc placé d'office,
 * puis l'ensemble est mélangé — sans quoi les classes garanties resteraient
 * en tête, ce qui est exactement le motif qu'un attaquant exploiterait.
 *
 * La source aléatoire est injectable : c'est ce qui rend le mélange et la
 * composition vérifiables par des tests déterministes.
 */

import { randomBytes } from '../crypto/primitives.js';

/** Options de génération, telles qu'exposées dans l'interface. */
export interface PasswordOptions {
  readonly length: number;
  readonly lowercase: boolean;
  readonly uppercase: boolean;
  readonly digits: boolean;
  readonly symbols: boolean;
  /** Exclut `l 1 I O 0 o`, illisibles selon la police. */
  readonly avoidAmbiguous: boolean;
}

export const DEFAULT_PASSWORD_OPTIONS: PasswordOptions = {
  length: 20,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
  avoidAmbiguous: true,
};

/** Bornes de longueur. Au-delà, la saisie est ramenée dans l'intervalle. */
export const MIN_LENGTH = 8;
export const MAX_LENGTH = 128;

/** Levée quand les options ne permettent de composer aucun mot de passe. */
export class GeneratorError extends Error {
  override readonly name = 'GeneratorError';
  readonly code = 'generator-empty-alphabet';
}

const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS = '0123456789';
/** Jeu de symboles de l'extension officielle : accepté par la plupart des sites. */
const SYMBOLS = '!@#$%^&*';
/** Caractères que l'œil confond d'une police à l'autre. */
const AMBIGUOUS = 'l1IO0o';

/** Source d'octets aléatoires, injectable pour les tests. */
export type RandomSource = (length: number) => Uint8Array;

/**
 * Taille du tampon d'aléa. Un mot de passe de 128 caractères consomme au moins
 * autant d'octets, davantage avec les rejets et le mélange : demander un octet
 * à la fois faisait une centaine d'appels au CSPRNG par tirage, et le curseur
 * de longueur retire à chaque cran.
 */
const RANDOM_CHUNK = 64;

/**
 * Distributeur d'octets aléatoires, rechargé par blocs.
 *
 * Le regroupement ne change **rien** à la distribution : les octets sont
 * consommés dans l'ordre, un par un, exactement comme s'ils avaient été
 * demandés séparément. Seul le nombre d'appels à la source diminue.
 */
function byteStream(random: RandomSource): () => number {
  let buffer: Uint8Array = new Uint8Array(0);
  let offset = 0;
  return () => {
    if (offset >= buffer.length) {
      buffer = random(RANDOM_CHUNK);
      offset = 0;
      if (buffer.length === 0) {
        // Source épuisée ou défaillante : mieux vaut échouer que rendre un mot
        // de passe prévisible.
        throw new GeneratorError("La source aléatoire n'a fourni aucun octet");
      }
    }
    return buffer[offset++]!;
  };
}

/**
 * Tire un entier uniforme dans `[0, bound[`.
 *
 * Rejette les octets de la tranche incomplète : c'est ce rejet, et lui seul,
 * qui garantit l'uniformité.
 */
function nextIndex(bound: number, nextByte: () => number): number {
  const limit = 256 - (256 % bound);
  for (;;) {
    const byte = nextByte();
    if (byte < limit) {
      return byte % bound;
    }
  }
}

/** Mélange de Fisher-Yates, avec la même source non biaisée. */
function shuffle(chars: string[], nextByte: () => number): void {
  for (let i = chars.length - 1; i > 0; i--) {
    const j = nextIndex(i + 1, nextByte);
    [chars[i], chars[j]] = [chars[j]!, chars[i]!];
  }
}

/** Retire les caractères ambigus d'un jeu, si l'option est active. */
function filterSet(set: string, avoidAmbiguous: boolean): string {
  return avoidAmbiguous ? [...set].filter((c) => !AMBIGUOUS.includes(c)).join('') : set;
}

/**
 * Compose les jeux de caractères retenus.
 *
 * @returns Les jeux non vides demandés. Vide si aucune classe n'est cochée.
 */
function activeSets(options: PasswordOptions): string[] {
  const sets = [
    options.lowercase ? LOWERCASE : '',
    options.uppercase ? UPPERCASE : '',
    options.digits ? DIGITS : '',
    options.symbols ? SYMBOLS : '',
  ];
  return sets.map((set) => filterSet(set, options.avoidAmbiguous)).filter((set) => set !== '');
}

/**
 * Engendre un mot de passe.
 *
 * @param options Longueur et classes de caractères souhaitées.
 * @param random Source d'octets. Par défaut `crypto.getRandomValues`.
 * @returns Le mot de passe, garanti d'un caractère par classe demandée dès
 *   que la longueur le permet.
 * @throws {GeneratorError} Aucune classe de caractères retenue.
 */
export function generatePassword(
  options: PasswordOptions = DEFAULT_PASSWORD_OPTIONS,
  random: RandomSource = randomBytes,
): string {
  const sets = activeSets(options);
  if (sets.length === 0) {
    throw new GeneratorError('Aucune classe de caractères sélectionnée');
  }

  const length = Math.min(MAX_LENGTH, Math.max(MIN_LENGTH, Math.round(options.length)));
  const alphabet = sets.join('');
  const nextByte = byteStream(random);

  // Un caractère par classe d'abord : la garantie de composition. Si la
  // longueur est inférieure au nombre de classes, les dernières sautent —
  // cas impossible avec MIN_LENGTH = 8 et quatre classes, mais la borne
  // protège l'invariant plutôt que de compter dessus.
  const chars: string[] = [];
  for (const set of sets.slice(0, length)) {
    chars.push(set[nextIndex(set.length, nextByte)]!);
  }
  while (chars.length < length) {
    chars.push(alphabet[nextIndex(alphabet.length, nextByte)]!);
  }

  shuffle(chars, nextByte);
  return chars.join('');
}
