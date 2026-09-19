/**
 * @file Password generator.
 *
 * ## Two traps, and how they are avoided
 *
 * **Modulo bias.** `byte % alphabet.length` looks innocent: it is not. With a
 * 62-character alphabet, a byte's 256 values split into 4 complete rounds plus a
 * remainder of 8 — the alphabet's first 8 characters come up 5 times in 256, the
 * others 4. The generator loses entropy without ever visibly failing. So we draw
 * again (rejection sampling) instead of folding the remainder back in.
 *
 * **The composition guarantee.** Ticking "digits" and not getting one is a
 * frequent disappointment, and above all a password the site rejects after the
 * fact. One character from each requested class is therefore placed up front,
 * then the whole thing is shuffled — without which the guaranteed classes would
 * stay at the head, which is exactly the pattern an attacker would exploit.
 *
 * The random source is injectable: that is what makes the shuffle and the
 * composition verifiable by deterministic tests.
 */

import { randomBytes } from '../crypto/primitives.js';

/** Generation options, as exposed in the UI. */
export interface PasswordOptions {
  readonly length: number;
  readonly lowercase: boolean;
  readonly uppercase: boolean;
  readonly digits: boolean;
  readonly symbols: boolean;
  /** Excludes `l 1 I O 0 o`, unreadable depending on the font. */
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

/** Length bounds. Beyond them, the input is brought back into range. */
export const MIN_LENGTH = 8;
export const MAX_LENGTH = 128;

/** Thrown when the options allow no password to be composed at all. */
export class GeneratorError extends Error {
  override readonly name = 'GeneratorError';
  readonly code = 'generator-empty-alphabet';
}

const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS = '0123456789';
/** The official extension's symbol set: accepted by most sites. */
const SYMBOLS = '!@#$%^&*';
/** Characters the eye confuses from one font to the next. */
const AMBIGUOUS = 'l1IO0o';

/** Source of random bytes, injectable for tests. */
export type RandomSource = (length: number) => Uint8Array;

/**
 * Random buffer size. A 128-character password consumes at least as many bytes,
 * more once rejections and the shuffle are counted: asking for one byte at a
 * time meant about a hundred CSPRNG calls per draw, and the length slider draws
 * again on every notch.
 */
const RANDOM_CHUNK = 64;

/**
 * Random-byte dispenser, refilled in chunks.
 *
 * The chunking changes **nothing** about the distribution: bytes are consumed in
 * order, one at a time, exactly as if they had been requested separately. Only
 * the number of calls to the source goes down.
 */
function byteStream(random: RandomSource): () => number {
  let buffer: Uint8Array = new Uint8Array(0);
  let offset = 0;
  return () => {
    if (offset >= buffer.length) {
      buffer = random(RANDOM_CHUNK);
      offset = 0;
      if (buffer.length === 0) {
        // Source exhausted or broken: better to fail than to return a
        // predictable password.
        throw new GeneratorError('The random source supplied no bytes');
      }
    }
    return buffer[offset++]!;
  };
}

/**
 * Draws a uniform integer in `[0, bound[`.
 *
 * Rejects the bytes of the incomplete slice: it is that rejection, and it alone,
 * that guarantees uniformity.
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

/** Fisher-Yates shuffle, with the same unbiased source. */
function shuffle(chars: string[], nextByte: () => number): void {
  for (let i = chars.length - 1; i > 0; i--) {
    const j = nextIndex(i + 1, nextByte);
    [chars[i], chars[j]] = [chars[j]!, chars[i]!];
  }
}

/** Strips the ambiguous characters from a set, if the option is on. */
function filterSet(set: string, avoidAmbiguous: boolean): string {
  return avoidAmbiguous ? [...set].filter((c) => !AMBIGUOUS.includes(c)).join('') : set;
}

/**
 * Assembles the character sets in play.
 *
 * @returns The non-empty requested sets. Empty if no class is ticked.
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
 * Generates a password.
 *
 * @param options Desired length and character classes.
 * @param random Byte source. Defaults to `crypto.getRandomValues`.
 * @returns The password, guaranteed one character per requested class as soon as
 *   the length allows it.
 * @throws {GeneratorError} No character class selected.
 */
export function generatePassword(
  options: PasswordOptions = DEFAULT_PASSWORD_OPTIONS,
  random: RandomSource = randomBytes,
): string {
  const sets = activeSets(options);
  if (sets.length === 0) {
    throw new GeneratorError('No character class selected');
  }

  const length = Math.min(MAX_LENGTH, Math.max(MIN_LENGTH, Math.round(options.length)));
  const alphabet = sets.join('');
  const nextByte = byteStream(random);

  // One character per class first: the composition guarantee. If the length is
  // below the number of classes, the last ones are skipped — impossible with
  // MIN_LENGTH = 8 and four classes, but the bound protects the invariant rather
  // than relying on it.
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
