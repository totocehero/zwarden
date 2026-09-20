/**
 * @file How weak a password is, estimated honestly.
 *
 * ## What this is, and what it is not
 *
 * It is **not** zxcvbn. zxcvbn is four hundred kilobytes of dictionaries and
 * matchers, which is more than this entire extension is allowed to weigh, and
 * shipping it would contradict the one promise the project makes.
 *
 * It is a pool-entropy estimate with penalties for the patterns that estimate
 * is blind to. Stated plainly, so nobody reads more into a verdict than it
 * carries:
 *
 * - **a "weak" verdict is reliable.** Everything it flags is genuinely bad;
 * - **a "strong" verdict is not a certificate.** A password this calls strong
 *   may still fall to a targeted attack — a name, a date, a phrase from a
 *   language this knows nothing about.
 *
 * Its job is to find the passwords that are obviously bad, not to certify the
 * rest. That is worth doing, because in real vaults the obviously bad ones are
 * there.
 */

/** Character classes a password can draw from, and the size of each pool. */
const POOLS: readonly (readonly [RegExp, number])[] = [
  [/[a-z]/, 26],
  [/[A-Z]/, 26],
  [/[0-9]/, 10],
  // Everything printable that is not alphanumeric, ASCII: 32 of them.
  [/[^a-zA-Z0-9]/, 33],
];

/**
 * The passwords that appear at the top of every breach corpus.
 *
 * A short list on purpose: it is not a dictionary attack, it is a floor. These
 * are the ones a naive entropy count gets *wrong* — `Password1` scores 53 bits
 * and is cracked instantly — which is precisely the gap a list has to fill.
 */
const NOTORIOUS: ReadonlySet<string> = new Set([
  'password', 'passw0rd', 'p@ssword', 'p@ssw0rd', 'motdepasse', 'azerty', 'qwerty',
  'qwertyuiop', 'azertyuiop', 'letmein', 'welcome', 'monkey', 'dragon', 'sunshine',
  'princess', 'football', 'baseball', 'superman', 'batman', 'iloveyou', 'trustno1',
  'admin', 'administrator', 'root', 'toor', 'guest', 'test', 'login', 'user',
  'abc123', 'a1b2c3', 'changeme', 'secret', 'master', 'shadow', 'freedom',
  'whatever', 'starwars', 'computer', 'internet', 'samsung', 'google', 'facebook',
  'soleil', 'bonjour', 'chocolat', 'doudou', 'coucou', 'camille', 'nicolas',
]);

/** Decorations people add to a base word, and which fool an entropy count. */
const DECORATION = /^[^a-z]*([a-z]+?)[^a-z]*$/i;

/**
 * Letter-for-symbol substitutions, the most common decoration of all.
 *
 * Only the unambiguous ones. `1` is deliberately absent: in `Password1` it is a
 * suffix, not an `l`, and mapping it would turn a word the list knows into one
 * it does not. Both the substituted and the plain form are tested, so nothing
 * has to be guessed — see {@link isNotorious}.
 */
const LEET: Readonly<Record<string, string>> = {
  '@': 'a',
  '4': 'a',
  '0': 'o',
  '3': 'e',
  '5': 's',
  $: 's',
  '7': 't',
};

/** The password with its letter-for-symbol substitutions undone. */
function deLeet(password: string): string {
  return [...password].map((c) => LEET[c] ?? c).join('');
}

/** The base word, with whatever was hung off either end removed. */
function bareWord(password: string): string | undefined {
  return DECORATION.exec(password)?.[1];
}

/** Keyboard rows and the alphabet, forwards and backwards, for run detection. */
const RUNS = [
  'abcdefghijklmnopqrstuvwxyz',
  '01234567890',
  'azertyuiop',
  'qwertyuiop',
  'asdfghjkl',
  'qsdfghjklm',
  'zxcvbnm',
  'wxcvbn',
];

/** How the interface should treat a password. */
export type Strength = 'weak' | 'fair' | 'strong';

/** Why a password was judged as it was. */
export type StrengthReason =
  | 'short'
  | 'notorious'
  | 'repeated'
  | 'sequence'
  | 'single-class'
  | 'entropy'
  | 'ok';

export interface StrengthVerdict {
  readonly strength: Strength;
  /** Estimated bits, after penalties. Indicative, never a guarantee. */
  readonly bits: number;
  readonly reason: StrengthReason;
}

/** The size of the alphabet a password appears to draw from. */
function poolSize(password: string): number {
  return POOLS.reduce((total, [test, size]) => (test.test(password) ? total + size : total), 0);
}

/** How many distinct character classes appear. */
function classCount(password: string): number {
  return POOLS.filter(([test]) => test.test(password)).length;
}

/** True if the password is one character repeated: `aaaaaa`, `111111`. */
function isRepeated(password: string): boolean {
  return password.length > 1 && new Set(password.toLowerCase()).size === 1;
}

/**
 * True if the password is a straight run along a keyboard row or the alphabet,
 * in either direction — `abcdef`, `123456`, `qwerty`, `654321`.
 */
function isRun(password: string): boolean {
  const lower = password.toLowerCase();
  if (lower.length < 4) {
    return false;
  }
  const reversed = [...lower].reverse().join('');
  return RUNS.some((row) => row.includes(lower) || row.includes(reversed));
}

/**
 * True if the password is a notorious one, however it has been dressed up.
 *
 * Four forms are tried, because the decorations combine: the word itself,
 * the word with a prefix or suffix (`Password1!`, `123azerty`), the word with
 * symbols substituted for letters (`P4ssw0rd`), and both at once (`P@ssw0rd!`).
 */
function isNotorious(password: string): boolean {
  const lower = password.toLowerCase();
  for (const form of [lower, deLeet(lower)]) {
    if (NOTORIOUS.has(form)) {
      return true;
    }
    const bare = bareWord(form);
    if (bare !== undefined && bare.length >= 4 && NOTORIOUS.has(bare)) {
      return true;
    }
  }
  return false;
}

/** Bits below which a password is weak, and below which it is merely fair. */
const WEAK_BELOW = 45;
const FAIR_BELOW = 70;

/**
 * Judges one password.
 *
 * @param password The password in clear.
 * @returns Its strength, an indicative bit count, and the reason.
 */
export function passwordStrength(password: string): StrengthVerdict {
  if (password === '') {
    return { strength: 'weak', bits: 0, reason: 'short' };
  }

  // The patterns an entropy count cannot see, checked first because when one
  // matches the count is meaningless.
  if (isNotorious(password)) {
    return { strength: 'weak', bits: 4, reason: 'notorious' };
  }
  if (isRepeated(password)) {
    return { strength: 'weak', bits: 4, reason: 'repeated' };
  }
  if (isRun(password)) {
    return { strength: 'weak', bits: 6, reason: 'sequence' };
  }
  if (password.length < 8) {
    return { strength: 'weak', bits: Math.round(password.length * Math.log2(poolSize(password))), reason: 'short' };
  }

  const bits = Math.round(password.length * Math.log2(poolSize(password)));

  // One class and nothing else, however long: a lowercase-only passphrase
  // survives this, a lowercase-only twelve-character word does not.
  if (classCount(password) === 1 && password.length < 16) {
    return { strength: 'weak', bits, reason: 'single-class' };
  }
  if (bits < WEAK_BELOW) {
    return { strength: 'weak', bits, reason: 'entropy' };
  }
  return { strength: bits < FAIR_BELOW ? 'fair' : 'strong', bits, reason: 'ok' };
}

/**
 * Labels that say nothing about which site this is.
 *
 * Without them, every host would contribute a token every other host also has,
 * and `com` inside a password would look like a finding.
 */
const NOISE: ReadonlySet<string> = new Set([
  'www', 'com', 'net', 'org', 'edu', 'gov', 'int', 'mil',
  'app', 'dev', 'xyz', 'info', 'biz', 'online', 'site', 'shop',
  'fr', 'uk', 'de', 'es', 'it', 'nl', 'be', 'ch', 'ca', 'us', 'io', 'co', 'eu',
  'mail', 'login', 'account', 'user', 'com.br',
]);

/** The words a hint contributes: alphanumeric runs, minus the noise. */
function tokensOf(hint: string | null): readonly string[] {
  return (hint?.toLowerCase().match(/[a-z0-9]+/g) ?? []).filter(
    (token) => token.length >= 3 && !NOISE.has(token),
  );
}

/**
 * True if the password merely repeats something the item already says.
 *
 * `github` on the GitHub entry, `Bank2024!` on the bank's. An entropy count
 * sees nothing wrong with either, and they are among the first things anyone
 * guessing tries.
 *
 * Compared **by word, not by whole string**: what matters is that the password
 * and the item share a distinctive word, wherever it sits and whatever is hung
 * around it. Only runs of four letters or more count towards that, so a
 * generated password is not flagged for happening to contain `ada`.
 *
 * @param password The password in clear.
 * @param hints The item's name, username, host — whatever is already known
 *   about it to anyone looking at the site.
 */
export function echoesItsOwner(password: string, hints: readonly (string | null)[]): boolean {
  const tokens = new Set(hints.flatMap((hint) => tokensOf(hint)));
  if (tokens.size === 0) {
    return false;
  }

  const lower = password.toLowerCase();
  // The password *is* the name or the username, however short.
  if (tokens.has(lower) || tokens.has(bareWord(lower) ?? lower)) {
    return true;
  }
  // Or it contains one of those words, with decoration around it.
  return (lower.match(/[a-z]+/g) ?? []).some(
    (run) => run.length >= 4 && tokens.has(run),
  );
}
