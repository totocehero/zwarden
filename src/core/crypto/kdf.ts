/**
 * @file Deriving the master key from the password.
 *
 * ## Key chain
 *
 * ```
 *   master password
 *          │  KDF (PBKDF2-SHA256 or Argon2id), salt = email
 *          ▼
 *      master key (32 B)  ─────────────┐
 *          │  HKDF-Expand              │  PBKDF2, 1 or 2 iterations
 *          ▼                           ▼
 *   stretched master key (64 B)    password hash
 *          │  decrypts                  (server authentication /
 *          ▼                             offline validation)
 *     vault key (64 B)
 *          │  decrypts
 *          ▼
 *      item contents
 * ```
 *
 * The essential point: **the master key never encrypts data**. It serves only to
 * unlock the vault key. That is what makes changing the master password possible
 * without re-encrypting the whole vault — only the vault key is re-wrapped.
 *
 * ## The cost of WASM
 *
 * PBKDF2-SHA256 goes through WebCrypto: native, 0 bytes of bundle. Argon2id has
 * no native equivalent in browsers; the WASM module (~45 KB) is loaded behind a
 * dynamic import, hence only when unlocking an account actually configured for
 * Argon2id. A PBKDF2 account never downloads it. Compare with the 7.4 MB of SDK
 * the official client loads unconditionally.
 */

import { hkdfExpandSha256, pbkdf2Sha256, sha256 } from './primitives.js';
import { SymmetricCryptoKey } from './symmetricCryptoKey.js';
import { fromBase64, timingSafeEqual, toBase64, toUtf8Bytes, wipe } from './encoding.js';

/** Supported derivation functions, values as the API announces them. */
export const KdfType = {
  PBKDF2_SHA256: 0,
  Argon2id: 1,
} as const;

export type KdfType = (typeof KdfType)[keyof typeof KdfType];

/**
 * What a password hash is for.
 *
 * The numeric value **is** the PBKDF2 iteration count applied, which guarantees
 * the two hashes differ. Consequence: the hash kept locally to validate the
 * password offline cannot be replayed as proof of authentication to the server,
 * and vice versa.
 */
export const HashPurpose = {
  /** Sent to the server at authentication time. */
  ServerAuthorization: 1,
  /** Kept locally to validate the password without a network. */
  LocalAuthorization: 2,
} as const;

export type HashPurpose = (typeof HashPurpose)[keyof typeof HashPurpose];

/** OWASP 2023 floor for PBKDF2-SHA256. */
export const PBKDF2_DEFAULT_ITERATIONS = 600_000;

/**
 * Refusal floor for PBKDF2.
 *
 * Deliberately below the recommended value: many existing vaults were created
 * with 100,000 iterations (Bitwarden's old default) and must stay unlockable.
 * Below that, the cost of an offline attack becomes trivial.
 */
export const PBKDF2_MIN_ITERATIONS = 100_000;

/**
 * Refusal ceiling for PBKDF2.
 *
 * The floor's mirror image: the parameters come from the server before
 * authentication, so a hostile server can announce an absurd value (2³¹
 * iterations) to freeze the client at unlock — a denial of service that nudges
 * the user towards a less careful client. The official client's UI caps at
 * 2,000,000; 5,000,000 leaves comfortable headroom without ever refusing a
 * legitimate vault.
 */
export const PBKDF2_MAX_ITERATIONS = 5_000_000;

/** Default Argon2id parameters, aligned with Bitwarden's. */
export const ARGON2_DEFAULTS = {
  iterations: 3,
  /** In mebibytes, as in the API. */
  memoryMiB: 64,
  parallelism: 4,
} as const;

/** Refusal floors for Argon2id. */
const ARGON2_MINIMUMS = {
  iterations: 2,
  memoryMiB: 16,
  parallelism: 1,
} as const;

/**
 * Refusal ceilings for Argon2id, aligned with the maxima in the official
 * client's UI: no vault created by Bitwarden can exceed them.
 *
 * The most critical is memory: `memoryMiB` translates into a real WASM
 * allocation. Without a ceiling, a hostile server announcing several gibibytes
 * makes the allocation fail or kills the tab — denial of service at unlock.
 */
const ARGON2_MAXIMUMS = {
  iterations: 10,
  memoryMiB: 1024,
  parallelism: 16,
} as const;

/** Derivation parameters, as the server announces them. */
export type KdfConfig =
  | { readonly type: typeof KdfType.PBKDF2_SHA256; readonly iterations: number }
  | {
      readonly type: typeof KdfType.Argon2id;
      readonly iterations: number;
      readonly memoryMiB: number;
      readonly parallelism: number;
    };

/** Thrown when the server announces dangerous or malformed KDF parameters. */
export class WeakKdfError extends Error {
  override readonly name = 'WeakKdfError';
  /** Stable identifier for the UI: the messages are for logs. */
  readonly code = 'weak-kdf';
}

/**
 * Validates a server-announced KDF parameter: safe integer, within [min, max].
 *
 * @throws {WeakKdfError} With a message fitted to the case encountered.
 */
function assertParameterInRange(label: string, value: number, min: number, max: number): void {
  if (!Number.isSafeInteger(value)) {
    // Covers NaN, ±Infinity, floats, and the non-numeric values a hostile server
    // would slip into the JSON: none of that may reach the KDF.
    throw new WeakKdfError(
      `${label}: non-integer or missing value (${String(value)}). Connection refused.`,
    );
  }
  if (value < min) {
    throw new WeakKdfError(
      `${label} announced as ${value}, minimum accepted ${min}. ` +
        'Connection refused: this parameter would leave the master password open to offline attack.',
    );
  }
  if (value > max) {
    throw new WeakKdfError(
      `${label} announced as ${value}, maximum accepted ${max}. ` +
        'Connection refused: an absurd value would freeze the client at unlock.',
    );
  }
}

/**
 * Refuses KDF parameters that are too weak, absurd, or malformed.
 *
 * ## Why this check exists
 *
 * KDF parameters are supplied by the server through `/api/accounts/prelogin`,
 * **before any authentication**. They are therefore untrusted input. A
 * compromised server — or an attacker positioned as a man in the middle on a
 * badly configured instance — can answer `iterations: 1`. The client then derives
 * a master key at the cost of a single PBKDF2 round: the password becomes
 * attackable offline within seconds, and the authentication hash it sends is
 * enough to mount the attack.
 *
 * The check is bounded in both directions: too low, and the key becomes
 * crackable offline; too high (2³¹ iterations, Argon2 memory in gibibytes), and
 * the client freezes or the tab dies — denial of service at unlock. The official
 * Bitwarden client performs neither of these checks. Zwarden would rather refuse
 * to connect than silently weaken the key or let itself be frozen.
 *
 * @param config Parameters announced by the server.
 * @throws {WeakKdfError} If a parameter is out of bounds or not an integer.
 */
export function assertKdfIsAcceptable(config: KdfConfig): void {
  if (config.type === KdfType.PBKDF2_SHA256) {
    assertParameterInRange(
      'PBKDF2 (iterations)',
      config.iterations,
      PBKDF2_MIN_ITERATIONS,
      PBKDF2_MAX_ITERATIONS,
    );
    return;
  }

  assertParameterInRange(
    'Argon2id (iterations)',
    config.iterations,
    ARGON2_MINIMUMS.iterations,
    ARGON2_MAXIMUMS.iterations,
  );
  assertParameterInRange(
    'Argon2id (memory MiB)',
    config.memoryMiB,
    ARGON2_MINIMUMS.memoryMiB,
    ARGON2_MAXIMUMS.memoryMiB,
  );
  assertParameterInRange(
    'Argon2id (parallelism)',
    config.parallelism,
    ARGON2_MINIMUMS.parallelism,
    ARGON2_MAXIMUMS.parallelism,
  );
}

/**
 * Normalises the email used as the salt.
 *
 * The salt must be identical across all clients, otherwise the derived key
 * differs and the vault becomes unreadable. Bitwarden applies `trim()` then
 * `toLowerCase()`; any divergence here breaks interoperability.
 */
function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

/**
 * Normalises the password before derivation.
 *
 * NFKD aligns equivalent Unicode representations: an "é" typed as a single code
 * point and the same character composed of an "e" followed by a combining accent
 * then produce the same key, whatever the keyboard or the OS.
 */
function normalizePassword(password: string): Uint8Array {
  return toUtf8Bytes(password.normalize('NFKD'));
}

/**
 * Derives the master key from the password and the email.
 *
 * @param password Master password, in the clear.
 * @param email Account email, used as the salt.
 * @param config KDF parameters announced by the server.
 * @returns 32-byte master key, unauthenticated (no `macKey`).
 * @throws {WeakKdfError} If the parameters fall outside the accepted bounds.
 */
export async function deriveMasterKey(
  password: string,
  email: string,
  config: KdfConfig,
): Promise<SymmetricCryptoKey> {
  assertKdfIsAcceptable(config);

  const passwordBytes = normalizePassword(password);
  try {
    if (config.type === KdfType.PBKDF2_SHA256) {
      // PBKDF2 takes the normalised email directly as the salt.
      const salt = toUtf8Bytes(normalizeEmail(email));
      return new SymmetricCryptoKey(await pbkdf2Sha256(passwordBytes, salt, config.iterations, 32));
    }

    // Argon2id requires a fixed-size salt: Bitwarden uses the SHA-256 of the
    // email, not the raw email. Diverge and vaults become unreadable.
    const salt = await sha256(toUtf8Bytes(normalizeEmail(email)));

    // A per-algorithm build (29 KB) rather than the package's monolithic ESM
    // (212 KB once bundled). This UMD build exposes its functions either by name
    // or under `default`, depending on the environment's CJS interop: we cover
    // both. See `src/types/hash-wasm-argon2.d.ts`.
    const umd = await import('hash-wasm/dist/argon2.umd.min.js');
    const argon2id = umd.argon2id ?? umd.default?.argon2id;
    if (argon2id === undefined) {
      throw new Error('Unreadable Argon2 module: no argon2id export');
    }

    const derived = await argon2id({
      password: passwordBytes,
      salt,
      parallelism: config.parallelism,
      iterations: config.iterations,
      memorySize: config.memoryMiB * 1024, // hash-wasm expects KiB
      hashLength: 32,
      outputType: 'binary',
    });

    return new SymmetricCryptoKey(derived);
  } finally {
    // The encoded password has no further use once the key is derived.
    // Best-effort, like every erasure in JavaScript.
    wipe(passwordBytes);
  }
}

/**
 * Stretches the master key into an authenticated key usable for encryption.
 *
 * The master key is 32 bytes: enough to encrypt, not to authenticate. We expand
 * it to 64 bytes (`encKey` ‖ `macKey`) through two HKDF-Expand calls.
 *
 * HKDF's Extract step is deliberately omitted: the master key is already a
 * uniformly random PRK out of the KDF. That is also what Bitwarden does — adding
 * Extract would produce a different key and make existing vaults unreadable.
 *
 * @param masterKey Master key from {@link deriveMasterKey}.
 * @returns 64-byte authenticated key.
 */
export async function stretchMasterKey(masterKey: SymmetricCryptoKey): Promise<SymmetricCryptoKey> {
  // The two derivations are independent: run in parallel.
  const [encKey, macKey] = await Promise.all([
    hkdfExpandSha256(masterKey.key, 'enc', 32),
    hkdfExpandSha256(masterKey.key, 'mac', 32),
  ]);

  const stretched = new Uint8Array(64);
  stretched.set(encKey, 0);
  stretched.set(macKey, 32);
  wipe(encKey);
  wipe(macKey);
  return new SymmetricCryptoKey(stretched);
}

/**
 * Computes a hash of the master password.
 *
 * PBKDF2 is applied "backwards": the master key plays the role of the password
 * and the password that of the salt. The server therefore receives a value from
 * which it can recover neither the password nor the master key.
 *
 * The iteration count *is* the purpose itself ({@link HashPurpose}), which makes
 * the two hashes structurally distinct.
 *
 * @param masterKey Master key.
 * @param password Master password, in the clear.
 * @param purpose What the hash is for.
 * @returns 32-byte hash, base64-encoded.
 */
export async function derivePasswordHash(
  masterKey: SymmetricCryptoKey,
  password: string,
  purpose: HashPurpose,
): Promise<string> {
  const salt = normalizePassword(password);
  try {
    const hash = await pbkdf2Sha256(masterKey.key, salt, purpose, 32);
    return toBase64(hash);
  } finally {
    wipe(salt);
  }
}

/**
 * Validates a password against the local hash, with no network.
 *
 * This is the lock screen's path: the `LocalAuthorization` hash is kept at the
 * first unlock, then every entry is revalidated against it. The comparison is on
 * the **decoded bytes**, in constant time — never a `===` on the base64 strings,
 * which short-circuits at the first differing character.
 *
 * @param masterKey Master key derived from the entry to validate.
 * @param password Password entered, in the clear.
 * @param expectedHashB64 The stored local hash, in base64.
 * @returns `true` if the entry matches.
 */
export async function verifyLocalPasswordHash(
  masterKey: SymmetricCryptoKey,
  password: string,
  expectedHashB64: string,
): Promise<boolean> {
  const actual = await derivePasswordHash(masterKey, password, HashPurpose.LocalAuthorization);
  return timingSafeEqual(fromBase64(actual), fromBase64(expectedHashB64));
}
