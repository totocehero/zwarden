/**
 * @file The vault's symmetric key.
 *
 * Two shapes coexist in the Bitwarden ecosystem, and the buffer length is enough
 * to tell them apart — there is no type field on the wire:
 *
 * - **32 bytes**: `encKey` alone. Unauthenticated encryption (type 0). A legacy
 *   shape, kept read-only for old vaults. It is also the shape of the raw master
 *   key out of the KDF, before stretching.
 * - **64 bytes**: `encKey` (32) ‖ `macKey` (32). Authenticated encryption
 *   (type 2). The shape used for everything Zwarden writes.
 *
 * ## Why two distinct keys
 *
 * Reusing the same key for AES and for HMAC is a classic design fault: the two
 * primitives do not share the same requirements, and their composition no longer
 * carries any proven guarantee. The two halves are therefore derived
 * independently (HKDF-Expand with the `enc` and `mac` labels, see `kdf.ts`).
 */

import { EncryptionType } from './encString.js';
import { fromBase64, toBase64, wipe } from './encoding.js';
import { importAesCbcKey, importHmacSha256Key, randomBytes } from './primitives.js';

/** Length of an unauthenticated key, in bytes. */
const UNAUTHENTICATED_LENGTH = 32;

/** Length of an authenticated key (`encKey` ‖ `macKey`), in bytes. */
const AUTHENTICATED_LENGTH = 64;

export class SymmetricCryptoKey {
  /** AES-256 encryption key. Always 32 bytes. */
  readonly encKey: Uint8Array;

  /** HMAC-SHA256 authentication key, or `undefined` for a 32-byte key. */
  readonly macKey: Uint8Array | undefined;

  /** The encryption type this key can produce. */
  readonly encryptionType: EncryptionType;

  /**
   * WebCrypto handles imported lazily, then reused.
   *
   * `subtle.importKey` costs an async round trip: without a cache, every
   * encryption or decryption would pay it twice (AES + HMAC). Syncing a vault of
   * N items under the same key, the cache saves 2 N imports. The handles are
   * non-extractable.
   */
  #encCryptoKey: Promise<CryptoKey> | undefined;
  #macCryptoKey: Promise<CryptoKey> | undefined;

  /**
   * @param key Raw key material, 32 or 64 bytes. **The buffer becomes the key's
   *   property**: `encKey` and `macKey` are views onto it, not copies. The caller
   *   must neither reuse nor erase it any more — `destroy()` handles that at
   *   lock time.
   * @throws {RangeError} For any other length.
   */
  constructor(readonly key: Uint8Array) {
    switch (key.length) {
      case UNAUTHENTICATED_LENGTH:
        this.encKey = key;
        this.macKey = undefined;
        this.encryptionType = EncryptionType.AesCbc256_B64;
        break;

      case AUTHENTICATED_LENGTH:
        // `subarray`, not `slice`: views onto the same buffer, so that
        // `destroy()` actually erases encKey and macKey in one pass.
        this.encKey = key.subarray(0, 32);
        this.macKey = key.subarray(32, 64);
        this.encryptionType = EncryptionType.AesCbc256_HmacSha256_B64;
        break;

      default:
        throw new RangeError(
          `Unsupported key length: ${key.length} bytes ` +
            `(${UNAUTHENTICATED_LENGTH} or ${AUTHENTICATED_LENGTH} expected)`,
        );
    }
  }

  /**
   * Rebuilds a key from its base64 form, as stored or received.
   *
   * @param value Base64-encoded key.
   * @throws {RangeError} If the decoded length is invalid.
   */
  static fromBase64(value: string): SymmetricCryptoKey {
    return new SymmetricCryptoKey(fromBase64(value));
  }

  /**
   * Generates an authenticated vault key.
   *
   * Used at account creation and at key rotation. The 64 bytes come straight
   * from the CSPRNG: no derivation, the vault key is independent of the master
   * password. That is what makes changing the master password possible without
   * re-encrypting the vault.
   */
  static generate(): SymmetricCryptoKey {
    return new SymmetricCryptoKey(randomBytes(AUTHENTICATED_LENGTH));
  }

  /** `true` if the key allows authenticated encryption. */
  get isAuthenticated(): boolean {
    return this.macKey !== undefined;
  }

  /**
   * Imported AES-CBC handle, cached on first call.
   *
   * @returns Non-extractable `CryptoKey` for `encKey`.
   */
  getEncCryptoKey(): Promise<CryptoKey> {
    return (this.#encCryptoKey ??= importAesCbcKey(this.encKey));
  }

  /**
   * Imported HMAC-SHA256 handle, cached on first call.
   *
   * @returns Non-extractable `CryptoKey` for `macKey`.
   * @throws {RangeError} If the key is 32 bytes, hence without a `macKey`.
   *   Callers must test `isAuthenticated` or `macKey` first.
   */
  getMacCryptoKey(): Promise<CryptoKey> {
    if (this.macKey === undefined) {
      throw new RangeError('32-byte key: no macKey to import');
    }
    return (this.#macCryptoKey ??= importHmacSha256Key(this.macKey));
  }

  /** Encodes the key as base64, for storage or transmission. */
  toBase64(): string {
    return toBase64(this.key);
  }

  /**
   * Erases the key material in place.
   *
   * To be called when the vault locks. Best-effort, and known to be: a JS engine
   * with a generational GC may have copied the buffer during a memory promotion,
   * and those copies are out of JavaScript's reach. It narrows the exposure
   * window without closing it.
   *
   * The instance becomes unusable: `encKey` and `macKey` are views onto the
   * erased buffer. The cached WebCrypto handles are dropped; being
   * non-extractable, they never hand back key material anyway, and the GC will
   * reclaim them.
   */
  destroy(): void {
    wipe(this.key);
    this.#encCryptoKey = undefined;
    this.#macCryptoKey = undefined;
  }
}
