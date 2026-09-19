/**
 * @file Authenticated encryption and decryption of `EncString`s.
 *
 * This is the only place in the codebase allowed to call AES. Every security
 * decision is concentrated here, so that an audit has a single file to read.
 *
 * ## Construction: encrypt-then-MAC
 *
 * ```
 *   iv  ← random, 16 bytes
 *   ct  ← AES-256-CBC(encKey, iv, plaintext)
 *   mac ← HMAC-SHA256(macKey, iv ‖ ct)
 * ```
 *
 * `encKey` and `macKey` are two independent halves of a 64-byte key. The MAC
 * covers the IV **and** the ciphertext: a forged IV, which would let an attacker
 * flip bits in the first plaintext block, is therefore detected.
 *
 * Encrypt-then-MAC is the only one of the three classic compositions (E&M, MtE,
 * EtM) that is generically secure. Above all it allows a forged ciphertext to be
 * rejected **without ever decrypting it**.
 *
 * ## Three rules, never negotiable
 *
 * 1. **MAC verified before decryption.** AES-CBC throws on invalid PKCS#7
 *    padding. Decrypting before verifying turns that exception into a padding
 *    oracle: an attacker able to submit ciphertexts and observe the failure
 *    recovers the plaintext block by block, without ever learning the key.
 *    Swapping the order of those two steps in {@link decryptBytes} is all it
 *    takes to reopen that hole.
 *
 * 2. **Constant-time MAC comparison.** Delegated to `subtle.verify`: native
 *    code, with constant time guaranteed by the platform rather than by how the
 *    JIT happens to treat a JavaScript loop.
 *
 * 3. **No downgrade.** Authenticated data served back as unauthenticated is
 *    rejected. Without that, a hostile server simply strips the MAC and declares
 *    type 0 to recover the padding oracle rule 1 closed.
 */

import { EncString, EncryptionType } from './encString.js';
import { concatBytes, fromUtf8Bytes, toUtf8Bytes } from './encoding.js';
import {
  aesCbcDecrypt,
  aesCbcEncrypt,
  hmacSha256,
  hmacSha256Verify,
  importRsaOaepPrivateKey,
  randomBytes,
  rsaOaepDecrypt,
} from './primitives.js';
import type { SymmetricCryptoKey } from './symmetricCryptoKey.js';

/**
 * Thrown when the MAC does not match.
 *
 * Means one of three things, deliberately indistinguishable from the caller's
 * point of view: tampered data, corrupted data, or the wrong key.
 */
export class MacMismatchError extends Error {
  override readonly name = 'MacMismatchError';
  /** Stable identifier for the UI: the messages are for logs. */
  readonly code = 'mac-mismatch';

  constructor() {
    super('MAC verification failed: data tampered with, corrupted, or wrong key');
  }
}

/** Thrown when a type / key combination is refused by policy. */
export class UnsupportedEncryptionError extends Error {
  override readonly name = 'UnsupportedEncryptionError';
  /** Stable identifier for the UI: the messages are for logs. */
  readonly code = 'unsupported-encryption';
}

/** Size of an AES IV, in bytes. */
const IV_LENGTH = 16;

/**
 * The data the MAC covers: IV ‖ ciphertext.
 *
 * The concatenation order is part of the wire format: changing it would make
 * every existing vault unreadable.
 */
function macPayload(iv: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  return concatBytes(iv, ciphertext);
}

/**
 * Encrypts raw bytes.
 *
 * Always produces type 2 (AES-256-CBC + HMAC-SHA256). Zwarden never emits
 * unauthenticated data, whatever the vault's configuration.
 *
 * A fresh IV is drawn on every call. Reusing an IV under CBC reveals that two
 * messages share a plaintext prefix.
 *
 * @param plaintext Data to encrypt.
 * @param key 64-byte authenticated key.
 * @returns A type 2 `EncString`.
 * @throws {UnsupportedEncryptionError} If the key has no `macKey`.
 */
export async function encryptBytes(
  plaintext: Uint8Array,
  key: SymmetricCryptoKey,
): Promise<EncString> {
  if (key.macKey === undefined) {
    throw new UnsupportedEncryptionError(
      'Encryption refused: 32-byte key, without a macKey. ' +
        'Zwarden never writes unauthenticated data.',
    );
  }

  const iv = randomBytes(IV_LENGTH);
  const ciphertext = await aesCbcEncrypt(await key.getEncCryptoKey(), iv, plaintext);
  const mac = await hmacSha256(await key.getMacCryptoKey(), macPayload(iv, ciphertext));

  return EncString.fromParts(EncryptionType.AesCbc256_HmacSha256_B64, iv, ciphertext, mac);
}

/**
 * Encrypts text, encoded as UTF-8.
 *
 * @param plaintext Text to encrypt.
 * @param key 64-byte authenticated key.
 * @returns A type 2 `EncString`.
 * @throws {UnsupportedEncryptionError} If the key has no `macKey`.
 */
export async function encryptString(
  plaintext: string,
  key: SymmetricCryptoKey,
): Promise<EncString> {
  return encryptBytes(toUtf8Bytes(plaintext), key);
}

/**
 * Decrypts to raw bytes, after MAC verification.
 *
 * The policy applied, from most permissive to strictest:
 *
 * | Type | Authenticated key | Outcome                                    |
 * |------|-------------------|--------------------------------------------|
 * | 2    | yes               | MAC verified, then decrypted               |
 * | 2    | no                | refused — unsuitable key                   |
 * | 0    | no                | decrypted — legacy vault, to be migrated   |
 * | 0    | yes               | refused — downgrade attempt                |
 * | 1    | —                 | refused — AES-128 obsolete                 |
 * | 3-6  | —                 | refused — RSA, outside this service's scope |
 *
 * @param encString Parsed encrypted data.
 * @param key Decryption key.
 * @returns Plaintext.
 * @throws {MacMismatchError} If the MAC is missing or does not match.
 * @throws {UnsupportedEncryptionError} If the type / key combination is refused.
 */
export async function decryptBytes(
  encString: EncString,
  key: SymmetricCryptoKey,
): Promise<Uint8Array> {
  switch (encString.encryptionType) {
    case EncryptionType.AesCbc256_HmacSha256_B64:
      return decryptAuthenticated(encString, key);

    case EncryptionType.AesCbc256_B64:
      return decryptLegacyUnauthenticated(encString, key);

    case EncryptionType.AesCbc128_HmacSha256_B64:
      throw new UnsupportedEncryptionError(
        'Type 1 (AES-128) is obsolete: the vault must be re-encrypted as type 2',
      );

    default:
      throw new UnsupportedEncryptionError(
        `Type ${encString.encryptionType}: RSA encryption, outside the symmetric service's scope`,
      );
  }
}

/**
 * Decrypts type 2, after MAC verification.
 *
 * The order of operations is this module's central security property: verify
 * first, decrypt second. See the file header.
 */
async function decryptAuthenticated(
  encString: EncString,
  key: SymmetricCryptoKey,
): Promise<Uint8Array> {
  if (key.macKey === undefined) {
    throw new UnsupportedEncryptionError(
      'Authenticated data presented with a 32-byte key, without a macKey',
    );
  }

  if (encString.mac === undefined) {
    // Structurally impossible after `EncString.parse`, so necessarily a
    // hand-built instance. Treated as an authentication failure, not as a
    // programming error.
    throw new MacMismatchError();
  }

  const iv = encString.iv!;
  const macValid = await hmacSha256Verify(
    await key.getMacCryptoKey(),
    encString.mac,
    macPayload(iv, encString.ciphertext),
  );
  if (!macValid) {
    throw new MacMismatchError();
  }

  return aesCbcDecrypt(await key.getEncCryptoKey(), iv, encString.ciphertext);
}

/**
 * Decrypts type 0, with no integrity guarantee at all.
 *
 * Tolerated solely to read and then migrate an old vault. An authenticated key
 * signals a downgrade attempt and fails the call.
 */
async function decryptLegacyUnauthenticated(
  encString: EncString,
  key: SymmetricCryptoKey,
): Promise<Uint8Array> {
  if (key.macKey !== undefined) {
    throw new UnsupportedEncryptionError(
      'Type 0 (unauthenticated) data presented with an authenticated key: ' +
        'downgrade refused',
    );
  }

  return aesCbcDecrypt(await key.getEncCryptoKey(), encString.iv!, encString.ciphertext);
}

/**
 * Decrypts RSA data (types 3 and 4) with the account's private key.
 *
 * Single use in the Bitwarden ecosystem: unwrapping **organisation keys**, which
 * the server shares encrypted to each member's public key. The type actually
 * emitted is 4 (OAEP SHA-1); 3 (OAEP SHA-256) is accepted for completeness.
 * Types 5 and 6 (RSA + MAC) are a legacy that never took hold: refused.
 *
 * @param encString Parsed encrypted data, of type 3 or 4.
 * @param pkcs8PrivateKey The account's RSA private key, DER/PKCS#8 — itself
 *   obtained by decrypting `profile.privateKey` with the vault key.
 * @returns Plaintext.
 * @throws {UnsupportedEncryptionError} If the type is neither 3 nor 4.
 * @throws {DOMException} If the block does not decrypt under this key.
 */
export async function decryptRsaBytes(
  encString: EncString,
  pkcs8PrivateKey: Uint8Array,
): Promise<Uint8Array> {
  let hash: 'SHA-1' | 'SHA-256';
  switch (encString.encryptionType) {
    case EncryptionType.Rsa2048_OaepSha256_B64:
      hash = 'SHA-256';
      break;
    case EncryptionType.Rsa2048_OaepSha1_B64:
      hash = 'SHA-1';
      break;
    default:
      throw new UnsupportedEncryptionError(
        `Type ${encString.encryptionType}: RSA decryption is limited to types 3 and 4`,
      );
  }

  const privateKey = await importRsaOaepPrivateKey(pkcs8PrivateKey, hash);
  return rsaOaepDecrypt(privateKey, encString.ciphertext);
}

/**
 * Decrypts to UTF-8 text.
 *
 * @param encString Parsed encrypted data.
 * @param key Decryption key.
 * @returns Plaintext.
 * @throws {MacMismatchError} If the MAC is missing or does not match.
 * @throws {UnsupportedEncryptionError} If the type / key combination is refused.
 */
export async function decryptString(
  encString: EncString,
  key: SymmetricCryptoKey,
): Promise<string> {
  return fromUtf8Bytes(await decryptBytes(encString, key));
}

/**
 * Decrypts an optional field coming from the server.
 *
 * One corrupted item must not fail the whole sync: the function returns `null`
 * and lets the caller decide. Errors stay observable through `onError`, which is
 * deliberately **mandatory**: a field that vanishes without trace is
 * indistinguishable from a deletion attack, so the compiler forces every caller
 * to choose explicitly what to do about it.
 *
 * @param value Serialised string, `null` or `undefined`.
 * @param key Decryption key.
 * @param onError Failure notification, for logging or telemetry.
 * @returns Plaintext, or `null` if the field is absent or unreadable.
 */
export async function decryptStringOrNull(
  value: string | null | undefined,
  key: SymmetricCryptoKey,
  onError: (error: unknown) => void,
): Promise<string | null> {
  if (value == null || value === '') {
    return null;
  }

  try {
    return await decryptString(EncString.parse(value), key);
  } catch (error) {
    onError(error);
    return null;
  }
}
