/**
 * @file Cryptographic primitives, backed by WebCrypto.
 *
 * ## Guiding principle
 *
 * Everything WebCrypto can do is delegated to WebCrypto. The browser
 * implementation is native code, constant-time, continuously audited by the
 * Chromium and Firefox security teams — and it weighs nothing in the bundle.
 * Reimplementing AES or SHA-2 in JavaScript or WASM would add weight, timing
 * side channels and extra audit surface, for no gain at all.
 *
 * Argon2id alone escapes this rule: it does not exist in WebCrypto. It is
 * handled separately, behind a dynamic import, in `kdf.ts`.
 *
 * ## Scope
 *
 * This module exposes stateless transformations only. All format logic lives in
 * `encString.ts`, and the security decisions (MAC verification, downgrade
 * refusal) in `cryptoService.ts`. Add nothing here that makes a decision.
 */

import { concatBytes, toUtf8Bytes, wipe } from './encoding.js';

const subtle = globalThis.crypto.subtle;

/**
 * Adapts a `Uint8Array` to the signature WebCrypto expects.
 *
 * Since TypeScript 5.7, `Uint8Array` is generic over `ArrayBufferLike`, which
 * includes `SharedArrayBuffer` and is therefore no longer assignable to
 * `BufferSource`. Our buffers are never backed by shared memory. The conversion
 * is confined to this function rather than scattered as casts throughout the
 * cryptographic code, where they would be hard to tell apart from a genuine
 * typing escape hatch.
 */
function asBufferSource(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

/**
 * Produces cryptographically random bytes.
 *
 * @param length Number of bytes wanted.
 * @returns Buffer filled by the system CSPRNG.
 */
export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  globalThis.crypto.getRandomValues(out);
  return out;
}

/**
 * Computes a SHA-256 digest.
 *
 * @param data Data to digest.
 * @returns 32-byte digest.
 */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle.digest('SHA-256', asBufferSource(data)));
}

/**
 * Imports an HMAC-SHA256 key as a non-extractable `CryptoKey`.
 *
 * An `importKey` costs an async round trip to the platform crypto module:
 * importing once and reusing the handle (see the cache in `SymmetricCryptoKey`)
 * avoids paying that on every operation. The key is non-extractable: once
 * imported, its material is no longer readable from JavaScript.
 *
 * @param raw Raw key material.
 * @returns Handle usable for signing and verifying.
 */
export async function importHmacSha256Key(raw: Uint8Array): Promise<CryptoKey> {
  return subtle.importKey('raw', asBufferSource(raw), { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
    'verify',
  ]);
}

/**
 * Imports an AES-CBC key as a non-extractable `CryptoKey`.
 *
 * Same motivation as {@link importHmacSha256Key}.
 *
 * @param raw 32-byte key.
 * @returns Handle usable for encrypting and decrypting.
 */
export async function importAesCbcKey(raw: Uint8Array): Promise<CryptoKey> {
  return subtle.importKey('raw', asBufferSource(raw), 'AES-CBC', false, ['encrypt', 'decrypt']);
}

/** Accepts either raw material or an already-imported handle. */
async function toHmacKey(key: Uint8Array | CryptoKey): Promise<CryptoKey> {
  return key instanceof CryptoKey ? key : importHmacSha256Key(key);
}

/** Accepts either raw material or an already-imported handle. */
async function toAesKey(key: Uint8Array | CryptoKey): Promise<CryptoKey> {
  return key instanceof CryptoKey ? key : importAesCbcKey(key);
}

/**
 * Computes an HMAC-SHA256.
 *
 * @param key Authentication key, raw or already imported. Raw, any length is
 *   accepted: HMAC hashes or pads it per RFC 2104.
 * @param data Data to authenticate.
 * @returns 32-byte MAC.
 */
export async function hmacSha256(key: Uint8Array | CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await toHmacKey(key);
  return new Uint8Array(await subtle.sign('HMAC', cryptoKey, asBufferSource(data)));
}

/** Hash algorithms RFC 6238 admits. */
export type OtpAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-512';

/**
 * Computes an HMAC for a one-time code (RFC 4226 / 6238).
 *
 * **A single-purpose function, literally.** It exists because TOTP is specified
 * on HMAC-SHA1 and the vast majority of sites offer nothing else: refusing SHA-1
 * here would not make codes safer, it would make the second factor unusable.
 * SHA-1's weakness is collisions; HMAC does not depend on collision resistance,
 * and a six-digit code valid for thirty seconds does not have the lifetime of a
 * vault key anyway.
 *
 * It must **never** authenticate vault data: `hmacSha256` and it alone carries
 * "encrypt-then-MAC", and no encrypted data passes through here.
 *
 * @param algorithm Algorithm announced by the `otpauth://` URI.
 * @param key Shared secret, already decoded.
 * @param data 8-byte big-endian counter.
 * @returns Raw MAC, whose length depends on the algorithm.
 */
export async function hmacForOtp(
  algorithm: OtpAlgorithm,
  key: Uint8Array,
  data: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await subtle.importKey(
    'raw',
    asBufferSource(key),
    { name: 'HMAC', hash: algorithm },
    false,
    ['sign'],
  );
  return new Uint8Array(await subtle.sign('HMAC', cryptoKey, asBufferSource(data)));
}

/**
 * Verifies an HMAC-SHA256 in constant time.
 *
 * Delegates the comparison to `subtle.verify`: it runs as native code, with
 * constant time guaranteed by the platform — unlike a JavaScript loop, whose
 * timing profile ultimately depends on the JIT. This is the path to use for any
 * MAC verification.
 *
 * @param key Authentication key, raw or already imported.
 * @param mac Expected MAC, 32 bytes.
 * @param data Authenticated data.
 * @returns `true` if the MAC matches.
 */
export async function hmacSha256Verify(
  key: Uint8Array | CryptoKey,
  mac: Uint8Array,
  data: Uint8Array,
): Promise<boolean> {
  const cryptoKey = await toHmacKey(key);
  return subtle.verify('HMAC', cryptoKey, asBufferSource(mac), asBufferSource(data));
}

/**
 * Derives a key with PBKDF2-SHA256 (RFC 8018).
 *
 * The compute cost is strictly proportional to `iterations`: that is the only
 * parameter protecting against an offline attack. See `assertKdfIsAcceptable` in
 * `kdf.ts` for the validation of this value when it comes from the server.
 *
 * @param password Secret to stretch.
 * @param salt Salt, which must be identical across all clients.
 * @param iterations Iteration count.
 * @param lengthBytes Desired output length.
 * @returns Derived key.
 * @throws {RangeError} If `iterations` is below 1.
 */
export async function pbkdf2Sha256(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  lengthBytes = 32,
): Promise<Uint8Array> {
  if (iterations < 1) {
    throw new RangeError('pbkdf2Sha256: at least 1 iteration is required');
  }

  const baseKey = await subtle.importKey('raw', asBufferSource(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'PBKDF2', salt: asBufferSource(salt), iterations, hash: 'SHA-256' },
    baseKey,
    lengthBytes * 8,
  );
  return new Uint8Array(bits);
}

/**
 * Applies HKDF-SHA256's Expand step, without Extract (RFC 5869 §2.3).
 *
 * ## Why not WebCrypto's HKDF
 *
 * WebCrypto only exposes full HKDF, that is Extract followed by Expand.
 * Bitwarden applies Expand directly to the master key, which is already a
 * uniformly random 32-byte PRK produced by the KDF — Extract would add nothing.
 * Going through full HKDF would give a numerically different result and make
 * every existing vault unreadable. Hence this reimplementation, which amounts to
 * a loop of native HMACs.
 *
 * @param prk Starting pseudo-random key.
 * @param info Context label, which separates uses. Two distinct `info` values
 *   produce independent keys from the same PRK.
 * @param lengthBytes Desired output length.
 * @returns Derived key of `lengthBytes` bytes.
 * @throws {RangeError} If the requested length exceeds 255 hash blocks.
 */
export async function hkdfExpandSha256(
  prk: Uint8Array,
  info: string | Uint8Array,
  lengthBytes: number,
): Promise<Uint8Array> {
  const HASH_LENGTH = 32;
  const blocks = Math.ceil(lengthBytes / HASH_LENGTH);
  if (blocks > 255) {
    throw new RangeError('hkdfExpandSha256: requested length exceeds 255 blocks');
  }

  const infoBytes = typeof info === 'string' ? toUtf8Bytes(info) : info;
  const out = new Uint8Array(lengthBytes);

  // The PRK is imported once for the whole loop.
  const prkKey = await importHmacSha256Key(prk);

  // T(0) = empty string; T(i) = HMAC(PRK, T(i-1) ‖ info ‖ i)
  let previous: Uint8Array = new Uint8Array(0);
  let offset = 0;

  for (let i = 1; i <= blocks; i++) {
    const block = await hmacSha256(prkKey, concatBytes(previous, infoBytes, Uint8Array.of(i)));
    out.set(block.subarray(0, Math.min(HASH_LENGTH, lengthBytes - offset)), offset);
    offset += HASH_LENGTH;
    // Each block is a slice of the derived key: copied out, then erased, so
    // the only copy left is the one the caller owns and can wipe.
    wipe(previous);
    previous = block;
  }
  wipe(previous);

  return out;
}

/**
 * Imports an RSA private key (PKCS#8) for RSA-OAEP decryption.
 *
 * WebCrypto fixes the OAEP hash at import time: Bitwarden's type 4 (the only
 * one actually emitted for sharing) uses SHA-1, type 3 uses SHA-256.
 *
 * SHA-1 is broken for collisions, not for OAEP: OAEP's security rests on MGF1
 * masking, not on collision resistance. This is Bitwarden's historical format,
 * non-negotiable for reading vaults.
 *
 * @param pkcs8 Private key in DER/PKCS#8 encoding.
 * @param hash OAEP hash function.
 * @returns Non-extractable handle, limited to decryption.
 */
export async function importRsaOaepPrivateKey(
  pkcs8: Uint8Array,
  hash: 'SHA-1' | 'SHA-256',
): Promise<CryptoKey> {
  return subtle.importKey('pkcs8', asBufferSource(pkcs8), { name: 'RSA-OAEP', hash }, false, [
    'decrypt',
  ]);
}

/**
 * Decrypts one RSA-OAEP block.
 *
 * @param privateKey Key imported by {@link importRsaOaepPrivateKey}.
 * @param data Encrypted block (256 bytes for RSA-2048).
 * @returns Plaintext.
 * @throws {DOMException} If the block does not decrypt under this key.
 */
export async function rsaOaepDecrypt(privateKey: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, asBufferSource(data)));
}

/**
 * Encrypts with AES-256-CBC and PKCS#7 padding.
 *
 * CBC provides **no authentication whatsoever**. This mode must never be used
 * alone: the caller is required to add a MAC. See `cryptoService.ts`, the only
 * legitimate entry point.
 *
 * @param key 32-byte key, raw or already imported.
 * @param iv 16-byte initialisation vector, unique per encryption.
 * @param plaintext Plaintext data.
 * @returns Ciphertext, padding included.
 */
export async function aesCbcEncrypt(
  key: Uint8Array | CryptoKey,
  iv: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await toAesKey(key);
  return new Uint8Array(
    await subtle.encrypt({ name: 'AES-CBC', iv: asBufferSource(iv) }, cryptoKey, asBufferSource(plaintext)),
  );
}

/**
 * Decrypts with AES-256-CBC and strips PKCS#7 padding.
 *
 * ## Warning
 *
 * Invalid padding throws, which constitutes a padding oracle an attacker can
 * exploit given the ability to submit arbitrary ciphertexts and observe the
 * outcome. The countermeasure is to **verify the MAC before calling this
 * function** — a forged ciphertext is then rejected without ever reaching AES.
 * `cryptoService.decryptBytes` enforces that rule; do not call this function
 * directly.
 *
 * @param key 32-byte key, raw or already imported.
 * @param iv 16-byte initialisation vector.
 * @param ciphertext Encrypted data.
 * @returns Plaintext.
 * @throws {DOMException} If the padding is invalid, which means a wrong key or
 *   tampered data.
 */
export async function aesCbcDecrypt(
  key: Uint8Array | CryptoKey,
  iv: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await toAesKey(key);
  return new Uint8Array(
    await subtle.decrypt({ name: 'AES-CBC', iv: asBufferSource(iv) }, cryptoKey, asBufferSource(ciphertext)),
  );
}
