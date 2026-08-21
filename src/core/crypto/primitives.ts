/**
 * Primitives cryptographiques, adossées à WebCrypto.
 *
 * Choix structurant du projet : tout ce qui peut être fait par WebCrypto l'est.
 * L'implémentation native est en code natif, à temps constant, auditée par les
 * équipes navigateur — et elle pèse 0 octet dans notre bundle. On ne charge du
 * WASM que pour Argon2id, qui n'a pas d'équivalent natif.
 */

import { concatBytes, toUtf8Bytes } from './encoding.js';

const subtle = globalThis.crypto.subtle;

/**
 * Passe un Uint8Array à WebCrypto.
 *
 * Depuis TypeScript 5.7, `Uint8Array` est générique sur `ArrayBufferLike`, ce
 * qui inclut `SharedArrayBuffer` et n'est donc plus assignable à `BufferSource`.
 * Nos tampons ne sont jamais partagés. On confine la conversion ici plutôt que
 * de disséminer des casts dans tout le code.
 */
function buf(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  globalThis.crypto.getRandomValues(out);
  return out;
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle.digest('SHA-256', buf(data)));
}

export async function sha512(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle.digest('SHA-512', buf(data)));
}

export async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await subtle.importKey(
    'raw',
    buf(key),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return new Uint8Array(await subtle.sign('HMAC', cryptoKey, buf(data)));
}

export async function pbkdf2Sha256(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  lengthBytes = 32,
): Promise<Uint8Array> {
  if (iterations < 1) {
    throw new RangeError('pbkdf2 : itérations >= 1 requis');
  }
  const baseKey = await subtle.importKey('raw', buf(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'PBKDF2', salt: buf(salt), iterations, hash: 'SHA-256' },
    baseKey,
    lengthBytes * 8,
  );
  return new Uint8Array(bits);
}

/**
 * HKDF-Expand seul (RFC 5869 §2.3), sans l'étape Extract.
 *
 * WebCrypto n'expose que HKDF complet (Extract + Expand). Bitwarden applique
 * Expand directement sur la clé maître, qui est déjà une PRK de 32 octets
 * uniformément aléatoire — passer par Extract donnerait un résultat différent
 * et casserait la compatibilité des coffres. D'où cette implémentation.
 */
export async function hkdfExpandSha256(
  prk: Uint8Array,
  info: string | Uint8Array,
  lengthBytes: number,
): Promise<Uint8Array> {
  const HASH_LEN = 32;
  const blocks = Math.ceil(lengthBytes / HASH_LEN);
  if (blocks > 255) {
    throw new RangeError('hkdfExpand : longueur demandée > 255 blocs');
  }

  const infoBytes = typeof info === 'string' ? toUtf8Bytes(info) : info;
  const out = new Uint8Array(lengthBytes);
  let previous: Uint8Array = new Uint8Array(0);
  let offset = 0;

  for (let i = 1; i <= blocks; i++) {
    const block = await hmacSha256(prk, concatBytes(previous, infoBytes, Uint8Array.of(i)));
    const take = Math.min(HASH_LEN, lengthBytes - offset);
    out.set(block.subarray(0, take), offset);
    offset += take;
    previous = block;
  }

  return out;
}

export async function aesCbcEncrypt(
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await subtle.importKey('raw', buf(key), 'AES-CBC', false, ['encrypt']);
  return new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv: buf(iv) }, cryptoKey, buf(plaintext)));
}

export async function aesCbcDecrypt(
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await subtle.importKey('raw', buf(key), 'AES-CBC', false, ['decrypt']);
  return new Uint8Array(await subtle.decrypt({ name: 'AES-CBC', iv: buf(iv) }, cryptoKey, buf(ciphertext)));
}
