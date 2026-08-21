/**
 * Chiffrement / déchiffrement des EncString.
 *
 * Règle absolue appliquée ici : **Encrypt-then-MAC, MAC vérifié avant tout
 * déchiffrement**. Toute EncString de type 2 dont le MAC ne correspond pas est
 * rejetée sans que le ciphertext ne touche AES. C'est ce qui neutralise les
 * attaques par oracle de padding sur AES-CBC.
 */

import { EncString, EncryptionType } from './encString.js';
import { concatBytes, fromUtf8Bytes, timingSafeEqual, toUtf8Bytes } from './encoding.js';
import { aesCbcDecrypt, aesCbcEncrypt, hmacSha256, randomBytes } from './primitives.js';
import type { SymmetricCryptoKey } from './symmetricCryptoKey.js';

export class MacMismatchError extends Error {
  override readonly name = 'MacMismatchError';
  constructor() {
    super("Échec de vérification du MAC : donnée corrompue ou clé incorrecte");
  }
}

export class UnsupportedEncryptionError extends Error {
  override readonly name = 'UnsupportedEncryptionError';
}

/** MAC Bitwarden : HMAC-SHA256(macKey, iv || ciphertext). */
async function computeMac(
  macKey: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  return hmacSha256(macKey, concatBytes(iv, ciphertext));
}

/** Chiffre des octets bruts. Produit toujours une EncString de type 2. */
export async function encryptBytes(
  plaintext: Uint8Array,
  key: SymmetricCryptoKey,
): Promise<EncString> {
  if (key.macKey === undefined) {
    throw new UnsupportedEncryptionError(
      "Chiffrement refusé : clé sans MAC. NewVarden n'écrit jamais de données non authentifiées.",
    );
  }

  const iv = randomBytes(16);
  const ciphertext = await aesCbcEncrypt(key.encKey, iv, plaintext);
  const mac = await computeMac(key.macKey, iv, ciphertext);

  return EncString.fromParts(EncryptionType.AesCbc256_HmacSha256_B64, iv, ciphertext, mac);
}

export async function encryptString(
  plaintext: string,
  key: SymmetricCryptoKey,
): Promise<EncString> {
  return encryptBytes(toUtf8Bytes(plaintext), key);
}

/** Déchiffre vers des octets bruts, après vérification du MAC. */
export async function decryptBytes(
  encString: EncString,
  key: SymmetricCryptoKey,
): Promise<Uint8Array> {
  if (!encString.isSymmetric) {
    throw new UnsupportedEncryptionError(
      `Type ${encString.encryptionType} : déchiffrement RSA non pris en charge par ce service`,
    );
  }

  if (encString.encryptionType === EncryptionType.AesCbc128_HmacSha256_B64) {
    throw new UnsupportedEncryptionError(
      'Type 1 (AES-128) obsolète : ré-chiffrement du coffre requis',
    );
  }

  const iv = encString.iv!;

  if (encString.encryptionType === EncryptionType.AesCbc256_HmacSha256_B64) {
    if (key.macKey === undefined) {
      throw new UnsupportedEncryptionError('Donnée authentifiée mais clé sans macKey');
    }
    if (encString.mac === undefined) {
      throw new MacMismatchError();
    }

    // Vérification AVANT déchiffrement. Ne jamais inverser ces deux étapes.
    const expected = await computeMac(key.macKey, iv, encString.ciphertext);
    if (!timingSafeEqual(expected, encString.mac)) {
      throw new MacMismatchError();
    }

    return aesCbcDecrypt(key.encKey, iv, encString.ciphertext);
  }

  // Type 0 : legacy, aucune authentification. Toléré en lecture seule pour
  // permettre la migration d'anciens coffres.
  if (key.macKey !== undefined) {
    throw new UnsupportedEncryptionError(
      'EncString de type 0 (sans MAC) présentée avec une clé authentifiée : rejet par prudence',
    );
  }
  return aesCbcDecrypt(key.encKey, iv, encString.ciphertext);
}

export async function decryptString(
  encString: EncString,
  key: SymmetricCryptoKey,
): Promise<string> {
  return fromUtf8Bytes(await decryptBytes(encString, key));
}

/**
 * Déchiffre un champ optionnel du coffre.
 *
 * Un item corrompu ne doit pas faire échouer la synchronisation entière :
 * on renvoie `null` et l'appelant décide. Les erreurs sont remontées via
 * `onError` pour rester observables plutôt que silencieuses.
 */
export async function decryptStringOrNull(
  value: string | null | undefined,
  key: SymmetricCryptoKey,
  onError?: (error: unknown) => void,
): Promise<string | null> {
  if (value == null || value === '') {
    return null;
  }
  try {
    return await decryptString(EncString.parse(value), key);
  } catch (error) {
    onError?.(error);
    return null;
  }
}
