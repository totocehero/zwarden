/**
 * @file Chiffrement et déchiffrement authentifiés des `EncString`.
 *
 * C'est le seul point du code autorisé à appeler AES. Toutes les décisions de
 * sécurité sont concentrées ici, pour qu'un audit n'ait qu'un fichier à lire.
 *
 * ## Construction : Encrypt-then-MAC
 *
 * ```
 *   iv  ← aléatoire, 16 octets
 *   ct  ← AES-256-CBC(encKey, iv, clair)
 *   mac ← HMAC-SHA256(macKey, iv ‖ ct)
 * ```
 *
 * `encKey` et `macKey` sont deux moitiés indépendantes d'une clé de 64 octets.
 * Le MAC couvre l'IV **et** le ciphertext : un IV falsifié, qui permettrait de
 * retourner des bits du premier bloc en clair, est donc détecté.
 *
 * Encrypt-then-MAC est la seule des trois compositions classiques (E&M, MtE,
 * EtM) qui soit génériquement sûre. Elle permet surtout de rejeter un
 * ciphertext falsifié **sans jamais le déchiffrer**.
 *
 * ## Trois règles, jamais négociables
 *
 * 1. **MAC vérifié avant déchiffrement.** AES-CBC lève une exception sur
 *    remplissage PKCS#7 invalide. Déchiffrer avant de vérifier transforme cette
 *    exception en oracle de padding : un attaquant capable de soumettre des
 *    ciphertexts et d'observer l'échec récupère le clair bloc par bloc, sans
 *    jamais connaître la clé. Inverser l'ordre des deux étapes dans
 *    {@link decryptBytes} suffit à rouvrir cette faille.
 *
 * 2. **Comparaison de MAC à temps constant.** Voir `timingSafeEqual`.
 *
 * 3. **Aucune rétrogradation.** Une donnée authentifiée resservie comme non
 *    authentifiée est rejetée. Sans cela, un serveur hostile retire simplement
 *    le MAC et annonce le type 0 pour retrouver l'oracle de padding neutralisé
 *    par la règle 1.
 */

import { EncString, EncryptionType } from './encString.js';
import { concatBytes, fromUtf8Bytes, timingSafeEqual, toUtf8Bytes } from './encoding.js';
import { aesCbcDecrypt, aesCbcEncrypt, hmacSha256, randomBytes } from './primitives.js';
import type { SymmetricCryptoKey } from './symmetricCryptoKey.js';

/**
 * Levée lorsque le MAC ne correspond pas.
 *
 * Signifie l'un de trois cas, volontairement indistinguables du point de vue de
 * l'appelant : donnée altérée, donnée corrompue, ou mauvaise clé.
 */
export class MacMismatchError extends Error {
  override readonly name = 'MacMismatchError';

  constructor() {
    super('Vérification du MAC échouée : donnée altérée, corrompue, ou clé incorrecte');
  }
}

/** Levée lorsqu'une combinaison type / clé est refusée par politique. */
export class UnsupportedEncryptionError extends Error {
  override readonly name = 'UnsupportedEncryptionError';
}

/** Taille d'un IV AES, en octets. */
const IV_LENGTH = 16;

/**
 * Calcule le MAC d'un couple (IV, ciphertext).
 *
 * L'ordre de concaténation fait partie du format sur le fil : le modifier
 * rendrait tous les coffres existants illisibles.
 */
async function computeMac(
  macKey: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  return hmacSha256(macKey, concatBytes(iv, ciphertext));
}

/**
 * Chiffre des octets bruts.
 *
 * Produit systématiquement du type 2 (AES-256-CBC + HMAC-SHA256). Zwarden
 * n'émet jamais de donnée non authentifiée, quelle que soit la configuration
 * du coffre.
 *
 * Un IV est tiré aléatoirement à chaque appel. Réutiliser un IV en CBC révèle
 * l'égalité des préfixes en clair entre deux messages.
 *
 * @param plaintext Données à chiffrer.
 * @param key Clé de 64 octets, authentifiée.
 * @returns `EncString` de type 2.
 * @throws {UnsupportedEncryptionError} Si la clé ne comporte pas de `macKey`.
 */
export async function encryptBytes(
  plaintext: Uint8Array,
  key: SymmetricCryptoKey,
): Promise<EncString> {
  if (key.macKey === undefined) {
    throw new UnsupportedEncryptionError(
      'Chiffrement refusé : clé de 32 octets, sans macKey. ' +
        "Zwarden n'écrit jamais de donnée non authentifiée.",
    );
  }

  const iv = randomBytes(IV_LENGTH);
  const ciphertext = await aesCbcEncrypt(key.encKey, iv, plaintext);
  const mac = await computeMac(key.macKey, iv, ciphertext);

  return EncString.fromParts(EncryptionType.AesCbc256_HmacSha256_B64, iv, ciphertext, mac);
}

/**
 * Chiffre du texte, encodé en UTF-8.
 *
 * @param plaintext Texte à chiffrer.
 * @param key Clé de 64 octets, authentifiée.
 * @returns `EncString` de type 2.
 * @throws {UnsupportedEncryptionError} Si la clé ne comporte pas de `macKey`.
 */
export async function encryptString(
  plaintext: string,
  key: SymmetricCryptoKey,
): Promise<EncString> {
  return encryptBytes(toUtf8Bytes(plaintext), key);
}

/**
 * Déchiffre vers des octets bruts, après vérification du MAC.
 *
 * Politique appliquée, du plus permissif au plus strict :
 *
 * | Type | Clé authentifiée | Résultat                                  |
 * |------|------------------|-------------------------------------------|
 * | 2    | oui              | MAC vérifié, puis déchiffrement            |
 * | 2    | non              | refus — clé inadaptée                      |
 * | 0    | non              | déchiffré — coffre legacy, à migrer        |
 * | 0    | oui              | refus — tentative de rétrogradation        |
 * | 1    | —                | refus — AES-128 obsolète                   |
 * | 3-6  | —                | refus — RSA, hors périmètre de ce service  |
 *
 * @param encString Donnée chiffrée analysée.
 * @param key Clé de déchiffrement.
 * @returns Données en clair.
 * @throws {MacMismatchError} Si le MAC est absent ou ne correspond pas.
 * @throws {UnsupportedEncryptionError} Si la combinaison type / clé est refusée.
 */
export async function decryptBytes(
  encString: EncString,
  key: SymmetricCryptoKey,
): Promise<Uint8Array> {
  switch (encString.encryptionType) {
    case EncryptionType.AesCbc256_HmacSha256_B64: {
      if (key.macKey === undefined) {
        throw new UnsupportedEncryptionError(
          'Donnée authentifiée présentée avec une clé de 32 octets, sans macKey',
        );
      }
      if (encString.mac === undefined) {
        // Type 2 sans MAC : structurellement impossible après `EncString.parse`,
        // donc forcément une instance construite à la main. Traité comme un
        // échec d'authentification, pas comme une erreur de programmation.
        throw new MacMismatchError();
      }

      const iv = encString.iv!;

      // Ordre critique : vérifier, puis seulement déchiffrer. Voir l'en-tête.
      const expected = await computeMac(key.macKey, iv, encString.ciphertext);
      if (!timingSafeEqual(expected, encString.mac)) {
        throw new MacMismatchError();
      }

      return aesCbcDecrypt(key.encKey, iv, encString.ciphertext);
    }

    case EncryptionType.AesCbc256_B64: {
      if (key.macKey !== undefined) {
        throw new UnsupportedEncryptionError(
          'Donnée de type 0 (non authentifiée) présentée avec une clé authentifiée : ' +
            'rétrogradation refusée',
        );
      }
      // Coffre legacy assumé : aucune garantie d'intégrité. Toléré uniquement
      // pour permettre la lecture puis la migration vers le type 2.
      return aesCbcDecrypt(key.encKey, encString.iv!, encString.ciphertext);
    }

    case EncryptionType.AesCbc128_HmacSha256_B64:
      throw new UnsupportedEncryptionError(
        'Type 1 (AES-128) obsolète : le coffre doit être ré-chiffré en type 2',
      );

    default:
      throw new UnsupportedEncryptionError(
        `Type ${encString.encryptionType} : chiffrement RSA, hors périmètre du service symétrique`,
      );
  }
}

/**
 * Déchiffre vers du texte UTF-8.
 *
 * @param encString Donnée chiffrée analysée.
 * @param key Clé de déchiffrement.
 * @returns Texte en clair.
 * @throws {MacMismatchError} Si le MAC est absent ou ne correspond pas.
 * @throws {UnsupportedEncryptionError} Si la combinaison type / clé est refusée.
 */
export async function decryptString(
  encString: EncString,
  key: SymmetricCryptoKey,
): Promise<string> {
  return fromUtf8Bytes(await decryptBytes(encString, key));
}

/**
 * Déchiffre un champ optionnel provenant du serveur.
 *
 * Un item corrompu ne doit pas faire échouer la synchronisation entière : la
 * fonction renvoie `null` et laisse l'appelant décider. Les erreurs restent
 * observables via `onError` — ne jamais les avaler en silence, un champ qui
 * disparaît sans trace est indiscernable d'une attaque de suppression.
 *
 * @param value Chaîne sérialisée, `null` ou `undefined`.
 * @param key Clé de déchiffrement.
 * @param onError Notification d'échec, pour journalisation ou télémétrie.
 * @returns Texte en clair, ou `null` si le champ est absent ou illisible.
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
