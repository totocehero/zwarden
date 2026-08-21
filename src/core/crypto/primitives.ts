/**
 * @file Primitives cryptographiques, adossées à WebCrypto.
 *
 * ## Principe directeur
 *
 * Tout ce que WebCrypto sait faire est délégué à WebCrypto. L'implémentation
 * navigateur est en code natif, à temps constant, auditée en continu par les
 * équipes de sécurité de Chromium et Firefox — et elle ne pèse rien dans le
 * bundle. Réimplémenter AES ou SHA-2 en JavaScript ou en WASM apporterait du
 * poids, des canaux auxiliaires temporels, et une surface d'audit
 * supplémentaire, sans aucun gain.
 *
 * Seul Argon2id échappe à cette règle : il n'existe pas dans WebCrypto. Il est
 * traité à part, en import dynamique, dans `kdf.ts`.
 *
 * ## Portée
 *
 * Ce module n'expose que des transformations sans état. Toute la logique de
 * format vit dans `encString.ts`, et les décisions de sécurité (vérification
 * de MAC, refus de rétrogradation) dans `cryptoService.ts`. Ne rien ajouter
 * ici qui prenne une décision.
 */

import { concatBytes, toUtf8Bytes } from './encoding.js';

const subtle = globalThis.crypto.subtle;

/**
 * Adapte un `Uint8Array` à la signature attendue par WebCrypto.
 *
 * Depuis TypeScript 5.7, `Uint8Array` est générique sur `ArrayBufferLike`, ce
 * qui inclut `SharedArrayBuffer` et n'est donc plus assignable à `BufferSource`.
 * Nos tampons ne sont jamais adossés à de la mémoire partagée. On confine la
 * conversion à cette fonction plutôt que de disséminer des casts dans tout le
 * code cryptographique, où ils seraient difficiles à distinguer d'un vrai
 * contournement de typage.
 */
function asBufferSource(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

/**
 * Produit des octets cryptographiquement aléatoires.
 *
 * @param length Nombre d'octets voulus.
 * @returns Tampon rempli par le CSPRNG du système.
 */
export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  globalThis.crypto.getRandomValues(out);
  return out;
}

/**
 * Calcule un condensat SHA-256.
 *
 * @param data Données à condenser.
 * @returns Condensat de 32 octets.
 */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle.digest('SHA-256', asBufferSource(data)));
}

/**
 * Calcule un HMAC-SHA256.
 *
 * @param key Clé d'authentification. Toute longueur est acceptée : HMAC la
 *   condense ou la complète selon RFC 2104.
 * @param data Données à authentifier.
 * @returns MAC de 32 octets.
 */
export async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await subtle.importKey('raw', asBufferSource(key), { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
  ]);
  return new Uint8Array(await subtle.sign('HMAC', cryptoKey, asBufferSource(data)));
}

/**
 * Dérive une clé par PBKDF2-SHA256 (RFC 8018).
 *
 * Le coût de calcul est strictement proportionnel à `iterations` : c'est le
 * seul paramètre qui protège contre une attaque hors ligne. Voir
 * `assertKdfIsAcceptable` dans `kdf.ts` pour la validation de cette valeur
 * lorsqu'elle provient du serveur.
 *
 * @param password Secret à étirer.
 * @param salt Sel, qui doit être identique sur tous les clients.
 * @param iterations Nombre d'itérations.
 * @param lengthBytes Longueur de sortie souhaitée.
 * @returns Clé dérivée.
 * @throws {RangeError} Si `iterations` est inférieur à 1.
 */
export async function pbkdf2Sha256(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  lengthBytes = 32,
): Promise<Uint8Array> {
  if (iterations < 1) {
    throw new RangeError('pbkdf2Sha256 : au moins 1 itération requise');
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
 * Applique l'étape Expand de HKDF-SHA256, sans l'étape Extract (RFC 5869 §2.3).
 *
 * ## Pourquoi ne pas utiliser HKDF de WebCrypto
 *
 * WebCrypto n'expose que HKDF complet, soit Extract suivi d'Expand. Bitwarden
 * applique Expand directement sur la clé maître, qui est déjà une PRK de
 * 32 octets uniformément aléatoire produite par le KDF — Extract n'y ajouterait
 * rien. Passer par HKDF complet donnerait un résultat numériquement différent
 * et rendrait tous les coffres existants illisibles. D'où cette
 * réimplémentation, qui se limite à une boucle de HMAC natifs.
 *
 * @param prk Clé pseudo-aléatoire de départ.
 * @param info Étiquette de contexte, qui sépare les usages. Deux `info`
 *   distinctes produisent des clés indépendantes à partir de la même PRK.
 * @param lengthBytes Longueur de sortie souhaitée.
 * @returns Clé dérivée de `lengthBytes` octets.
 * @throws {RangeError} Si la longueur demandée dépasse 255 blocs de hash.
 */
export async function hkdfExpandSha256(
  prk: Uint8Array,
  info: string | Uint8Array,
  lengthBytes: number,
): Promise<Uint8Array> {
  const HASH_LENGTH = 32;
  const blocks = Math.ceil(lengthBytes / HASH_LENGTH);
  if (blocks > 255) {
    throw new RangeError('hkdfExpandSha256 : longueur demandée supérieure à 255 blocs');
  }

  const infoBytes = typeof info === 'string' ? toUtf8Bytes(info) : info;
  const out = new Uint8Array(lengthBytes);

  // T(0) = chaîne vide ; T(i) = HMAC(PRK, T(i-1) ‖ info ‖ i)
  let previous: Uint8Array = new Uint8Array(0);
  let offset = 0;

  for (let i = 1; i <= blocks; i++) {
    const block = await hmacSha256(prk, concatBytes(previous, infoBytes, Uint8Array.of(i)));
    out.set(block.subarray(0, Math.min(HASH_LENGTH, lengthBytes - offset)), offset);
    offset += HASH_LENGTH;
    previous = block;
  }

  return out;
}

/**
 * Chiffre en AES-256-CBC avec remplissage PKCS#7.
 *
 * CBC ne fournit **aucune authentification**. Ce mode ne doit jamais être
 * utilisé seul : l'appelant est tenu d'ajouter un MAC. Voir `cryptoService.ts`,
 * seul point d'entrée légitime.
 *
 * @param key Clé de 32 octets.
 * @param iv Vecteur d'initialisation de 16 octets, unique par chiffrement.
 * @param plaintext Données en clair.
 * @returns Ciphertext, remplissage inclus.
 */
export async function aesCbcEncrypt(
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await subtle.importKey('raw', asBufferSource(key), 'AES-CBC', false, ['encrypt']);
  return new Uint8Array(
    await subtle.encrypt({ name: 'AES-CBC', iv: asBufferSource(iv) }, cryptoKey, asBufferSource(plaintext)),
  );
}

/**
 * Déchiffre en AES-256-CBC et retire le remplissage PKCS#7.
 *
 * ## Avertissement
 *
 * Un remplissage invalide fait lever une exception, ce qui constitue un oracle
 * de padding exploitable si un attaquant peut soumettre des ciphertexts
 * arbitraires et observer le résultat. La contre-mesure est de **vérifier le
 * MAC avant d'appeler cette fonction** — un ciphertext falsifié est alors
 * rejeté sans jamais atteindre AES. `cryptoService.decryptBytes` applique cette
 * règle ; ne pas appeler cette fonction directement.
 *
 * @param key Clé de 32 octets.
 * @param iv Vecteur d'initialisation de 16 octets.
 * @param ciphertext Données chiffrées.
 * @returns Données en clair.
 * @throws {DOMException} Si le remplissage est invalide, ce qui traduit une
 *   mauvaise clé ou une donnée altérée.
 */
export async function aesCbcDecrypt(
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await subtle.importKey('raw', asBufferSource(key), 'AES-CBC', false, ['decrypt']);
  return new Uint8Array(
    await subtle.decrypt({ name: 'AES-CBC', iv: asBufferSource(iv) }, cryptoKey, asBufferSource(ciphertext)),
  );
}
