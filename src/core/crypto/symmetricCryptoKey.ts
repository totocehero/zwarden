/**
 * @file Clé symétrique du coffre.
 *
 * Deux formes coexistent dans l'écosystème Bitwarden, et la longueur du tampon
 * suffit à les distinguer — il n'y a pas de champ de type sur le fil :
 *
 * - **32 octets** : `encKey` seule. Chiffrement sans authentification (type 0).
 *   Forme legacy, conservée en lecture pour les coffres anciens. C'est aussi la
 *   forme de la clé maître brute issue du KDF, avant étirement.
 * - **64 octets** : `encKey` (32) ‖ `macKey` (32). Chiffrement authentifié
 *   (type 2). Forme utilisée pour tout ce que Zwarden écrit.
 *
 * ## Pourquoi deux clés distinctes
 *
 * Réutiliser la même clé pour AES et pour HMAC est une faute de conception
 * classique : les deux primitives n'ont pas les mêmes exigences, et leur
 * composition n'offre plus de garantie prouvée. Les deux moitiés sont donc
 * dérivées indépendamment (HKDF-Expand avec les étiquettes `enc` et `mac`,
 * voir `kdf.ts`).
 */

import { EncryptionType } from './encString.js';
import { fromBase64, toBase64, wipe } from './encoding.js';
import { importAesCbcKey, importHmacSha256Key, randomBytes } from './primitives.js';

/** Longueur d'une clé sans authentification, en octets. */
const UNAUTHENTICATED_LENGTH = 32;

/** Longueur d'une clé authentifiée (`encKey` ‖ `macKey`), en octets. */
const AUTHENTICATED_LENGTH = 64;

export class SymmetricCryptoKey {
  /** Clé de chiffrement AES-256. Toujours 32 octets. */
  readonly encKey: Uint8Array;

  /** Clé d'authentification HMAC-SHA256, ou `undefined` pour une clé de 32 octets. */
  readonly macKey: Uint8Array | undefined;

  /** Type de chiffrement que cette clé permet de produire. */
  readonly encryptionType: EncryptionType;

  /**
   * Handles WebCrypto importés paresseusement, puis réutilisés.
   *
   * `subtle.importKey` coûte un aller-retour asynchrone : sans cache, chaque
   * chiffrement ou déchiffrement le paierait deux fois (AES + HMAC). Lors de la
   * synchronisation d'un coffre de N items avec la même clé, le cache économise
   * 2 N imports. Les handles sont non extractibles.
   */
  #encCryptoKey: Promise<CryptoKey> | undefined;
  #macCryptoKey: Promise<CryptoKey> | undefined;

  /**
   * @param key Matériel de clé brut, de 32 ou 64 octets. **Le tampon devient
   *   la propriété de la clé** : `encKey` et `macKey` sont des vues dessus,
   *   pas des copies. L'appelant ne doit plus ni le réutiliser ni l'effacer —
   *   c'est `destroy()` qui s'en charge au verrouillage.
   * @throws {RangeError} Pour toute autre longueur.
   */
  constructor(readonly key: Uint8Array) {
    switch (key.length) {
      case UNAUTHENTICATED_LENGTH:
        this.encKey = key;
        this.macKey = undefined;
        this.encryptionType = EncryptionType.AesCbc256_B64;
        break;

      case AUTHENTICATED_LENGTH:
        // `subarray` et non `slice` : vues sur le même tampon, pour que
        // `destroy()` efface effectivement encKey et macKey en une passe.
        this.encKey = key.subarray(0, 32);
        this.macKey = key.subarray(32, 64);
        this.encryptionType = EncryptionType.AesCbc256_HmacSha256_B64;
        break;

      default:
        throw new RangeError(
          `Longueur de clé non supportée : ${key.length} octets ` +
            `(${UNAUTHENTICATED_LENGTH} ou ${AUTHENTICATED_LENGTH} attendus)`,
        );
    }
  }

  /**
   * Reconstruit une clé depuis sa forme base64, telle que stockée ou reçue.
   *
   * @param value Clé encodée en base64.
   * @throws {RangeError} Si la longueur décodée est invalide.
   */
  static fromBase64(value: string): SymmetricCryptoKey {
    return new SymmetricCryptoKey(fromBase64(value));
  }

  /**
   * Génère une clé de coffre authentifiée.
   *
   * Utilisée à la création d'un compte et à la rotation de clé. Les 64 octets
   * proviennent directement du CSPRNG : aucune dérivation, la clé du coffre est
   * indépendante du mot de passe maître. C'est ce qui rend le changement de mot
   * de passe possible sans re-chiffrer le coffre.
   */
  static generate(): SymmetricCryptoKey {
    return new SymmetricCryptoKey(randomBytes(AUTHENTICATED_LENGTH));
  }

  /** `true` si la clé permet le chiffrement authentifié. */
  get isAuthenticated(): boolean {
    return this.macKey !== undefined;
  }

  /**
   * Handle AES-CBC importé, mis en cache au premier appel.
   *
   * @returns `CryptoKey` non extractible pour `encKey`.
   */
  getEncCryptoKey(): Promise<CryptoKey> {
    return (this.#encCryptoKey ??= importAesCbcKey(this.encKey));
  }

  /**
   * Handle HMAC-SHA256 importé, mis en cache au premier appel.
   *
   * @returns `CryptoKey` non extractible pour `macKey`.
   * @throws {RangeError} Si la clé fait 32 octets, donc sans `macKey`. Les
   *   appelants doivent tester `isAuthenticated` ou `macKey` avant.
   */
  getMacCryptoKey(): Promise<CryptoKey> {
    if (this.macKey === undefined) {
      throw new RangeError('Clé de 32 octets : aucune macKey à importer');
    }
    return (this.#macCryptoKey ??= importHmacSha256Key(this.macKey));
  }

  /** Encode la clé en base64, pour stockage ou transmission. */
  toBase64(): string {
    return toBase64(this.key);
  }

  /**
   * Efface le matériel de clé en place.
   *
   * À appeler au verrouillage du coffre. Best-effort assumé : un moteur JS à
   * GC générationnel a pu recopier le tampon lors d'une promotion mémoire, et
   * ces copies sont hors d'atteinte depuis JavaScript. Réduit la fenêtre
   * d'exposition sans l'éliminer.
   *
   * L'instance devient inutilisable : `encKey` et `macKey` sont des vues sur
   * le tampon effacé. Les handles WebCrypto en cache sont abandonnés ; non
   * extractibles, ils ne redonnent de toute façon jamais le matériel de clé,
   * et le GC les libérera.
   */
  destroy(): void {
    wipe(this.key);
    this.#encCryptoKey = undefined;
    this.#macCryptoKey = undefined;
  }
}
