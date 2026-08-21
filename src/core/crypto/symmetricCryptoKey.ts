/**
 * Clé symétrique du coffre.
 *
 * Deux formes existent dans l'écosystème Bitwarden :
 *   - 32 octets : chiffrement seul, sans authentification (type 0, legacy)
 *   - 64 octets : encKey (32) || macKey (32), AES-CBC + HMAC (type 2)
 *
 * Toute écriture produite par NewVarden utilise le type 2.
 */

import { EncryptionType } from './encString.js';
import { fromBase64, toBase64, wipe } from './encoding.js';

export class SymmetricCryptoKey {
  readonly encKey: Uint8Array;
  readonly macKey: Uint8Array | undefined;
  readonly encryptionType: EncryptionType;

  constructor(readonly key: Uint8Array) {
    switch (key.length) {
      case 32:
        this.encKey = key;
        this.macKey = undefined;
        this.encryptionType = EncryptionType.AesCbc256_B64;
        break;
      case 64:
        this.encKey = key.subarray(0, 32);
        this.macKey = key.subarray(32, 64);
        this.encryptionType = EncryptionType.AesCbc256_HmacSha256_B64;
        break;
      default:
        throw new RangeError(
          `Longueur de clé non supportée : ${key.length} octets (32 ou 64 attendus)`,
        );
    }
  }

  static fromBase64(value: string): SymmetricCryptoKey {
    return new SymmetricCryptoKey(fromBase64(value));
  }

  static generate(): SymmetricCryptoKey {
    const key = new Uint8Array(64);
    globalThis.crypto.getRandomValues(key);
    return new SymmetricCryptoKey(key);
  }

  get isAuthenticated(): boolean {
    return this.macKey !== undefined;
  }

  toBase64(): string {
    return toBase64(this.key);
  }

  /**
   * Efface le matériel de clé. À appeler au verrouillage du coffre.
   * Best-effort : le moteur JS a pu recopier le tampon (GC générationnel).
   */
  destroy(): void {
    wipe(this.key);
  }
}
