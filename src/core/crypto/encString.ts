/**
 * Format `EncString` de Bitwarden / Vaultwarden.
 *
 * Sérialisation : `<type>.<partie1>|<partie2>|<partie3>`
 *
 *   0.iv|ct            AES-256-CBC, sans MAC          (legacy, refusé en écriture)
 *   1.iv|ct|mac        AES-128-CBC + HMAC-SHA256      (legacy, refusé en écriture)
 *   2.iv|ct|mac        AES-256-CBC + HMAC-SHA256      <- format courant
 *   3.data             RSA-2048 OAEP SHA-256
 *   4.data             RSA-2048 OAEP SHA-1
 *   5.data|mac         RSA-2048 OAEP SHA-256 + HMAC   (legacy)
 *   6.data|mac         RSA-2048 OAEP SHA-1 + HMAC     (legacy)
 *
 * Le type 0 est accepté en lecture uniquement pour permettre la migration de
 * vieux coffres ; il n'offre aucune authentification et doit être ré-chiffré.
 */

import { fromBase64, toBase64 } from './encoding.js';

export const EncryptionType = {
  AesCbc256_B64: 0,
  AesCbc128_HmacSha256_B64: 1,
  AesCbc256_HmacSha256_B64: 2,
  Rsa2048_OaepSha256_B64: 3,
  Rsa2048_OaepSha1_B64: 4,
  Rsa2048_OaepSha256_HmacSha256_B64: 5,
  Rsa2048_OaepSha1_HmacSha256_B64: 6,
} as const;

export type EncryptionType = (typeof EncryptionType)[keyof typeof EncryptionType];

/** Nombre de segments séparés par `|` attendus pour chaque type. */
const SEGMENT_COUNT: Record<number, number> = {
  0: 2,
  1: 3,
  2: 3,
  3: 1,
  4: 1,
  5: 2,
  6: 2,
};

const SYMMETRIC_TYPES = new Set<number>([0, 1, 2]);

export class EncStringParseError extends Error {
  override readonly name = 'EncStringParseError';
}

export class EncString {
  private constructor(
    readonly encryptionType: EncryptionType,
    /** IV pour les types symétriques, `undefined` pour RSA. */
    readonly iv: Uint8Array | undefined,
    readonly ciphertext: Uint8Array,
    readonly mac: Uint8Array | undefined,
  ) {}

  static fromParts(
    encryptionType: EncryptionType,
    iv: Uint8Array | undefined,
    ciphertext: Uint8Array,
    mac: Uint8Array | undefined,
  ): EncString {
    return new EncString(encryptionType, iv, ciphertext, mac);
  }

  /**
   * Analyse une chaîne sérialisée. Lève `EncStringParseError` si la forme est
   * invalide — on ne renvoie jamais `null` silencieusement, une EncString
   * malformée est toujours une anomalie qui doit remonter.
   */
  static parse(value: string): EncString {
    const dot = value.indexOf('.');
    if (dot < 1) {
      throw new EncStringParseError('EncString sans préfixe de type');
    }

    const rawType = value.slice(0, dot);
    if (!/^[0-9]+$/.test(rawType)) {
      throw new EncStringParseError(`type non numérique : ${rawType}`);
    }
    const encryptionType = Number(rawType);
    const expected = SEGMENT_COUNT[encryptionType];
    if (expected === undefined) {
      throw new EncStringParseError(`type inconnu : ${encryptionType}`);
    }

    const segments = value.slice(dot + 1).split('|');
    if (segments.length !== expected) {
      throw new EncStringParseError(
        `type ${encryptionType} : ${expected} segment(s) attendu(s), ${segments.length} reçu(s)`,
      );
    }

    if (SYMMETRIC_TYPES.has(encryptionType)) {
      const iv = fromBase64(segments[0]!);
      if (iv.length !== 16) {
        throw new EncStringParseError(`IV de ${iv.length} octets, 16 attendus`);
      }
      const ciphertext = fromBase64(segments[1]!);
      const mac = expected === 3 ? fromBase64(segments[2]!) : undefined;
      if (mac !== undefined && mac.length !== 32) {
        throw new EncStringParseError(`MAC de ${mac.length} octets, 32 attendus`);
      }
      return new EncString(encryptionType as EncryptionType, iv, ciphertext, mac);
    }

    const ciphertext = fromBase64(segments[0]!);
    const mac = expected === 2 ? fromBase64(segments[1]!) : undefined;
    return new EncString(encryptionType as EncryptionType, undefined, ciphertext, mac);
  }

  /** Variante tolérante, pour les champs optionnels venant du serveur. */
  static parseOrNull(value: string | null | undefined): EncString | null {
    if (value == null || value === '') {
      return null;
    }
    try {
      return EncString.parse(value);
    } catch {
      return null;
    }
  }

  get isSymmetric(): boolean {
    return SYMMETRIC_TYPES.has(this.encryptionType);
  }

  get hasMac(): boolean {
    return this.mac !== undefined;
  }

  toString(): string {
    const head = `${this.encryptionType}.`;
    if (this.isSymmetric) {
      const base = `${toBase64(this.iv!)}|${toBase64(this.ciphertext)}`;
      return this.mac ? `${head}${base}|${toBase64(this.mac)}` : head + base;
    }
    const base = toBase64(this.ciphertext);
    return this.mac ? `${head}${base}|${toBase64(this.mac)}` : head + base;
  }

  toJSON(): string {
    return this.toString();
  }
}
