/**
 * @file Format `EncString` de Bitwarden / Vaultwarden.
 *
 * C'est le format de sérialisation de toute donnée chiffrée échangée avec le
 * serveur : titres, mots de passe, notes, clés de coffre, clés d'organisation.
 *
 * ## Grammaire
 *
 * ```
 * encstring := type "." segment ( "|" segment )*
 * segment   := base64
 * ```
 *
 * ## Types
 *
 * | Type | Forme          | Algorithme                     | Statut          |
 * |------|----------------|--------------------------------|-----------------|
 * | 0    | `iv\|ct`        | AES-256-CBC, sans MAC          | legacy, lecture |
 * | 1    | `iv\|ct\|mac`    | AES-128-CBC + HMAC-SHA256      | obsolète        |
 * | 2    | `iv\|ct\|mac`    | AES-256-CBC + HMAC-SHA256      | **courant**     |
 * | 3    | `data`         | RSA-2048 OAEP SHA-256          | partage         |
 * | 4    | `data`         | RSA-2048 OAEP SHA-1            | legacy          |
 * | 5    | `data\|mac`     | RSA-2048 OAEP SHA-256 + HMAC   | legacy          |
 * | 6    | `data\|mac`     | RSA-2048 OAEP SHA-1 + HMAC     | legacy          |
 *
 * Zwarden n'émet que du type 2. Les autres sont analysables pour rester
 * interopérable avec des coffres existants, mais le déchiffrement applique ses
 * propres restrictions (voir `cryptoService.ts`).
 *
 * ## Rôle de sécurité de ce module
 *
 * L'analyse est la première frontière de confiance : ces chaînes viennent du
 * serveur, qui est considéré comme hostile. Les tailles d'IV et de MAC sont
 * donc validées ici, une fois, plutôt que supposées correctes plus loin dans
 * la chaîne. Une `EncString` construite est structurellement bien formée.
 */

import { fromBase64, toBase64 } from './encoding.js';

/** Identifiants de type, tels que sérialisés en préfixe. */
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

/** Taille d'un bloc AES, donc de l'IV, en octets. */
const IV_LENGTH = 16;

/** Taille d'une sortie HMAC-SHA256, en octets. */
const MAC_LENGTH = 32;

/**
 * Description structurelle d'un type de chiffrement.
 *
 * Cette table remplace un raisonnement implicite sur le nombre de segments.
 * Ajouter un type se fait ici et nulle part ailleurs.
 */
interface TypeShape {
  /** Le premier segment est un IV (chiffrement symétrique par blocs). */
  readonly hasIv: boolean;
  /** Un segment de MAC est présent en dernière position. */
  readonly hasMac: boolean;
}

const SHAPES: Readonly<Record<number, TypeShape>> = {
  [EncryptionType.AesCbc256_B64]: { hasIv: true, hasMac: false },
  [EncryptionType.AesCbc128_HmacSha256_B64]: { hasIv: true, hasMac: true },
  [EncryptionType.AesCbc256_HmacSha256_B64]: { hasIv: true, hasMac: true },
  [EncryptionType.Rsa2048_OaepSha256_B64]: { hasIv: false, hasMac: false },
  [EncryptionType.Rsa2048_OaepSha1_B64]: { hasIv: false, hasMac: false },
  [EncryptionType.Rsa2048_OaepSha256_HmacSha256_B64]: { hasIv: false, hasMac: true },
  [EncryptionType.Rsa2048_OaepSha1_HmacSha256_B64]: { hasIv: false, hasMac: true },
};

/** Nombre de segments attendus pour une forme donnée. */
function segmentCount(shape: TypeShape): number {
  // ciphertext, toujours présent ; + IV éventuel ; + MAC éventuel.
  return 1 + (shape.hasIv ? 1 : 0) + (shape.hasMac ? 1 : 0);
}

/** Levée lorsqu'une chaîne ne respecte pas la grammaire ou les tailles. */
export class EncStringParseError extends Error {
  override readonly name = 'EncStringParseError';
}

/**
 * Décode un segment base64 en convertissant tout échec en erreur du domaine.
 *
 * `atob` lève une `DOMException` peu parlante. On la traduit pour que les
 * appelants n'aient qu'un seul type d'erreur à intercepter, et pour que le
 * message identifie le segment fautif.
 */
function decodeSegment(segment: string, label: string): Uint8Array {
  try {
    return fromBase64(segment);
  } catch {
    throw new EncStringParseError(`segment « ${label} » : base64 invalide`);
  }
}

/** Décode un segment et vérifie sa longueur, pour l'IV et le MAC. */
function decodeFixedLength(segment: string, label: string, expected: number): Uint8Array {
  const bytes = decodeSegment(segment, label);
  if (bytes.length !== expected) {
    throw new EncStringParseError(
      `segment « ${label} » : ${bytes.length} octets, ${expected} attendus`,
    );
  }
  return bytes;
}

/**
 * Extrait et valide le préfixe numérique de type.
 *
 * @throws {EncStringParseError} Si le préfixe est absent ou non numérique.
 */
function parseTypePrefix(value: string): EncryptionType {
  const separator = value.indexOf('.');
  if (separator < 1) {
    throw new EncStringParseError('préfixe de type absent');
  }

  const raw = value.slice(0, separator);
  if (!/^\d+$/.test(raw)) {
    throw new EncStringParseError(`préfixe de type non numérique : « ${raw} »`);
  }

  return Number(raw) as EncryptionType;
}

/**
 * Donnée chiffrée analysée et structurellement validée.
 *
 * Immuable. Instanciable uniquement via {@link EncString.parse} ou
 * {@link EncString.fromParts}, ce qui garantit qu'aucune instance ne porte un
 * IV ou un MAC de taille aberrante.
 */
export class EncString {
  private constructor(
    /** Type de chiffrement, déterminant l'interprétation des segments. */
    readonly encryptionType: EncryptionType,
    /** IV de 16 octets pour les types symétriques, `undefined` pour RSA. */
    readonly iv: Uint8Array | undefined,
    /** Donnée chiffrée. */
    readonly ciphertext: Uint8Array,
    /** MAC de 32 octets si le type est authentifié, sinon `undefined`. */
    readonly mac: Uint8Array | undefined,
  ) {}

  /**
   * Construit une `EncString` à partir de composants déjà en mémoire.
   *
   * Réservé à la sortie du chiffrement et aux tests. N'effectue pas les
   * validations de taille de {@link EncString.parse} : l'appelant est
   * responsable de la cohérence.
   */
  static fromParts(
    encryptionType: EncryptionType,
    iv: Uint8Array | undefined,
    ciphertext: Uint8Array,
    mac: Uint8Array | undefined,
  ): EncString {
    return new EncString(encryptionType, iv, ciphertext, mac);
  }

  /**
   * Analyse une chaîne sérialisée.
   *
   * Échoue bruyamment plutôt que de renvoyer `null` : une `EncString`
   * malformée traduit soit une corruption du coffre, soit une réponse serveur
   * falsifiée. Dans les deux cas l'anomalie doit remonter. Utiliser
   * {@link EncString.parseOrNull} pour les champs dont l'absence est normale.
   *
   * @param value Chaîne à analyser.
   * @returns Instance validée.
   * @throws {EncStringParseError} Préfixe absent ou non numérique, type
   *   inconnu, nombre de segments incorrect, IV ou MAC de taille invalide.
   */
  static parse(value: string): EncString {
    const encryptionType = parseTypePrefix(value);
    const shape = SHAPES[encryptionType];
    if (shape === undefined) {
      throw new EncStringParseError(`type de chiffrement inconnu : ${encryptionType}`);
    }

    const segments = value.slice(value.indexOf('.') + 1).split('|');
    const expected = segmentCount(shape);
    if (segments.length !== expected) {
      throw new EncStringParseError(
        `type ${encryptionType} : ${expected} segment(s) attendu(s), ${segments.length} reçu(s)`,
      );
    }

    // Les segments sont consommés dans l'ordre : [iv] ciphertext [mac].
    let cursor = 0;
    const iv = shape.hasIv
      ? decodeFixedLength(segments[cursor++]!, 'iv', IV_LENGTH)
      : undefined;
    const ciphertext = decodeSegment(segments[cursor++]!, 'ciphertext');
    const mac = shape.hasMac
      ? decodeFixedLength(segments[cursor++]!, 'mac', MAC_LENGTH)
      : undefined;

    return new EncString(encryptionType, iv, ciphertext, mac);
  }

  /**
   * Variante tolérante de {@link EncString.parse}.
   *
   * Destinée aux champs optionnels du modèle serveur, où `null` et chaîne vide
   * signifient légitimement « absent ».
   *
   * @param value Chaîne, `null` ou `undefined`.
   * @returns Instance analysée, ou `null` si absente ou malformée.
   */
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

  /** `true` pour les types à chiffrement symétrique (0, 1, 2). */
  get isSymmetric(): boolean {
    return SHAPES[this.encryptionType]?.hasIv ?? false;
  }

  /** `true` si la donnée porte un MAC, donc est authentifiée. */
  get hasMac(): boolean {
    return this.mac !== undefined;
  }

  /**
   * Sérialise au format attendu par l'API.
   *
   * L'aller-retour `parse(s).toString() === s` est garanti pour toute chaîne
   * canonique (base64 standard, padding présent).
   */
  toString(): string {
    const segments: string[] = [];
    if (this.iv !== undefined) {
      segments.push(toBase64(this.iv));
    }
    segments.push(toBase64(this.ciphertext));
    if (this.mac !== undefined) {
      segments.push(toBase64(this.mac));
    }
    return `${this.encryptionType}.${segments.join('|')}`;
  }

  /** Permet à `JSON.stringify` de produire directement la forme sérialisée. */
  toJSON(): string {
    return this.toString();
  }
}
