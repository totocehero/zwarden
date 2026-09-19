/**
 * @file Bitwarden / Vaultwarden's `EncString` format.
 *
 * This is the serialisation format of every piece of encrypted data exchanged
 * with the server: titles, passwords, notes, vault keys, organisation keys.
 *
 * ## Grammar
 *
 * ```
 * encstring := type "." segment ( "|" segment )*
 * segment   := base64
 * ```
 *
 * ## Types
 *
 * | Type | Shape          | Algorithm                      | Status           |
 * |------|----------------|--------------------------------|------------------|
 * | 0    | `iv\|ct`        | AES-256-CBC, no MAC            | legacy, read-only|
 * | 1    | `iv\|ct\|mac`    | AES-128-CBC + HMAC-SHA256      | obsolete         |
 * | 2    | `iv\|ct\|mac`    | AES-256-CBC + HMAC-SHA256      | **current**      |
 * | 3    | `data`         | RSA-2048 OAEP SHA-256          | sharing          |
 * | 4    | `data`         | RSA-2048 OAEP SHA-1            | legacy           |
 * | 5    | `data\|mac`     | RSA-2048 OAEP SHA-256 + HMAC   | legacy           |
 * | 6    | `data\|mac`     | RSA-2048 OAEP SHA-1 + HMAC     | legacy           |
 *
 * Zwarden only ever emits type 2. The others remain parseable to stay
 * interoperable with existing vaults, but decryption applies its own
 * restrictions (see `cryptoService.ts`).
 *
 * ## This module's security role
 *
 * Parsing is the first trust boundary: these strings come from the server, which
 * is treated as hostile. IV and MAC sizes, and the ciphertext's alignment on AES
 * blocks for the symmetric types, are therefore validated here, once, rather
 * than assumed correct further down the chain. A constructed `EncString` is
 * structurally well-formed.
 */

import { fromBase64, toBase64 } from './encoding.js';

/** Type identifiers, as serialised in the prefix. */
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

/** Size of an AES block, hence of the IV, in bytes. */
const IV_LENGTH = 16;

/** Size of an HMAC-SHA256 output, in bytes. */
const MAC_LENGTH = 32;

/**
 * Structural description of an encryption type.
 *
 * This table replaces implicit reasoning about segment counts. Adding a type
 * happens here and nowhere else.
 */
interface TypeShape {
  /** The first segment is an IV (symmetric block cipher). */
  readonly hasIv: boolean;
  /** A MAC segment is present in last position. */
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

/** Number of segments expected for a given shape. */
function segmentCount(shape: TypeShape): number {
  // ciphertext, always present; + optional IV; + optional MAC.
  return 1 + (shape.hasIv ? 1 : 0) + (shape.hasMac ? 1 : 0);
}

/** Thrown when a string violates the grammar or the expected sizes. */
export class EncStringParseError extends Error {
  override readonly name = 'EncStringParseError';
  /** Stable identifier for the UI: the messages are for logs. */
  readonly code = 'enc-string-parse';
}

/**
 * Decodes a base64 segment, turning any failure into a domain error.
 *
 * `atob` throws an uninformative `DOMException`. We translate it so callers have
 * a single error type to catch, and so the message names the offending segment.
 */
function decodeSegment(segment: string, label: string): Uint8Array {
  try {
    return fromBase64(segment);
  } catch {
    throw new EncStringParseError(`segment "${label}": invalid base64`);
  }
}

/** Decodes a segment and checks its length, for the IV and the MAC. */
function decodeFixedLength(segment: string, label: string, expected: number): Uint8Array {
  const bytes = decodeSegment(segment, label);
  if (bytes.length !== expected) {
    throw new EncStringParseError(
      `segment "${label}": ${bytes.length} bytes, ${expected} expected`,
    );
  }
  return bytes;
}

/**
 * Splits the numeric type prefix from the rest of the string.
 *
 * @throws {EncStringParseError} If the prefix is missing or not numeric.
 */
function splitTypePrefix(value: string): {
  readonly encryptionType: EncryptionType;
  readonly body: string;
} {
  const separator = value.indexOf('.');
  if (separator < 1) {
    throw new EncStringParseError('missing type prefix');
  }

  const raw = value.slice(0, separator);
  if (!/^\d+$/.test(raw)) {
    throw new EncStringParseError(`non-numeric type prefix: "${raw}"`);
  }

  return { encryptionType: Number(raw) as EncryptionType, body: value.slice(separator + 1) };
}

/**
 * Parsed, structurally validated encrypted data.
 *
 * Immutable. Instantiable only through {@link EncString.parse} or
 * {@link EncString.fromParts}, which guarantees no instance carries an IV or MAC
 * of nonsensical size.
 */
export class EncString {
  private constructor(
    /** Encryption type, which determines how the segments are read. */
    readonly encryptionType: EncryptionType,
    /** 16-byte IV for symmetric types, `undefined` for RSA. */
    readonly iv: Uint8Array | undefined,
    /** Encrypted data. */
    readonly ciphertext: Uint8Array,
    /** 32-byte MAC if the type is authenticated, otherwise `undefined`. */
    readonly mac: Uint8Array | undefined,
  ) {}

  /**
   * Builds an `EncString` from components already in memory.
   *
   * Reserved for the output of encryption and for tests. It does not perform
   * {@link EncString.parse}'s size validation: the caller is responsible for
   * consistency.
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
   * Parses a serialised string.
   *
   * Fails loudly rather than returning `null`: a malformed `EncString` means
   * either vault corruption or a tampered server response. Either way the
   * anomaly must surface. Use {@link EncString.parseOrNull} for fields whose
   * absence is normal.
   *
   * @param value String to parse.
   * @returns Validated instance.
   * @throws {EncStringParseError} Missing or non-numeric prefix, unknown type,
   *   wrong segment count, invalid IV or MAC size.
   */
  static parse(value: string): EncString {
    const { encryptionType, body } = splitTypePrefix(value);
    const shape = SHAPES[encryptionType];
    if (shape === undefined) {
      throw new EncStringParseError(`unknown encryption type: ${encryptionType}`);
    }

    const segments = body.split('|');
    const expected = segmentCount(shape);
    if (segments.length !== expected) {
      throw new EncStringParseError(
        `type ${encryptionType}: ${expected} segment(s) expected, ${segments.length} received`,
      );
    }

    // Segments are consumed in order: [iv] ciphertext [mac].
    let cursor = 0;
    const iv = shape.hasIv
      ? decodeFixedLength(segments[cursor++]!, 'iv', IV_LENGTH)
      : undefined;
    const ciphertext = decodeSegment(segments[cursor++]!, 'ciphertext');
    const mac = shape.hasMac
      ? decodeFixedLength(segments[cursor++]!, 'mac', MAC_LENGTH)
      : undefined;

    // For the symmetric types (CBC), a valid ciphertext is a non-zero whole
    // number of AES blocks: PKCS#7 always adds at least one byte, so even empty
    // plaintext produces one block. Rejecting here yields a domain error instead
    // of an opaque DOMException deep inside AES.
    if (shape.hasIv && (ciphertext.length === 0 || ciphertext.length % IV_LENGTH !== 0)) {
      throw new EncStringParseError(
        `segment "ciphertext": ${ciphertext.length} bytes, non-zero multiple of ${IV_LENGTH} expected`,
      );
    }

    return new EncString(encryptionType, iv, ciphertext, mac);
  }

  /**
   * Lenient variant of {@link EncString.parse}.
   *
   * Meant for the server model's optional fields, where `null` and the empty
   * string legitimately mean "absent". A **malformed** string, however, is not an
   * absence: `onError` is mandatory, as it is for `decryptStringOrNull` — a field
   * that vanishes without trace is indistinguishable from a deletion attack.
   *
   * @param value String, `null` or `undefined`.
   * @param onError Parse-failure notification, for logging.
   * @returns Parsed instance, or `null` if absent or malformed.
   */
  static parseOrNull(
    value: string | null | undefined,
    onError: (error: unknown) => void,
  ): EncString | null {
    if (value == null || value === '') {
      return null;
    }
    try {
      return EncString.parse(value);
    } catch (error) {
      onError(error);
      return null;
    }
  }

  /** `true` for the symmetrically encrypted types (0, 1, 2). */
  get isSymmetric(): boolean {
    return SHAPES[this.encryptionType]?.hasIv ?? false;
  }

  /** `true` if the data carries a MAC, hence is authenticated. */
  get hasMac(): boolean {
    return this.mac !== undefined;
  }

  /**
   * Serialises to the format the API expects.
   *
   * The round trip `parse(s).toString() === s` is guaranteed for any canonical
   * string (standard base64, padding present).
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

  /** Lets `JSON.stringify` produce the serialised form directly. */
  toJSON(): string {
    return this.toString();
  }
}
