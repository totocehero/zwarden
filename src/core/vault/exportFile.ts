/**
 * @file The encrypted export file: its shape, and how it is sealed.
 *
 * ## Encrypted only
 *
 * There is no cleartext export, and there will not be one. Bitwarden offers a
 * plain JSON export, and the predictable result is a file holding every
 * password a person has, sitting in a downloads folder, surviving every backup
 * and every disk resale. A feature whose most likely outcome is that is not a
 * feature.
 *
 * ## The envelope
 *
 * ```json
 * {
 *   "format": "zwarden-export", "version": 1,
 *   "kdf": { "type": "argon2id", "iterations": 3, "memoryMiB": 64, "parallelism": 4 },
 *   "salt": "…", "nonce": "…", "data": "…"
 * }
 * ```
 *
 * Argon2id over a **random per-file salt**, then AES-256-GCM. Two exports of
 * the same vault with the same passphrase share no bytes, which matters more
 * than it looks: identical files would tell anyone holding both that nothing
 * had changed between them.
 *
 * ## Why the header is authenticated too
 *
 * The KDF parameters travel in clear — they have to, since they are needed
 * before the key exists. That invites the obvious attack: rewrite
 * `iterations: 3` to `iterations: 2` and hand the file back, hoping it is
 * re-encrypted under something cheaper to crack.
 *
 * It does not work here, because the header is fed to AES-GCM as additional
 * authenticated data. Change a parameter and the tag fails: the file refuses to
 * open rather than opening weaker. The alternative — trusting that a wrong key
 * simply yields rubbish — happens to hold for this construction, but it holds
 * by luck, and binding the header states the intent.
 *
 * ## What is inside
 *
 * Bitwarden's own unencrypted-export shape, so a decrypted Zwarden export can
 * be imported straight into Bitwarden or Vaultwarden. Leaving is a feature, not
 * an oversight: a vault one cannot take elsewhere is a vault one is locked
 * into, and that is the position this project exists to argue against.
 */

import { fromBase64, toBase64, toUtf8Bytes } from '../crypto/encoding.js';
import { type Argon2Config, ARGON2_DEFAULTS, KdfType, deriveFromPassphrase } from '../crypto/kdf.js';
import { wipe } from '../crypto/encoding.js';

/** What the file says it is. Refused if either differs. */
const FORMAT = 'zwarden-export';
const VERSION = 1;

/** Bytes of AES-GCM nonce, and of the per-file salt. */
const NONCE_LENGTH = 12;
const SALT_LENGTH = 16;

/**
 * Argon2id parameters for an export.
 *
 * Deliberately the vault's own defaults rather than something heavier. An
 * export is opened on a machine that may not be this one, years later, possibly
 * a weak one; parameters nobody can afford to run are a backup nobody can
 * restore.
 */
export const EXPORT_KDF: Argon2Config = {
  type: KdfType.Argon2id,
  iterations: ARGON2_DEFAULTS.iterations,
  memoryMiB: ARGON2_DEFAULTS.memoryMiB,
  parallelism: ARGON2_DEFAULTS.parallelism,
};

/** One exported item, in Bitwarden's unencrypted-export shape. */
export interface ExportedItem {
  readonly id: string;
  readonly type: number;
  readonly name: string;
  readonly notes: string | null;
  readonly favorite: boolean;
  readonly folderId: string | null;
  readonly login?: {
    readonly username: string | null;
    readonly password: string | null;
    readonly totp: string | null;
    readonly uris: readonly { readonly uri: string }[];
  };
  readonly card?: Readonly<Record<string, string | null>>;
  readonly identity?: Readonly<Record<string, string | null>>;
}

/** The whole cleartext payload, as Bitwarden writes it. */
export interface ExportPayload {
  /** Always `false`: this is the *inside* of the envelope, already decrypted. */
  readonly encrypted: false;
  readonly folders: readonly { readonly id: string; readonly name: string }[];
  readonly items: readonly ExportedItem[];
}

/** Why an export could not be opened. */
export class ExportError extends Error {
  override readonly name = 'ExportError';
  constructor(readonly code: 'not-an-export' | 'wrong-passphrase' | 'unsupported-version') {
    super(code);
  }
}

/**
 * The bytes bound into the AES-GCM tag alongside the ciphertext.
 *
 * An array rather than the header object: `JSON.stringify` of an object depends
 * on key insertion order, which is a fragile thing to make a security property
 * of. A positional list says exactly what is covered, and adding a field to the
 * header without adding it here would be a visible omission rather than a
 * silent one.
 */
function authenticatedHeader(kdf: Argon2Config, saltB64: string): Uint8Array {
  return toUtf8Bytes(
    JSON.stringify([FORMAT, VERSION, kdf.iterations, kdf.memoryMiB, kdf.parallelism, saltB64]),
  );
}

/** Imports derived bytes as an AES-GCM key, non-extractable. */
async function gcmKey(material: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', material as BufferSource, 'AES-GCM', false, [
    'encrypt',
    'decrypt',
  ]);
}

/**
 * Seals a payload into an export file.
 *
 * @param payload The vault, decrypted.
 * @param passphrase The passphrase protecting the file. Never the vault key:
 *   an export that could be opened with something already stored would be a
 *   copy of the vault with extra steps.
 * @param kdf Argon2id parameters. Recorded in the file, and authenticated.
 * @returns The file's text, ready to be written out.
 */
export async function sealExport(
  payload: ExportPayload,
  passphrase: string,
  kdf: Argon2Config = EXPORT_KDF,
): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LENGTH));
  const saltB64 = toBase64(salt);

  const material = await deriveFromPassphrase(passphrase, salt, kdf);
  try {
    const key = await gcmKey(material);
    const sealed = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: nonce as BufferSource,
          additionalData: authenticatedHeader(kdf, saltB64) as BufferSource,
        },
        key,
        toUtf8Bytes(JSON.stringify(payload)) as BufferSource,
      ),
    );

    return `${JSON.stringify(
      {
        format: FORMAT,
        version: VERSION,
        kdf: {
          type: 'argon2id',
          iterations: kdf.iterations,
          memoryMiB: kdf.memoryMiB,
          parallelism: kdf.parallelism,
        },
        salt: saltB64,
        nonce: toBase64(nonce),
        data: toBase64(sealed),
      },
      null,
      2,
    )}\n`;
  } finally {
    // The derived key has no further use; the passphrase is the caller's.
    wipe(material);
  }
}

/** Reads a number the file claims, refusing anything that is not one. */
function readNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isInteger(value) ? value : null;
}

/**
 * Opens an export file.
 *
 * Every failure that could be a wrong passphrase **is reported as one**. A
 * tampered header, a truncated file and a mistyped passphrase all surface the
 * same way, because distinguishing them would tell whoever holds the file
 * which of its parts they got right.
 *
 * @param text The file's contents.
 * @param passphrase The passphrase it was sealed with.
 * @throws {ExportError} `not-an-export` if it is not one at all,
 *   `unsupported-version` if it comes from a later format, `wrong-passphrase`
 *   for everything else.
 */
export async function openExport(text: string, passphrase: string): Promise<ExportPayload> {
  let envelope: Record<string, unknown>;
  try {
    envelope = JSON.parse(text) as Record<string, unknown>;
  } catch {
    throw new ExportError('not-an-export');
  }

  if (envelope['format'] !== FORMAT) {
    throw new ExportError('not-an-export');
  }
  const version = readNumber(envelope['version']);
  if (version === null || version > VERSION) {
    // A file from a later version: say so, rather than blaming the passphrase
    // for something no passphrase can fix.
    throw new ExportError('unsupported-version');
  }

  const rawKdf = envelope['kdf'] as Record<string, unknown> | undefined;
  const iterations = readNumber(rawKdf?.['iterations']);
  const memoryMiB = readNumber(rawKdf?.['memoryMiB']);
  const parallelism = readNumber(rawKdf?.['parallelism']);
  const saltB64 = envelope['salt'];
  const nonceB64 = envelope['nonce'];
  const dataB64 = envelope['data'];
  if (
    rawKdf?.['type'] !== 'argon2id' ||
    iterations === null ||
    memoryMiB === null ||
    parallelism === null ||
    typeof saltB64 !== 'string' ||
    typeof nonceB64 !== 'string' ||
    typeof dataB64 !== 'string'
  ) {
    throw new ExportError('not-an-export');
  }

  const kdf: Argon2Config = { type: KdfType.Argon2id, iterations, memoryMiB, parallelism };

  let material: Uint8Array | undefined;
  try {
    // `deriveFromPassphrase` validates the parameters: a file claiming one
    // iteration, or a gibibyte of memory, is refused before any work is done.
    material = await deriveFromPassphrase(passphrase, fromBase64(saltB64), kdf);
    const plain = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: fromBase64(nonceB64) as BufferSource,
        additionalData: authenticatedHeader(kdf, saltB64) as BufferSource,
      },
      await gcmKey(material),
      fromBase64(dataB64) as BufferSource,
    );
    return JSON.parse(new TextDecoder().decode(plain)) as ExportPayload;
  } catch {
    throw new ExportError('wrong-passphrase');
  } finally {
    if (material !== undefined) {
      wipe(material);
    }
  }
}
