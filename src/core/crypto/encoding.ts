/**
 * @file Encoding conversions and safe comparisons.
 *
 * Project convention: all binary data travels as `Uint8Array`. No "binary
 * string" (a string whose every code unit stands for one byte) ever escapes
 * this module — that is a classic source of silent corruption the moment a byte
 * exceeds 0x7f and a `TextEncoder` passes over it.
 *
 * These functions handle key material and ciphertexts: any change here must
 * come with a round trip over all 256 byte values (see
 * `tests/encoding.test.ts`).
 */

/**
 * Chunk size used for `String.fromCharCode(...)`.
 *
 * The spread operator turns into a call with as many arguments as there are
 * elements; past a few tens of thousands, the stack overflows. 8192 stays well
 * below the limit while still amortising call overhead.
 */
const FROM_CHAR_CODE_CHUNK = 8192;

/**
 * Native base64 methods on `Uint8Array` (TC39 arraybuffer-base64 proposal),
 * available in recent target browsers. Detected once at module load; their
 * absence falls back to `btoa`/`atob`.
 *
 * The types are not in `lib.es2022` yet, hence the local widenings — confined
 * to these two constants.
 */
const NATIVE_TO_BASE64 = (Uint8Array.prototype as Uint8Array & { toBase64?: () => string })
  .toBase64;
const NATIVE_FROM_BASE64 = (
  Uint8Array as typeof Uint8Array & { fromBase64?: (input: string) => Uint8Array }
).fromBase64;

/**
 * Encodes bytes as standard base64 (RFC 4648 §4), with padding.
 *
 * Uses `Uint8Array.prototype.toBase64` where the platform offers it —
 * purpose-built native code, faster than `btoa` — otherwise {@link toBase64Js}.
 * A hand-written JS implementation measured slower than both (see
 * `scripts/bench-base64.mjs`): we do not reimplement what the platform does
 * better.
 *
 * @param bytes Bytes to encode.
 * @returns Base64 string with `=` padding.
 */
export function toBase64(bytes: Uint8Array): string {
  return NATIVE_TO_BASE64 !== undefined ? NATIVE_TO_BASE64.call(bytes) : toBase64Js(bytes);
}

/**
 * Fallback for {@link toBase64} on `btoa`, for platforms without
 * `Uint8Array.prototype.toBase64`. Exported so tests cover both paths whatever
 * the host platform.
 */
export function toBase64Js(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += FROM_CHAR_CODE_CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + FROM_CHAR_CODE_CHUNK));
  }
  return btoa(binary);
}

/**
 * Encodes bytes as unpadded base64url (RFC 4648 §5).
 *
 * The form the API's `Auth-Email` header expects, among others. Centralised
 * here to honour the module convention: no "binary string" travels anywhere
 * else.
 *
 * @param bytes Bytes to encode.
 * @returns Base64url string, without trailing `=`.
 */
export function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Decodes a base64 string into bytes.
 *
 * Deliberately lenient on input: whitespace and newlines are ignored, and the
 * URL-safe alphabet (`-` and `_`) is accepted. Payloads pass through several
 * server implementations and third-party clients; refusing a perfectly
 * decryptable vault over a stray `\n` would be a functional regression with no
 * security benefit.
 *
 * Missing padding is restored: strict decoders reject it, but unpadded base64
 * remains unambiguously decodable.
 *
 * The decoding itself goes through `Uint8Array.fromBase64` where it exists,
 * otherwise {@link fromBase64Js}.
 *
 * @param input Base64 string, standard or URL-safe.
 * @returns Decoded bytes.
 * @throws {DOMException | SyntaxError} If the input holds characters outside
 *   the alphabet after normalisation.
 */
export function fromBase64(input: string): Uint8Array {
  const normalized = input.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), '=');

  return NATIVE_FROM_BASE64 !== undefined
    ? NATIVE_FROM_BASE64.call(Uint8Array, padded)
    : fromBase64Js(padded);
}

/**
 * Fallback for {@link fromBase64} on `atob`.
 *
 * Expects already-normalised input: standard alphabet, padding present — that
 * is {@link fromBase64}'s job. Exported so tests cover both paths whatever the
 * host platform.
 */
export function fromBase64Js(padded: string): Uint8Array {
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

/** Base32 alphabet, RFC 4648 — the one TOTP secrets use. */
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Thrown by {@link fromBase32} on a character outside the alphabet. */
export class Base32Error extends Error {
  override readonly name = 'Base32Error';
  readonly code = 'base32-invalid';
}

/**
 * Decodes base32 (RFC 4648).
 *
 * Used for TOTP secrets alone, which sites publish in this alphabet. Lenient
 * about shape — case-insensitive, spaces and dashes ignored, padding optional —
 * because those secrets get copied by hand from a web page or read out of a QR
 * code, and "2FA is broken" over one extra space would be baffling. Strict
 * about the alphabet, though: a foreign character signals a transcription
 * mistake, not a variant spelling.
 *
 * @param input Base32 string.
 * @returns Decoded bytes.
 * @throws {Base32Error} Character outside the alphabet.
 */
export function fromBase32(input: string): Uint8Array {
  const normalized = input.replace(/[\s-]/g, '').replace(/=+$/, '').toUpperCase();
  const out = new Uint8Array(Math.floor((normalized.length * 5) / 8));

  let buffer = 0;
  let bits = 0;
  let written = 0;
  for (const char of normalized) {
    const value = BASE32_ALPHABET.indexOf(char);
    if (value === -1) {
      throw new Base32Error(`Character outside the base32 alphabet: ${JSON.stringify(char)}`);
    }
    buffer = (buffer << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[written] = (buffer >> bits) & 0xff;
      written += 1;
    }
  }
  // The leftover bits (< 8) are the last letter's padding: ignoring them is
  // what the RFC prescribes.
  return out.subarray(0, written);
}

const UTF8_ENCODER = /* @__PURE__ */ new TextEncoder();
const UTF8_DECODER = /* @__PURE__ */ new TextDecoder('utf-8', { fatal: false });

/**
 * Encodes text as UTF-8.
 *
 * @param text Source text.
 * @returns UTF-8 bytes.
 */
export function toUtf8Bytes(text: string): Uint8Array {
  return UTF8_ENCODER.encode(text);
}

/**
 * Decodes UTF-8 bytes into text.
 *
 * The decoder is non-strict (`fatal: false`): an invalid sequence yields U+FFFD
 * rather than an exception. That is deliberate — a corrupted vault field must
 * stay displayable and reportable, not fail the whole sync.
 *
 * @param bytes UTF-8 bytes.
 * @returns Decoded text, invalid characters replaced by U+FFFD.
 */
export function fromUtf8Bytes(bytes: Uint8Array): string {
  return UTF8_DECODER.decode(bytes);
}

/**
 * Concatenates several buffers into one.
 *
 * @param parts Buffers to concatenate, in order.
 * @returns A new buffer holding the concatenation.
 */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const part of parts) {
    total += part.length;
  }

  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/**
 * Compares two buffers in constant time.
 *
 * Indispensable for MAC verification. A naive comparison stops at the first
 * differing byte: the response time then reveals how many leading bytes are
 * correct, which lets an attacker forge a valid MAC byte by byte in 256 × 32
 * requests instead of 2^256.
 *
 * The duration depends only on the input lengths, never on their contents. MACs
 * here are always 32 bytes, so the length is not a secret; we avoid any early
 * return all the same.
 *
 * @param a First buffer.
 * @param b Second buffer.
 * @returns `true` if the buffers are identical.
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  let diff = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

/**
 * Overwrites a sensitive buffer in place.
 *
 * Best-effort, and known to be. A JS engine with a generational GC may have
 * copied the buffer during a memory promotion, and nothing in JavaScript can
 * guarantee those copies are erased. This narrows the exposure window (memory
 * dumps, hibernation) without closing it.
 *
 * @param bytes Buffer to erase.
 */
export function wipe(bytes: Uint8Array): void {
  bytes.fill(0);
}
