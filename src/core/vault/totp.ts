/**
 * @file One-time codes (TOTP, RFC 6238).
 *
 * ## What the vault stores, and what to do with it
 *
 * A Bitwarden item's `totp` field has no single shape. Three cases occur in the
 * wild, and a manager that handles only one of them displays wrong codes:
 *
 * ```
 *   JBSWY3DPEHPK3PXP                    bare base32 secret
 *   otpauth://totp/GitHub:me?secret=…   full URI, with its parameters
 *   steam://…                           Steam variant (out of scope)
 * ```
 *
 * The URI may carry `digits`, `period` and `algorithm`: ignoring them would give
 * a six-digit code where the site expects eight, or a SHA-1 code where it expects
 * SHA-256. Those are silent failures — the code shows up, it is simply refused —
 * hence the explicit parsing here.
 *
 * ## Separation of concerns
 *
 * This module touches neither the vault, nor the network, nor the clock: `now`
 * is a parameter. That is what makes the RFC's vectors replayable as they stand.
 */

import { fromBase32 } from '../crypto/encoding.js';
import { type OtpAlgorithm, hmacForOtp } from '../crypto/primitives.js';

/** A TOTP generator's parameters, with defaults resolved. */
export interface TotpConfig {
  /** Shared secret, decoded. */
  readonly secret: Uint8Array;
  /** Number of digits in the code. */
  readonly digits: number;
  /** How long a code stays valid, in seconds. */
  readonly period: number;
  readonly algorithm: OtpAlgorithm;
}

/** Thrown when an item's `totp` field is unusable. */
export class TotpError extends Error {
  override readonly name = 'TotpError';
  readonly code = 'totp-invalid';
}

/** RFC 6238 defaults, the ones any silent site assumes. */
const DEFAULTS = { digits: 6, period: 30, algorithm: 'SHA-1' as OtpAlgorithm };

/** Translates a URI's algorithm name into WebCrypto's. */
function toWebCryptoAlgorithm(raw: string | null): OtpAlgorithm {
  switch (raw?.toUpperCase()) {
    case undefined:
    case 'SHA1':
    case 'SHA-1':
      return 'SHA-1';
    case 'SHA256':
    case 'SHA-256':
      return 'SHA-256';
    case 'SHA512':
    case 'SHA-512':
      return 'SHA-512';
    default:
      throw new TotpError(`Unsupported TOTP algorithm: ${raw}`);
  }
}

/** Reads an integer URI parameter, falling back if absent or absurd. */
function readInt(params: URLSearchParams, key: string, fallback: number, min: number, max: number): number {
  const raw = params.get(key);
  if (raw === null) {
    return fallback;
  }
  const value = Number.parseInt(raw, 10);
  // An out-of-range parameter is the site's data-entry mistake, not an
  // instruction: the RFC default beats an impossible code.
  return Number.isFinite(value) && value >= min && value <= max ? value : fallback;
}

/**
 * Parses an item's `totp` field.
 *
 * @param raw Decrypted field contents, a bare secret or an `otpauth://` URI.
 * @returns Resolved parameters, ready for {@link generateTotp}.
 * @throws {TotpError} Empty field, unknown scheme, missing or unreadable secret.
 */
export function parseTotp(raw: string): TotpConfig {
  const trimmed = raw.trim();
  if (trimmed === '') {
    throw new TotpError('Empty TOTP field');
  }

  if (!trimmed.toLowerCase().startsWith('otpauth://')) {
    return { secret: decodeSecret(trimmed), ...DEFAULTS };
  }

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    throw new TotpError('Unreadable otpauth:// URI');
  }
  if (url.host.toLowerCase() !== 'totp') {
    // `otpauth://hotp/…` is a counter, not a clock: showing a TOTP code for an
    // HOTP item would give a wrong code every single time.
    throw new TotpError(`Unsupported code type: ${url.host}`);
  }

  const secret = url.searchParams.get('secret');
  if (secret === null || secret === '') {
    throw new TotpError('otpauth:// URI without a secret parameter');
  }

  return {
    secret: decodeSecret(secret),
    digits: readInt(url.searchParams, 'digits', DEFAULTS.digits, 6, 10),
    period: readInt(url.searchParams, 'period', DEFAULTS.period, 1, 300),
    algorithm: toWebCryptoAlgorithm(url.searchParams.get('algorithm')),
  };
}

function decodeSecret(raw: string): Uint8Array {
  let secret: Uint8Array;
  try {
    secret = fromBase32(raw);
  } catch (error) {
    throw new TotpError(`Unreadable TOTP secret: ${(error as Error).message}`);
  }
  if (secret.length === 0) {
    throw new TotpError('Empty TOTP secret');
  }
  return secret;
}

/**
 * Computes the current code.
 *
 * @param config Parameters resolved by {@link parseTotp}.
 * @param now Instant, in milliseconds since the epoch.
 * @returns The code, zero-padded on the left to the requested length.
 */
export async function generateTotp(config: TotpConfig, now: number = Date.now()): Promise<string> {
  const counter = Math.floor(now / 1000 / config.period);

  // 8-byte big-endian counter. `BigInt` rather than a shift: past 2^31
  // JavaScript's bitwise operators fall back to signed 32 bits — the bug waits
  // until 2038 to show itself.
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(counter), false);

  const mac = await hmacForOtp(config.algorithm, config.secret, bytes);

  // Dynamic truncation, RFC 4226 §5.3.
  const offset = mac[mac.length - 1]! & 0x0f;
  const binary =
    ((mac[offset]! & 0x7f) << 24) |
    ((mac[offset + 1]! & 0xff) << 16) |
    ((mac[offset + 2]! & 0xff) << 8) |
    (mac[offset + 3]! & 0xff);

  return String(binary % 10 ** config.digits).padStart(config.digits, '0');
}

/**
 * Seconds left before the current code expires.
 *
 * @param config Resolved parameters.
 * @param now Instant, in milliseconds since the epoch.
 */
export function secondsRemaining(config: TotpConfig, now: number = Date.now()): number {
  return config.period - Math.floor(now / 1000) % config.period;
}

/** Inserts a space in the middle of the code: `123456` → `123 456`. */
export function formatTotp(code: string): string {
  const half = Math.ceil(code.length / 2);
  return `${code.slice(0, half)} ${code.slice(half)}`;
}
