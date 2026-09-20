/**
 * @file Answering a WebAuthn assertion with a passkey from the vault.
 *
 * Until now the extension could *see* passkeys — it decrypts their metadata and
 * shows a badge — and could not use one. This is the part that signs.
 *
 * Everything here is pure or WebCrypto: no DOM, no messaging, no user
 * interface. What a browser asks for in a `navigator.credentials.get()` is a
 * precise sequence of bytes, and getting it wrong does not raise an error —
 * the site simply refuses the sign-in, with no clue as to why. So the shape is
 * built here, where it can be tested, and the plumbing lives elsewhere.
 *
 * ## The three pieces of an assertion
 *
 * 1. **`clientDataJSON`** — what the browser saw: the ceremony type, the
 *    challenge, the origin. It is hashed into the signature, which is what
 *    binds the signature to *this* site and *this* challenge.
 * 2. **`authenticatorData`** — what the authenticator did: a hash of the
 *    relying party's identifier, a byte of flags, a counter.
 * 3. **the signature**, over `authenticatorData ‖ SHA-256(clientDataJSON)`.
 *
 * ## The trap
 *
 * WebCrypto's ECDSA produces a **raw** signature: `r ‖ s`, sixty-four bytes.
 * WebAuthn requires **ASN.1 DER**. Nothing warns about this — the bytes are
 * accepted, the relying party's verification fails, and the sign-in is refused
 * with no explanation. {@link derFromRawSignature} is the conversion, and it is
 * tested by verifying a real signature both ways round.
 */

// `fromBase64` already normalises the URL-safe alphabet and restores missing
// padding, which is what WebAuthn hands around.
import { fromBase64, toBase64Url } from '../crypto/encoding.js';

/** A passkey, with its private key, ready to sign. */
export interface PasskeyCredential {
  /** The credential's identifier, base64url — what the site refers to it by. */
  readonly credentialId: string;
  /** The relying party, e.g. `github.com`. */
  readonly rpId: string;
  /** The account handle at that site, base64url. */
  readonly userHandle: string | null;
  /** The ECDSA P-256 private key, PKCS#8, base64url. */
  readonly keyValue: string;
  /** Signature counter as stored. Zero means "not counted" — see below. */
  readonly counter: number;
}

/** What the caller must supply for one assertion. */
export interface AssertionRequest {
  /** The relying party the page asked for. */
  readonly rpId: string;
  /** The page's origin, exactly as the browser saw it. */
  readonly origin: string;
  /** The challenge, raw bytes. */
  readonly challenge: Uint8Array;
  /** `true` once the user has been verified — a master password counts. */
  readonly userVerified: boolean;
}

/** The pieces a page needs to complete `navigator.credentials.get()`. */
export interface Assertion {
  readonly credentialId: string;
  readonly clientDataJSON: string;
  readonly authenticatorData: Uint8Array;
  readonly signature: Uint8Array;
  readonly userHandle: string | null;
}

/** Authenticator data flags, as the specification numbers them. */
const FLAG_USER_PRESENT = 0x01;
const FLAG_USER_VERIFIED = 0x04;
const FLAG_BACKUP_ELIGIBLE = 0x08;
const FLAG_BACKED_UP = 0x10;

/**
 * Which passkeys can answer this request.
 *
 * Generic over the shape, so the choice can be made from metadata alone: the
 * private key of the credential actually used is decrypted afterwards, and the
 * others never are.
 *
 * @param credentials Every passkey the vault holds — full credentials, or the
 *   metadata views that carry no private key.
 * @param rpId The relying party asking.
 * @param allowed The `allowCredentials` list, base64url ids — empty or absent
 *   means the site will take any credential it has for that party, which is
 *   what a passwordless sign-in looks like.
 * @returns The candidates, in the order they were given.
 */
export function selectCredentials<T extends { readonly credentialId: string; readonly rpId: string }>(
  credentials: readonly T[],
  rpId: string,
  allowed: readonly string[] = [],
): readonly T[] {
  // The relying party must match exactly. A passkey for `example.com` must
  // never answer `evil-example.com`, and a prefix or suffix test is how that
  // happens.
  const forParty = credentials.filter((credential) => credential.rpId === rpId);
  if (allowed.length === 0) {
    return forParty;
  }
  const wanted = new Set(allowed);
  return forParty.filter((credential) => wanted.has(credential.credentialId));
}

/**
 * Builds `clientDataJSON`.
 *
 * Assembled by hand rather than through `JSON.stringify` of an object: the
 * relying party hashes these exact bytes, so the key order and the spacing are
 * part of the contract. An object literal would leave that to the engine.
 *
 * @param challenge The challenge, raw bytes.
 * @param origin The page's origin.
 * @param type `webauthn.get` for an assertion.
 */
export function buildClientData(
  challenge: Uint8Array,
  origin: string,
  type = 'webauthn.get',
): string {
  return JSON.stringify({
    type,
    challenge: toBase64Url(challenge),
    origin,
    crossOrigin: false,
  });
}

/**
 * Builds `authenticatorData`: 37 bytes for an assertion.
 *
 * `rpIdHash` (32) ‖ `flags` (1) ‖ `signCount` (4, big-endian).
 *
 * The counter stays at whatever the vault holds, and for a passkey that is
 * normally zero. A signature counter exists to detect a *cloned* hardware
 * authenticator; a passkey synced across a user's devices is cloned by design,
 * so the specification's answer is to report zero and let the relying party
 * skip the check. Inventing an increasing counter would be claiming a property
 * this does not have.
 *
 * The backup flags are set because that is exactly what this is: a credential
 * that exists in more than one place, on purpose. Relying parties use them to
 * decide whether to offer a second factor.
 */
export async function buildAuthenticatorData(
  rpId: string,
  userVerified: boolean,
  counter = 0,
): Promise<Uint8Array> {
  const rpIdHash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpId)),
  );

  let flags = FLAG_USER_PRESENT | FLAG_BACKUP_ELIGIBLE | FLAG_BACKED_UP;
  if (userVerified) {
    flags |= FLAG_USER_VERIFIED;
  }

  const data = new Uint8Array(37);
  data.set(rpIdHash, 0);
  data[32] = flags;
  new DataView(data.buffer).setUint32(33, counter, false);
  return data;
}

/** Strips the leading zeros DER forbids, and adds one back if the top bit is set. */
function derInteger(bytes: Uint8Array): Uint8Array {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) {
    start += 1;
  }
  const trimmed = bytes.subarray(start);
  // A leading bit of 1 would read as a negative number: DER prefixes a zero.
  const needsPad = (trimmed[0]! & 0x80) !== 0;
  const out = new Uint8Array(2 + (needsPad ? 1 : 0) + trimmed.length);
  out[0] = 0x02; // INTEGER
  out[1] = trimmed.length + (needsPad ? 1 : 0);
  out.set(trimmed, needsPad ? 3 : 2);
  return out;
}

/**
 * Converts WebCrypto's raw ECDSA signature into the DER form WebAuthn expects.
 *
 * This is the single most likely thing to be wrong in a WebAuthn
 * implementation, and the failure is silent: the relying party simply rejects
 * the assertion. WebCrypto gives `r ‖ s` as sixty-four fixed-width bytes;
 * WebAuthn wants `SEQUENCE { INTEGER r, INTEGER s }`, where each integer is
 * minimally encoded and prefixed with a zero if its top bit is set.
 *
 * @param raw 64 bytes, `r ‖ s`.
 * @returns The DER encoding.
 * @throws {RangeError} If the input is not 64 bytes.
 */
export function derFromRawSignature(raw: Uint8Array): Uint8Array {
  if (raw.length !== 64) {
    throw new RangeError(`Expected a 64-byte ECDSA signature, got ${raw.length}`);
  }
  const r = derInteger(raw.subarray(0, 32));
  const s = derInteger(raw.subarray(32));
  const out = new Uint8Array(2 + r.length + s.length);
  out[0] = 0x30; // SEQUENCE
  out[1] = r.length + s.length;
  out.set(r, 2);
  out.set(s, 2 + r.length);
  return out;
}

/** Imports the stored PKCS#8 private key for signing. */
async function importPrivateKey(keyValue: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'pkcs8',
    fromBase64(keyValue) as BufferSource,
    { name: 'ECDSA', namedCurve: 'P-256' },
    // Non-extractable: once imported, not even this code can read it back out.
    false,
    ['sign'],
  );
}

/**
 * Signs one assertion.
 *
 * The signature covers `authenticatorData ‖ SHA-256(clientDataJSON)` — the two
 * halves that bind it to this authenticator, this relying party, this origin
 * and this challenge. Leave any of them out and the signature is valid over
 * something the site did not ask for.
 *
 * @param credential The passkey, with its private key decrypted.
 * @param request What the page asked for.
 * @returns Everything the page needs to resolve its promise.
 */
export async function signAssertion(
  credential: PasskeyCredential,
  request: AssertionRequest,
): Promise<Assertion> {
  const clientDataJSON = buildClientData(request.challenge, request.origin);
  const authenticatorData = await buildAuthenticatorData(
    request.rpId,
    request.userVerified,
    credential.counter,
  );

  const clientDataHash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(clientDataJSON)),
  );
  const signed = new Uint8Array(authenticatorData.length + clientDataHash.length);
  signed.set(authenticatorData, 0);
  signed.set(clientDataHash, authenticatorData.length);

  const raw = new Uint8Array(
    await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      await importPrivateKey(credential.keyValue),
      signed as BufferSource,
    ),
  );

  return {
    credentialId: credential.credentialId,
    clientDataJSON,
    authenticatorData,
    signature: derFromRawSignature(raw),
    userHandle: credential.userHandle,
  };
}
