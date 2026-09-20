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
import { type CborValue, encodeCbor } from '../crypto/cbor.js';
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

/** What a site must supply to have a passkey created. */
export interface CreationRequest {
  readonly rpId: string;
  readonly origin: string;
  readonly challenge: Uint8Array;
  /** The account at the site: its opaque handle and its display name. */
  readonly userId: Uint8Array;
  readonly userName: string;
  readonly userDisplayName: string;
  readonly userVerified: boolean;
}

/** A passkey just created: what the site gets, and what the vault keeps. */
export interface CreatedCredential {
  /** What the site is given, base64url — a credential identifier is bytes. */
  readonly credentialId: string;
  /** The same bytes as the vault records them, as a UUID. */
  readonly storedCredentialId: string;
  readonly clientDataJSON: string;
  /** CBOR, `none` attestation. What `credentials.create()` resolves with. */
  readonly attestationObject: Uint8Array;
  /** PKCS#8, base64url — encrypted into the vault by the caller. */
  readonly privateKey: string;
}

/** Authenticator data flags, as the specification numbers them. */
const FLAG_USER_PRESENT = 0x01;
const FLAG_USER_VERIFIED = 0x04;
const FLAG_BACKUP_ELIGIBLE = 0x08;
const FLAG_BACKED_UP = 0x10;
/** Attested credential data follows: set on creation, never on an assertion. */
const FLAG_ATTESTED = 0x40;

/**
 * The identifier a relying party reads as "which authenticator made this".
 *
 * All zeroes, which the specification reserves for exactly this: an
 * authenticator that declines to identify its model. A made-up value would be
 * a claim about hardware that does not exist, and a borrowed one would be a
 * lie about whose it is. Both are what `none` attestation exists to avoid.
 */
const AAGUID = new Uint8Array(16);

/** The only algorithm offered: ECDSA with SHA-256 over P-256. */
export const ES256 = -7;

/** A UUID as it is written down: eight-four-four-four-twelve hex digits. */
const UUID_SHAPE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * The raw bytes of a stored credential identifier, whichever way it was written.
 *
 * A site names credentials by their **bytes**, base64url, in
 * `allowCredentials`. A vault stores that identifier as a string — and which
 * string is not something the format documentation settles: an identifier
 * written as a UUID is sixteen bytes of hexadecimal with dashes, while one
 * written base64url is the bytes themselves.
 *
 * Comparing the wrong pair matches nothing, offers no passkey, and looks
 * exactly like a vault that holds none — which is the failure this function
 * exists to prevent. So both readings are accepted, and whichever the vault
 * uses, the comparison lands.
 *
 * @returns The bytes, or `null` if the string is neither.
 */
export function credentialIdBytes(stored: string): Uint8Array | null {
  if (UUID_SHAPE.test(stored)) {
    const hex = stored.replace(/-/g, '');
    const out = new Uint8Array(16);
    for (let i = 0; i < 16; i += 1) {
      out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  }
  try {
    const bytes = fromBase64(stored);
    return bytes.length === 0 ? null : bytes;
  } catch {
    return null;
  }
}

/**
 * Whether a stored identifier is the one a site named.
 *
 * Compared on bytes, not on text: the same credential can be written as a UUID
 * in one place and base64url in another, and two spellings of one identifier
 * must not read as two credentials.
 */
export function credentialIdMatches(stored: string, wanted: string): boolean {
  if (stored === wanted) {
    return true;
  }
  const ours = credentialIdBytes(stored);
  const theirs = credentialIdBytes(wanted);
  if (ours === null || theirs === null || ours.length !== theirs.length) {
    return false;
  }
  return ours.every((byte, index) => byte === theirs[index]);
}

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
  return forParty.filter((credential) =>
    allowed.some((id) => credentialIdMatches(credential.credentialId, id)),
  );
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

/**
 * The public key as COSE, which is the form an attestation carries it in.
 *
 * A raw P-256 public key is `0x04 ‖ x ‖ y`, sixty-five bytes. COSE wants a map,
 * and the labels are negative on purpose — the specification uses negative
 * integers for algorithm-specific parameters so they cannot collide with the
 * common ones.
 *
 * Keys are written in the order CTAP2's canonical form wants them.
 */
function coseKeyFrom(rawPublicKey: Uint8Array): Uint8Array {
  if (rawPublicKey.length !== 65 || rawPublicKey[0] !== 0x04) {
    throw new RangeError('Expected an uncompressed P-256 public key');
  }
  return encodeCbor(
    new Map<number, number | Uint8Array>([
      [1, 2], // kty: EC2
      [3, ES256], // alg
      [-1, 1], // crv: P-256
      [-2, rawPublicKey.subarray(1, 33)], // x
      [-3, rawPublicKey.subarray(33)], // y
    ]),
  );
}

/**
 * `attestedCredentialData`: who made the credential, what it is called, and
 * its public key.
 *
 * `aaguid ‖ credentialIdLength ‖ credentialId ‖ COSE public key`, the length
 * big-endian over two bytes.
 */
function attestedCredentialData(credentialId: Uint8Array, cose: Uint8Array): Uint8Array {
  const out = new Uint8Array(AAGUID.length + 2 + credentialId.length + cose.length);
  out.set(AAGUID, 0);
  new DataView(out.buffer).setUint16(AAGUID.length, credentialId.length, false);
  out.set(credentialId, AAGUID.length + 2);
  out.set(cose, AAGUID.length + 2 + credentialId.length);
  return out;
}

/**
 * Creates a passkey for a site.
 *
 * The key pair is generated here and never leaves: the private half comes back
 * as PKCS#8 for the caller to encrypt into the vault, and the public half goes
 * to the site inside the attestation object. Nothing else is kept.
 *
 * Attestation is `none` — no statement about what made this credential,
 * because no honest statement is available. A software authenticator claiming
 * otherwise is claiming hardware it does not have.
 *
 * @param request What the site asked for, already validated.
 * @returns The credential: the site's half and the vault's.
 */
export async function createCredential(request: CreationRequest): Promise<CreatedCredential> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]);
  const privateKey = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  const rawPublicKey = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));

  // A UUID, and stored as one.
  //
  // The site is handed its sixteen raw bytes, which is what a credential
  // identifier is. Keeping the text form a UUID is what makes the credential
  // legible to other clients: a vault that writes identifiers as UUIDs can
  // read this one, and a vault that writes them base64url can read it too,
  // since sixteen bytes are sixteen bytes. Thirty-two random bytes would have
  // been readable by one convention only — and which one this format uses is
  // not something its documentation settles.
  const credentialUuid = crypto.randomUUID();
  const credentialId = credentialIdBytes(credentialUuid)!;

  const rpIdHash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(request.rpId)),
  );
  let flags = FLAG_USER_PRESENT | FLAG_BACKUP_ELIGIBLE | FLAG_BACKED_UP | FLAG_ATTESTED;
  if (request.userVerified) {
    flags |= FLAG_USER_VERIFIED;
  }

  const attested = attestedCredentialData(credentialId, coseKeyFrom(rawPublicKey));
  const authData = new Uint8Array(37 + attested.length);
  authData.set(rpIdHash, 0);
  authData[32] = flags;
  // The counter starts, and stays, at zero — see `buildAuthenticatorData`.
  new DataView(authData.buffer).setUint32(33, 0, false);
  authData.set(attested, 37);

  return {
    // What the site is told, and what the vault keeps, are two spellings of the
    // same sixteen bytes.
    credentialId: toBase64Url(credentialId),
    storedCredentialId: credentialUuid,
    clientDataJSON: buildClientData(request.challenge, request.origin, 'webauthn.create'),
    attestationObject: encodeCbor(
      new Map<string, CborValue>([
        ['fmt', 'none'],
        // Empty, and that is the whole of `none` attestation: no claim is made
        // about what produced this credential, because none would be true.
        ['attStmt', new Map<string, CborValue>()],
        ['authData', authData],
      ]),
    ),
    privateKey: toBase64Url(privateKey),
  };
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
