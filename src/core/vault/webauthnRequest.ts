/**
 * @file Deciding whether a page may ask for the passkey it is asking for.
 *
 * ## Why this file is the dangerous one
 *
 * Normally the browser enforces the relationship between a page and the
 * relying party it may claim: a script on `evil.example` cannot ask for an
 * assertion for `bank.example`, because the browser refuses. Intercepting
 * `navigator.credentials.get()` takes that enforcement away and leaves it to
 * us.
 *
 * Get it wrong and the failure is the worst kind there is: a page the user has
 * never trusted obtains a signature for a site they bank with. Nothing warns,
 * and the user's own confirmation click is what authorises it — they would be
 * confirming a sign-in to the right site, at the wrong site's request.
 *
 * So the rule is applied here, on its own, in a file with no DOM and no
 * network, and it is tested against the attacks it exists to stop.
 *
 * ## The rule
 *
 * The relying party must be the page's own host, or a parent domain of it.
 * `login.bank.example` may claim `bank.example`; `evil.example` may claim
 * neither.
 *
 * ## The limit of it, stated rather than hidden
 *
 * The specification says a *registrable* domain suffix, which means knowing
 * where the registry boundary falls — that `co.uk` is one and `bank.co.uk` is
 * not. Knowing that properly requires the Public Suffix List: tens of
 * thousands of entries, a recurring update, and far more weight than this
 * extension is allowed.
 *
 * The approximation here refuses any relying party with no dot in it, which
 * stops `com` and `org`, and refuses anything that is not a suffix of the
 * host. What it does not stop is a page on `evil.co.uk` claiming `co.uk` — a
 * two-label public suffix. That attack requires the attacker to hold a domain
 * under the same multi-label suffix as the target **and** the target to have
 * registered its passkeys against the suffix itself, which no relying party
 * does. It is a real gap; it is named here rather than left to be discovered.
 */

import { credentialIdMatches } from './passkey.js';

/** The one signature algorithm this authenticator offers: ECDSA with SHA-256. */
const ES256_ALGORITHM = -7;

/** A request from a page, reduced to what signing needs. */
export interface AssertionAsk {
  readonly rpId: string;
  readonly origin: string;
  readonly challenge: Uint8Array;
  /** Credential ids the site will accept, base64url. Empty means any. */
  readonly allowCredentials: readonly string[];
  /** `true` if the site insists the user be verified, not merely present. */
  readonly requiresVerification: boolean;
}

/** A registration request from a page, reduced to what creating needs. */
export interface CreationAsk {
  readonly rpId: string;
  /** What the site calls itself, for the confirmation screen. */
  readonly rpName: string;
  readonly origin: string;
  readonly challenge: Uint8Array;
  /** The account at the site: an opaque handle it will hand back. */
  readonly userId: Uint8Array;
  readonly userName: string;
  readonly userDisplayName: string;
  /** Credentials the site already has: it must not be given a second. */
  readonly excludeCredentials: readonly string[];
  readonly requiresVerification: boolean;
}

/** Why a request was refused. */
export class WebAuthnRefusal extends Error {
  override readonly name = 'WebAuthnRefusal';
  constructor(
    readonly code:
      | 'bad-origin'
      | 'rp-mismatch'
      | 'malformed'
      | 'unsupported-algorithm'
      | 'already-registered',
  ) {
    super(code);
  }
}

/**
 * Whether a page on `host` may claim `rpId`.
 *
 * @param host The page's hostname, lowercased.
 * @param rpId The relying party it claims.
 */
export function mayClaimRelyingParty(host: string, rpId: string): boolean {
  if (rpId === '' || host === '') {
    return false;
  }
  // A relying party with no dot is a top-level domain: `com`, `org`,
  // `localhost`. Letting a page claim one would let it claim every site under
  // it. `localhost` is refused with the rest — a passkey there is a developer's
  // problem, not a user's.
  if (!rpId.includes('.')) {
    return false;
  }
  if (host === rpId) {
    return true;
  }
  // An IP address has no parent: `1.2.3.4` is not "under" `3.4`, and letting a
  // page on one address claim a suffix of it would let it claim a range.
  if (isIpLiteral(host)) {
    return false;
  }
  // A parent domain, and only on a label boundary: `evil-bank.example` must not
  // pass for `bank.example`, which a plain `endsWith` would allow.
  return host.endsWith(`.${rpId}`);
}

/** `true` for an IPv4 dotted quad or a bracketed IPv6 literal. */
function isIpLiteral(host: string): boolean {
  return /^\d+(\.\d+){3}$/.test(host) || host.startsWith('[');
}

/**
 * Whether a page at `origin` may so much as **ask** about `options`.
 *
 * The same rule as {@link validateAssertionAsk}, reduced to a yes or no and
 * applied in the service worker, before anything is looked up on the page's
 * behalf. It matters because the worker's early decline is observable: a page
 * that is answered at once learns the vault holds nothing for the party it
 * named, and one that is held learns the opposite. Asked about a thousand
 * parties, that is a list of the sites the user has passkeys at. Refusing the
 * question itself, whenever the party is not the page's own to claim, leaves a
 * page able to learn only what it is entitled to — whether the user has a
 * passkey at **this** site.
 *
 * @param origin The page's origin, as the browser reported it.
 * @param options The `publicKey` options, untrusted.
 */
export function pageMayAsk(origin: string, options: unknown): boolean {
  let parsed: URL;
  try {
    parsed = new URL(origin);
  } catch {
    return false;
  }
  if (parsed.protocol !== 'https:') {
    return false;
  }
  if (typeof options !== 'object' || options === null) {
    return false;
  }
  const host = parsed.hostname.toLowerCase();
  const claimed = (options as { rpId?: unknown }).rpId;
  if (claimed === undefined || claimed === null || claimed === '') {
    return mayClaimRelyingParty(host, host);
  }
  return typeof claimed === 'string' && mayClaimRelyingParty(host, claimed.toLowerCase());
}

/** Decodes base64url, or whatever the page sent, into bytes. */
function decodeBinary(value: unknown): Uint8Array | null {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (Array.isArray(value)) {
    return Uint8Array.from(value as number[]);
  }
  if (typeof value === 'string') {
    try {
      const normalised = value.replace(/-/g, '+').replace(/_/g, '/');
      const padded = normalised.padEnd(
        normalised.length + ((4 - (normalised.length % 4)) % 4),
        '=',
      );
      return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * Validates a page's request and reduces it to what signing needs.
 *
 * @param options The `publicKey` options the page passed, already serialised
 *   across the world boundary — so every binary field arrives as base64url.
 * @param origin The page's origin, taken from the browser and **never** from
 *   the page: a value the page supplies is a value the page chooses.
 * @returns The validated request.
 * @throws {WebAuthnRefusal} If the origin is unusable, the relying party is not
 *   the page's to claim, or the request is malformed.
 */
export function validateAssertionAsk(
  options: Record<string, unknown>,
  origin: string,
): AssertionAsk {
  let host: string;
  let parsed: URL;
  try {
    parsed = new URL(origin);
    host = parsed.hostname.toLowerCase();
  } catch {
    throw new WebAuthnRefusal('bad-origin');
  }
  // WebAuthn is a secure-context feature. A passkey answered over plain HTTP
  // would be a signature handed to whoever is on the wire.
  if (parsed.protocol !== 'https:') {
    throw new WebAuthnRefusal('bad-origin');
  }

  const challenge = decodeBinary(options['challenge']);
  if (challenge === null || challenge.length === 0) {
    throw new WebAuthnRefusal('malformed');
  }

  // Absent means "this page's own host", which is the common case.
  const claimed = options['rpId'];
  const rpId = typeof claimed === 'string' && claimed !== '' ? claimed.toLowerCase() : host;
  if (!mayClaimRelyingParty(host, rpId)) {
    throw new WebAuthnRefusal('rp-mismatch');
  }

  const allowed = Array.isArray(options['allowCredentials'])
    ? (options['allowCredentials'] as Record<string, unknown>[])
        .map((entry) => entry?.['id'])
        .filter((id): id is string => typeof id === 'string')
    : [];

  return {
    rpId,
    origin: parsed.origin,
    challenge,
    allowCredentials: allowed,
    requiresVerification: options['userVerification'] === 'required',
  };
}

/**
 * Validates a registration request and reduces it to what creating needs.
 *
 * Two refusals here are not failures but honest declines, and both send the
 * page back to the browser rather than showing the user anything:
 *
 * - **an algorithm we do not implement.** Only ES256 is offered. A site that
 *   insists on RS256 or Ed25519 is better served by the platform
 *   authenticator than by an extension pretending;
 * - **a credential the site already holds.** `excludeCredentials` exists so an
 *   authenticator does not hand out a second key for an account that already
 *   has one; the caller supplies what the vault holds and this refuses on the
 *   overlap.
 *
 * @param options The `publicKey` options the page passed, serialised.
 * @param origin The page's origin, from the browser and never from the page.
 * @param existing Credential ids the vault already holds for this site.
 * @throws {WebAuthnRefusal} Origin unusable, relying party not the page's to
 *   claim, request malformed, or nothing we can serve.
 */
export function validateCreationAsk(
  options: Record<string, unknown>,
  origin: string,
  existing: readonly string[] = [],
): CreationAsk {
  let parsed: URL;
  try {
    parsed = new URL(origin);
  } catch {
    throw new WebAuthnRefusal('bad-origin');
  }
  if (parsed.protocol !== 'https:') {
    throw new WebAuthnRefusal('bad-origin');
  }
  const host = parsed.hostname.toLowerCase();

  const challenge = decodeBinary(options['challenge']);
  if (challenge === null || challenge.length === 0) {
    throw new WebAuthnRefusal('malformed');
  }

  const rp = (options['rp'] ?? {}) as Record<string, unknown>;
  const claimed = rp['id'];
  const rpId = typeof claimed === 'string' && claimed !== '' ? claimed.toLowerCase() : host;
  if (!mayClaimRelyingParty(host, rpId)) {
    throw new WebAuthnRefusal('rp-mismatch');
  }

  const user = (options['user'] ?? {}) as Record<string, unknown>;
  const userId = decodeBinary(user['id']);
  if (userId === null || userId.length === 0) {
    throw new WebAuthnRefusal('malformed');
  }

  // The site lists the algorithms it accepts, best first. We serve exactly one.
  const params = Array.isArray(options['pubKeyCredParams'])
    ? (options['pubKeyCredParams'] as Record<string, unknown>[])
    : [];
  if (params.length > 0 && !params.some((entry) => entry?.['alg'] === ES256_ALGORITHM)) {
    throw new WebAuthnRefusal('unsupported-algorithm');
  }

  const excluded = Array.isArray(options['excludeCredentials'])
    ? (options['excludeCredentials'] as Record<string, unknown>[])
        .map((entry) => entry?.['id'])
        .filter((id): id is string => typeof id === 'string')
    : [];
  // On bytes, not text: the vault spells a credential as a UUID, the page as
  // base64url, and the two never compare equal as strings — which is how this
  // check silently never fired for the extension's own credentials.
  if (excluded.some((id) => existing.some((ours) => credentialIdMatches(ours, id)))) {
    // The account already has a key here. Making a second would leave the user
    // with two and the site expecting one.
    throw new WebAuthnRefusal('already-registered');
  }

  const selection = (options['authenticatorSelection'] ?? {}) as Record<string, unknown>;

  return {
    rpId,
    rpName: typeof rp['name'] === 'string' && rp['name'] !== '' ? rp['name'] : rpId,
    origin: parsed.origin,
    challenge,
    userId,
    userName: typeof user['name'] === 'string' ? user['name'] : '',
    userDisplayName: typeof user['displayName'] === 'string' ? user['displayName'] : '',
    excludeCredentials: excluded,
    // `preferred` is the default and means "if you can": we can, and a passkey
    // created without verification is one the site may later refuse.
    requiresVerification: selection['userVerification'] !== 'discouraged',
  };
}

/**
 * Whether a vault holding passkeys for `parties` can answer for `rpId`.
 *
 * Asked by the service worker, which has no keys: the popup leaves the list
 * behind when it opens the vault. Without this, every ceremony has to be held
 * open until somebody opens the popup to discover there was nothing to offer —
 * and most sign-ins use a hardware key or the platform authenticator, so most
 * ceremonies would be a ninety-second delay Zwarden added for nothing.
 *
 * **Never narrower than the real decision.** This is an optimisation, not a
 * rule: the rule is `selectCredentials`, which has the credentials and the
 * validated origin. Anything this declines is a ceremony nobody ever sees —
 * no badge, no window, no explanation — so it declines only what it is sure
 * about, and a party merely *related* to one the vault holds is let through.
 *
 * The first version compared for equality and was wrong exactly there: a vault
 * holding a passkey for `id.bank.example` refused a site asking for
 * `bank.example` before the popup could look, and the feature died in silence.
 *
 * Permissive for the same reason when it does not know: a locked vault, or one
 * opened by a version that left no list, gives `null` and the answer is yes.
 *
 * @param parties Relying parties the vault holds a passkey for, or `null` if
 *   it has not said — which is not the same as an empty list.
 * @param rpId The party claimed, or `null` when the site named none and it
 *   therefore means its own host, which this layer does not know.
 */
export function vaultMayAnswer(
  parties: readonly string[] | null,
  rpId: string | null,
): boolean {
  if (parties === null) {
    return true;
  }
  if (parties.length === 0) {
    return false;
  }
  if (rpId === null || rpId === '') {
    return true;
  }
  // Related is enough. A passkey registered for `id.bank.example` and a site
  // asking for `bank.example` are not the same relying party, and `selectCredentials`
  // is right to refuse them — but that refusal belongs to the popup, which has
  // the credentials and the origin. Here it would only be a guess, and a guess
  // that says no stops the ceremony before anyone can see it.
  const wanted = rpId.toLowerCase();
  return parties.some(
    (party) =>
      party === wanted || party.endsWith(`.${wanted}`) || wanted.endsWith(`.${party}`),
  );
}
