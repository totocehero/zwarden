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
  // A parent domain, and only on a label boundary: `evil-bank.example` must not
  // pass for `bank.example`, which a plain `endsWith` would allow.
  return host.endsWith(`.${rpId}`);
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
  if (excluded.some((id) => existing.includes(id))) {
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
