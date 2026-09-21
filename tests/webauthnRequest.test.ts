/**
 * @file Whether a page may ask for the passkey it is asking for.
 *
 * Normally the browser enforces this. Intercepting `navigator.credentials.get()`
 * takes that enforcement away and leaves it here, so these tests are written as
 * the attacks rather than as the happy path: the failure being guarded against
 * is a page the user has never trusted obtaining a signature for their bank,
 * authorised by a confirmation click that looked entirely reasonable.
 */

import { describe, expect, it } from 'vitest';

import {
  mayClaimRelyingParty,
  pageMayAsk,
  validateAssertionAsk,
  validateCreationAsk,
  vaultMayAnswer,
  WebAuthnRefusal,
} from '../src/core/vault/webauthnRequest.js';

const CHALLENGE = 'AQIDBAUGBwg';

const refusalFor = (options: Record<string, unknown>, origin: string): string => {
  try {
    validateAssertionAsk(options, origin);
    return 'accepted';
  } catch (error) {
    return error instanceof WebAuthnRefusal ? error.code : 'other';
  }
};

describe('mayClaimRelyingParty', () => {
  it('lets a site claim itself', () => {
    expect(mayClaimRelyingParty('bank.example', 'bank.example')).toBe(true);
  });

  it('lets a subdomain claim its parent', () => {
    expect(mayClaimRelyingParty('login.bank.example', 'bank.example')).toBe(true);
    expect(mayClaimRelyingParty('a.b.bank.example', 'bank.example')).toBe(true);
  });

  it('refuses an unrelated site outright', () => {
    // The attack: a script on a page the user opened once, asking for a
    // signature that belongs to their bank.
    expect(mayClaimRelyingParty('evil.example', 'bank.example')).toBe(false);
  });

  it('refuses a name that merely ends the same way', () => {
    // What a plain `endsWith` would let through. The boundary must be a label.
    expect(mayClaimRelyingParty('evil-bank.example', 'bank.example')).toBe(false);
    expect(mayClaimRelyingParty('notbank.example', 'bank.example')).toBe(false);
  });

  it('refuses a parent claimed from the wrong side', () => {
    // `bank.example` is not under `bank.example.evil.test`.
    expect(mayClaimRelyingParty('bank.example', 'bank.example.evil.test')).toBe(false);
  });

  it('refuses a bare top-level domain', () => {
    // Claiming `com` would be claiming every site under it.
    expect(mayClaimRelyingParty('bank.example', 'example')).toBe(false);
    expect(mayClaimRelyingParty('anything.com', 'com')).toBe(false);
  });

  it('refuses an address claiming a suffix of itself', () => {
    // `1.2.3.4` is not "under" `3.4`: an address has no parent, and letting a
    // page on one claim a suffix would let it claim a range of addresses.
    expect(mayClaimRelyingParty('1.2.3.4', '3.4')).toBe(false);
    expect(mayClaimRelyingParty('1.2.3.4', '2.3.4')).toBe(false);
    expect(mayClaimRelyingParty('1.2.3.4', '1.2.3.4')).toBe(true);
    expect(mayClaimRelyingParty('[::1]', '::1]')).toBe(false);
  });

  it('refuses localhost, which has no dot and no owner', () => {
    expect(mayClaimRelyingParty('localhost', 'localhost')).toBe(false);
  });

  it('refuses the empty cases rather than defaulting to yes', () => {
    expect(mayClaimRelyingParty('', 'bank.example')).toBe(false);
    expect(mayClaimRelyingParty('bank.example', '')).toBe(false);
  });
});

describe('validateAssertionAsk', () => {
  it('accepts an ordinary request and reduces it', () => {
    const ask = validateAssertionAsk(
      { challenge: CHALLENGE, rpId: 'bank.example', userVerification: 'required' },
      'https://login.bank.example/signin',
    );

    expect(ask.rpId).toBe('bank.example');
    expect(ask.origin).toBe('https://login.bank.example');
    expect([...ask.challenge]).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(ask.requiresVerification).toBe(true);
  });

  it('takes the page host when no party is named, which is the common case', () => {
    const ask = validateAssertionAsk({ challenge: CHALLENGE }, 'https://bank.example/');
    expect(ask.rpId).toBe('bank.example');
  });

  it('refuses a party the page has no claim to', () => {
    expect(refusalFor({ challenge: CHALLENGE, rpId: 'bank.example' }, 'https://evil.example/')).toBe(
      'rp-mismatch',
    );
  });

  it('refuses anything that is not https', () => {
    // A passkey answered over plain HTTP is a signature handed to whoever is
    // on the wire.
    expect(refusalFor({ challenge: CHALLENGE }, 'http://bank.example/')).toBe('bad-origin');
    expect(refusalFor({ challenge: CHALLENGE }, 'file:///tmp/x.html')).toBe('bad-origin');
  });

  it('refuses an origin it cannot read', () => {
    expect(refusalFor({ challenge: CHALLENGE }, 'not a url')).toBe('bad-origin');
  });

  it('refuses a request with no challenge to sign', () => {
    expect(refusalFor({}, 'https://bank.example/')).toBe('malformed');
    expect(refusalFor({ challenge: '' }, 'https://bank.example/')).toBe('malformed');
    expect(refusalFor({ challenge: 42 }, 'https://bank.example/')).toBe('malformed');
  });

  it('does not care what case the page wrote the party in', () => {
    const ask = validateAssertionAsk(
      { challenge: CHALLENGE, rpId: 'Bank.Example' },
      'https://LOGIN.BANK.EXAMPLE/',
    );
    expect(ask.rpId).toBe('bank.example');
  });

  it('reads the credentials the site will accept', () => {
    const ask = validateAssertionAsk(
      { challenge: CHALLENGE, allowCredentials: [{ id: 'aaa' }, { id: 'bbb' }, { nope: 1 }] },
      'https://bank.example/',
    );
    expect(ask.allowCredentials).toEqual(['aaa', 'bbb']);
  });

  it('treats no list as "any credential for this site"', () => {
    const ask = validateAssertionAsk({ challenge: CHALLENGE }, 'https://bank.example/');
    expect(ask.allowCredentials).toEqual([]);
  });

  it('takes the origin from the browser, never a field the page supplies', () => {
    // A page that could name its own origin could name any.
    const ask = validateAssertionAsk(
      { challenge: CHALLENGE, origin: 'https://bank.example' },
      'https://evil.example/',
    );
    expect(ask.origin).toBe('https://evil.example');
  });
});

/**
 * Registration requests.
 *
 * The same relying-party rule applies, for the same reason — a page must not
 * register a passkey under a name it does not own — and two refusals here are
 * honest declines rather than errors: an algorithm we do not implement, and an
 * account the vault already holds a key for.
 */
describe('validateCreationAsk', () => {
  const USER = { id: 'dXNlci0x', name: 'ada@example.org', displayName: 'Ada' };
  const ES256 = [{ type: 'public-key', alg: -7 }];

  const ask = (patch: Record<string, unknown> = {}, origin = 'https://bank.example/') =>
    validateCreationAsk(
      { challenge: CHALLENGE, rp: { id: 'bank.example', name: 'The Bank' }, user: USER, pubKeyCredParams: ES256, ...patch },
      origin,
    );

  const refusal = (patch: Record<string, unknown> = {}, origin = 'https://bank.example/', existing: string[] = []) => {
    try {
      validateCreationAsk(
        { challenge: CHALLENGE, rp: { id: 'bank.example' }, user: USER, pubKeyCredParams: ES256, ...patch },
        origin,
        existing,
      );
      return 'accepted';
    } catch (error) {
      return error instanceof WebAuthnRefusal ? error.code : 'other';
    }
  };

  it('accepts an ordinary registration', () => {
    const request = ask();
    expect(request.rpId).toBe('bank.example');
    expect(request.rpName).toBe('The Bank');
    expect(request.userName).toBe('ada@example.org');
    expect([...request.userId]).toEqual([...new TextEncoder().encode('user-1')]);
  });

  it('refuses a party the page has no claim to', () => {
    expect(refusal({ rp: { id: 'bank.example' } }, 'https://evil.example/')).toBe('rp-mismatch');
  });

  it('declines an algorithm it does not implement', () => {
    // RS256 only. Better served by the platform authenticator than by an
    // extension pretending.
    expect(refusal({ pubKeyCredParams: [{ type: 'public-key', alg: -257 }] })).toBe(
      'unsupported-algorithm',
    );
  });

  it('serves a site that will take ES256 among others', () => {
    expect(
      ask({ pubKeyCredParams: [{ alg: -257 }, { alg: -7 }] }).rpId,
    ).toBe('bank.example');
  });

  it('declines when the account already has a key here', () => {
    // `excludeCredentials` exists so an authenticator does not hand out a
    // second key for an account that already has one.
    expect(refusal({ excludeCredentials: [{ id: 'already-there' }] }, 'https://bank.example/', ['already-there'])).toBe(
      'already-registered',
    );
  });

  it('proceeds when the excluded credentials are somebody else’s', () => {
    expect(
      ask({ excludeCredentials: [{ id: 'not-ours' }] }).rpId,
    ).toBe('bank.example');
  });

  it('refuses a registration with no account to attach it to', () => {
    expect(refusal({ user: { name: 'ada' } })).toBe('malformed');
  });

  it('refuses anything that is not https', () => {
    expect(refusal({}, 'http://bank.example/')).toBe('bad-origin');
  });

  it('asks for verification unless the site says not to', () => {
    // `preferred` is the default and means "if you can". We can, and a passkey
    // made without verification is one the site may later refuse.
    expect(ask().requiresVerification).toBe(true);
    expect(ask({ authenticatorSelection: { userVerification: 'preferred' } }).requiresVerification).toBe(true);
    expect(ask({ authenticatorSelection: { userVerification: 'discouraged' } }).requiresVerification).toBe(false);
  });

  it('falls back to the relying party id when the site gives no name', () => {
    expect(ask({ rp: { id: 'bank.example' } }).rpName).toBe('bank.example');
  });
});

/**
 * Whether the vault can answer at all, asked by the service worker.
 *
 * The worker has no keys, so the popup leaves the list of relying parties
 * behind. Without it every ceremony is held open until somebody opens the
 * popup to find out there was nothing to offer — and most sign-ins use a
 * hardware key, so most ceremonies would be ninety seconds of delay that
 * Zwarden added and nobody asked for.
 */
describe('pageMayAsk', () => {
  // The worker's early decline is observable from the page: answered at once
  // means "nothing for that party", held means the opposite. So the question
  // itself is refused whenever the party is not the page's own to claim —
  // otherwise a page enumerates, one `rpId` per question, the sites the user
  // holds passkeys at, with no click and no badge until the last one.
  it('lets a page ask about itself, named or not', () => {
    expect(pageMayAsk('https://login.bank.example', {})).toBe(true);
    expect(pageMayAsk('https://login.bank.example', { rpId: 'bank.example' })).toBe(true);
    expect(pageMayAsk('https://login.bank.example', { rpId: 'Login.Bank.Example' })).toBe(true);
  });

  it("refuses a question about somebody else's party", () => {
    expect(pageMayAsk('https://evil.example', { rpId: 'bank.example' })).toBe(false);
    expect(pageMayAsk('https://evil.example', { rpId: 'com' })).toBe(false);
    expect(pageMayAsk('https://evil.example', { rpId: 'example' })).toBe(false);
  });

  it('refuses a page that is not https, or not a page', () => {
    expect(pageMayAsk('http://bank.example', {})).toBe(false);
    expect(pageMayAsk('null', {})).toBe(false);
    expect(pageMayAsk('not a url', {})).toBe(false);
  });

  it('refuses a party that is not a string', () => {
    expect(pageMayAsk('https://bank.example', { rpId: 42 })).toBe(false);
    expect(pageMayAsk('https://bank.example', { rpId: ['bank.example'] })).toBe(false);
    expect(pageMayAsk('https://bank.example', null)).toBe(false);
  });
});

describe('vaultMayAnswer', () => {
  it('answers for a party the vault holds', () => {
    expect(vaultMayAnswer(['bank.example'], 'bank.example')).toBe(true);
  });

  it('lets a related party through, because the popup decides, not this', () => {
    // The bug this was found by: a vault holding a passkey for
    // `id.bank.example`, a site asking for `bank.example`. They are not the
    // same relying party and `selectCredentials` will say so — but that
    // refusal belongs to the popup. Declining here means no badge, no window
    // and no explanation, which is how the feature died in silence.
    expect(vaultMayAnswer(['id.bank.example'], 'bank.example')).toBe(true);
    expect(vaultMayAnswer(['bank.example'], 'id.bank.example')).toBe(true);
  });

  it('still declines something unrelated', () => {
    // Related means a label boundary, in one direction or the other. A name
    // that merely ends the same way, or one that wears the party as a prefix,
    // is a different site — and `validateAssertionAsk` would refuse it anyway
    // a layer down.
    expect(vaultMayAnswer(['bank.example'], 'evil-bank.example')).toBe(false);
    expect(vaultMayAnswer(['bank.example'], 'bank.example.evil.test')).toBe(false);
    expect(vaultMayAnswer(['bank.example'], 'other.example')).toBe(false);
  });

  it('declines a party it holds nothing for', () => {
    // The case that was stalling real sign-ins: a hardware key registered with
    // a site the vault knows nothing about.
    expect(vaultMayAnswer(['bank.example'], 'gandi.example')).toBe(false);
  });

  it('declines everything when the vault holds no passkey at all', () => {
    expect(vaultMayAnswer([], 'bank.example')).toBe(false);
  });

  it('says yes when it has not been told, rather than guessing no', () => {
    // A locked vault, or one opened by a version that left no list. Guessing no
    // would disable the feature for anyone in that state, silently, and nobody
    // would notice for weeks.
    expect(vaultMayAnswer(null, 'bank.example')).toBe(true);
  });

  it('defers when the site named no party', () => {
    // It then means the page's own host, which this layer does not know. The
    // popup validates the origin and settles it.
    expect(vaultMayAnswer(['bank.example'], null)).toBe(true);
    expect(vaultMayAnswer(['bank.example'], '')).toBe(true);
  });

  it('does not care about case', () => {
    expect(vaultMayAnswer(['bank.example'], 'Bank.Example')).toBe(true);
  });
});
