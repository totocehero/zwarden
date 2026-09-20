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
  validateAssertionAsk,
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
