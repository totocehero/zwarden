/**
 * @file Answering a WebAuthn assertion.
 *
 * A relying party does not explain why it rejected an assertion; it simply
 * refuses the sign-in. Every mistake this file guards against is therefore
 * silent, and the only way to be sure is to **verify the signature the way the
 * site will** — which is what the round-trip tests do, with a real P-256 key
 * pair and WebCrypto's own verifier.
 */

import { beforeAll, describe, expect, it } from 'vitest';

import type { CipherResponse } from '../src/core/api/models.js';
import { encryptString } from '../src/core/crypto/cryptoService.js';
import { toBase64Url } from '../src/core/crypto/encoding.js';
import { SymmetricCryptoKey } from '../src/core/crypto/symmetricCryptoKey.js';
import { decryptCipherDetails, decryptPasskeys } from '../src/core/vault/cipherService.js';
import {
  buildAuthenticatorData,
  buildClientData,
  derFromRawSignature,
  type PasskeyCredential,
  selectCredentials,
  signAssertion,
} from '../src/core/vault/passkey.js';

let credential: PasskeyCredential;
let publicKey: CryptoKey;

beforeAll(async () => {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  publicKey = pair.publicKey;
  credential = {
    credentialId: 'Y3JlZC0x',
    rpId: 'example.org',
    userHandle: 'dXNlci0x',
    keyValue: toBase64Url(pkcs8),
    counter: 0,
  };
});

/** Verifies an assertion exactly as a relying party would. */
async function verifyLikeARelyingParty(
  authenticatorData: Uint8Array,
  clientDataJSON: string,
  derSignature: Uint8Array,
): Promise<boolean> {
  const clientHash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(clientDataJSON)),
  );
  const signed = new Uint8Array(authenticatorData.length + clientHash.length);
  signed.set(authenticatorData, 0);
  signed.set(clientHash, authenticatorData.length);

  // Back from DER to the raw pair WebCrypto verifies.
  const r = derSignature.subarray(4, 4 + derSignature[3]!);
  const sStart = 4 + derSignature[3]! + 2;
  const s = derSignature.subarray(sStart, sStart + derSignature[sStart - 1]!);
  const raw = new Uint8Array(64);
  raw.set(r.subarray(Math.max(0, r.length - 32)), 32 - Math.min(32, r.length));
  raw.set(s.subarray(Math.max(0, s.length - 32)), 64 - Math.min(32, s.length));

  return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, raw, signed);
}

describe('signAssertion', () => {
  const request = {
    rpId: 'example.org',
    origin: 'https://example.org',
    challenge: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
    userVerified: true,
  };

  it('produces a signature the relying party accepts', async () => {
    const assertion = await signAssertion(credential, request);

    expect(
      await verifyLikeARelyingParty(
        assertion.authenticatorData,
        assertion.clientDataJSON,
        assertion.signature,
      ),
    ).toBe(true);
  });

  it('binds the signature to the challenge', async () => {
    const assertion = await signAssertion(credential, request);
    const other = await signAssertion(credential, {
      ...request,
      challenge: new Uint8Array([9, 9, 9, 9]),
    });

    // Swapping in another ceremony's client data must break it: that binding
    // is the whole defence against a replayed signature.
    expect(
      await verifyLikeARelyingParty(
        assertion.authenticatorData,
        other.clientDataJSON,
        assertion.signature,
      ),
    ).toBe(false);
  });

  it('binds the signature to the relying party', async () => {
    const assertion = await signAssertion(credential, request);
    const elsewhere = await buildAuthenticatorData('evil.example', true);

    expect(
      await verifyLikeARelyingParty(elsewhere, assertion.clientDataJSON, assertion.signature),
    ).toBe(false);
  });

  it('hands back what the page needs to resolve its promise', async () => {
    const assertion = await signAssertion(credential, request);

    expect(assertion.credentialId).toBe('Y3JlZC0x');
    expect(assertion.userHandle).toBe('dXNlci0x');
    expect(JSON.parse(assertion.clientDataJSON)).toEqual({
      type: 'webauthn.get',
      challenge: 'AQIDBAUGBwg',
      origin: 'https://example.org',
      crossOrigin: false,
    });
  });
});

describe('derFromRawSignature', () => {
  it('wraps the two halves in a SEQUENCE of INTEGERs', () => {
    const raw = new Uint8Array(64).fill(0x11);
    const der = derFromRawSignature(raw);

    expect(der[0]).toBe(0x30);
    expect(der[2]).toBe(0x02);
    expect(der[1]).toBe(der.length - 2);
  });

  it('prefixes a zero when the top bit is set', () => {
    // Without it the integer reads as negative and the relying party rejects a
    // signature that is arithmetically correct.
    const raw = new Uint8Array(64);
    raw[0] = 0xff;
    raw[32] = 0x7f;
    const der = derFromRawSignature(raw);

    expect(der[3]).toBe(33); // r: 32 bytes plus the pad
    expect(der[4]).toBe(0x00);
  });

  it('drops the leading zeros DER forbids', () => {
    const raw = new Uint8Array(64);
    raw[31] = 0x01;
    raw[63] = 0x01;
    const der = derFromRawSignature(raw);

    // One byte each, minimally encoded.
    expect(der[3]).toBe(1);
    expect(der.length).toBe(8);
  });

  it('refuses anything that is not a P-256 signature', () => {
    expect(() => derFromRawSignature(new Uint8Array(63))).toThrow(RangeError);
  });
});

describe('selectCredentials', () => {
  const forExample = { ...({} as PasskeyCredential), credentialId: 'a', rpId: 'example.org' };
  const forOther = { ...({} as PasskeyCredential), credentialId: 'b', rpId: 'other.example' };

  it('offers every credential for the party when the site names none', () => {
    // What a passwordless sign-in looks like.
    expect(selectCredentials([forExample, forOther], 'example.org')).toEqual([forExample]);
  });

  it('narrows to the ones the site asked for', () => {
    const second = { ...forExample, credentialId: 'c' };
    expect(selectCredentials([forExample, second], 'example.org', ['c'])).toEqual([second]);
  });

  it('matches the relying party exactly, never by resemblance', () => {
    // The attack this closes: a passkey for `example.org` answering
    // `evil-example.org` or `example.org.evil.test`.
    expect(selectCredentials([forExample], 'evil-example.org')).toEqual([]);
    expect(selectCredentials([forExample], 'example.org.evil.test')).toEqual([]);
    expect(selectCredentials([forExample], 'xample.org')).toEqual([]);
  });

  it('offers nothing when the site asks for a credential we do not have', () => {
    expect(selectCredentials([forExample], 'example.org', ['unknown'])).toEqual([]);
  });
});

describe('buildAuthenticatorData', () => {
  it('is the thirty-seven bytes an assertion carries', async () => {
    expect((await buildAuthenticatorData('example.org', true)).length).toBe(37);
  });

  it('reports user presence, verification and backup', async () => {
    const data = await buildAuthenticatorData('example.org', true);
    // UP | UV | BE | BS.
    expect(data[32]).toBe(0x1d);
  });

  it('drops the verification flag when nobody was verified', async () => {
    const data = await buildAuthenticatorData('example.org', false);
    expect(data[32]! & 0x04).toBe(0);
    expect(data[32]! & 0x01).toBe(0x01);
  });

  it('writes the counter big-endian, as the specification says', async () => {
    const data = await buildAuthenticatorData('example.org', true, 0x01020304);
    expect([...data.subarray(33)]).toEqual([1, 2, 3, 4]);
  });

  it('hashes the relying party, so two parties never share a prefix', async () => {
    const first = await buildAuthenticatorData('example.org', true);
    const second = await buildAuthenticatorData('other.example', true);
    expect([...first.subarray(0, 32)]).not.toEqual([...second.subarray(0, 32)]);
  });
});

describe('buildClientData', () => {
  it('encodes the challenge base64url, unpadded', () => {
    const data = JSON.parse(buildClientData(new Uint8Array([251, 255]), 'https://example.org'));
    expect(data.challenge).toBe('-_8');
  });

  it('keeps the key order the relying party hashes', () => {
    // These exact bytes are hashed into the signature: the order is part of
    // the contract, not a formatting choice.
    expect(buildClientData(new Uint8Array([1]), 'https://example.org')).toBe(
      '{"type":"webauthn.get","challenge":"AQ","origin":"https://example.org","crossOrigin":false}',
    );
  });
});

/**
 * Getting a passkey out of the vault.
 *
 * The one place that decrypts `keyValue`. Everything else — including the
 * detail view that shows the passkey badge — deliberately stops short of it,
 * so these tests check that the separation holds in both directions.
 */
describe('decryptPasskeys', () => {
  let key: SymmetricCryptoKey;

  beforeAll(() => {
    key = SymmetricCryptoKey.generate();
  });

  const enc = async (text: string): Promise<string> =>
    (await encryptString(text, key)).toString();

  async function cipherWithPasskey(
    patch: Record<string, string | undefined> = {},
  ): Promise<CipherResponse> {
    const entry: Record<string, string> = {
      credentialId: await enc('cred-1'),
      rpId: await enc('example.org'),
      userHandle: await enc('user-1'),
      keyValue: await enc('cGtjczgtYnl0ZXM'),
      counter: await enc('7'),
    };
    for (const [field, value] of Object.entries(patch)) {
      if (value === undefined) {
        delete entry[field];
      } else {
        entry[field] = value;
      }
    }
    return {
      id: 'item-1',
      type: 1,
      name: await enc('GitHub'),
      login: { fido2Credentials: [entry] },
      organizationId: null,
    } as unknown as CipherResponse;
  }

  it('hands back the credential, private key included', async () => {
    const [credential] = await decryptPasskeys(await cipherWithPasskey(), key, () => undefined);

    expect(credential).toEqual({
      credentialId: 'cred-1',
      rpId: 'example.org',
      userHandle: 'user-1',
      keyValue: 'cGtjczgtYnl0ZXM',
      counter: 7,
    });
  });

  it('is the only path that does: the detail view still withholds it', async () => {
    const details = await decryptCipherDetails(await cipherWithPasskey(), key, () => undefined);

    // `PasskeyView` carries the metadata and nothing else. Showing an item must
    // not put a private key in memory.
    expect(JSON.stringify(details)).not.toContain('cGtjczgtYnl0ZXM');
    expect(details.passkeys[0]).toEqual({
      credentialId: 'cred-1',
      rpId: 'example.org',
      userName: null,
    });
  });

  it('drops a credential whose private key will not decrypt', async () => {
    // A credential that cannot sign is not a credential; offering it would
    // fail in the middle of a ceremony instead of before it.
    const cipher = await cipherWithPasskey({ keyValue: '2.bm90|dmFsaWQ=|bWFj' });
    expect(await decryptPasskeys(cipher, key, () => undefined)).toEqual([]);
  });

  it('drops one with no relying party to match against', async () => {
    const cipher = await cipherWithPasskey({ rpId: undefined });
    expect(await decryptPasskeys(cipher, key, () => undefined)).toEqual([]);
  });

  it('treats an absent counter as zero, which is what a synced passkey reports', async () => {
    const cipher = await cipherWithPasskey({ counter: undefined });
    const [credential] = await decryptPasskeys(cipher, key, () => undefined);
    expect(credential!.counter).toBe(0);
  });

  it('finds nothing on an item that carries no passkey', async () => {
    const plain = {
      id: 'i',
      type: 1,
      name: await enc('Plain'),
      login: { username: await enc('ada') },
      organizationId: null,
    } as unknown as CipherResponse;

    expect(await decryptPasskeys(plain, key, () => undefined)).toEqual([]);
  });
});
