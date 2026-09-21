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
import {
  buildCipherCreatePayload,
  buildCipherUpdatePayload,
  decryptCipherDetails,
  decryptPasskeys,
} from '../src/core/vault/cipherService.js';
import {
  buildAuthenticatorData,
  buildClientData,
  createCredential,
  credentialIdMatches,
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

/**
 * Creating a passkey.
 *
 * The proof that matters is not that bytes came out in the right shape: it is
 * that the public key handed to the site **verifies a signature made by the
 * private key handed to the vault**. A registration that produces a mismatched
 * pair looks perfectly well-formed and fails on the next sign-in, weeks later.
 *
 * So the attestation object is decoded the way a relying party decodes it, the
 * COSE key is pulled out of it, and the two halves are checked against each
 * other.
 */
describe('createCredential', () => {
  const request = {
    rpId: 'example.org',
    origin: 'https://example.org',
    challenge: new Uint8Array([1, 2, 3, 4]),
    userId: new Uint8Array([9, 9]),
    userName: 'ada@example.org',
    userDisplayName: 'Ada',
    userVerified: true,
  };

  /** Just enough CBOR to read back what we wrote, as a site would. */
  function decodeCbor(bytes: Uint8Array, at = { i: 0 }): unknown {
    const first = bytes[at.i++]!;
    const major = first >> 5;
    let value = first & 0x1f;
    if (value === 24) {
      value = bytes[at.i++]!;
    } else if (value === 25) {
      value = (bytes[at.i++]! << 8) | bytes[at.i++]!;
    } else if (value === 26) {
      value = 0;
      for (let n = 0; n < 4; n += 1) {
        value = value * 256 + bytes[at.i++]!;
      }
    }
    if (major === 0) return value;
    if (major === 1) return -1 - value;
    if (major === 2) return bytes.subarray(at.i, (at.i += value));
    if (major === 3) return new TextDecoder().decode(bytes.subarray(at.i, (at.i += value)));
    if (major === 4) return Array.from({ length: value }, () => decodeCbor(bytes, at));
    const map = new Map<unknown, unknown>();
    for (let n = 0; n < value; n += 1) {
      map.set(decodeCbor(bytes, at), decodeCbor(bytes, at));
    }
    return map;
  }

  const b64url = (bytes: Uint8Array): string =>
    btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  it('hands the site a public key that matches the private key it keeps', async () => {
    const created = await createCredential(request);

    const attestation = decodeCbor(created.attestationObject) as Map<string, unknown>;
    const authData = attestation.get('authData') as Uint8Array;
    // rpIdHash 32, flags 1, counter 4, aaguid 16, then the id length.
    const idLength = (authData[53]! << 8) | authData[54]!;
    const cose = decodeCbor(authData.subarray(55 + idLength)) as Map<number, unknown>;

    const publicKey = await crypto.subtle.importKey(
      'jwk',
      {
        kty: 'EC',
        crv: 'P-256',
        x: b64url(cose.get(-2) as Uint8Array),
        y: b64url(cose.get(-3) as Uint8Array),
      },
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );
    const privateKey = await crypto.subtle.importKey(
      'pkcs8',
      Uint8Array.from(atob(created.privateKey.replace(/-/g, '+').replace(/_/g, '/')), (c) =>
        c.charCodeAt(0),
      ),
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign'],
    );

    const message = new TextEncoder().encode('a later sign-in');
    const signature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      privateKey,
      message,
    );

    expect(
      await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, signature, message),
    ).toBe(true);
  });

  it('makes no claim about what produced the credential', async () => {
    const attestation = decodeCbor(
      (await createCredential(request)).attestationObject,
    ) as Map<string, unknown>;

    // `none`, with an empty statement. A software authenticator claiming
    // otherwise is claiming hardware it does not have.
    expect(attestation.get('fmt')).toBe('none');
    expect((attestation.get('attStmt') as Map<unknown, unknown>).size).toBe(0);

    const authData = attestation.get('authData') as Uint8Array;
    // The AAGUID is all zeroes, which is what the specification reserves for
    // an authenticator declining to identify its model.
    expect([...authData.subarray(37, 53)]).toEqual(new Array(16).fill(0));
  });

  it('says attested credential data follows, which an assertion never does', async () => {
    const attestation = decodeCbor(
      (await createCredential(request)).attestationObject,
    ) as Map<string, unknown>;
    const flags = (attestation.get('authData') as Uint8Array)[32]!;

    expect(flags & 0x40).toBe(0x40); // AT
    expect(flags & 0x04).toBe(0x04); // UV, because this request verified
    expect(await buildAuthenticatorData('example.org', true)).not.toContain(0x40);
  });

  it('records the ceremony as a creation, not a sign-in', async () => {
    const created = await createCredential(request);
    expect(JSON.parse(created.clientDataJSON).type).toBe('webauthn.create');
  });

  it('records the identifier in a form other clients can read', async () => {
    const created = await createCredential(request);

    // A UUID in the vault, its raw bytes to the site. Thirty-two random bytes
    // would have been legible to one convention only, and which one this
    // format uses is not something its documentation settles.
    expect(created.storedCredentialId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
    expect(credentialIdMatches(created.storedCredentialId, created.credentialId)).toBe(true);
  });

  it('gives every credential a different identifier', async () => {
    const first = await createCredential(request);
    const second = await createCredential(request);

    // The site stores this and hands it back in `allowCredentials`; two vaults
    // colliding would be two accounts fighting over one entry.
    expect(first.credentialId).not.toBe(second.credentialId);
    expect(first.privateKey).not.toBe(second.privateKey);
  });
});

/**
 * Writing a new passkey into the vault.
 *
 * It goes through the same payload builder as every other edit, which is the
 * point: that builder is where the carry-over of fields nobody edits lives,
 * and a passkey arriving by a second path would be a second chance to lose
 * them.
 */
describe('storing a created passkey', () => {
  let key: SymmetricCryptoKey;

  beforeAll(() => {
    key = SymmetricCryptoKey.generate();
  });

  const NEW_PASSKEY = {
    credentialId: 'bmV3LWNyZWQ',
    rpId: 'bank.example',
    rpName: 'The Bank',
    userHandle: 'dXNlci0x',
    userName: 'ada@example.org',
    userDisplayName: 'Ada',
    keyValue: 'cGtjczgtYnl0ZXM',
  };

  const EDIT = {
    name: 'The Bank',
    username: 'ada@example.org',
    password: '',
    totp: '',
    notes: '',
    uris: ['https://bank.example'],
  };

  it('appends to the passkeys an item already has, never replaces them', async () => {
    const existing = {
      id: 'i1',
      type: 1,
      name: (await encryptString('The Bank', key)).toString(),
      login: { fido2Credentials: [{ credentialId: 'already-there' }] },
      organizationId: null,
    } as unknown as CipherResponse;

    const payload = await buildCipherUpdatePayload(
      existing,
      { ...EDIT, addPasskey: NEW_PASSKEY },
      key,
      false,
    );

    const stored = (payload['login'] as Record<string, unknown>)['fido2Credentials'] as unknown[];
    expect(stored).toHaveLength(2);
    // The one that was there is untouched, still encrypted as it was.
    expect((stored[0] as Record<string, unknown>)['credentialId']).toBe('already-there');
  });

  it('encrypts every field of the new one', async () => {
    const payload = await buildCipherCreatePayload({ ...EDIT, addPasskey: NEW_PASSKEY }, key);
    const stored = (payload['login'] as Record<string, unknown>)['fido2Credentials'] as Record<
      string,
      unknown
    >[];

    const written = JSON.stringify(stored[0]);
    // The private key above all, but the account name too: a vault that leaked
    // which sites hold which accounts would be leaking the vault.
    expect(written).not.toContain('cGtjczgtYnl0ZXM');
    expect(written).not.toContain('ada@example.org');
    expect(written).not.toContain('bank.example');
  });

  it('reads back exactly what was put in', async () => {
    const payload = await buildCipherCreatePayload({ ...EDIT, addPasskey: NEW_PASSKEY }, key);
    const cipher = { id: 'i1', type: 1, ...payload, organizationId: null } as unknown as CipherResponse;

    const [credential] = await decryptPasskeys(cipher, key, () => undefined);
    expect(credential).toEqual({
      credentialId: 'bmV3LWNyZWQ',
      rpId: 'bank.example',
      userHandle: 'dXNlci0x',
      keyValue: 'cGtjczgtYnl0ZXM',
      counter: 0,
    });
  });

  it('records what the official clients expect alongside it', async () => {
    const payload = await buildCipherCreatePayload({ ...EDIT, addPasskey: NEW_PASSKEY }, key);
    const stored = ((payload['login'] as Record<string, unknown>)['fido2Credentials'] as Record<
      string,
      unknown
    >[])[0]!;

    // A credential missing these is one Bitwarden's own clients will not use.
    for (const field of ['keyType', 'keyAlgorithm', 'keyCurve', 'counter', 'discoverable']) {
      expect(stored[field]).toBeDefined();
    }
    expect(typeof stored['creationDate']).toBe('string');
  });

  it('leaves an item alone when no passkey is being added', async () => {
    const payload = await buildCipherCreatePayload(EDIT, key);
    expect((payload['login'] as Record<string, unknown>)['fido2Credentials']).toBeNull();
  });
});

/**
 * Naming a credential.
 *
 * A site names credentials by their bytes, base64url. A vault stores the same
 * identifier as a string, and which string is not something the format
 * documentation settles — a UUID and a base64url encoding of the same sixteen
 * bytes look nothing alike as text.
 *
 * Comparing the wrong pair matches nothing, offers no passkey, and is
 * indistinguishable from a vault that holds none. That is the bug these tests
 * exist for, found on a real site where the passkey was there all along.
 */
describe('credentialIdMatches', () => {
  // The same sixteen bytes, written both ways.
  const AS_UUID = '0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0';
  const AS_BASE64URL = 'Dx4tPEtaaXiHlqW0w9Lh8A';

  it('sees one identifier through two spellings', () => {
    expect(credentialIdMatches(AS_UUID, AS_BASE64URL)).toBe(true);
    expect(credentialIdMatches(AS_BASE64URL, AS_UUID)).toBe(true);
  });

  it('matches a spelling with itself', () => {
    expect(credentialIdMatches(AS_UUID, AS_UUID)).toBe(true);
    expect(credentialIdMatches(AS_BASE64URL, AS_BASE64URL)).toBe(true);
  });

  it('does not match two different credentials', () => {
    expect(credentialIdMatches(AS_UUID, 'ffffffff-4b5a-6978-8796-a5b4c3d2e1f0')).toBe(false);
  });

  it('does not match on length alone', () => {
    expect(credentialIdMatches(AS_BASE64URL, 'Dx4tPEtaaXiHlqW0w9Lh8AAA')).toBe(false);
  });

  it('refuses what it cannot read as an identifier', () => {
    expect(credentialIdMatches('', AS_UUID)).toBe(false);
    expect(credentialIdMatches(AS_UUID, '')).toBe(false);
  });

  it('reads a UUID whatever its case', () => {
    expect(credentialIdMatches(AS_UUID.toUpperCase(), AS_BASE64URL)).toBe(true);
  });
});

describe('selectCredentials, against a real allowCredentials list', () => {
  const uuidCredential = {
    credentialId: '0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0',
    rpId: 'gandi.example',
  };

  it('finds a passkey the site named in the other spelling', () => {
    // The failure reported from use: the passkey was in the vault, the site
    // asked for it, and nothing was offered.
    expect(
      selectCredentials([uuidCredential], 'gandi.example', ['Dx4tPEtaaXiHlqW0w9Lh8A']),
    ).toEqual([uuidCredential]);
  });

  it('still refuses a credential the site did not name', () => {
    expect(selectCredentials([uuidCredential], 'gandi.example', ['AAAAAAAAAAAAAAAAAAAAAA'])).toEqual(
      [],
    );
  });
});

/**
 * What the site is handed back as the credential's identifier.
 *
 * A vault may store it as a UUID; a site understands only bytes, base64url.
 * Handing the stored spelling straight through gives the page sixteen bytes
 * of nothing once it decodes it, a `rawId` that names no credential, and a
 * relying party that refuses the assertion — reporting it, as Gandi did, as
 * its own service being unavailable.
 */
describe('the identifier an assertion carries', () => {
  const request = {
    rpId: 'example.org',
    origin: 'https://example.org',
    challenge: new Uint8Array([1, 2, 3, 4]),
    userVerified: true,
  };

  it('converts a UUID to the bytes the site expects', async () => {
    const assertion = await signAssertion(
      { ...credential, credentialId: '0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0' },
      request,
    );

    expect(assertion.credentialId).toBe('Dx4tPEtaaXiHlqW0w9Lh8A');
    // And the round trip holds: what the site gets decodes back to what the
    // vault holds.
    expect(credentialIdMatches('0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0', assertion.credentialId)).toBe(
      true,
    );
  });

  it('leaves an identifier already written as bytes alone', async () => {
    const assertion = await signAssertion(
      { ...credential, credentialId: 'Dx4tPEtaaXiHlqW0w9Lh8A' },
      request,
    );
    expect(assertion.credentialId).toBe('Dx4tPEtaaXiHlqW0w9Lh8A');
  });

  it('refuses to sign with an identifier it cannot read', async () => {
    // Better a refusal here than a signature the site cannot attribute.
    await expect(
      signAssertion({ ...credential, credentialId: '' }, request),
    ).rejects.toThrow(RangeError);
  });
});
