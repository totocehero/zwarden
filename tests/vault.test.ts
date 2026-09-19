/**
 * @file Tests for the vault layer: the unlock orchestrator and item decryption.
 *
 * The unlock's stubbed "server" is not a mere response dispenser: it **verifies
 * the authorization hash** against a value precomputed with the same
 * primitives. An `unlock` that succeeds therefore proves the chain derivation →
 * hash → login → stretching → unwrapping is coherent end to end, with no
 * network.
 */

import { beforeAll, describe, expect, it } from 'vitest';

import { ApiClient, ApiError, TwoFactorRequiredError } from '../src/core/api/apiClient.js';
import type { CipherResponse, SyncResponse } from '../src/core/api/models.js';
import { toBase64 } from '../src/core/crypto/encoding.js';
import {
  MacMismatchError,
  decryptStringOrNull,
  encryptBytes,
  encryptString,
} from '../src/core/crypto/cryptoService.js';
import {
  HashPurpose,
  KdfType,
  WeakKdfError,
  deriveMasterKey,
  derivePasswordHash,
  stretchMasterKey,
  verifyLocalPasswordHash,
  type KdfConfig,
} from '../src/core/crypto/kdf.js';
import { SymmetricCryptoKey } from '../src/core/crypto/symmetricCryptoKey.js';
import {
  type CipherOverview,
  buildCipherCreatePayload,
  buildCipherUpdatePayload,
  decryptCipherDetails,
  decryptCipherList,
  decryptCipherOverview,
  resolveItemKey,
  reuseByRevision,
} from '../src/core/vault/cipherService.js';
import { MissingOrgKeyError, buildVaultKeys } from '../src/core/vault/keyring.js';
import { decryptLabels } from '../src/core/vault/labels.js';
import { matchesOrigin, uriOrigin } from '../src/core/vault/uriMatch.js';
import { UnlockError, unlock } from '../src/core/vault/session.js';

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status });
}

/** Encrypts a string and serialises it, to build test items. */
async function enc(text: string, key: SymmetricCryptoKey): Promise<string> {
  return (await encryptString(text, key)).toString();
}

describe('cipherService', () => {
  let userKey: SymmetricCryptoKey;

  beforeAll(() => {
    userKey = SymmetricCryptoKey.generate();
  });

  /** Builds a complete camelCase item, encrypted with the given key. */
  async function makeCipher(key: SymmetricCryptoKey): Promise<CipherResponse> {
    return {
      id: 'item-1',
      type: 1,
      name: await enc('Ma banque', key),
      notes: await enc('private notes', key),
      login: {
        username: await enc('alice@exemple.fr', key),
        password: await enc('strong-password', key),
        totp: await enc('otpauth://totp/x', key),
        uris: [{ uri: await enc('https://banque.exemple.fr', key) }],
      },
      organizationId: null,
    };
  }

  it('decrypts the list view (camelCase)', async () => {
    const errors: unknown[] = [];
    const vue = await decryptCipherOverview(await makeCipher(userKey), userKey, (e) =>
      errors.push(e),
    );

    expect(vue).toEqual({
      id: 'item-1',
      type: 1,
      name: 'Ma banque',
      username: 'alice@exemple.fr',
      // A login identifies itself by its username: no subtitle to add.
      subtitle: null,
      uris: ['https://banque.exemple.fr'],
      hasPasskey: false,
      // The test item carries a TOTP: detected without being decrypted.
      hasTotp: true,
      reprompt: false,
      organizationId: null,
      folderId: null,
      collectionIds: [],
    });
    expect(errors).toHaveLength(0);
  });

  /**
   * `reprompt` is a guard the user chooses: the popup refuses to hand over a
   * secret without the master password being entered again. It must therefore be
   * readable **without** decryption, and any non-zero value must protect —
   * erring that way asks for a password, erring the other hands over a secret
   * with no guard.
   */
  it('spots the master-password guard without decrypting', async () => {
    const base = await makeCipher(userKey);
    const lire = async (reprompt: unknown): Promise<boolean> =>
      (await decryptCipherOverview({ ...base, reprompt } as CipherResponse, userKey, () => {}))
        .reprompt;

    expect(await lire(undefined)).toBe(false);
    expect(await lire(0)).toBe(false);
    expect(await lire(1)).toBe(true);
    expect(await lire(2)).toBe(true);
  });

  it('decrypts the details on demand', async () => {
    const errors: unknown[] = [];
    const details = await decryptCipherDetails(await makeCipher(userKey), userKey, (e) =>
      errors.push(e),
    );

    expect(details).toEqual({
      username: 'alice@exemple.fr',
      password: 'strong-password',
      totp: 'otpauth://totp/x',
      notes: 'private notes',
      passkeys: [],
      card: null,
      identity: null,
    });
    expect(errors).toHaveLength(0);
  });

  it('reports and decrypts passkeys (FIDO2)', async () => {
    const base = await makeCipher(userKey);
    const cipher: CipherResponse = {
      ...base,
      login: {
        ...base.login,
        fido2Credentials: [
          {
            credentialId: await enc('uuid-credential', userKey),
            keyType: await enc('public-key', userKey),
            keyAlgorithm: await enc('ECDSA', userKey),
            keyCurve: await enc('P-256', userKey),
            keyValue: await enc('private-key-pkcs8-b64', userKey),
            rpId: await enc('npmjs.com', userKey),
            userName: await enc('fredc', userKey),
            counter: await enc('0', userKey),
            creationDate: '2026-08-22T00:00:00Z',
          },
        ],
      },
    };

    const errors: unknown[] = [];
    const vue = await decryptCipherOverview(cipher, userKey, (e) => errors.push(e));
    expect(vue.hasPasskey).toBe(true);

    const details = await decryptCipherDetails(cipher, userKey, (e) => errors.push(e));
    expect(details.passkeys).toEqual([{ rpId: 'npmjs.com', userName: 'fredc' }]);
    expect(errors).toHaveLength(0);

    // The private key is never exposed by the views.
    expect(JSON.stringify(details)).not.toContain('private-key');
  });

  it('tolerates the PascalCase of older API versions', async () => {
    const pascal = {
      Id: 'item-pascal',
      Type: 1,
      Name: await enc('Titre', userKey),
      Notes: await enc('note', userKey),
      Login: {
        Username: await enc('bob', userKey),
        Password: await enc('secret', userKey),
        Uris: [{ Uri: await enc('https://exemple.fr', userKey) }],
      },
    } as unknown as CipherResponse;

    const errors: unknown[] = [];
    const onError = (e: unknown) => errors.push(e);

    const vue = await decryptCipherOverview(pascal, userKey, onError);
    expect(vue.id).toBe('item-pascal');
    expect(vue.name).toBe('Titre');
    expect(vue.username).toBe('bob');
    expect(vue.uris).toEqual(['https://exemple.fr']);

    const details = await decryptCipherDetails(pascal, userKey, onError);
    expect(details.username).toBe('bob');
    expect(details.password).toBe('secret');
    expect(errors).toHaveLength(0);
  });

  it('uses the item own key when it is present', async () => {
    const itemKey = SymmetricCryptoKey.generate();
    const cipher: CipherResponse = {
      ...(await makeCipher(itemKey)),
      key: (await encryptBytes(itemKey.key, userKey)).toString(),
    };

    const errors: unknown[] = [];
    const vue = await decryptCipherOverview(cipher, userKey, (e) => errors.push(e));
    const details = await decryptCipherDetails(cipher, userKey, (e) => errors.push(e));

    expect(vue.name).toBe('Ma banque');
    expect(details.password).toBe('strong-password');
    expect(errors).toHaveLength(0);

    // And resolution alone returns the item's key, not the vault's.
    const resolved = await resolveItemKey(cipher, userKey);
    expect(resolved.toBase64()).toBe(itemKey.toBase64());
    expect((await resolveItemKey(await makeCipher(userKey), userKey)).toBase64()).toBe(
      userKey.toBase64(),
    );
  });

  it('produces an empty view and reports if the item key is forged', async () => {
    const itemKey = SymmetricCryptoKey.generate();
    const otherKey = SymmetricCryptoKey.generate();
    const cipher: CipherResponse = {
      ...(await makeCipher(itemKey)),
      // Wrapped with a different key: the MAC will not match.
      key: (await encryptBytes(itemKey.key, otherKey)).toString(),
    };

    const errors: unknown[] = [];
    const vue = await decryptCipherOverview(cipher, userKey, (e) => errors.push(e));

    expect(vue.name).toBeNull();
    expect(vue.uris).toEqual([]);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toBeInstanceOf(MacMismatchError);
  });

  it('isolates a corrupted field without losing the others', async () => {
    const cipher: CipherResponse = {
      ...(await makeCipher(userKey)),
      name: 'pas une EncString',
    };

    const errors: unknown[] = [];
    const vue = await decryptCipherOverview(cipher, userKey, (e) => errors.push(e));

    expect(vue.name).toBeNull();
    expect(vue.uris).toEqual(['https://banque.exemple.fr']);
    expect(errors).toHaveLength(1);
  });

  it('decrypts a list preserving order, with bounded concurrency', async () => {
    const ciphers: CipherResponse[] = [];
    for (let i = 0; i < 20; i++) {
      ciphers.push({
        id: `item-${i}`,
        type: 1,
        name: await enc(`nom-${i}`, userKey),
        login: null,
      });
    }
    // One corrupted item in the middle must not fail the list.
    ciphers[7] = { ...ciphers[7]!, name: 'corrompu' };

    const errors: unknown[] = [];
    const vues = await decryptCipherList(ciphers, userKey, (e) => errors.push(e), 3);

    expect(vues).toHaveLength(20);
    expect(vues.map((v) => v.id)).toEqual(ciphers.map((c) => c.id));
    expect(vues[0]!.name).toBe('nom-0');
    expect(vues[7]!.name).toBeNull();
    expect(vues[19]!.name).toBe('nom-19');
    expect(errors).toHaveLength(1);
  });

  it('handles an empty list', async () => {
    expect(
      await decryptCipherList([], userKey, () => {
        throw new Error('must not be called');
      }),
    ).toEqual([]);
  });
});

describe('item update (buildCipherUpdatePayload)', () => {
  let userKey: SymmetricCryptoKey;

  beforeAll(() => {
    userKey = SymmetricCryptoKey.generate();
  });

  /** An existing item, encrypted with the given key. */
  async function rawCipher(key: SymmetricCryptoKey): Promise<CipherResponse> {
    return {
      id: 'item-1',
      type: 1,
      name: await enc('Ancien nom', key),
      notes: await enc('anciennes notes', key),
      login: {
        username: await enc('ancien@exemple.fr', key),
        password: await enc('ancien-mdp', key),
        uris: [{ uri: await enc('https://ancien.fr', key) }],
      },
      organizationId: null,
    };
  }

  const EDIT = {
    name: 'Nouveau nom',
    username: 'nouveau@exemple.fr',
    password: 'nouveau-mdp',
    totp: '',
    notes: 'nouvelles notes',
    uris: ['https://nouveau.fr', '  '],
  };

  async function dec(value: unknown, key: SymmetricCryptoKey): Promise<string | null> {
    return decryptStringOrNull(value as string, key, (e) => {
      throw e;
    });
  }

  it('re-encrypts the edited fields and preserves the others', async () => {
    const brut = {
      ...(await rawCipher(userKey)),
      folderId: 'dossier-1',
      favorite: true,
      reprompt: 1,
      fields: [{ name: 'champ-perso' }],
    } as unknown as CipherResponse;

    const payload = await buildCipherUpdatePayload(brut, EDIT, userKey, false);

    expect(await dec(payload['name'], userKey)).toBe('Nouveau nom');
    expect(await dec(payload['notes'], userKey)).toBe('nouvelles notes');

    const login = payload['login'] as Record<string, unknown>;
    expect(await dec(login['username'], userKey)).toBe('nouveau@exemple.fr');
    expect(await dec(login['password'], userKey)).toBe('nouveau-mdp');
    expect(login['totp']).toBeNull();

    const uris = login['uris'] as ReadonlyArray<Record<string, unknown>>;
    expect(uris).toHaveLength(1); // the blank line is dropped
    expect(await dec(uris[0]!['uri'], userKey)).toBe('https://nouveau.fr');

    // Unedited fields: carried over as-is.
    expect(payload['type']).toBe(1);
    expect(payload['folderId']).toBe('dossier-1');
    expect(payload['favorite']).toBe(true);
    expect(payload['reprompt']).toBe(1);
    expect(payload['fields']).toEqual([{ name: 'champ-perso' }]);
    expect(payload['organizationId']).toBeNull();
  });

  it('keeps the item key and encrypts with it', async () => {
    const itemKey = SymmetricCryptoKey.generate();
    const wrapped = (await encryptBytes(itemKey.key, userKey)).toString();
    const brut: CipherResponse = { ...(await rawCipher(itemKey)), key: wrapped };

    const payload = await buildCipherUpdatePayload(brut, EDIT, userKey, false);

    expect(payload['key']).toBe(wrapped);
    // The fields decrypt with the item's key, not the vault's.
    expect(await dec(payload['name'], itemKey)).toBe('Nouveau nom');
  });

  it('records the old password, still encrypted, in the history', async () => {
    const brut = await rawCipher(userKey);
    const payload = await buildCipherUpdatePayload(brut, EDIT, userKey, true);

    const histo = payload['passwordHistory'] as ReadonlyArray<Record<string, unknown>>;
    expect(histo).toHaveLength(1);
    expect(histo[0]!['password']).toBe(brut.login!.password);
    expect(await dec(histo[0]!['password'], userKey)).toBe('ancien-mdp');
  });

  it('caps the history at 5 entries', async () => {
    const existant = Array.from({ length: 6 }, (_, i) => ({ password: `h${i}`, lastUsedDate: 'd' }));
    const brut = { ...(await rawCipher(userKey)), passwordHistory: existant } as unknown as CipherResponse;

    const payload = await buildCipherUpdatePayload(brut, EDIT, userKey, true);
    expect(payload['passwordHistory'] as unknown[]).toHaveLength(5);
  });

  it('organisation item: encrypts with the organisation key', async () => {
    const orgKey = SymmetricCryptoKey.generate();
    const keys = { userKey, orgKeys: new Map([['org-9', orgKey]]) };
    const brut: CipherResponse = { ...(await rawCipher(orgKey)), organizationId: 'org-9' };

    const payload = await buildCipherUpdatePayload(brut, EDIT, keys, false);

    expect(payload['organizationId']).toBe('org-9');
    expect(await dec(payload['name'], orgKey)).toBe('Nouveau nom');
  });

  /**
   * The same class of bug as the erased passkeys, on every non-login type.
   *
   * An update replaces the whole item server-side. The payload only ever built a
   * `login` section, so renaming a card — or simply editing its notes — sent a
   * body with no `card` at all, and the server dropped the number, the holder
   * and the expiry. Silent, irreversible, and triggered by the most innocuous
   * edit there is.
   */
  it.each([
    ['card', 3, 'card', { number: 'enc-number', cardholderName: 'enc-holder' }],
    ['identity', 4, 'identity', { firstName: 'enc-first', ssn: 'enc-ssn' }],
    ['secure note', 2, 'secureNote', { type: 0 }],
    ['SSH key', 5, 'sshKey', { privateKey: 'enc-private' }],
  ])('preserves the %s section during an edit', async (_label, type, section, content) => {
    const existing = {
      ...(await rawCipher(userKey)),
      type,
      [section]: content,
    } as unknown as CipherResponse;

    const payload = await buildCipherUpdatePayload(existing, EDIT, userKey, false);

    expect(payload[section]).toEqual(content);
  });

  it('preserves passkeys as-is during an edit', async () => {
    const base = await rawCipher(userKey);
    const passkeys = [{ rpId: await enc('npmjs.com', userKey), keyValue: await enc('pk', userKey) }];
    const brut: CipherResponse = {
      ...base,
      login: { ...base.login, fido2Credentials: passkeys },
    };

    const payload = await buildCipherUpdatePayload(brut, EDIT, userKey, false);
    const login = payload['login'] as Record<string, unknown>;

    // Carried over identically, with no re-encryption and no loss.
    expect(login['fido2Credentials']).toEqual(passkeys);
  });
});

describe('organisation keyring', () => {
  let userKey: SymmetricCryptoKey;
  let orgKey: SymmetricCryptoKey;
  let profile: SyncResponse['profile'];

  beforeAll(async () => {
    userKey = SymmetricCryptoKey.generate();
    orgKey = SymmetricCryptoKey.generate();

    // A faithful reconstruction of the server profile: a member RSA pair, the
    // private key wrapped by the vault key (type 2), and the organisation key
    // encrypted to the public key (type 4, OAEP SHA-1).
    const pair = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-1',
      },
      true,
      ['encrypt', 'decrypt'],
    );
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
    const wrappedOrgKey = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'RSA-OAEP' },
        pair.publicKey,
        orgKey.key as unknown as BufferSource,
      ),
    );

    profile = {
      privateKey: (await encryptBytes(pkcs8, userKey)).toString(),
      organizations: [{ id: 'org-1', key: `4.${toBase64(wrappedOrgKey)}` }],
    };
  });

  it('unwraps the organisation key through the RSA private key', async () => {
    const errors: unknown[] = [];
    const keys = await buildVaultKeys(profile, userKey, (e) => errors.push(e));

    expect(errors).toHaveLength(0);
    expect(keys.orgKeys.size).toBe(1);
    expect(keys.orgKeys.get('org-1')?.toBase64()).toBe(orgKey.toBase64());
  });

  it('decrypts personal and organisation items side by side', async () => {
    const errors: unknown[] = [];
    const keys = await buildVaultKeys(profile, userKey, (e) => errors.push(e));

    const shared: CipherResponse = {
      id: 'shared',
      type: 1,
      organizationId: 'org-1',
      name: await enc('Compte shared', orgKey),
      login: { username: await enc('equipe@exemple.fr', orgKey) },
    };
    const perso: CipherResponse = {
      id: 'perso',
      type: 1,
      name: await enc('Compte perso', userKey),
      login: null,
    };

    const vues = await decryptCipherList([shared, perso], keys, (e) => errors.push(e));

    expect(errors).toHaveLength(0);
    expect(vues[0]!.name).toBe('Compte shared');
    expect(vues[0]!.username).toBe('equipe@exemple.fr');
    expect(vues[1]!.name).toBe('Compte perso');
  });

  it('reports MissingOrgKeyError for an unknown organisation', async () => {
    const keys = await buildVaultKeys(profile, userKey, () => undefined);
    const orphelin: CipherResponse = {
      id: 'orphelin',
      type: 1,
      organizationId: 'org-inconnue',
      name: await enc('Invisible', orgKey),
    };

    const errors: unknown[] = [];
    const vue = await decryptCipherOverview(orphelin, keys, (e) => errors.push(e));

    expect(vue.name).toBeNull();
    expect(errors).toHaveLength(1);
    expect(errors[0]).toBeInstanceOf(MissingOrgKeyError);
    expect((errors[0] as MissingOrgKeyError).organizationId).toBe('org-inconnue');
  });

  it('a profile with no organisation never touches RSA', async () => {
    const errors: unknown[] = [];
    const keys = await buildVaultKeys({}, userKey, (e) => errors.push(e));

    expect(keys.orgKeys.size).toBe(0);
    expect(errors).toHaveLength(0);
  });

  it('reports an unreadable private key without failing the keyring', async () => {
    const errors: unknown[] = [];
    const otherKey = SymmetricCryptoKey.generate();
    const brokenProfile: SyncResponse['profile'] = {
      // Private key wrapped by a different key: invalid MAC at unwrap time.
      privateKey: (await encryptBytes(new Uint8Array(64), otherKey)).toString(),
      organizations: [{ id: 'org-1', key: '4.AAAA' }],
    };

    const keys = await buildVaultKeys(brokenProfile, userKey, (e) => errors.push(e));
    expect(keys.orgKeys.size).toBe(0);
    expect(errors).toHaveLength(1);
  });
});

describe('labels: folders and collections', () => {
  let userKey: SymmetricCryptoKey;
  let orgKey: SymmetricCryptoKey;

  beforeAll(() => {
    userKey = SymmetricCryptoKey.generate();
    orgKey = SymmetricCryptoKey.generate();
  });

  it('decrypts folders (vault key) and collections (organisation key)', async () => {
    const errors: unknown[] = [];
    const sync: SyncResponse = {
      profile: {
        organizations: [{ id: 'org-1', name: 'Famille' }],
      },
      folders: [
        { id: 'f-1', name: await enc('Travail', userKey) },
        { id: 'f-2', name: await enc('Perso', userKey) },
      ],
      collections: [
        { id: 'c-1', organizationId: 'org-1', name: await enc('Banque', orgKey), readOnly: false },
        { id: 'c-2', organizationId: 'org-1', name: await enc('Archives', orgKey), readOnly: true },
      ],
    };
    const keys = { userKey, orgKeys: new Map([['org-1', orgKey]]) };

    const labels = await decryptLabels(sync, keys, (e) => errors.push(e));

    expect(errors).toHaveLength(0);
    expect(labels.folders.get('f-1')).toBe('Travail');
    expect(labels.folders.get('f-2')).toBe('Perso');
    expect(labels.collections.get('c-1')).toEqual({
      name: 'Banque',
      organizationId: 'org-1',
      readOnly: false,
    });
    expect(labels.collections.get('c-2')?.readOnly).toBe(true);
    expect(labels.organizations.get('org-1')).toBe('Famille');
  });

  it('skips and reports a collection whose organisation has no key', async () => {
    const errors: unknown[] = [];
    const sync: SyncResponse = {
      collections: [
        { id: 'c-x', organizationId: 'org-inconnue', name: await enc('Invisible', orgKey) },
      ],
    };

    const labels = await decryptLabels(sync, userKey, (e) => errors.push(e));

    expect(labels.collections.size).toBe(0);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toBeInstanceOf(MissingOrgKeyError);
  });

  it('a vault with no folder and no collection yields empty labels', async () => {
    const labels = await decryptLabels({}, userKey, (e) => {
      throw e;
    });
    expect(labels.folders.size).toBe(0);
    expect(labels.collections.size).toBe(0);
    expect(labels.organizations.size).toBe(0);
  });

  it('the list view carries folderId and collectionIds', async () => {
    const cipher: CipherResponse = {
      id: 'item-x',
      type: 1,
      name: await enc('Labelled', userKey),
      folderId: 'f-1',
      collectionIds: ['c-1', 'c-2'],
    };

    const vue = await decryptCipherOverview(cipher, userKey, (e) => {
      throw e;
    });
    expect(vue.folderId).toBe('f-1');
    expect(vue.collectionIds).toEqual(['c-1', 'c-2']);
  });
});

describe('reuseByRevision', () => {
  const apercu = (id: string, name: string): CipherOverview =>
    ({ id, name }) as CipherOverview;
  const chiffre = (id: string, revisionDate: string): CipherResponse =>
    ({ id, revisionDate }) as unknown as CipherResponse;

  it('reuses the overview when the revision has not changed', () => {
    const reuse = reuseByRevision(
      [apercu('i1', 'Ma banque')],
      new Map([['i1', chiffre('i1', '2026-09-01T10:00:00Z')]]),
    );
    expect(reuse(chiffre('i1', '2026-09-01T10:00:00Z'))?.name).toBe('Ma banque');
  });

  /** Edited here or from another device: it must be re-decrypted. */
  it('refuses to reuse when the revision has changed', () => {
    const reuse = reuseByRevision(
      [apercu('i1', 'Ma banque')],
      new Map([['i1', chiffre('i1', '2026-09-01T10:00:00Z')]]),
    );
    expect(reuse(chiffre('i1', '2026-09-02T11:00:00Z'))).toBeUndefined();
  });

  it('reuses nothing for an unknown item', () => {
    const reuse = reuseByRevision([], new Map());
    expect(reuse(chiffre('i9', '2026-09-01T10:00:00Z'))).toBeUndefined();
  });

  /**
   * With no date, nothing proves the content has not moved: the identifier alone
   * is never enough.
   */
  it('reuses nothing without a revision date', () => {
    const reuse = reuseByRevision(
      [apercu('i1', 'Ma banque')],
      new Map([['i1', chiffre('i1', '2026-09-01T10:00:00Z')]]),
    );
    expect(reuse({ id: 'i1' } as unknown as CipherResponse)).toBeUndefined();
  });
});

describe('origin matching (uriMatch)', () => {
  it('normalises to the strict origin', () => {
    expect(uriOrigin('https://exemple.fr/chemin/login?x=1')).toBe('https://exemple.fr');
    expect(uriOrigin('https://exemple.fr:8443/x')).toBe('https://exemple.fr:8443');
    expect(uriOrigin('exemple.fr')).toBe('https://exemple.fr');
    expect(uriOrigin('  exemple.fr/login  ')).toBe('https://exemple.fr');
  });

  it('rejects unusable URIs', () => {
    expect(uriOrigin('')).toBeNull();
    expect(uriOrigin('androidapp://com.exemple')).toBeNull();
  });

  /**
   * The common shape of a self-hosted service. `new URL('localhost:8080')`
   * succeeds, with protocol `localhost:`: stopping at the first parseable
   * candidate made all such URIs fail, silently.
   */
  it('accepts a host and a port with no scheme', () => {
    expect(uriOrigin('exemple.fr:8080')).toBe('https://exemple.fr:8080');
    expect(uriOrigin('exemple.fr:8080/connexion')).toBe('https://exemple.fr:8080');
    expect(uriOrigin('localhost:8080')).toBe('https://localhost:8080');
  });

  /**
   * The trap in the previous fix, and the reason scheme detection exists:
   * `https://mailto:alice@bank.example` parses as `https://bank.example`.
   * Prefixing without thinking turned a silent failure into a false match — an
   * item whose only URI is an email address would have offered autofill on the
   * bank.
   */
  it('does not fabricate an origin from an opaque scheme', () => {
    expect(uriOrigin('mailto:alice@banque.fr')).toBeNull();
    expect(uriOrigin('ssh://git@exemple.fr')).toBeNull();
    expect(uriOrigin('tel:+33123456789')).toBeNull();
    expect(matchesOrigin(['mailto:alice@banque.fr'], 'https://banque.fr')).toBe(false);
  });

  it('matches exactly, never by substring', () => {
    expect(matchesOrigin(['https://exemple.fr/login'], 'https://exemple.fr')).toBe(true);
    // The attack the strict-origin rule neutralises:
    expect(matchesOrigin(['https://banque.fr'], 'https://banque.fr.attaquant.com')).toBe(false);
    // A subdomain is not the origin.
    expect(matchesOrigin(['https://exemple.fr'], 'https://mail.exemple.fr')).toBe(false);
    // A different port is not the origin.
    expect(matchesOrigin(['https://exemple.fr'], 'https://exemple.fr:8443')).toBe(false);
    // HTTP is not HTTPS.
    expect(matchesOrigin(['https://exemple.fr'], 'http://exemple.fr')).toBe(false);
  });
});

describe('unlock (the unlock orchestrator)', () => {
  const EMAIL = 'test@exemple.fr';
  const PASSWORD = 'master password';
  const KDF_CONFIG: KdfConfig = { type: KdfType.PBKDF2_SHA256, iterations: 100_000 };

  let masterKey: SymmetricCryptoKey;
  let userKey: SymmetricCryptoKey;
  let protectedUserKey: string;
  let serverHash: string;

  beforeAll(async () => {
    // Fixture: the "server" knows the expected authorization hash and the
    // wrapped vault key, exactly as a real Vaultwarden does.
    masterKey = await deriveMasterKey(PASSWORD, EMAIL, KDF_CONFIG);
    const stretched = await stretchMasterKey(masterKey);
    userKey = SymmetricCryptoKey.generate();
    protectedUserKey = (await encryptBytes(userKey.key, stretched)).toString();
    serverHash = await derivePasswordHash(masterKey, PASSWORD, HashPurpose.ServerAuthorization);
  });

  /** Stubbed server: prelogin + token, with hash verification. */
  function fakeServer(options?: {
    kdfIterations?: number;
    omitKey?: boolean;
    protectedKeyOverride?: string;
    calls?: string[];
    /** Exige `twoFactorToken=code-123` avec le fournisseur 3, comme un compte YubiKey. */
    requireTwoFactor?: boolean;
  }): typeof fetch {
    return async (input, init) => {
      const url = String(input);
      options?.calls?.push(url);

      if (url.endsWith('/identity/accounts/prelogin')) {
        return jsonResponse(200, { kdf: 0, kdfIterations: options?.kdfIterations ?? 100_000 });
      }

      if (url.endsWith('/identity/connect/token')) {
        const form = new URLSearchParams(String(init?.body));
        if (form.get('password') !== serverHash) {
          return jsonResponse(400, {
            error: 'invalid_grant',
            error_description: 'Username or password is incorrect.',
          });
        }
        if (
          options?.requireTwoFactor === true &&
          !(form.get('twoFactorProvider') === '3' && form.get('twoFactorToken') === 'code-123')
        ) {
          return jsonResponse(400, {
            error: 'invalid_grant',
            TwoFactorProviders: ['3', '7'],
          });
        }
        const key = options?.protectedKeyOverride ?? protectedUserKey;
        return jsonResponse(200, {
          access_token: 'session-token',
          refresh_token: 'jeton-de-rafraichissement',
          expires_in: 3600,
          token_type: 'Bearer',
          ...(form.get('twoFactorRemember') === '1' ? { TwoFactorToken: '2fa-remember' } : {}),
          ...(options?.omitKey ? {} : { Key: key }),
        });
      }

      return new Response('', { status: 404 });
    };
  }

  function makeClient(fetchFn: typeof fetch): ApiClient {
    return new ApiClient({
      serverUrl: 'https://vault.example.com',
      deviceIdentifier: 'test-device',
      fetchFn,
    });
  }

  it('unlocks: hash accepted by the server, vault key returned', async () => {
    const result = await unlock(makeClient(fakeServer()), EMAIL, PASSWORD);

    // The key returned is bit for bit the one that was wrapped: the whole
    // derivation → stretching → unwrapping chain is coherent.
    expect(result.userKey.toBase64()).toBe(userKey.toBase64());
    expect(result.userKey.isAuthenticated).toBe(true);
    expect(result.session.accessToken).toBe('session-token');
    expect(result.kdfConfig).toEqual(KDF_CONFIG);

    // The local hash returned does validate the password offline.
    expect(await verifyLocalPasswordHash(masterKey, PASSWORD, result.localPasswordHash)).toBe(
      true,
    );
  });

  it('fails cleanly on a wrong password', async () => {
    const erreur = await unlock(makeClient(fakeServer()), EMAIL, 'mauvais mot de passe').catch(
      (e: unknown) => e,
    );
    expect(erreur).toBeInstanceOf(ApiError);
  });

  it('refuses a weak KDF before any derivation and any hash is sent', async () => {
    const calls: string[] = [];
    const erreur = await unlock(
      makeClient(fakeServer({ kdfIterations: 1, calls })),
      EMAIL,
      PASSWORD,
    ).catch((e: unknown) => e);

    expect(erreur).toBeInstanceOf(WeakKdfError);
    // Only prelogin was called: no hash was computed nor sent.
    expect(calls).toHaveLength(1);
    expect(calls[0]).toContain('/prelogin');
  });

  it('surfaces the second-factor demand with its providers', async () => {
    const erreur = await unlock(
      makeClient(fakeServer({ requireTwoFactor: true })),
      EMAIL,
      PASSWORD,
    ).catch((e: unknown) => e);

    expect(erreur).toBeInstanceOf(TwoFactorRequiredError);
    expect((erreur as TwoFactorRequiredError).providers).toEqual(['3', '7']);
  });

  it('unlocks with a second factor, and returns the remember token', async () => {
    const result = await unlock(
      makeClient(fakeServer({ requireTwoFactor: true })),
      EMAIL,
      PASSWORD,
      { provider: 3, token: 'code-123', remember: true },
    );

    expect(result.userKey.toBase64()).toBe(userKey.toBase64());
    expect(result.twoFactorRememberToken).toBe('2fa-remember');
  });

  it('rejects an invalid second factor as a fresh 2FA demand', async () => {
    const erreur = await unlock(
      makeClient(fakeServer({ requireTwoFactor: true })),
      EMAIL,
      PASSWORD,
      { provider: 3, token: 'mauvais-code' },
    ).catch((e: unknown) => e);

    expect(erreur).toBeInstanceOf(TwoFactorRequiredError);
  });

  it('returns no remember token without remember', async () => {
    const result = await unlock(makeClient(fakeServer()), EMAIL, PASSWORD);
    expect(result.twoFactorRememberToken).toBeUndefined();
  });

  it('fails with UnlockError if the server omits the vault key', async () => {
    const erreur = await unlock(makeClient(fakeServer({ omitKey: true })), EMAIL, PASSWORD).catch(
      (e: unknown) => e,
    );

    expect(erreur).toBeInstanceOf(UnlockError);
    expect((erreur as UnlockError).code).toBe('unlock-failed');
  });

  it('fails with MacMismatchError if the wrapped key is forged', async () => {
    // A key wrapped by a different stretched key: detectable through the MAC alone.
    const autreMaster = await deriveMasterKey('autre mot de passe', EMAIL, KDF_CONFIG);
    const otherStretched = await stretchMasterKey(autreMaster);
    const forged = (await encryptBytes(userKey.key, otherStretched)).toString();

    const erreur = await unlock(
      makeClient(fakeServer({ protectedKeyOverride: forged })),
      EMAIL,
      PASSWORD,
    ).catch((e: unknown) => e);

    expect(erreur).toBeInstanceOf(MacMismatchError);
  });
});

/**
 * Cards and identities, end to end.
 *
 * What is checked here is the round trip — a section written by the editor comes
 * back through decryption unchanged — and the promise the list makes: that a
 * card is identifiable in it **without** the chargeable number ever being held.
 */
describe('cards and identities', () => {
  let key: SymmetricCryptoKey;

  beforeAll(() => {
    key = SymmetricCryptoKey.generate();
  });

  const CARD = {
    cardholderName: 'Ada Lovelace',
    brand: 'Visa',
    number: '4242424242424242',
    expMonth: '4',
    expYear: '2030',
    code: '123',
  };

  const IDENTITY = {
    title: 'Dr',
    firstName: 'Ada',
    middleName: 'King',
    lastName: 'Lovelace',
    company: 'Analytical Engines',
    email: 'ada@example.org',
    phone: '+33100000000',
    username: 'ada',
    address1: '12 rue de la Paix',
    address2: '',
    address3: '',
    city: 'Paris',
    state: '',
    postalCode: '75002',
    country: 'France',
    ssn: '1 85 12 75 123 456',
    passportNumber: '20AB12345',
    licenseNumber: 'B-123456',
  };

  /** Encrypts every field of a section, as the server stores it. */
  async function encSection(values: Record<string, string>): Promise<Record<string, string>> {
    const entries = await Promise.all(
      Object.entries(values)
        .filter(([, value]) => value !== '')
        .map(async ([field, value]) => [field, await enc(value, key)] as const),
    );
    return Object.fromEntries(entries);
  }

  async function cardCipher(): Promise<CipherResponse> {
    return {
      id: 'card-1',
      type: 3,
      name: await enc('Carte bleue', key),
      card: await encSection(CARD),
      organizationId: null,
    } as unknown as CipherResponse;
  }

  async function identityCipher(): Promise<CipherResponse> {
    return {
      id: 'id-1',
      type: 4,
      name: await enc('Papiers', key),
      identity: await encSection(IDENTITY),
      organizationId: null,
    } as unknown as CipherResponse;
  }

  it('identifies a card in the list by its brand and its last four digits', async () => {
    const overview = await decryptCipherOverview(await cardCipher(), key, () => {
      throw new Error('no error expected');
    });
    expect(overview.subtitle).toBe('Visa \u2022\u2022\u2022\u2022 4242');
  });

  it('never lets the full number into the list view', async () => {
    const overview = await decryptCipherOverview(await cardCipher(), key, () => undefined);
    // The whole point of the subtitle: what the popup holds for the session is
    // the masked form, never a number that could be charged.
    expect(JSON.stringify(overview)).not.toContain('4242424242424242');
  });

  it('derives the brand from the number rather than trusting what was stored', async () => {
    const cipher = await cardCipher();
    // A vault imported from elsewhere can carry a brand that contradicts the
    // number; the number is the one that decides.
    (cipher as unknown as Record<string, Record<string, string>>)['card']!['brand'] = await enc(
      'Mastercard',
      key,
    );
    const overview = await decryptCipherOverview(cipher, key, () => undefined);
    expect(overview.subtitle).toBe('Visa \u2022\u2022\u2022\u2022 4242');
  });

  it('identifies an identity in the list by its name', async () => {
    const overview = await decryptCipherOverview(await identityCipher(), key, () => undefined);
    expect(overview.subtitle).toBe('Ada Lovelace');
  });

  it('decrypts every field of a card on demand', async () => {
    const details = await decryptCipherDetails(await cardCipher(), key, () => undefined);
    expect(details.card).toEqual(CARD);
    expect(details.identity).toBeNull();
  });

  it('decrypts every field of an identity on demand', async () => {
    const details = await decryptCipherDetails(await identityCipher(), key, () => undefined);
    expect(details.identity).toEqual({
      ...IDENTITY,
      address2: null,
      address3: null,
      state: null,
    });
    expect(details.card).toBeNull();
  });

  const EDIT = {
    name: 'Carte bleue',
    username: '',
    password: '',
    totp: '',
    notes: '',
    uris: [],
  };

  /** Decrypts a section of a payload back to cleartext. */
  async function readSection(section: unknown): Promise<Record<string, string | null>> {
    const entries = await Promise.all(
      Object.entries(section as Record<string, string | null>).map(
        async ([field, value]) =>
          [field, await decryptStringOrNull(value ?? undefined, key, () => undefined)] as const,
      ),
    );
    return Object.fromEntries(entries);
  }

  it('re-encrypts an edited card and reads it back unchanged', async () => {
    const edited = { ...CARD, number: '5555555555554444', code: '999' };
    const payload = await buildCipherUpdatePayload(
      await cardCipher(),
      { ...EDIT, card: edited },
      key,
      false,
    );
    expect(await readSection(payload['card'])).toEqual(edited);
  });

  it('re-encrypts an edited identity and reads it back unchanged', async () => {
    const edited = { ...IDENTITY, city: 'Lyon' };
    const payload = await buildCipherUpdatePayload(
      await identityCipher(),
      { ...EDIT, identity: edited },
      key,
      false,
    );
    expect(await readSection(payload['identity'])).toEqual({
      ...edited,
      address2: null,
      address3: null,
      state: null,
    });
  });

  it('carries the stored card over when the editor says nothing about it', async () => {
    const cipher = await cardCipher();
    const payload = await buildCipherUpdatePayload(cipher, EDIT, key, false);
    expect(payload['card']).toBe(
      (cipher as unknown as Record<string, unknown>)['card'],
    );
  });

  it('creates a card, with no login section', async () => {
    const payload = await buildCipherCreatePayload({ ...EDIT, type: 3, card: CARD }, key);
    expect(payload['type']).toBe(3);
    expect(payload['login']).toBeUndefined();
    expect(await readSection(payload['card'])).toEqual(CARD);
  });

  it('creates an identity, with no login section', async () => {
    const payload = await buildCipherCreatePayload({ ...EDIT, type: 4, identity: IDENTITY }, key);
    expect(payload['type']).toBe(4);
    expect(payload['login']).toBeUndefined();
  });

  it('creates a secure note with the sub-object the API demands', async () => {
    const payload = await buildCipherCreatePayload({ ...EDIT, type: 2 }, key);
    expect(payload['secureNote']).toEqual({ type: 0 });
  });

  it('still creates a login by default', async () => {
    const payload = await buildCipherCreatePayload(EDIT, key);
    expect(payload['type']).toBe(1);
    expect(payload['login']).toBeDefined();
  });
});

/**
 * What a rewrite must not drop.
 *
 * An update replaces the item whole, so every field the editor does not know
 * about has to be carried across explicitly. This is the failure that erased
 * passkeys once and wiped whole card sections a second time; these tests are
 * what stops it happening a third.
 */
describe('rewriting preserves what it does not edit', () => {
  let key: SymmetricCryptoKey;

  beforeAll(() => {
    key = SymmetricCryptoKey.generate();
  });

  const EDIT = {
    name: 'Renamed',
    username: 'alice',
    password: 'secret',
    totp: '',
    notes: '',
    uris: [],
  };

  it('keeps login settings the form never shows', async () => {
    const cipher = {
      id: 'x',
      type: 1,
      name: await enc('Before', key),
      login: {
        username: await enc('alice', key),
        password: await enc('secret', key),
        // Set in another client, invisible here — and lost until now on any
        // edit, including a rename.
        autofillOnPageLoad: true,
        passwordRevisionDate: '2024-01-01T00:00:00Z',
      },
      organizationId: null,
    } as unknown as CipherResponse;

    const payload = await buildCipherUpdatePayload(cipher, EDIT, key, false);
    const login = payload['login'] as Record<string, unknown>;
    expect(login['autofillOnPageLoad']).toBe(true);
    expect(login['passwordRevisionDate']).toBe('2024-01-01T00:00:00Z');
  });

  it('keeps a card field this version has never heard of', async () => {
    const cipher = {
      id: 'x',
      type: 3,
      name: await enc('Card', key),
      card: { number: await enc('4242424242424242', key), futureField: 'opaque' },
      organizationId: null,
    } as unknown as CipherResponse;

    const card = {
      cardholderName: 'Ada',
      brand: '',
      number: '4242424242424242',
      expMonth: '4',
      expYear: '2030',
      code: '123',
    };
    const payload = await buildCipherUpdatePayload(cipher, { ...EDIT, card }, key, false);
    expect((payload['card'] as Record<string, unknown>)['futureField']).toBe('opaque');
  });

  it('does not send the same field twice when the cache holds PascalCase', async () => {
    const cipher = {
      id: 'x',
      type: 3,
      name: await enc('Card', key),
      Card: { Number: await enc('4242424242424242', key) },
      organizationId: null,
    } as unknown as CipherResponse;

    const card = {
      cardholderName: '',
      brand: '',
      number: '4242424242424242',
      expMonth: '',
      expYear: '',
      code: '',
    };
    const payload = await buildCipherUpdatePayload(cipher, { ...EDIT, card }, key, false);
    const keys = Object.keys(payload['card'] as Record<string, unknown>);
    expect(keys.filter((name) => name.toLowerCase() === 'number')).toHaveLength(1);
  });
});
