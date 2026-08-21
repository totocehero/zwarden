/**
 * @file Tests de la couche coffre : orchestrateur de déverrouillage et
 * déchiffrement d'items.
 *
 * Le « serveur » simulé du déverrouillage n'est pas un simple distributeur de
 * réponses : il **vérifie le hash d'autorisation** contre une valeur
 * précalculée avec les mêmes primitives. Un `unlock` qui réussit prouve donc
 * que la chaîne dérivation → hash → login → étirement → déballage est
 * cohérente de bout en bout, sans réseau.
 */

import { beforeAll, describe, expect, it } from 'vitest';

import { ApiClient, ApiError, TwoFactorRequiredError } from '../src/core/api/apiClient.js';
import type { CipherResponse } from '../src/core/api/models.js';
import {
  MacMismatchError,
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
  decryptCipherDetails,
  decryptCipherList,
  decryptCipherOverview,
  resolveItemKey,
} from '../src/core/vault/cipherService.js';
import { UnlockError, unlock } from '../src/core/vault/session.js';

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status });
}

/** Chiffre une chaîne et la sérialise, pour construire des items de test. */
async function enc(text: string, key: SymmetricCryptoKey): Promise<string> {
  return (await encryptString(text, key)).toString();
}

describe('cipherService', () => {
  let userKey: SymmetricCryptoKey;

  beforeAll(() => {
    userKey = SymmetricCryptoKey.generate();
  });

  /** Construit un item camelCase complet, chiffré avec la clé fournie. */
  async function makeCipher(key: SymmetricCryptoKey): Promise<CipherResponse> {
    return {
      id: 'item-1',
      type: 1,
      name: await enc('Ma banque', key),
      notes: await enc('notes privées', key),
      login: {
        username: await enc('alice@exemple.fr', key),
        password: await enc('mot-de-passe-fort', key),
        totp: await enc('otpauth://totp/x', key),
        uris: [{ uri: await enc('https://banque.exemple.fr', key) }],
      },
      organizationId: null,
    };
  }

  it('déchiffre la vue de liste (camelCase)', async () => {
    const erreurs: unknown[] = [];
    const vue = await decryptCipherOverview(await makeCipher(userKey), userKey, (e) =>
      erreurs.push(e),
    );

    expect(vue).toEqual({
      id: 'item-1',
      type: 1,
      name: 'Ma banque',
      username: 'alice@exemple.fr',
      uris: ['https://banque.exemple.fr'],
      organizationId: null,
    });
    expect(erreurs).toHaveLength(0);
  });

  it('déchiffre les détails à la demande', async () => {
    const erreurs: unknown[] = [];
    const détails = await decryptCipherDetails(await makeCipher(userKey), userKey, (e) =>
      erreurs.push(e),
    );

    expect(détails).toEqual({
      username: 'alice@exemple.fr',
      password: 'mot-de-passe-fort',
      totp: 'otpauth://totp/x',
      notes: 'notes privées',
    });
    expect(erreurs).toHaveLength(0);
  });

  it('tolère la casse PascalCase des anciennes versions de l’API', async () => {
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

    const erreurs: unknown[] = [];
    const surErreur = (e: unknown) => erreurs.push(e);

    const vue = await decryptCipherOverview(pascal, userKey, surErreur);
    expect(vue.id).toBe('item-pascal');
    expect(vue.name).toBe('Titre');
    expect(vue.username).toBe('bob');
    expect(vue.uris).toEqual(['https://exemple.fr']);

    const détails = await decryptCipherDetails(pascal, userKey, surErreur);
    expect(détails.username).toBe('bob');
    expect(détails.password).toBe('secret');
    expect(erreurs).toHaveLength(0);
  });

  it('utilise la clé propre à l’item quand elle est présente', async () => {
    const itemKey = SymmetricCryptoKey.generate();
    const cipher: CipherResponse = {
      ...(await makeCipher(itemKey)),
      key: (await encryptBytes(itemKey.key, userKey)).toString(),
    };

    const erreurs: unknown[] = [];
    const vue = await decryptCipherOverview(cipher, userKey, (e) => erreurs.push(e));
    const détails = await decryptCipherDetails(cipher, userKey, (e) => erreurs.push(e));

    expect(vue.name).toBe('Ma banque');
    expect(détails.password).toBe('mot-de-passe-fort');
    expect(erreurs).toHaveLength(0);

    // Et la résolution seule rend bien la clé de l'item, pas celle du coffre.
    const résolue = await resolveItemKey(cipher, userKey);
    expect(résolue.toBase64()).toBe(itemKey.toBase64());
    expect((await resolveItemKey(await makeCipher(userKey), userKey)).toBase64()).toBe(
      userKey.toBase64(),
    );
  });

  it('produit une vue vide et notifie si la clé de l’item est falsifiée', async () => {
    const itemKey = SymmetricCryptoKey.generate();
    const autreClé = SymmetricCryptoKey.generate();
    const cipher: CipherResponse = {
      ...(await makeCipher(itemKey)),
      // Enveloppée avec une autre clé : le MAC ne correspondra pas.
      key: (await encryptBytes(itemKey.key, autreClé)).toString(),
    };

    const erreurs: unknown[] = [];
    const vue = await decryptCipherOverview(cipher, userKey, (e) => erreurs.push(e));

    expect(vue.name).toBeNull();
    expect(vue.uris).toEqual([]);
    expect(erreurs).toHaveLength(1);
    expect(erreurs[0]).toBeInstanceOf(MacMismatchError);
  });

  it('isole un champ corrompu sans perdre les autres', async () => {
    const cipher: CipherResponse = {
      ...(await makeCipher(userKey)),
      name: 'pas une EncString',
    };

    const erreurs: unknown[] = [];
    const vue = await decryptCipherOverview(cipher, userKey, (e) => erreurs.push(e));

    expect(vue.name).toBeNull();
    expect(vue.uris).toEqual(['https://banque.exemple.fr']);
    expect(erreurs).toHaveLength(1);
  });

  it('déchiffre une liste en préservant l’ordre, avec concurrence bornée', async () => {
    const ciphers: CipherResponse[] = [];
    for (let i = 0; i < 20; i++) {
      ciphers.push({
        id: `item-${i}`,
        type: 1,
        name: await enc(`nom-${i}`, userKey),
        login: null,
      });
    }
    // Un item corrompu au milieu ne doit pas faire échouer la liste.
    ciphers[7] = { ...ciphers[7]!, name: 'corrompu' };

    const erreurs: unknown[] = [];
    const vues = await decryptCipherList(ciphers, userKey, (e) => erreurs.push(e), 3);

    expect(vues).toHaveLength(20);
    expect(vues.map((v) => v.id)).toEqual(ciphers.map((c) => c.id));
    expect(vues[0]!.name).toBe('nom-0');
    expect(vues[7]!.name).toBeNull();
    expect(vues[19]!.name).toBe('nom-19');
    expect(erreurs).toHaveLength(1);
  });

  it('gère une liste vide', async () => {
    expect(
      await decryptCipherList([], userKey, () => {
        throw new Error('ne doit pas être appelé');
      }),
    ).toEqual([]);
  });
});

describe('unlock (orchestrateur de déverrouillage)', () => {
  const EMAIL = 'test@exemple.fr';
  const PASSWORD = 'mot de passe maître';
  const KDF_CONFIG: KdfConfig = { type: KdfType.PBKDF2_SHA256, iterations: 100_000 };

  let masterKey: SymmetricCryptoKey;
  let userKey: SymmetricCryptoKey;
  let protectedUserKey: string;
  let serverHash: string;

  beforeAll(async () => {
    // Fixture : le « serveur » connaît le hash d'autorisation attendu et la
    // clé de coffre enveloppée, exactement comme un vrai Vaultwarden.
    masterKey = await deriveMasterKey(PASSWORD, EMAIL, KDF_CONFIG);
    const stretched = await stretchMasterKey(masterKey);
    userKey = SymmetricCryptoKey.generate();
    protectedUserKey = (await encryptBytes(userKey.key, stretched)).toString();
    serverHash = await derivePasswordHash(masterKey, PASSWORD, HashPurpose.ServerAuthorization);
  });

  /** Serveur simulé : prelogin + jeton, avec vérification du hash. */
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
          access_token: 'jeton-de-session',
          refresh_token: 'jeton-de-rafraichissement',
          expires_in: 3600,
          token_type: 'Bearer',
          ...(form.get('twoFactorRemember') === '1' ? { TwoFactorToken: 'dispense-2fa' } : {}),
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

  it('déverrouille : hash accepté par le serveur, clé de coffre restituée', async () => {
    const résultat = await unlock(makeClient(fakeServer()), EMAIL, PASSWORD);

    // La clé restituée est bit à bit celle qui avait été enveloppée : toute la
    // chaîne dérivation → étirement → déballage est cohérente.
    expect(résultat.userKey.toBase64()).toBe(userKey.toBase64());
    expect(résultat.userKey.isAuthenticated).toBe(true);
    expect(résultat.session.accessToken).toBe('jeton-de-session');
    expect(résultat.kdfConfig).toEqual(KDF_CONFIG);

    // Le hash local restitué valide bien le mot de passe hors ligne.
    expect(await verifyLocalPasswordHash(masterKey, PASSWORD, résultat.localPasswordHash)).toBe(
      true,
    );
  });

  it('échoue proprement sur un mauvais mot de passe', async () => {
    const erreur = await unlock(makeClient(fakeServer()), EMAIL, 'mauvais mot de passe').catch(
      (e: unknown) => e,
    );
    expect(erreur).toBeInstanceOf(ApiError);
  });

  it('refuse un KDF faible avant toute dérivation et tout envoi de hash', async () => {
    const calls: string[] = [];
    const erreur = await unlock(
      makeClient(fakeServer({ kdfIterations: 1, calls })),
      EMAIL,
      PASSWORD,
    ).catch((e: unknown) => e);

    expect(erreur).toBeInstanceOf(WeakKdfError);
    // Seul prelogin a été appelé : aucun hash n'a été calculé ni transmis.
    expect(calls).toHaveLength(1);
    expect(calls[0]).toContain('/prelogin');
  });

  it('remonte la demande de second facteur avec ses fournisseurs', async () => {
    const erreur = await unlock(
      makeClient(fakeServer({ requireTwoFactor: true })),
      EMAIL,
      PASSWORD,
    ).catch((e: unknown) => e);

    expect(erreur).toBeInstanceOf(TwoFactorRequiredError);
    expect((erreur as TwoFactorRequiredError).providers).toEqual(['3', '7']);
  });

  it('déverrouille avec un second facteur, et rend le jeton de dispense', async () => {
    const résultat = await unlock(
      makeClient(fakeServer({ requireTwoFactor: true })),
      EMAIL,
      PASSWORD,
      { provider: 3, token: 'code-123', remember: true },
    );

    expect(résultat.userKey.toBase64()).toBe(userKey.toBase64());
    expect(résultat.twoFactorRememberToken).toBe('dispense-2fa');
  });

  it('rejette un second facteur invalide comme une nouvelle demande de 2FA', async () => {
    const erreur = await unlock(
      makeClient(fakeServer({ requireTwoFactor: true })),
      EMAIL,
      PASSWORD,
      { provider: 3, token: 'mauvais-code' },
    ).catch((e: unknown) => e);

    expect(erreur).toBeInstanceOf(TwoFactorRequiredError);
  });

  it('ne rend aucun jeton de dispense sans remember', async () => {
    const résultat = await unlock(makeClient(fakeServer()), EMAIL, PASSWORD);
    expect(résultat.twoFactorRememberToken).toBeUndefined();
  });

  it('échoue en UnlockError si le serveur omet la clé de coffre', async () => {
    const erreur = await unlock(makeClient(fakeServer({ omitKey: true })), EMAIL, PASSWORD).catch(
      (e: unknown) => e,
    );

    expect(erreur).toBeInstanceOf(UnlockError);
    expect((erreur as UnlockError).code).toBe('unlock-failed');
  });

  it('échoue en MacMismatchError si la clé enveloppée est falsifiée', async () => {
    // Clé enveloppée par une autre clé étirée : détectable uniquement par le MAC.
    const autreMaster = await deriveMasterKey('autre mot de passe', EMAIL, KDF_CONFIG);
    const autreStretched = await stretchMasterKey(autreMaster);
    const falsifiée = (await encryptBytes(userKey.key, autreStretched)).toString();

    const erreur = await unlock(
      makeClient(fakeServer({ protectedKeyOverride: falsifiée })),
      EMAIL,
      PASSWORD,
    ).catch((e: unknown) => e);

    expect(erreur).toBeInstanceOf(MacMismatchError);
  });
});
