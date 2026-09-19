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
  buildCipherUpdatePayload,
  decryptCipherDetails,
  decryptCipherList,
  decryptCipherOverview,
  resolveItemKey,
} from '../src/core/vault/cipherService.js';
import { MissingOrgKeyError, buildVaultKeys } from '../src/core/vault/keyring.js';
import { decryptLabels } from '../src/core/vault/labels.js';
import { matchesOrigin, uriOrigin } from '../src/core/vault/uriMatch.js';
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
      hasPasskey: false,
      // L'item de test porte un TOTP : détecté sans être déchiffré.
      hasTotp: true,
      reprompt: false,
      organizationId: null,
      folderId: null,
      collectionIds: [],
    });
    expect(erreurs).toHaveLength(0);
  });

  /**
   * `reprompt` est une garde choisie par l'utilisateur : la popup refuse de
   * livrer un secret sans une nouvelle saisie du mot de passe maître. Elle
   * doit donc être lisible **sans** déchiffrement, et toute valeur non nulle
   * doit protéger — se tromper dans ce sens redemande un mot de passe,
   * l'inverse livre un secret sans garde.
   */
  it('repère la garde de mot de passe maître sans déchiffrer', async () => {
    const base = await makeCipher(userKey);
    const lire = async (reprompt: unknown): Promise<boolean> =>
      (await decryptCipherOverview({ ...base, reprompt } as CipherResponse, userKey, () => {}))
        .reprompt;

    expect(await lire(undefined)).toBe(false);
    expect(await lire(0)).toBe(false);
    expect(await lire(1)).toBe(true);
    expect(await lire(2)).toBe(true);
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
      passkeys: [],
    });
    expect(erreurs).toHaveLength(0);
  });

  it('signale et déchiffre les passkeys (FIDO2)', async () => {
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
            keyValue: await enc('clé-privée-pkcs8-b64', userKey),
            rpId: await enc('npmjs.com', userKey),
            userName: await enc('fredc', userKey),
            counter: await enc('0', userKey),
            creationDate: '2026-08-22T00:00:00Z',
          },
        ],
      },
    };

    const erreurs: unknown[] = [];
    const vue = await decryptCipherOverview(cipher, userKey, (e) => erreurs.push(e));
    expect(vue.hasPasskey).toBe(true);

    const détails = await decryptCipherDetails(cipher, userKey, (e) => erreurs.push(e));
    expect(détails.passkeys).toEqual([{ rpId: 'npmjs.com', userName: 'fredc' }]);
    expect(erreurs).toHaveLength(0);

    // La clé privée n'est jamais exposée par les vues.
    expect(JSON.stringify(détails)).not.toContain('clé-privée');
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

describe('mise à jour d’item (buildCipherUpdatePayload)', () => {
  let userKey: SymmetricCryptoKey;

  beforeAll(() => {
    userKey = SymmetricCryptoKey.generate();
  });

  /** Item existant, chiffré avec la clé fournie. */
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

  it('rechiffre les champs édités et préserve les autres', async () => {
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
    expect(uris).toHaveLength(1); // la ligne vide est écartée
    expect(await dec(uris[0]!['uri'], userKey)).toBe('https://nouveau.fr');

    // Champs non édités : repris tels quels.
    expect(payload['type']).toBe(1);
    expect(payload['folderId']).toBe('dossier-1');
    expect(payload['favorite']).toBe(true);
    expect(payload['reprompt']).toBe(1);
    expect(payload['fields']).toEqual([{ name: 'champ-perso' }]);
    expect(payload['organizationId']).toBeNull();
  });

  it('conserve la clé d’item et chiffre avec elle', async () => {
    const itemKey = SymmetricCryptoKey.generate();
    const wrapped = (await encryptBytes(itemKey.key, userKey)).toString();
    const brut: CipherResponse = { ...(await rawCipher(itemKey)), key: wrapped };

    const payload = await buildCipherUpdatePayload(brut, EDIT, userKey, false);

    expect(payload['key']).toBe(wrapped);
    // Les champs se déchiffrent avec la clé de l'item, pas celle du coffre.
    expect(await dec(payload['name'], itemKey)).toBe('Nouveau nom');
  });

  it('consigne l’ancien mot de passe, encore chiffré, dans l’historique', async () => {
    const brut = await rawCipher(userKey);
    const payload = await buildCipherUpdatePayload(brut, EDIT, userKey, true);

    const histo = payload['passwordHistory'] as ReadonlyArray<Record<string, unknown>>;
    expect(histo).toHaveLength(1);
    expect(histo[0]!['password']).toBe(brut.login!.password);
    expect(await dec(histo[0]!['password'], userKey)).toBe('ancien-mdp');
  });

  it('plafonne l’historique à 5 entrées', async () => {
    const existant = Array.from({ length: 6 }, (_, i) => ({ password: `h${i}`, lastUsedDate: 'd' }));
    const brut = { ...(await rawCipher(userKey)), passwordHistory: existant } as unknown as CipherResponse;

    const payload = await buildCipherUpdatePayload(brut, EDIT, userKey, true);
    expect(payload['passwordHistory'] as unknown[]).toHaveLength(5);
  });

  it('item d’organisation : chiffre avec la clé de l’organisation', async () => {
    const orgKey = SymmetricCryptoKey.generate();
    const keys = { userKey, orgKeys: new Map([['org-9', orgKey]]) };
    const brut: CipherResponse = { ...(await rawCipher(orgKey)), organizationId: 'org-9' };

    const payload = await buildCipherUpdatePayload(brut, EDIT, keys, false);

    expect(payload['organizationId']).toBe('org-9');
    expect(await dec(payload['name'], orgKey)).toBe('Nouveau nom');
  });

  it('préserve les passkeys telles quelles lors d’une édition', async () => {
    const base = await rawCipher(userKey);
    const passkeys = [{ rpId: await enc('npmjs.com', userKey), keyValue: await enc('pk', userKey) }];
    const brut: CipherResponse = {
      ...base,
      login: { ...base.login, fido2Credentials: passkeys },
    };

    const payload = await buildCipherUpdatePayload(brut, EDIT, userKey, false);
    const login = payload['login'] as Record<string, unknown>;

    // Reprises à l'identique, sans re-chiffrement ni perte.
    expect(login['fido2Credentials']).toEqual(passkeys);
  });
});

describe('trousseau d’organisations (keyring)', () => {
  let userKey: SymmetricCryptoKey;
  let orgKey: SymmetricCryptoKey;
  let profile: SyncResponse['profile'];

  beforeAll(async () => {
    userKey = SymmetricCryptoKey.generate();
    orgKey = SymmetricCryptoKey.generate();

    // Reconstitution fidèle du profil serveur : une paire RSA de membre, la
    // clé privée enveloppée par la clé du coffre (type 2), et la clé de
    // l'organisation chiffrée vers la clé publique (type 4, OAEP SHA-1).
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

  it('déballe la clé d’organisation via la clé privée RSA', async () => {
    const erreurs: unknown[] = [];
    const keys = await buildVaultKeys(profile, userKey, (e) => erreurs.push(e));

    expect(erreurs).toHaveLength(0);
    expect(keys.orgKeys.size).toBe(1);
    expect(keys.orgKeys.get('org-1')?.toBase64()).toBe(orgKey.toBase64());
  });

  it('déchiffre côte à côte items personnels et items d’organisation', async () => {
    const erreurs: unknown[] = [];
    const keys = await buildVaultKeys(profile, userKey, (e) => erreurs.push(e));

    const partagé: CipherResponse = {
      id: 'partagé',
      type: 1,
      organizationId: 'org-1',
      name: await enc('Compte partagé', orgKey),
      login: { username: await enc('equipe@exemple.fr', orgKey) },
    };
    const perso: CipherResponse = {
      id: 'perso',
      type: 1,
      name: await enc('Compte perso', userKey),
      login: null,
    };

    const vues = await decryptCipherList([partagé, perso], keys, (e) => erreurs.push(e));

    expect(erreurs).toHaveLength(0);
    expect(vues[0]!.name).toBe('Compte partagé');
    expect(vues[0]!.username).toBe('equipe@exemple.fr');
    expect(vues[1]!.name).toBe('Compte perso');
  });

  it('signale MissingOrgKeyError pour une organisation inconnue', async () => {
    const keys = await buildVaultKeys(profile, userKey, () => undefined);
    const orphelin: CipherResponse = {
      id: 'orphelin',
      type: 1,
      organizationId: 'org-inconnue',
      name: await enc('Invisible', orgKey),
    };

    const erreurs: unknown[] = [];
    const vue = await decryptCipherOverview(orphelin, keys, (e) => erreurs.push(e));

    expect(vue.name).toBeNull();
    expect(erreurs).toHaveLength(1);
    expect(erreurs[0]).toBeInstanceOf(MissingOrgKeyError);
    expect((erreurs[0] as MissingOrgKeyError).organizationId).toBe('org-inconnue');
  });

  it('un profil sans organisation ne touche jamais au RSA', async () => {
    const erreurs: unknown[] = [];
    const keys = await buildVaultKeys({}, userKey, (e) => erreurs.push(e));

    expect(keys.orgKeys.size).toBe(0);
    expect(erreurs).toHaveLength(0);
  });

  it('signale une clé privée illisible sans faire échouer le trousseau', async () => {
    const erreurs: unknown[] = [];
    const autreClé = SymmetricCryptoKey.generate();
    const profilCassé: SyncResponse['profile'] = {
      // Clé privée enveloppée par une autre clé : MAC invalide au déballage.
      privateKey: (await encryptBytes(new Uint8Array(64), autreClé)).toString(),
      organizations: [{ id: 'org-1', key: '4.AAAA' }],
    };

    const keys = await buildVaultKeys(profilCassé, userKey, (e) => erreurs.push(e));
    expect(keys.orgKeys.size).toBe(0);
    expect(erreurs).toHaveLength(1);
  });
});

describe('étiquettes : dossiers et collections (labels)', () => {
  let userKey: SymmetricCryptoKey;
  let orgKey: SymmetricCryptoKey;

  beforeAll(() => {
    userKey = SymmetricCryptoKey.generate();
    orgKey = SymmetricCryptoKey.generate();
  });

  it('déchiffre dossiers (clé du coffre) et collections (clé d’organisation)', async () => {
    const erreurs: unknown[] = [];
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

    const labels = await decryptLabels(sync, keys, (e) => erreurs.push(e));

    expect(erreurs).toHaveLength(0);
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

  it('ignore et signale une collection dont l’organisation n’a pas de clé', async () => {
    const erreurs: unknown[] = [];
    const sync: SyncResponse = {
      collections: [
        { id: 'c-x', organizationId: 'org-inconnue', name: await enc('Invisible', orgKey) },
      ],
    };

    const labels = await decryptLabels(sync, userKey, (e) => erreurs.push(e));

    expect(labels.collections.size).toBe(0);
    expect(erreurs).toHaveLength(1);
    expect(erreurs[0]).toBeInstanceOf(MissingOrgKeyError);
  });

  it('un coffre sans dossier ni collection rend des étiquettes vides', async () => {
    const labels = await decryptLabels({}, userKey, (e) => {
      throw e;
    });
    expect(labels.folders.size).toBe(0);
    expect(labels.collections.size).toBe(0);
    expect(labels.organizations.size).toBe(0);
  });

  it('la vue de liste transporte folderId et collectionIds', async () => {
    const cipher: CipherResponse = {
      id: 'item-x',
      type: 1,
      name: await enc('Étiqueté', userKey),
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

describe('correspondance d’origine (uriMatch)', () => {
  it('normalise vers l’origine stricte', () => {
    expect(uriOrigin('https://exemple.fr/chemin/login?x=1')).toBe('https://exemple.fr');
    expect(uriOrigin('https://exemple.fr:8443/x')).toBe('https://exemple.fr:8443');
    expect(uriOrigin('exemple.fr')).toBe('https://exemple.fr');
    expect(uriOrigin('  exemple.fr/login  ')).toBe('https://exemple.fr');
  });

  it('rejette les URIs inexploitables', () => {
    expect(uriOrigin('')).toBeNull();
    expect(uriOrigin('androidapp://com.exemple')).toBeNull();
  });

  /**
   * Forme courante d'un service auto-hébergé. `new URL('localhost:8080')`
   * réussit, avec le protocole `localhost:` : s'arrêter au premier candidat
   * analysable faisait échouer toutes ces URIs, silencieusement.
   */
  it('accepte un hôte et un port sans schéma', () => {
    expect(uriOrigin('exemple.fr:8080')).toBe('https://exemple.fr:8080');
    expect(uriOrigin('exemple.fr:8080/connexion')).toBe('https://exemple.fr:8080');
    expect(uriOrigin('localhost:8080')).toBe('https://localhost:8080');
  });

  /**
   * Le piège de la correction précédente, et la raison d'être de la détection
   * de schéma : `https://mailto:alice@banque.fr` s'analyse en
   * `https://banque.fr`. Préfixer sans réfléchir transformait un échec muet en
   * correspondance fausse — un item dont l'unique URI est une adresse e-mail
   * aurait proposé le remplissage sur la banque.
   */
  it('ne fabrique pas une origine depuis un schéma opaque', () => {
    expect(uriOrigin('mailto:alice@banque.fr')).toBeNull();
    expect(uriOrigin('ssh://git@exemple.fr')).toBeNull();
    expect(uriOrigin('tel:+33123456789')).toBeNull();
    expect(matchesOrigin(['mailto:alice@banque.fr'], 'https://banque.fr')).toBe(false);
  });

  it('correspond exactement, jamais par sous-chaîne', () => {
    expect(matchesOrigin(['https://exemple.fr/login'], 'https://exemple.fr')).toBe(true);
    // L'attaque que la règle d'origine stricte neutralise :
    expect(matchesOrigin(['https://banque.fr'], 'https://banque.fr.attaquant.com')).toBe(false);
    // Sous-domaine ≠ origine.
    expect(matchesOrigin(['https://exemple.fr'], 'https://mail.exemple.fr')).toBe(false);
    // Port différent ≠ origine.
    expect(matchesOrigin(['https://exemple.fr'], 'https://exemple.fr:8443')).toBe(false);
    // HTTP ≠ HTTPS.
    expect(matchesOrigin(['https://exemple.fr'], 'http://exemple.fr')).toBe(false);
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
