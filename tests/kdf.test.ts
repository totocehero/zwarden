import { describe, expect, it } from 'vitest';

import {
  ARGON2_DEFAULTS,
  KdfType,
  WeakKdfError,
  assertKdfIsAcceptable,
  HashPurpose,
  derivePasswordHash,
  deriveMasterKey,
  stretchMasterKey,
  verifyLocalPasswordHash,
  type KdfConfig,
} from '../src/core/crypto/kdf.js';
import { decryptString, encryptString } from '../src/core/crypto/cryptoService.js';

const PBKDF2: KdfConfig = { type: KdfType.PBKDF2_SHA256, iterations: 600_000 };
/** Configuration allégée : on teste la mécanique, pas la résistance. */
const PBKDF2_RAPIDE: KdfConfig = { type: KdfType.PBKDF2_SHA256, iterations: 100_000 };

describe('validation des paramètres KDF', () => {
  it('accepte PBKDF2 aux valeurs recommandées', () => {
    expect(() => assertKdfIsAcceptable(PBKDF2)).not.toThrow();
  });

  it.each([1, 100, 5_000, 99_999])('refuse PBKDF2 à %i itérations', (iterations) => {
    expect(() => assertKdfIsAcceptable({ type: KdfType.PBKDF2_SHA256, iterations })).toThrow(
      WeakKdfError,
    );
  });

  it('accepte Argon2id aux valeurs par défaut', () => {
    expect(() =>
      assertKdfIsAcceptable({ type: KdfType.Argon2id, ...ARGON2_DEFAULTS }),
    ).not.toThrow();
  });

  it.each([
    ['itérations trop basses', { iterations: 1, memoryMiB: 64, parallelism: 4 }],
    ['mémoire trop basse', { iterations: 3, memoryMiB: 8, parallelism: 4 }],
    ['parallélisme nul', { iterations: 3, memoryMiB: 64, parallelism: 0 }],
  ])('refuse Argon2id : %s', (_label, params) => {
    expect(() => assertKdfIsAcceptable({ type: KdfType.Argon2id, ...params })).toThrow(WeakKdfError);
  });

  // Bornes hautes : un serveur hostile peut annoncer des paramètres absurdes
  // pour geler le client au déverrouillage (déni de service). Voir kdf.ts.
  it.each([5_000_001, 2 ** 31, Number.MAX_SAFE_INTEGER])(
    'refuse PBKDF2 à %i itérations (plafond anti-DoS)',
    (iterations) => {
      expect(() => assertKdfIsAcceptable({ type: KdfType.PBKDF2_SHA256, iterations })).toThrow(
        WeakKdfError,
      );
    },
  );

  it.each([
    ['itérations trop hautes', { iterations: 11, memoryMiB: 64, parallelism: 4 }],
    ['mémoire démesurée', { iterations: 3, memoryMiB: 1_048_576, parallelism: 4 }],
    ['parallélisme trop haut', { iterations: 3, memoryMiB: 64, parallelism: 17 }],
  ])('refuse Argon2id (plafond anti-DoS) : %s', (_label, params) => {
    expect(() => assertKdfIsAcceptable({ type: KdfType.Argon2id, ...params })).toThrow(WeakKdfError);
  });

  // Les paramètres viennent d'un JSON non fiable : un flottant, NaN ou une
  // chaîne déguisée en nombre ne doivent jamais atteindre le KDF.
  it.each([
    ['flottant', 600_000.5],
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['chaîne', '600000' as unknown as number],
    ['null', null as unknown as number],
  ])('refuse PBKDF2 avec des itérations non entières : %s', (_label, iterations) => {
    expect(() => assertKdfIsAcceptable({ type: KdfType.PBKDF2_SHA256, iterations })).toThrow(
      WeakKdfError,
    );
  });

  it('refuse Argon2id avec une mémoire non entière', () => {
    expect(() =>
      assertKdfIsAcceptable({ type: KdfType.Argon2id, iterations: 3, memoryMiB: 64.5, parallelism: 4 }),
    ).toThrow(WeakKdfError);
  });
});

describe('dérivation de la clé maître (PBKDF2)', () => {
  it('produit une clé de 32 octets non authentifiée', async () => {
    const key = await deriveMasterKey('mot-de-passe', 'user@example.com', PBKDF2_RAPIDE);
    expect(key.key).toHaveLength(32);
    expect(key.isAuthenticated).toBe(false);
  });

  it('est déterministe', async () => {
    const a = await deriveMasterKey('mdp', 'a@b.c', PBKDF2_RAPIDE);
    const b = await deriveMasterKey('mdp', 'a@b.c', PBKDF2_RAPIDE);
    expect(a.toBase64()).toBe(b.toBase64());
  });

  it('normalise l’e-mail (casse et espaces)', async () => {
    const ref = await deriveMasterKey('mdp', 'user@example.com', PBKDF2_RAPIDE);
    for (const variante of ['USER@EXAMPLE.COM', '  user@example.com  ', 'User@Example.Com']) {
      expect((await deriveMasterKey('mdp', variante, PBKDF2_RAPIDE)).toBase64()).toBe(
        ref.toBase64(),
      );
    }
  });

  it('ne normalise pas la casse du mot de passe', async () => {
    const a = await deriveMasterKey('mdp', 'a@b.c', PBKDF2_RAPIDE);
    const b = await deriveMasterKey('MDP', 'a@b.c', PBKDF2_RAPIDE);
    expect(a.toBase64()).not.toBe(b.toBase64());
  });

  it('sépare les comptes par le sel (l’e-mail)', async () => {
    const a = await deriveMasterKey('mdp', 'alice@example.com', PBKDF2_RAPIDE);
    const b = await deriveMasterKey('mdp', 'bob@example.com', PBKDF2_RAPIDE);
    expect(a.toBase64()).not.toBe(b.toBase64());
  });

  it('refuse un KDF trop faible annoncé par le serveur', async () => {
    await expect(
      deriveMasterKey('mdp', 'a@b.c', { type: KdfType.PBKDF2_SHA256, iterations: 1 }),
    ).rejects.toThrow(WeakKdfError);
  });
});

describe('dérivation de la clé maître (Argon2id)', () => {
  const config: KdfConfig = {
    type: KdfType.Argon2id,
    iterations: 2,
    memoryMiB: 16,
    parallelism: 1,
  };

  it('produit une clé de 32 octets', async () => {
    const key = await deriveMasterKey('mot-de-passe', 'user@example.com', config);
    expect(key.key).toHaveLength(32);
  });

  it('est déterministe', async () => {
    const a = await deriveMasterKey('mdp', 'a@b.c', config);
    const b = await deriveMasterKey('mdp', 'a@b.c', config);
    expect(a.toBase64()).toBe(b.toBase64());
  });

  it('diffère du résultat PBKDF2', async () => {
    const argon = await deriveMasterKey('mdp', 'a@b.c', config);
    const pbkdf2 = await deriveMasterKey('mdp', 'a@b.c', PBKDF2_RAPIDE);
    expect(argon.toBase64()).not.toBe(pbkdf2.toBase64());
  });
});

describe('étirement de la clé maître', () => {
  it('produit 64 octets authentifiés', async () => {
    const master = await deriveMasterKey('mdp', 'a@b.c', PBKDF2_RAPIDE);
    const stretched = await stretchMasterKey(master);

    expect(stretched.key).toHaveLength(64);
    expect(stretched.isAuthenticated).toBe(true);
    expect(stretched.encKey).not.toEqual(stretched.macKey);
  });

  it('donne une clé utilisable pour chiffrer', async () => {
    const master = await deriveMasterKey('mdp', 'a@b.c', PBKDF2_RAPIDE);
    const stretched = await stretchMasterKey(master);
    const enc = await encryptString('clé du coffre', stretched);
    expect(await decryptString(enc, stretched)).toBe('clé du coffre');
  });

  it('est déterministe', async () => {
    const master = await deriveMasterKey('mdp', 'a@b.c', PBKDF2_RAPIDE);
    expect((await stretchMasterKey(master)).toBase64()).toBe(
      (await stretchMasterKey(master)).toBase64(),
    );
  });
});

describe('hash du mot de passe maître', () => {
  it('produit 32 octets en base64', async () => {
    const master = await deriveMasterKey('mdp', 'a@b.c', PBKDF2_RAPIDE);
    const hash = await derivePasswordHash(master, 'mdp', HashPurpose.ServerAuthorization);
    expect(hash).toMatch(/^[A-Za-z0-9+/]{43}=$/);
  });

  it('diffère du hash local (le serveur ne peut pas rejouer le hash stocké)', async () => {
    const master = await deriveMasterKey('mdp', 'a@b.c', PBKDF2_RAPIDE);
    const serveur = await derivePasswordHash(master, 'mdp', HashPurpose.ServerAuthorization);
    const local = await derivePasswordHash(master, 'mdp', HashPurpose.LocalAuthorization);
    expect(serveur).not.toBe(local);
  });

  it('ne divulgue pas la clé maître', async () => {
    const master = await deriveMasterKey('mdp', 'a@b.c', PBKDF2_RAPIDE);
    const hash = await derivePasswordHash(master, 'mdp', HashPurpose.ServerAuthorization);
    expect(hash).not.toBe(master.toBase64());
  });

  it('change avec le mot de passe', async () => {
    const master = await deriveMasterKey('mdp', 'a@b.c', PBKDF2_RAPIDE);
    expect(await derivePasswordHash(master, 'mdp', HashPurpose.ServerAuthorization)).not.toBe(
      await derivePasswordHash(master, 'autre', HashPurpose.ServerAuthorization),
    );
  });
});

describe('validation locale du mot de passe (écran de verrouillage)', () => {
  it('accepte le bon mot de passe', async () => {
    const master = await deriveMasterKey('mdp', 'a@b.c', PBKDF2_RAPIDE);
    const stocké = await derivePasswordHash(master, 'mdp', HashPurpose.LocalAuthorization);

    expect(await verifyLocalPasswordHash(master, 'mdp', stocké)).toBe(true);
  });

  it('rejette un mauvais mot de passe', async () => {
    const master = await deriveMasterKey('mdp', 'a@b.c', PBKDF2_RAPIDE);
    const stocké = await derivePasswordHash(master, 'mdp', HashPurpose.LocalAuthorization);

    expect(await verifyLocalPasswordHash(master, 'presque-mdp', stocké)).toBe(false);
  });

  it('rejette le hash serveur rejoué comme hash local', async () => {
    // Les deux usages diffèrent par leur nombre d'itérations : le hash
    // d'autorisation intercepté ne déverrouille pas le coffre localement.
    const master = await deriveMasterKey('mdp', 'a@b.c', PBKDF2_RAPIDE);
    const serveur = await derivePasswordHash(master, 'mdp', HashPurpose.ServerAuthorization);

    expect(await verifyLocalPasswordHash(master, 'mdp', serveur)).toBe(false);
  });
});
