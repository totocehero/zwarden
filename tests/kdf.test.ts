import { describe, expect, it } from 'vitest';

import {
  ARGON2_DEFAULTS,
  KdfType,
  WeakKdfError,
  assertKdfIsAcceptable,
  deriveLocalPasswordHash,
  deriveMasterKey,
  deriveMasterPasswordHash,
  stretchMasterKey,
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
    const hash = await deriveMasterPasswordHash(master, 'mdp');
    expect(hash).toMatch(/^[A-Za-z0-9+/]{43}=$/);
  });

  it('diffère du hash local (le serveur ne peut pas rejouer le hash stocké)', async () => {
    const master = await deriveMasterKey('mdp', 'a@b.c', PBKDF2_RAPIDE);
    const serveur = await deriveMasterPasswordHash(master, 'mdp');
    const local = await deriveLocalPasswordHash(master, 'mdp');
    expect(serveur).not.toBe(local);
  });

  it('ne divulgue pas la clé maître', async () => {
    const master = await deriveMasterKey('mdp', 'a@b.c', PBKDF2_RAPIDE);
    const hash = await deriveMasterPasswordHash(master, 'mdp');
    expect(hash).not.toBe(master.toBase64());
  });

  it('change avec le mot de passe', async () => {
    const master = await deriveMasterKey('mdp', 'a@b.c', PBKDF2_RAPIDE);
    expect(await deriveMasterPasswordHash(master, 'mdp')).not.toBe(
      await deriveMasterPasswordHash(master, 'autre'),
    );
  });
});
