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
/** A lighter configuration: we test the mechanism, not the resistance. */
const PBKDF2_FAST: KdfConfig = { type: KdfType.PBKDF2_SHA256, iterations: 100_000 };

describe('KDF parameter validation', () => {
  it('accepts PBKDF2 at the recommended values', () => {
    expect(() => assertKdfIsAcceptable(PBKDF2)).not.toThrow();
  });

  it.each([1, 100, 5_000, 99_999])('refuses PBKDF2 at %i iterations', (iterations) => {
    expect(() => assertKdfIsAcceptable({ type: KdfType.PBKDF2_SHA256, iterations })).toThrow(
      WeakKdfError,
    );
  });

  it('accepts Argon2id at the default values', () => {
    expect(() =>
      assertKdfIsAcceptable({ type: KdfType.Argon2id, ...ARGON2_DEFAULTS }),
    ).not.toThrow();
  });

  it.each([
    ['iterations too low', { iterations: 1, memoryMiB: 64, parallelism: 4 }],
    ['memory too low', { iterations: 3, memoryMiB: 8, parallelism: 4 }],
    ['zero parallelism', { iterations: 3, memoryMiB: 64, parallelism: 0 }],
  ])('refuses Argon2id: %s', (_label, params) => {
    expect(() => assertKdfIsAcceptable({ type: KdfType.Argon2id, ...params })).toThrow(WeakKdfError);
  });

  // Upper bounds: a hostile server can announce absurd parameters to freeze the
  // client at unlock (denial of service). See kdf.ts.
  it.each([5_000_001, 2 ** 31, Number.MAX_SAFE_INTEGER])(
    'refuses PBKDF2 at %i iterations (anti-DoS ceiling)',
    (iterations) => {
      expect(() => assertKdfIsAcceptable({ type: KdfType.PBKDF2_SHA256, iterations })).toThrow(
        WeakKdfError,
      );
    },
  );

  it.each([
    ['iterations too high', { iterations: 11, memoryMiB: 64, parallelism: 4 }],
    ['outsized memory', { iterations: 3, memoryMiB: 1_048_576, parallelism: 4 }],
    ['parallelism too high', { iterations: 3, memoryMiB: 64, parallelism: 17 }],
  ])('refuses Argon2id (anti-DoS ceiling): %s', (_label, params) => {
    expect(() => assertKdfIsAcceptable({ type: KdfType.Argon2id, ...params })).toThrow(WeakKdfError);
  });

  // The parameters come from untrusted JSON: a float, NaN, or a string dressed
  // up as a number must never reach the KDF.
  it.each([
    ['float', 600_000.5],
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['string', '600000' as unknown as number],
    ['null', null as unknown as number],
  ])('refuses PBKDF2 with non-integer iterations: %s', (_label, iterations) => {
    expect(() => assertKdfIsAcceptable({ type: KdfType.PBKDF2_SHA256, iterations })).toThrow(
      WeakKdfError,
    );
  });

  it('refuses Argon2id with non-integer memory', () => {
    expect(() =>
      assertKdfIsAcceptable({ type: KdfType.Argon2id, iterations: 3, memoryMiB: 64.5, parallelism: 4 }),
    ).toThrow(WeakKdfError);
  });
});

describe('master key derivation (PBKDF2)', () => {
  it('produces an unauthenticated 32-byte key', async () => {
    const key = await deriveMasterKey('password', 'user@example.com', PBKDF2_FAST);
    expect(key.key).toHaveLength(32);
    expect(key.isAuthenticated).toBe(false);
  });

  it('is deterministic', async () => {
    const a = await deriveMasterKey('pw', 'a@b.c', PBKDF2_FAST);
    const b = await deriveMasterKey('pw', 'a@b.c', PBKDF2_FAST);
    expect(a.toBase64()).toBe(b.toBase64());
  });

  it('normalises the email (case and spaces)', async () => {
    const ref = await deriveMasterKey('pw', 'user@example.com', PBKDF2_FAST);
    for (const variant of ['USER@EXAMPLE.COM', '  user@example.com  ', 'User@Example.Com']) {
      expect((await deriveMasterKey('pw', variant, PBKDF2_FAST)).toBase64()).toBe(
        ref.toBase64(),
      );
    }
  });

  it('does not normalise the password case', async () => {
    const a = await deriveMasterKey('pw', 'a@b.c', PBKDF2_FAST);
    const b = await deriveMasterKey('PW', 'a@b.c', PBKDF2_FAST);
    expect(a.toBase64()).not.toBe(b.toBase64());
  });

  it('separates accounts through the salt (the email)', async () => {
    const a = await deriveMasterKey('pw', 'alice@example.com', PBKDF2_FAST);
    const b = await deriveMasterKey('pw', 'bob@example.com', PBKDF2_FAST);
    expect(a.toBase64()).not.toBe(b.toBase64());
  });

  it('refuses a too-weak KDF announced by the server', async () => {
    await expect(
      deriveMasterKey('pw', 'a@b.c', { type: KdfType.PBKDF2_SHA256, iterations: 1 }),
    ).rejects.toThrow(WeakKdfError);
  });
});

describe('master key derivation (Argon2id)', () => {
  const config: KdfConfig = {
    type: KdfType.Argon2id,
    iterations: 2,
    memoryMiB: 16,
    parallelism: 1,
  };

  it('produces a 32-byte key', async () => {
    const key = await deriveMasterKey('password', 'user@example.com', config);
    expect(key.key).toHaveLength(32);
  });

  it('is deterministic', async () => {
    const a = await deriveMasterKey('pw', 'a@b.c', config);
    const b = await deriveMasterKey('pw', 'a@b.c', config);
    expect(a.toBase64()).toBe(b.toBase64());
  });

  it('differs from the PBKDF2 result', async () => {
    const argon = await deriveMasterKey('pw', 'a@b.c', config);
    const pbkdf2 = await deriveMasterKey('pw', 'a@b.c', PBKDF2_FAST);
    expect(argon.toBase64()).not.toBe(pbkdf2.toBase64());
  });
});

describe('master key stretching', () => {
  it('produces 64 authenticated bytes', async () => {
    const master = await deriveMasterKey('pw', 'a@b.c', PBKDF2_FAST);
    const stretched = await stretchMasterKey(master);

    expect(stretched.key).toHaveLength(64);
    expect(stretched.isAuthenticated).toBe(true);
    expect(stretched.encKey).not.toEqual(stretched.macKey);
  });

  it('yields a key usable for encryption', async () => {
    const master = await deriveMasterKey('pw', 'a@b.c', PBKDF2_FAST);
    const stretched = await stretchMasterKey(master);
    const enc = await encryptString('vault key', stretched);
    expect(await decryptString(enc, stretched)).toBe('vault key');
  });

  it('is deterministic', async () => {
    const master = await deriveMasterKey('pw', 'a@b.c', PBKDF2_FAST);
    expect((await stretchMasterKey(master)).toBase64()).toBe(
      (await stretchMasterKey(master)).toBase64(),
    );
  });
});

describe('master password hash', () => {
  it('produces 32 bytes in base64', async () => {
    const master = await deriveMasterKey('pw', 'a@b.c', PBKDF2_FAST);
    const hash = await derivePasswordHash(master, 'pw', HashPurpose.ServerAuthorization);
    expect(hash).toMatch(/^[A-Za-z0-9+/]{43}=$/);
  });

  it('differs from the local hash (the server cannot replay the stored one)', async () => {
    const master = await deriveMasterKey('pw', 'a@b.c', PBKDF2_FAST);
    const server = await derivePasswordHash(master, 'pw', HashPurpose.ServerAuthorization);
    const local = await derivePasswordHash(master, 'pw', HashPurpose.LocalAuthorization);
    expect(server).not.toBe(local);
  });

  it('does not disclose the master key', async () => {
    const master = await deriveMasterKey('pw', 'a@b.c', PBKDF2_FAST);
    const hash = await derivePasswordHash(master, 'pw', HashPurpose.ServerAuthorization);
    expect(hash).not.toBe(master.toBase64());
  });

  it('changes with the password', async () => {
    const master = await deriveMasterKey('pw', 'a@b.c', PBKDF2_FAST);
    expect(await derivePasswordHash(master, 'pw', HashPurpose.ServerAuthorization)).not.toBe(
      await derivePasswordHash(master, 'other', HashPurpose.ServerAuthorization),
    );
  });
});

describe('local password validation (lock screen)', () => {
  it('accepts the right password', async () => {
    const master = await deriveMasterKey('pw', 'a@b.c', PBKDF2_FAST);
    const stored = await derivePasswordHash(master, 'pw', HashPurpose.LocalAuthorization);

    expect(await verifyLocalPasswordHash(master, 'pw', stored)).toBe(true);
  });

  it('rejects a wrong password', async () => {
    const master = await deriveMasterKey('pw', 'a@b.c', PBKDF2_FAST);
    const stored = await derivePasswordHash(master, 'pw', HashPurpose.LocalAuthorization);

    expect(await verifyLocalPasswordHash(master, 'almost-pw', stored)).toBe(false);
  });

  it('rejects the server hash replayed as a local one', async () => {
    // The two purposes differ in iteration count: an intercepted authorization
    // hash does not unlock the vault locally.
    const master = await deriveMasterKey('pw', 'a@b.c', PBKDF2_FAST);
    const server = await derivePasswordHash(master, 'pw', HashPurpose.ServerAuthorization);

    expect(await verifyLocalPasswordHash(master, 'pw', server)).toBe(false);
  });
});
