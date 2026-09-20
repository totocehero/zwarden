/**
 * @file Sealing the vault key.
 *
 * The claim being tested is narrow and worth stating exactly: the session store
 * no longer holds the vault key in clear, so the plaintext's lifetime drops
 * from the browser session to the popup's. It is **not** that a memory dump of
 * the browser would come up empty — Chrome implements WebCrypto in its own
 * process, and a full dump yields everything.
 *
 * What is pinned here: the round trip works, the stored form never contains the
 * key, a tampered seal refuses to open rather than yielding rubbish, and every
 * failure path returns "locked" instead of falling back to storing in clear.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';

import { fakeIndexedDb, withoutIndexedDb } from './support/fakes.js';

const VAULT_KEY = 'q83vEjRWeJCrze8SNFZ4kKvN7xI0VniQq83vEjRWeJA=';

describe('sealing the vault key', () => {
  let db: { records: Map<string, unknown> };

  beforeEach(() => {
    vi.resetModules();
    db = fakeIndexedDb();
  });

  async function load() {
    return import('../src/shared/keyGuard.js');
  }

  it('opens what it sealed', async () => {
    const { openVaultKey, sealVaultKey } = await load();
    const sealed = await sealVaultKey(VAULT_KEY);

    expect(sealed).not.toBeNull();
    expect(await openVaultKey(sealed!)).toBe(VAULT_KEY);
  });

  it('never puts the key itself in the sealed form', async () => {
    const { sealVaultKey } = await load();
    const sealed = await sealVaultKey(VAULT_KEY);

    // The whole point: what stays resident for the session is ciphertext.
    expect(sealed).not.toContain(VAULT_KEY);
    expect(sealed).not.toContain(VAULT_KEY.slice(0, 16));
  });

  it('keeps a key that cannot be exported, not key material', async () => {
    const { sealVaultKey } = await load();
    await sealVaultKey(VAULT_KEY);

    const stored = db.records.get('seal') as CryptoKey;
    expect(stored.type).toBe('secret');
    // Non-extractable: this module cannot export it either, which is what makes
    // storing it on disk defensible.
    expect(stored.extractable).toBe(false);
  });

  it('seals the same key differently every time', async () => {
    const { sealVaultKey } = await load();

    // A fresh nonce each time: two identical blobs would say the vault key had
    // not changed between two sessions.
    expect(await sealVaultKey(VAULT_KEY)).not.toBe(await sealVaultKey(VAULT_KEY));
  });

  it('refuses a seal that was altered, rather than yielding a wrong key', async () => {
    const { openVaultKey, sealVaultKey } = await load();
    const sealed = (await sealVaultKey(VAULT_KEY))!;

    // AES-GCM authenticates. A wrong key returned here would surface as an
    // unreadable vault and send the user looking in the wrong place.
    const flipped = sealed.slice(0, -2) + (sealed.endsWith('A=') ? 'B=' : 'A=');
    expect(await openVaultKey(flipped)).toBeNull();
  });

  it('opens nothing once the sealing key is destroyed', async () => {
    const { forgetSealingKey, openVaultKey, sealVaultKey } = await load();
    const sealed = (await sealVaultKey(VAULT_KEY))!;

    await forgetSealingKey();

    // Locking destroys one half; the other becomes inert, which is the property
    // that lets the disk half be stored on disk at all.
    expect(await openVaultKey(sealed)).toBeNull();
  });

  it('fails closed when there is no IndexedDB at all', async () => {
    withoutIndexedDb();
    const { openVaultKey, sealVaultKey } = await load();

    // No silent fallback to storing the key in clear. The user unlocks again.
    expect(await sealVaultKey(VAULT_KEY)).toBeNull();
    expect(await openVaultKey('AAAA')).toBeNull();
  });

  it('fails closed on a blob that is not a seal', async () => {
    const { openVaultKey, sealVaultKey } = await load();
    await sealVaultKey(VAULT_KEY);

    expect(await openVaultKey('not base64 at all !!')).toBeNull();
  });
});
