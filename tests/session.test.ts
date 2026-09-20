/**
 * @file The vault key's own entry, and who is allowed to read it.
 *
 * `chrome.storage` serialises to JSON, so the vault key crosses as a base64
 * string — and a JavaScript string is immutable: it cannot be wiped, only
 * dropped and left to the collector. Every needless read is therefore a
 * needless copy of the key lying in the reader's heap, possibly paged to swap
 * before it is collected (`docs/STORAGE.md` §1).
 *
 * Nothing can make that string wipeable under MV3 — a non-extractable
 * `CryptoKey` would, and `chrome.storage` cannot hold one. What can be done is
 * confine the key to the one context that decrypts. These tests are what keeps
 * it confined: the service worker asks four times a session whether it exists,
 * one of them on every credential capture, and none of those may bring the key
 * along.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';

import { KdfType } from '../src/core/crypto/kdf.js';

/** A `chrome.storage.session` that records which keys were asked for. */
function fakeSession(): { data: Record<string, unknown>; reads: string[] } {
  const data: Record<string, unknown> = {};
  const reads: string[] = [];
  const area = {
    get: vi.fn(async (keys: string | string[] | null) => {
      const list = keys === null ? Object.keys(data) : Array.isArray(keys) ? keys : [keys];
      reads.push(...list);
      return Object.fromEntries(list.filter((k) => k in data).map((k) => [k, data[k]]));
    }),
    set: vi.fn(async (patch: Record<string, unknown>) => Object.assign(data, patch)),
    remove: vi.fn(async (keys: string | string[]) => {
      for (const k of Array.isArray(keys) ? keys : [keys]) delete data[k];
    }),
  };
  (globalThis as unknown as { chrome: unknown }).chrome = {
    storage: { session: area, local: area },
  };
  return { data, reads };
}

const SESSION = {
  accessToken: 'access',
  refreshToken: 'refresh',
  expiresAt: Date.now() + 3_600_000,
  serverUrl: 'https://vault.example.org',
  email: 'ada@example.org',
  cachedSync: null,
  localPasswordHash: 'hash',
  kdfConfig: { type: KdfType.PBKDF2_SHA256, iterations: 600_000 },
} as const;

describe('the vault key lives apart from the session', () => {
  let store: { data: Record<string, unknown>; reads: string[] };

  beforeEach(() => {
    vi.resetModules();
    store = fakeSession();
  });

  async function load() {
    return import('../src/shared/storage.js');
  }

  it('stores the key under its own entry, not inside the session', async () => {
    const { saveStoredSession, saveVaultKey } = await load();
    await saveStoredSession(SESSION);
    await saveVaultKey('dmF1bHQta2V5');

    expect(JSON.stringify(store.data['session'])).not.toContain('dmF1bHQta2V5');
    expect(store.data['vaultKey']).toBe('dmF1bHQta2V5');
  });

  it('hands the key back to the one caller that decrypts', async () => {
    const { loadVaultKey, saveVaultKey } = await load();
    await saveVaultKey('dmF1bHQta2V5');

    expect(await loadVaultKey()).toBe('dmF1bHQta2V5');
  });

  it('does not read the key when only asked whether a session exists', async () => {
    const { hasStoredSession, saveStoredSession, saveVaultKey } = await load();
    await saveStoredSession(SESSION);
    await saveVaultKey('dmF1bHQta2V5');
    store.reads.length = 0;

    expect(await hasStoredSession()).toBe(true);
    // The service worker's whole relationship with the session, on every
    // credential capture. It must not pull the key into its heap to answer.
    expect(store.reads).not.toContain('vaultKey');
  });

  it('does not read the key when reading the session', async () => {
    const { loadStoredSession, saveStoredSession, saveVaultKey } = await load();
    await saveStoredSession(SESSION);
    await saveVaultKey('dmF1bHQta2V5');
    store.reads.length = 0;

    const session = await loadStoredSession();
    expect(session?.accessToken).toBe('access');
    expect(store.reads).not.toContain('vaultKey');
    // Belt and braces: the shape itself must not carry it.
    expect(JSON.stringify(session)).not.toContain('dmF1bHQta2V5');
  });

  it('clears the key with the session, never one without the other', async () => {
    const { clearStoredSession, loadVaultKey, saveStoredSession, saveVaultKey } = await load();
    await saveStoredSession(SESSION);
    await saveVaultKey('dmF1bHQta2V5');

    await clearStoredSession();

    // A key outliving its session would be one nothing can use and nothing
    // would think to clear.
    expect(await loadVaultKey()).toBeNull();
    expect(store.data['session']).toBeUndefined();
  });

  it('reports no key when the vault is locked', async () => {
    const { loadVaultKey } = await load();
    expect(await loadVaultKey()).toBeNull();
  });

  it('refuses a session that lost its KDF parameters', async () => {
    // Without them a re-entered master password could not be verified, and a
    // `reprompt` item would open with no guard at all.
    const { loadStoredSession } = await load();
    store.data['session'] = { ...SESSION, kdfConfig: { type: 99 } };

    expect(await loadStoredSession()).toBeNull();
  });
});
