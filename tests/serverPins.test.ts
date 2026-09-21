/**
 * @file What the server said last time, remembered so a change is a refusal.
 *
 * Two facts a hostile server can change between two unlocks: the KDF
 * parameters it announces before authentication, and the organisation keys it
 * wraps to the member's public key. Neither is bound to anything the user
 * controls, so the only defence available client-side is memory — trust on
 * first use, and refusal on change.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';

import { KdfType } from '../src/core/crypto/kdf.js';
import { SymmetricCryptoKey } from '../src/core/crypto/symmetricCryptoKey.js';
import type { OrgKeyRefusedError } from '../src/core/vault/keyring.js';

import { fakeChromeStorage } from './support/fakes.js';

const SERVER = 'https://vault.example.org';
const EMAIL = 'Ada@Example.org';

describe('remembered server parameters', () => {
  let store: { data: Record<string, unknown> };

  beforeEach(() => {
    vi.resetModules();
    store = fakeChromeStorage();
  });

  async function load() {
    return import('../src/shared/storage.js');
  }

  it('remembers the KDF that unlocked, per account, and forgets on request', async () => {
    const { loadPinnedKdf, savePinnedKdf, clearAllServerPins } = await load();
    expect(await loadPinnedKdf(SERVER, EMAIL)).toBeNull();

    await savePinnedKdf(SERVER, EMAIL, { type: KdfType.PBKDF2_SHA256, iterations: 600_000 });
    // The email is normalised: the same account, however it was typed.
    expect(await loadPinnedKdf(SERVER, 'ada@example.org')).toEqual({
      type: KdfType.PBKDF2_SHA256,
      iterations: 600_000,
    });
    expect(await loadPinnedKdf('https://other.example.org', EMAIL)).toBeNull();

    expect(await clearAllServerPins()).toBe(1);
    expect(await loadPinnedKdf(SERVER, EMAIL)).toBeNull();
  });

  it('pins organisation keys on first sight and notes them as new for the session', async () => {
    const { pinOrganisationKeys, loadNewOrganisations, loadOrgKeyPins } = await load();
    const ring = {
      userKey: SymmetricCryptoKey.generate(),
      orgKeys: new Map([['org-1', SymmetricCryptoKey.generate()]]),
    };
    const errors: unknown[] = [];

    const out = await pinOrganisationKeys(SERVER, EMAIL, ring, (e) => errors.push(e));

    expect(errors).toEqual([]);
    expect(out.orgKeys.has('org-1')).toBe(true);
    expect(Object.keys(await loadOrgKeyPins(SERVER, EMAIL))).toEqual(['org-1']);
    expect(await loadNewOrganisations()).toEqual(['org-1']);
  });

  it('refuses a changed organisation key, reports it, and drops it from the ring', async () => {
    const { pinOrganisationKeys, loadNewOrganisations } = await load();
    const userKey = SymmetricCryptoKey.generate();
    const first = { userKey, orgKeys: new Map([['org-1', SymmetricCryptoKey.generate()]]) };
    await pinOrganisationKeys(SERVER, EMAIL, first, () => undefined);
    // A new session: the "new" list is memory and is gone.
    delete store.data['newOrganisations'];

    const swapped = { userKey, orgKeys: new Map([['org-1', SymmetricCryptoKey.generate()]]) };
    const errors: unknown[] = [];
    const out = await pinOrganisationKeys(SERVER, EMAIL, swapped, (e) => errors.push(e));

    expect(out.orgKeys.size).toBe(0);
    expect(errors).toHaveLength(1);
    // By name, not `instanceof`: `vi.resetModules()` gives the storage module
    // its own copy of the class, and two copies of one class are two classes.
    const refused = errors[0] as OrgKeyRefusedError;
    expect(refused.name).toBe('OrgKeyRefusedError');
    expect(refused.organizationId).toBe('org-1');
    expect(refused.reason).toBe('changed');
    // Seen before, refused now: not "new", so nothing else changes for it.
    expect(await loadNewOrganisations()).toEqual([]);
  });

  it('accepts the same key again without noting it as new', async () => {
    const { pinOrganisationKeys, loadNewOrganisations } = await load();
    const userKey = SymmetricCryptoKey.generate();
    const orgKey = SymmetricCryptoKey.generate();
    const ring = { userKey, orgKeys: new Map([['org-1', orgKey]]) };
    await pinOrganisationKeys(SERVER, EMAIL, ring, () => undefined);
    delete store.data['newOrganisations'];

    const errors: unknown[] = [];
    const out = await pinOrganisationKeys(SERVER, EMAIL, ring, (e) => errors.push(e));

    expect(errors).toEqual([]);
    expect(out).toBe(ring);
    expect(await loadNewOrganisations()).toEqual([]);
  });

  it('forgets the new organisations with the session', async () => {
    const { noteNewOrganisations, loadNewOrganisations, clearStoredSession } = await load();
    await noteNewOrganisations(['org-1']);
    await clearStoredSession();
    expect(await loadNewOrganisations()).toEqual([]);
  });
});
