/**
 * @file The exclusion list, and the reason it is hashed.
 *
 * This list lives in `chrome.storage.local`, which is an unencrypted database
 * inside the browser profile. A plain list of hostnames there is a list of the
 * sites the user holds an account on, readable by anyone holding the drive and
 * needing no vault at all (`docs/STORAGE.md`).
 *
 * What the hashing changes is the question an attacker can ask — enumerate
 * becomes confirm — and that is what these tests pin: the behaviour is
 * unchanged, and the stored form never contains a host.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';

import { fakeChromeStorage } from './support/fakes.js';

describe('never-save hosts', () => {
  let store: { data: Record<string, unknown> };

  beforeEach(async () => {
    vi.resetModules();
    store = fakeChromeStorage();
  });

  /** Imported after the stub is in place: the module reads `chrome` at load. */
  async function load() {
    return import('../src/shared/storage.js');
  }

  it('remembers a host and recognises it again', async () => {
    const { addNeverSaveHost, isNeverSaveHost } = await load();
    await addNeverSaveHost('bank.example');

    expect(await isNeverSaveHost('bank.example')).toBe(true);
    expect(await isNeverSaveHost('other.example')).toBe(false);
  });

  it('never writes the host itself to disk', async () => {
    const { addNeverSaveHost } = await load();
    await addNeverSaveHost('bank.example');

    // The whole point: what lands on disk must not name the site.
    expect(JSON.stringify(store.data)).not.toContain('bank.example');
  });

  it('stores a SHA-256 digest', async () => {
    const { addNeverSaveHost } = await load();
    await addNeverSaveHost('bank.example');

    const entries = store.data['neverSaveHosts'] as string[];
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatch(/^[0-9a-f]{64}$/);
  });

  it('gives two installs different digests for the same host', async () => {
    const { addNeverSaveHost } = await load();
    await addNeverSaveHost('bank.example');
    const first = (store.data['neverSaveHosts'] as string[])[0];

    vi.resetModules();
    const second = fakeChromeStorage();
    const fresh = await import('../src/shared/storage.js');
    await fresh.addNeverSaveHost('bank.example');

    // A per-install salt: a digest captured from one profile proves nothing
    // about another.
    expect((second.data['neverSaveHosts'] as string[])[0]).not.toBe(first);
  });

  it('does not add the same host twice', async () => {
    const { addNeverSaveHost } = await load();
    await addNeverSaveHost('bank.example');
    await addNeverSaveHost('bank.example');

    expect(store.data['neverSaveHosts']).toHaveLength(1);
  });

  it('normalises case and surrounding space', async () => {
    const { addNeverSaveHost, isNeverSaveHost } = await load();
    await addNeverSaveHost('Bank.Example');

    expect(await isNeverSaveHost('  bank.example ')).toBe(true);
  });

  it('still honours a list written before hashing existed', async () => {
    // An upgrade must not silently forget the user's exclusions.
    store.data['neverSaveHosts'] = ['legacy.example'];
    const { isNeverSaveHost } = await load();

    expect(await isNeverSaveHost('legacy.example')).toBe(true);
  });

  it('forgets the salt along with the list', async () => {
    const { addNeverSaveHost, clearNeverSaveHosts } = await load();
    await addNeverSaveHost('bank.example');

    expect(await clearNeverSaveHosts()).toBe(1);
    // Keeping the salt would let a digest captured from the old list be tested
    // against the new one.
    expect(store.data['neverSaveSalt']).toBeUndefined();
    expect(store.data['neverSaveHosts']).toBeUndefined();
  });

  it('reports nothing to forget when the list is empty', async () => {
    const { clearNeverSaveHosts } = await load();
    expect(await clearNeverSaveHosts()).toBe(0);
  });
});
