/**
 * @file The "most recently used first" ordering.
 *
 * Two pure functions carry all the observable behaviour: the list's order
 * (`sortByLastUsed`) and the use log's cap (`pruneLastUsed`). The rest is just
 * storage.
 */

import { describe, expect, it } from 'vitest';

import type { CipherOverview } from '../src/core/vault/cipherService.js';
import { sortByLastUsed } from '../src/core/vault/cipherService.js';
import { pruneLastUsed } from '../src/shared/storage.js';

function item(id: string): CipherOverview {
  return {
    id,
    type: 1,
    name: id,
    username: null,
    uris: [],
    hasPasskey: false,
    hasTotp: false,
    reprompt: false,
    organizationId: null,
    folderId: null,
    collectionIds: [],
  };
}

const ids = (items: readonly CipherOverview[]): string[] => items.map((i) => i.id);

describe('sortByLastUsed', () => {
  const list = [item('a'), item('b'), item('c'), item('d')];

  it('leaves the list untouched when nothing has been used', () => {
    expect(sortByLastUsed(list, {})).toBe(list);
  });

  it('floats the used item to the top', () => {
    expect(ids(sortByLastUsed(list, { c: 1000 }))).toEqual(['c', 'a', 'b', 'd']);
  });

  it('orders used items from most to least recent', () => {
    expect(ids(sortByLastUsed(list, { a: 10, c: 30, d: 20 }))).toEqual(['c', 'd', 'a', 'b']);
  });

  it('preserves the original order of items never used', () => {
    expect(ids(sortByLastUsed(list, { d: 1 }))).toEqual(['d', 'a', 'b', 'c']);
  });

  it('ignores uses of items absent from the vault', () => {
    // An item deleted since, or belonging to another account.
    expect(ids(sortByLastUsed(list, { zzz: 999 }))).toEqual(['a', 'b', 'c', 'd']);
  });
});

describe('pruneLastUsed', () => {
  it('lets a short log through', () => {
    expect(pruneLastUsed({ a: 1, b: 2 })).toEqual({ a: 1, b: 2 });
  });

  it('keeps only the 100 most recent uses', () => {
    const large: Record<string, number> = {};
    for (let i = 0; i < 150; i += 1) {
      large[`id${i}`] = i;
    }
    const pruned = pruneLastUsed(large);
    expect(Object.keys(pruned)).toHaveLength(100);
    expect(pruned['id149']).toBe(149);
    expect(pruned['id50']).toBe(50);
    expect(pruned['id49']).toBeUndefined();
  });
});
