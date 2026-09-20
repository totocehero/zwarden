/**
 * @file The "most recently used first" ordering.
 *
 * Two pure functions carry all the observable behaviour: the list's order
 * (`sortCiphersByLastUsed`) and the use log's cap (`pruneLastUsed`). The rest is
 * just storage.
 *
 * The ordering is applied to items **before** they are decrypted, which is what
 * lets the popup decrypt the first screenful first. So it is checked on raw
 * items, in both the casings the API has used over its life — a sort that quietly
 * failed to read an identifier would put the whole vault back in server order.
 */

import { describe, expect, it } from 'vitest';

import type { CipherResponse } from '../src/core/api/models.js';
import { sortCiphersByLastUsed } from '../src/core/vault/cipherService.js';
import { pruneLastUsed } from '../src/shared/storage.js';

const item = (id: string): CipherResponse => ({ id, type: 1 }) as unknown as CipherResponse;

const ids = (items: readonly CipherResponse[]): string[] =>
  items.map((i) => (i as unknown as { id?: string; Id?: string }).id ?? '');

describe('sortCiphersByLastUsed', () => {
  const list = [item('a'), item('b'), item('c'), item('d')];

  it('leaves the list untouched when nothing has been used', () => {
    expect(sortCiphersByLastUsed(list, {})).toBe(list);
  });

  it('floats the used item to the top', () => {
    expect(ids(sortCiphersByLastUsed(list, { c: 1000 }))).toEqual(['c', 'a', 'b', 'd']);
  });

  it('orders used items from most to least recent', () => {
    expect(ids(sortCiphersByLastUsed(list, { a: 10, c: 30, d: 20 }))).toEqual([
      'c',
      'd',
      'a',
      'b',
    ]);
  });

  it('preserves the original order of items never used', () => {
    expect(ids(sortCiphersByLastUsed(list, { d: 1 }))).toEqual(['d', 'a', 'b', 'c']);
  });

  it('ignores uses of items absent from the vault', () => {
    // An item deleted since, or belonging to another account.
    expect(ids(sortCiphersByLastUsed(list, { zzz: 999 }))).toEqual(['a', 'b', 'c', 'd']);
  });

  it('reads the identifier in either casing', () => {
    // A cache written by an older API version holds PascalCase. Failing to read
    // the identifier here would silently return the whole vault in server order.
    const pascal = [
      { Id: 'a', Type: 1 },
      { Id: 'b', Type: 1 },
    ] as unknown as CipherResponse[];
    const sorted = sortCiphersByLastUsed(pascal, { b: 1000 });
    expect((sorted[0] as unknown as { Id: string }).Id).toBe('b');
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
