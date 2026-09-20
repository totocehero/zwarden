/**
 * @file Which type chips the list offers.
 *
 * The only rule in the filter bar worth being sure of: it offers the types the
 * vault actually holds, in a fixed order, and it says nothing at all when
 * saying something would change nothing.
 */

import { describe, expect, it } from 'vitest';

import { chipsToShow, toggleType } from '../src/popup/components/TypeFilter.js';

const counts = (entries: Record<number, number>): ReadonlyMap<number, number> =>
  new Map(Object.entries(entries).map(([type, n]) => [Number(type), n]));

describe('chipsToShow', () => {
  it('offers only the types the vault holds', () => {
    expect(chipsToShow(counts({ 1: 40, 3: 2 }))).toEqual([1, 3]);
  });

  it('lays them out in the order they are used, not the order the API numbers them', () => {
    // Cards and identities before secure notes, whatever their type numbers.
    expect(chipsToShow(counts({ 1: 1, 2: 1, 3: 1, 4: 1, 5: 1 }))).toEqual([1, 3, 4, 2, 5]);
  });

  it('says nothing when every chip would show the same list', () => {
    expect(chipsToShow(counts({ 1: 40 }))).toEqual([]);
    expect(chipsToShow(counts({}))).toEqual([]);
  });

  it('ignores a type present only as an empty count', () => {
    expect(chipsToShow(counts({ 1: 40, 4: 0 }))).toEqual([]);
  });

  it('ignores a type it has no chip for', () => {
    // Type 6 does not exist today; it must not create a nameless chip.
    expect(chipsToShow(counts({ 1: 3, 6: 9 }))).toEqual([]);
  });
});

describe('toggleType', () => {
  it('adds a type that was not shown', () => {
    expect([...toggleType(new Set(), 3)]).toEqual([3]);
  });

  it('keeps several types at once', () => {
    const selection = toggleType(toggleType(new Set([1]), 3), 4);
    expect([...selection].sort()).toEqual([1, 3, 4]);
  });

  it('removes a type that was shown', () => {
    expect([...toggleType(new Set([1, 3]), 3)]).toEqual([1]);
  });

  it('falls back to everything rather than nothing when the last one goes off', () => {
    // An empty selection means every type. The alternative — an empty list whose
    // only escape is guessing which chip to press again — would be a trap.
    expect(toggleType(new Set([3]), 3).size).toBe(0);
  });

  it('does not alter the selection it was given', () => {
    const before = new Set([1]);
    toggleType(before, 3);
    expect([...before]).toEqual([1]);
  });
});
