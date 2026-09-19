/**
 * @file Classement « dernier utilisé en tête ».
 *
 * Deux fonctions pures portent tout le comportement observable : l'ordre de
 * la liste (`sortByLastUsed`) et le plafond du journal d'usage
 * (`pruneLastUsed`). Le reste n'est que du stockage.
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
  const liste = [item('a'), item('b'), item('c'), item('d')];

  it('laisse la liste intacte sans aucun usage', () => {
    expect(sortByLastUsed(liste, {})).toBe(liste);
  });

  it('remonte l’item utilisé en tête', () => {
    expect(ids(sortByLastUsed(liste, { c: 1000 }))).toEqual(['c', 'a', 'b', 'd']);
  });

  it('classe les items utilisés du plus récent au plus ancien', () => {
    expect(ids(sortByLastUsed(liste, { a: 10, c: 30, d: 20 }))).toEqual(['c', 'd', 'a', 'b']);
  });

  it('préserve l’ordre d’origine des items jamais utilisés', () => {
    expect(ids(sortByLastUsed(liste, { d: 1 }))).toEqual(['d', 'a', 'b', 'c']);
  });

  it('ignore les usages d’items absents du coffre', () => {
    // Item supprimé depuis, ou appartenant à un autre compte.
    expect(ids(sortByLastUsed(liste, { zzz: 999 }))).toEqual(['a', 'b', 'c', 'd']);
  });
});

describe('pruneLastUsed', () => {
  it('laisse passer un journal court', () => {
    expect(pruneLastUsed({ a: 1, b: 2 })).toEqual({ a: 1, b: 2 });
  });

  it('ne garde que les 100 usages les plus récents', () => {
    const gros: Record<string, number> = {};
    for (let i = 0; i < 150; i += 1) {
      gros[`id${i}`] = i;
    }
    const élagué = pruneLastUsed(gros);
    expect(Object.keys(élagué)).toHaveLength(100);
    expect(élagué['id149']).toBe(149);
    expect(élagué['id50']).toBe(50);
    expect(élagué['id49']).toBeUndefined();
  });
});
