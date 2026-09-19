/**
 * @file The locale files, kept in step with the code.
 *
 * Translation drifts silently: a key added to the interface and forgotten in one
 * locale shows an empty label to exactly the users who speak that language, and
 * to nobody else. No amount of manual review catches that reliably — hence this
 * file, which closes the loop in both directions.
 */

import { describe, expect, it } from 'vitest';

import en from '../public/_locales/en/messages.json' with { type: 'json' };
import fr from '../public/_locales/fr/messages.json' with { type: 'json' };
import { MESSAGE_KEYS } from '../src/shared/i18n.js';

type Catalogue = Record<string, { message: string }>;

const LOCALES: ReadonlyArray<readonly [string, Catalogue]> = [
  ['en', en as Catalogue],
  ['fr', fr as Catalogue],
];

/** The `$1`…`$9` placeholders a message uses, deduplicated and sorted. */
function placeholders(message: string): string[] {
  return [...new Set(message.match(/\$\d/g) ?? [])].sort();
}

describe('message catalogues', () => {
  it.each(LOCALES)('%s holds exactly the keys the code asks for', (_lang, catalogue) => {
    const declared = new Set<string>(MESSAGE_KEYS);
    const present = new Set(Object.keys(catalogue));

    // Both directions: a missing key is an empty label, an extra one is dead
    // weight shipped to every user of that language.
    expect([...declared].filter((k) => !present.has(k))).toEqual([]);
    expect([...present].filter((k) => !declared.has(k))).toEqual([]);
  });

  it.each(LOCALES)('%s has no empty message', (_lang, catalogue) => {
    const empty = Object.entries(catalogue)
      .filter(([, v]) => v.message.trim() === '')
      .map(([k]) => k);
    expect(empty).toEqual([]);
  });

  /**
   * A placeholder present in one language and absent in another produces either
   * a `$1` left raw on screen, or a value silently dropped — a hostname or a
   * count the sentence needed.
   */
  it('uses the same placeholders in every language', () => {
    const mismatched = MESSAGE_KEYS.filter((key) => {
      const a = placeholders((en as Catalogue)[key]?.message ?? '');
      const b = placeholders((fr as Catalogue)[key]?.message ?? '');
      return a.join() !== b.join();
    });
    expect(mismatched).toEqual([]);
  });

  it('declares no duplicate key', () => {
    expect(new Set(MESSAGE_KEYS).size).toBe(MESSAGE_KEYS.length);
  });
});
