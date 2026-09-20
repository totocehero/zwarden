/**
 * @file The locale files, kept in step with the code.
 *
 * Translation drifts silently: a key added to the interface and forgotten in one
 * locale shows an empty label to exactly the users who speak that language, and
 * to nobody else. No amount of manual review catches that reliably — hence this
 * file, which closes the loop in both directions.
 *
 * The catalogues are **read from disk rather than imported by name**, so that
 * adding `_locales/de/` is enough to put German under every rule here. A new
 * language needs no line in this file, which is the point: the check one has to
 * remember to extend is the check that does not hold.
 */

import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { AVAILABLE_LOCALES, MESSAGE_KEYS } from '../src/shared/i18n.js';

type Catalogue = Record<string, { message: string }>;

const LOCALES_DIR = fileURLToPath(new URL('../public/_locales', import.meta.url));

/** Every locale folder shipped, with its catalogue. */
const LOCALES: ReadonlyArray<readonly [string, Catalogue]> = readdirSync(LOCALES_DIR, {
  withFileTypes: true,
})
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name)
  .sort()
  .map(
    (code) =>
      [
        code,
        JSON.parse(readFileSync(`${LOCALES_DIR}/${code}/messages.json`, 'utf8')) as Catalogue,
      ] as const,
  );

/** The `$1`…`$9` placeholders a message uses, deduplicated and sorted. */
function placeholders(message: string): string[] {
  return [...new Set(message.match(/\$\d/g) ?? [])].sort();
}

describe('message catalogues', () => {
  it('ships at least the default locale', () => {
    // A guard on the guard: a glob that silently matched nothing would make
    // every `it.each` below vacuous, and a vacuous test passes.
    expect(LOCALES.map(([code]) => code)).toContain('en');
  });

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
   * count the sentence needed. Every language is compared against the default
   * one, which is the fallback and therefore the reference.
   */
  it.each(LOCALES.filter(([code]) => code !== 'en'))(
    '%s uses the same placeholders as the default locale',
    (_lang, catalogue) => {
      const reference = LOCALES.find(([code]) => code === 'en')![1];
      const mismatched = MESSAGE_KEYS.filter(
        (key) =>
          placeholders(reference[key]?.message ?? '').join() !==
          placeholders(catalogue[key]?.message ?? '').join(),
      );
      expect(mismatched).toEqual([]);
    },
  );

  /**
   * `$$` is Chrome's escape for a literal `$`. The chosen-language path reads
   * the catalogue directly, outside `chrome.i18n`, and its substitution does not
   * implement that escape — so the two would disagree on any message using it.
   * Forbidding it is cheaper and more honest than a case nothing exercises.
   */
  it.each(LOCALES)('%s escapes no literal dollar', (_lang, catalogue) => {
    const offenders = Object.entries(catalogue)
      .filter(([, v]) => v.message.includes('$$'))
      .map(([k]) => k);
    expect(offenders).toEqual([]);
  });

  it('declares no duplicate key', () => {
    expect(new Set(MESSAGE_KEYS).size).toBe(MESSAGE_KEYS.length);
  });
});

/**
 * The list offered in the settings against the folders actually shipped.
 *
 * Both directions matter and neither is visible without a test: a language
 * shipped but unlisted can never be chosen, and a language listed but unshipped
 * is an entry that silently falls back to the browser when picked.
 */
describe('offered languages', () => {
  it('offers exactly the languages shipped', () => {
    expect(AVAILABLE_LOCALES.map(([code]) => code).sort()).toEqual(
      LOCALES.map(([code]) => code).sort(),
    );
  });

  it('names each language in that language, and only once', () => {
    const names = AVAILABLE_LOCALES.map(([, name]) => name);
    expect(names.filter((name) => name.trim() === '')).toEqual([]);
    expect(new Set(names).size).toBe(names.length);
  });
});
