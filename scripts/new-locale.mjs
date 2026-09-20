/**
 * Scaffolds a new interface language.
 *
 *   node scripts/new-locale.mjs de
 *
 * Copies `_locales/en/messages.json` to `_locales/<code>/messages.json`, keys
 * in the same order, messages left in English. That is deliberate: a file with
 * every key already in it, in the order the interface reads them, is a file a
 * translator can work down without wondering what is missing — and English
 * showing through where a line has not been touched is visible, where an empty
 * string is not.
 *
 * Two things this script does NOT do, on purpose:
 *
 *  - it does not add the language to `AVAILABLE_LOCALES` in `src/shared/i18n.ts`.
 *    Offering a language that is still entirely in English would be a worse
 *    promise than not offering it. Add the line when the translation is done;
 *    `tests/i18n.test.ts` fails until the list and the folders agree, so the
 *    step cannot be forgotten, only postponed;
 *  - it does not translate anything. See the README on why a security interface
 *    is a poor candidate for unreviewed machine translation.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';

const LOCALES = new URL('../public/_locales/', import.meta.url);

const code = process.argv[2];
if (code === undefined || !/^[a-z]{2,3}(_[A-Za-z0-9]{2,8})?$/.test(code)) {
  console.error('Usage: node scripts/new-locale.mjs <code>   (e.g. de, pt_BR, es_419)');
  process.exit(2);
}

const target = new URL(`${code}/messages.json`, LOCALES);
if (existsSync(target)) {
  console.error(`_locales/${code}/messages.json already exists — nothing written.`);
  process.exit(1);
}

const source = JSON.parse(readFileSync(new URL('en/messages.json', LOCALES), 'utf8'));
mkdirSync(new URL(`${code}/`, LOCALES), { recursive: true });
writeFileSync(target, `${JSON.stringify(source, null, 2)}\n`, 'utf8');

const count = Object.keys(source).length;
console.log(`_locales/${code}/messages.json — ${count} keys, copied from English.`);
console.log('Next: translate the messages, then add the language to AVAILABLE_LOCALES');
console.log("in src/shared/i18n.ts (e.g. ['%s', 'Deutsch']), then run the tests.", code);
