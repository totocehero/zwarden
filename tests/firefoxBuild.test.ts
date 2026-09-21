/**
 * @file The Firefox package differs from the Chrome one in the ways it must.
 *
 * Firefox refuses the Chrome manifest outright — it wants an event page where
 * Chrome wants a service worker — so this is not a nicety but the difference
 * between a package that loads and one that does not. The transformation is a
 * script, and a script that silently stops transforming is a package that
 * silently stops loading.
 */

import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const root = (path: string): string => fileURLToPath(new URL(`../${path}`, import.meta.url));
const built = existsSync(root('dist-firefox/manifest.json'));

const read = (path: string): Record<string, unknown> =>
  JSON.parse(readFileSync(root(path), 'utf8')) as Record<string, unknown>;

// Skipped rather than failing when nothing has been built: `npm test` must not
// demand `npm run build:firefox` first, and CI runs both.
describe.skipIf(!built)('the Firefox package', () => {
  const manifest = built ? read('dist-firefox/manifest.json') : {};
  const background = manifest['background'] as Record<string, unknown>;

  it('declares an event page, never a service worker', () => {
    // The one difference Firefox will not overlook.
    expect(background['scripts']).toEqual(['background.js']);
    expect(background['service_worker']).toBeUndefined();
  });

  it('carries the identifier Firefox demands of an MV3 extension', () => {
    const gecko = (manifest['browser_specific_settings'] as Record<string, unknown>)[
      'gecko'
    ] as Record<string, unknown>;
    expect(typeof gecko['id']).toBe('string');
    // 128 is where `world: "MAIN"` arrived for registered content scripts,
    // without which passkeys cannot be hooked at all.
    expect(gecko['strict_min_version']).toBe('128.0');
  });

  it('claims no capability the browser does not have', () => {
    // Firefox has no offscreen documents. Shipping the permission, or the
    // document, would be claiming something.
    expect(manifest['permissions']).not.toContain('offscreen');
    expect(existsSync(root('dist-firefox/offscreen.html'))).toBe(false);
    expect(existsSync(root('dist-firefox/offscreen.js'))).toBe(false);
  });

  it('keeps the theme icons, which are Firefox’s own mechanism', () => {
    const action = manifest['action'] as Record<string, unknown>;
    expect(action['theme_icons']).toBeDefined();
  });

  it('ships the same code as the Chrome package', () => {
    // Only the manifest differs. A second copy of the logic would be a second
    // thing to keep right.
    for (const file of ['background.js', 'content.js', 'webauthnHook.js']) {
      expect(readFileSync(root(`dist-firefox/${file}`), 'utf8')).toBe(
        readFileSync(root(`dist/${file}`), 'utf8'),
      );
    }
  });
});
