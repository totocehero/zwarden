/**
 * @file The toolbar icon and the theme.
 *
 * One line decides everything here, and it reads backwards: a **dark** toolbar
 * calls for the **light** drawing. Getting it the other way round ships an icon
 * that is invisible for exactly half the users — and invisible, not faint, since
 * the drawing is pure white.
 *
 * Firefox's `theme_icons` uses the same counter-intuitive convention — the keys
 * name the icon's own colour, not the background it suits — so the manifest is
 * checked against the same rule rather than trusted to a reader's attention.
 *
 * The third drawing, `-outline`, answers the two places where no swap is
 * possible and is therefore checked too: it is the one the manifest must
 * declare, and pointing either of those keys back at the plain white file is a
 * change that looks like tidying and ships an invisible icon.
 */

import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { variantFor } from '../src/shared/theme.js';

interface ThemeIcon {
  readonly light: string;
  readonly dark: string;
  readonly size: number;
}

const manifest = JSON.parse(readFileSync('public/manifest.json', 'utf8')) as {
  icons: Readonly<Record<string, string>>;
  action: {
    theme_icons?: readonly ThemeIcon[];
    default_icon: Readonly<Record<string, string>>;
  };
};

describe('variantFor', () => {
  it('picks the light drawing for a dark toolbar', () => {
    expect(variantFor(true)).toBe('light');
  });

  it('picks the dark drawing for a light toolbar', () => {
    expect(variantFor(false)).toBe('dark');
  });
});

describe('manifest theme_icons', () => {
  const icons = manifest.action.theme_icons ?? [];

  it('declares a pair for every advertised size', () => {
    expect(icons.map((i) => i.size)).toEqual([16, 32]);
  });

  /**
   * Firefox names each entry by the icon's own colour: `light` is the light
   * drawing, shown when a dark theme is active. Our file names follow the same
   * convention, so `light` must point at the plain file and `dark` at the
   * `-dark` one. The reverse compiles, passes review, and is invisible.
   */
  it.each([16, 32])('maps size %i by the icon own colour, not the background', (size) => {
    const entry = icons.find((i) => i.size === size);

    expect(entry?.light).toBe(`images/icon${size}.png`);
    expect(entry?.dark).toBe(`images/icon${size}-dark.png`);
  });
});

/**
 * Where the browser paints an icon we cannot swap.
 *
 * Two surfaces, and neither accepts a theme variant:
 *
 * - `action.default_icon`, which Chrome shows between launching the browser and
 *   waking the service worker that would call `setIcon` — precisely the moment
 *   one looks for the extension one just installed;
 * - `icons`, the card on `chrome://extensions` and the store listing, which has
 *   no theme mechanism at all.
 *
 * Both must therefore carry the outlined drawing, which reads on either
 * background. Choosing the white one for the majority on a light theme, or the
 * dark one for the majority on a dark theme, is a coin toss dressed as a
 * decision — hence a third drawing, and hence this test.
 */
describe('icons the browser paints unswapped', () => {
  it.each(['16', '32', '48', '128'])('advertises the outlined drawing at size %s', (size) => {
    expect(manifest.icons[size]).toBe(`images/icon${size}-outline.png`);
  });

  it.each(['16', '32'])('falls back to the outlined drawing at size %s', (size) => {
    expect(manifest.action.default_icon[size]).toBe(`images/icon${size}-outline.png`);
  });

  /**
   * The swap itself still uses the two clean drawings: an outline is insurance
   * against not knowing the background, and once the background is known it is
   * only noise.
   */
  it('leaves the swapped icons unoutlined', () => {
    const swapped = (manifest.action.theme_icons ?? []).flatMap((i) => [i.light, i.dark]);
    expect(swapped.filter((path) => path.includes('outline'))).toEqual([]);
  });
});
