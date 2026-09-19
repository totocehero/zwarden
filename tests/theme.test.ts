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
  action: { theme_icons?: readonly ThemeIcon[] };
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
