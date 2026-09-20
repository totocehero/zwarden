/**
 * @file The toolbar icon, matched to the browser's theme.
 *
 * ## The problem
 *
 * The icon is a white padlock. On a dark toolbar it reads perfectly; on a light
 * one it is invisible — not faint, invisible, since it is pure white on
 * near-white. A user on a light theme sees an empty slot and concludes the
 * extension failed to install.
 *
 * ## Two drawings, one shape
 *
 * `icon*.png` (white) and `icon*-dark.png` (the application's background colour)
 * share the same alpha channel down to the pixel: the same drawing, two
 * colours. Only the RGB differs, so no anti-aliasing is lost in the swap.
 *
 * The naming says the icon's **own** colour, not the background it suits —
 * Firefox's `theme_icons` uses the opposite convention, and mixing the two is
 * how one ships an invisible icon.
 *
 * ## The third drawing
 *
 * A swap needs someone to swap, and two surfaces have nobody: `default_icon`,
 * which Chrome paints between launching the browser and waking the worker, and
 * `manifest.icons` — the card on `chrome://extensions`, the store listing —
 * which accepts no theme variant at all. Choosing white there loses the users on
 * a light theme, choosing dark loses the others; it is a coin toss dressed as a
 * decision.
 *
 * Hence `icon*-outline.png`: the white drawing with a dark rim, readable on
 * either background. It is the manifest's answer, never `setIcon`'s — once the
 * background is known the rim is only noise. The rim is dilated in place, so the
 * glyph keeps its size and the swap moves nothing; `scripts/make-icons.py`
 * derives all three drawings from the one source.
 *
 * ## Who decides
 *
 * A service worker has no DOM and therefore no `matchMedia`. Chrome provides
 * exactly one way out: an offscreen document created with the `MATCH_MEDIA`
 * reason. The worker uses it at start-up, then closes it.
 *
 * Extension pages (popup, options) have a DOM and settle it themselves, which
 * also covers the user changing their system theme mid-session.
 */

/** Which of the two drawings to display. */
export type IconVariant = 'light' | 'dark';

/**
 * Icon paths by variant, in the shape `chrome.action.setIcon` expects.
 *
 * `light` is the white drawing, for a dark toolbar; `dark` is the dark drawing,
 * for a light one.
 */
const ICONS: Readonly<Record<IconVariant, Readonly<Record<number, string>>>> = {
  light: {
    16: 'images/icon16.png',
    32: 'images/icon32.png',
    48: 'images/icon48.png',
    128: 'images/icon128.png',
  },
  dark: {
    16: 'images/icon16-dark.png',
    32: 'images/icon32-dark.png',
    48: 'images/icon48-dark.png',
    128: 'images/icon128-dark.png',
  },
};

/** The variant that suits a given colour scheme. */
export function variantFor(prefersDark: boolean): IconVariant {
  // A dark toolbar calls for the light drawing, and the reverse. Getting this
  // one line backwards is precisely the bug this module exists to fix.
  return prefersDark ? 'light' : 'dark';
}

/**
 * Applies the variant to the toolbar icon.
 *
 * Silent on failure: an icon that stays as it was is a cosmetic disappointment,
 * never a reason to break whatever the caller was doing.
 */
export async function applyToolbarIcon(variant: IconVariant): Promise<void> {
  if (typeof chrome === 'undefined' || typeof chrome.action?.setIcon !== 'function') {
    return;
  }
  try {
    await chrome.action.setIcon({ path: { ...ICONS[variant] } });
  } catch {
    // An unavailable icon, or an API narrowed by the browser.
  }
}

/**
 * Settles the icon from the page's own colour scheme, and keeps it settled.
 *
 * For extension pages only — they have a DOM. The returned function detaches
 * the listener.
 */
export function followPageColorScheme(): () => void {
  if (typeof matchMedia !== 'function') {
    return () => undefined;
  }
  const query = matchMedia('(prefers-color-scheme: dark)');
  const apply = (): void => void applyToolbarIcon(variantFor(query.matches));

  apply();
  query.addEventListener('change', apply);
  return () => query.removeEventListener('change', apply);
}
