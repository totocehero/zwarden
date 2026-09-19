// @vitest-environment jsdom

/**
 * @file Tests for the credential detector's heuristics.
 *
 * These cases used to be unverifiable other than by hand on a real site — and
 * that is exactly why a comment in the detector had been able to promise a guard
 * the code did not apply. This file exists so that the promise and the code can
 * no longer drift apart quietly.
 *
 * `offsetParent` does not exist under jsdom, which implements no layout: the
 * visibility test is therefore injected. The hidden-field cases are covered by
 * driving it explicitly.
 */

import { describe, expect, it } from 'vitest';

import {
  type VisibilityTest,
  filledPasswords,
  findCapture,
  guessUsername,
  isVisibilityToggle,
} from '../src/content/heuristics.js';

/** Everything is visible: the normal case of a displayed sign-in page. */
const ALL_VISIBLE: VisibilityTest = () => true;

/** Builds a detached subtree from HTML, and returns its root element. */
function fragment(html: string): HTMLElement {
  const host = document.createElement('div');
  host.innerHTML = html;
  document.body.replaceChildren(host);
  return host;
}

/** Fills the named fields, as a user's typing would. */
function type(root: ParentNode, values: Record<string, string>): void {
  for (const [name, value] of Object.entries(values)) {
    const field = root.querySelector<HTMLInputElement>(`[name="${name}"]`);
    if (field === null) {
      throw new Error(`Field missing from the fragment: ${name}`);
    }
    field.value = value;
  }
}

describe('findCapture — ordinary sign-in form', () => {
  it('captures the username and the password', () => {
    const f = fragment(`
      <form>
        <input name="u" type="text">
        <input name="p" type="password">
        <button type="submit">Sign in</button>
      </form>`);
    type(f, { u: 'alice@example.com', p: 'secret-1' });

    expect(findCapture(f, null, ALL_VISIBLE)).toEqual({
      username: 'alice@example.com',
      password: 'secret-1',
    });
  });

  it('captures nothing when no password was entered', () => {
    const f = fragment('<form><input name="u" type="text"><input name="p" type="password"></form>');
    type(f, { u: 'alice', p: '' });

    expect(findCapture(f, null, ALL_VISIBLE)).toBeNull();
  });

  it('ignores a hidden password field', () => {
    const f = fragment(`
      <form>
        <input name="visible" type="password">
        <input name="hidden" type="password">
      </form>`);
    type(f, { visible: '', hidden: 'trap' });
    const masked: VisibilityTest = (el) => el.getAttribute('name') !== 'hidden';

    expect(findCapture(f, null, masked)).toBeNull();
  });
});

describe('findCapture — account creation', () => {
  it('captures when both passwords agree', () => {
    const f = fragment(`
      <form>
        <input name="u" type="email">
        <input name="p1" type="password">
        <input name="p2" type="password">
      </form>`);
    type(f, { u: 'a@b.com', p1: 'identical', p2: 'identical' });

    expect(findCapture(f, null, ALL_VISIBLE)?.password).toBe('identical');
  });

  /**
   * The entry is still incomplete: the site is going to refuse it. Offering to
   * save would amount to keeping a password that was never accepted.
   */
  it('captures nothing when the confirmation differs', () => {
    const f = fragment(`
      <form>
        <input name="p1" type="password">
        <input name="p2" type="password">
      </form>`);
    type(f, { p1: 'secret-1', p2: 'secret-2' });

    expect(findCapture(f, null, ALL_VISIBLE)).toBeNull();
  });
});

describe('isVisibilityToggle — the click fallback’s false positive', () => {
  /**
   * The case that motivates this whole guard: clicking the "show password" eye
   * triggered a capture and lit the badge, while the user had submitted nothing.
   */
  it('rules out a "show" eye lodged in the field’s block', () => {
    const f = fragment(`
      <form>
        <input name="u" type="text">
        <div class="field">
          <input name="p" type="password">
          <button type="button" class="eye">show</button>
        </div>
        <button type="submit">Enter</button>
      </form>`);
    type(f, { u: 'alice', p: 'secret-1' });
    const eye = f.querySelector('.eye')!;

    expect(findCapture(f, eye, ALL_VISIBLE)).toBeNull();
  });

  it('rules out any two-state button', () => {
    const f = fragment(`
      <form>
        <input name="p" type="password">
        <button type="button" aria-pressed="false" class="toggle">view</button>
      </form>`);
    type(f, { p: 'secret-1' });
    const toggle = f.querySelector('.toggle')!;

    expect(findCapture(f, toggle, ALL_VISIBLE)).toBeNull();
  });

  it('lets the submit button through', () => {
    const f = fragment(`
      <form>
        <input name="u" type="text">
        <input name="p" type="password">
        <button type="submit" class="send">Sign in</button>
      </form>`);
    type(f, { u: 'alice', p: 'secret-1' });
    const send = f.querySelector('.send')!;

    expect(findCapture(f, send, ALL_VISIBLE)?.password).toBe('secret-1');
  });

  /** A button outside the field's block remains a plausible submission. */
  it('lets a type-less button outside the field’s block through', () => {
    const f = fragment(`
      <form>
        <div><input name="p" type="password"></div>
        <button class="action">Continue</button>
      </form>`);
    type(f, { p: 'secret-1' });
    const action = f.querySelector('.action')!;

    expect(isVisibilityToggle(action, f.querySelector('[name="p"]')!)).toBe(false);
  });
});

describe('guessUsername', () => {
  it('prefers the site’s explicit annotation', () => {
    const f = fragment(`
      <form>
        <input name="noise" type="text">
        <input name="real" type="text" autocomplete="username">
        <input name="p" type="password">
      </form>`);
    type(f, { noise: 'to-ignore', real: 'alice', p: 'x' });

    expect(guessUsername(f, f.querySelector('[name="p"]')!, ALL_VISIBLE)).toBe('alice');
  });

  it('otherwise takes the last field filled before the password', () => {
    const f = fragment(`
      <form>
        <input name="a" type="text">
        <input name="b" type="email">
        <input name="p" type="password">
        <input name="after" type="text">
      </form>`);
    type(f, { a: 'first', b: 'second@example.com', p: 'x', after: 'after' });

    expect(guessUsername(f, f.querySelector('[name="p"]')!, ALL_VISIBLE)).toBe(
      'second@example.com',
    );
  });

  /**
   * Some sites place the username field after the password in the document while
   * displaying it before. Failing a preceding candidate, the first filled field
   * beats an empty string.
   */
  it('falls back to the first filled field when none precedes', () => {
    const f = fragment(`
      <form>
        <input name="p" type="password">
        <input name="u" type="text">
      </form>`);
    type(f, { p: 'x', u: 'alice' });

    expect(guessUsername(f, f.querySelector('[name="p"]')!, ALL_VISIBLE)).toBe('alice');
  });

  /**
   * The bug found in use: "it put the password in the login".
   *
   * The two-field "show password" pattern — a `password` and a `text` mirror
   * whose visibility the site toggles. The mirror is filled, visible, and placed
   * before the password field: it was therefore the perfect candidate for the
   * proximity rule, which handed the password over as the username. The item
   * created then carried the password in the clear in its username field.
   */
  it('never accepts a field holding the password', () => {
    const f = fragment(`
      <form>
        <input name="u" type="text">
        <input name="mirror" type="text">
        <input name="p" type="password">
      </form>`);
    type(f, { u: 'alice@example.com', mirror: 'S3cret!', p: 'S3cret!' });

    expect(findCapture(f, null, ALL_VISIBLE)).toEqual({
      username: 'alice@example.com',
      password: 'S3cret!',
    });
  });

  /** Same trap, with no username to recover: empty beats wrong. */
  it('returns empty rather than the password when the mirror stands alone', () => {
    const f = fragment(`
      <form>
        <input name="mirror" type="text">
        <input name="p" type="password">
      </form>`);
    type(f, { mirror: 'S3cret!', p: 'S3cret!' });

    expect(findCapture(f, null, ALL_VISIBLE)?.username).toBe('');
  });

  /** The site itself announces the field as a password: we believe it. */
  it('rules out a field annotated as a password', () => {
    const f = fragment(`
      <form>
        <input name="new" type="text" autocomplete="new-password">
        <input name="p" type="password">
      </form>`);
    type(f, { new: 'something-else', p: 'S3cret!' });

    expect(findCapture(f, null, ALL_VISIBLE)?.username).toBe('');
  });

  /**
   * Outside a form, the sweep covers the whole document: a search box where the
   * user happened to paste their password must not come back as the username.
   */
  it('does not pick up the password found elsewhere in the page', () => {
    fragment(`
      <div>
        <input name="search" type="text">
        <div><input name="p" type="password"></div>
      </div>`);
    type(document, { search: 'S3cret!', p: 'S3cret!' });

    expect(findCapture(document, null, ALL_VISIBLE)?.username).toBe('');
  });

  it('returns an empty string when nothing looks like a username', () => {
    const f = fragment('<form><input name="p" type="password"></form>');
    type(f, { p: 'x' });

    expect(guessUsername(f, f.querySelector('[name="p"]')!, ALL_VISIBLE)).toBe('');
  });
});

describe('filledPasswords', () => {
  it('returns the filled fields in document order', () => {
    const f = fragment(`
      <form>
        <input name="p1" type="password">
        <input name="empty" type="password">
        <input name="p2" type="password">
      </form>`);
    type(f, { p1: 'one', empty: '', p2: 'two' });

    expect(filledPasswords(f, ALL_VISIBLE).map((i) => i.value)).toEqual(['one', 'two']);
  });
});
