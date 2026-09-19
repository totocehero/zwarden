/**
 * @file Credential-detection heuristics — the decision, without the global DOM.
 *
 * ## Why this file is separate from the detector
 *
 * `detector.ts` is a content script: it hooks onto `document`, reads `location`,
 * talks to the service worker. None of that is testable, and it is precisely for
 * that reason that the decisions must not live there.
 *
 * Here there is no extension API, no event, no global state: functions that take
 * a DOM subtree and return a verdict. That is what makes it possible to replay,
 * on HTML fragments, the cases that would otherwise only ever be checked by hand
 * on a real site — the "show password" button, the account-creation form, the
 * page with no `<form>`.
 *
 * The detector keeps only what needs a real browser: wiring the events,
 * deduplicating in time, and sending the message.
 */

/**
 * A field visibility test, injectable.
 *
 * The real test is `offsetParent !== null`: it covers `display:none` and
 * detached fields, which are the cases that occur. But it relies on layout,
 * which jsdom does not implement — `offsetParent` is always `null` there.
 * Without this seam, none of this file's decisions would be verifiable other
 * than by hand on a real site. It is the same device as the generator's
 * injectable random source, for the same reason.
 */
export type VisibilityTest = (element: HTMLElement) => boolean;

/** The real visibility test, the browser's. */
export const isDisplayed: VisibilityTest = (element) => element.offsetParent !== null;

/** Credentials spotted in a page, ready to be handed to the worker. */
export interface CaptureCandidate {
  readonly username: string;
  readonly password: string;
}

/**
 * Password fields that are visible and filled, in document order.
 *
 * `offsetParent === null` acts as the visibility test: it covers `display:none`
 * and detached fields, which are the real cases — a field the user could not
 * have filled has no business being captured.
 */
export function filledPasswords(
  root: ParentNode,
  visible: VisibilityTest = isDisplayed,
): HTMLInputElement[] {
  return [...root.querySelectorAll<HTMLInputElement>('input[type="password"]')].filter(
    (input) => input.value !== '' && visible(input),
  );
}

/**
 * Recognises a "show password" button.
 *
 * This is the click fallback's structural false positive: the reveal eye is a
 * button, it sits next to a filled password field, and it is clicked at exactly
 * the moment a capture would seem warranted. Two marks tell it apart from a
 * submission, and neither rests on its label — a label is translated, a
 * structure is not:
 *
 * - `aria-pressed` denotes a two-state button; a submission has none;
 * - an explicit `type="button"` lodged in the field's own block, which is where
 *   the eye sits in very nearly every form.
 */
export function isVisibilityToggle(control: Element, password: HTMLInputElement): boolean {
  if (control.hasAttribute('aria-pressed')) {
    return true;
  }
  return (
    control.getAttribute('type') === 'button' &&
    password.parentElement !== null &&
    password.parentElement.contains(control)
  );
}

/**
 * Rules out a text field that is not a username but a password.
 *
 * Two marks, and the first almost always suffices:
 *
 * - **its value is exactly the captured password.** This is the two-field "show
 *   password" pattern: the site keeps a `password` and a `text` mirror, and
 *   toggles visibility between the two. The mirror is a filled, visible text
 *   field, often placed just before the password field — hence the perfect
 *   candidate for the proximity rule, which then handed the password over as the
 *   username. A username equal to the password is never what the user wanted:
 *   refusing it costs nothing and closes every variant of the pattern at once;
 * - the site itself announces it as a password (`autocomplete`).
 */
function isDisguisedPassword(input: HTMLInputElement, password: string): boolean {
  if (input.value === password) {
    return true;
  }
  const auto = input.getAttribute('autocomplete');
  return auto === 'current-password' || auto === 'new-password';
}

/**
 * Guesses the username that goes with a password field.
 *
 * In order of reliability: the site's explicit annotation
 * (`autocomplete="username"`), then an email field, then the last text field
 * filled **before** the password — visual order is the only clue when the site
 * annotates nothing. Failing all that: the empty string, and the user completes
 * it in the popup.
 *
 * In every case, a field carrying the password is ruled out — see
 * {@link isDisguisedPassword}.
 */
export function guessUsername(
  scope: ParentNode,
  password: HTMLInputElement,
  visible: VisibilityTest = isDisplayed,
): string {
  const annotated = scope.querySelector<HTMLInputElement>(
    'input[autocomplete="username"], input[autocomplete="email"]',
  );
  if (
    annotated !== null &&
    annotated.value !== '' &&
    !isDisguisedPassword(annotated, password.value)
  ) {
    return annotated.value;
  }

  const candidates = [
    ...scope.querySelectorAll<HTMLInputElement>('input[type="email"], input[type="text"]'),
  ].filter(
    (input) =>
      input.value !== '' && visible(input) && !isDisguisedPassword(input, password.value),
  );

  let best = '';
  for (const candidate of candidates) {
    // `compareDocumentPosition` rather than an index: the password field is not
    // necessarily in the same subtree as the text field.
    const precedes = password.compareDocumentPosition(candidate) & Node.DOCUMENT_POSITION_PRECEDING;
    if (precedes !== 0) {
      best = candidate.value;
    }
  }
  return best === '' ? (candidates[0]?.value ?? '') : best;
}

/**
 * The full verdict: is there anything to capture in this subtree?
 *
 * @param scope The submitted form, or the document when there is no `<form>`.
 * @param control The clicked control, if the capture comes from the click
 *   fallback. It is then examined: anything resembling a visibility toggle is
 *   ruled out.
 * @param visible Visibility test — see {@link VisibilityTest}.
 * @returns The credentials to hand over, or `null` if there is nothing to offer.
 */
export function findCapture(
  scope: ParentNode,
  control: Element | null = null,
  visible: VisibilityTest = isDisplayed,
): CaptureCandidate | null {
  const passwords = filledPasswords(scope, visible);
  const password = passwords[0];
  if (password === undefined) {
    return null;
  }
  if (control !== null && isVisibilityToggle(control, password)) {
    return null;
  }
  // Two filled, differing password fields: this is account creation or a
  // password change with confirmation. We keep the first; if they differ, the
  // entry is not valid yet and the site will refuse it — no point offering
  // anything.
  if (passwords.length > 1 && passwords.some((p) => p.value !== password.value)) {
    return null;
  }

  return { username: guessUsername(scope, password, visible), password: password.value };
}
