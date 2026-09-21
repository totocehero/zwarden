/**
 * @file Entered-credentials detector — content script.
 *
 * ## What it does, and nothing else
 *
 * It watches the page's form submissions, and when a non-empty password has just
 * been entered, it sends it **to the extension's service worker** — never
 * anywhere else. It injects no UI, never reads the vault, fills nothing in: the
 * "save or not" decision belongs to the popup, which alone knows what the vault
 * already contains.
 *
 * ## This file decides nothing
 *
 * All the judgement — which field, which username, is this a "show" button —
 * lives in `heuristics.ts`, with no extension API and no global state, hence
 * under test. What remains here is only what needs a real browser: wiring the
 * events, deduplicating in time, sending the message.
 *
 * ## Why it does not fill
 *
 * The two autofill rules from `docs/EXTENSION.md` §4 stand whole: no filling
 * without an explicit gesture. This script writes nothing into the page; it only
 * reads what the user has just typed themselves.
 *
 * ## What stays imperfect, knowingly
 *
 * Sign-ins with no `<form>` (single-page apps that call `fetch` on a click) fire
 * no `submit` event. The click fallback covers the most common ones; it does not
 * claim to be exhaustive. A missed credential is recovered through "Add" in the
 * popup — a credential captured in error costs only a "Dismiss".
 *
 * The username, for its part, is **guessed**: no site is obliged to announce it.
 * Guessing wrong is possible; guessing it *equal to the password* no longer is
 * (`heuristics.ts`), because that was the one case where a wrong guess wrote a
 * secret into a field not made for it.
 */

// The namespace bridge is deliberately **not** imported here, unlike in every
// other entry. A content script cannot import anything — there is no module
// loader where it runs — and this one has no need of it: it awaits no
// `chrome.*` call, it only fires `sendMessage` and forgets it.

import { findCapture } from './heuristics.js';

/** Message type, shared with the service worker. */
const MESSAGE_TYPE = 'zwarden-credentials';

/** Deduplication window between a `submit` and the click that caused it. */
const DEDUPE_MS = 1000;

let lastSentAt = 0;

/** Hands the capture to the service worker, if the verdict is positive. */
function report(scope: ParentNode, control: Element | null = null): void {
  const now = Date.now();
  if (now - lastSentAt < DEDUPE_MS) {
    return;
  }
  const capture = findCapture(scope, control);
  if (capture === null) {
    return;
  }

  lastSentAt = now;
  // Neither origin nor host is sent: the worker reads them off the sender, which
  // the browser fills in. Announcing them here would suggest they count, and
  // would one day invite trusting them.
  //
  // The popup or the worker may be absent: the error is of no consequence and
  // must not pollute the site's console.
  void chrome.runtime
    .sendMessage({ type: MESSAGE_TYPE, username: capture.username, password: capture.password })
    .catch(() => undefined);
}

document.addEventListener(
  'submit',
  (event) => {
    const form = event.target;
    report(form instanceof HTMLFormElement ? form : document);
  },
  true,
);

// Fallback for sign-ins with no form submission. Restricted to elements that
// present themselves as a button: a click anywhere in the page must not trigger
// a capture.
document.addEventListener(
  'click',
  (event) => {
    const target = event.target;
    if (!(target instanceof Element)) {
      return;
    }
    const button = target.closest('button, input[type="submit"], [role="button"]');
    if (button === null) {
      return;
    }
    // The control is passed along to be examined: that is where visibility
    // toggles are ruled out. Outside a form, the search covers the whole
    // document — that is this fallback's reason to exist (sign-ins with no
    // `<form>`), and its acknowledged share of imprecision.
    report(button.closest('form') ?? document, button);
  },
  true,
);
