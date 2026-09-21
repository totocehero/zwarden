/**
 * @file Offscreen document: the service worker's DOM.
 *
 * ## Why this document exists
 *
 * An MV3 service worker has no DOM, and the clipboard requires one. Without it,
 * the deferred clipboard wipe could only be carried by a `setTimeout` in the
 * popup — and therefore died with it. A password copied and then the popup
 * closed stayed in the clipboard indefinitely, while the setting promised the
 * opposite.
 *
 * ## Why `execCommand`, which is deprecated
 *
 * `navigator.clipboard.writeText` requires a focused document. An offscreen
 * document never is, by definition. `document.execCommand('copy')` on a
 * `<textarea>` selection remains the method Chrome documents for this precise
 * case. The Clipboard API is tried first all the same: the day it works here,
 * the fallback becomes dead code without anyone having to come back to it.
 *
 * ## Overwritten, not emptied
 *
 * `execCommand('copy')` does nothing with an empty selection. The wipe therefore
 * writes a single space. The useful effect is the same — the secret is no longer
 * in the clipboard — but the right word is "overwritten".
 *
 * ## Second role: reading the colour scheme
 *
 * `matchMedia` needs a DOM too, and the worker needs the answer to pick the
 * toolbar icon. Chrome provides the `MATCH_MEDIA` offscreen reason for exactly
 * this, so the same document answers both questions and is closed straight
 * after.
 */

/** Message types accepted, shared with the service worker. */
const CLIPBOARD_MESSAGE = 'zwarden-clipboard';
const COLOR_SCHEME_MESSAGE = 'zwarden-color-scheme';

interface ClipboardMessage {
  readonly type: string;
  /** Text to place in the clipboard. Empty = wipe. */
  readonly text: unknown;
}

/** Places `text` in the clipboard. A single space if `text` is empty. */
async function write(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    return;
  } catch {
    // Expected when not focused: on to the fallback.
  }

  const buffer = document.getElementById('buffer');
  if (!(buffer instanceof HTMLTextAreaElement)) {
    return;
  }
  buffer.value = text === '' ? ' ' : text;
  buffer.select();
  document.execCommand('copy');
  // The buffer does not keep the secret once the copy is done.
  buffer.value = '';
}

chrome.runtime.onMessage.addListener((message: unknown, sender, respond) => {
  // Only the extension's own pages — the service worker, in practice. A
  // content script is extension code too, but it runs inside a page that may
  // be hostile, and this document writes whatever it is told into the
  // clipboard: a message from a tab is refused before it is read.
  if (sender.tab !== undefined) {
    return false;
  }
  const type =
    typeof message === 'object' && message !== null
      ? (message as { type?: unknown }).type
      : undefined;

  if (type === COLOR_SCHEME_MESSAGE) {
    respond(matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    return false;
  }

  if (type !== CLIPBOARD_MESSAGE) {
    return false;
  }
  const { text } = message as ClipboardMessage;
  void write(typeof text === 'string' ? text : '').then(() => respond(true));
  // Async response: the worker waits for confirmation before closing this
  // document, otherwise it would close it mid-write.
  return true;
});

export {};
