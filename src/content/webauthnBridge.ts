/**
 * @file Carries a passkey request between the page and the extension.
 *
 * Two worlds cannot talk directly: the hook runs in the page's own context and
 * can reach `navigator.credentials`; only an isolated content script can reach
 * `chrome.runtime`. This file is the hinge, and it is deliberately thin —
 * it validates nothing and decides nothing, because everything it receives
 * comes from the page and must be treated as such by whoever does decide
 * (`core/vault/webauthnRequest.ts`).
 *
 * The connection is a **port**, not a one-off message. A ceremony waits on a
 * human, and a service worker that answers messages is allowed to die between
 * them; an open port is what keeps it alive for as long as the page is
 * waiting.
 */

/**
 * The names the hook and the bridge agree on.
 *
 * Written out in both files rather than imported from a third. A content script
 * is not an ES module — an `import` in one simply fails at load — and a bundler
 * asked to share code between two entries emits exactly that. The duplication
 * is therefore the platform's, not a preference, and `tests/webauthnProtocol.test.ts`
 * is what keeps the two copies identical: a renamed message would otherwise
 * fail silently, the page falling back to the browser for ever, which looks
 * exactly like "no passkey here".
 */
const TO_EXTENSION = 'zwarden-webauthn-ask';
const FROM_EXTENSION = 'zwarden-webauthn-answer';
const PORT_NAME = 'zwarden-webauthn';

type Json = Record<string, unknown>;

window.addEventListener('message', (event: MessageEvent) => {
  // Only this window's own hook. A frame must not ask on its parent's behalf.
  if (event.source !== window) {
    return;
  }
  const data = event.data as Json | null;
  if (data?.['source'] !== TO_EXTENSION || typeof data['id'] !== 'string') {
    return;
  }

  const id = data['id'];
  let port: chrome.runtime.Port;
  try {
    port = chrome.runtime.connect({ name: PORT_NAME });
  } catch {
    // The extension was reloaded or removed: answer nothing and let the page
    // fall back to the browser.
    window.postMessage({ source: FROM_EXTENSION, id }, window.location.origin);
    return;
  }

  /** Hands the answer back to the hook, once. */
  function answer(assertion: unknown): void {
    window.postMessage(
      assertion === undefined || assertion === null
        ? { source: FROM_EXTENSION, id }
        : { source: FROM_EXTENSION, id, assertion },
      window.location.origin,
    );
  }

  port.onMessage.addListener((message: unknown) => {
    answer((message as Json | null)?.['result']);
    port.disconnect();
  });

  // The worker dying, the vault locking, the popup being dismissed: whatever
  // the reason, silence means "we have nothing", and the page recovers.
  port.onDisconnect.addListener(() => {
    console.log('[zwarden] the extension closed the channel without answering');
    answer(null);
  });

  console.log('[zwarden] relaying a', data['ceremony'], 'ceremony to the extension');
  port.postMessage({
    type: 'webauthn-request',
    ceremony: data['ceremony'],
    options: data['options'],
  });
});

// Nothing is imported and nothing is used elsewhere; this only tells TypeScript
// the file is a module, so its declarations do not collide with the other
// content script's. The bundle stays a standalone script either way.
export {};
