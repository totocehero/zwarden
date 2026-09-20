/**
 * @file The hook that lets Zwarden answer a passkey sign-in.
 *
 * Runs in the **page's own world**, because `navigator.credentials.get` lives
 * there and an isolated content script cannot reach it. This is the one place
 * the extension puts code inside a page, and it is worth being exact about
 * what that means: it replaces a *function*, not the interface. Nothing is
 * drawn, no element is inserted, no style is applied. The confirmation happens
 * in the popup, as every other decision in this extension does.
 *
 * ## Falling back rather than breaking
 *
 * If the extension has nothing to offer — locked vault, no passkey for the
 * site, a request it refuses, the user declining — the original function is
 * called and the browser does what it always would. A hardware key still
 * works, the platform authenticator still works. A hook that swallowed those
 * cases would make every passkey sign-in on the machine depend on this
 * extension being right.
 *
 * ## What it cannot do
 *
 * The object handed back is shaped like a `PublicKeyCredential` but is not one:
 * that interface cannot be constructed. Sites that read the fields — nearly all
 * of them — are satisfied; a site that tests `instanceof` is not, and will fall
 * back to its own flow.
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
const ASK_TIMEOUT_MS = 90_000;

type Json = Record<string, unknown>;

/** base64url — how bytes cross a boundary that only carries strings. */
function toBase64Url(bytes: ArrayBuffer | ArrayBufferView): string {
  const view =
    bytes instanceof ArrayBuffer
      ? new Uint8Array(bytes)
      : new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let binary = '';
  for (const byte of view) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** The inverse, tolerant of the padding base64url leaves off. */
function fromBase64Url(text: string): ArrayBuffer {
  const normalised = text.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalised.padEnd(normalised.length + ((4 - (normalised.length % 4)) % 4), '=');
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out.buffer;
}

/** Reduces the page's options to something that can cross a `postMessage`. */
function serialiseOptions(options: PublicKeyCredentialRequestOptions): Json {
  return {
    challenge: toBase64Url(options.challenge as ArrayBuffer),
    rpId: options.rpId,
    userVerification: options.userVerification,
    allowCredentials: (options.allowCredentials ?? []).map((credential) => ({
      id: toBase64Url(credential.id as ArrayBuffer),
    })),
  };
}

/** Asks the extension, through the bridge in the isolated world. */
function ask(options: Json): Promise<Json | null> {
  return new Promise((resolve) => {
    const id = crypto.randomUUID();
    const timer = setTimeout(() => finish(null), ASK_TIMEOUT_MS);

    function finish(answer: Json | null): void {
      clearTimeout(timer);
      window.removeEventListener('message', onMessage);
      resolve(answer);
    }

    function onMessage(event: MessageEvent): void {
      // Only this window: a frame must not answer for its parent.
      if (event.source !== window) {
        return;
      }
      const data = event.data as Json | null;
      if (data?.['source'] !== FROM_EXTENSION || data['id'] !== id) {
        return;
      }
      finish(data['assertion'] === undefined ? null : (data['assertion'] as Json));
    }

    window.addEventListener('message', onMessage);
    window.postMessage({ source: TO_EXTENSION, id, options }, window.location.origin);
  });
}

/** Builds what the page expects `credentials.get()` to resolve with. */
function buildCredential(assertion: Json): Credential {
  const rawId = fromBase64Url(assertion['credentialId'] as string);
  const userHandle = assertion['userHandle'];
  return {
    id: assertion['credentialId'] as string,
    rawId,
    type: 'public-key',
    authenticatorAttachment: 'platform',
    response: {
      clientDataJSON: fromBase64Url(assertion['clientDataJSON'] as string),
      authenticatorData: fromBase64Url(assertion['authenticatorData'] as string),
      signature: fromBase64Url(assertion['signature'] as string),
      userHandle: typeof userHandle === 'string' ? fromBase64Url(userHandle) : null,
    },
    getClientExtensionResults: () => ({}),
  } as unknown as Credential;
}

const credentials = navigator.credentials;
const original = credentials.get.bind(credentials);

credentials.get = async function get(
  options?: CredentialRequestOptions,
): Promise<Credential | null> {
  if (options?.publicKey === undefined) {
    // Not a WebAuthn call at all — a federated or password credential.
    return original(options);
  }
  try {
    const assertion = await ask(serialiseOptions(options.publicKey));
    // Nothing to offer, or the user said no: the browser takes over, and the
    // hardware key in their pocket still works.
    return assertion === null ? original(options) : buildCredential(assertion);
  } catch {
    return original(options);
  }
};

// Nothing is imported and nothing is used elsewhere; this only tells TypeScript
// the file is a module, so its declarations do not collide with the other
// content script's. The bundle stays a standalone script either way.
export {};
