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

/** Which ceremony a request is for. */
type Ceremony = 'get' | 'create';

/** Asks the extension, through the bridge in the isolated world. */
function ask(ceremony: Ceremony, options: Json): Promise<Json | null> {
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
    window.postMessage({ source: TO_EXTENSION, id, ceremony, options }, window.location.origin);
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

/** Reduces a registration's options the same way. */
function serialiseCreation(options: PublicKeyCredentialCreationOptions): Json {
  return {
    challenge: toBase64Url(options.challenge as ArrayBuffer),
    rp: { id: options.rp.id, name: options.rp.name },
    user: {
      id: toBase64Url(options.user.id as ArrayBuffer),
      name: options.user.name,
      displayName: options.user.displayName,
    },
    pubKeyCredParams: options.pubKeyCredParams.map((p) => ({ type: p.type, alg: p.alg })),
    excludeCredentials: (options.excludeCredentials ?? []).map((c) => ({
      id: toBase64Url(c.id as ArrayBuffer),
    })),
    authenticatorSelection: options.authenticatorSelection,
  };
}

/** Builds what the page expects `credentials.create()` to resolve with. */
function buildRegistration(created: Json): Credential {
  const rawId = fromBase64Url(created['credentialId'] as string);
  return {
    id: created['credentialId'] as string,
    rawId,
    type: 'public-key',
    authenticatorAttachment: 'platform',
    response: {
      clientDataJSON: fromBase64Url(created['clientDataJSON'] as string),
      attestationObject: fromBase64Url(created['attestationObject'] as string),
      // Sites commonly call these. Answering what is true is better than
      // omitting them and being read as `undefined` by code expecting a
      // function.
      getTransports: () => ['internal', 'hybrid'],
      getPublicKeyAlgorithm: () => -7,
      // Permitted to be null, and honest: the key is in the attestation object,
      // which is where a relying party reads it from anyway.
      getPublicKey: () => null,
      getAuthenticatorData: () => fromBase64Url(created['authenticatorData'] as string),
    },
    getClientExtensionResults: () => ({}),
  } as unknown as Credential;
}

/**
 * A marker saying the hook is installed.
 *
 * The only property this adds to a page, and it exists to answer one question
 * that is otherwise unanswerable from outside: *is the hook here at all?* When
 * a site shows the browser's own prompt instead of Zwarden's, the cause is
 * almost always that this script never ran — the tab was open before the
 * setting was switched on, the sign-in lives in an iframe, or the registration
 * failed. Typing `window.zwardenPasskeyHook` in the page console separates
 * those from a bug in the signing.
 *
 * Non-enumerable, so it does not show up in an `Object.keys(window)` or in a
 * page's own inventory of globals.
 */
Object.defineProperty(window, 'zwardenPasskeyHook', {
  value: 1,
  enumerable: false,
  configurable: true,
});

const credentials = navigator.credentials;
const originalGet = credentials.get.bind(credentials);
const originalCreate = credentials.create.bind(credentials);

credentials.get = async function get(
  options?: CredentialRequestOptions,
): Promise<Credential | null> {
  if (options?.publicKey === undefined) {
    // Not a WebAuthn call at all — a federated or password credential.
    return originalGet(options);
  }
  // One line per WebAuthn call, which is a rare event — not noise, and it is
  // the only way to tell "the hook never ran" from "the hook declined" without
  // guessing from a screenshot. The whole chain logs the same way.
  console.debug('[zwarden] intercepted credentials.get', {
    rpId: options.publicKey.rpId,
    allowCredentials: (options.publicKey.allowCredentials ?? []).length,
  });
  try {
    const assertion = await ask('get', serialiseOptions(options.publicKey));
    console.debug('[zwarden] credentials.get answered', assertion === null ? 'nothing' : 'signed');
    // Nothing to offer, or the user said no: the browser takes over, and the
    // hardware key in their pocket still works.
    return assertion === null ? originalGet(options) : buildCredential(assertion);
  } catch (error) {
    console.debug('[zwarden] credentials.get failed, falling back', error);
    return originalGet(options);
  }
};

credentials.create = async function create(
  options?: CredentialCreationOptions,
): Promise<Credential | null> {
  if (options?.publicKey === undefined) {
    return originalCreate(options);
  }
  try {
    const created = await ask('create', serialiseCreation(options.publicKey));
    // Declined, or an algorithm we do not implement, or an account that already
    // has a key here: the browser offers its own authenticator instead.
    return created === null ? originalCreate(options) : buildRegistration(created);
  } catch {
    return originalCreate(options);
  }
};

// Nothing is imported and nothing is used elsewhere; this only tells TypeScript
// the file is a module, so its declarations do not collide with the other
// content script's. The bundle stays a standalone script either way.
export {};
