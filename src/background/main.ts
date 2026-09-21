/**
 * @file Service worker — auto-lock and credential capture.
 *
 * ## Why the timer lives here
 *
 * The inactivity that matters to the user is the **browser's**, not the popup's:
 * someone filling forms and switching tabs for an hour is active, even without
 * reopening the panel. Only the service worker sees those events; it is
 * therefore the one that keeps the activity timestamp and decides.
 *
 * ## Mechanics
 *
 * ```
 *   tab activated ─┐
 *   window focus ──┼─► recordActivity()  (storage.session, 20 s threshold)
 *   navigation ────┤                                │
 *   popup open ────┘  (the popup's own heartbeat)   ▼
 *   alarm (1 min) ───────────► shouldAutoLock() ──► session purged
 *                                                        ▲
 *   system session locked ─────────────────────────────────┘ (immediate)
 * ```
 *
 * The alarm is a heartbeat, not a deadline: recreating it on every activity
 * event would run into `chrome.alarms`' rate limit. Acknowledged trade-off:
 * locking can be up to a minute later than the configured delay.
 *
 * Locking the system session (`Win+L`, sleep, lock screen) short-circuits every
 * delay: one walks away from a machine far more often than one closes the
 * browser, and it is that net which makes the "lock on browser close" default
 * tenable.
 *
 * Activity is recorded only while the vault is unlocked — locked, there is
 * nothing to preserve and the service worker has no reason to write.
 *
 * ## Second role: the save proposal
 *
 * The in-page detector (`content/detector.ts`) sends here only what the user has
 * just typed. The worker filters — vault unlocked? feature on? site not
 * excluded? — then files the capture in memory and lights the badge. It does
 * **not** decide whether to offer: it has no key, and does not know what the
 * vault already holds. The popup settles that, when it opens.
 *
 * The target described in `docs/EXTENSION.md` — derivation in the worker, a
 * popup with no key — will gradually replace this file.
 */

import { generatePassword } from '@core/generator/password.js';
import { vaultMayAnswer } from '@core/vault/webauthnRequest.js';
import { applyToolbarIcon, variantFor } from '@shared/theme.js';
import {
  AUTOLOCK_ALARM_NAME,
  CLIPBOARD_ALARM_NAME,
  loadGeneratorOptions,
  loadLastActivity,
  isNeverSaveHost,
  loadPasskeyParties,
  savePasskeyHookStatus,
  loadSettings,
  hasStoredSession,
  lockVault,
  recordActivity,
  savePendingSave,
  scheduleClipboardWipe,
  setBadge,
  setSaveBadge,
  shouldAutoLock,
  startAutoLockWatch,
  stopAutoLockWatch,
} from '@shared/storage.js';

/**
 * Records activity, unless the vault is locked. The session read precedes the
 * write: without it, every tab switch would have the service worker writing when
 * there is no deadline to push back.
 */
async function onActivity(): Promise<void> {
  if (!(await hasStoredSession())) {
    return;
  }
  await recordActivity();
}

/** Locks — a full purge, `lockVault` carries the list. */
async function lockNow(): Promise<void> {
  await lockVault();
}

/** One heartbeat: compares inactivity against the configured delay. */
async function tick(): Promise<void> {
  if (!(await hasStoredSession())) {
    // Session already gone (manual lock, browser restart): the heartbeat has
    // nothing left to do.
    await stopAutoLockWatch();
    return;
  }

  const { autoLockMinutes } = await loadSettings();
  if (autoLockMinutes <= 0) {
    // The setting moved to "browser close" since the watch was armed.
    await stopAutoLockWatch();
    return;
  }

  const last = await loadLastActivity();
  if (last === null) {
    // Timestamp lost: start again from now rather than lock on an absence of
    // information.
    await recordActivity();
    return;
  }

  if (shouldAutoLock(last, autoLockMinutes)) {
    await lockNow();
  }
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === AUTOLOCK_ALARM_NAME) {
    void tick();
  } else if (alarm.name === CLIPBOARD_ALARM_NAME) {
    void writeClipboard('');
  }
});

/**
 * System state transitions. Only `locked` locks — `idle` (no input for a few
 * minutes) says nothing about the user's presence, who may well be reading their
 * screen. `active` counts as activity: coming back from sleep pushes the
 * deadline back.
 */
async function onIdleState(state: chrome.idle.IdleState): Promise<void> {
  if (state === 'locked') {
    const { lockOnSystemLock } = await loadSettings();
    if (lockOnSystemLock) {
      await lockNow();
    }
    return;
  }
  if (state === 'active') {
    await onActivity();
  }
}

chrome.idle.onStateChanged.addListener((state) => void onIdleState(state));

chrome.tabs.onActivated.addListener(() => void onActivity());

chrome.windows.onFocusChanged.addListener((windowId) => {
  if (windowId !== chrome.windows.WINDOW_ID_NONE) {
    void onActivity();
  }
});

// Only the foreground tab counts: a background page refreshing itself must not
// hold the vault open.
chrome.tabs.onUpdated.addListener((_tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading' && tab.active) {
    void onActivity();
  }
});

/**
 * Browser wake-up or extension update: `storage.session` is purged, but the
 * alarms are persisted. We bring the two back into agreement rather than leave a
 * heartbeat running on a locked vault.
 */
async function resync(): Promise<void> {
  await syncToolbarIcon();
  await applyDetectorRegistration();
  await applyPasskeyRegistration();
  if (!(await hasStoredSession())) {
    await lockVault();
    return;
  }
  const { autoLockMinutes } = await loadSettings();
  await startAutoLockWatch(autoLockMinutes);
}

chrome.runtime.onStartup.addListener(() => void resync());

chrome.runtime.onInstalled.addListener((details) => {
  console.log(`Zwarden installed (${details.reason})`);
  void resync();
});

export {};

// --- Clipboard ---------------------------------------------------------------

/** Path of the offscreen document, relative to the root of `dist/`. */
const OFFSCREEN_PATH = 'offscreen.html';

/** Types of the messages addressed to the offscreen document. */
const CLIPBOARD_MESSAGE = 'zwarden-clipboard';
const COLOR_SCHEME_MESSAGE = 'zwarden-color-scheme';

/**
 * Writes to the clipboard from the service worker.
 *
 * An MV3 worker has no DOM, and the clipboard requires one: we therefore open an
 * offscreen document for the duration of the write, then close it. Keeping it
 * open would cost a permanent process for an operation lasting milliseconds.
 *
 * Silent on failure, and deliberately so: the `offscreen` API may be missing
 * (another browser, an older version), in which case the popup's timer remains
 * the only wipe — the previous behaviour, never less.
 *
 * @param text Text to place in the clipboard. Empty = wipe.
 */
async function writeClipboard(text: string): Promise<void> {
  await withOffscreen(async () => {
    await chrome.runtime.sendMessage({ type: CLIPBOARD_MESSAGE, text });
  });
}

/**
 * Opens the offscreen document, runs `use`, and closes it again.
 *
 * Both reasons are declared at creation because a single offscreen document is
 * allowed per extension: asking for one reason now and the other later would
 * mean tearing down and recreating it.
 *
 * Silent on failure, and deliberately so: the `offscreen` API may be missing
 * (another browser, an older version), in which case the caller keeps whatever
 * fallback it has — never less than before.
 */
async function withOffscreen(use: () => Promise<void>): Promise<void> {
  if (typeof chrome.offscreen === 'undefined') {
    return;
  }
  try {
    await chrome.offscreen.createDocument({
      url: OFFSCREEN_PATH,
      reasons: [chrome.offscreen.Reason.CLIPBOARD, chrome.offscreen.Reason.MATCH_MEDIA],
      justification:
        'Deferred clipboard wipe after copying a secret, and reading the colour scheme ' +
        'to pick the toolbar icon.',
    });
  } catch {
    // Already open: it is exactly the document we need.
  }

  try {
    await use();
  } catch {
    // Document absent or already closed: nothing to recover from.
  } finally {
    try {
      await chrome.offscreen.closeDocument();
    } catch {
      // Already closed.
    }
  }
}

// --- Toolbar icon ------------------------------------------------------------

/**
 * Matches the toolbar icon to the browser's theme.
 *
 * The icon is a white padlock: on a light toolbar it is invisible, and the user
 * concludes the extension failed to install. A service worker has no DOM, hence
 * no `matchMedia` — the offscreen document answers for it.
 *
 * Run at start-up and on install. An icon set through `setIcon` does not survive
 * the extension reloading, which is exactly when those two events fire.
 * Extension pages settle it again when they open, which covers the user changing
 * their system theme mid-session.
 */
async function syncToolbarIcon(): Promise<void> {
  await withOffscreen(async () => {
    const scheme: unknown = await chrome.runtime.sendMessage({ type: COLOR_SCHEME_MESSAGE });
    if (scheme === 'dark' || scheme === 'light') {
      await applyToolbarIcon(variantFor(scheme === 'dark'));
    }
  });
}

// --- Keyboard shortcuts ------------------------------------------------------

/**
 * Manifest commands.
 *
 * Only those that can succeed **without the vault key** are declared: the worker
 * does not hold it. Autofill by shortcut (`Ctrl+Shift+L` in the official
 * extension) therefore waits on the in-worker derivation described as a target
 * in `docs/EXTENSION.md` — declaring a shortcut that does nothing would be worse
 * than not declaring it.
 */
async function onCommand(command: string): Promise<void> {
  if (command === 'lock-vault') {
    await lockNow();
    return;
  }
  if (command === 'generate-password') {
    // Generating requires no key: that is what makes this shortcut possible
    // right now.
    const password = generatePassword(await loadGeneratorOptions());
    await writeClipboard(password);
    const { clipboardClearSeconds } = await loadSettings();
    await scheduleClipboardWipe(clipboardClearSeconds);
  }
}

if (typeof chrome.commands !== 'undefined') {
  chrome.commands.onCommand.addListener((command) => void onCommand(command));
}

// --- Credential capture ------------------------------------------------------

/** Identifier of the detector's dynamic registration. */
const DETECTOR_SCRIPT_ID = 'zwarden-detector';

/** Type of the message the detector emits. */
const CREDENTIALS_MESSAGE = 'zwarden-credentials';

interface CredentialsMessage {
  readonly type: string;
  readonly username: unknown;
  readonly password: unknown;
}

/**
 * Files a capture and lights the badge — or drops it, silently.
 *
 * Four refusals, all silent: anything not coming from a tab (hence not from the
 * detector), the feature switched off, the vault locked — we do not keep a
 * cleartext password in memory while everything else is purged — and the sites
 * the user has excluded.
 *
 * **The origin does not come from the message.** It is read off `sender`, which
 * the browser fills in itself: a message field is declared, whereas this one is
 * observed. The gap matters, because this origin becomes the created item's URI
 * and the matching key — an origin chosen by the sender would have a password
 * saved under another site's address.
 */
async function onCredentials(
  message: CredentialsMessage,
  sender: chrome.runtime.MessageSender,
): Promise<void> {
  if (sender.tab === undefined || sender.origin === undefined) {
    return;
  }
  const { username, password } = message;
  if (typeof username !== 'string' || typeof password !== 'string' || password === '') {
    return;
  }

  let origin: string;
  let host: string;
  try {
    const url = new URL(sender.origin);
    origin = url.origin;
    host = url.hostname;
  } catch {
    return;
  }

  const { offerToSave } = await loadSettings();
  if (!offerToSave || !(await hasStoredSession())) {
    return;
  }
  if (await isNeverSaveHost(host)) {
    return;
  }

  await savePendingSave({ origin, host, username, password, capturedAt: Date.now() });
  await setSaveBadge(true);
  // Typing a password is activity: it pushes the deadline back just as a tab
  // switch does.
  await recordActivity();
}

chrome.runtime.onMessage.addListener((message: unknown, sender) => {
  if (
    typeof message === 'object' &&
    message !== null &&
    (message as { type?: unknown }).type === CREDENTIALS_MESSAGE
  ) {
    void onCredentials(message as CredentialsMessage, sender);
  }
  // The popup's verdict on a passkey ceremony, on its way back to the page.
  const body = message as { type?: unknown; id?: unknown; assertion?: unknown } | null;
  if (body?.type === 'assertion-answer' && typeof body.id === 'string') {
    void answerAssertion(body.id, body.assertion);
  }
  // No async response expected: do not return `true`.
  return false;
});

/**
 * Keeps the detector's presence aligned with the setting.
 *
 * Dynamic registration rather than a manifest declaration: with the setting off,
 * there is **no** script injected into pages — not a script keeping quiet, no
 * script at all. That is the difference between a promise and a guarantee.
 */
async function applyDetectorRegistration(): Promise<void> {
  if (typeof chrome.scripting?.getRegisteredContentScripts !== 'function') {
    return;
  }
  const { offerToSave } = await loadSettings();
  const existing = await chrome.scripting.getRegisteredContentScripts({
    ids: [DETECTOR_SCRIPT_ID],
  });

  if (offerToSave && existing.length === 0) {
    await chrome.scripting.registerContentScripts([
        {
          id: DETECTOR_SCRIPT_ID,
          js: ['content.js'],
          // Same hosts as the manifest permissions, main frame only: iframes are
          // explicitly out of scope (§4).
          matches: ['https://*/*', 'http://localhost/*', 'http://127.0.0.1/*'],
          allFrames: false,
          runAt: 'document_idle',
          persistAcrossSessions: true,
        },
      ]);
  } else if (!offerToSave && existing.length > 0) {
    await chrome.scripting.unregisterContentScripts({ ids: [DETECTOR_SCRIPT_ID] });
  }
}

// The setting changes from the options page, in another context: storage is what
// notifies us.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && 'offerToSave' in changes) {
    void applyDetectorRegistration();
  }
  if (area === 'local' && 'passkeySignIn' in changes) {
    void applyPasskeyRegistration();
  }
});

// --- Passkey sign-in ---------------------------------------------------------

const PASSKEY_HOOK_ID = 'zwarden-passkey-hook';
const PASSKEY_BRIDGE_ID = 'zwarden-passkey-bridge';
const PASSKEY_PORT = 'zwarden-webauthn';

/** Where the popup reads what a page is waiting for. */
const PENDING_ASSERTION_KEY = 'pendingAssertion';

/** How long a ceremony is held before it is let go. */
const ASSERTION_TIMEOUT_MS = 90_000;

/**
 * Registers, or removes, the two halves of the passkey hook.
 *
 * Two scripts because they live in two worlds: the hook replaces
 * `navigator.credentials.get` in the page's own context, which is the only
 * place that function exists, and the bridge is the only one that can reach
 * `chrome.runtime`.
 *
 * Both at `document_start`: a page may call for an assertion before it has
 * finished loading, and a hook installed afterwards would have missed it.
 *
 * Off unless asked for, like the detector. This is the one thing Zwarden puts
 * inside a page, and a user who never signs in with a passkey should carry
 * none of it.
 */
async function applyPasskeyRegistration(): Promise<void> {
  if (typeof chrome.scripting?.getRegisteredContentScripts !== 'function') {
    return;
  }
  const { passkeySignIn } = await loadSettings();
  const ids = [PASSKEY_HOOK_ID, PASSKEY_BRIDGE_ID];
  const existing = await chrome.scripting.getRegisteredContentScripts({ ids });
  // Said on every start-up. Whether the setting is even on was the one fact
  // never confirmed while several real but unrelated faults were found and
  // fixed; it should not have taken that long, and it will not again.
  console.debug('[zwarden] passkey sign-in', {
    setting: passkeySignIn ? 'on' : 'off',
    alreadyRegistered: existing.map((script) => script.id),
  });

  if (!passkeySignIn) {
    if (existing.length > 0) {
      await chrome.scripting.unregisterContentScripts({ ids });
    }
    await savePasskeyHookStatus({ registered: false, error: null });
    return;
  }
  if (existing.length === ids.length) {
    await savePasskeyHookStatus({ registered: true, error: null });
    return;
  }
  // Partially registered — one half there, the other not. Registering would be
  // refused for the duplicate identifier and the missing half would stay
  // missing, for ever and in silence. Clearing first is the only way out.
  if (existing.length > 0) {
    await chrome.scripting.unregisterContentScripts({
      ids: existing.map((script) => script.id),
    });
  }

  // Whether `world: 'MAIN'` may be combined with `persistAcrossSessions` is not
  // something the documentation settles, and a refusal here is invisible from
  // the page — it looks exactly like a site that simply never calls WebAuthn.
  // So the persistent form is tried, and the session-only form after it.
  for (const persistAcrossSessions of [true, false]) {
    try {
      await chrome.scripting.registerContentScripts([
      {
        id: PASSKEY_HOOK_ID,
        js: ['webauthnHook.js'],
        // The page's own world: an isolated script cannot replace a function
        // the page will call.
        world: 'MAIN',
        // HTTPS only. WebAuthn is a secure-context feature, and an assertion
        // answered over plain HTTP is a signature handed to whoever is on the
        // wire — `validateAssertionAsk` refuses it too, one layer down.
        matches: ['https://*/*'],
        // Main frame only, as §4 has it for the detector. A sign-in inside an
        // iframe is therefore **not** intercepted and the browser handles it —
        // a real limitation, and the first thing to check when a site shows its
        // own prompt instead of ours.
        allFrames: false,
        runAt: 'document_start',
        persistAcrossSessions,
      },
      {
        id: PASSKEY_BRIDGE_ID,
        js: ['webauthnBridge.js'],
        world: 'ISOLATED',
        matches: ['https://*/*'],
        allFrames: false,
        runAt: 'document_start',
        persistAcrossSessions,
      },
      ]);
      console.debug('[zwarden] passkey hook registered', { persistAcrossSessions });
      await savePasskeyHookStatus({ registered: true, error: null });
      return;
    } catch (error) {
      // Recorded where the settings page can show it. A registration that fails
      // silently leaves the feature switched on and absent from every page —
      // the worst of both, since the user believes it works and has no way to
      // find out.
      console.error('[zwarden] could not install the passkey hook:', error);
      await savePasskeyHookStatus({ registered: false, error: String(error) });
    }
  }
}

/**
 * The page waiting on an answer, held by request identifier.
 *
 * In memory and not in storage, on purpose: a `chrome.runtime.Port` cannot be
 * serialised, and while one is open the service worker is not killed. The port
 * is therefore both the address to answer at and the thing keeping this code
 * alive long enough to answer.
 */
const waitingPages = new Map<string, chrome.runtime.Port>();

chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== PASSKEY_PORT) {
    return;
  }
  port.onMessage.addListener((message: unknown) => {
    const body = message as { type?: unknown; ceremony?: unknown; options?: unknown } | null;
    if (body?.type === 'webauthn-request') {
      const ceremony = body.ceremony === 'create' ? 'create' : 'get';
      void onAssertionRequest(port, ceremony, body.options);
    }
  });
});

/**
 * Takes a page's request and puts it where the popup will find it.
 *
 * The **origin is taken from the sender**, never from the message: a page that
 * could name its own origin could name any, and the whole protection against a
 * site asking for another site's passkey rests on that one value being the
 * browser's word rather than the page's.
 */
async function onAssertionRequest(
  port: chrome.runtime.Port,
  ceremony: 'get' | 'create',
  options: unknown,
): Promise<void> {
  const sender = port.sender;
  const origin = sender?.origin ?? (sender?.url === undefined ? null : originOf(sender.url));
  if (origin === null || typeof options !== 'object' || options === null) {
    port.postMessage({ result: null });
    return;
  }

  // Can this vault answer at all? The popup leaves the list of relying parties
  // behind when it opens the vault, precisely so this question can be settled
  // here, without keys and without waking anybody.
  //
  // Holding the page until somebody opens the popup to find out there was
  // nothing would make Zwarden a ninety-second delay on every sign-in done with
  // a hardware key — which is most of them.
  if (ceremony === 'get' && !(await canAnswerFor(options))) {
    console.debug('[zwarden] declined before asking: no related passkey', {
      rpId: (options as { rpId?: unknown }).rpId ?? '(the page\u2019s own host)',
      known: await loadPasskeyParties(),
    });
    port.postMessage({ result: null });
    return;
  }
  console.debug('[zwarden] holding a', ceremony, 'ceremony for', origin);

  const id = crypto.randomUUID();
  waitingPages.set(id, port);
  port.onDisconnect.addListener(() => void forgetAssertion(id));

  await chrome.storage.session.set({
    [PENDING_ASSERTION_KEY]: { id, ceremony, origin, options, askedAt: Date.now() },
  });
  // Its own badge, not the save proposal's. They were the same mark, and an
  // "alert appeared" then meant either — which is how a ceremony that never
  // fired looked exactly like one that did.
  await setBadge('passkey');

  // A ceremony nobody answers must not hold the worker awake for ever.
  setTimeout(() => void forgetAssertion(id), ASSERTION_TIMEOUT_MS);
}

/** Whether this vault can answer for the party a page is asking about. */
async function canAnswerFor(options: unknown): Promise<boolean> {
  const claimed = (options as { rpId?: unknown }).rpId;
  return vaultMayAnswer(
    await loadPasskeyParties(),
    typeof claimed === 'string' ? claimed : null,
  );
}

/** Drops a pending ceremony, however it ended. */
async function forgetAssertion(id: string): Promise<void> {
  if (!waitingPages.delete(id)) {
    // Not ours, or already forgotten. Clearing the badge here would take down
    // a mark another ceremony, or a captured credential, still needs.
    return;
  }

  // The badge comes down because **this** ceremony is over, not because the
  // stored entry happens to still be there. It usually is not: the popup
  // clears it before it answers, so the old check — remove the entry, and only
  // then the badge — matched nothing and left the mark up for ever after a
  // successful sign-in.
  const stored = await chrome.storage.session.get(PENDING_ASSERTION_KEY);
  const pending = stored[PENDING_ASSERTION_KEY] as { id?: string } | undefined;
  if (pending?.id === id) {
    await chrome.storage.session.remove(PENDING_ASSERTION_KEY);
  }
  await setBadge(null);
}

/** The origin of a URL, or `null` if it has none worth having. */
function originOf(url: string): string | null {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

/**
 * Carries the popup's answer back down to the page.
 *
 * `null` means "we have nothing" — a declined confirmation, a locked vault, a
 * request refused. The hook then calls the browser's own `credentials.get`,
 * and the user's hardware key works as it always did.
 */
async function answerAssertion(id: string, assertion: unknown): Promise<void> {
  const port = waitingPages.get(id);
  if (port !== undefined) {
    port.postMessage({ result: assertion ?? null });
  }
  await forgetAssertion(id);
}
