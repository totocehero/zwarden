/**
 * @file The popup.
 *
 * The complete chain in a real extension context: `unlock()` → an optional
 * second factor → `sync` → `decryptCipherList` → a filterable list → copying or
 * revealing a password decrypted on demand.
 *
 * ## Filtering by active tab
 *
 * When the vault opens, if the active tab's domain matches at least one item,
 * the filter is pre-filled with that domain — the sketch of the "Zwarden view"
 * from `docs/EXTENSION.md`. Clearing the field shows everything.
 *
 * ## Second factor
 *
 * Providers whose code can be entered: TOTP (0), email code (1), YubiKey OTP
 * (3). WebAuthn (7) requires a bounce page served by the server (an extension's
 * origin cannot answer the vault's RP ID): out of scope for this version — a
 * YubiKey is used in OTP mode. "Remember this device" keeps the remember token
 * (provider 5) and replays it automatically; when it expires, the entry screen
 * comes back.
 *
 * ## Session persistence and locking
 *
 * The unlocked vault survives the popup closing: key and tokens sit in
 * `chrome.storage.session` (pure memory, purged when the browser closes). By
 * default it only locks on that close. If an inactivity delay is configured, the
 * service worker is what carries it: the popup merely signals its activity
 * (`recordActivity`), just as a tab switch would. The password is never
 * persisted.
 *
 * Remaining acknowledged limit (`docs/EXTENSION.md`): derivation runs here, not
 * yet in the service worker.
 */

import { applyLocale, t } from '@shared/i18n.js';
import { followPageColorScheme } from '@shared/theme.js';
import { render } from 'preact';
import { useEffect, useMemo, useRef, useState } from 'preact/hooks';

import { type EditForm, EMPTY_EDIT, EditItemForm } from './components/EditItemForm.js';
import type { RevealedContent } from './components/ItemRow.js';
import { type AssertionChoice, AssertionScreen } from './components/AssertionScreen.js';
import { ExportScreen } from './components/ExportScreen.js';
import { HealthPanel } from './components/HealthPanel.js';
import { TypeFilter } from './components/TypeFilter.js';
import { type MenuAction, VaultHeader } from './components/VaultHeader.js';
import { chipsFor, ItemRow } from './components/ItemRow.js';
import { RepromptGuard } from './components/RepromptGuard.js';
import { SaveProposalBanner, type SaveProposal } from './components/SaveProposal.js';
import { TwoFactorScreen, UnlockScreen } from './components/SignInScreens.js';
import { useGenerator } from './hooks/useGenerator.js';
import { useReprompt } from './hooks/useReprompt.js';

import {
  ApiClient,
  ApiError,
  TwoFactorRequiredError,
  type TwoFactorSubmission,
} from '@core/api/apiClient.js';
import {
  TwoFactorProvider,
  readField,
  type CipherResponse,
  type SyncResponse,
} from '@core/api/models.js';
import { SymmetricCryptoKey } from '@core/crypto/symmetricCryptoKey.js';
import { toBase64Url } from '@core/crypto/encoding.js';
import { digitsOf, EMPTY_CARD_EDIT } from '@core/vault/card.js';
import { EMPTY_IDENTITY_EDIT, fullName } from '@core/vault/identity.js';
import {
  type CipherDetails,
  type CipherEdit,
  type CipherKeys,
  type CipherOverview,
  type PasskeyView,
  buildCipherCreatePayload,
  buildCipherUpdatePayload,
  countTypes,
  decideProposal,
  decryptCipherDetails,
  decryptCipherList,
  decryptPasskeys,
  findSaveCandidate,
  reuseByRevision,
  sortCiphersByLastUsed,
} from '@core/vault/cipherService.js';
import { buildVaultKeys, destroyVaultKeys } from '@core/vault/keyring.js';
import { type VaultLabels, decryptLabels } from '@core/vault/labels.js';
import { matchesOrigin } from '@core/vault/uriMatch.js';
import { decideReplay, isUnreachable } from '@core/vault/offlineQueue.js';
import { buildHealthReport, type HealthReport } from '@core/vault/health.js';
import { checkPasswords } from '@core/vault/breachCheck.js';
import { createCredential, selectCredentials, signAssertion } from '@core/vault/passkey.js';
import {
  type AssertionAsk,
  type CreationAsk,
  validateAssertionAsk,
  validateCreationAsk,
  WebAuthnRefusal,
} from '@core/vault/webauthnRequest.js';
import { type ExportPayload, type ExportedItem, sealExport } from '@core/vault/exportFile.js';
import {
  clearWriteQueue,
  enqueueWrite,
  loadWriteQueue,
  removeWrites,
} from '@shared/writeQueue.js';
import { type TotpConfig, generateTotp, parseTotp } from '@core/vault/totp.js';
import { type UnlockResult, unlock } from '@core/vault/session.js';
import { deriveMasterKey, verifyLocalPasswordHash } from '@core/crypto/kdf.js';
import {
  type AppSettings,
  type PendingSave,
  type StoredSession,
  DEFAULT_SETTINGS,
  addNeverSaveHost,
  clearPendingSave,
  clearRememberToken,
  getDeviceId,
  loadLastUsed,
  clearPendingAssertion,
  loadPendingAssertion,
  savePasskeyParties,
  loadPendingSave,
  loadRememberToken,
  loadSettings,
  loadStoredSession,
  loadVaultKey,
  lockVault,
  markUsed,
  recordActivity,
  setSaveBadge,
  saveRememberToken,
  saveSettings,
  saveStoredSession,
  saveVaultKey,
  scheduleClipboardWipe,
  startAutoLockWatch,
} from '@shared/storage.js';

/** An unlocked vault's state, alive only for as long as the popup is. */
interface OpenVault {
  readonly userKey: SymmetricCryptoKey;
  /** The full keyring: vault key + unwrapped organisation keys. */
  readonly keys: CipherKeys;
  readonly items: readonly CipherOverview[];
  readonly raw: ReadonlyMap<string, CipherResponse>;
  /** Folders, collections and organisations, names decrypted. */
  readonly labels: VaultLabels;
  /** Decryption failures encountered, for on-screen diagnosis. */
  readonly errors: readonly unknown[];
  /**
   * How many items are still being decrypted, `0` once the vault is whole.
   *
   * Shown rather than hidden: while it is above zero the list is incomplete, so
   * a search that finds nothing may simply not have reached the item yet. An
   * empty result the user cannot tell from a missing one is worse than a wait.
   */
  readonly pending: number;
}

/**
 * The one-time code open on a row of the list.
 *
 * `App` keeps only the item concerned and the resolved parameters — the code and
 * its countdown belong to {@link OtpCode}, which recomputes them every second.
 * Keeping them here re-rendered the whole popup on every beat.
 */
interface OtpView {
  readonly id: string;
  readonly config: TotpConfig;
  /**
   * The code computed when the panel opened — the very one put on the
   * clipboard. Handed to {@link OtpCode} so that what is displayed and what was
   * copied cannot differ. See that component's header.
   */
  readonly code: string;
}

/** A session ready to write: API client and valid tokens. */
interface AuthorizedSession {
  readonly client: ApiClient;
  readonly stored: StoredSession;
  readonly accessToken: string;
  readonly refreshToken: string | null;
  readonly expiresAt: number;
}

/** Groups errors by name, for a readable diagnosis. */
function groupErrors(errors: readonly unknown[]): ReadonlyArray<readonly [string, number]> {
  const grouped = new Map<string, number>();
  for (const error of errors) {
    const name = error instanceof Error ? error.name : t('errorUnknown');
    grouped.set(name, (grouped.get(name) ?? 0) + 1);
  }
  return [...grouped.entries()].sort((a, b) => b[1] - a[1]);
}

/** Providers whose code the popup knows how to collect. */
function providerLabels(): Readonly<Record<string, string>> {
  return {
    [String(TwoFactorProvider.Authenticator)]: t('twoFaProviderAuthenticator'),
    [String(TwoFactorProvider.Email)]: t('twoFaProviderEmail'),
    [String(TwoFactorProvider.YubiKey)]: t('twoFaProviderYubiKey'),
  };
}

/** The active tab, if it points at a web page. */
async function activeWebTab(): Promise<{ tabId: number; url: URL } | null> {
  if (typeof chrome === 'undefined' || typeof chrome.tabs?.query === 'undefined') {
    return null;
  }
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.id === undefined || tab.url === undefined) {
      return null;
    }
    const url = new URL(tab.url);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return null;
    }
    return { tabId: tab.id, url };
  } catch {
    return null;
  }
}

/**
 * Fills the page's first visible sign-in form.
 *
 * This function is **serialised** and then executed inside the page through
 * `chrome.scripting`: it must reference no outside variable. Main frame only,
 * never an automatic submission.
 */
function fillCredentials(username: string, password: string): void {
  const visible = (el: HTMLElement): boolean => el.getClientRects().length > 0;
  const setValue = (input: HTMLInputElement, value: string): void => {
    // Go through the prototype's native setter, so that frameworks intercepting
    // `value` (React and friends) actually see the change.
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
    setter?.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
  };

  const passwordInput = Array.from(
    document.querySelectorAll<HTMLInputElement>('input[type="password"]'),
  ).find(visible);
  if (passwordInput !== undefined && password !== '') {
    setValue(passwordInput, password);
  }

  if (username !== '') {
    const scope = passwordInput?.form ?? document;
    const usernameInput = Array.from(
      scope.querySelectorAll<HTMLInputElement>(
        'input[type="email"], input[autocomplete="username"], input[type="text"], input:not([type])',
      ),
    ).find(visible);
    if (usernameInput !== undefined) {
      setValue(usernameInput, username);
    }
  }
}

function openOptions(): void {
  if (typeof chrome !== 'undefined' && typeof chrome.runtime?.openOptionsPage === 'function') {
    void chrome.runtime.openOptionsPage();
  }
}

/**
 * Turns a decrypted section into the form's values.
 *
 * Two shapes for the same fields: decryption yields `null` for what is absent,
 * a form field holds an empty string. The blank value carries the field list, so
 * a field the model gains cannot go missing from the form.
 */
function toEditValues<F extends string>(
  view: Readonly<Record<F, string | null>> | null,
  blank: Readonly<Record<F, string>>,
): Readonly<Record<F, string>> {
  if (view === null) {
    return blank;
  }
  const fields = Object.keys(blank) as F[];
  return Object.fromEntries(fields.map((field) => [field, view[field] ?? ''])) as Readonly<
    Record<F, string>
  >;
}

/**
 * How many items are decrypted before the list is first drawn.
 *
 * A vault of five hundred items with a key of its own per item costs the better
 * part of a second to decrypt, and a popup is a cold start every time — no JIT,
 * no warm cache. Twenty rows is more than the 420-pixel popup shows, so the
 * list is complete as far as the eye goes, and the rest lands while the hand is
 * still moving.
 *
 * The server cannot help here: Bitwarden's `/api/sync` returns the vault whole
 * and takes no page parameter. What is split is the decryption, which is where
 * the time actually goes.
 */
const FIRST_SLICE = 20;

/** The total held by a per-type count. */
function countOf(counts: ReadonlyMap<number, number>): number {
  let total = 0;
  for (const n of counts.values()) {
    total += n;
  }
  return total;
}

/** How long a revealed password stays on screen before being hidden again. */
const REVEAL_HIDE_MS = 20_000;

/**
 * Period of the activity heartbeat emitted while the popup is open on an
 * unlocked vault. Below `recordActivity`'s write threshold (20 s) there would be
 * no extra write; above it, the timestamp could grow stale for nothing.
 */
const ACTIVITY_PING_MS = 30_000;

/** The error message to display. Stable codes take precedence over messages. */
function messageFor(err: unknown): string {
  if (err instanceof DOMException && err.name === 'TimeoutError') {
    return t('errorTimeout');
  }
  if (err instanceof Error) {
    return err.message;
  }
  return String(err);
}

function App() {
  const [settings, setSettings] = useState<AppSettings>(DEFAULT_SETTINGS);
  /** True until the initial restore attempt has concluded. */
  const [initializing, setInitializing] = useState(true);
  const [serverUrl, setServerUrl] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [vault, setVault] = useState<OpenVault | null>(null);
  const [tabOrigin, setTabOrigin] = useState<string | null>(null);
  const [filter, setFilter] = useState('');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [copiedUserId, setCopiedUserId] = useState<string | null>(null);
  const [revealed, setRevealed] = useState<{ id: string; content: RevealedContent } | null>(null);
  /** Label of the detail field copied a moment ago — feeds the tick on it. */
  const [copiedField, setCopiedField] = useState<string | null>(null);
  /**
   * The types the list is narrowed to. Empty means every type.
   *
   * Not persisted: a filter left on from yesterday would hide items with no
   * visible reason, and the cost of setting it again is one click.
   */
  const [typeFilter, setTypeFilter] = useState<ReadonlySet<number>>(new Set());
  /**
   * Item count per type, read from the raw sync before anything is decrypted.
   *
   * Lets the filter appear with true counts while the list is still being
   * decrypted, rather than arriving after it and shifting the layout under a
   * cursor already on its way.
   */
  const [rawCounts, setRawCounts] = useState<ReadonlyMap<number, number>>(new Map());
  /**
   * Writes made while the server was unreachable: how many are waiting, and how
   * many could not be applied because the item changed elsewhere.
   */
  const [queued, setQueued] = useState({ pending: 0, held: 0 });
  /** The health report, while its screen is open. */
  const [health, setHealth] = useState<HealthReport | null>(null);
  /** The export form's three secrets, while its screen is open. */
  const [exporting, setExporting] = useState(false);
  const [exportMaster, setExportMaster] = useState('');
  const [exportPassphrase, setExportPassphrase] = useState('');
  const [exportConfirmation, setExportConfirmation] = useState('');
  /** The passkey ceremony a page is waiting on, once it has been validated. */
  const [assertion, setAssertion] = useState<
    | { readonly kind: 'get'; readonly id: string; readonly ask: AssertionAsk; readonly choices: readonly AssertionChoice[] }
    | { readonly kind: 'create'; readonly id: string; readonly ask: CreationAsk; readonly choices: readonly AssertionChoice[] }
    | null
  >(null);
  const [assertionChoice, setAssertionChoice] = useState<string | null>(null);
  const [assertionPassword, setAssertionPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [proposal, setProposal] = useState<SaveProposal | null>(null);
  const reprompt = useReprompt(messageFor);

  // The open one-time code: `App` keeps only the item and the resolved
  // parameters, the heartbeat belongs to `OtpCode`.
  const [otp, setOtp] = useState<OtpView | null>(null);
  const [copiedOtp, setCopiedOtp] = useState(false);

  const generator = useGenerator({
    onError: setError,
    onUse: (generated: string) => {
      setEditForm((current) => ({ ...current, password: generated }));
      // Shown: we have just made it, hiding it no longer makes sense and would
      // leave doubt about what is going to be saved.
      setEditShowPassword(true);
    },
    onCopied: scheduleClipboardClear,
  });

  // Editing: the item in progress, the form's values, the original password
  // (for the history), and the field's visibility.
  const [editing, setEditing] = useState<CipherOverview | null>(null);
  /** True while a **new** item is being composed: the type is still open. */
  const [creating, setCreating] = useState(false);
  const [editForm, setEditForm] = useState<EditForm>(EMPTY_EDIT);
  const [editOriginalPassword, setEditOriginalPassword] = useState('');
  const [editShowPassword, setEditShowPassword] = useState(false);
  const [editPasskeys, setEditPasskeys] = useState<readonly PasskeyView[]>([]);

  // Second factor: the providers the server announced, the choice and the code.
  const [twoFaProviders, setTwoFaProviders] = useState<readonly string[] | null>(null);
  const [twoFaChoice, setTwoFaChoice] = useState('');
  const [twoFaCode, setTwoFaCode] = useState('');
  const [rememberDevice, setRememberDevice] = useState(true);

  /**
   * Keeps the toolbar icon matched to the theme for as long as the popup is
   * open — which is also how a system theme change mid-session gets picked up.
   */
  useEffect(followPageColorScheme, []);

  useEffect(() => {
    void (async () => {
      const loaded = await loadSettings();
      setSettings(loaded);
      // Held writes survive the browser closing, so the count is read at every
      // opening, not only after a failure.
      void refreshQueueCounts();
      setServerUrl(loaded.serverUrl);
      setEmail(loaded.email);
      await restoreSession(loaded);
    })();
  }, []);

  /**
   * Activity heartbeat while the popup is open on an unlocked vault. Without it,
   * a popup left open long enough to compose a password could be locked out from
   * under the user by the service worker: reading the screen is activity, it
   * simply emits no browser event.
   */
  useEffect(() => {
    if (vault === null) {
      return;
    }
    void recordActivity();
    const timer = setInterval(() => void recordActivity(), ACTIVITY_PING_MS);
    return () => clearInterval(timer);
  }, [vault]);

  function makeClient(s: AppSettings, url: string, deviceId: string): ApiClient {
    return new ApiClient({
      serverUrl: url,
      deviceIdentifier: deviceId,
      deviceName: s.deviceName,
      timeoutMs: s.timeoutSeconds * 1000,
    });
  }

  /**
   * Restores a session still alive in `chrome.storage.session`.
   *
   * In two stages, so the sign-in screen is never shown needlessly:
   *
   * 1. **Immediate display** from the last cached sync — no network, the list
   *    appears within tens of milliseconds.
   * 2. **Network refresh** in the background, which brings the list up to date.
   *
   * A network failure keeps the cache on screen — being offline does not lock
   * the vault. Only an authentication refusal (a revoked token) locks.
   */
  async function restoreSession(s: AppSettings): Promise<void> {
    const stored = await loadStoredSession();
    // The key is fetched apart, and only here: this is the one place in the
    // extension that goes on to decrypt (`docs/STORAGE.md`).
    const userKeyB64 = stored === null ? null : await loadVaultKey();
    if (stored === null || userKeyB64 === null) {
      setInitializing(false);
      return;
    }

    setServerUrl(stored.serverUrl);
    setEmail(stored.email);
    const userKey = SymmetricCryptoKey.fromBase64(userKeyB64);
    void startAutoLockWatch(s.autoLockMinutes);

    // The cache first: it displays without a network, hence immediately. The
    // refresh that follows will correct whatever changed.
    const displayed = await showCachedVault(stored, userKey);

    try {
      await refreshFromServer(s, stored, userKey, displayed);
    } catch (err) {
      await onRestoreFailure(err, userKey, displayed);
    } finally {
      setBusy(null);
      setInitializing(false);
    }
  }

  /**
   * Displays the last synced state, if there is a usable one.
   *
   * @returns True if the vault is on screen — which changes what follows: with
   *   nothing displayed a network failure must be said; with the vault up, it
   *   can stay quiet.
   */
  async function showCachedVault(
    stored: StoredSession,
    userKey: SymmetricCryptoKey,
  ): Promise<boolean> {
    if (stored.cachedSync === null) {
      return false;
    }
    // Before decrypting: the types are in clear, so the filter can be drawn
    // while the names are still being worked through.
    setRawCounts(countTypes(stored.cachedSync.ciphers ?? []));
    try {
      await showVault(stored.cachedSync, userKey, false);
      setInitializing(false);
      return true;
    } catch {
      // Cache unusable: the network path will settle it.
      return false;
    }
  }

  /** Renews the tokens if needed, resyncs, and redisplays. */
  async function refreshFromServer(
    s: AppSettings,
    stored: StoredSession,
    userKey: SymmetricCryptoKey,
    displayed: boolean,
  ): Promise<void> {
    const client = makeClient(s, stored.serverUrl, await getDeviceId());

    let accessToken = stored.accessToken;
    let refreshToken = stored.refreshToken;
    let expiresAt = stored.expiresAt;
    if (Date.now() > expiresAt - 60_000) {
      if (refreshToken === null) {
        throw new ApiError(t('errorSessionNoRefresh'), 401, '');
      }
      const renewed = await client.refreshToken(refreshToken);
      accessToken = renewed.accessToken;
      refreshToken = renewed.refreshToken ?? refreshToken;
      expiresAt = renewed.expiresAt;
    }

    if (!displayed) {
      setBusy(t('statusOpeningVault'));
    }
    let sync = await client.sync(accessToken);

    // The server is answering again: send what was held while it was not.
    // Decided against this very sync, so a conflict is read off the server's
    // own current state rather than guessed.
    const replayed = await replayQueue(client, accessToken, sync);
    if (replayed.sent > 0) {
      // A second sync, and only when something actually went out: the list must
      // show what was just written, not the state from before it.
      sync = await client.sync(accessToken);
    }
    await refreshQueueCounts(replayed.held);

    await saveStoredSession({
      ...stored,
      accessToken,
      refreshToken,
      expiresAt,
      cachedSync: sync,
    });
    await showVault(sync, userKey, !displayed);
    if (replayed.sent > 0) {
      setError(t('queueSent', String(replayed.sent)));
    }
  }

  /**
   * Decides what to do with a restore failure. Three cases, three conducts:
   *
   * - token refused (400/401): the session is dead server-side, so lock outright
   *   — keeping it would give a vault that looks open and can do nothing;
   * - network failure with nothing on screen: it must be said, and the session
   *   is kept for a later attempt;
   * - network failure with the cache displayed: stay quiet. The user has their
   *   vault.
   */
  async function onRestoreFailure(
    err: unknown,
    userKey: SymmetricCryptoKey,
    displayed: boolean,
  ): Promise<void> {
    if (err instanceof ApiError && (err.status === 400 || err.status === 401)) {
      await lockVault();
      userKey.destroy();
      resetVaultState();
      return;
    }
    if (!displayed) {
      setError(t('errorServerUnreachable'));
    }
  }

  /** Decrypts a sync response and displays the vault. */
  async function showVault(
    sync: SyncResponse,
    userKey: SymmetricCryptoKey,
    announce: boolean,
  ): Promise<void> {
    const ciphers = sync.ciphers ?? [];

    // Failures are logged to THE POPUP's console (right-click the popup →
    // Inspect) AND summarised on screen — the page's console never sees them.
    const errors: unknown[] = [];
    const onDecryptError = (error: unknown): void => {
      errors.push(error);
      console.warn('[zwarden] unreadable field:', error);
    };

    if (announce) {
      setBusy(t('statusDecrypting', String(ciphers.length)));
    }
    const keys = await buildVaultKeys(sync.profile, userKey, onDecryptError);

    // Counted from the raw items: `type` is not encrypted, so the filter is
    // right from the first frame and never has to be revised.
    setRawCounts(countTypes(ciphers));

    const raw = new Map<string, CipherResponse>();
    for (const cipher of ciphers) {
      raw.set(cipher.id, cipher);
    }

    // The ordering is frozen at opening, never reapplied while the popup is
    // open: an item floating up under the cursor at the moment it is copied
    // would make the next click land on the wrong row.
    //
    // Applied to the raw items, before decryption — the use log is keyed by
    // identifier, and an identifier is in clear. That is the whole trick: it is
    // what makes the first slice the rows actually on screen, rather than
    // whichever twenty the server happened to list first.
    const ordered = sortCiphersByLastUsed(ciphers, await loadLastUsed());
    const head = ordered.slice(0, FIRST_SLICE);
    const tail = ordered.slice(FIRST_SLICE);

    // Items whose revision date has not moved since the previous display are
    // reused as-is: after a write, only the written item is re-decrypted rather
    // than the whole vault.
    const reuse = vault === null ? undefined : reuseByRevision(vault.items, vault.raw);
    const [headItems, labels] = await Promise.all([
      decryptCipherList(head, keys, onDecryptError, undefined, reuse),
      decryptLabels(sync, keys, onDecryptError),
    ]);

    const base = { userKey, keys, raw, labels, errors };
    if (tail.length > 0) {
      // On screen at once. The rest follows in the same turn of the loop, but
      // the rows the user is about to read are already there.
      setVault({ ...base, items: headItems, pending: tail.length });
    }

    const items = [
      ...headItems,
      ...(tail.length === 0
        ? []
        : await decryptCipherList(tail, keys, onDecryptError, undefined, reuse)),
    ];
    setVault({ ...base, items, pending: 0 });

    // Both of these need the whole vault: a save candidate missed because its
    // item was still encrypted would offer to create a duplicate.
    await evaluatePending(items, raw, keys, onDecryptError);
    await pickUpAssertion({ userKey, keys, raw, labels, errors, items, pending: 0 });

    // Active tab: strict origin for "Fill", domain for the pre-filled filter —
    // without overwriting a search already typed, and only if it matches
    // something, since an empty list would be baffling.
    const tab = await activeWebTab();
    setTabOrigin(tab === null ? null : tab.url.origin);
    const host = tab?.url.hostname.replace(/^www\./, '');
    if (host !== undefined && items.some((item) => matchesNeedle(item, host, labels))) {
      setFilter((current) => (current === '' ? host : current));
    }
  }

  /**
   * A full unlock attempt. Without `twoFactor`, it first replays any remember
   * token kept for this device.
   */
  async function attemptUnlock(twoFactor?: TwoFactorSubmission): Promise<void> {
    setError(null);
    setBusy(t('statusDeriving'));

    // Persisted from the attempt, not only on success: a password or
    // second-factor failure must not force the server and the email to be typed
    // again next time. Never the password.
    await saveSettings({ serverUrl, email });

    const submission = twoFactor ?? (await rememberedSubmission());

    try {
      const client = makeClient(settings, serverUrl, await getDeviceId());
      const result = await unlock(client, email, password, submission);
      await onUnlocked(client, result);
    } catch (err) {
      await onUnlockFailure(err, twoFactor, submission);
    } finally {
      setBusy(null);
    }
  }

  /** The 2FA remember token kept for this device, if there is one. */
  async function rememberedSubmission(): Promise<TwoFactorSubmission | undefined> {
    const remembered = await loadRememberToken(serverUrl, email);
    return remembered === null
      ? undefined
      : { provider: TwoFactorProvider.Remember, token: remembered };
  }

  /** Files the opened session away and displays the vault. */
  async function onUnlocked(client: ApiClient, result: UnlockResult): Promise<void> {
    setPassword('');
    setShowPassword(false);
    setTwoFaProviders(null);
    setTwoFaCode('');

    if (result.twoFactorRememberToken !== undefined) {
      await saveRememberToken(serverUrl, email, result.twoFactorRememberToken);
    }

    setBusy(t('statusSyncing'));
    const sync = await client.sync(result.session.accessToken);

    // The session survives the popup closing, until the browser closes, the
    // inactivity deadline passes, or a manual lock. The sync is cached for an
    // immediate display the next time it opens.
    // Sealed, not stored in clear. If it cannot be sealed nothing is kept and
    // the next opening asks for the master password again — the honest failure.
    await saveVaultKey(result.userKey.toBase64());
    await saveStoredSession({
      accessToken: result.session.accessToken,
      refreshToken: result.session.refreshToken ?? null,
      expiresAt: result.session.expiresAt,
      serverUrl,
      email,
      cachedSync: sync,
      // Kept to verify the master password without a network when an item
      // demands it again.
      localPasswordHash: result.localPasswordHash,
      kdfConfig: result.kdfConfig,
    });
    await startAutoLockWatch(settings.autoLockMinutes);

    await showVault(sync, result.userKey, true);
  }

  /**
   * Routes an unlock failure.
   *
   * A second-factor demand is not an error: it is a step, and showing it as a
   * failure would suggest a wrong password. Everything else goes through
   * `messageFor`, which tells the cases apart on the `code` field.
   *
   * @param twoFactor The second factor the user supplied, if there was one.
   * @param submission What was actually sent — possibly a remember token taken
   *   from storage.
   */
  async function onUnlockFailure(
    err: unknown,
    twoFactor: TwoFactorSubmission | undefined,
    submission: TwoFactorSubmission | undefined,
  ): Promise<void> {
    if (!(err instanceof TwoFactorRequiredError)) {
      setError(messageFor(err));
      return;
    }
    // A refused remember token is an expired one: forget it and fall back to
    // the entry screen.
    if (submission?.provider === TwoFactorProvider.Remember) {
      await clearRememberToken(serverUrl, email);
    }
    const available = err.providers.filter((p) => p in providerLabels());
    setTwoFaProviders(err.providers);
    setTwoFaChoice(available[0] ?? '');
    if (twoFactor !== undefined) {
      setError(t('twoFaRefused'));
    }
  }

  /**
   * Purges everything the unlocked state left in the popup.
   *
   * `lockVault()` carries the storage-side list; this one carries the
   * memory-side list, and the two must be called together — otherwise the rule
   * "to lock is to purge everything" (`docs/EXTENSION.md` §2) only holds for the
   * half somebody remembered to write.
   *
   * It includes decrypted secrets one does not expect at first glance: `otp`
   * carries the TOTP secret **and** a timer recomputing a code every second, the
   * generator its output, and the edit form the open item's password. None of
   * them is visible after locking — they survived in memory all the same.
   */
  function resetVaultState(): void {
    clearRevealTimer();
    setVault(null);
    setFilter('');
    setRevealed(null);
    setProposal(null);
    setOtp(null);
    generator.close();
    setEditing(null);
    setEditForm(EMPTY_EDIT);
    setEditOriginalPassword('');
    setEditShowPassword(false);
    setEditPasskeys([]);
    setHealth(null);
    // The export form holds the master password and a passphrase in its own
    // state: locking must take those with it, like every other secret on
    // screen (`docs/EXTENSION.md` §2).
    setExporting(false);
    setExportMaster('');
    setExportPassphrase('');
    setExportConfirmation('');
    setAssertion(null);
    setAssertionPassword('');
    reprompt.cancel();
  }

  function onLock(): void {
    if (vault !== null) {
      // The whole keyring, not just the vault key: organisation keys decrypt
      // the shared items.
      destroyVaultKeys(vault.keys);
    }
    void lockVault();
    resetVaultState();
  }

  async function detailsOf(item: CipherOverview): Promise<CipherDetails | null> {
    if (vault === null) {
      return null;
    }
    const cipher = vault.raw.get(item.id);
    if (cipher === undefined) {
      return null;
    }
    return decryptCipherDetails(cipher, vault.keys, (err) => {
      setError(messageFor(err));
    });
  }

  /**
   * Decides whether there is anything to offer, once the vault is on screen.
   *
   * The service worker captures without knowing what the vault holds — it has no
   * key. So it is here, and only here, that the question is settled:
   *
   * - username already known on this origin, **same** password → nothing to
   *   offer, the capture is dropped with nothing shown. This is the most
   *   frequent case, an ordinary sign-in: not keeping quiet about it would make
   *   the badge meaningless by lighting up for nothing;
   * - username known, different password → update;
   * - otherwise → a new item.
   */
  async function evaluatePending(
    items: readonly CipherOverview[],
    raw: Map<string, CipherResponse>,
    keys: CipherKeys,
    onDecryptError: (error: unknown) => void,
  ): Promise<void> {
    const capture = await loadPendingSave();
    if (capture === null) {
      setProposal(null);
      return;
    }

    const existing = findSaveCandidate(items, capture.origin, capture.username, matchesOrigin);

    // The matched item's password is decrypted here — the popup is what holds
    // the keys — and then the rule is applied by `decideProposal`, pure and
    // tested. An item missing from `raw` yields `null`, which the rule treats as
    // "unreadable": it offers rather than stay quiet.
    let existingPassword: string | null = null;
    if (existing !== null) {
      const cipher = raw.get(existing.id);
      existingPassword =
        cipher === undefined
          ? null
          : (await decryptCipherDetails(cipher, keys, onDecryptError)).password;
    }

    const issue = decideProposal(existing, capture.password, existingPassword);
    if (issue.kind === 'none') {
      await dismissProposal();
      return;
    }
    setProposal({ capture, existing: issue.kind === 'update' ? issue.item : null });
  }

  /** Forgets the current proposal: capture purged, badge switched off. */
  async function dismissProposal(): Promise<void> {
    setProposal(null);
    await clearPendingSave();
    await setSaveBadge(false);
  }

  /** "Never for this site" — the host joins the exclusion list. */
  async function onNeverForHost(): Promise<void> {
    if (proposal !== null) {
      await addNeverSaveHost(proposal.capture.host);
    }
    await dismissProposal();
  }

  /**
   * Saves the capture: creating an item, or updating the matched item's
   * password.
   *
   * The update takes the existing item as it stands and changes only the
   * password — name, folder, notes and custom fields survive — and records the
   * old one in the history: a near-automatic save must never lose what was there
   * before.
   */
  async function onSaveProposal(): Promise<void> {
    if (vault === null || proposal === null) {
      return;
    }
    const open = vault;
    const { capture, existing } = proposal;

    setError(null);
    setBusy(t('statusEncrypting'));
    try {
      // Encrypted before anything is attempted over the network: a body that
      // exists can be held, and one that does not cannot.
      const payload =
        existing === null
          ? await createFromCapture(open, capture)
          : await updateFromCapture(open, capture, existing);

      setBusy(t('statusSaving'));
      try {
        const auth = await authorize();
        if (existing === null) {
          await auth.client.createCipher(auth.accessToken, payload);
        } else {
          await auth.client.updateCipher(auth.accessToken, existing.id, payload);
        }
        await dismissProposal();
        await refreshAfterWrite(auth, open.userKey);
      } catch (err) {
        if (!isUnreachable(err)) {
          throw err;
        }
        await dismissProposal();
        await holdWrite(
          existing === null ? 'create' : 'update',
          existing?.id ?? null,
          payload,
          existing === null ? null : revisionOf(open, existing.id),
          existing?.name ?? capture.host,
        );
      }
    } catch (err) {
      setError(messageFor(err));
      setBusy(null);
    }
  }

  /** The server's revision for an item, as last synced. */
  function revisionOf(open: OpenVault, cipherId: string): string | null {
    const cipher = open.raw.get(cipherId);
    return cipher === undefined ? null : (readField<string>(cipher, 'revisionDate') ?? null);
  }

  /**
   * Creates an item from a capture.
   *
   * Deliberately poor: no folder, no organisation, no custom fields. An item
   * born of an observed entry carries what was observed and nothing more — the
   * user fills in the rest if they wish.
   */
  async function createFromCapture(
    open: OpenVault,
    capture: PendingSave,
  ): Promise<Record<string, unknown>> {
    const payload = await buildCipherCreatePayload(
      {
        name: capture.host,
        username: capture.username,
        password: capture.password,
        totp: '',
        notes: '',
        uris: [capture.origin],
      },
      open.userKey,
    );
    return payload;
  }

  /**
   * Updates a matched item's password, and that alone.
   *
   * Name, folder, notes, TOTP and custom fields are read back from the existing
   * item and rewritten as-is: an update replaces the whole item server-side, so
   * any field not sent would be lost. A near-automatic save must never make what
   * was there disappear.
   */
  async function updateFromCapture(
    open: OpenVault,
    capture: PendingSave,
    existing: CipherOverview,
  ): Promise<Record<string, unknown>> {
    const cipher = open.raw.get(existing.id);
    if (cipher === undefined) {
      throw new Error(t('errorItemNotFound'));
    }
    // An `onError` that rethrows: on a write, an unreadable field must stop the
    // operation, not let it overwrite what it could not read.
    const details = await decryptCipherDetails(cipher, open.keys, (err) => {
      throw err;
    });
    const payload = await buildCipherUpdatePayload(
      cipher,
      {
        name: existing.name ?? capture.host,
        username: details.username ?? capture.username,
        password: capture.password,
        totp: details.totp ?? '',
        notes: details.notes ?? '',
        uris: existing.uris.length > 0 ? existing.uris : [capture.origin],
      },
      open.keys,
      true,
    );
    return payload;
  }

  /**
   * Shows — and copies — an item's one-time code.
   *
   * The TOTP secret is decrypted on demand, like the password: the partial
   * decryption rule (`docs/EXTENSION.md` §3) applies to it too. A second click
   * closes it again.
   *
   * The copy is immediate because a six-digit code is never looked at for
   * pleasure: one wants it in the clipboard, and it will have expired before one
   * finishes copying it by hand.
   */
  function onToggleOtp(item: CipherOverview): void {
    // Closing exposes nothing: the guard covers opening only.
    if (otp?.id === item.id) {
      setOtp(null);
      return;
    }
    reprompt.guarded(item, () => doShowOtp(item));
  }

  async function doShowOtp(item: CipherOverview): Promise<void> {
    const secret = (await detailsOf(item))?.totp ?? null;
    if (secret === null) {
      return;
    }
    try {
      const config = parseTotp(secret);
      // Computed **once**: the same value is displayed and copied. Two separate
      // computations, a few milliseconds apart, can straddle a window boundary
      // and land in different windows — the user then reads one code and pastes
      // another.
      const code = await generateTotp(config);
      setOtp({ id: item.id, config, code });
      void noteUsage(item);
      // The copy is immediate because a six-digit code is never looked at for
      // pleasure: one wants it in the clipboard, and it will have expired before
      // one finishes copying it by hand.
      await copyOtp(code);
    } catch (err) {
      setError(messageFor(err));
    }
  }

  /**
   * Schedules the clipboard wipe after the configured delay.
   *
   * Factored out because the three copies — password, one-time code, generated
   * password — must all follow the same rule, and duplicating the condition was
   * already the reason the one-time code escaped it.
   */
  function scheduleClipboardClear(): void {
    if (settings.clipboardClearSeconds <= 0) {
      return;
    }
    // Two wipes, deliberately. The local timer honours the exact delay while the
    // popup lives; the alarm survives its closing but is raised to thirty
    // seconds minimum by Chrome. The first to land wins, and neither needs the
    // other.
    setTimeout(() => {
      void navigator.clipboard.writeText('');
    }, settings.clipboardClearSeconds * 1000);
    void scheduleClipboardWipe(settings.clipboardClearSeconds);
  }

  async function copyOtp(code: string): Promise<void> {
    await navigator.clipboard.writeText(code);
    setCopiedOtp(true);
    setTimeout(() => setCopiedOtp(false), 1500);
    scheduleClipboardClear();
  }

  /**
   * Records that an item was used: it will float to the top next time.
   *
   * Called on every action that genuinely takes a secret out of the vault —
   * copy, fill, reveal. Opening the editor is not one: one goes there to fix a
   * typo as often as to use the item.
   */
  async function noteUsage(item: CipherOverview): Promise<void> {
    await markUsed(item.id);
  }

  function onCopyPassword(item: CipherOverview): void {
    reprompt.guarded(item, () => doCopyPassword(item));
  }

  /**
   * What the row's copy button takes, which is the value one opened the vault
   * for: a password, a card number, a full name, a note.
   *
   * A card number is reduced to its digits — payment forms reject the spaces,
   * and a value that has to be cleaned up after pasting is a value one ends up
   * retyping by hand.
   */
  function primaryValueOf(item: CipherOverview, details: CipherDetails): string | null {
    if (item.type === 3) {
      return details.card === null ? null : digitsOf(details.card.number ?? '');
    }
    if (item.type === 4) {
      return details.identity === null ? null : fullName(details.identity);
    }
    if (item.type === 2) {
      return details.notes;
    }
    return details.password;
  }

  async function doCopyPassword(item: CipherOverview): Promise<void> {
    const details = await detailsOf(item);
    const secret = details === null ? null : primaryValueOf(item, details);
    if (secret !== null && secret !== '') {
      await navigator.clipboard.writeText(secret);
      void noteUsage(item);
      setCopiedId(item.id);
      setTimeout(() => setCopiedId(null), 1500);
      scheduleClipboardClear();
    }
  }

  /**
   * Copies one field of an open detail panel.
   *
   * No `reprompt` guard: the panel is only open because the guard already let
   * the user through, and asking again for a field of something already on
   * screen would ask for nothing.
   */
  async function onCopyField(label: string, value: string): Promise<void> {
    if (value === '') {
      return;
    }
    await navigator.clipboard.writeText(value);
    setCopiedField(label);
    setTimeout(() => setCopiedField(null), 1500);
    scheduleClipboardClear();
  }

  async function onCopyUsername(item: CipherOverview): Promise<void> {
    if (item.username !== null) {
      await navigator.clipboard.writeText(item.username);
      void noteUsage(item);
      setCopiedUserId(item.id);
      setTimeout(() => setCopiedUserId(null), 1500);
    }
  }

  /** Auto-hide timer for the revealed password. */
  const revealTimer = useRef<number | undefined>(undefined);

  function clearRevealTimer(): void {
    if (revealTimer.current !== undefined) {
      clearTimeout(revealTimer.current);
      revealTimer.current = undefined;
    }
  }

  function onToggleReveal(item: CipherOverview): void {
    clearRevealTimer();
    // Hiding exposes nothing: only revealing is guarded.
    if (revealed?.id === item.id) {
      setRevealed(null);
      return;
    }
    reprompt.guarded(item, () => doReveal(item));
  }

  /**
   * What the eye shows for this type, or `null` if there is nothing to show.
   *
   * One union for the four types, so that the guard, the auto-hide timer and the
   * clipboard clearing cover them all without being written four times.
   */
  function revealedContentFor(item: CipherOverview, details: CipherDetails): RevealedContent | null {
    if (item.type === 3) {
      return details.card === null ? null : { kind: 'card', card: details.card };
    }
    if (item.type === 4) {
      return details.identity === null ? null : { kind: 'identity', identity: details.identity };
    }
    if (item.type === 2) {
      return details.notes === null ? null : { kind: 'note', notes: details.notes };
    }
    return details.password === null ? null : { kind: 'password', password: details.password };
  }

  async function doReveal(item: CipherOverview): Promise<void> {
    const details = await detailsOf(item);
    const content = details === null ? null : revealedContentFor(item, details);
    if (content !== null) {
      void noteUsage(item);
      setRevealed({ id: item.id, content });
      // Auto-hide: a secret on display must not stay there through
      // forgetfulness — a card panel no less than a password.
      revealTimer.current = window.setTimeout(() => setRevealed(null), REVEAL_HIDE_MS);
    }
  }

  /**
   * Fills the active tab's form with the item's credentials.
   *
   * On an explicit gesture only, and only if the button was visible — that is,
   * if the item's origin matches the tab's (`docs/EXTENSION.md`, autofill
   * rules). Rechecked here: the tab may have changed since the render.
   */
  async function onFill(item: CipherOverview): Promise<void> {
    const tab = await activeWebTab();
    if (tab === null || !matchesOrigin(item.uris, tab.url.origin)) {
      setError(t('errorTabMismatch'));
      return;
    }
    // Origin first, guard second: asking for a password only to then refuse the
    // fill would be the worst of the two orders.
    reprompt.guarded(item, () => doFill(item, tab));
  }

  async function doFill(item: CipherOverview, tab: { tabId: number }): Promise<void> {
    const details = await detailsOf(item);
    if (details === null || (details.username === null && details.password === null)) {
      return;
    }

    await chrome.scripting.executeScript({
      target: { tabId: tab.tabId },
      func: fillCredentials,
      args: [details.username ?? '', details.password ?? ''],
    });
    // Awaited, not fired and forgotten: `window.close()` kills the popup before
    // the write leaves, and the most frequent use would be the only one never
    // counted.
    await noteUsage(item);
    window.close();
  }

  /** Opens the edit screen, pre-filled with the decrypted values. */
  function onEdit(item: CipherOverview): void {
    // The form shows the password in the clear in its field: that is a secret
    // leaving the vault like any other.
    reprompt.guarded(item, () => doEdit(item));
  }

  async function doEdit(item: CipherOverview): Promise<void> {
    const details = await detailsOf(item);
    if (details === null) {
      return;
    }
    setEditForm({
      type: item.type,
      name: item.name ?? '',
      username: details.username ?? '',
      password: details.password ?? '',
      totp: details.totp ?? '',
      notes: details.notes ?? '',
      uris: item.uris.join('\n'),
      card: toEditValues(details.card, EMPTY_CARD_EDIT),
      identity: toEditValues(details.identity, EMPTY_IDENTITY_EDIT),
    });
    setEditOriginalPassword(details.password ?? '');
    setEditPasskeys(details.passkeys);
    setEditShowPassword(false);
    setEditing(item);
    setError(null);
  }

  /**
   * A writable session: API client and tokens refreshed if needed.
   *
   * Every write (an edit, saving a capture) starts here. The access token
   * expires in about an hour; renewing it at write time avoids a 401 on a
   * gesture the user believes has succeeded.
   *
   * @throws {Error} No session — the vault was locked in the meantime.
   */
  async function authorize(): Promise<AuthorizedSession> {
    const stored = await loadStoredSession();
    if (stored === null) {
      throw new Error(t('errorSessionExpired'));
    }
    const client = makeClient(settings, stored.serverUrl, await getDeviceId());

    let accessToken = stored.accessToken;
    let refreshToken = stored.refreshToken;
    let expiresAt = stored.expiresAt;
    if (Date.now() > expiresAt - 60_000 && refreshToken !== null) {
      const renewed = await client.refreshToken(refreshToken);
      accessToken = renewed.accessToken;
      refreshToken = renewed.refreshToken ?? refreshToken;
      expiresAt = renewed.expiresAt;
      // Persisted **before** the write they authorise. A server that rotates
      // refresh tokens has already invalidated the old one: if the next call
      // fails and nothing was saved, the session is dead and everything must be
      // unlocked again over a simple network failure.
      await saveStoredSession({ ...stored, accessToken, refreshToken, expiresAt });
    }
    return { client, stored, accessToken, refreshToken, expiresAt };
  }

  /**
   * Resyncs after a write, updates the cache and redisplays the list. Without
   * it, the popup would still be showing the state from before the write.
   */
  async function refreshAfterWrite(auth: AuthorizedSession, userKey: SymmetricCryptoKey): Promise<void> {
    setBusy(t('statusSyncing'));
    const sync = await auth.client.sync(auth.accessToken);
    // The key is untouched by a resync: it is not rewritten, so it is not
    // read either.
    await saveStoredSession({
      accessToken: auth.accessToken,
      refreshToken: auth.refreshToken,
      expiresAt: auth.expiresAt,
      serverUrl: auth.stored.serverUrl,
      email: auth.stored.email,
      cachedSync: sync,
      localPasswordHash: auth.stored.localPasswordHash,
      kdfConfig: auth.stored.kdfConfig,
    });
    await showVault(sync, userKey, false);
  }

  /**
   * Holds a write the server never received.
   *
   * Only called for a failure that means "no answer" — `isUnreachable` keeps a
   * refusal out of the queue, since retrying a refusal never succeeds and would
   * hide a real error behind a reassuring "saved locally".
   *
   * What is stored is the **already-encrypted** body. The cleartext edit never
   * reaches disk (`docs/STORAGE.md` §4).
   */
  async function holdWrite(
    kind: 'create' | 'update',
    cipherId: string | null,
    payload: Record<string, unknown>,
    baseRevision: string | null,
    label: string,
  ): Promise<void> {
    await enqueueWrite({
      id: crypto.randomUUID(),
      kind,
      cipherId,
      payload,
      baseRevision,
      queuedAt: Date.now(),
      label,
    });
    await refreshQueueCounts();
    setBusy(null);
    setError(t('queueSavedOffline'));
  }

  /** Reflects the queue's size on screen. */
  async function refreshQueueCounts(held = 0): Promise<void> {
    const queue = await loadWriteQueue();
    setQueued({ pending: queue.length, held });
  }

  /**
   * Sends what was held, once the server answers again.
   *
   * Decided against the sync that has just come back, so a conflict is detected
   * from the server's own current state rather than from a guess.
   *
   * @returns How many were sent, and how many were held back.
   */
  async function replayQueue(
    client: ApiClient,
    accessToken: string,
    sync: SyncResponse,
  ): Promise<{ sent: number; held: number }> {
    const queue = await loadWriteQueue();
    if (queue.length === 0) {
      return { sent: 0, held: 0 };
    }
    const byId = new Map((sync.ciphers ?? []).map((c) => [c.id, c]));
    const done: string[] = [];
    let held = 0;

    for (const entry of queue) {
      const outcome = decideReplay(entry, byId.get(entry.cipherId ?? ''));
      if (outcome.kind !== 'replay') {
        // Nothing is overwritten and nothing is resurrected. The user is told,
        // and decides.
        held += 1;
        continue;
      }
      try {
        if (entry.kind === 'create') {
          await client.createCipher(accessToken, entry.payload);
        } else {
          await client.updateCipher(accessToken, entry.cipherId!, entry.payload);
        }
        done.push(entry.id);
      } catch (err) {
        if (isUnreachable(err)) {
          // Still offline: stop, keep the rest, try again next time.
          break;
        }
        // Refused. Retrying would refuse again for ever; it is dropped and
        // counted as held so the user hears about it.
        done.push(entry.id);
        held += 1;
      }
    }

    await removeWrites(done);
    return { sent: done.length - held, held };
  }

  /** Abandons the held writes the user has given up on. */
  async function onDiscardQueue(): Promise<void> {
    const n = await clearWriteQueue();
    setQueued({ pending: 0, held: 0 });
    setError(n === 0 ? null : t('queueDiscarded', String(n)));
  }

  /**
   * Examines the vault and opens the report.
   *
   * Every password has to be decrypted for this, which is why it happens on an
   * explicit gesture and not on opening: it is exactly the work the list was
   * just taught to avoid. Items guarded by `reprompt` are handed over
   * untouched — `buildHealthReport` skips them, and says how many.
   */
  async function onCheckHealth(): Promise<void> {
    if (vault === null) {
      return;
    }
    setError(null);
    setBusy(t('healthChecking'));
    try {
      const open = vault;
      const inputs = await Promise.all(
        open.items.map(async (item) => {
          const cipher = open.raw.get(item.id);
          // A guarded item is never decrypted, not even to be counted.
          const details =
            item.reprompt || cipher === undefined
              ? null
              : await decryptCipherDetails(cipher, open.keys, () => undefined);
          const login = cipher === undefined ? undefined : readField<unknown>(cipher, 'login');
          return {
            id: item.id,
            name: item.name,
            username: item.username,
            uris: item.uris,
            type: item.type,
            reprompt: item.reprompt,
            password: details?.password ?? null,
            // Neither is encrypted, so reading them costs nothing and asks
            // nothing of the guard.
            //
            // The fallback is the point: Bitwarden sets `passwordRevisionDate`
            // only when a password is **changed after creation**, so an item
            // made years ago and never edited has none at all. Skipping those
            // would hide exactly the oldest passwords, which is the opposite of
            // what this list is for. If the password was never revised, it is
            // as old as the item.
            passwordUpdatedAt:
              readField<string>(login, 'passwordRevisionDate') ??
              readField<string>(cipher, 'creationDate') ??
              null,
            card: details?.card ?? null,
          };
        }),
      );
      // The corpus is consulted only if the user asked for it to be, and only
      // as part of a report they explicitly requested. Never on opening, never
      // in the background.
      let breached: ReadonlyMap<string, number> | undefined;
      if (settings.breachCheckEnabled) {
        const passwords = inputs
          .map((input) => input.password)
          .filter((password): password is string => password !== null && password !== '');
        setBusy(t('healthBreachChecking', String(new Set(passwords).size)));
        breached = await checkPasswords(passwords);
      }
      setHealth(buildHealthReport(inputs, new Date(), breached === undefined ? {} : { breached }));
    } catch (err) {
      setError(messageFor(err));
    } finally {
      setBusy(null);
    }
  }

  /**
   * Picks up a page waiting on a passkey, if there is one.
   *
   * Runs once the vault is open, because answering needs keys — a locked vault
   * simply leaves the page waiting until the user unlocks, which is the same
   * position they would be in with any other authenticator.
   *
   * The request is validated **before anything is shown**: whether this page
   * may ask for this relying party is not a question to put to the user, who
   * would be looking at the name of a site they trust and clicking yes.
   */
  async function pickUpAssertion(open: OpenVault): Promise<void> {
    // Read from storage, not from `settings`. This runs inside the very turn
    // that loads the settings, before the state update has been applied, so
    // the closure would still hold the defaults — and `passkeySignIn` defaults
    // to false, which silently disabled the whole feature.
    const { passkeySignIn } = await loadSettings();
    if (!passkeySignIn) {
      return;
    }

    // Computed on every opening, before anything else, and left where the
    // service worker can read it. That worker has no keys and cannot work out
    // whether this vault can answer for a site; without this list it must hold
    // every ceremony open until somebody opens this window to find out there
    // was nothing to offer — which is most ceremonies, since most sign-ins use
    // a hardware key, and it makes Zwarden a ninety-second delay on all of
    // them.
    const views = await passkeyViews(open);
    await savePasskeyParties(views.map((view) => view.rpId));

    const pending = await loadPendingAssertion();
    if (pending === null) {
      return;
    }
    if (pending.ceremony === 'create') {
      try {
        const ask = validateCreationAsk(
          pending.options,
          pending.origin,
          views.map((view) => view.credentialId),
        );
        setAssertion({
          kind: 'create',
          id: pending.id,
          ask,
          // Where to put it: any item, or a new one — the empty value.
          choices: [
            { itemId: '', credentialId: '', label: t('registrationNewItem') },
            ...open.items.map((item) => ({
              itemId: item.id,
              credentialId: item.id,
              label: item.name ?? item.id,
            })),
          ],
        });
        setAssertionChoice('');
        setAssertionPassword('');
      } catch (error) {
        await answerAssertion(pending.id, null);
        setError(error instanceof WebAuthnRefusal ? t('assertionRefused') : messageFor(error));
      }
      return;
    }

    let ask: AssertionAsk;
    try {
      ask = validateAssertionAsk(pending.options, pending.origin);
    } catch (error) {
      // Refused outright, and the page is told nothing beyond "we have
      // nothing" — it falls back to the browser.
      await answerAssertion(pending.id, null);
      setError(error instanceof WebAuthnRefusal ? t('assertionRefused') : messageFor(error));
      return;
    }

    const choices = selectCredentials(views, ask.rpId, ask.allowCredentials);
    if (choices.length === 0) {
      // Nothing to offer. Answered **at once** so the page falls back to the
      // browser now rather than after the ninety-second timeout: a user staring
      // at a stalled sign-in has no way to tell a slow extension from a broken
      // one, and it was the extension holding the ceremony open for nothing.
      await answerAssertion(pending.id, null);
      return;
    }
    setAssertion({ kind: 'get', id: pending.id, ask, choices });
    setAssertionChoice(choices[0]?.credentialId ?? null);
    setAssertionPassword('');
  }

  /**
   * Every passkey the vault holds, as metadata.
   *
   * No private key is decrypted here. Signing opens exactly the one the user
   * chose, afterwards; registering never opens any.
   */
  async function passkeyViews(
    open: OpenVault,
  ): Promise<readonly (AssertionChoice & { readonly rpId: string })[]> {
    const perItem = await Promise.all(
      open.items
        .filter((item) => item.hasPasskey)
        .map(async (item) => {
          const cipher = open.raw.get(item.id);
          if (cipher === undefined) {
            return [];
          }
          const details = await decryptCipherDetails(cipher, open.keys, () => undefined);
          return details.passkeys
            .filter((view) => view.credentialId !== null && view.rpId !== null)
            .map((view) => ({
              itemId: item.id,
              credentialId: view.credentialId!,
              rpId: view.rpId!,
              label:
                view.userName === null
                  ? (item.name ?? item.id)
                  : `${item.name ?? item.id} — ${view.userName}`,
            }));
        }),
    );
    return perItem.flat();
  }

  /** Hands the verdict to the service worker, which carries it to the page. */
  async function answerAssertion(id: string, payload: unknown): Promise<void> {
    await clearPendingAssertion();
    await chrome.runtime.sendMessage({ type: 'assertion-answer', id, assertion: payload });
  }

  /**
   * Verifies the master password, when the ceremony asked for it.
   *
   * The same offline check a per-item guard makes: re-derive and compare
   * against the witness kept at unlock. Having the server confirm it would
   * hand whoever controls the network the power to wave a passkey through.
   */
  async function verifyMaster(candidate: string): Promise<boolean> {
    const stored = await loadStoredSession();
    if (stored === null) {
      throw new Error(t('errorSessionExpired'));
    }
    const masterKey = await deriveMasterKey(candidate, stored.email, stored.kdfConfig);
    try {
      return await verifyLocalPasswordHash(masterKey, candidate, stored.localPasswordHash);
    } finally {
      masterKey.destroy();
    }
  }

  /** Creates a passkey and puts it in the vault. */
  async function onCreatePasskey(): Promise<void> {
    if (vault === null || assertion === null || assertion.kind !== 'create') {
      return;
    }
    const ask = assertion.ask;
    setError(null);
    setBusy(t('assertionWorking'));
    try {
      let verified = false;
      if (ask.requiresVerification) {
        verified = await verifyMaster(assertionPassword);
        if (!verified) {
          setError(t('exportWrongMaster'));
          return;
        }
      }

      const created = await createCredential({
        rpId: ask.rpId,
        origin: ask.origin,
        challenge: ask.challenge,
        userId: ask.userId,
        userName: ask.userName,
        userDisplayName: ask.userDisplayName,
        userVerified: verified,
      });

      const addPasskey = {
        // The vault records the UUID spelling; the site was given the bytes.
        credentialId: created.storedCredentialId,
        rpId: ask.rpId,
        rpName: ask.rpName,
        userHandle: toBase64Url(ask.userId),
        userName: ask.userName,
        userDisplayName: ask.userDisplayName,
        keyValue: created.privateKey,
      };

      // Attached to an item the user chose, or to one made for it. Either way
      // through the write path every other edit uses.
      const target = assertionChoice === '' ? undefined : vault.raw.get(assertionChoice ?? '');
      const edit = {
        name: target === undefined ? ask.rpName : (vault.items.find((i) => i.id === assertionChoice)?.name ?? ask.rpName),
        username: ask.userName,
        password: '',
        totp: '',
        notes: '',
        uris: [ask.origin],
        addPasskey,
      };

      const auth = await authorize();
      if (target === undefined) {
        await auth.client.createCipher(
          auth.accessToken,
          await buildCipherCreatePayload(edit, vault.userKey),
        );
      } else {
        await auth.client.updateCipher(
          auth.accessToken,
          assertionChoice!,
          await buildCipherUpdatePayload(target, edit, vault.keys, false),
        );
      }

      // The site only hears about it once the vault has it: a passkey a site
      // believes in and the vault has lost is an account locked shut.
      await answerAssertion(assertion.id, {
        credentialId: created.credentialId,
        clientDataJSON: toBase64Url(new TextEncoder().encode(created.clientDataJSON)),
        attestationObject: toBase64Url(created.attestationObject),
        authenticatorData: toBase64Url(created.attestationObject),
      });
      setAssertion(null);
      window.close();
    } catch (err) {
      setError(messageFor(err));
    } finally {
      setBusy(null);
    }
  }

  /** Signs, and lets the page in. */
  async function onConfirmAssertion(event: Event): Promise<void> {
    event.preventDefault();
    if (vault === null || assertion === null || assertionChoice === null) {
      return;
    }
    if (assertion.kind === 'create') {
      await onCreatePasskey();
      return;
    }
    const choice = assertion.choices.find((c) => c.credentialId === assertionChoice);
    const cipher = choice === undefined ? undefined : vault.raw.get(choice.itemId);
    if (choice === undefined || cipher === undefined) {
      return;
    }

    setError(null);
    setBusy(t('assertionWorking'));
    try {
      let verified = false;
      if (assertion.ask.requiresVerification) {
        verified = await verifyMaster(assertionPassword);
        if (!verified) {
          setError(t('exportWrongMaster'));
          return;
        }
      }

      // The one call that decrypts a private key, on the one credential the
      // user has just chosen.
      const credentials = await decryptPasskeys(cipher, vault.keys, () => undefined);
      const credential = credentials.find((c) => c.credentialId === choice.credentialId);
      if (credential === undefined) {
        throw new Error(t('errorItemNotFound'));
      }

      const signed = await signAssertion(credential, { ...assertion.ask, userVerified: verified });
      await answerAssertion(assertion.id, {
        credentialId: signed.credentialId,
        clientDataJSON: toBase64Url(new TextEncoder().encode(signed.clientDataJSON)),
        authenticatorData: toBase64Url(signed.authenticatorData),
        signature: toBase64Url(signed.signature),
        userHandle: signed.userHandle,
      });
      void noteUsage(vault.items.find((i) => i.id === choice.itemId)!);
      setAssertion(null);
      window.close();
    } catch (err) {
      setError(messageFor(err));
    } finally {
      setBusy(null);
    }
  }

  /** Declines, and lets the browser take over. */
  async function onDeclineAssertion(): Promise<void> {
    if (assertion !== null) {
      await answerAssertion(assertion.id, null);
    }
    setAssertion(null);
    setAssertionPassword('');
  }

  /** How short a passphrase may not be. Long beats complicated. */
  const MIN_PASSPHRASE = 12;

  /** Leaves the export screen, taking its three secrets with it. */
  function closeExport(): void {
    setExporting(false);
    setExportMaster('');
    setExportPassphrase('');
    setExportConfirmation('');
    setError(null);
  }

  /**
   * Builds the encrypted export and hands it to the browser to save.
   *
   * The master password is asked for once and verified **offline**, against the
   * witness kept at unlock — the same check a per-item guard makes. That single
   * answer covers every `reprompt` item at once, which is what lets the backup
   * be complete: one missing exactly the items the user was most careful about
   * would be worse than none, because it would be trusted.
   */
  async function onExport(event: Event): Promise<void> {
    event.preventDefault();
    if (vault === null) {
      return;
    }
    if (exportPassphrase !== exportConfirmation) {
      setError(t('exportMismatch'));
      return;
    }
    if (exportPassphrase.length < MIN_PASSPHRASE) {
      setError(t('exportTooShort'));
      return;
    }

    setError(null);
    setBusy(t('exportWorking'));
    try {
      const stored = await loadStoredSession();
      if (stored === null) {
        throw new Error(t('errorSessionExpired'));
      }
      const masterKey = await deriveMasterKey(exportMaster, stored.email, stored.kdfConfig);
      let verified: boolean;
      try {
        verified = await verifyLocalPasswordHash(
          masterKey,
          exportMaster,
          stored.localPasswordHash,
        );
      } finally {
        masterKey.destroy();
      }
      if (!verified) {
        setError(t('exportWrongMaster'));
        return;
      }

      const payload = await buildExportPayload(vault);
      const file = await sealExport(payload, exportPassphrase);
      downloadFile(file, `zwarden-${new Date().toISOString().slice(0, 10)}.json`);

      closeExport();
      setError(t('exportDone', String(payload.items.length)));
    } catch (err) {
      setError(messageFor(err));
    } finally {
      setBusy(null);
    }
  }

  /** Decrypts the whole vault into the shape the file carries. */
  async function buildExportPayload(open: OpenVault): Promise<ExportPayload> {
    const items = await Promise.all(
      open.items.map(async (item): Promise<ExportedItem> => {
        const cipher = open.raw.get(item.id);
        const details =
          cipher === undefined
            ? null
            : await decryptCipherDetails(cipher, open.keys, () => undefined);
        const base = {
          id: item.id,
          type: item.type,
          name: item.name ?? '',
          notes: details?.notes ?? null,
          favorite: cipher === undefined ? false : (readField<boolean>(cipher, 'favorite') ?? false),
          folderId: item.folderId,
        };
        if (item.type === 1) {
          return {
            ...base,
            login: {
              username: details?.username ?? null,
              password: details?.password ?? null,
              totp: details?.totp ?? null,
              uris: item.uris.map((uri) => ({ uri })),
            },
          };
        }
        if (item.type === 3 && details?.card != null) {
          return { ...base, card: { ...details.card } };
        }
        if (item.type === 4 && details?.identity != null) {
          return { ...base, identity: { ...details.identity } };
        }
        return base;
      }),
    );

    return {
      encrypted: false,
      folders: [...open.labels.folders].map(([id, name]) => ({ id, name })),
      items,
    };
  }

  /**
   * Hands a file to the browser.
   *
   * A blob URL and an anchor rather than `chrome.downloads`: the API would need
   * a permission in the manifest, and a password manager asking for one more
   * than it needs is a password manager asking to be distrusted. The URL is
   * revoked straight after — it names the whole vault, encrypted or not.
   */
  function downloadFile(text: string, filename: string): void {
    const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  /**
   * Opens an item's site in a new tab.
   *
   * The URL is one `openableUri` has already narrowed to `http`/`https`: a
   * vault URI is arbitrary text, and handing `javascript:` to the browser from
   * the extension's own page would run it with the extension's privileges.
   * Checked there, where it is tested, rather than trusted here.
   */
  function openSite(url: string): void {
    void chrome.tabs.create({ url });
    window.close();
  }

  /**
   * Moves an item to the trash, from the health report.
   *
   * The trash and not the permanent deletion: the official clients keep a
   * trashed item for thirty days, so a misclick on a list one is skimming costs
   * a trip to the web vault rather than a password that exists nowhere any
   * more.
   *
   * Not queued when the server is unreachable, unlike an edit. A held deletion
   * would have to decide what to do about an item changed in the meantime, and
   * "delete it anyway" is the wrong answer often enough that the honest
   * behaviour is to fail visibly and let the user try again.
   */
  async function onTrashItem(cipherId: string): Promise<void> {
    if (vault === null) {
      return;
    }
    const name = vault.items.find((i) => i.id === cipherId)?.name ?? cipherId;
    setError(null);
    setBusy(t('statusSaving'));
    try {
      const auth = await authorize();
      await auth.client.trashCipher(auth.accessToken, cipherId);
      await refreshAfterWrite(auth, vault.userKey);
      // The report described a vault that no longer holds this item: the row
      // goes, rather than staying until the panel is reopened.
      setHealth((current) =>
        current === null
          ? null
          : { ...current, stale: current.stale.filter((f) => f.id !== cipherId) },
      );
      setError(t('healthDeleted', name));
    } catch (err) {
      setError(messageFor(err));
    } finally {
      setBusy(null);
    }
  }

  /**
   * What the header's menu holds.
   *
   * Built here rather than in the header: the header knows how to show a menu,
   * not what the vault can do. `undefined` renders an entry disabled — visible
   * but out of reach — which is how a still-opening vault says "not yet"
   * instead of rearranging its own menu under the cursor.
   */
  function menuActions(unlocked: boolean): readonly MenuAction[] {
    return [
      { key: 'health', label: 'actionHealth', run: unlocked ? () => void onCheckHealth() : undefined },
      { key: 'export', label: 'actionExport', run: unlocked ? () => setExporting(true) : undefined },
      { key: 'settings', label: 'actionSettings', run: openOptions },
      { key: 'lock', label: 'actionLock', run: onLock },
    ];
  }

  /** Opens the edit screen on a blank item, type still to be chosen. */
  function onNewItem(): void {
    setEditForm(EMPTY_EDIT);
    setEditOriginalPassword('');
    setEditPasskeys([]);
    setEditShowPassword(false);
    setEditing(null);
    setCreating(true);
    setError(null);
  }

  /**
   * The form's values, as the vault layer expects them.
   *
   * The typed section is supplied **only** for the type that owns it. That is
   * not tidiness: on an update, a section the editor says nothing about is
   * carried over from the server untouched, and handing a blank card to a secure
   * note would be handing it an erasure.
   */
  function cipherEditFrom(form: EditForm): CipherEdit {
    const base = {
      type: form.type,
      name: form.name.trim(),
      username: form.username,
      password: form.password,
      totp: form.totp,
      notes: form.notes,
      uris: form.uris.split('\n'),
    };
    if (form.type === 3) {
      return { ...base, card: form.card };
    }
    if (form.type === 4) {
      return { ...base, identity: form.identity };
    }
    return base;
  }

  /** Encrypts, sends the write, resyncs and returns to the list. */
  async function onSaveEdit(event: Event): Promise<void> {
    event.preventDefault();
    if (vault === null) {
      return;
    }
    const raw = editing === null ? undefined : vault.raw.get(editing.id);
    if (editing !== null && raw === undefined) {
      return;
    }

    setError(null);
    setBusy(t('statusEncrypting'));
    try {
      const edit = cipherEditFrom(editForm);
      // Encryption first, and entirely local. Only then is the network tried —
      // so a server that cannot be reached leaves a body ready to be held,
      // rather than an edit that has to be retyped.
      const payload =
        raw === undefined
          ? // Creation goes out under the vault key, with no item key of its
            // own — the shape the interoperability round trip validates.
            await buildCipherCreatePayload(edit, vault.userKey)
          : await buildCipherUpdatePayload(
              raw,
              edit,
              vault.keys,
              editForm.password !== editOriginalPassword,
            );

      setBusy(t('statusSaving'));
      try {
        const auth = await authorize();
        if (raw === undefined) {
          await auth.client.createCipher(auth.accessToken, payload);
        } else {
          await auth.client.updateCipher(auth.accessToken, editing!.id, payload);
        }
        await refreshAfterWrite(auth, vault.userKey);
      } catch (err) {
        if (!isUnreachable(err)) {
          throw err;
        }
        await holdWrite(
          raw === undefined ? 'create' : 'update',
          editing?.id ?? null,
          payload,
          raw === undefined ? null : (readField<string>(raw, 'revisionDate') ?? null),
          editForm.name.trim(),
        );
      }

      setEditing(null);
      setCreating(false);
      setEditForm(EMPTY_EDIT);
      setEditOriginalPassword('');
      setRevealed(null);
    } catch (err) {
      setError(messageFor(err));
      setBusy(null);
    }
  }

  function onCancelEdit(): void {
    setEditing(null);
    setEditForm(EMPTY_EDIT);
    setEditOriginalPassword('');
    setCreating(false);
    setError(null);
  }

  function matchesNeedle(item: CipherOverview, needle: string, labels: VaultLabels): boolean {
    return (
      (item.name ?? '').toLowerCase().includes(needle) ||
      (item.username ?? '').toLowerCase().includes(needle) ||
      // Typing the last four digits of a card, or a surname, finds the item.
      (item.subtitle ?? '').toLowerCase().includes(needle) ||
      item.uris.some((uri) => uri.toLowerCase().includes(needle)) ||
      chipsFor(item, labels).some((chip) => chip.name.toLowerCase().includes(needle))
    );
  }

  // --- Initialising: neither sign-in screen nor list until we know ----------
  //
  // The filter and the search box are drawn straight away, with real counts —
  // the types come from the raw sync, which costs no decryption. Waiting for the
  // list to render them would move two controls into place just as the user
  // reaches for them, and would throw away whatever they had started typing.
  if (vault === null && initializing) {
    return (
      <div>
        <VaultHeader
          canCreate={false}
          onNew={() => undefined}
          onGenerate={() => void generator.open('standalone')}
          // No vault yet: only what does not need one is offered.
          actions={menuActions(false)}
        />
        <main>
          <TypeFilter counts={rawCounts} selected={typeFilter} onSelect={setTypeFilter} />
          <input
            class="search"
            type="search"
            // A cold start has no cached sync and therefore no count. Better a
            // placeholder that says nothing than one that says zero.
            placeholder={
              countOf(rawCounts) === 0
                ? t('listSearchUnknown')
                : t('listSearch', String(countOf(rawCounts)))
            }
            value={filter}
            onInput={(e) => setFilter(e.currentTarget.value)}
          />
          <p class="status">{busy ?? t('listOpening')}</p>
        </main>
      </div>
    );
  }

  // --- Second-factor screen -------------------------------------------------
  if (vault === null && twoFaProviders !== null) {
    return (
      <TwoFactorScreen
        available={twoFaProviders.filter((p) => p in providerLabels())}
        labels={providerLabels()}
        choice={twoFaChoice}
        code={twoFaCode}
        remember={rememberDevice}
        busy={busy}
        error={error}
        onChoice={setTwoFaChoice}
        onCode={setTwoFaCode}
        onRemember={setRememberDevice}
        onSubmit={() =>
          void attemptUnlock({
            provider: Number(twoFaChoice),
            token: twoFaCode.trim(),
            remember: rememberDevice,
          })
        }
        onBack={() => {
          setTwoFaProviders(null);
          setTwoFaCode('');
          setError(null);
        }}
        onOptions={openOptions}
      />
    );
  }

  // --- Unlock screen --------------------------------------------------------
  if (vault === null) {
    return (
      <UnlockScreen
        serverUrl={serverUrl}
        email={email}
        password={password}
        showPassword={showPassword}
        busy={busy}
        error={error}
        onServerUrl={setServerUrl}
        onEmail={setEmail}
        onPassword={setPassword}
        onToggleShowPassword={() => setShowPassword(!showPassword)}
        onSubmit={() => void attemptUnlock()}
        onOptions={openOptions}
      />
    );
  }

  // --- A page waiting on a passkey ------------------------------------------
  //
  // Before every other screen: a ceremony is a page held open, waiting, and
  // anything else shown first would be the extension ignoring it.
  if (assertion !== null) {
    return (
      <AssertionScreen
        ceremony={assertion.kind}
        origin={assertion.ask.origin}
        siteName={assertion.kind === 'create' ? assertion.ask.rpName : assertion.ask.rpId}
        choices={assertion.choices}
        chosen={assertionChoice}
        needsVerification={assertion.ask.requiresVerification}
        masterPassword={assertionPassword}
        busy={busy}
        error={error}
        onChoose={setAssertionChoice}
        onMasterPassword={setAssertionPassword}
        onConfirm={(e) => void onConfirmAssertion(e)}
        onDecline={() => void onDeclineAssertion()}
      />
    );
  }

  // --- Encrypted export -----------------------------------------------------
  if (exporting) {
    return (
      <ExportScreen
        masterPassword={exportMaster}
        passphrase={exportPassphrase}
        confirmation={exportConfirmation}
        busy={busy}
        error={error}
        onMasterPassword={setExportMaster}
        onPassphrase={setExportPassphrase}
        onConfirmation={setExportConfirmation}
        onSubmit={(e) => void onExport(e)}
        onCancel={closeExport}
      />
    );
  }

  // --- Vault health ---------------------------------------------------------
  if (health !== null) {
    return (
      <div>
        <HealthPanel
          report={health}
          onBack={() => setHealth(null)}
          onDelete={(id) => void onTrashItem(id)}
          onOpen={openSite}
        />
        {busy !== null && <p class="status">{busy}</p>}
        {error !== null && <p class="error">{error}</p>}
      </div>
    );
  }

  // --- Edit screen ----------------------------------------------------------
  if (editing !== null || creating) {
    return (
      <EditItemForm
        form={editForm}
        creating={creating}
        showPassword={editShowPassword}
        passkeys={editPasskeys}
        busy={busy}
        error={error}
        generator={generator.render()}
        onPatch={(patch) => setEditForm({ ...editForm, ...patch })}
        onToggleShowPassword={() => setEditShowPassword(!editShowPassword)}
        onOpenGenerator={() => void generator.open('edit')}
        onSubmit={(e) => void onSaveEdit(e)}
        onCancel={onCancelEdit}
      />
    );
  }

  // --- Vault list -----------------------------------------------------------
  // Memoised: filtering used to walk the whole vault on every re-render, and an
  // open one-time code caused one of those every second.
  const needle = filter.trim().toLowerCase();
  const visible = useMemo(
    () =>
      vault.items.filter(
        (i) =>
          (typeFilter.size === 0 || typeFilter.has(i.type)) &&
          (needle === '' || matchesNeedle(i, needle, vault.labels)),
      ),
    [vault.items, vault.labels, needle, typeFilter],
  );

  return (
    <div>
      <VaultHeader
        canCreate
        onNew={onNewItem}
        onGenerate={() => void generator.open('standalone')}
        actions={menuActions(true)}
      />
      <main>
        {reprompt.state !== null && (
          <RepromptGuard
            state={reprompt.state}
            onPassword={reprompt.setPassword}
            onConfirm={(e) => void reprompt.confirm(e)}
            onCancel={reprompt.cancel}
          />
        )}
        {generator.render()}
        {queued.pending > 0 && (
          <div class={`queue-banner${queued.held > 0 ? ' queue-held' : ''}`}>
            <p>
              {queued.held > 0
                ? t('queueHeld', String(queued.held))
                : t('queuePending', String(queued.pending))}
            </p>
            {queued.held > 0 && (
              <>
                <p class="hint-diag">{t('queueHeldDetail')}</p>
                <button class="secondary" onClick={() => void onDiscardQueue()}>
                  {t('queueDiscard')}
                </button>
              </>
            )}
          </div>
        )}
        {proposal !== null && (
          <SaveProposalBanner
            proposal={proposal}
            busy={busy !== null}
            onSave={() => void onSaveProposal()}
            onDismiss={() => void dismissProposal()}
            onNever={() => void onNeverForHost()}
          />
        )}
        {/* The same counts the loading screen showed, from the same source:
            `type` is not encrypted, so they were right before a single field
            was read and there is nothing to revise. */}
        <TypeFilter counts={rawCounts} selected={typeFilter} onSelect={setTypeFilter} />
        <input
          class="search"
          type="search"
          placeholder={t('listSearch', String(vault.items.length))}
          value={filter}
          onInput={(e) => setFilter(e.currentTarget.value)}
        />
        {vault.errors.length > 0 && (
          <details class="diagnostic">
            <summary class="error">
              {t('listUnreadableFields', String(vault.errors.length))}
            </summary>
            <ul>
              {groupErrors(vault.errors).map(([name, count]) => (
                <li key={name}>
                  {name} × {count}
                </li>
              ))}
            </ul>
            <p class="hint-diag">{t('listFullLog')}</p>
          </details>
        )}
        {error !== null && <p class="error">{error}</p>}
        {vault.pending > 0 && (
          // Said out loud: while this is up, a search that finds nothing may
          // simply not have reached the item yet.
          <p class="status">{t('listStillOpening', String(vault.pending))}</p>
        )}
        {visible.length === 0 && vault.pending === 0 ? (
          <p class="empty">{t('listEmpty')}</p>
        ) : (
          <ul class="items">
            {visible.map((item) => (
              <ItemRow
                key={item.id}
                item={item}
                labels={vault.labels}
                passwordCopied={copiedId === item.id}
                usernameCopied={copiedUserId === item.id}
                revealed={revealed?.id === item.id ? revealed.content : null}
                copiedField={copiedField}
                otp={otp?.id === item.id ? otp : null}
                otpCopied={copiedOtp}
                fillable={tabOrigin !== null && matchesOrigin(item.uris, tabOrigin)}
                onCopyUsername={() => void onCopyUsername(item)}
                onCopyPassword={() => onCopyPassword(item)}
                onToggleReveal={() => onToggleReveal(item)}
                onToggleOtp={() => onToggleOtp(item)}
                onEdit={() => onEdit(item)}
                onFill={() => void onFill(item)}
                onCopyOtp={(code) => void copyOtp(code)}
                onCopyField={(label, value) => void onCopyField(label, value)}
                onFilter={setFilter}
              />
            ))}
          </ul>
        )}
      </main>
    </div>
  );
}

/**
 * The catalogue is in place before the first paint.
 *
 * `t` is synchronous, so a language arriving after the first render would
 * repaint every label under the reader's eyes. One storage read and — only when
 * a language has actually been chosen — one fetch of a packaged file stand
 * between the page opening and its first frame; following the browser, the
 * default, costs neither.
 */
void (async () => {
  await applyLocale((await loadSettings()).language);
  render(<App />, document.getElementById('app')!);
})();
