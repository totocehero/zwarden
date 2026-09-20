/**
 * @file Storage shared between the popup, the options page and the service
 * worker.
 *
 * Two levels, never to be confused:
 *
 * - `chrome.storage.local` — durable preferences: settings, device identifier,
 *   2FA remember tokens. **Never a key, never a password.**
 * - `chrome.storage.session` — unlocked state: vault key and session tokens.
 *   Pure memory, restricted to the extension's trusted contexts, purged when the
 *   browser closes.
 *
 * Every function tolerates the absence of `chrome.*` (Vite preview, tests) by
 * behaving as empty storage.
 */

import type { KdfConfig } from '../core/crypto/kdf.js';
import { KdfType } from '../core/crypto/kdf.js';
import type { SyncResponse } from '../core/api/models.js';
import { toBase64 } from '../core/crypto/encoding.js';
import { forgetSealingKey, openVaultKey, sealVaultKey } from './keyGuard.js';
import {
  DEFAULT_PASSWORD_OPTIONS,
  type PasswordOptions,
} from '../core/generator/password.js';

/** Application settings, as edited in the options page. */
export interface AppSettings {
  readonly serverUrl: string;
  readonly email: string;
  /** Name shown among the server's active sessions. */
  readonly deviceName: string;
  /** Network timeout, in seconds. */
  readonly timeoutSeconds: number;
  /**
   * Auto-lock after inactivity, in minutes — "inactivity" meaning: no activity
   * in the browser (tab switch, window switch, navigation) nor in the popup.
   * 0 = never (lock on browser close only), which is the default.
   */
  readonly autoLockMinutes: number;
  /**
   * Lock as soon as the system session locks (screensaver, `Win+L`, suspend).
   * Independent of the inactivity delay: it is the safety net that makes the
   * "browser close" default tenable — one walks away from a machine far more
   * often than one closes the browser.
   */
  readonly lockOnSystemLock: boolean;
  /**
   * Offer to save credentials entered on a site the vault does not know.
   * Switched off, the detector is not even injected into pages.
   */
  readonly offerToSave: boolean;
  /** Clipboard wipe after a copy, in seconds. 0 = never. */
  readonly clipboardClearSeconds: number;
  /**
   * Interface language, as a code from `AVAILABLE_LOCALES` — or the empty
   * string, the default, to follow the browser's own.
   *
   * Stored as a plain code rather than a boolean plus a code: "follow the
   * browser" is one choice among the others, not a mode layered over them.
   */
  readonly language: string;
  /**
   * Ask Have I Been Pwned whether a password has appeared in a public breach.
   *
   * **Off by default**, and the only setting that lets the extension talk to
   * anyone but the user's own server. What it sends and what it leaks is laid
   * out in `breachCheck.ts` and repeated in the settings page rather than
   * summarised into reassurance.
   */
  readonly breachCheckEnabled: boolean;
  /**
   * Answer passkey sign-ins with the vault.
   *
   * **Off by default.** It is the one feature that puts code inside every page
   * visited — a replacement for `navigator.credentials.get`, and nothing else:
   * no element, no style, no interface. The confirmation happens in the popup,
   * like every other decision here.
   */
  readonly passkeySignIn: boolean;
}

export const DEFAULT_SETTINGS: AppSettings = {
  serverUrl: '',
  email: '',
  deviceName: 'Zwarden',
  timeoutSeconds: 30,
  autoLockMinutes: 0,
  lockOnSystemLock: true,
  offerToSave: true,
  clipboardClearSeconds: 30,
  language: '',
  breachCheckEnabled: false,
  passkeySignIn: false,
};

const hasLocal = typeof chrome !== 'undefined' && typeof chrome.storage?.local !== 'undefined';
const hasSession = typeof chrome !== 'undefined' && typeof chrome.storage?.session !== 'undefined';
const hasAlarms = typeof chrome !== 'undefined' && typeof chrome.alarms !== 'undefined';

function readString(source: Record<string, unknown>, key: string, fallback: string): string {
  const value = source[key];
  return typeof value === 'string' ? value : fallback;
}

function readNumber(source: Record<string, unknown>, key: string, fallback: number): number {
  const value = source[key];
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : fallback;
}

function readBoolean(source: Record<string, unknown>, key: string, fallback: boolean): boolean {
  const value = source[key];
  return typeof value === 'boolean' ? value : fallback;
}

/** Loads the settings, falling back to defaults for any missing or invalid field. */
export async function loadSettings(): Promise<AppSettings> {
  if (!hasLocal) {
    return DEFAULT_SETTINGS;
  }
  const stored = await chrome.storage.local.get([
    'serverUrl',
    'email',
    'deviceName',
    'timeoutSeconds',
    'autoLockMinutes',
    'lockOnSystemLock',
    'offerToSave',
    'clipboardClearSeconds',
    'language',
    'breachCheckEnabled',
    'passkeySignIn',
  ]);
  return {
    serverUrl: readString(stored, 'serverUrl', DEFAULT_SETTINGS.serverUrl),
    email: readString(stored, 'email', DEFAULT_SETTINGS.email),
    deviceName: readString(stored, 'deviceName', DEFAULT_SETTINGS.deviceName),
    timeoutSeconds: readNumber(stored, 'timeoutSeconds', DEFAULT_SETTINGS.timeoutSeconds),
    autoLockMinutes: readNumber(stored, 'autoLockMinutes', DEFAULT_SETTINGS.autoLockMinutes),
    lockOnSystemLock: readBoolean(stored, 'lockOnSystemLock', DEFAULT_SETTINGS.lockOnSystemLock),
    offerToSave: readBoolean(stored, 'offerToSave', DEFAULT_SETTINGS.offerToSave),
    clipboardClearSeconds: readNumber(
      stored,
      'clipboardClearSeconds',
      DEFAULT_SETTINGS.clipboardClearSeconds,
    ),
    language: readString(stored, 'language', DEFAULT_SETTINGS.language),
    breachCheckEnabled: readBoolean(
      stored,
      'breachCheckEnabled',
      DEFAULT_SETTINGS.breachCheckEnabled,
    ),
    passkeySignIn: readBoolean(stored, 'passkeySignIn', DEFAULT_SETTINGS.passkeySignIn),
  };
}

/** Saves a subset of the settings. */
export async function saveSettings(patch: Partial<AppSettings>): Promise<void> {
  if (hasLocal) {
    await chrome.storage.local.set(patch);
  }
}

// --- Device identifier -------------------------------------------------------

/**
 * Stable device identifier: generated once, persisted. Regenerating it on every
 * connection would create one server session per unlock and trigger "new device"
 * alerts.
 */
export async function getDeviceId(): Promise<string> {
  if (!hasLocal) {
    return crypto.randomUUID();
  }
  const stored = await chrome.storage.local.get('deviceId');
  if (typeof stored['deviceId'] === 'string') {
    return stored['deviceId'];
  }
  return regenerateDeviceId();
}

/** Regenerates the device identifier. The server will see a new device. */
export async function regenerateDeviceId(): Promise<string> {
  const id = crypto.randomUUID();
  if (hasLocal) {
    await chrome.storage.local.set({ deviceId: id });
  }
  return id;
}

// --- 2FA remember tokens -----------------------------------------------------

const REMEMBER_PREFIX = '2faRemember:';

/** Storage key for the remember token, specific to the account/server pair. */
function rememberKey(serverUrl: string, email: string): string {
  return `${REMEMBER_PREFIX}${email.trim().toLowerCase()}@${serverUrl}`;
}

export async function loadRememberToken(serverUrl: string, email: string): Promise<string | null> {
  if (!hasLocal) {
    return null;
  }
  const key = rememberKey(serverUrl, email);
  const stored = await chrome.storage.local.get(key);
  return typeof stored[key] === 'string' ? stored[key] : null;
}

export async function saveRememberToken(
  serverUrl: string,
  email: string,
  token: string,
): Promise<void> {
  if (hasLocal) {
    await chrome.storage.local.set({ [rememberKey(serverUrl, email)]: token });
  }
}

export async function clearRememberToken(serverUrl: string, email: string): Promise<void> {
  if (hasLocal) {
    await chrome.storage.local.remove(rememberKey(serverUrl, email));
  }
}

/**
 * Forgets every 2FA exemption on this device, across all accounts.
 *
 * @returns How many exemptions were removed.
 */
export async function clearAllRememberTokens(): Promise<number> {
  if (!hasLocal) {
    return 0;
  }
  const all = await chrome.storage.local.get(null);
  const keys = Object.keys(all).filter((key) => key.startsWith(REMEMBER_PREFIX));
  if (keys.length > 0) {
    await chrome.storage.local.remove(keys);
  }
  return keys.length;
}

// --- Save proposal -----------------------------------------------------------

/**
 * Credentials entered in a page, awaiting the user's decision.
 *
 * **Holds a cleartext password**: it therefore lives in
 * `chrome.storage.session` — pure memory, purged when the browser closes — on
 * the same footing as the vault key, and never on disk. Only one capture is kept
 * at a time: the last entry is the one the user cares about, and stacking up
 * cleartext passwords would be surface for free.
 */
export interface PendingSave {
  /** The page's origin (scheme + host + port), for the created item's URI. */
  readonly origin: string;
  /** Host alone, for display and for the exclusion list. */
  readonly host: string;
  readonly username: string;
  readonly password: string;
  /** When the capture happened, for expiry. */
  readonly capturedAt: number;
}

const PENDING_KEY = 'pendingSave';

/**
 * How long a capture lives. Past that, the proposal no longer connects to
 * anything in the user's mind, and keeping a cleartext password in memory for
 * nothing buys nothing at all.
 */
export const PENDING_TTL_MS = 10 * 60_000;

export async function savePendingSave(pending: PendingSave): Promise<void> {
  if (hasSession) {
    await chrome.storage.session.set({ [PENDING_KEY]: pending });
  }
}

/** The pending capture, `null` if there is none or it has expired. */
export async function loadPendingSave(now: number = Date.now()): Promise<PendingSave | null> {
  if (!hasSession) {
    return null;
  }
  const stored = await chrome.storage.session.get(PENDING_KEY);
  const p = stored[PENDING_KEY] as Partial<PendingSave> | undefined;
  if (
    p === undefined ||
    typeof p.origin !== 'string' ||
    typeof p.host !== 'string' ||
    typeof p.username !== 'string' ||
    typeof p.password !== 'string' ||
    typeof p.capturedAt !== 'number'
  ) {
    return null;
  }
  if (now - p.capturedAt > PENDING_TTL_MS) {
    await clearPendingSave();
    return null;
  }
  return {
    origin: p.origin,
    host: p.host,
    username: p.username,
    password: p.password,
    capturedAt: p.capturedAt,
  };
}

export async function clearPendingSave(): Promise<void> {
  if (hasSession) {
    await chrome.storage.session.remove(PENDING_KEY);
  }
}

// --- Icon badge --------------------------------------------------------------

const hasAction = typeof chrome !== 'undefined' && typeof chrome.action !== 'undefined';

/**
 * A badge on the extension's icon, the only visible signal of a pending
 * proposal. Deliberately quiet: no system notification, no UI injected into the
 * page.
 */
export async function setSaveBadge(visible: boolean): Promise<void> {
  if (!hasAction) {
    return;
  }
  await chrome.action.setBadgeText({ text: visible ? '+' : '' });
  if (visible) {
    await chrome.action.setBadgeBackgroundColor({ color: '#2f7d5b' });
  }
}

// --- Sites never to offer on -------------------------------------------------

const NEVER_SAVE_KEY = 'neverSaveHosts';
const NEVER_SAVE_SALT_KEY = 'neverSaveSalt';

/**
 * Hosts are stored **hashed**, never in clear.
 *
 * This list lives on disk, unencrypted, like everything in `storage.local` — a
 * plain list of hostnames is a list of the sites the user holds an account on,
 * readable by anyone holding the drive and needing no vault at all
 * (`docs/STORAGE.md` §3.B).
 *
 * The salt buys nothing against someone who has the file, since they have the
 * salt too, and that is not its job. What changes is the question the attacker
 * can ask: **enumerate** the list becomes **confirm** a host already guessed.
 * Turning a disclosure into an oracle is a real reduction, and since the lookup
 * is an exact match, hashing costs nothing in function.
 *
 * It is not a defence against someone working through a list of popular sites.
 * It is the removal of a free gift.
 */
async function neverSaveDigest(host: string, salt: string): Promise<string> {
  const bytes = new TextEncoder().encode(`${salt}:${host.trim().toLowerCase()}`);
  const digest = await crypto.subtle.digest('SHA-256', bytes as BufferSource);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** The per-install salt, created on first use. */
async function neverSaveSalt(): Promise<string> {
  const stored = await chrome.storage.local.get(NEVER_SAVE_SALT_KEY);
  const existing = stored[NEVER_SAVE_SALT_KEY];
  if (typeof existing === 'string' && existing !== '') {
    return existing;
  }
  const fresh = toBase64(crypto.getRandomValues(new Uint8Array(16)));
  await chrome.storage.local.set({ [NEVER_SAVE_SALT_KEY]: fresh });
  return fresh;
}

/** The stored entries, hashed or — for a list written before this — in clear. */
async function loadNeverSaveEntries(): Promise<readonly string[]> {
  if (!hasLocal) {
    return [];
  }
  const stored = await chrome.storage.local.get(NEVER_SAVE_KEY);
  const value = stored[NEVER_SAVE_KEY];
  return Array.isArray(value) ? value.filter((h): h is string => typeof h === 'string') : [];
}

/**
 * Whether the user asked that nothing be offered on this host.
 *
 * A membership test rather than a getter, so no caller ever holds the list. It
 * could not be a getter anyway now that the entries are hashed — which is a
 * good sign about the shape rather than a constraint to work around.
 *
 * Entries written before hashing existed are plain hostnames; they are still
 * matched, so nobody's exclusions are silently forgotten on upgrade.
 */
export async function isNeverSaveHost(host: string): Promise<boolean> {
  const entries = await loadNeverSaveEntries();
  if (entries.length === 0) {
    return false;
  }
  if (entries.includes(host)) {
    return true;
  }
  return entries.includes(await neverSaveDigest(host, await neverSaveSalt()));
}

export async function addNeverSaveHost(host: string): Promise<void> {
  if (!hasLocal) {
    return;
  }
  const entries = await loadNeverSaveEntries();
  const digest = await neverSaveDigest(host, await neverSaveSalt());
  if (!entries.includes(digest) && !entries.includes(host)) {
    await chrome.storage.local.set({ [NEVER_SAVE_KEY]: [...entries, digest] });
  }
}

/** Empties the exclusion list. @returns How many hosts were forgotten. */
export async function clearNeverSaveHosts(): Promise<number> {
  const entries = await loadNeverSaveEntries();
  if (hasLocal && entries.length > 0) {
    // The salt goes with them: keeping it would let the next list be tested
    // against digests captured from this one.
    await chrome.storage.local.remove([NEVER_SAVE_KEY, NEVER_SAVE_SALT_KEY]);
  }
  return entries.length;
}

// --- Generator options -------------------------------------------------------

const GENERATOR_KEY = 'generatorOptions';

/**
 * Password generator preferences.
 *
 * Stored apart rather than added to `AppSettings`: these are tool settings,
 * changed from the popup as one goes, not application settings edited in the
 * options page. Mixing them would have the popup writing into the same object as
 * the options page, and one would overwrite the other.
 */
export async function loadGeneratorOptions(): Promise<PasswordOptions> {
  if (!hasLocal) {
    return DEFAULT_PASSWORD_OPTIONS;
  }
  const stored = await chrome.storage.local.get(GENERATOR_KEY);
  const o = stored[GENERATOR_KEY] as Partial<PasswordOptions> | undefined;
  if (o === undefined) {
    return DEFAULT_PASSWORD_OPTIONS;
  }
  const bool = (value: unknown, fallback: boolean): boolean =>
    typeof value === 'boolean' ? value : fallback;
  return {
    length:
      typeof o.length === 'number' && Number.isFinite(o.length)
        ? o.length
        : DEFAULT_PASSWORD_OPTIONS.length,
    lowercase: bool(o.lowercase, DEFAULT_PASSWORD_OPTIONS.lowercase),
    uppercase: bool(o.uppercase, DEFAULT_PASSWORD_OPTIONS.uppercase),
    digits: bool(o.digits, DEFAULT_PASSWORD_OPTIONS.digits),
    symbols: bool(o.symbols, DEFAULT_PASSWORD_OPTIONS.symbols),
    avoidAmbiguous: bool(o.avoidAmbiguous, DEFAULT_PASSWORD_OPTIONS.avoidAmbiguous),
  };
}

export async function saveGeneratorOptions(options: PasswordOptions): Promise<void> {
  if (hasLocal) {
    await chrome.storage.local.set({ [GENERATOR_KEY]: options });
  }
}

// --- Recent use --------------------------------------------------------------

/**
 * Last-use timestamps, by item identifier. Persisted in
 * `chrome.storage.local`: the whole point of the ordering is precisely to
 * survive the browser closing.
 *
 * **What this exposes.** Item identifiers (opaque UUIDs) and timestamps — never
 * a name, a URL, a username or a password. Whoever reads the browser profile
 * learns that an item was used at a given time, not which one nor on which site.
 * The rule from `docs/CRYPTO.md` — no key, no secret on disk — holds.
 */
const LAST_USED_KEY = 'lastUsed';

/**
 * How many items are kept. Beyond that, the oldest are forgotten: the ordering
 * only matters for the head of the list, and a vault of several thousand items
 * must not grow storage without bound.
 */
const LAST_USED_MAX = 100;

/** Last-use timestamps, empty if none was ever recorded. */
export async function loadLastUsed(): Promise<Readonly<Record<string, number>>> {
  if (!hasLocal) {
    return {};
  }
  const stored = await chrome.storage.local.get(LAST_USED_KEY);
  const value = stored[LAST_USED_KEY];
  if (typeof value !== 'object' || value === null) {
    return {};
  }
  const clean: Record<string, number> = {};
  for (const [id, at] of Object.entries(value as Record<string, unknown>)) {
    if (typeof at === 'number' && Number.isFinite(at)) {
      clean[id] = at;
    }
  }
  return clean;
}

/**
 * Records that an item has just been used — copied, filled or revealed.
 *
 * @param id Item identifier.
 * @param now Current instant.
 */
export async function markUsed(id: string, now: number = Date.now()): Promise<void> {
  if (!hasLocal) {
    return;
  }
  const merged = { ...(await loadLastUsed()), [id]: now };
  await chrome.storage.local.set({ [LAST_USED_KEY]: pruneLastUsed(merged) });
}

/** Keeps only the `LAST_USED_MAX` most recent uses. A pure function. */
export function pruneLastUsed(
  lastUsed: Readonly<Record<string, number>>,
): Record<string, number> {
  const entries = Object.entries(lastUsed);
  if (entries.length <= LAST_USED_MAX) {
    return Object.fromEntries(entries);
  }
  entries.sort((a, b) => b[1] - a[1]);
  return Object.fromEntries(entries.slice(0, LAST_USED_MAX));
}

/** Forgets the whole use ordering. */
export async function clearLastUsed(): Promise<void> {
  if (hasLocal) {
    await chrome.storage.local.remove(LAST_USED_KEY);
  }
}

// --- Unlocked session --------------------------------------------------------

/**
 * The unlocked session, as kept in `chrome.storage.session`.
 *
 * **The vault key is deliberately not in here.** It lives under its own entry,
 * fetched only by the one caller that decrypts — see {@link loadVaultKey}.
 */
export interface StoredSession {
  readonly accessToken: string;
  readonly refreshToken: string | null;
  readonly expiresAt: number;
  readonly serverUrl: string;
  readonly email: string;
  /**
   * The last sync response, as-is — sensitive fields still encrypted. Lets the
   * vault be displayed the instant the popup opens, before the network refresh.
   * Same memory storage as the key: no extra surface.
   */
  readonly cachedSync: SyncResponse | null;
  /**
   * Local hash of the master password, as produced by `unlock`.
   *
   * Used to verify a fresh entry **without a network** when an item demands the
   * password again (`reprompt`). It cannot be replayed against the server — its
   * iteration count differs from the authorization hash's.
   */
  readonly localPasswordHash: string;
  /** The account's KDF parameters, to re-derive the master key on verification. */
  readonly kdfConfig: KdfConfig;
}

/**
 * Reads back stored KDF parameters. `null` if the shape matches neither of the
 * two admitted KDFs — we would rather treat the session as absent than keep a
 * session whose password we could no longer verify.
 */
function readKdfConfig(value: unknown): KdfConfig | null {
  if (typeof value !== 'object' || value === null) {
    return null;
  }
  const c = value as Record<string, unknown>;
  if (typeof c['iterations'] !== 'number') {
    return null;
  }
  if (c['type'] === KdfType.PBKDF2_SHA256) {
    return { type: KdfType.PBKDF2_SHA256, iterations: c['iterations'] };
  }
  if (
    c['type'] === KdfType.Argon2id &&
    typeof c['memoryMiB'] === 'number' &&
    typeof c['parallelism'] === 'number'
  ) {
    return {
      type: KdfType.Argon2id,
      iterations: c['iterations'],
      memoryMiB: c['memoryMiB'],
      parallelism: c['parallelism'],
    };
  }
  return null;
}

const SESSION_KEY = 'session';

/**
 * The vault key, under an entry of its own.
 *
 * ## Why it is not part of {@link StoredSession}
 *
 * It was, and that meant every reader of the session pulled the key into its
 * own heap whether it needed it or not. Four of the callers are in the service
 * worker, and **not one of them decrypts anything** — they ask whether a
 * session exists. One of those four runs on every credential capture, which is
 * to say on form submissions across every page the user visits.
 *
 * `chrome.storage` serialises to JSON, so the key crosses as a base64 string,
 * and a JavaScript string is immutable: it cannot be wiped, only dropped and
 * left to the garbage collector. Every needless read was therefore a needless
 * copy of the vault key lying in the longest-lived, most-exposed context the
 * extension has, waiting to be collected — and possibly paged to swap in the
 * meantime (`docs/STORAGE.md` §1).
 *
 * Splitting the entry confines the key to the one context that decrypts — the
 * popup — and keeps it out of the service worker entirely.
 *
 * ## And the entry itself holds ciphertext
 *
 * What is stored under this key is **sealed**, not the vault key: AES-GCM under
 * a non-extractable `CryptoKey` kept in IndexedDB (`keyGuard.ts`). The two
 * halves are useless apart, and closing the browser purges this one, leaving
 * the half on disk inert.
 *
 * So the plaintext key no longer sits resident for the whole browser session.
 * It exists in the popup's heap, while the popup is open, and nowhere else.
 */
const VAULT_KEY_KEY = 'vaultKey';

/**
 * The vault key, base64. `null` if the vault is locked.
 *
 * Call it only where a decryption actually follows. Everything else that used
 * to reach for the session wholesale wants {@link hasStoredSession} or
 * {@link loadStoredSession}, neither of which touches this entry.
 */
export async function loadVaultKey(): Promise<string | null> {
  if (!hasSession) {
    return null;
  }
  const stored = await chrome.storage.session.get(VAULT_KEY_KEY);
  const sealed = stored[VAULT_KEY_KEY];
  if (typeof sealed !== 'string' || sealed === '') {
    return null;
  }
  // A seal that will not open means locked. Failing closed here costs one
  // unlock; failing open would mean storing the key in clear, which is the one
  // thing this path exists to avoid.
  return openVaultKey(sealed);
}

/**
 * Seals the vault key for the session.
 *
 * @returns `false` if it could not be sealed — no key is then stored, and the
 *   vault will ask to be unlocked again rather than be kept in clear.
 */
export async function saveVaultKey(userKeyB64: string): Promise<boolean> {
  if (!hasSession) {
    return false;
  }
  const sealed = await sealVaultKey(userKeyB64);
  if (sealed === null) {
    return false;
  }
  await chrome.storage.session.set({ [VAULT_KEY_KEY]: sealed });
  return true;
}

/**
 * Whether a session is open, **without reading the key**.
 *
 * What the service worker actually wanted every time it loaded the whole
 * session and compared it to `null`.
 */
export async function hasStoredSession(): Promise<boolean> {
  return (await loadStoredSession()) !== null;
}

export async function loadStoredSession(): Promise<StoredSession | null> {
  if (!hasSession) {
    return null;
  }
  const stored = await chrome.storage.session.get(SESSION_KEY);
  const s = stored[SESSION_KEY] as Partial<StoredSession> | undefined;
  const kdfConfig = readKdfConfig(s?.kdfConfig);
  if (
    s !== undefined &&
    typeof s.accessToken === 'string' &&
    typeof s.expiresAt === 'number' &&
    typeof s.serverUrl === 'string' &&
    typeof s.email === 'string' &&
    // Required, not optional: a session without them could not verify the
    // master password, and a `reprompt` item would open with no guard. The cost
    // is nil in practice — this storage is purged when the browser closes, so
    // only a session in progress at the moment of an extension update will ask
    // for one extra unlock.
    typeof s.localPasswordHash === 'string' &&
    kdfConfig !== null
  ) {
    return {
      accessToken: s.accessToken,
      refreshToken: typeof s.refreshToken === 'string' ? s.refreshToken : null,
      expiresAt: s.expiresAt,
      serverUrl: s.serverUrl,
      email: s.email,
      cachedSync: (s.cachedSync as SyncResponse | null | undefined) ?? null,
      localPasswordHash: s.localPasswordHash,
      kdfConfig,
    };
  }
  return null;
}

export async function saveStoredSession(session: StoredSession): Promise<void> {
  if (hasSession) {
    await chrome.storage.session.set({ [SESSION_KEY]: session });
  }
}

export async function clearStoredSession(): Promise<void> {
  if (hasSession) {
    // Both entries, always together: a key outliving its session would be a key
    // nothing could use and nothing would clear.
    await chrome.storage.session.remove([SESSION_KEY, VAULT_KEY_KEY]);
  }
  // And the other half. Either alone is inert, so this is belt and braces —
  // but a sealing key left behind outlives its purpose, and those accumulate.
  await forgetSealingKey();
}

// --- A page waiting on a passkey ---------------------------------------------

const PENDING_ASSERTION_KEY = 'pendingAssertion';

/** What a page is waiting for, as the service worker recorded it. */
export interface PendingAssertion {
  readonly id: string;
  /**
   * The page's origin **as the browser reported it**, never as the page said.
   * Everything that stops one site asking for another's passkey rests on this.
   */
  readonly origin: string;
  /** The `publicKey` options the page passed, serialised. Untrusted. */
  readonly options: Record<string, unknown>;
  readonly askedAt: number;
}

/** The ceremony in progress, or `null`. */
export async function loadPendingAssertion(): Promise<PendingAssertion | null> {
  if (!hasSession) {
    return null;
  }
  const stored = await chrome.storage.session.get(PENDING_ASSERTION_KEY);
  const value = stored[PENDING_ASSERTION_KEY] as Partial<PendingAssertion> | undefined;
  if (
    value === undefined ||
    typeof value.id !== 'string' ||
    typeof value.origin !== 'string' ||
    typeof value.options !== 'object' ||
    value.options === null
  ) {
    return null;
  }
  return {
    id: value.id,
    origin: value.origin,
    options: value.options,
    askedAt: typeof value.askedAt === 'number' ? value.askedAt : 0,
  };
}

/** Forgets it. The worker clears its own copy when the page goes away. */
export async function clearPendingAssertion(): Promise<void> {
  if (hasSession) {
    await chrome.storage.session.remove(PENDING_ASSERTION_KEY);
  }
}

// --- Auto-lock ---------------------------------------------------------------

/**
 * Name of the watch alarm. `chrome.alarms` is the only timer that survives the
 * death of an MV3 service worker: it, not a `setTimeout`, is what carries the
 * auto-lock.
 *
 * The alarm is **not** the deadline: it is a periodic heartbeat (one minute)
 * that compares the last-activity timestamp against the configured delay. A
 * deadline carried directly by the alarm would force it to be recreated on every
 * activity event — dozens of times a minute during ordinary browsing, and Chrome
 * rate-limits creation.
 */
export const AUTOLOCK_ALARM_NAME = 'zwarden-autolock';

/** The heartbeat's period. Locking can therefore be up to 1 min late. */
const WATCH_PERIOD_MINUTES = 1;

/** Key of the last-activity timestamp, in `chrome.storage.session`. */
const ACTIVITY_KEY = 'lastActivityAt';

/**
 * Minimum gap between two activity records. Without this threshold, a tab switch
 * would wake the service worker for a write on every single event; with it, the
 * timestamp lags reality by at most 20 s — negligible against a delay counted in
 * minutes.
 */
const ACTIVITY_THROTTLE_MS = 20_000;

/**
 * Records user activity: the countdown restarts.
 *
 * Callable from any trusted context (service worker, popup): the timestamp lives
 * in the same memory storage as the session.
 */
export async function recordActivity(now: number = Date.now()): Promise<void> {
  if (!hasSession) {
    return;
  }
  const stored = await chrome.storage.session.get(ACTIVITY_KEY);
  const previous = stored[ACTIVITY_KEY];
  if (typeof previous === 'number' && now - previous < ACTIVITY_THROTTLE_MS) {
    return;
  }
  await chrome.storage.session.set({ [ACTIVITY_KEY]: now });
}

/** The last-activity timestamp, `null` if none was ever recorded. */
export async function loadLastActivity(): Promise<number | null> {
  if (!hasSession) {
    return null;
  }
  const stored = await chrome.storage.session.get(ACTIVITY_KEY);
  const value = stored[ACTIVITY_KEY];
  return typeof value === 'number' ? value : null;
}

/**
 * Decides whether to lock. A pure function — it is what carries the rule, and it
 * alone is testable without a browser.
 *
 * @param lastActivityAt Last-activity timestamp, or `null`.
 * @param minutes Configured delay; 0 or less = never.
 * @param now Current instant.
 */
export function shouldAutoLock(
  lastActivityAt: number | null,
  minutes: number,
  now: number = Date.now(),
): boolean {
  if (minutes <= 0 || lastActivityAt === null) {
    return false;
  }
  return now - lastActivityAt >= minutes * 60_000;
}

/**
 * Arms the inactivity watch and records immediate activity. Called at unlock, on
 * reopening the popup onto a live session, and after the setting changes.
 * `minutes = 0` disarms.
 */
export async function startAutoLockWatch(minutes: number): Promise<void> {
  if (minutes <= 0) {
    await stopAutoLockWatch();
    return;
  }
  await recordActivity();
  if (hasAlarms) {
    // Awaited: without this, the function returns before the alarm exists, and a
    // caller locking right afterwards could create it after the `clear` meant to
    // remove it.
    await chrome.alarms.create(AUTOLOCK_ALARM_NAME, {
      delayInMinutes: WATCH_PERIOD_MINUTES,
      periodInMinutes: WATCH_PERIOD_MINUTES,
    });
  }
}

/**
 * Disarms the watch and forgets the timestamp. Called at lock time — otherwise
 * the heartbeat would keep waking the service worker for nothing.
 */
export async function stopAutoLockWatch(): Promise<void> {
  if (hasAlarms) {
    await chrome.alarms.clear(AUTOLOCK_ALARM_NAME);
  }
  if (hasSession) {
    await chrome.storage.session.remove(ACTIVITY_KEY);
  }
}

// --- Clipboard wipe ----------------------------------------------------------

/**
 * Name of the clipboard-wipe alarm.
 *
 * Carried by `chrome.alarms` rather than a `setTimeout` in the popup: a
 * `setTimeout` dies with the popup, and it is precisely when the user closes the
 * popup that the wipe matters. The popup keeps its own timer all the same — the
 * first of the two to land wins, and if the alarm fails the previous behaviour
 * remains.
 */
export const CLIPBOARD_ALARM_NAME = 'zwarden-clipboard';

/**
 * Minimum delay of an MV3 alarm, in seconds.
 *
 * Chrome raises any shorter alarm to thirty seconds. The ten-second setting is
 * therefore honoured by the popup while it is open, and the alarm serves only as
 * a net — later than asked, but where there used to be nothing.
 */
export const ALARM_MIN_SECONDS = 30;

/** Schedules the clipboard overwrite. `seconds <= 0` cancels. */
export async function scheduleClipboardWipe(seconds: number): Promise<void> {
  if (!hasAlarms) {
    return;
  }
  if (seconds <= 0) {
    await cancelClipboardWipe();
    return;
  }
  await chrome.alarms.create(CLIPBOARD_ALARM_NAME, {
    delayInMinutes: Math.max(seconds, ALARM_MIN_SECONDS) / 60,
  });
}

export async function cancelClipboardWipe(): Promise<void> {
  if (hasAlarms) {
    await chrome.alarms.clear(CLIPBOARD_ALARM_NAME);
  }
}

// --- Full lock ---------------------------------------------------------------

/**
 * Locks: purges everything the unlocked state left behind.
 *
 * Session, activity timestamp, alarm, pending capture and badge: the rule "to
 * lock is to purge everything" (`docs/EXTENSION.md` §2) is only worth something
 * if it is applied in a single gesture. Every caller that rewrote the list would
 * be one more chance to forget a piece — and the forgotten piece would be a
 * cleartext password.
 *
 * It does not destroy the caller's in-memory key: `userKey.destroy()` stays
 * their responsibility, since they alone hold it.
 */
export async function lockVault(): Promise<void> {
  await clearStoredSession();
  await clearPendingSave();
  await stopAutoLockWatch();
  await setSaveBadge(false);
  // The clipboard may hold a secret taken out of the vault: locking without
  // wiping it would leave outside what we have just put away. The alarm is
  // brought forward rather than cancelled.
  await scheduleClipboardWipe(1);
}
