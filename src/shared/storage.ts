/**
 * @file Stockage partagé entre popup, page d'options et service worker.
 *
 * Deux niveaux, à ne jamais confondre :
 *
 * - `chrome.storage.local` — préférences durables : paramètres, identifiant
 *   d'appareil, jetons de dispense 2FA. **Jamais de clé, jamais de mot de
 *   passe.**
 * - `chrome.storage.session` — état déverrouillé : clé de coffre et jetons de
 *   session. Mémoire pure, réservée aux contextes de confiance de
 *   l'extension, purgée à la fermeture du navigateur.
 *
 * Toutes les fonctions tolèrent l'absence de `chrome.*` (aperçu Vite, tests)
 * en se comportant comme un stockage vide.
 */

/** Paramètres de l'application, tels qu'édités dans la page d'options. */
export interface AppSettings {
  readonly serverUrl: string;
  readonly email: string;
  /** Nom affiché dans les sessions actives côté serveur. */
  readonly deviceName: string;
  /** Délai réseau, en secondes. */
  readonly timeoutSeconds: number;
  /**
   * Verrouillage automatique après inactivité, en minutes — « inactivité »
   * signifiant : popup non rouverte. 0 = jamais (verrouillage à la fermeture
   * du navigateur seulement).
   */
  readonly autoLockMinutes: number;
  /** Effacement du presse-papiers après une copie, en secondes. 0 = jamais. */
  readonly clipboardClearSeconds: number;
}

export const DEFAULT_SETTINGS: AppSettings = {
  serverUrl: '',
  email: '',
  deviceName: 'Zwarden',
  timeoutSeconds: 30,
  autoLockMinutes: 15,
  clipboardClearSeconds: 30,
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

/** Charge les paramètres, valeurs par défaut pour tout champ absent ou invalide. */
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
    'clipboardClearSeconds',
  ]);
  return {
    serverUrl: readString(stored, 'serverUrl', DEFAULT_SETTINGS.serverUrl),
    email: readString(stored, 'email', DEFAULT_SETTINGS.email),
    deviceName: readString(stored, 'deviceName', DEFAULT_SETTINGS.deviceName),
    timeoutSeconds: readNumber(stored, 'timeoutSeconds', DEFAULT_SETTINGS.timeoutSeconds),
    autoLockMinutes: readNumber(stored, 'autoLockMinutes', DEFAULT_SETTINGS.autoLockMinutes),
    clipboardClearSeconds: readNumber(
      stored,
      'clipboardClearSeconds',
      DEFAULT_SETTINGS.clipboardClearSeconds,
    ),
  };
}

/** Enregistre un sous-ensemble de paramètres. */
export async function saveSettings(patch: Partial<AppSettings>): Promise<void> {
  if (hasLocal) {
    await chrome.storage.local.set(patch);
  }
}

// --- Identifiant d'appareil --------------------------------------------------

/**
 * Identifiant d'appareil stable : généré une fois, persisté. Le régénérer à
 * chaque connexion créerait une session serveur par déverrouillage et
 * déclencherait les alertes « nouvel appareil ».
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

/** Régénère l'identifiant d'appareil. Le serveur verra un nouvel appareil. */
export async function regenerateDeviceId(): Promise<string> {
  const id = crypto.randomUUID();
  if (hasLocal) {
    await chrome.storage.local.set({ deviceId: id });
  }
  return id;
}

// --- Jetons de dispense 2FA --------------------------------------------------

const REMEMBER_PREFIX = '2faRemember:';

/** Clé de stockage du jeton de dispense, propre au couple compte/serveur. */
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
 * Oublie toutes les dispenses 2FA de cet appareil, tous comptes confondus.
 *
 * @returns Le nombre de dispenses supprimées.
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

// --- Session déverrouillée ---------------------------------------------------

/** Session déverrouillée, telle que conservée dans `chrome.storage.session`. */
export interface StoredSession {
  readonly userKeyB64: string;
  readonly accessToken: string;
  readonly refreshToken: string | null;
  readonly expiresAt: number;
  readonly serverUrl: string;
  readonly email: string;
}

const SESSION_KEY = 'session';

export async function loadStoredSession(): Promise<StoredSession | null> {
  if (!hasSession) {
    return null;
  }
  const stored = await chrome.storage.session.get(SESSION_KEY);
  const s = stored[SESSION_KEY] as Partial<StoredSession> | undefined;
  if (
    s !== undefined &&
    typeof s.userKeyB64 === 'string' &&
    typeof s.accessToken === 'string' &&
    typeof s.expiresAt === 'number' &&
    typeof s.serverUrl === 'string' &&
    typeof s.email === 'string'
  ) {
    return {
      userKeyB64: s.userKeyB64,
      accessToken: s.accessToken,
      refreshToken: typeof s.refreshToken === 'string' ? s.refreshToken : null,
      expiresAt: s.expiresAt,
      serverUrl: s.serverUrl,
      email: s.email,
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
    await chrome.storage.session.remove(SESSION_KEY);
  }
}

// --- Verrouillage automatique ------------------------------------------------

/**
 * Nom de l'alarme de verrouillage. `chrome.alarms` est le seul minuteur qui
 * survive à la mort du service worker MV3 : c'est lui, pas un `setTimeout`,
 * qui porte le verrouillage automatique.
 */
export const AUTOLOCK_ALARM_NAME = 'zwarden-autolock';

/**
 * (Re)programme le verrouillage automatique. Appelé à chaque activité
 * (déverrouillage, réouverture de popup avec session active) : l'échéance
 * repart de zéro. `minutes = 0` annule.
 */
export function scheduleAutoLock(minutes: number): void {
  if (!hasAlarms) {
    return;
  }
  if (minutes > 0) {
    chrome.alarms.create(AUTOLOCK_ALARM_NAME, { delayInMinutes: minutes });
  } else {
    void chrome.alarms.clear(AUTOLOCK_ALARM_NAME);
  }
}

export function cancelAutoLock(): void {
  if (hasAlarms) {
    void chrome.alarms.clear(AUTOLOCK_ALARM_NAME);
  }
}
