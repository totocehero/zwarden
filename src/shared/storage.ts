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

import type { KdfConfig } from '../core/crypto/kdf.js';
import { KdfType } from '../core/crypto/kdf.js';
import type { SyncResponse } from '../core/api/models.js';
import {
  DEFAULT_PASSWORD_OPTIONS,
  type PasswordOptions,
} from '../core/generator/password.js';

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
   * signifiant : aucune activité dans le navigateur (changement d'onglet,
   * de fenêtre, navigation) ni dans la popup. 0 = jamais (verrouillage à la
   * fermeture du navigateur seulement), qui est le défaut.
   */
  readonly autoLockMinutes: number;
  /**
   * Verrouiller dès que la session du système est verrouillée (écran de
   * veille, `Win+L`, suspension). Indépendant du délai d'inactivité : c'est
   * le filet qui rend le défaut « fermeture du navigateur » tenable — on
   * s'éloigne d'une machine bien plus souvent qu'on ne ferme son navigateur.
   */
  readonly lockOnSystemLock: boolean;
  /**
   * Proposer d'enregistrer un identifiant saisi sur un site absent du coffre.
   * Désactivé, le détecteur n'est même pas injecté dans les pages.
   */
  readonly offerToSave: boolean;
  /** Effacement du presse-papiers après une copie, en secondes. 0 = jamais. */
  readonly clipboardClearSeconds: number;
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
    'lockOnSystemLock',
    'offerToSave',
    'clipboardClearSeconds',
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

// --- Proposition d'enregistrement --------------------------------------------

/**
 * Identifiants saisis dans une page, en attente d'une décision de
 * l'utilisateur.
 *
 * **Contient un mot de passe en clair** : vit donc dans
 * `chrome.storage.session` — mémoire pure, purgée à la fermeture du
 * navigateur — au même titre que la clé du coffre, et jamais sur disque. Une
 * seule capture est retenue à la fois : la dernière saisie est celle qui
 * intéresse l'utilisateur, et empiler des mots de passe en clair serait une
 * surface gratuite.
 */
export interface PendingSave {
  /** Origine de la page (schéma + hôte + port), pour l'URI de l'item créé. */
  readonly origin: string;
  /** Hôte seul, pour l'affichage et la liste d'exclusion. */
  readonly host: string;
  readonly username: string;
  readonly password: string;
  /** Instant de la capture, pour l'expiration. */
  readonly capturedAt: number;
}

const PENDING_KEY = 'pendingSave';

/**
 * Durée de vie d'une capture. Passé ce délai, la proposition ne se rattache
 * plus à rien dans la tête de l'utilisateur, et garder un mot de passe en
 * clair en mémoire pour rien n'a aucune contrepartie.
 */
export const PENDING_TTL_MS = 10 * 60_000;

export async function savePendingSave(pending: PendingSave): Promise<void> {
  if (hasSession) {
    await chrome.storage.session.set({ [PENDING_KEY]: pending });
  }
}

/** Capture en attente, `null` si aucune ou si elle a expiré. */
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

// --- Badge de l'icône --------------------------------------------------------

const hasAction = typeof chrome !== 'undefined' && typeof chrome.action !== 'undefined';

/**
 * Pastille sur l'icône de l'extension, unique signal visible d'une
 * proposition en attente. Volontairement muet : pas de notification système,
 * pas d'interface injectée dans la page.
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

// --- Sites où ne jamais proposer --------------------------------------------

const NEVER_SAVE_KEY = 'neverSaveHosts';

/** Hôtes pour lesquels l'utilisateur a demandé qu'on ne propose plus rien. */
export async function loadNeverSaveHosts(): Promise<readonly string[]> {
  if (!hasLocal) {
    return [];
  }
  const stored = await chrome.storage.local.get(NEVER_SAVE_KEY);
  const value = stored[NEVER_SAVE_KEY];
  return Array.isArray(value) ? value.filter((h): h is string => typeof h === 'string') : [];
}

export async function addNeverSaveHost(host: string): Promise<void> {
  if (!hasLocal) {
    return;
  }
  const hosts = await loadNeverSaveHosts();
  if (!hosts.includes(host)) {
    await chrome.storage.local.set({ [NEVER_SAVE_KEY]: [...hosts, host] });
  }
}

/** Vide la liste d'exclusion. @returns Le nombre d'hôtes oubliés. */
export async function clearNeverSaveHosts(): Promise<number> {
  const hosts = await loadNeverSaveHosts();
  if (hasLocal && hosts.length > 0) {
    await chrome.storage.local.remove(NEVER_SAVE_KEY);
  }
  return hosts.length;
}

// --- Options du générateur ---------------------------------------------------

const GENERATOR_KEY = 'generatorOptions';

/**
 * Préférences du générateur de mots de passe.
 *
 * Stockage à part plutôt qu'ajout à `AppSettings` : ce sont des réglages
 * d'outil, modifiés depuis la popup au fil de l'usage, pas des paramètres
 * d'application édités dans la page d'options. Les mêler ferait écrire la
 * popup dans le même objet que la page d'options, et l'un écraserait l'autre.
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

// --- Usage récent ------------------------------------------------------------

/**
 * Horodatages de dernier usage, par identifiant d'item. Persistés dans
 * `chrome.storage.local` : l'intérêt du classement est justement de survivre
 * à la fermeture du navigateur.
 *
 * **Ce que cela expose.** Des identifiants d'items (UUID opaques) et des
 * horodatages — jamais un nom, une URL, un identifiant de connexion ni un
 * mot de passe. Qui lit le profil du navigateur apprend qu'un item a été
 * utilisé à telle heure, pas lequel ni sur quel site. La règle de
 * `docs/CRYPTO.md` — aucune clé, aucun secret sur disque — tient.
 */
const LAST_USED_KEY = 'lastUsed';

/**
 * Nombre d'items retenus. Au-delà, les plus anciens sont oubliés : le
 * classement ne sert que pour la tête de liste, et un coffre de plusieurs
 * milliers d'items ne doit pas faire grossir le stockage indéfiniment.
 */
const LAST_USED_MAX = 100;

/** Horodatages de dernier usage, vides si aucun n'a été enregistré. */
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
 * Note qu'un item vient de servir — copie, remplissage ou révélation.
 *
 * @param id Identifiant de l'item.
 * @param now Instant courant.
 */
export async function markUsed(id: string, now: number = Date.now()): Promise<void> {
  if (!hasLocal) {
    return;
  }
  const merged = { ...(await loadLastUsed()), [id]: now };
  await chrome.storage.local.set({ [LAST_USED_KEY]: pruneLastUsed(merged) });
}

/** Ne garde que les `LAST_USED_MAX` usages les plus récents. Fonction pure. */
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

/** Oublie tout le classement d'usage. */
export async function clearLastUsed(): Promise<void> {
  if (hasLocal) {
    await chrome.storage.local.remove(LAST_USED_KEY);
  }
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
  /**
   * Dernière réponse de synchronisation, telle quelle — champs sensibles
   * toujours chiffrés. Permet d'afficher le coffre immédiatement à
   * l'ouverture de la popup, avant le rafraîchissement réseau. Même stockage
   * mémoire que la clé : aucune surface supplémentaire.
   */
  readonly cachedSync: SyncResponse | null;
  /**
   * Hash local du mot de passe maître, tel que produit par `unlock`.
   *
   * Sert à vérifier une nouvelle saisie **sans réseau** quand un item exige
   * de redemander le mot de passe (`reprompt`). Il ne peut pas être rejoué
   * auprès du serveur — son nombre d'itérations diffère du hash
   * d'autorisation — et il vit dans le même stockage mémoire que la clé du
   * coffre, laquelle est strictement plus sensible : aucune surface nouvelle.
   */
  readonly localPasswordHash: string;
  /** Paramètres KDF du compte, pour redériver la clé maître à la vérification. */
  readonly kdfConfig: KdfConfig;
}

/**
 * Relit des paramètres KDF stockés. `null` si la forme ne correspond à aucun
 * des deux KDF admis — on préfère traiter la session comme absente plutôt que
 * de garder une session dont on ne saurait plus vérifier le mot de passe.
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

export async function loadStoredSession(): Promise<StoredSession | null> {
  if (!hasSession) {
    return null;
  }
  const stored = await chrome.storage.session.get(SESSION_KEY);
  const s = stored[SESSION_KEY] as Partial<StoredSession> | undefined;
  const kdfConfig = readKdfConfig(s?.kdfConfig);
  if (
    s !== undefined &&
    typeof s.userKeyB64 === 'string' &&
    typeof s.accessToken === 'string' &&
    typeof s.expiresAt === 'number' &&
    typeof s.serverUrl === 'string' &&
    typeof s.email === 'string' &&
    // Exigés, non facultatifs : une session sans eux ne saurait pas vérifier
    // le mot de passe maître, et un item `reprompt` s'ouvrirait sans garde.
    // Le coût est nul en pratique — ce stockage est purgé à la fermeture du
    // navigateur, donc seule une session en cours au moment d'une mise à jour
    // de l'extension demandera un déverrouillage de plus.
    typeof s.localPasswordHash === 'string' &&
    kdfConfig !== null
  ) {
    return {
      userKeyB64: s.userKeyB64,
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
    await chrome.storage.session.remove(SESSION_KEY);
  }
}

// --- Verrouillage automatique ------------------------------------------------

/**
 * Nom de l'alarme de surveillance. `chrome.alarms` est le seul minuteur qui
 * survive à la mort du service worker MV3 : c'est lui, pas un `setTimeout`,
 * qui porte le verrouillage automatique.
 *
 * L'alarme n'est **pas** l'échéance : elle est un battement périodique (une
 * minute) qui compare l'horodatage de dernière activité au délai configuré.
 * Une échéance portée directement par l'alarme obligerait à la recréer à
 * chaque événement d'activité — dizaines de fois par minute lors d'une
 * navigation normale, et Chrome limite le débit de création.
 */
export const AUTOLOCK_ALARM_NAME = 'zwarden-autolock';

/** Période du battement. Le verrouillage peut donc tarder d'au plus 1 min. */
const WATCH_PERIOD_MINUTES = 1;

/** Clé de l'horodatage de dernière activité, dans `chrome.storage.session`. */
const ACTIVITY_KEY = 'lastActivityAt';

/**
 * Écriture minimale entre deux enregistrements d'activité. Sans ce seuil, un
 * changement d'onglet réveillerait le service worker pour une écriture à
 * chaque événement ; avec lui, l'horodatage retarde d'au plus 20 s sur la
 * réalité — négligeable face à un délai qui se compte en minutes.
 */
const ACTIVITY_THROTTLE_MS = 20_000;

/**
 * Enregistre une activité de l'utilisateur : le compte à rebours repart.
 *
 * Appelable depuis n'importe quel contexte de confiance (service worker,
 * popup) : l'horodatage vit dans le même stockage mémoire que la session.
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

/** Horodatage de la dernière activité, `null` si aucune n'a été enregistrée. */
export async function loadLastActivity(): Promise<number | null> {
  if (!hasSession) {
    return null;
  }
  const stored = await chrome.storage.session.get(ACTIVITY_KEY);
  const value = stored[ACTIVITY_KEY];
  return typeof value === 'number' ? value : null;
}

/**
 * Décide s'il faut verrouiller. Fonction pure — c'est elle qui porte la règle,
 * et elle seule est testable sans navigateur.
 *
 * @param lastActivityAt Horodatage de dernière activité, ou `null`.
 * @param minutes Délai configuré ; 0 ou moins = jamais.
 * @param now Instant courant.
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
 * Arme la surveillance d'inactivité et enregistre une activité immédiate.
 * Appelé au déverrouillage, à la réouverture de la popup sur une session
 * vivante, et après modification du réglage. `minutes = 0` désarme.
 */
export async function startAutoLockWatch(minutes: number): Promise<void> {
  if (minutes <= 0) {
    await stopAutoLockWatch();
    return;
  }
  await recordActivity();
  if (hasAlarms) {
    // Attendue : sans cela, la fonction rend la main avant que l'alarme
    // existe, et l'appelant qui verrouille juste après pourrait la créer
    // après le `clear` censé l'effacer.
    await chrome.alarms.create(AUTOLOCK_ALARM_NAME, {
      delayInMinutes: WATCH_PERIOD_MINUTES,
      periodInMinutes: WATCH_PERIOD_MINUTES,
    });
  }
}

/**
 * Désarme la surveillance et oublie l'horodatage. Appelé au verrouillage —
 * sans quoi le battement continuerait à réveiller le service worker pour rien.
 */
export async function stopAutoLockWatch(): Promise<void> {
  if (hasAlarms) {
    await chrome.alarms.clear(AUTOLOCK_ALARM_NAME);
  }
  if (hasSession) {
    await chrome.storage.session.remove(ACTIVITY_KEY);
  }
}

// --- Effacement du presse-papiers --------------------------------------------

/**
 * Nom de l'alarme d'effacement du presse-papiers.
 *
 * Portée par `chrome.alarms` et non par un `setTimeout` de la popup : un
 * `setTimeout` meurt avec la popup, et c'est précisément quand l'utilisateur
 * referme la popup que l'effacement compte. La popup garde tout de même son
 * minuteur — le premier des deux qui aboutit gagne, et si l'alarme échoue le
 * comportement d'avant subsiste.
 */
export const CLIPBOARD_ALARM_NAME = 'zwarden-clipboard';

/**
 * Délai minimal d'une alarme MV3, en secondes.
 *
 * Chrome ramène à trente secondes toute alarme plus courte. Le réglage de dix
 * secondes reste donc tenu par la popup tant qu'elle est ouverte, et l'alarme ne
 * sert que de filet — plus tard que demandé, mais là où il n'y avait rien.
 */
export const ALARM_MIN_SECONDS = 30;

/** Programme l'écrasement du presse-papiers. `seconds <= 0` annule. */
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

// --- Verrouillage complet ----------------------------------------------------

/**
 * Verrouille : purge de tout ce que l'état déverrouillé a laissé derrière lui.
 *
 * Session, horodatage d'activité, alarme, capture en attente et pastille : la
 * règle « verrouiller, c'est tout purger » (`docs/EXTENSION.md` §2) n'a de
 * valeur que si elle est appliquée d'un seul geste. Chaque appelant qui
 * réécrirait la liste serait une occasion d'en oublier un morceau — et le
 * morceau oublié serait un mot de passe en clair.
 *
 * Ne détruit pas la clé en mémoire de l'appelant : `userKey.destroy()` reste
 * à sa charge, lui seul la détient.
 */
export async function lockVault(): Promise<void> {
  await clearStoredSession();
  await clearPendingSave();
  await stopAutoLockWatch();
  await setSaveBadge(false);
  // Le presse-papiers peut contenir un secret sorti du coffre : verrouiller sans
  // l'effacer laisserait dehors ce qu'on vient de ranger. L'alarme est avancée
  // au plus tôt plutôt qu'annulée.
  await scheduleClipboardWipe(1);
}
