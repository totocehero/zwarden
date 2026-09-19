/**
 * @file Service worker — verrouillage automatique et capture d'identifiants.
 *
 * ## Pourquoi le minuteur vit ici
 *
 * L'inactivité qui intéresse l'utilisateur est celle du **navigateur**, pas
 * celle de la popup : celui qui remplit des formulaires et change d'onglet
 * pendant une heure est actif, même s'il n'a pas rouvert le panneau. Seul le
 * service worker voit ces événements ; c'est donc lui qui tient l'horodatage
 * d'activité et qui tranche.
 *
 * ## Mécanique
 *
 * ```
 *   onglet activé ─┐
 *   fenêtre focus ─┼─► recordActivity()  (storage.session, seuil 20 s)
 *   navigation ────┤                                │
 *   popup ouverte ─┘  (battement propre à la popup) ▼
 *   alarme (1 min) ──────────► shouldAutoLock() ──► purge de la session
 *                                                        ▲
 *   session du système verrouillée ────────────────────────┘ (immédiat)
 * ```
 *
 * L'alarme est un battement, pas une échéance : la recréer à chaque
 * événement d'activité se heurterait à la limitation de débit de
 * `chrome.alarms`. Contrepartie assumée : le verrouillage peut tarder d'au
 * plus une minute sur le délai configuré.
 *
 * Le verrouillage de la session du système (`Win+L`, veille, écran de
 * verrouillage) court-circuite tout délai : on s'éloigne d'une machine bien
 * plus souvent qu'on ne ferme son navigateur, et c'est ce filet qui rend le
 * défaut « verrouiller à la fermeture du navigateur » tenable.
 *
 * L'activité n'est enregistrée que coffre déverrouillé — verrouillé, il n'y a
 * rien à préserver et le service worker n'a aucune raison d'écrire.
 *
 * ## Second rôle : la proposition d'enregistrement
 *
 * Le détecteur en page (`content/detector.ts`) n'envoie ici que ce que
 * l'utilisateur vient de taper. Le worker filtre — coffre déverrouillé ?
 * fonction activée ? site non exclu ? — puis range la capture en mémoire et
 * allume la pastille. Il ne décide **pas** s'il faut proposer : lui n'a pas
 * la clé, il ne sait pas ce que le coffre contient déjà. C'est la popup qui
 * tranche, à l'ouverture.
 *
 * La cible décrite dans `docs/EXTENSION.md` — dérivation dans le worker,
 * popup sans clé — remplacera progressivement ce fichier.
 */

import {
  AUTOLOCK_ALARM_NAME,
  loadLastActivity,
  loadNeverSaveHosts,
  loadSettings,
  loadStoredSession,
  lockVault,
  recordActivity,
  savePendingSave,
  setSaveBadge,
  shouldAutoLock,
  startAutoLockWatch,
  stopAutoLockWatch,
} from '@shared/storage.js';

/**
 * Enregistre une activité, sauf coffre verrouillé. La lecture de session
 * précède l'écriture : sans elle, chaque changement d'onglet ferait écrire le
 * service worker alors qu'il n'y a aucune échéance à repousser.
 */
async function onActivity(): Promise<void> {
  if ((await loadStoredSession()) === null) {
    return;
  }
  await recordActivity();
}

/** Verrouille — purge complète, `lockVault` en porte la liste. */
async function lockNow(): Promise<void> {
  await lockVault();
}

/** Un battement : compare l'inactivité au délai configuré. */
async function tick(): Promise<void> {
  if ((await loadStoredSession()) === null) {
    // Session déjà partie (verrouillage manuel, redémarrage du navigateur) :
    // le battement n'a plus d'objet.
    await stopAutoLockWatch();
    return;
  }

  const { autoLockMinutes } = await loadSettings();
  if (autoLockMinutes <= 0) {
    // Réglage passé à « fermeture du navigateur » depuis l'armement.
    await stopAutoLockWatch();
    return;
  }

  const last = await loadLastActivity();
  if (last === null) {
    // Horodatage perdu : on repart de maintenant plutôt que de verrouiller
    // sur une absence d'information.
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
  }
});

/**
 * Transitions d'état du système. Seul `locked` verrouille — `idle` (aucune
 * saisie depuis quelques minutes) ne dit rien de la présence de
 * l'utilisateur, qui peut lire son écran. `active` compte comme activité :
 * revenir d'une veille repousse l'échéance.
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

// Seul l'onglet au premier plan compte : une page d'arrière-plan qui se
// rafraîchit toute seule ne doit pas maintenir le coffre ouvert.
chrome.tabs.onUpdated.addListener((_tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading' && tab.active) {
    void onActivity();
  }
});

/**
 * Réveil du navigateur ou mise à jour de l'extension : `storage.session` est
 * purgé, mais les alarmes, elles, sont persistées. On remet les deux d'accord
 * plutôt que de laisser un battement tourner sur un coffre verrouillé.
 */
async function resync(): Promise<void> {
  await applyDetectorRegistration();
  if ((await loadStoredSession()) === null) {
    await lockVault();
    return;
  }
  const { autoLockMinutes } = await loadSettings();
  await startAutoLockWatch(autoLockMinutes);
}

chrome.runtime.onStartup.addListener(() => void resync());

chrome.runtime.onInstalled.addListener((details) => {
  console.log(`Zwarden installé (${details.reason})`);
  void resync();
});

export {};

// --- Capture d'identifiants --------------------------------------------------

/** Identifiant de l'enregistrement dynamique du détecteur. */
const DETECTOR_SCRIPT_ID = 'zwarden-detector';

/** Type de message émis par le détecteur. */
const CREDENTIALS_MESSAGE = 'zwarden-credentials';

interface CredentialsMessage {
  readonly type: string;
  readonly username: unknown;
  readonly password: unknown;
}

/**
 * Range une capture et allume la pastille — ou l'ignore, silencieusement.
 *
 * Quatre refus, tous silencieux : ce qui ne vient pas d'un onglet (donc pas
 * du détecteur), la fonction désactivée, le coffre verrouillé — on ne garde
 * pas un mot de passe en clair en mémoire quand tout le reste est purgé — et
 * les sites que l'utilisateur a exclus.
 *
 * **L'origine ne vient pas du message.** Elle est lue sur `sender`, que le
 * navigateur remplit lui-même : un champ du message est déclaratif, alors que
 * celui-ci est constaté. L'écart compte, parce que c'est cette origine qui
 * devient l'URI de l'item créé et la clé du rapprochement — une origine
 * choisie par l'émetteur ferait enregistrer un mot de passe sous l'adresse
 * d'un autre site.
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
  if (!offerToSave || (await loadStoredSession()) === null) {
    return;
  }
  if ((await loadNeverSaveHosts()).includes(host)) {
    return;
  }

  await savePendingSave({ origin, host, username, password, capturedAt: Date.now() });
  await setSaveBadge(true);
  // Taper un mot de passe est une activité : elle repousse l'échéance au même
  // titre qu'un changement d'onglet.
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
  // Aucune réponse asynchrone attendue : ne pas retourner `true`.
  return false;
});

/**
 * Aligne la présence du détecteur sur le réglage.
 *
 * Enregistrement dynamique plutôt que déclaration dans le manifest : réglage
 * désactivé, il n'y a **aucun** script injecté dans les pages — pas un script
 * qui se tait, pas de script du tout. C'est la différence entre une promesse
 * et une garantie.
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
        // Mêmes hôtes que les permissions du manifest, cadre principal
        // seulement : les iframes sont explicitement hors périmètre (§4).
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

// Le réglage se modifie depuis la page d'options, dans un autre contexte :
// c'est le stockage qui le notifie.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && 'offerToSave' in changes) {
    void applyDetectorRegistration();
  }
});
