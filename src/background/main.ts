/**
 * @file Service worker.
 *
 * Rôle actuel : exécuter le verrouillage automatique. L'échéance est portée
 * par `chrome.alarms` — le seul minuteur qui survive à la mort du worker
 * MV3 — et (re)programmée par la popup à chaque activité. À l'échéance, la
 * session (clé de coffre, jetons) est purgée de `chrome.storage.session` :
 * la prochaine ouverture de popup retombe sur l'écran de déverrouillage.
 *
 * La cible décrite dans `docs/EXTENSION.md` — dérivation dans le worker,
 * popup sans clé — remplacera progressivement ce fichier.
 */

import { AUTOLOCK_ALARM_NAME, clearStoredSession } from '@shared/storage.js';

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === AUTOLOCK_ALARM_NAME) {
    void clearStoredSession();
  }
});

chrome.runtime.onInstalled.addListener((details) => {
  console.log(`Zwarden installé (${details.reason})`);
});

export {};
