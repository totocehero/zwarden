/**
 * @file État et actions de la page de paramètres.
 *
 * Tout ce que la page fait — charger, enregistrer, et les cinq actions
 * d'hygiène — vit ici, hors du rendu. Les actions partagent un même motif : agir,
 * puis dire ce qui a été fait. Ce message compte plus qu'il n'y paraît : « oublier
 * les dispenses 2FA » et « réintégrer les sites exclus » sont sans effet visible,
 * et sans confirmation l'utilisateur ne peut pas savoir s'il a cliqué.
 */

import { useEffect, useState } from 'preact/hooks';

import {
  type AppSettings,
  DEFAULT_SETTINGS,
  clearAllRememberTokens,
  clearLastUsed,
  clearNeverSaveHosts,
  getDeviceId,
  loadSettings,
  lockVault,
  regenerateDeviceId,
  saveSettings,
  startAutoLockWatch,
} from '@shared/storage.js';

/** Bornes du délai réseau, en secondes. */
const TIMEOUT_MIN = 5;
const TIMEOUT_MAX = 120;

/** Durée d'affichage d'un message de confirmation. */
const FLASH_MS = 2500;

export interface Parametres {
  readonly settings: AppSettings;
  readonly deviceId: string;
  /** Message de confirmation courant, ou chaîne vide. */
  readonly statut: string;
  readonly patch: (champ: Partial<AppSettings>) => void;
  readonly save: (event: Event) => Promise<void>;
  readonly lockNow: () => Promise<void>;
  readonly forgetTwoFa: () => Promise<void>;
  readonly forgetNeverSave: () => Promise<void>;
  readonly forgetLastUsed: () => Promise<void>;
  readonly regenerateDevice: () => Promise<void>;
}

export function useParametres(): Parametres {
  const [settings, setSettings] = useState<AppSettings>(DEFAULT_SETTINGS);
  const [deviceId, setDeviceId] = useState('');
  const [statut, setStatut] = useState('');

  useEffect(() => {
    void (async () => {
      setSettings(await loadSettings());
      setDeviceId(await getDeviceId());
    })();
  }, []);

  function flash(message: string): void {
    setStatut(message);
    setTimeout(() => setStatut(''), FLASH_MS);
  }

  return {
    settings,
    deviceId,
    statut,

    patch(champ) {
      setSettings((courant) => ({ ...courant, ...champ }));
    },

    async save(event) {
      event.preventDefault();
      const timeoutSeconds = Math.min(
        TIMEOUT_MAX,
        Math.max(TIMEOUT_MIN, Math.round(settings.timeoutSeconds)),
      );
      const propre = { ...settings, timeoutSeconds };
      setSettings(propre);
      await saveSettings(propre);
      // Le nouveau délai s'applique au coffre déjà déverrouillé, sans attendre la
      // prochaine ouverture de popup.
      await startAutoLockWatch(propre.autoLockMinutes);
      flash('Paramètres enregistrés.');
    },

    async lockNow() {
      await lockVault();
      flash('Coffre verrouillé.');
    },

    async forgetTwoFa() {
      const n = await clearAllRememberTokens();
      flash(
        n === 0
          ? 'Aucune dispense 2FA à oublier.'
          : `${n} dispense(s) 2FA oubliée(s) — le second facteur sera redemandé.`,
      );
    },

    async forgetNeverSave() {
      const n = await clearNeverSaveHosts();
      flash(
        n === 0
          ? 'Aucun site exclu.'
          : `${n} site(s) réintégré(s) — l’enregistrement y sera de nouveau proposé.`,
      );
    },

    async forgetLastUsed() {
      await clearLastUsed();
      flash('Classement d’usage oublié — la liste reprend l’ordre du serveur.');
    },

    /**
     * Régénère l'identifiant d'appareil, après confirmation explicite.
     *
     * Les conséquences sont réelles côté serveur — session supplémentaire,
     * alerte « nouvel appareil », dispenses 2FA invalidées — et invisibles
     * depuis l'extension : d'où la confirmation, et l'énumération de ce qui va
     * se produire plutôt qu'un « êtes-vous sûr ? ».
     */
    async regenerateDevice() {
      const ok = confirm(
        'Régénérer l’identifiant d’appareil ?\n\n' +
          'Le serveur verra un nouvel appareil : une session supplémentaire apparaîtra ' +
          'dans la liste, une alerte « nouvel appareil » peut être envoyée, et les ' +
          'dispenses 2FA de cet appareil deviendront invalides.',
      );
      if (!ok) {
        return;
      }
      setDeviceId(await regenerateDeviceId());
      await clearAllRememberTokens();
      flash('Identifiant régénéré.');
    },
  };
}
