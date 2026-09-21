/**
 * @file The settings page's state and actions.
 *
 * Everything the page does — load, save, and the five hygiene actions — lives
 * here, outside the render. The actions share one pattern: act, then say what
 * was done. That message matters more than it looks: "forget 2FA exemptions" and
 * "restore excluded sites" have no visible effect, and without confirmation the
 * user cannot know whether their click registered.
 */

import { applyLocale, t } from '@shared/i18n.js';
import { useEffect, useState } from 'preact/hooks';

import {
  type AppSettings,
  DEFAULT_SETTINGS,
  clearAllRememberTokens,
  clearAllServerPins,
  clearLastUsed,
  clearNeverSaveHosts,
  getDeviceId,
  loadSettings,
  lockVault,
  regenerateDeviceId,
  saveSettings,
  startAutoLockWatch,
} from '@shared/storage.js';

/** Network timeout bounds, in seconds. */
const TIMEOUT_MIN = 5;
const TIMEOUT_MAX = 120;

/** How long a confirmation message stays up. */
const FLASH_MS = 2500;

export interface Settings {
  readonly settings: AppSettings;
  readonly deviceId: string;
  /** The current confirmation message, or the empty string. */
  readonly status: string;
  readonly patch: (field: Partial<AppSettings>) => void;
  /** Flips a switch: applied and written at once, without the Save button. */
  readonly toggle: (field: Partial<AppSettings>) => Promise<void>;
  /** Changes the interface language, applied and saved at once. */
  readonly setLanguage: (locale: string) => Promise<void>;
  readonly save: (event: Event) => Promise<void>;
  readonly lockNow: () => Promise<void>;
  readonly forgetTwoFa: () => Promise<void>;
  readonly forgetNeverSave: () => Promise<void>;
  readonly forgetLastUsed: () => Promise<void>;
  /** Forgets the KDF parameters and organisation keys remembered per account. */
  readonly forgetPins: () => Promise<void>;
  readonly regenerateDevice: () => Promise<void>;
}

export function useSettings(): Settings {
  const [settings, setSettings] = useState<AppSettings>(DEFAULT_SETTINGS);
  const [deviceId, setDeviceId] = useState('');
  const [status, setStatus] = useState('');

  useEffect(() => {
    void (async () => {
      setSettings(await loadSettings());
      setDeviceId(await getDeviceId());
    })();
  }, []);

  function flash(message: string): void {
    setStatus(message);
    setTimeout(() => setStatus(''), FLASH_MS);
  }

  return {
    settings,
    deviceId,
    status,

    patch(field) {
      setSettings((current) => ({ ...current, ...field }));
    },

    /**
     * A switch acts when it is flipped; a field is saved when you are done
     * typing. That distinction was missing, and it cost real time.
     *
     * Every checkbox here went through `patch`, which only changes what is on
     * screen. Nothing reached storage until the Save button was pressed — and
     * two of these switches do their work *through* that write: the service
     * worker watches `chrome.storage.onChanged` and installs or removes the
     * content scripts in response. So ticking "answer passkey sign-ins" and
     * reloading the page looked exactly like a setting that refused to stick,
     * and the feature it controls was never installed at all.
     *
     * A text field is different: writing on every keystroke would be a storage
     * write per character, and half-typed values in between. Those keep the
     * button.
     */
    async toggle(field) {
      setSettings((current) => ({ ...current, ...field }));
      await saveSettings(field);
    },

    /**
     * Unlike every other field, the language applies and saves on the spot,
     * without waiting for the Save button.
     *
     * Two reasons, and neither is impatience. A language one cannot see the
     * effect of is a language one cannot check one has picked correctly — and
     * the catalogue has to be loaded before the page re-renders anyway, or the
     * labels would stay in the old language until something else forced a
     * render. Saving at the same moment simply keeps the popup from disagreeing
     * with the page that set it.
     */
    async setLanguage(locale) {
      await applyLocale(locale);
      setSettings((current) => ({ ...current, language: locale }));
      await saveSettings({ language: locale });
    },

    async save(event) {
      event.preventDefault();
      const timeoutSeconds = Math.min(
        TIMEOUT_MAX,
        Math.max(TIMEOUT_MIN, Math.round(settings.timeoutSeconds)),
      );
      const clean = { ...settings, timeoutSeconds };
      setSettings(clean);
      await saveSettings(clean);
      // The new delay applies to an already-unlocked vault, without waiting for
      // the popup to open again.
      await startAutoLockWatch(clean.autoLockMinutes);
      flash(t('settingsSaved'));
    },

    async lockNow() {
      await lockVault();
      flash(t('settingsVaultLocked'));
    },

    async forgetTwoFa() {
      const n = await clearAllRememberTokens();
      flash(
        n === 0 ? t('settingsNoTwoFa') : t('settingsTwoFaForgotten', String(n)),
      );
    },

    async forgetNeverSave() {
      const n = await clearNeverSaveHosts();
      flash(
        n === 0 ? t('settingsNoExcluded') : t('settingsExcludedRestored', String(n)),
      );
    },

    async forgetLastUsed() {
      await clearLastUsed();
      flash(t('settingsOrderingForgotten'));
    },

    async forgetPins() {
      const n = await clearAllServerPins();
      flash(n === 0 ? t('settingsNoPins') : t('settingsPinsForgotten', String(n)));
    },

    /**
     * Regenerates the device identifier, after explicit confirmation.
     *
     * The consequences are real server-side — an extra session, a "new device"
     * alert, invalidated 2FA exemptions — and invisible from the extension:
     * hence the confirmation, and the enumeration of what is about to happen
     * rather than an "are you sure?".
     */
    async regenerateDevice() {
      const ok = confirm(t('settingsRegenerateConfirm'));
      if (!ok) {
        return;
      }
      setDeviceId(await regenerateDeviceId());
      await clearAllRememberTokens();
      flash(t('settingsDeviceRegenerated'));
    },
  };
}
