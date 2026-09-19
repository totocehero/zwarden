/**
 * @file The settings form's sections.
 *
 * Split by subject, as they are on screen. Each receives the current settings
 * and raises a partial change: none of them reads or writes storage, which
 * leaves `App` solely responsible for saving and for its confirmation message.
 */

import { type MessageKey, t } from '@shared/i18n.js';
import { type AppSettings, DEFAULT_SETTINGS } from '@shared/storage.js';

/** A partial settings change, raised to `App`. */
export type PatchSettings = (patch: Partial<AppSettings>) => void;

/** Values offered for auto-lock, in minutes. */
const AUTOLOCK_CHOICES: ReadonlyArray<readonly [number, MessageKey]> = [
  [0, 'settingsAutoLockOnClose'],
  [1, 'settingsMinutes1'],
  [5, 'settingsMinutes5'],
  [15, 'settingsMinutes15'],
  [30, 'settingsMinutes30'],
  [60, 'settingsHours1'],
  [240, 'settingsHours4'],
];

/** Values offered for the clipboard wipe, in seconds. */
const CLIPBOARD_CHOICES: ReadonlyArray<readonly [number, MessageKey]> = [
  [10, 'settingsSeconds10'],
  [30, 'settingsSeconds30'],
  [60, 'settingsMinute1'],
  [0, 'settingsNever'],
];

/** Instance, account, device name and network timeout. */
export function ServerSection({ settings, patch }: { settings: AppSettings; patch: PatchSettings }) {
  return (
    <section>
      <h2>{t('settingsServerSection')}</h2>
      <div class="fields">
        <label>
          {t('settingsInstanceUrl')}
          <input
            type="url"
            placeholder={t('unlockServerPlaceholder')}
            value={settings.serverUrl}
            onInput={(e) => patch({ serverUrl: e.currentTarget.value })}
          />
        </label>
        <label>
          {t('settingsAccountEmail')}
          <input
            type="email"
            value={settings.email}
            onInput={(e) => patch({ email: e.currentTarget.value })}
          />
        </label>
        <label>
          {t('settingsDeviceName')}
          <input
            type="text"
            value={settings.deviceName}
            onInput={(e) => patch({ deviceName: e.currentTarget.value })}
          />
        </label>
        <label>
          {t('settingsNetworkTimeout')}
          <input
            type="number"
            min="5"
            max="120"
            value={settings.timeoutSeconds}
            onInput={(e) => {
              const n = e.currentTarget.valueAsNumber;
              patch({ timeoutSeconds: Number.isFinite(n) ? n : DEFAULT_SETTINGS.timeoutSeconds });
            }}
          />
        </label>
      </div>
    </section>
  );
}

/** Auto-lock and clipboard wiping. */
export function SecuritySection({
  settings,
  patch,
}: {
  settings: AppSettings;
  patch: PatchSettings;
}) {
  return (
    <section>
      <h2>{t('settingsSecuritySection')}</h2>
      <div class="fields">
        <label>
          {t('settingsAutoLock')}
          <select
            value={String(settings.autoLockMinutes)}
            onInput={(e) => patch({ autoLockMinutes: Number(e.currentTarget.value) })}
          >
            {AUTOLOCK_CHOICES.map(([minutes, label]) => (
              <option key={minutes} value={String(minutes)}>
                {t(label)}
              </option>
            ))}
          </select>
        </label>
        <p class="hint">{t('settingsAutoLockHint')}</p>
        <label class="row">
          <input
            type="checkbox"
            checked={settings.lockOnSystemLock}
            onInput={(e) => patch({ lockOnSystemLock: e.currentTarget.checked })}
          />
          {t('settingsLockOnSystemLock')}
        </label>
        <p class="hint">{t('settingsLockOnSystemLockHint')}</p>
        <label>
          {t('settingsClipboard')}
          <select
            value={String(settings.clipboardClearSeconds)}
            onInput={(e) => patch({ clipboardClearSeconds: Number(e.currentTarget.value) })}
          >
            {CLIPBOARD_CHOICES.map(([seconds, label]) => (
              <option key={seconds} value={String(seconds)}>
                {t(label)}
              </option>
            ))}
          </select>
        </label>
        <p class="hint">{t('settingsClipboardHint')}</p>
      </div>
    </section>
  );
}

/** Offering to save an entered credential. */
export function SaveSection({ settings, patch }: { settings: AppSettings; patch: PatchSettings }) {
  return (
    <section>
      <h2>{t('settingsSaveSection')}</h2>
      <div class="fields">
        <label class="row">
          <input
            type="checkbox"
            checked={settings.offerToSave}
            onInput={(e) => patch({ offerToSave: e.currentTarget.checked })}
          />
          {t('settingsOfferToSave')}
        </label>
        <p class="hint">{t('settingsOfferToSaveHint')}</p>
      </div>
    </section>
  );
}
