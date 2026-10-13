/**
 * @file The settings form's sections.
 *
 * Split by subject, as they are on screen. Each receives the current settings
 * and raises a partial change: none of them reads or writes storage, which
 * leaves `App` solely responsible for saving and for its confirmation message.
 */

import { AVAILABLE_LOCALES, FOLLOW_BROWSER, type MessageKey, t } from '@shared/i18n.js';
import { useEffect, useState } from 'preact/hooks';

import {
  type AppSettings,
  DEFAULT_SETTINGS,
  loadPasskeyHookStatus,
  loadUpdateStatus,
  type PasskeyHookStatus,
  saveUpdateStatus,
} from '@shared/storage.js';
import {
  checkForUpdate,
  fetchGitHubJson,
  isNewer,
  type UpdateStatus,
} from '@core/update/updateCheck.js';

/** A partial settings change, raised to `App`. */
export type PatchSettings = (patch: Partial<AppSettings>) => void;

/** A switch being flipped: applied and written at once, without the button. */
export type ToggleSetting = (patch: Partial<AppSettings>) => void;

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
/**
 * Interface language.
 *
 * Its own section rather than a field in another: it is the one setting that
 * changes nothing about how the vault behaves, and filing it under "Security"
 * or "Server" would say something untrue about it.
 */
export function InterfaceSection({
  settings,
  onLanguage,
}: {
  settings: AppSettings;
  onLanguage: (locale: string) => void;
}) {
  return (
    <section>
      <h2>{t('settingsInterfaceSection')}</h2>
      <div class="fields">
        <label>
          {t('settingsLanguage')}
          <select
            value={settings.language}
            onInput={(e) => onLanguage(e.currentTarget.value)}
          >
            <option value={FOLLOW_BROWSER}>{t('settingsLanguageFollow')}</option>
            {AVAILABLE_LOCALES.map(([code, name]) => (
              <option key={code} value={code}>
                {name}
              </option>
            ))}
          </select>
        </label>
        <p class="hint">{t('settingsLanguageHint')}</p>
      </div>
    </section>
  );
}

/**
 * Breach checking: the one switch that lets the extension talk to a third
 * party.
 *
 * Its own section, and off by default. The hint does not summarise the
 * trade-off into reassurance — it says what is sent, what cannot be learnt from
 * it, and what can. A user who reads it and declines has made the right
 * decision as surely as one who accepts.
 */
export function BreachSection({
  settings,
  toggle,
}: {
  settings: AppSettings;
  toggle: ToggleSetting;
}) {
  return (
    <section>
      <h2>{t('settingsBreachSection')}</h2>
      <div class="fields">
        <label class="row">
          <input
            type="checkbox"
            checked={settings.breachCheckEnabled}
            onInput={(e) => void toggle({ breachCheckEnabled: e.currentTarget.checked })}
          />
          {t('settingsBreachEnable')}
        </label>
        <p class="hint">{t('settingsBreachHint')}</p>
      </div>
    </section>
  );
}

/**
 * Passkey sign-in: the one switch that puts code inside every page.
 *
 * Its own section, off by default, and the hint is precise about what "inside
 * the page" means here — one browser function replaced, and nothing drawn. A
 * user weighing that deserves the distinction, since most extensions that
 * claim it inject an interface as well.
 */
export function PasskeySection({
  settings,
  toggle,
}: {
  settings: AppSettings;
  toggle: ToggleSetting;
}) {
  const [status, setStatus] = useState<PasskeyHookStatus | null>(null);

  // Re-read whenever the switch moves: the worker rewrites it in response, and
  // a stale "installed: no" beside a switch just turned on would be worse than
  // saying nothing.
  useEffect(() => {
    const timer = setTimeout(() => void loadPasskeyHookStatus().then(setStatus), 200);
    return () => clearTimeout(timer);
  }, [settings.passkeySignIn]);

  return (
    <section>
      <h2>{t('settingsPasskeySection')}</h2>
      <div class="fields">
        <label class="row">
          <input
            type="checkbox"
            checked={settings.passkeySignIn}
            onInput={(e) => void toggle({ passkeySignIn: e.currentTarget.checked })}
          />
          {t('settingsPasskeyEnable')}
        </label>
        {/* Whether the scripts are actually in pages, said here rather than
            left in a console. A failed installation is indistinguishable from
            a site that never asks for a passkey, which is how it went
            unnoticed through several rounds of looking elsewhere. */}
        {settings.passkeySignIn && status !== null && (
          <p class={status.registered ? 'hint' : 'error'}>
            {status.registered ? t('settingsPasskeyInstalled') : t('settingsPasskeyMissing')}
            {status.error !== null ? ` ${status.error}` : ''}
          </p>
        )}
        {settings.passkeySignIn && (
          <>
            <p class="hint-diag">{t('settingsPasskeyReload')}</p>
            {/* Where the traces are, said here rather than left to be
                discovered. They sit at verbose level because this runs on
                every page and the lines name the sites where passkeys are
                used — but a diagnostic nobody can find is one that does not
                exist, which cost several rounds of looking. */}
            <p class="hint-diag">{t('settingsPasskeyTraces')}</p>
          </>
        )}
        <p class="hint">{t('settingsPasskeyHint')}</p>
      </div>
    </section>
  );
}

export function SecuritySection({
  settings,
  patch,
  toggle,
}: {
  settings: AppSettings;
  patch: PatchSettings;
  toggle: ToggleSetting;
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
            onInput={(e) => void toggle({ lockOnSystemLock: e.currentTarget.checked })}
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
export function SaveSection({ settings, toggle }: { settings: AppSettings; toggle: ToggleSetting }) {
  return (
    <section>
      <h2>{t('settingsSaveSection')}</h2>
      <div class="fields">
        <label class="row">
          <input
            type="checkbox"
            checked={settings.offerToSave}
            onInput={(e) => void toggle({ offerToSave: e.currentTarget.checked })}
          />
          {t('settingsOfferToSave')}
        </label>
        <p class="hint">{t('settingsOfferToSaveHint')}</p>
      </div>
    </section>
  );
}

/**
 * Updates: a daily question to the repository, and a button to ask it now.
 *
 * The switch is off by default and the hint says exactly what the request
 * carries, in the same voice as the breach section: a request to a third party
 * is the kind of thing a password manager says out loud. The button needs no
 * switch — pressing it is the consent — and whatever either finds is shown
 * here with its date, so "up to date" can be told from "never looked".
 */
export function UpdateSection({
  settings,
  toggle,
  version,
}: {
  settings: AppSettings;
  toggle: ToggleSetting;
  version: string;
}) {
  const [status, setStatus] = useState<UpdateStatus | null>(null);
  const [checking, setChecking] = useState(false);

  // Re-read when the switch moves: the worker checks at once when it is turned
  // on, and the answer should appear here without a reload.
  useEffect(() => {
    void loadUpdateStatus().then(setStatus);
    const timer = setTimeout(() => void loadUpdateStatus().then(setStatus), 3000);
    return () => clearTimeout(timer);
  }, [settings.updateCheckEnabled]);

  async function checkNow(): Promise<void> {
    setChecking(true);
    try {
      const found = await checkForUpdate(fetchGitHubJson);
      await saveUpdateStatus(found);
      setStatus(found);
    } finally {
      setChecking(false);
    }
  }

  return (
    <section>
      <h2>{t('settingsUpdateSection')}</h2>
      <div class="fields">
        <label class="row">
          <input
            type="checkbox"
            checked={settings.updateCheckEnabled}
            onInput={(e) => void toggle({ updateCheckEnabled: e.currentTarget.checked })}
          />
          {t('settingsUpdateEnable')}
        </label>
        <p class="hint">{t('settingsUpdateHint')}</p>
        <div class="actions">
          <button type="button" class="secondary" disabled={checking} onClick={() => void checkNow()}>
            {checking ? t('settingsUpdateChecking') : t('settingsUpdateCheckNow')}
          </button>
        </div>
        <UpdateVerdict status={status} version={version} />
      </div>
    </section>
  );
}

/** What the last check found, in one line, with a link when there is somewhere to go. */
function UpdateVerdict({ status, version }: { status: UpdateStatus | null; version: string }) {
  if (status === null) {
    return <p class="hint">{t('settingsUpdateNever')}</p>;
  }
  const when = new Date(status.checkedAt).toLocaleString();
  if (status.latest === null) {
    return <p class="error">{t('settingsUpdateFailed', when)}</p>;
  }
  if (!isNewer(version, status.latest.version)) {
    return <p class="hint">{t('settingsUpdateUpToDate', status.latest.version, when)}</p>;
  }
  return (
    <p class="hint">
      {t('settingsUpdateAvailable', status.latest.version, version, when)}{' '}
      <a href={status.latest.url} target="_blank" rel="noopener noreferrer">
        {t('settingsUpdateOpen')}
      </a>
    </p>
  );
}
