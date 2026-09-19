/**
 * @file The settings form's sections.
 *
 * Split by subject, as they are on screen. Each receives the current settings
 * and raises a partial change: none of them reads or writes storage, which
 * leaves `App` solely responsible for saving and for its confirmation message.
 */

import { type AppSettings, DEFAULT_SETTINGS } from '@shared/storage.js';

/** A partial settings change, raised to `App`. */
export type PatchSettings = (patch: Partial<AppSettings>) => void;

/** Values offered for auto-lock, in minutes. */
const AUTOLOCK_CHOICES: ReadonlyArray<readonly [number, string]> = [
  [0, 'When the browser closes'],
  [1, '1 minute'],
  [5, '5 minutes'],
  [15, '15 minutes'],
  [30, '30 minutes'],
  [60, '1 hour'],
  [240, '4 hours'],
];

/** Values offered for the clipboard wipe, in seconds. */
const CLIPBOARD_CHOICES: ReadonlyArray<readonly [number, string]> = [
  [10, '10 seconds'],
  [30, '30 seconds'],
  [60, '1 minute'],
  [0, 'Never'],
];

/** Instance, account, device name and network timeout. */
export function ServerSection({ settings, patch }: { settings: AppSettings; patch: PatchSettings }) {
  return (
    <section>
      <h2>Server</h2>
      <div class="fields">
        <label>
          Instance URL
          <input
            type="url"
            placeholder="https://vault.example.com"
            value={settings.serverUrl}
            onInput={(e) => patch({ serverUrl: e.currentTarget.value })}
          />
        </label>
        <label>
          Account email
          <input
            type="email"
            value={settings.email}
            onInput={(e) => patch({ email: e.currentTarget.value })}
          />
        </label>
        <label>
          Device name (shown among the server's active sessions)
          <input
            type="text"
            value={settings.deviceName}
            onInput={(e) => patch({ deviceName: e.currentTarget.value })}
          />
        </label>
        <label>
          Network timeout (seconds, 5–120)
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
      <h2>Security</h2>
      <div class="fields">
        <label>
          Auto-lock after inactivity
          <select
            value={String(settings.autoLockMinutes)}
            onInput={(e) => patch({ autoLockMinutes: Number(e.currentTarget.value) })}
          >
            {AUTOLOCK_CHOICES.map(([minutes, label]) => (
              <option key={minutes} value={String(minutes)}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <p class="hint">
          “Inactivity” means: no tab, window or page change, and the popup closed. Simply
          browsing is therefore enough to keep the vault open. Locking may run up to a minute
          past the chosen delay. When the browser closes, the vault is locked regardless: the
          key only ever lives in memory.
        </p>
        <label class="row">
          <input
            type="checkbox"
            checked={settings.lockOnSystemLock}
            onInput={(e) => patch({ lockOnSystemLock: e.currentTarget.checked })}
          />
          Also lock when the computer's session locks
        </label>
        <p class="hint">
          Lock screen, sleep, “Win+L”: the vault locks immediately, whatever the delay above.
          Walking away from your machine happens more often than closing your browser.
        </p>
        <label>
          Wipe the clipboard after a copy
          <select
            value={String(settings.clipboardClearSeconds)}
            onInput={(e) => patch({ clipboardClearSeconds: Number(e.currentTarget.value) })}
          >
            {CLIPBOARD_CHOICES.map(([seconds, label]) => (
              <option key={seconds} value={String(seconds)}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <p class="hint">
          Two wipes back this up: a timer that honours the exact delay while the popup is open,
          and an alarm that survives its closing but that Chrome raises to thirty seconds
          minimum.
        </p>
      </div>
    </section>
  );
}

/** Offering to save an entered credential. */
export function SaveSection({ settings, patch }: { settings: AppSettings; patch: PatchSettings }) {
  return (
    <section>
      <h2>Saving credentials</h2>
      <div class="fields">
        <label class="row">
          <input
            type="checkbox"
            checked={settings.offerToSave}
            onInput={(e) => patch({ offerToSave: e.currentTarget.checked })}
          />
          Offer to save credentials entered on an unknown site
        </label>
        <p class="hint">
          A detector watches sign-in forms and signals an entry with a badge on the icon; the
          offer appears when the popup opens. Nothing is added to the vault without a click,
          nothing is injected into the page, and nothing is sent anywhere but to the extension.
          Unticked, the detector is not injected at all — not a silent script, no script.
        </p>
      </div>
    </section>
  );
}
