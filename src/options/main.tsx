/**
 * @file The settings page.
 *
 * Edits the durable preferences (`chrome.storage.local`) and offers the hygiene
 * actions: lock, forget 2FA exemptions or the use ordering, regenerate the
 * device identifier. No key and no password passes through this page.
 *
 * This file only assembles: the state and the actions live in `useSettings`, the
 * rendering in `components/`.
 */

import { render } from 'preact';

import { ActionsSection, DeviceSection } from './components/ActionSections.js';
import { SaveSection, SecuritySection, ServerSection } from './components/SettingsSections.js';
import { useSettings } from './hooks/useSettings.js';

/** Displayed version. `dev` outside an extension context (Vite preview). */
function appVersion(): string {
  if (typeof chrome !== 'undefined' && typeof chrome.runtime?.getManifest === 'function') {
    return chrome.runtime.getManifest().version;
  }
  return 'dev';
}

function App() {
  const s = useSettings();

  return (
    <div class="page">
      <h1>Zwarden — Settings</h1>
      <p class="version">Version {appVersion()}</p>

      <form onSubmit={(e) => void s.save(e)}>
        <ServerSection settings={s.settings} patch={s.patch} />
        <SecuritySection settings={s.settings} patch={s.patch} />
        <SaveSection settings={s.settings} patch={s.patch} />

        <button type="submit">Save</button>
        <p class="status">{s.status}</p>
      </form>

      <ActionsSection
        onLockNow={() => void s.lockNow()}
        onForgetTwoFa={() => void s.forgetTwoFa()}
        onForgetNeverSave={() => void s.forgetNeverSave()}
        onForgetLastUsed={() => void s.forgetLastUsed()}
      />

      <DeviceSection deviceId={s.deviceId} onRegenerate={() => void s.regenerateDevice()} />
    </div>
  );
}

render(<App />, document.getElementById('app')!);
