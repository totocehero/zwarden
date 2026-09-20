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

import { applyLocale, t } from '@shared/i18n.js';
import { loadSettings } from '@shared/storage.js';
import { render } from 'preact';
import { useEffect } from 'preact/hooks';

import { ActionsSection, DeviceSection } from './components/ActionSections.js';
import {
  InterfaceSection,
  SaveSection,
  SecuritySection,
  ServerSection,
} from './components/SettingsSections.js';
import { useSettings } from './hooks/useSettings.js';
import { followPageColorScheme } from '@shared/theme.js';

/** Displayed version. `dev` outside an extension context (Vite preview). */
function appVersion(): string {
  if (typeof chrome !== 'undefined' && typeof chrome.runtime?.getManifest === 'function') {
    return chrome.runtime.getManifest().version;
  }
  return 'dev';
}

function App() {
  const s = useSettings();

  // The settings page is the other extension page with a DOM: it settles the
  // toolbar icon too, so opening it is enough to correct one left stale.
  useEffect(followPageColorScheme, []);

  return (
    <div class="page">
      <h1>{t('appSettingsTitle')}</h1>
      <p class="version">{t('settingsVersion', appVersion())}</p>

      <form onSubmit={(e) => void s.save(e)}>
        <ServerSection settings={s.settings} patch={s.patch} />
        <InterfaceSection
          settings={s.settings}
          onLanguage={(locale) => void s.setLanguage(locale)}
        />
        <SecuritySection settings={s.settings} patch={s.patch} />
        <SaveSection settings={s.settings} patch={s.patch} />

        <button type="submit">{t('actionSave')}</button>
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

/**
 * The catalogue is in place before the first paint.
 *
 * `t` is synchronous, so a language arriving after the first render would
 * repaint every label under the reader's eyes. One storage read and — only when
 * a language has actually been chosen — one fetch of a packaged file stand
 * between the page opening and its first frame; following the browser, the
 * default, costs neither.
 */
void (async () => {
  await applyLocale((await loadSettings()).language);
  render(<App />, document.getElementById('app')!);
})();
