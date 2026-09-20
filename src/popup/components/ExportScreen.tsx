/**
 * @file The encrypted export form.
 *
 * Purely presentational: it collects three secrets and raises them. It
 * encrypts nothing, reads no key and touches no file — `App` does all of that,
 * and `core/vault/exportFile.ts` decides what the file looks like.
 *
 * Three fields, and each is asked for a reason the form states rather than
 * assumes the user will infer:
 *
 * - the **master password**, once, so that items set to demand it again are in
 *   the backup. A backup missing exactly the items one was most careful about
 *   would be worse than none, because it would be trusted;
 * - the **passphrase**, twice. Nobody can recover it, so a typo made once is a
 *   file that will never open, discovered on the day it is needed.
 */

import { t } from '@shared/i18n.js';

export function ExportScreen({
  masterPassword,
  passphrase,
  confirmation,
  busy,
  error,
  onMasterPassword,
  onPassphrase,
  onConfirmation,
  onSubmit,
  onCancel,
}: {
  masterPassword: string;
  passphrase: string;
  confirmation: string;
  busy: string | null;
  error: string | null;
  onMasterPassword: (value: string) => void;
  onPassphrase: (value: string) => void;
  onConfirmation: (value: string) => void;
  onSubmit: (event: Event) => void;
  onCancel: () => void;
}) {
  return (
    <div>
      <header>
        <h1>{t('exportTitle')}</h1>
        <button class="quiet" onClick={onCancel}>
          {t('actionBack')}
        </button>
      </header>
      <main>
        <p class="hint">{t('exportIntro')}</p>
        <form onSubmit={onSubmit}>
          <label>
            {t('exportMaster')}
            <input
              type="password"
              autocomplete="current-password"
              value={masterPassword}
              onInput={(e) => onMasterPassword(e.currentTarget.value)}
              required
            />
          </label>
          <p class="hint-diag">{t('exportMasterHint')}</p>

          <label>
            {t('exportPassphrase')}
            <input
              type="password"
              autocomplete="new-password"
              value={passphrase}
              onInput={(e) => onPassphrase(e.currentTarget.value)}
              required
            />
          </label>
          <label>
            {t('exportPassphraseAgain')}
            <input
              type="password"
              autocomplete="new-password"
              value={confirmation}
              onInput={(e) => onConfirmation(e.currentTarget.value)}
              required
            />
          </label>
          <p class="hint-diag">{t('exportPassphraseHint')}</p>

          <button type="submit" disabled={busy !== null}>
            {t('exportRun')}
          </button>
        </form>
        {busy !== null && <p class="status">{busy}</p>}
        {error !== null && <p class="error">{error}</p>}
        <p class="hint-diag">{t('exportAlgorithm')}</p>
      </main>
    </div>
  );
}
