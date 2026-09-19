/**
 * @file The two pre-vault screens: unlock and second factor.
 *
 * Kept in one file because they form a single sequence — the second factor only
 * appears after a first attempt — and share the header and the error reporting.
 *
 * Neither of them holds a secret beyond the keystrokes in progress: they raise
 * the entry, and it is `App` that calls `unlock()`.
 */

import { t } from '@shared/i18n.js';
import { IconEye } from './Icons.js';

/** Shared header: the name, and the way to the settings. */
function Header({ onOptions }: { onOptions: () => void }) {
  return (
    <header>
      <h1>Zwarden</h1>
      <button class="quiet" onClick={onOptions}>
        {t('actionSettings')}
      </button>
    </header>
  );
}

/** Status and error messages, in that order, below the form. */
function Status({ busy, error }: { busy: string | null; error: string | null }) {
  return (
    <>
      {busy !== null && <p class="status">{busy}</p>}
      {error !== null && <p class="error">{error}</p>}
    </>
  );
}

export function UnlockScreen({
  serverUrl,
  email,
  password,
  showPassword,
  busy,
  error,
  onServerUrl,
  onEmail,
  onPassword,
  onToggleShowPassword,
  onSubmit,
  onOptions,
}: {
  serverUrl: string;
  email: string;
  password: string;
  showPassword: boolean;
  busy: string | null;
  error: string | null;
  onServerUrl: (value: string) => void;
  onEmail: (value: string) => void;
  onPassword: (value: string) => void;
  onToggleShowPassword: () => void;
  onSubmit: () => void;
  onOptions: () => void;
}) {
  return (
    <div>
      <Header onOptions={onOptions} />
      <main>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            onSubmit();
          }}
        >
          <label>
            {t('unlockServer')}
            <input
              type="url"
              placeholder={t('unlockServerPlaceholder')}
              value={serverUrl}
              onInput={(e) => onServerUrl(e.currentTarget.value)}
              required
            />
          </label>
          <label>
            {t('unlockEmail')}
            <input
              type="email"
              value={email}
              onInput={(e) => onEmail(e.currentTarget.value)}
              required
            />
          </label>
          <label>
            {t('unlockMasterPassword')}
            <div class="password-field">
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onInput={(e) => onPassword(e.currentTarget.value)}
                required
              />
              <button
                type="button"
                class="eye"
                title={showPassword ? t('unlockHidePassword') : t('unlockShowPassword')}
                onClick={onToggleShowPassword}
              >
                <IconEye struck={showPassword} />
              </button>
            </div>
          </label>
          <button type="submit" disabled={busy !== null}>
            {t('unlockSubmit')}
          </button>
        </form>
        <Status busy={busy} error={error} />
      </main>
    </div>
  );
}

export function TwoFactorScreen({
  available,
  labels,
  choice,
  code,
  remember,
  busy,
  error,
  onChoice,
  onCode,
  onRemember,
  onSubmit,
  onBack,
  onOptions,
}: {
  /** Providers whose code the popup knows how to collect. */
  available: readonly string[];
  labels: Readonly<Record<string, string>>;
  choice: string;
  code: string;
  remember: boolean;
  busy: string | null;
  error: string | null;
  onChoice: (value: string) => void;
  onCode: (value: string) => void;
  onRemember: (value: boolean) => void;
  onSubmit: () => void;
  onBack: () => void;
  onOptions: () => void;
}) {
  return (
    <div>
      <Header onOptions={onOptions} />
      <main>
        <p class="status">{t('twoFaRequired')}</p>
        {available.length === 0 ? (
          <p class="error">{t('twoFaWebAuthnOnly')}</p>
        ) : (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              onSubmit();
            }}
          >
            <label>
              {t('twoFaMethod')}
              <select value={choice} onInput={(e) => onChoice(e.currentTarget.value)}>
                {available.map((p) => (
                  <option key={p} value={p}>
                    {labels[p]}
                  </option>
                ))}
              </select>
            </label>
            <label>
              {t('twoFaCode')}
              <input
                type="text"
                autocomplete="one-time-code"
                autofocus
                value={code}
                onInput={(e) => onCode(e.currentTarget.value)}
                required
              />
            </label>
            <label class="row">
              <input
                type="checkbox"
                checked={remember}
                onInput={(e) => onRemember(e.currentTarget.checked)}
              />
              {t('twoFaRemember')}
            </label>
            <button type="submit" disabled={busy !== null || code.trim() === ''}>
              {t('twoFaSubmit')}
            </button>
          </form>
        )}
        <button class="quiet" onClick={onBack}>
          {t('actionBack')}
        </button>
        <Status busy={busy} error={error} />
      </main>
    </div>
  );
}
