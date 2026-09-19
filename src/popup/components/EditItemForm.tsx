/**
 * @file The item edit form.
 *
 * Purely presentational: it receives cleartext values already decrypted by
 * `App`, and raises every keystroke. It encrypts nothing, calls no network and
 * does not know what a key is — which puts it outside the vault logic
 * (`docs/EXTENSION.md` §3).
 *
 * The login-specific fields (username, password, TOTP, URIs) only appear for
 * type 1: showing them empty on a secure note would suggest they can be saved
 * there.
 */

import type { JSX } from 'preact';

import { t } from '@shared/i18n.js';
import type { PasskeyView } from '@core/vault/cipherService.js';

import { IconDice, IconEye } from './Icons.js';

/** The form's cleartext values. */
export interface EditForm {
  name: string;
  username: string;
  password: string;
  totp: string;
  notes: string;
  /** One URI per line. */
  uris: string;
}

export const EMPTY_EDIT: EditForm = {
  name: '',
  username: '',
  password: '',
  totp: '',
  notes: '',
  uris: '',
};

export function EditItemForm({
  form,
  isLogin,
  showPassword,
  passkeys,
  busy,
  error,
  generator,
  onPatch,
  onToggleShowPassword,
  onOpenGenerator,
  onSubmit,
  onCancel,
}: {
  form: EditForm;
  isLogin: boolean;
  showPassword: boolean;
  passkeys: readonly PasskeyView[];
  busy: string | null;
  error: string | null;
  /** The generator panel, rendered by the caller — or nothing if it is closed. */
  generator: JSX.Element | null;
  onPatch: (patch: Partial<EditForm>) => void;
  onToggleShowPassword: () => void;
  onOpenGenerator: () => void;
  onSubmit: (event: Event) => void;
  onCancel: () => void;
}) {
  return (
    <div>
      <header>
        <h1>Zwarden</h1>
        <button class="quiet" onClick={onCancel}>
          {t('actionBack')}
        </button>
      </header>
      <main>
        <form onSubmit={onSubmit}>
          <label>
            {t('editName')}
            <input
              type="text"
              value={form.name}
              onInput={(e) => onPatch({ name: e.currentTarget.value })}
              required
            />
          </label>
          {isLogin && (
            <label>
              {t('editUsername')}
              <input
                type="text"
                value={form.username}
                onInput={(e) => onPatch({ username: e.currentTarget.value })}
              />
            </label>
          )}
          {isLogin && (
            <label>
              {t('editPassword')}
              <div class="password-field">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={form.password}
                  onInput={(e) => onPatch({ password: e.currentTarget.value })}
                />
                <button
                  type="button"
                  class="eye"
                  title={showPassword ? t('editHide') : t('editShow')}
                  onClick={onToggleShowPassword}
                >
                  <IconEye struck={showPassword} />
                </button>
                <button
                  type="button"
                  class="eye dice"
                  title={t('editGeneratePassword')}
                  onClick={onOpenGenerator}
                >
                  <IconDice />
                </button>
              </div>
            </label>
          )}
          {/* Outside the `<label>`: nesting one field inside another's label
              would make the panel's checkbox toggle the password field. */}
          {generator}
          {isLogin && (
            <label>
              {t('editTotp')}
              <input
                type="text"
                value={form.totp}
                onInput={(e) => onPatch({ totp: e.currentTarget.value })}
              />
            </label>
          )}
          {isLogin && (
            <label>
              {t('editUris')}
              <textarea
                rows={2}
                value={form.uris}
                onInput={(e) => onPatch({ uris: e.currentTarget.value })}
              />
            </label>
          )}
          <label>
            {t('editNotes')}
            <textarea
              rows={3}
              value={form.notes}
              onInput={(e) => onPatch({ notes: e.currentTarget.value })}
            />
          </label>
          {passkeys.length > 0 && (
            <div class="passkeys-info">
              {passkeys.map((pk, i) => (
                <p key={i}>
                  <span class="badge">{t('itemPasskeyBadge')}</span> {pk.rpId ?? '?'}
                  {pk.userName !== null ? ` — ${pk.userName}` : ''}
                </p>
              ))}
              <p class="hint-diag">{t('editPasskeyNote')}</p>
            </div>
          )}
          <button type="submit" disabled={busy !== null}>
            {t('actionSave')}
          </button>
        </form>
        {busy !== null && <p class="status">{busy}</p>}
        {error !== null && <p class="error">{error}</p>}
      </main>
    </div>
  );
}
