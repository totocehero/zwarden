/**
 * @file The item edit form.
 *
 * Purely presentational: it receives cleartext values already decrypted by
 * `App`, and raises every keystroke. It encrypts nothing, calls no network and
 * does not know what a key is — which puts it outside the vault logic
 * (`docs/EXTENSION.md` §3).
 *
 * Each type shows its own fields and no others: the login fields (username,
 * password, TOTP, URIs) on a type 1, the card fields on a type 3, the identity's
 * on a type 4. Showing them all and leaving the irrelevant ones empty — which is
 * what a single form for every type amounts to — suggests they can be saved
 * there, and they cannot.
 */

import type { JSX } from 'preact';

import { t } from '@shared/i18n.js';
import { type CardEdit, EMPTY_CARD_EDIT } from '@core/vault/card.js';
import { EMPTY_IDENTITY_EDIT, type IdentityEdit } from '@core/vault/identity.js';
import type { PasskeyView } from '@core/vault/cipherService.js';

import { CardFields } from './CardFields.js';
import { IdentityFields } from './IdentityFields.js';
import { IconDice, IconEye } from './Icons.js';
import { TYPE_LABELS } from './itemLabels.js';

/** The form's cleartext values. */
export interface EditForm {
  /**
   * The item type. Chosen on creation, fixed afterwards: changing the type of an
   * existing item would orphan the section it already carries.
   */
  type: number;
  name: string;
  username: string;
  password: string;
  totp: string;
  notes: string;
  /** One URI per line. */
  uris: string;
  /** The card's values — read only for a type 3. */
  card: CardEdit;
  /** The identity's values — read only for a type 4. */
  identity: IdentityEdit;
}

export const EMPTY_EDIT: EditForm = {
  type: 1,
  name: '',
  username: '',
  password: '',
  totp: '',
  notes: '',
  uris: '',
  card: EMPTY_CARD_EDIT,
  identity: EMPTY_IDENTITY_EDIT,
};

/**
 * The types one can create here.
 *
 * SSH keys are absent on purpose: the extension carries them over faithfully
 * when they are already in the vault, but it cannot generate a key pair, and
 * offering to create an item one can only leave empty would be a promise it does
 * not keep.
 */
const CREATABLE_TYPES: readonly number[] = [1, 3, 4, 2];

export function EditItemForm({
  form,
  creating,
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
  /** True for a new item: the type can still be chosen. */
  creating: boolean;
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
  const isLogin = form.type === 1;

  return (
    <div>
      <header>
        <h1>{creating ? t('newItemTitle') : 'Zwarden'}</h1>
        <button class="quiet" onClick={onCancel}>
          {t('actionBack')}
        </button>
      </header>
      <main>
        <form onSubmit={onSubmit}>
          {creating && (
            <label>
              {t('newItemType')}
              <select
                value={String(form.type)}
                onChange={(e) => onPatch({ type: Number(e.currentTarget.value) })}
              >
                {CREATABLE_TYPES.map((type) => (
                  <option key={type} value={String(type)}>
                    {t(TYPE_LABELS[type] ?? 'typeLogin')}
                  </option>
                ))}
              </select>
            </label>
          )}
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
          {form.type === 3 && (
            <CardFields
              card={form.card}
              onPatch={(patch) => onPatch({ card: { ...form.card, ...patch } })}
            />
          )}
          {form.type === 4 && (
            <IdentityFields
              identity={form.identity}
              onPatch={(patch) => onPatch({ identity: { ...form.identity, ...patch } })}
            />
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
