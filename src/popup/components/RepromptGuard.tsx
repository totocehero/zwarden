/**
 * @file The "master password required" guard.
 *
 * An overlay rather than a banner: the prompt protects one precise action, and
 * leaving the list clickable behind it would blur what the user is confirming.
 *
 * This component verifies nothing — it collects an entry and renders a gesture.
 * The verification itself is offline and lives in `App` with the keys (see
 * `docs/CRYPTO.md` §7).
 */

import { t } from '@shared/i18n.js';
/** An action suspended until the master password is entered again. */
export interface RepromptState<T> {
  /** What the guard protects. Only its name is displayed. */
  readonly item: { readonly name: string | null };
  /** The action to resume once verified. */
  readonly run: () => T;
  readonly password: string;
  readonly error: string | null;
  /** True during derivation, which takes time — the KDF is slow by design. */
  readonly busy: boolean;
}

export function RepromptGuard<T>({
  state,
  onPassword,
  onConfirm,
  onCancel,
}: {
  state: RepromptState<T>;
  onPassword: (password: string) => void;
  onConfirm: (event: Event) => void;
  onCancel: () => void;
}) {
  return (
    <div class="overlay">
      <form class="reprompt" onSubmit={onConfirm}>
        <p class="reprompt-title">{t('repromptTitle')}</p>
        <p class="reprompt-detail">{t('repromptDetail', state.item.name ?? t('repromptThisItem'))}</p>
        <input
          type="password"
          autofocus
          autocomplete="off"
          value={state.password}
          disabled={state.busy}
          placeholder={t('repromptPlaceholder')}
          onInput={(e) => onPassword(e.currentTarget.value)}
        />
        {state.error !== null && <p class="reprompt-error">{state.error}</p>}
        <div class="reprompt-actions">
          <button type="submit" disabled={state.busy || state.password === ''}>
            {state.busy ? t('repromptVerifying') : t('repromptUnlock')}
          </button>
          <button type="button" class="quiet" disabled={state.busy} onClick={onCancel}>
            {t('actionCancel')}
          </button>
        </div>
      </form>
    </div>
  );
}
