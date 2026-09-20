/**
 * @file Confirming a passkey sign-in.
 *
 * This is what the second option looked like when it was chosen: the page waits,
 * the icon carries a badge, and the decision is made here — in the extension's
 * own window, where the user can see which site is asking and which passkey
 * would answer.
 *
 * Purely presentational. It validates nothing: whether the page may ask for
 * that relying party at all is settled in `core/vault/webauthnRequest.ts`,
 * before this screen is ever shown, because a rule enforced by a form is a rule
 * enforced by whatever renders the form.
 */

import { t } from '@shared/i18n.js';

/** One passkey this vault could answer with. */
export interface AssertionChoice {
  readonly itemId: string;
  readonly credentialId: string;
  /** What to call it: the item's name, and the account at the site. */
  readonly label: string;
}

export function AssertionScreen({
  ceremony,
  origin,
  siteName,
  choices,
  chosen,
  needsVerification,
  masterPassword,
  busy,
  error,
  onChoose,
  onMasterPassword,
  onConfirm,
  onDecline,
}: {
  /** Signing in with a passkey, or creating one. */
  ceremony: 'get' | 'create';
  /** The site asking, as the browser reported it — never as the page said. */
  origin: string;
  /** What the site calls itself, shown only when creating. */
  siteName: string;
  choices: readonly AssertionChoice[];
  chosen: string | null;
  /** The site asked that the user be verified, not merely present. */
  needsVerification: boolean;
  masterPassword: string;
  busy: string | null;
  error: string | null;
  onChoose: (credentialId: string) => void;
  onMasterPassword: (value: string) => void;
  onConfirm: (event: Event) => void;
  onDecline: () => void;
}) {
  const creating = ceremony === 'create';

  return (
    <div>
      <header>
        <h1>{creating ? t('registrationTitle') : t('assertionTitle')}</h1>
        <button class="quiet" onClick={onDecline}>
          {t('assertionDecline')}
        </button>
      </header>
      <main>
        {/* The origin, spelled out. It is the one thing worth reading before
            authorising a signature, and it comes from the browser. */}
        <p class="assertion-origin">
          {creating ? t('registrationAsks', origin, siteName) : t('assertionAsks', origin)}
        </p>

        {choices.length === 0 && !creating ? (
          <p class="empty">{t('assertionNone')}</p>
        ) : (
          <form onSubmit={onConfirm}>
            <label>
              {creating ? t('registrationAttach') : t('assertionChoose')}
              <select
                value={chosen ?? ''}
                onChange={(e) => onChoose(e.currentTarget.value)}
              >
                {choices.map((choice) => (
                  <option key={choice.credentialId} value={choice.credentialId}>
                    {choice.label}
                  </option>
                ))}
              </select>
            </label>

            {needsVerification && (
              <>
                <label>
                  {t('assertionVerify')}
                  <input
                    type="password"
                    autocomplete="current-password"
                    autofocus
                    value={masterPassword}
                    onInput={(e) => onMasterPassword(e.currentTarget.value)}
                    required
                  />
                </label>
                <p class="hint-diag">
                  {creating ? t('registrationVerifyHint') : t('assertionVerifyHint')}
                </p>
              </>
            )}

            <button type="submit" disabled={busy !== null}>
              {creating ? t('registrationConfirm') : t('assertionConfirm')}
            </button>
          </form>
        )}
        {busy !== null && <p class="status">{busy}</p>}
        {error !== null && <p class="error">{error}</p>}
      </main>
    </div>
  );
}
