/**
 * @file The offer to save a captured credential.
 *
 * The only earlier signal is a badge on the icon: nothing is injected into the
 * visited page (`docs/EXTENSION.md` §4 bis). This banner is therefore the first
 * place the user sees what was captured — and the only place they can refuse it.
 */

import { t } from '@shared/i18n.js';
import type { CipherOverview } from '@core/vault/cipherService.js';
import type { PendingSave } from '@shared/storage.js';

/** What the user entered, and the item it would update. */
export interface SaveProposal {
  readonly capture: PendingSave;
  /** `null` if this is a new item. */
  readonly existing: CipherOverview | null;
}

/** Maximum number of dots shown for the captured password. */
const MASKED_LENGTH_MAX = 12;

export function SaveProposalBanner({
  proposal,
  busy,
  onSave,
  onDismiss,
  onNever,
}: {
  proposal: SaveProposal;
  busy: boolean;
  onSave: () => void;
  onDismiss: () => void;
  onNever: () => void;
}) {
  const { capture, existing } = proposal;

  return (
    <section class="proposal">
      <p class="proposal-title">
        {existing === null
          ? t('proposalCreateTitle', capture.host)
          : t('proposalUpdateTitle', existing.name ?? capture.host)}
      </p>
      <p class="proposal-detail">
        {capture.username === '' ? t('proposalNoUsername') : capture.username}
        {' — '}
        {/* Length capped: it teaches the user nothing and tells too much to
            anyone looking over their shoulder. */}
        {'•'.repeat(Math.min(capture.password.length, MASKED_LENGTH_MAX))}
      </p>
      <div class="proposal-actions">
        <button disabled={busy} onClick={onSave}>
          {t('proposalSave')}
        </button>
        <button class="quiet" onClick={onDismiss}>
          {t('proposalDismiss')}
        </button>
        <button class="quiet" title={t('proposalNeverTitle', capture.host)} onClick={onNever}>
          {t('proposalNever')}
        </button>
      </div>
    </section>
  );
}
