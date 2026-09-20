/**
 * @file The vault's header bar.
 *
 * Extracted for one reason: it is drawn twice — once while the vault is still
 * being decrypted, once over the list — and two copies of a header are two
 * chances for them to differ by a few pixels. They did: `button.quiet` stands
 * five pixels taller than the title alone, so a header that gained its buttons
 * on arrival pushed the search box down just as the user reached for it.
 *
 * Creating an item is the only action here that needs the keys, so it is the
 * only one disabled while they are being made ready. Generating a password,
 * opening the settings and locking all work with a vault still closed — and
 * locking is a reasonable thing to want during a load one did not expect.
 */

import { t } from '@shared/i18n.js';

export function VaultHeader({
  canCreate,
  onNew,
  onGenerate,
  onOptions,
  onLock,
}: {
  /** False while the vault is still opening: there is nothing to save into yet. */
  canCreate: boolean;
  onNew: () => void;
  onGenerate: () => void;
  onOptions: () => void;
  onLock: () => void;
}) {
  return (
    <header>
      <h1>Zwarden</h1>
      <div>
        <button class="quiet" title={t('newItemTitle')} disabled={!canCreate} onClick={onNew}>
          {t('newItem')}
        </button>
        <button class="quiet" title={t('editGeneratePassword')} onClick={onGenerate}>
          {t('actionGenerate')}
        </button>
        <button class="quiet" onClick={onOptions}>
          {t('actionSettings')}
        </button>
        <button class="quiet" onClick={onLock}>
          {t('actionLock')}
        </button>
      </div>
    </header>
  );
}
