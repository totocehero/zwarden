import { t } from '@shared/i18n.js';

/**
 * @file Action sections: hygiene and device identity.
 *
 * Kept apart from the form because they have nothing to save: every button acts
 * immediately. Mixing them into the form would have suggested one must click
 * "Save" afterwards.
 */

export function ActionsSection({
  onLockNow,
  onForgetTwoFa,
  onForgetNeverSave,
  onForgetLastUsed,
}: {
  onLockNow: () => void;
  onForgetTwoFa: () => void;
  onForgetNeverSave: () => void;
  onForgetLastUsed: () => void;
}) {
  return (
    <section>
      <h2>{t('settingsActionsSection')}</h2>
      <div class="actions">
        <button class="secondary" onClick={onLockNow}>
          {t('settingsLockNow')}
        </button>
        <button class="secondary" onClick={onForgetTwoFa}>
          {t('settingsForgetTwoFa')}
        </button>
        <button class="secondary" onClick={onForgetNeverSave}>
          {t('settingsRestoreExcluded')}
        </button>
        <button class="secondary" onClick={onForgetLastUsed}>
          {t('settingsForgetOrdering')}
        </button>
      </div>
    </section>
  );
}

export function DeviceSection({
  deviceId,
  onRegenerate,
}: {
  deviceId: string;
  onRegenerate: () => void;
}) {
  return (
    <section>
      <h2>{t('settingsDeviceSection')}</h2>
      <div class="fields">
        <div>
          <p class="hint">{t('settingsDeviceIdLabel')}</p>
          <p class="device-id">{deviceId}</p>
        </div>
        <button class="danger" onClick={onRegenerate}>
          {t('settingsRegenerateDevice')}
        </button>
      </div>
    </section>
  );
}
