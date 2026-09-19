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
      <h2>Actions</h2>
      <div class="actions">
        <button class="secondary" onClick={onLockNow}>
          Lock the vault now
        </button>
        <button class="secondary" onClick={onForgetTwoFa}>
          Forget 2FA exemptions
        </button>
        <button class="secondary" onClick={onForgetNeverSave}>
          Restore excluded sites
        </button>
        <button class="secondary" onClick={onForgetLastUsed}>
          Forget the use ordering
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
      <h2>Device</h2>
      <div class="fields">
        <div>
          <p class="hint">Identifier sent to the server:</p>
          <p class="device-id">{deviceId}</p>
        </div>
        <button class="danger" onClick={onRegenerate}>
          Regenerate the device identifier
        </button>
      </div>
    </section>
  );
}
