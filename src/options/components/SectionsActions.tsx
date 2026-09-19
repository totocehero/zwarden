/**
 * @file Sections d'actions : hygiène et identité d'appareil.
 *
 * Séparées du formulaire parce qu'elles n'ont rien à enregistrer : chaque bouton
 * agit immédiatement. Les mêler au formulaire aurait laissé croire qu'il faut
 * cliquer « Enregistrer » après.
 */

export function SectionActions({
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
        <button class="secondaire" onClick={onLockNow}>
          Verrouiller le coffre maintenant
        </button>
        <button class="secondaire" onClick={onForgetTwoFa}>
          Oublier les dispenses 2FA
        </button>
        <button class="secondaire" onClick={onForgetNeverSave}>
          Réintégrer les sites exclus
        </button>
        <button class="secondaire" onClick={onForgetLastUsed}>
          Oublier le classement d’usage
        </button>
      </div>
    </section>
  );
}

export function SectionAppareil({
  deviceId,
  onRegenerate,
}: {
  deviceId: string;
  onRegenerate: () => void;
}) {
  return (
    <section>
      <h2>Appareil</h2>
      <div class="champs">
        <div>
          <p class="aide">Identifiant transmis au serveur :</p>
          <p class="device-id">{deviceId}</p>
        </div>
        <button class="danger" onClick={onRegenerate}>
          Régénérer l’identifiant d’appareil
        </button>
      </div>
    </section>
  );
}
