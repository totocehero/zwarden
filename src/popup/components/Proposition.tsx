/**
 * @file Proposition d'enregistrer un identifiant capturé.
 *
 * Le seul signal antérieur est une pastille sur l'icône : rien n'est injecté
 * dans la page visitée (`docs/EXTENSION.md` §4 bis). Ce bandeau est donc le
 * premier endroit où l'utilisateur voit ce qui a été capturé — et le seul
 * endroit où il peut le refuser.
 */

import type { CipherOverview } from '@core/vault/cipherService.js';
import type { PendingSave } from '@shared/storage.js';

/** Ce que l'utilisateur a saisi, et l'item que cela mettrait à jour. */
export interface SaveProposal {
  readonly capture: PendingSave;
  /** `null` s'il s'agit d'un nouvel item. */
  readonly existing: CipherOverview | null;
}

/** Nombre maximal de points affichés pour le mot de passe capturé. */
const LONGUEUR_MASQUEE_MAX = 12;

export function Proposition({
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
    <section class="proposition">
      <p class="proposition-titre">
        {existing === null
          ? `Enregistrer les identifiants pour ${capture.host} ?`
          : `Mettre à jour le mot de passe de « ${existing.name ?? capture.host} » ?`}
      </p>
      <p class="proposition-detail">
        {capture.username === ''
          ? '(identifiant non détecté — à compléter après enregistrement)'
          : capture.username}
        {' — '}
        {/* Longueur plafonnée : elle n'apprend rien à l'utilisateur et en dit
            trop à qui regarde par-dessus son épaule. */}
        {'•'.repeat(Math.min(capture.password.length, LONGUEUR_MASQUEE_MAX))}
      </p>
      <div class="proposition-actions">
        <button disabled={busy} onClick={onSave}>
          Enregistrer
        </button>
        <button class="discret" onClick={onDismiss}>
          Ignorer
        </button>
        <button
          class="discret"
          title={`Ne plus rien proposer pour ${capture.host}`}
          onClick={onNever}
        >
          Ne plus proposer ici
        </button>
      </div>
    </section>
  );
}
