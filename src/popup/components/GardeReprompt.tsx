/**
 * @file Garde « mot de passe maître requis ».
 *
 * Superposition et non bandeau : la demande protège une action précise, et
 * laisser la liste cliquable derrière elle brouillerait ce que l'utilisateur
 * confirme.
 *
 * Ce composant ne vérifie rien — il recueille une saisie et rend un geste. La
 * vérification, elle, est hors réseau et vit dans `App` avec les clés (voir
 * `docs/CRYPTO.md` §7).
 */

/** Action suspendue en attente d'une nouvelle saisie du mot de passe maître. */
export interface RepromptState<T> {
  /** Ce que la garde protège. Seul son nom est affiché. */
  readonly item: { readonly name: string | null };
  /** Action à relancer après vérification. */
  readonly run: () => T;
  readonly password: string;
  readonly error: string | null;
  /** Vrai pendant la dérivation, qui dure — le KDF est lent par construction. */
  readonly busy: boolean;
}

export function GardeReprompt<T>({
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
    <div class="voile">
      <form class="reprompt" onSubmit={onConfirm}>
        <p class="reprompt-titre">Mot de passe maître requis</p>
        <p class="reprompt-detail">
          « {state.item.name ?? 'Cet item'} » est protégé par une nouvelle saisie.
        </p>
        <input
          type="password"
          autofocus
          autocomplete="off"
          value={state.password}
          disabled={state.busy}
          placeholder="Mot de passe maître"
          onInput={(e) => onPassword(e.currentTarget.value)}
        />
        {state.error !== null && <p class="reprompt-erreur">{state.error}</p>}
        <div class="reprompt-actions">
          <button type="submit" disabled={state.busy || state.password === ''}>
            {state.busy ? 'Vérification…' : 'Déverrouiller'}
          </button>
          <button type="button" class="discret" disabled={state.busy} onClick={onCancel}>
            Annuler
          </button>
        </div>
      </form>
    </div>
  );
}
