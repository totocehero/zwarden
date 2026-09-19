/**
 * @file Panneau du générateur de mots de passe.
 *
 * Rendu aussi bien au-dessus de la liste qu'au-dessus du formulaire d'édition :
 * c'est le même outil, appelé depuis deux endroits. Il ne connaît ni le coffre
 * ni le réseau — il reçoit son état et rend ses gestes, ce qui le laisse hors de
 * la logique de coffre (`docs/EXTENSION.md` §3).
 */

import {
  type PasswordOptions,
  MAX_LENGTH,
  MIN_LENGTH,
} from '@core/generator/password.js';

/** Panneau du générateur : ses options, sa production, et sa destination. */
export interface GeneratorState {
  readonly options: PasswordOptions;
  readonly password: string;
  /** `'edit'` : un bouton « Utiliser » réinjecte dans le formulaire ouvert. */
  readonly target: 'edit' | 'standalone';
}

/**
 * Panneau du générateur de mots de passe.
 *
 * Composant à part, rendu aussi bien au-dessus de la liste qu'au-dessus du
 * formulaire d'édition : c'est le même outil, appelé depuis deux endroits.
 * Il ne connaît ni le coffre ni le réseau — il reçoit son état et rend ses
 * gestes, ce qui le laisse hors de la logique de coffre (§3).
 */
export function PanneauGenerateur({
  state,
  onPatch,
  onRegenerate,
  onCopy,
  onUse,
  onClose,
  copie,
}: {
  state: GeneratorState;
  onPatch: (patch: Partial<PasswordOptions>) => void;
  onRegenerate: () => void;
  onCopy: () => void;
  onUse: () => void;
  onClose: () => void;
  copie: boolean;
}) {
  const { options, password } = state;
  const classes: ReadonlyArray<readonly [keyof PasswordOptions, string]> = [
    ['lowercase', 'a-z'],
    ['uppercase', 'A-Z'],
    ['digits', '0-9'],
    ['symbols', '!@#$%^&*'],
  ];

  return (
    <section class="generateur">
      <div class="generateur-sortie" title="Cliquer pour copier" onClick={onCopy}>
        {password === '' ? '—' : password}
      </div>
      <div class="generateur-actions">
        <button type="button" onClick={onRegenerate} disabled={password === ''}>
          Régénérer
        </button>
        <button type="button" class="secondaire" onClick={onCopy} disabled={password === ''}>
          {copie ? 'Copié !' : 'Copier'}
        </button>
        {state.target === 'edit' && (
          <button type="button" class="secondaire" onClick={onUse} disabled={password === ''}>
            Utiliser
          </button>
        )}
        <button type="button" class="discret" onClick={onClose}>
          Fermer
        </button>
      </div>
      <label class="generateur-longueur">
        Longueur : {options.length}
        <input
          type="range"
          min={MIN_LENGTH}
          max={MAX_LENGTH}
          value={options.length}
          onInput={(e) => onPatch({ length: e.currentTarget.valueAsNumber })}
        />
      </label>
      <div class="generateur-classes">
        {classes.map(([cle, libelle]) => (
          <label key={cle} class="ligne">
            <input
              type="checkbox"
              checked={options[cle] as boolean}
              onInput={(e) => onPatch({ [cle]: e.currentTarget.checked })}
            />
            {libelle}
          </label>
        ))}
        <label class="ligne">
          <input
            type="checkbox"
            checked={options.avoidAmbiguous}
            onInput={(e) => onPatch({ avoidAmbiguous: e.currentTarget.checked })}
          />
          Éviter l’ambigu (l 1 I O 0 o)
        </label>
      </div>
    </section>
  );
}

