/**
 * @file The password generator's panel.
 *
 * Rendered above the list as readily as above the edit form: it is the same
 * tool, called from two places. It knows neither the vault nor the network — it
 * receives its state and renders its gestures, which keeps it outside the vault
 * logic (`docs/EXTENSION.md` §3).
 */

import { type PasswordOptions, MAX_LENGTH, MIN_LENGTH } from '@core/generator/password.js';

/** The generator panel's state: its options, its output, and its destination. */
export interface GeneratorState {
  readonly options: PasswordOptions;
  readonly password: string;
  /** `'edit'`: a "Use" button feeds the result back into the open form. */
  readonly target: 'edit' | 'standalone';
}

export function GeneratorPanel({
  state,
  onPatch,
  onRegenerate,
  onCopy,
  onUse,
  onClose,
  copied,
}: {
  state: GeneratorState;
  onPatch: (patch: Partial<PasswordOptions>) => void;
  onRegenerate: () => void;
  onCopy: () => void;
  onUse: () => void;
  onClose: () => void;
  copied: boolean;
}) {
  const { options, password } = state;
  const classes: ReadonlyArray<readonly [keyof PasswordOptions, string]> = [
    ['lowercase', 'a-z'],
    ['uppercase', 'A-Z'],
    ['digits', '0-9'],
    ['symbols', '!@#$%^&*'],
  ];

  return (
    <section class="generator">
      <div class="generator-output" title="Click to copy" onClick={onCopy}>
        {password === '' ? '—' : password}
      </div>
      <div class="generator-actions">
        <button type="button" onClick={onRegenerate} disabled={password === ''}>
          Regenerate
        </button>
        <button type="button" class="secondary" onClick={onCopy} disabled={password === ''}>
          {copied ? 'Copied!' : 'Copy'}
        </button>
        {state.target === 'edit' && (
          <button type="button" class="secondary" onClick={onUse} disabled={password === ''}>
            Use
          </button>
        )}
        <button type="button" class="quiet" onClick={onClose}>
          Close
        </button>
      </div>
      <label class="generator-length">
        Length: {options.length}
        <input
          type="range"
          min={MIN_LENGTH}
          max={MAX_LENGTH}
          value={options.length}
          onInput={(e) => onPatch({ length: e.currentTarget.valueAsNumber })}
        />
      </label>
      <div class="generator-classes">
        {classes.map(([key, label]) => (
          <label key={key} class="row">
            <input
              type="checkbox"
              checked={options[key] as boolean}
              onInput={(e) => onPatch({ [key]: e.currentTarget.checked })}
            />
            {label}
          </label>
        ))}
        <label class="row">
          <input
            type="checkbox"
            checked={options.avoidAmbiguous}
            onInput={(e) => onPatch({ avoidAmbiguous: e.currentTarget.checked })}
          />
          Avoid ambiguous characters (l 1 I O 0 o)
        </label>
      </div>
    </section>
  );
}
