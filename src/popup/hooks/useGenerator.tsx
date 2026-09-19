/**
 * @file The password generator: its state, its preferences, its rendering.
 *
 * Lifted out of `App` because it is a self-contained tool: it does not read the
 * vault, does not talk to the network, and its only link to the rest is what it
 * produces. The two entry points — the list header and the edit form's password
 * field — thus share the same mechanism without duplicating it.
 */

import type { JSX } from 'preact';
import { useRef, useState } from 'preact/hooks';

import { type PasswordOptions, generatePassword } from '@core/generator/password.js';
import { loadGeneratorOptions, saveGeneratorOptions } from '@shared/storage.js';

import { type GeneratorState, GeneratorPanel } from '../components/GeneratorPanel.js';

/**
 * Delay before saving the options. Short enough that the preference survives the
 * popup closing in ordinary use, long enough that dragging a slider counts as
 * one write — the length slider fires an event per notch, which is a hundred and
 * twenty writes from 8 to 128.
 */
const SAVE_DELAY_MS = 400;

export interface Generator {
  /** Opens the panel, preferences reloaded and a first draw made. */
  readonly open: (target: 'edit' | 'standalone') => Promise<void>;
  readonly close: () => void;
  /** Renders the panel, or `null` if it is closed. */
  readonly render: () => JSX.Element | null;
}

/**
 * @param onError Reports an error to the caller — typically "no character class
 *   selected".
 * @param onUse Receives the password when the user clicks "Use".
 * @param onCopied Called after a copy, for the deferred clipboard wipe, whose
 *   rule belongs to the caller.
 */
export function useGenerator({
  onError,
  onUse,
  onCopied,
}: {
  onError: (message: string | null) => void;
  onUse: (password: string) => void;
  onCopied: () => void;
}): Generator {
  const [state, setState] = useState<GeneratorState | null>(null);
  const [copied, setCopied] = useState(false);
  const saveTimer = useRef<number | undefined>(undefined);

  function persist(options: PasswordOptions): void {
    if (saveTimer.current !== undefined) {
      clearTimeout(saveTimer.current);
    }
    saveTimer.current = window.setTimeout(() => {
      saveTimer.current = undefined;
      void saveGeneratorOptions(options);
    }, SAVE_DELAY_MS);
  }

  /**
   * Applies an options change: an immediate redraw, and the settings persisted.
   * Regenerating on every tick avoids the inconsistent state where the screen
   * shows a password that no longer matches the boxes displayed.
   */
  function patch(current: GeneratorState, change: Partial<PasswordOptions>): void {
    const options = { ...current.options, ...change };
    persist(options);
    try {
      setState({ ...current, options, password: generatePassword(options) });
      onError(null);
    } catch (err) {
      // Every box unticked: we keep the options — the user is in the middle of
      // ticking one back — but do not pretend to have generated anything.
      setState({ ...current, options, password: '' });
      onError(err instanceof Error ? err.message : String(err));
    }
  }

  async function copy(password: string): Promise<void> {
    await navigator.clipboard.writeText(password);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
    onCopied();
  }

  return {
    async open(target) {
      const options = await loadGeneratorOptions();
      onError(null);
      try {
        setState({ options, password: generatePassword(options), target });
      } catch (err) {
        onError(err instanceof Error ? err.message : String(err));
      }
    },

    close() {
      setState(null);
    },

    render() {
      if (state === null) {
        return null;
      }
      return (
        <GeneratorPanel
          state={state}
          copied={copied}
          onPatch={(change) => patch(state, change)}
          onRegenerate={() => patch(state, {})}
          onCopy={() => void copy(state.password)}
          onUse={() => {
            if (state.password !== '') {
              onUse(state.password);
              setState(null);
            }
          }}
          onClose={() => setState(null)}
        />
      );
    },
  };
}
