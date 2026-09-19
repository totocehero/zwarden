/**
 * @file Générateur de mots de passe : son état, ses préférences, son rendu.
 *
 * Sorti de `App` parce que c'est un outil autonome : il ne lit pas le coffre, ne
 * parle pas au réseau, et son seul lien avec le reste est ce qu'il produit. Les
 * deux points d'entrée — l'en-tête de la liste et le champ mot de passe de
 * l'édition — partagent ainsi la même mécanique sans la dupliquer.
 */

import type { JSX } from 'preact';
import { useRef, useState } from 'preact/hooks';

import { type PasswordOptions, generatePassword } from '@core/generator/password.js';
import { loadGeneratorOptions, saveGeneratorOptions } from '@shared/storage.js';

import { type GeneratorState, PanneauGenerateur } from '../components/PanneauGenerateur.js';

/**
 * Délai avant d'enregistrer les options. Assez court pour que la préférence
 * survive à la fermeture de la popup dans un usage normal, assez long pour qu'un
 * glissement de curseur ne compte que pour une écriture — le curseur de longueur
 * émet un événement par cran, soit cent vingt écritures de 8 à 128.
 */
const SAVE_DELAY_MS = 400;

export interface Generateur {
  /** Ouvre le panneau, préférences rechargées et premier tirage fait. */
  readonly open: (target: 'edit' | 'standalone') => Promise<void>;
  readonly close: () => void;
  /** Rend le panneau, ou `null` s'il est fermé. */
  readonly render: () => JSX.Element | null;
}

/**
 * @param onError Signale une erreur à l'appelant — typiquement « aucune classe
 *   de caractères sélectionnée ».
 * @param onUse Reçoit le mot de passe quand l'utilisateur clique « Utiliser ».
 * @param onCopied Appelé après une copie, pour l'effacement différé du
 *   presse-papiers, dont la règle appartient à l'appelant.
 */
export function useGenerateur({
  onError,
  onUse,
  onCopied,
}: {
  onError: (message: string | null) => void;
  onUse: (password: string) => void;
  onCopied: () => void;
}): Generateur {
  const [state, setState] = useState<GeneratorState | null>(null);
  const [copie, setCopie] = useState(false);
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
   * Applique un changement d'options : nouveau tirage immédiat, réglages
   * persistés. Régénérer à chaque coche évite l'état incohérent où l'écran
   * montre un mot de passe qui ne correspond plus aux cases affichées.
   */
  function patch(courant: GeneratorState, modif: Partial<PasswordOptions>): void {
    const options = { ...courant.options, ...modif };
    persist(options);
    try {
      setState({ ...courant, options, password: generatePassword(options) });
      onError(null);
    } catch (err) {
      // Toutes les cases décochées : on garde les options — l'utilisateur est en
      // train d'en recocher une — mais on ne prétend pas avoir engendré.
      setState({ ...courant, options, password: '' });
      onError(err instanceof Error ? err.message : String(err));
    }
  }

  async function copier(password: string): Promise<void> {
    await navigator.clipboard.writeText(password);
    setCopie(true);
    setTimeout(() => setCopie(false), 1500);
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
        <PanneauGenerateur
          state={state}
          copie={copie}
          onPatch={(modif) => patch(state, modif)}
          onRegenerate={() => patch(state, {})}
          onCopy={() => void copier(state.password)}
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
