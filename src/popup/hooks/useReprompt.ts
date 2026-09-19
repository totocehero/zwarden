/**
 * @file Garde par item : l'état, et la vérification du mot de passe maître.
 *
 * Regroupé hors de `App` parce que c'est une mécanique complète et refermée —
 * un état, une vérification, une action suspendue — et qu'elle n'a besoin de
 * rien du coffre déchiffré. La sortir la rend lisible d'un seul tenant, ce qui
 * compte pour un code dont le rôle est de **refuser** quelque chose.
 *
 * La vérification est hors réseau : on redérive la clé maître depuis la saisie
 * et on la compare au hash local conservé au déverrouillage. Voir
 * `docs/CRYPTO.md` §7 pour le raisonnement — faire valider un `reprompt` par le
 * serveur donnerait à qui contrôle le réseau le pouvoir de le désarmer.
 */

import { useState } from 'preact/hooks';

import { deriveMasterKey, verifyLocalPasswordHash } from '@core/crypto/kdf.js';
import type { CipherOverview } from '@core/vault/cipherService.js';
import { loadStoredSession } from '@shared/storage.js';

import type { RepromptState } from '../components/GardeReprompt.js';

/** Action protégée : elle peut être synchrone ou non, son résultat est ignoré. */
type Action = () => void | Promise<void>;

export interface Reprompt {
  /** État courant de la garde, ou `null` si aucune action n'est suspendue. */
  readonly state: RepromptState<void | Promise<void>> | null;
  /**
   * Exécute une action qui sort un secret du coffre, derrière la garde de
   * l'item.
   *
   * Item sans garde : l'action part immédiatement, rien ne change. Item marqué
   * `reprompt` : elle est suspendue jusqu'à vérification. Le point important est
   * que la garde se pose **avant** tout déchiffrement — un secret protégé n'est
   * pas déchiffré puis caché, il n'est pas déchiffré du tout.
   */
  readonly guarded: (item: CipherOverview, run: Action) => void;
  readonly setPassword: (password: string) => void;
  readonly confirm: (event: Event) => Promise<void>;
  readonly cancel: () => void;
}

/**
 * @param messageFor Traduction d'une erreur en message affichable, fournie par
 *   l'appelant pour rester cohérente avec le reste de la popup.
 */
export function useReprompt(messageFor: (error: unknown) => string): Reprompt {
  const [state, setState] = useState<RepromptState<void | Promise<void>> | null>(null);

  /** Redérive la clé maître et la compare au témoin local. */
  async function verify(candidate: string): Promise<boolean> {
    const stored = await loadStoredSession();
    if (stored === null) {
      throw new Error('Session expirée — verrouiller puis déverrouiller.');
    }
    const masterKey = await deriveMasterKey(candidate, stored.email, stored.kdfConfig);
    try {
      return await verifyLocalPasswordHash(masterKey, candidate, stored.localPasswordHash);
    } finally {
      // Elle n'a servi qu'à comparer.
      masterKey.destroy();
    }
  }

  return {
    state,

    guarded(item, run) {
      if (!item.reprompt) {
        void run();
        return;
      }
      setState({ item, run, password: '', error: null, busy: false });
    },

    setPassword(password) {
      setState((current) => (current === null ? current : { ...current, password }));
    },

    async confirm(event) {
      event.preventDefault();
      const en_cours = state;
      if (en_cours === null || en_cours.busy) {
        return;
      }
      // La dérivation dure : sans cet état, un second envoi lancerait un
      // deuxième KDF pendant que le premier tourne.
      setState({ ...en_cours, busy: true, error: null });
      try {
        if (!(await verify(en_cours.password))) {
          setState({ ...en_cours, busy: false, password: '', error: 'Mot de passe incorrect.' });
          return;
        }
        setState(null);
        await en_cours.run();
      } catch (err) {
        setState({ ...en_cours, busy: false, password: '', error: messageFor(err) });
      }
    },

    cancel() {
      setState(null);
    },
  };
}
