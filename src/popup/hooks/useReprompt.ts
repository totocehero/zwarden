/**
 * @file The per-item guard: its state, and master-password verification.
 *
 * Grouped outside `App` because it is a complete, self-contained mechanism — a
 * state, a verification, a suspended action — and needs nothing from the
 * decrypted vault. Lifting it out makes it readable in one piece, which matters
 * for code whose job is to **refuse** something.
 *
 * The verification is offline: we re-derive the master key from the entry and
 * compare it against the local hash kept at unlock. See `docs/CRYPTO.md` §7 for
 * the reasoning — having the server validate a `reprompt` would hand whoever
 * controls the network the power to disarm it.
 */

import { t } from '@shared/i18n.js';
import { useState } from 'preact/hooks';

import { deriveMasterKey, verifyLocalPasswordHash } from '@core/crypto/kdf.js';
import type { CipherOverview } from '@core/vault/cipherService.js';
import { loadStoredSession } from '@shared/storage.js';

import type { RepromptState } from '../components/RepromptGuard.js';

/** A guarded action: it may be sync or not, and its result is ignored. */
type Action = () => void | Promise<void>;

export interface Reprompt {
  /** Current guard state, or `null` if no action is suspended. */
  readonly state: RepromptState<void | Promise<void>> | null;
  /**
   * Runs an action that takes a secret out of the vault, behind the item's
   * guard.
   *
   * Item with no guard: the action leaves immediately, nothing changes. Item
   * marked `reprompt`: it is suspended until verification. The important part is
   * that the guard stands **before** any decryption — a protected secret is not
   * decrypted and then hidden, it is not decrypted at all.
   */
  readonly guarded: (item: CipherOverview, run: Action) => void;
  readonly setPassword: (password: string) => void;
  readonly confirm: (event: Event) => Promise<void>;
  readonly cancel: () => void;
}

/**
 * @param messageFor Turns an error into a displayable message, supplied by the
 *   caller so it stays consistent with the rest of the popup.
 */
export function useReprompt(messageFor: (error: unknown) => string): Reprompt {
  const [state, setState] = useState<RepromptState<void | Promise<void>> | null>(null);

  /** Re-derives the master key and compares it against the local witness. */
  async function verify(candidate: string): Promise<boolean> {
    const stored = await loadStoredSession();
    if (stored === null) {
      throw new Error(t('errorSessionExpired'));
    }
    const masterKey = await deriveMasterKey(candidate, stored.email, stored.kdfConfig);
    try {
      return await verifyLocalPasswordHash(masterKey, candidate, stored.localPasswordHash);
    } finally {
      // It only ever served to compare.
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
      const pending = state;
      if (pending === null || pending.busy) {
        return;
      }
      // Derivation takes time: without this state, a second submit would start a
      // second KDF while the first is still running.
      setState({ ...pending, busy: true, error: null });
      try {
        if (!(await verify(pending.password))) {
          setState({ ...pending, busy: false, password: '', error: t('repromptWrongPassword') });
          return;
        }
        setState(null);
        await pending.run();
      } catch (err) {
        setState({ ...pending, busy: false, password: '', error: messageFor(err) });
      }
    },

    cancel() {
      setState(null);
    },
  };
}
