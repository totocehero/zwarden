/**
 * @file Writes held back while the server was unreachable.
 *
 * Holding one, replaying the ones that are still safe to send, counting what
 * is left, and giving up on what cannot be applied. Lifted out of `App`, which
 * had no business knowing any of it.
 *
 * The rules themselves are not here — they are in `core/vault/offlineQueue.ts`,
 * pure and tested. What is here is the sequence: when to hold, what to tell
 * the user, and when to stop trying.
 */

import { useState } from 'preact/hooks';

import { t } from '@shared/i18n.js';
import type { ApiClient } from '@core/api/apiClient.js';
import type { SyncResponse } from '@core/api/models.js';
import { decideReplay, isUnreachable } from '@core/vault/offlineQueue.js';
import {
  clearWriteQueue,
  enqueueWrite,
  loadWriteQueue,
  removeWrites,
} from '@shared/writeQueue.js';

/** The queue as the interface needs it. */
export interface WriteQueue {
  /** How many writes are waiting to be sent. */
  readonly pending: number;
  /** How many could not be applied because the item changed elsewhere. */
  readonly held: number;
  readonly refreshCounts: (held?: number) => Promise<void>;
  readonly hold: (
    kind: 'create' | 'update',
    cipherId: string | null,
    payload: Record<string, unknown>,
    baseRevision: string | null,
    label: string,
  ) => Promise<void>;
  readonly replay: (
    client: ApiClient,
    accessToken: string,
    sync: SyncResponse,
  ) => Promise<{ sent: number; held: number }>;
  readonly discard: () => Promise<void>;
}

export function useWriteQueue({
  setBusy,
  setError,
}: {
  setBusy: (value: string | null) => void;
  setError: (value: string | null) => void;
}): WriteQueue {
  const [queued, setQueued] = useState({ pending: 0, held: 0 });

/**
 * Holds a write the server never received.
 *
 * Only called for a failure that means "no answer" — `isUnreachable` keeps a
 * refusal out of the queue, since retrying a refusal never succeeds and would
 * hide a real error behind a reassuring "saved locally".
 *
 * What is stored is the **already-encrypted** body. The cleartext edit never
 * reaches disk (`docs/STORAGE.md` §4).
 */
async function holdWrite(
  kind: 'create' | 'update',
  cipherId: string | null,
  payload: Record<string, unknown>,
  baseRevision: string | null,
  label: string,
): Promise<void> {
  await enqueueWrite({
    id: crypto.randomUUID(),
    kind,
    cipherId,
    payload,
    baseRevision,
    queuedAt: Date.now(),
    label,
  });
  await refreshQueueCounts();
  setBusy(null);
  setError(t('queueSavedOffline'));
}

/** Reflects the queue's size on screen. */
async function refreshQueueCounts(held = 0): Promise<void> {
  const queue = await loadWriteQueue();
  setQueued({ pending: queue.length, held });
}

/**
 * Sends what was held, once the server answers again.
 *
 * Decided against the sync that has just come back, so a conflict is detected
 * from the server's own current state rather than from a guess.
 *
 * @returns How many were sent, and how many were held back.
 */
async function replayQueue(
  client: ApiClient,
  accessToken: string,
  sync: SyncResponse,
): Promise<{ sent: number; held: number }> {
  const queue = await loadWriteQueue();
  if (queue.length === 0) {
    return { sent: 0, held: 0 };
  }
  const byId = new Map((sync.ciphers ?? []).map((c) => [c.id, c]));
  const done: string[] = [];
  let held = 0;

  for (const entry of queue) {
    const outcome = decideReplay(entry, byId.get(entry.cipherId ?? ''));
    if (outcome.kind !== 'replay') {
      // Nothing is overwritten and nothing is resurrected. The user is told,
      // and decides.
      held += 1;
      continue;
    }
    try {
      if (entry.kind === 'create') {
        await client.createCipher(accessToken, entry.payload);
      } else {
        await client.updateCipher(accessToken, entry.cipherId!, entry.payload);
      }
      done.push(entry.id);
    } catch (err) {
      if (isUnreachable(err)) {
        // Still offline: stop, keep the rest, try again next time.
        break;
      }
      // Refused. Retrying would refuse again for ever; it is dropped and
      // counted as held so the user hears about it.
      done.push(entry.id);
      held += 1;
    }
  }

  await removeWrites(done);
  return { sent: done.length - held, held };
}

/** Abandons the held writes the user has given up on. */
async function onDiscardQueue(): Promise<void> {
  const n = await clearWriteQueue();
  setQueued({ pending: 0, held: 0 });
  setError(n === 0 ? null : t('queueDiscarded', String(n)));
}

  return {
    pending: queued.pending,
    held: queued.held,
    refreshCounts: refreshQueueCounts,
    hold: holdWrite,
    replay: replayQueue,
    discard: onDiscardQueue,
  };
}
