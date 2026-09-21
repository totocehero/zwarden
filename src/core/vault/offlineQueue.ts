/**
 * @file The rules governing writes made while the server was unreachable.
 *
 * Pure: no storage, no network, no clock of its own. Two decisions live here
 * and both are the kind that must be right rather than plausible —
 *
 * 1. **is this failure worth queueing?** Queueing a write the server *refused*
 *    would retry it forever and never succeed;
 * 2. **is this write still safe to apply?** Replaying blindly over an item that
 *    changed in the meantime overwrites someone's password rotation with an
 *    older one. For a password manager that is not a merge conflict, it is a
 *    lockout.
 */

import { type CipherResponse, readField } from '../api/models.js';
import { ApiError } from '../api/apiClient.js';

/** A write held back because the server could not be reached. */
export interface QueuedWrite {
  /** Identifier of the queue entry itself, not of the item. */
  readonly id: string;
  readonly kind: 'create' | 'update';
  /** The item being updated, or `null` for a creation. */
  readonly cipherId: string | null;
  /**
   * The body to send — **already encrypted**.
   *
   * The cleartext edit is never queued. Encrypting at replay would mean a
   * cleartext password waiting on disk for the network to come back, which is
   * precisely what `docs/STORAGE.md` exists to forbid.
   */
  readonly payload: Record<string, unknown>;
  /**
   * The item's `revisionDate` as it stood when the edit was made, or `null` for
   * a creation.
   *
   * This is the whole conflict detection: if the server's copy has moved since,
   * this write was composed against a version that no longer exists.
   */
  readonly baseRevision: string | null;
  /** When it was queued, for display and for ordering. */
  readonly queuedAt: number;
}

/**
 * Whether a failure means "the server never answered".
 *
 * The distinction is the one that keeps the queue honest. An {@link ApiError}
 * is the server having heard the request and refused it — a malformed body, a
 * revoked token, a deleted item. Queueing that would retry a refusal until the
 * end of time, and would hide a real error behind a reassuring "saved locally".
 *
 * Everything else — a `TimeoutError` from `AbortSignal.timeout`, the `TypeError`
 * `fetch` throws with no network, a DNS failure on a self-hosted instance —
 * means the write never arrived, and is exactly what a queue is for.
 *
 * @param error Whatever the write threw.
 * @returns `true` if the write should be held and retried.
 */
export function isUnreachable(error: unknown): boolean {
  if (error instanceof ApiError) {
    return false;
  }
  if (error instanceof DOMException) {
    return error.name === 'TimeoutError' || error.name === 'AbortError';
  }
  // `fetch` rejects with a TypeError when the host cannot be reached at all.
  return error instanceof TypeError;
}

/** What should happen to a queued write once the server is back. */
export type ReplayOutcome =
  /** Safe to send: nothing has moved underneath it. */
  | { readonly kind: 'replay' }
  /** The item changed elsewhere since the edit. Sending would overwrite it. */
  | { readonly kind: 'conflict' }
  /** The item no longer exists on the server. */
  | { readonly kind: 'gone' };

/**
 * Decides the fate of one queued write against the server's current state.
 *
 * A creation always replays: there is nothing it could overwrite.
 *
 * An update replays only if the item's `revisionDate` is exactly the one the
 * edit was composed against. Anything else — the same password changed on
 * another device, a field edited in the web vault — and the write is held back
 * rather than applied. **Silently winning is the failure mode to avoid**: the
 * user would be left with a password their other device has already stopped
 * using, and no sign that anything happened.
 *
 * An item that has disappeared is not recreated. It was deleted deliberately,
 * on some device, and resurrecting it from a queue would undo that decision
 * without asking.
 *
 * @param entry The queued write.
 * @param current The server's copy, or `undefined` if it is no longer there.
 */
export function decideReplay(
  entry: QueuedWrite,
  current: CipherResponse | undefined,
): ReplayOutcome {
  if (entry.kind === 'create') {
    return { kind: 'replay' };
  }
  if (current === undefined) {
    return { kind: 'gone' };
  }
  const revision = readField<string>(current, 'revisionDate') ?? null;
  return revision === entry.baseRevision ? { kind: 'replay' } : { kind: 'conflict' };
}

/**
 * Sorts a queue into the order it must be sent in.
 *
 * Oldest first, and not merely for tidiness: two edits to the same item made
 * offline must land in the order they were made, or the earlier one wins.
 */
export function inSendOrder(entries: readonly QueuedWrite[]): readonly QueuedWrite[] {
  return [...entries].sort((a, b) => a.queuedAt - b.queuedAt);
}

/**
 * Collapses repeated edits of the same item down to the last one.
 *
 * Three offline edits of one password are three writes of which only the last
 * matters, and sending the first two would be two chances to fail for no gain.
 * Creations are never collapsed — each is a distinct item.
 *
 * The survivor keeps the **oldest** `baseRevision`, because that is the version
 * the whole chain of edits was composed against; keeping the newest would claim
 * agreement with a server state the user never saw.
 */
export function collapse(entries: readonly QueuedWrite[]): readonly QueuedWrite[] {
  const ordered = inSendOrder(entries);
  const lastByCipher = new Map<string, QueuedWrite>();
  const out: QueuedWrite[] = [];

  for (const entry of ordered) {
    if (entry.kind === 'create' || entry.cipherId === null) {
      out.push(entry);
      continue;
    }
    const previous = lastByCipher.get(entry.cipherId);
    const merged =
      previous === undefined ? entry : { ...entry, baseRevision: previous.baseRevision };
    lastByCipher.set(entry.cipherId, merged);
  }

  return inSendOrder([...out, ...lastByCipher.values()]);
}
