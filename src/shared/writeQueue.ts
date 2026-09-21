/**
 * @file Writes held back until the server can be reached.
 *
 * ## Why this lives on disk
 *
 * It has to survive the browser closing, or the feature does not exist: one
 * edits on a train, shuts the laptop, and opens it again somewhere with signal.
 * `chrome.storage.session` would forget it at exactly the wrong moment.
 *
 * That makes this the **first vault ciphertext Zwarden writes to disk**, and
 * the reasoning is in `docs/STORAGE.md` §4 rather than here. In short: what is
 * queued is the output of `buildCipherUpdatePayload`, every sensitive field
 * already an `EncString`. The cleartext edit is never stored — encrypting at
 * replay would leave a cleartext password waiting on disk for the network to
 * return. What it does add is metadata: the identifiers and revision dates of
 * items edited offline. **Not their names**: an entry once carried the item's
 * decrypted name as a label for the user, and nothing ever displayed it. A
 * list of the names of the items edited offline is a list of the user's
 * accounts, on disk, in clear, for as long as the network stays away.
 *
 * ## The cap
 *
 * A queue that cannot be sent is a queue that grows. Two hundred entries is far
 * beyond any plausible offline session and well inside the storage quota; past
 * it the oldest are dropped, because a queue that fills up and then silently
 * refuses new writes would be worse than one that forgets the stalest.
 */

import { collapse, type QueuedWrite } from '../core/vault/offlineQueue.js';

const QUEUE_KEY = 'writeQueue';

/** How many held writes are kept before the oldest are dropped. */
const QUEUE_LIMIT = 200;

const hasLocalStorage = typeof chrome !== 'undefined' && chrome.storage?.local !== undefined;

/** Everything a stored entry must have to be replayable. */
function isQueuedWrite(value: unknown): value is QueuedWrite {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const e = value as Partial<QueuedWrite>;
  return (
    typeof e.id === 'string' &&
    (e.kind === 'create' || e.kind === 'update') &&
    (typeof e.cipherId === 'string' || e.cipherId === null) &&
    typeof e.payload === 'object' &&
    e.payload !== null &&
    typeof e.queuedAt === 'number'
  );
}

/**
 * The held writes, oldest first, with repeated edits of one item collapsed.
 *
 * Entries that no longer parse are dropped rather than crashing the queue: a
 * write from a version whose shape has changed cannot be sent anyway, and
 * refusing to load the rest because of it would strand every other edit.
 */
export async function loadWriteQueue(): Promise<readonly QueuedWrite[]> {
  if (!hasLocalStorage) {
    return [];
  }
  const stored = await chrome.storage.local.get(QUEUE_KEY);
  const value = stored[QUEUE_KEY];
  return Array.isArray(value) ? collapse(value.filter(isQueuedWrite)) : [];
}

/** Adds one write to the queue. */
export async function enqueueWrite(entry: QueuedWrite): Promise<void> {
  if (!hasLocalStorage) {
    return;
  }
  const queue = [...(await loadWriteQueue()), entry];
  await chrome.storage.local.set({ [QUEUE_KEY]: collapse(queue).slice(-QUEUE_LIMIT) });
}

/** Removes the named entries — those sent, and those the user gave up on. */
export async function removeWrites(ids: readonly string[]): Promise<void> {
  if (!hasLocalStorage || ids.length === 0) {
    return;
  }
  const dropped = new Set(ids);
  const left = (await loadWriteQueue()).filter((entry) => !dropped.has(entry.id));
  if (left.length === 0) {
    await chrome.storage.local.remove(QUEUE_KEY);
  } else {
    await chrome.storage.local.set({ [QUEUE_KEY]: left });
  }
}

/** Abandons every held write. @returns How many were discarded. */
export async function clearWriteQueue(): Promise<number> {
  const queue = await loadWriteQueue();
  if (hasLocalStorage && queue.length > 0) {
    await chrome.storage.local.remove(QUEUE_KEY);
  }
  return queue.length;
}
