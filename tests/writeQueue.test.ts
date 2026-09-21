/**
 * @file The held-writes queue, as it is actually stored.
 *
 * The rules live in `offlineQueue.ts` and are tested apart; what is pinned here
 * is the storage contract — that the queue survives, that it collapses, that it
 * is capped, and above all that **no cleartext ever lands in it**.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { QueuedWrite } from '../src/core/vault/offlineQueue.js';

import { fakeChromeStorage } from './support/fakes.js';

function entry(patch: Partial<QueuedWrite> = {}): QueuedWrite {
  return {
    id: 'q1',
    kind: 'update',
    cipherId: 'item-1',
    payload: { name: '2.aXY=|Y2lwaGVy|bWFj' },
    baseRevision: '2026-09-01T10:00:00Z',
    queuedAt: 1_000,
    ...patch,
  };
}

describe('the held-writes queue', () => {
  let store: { data: Record<string, unknown> };

  beforeEach(() => {
    vi.resetModules();
    store = fakeChromeStorage();
  });

  async function load() {
    return import('../src/shared/writeQueue.js');
  }

  it('holds a write and gives it back', async () => {
    const { enqueueWrite, loadWriteQueue } = await load();
    await enqueueWrite(entry());

    const queue = await loadWriteQueue();
    expect(queue).toHaveLength(1);
    expect(queue[0]!.cipherId).toBe('item-1');
  });

  it('stores only what was already encrypted', async () => {
    const { enqueueWrite } = await load();
    await enqueueWrite(entry({ payload: { login: { password: '2.aXY=|Y2lwaGVy|bWFj' } } }));

    // The contract the whole feature rests on: encrypt, then queue. Queueing
    // the edit and encrypting at replay would leave a cleartext password
    // waiting on disk for the network to come back.
    const written = JSON.stringify(store.data);
    expect(written).not.toContain('hunter2');
    expect(written).toContain('2.aXY=');
  });

  it('keeps the last of several edits of one item', async () => {
    const { enqueueWrite, loadWriteQueue } = await load();
    await enqueueWrite(entry({ id: 'a', queuedAt: 1_000, payload: { name: 'first' } }));
    await enqueueWrite(entry({ id: 'b', queuedAt: 2_000, payload: { name: 'second' } }));

    const queue = await loadWriteQueue();
    expect(queue).toHaveLength(1);
    expect(queue[0]!.payload).toEqual({ name: 'second' });
  });

  it('survives the entries it cannot read', async () => {
    // A write from a version whose shape has changed cannot be sent anyway;
    // refusing to load the rest because of it would strand every other edit.
    store.data['writeQueue'] = [entry(), { nonsense: true }, null];
    const { loadWriteQueue } = await load();

    expect(await loadWriteQueue()).toHaveLength(1);
  });

  it('removes what was sent and keeps the rest', async () => {
    const { enqueueWrite, loadWriteQueue, removeWrites } = await load();
    await enqueueWrite(entry({ id: 'a', cipherId: 'item-1' }));
    await enqueueWrite(entry({ id: 'b', cipherId: 'item-2', queuedAt: 2_000 }));

    await removeWrites(['a']);

    const queue = await loadWriteQueue();
    expect(queue.map((e) => e.id)).toEqual(['b']);
  });

  it('leaves nothing behind once the last entry goes', async () => {
    const { enqueueWrite, removeWrites } = await load();
    await enqueueWrite(entry({ id: 'a' }));

    await removeWrites(['a']);

    // An empty array left in storage would be a queue that looks present for
    // ever after.
    expect(store.data['writeQueue']).toBeUndefined();
  });

  it('caps the queue rather than growing without end', async () => {
    const { enqueueWrite, loadWriteQueue } = await load();
    for (let i = 0; i < 205; i += 1) {
      await enqueueWrite(entry({ id: `q${i}`, cipherId: `item-${i}`, queuedAt: i }));
    }

    const queue = await loadWriteQueue();
    expect(queue).toHaveLength(200);
    // The oldest go: a queue that fills up and then silently refuses new writes
    // would be worse than one that forgets the stalest.
    expect(queue[0]!.id).toBe('q5');
  });

  it('discards everything on request, and says how many', async () => {
    const { clearWriteQueue, enqueueWrite, loadWriteQueue } = await load();
    await enqueueWrite(entry({ id: 'a', cipherId: 'item-1' }));
    await enqueueWrite(entry({ id: 'b', cipherId: 'item-2', queuedAt: 2_000 }));

    expect(await clearWriteQueue()).toBe(2);
    expect(await loadWriteQueue()).toEqual([]);
  });

  it('reports nothing to discard when empty', async () => {
    const { clearWriteQueue } = await load();
    expect(await clearWriteQueue()).toBe(0);
  });
});
