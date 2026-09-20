/**
 * @file The rules for writes made while the server was unreachable.
 *
 * Two decisions, both of the kind that must be right rather than plausible: is
 * this failure worth holding on to, and is this write still safe to apply once
 * the server is back.
 *
 * The second is the dangerous one. Replaying an offline edit over an item that
 * changed in the meantime overwrites a password rotation with an older
 * password. In a password manager that is not a merge conflict, it is a
 * lockout — and it is silent.
 */

import { describe, expect, it } from 'vitest';

import { ApiError, RateLimitedError } from '../src/core/api/apiClient.js';
import type { CipherResponse } from '../src/core/api/models.js';
import {
  collapse,
  decideReplay,
  inSendOrder,
  isUnreachable,
  type QueuedWrite,
} from '../src/core/vault/offlineQueue.js';

function entry(patch: Partial<QueuedWrite> = {}): QueuedWrite {
  return {
    id: 'q1',
    kind: 'update',
    cipherId: 'item-1',
    payload: { name: '2.abc|def|ghi' },
    baseRevision: '2026-09-01T10:00:00Z',
    queuedAt: 1_000,
    label: 'My bank',
    ...patch,
  };
}

const server = (revisionDate: string): CipherResponse =>
  ({ id: 'item-1', revisionDate }) as unknown as CipherResponse;

describe('isUnreachable', () => {
  it('holds a write that timed out', () => {
    expect(isUnreachable(new DOMException('timed out', 'TimeoutError'))).toBe(true);
  });

  it('holds a write that was aborted', () => {
    expect(isUnreachable(new DOMException('aborted', 'AbortError'))).toBe(true);
  });

  it('holds a write that never left the machine', () => {
    // What `fetch` throws with no network, or a DNS failure on a self-hosted
    // instance.
    expect(isUnreachable(new TypeError('Failed to fetch'))).toBe(true);
  });

  it('does not hold a write the server refused', () => {
    // The server heard it and said no. Queueing would retry a refusal for ever,
    // and would hide a real error behind a reassuring "saved locally".
    expect(isUnreachable(new ApiError('bad request', 400, ''))).toBe(false);
    expect(isUnreachable(new ApiError('unauthorised', 401, ''))).toBe(false);
    expect(isUnreachable(new ApiError('server error', 500, ''))).toBe(false);
  });

  it('does not hold a rate limit', () => {
    // Also an answer, and one that says explicitly to wait rather than retry.
    expect(isUnreachable(new RateLimitedError(30))).toBe(false);
  });

  it('does not hold something that is not an error at all', () => {
    expect(isUnreachable('oops')).toBe(false);
    expect(isUnreachable(null)).toBe(false);
  });
});

describe('decideReplay', () => {
  it('always sends a creation', () => {
    // There is nothing a new item could overwrite.
    expect(decideReplay(entry({ kind: 'create', cipherId: null }), undefined)).toEqual({
      kind: 'replay',
    });
  });

  it('sends an update when nothing moved underneath it', () => {
    expect(decideReplay(entry(), server('2026-09-01T10:00:00Z'))).toEqual({ kind: 'replay' });
  });

  it('holds an update when the item changed elsewhere', () => {
    // The password may have been rotated on another device. Sending would put
    // the old one back, and say nothing.
    expect(decideReplay(entry(), server('2026-09-02T11:00:00Z'))).toEqual({ kind: 'conflict' });
  });

  it('does not resurrect an item deleted since', () => {
    // The deletion was a decision, on some device. A queue must not undo it.
    expect(decideReplay(entry(), undefined)).toEqual({ kind: 'gone' });
  });

  it('treats a server copy with no revision date as a conflict', () => {
    // Unknown is not "unchanged": erring the other way overwrites.
    expect(decideReplay(entry(), server('' as string))).toEqual({ kind: 'conflict' });
    expect(decideReplay(entry(), {} as unknown as CipherResponse)).toEqual({ kind: 'conflict' });
  });
});

describe('inSendOrder', () => {
  it('sends the oldest first', () => {
    const out = inSendOrder([
      entry({ id: 'b', queuedAt: 2_000 }),
      entry({ id: 'a', queuedAt: 1_000 }),
    ]);
    expect(out.map((e) => e.id)).toEqual(['a', 'b']);
  });

  it('does not alter the array it was given', () => {
    const given = [entry({ id: 'b', queuedAt: 2_000 }), entry({ id: 'a', queuedAt: 1_000 })];
    inSendOrder(given);
    expect(given.map((e) => e.id)).toEqual(['b', 'a']);
  });
});

describe('collapse', () => {
  it('keeps only the last edit of an item', () => {
    const out = collapse([
      entry({ id: 'a', queuedAt: 1_000, payload: { name: 'first' } }),
      entry({ id: 'b', queuedAt: 2_000, payload: { name: 'second' } }),
      entry({ id: 'c', queuedAt: 3_000, payload: { name: 'third' } }),
    ]);
    expect(out).toHaveLength(1);
    expect(out[0]!.payload).toEqual({ name: 'third' });
  });

  it('keeps the revision the chain of edits started from', () => {
    // The survivor must not claim agreement with a server state the user never
    // saw: the first edit was composed against the old revision, and every one
    // after it built on that.
    const out = collapse([
      entry({ id: 'a', queuedAt: 1_000, baseRevision: 'rev-1' }),
      entry({ id: 'b', queuedAt: 2_000, baseRevision: 'rev-2' }),
    ]);
    expect(out[0]!.baseRevision).toBe('rev-1');
  });

  it('keeps edits of different items apart', () => {
    const out = collapse([
      entry({ id: 'a', cipherId: 'item-1', queuedAt: 1_000 }),
      entry({ id: 'b', cipherId: 'item-2', queuedAt: 2_000 }),
    ]);
    expect(out).toHaveLength(2);
  });

  it('never collapses creations', () => {
    // Each is a distinct item, however alike.
    const out = collapse([
      entry({ id: 'a', kind: 'create', cipherId: null, queuedAt: 1_000 }),
      entry({ id: 'b', kind: 'create', cipherId: null, queuedAt: 2_000 }),
    ]);
    expect(out).toHaveLength(2);
  });

  it('returns the survivors oldest first', () => {
    const out = collapse([
      entry({ id: 'a', cipherId: 'item-2', queuedAt: 3_000 }),
      entry({ id: 'b', cipherId: 'item-1', queuedAt: 1_000 }),
    ]);
    expect(out.map((e) => e.cipherId)).toEqual(['item-1', 'item-2']);
  });

  it('leaves an empty queue empty', () => {
    expect(collapse([])).toEqual([]);
  });
});
