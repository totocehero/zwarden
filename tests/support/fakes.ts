/**
 * @file The browser APIs the storage layer talks to, faked.
 *
 * Shared rather than copied into each test file: three suites need the same
 * two fakes, and three copies of a fake drift until they disagree about the
 * thing they are supposed to be pinning.
 *
 * Not collected as a suite — vitest only picks up `*.test.ts`.
 */

import { vi } from 'vitest';

/** What a fake storage area exposes to the test that installed it. */
export interface FakeArea {
  /** The stored data, readable directly for assertions. */
  readonly data: Record<string, unknown>;
  /** Every key any `get` asked for, in order. */
  readonly reads: string[];
}

/**
 * Installs a `chrome.storage` whose `local` and `session` areas share one map.
 *
 * Sharing is deliberate: the tests here assert *which entry* a call touches,
 * never which area it lives in, and two maps would only make the assertions
 * longer without making them stronger.
 */
export function fakeChromeStorage(): FakeArea {
  const data: Record<string, unknown> = {};
  const reads: string[] = [];
  const area = {
    get: vi.fn(async (keys: string | string[] | null) => {
      const list = keys === null ? Object.keys(data) : Array.isArray(keys) ? keys : [keys];
      reads.push(...list);
      return Object.fromEntries(list.filter((k) => k in data).map((k) => [k, data[k]]));
    }),
    set: vi.fn(async (patch: Record<string, unknown>) => {
      Object.assign(data, patch);
    }),
    remove: vi.fn(async (keys: string | string[]) => {
      for (const key of Array.isArray(keys) ? keys : [keys]) {
        delete data[key];
      }
    }),
  };
  (globalThis as unknown as { chrome: unknown }).chrome = {
    storage: { local: area, session: area },
  };
  return { data, reads };
}

/**
 * Installs an IndexedDB faithful enough for one store of one record.
 *
 * Written rather than installed: the alternative is a dependency in a password
 * manager's tree, to exercise sixty lines. It holds values by reference, so a
 * `CryptoKey` survives it exactly as structured clone would.
 */
export function fakeIndexedDb(): { records: Map<string, unknown> } {
  const records = new Map<string, unknown>();

  /** A request whose handlers fire once the caller has had a chance to set them. */
  function request<T>(compute: () => T): Record<string, unknown> {
    const req: Record<string, unknown> = { result: undefined, error: null };
    queueMicrotask(() => {
      try {
        req['result'] = compute();
        (req['onsuccess'] as (() => void) | undefined)?.();
      } catch (error) {
        req['error'] = error;
        (req['onerror'] as (() => void) | undefined)?.();
      }
    });
    return req;
  }

  const store = {
    get: (id: string) => request(() => records.get(id)),
    put: (value: unknown, id: string) => request(() => void records.set(id, value)),
    delete: (id: string) => request(() => void records.delete(id)),
  };

  const db = {
    close: () => undefined,
    createObjectStore: () => store,
    transaction: () => ({ objectStore: () => store }),
  };

  (globalThis as unknown as { indexedDB: unknown }).indexedDB = {
    open: () => {
      const req: Record<string, unknown> = { result: db, error: null };
      queueMicrotask(() => {
        (req['onupgradeneeded'] as (() => void) | undefined)?.();
        (req['onsuccess'] as (() => void) | undefined)?.();
      });
      return req;
    },
  };
  return { records };
}

/** Removes IndexedDB, to exercise the fail-closed path. */
export function withoutIndexedDb(): void {
  (globalThis as unknown as { indexedDB: unknown }).indexedDB = undefined;
}
