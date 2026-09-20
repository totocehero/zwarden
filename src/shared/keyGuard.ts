/**
 * @file Sealing the vault key, so the session store never holds it in clear.
 *
 * ## The circle, and the way out of it
 *
 * Encrypting the vault key needs another key, which needs somewhere to live,
 * which is the problem we started with. Stacking a layer buys nothing.
 *
 * The way out is a key that **has no bytes to store**. A `CryptoKey` created
 * with `extractable: false` cannot be exported by anyone, us included: its
 * material lives in the browser's crypto subsystem and never enters a
 * JavaScript heap. `chrome.storage` cannot hold one — it serialises to JSON —
 * but **IndexedDB can**, because it uses structured clone.
 *
 * So the two halves are split across the two stores, each useless alone:
 *
 * | Where | What | Alone, it is |
 * |---|---|---|
 * | IndexedDB, on disk | a non-extractable AES-GCM key | a key that opens nothing |
 * | `storage.session`, memory | the vault key, sealed | ciphertext with no key |
 *
 * Closing the browser purges `storage.session`, so the sealed half disappears
 * and the half on disk is inert. The lock guarantee is unchanged — which is the
 * reason the sealed half is *not* the one on disk.
 *
 * ## What this buys, precisely
 *
 * Before, the vault key sat in the session store as a base64 string for the
 * whole browser session — hours or days — and a JavaScript string cannot be
 * wiped. Now the resident copy is ciphertext, and the plaintext exists only in
 * the popup's heap, for as long as the popup is open.
 *
 * **The plaintext lifetime drops from the browser session to the popup's.**
 * That is the whole claim.
 *
 * ## What it does not buy
 *
 * Said plainly, because this is the kind of measure that turns into theatre if
 * left unqualified: Chrome implements WebCrypto in its own process, not in an
 * enclave. **A full memory dump of the browser still yields everything** — the
 * sealed blob and the material of the "non-extractable" key both. What this
 * defends against is narrower and real: a swap page, a hibernation image, a
 * partial heap read, anything that catches the long-lived resident copy rather
 * than the live process entire.
 *
 * ## Failure is closed
 *
 * If IndexedDB is unavailable, or the seal cannot be opened, no key is
 * returned: the vault behaves as locked and the user unlocks again. An
 * inconvenience. The alternative — falling back to storing the key in clear —
 * would be a silent downgrade of the thing this file exists to do.
 */

/** The IndexedDB database and store holding the sealing key. */
const DB_NAME = 'zwarden-keyguard';
const STORE = 'keys';
const RECORD = 'seal';

/** Bytes of AES-GCM nonce, prefixed to the ciphertext. */
const IV_LENGTH = 12;

/** Opens — and on first use creates — the one-record database. */
function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('IndexedDB unavailable'));
  });
}

/** Runs one transaction against the store and resolves with its result. */
function transact<T>(
  db: IDBDatabase,
  mode: IDBTransactionMode,
  run: (store: IDBObjectStore) => IDBRequest,
): Promise<T> {
  return new Promise((resolve, reject) => {
    const request = run(db.transaction(STORE, mode).objectStore(STORE));
    request.onsuccess = () => resolve(request.result as T);
    request.onerror = () => reject(request.error ?? new Error('IndexedDB request failed'));
  });
}

/**
 * The sealing key: the one stored in IndexedDB, or a fresh one.
 *
 * Non-extractable, so it cannot be exported even by this module. Generated
 * once per unlocked session and destroyed with it.
 */
async function sealingKey(create: boolean): Promise<CryptoKey | null> {
  if (typeof indexedDB === 'undefined') {
    return null;
  }
  const db = await openDatabase();
  try {
    const existing = await transact<CryptoKey | undefined>(db, 'readonly', (s) => s.get(RECORD));
    if (existing !== undefined) {
      return existing;
    }
    if (!create) {
      return null;
    }
    const fresh = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
      'encrypt',
      'decrypt',
    ]);
    await transact(db, 'readwrite', (s) => s.put(fresh, RECORD));
    return fresh;
  } finally {
    db.close();
  }
}

/**
 * Seals the vault key.
 *
 * @param plain The vault key, base64 — what used to be stored as-is.
 * @returns `iv ‖ ciphertext`, base64, or `null` if sealing is unavailable.
 */
export async function sealVaultKey(plain: string): Promise<string | null> {
  try {
    const key = await sealingKey(true);
    if (key === null) {
      return null;
    }
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const sealed = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plain)),
    );
    const joined = new Uint8Array(iv.length + sealed.length);
    joined.set(iv);
    joined.set(sealed, iv.length);
    return btoa(String.fromCharCode(...joined));
  } catch {
    return null;
  }
}

/**
 * Opens a sealed vault key.
 *
 * AES-GCM authenticates: a blob altered by so much as a bit fails to open
 * rather than yielding a wrong key, which would surface as an unreadable vault
 * and send the user looking in the wrong place.
 *
 * @returns The vault key, base64 — or `null`, which means locked.
 */
export async function openVaultKey(sealed: string): Promise<string | null> {
  try {
    const key = await sealingKey(false);
    if (key === null) {
      return null;
    }
    const bytes = Uint8Array.from(atob(sealed), (c) => c.charCodeAt(0));
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: bytes.subarray(0, IV_LENGTH) },
      key,
      bytes.subarray(IV_LENGTH),
    );
    return new TextDecoder().decode(plain);
  } catch {
    return null;
  }
}

/**
 * Destroys the sealing key.
 *
 * Called on lock, with the sealed blob. Either half alone is inert, so this is
 * belt and braces — but a key left behind is a key that outlives its purpose,
 * and those accumulate.
 */
export async function forgetSealingKey(): Promise<void> {
  if (typeof indexedDB === 'undefined') {
    return;
  }
  try {
    const db = await openDatabase();
    try {
      await transact(db, 'readwrite', (s) => s.delete(RECORD));
    } finally {
      db.close();
    }
  } catch {
    // Nothing to destroy, or no database at all.
  }
}
