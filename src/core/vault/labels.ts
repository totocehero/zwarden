/**
 * @file Vault labels: folders and collections, unified as "tags".
 *
 * Two distinct protocol mechanisms, one notion on the surface:
 *
 * - **folder** (`#name`) — personal filing, one per item, name encrypted with
 *   the vault key;
 * - **collection** (`@name`) — sharing's unit of access control, several per
 *   item, name encrypted with **its organisation's** key.
 *
 * This phase is read-only: decrypt the names for display and filtering.
 * Assignment and sharing by tag come later.
 */

import {
  type CollectionResponse,
  type FolderResponse,
  type SyncResponse,
  readField,
} from '../api/models.js';
import { decryptStringOrNull } from '../crypto/cryptoService.js';
import { SymmetricCryptoKey } from '../crypto/symmetricCryptoKey.js';
import type { CipherKeys } from './cipherService.js';
import { MissingOrgKeyError } from './keyring.js';

/** A decrypted collection, with what the UI needs to know. */
export interface CollectionLabel {
  readonly name: string;
  readonly organizationId: string | null;
  /**
   * `true` if the member has read-only access to this collection: the UI must
   * disable editing its items rather than promise a save that will fail with a
   * 403.
   */
  readonly readOnly: boolean;
}

/** The vault's decrypted labels. */
export interface VaultLabels {
  /** Personal folders: id → name. */
  readonly folders: ReadonlyMap<string, string>;
  /** Collections: id → label. */
  readonly collections: ReadonlyMap<string, CollectionLabel>;
  /** Organisations: id → name (in the clear in the profile). */
  readonly organizations: ReadonlyMap<string, string>;
}

/** Empty labels, for the UI's intermediate states. */
export const EMPTY_LABELS: VaultLabels = {
  folders: new Map(),
  collections: new Map(),
  organizations: new Map(),
};

/**
 * Decrypts the labels of a sync response.
 *
 * Robust by construction: an unreadable label is reported through `onError` and
 * skipped — it does not show up, and the rest of the vault lives on.
 *
 * @param sync Complete sync response.
 * @param keys The vault key alone, or the full keyring (organisations).
 * @param onError Notification for each unreadable label.
 */
export async function decryptLabels(
  sync: SyncResponse,
  keys: CipherKeys,
  onError: (error: unknown) => void,
): Promise<VaultLabels> {
  const userKey = keys instanceof SymmetricCryptoKey ? keys : keys.userKey;
  const orgKeys =
    keys instanceof SymmetricCryptoKey ? new Map<string, SymmetricCryptoKey>() : keys.orgKeys;

  const [folders, collections] = await Promise.all([
    decryptFolders(sync, userKey, onError),
    decryptCollections(sync, userKey, orgKeys, onError),
  ]);

  return { folders, collections, organizations: readOrganizations(sync) };
}

/** Personal folders: name encrypted with the vault key. */
async function decryptFolders(
  sync: SyncResponse,
  userKey: SymmetricCryptoKey,
  onError: (error: unknown) => void,
): Promise<Map<string, string>> {
  const folders = new Map<string, string>();
  for (const folder of readField<readonly FolderResponse[]>(sync, 'folders') ?? []) {
    const id = readField<string>(folder, 'id');
    if (id == null) {
      continue;
    }
    const name = await decryptStringOrNull(readField<string>(folder, 'name'), userKey, onError);
    if (name !== null) {
      folders.set(id, name);
    }
  }
  return folders;
}

/**
 * Organisation names. The only family of labels that arrives **in the clear** in
 * the profile: hence no decryption, and no async function.
 */
function readOrganizations(sync: SyncResponse): Map<string, string> {
  const organizations = new Map<string, string>();
  const profile = readField<SyncResponse['profile']>(sync, 'profile');
  for (const org of readField<ReadonlyArray<Record<string, unknown>>>(profile, 'organizations') ??
    []) {
    const id = readField<string>(org, 'id');
    const name = readField<string>(org, 'name');
    if (id != null && name != null) {
      organizations.set(id, name);
    }
  }
  return organizations;
}

/**
 * Collections. The name is encrypted with **its** organisation's key, not the
 * vault's: a collection whose organisation key was not unwrapped is reported and
 * skipped, without failing the others.
 */
async function decryptCollections(
  sync: SyncResponse,
  userKey: SymmetricCryptoKey,
  orgKeys: ReadonlyMap<string, SymmetricCryptoKey>,
  onError: (error: unknown) => void,
): Promise<Map<string, CollectionLabel>> {
  const collections = new Map<string, CollectionLabel>();
  for (const collection of readField<readonly CollectionResponse[]>(sync, 'collections') ?? []) {
    const id = readField<string>(collection, 'id');
    if (id == null) {
      continue;
    }
    const organizationId = readField<string | null>(collection, 'organizationId') ?? null;

    const key = organizationId === null ? userKey : orgKeys.get(organizationId);
    if (key === undefined) {
      onError(new MissingOrgKeyError(organizationId ?? 'unknown'));
      continue;
    }

    const name = await decryptStringOrNull(readField<string>(collection, 'name'), key, onError);
    if (name === null) {
      continue;
    }
    collections.set(id, {
      name,
      organizationId,
      readOnly: readField<boolean>(collection, 'readOnly') ?? false,
    });
  }
  return collections;
}
