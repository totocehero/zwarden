/**
 * @file The vault's keyring: personal key + organisation keys.
 *
 * A personal item is encrypted with the vault key; a shared item, with **its
 * organisation's** key. Those organisation keys arrive in the sync profile,
 * RSA-encrypted to the member's public key. The unwrapping chain:
 *
 * ```
 *   vault key ──decrypts──► RSA private key (profile.privateKey, type 2)
 *   RSA private key ──decrypts──► organisation key (organizations[].key, type 4)
 *   organisation key ──decrypts──► the organisation's items
 * ```
 *
 * The keyring is rebuilt on every sync: none of this is persisted.
 */

import { type ProfileOrganizationResponse, type SyncResponse, readField } from '../api/models.js';
import { EncString } from '../crypto/encString.js';
import { decryptBytes, decryptRsaBytes } from '../crypto/cryptoService.js';
import { wipe } from '../crypto/encoding.js';
import { SymmetricCryptoKey } from '../crypto/symmetricCryptoKey.js';

/** Raised (through `onError`) when an organisation item has no known key. */
export class MissingOrgKeyError extends Error {
  override readonly name = 'MissingOrgKeyError';
  /** Stable identifier for the UI: the messages are for logs. */
  readonly code = 'missing-org-key';

  constructor(readonly organizationId: string) {
    super(`Organisation key unavailable: ${organizationId}`);
  }
}

/** The keys needed to decrypt the whole vault. */
export interface VaultKeys {
  readonly userKey: SymmetricCryptoKey;
  /** Unwrapped organisation keys, indexed by organisation identifier. */
  readonly orgKeys: ReadonlyMap<string, SymmetricCryptoKey>;
}

/**
 * Builds the keyring from the sync profile.
 *
 * Robust by construction: an organisation whose key fails to unwrap is reported
 * through `onError` and skipped — its items will be unreadable, the rest of the
 * vault will not. With no organisation, no RSA cryptography is touched at all.
 *
 * @param profile The `profile` field of the sync response.
 * @param userKey The vault key.
 * @param onError Notification for each key that cannot be unwrapped.
 * @returns The keyring, with organisation keys resolved.
 */
export async function buildVaultKeys(
  profile: SyncResponse['profile'],
  userKey: SymmetricCryptoKey,
  onError: (error: unknown) => void,
): Promise<VaultKeys> {
  const orgKeys = new Map<string, SymmetricCryptoKey>();
  const organizations =
    readField<readonly ProfileOrganizationResponse[]>(profile, 'organizations') ?? [];

  if (organizations.length === 0) {
    return { userKey, orgKeys };
  }

  const protectedPrivateKey = readField<string>(profile, 'privateKey');
  if (protectedPrivateKey == null || protectedPrivateKey === '') {
    onError(new Error('Profile without a private key: organisation keys are undecryptable'));
    return { userKey, orgKeys };
  }

  let pkcs8: Uint8Array;
  try {
    pkcs8 = await decryptBytes(EncString.parse(protectedPrivateKey), userKey);
  } catch (error) {
    onError(error);
    return { userKey, orgKeys };
  }

  try {
    for (const organization of organizations) {
      const id = readField<string>(organization, 'id');
      const wrapped = readField<string>(organization, 'key');
      if (id == null || wrapped == null || wrapped === '') {
        continue;
      }
      try {
        const raw = await decryptRsaBytes(EncString.parse(wrapped), pkcs8);
        orgKeys.set(id, new SymmetricCryptoKey(raw));
      } catch (error) {
        onError(error);
      }
    }
  } finally {
    // The private key has no further use once the organisation keys are
    // unwrapped. Best-effort, like every erasure in JavaScript.
    wipe(pkcs8);
  }

  return { userKey, orgKeys };
}

/**
 * Erases all of a keyring's key material.
 *
 * To be called at lock time, and that is the point: `userKey.destroy()` alone
 * left the organisation keys — able to decrypt every shared item — in memory
 * until the garbage collector came round, without being overwritten. The
 * inconsistency was all the sharper given that the RSA private key *is* erased
 * as soon as it has served its purpose ({@link buildVaultKeys}).
 *
 * Accepts a bare key as readily as a keyring: the caller locks without having to
 * know which case it is in.
 *
 * Best-effort, like every erasure in JavaScript — see
 * `SymmetricCryptoKey.destroy()`.
 */
export function destroyVaultKeys(keys: SymmetricCryptoKey | VaultKeys): void {
  if (keys instanceof SymmetricCryptoKey) {
    keys.destroy();
    return;
  }
  keys.userKey.destroy();
  for (const orgKey of keys.orgKeys.values()) {
    orgKey.destroy();
  }
}

/**
 * An item's base key: the vault's, or its organisation's.
 *
 * @returns `null` if the item belongs to an organisation whose key could not be
 *   unwrapped.
 */
export function keyForCipher(cipher: unknown, keys: VaultKeys): SymmetricCryptoKey | null {
  const organizationId = readField<string | null>(cipher, 'organizationId') ?? null;
  if (organizationId === null) {
    return keys.userKey;
  }
  return keys.orgKeys.get(organizationId) ?? null;
}
