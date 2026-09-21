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

/**
 * Raised (through `onError`) when an organisation key is refused.
 *
 * Two reasons, both about the server rather than the maths. The key wraps to
 * the member's **public** key, which the server holds: nothing in the format
 * binds an organisation key to anything the user controls, so a server can
 * hand out one it knows. What this code can check, it checks —
 *
 * - `length`: an organisation key is 64 bytes, always. A 32-byte one would
 *   make the unauthenticated legacy path reachable for that organisation's
 *   items, and the downgrade refusal of `docs/CRYPTO.md` §7 rests on key
 *   length alone;
 * - `changed`: the key differs from the one this device saw for the same
 *   organisation before. Keys are not rotated in this format; a changed key
 *   is a substituted one.
 */
export class OrgKeyRefusedError extends Error {
  override readonly name = 'OrgKeyRefusedError';
  readonly code = 'org-key-refused';

  constructor(
    readonly organizationId: string,
    readonly reason: 'length' | 'changed',
  ) {
    super(`Organisation key refused (${reason}): ${organizationId}`);
  }
}

/** Raised (through `onError`) when an organisation item has no known key. */
export class MissingOrgKeyError extends Error {
  override readonly name = 'MissingOrgKeyError';
  /** Stable identifier for the UI: the messages are for logs. */
  readonly code = 'missing-org-key';

  constructor(readonly organizationId: string) {
    super(`Organisation key unavailable: ${organizationId}`);
  }
}

/** An organisation key is an authenticated key: `enc ‖ mac`, 64 bytes. */
const ORG_KEY_LENGTH = 64;

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
        if (raw.length !== ORG_KEY_LENGTH) {
          wipe(raw);
          throw new OrgKeyRefusedError(id, 'length');
        }
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

/**
 * A fingerprint of a key, to recognise it later without keeping it.
 *
 * SHA-256 of the key bytes, hex. Comparing fingerprints tells "the same key"
 * from "a different one"; it does not weaken the key, which is 64 random bytes
 * and not something a digest can be inverted to.
 */
export async function fingerprintKey(key: SymmetricCryptoKey): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', key.key as unknown as BufferSource);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** What reconciling a keyring against remembered fingerprints produced. */
export interface PinOutcome {
  /** The fingerprints to remember from now on. */
  readonly pins: Readonly<Record<string, string>>;
  /** Organisations whose key differs from the one remembered. */
  readonly refused: readonly string[];
  /** Organisations this device had never seen before. */
  readonly firstSeen: readonly string[];
}

/**
 * Compares the organisation keys just unwrapped with the ones seen before.
 *
 * Trust on first use, the same bargain as an SSH host key. A key seen for the
 * first time is remembered; a key that differs from the remembered one is
 * refused, and the organisation's items go unread rather than be read — or,
 * worse, **written** — with a key the server chose. An organisation that
 * disappears from the profile keeps its pin: a server that removes one and
 * brings it back with a new key is exactly the case a pin is for.
 *
 * First use is the gap, and it is stated: a server can still add an
 * organisation the user never joined. What a pin buys is that it can only do
 * so **once**, visibly, and cannot touch the organisations already there.
 * What the caller does with `firstSeen` closes part of the rest.
 *
 * Pure: no storage. The caller loads and saves the pins.
 *
 * @param remembered Fingerprints by organisation id, as last saved.
 * @param current Fingerprints of the keys just unwrapped.
 */
export function reconcilePins(
  remembered: Readonly<Record<string, string>>,
  current: ReadonlyMap<string, string>,
): PinOutcome {
  const pins: Record<string, string> = { ...remembered };
  const refused: string[] = [];
  const firstSeen: string[] = [];
  for (const [id, fingerprint] of current) {
    const known = Object.hasOwn(remembered, id) ? remembered[id] : undefined;
    if (known === undefined) {
      pins[id] = fingerprint;
      firstSeen.push(id);
    } else if (known !== fingerprint) {
      refused.push(id);
    }
  }
  return { pins, refused, firstSeen };
}

/**
 * The keyring without the organisations named, their keys destroyed.
 *
 * For the keys a pin refused: a key that stays in the ring is a key something
 * will encrypt with.
 */
export function withoutOrganisations(keys: VaultKeys, ids: readonly string[]): VaultKeys {
  if (ids.length === 0) {
    return keys;
  }
  const orgKeys = new Map(keys.orgKeys);
  for (const id of ids) {
    orgKeys.get(id)?.destroy();
    orgKeys.delete(id);
  }
  return { userKey: keys.userKey, orgKeys };
}
