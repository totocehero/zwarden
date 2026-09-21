/**
 * @file Orchestrating the vault unlock.
 *
 * ## Why this module exists
 *
 * A full unlock is a choreography whose order is critical:
 *
 * ```
 *   prelogin ─► deriveMasterKey ─► derivePasswordHash ─► login
 *                     │                                    │
 *                     ▼                                    ▼
 *              stretchMasterKey ──────► decrypts `protectedUserKey`
 *                     │                                    │
 *                  destroy()                               ▼
 *                                                     vault key
 * ```
 *
 * plus, on top, the memory hygiene: the master key and the stretched key must be
 * erased the moment they have served. Only the vault key survives. Every
 * consumer (popup, service worker, tests) that rewrote this dance would be one
 * more chance to get the order wrong or forget an erasure. It is therefore
 * written and audited **once**, here.
 *
 * ## Layer split
 *
 * `core/crypto` provides the primitives and the keys, `core/api` the transport
 * with no secrets at all, and this module is the only one that makes the two
 * meet.
 */

import { ApiClient, type LoginResult, type TwoFactorSubmission } from '../api/apiClient.js';
import { EncString } from '../crypto/encString.js';
import { decryptBytes } from '../crypto/cryptoService.js';
import {
  HashPurpose,
  type KdfConfig,
  deriveMasterKey,
  derivePasswordHash,
  stretchMasterKey,
  KdfDowngradeError,
  isWeakerKdf,
} from '../crypto/kdf.js';
import { SymmetricCryptoKey } from '../crypto/symmetricCryptoKey.js';

/** Thrown when the server's response does not allow the vault to be opened. */
export class UnlockError extends Error {
  override readonly name = 'UnlockError';
  /** Stable identifier for the UI: the messages are for logs. */
  readonly code = 'unlock-failed';
}

/** The result of a successful unlock. */
export interface UnlockResult {
  /** Session tokens, for the API calls that follow. */
  readonly session: LoginResult;
  /**
   * Vault key, decrypted and authenticated. To be destroyed at lock time
   * (`userKey.destroy()`), together with a purge of all session storage.
   */
  readonly userKey: SymmetricCryptoKey;
  /**
   * Local password hash, to be kept for offline validation (see
   * `verifyLocalPasswordHash`). It cannot be replayed against the server: its
   * iteration count differs from the authorization hash's.
   */
  readonly localPasswordHash: string;
  /** Validated KDF parameters, to be kept for offline unlocking. */
  readonly kdfConfig: KdfConfig;
  /**
   * Two-factor remember token, present if `remember` was requested and granted.
   * To be persisted per device and replayed on subsequent unlocks (provider 5).
   */
  readonly twoFactorRememberToken: string | undefined;
}

/**
 * Unlocks the vault from the master password.
 *
 * Encapsulates the choreography described in the file header. On return, the
 * master key and the stretched key have been erased; only the vault key and the
 * tokens remain in memory.
 *
 * @param client API client pointing at the user's instance.
 * @param email Account email.
 * @param password Master password, in the clear. It is transmitted nowhere; its
 *   derived forms are erased by the layers below.
 * @param twoFactor Second factor to attach — a code entered after a first
 *   refusal, or a stored remember token (provider 5).
 * @returns Session, vault key, and the material for offline validation.
 * @param remembered The KDF parameters this device accepted for the account
 *   before, if any. Weaker ones announced now are refused.
 * @throws {WeakKdfError} Server KDF parameters out of bounds.
 * @throws {KdfDowngradeError} Server KDF parameters weaker than `remembered`.
 * @throws {TwoFactorRequiredError} A second step is demanded.
 * @throws {CaptchaRequiredError} The server demands a captcha.
 * @throws {RateLimitedError} The server is rate-limiting.
 * @throws {ApiError} Credentials refused, or any other HTTP failure.
 * @throws {UnlockError} A response with no usable vault key.
 * @throws {MacMismatchError} The wrapped vault key is unreadable — corruption or
 *   tampering server-side.
 */
export async function unlock(
  client: ApiClient,
  email: string,
  password: string,
  twoFactor?: TwoFactorSubmission,
  remembered?: KdfConfig | null,
): Promise<UnlockResult> {
  const kdfConfig = await client.prelogin(email);
  // Before any derivation, and so before any hash exists to be sent: the
  // announced parameters are compared with the ones this device accepted for
  // this account last time. Weaker is refused. The floors alone would let a
  // server take an account from 600,000 iterations to 100,000 unnoticed.
  if (remembered != null && isWeakerKdf(kdfConfig, remembered)) {
    throw new KdfDowngradeError(
      'The server announces weaker KDF parameters than this device accepted before',
    );
  }
  const masterKey = await deriveMasterKey(password, email, kdfConfig);

  try {
    // The two hashes are independent: computed side by side.
    const [serverHash, localPasswordHash] = await Promise.all([
      derivePasswordHash(masterKey, password, HashPurpose.ServerAuthorization),
      derivePasswordHash(masterKey, password, HashPurpose.LocalAuthorization),
    ]);

    const session = await client.login(email, serverHash, twoFactor);

    if (session.protectedUserKey === undefined) {
      throw new UnlockError(
        'The server supplied no wrapped vault key: incomplete account or tampered response',
      );
    }

    const stretched = await stretchMasterKey(masterKey);
    try {
      const rawUserKey = await decryptBytes(EncString.parse(session.protectedUserKey), stretched);
      return {
        session,
        userKey: new SymmetricCryptoKey(rawUserKey),
        localPasswordHash,
        kdfConfig,
        twoFactorRememberToken: session.twoFactorRememberToken,
      };
    } finally {
      stretched.destroy();
    }
  } finally {
    masterKey.destroy();
  }
}
