/**
 * @file Types for the Bitwarden / Vaultwarden API responses.
 *
 * These interfaces describe **untrusted** data: it comes from the server, which
 * is treated as hostile. They are therefore expected shapes, not guarantees.
 * Any value coming out of these types must be validated before use — the KDF
 * parameters in particular (see `assertKdfIsAcceptable`).
 *
 * ## Field casing
 *
 * The API migrated from PascalCase to camelCase over successive versions, and
 * Vaultwarden follows with offsets of its own. Rather than freezing a choice,
 * every access goes through `readField()`, which accepts both. This is
 * deliberate defensive code: casing is the leading cause of interoperability
 * breakage between third-party clients and Vaultwarden.
 */

/** Response of `POST /identity/accounts/prelogin`. */
export interface PreloginResponse {
  readonly kdf?: number;
  readonly kdfIterations?: number;
  readonly kdfMemory?: number | null;
  readonly kdfParallelism?: number | null;
}

/** Successful response of `POST /identity/connect/token`. */
export interface TokenResponse {
  readonly access_token: string;
  readonly refresh_token?: string;
  readonly expires_in: number;
  readonly token_type: string;
  /** Vault key, wrapped by the stretched master key. */
  readonly Key?: string;
  readonly PrivateKey?: string;
  /**
   * Two-factor remember token, issued if `twoFactorRemember=1` was requested.
   * To be kept and replayed as provider 5 (`Remember`).
   */
  readonly TwoFactorToken?: string;
}

/** Error response of `POST /identity/connect/token`. */
export interface TokenErrorResponse {
  readonly error?: string;
  readonly error_description?: string;
  /** Present when a second authentication step is required. */
  readonly TwoFactorProviders?: readonly string[];
  readonly TwoFactorProviders2?: Record<string, unknown>;
  /** Present when the server demands a captcha before retrying. */
  readonly HCaptcha_SiteKey?: string;
}

/**
 * Two-factor provider identifiers, as the API transmits them (as numeric
 * strings in the error responses).
 *
 * Values imposed by the API, do not renumber. The UI uses them to show a label
 * and to route to the right entry screen.
 */
export const TwoFactorProvider = {
  Authenticator: 0,
  Email: 1,
  Duo: 2,
  YubiKey: 3,
  U2f: 4,
  Remember: 5,
  OrganizationDuo: 6,
  WebAuthn: 7,
} as const;

export type TwoFactorProvider = (typeof TwoFactorProvider)[keyof typeof TwoFactorProvider];

/**
 * A passkey (FIDO2 credential) stored inside a login item.
 *
 * Every field is a serialised `EncString`, except `creationDate`. `keyValue` is
 * the ECDSA P-256 **private key** (PKCS#8): it is what lets the extension answer
 * WebAuthn ceremonies in place of a hardware key.
 */
export interface Fido2CredentialResponse {
  readonly credentialId?: string | null;
  readonly keyType?: string | null;
  readonly keyAlgorithm?: string | null;
  readonly keyCurve?: string | null;
  readonly keyValue?: string | null;
  readonly rpId?: string | null;
  readonly rpName?: string | null;
  readonly userHandle?: string | null;
  readonly userName?: string | null;
  readonly userDisplayName?: string | null;
  readonly counter?: string | null;
  readonly discoverable?: string | null;
  readonly creationDate?: string | null;
}

/** A vault item, as returned by `GET /api/sync`. */
export interface CipherResponse {
  readonly id: string;
  readonly type: number;
  readonly name?: string | null;
  readonly notes?: string | null;
  readonly login?: {
    readonly username?: string | null;
    readonly password?: string | null;
    readonly totp?: string | null;
    readonly uris?: ReadonlyArray<{ readonly uri?: string | null }> | null;
    readonly fido2Credentials?: readonly Fido2CredentialResponse[] | null;
  } | null;
  /** The item's own key, if present. Wrapped by the vault key. */
  readonly key?: string | null;
  readonly organizationId?: string | null;
  /** Personal folder (only one possible). */
  readonly folderId?: string | null;
  /** Organisation collections the item belongs to. */
  readonly collectionIds?: readonly string[] | null;
  /**
   * When the item was created, in clear.
   *
   * The only date that says how old a **password** is when it has never been
   * changed since — which is the common case, and precisely the one a health
   * report must not miss.
   */
  readonly creationDate?: string | null;
  /**
   * When the item last changed, in clear.
   *
   * Moves on any edit, a rename included, so it says nothing about the age of
   * the password. It is what conflict detection compares
   * (`offlineQueue.decideReplay`) and what lets an unchanged item be reused
   * without decrypting it again (`reuseByRevision`).
   */
  readonly revisionDate?: string | null;
}

/** A personal folder. The name is encrypted with the vault key. */
export interface FolderResponse {
  readonly id?: string;
  readonly name?: string | null;
}

/**
 * An organisation collection — sharing's unit of access control.
 * The name is encrypted with **the organisation's** key, not the vault's.
 */
export interface CollectionResponse {
  readonly id?: string;
  readonly organizationId?: string | null;
  readonly name?: string | null;
  readonly readOnly?: boolean;
  readonly hidePasswords?: boolean;
}

/** An organisation the account belongs to, as listed in the profile. */
export interface ProfileOrganizationResponse {
  readonly id?: string;
  /**
   * The organisation's key (64 bytes), RSA-encrypted to the member's public
   * key — an `EncString` of type 4 (or 3).
   */
  readonly key?: string | null;
  readonly name?: string | null;
}

/** Response of `GET /api/sync`. */
export interface SyncResponse {
  readonly profile?: {
    readonly id?: string;
    readonly email?: string;
    readonly key?: string;
    readonly privateKey?: string | null;
    readonly organizations?: readonly ProfileOrganizationResponse[] | null;
  };
  readonly ciphers?: readonly CipherResponse[];
  readonly folders?: readonly FolderResponse[] | null;
  readonly collections?: readonly CollectionResponse[] | null;
}

/**
 * Vault item types.
 *
 * Values imposed by the API, do not renumber.
 */
export const CipherType = {
  Login: 1,
  SecureNote: 2,
  Card: 3,
  Identity: 4,
  SshKey: 5,
} as const;

export type CipherType = (typeof CipherType)[keyof typeof CipherType];

/**
 * Device type identifier, sent at authentication time.
 *
 * Vaultwarden uses it to display active sessions and for new-device
 * notifications.
 */
export const DeviceType = {
  ChromeExtension: 2,
  FirefoxExtension: 3,
} as const;

export type DeviceType = (typeof DeviceType)[keyof typeof DeviceType];

/**
 * Reads a field while tolerating both casing conventions.
 *
 * Tries the name as given, then with the first letter flipped. Saves writing
 * every access as `obj.Key ?? obj.key`.
 *
 * @param source Raw response object.
 * @param name Field name, in either casing.
 * @returns The value found, or `undefined`.
 */
export function readField<T>(source: unknown, name: string): T | undefined {
  if (source === null || typeof source !== 'object') {
    return undefined;
  }

  const record = source as Record<string, unknown>;
  // `Object.hasOwn` rather than `in`: `in` walks the prototype chain, where
  // `constructor`, `toString` and `valueOf` always answer present. No API field
  // name collides with them today — so the guarantee rested on a coincidence,
  // when it can be structural for the same price.
  if (Object.hasOwn(record, name)) {
    return record[name] as T;
  }

  const flipped =
    name.charAt(0) === name.charAt(0).toUpperCase()
      ? name.charAt(0).toLowerCase() + name.slice(1)
      : name.charAt(0).toUpperCase() + name.slice(1);

  return Object.hasOwn(record, flipped) ? (record[flipped] as T) : undefined;
}
