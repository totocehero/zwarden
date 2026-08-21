/**
 * @file Types des réponses de l'API Bitwarden / Vaultwarden.
 *
 * Ces interfaces décrivent des données **non fiables** : elles proviennent du
 * serveur, considéré comme hostile. Elles ne sont donc que des formes attendues,
 * pas des garanties. Toute valeur issue de ces types doit être validée avant
 * usage — en particulier les paramètres KDF (voir `assertKdfIsAcceptable`).
 *
 * ## Casse des champs
 *
 * L'API a migré de PascalCase vers camelCase au fil des versions, et
 * Vaultwarden suit avec ses propres décalages. Plutôt que de figer un choix,
 * les accès passent par `readField()`, qui accepte les deux. C'est du code
 * défensif assumé : la casse est la première cause de casse d'interopérabilité
 * entre clients tiers et Vaultwarden.
 */

/** Réponse de `POST /identity/accounts/prelogin`. */
export interface PreloginResponse {
  readonly kdf?: number;
  readonly kdfIterations?: number;
  readonly kdfMemory?: number | null;
  readonly kdfParallelism?: number | null;
}

/** Réponse de `POST /identity/connect/token` en cas de succès. */
export interface TokenResponse {
  readonly access_token: string;
  readonly refresh_token?: string;
  readonly expires_in: number;
  readonly token_type: string;
  /** Clé du coffre, enveloppée par la clé maître étirée. */
  readonly Key?: string;
  readonly PrivateKey?: string;
  /**
   * Jeton de dispense de second facteur, émis si `twoFactorRemember=1` a été
   * demandé. À conserver et rejouer comme fournisseur 5 (`Remember`).
   */
  readonly TwoFactorToken?: string;
}

/** Réponse d'erreur de `POST /identity/connect/token`. */
export interface TokenErrorResponse {
  readonly error?: string;
  readonly error_description?: string;
  /** Présent lorsqu'une seconde étape d'authentification est requise. */
  readonly TwoFactorProviders?: readonly string[];
  readonly TwoFactorProviders2?: Record<string, unknown>;
  /** Présent lorsque le serveur exige un captcha avant de réessayer. */
  readonly HCaptcha_SiteKey?: string;
}

/**
 * Identifiants des fournisseurs de second facteur, tels que transmis par
 * l'API (sous forme de chaînes numériques dans les réponses d'erreur).
 *
 * Valeurs imposées par l'API, ne pas renuméroter. L'interface s'en sert pour
 * afficher un libellé et router vers le bon écran de saisie.
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
 * Passkey (identifiant FIDO2) rangée dans un item de connexion.
 *
 * Tous les champs sont des `EncString` sérialisées, sauf `creationDate`.
 * `keyValue` est la **clé privée** ECDSA P-256 (PKCS#8) : c'est elle qui
 * permet à l'extension de répondre aux cérémonies WebAuthn à la place d'une
 * clé matérielle.
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

/** Item du coffre, tel que renvoyé par `GET /api/sync`. */
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
  /** Clé propre à l'item, si présente. Enveloppée par la clé du coffre. */
  readonly key?: string | null;
  readonly organizationId?: string | null;
}

/** Organisation dont le compte est membre, telle que listée dans le profil. */
export interface ProfileOrganizationResponse {
  readonly id?: string;
  /**
   * Clé de l'organisation (64 octets), chiffrée en RSA vers la clé publique
   * du membre — `EncString` de type 4 (ou 3).
   */
  readonly key?: string | null;
  readonly name?: string | null;
}

/** Réponse de `GET /api/sync`. */
export interface SyncResponse {
  readonly profile?: {
    readonly id?: string;
    readonly email?: string;
    readonly key?: string;
    readonly privateKey?: string | null;
    readonly organizations?: readonly ProfileOrganizationResponse[] | null;
  };
  readonly ciphers?: readonly CipherResponse[];
  readonly folders?: readonly unknown[];
}

/**
 * Types d'items du coffre.
 *
 * Valeurs imposées par l'API, ne pas renuméroter.
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
 * Identifiant de type d'appareil, transmis à l'authentification.
 *
 * Vaultwarden s'en sert pour l'affichage des sessions actives et pour les
 * notifications de nouvel appareil.
 */
export const DeviceType = {
  ChromeExtension: 2,
  FirefoxExtension: 3,
} as const;

export type DeviceType = (typeof DeviceType)[keyof typeof DeviceType];

/**
 * Lit un champ en tolérant les deux conventions de casse.
 *
 * Essaie le nom tel quel, puis avec la première lettre inversée. Évite de
 * dupliquer chaque accès en `obj.Key ?? obj.key`.
 *
 * @param source Objet de réponse brut.
 * @param name Nom du champ, dans l'une ou l'autre casse.
 * @returns La valeur trouvée, ou `undefined`.
 */
export function readField<T>(source: unknown, name: string): T | undefined {
  if (source === null || typeof source !== 'object') {
    return undefined;
  }

  const record = source as Record<string, unknown>;
  if (name in record) {
    return record[name] as T;
  }

  const flipped =
    name.charAt(0) === name.charAt(0).toUpperCase()
      ? name.charAt(0).toLowerCase() + name.slice(1)
      : name.charAt(0).toUpperCase() + name.slice(1);

  return record[flipped] as T | undefined;
}
