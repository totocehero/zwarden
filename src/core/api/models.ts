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
}

/** Réponse d'erreur de `POST /identity/connect/token`. */
export interface TokenErrorResponse {
  readonly error?: string;
  readonly error_description?: string;
  /** Présent lorsqu'une seconde étape d'authentification est requise. */
  readonly TwoFactorProviders?: readonly string[];
  readonly TwoFactorProviders2?: Record<string, unknown>;
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
  } | null;
  /** Clé propre à l'item, si présente. Enveloppée par la clé du coffre. */
  readonly key?: string | null;
  readonly organizationId?: string | null;
}

/** Réponse de `GET /api/sync`. */
export interface SyncResponse {
  readonly profile?: {
    readonly id?: string;
    readonly email?: string;
    readonly key?: string;
    readonly privateKey?: string | null;
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
