/**
 * @file Client HTTP pour l'API Bitwarden / Vaultwarden.
 *
 * ## Responsabilité
 *
 * Ce module ne fait que du transport et de l'analyse de réponses. Il ne
 * déchiffre rien et ne détient aucune clé — la cryptographie vit dans
 * `core/crypto`. Cette séparation permet d'auditer les deux indépendamment :
 * une faille de transport ne peut pas exposer de clé, puisqu'il n'y en a pas
 * ici.
 *
 * ## Le mot de passe ne quitte jamais le client
 *
 * `login()` prend une clé maître déjà dérivée, jamais le mot de passe. Le
 * serveur ne reçoit que le hash d'autorisation (PBKDF2 à 1 itération sur la
 * clé maître). Cette signature rend l'erreur difficile à commettre.
 */

import { HashPurpose, derivePasswordHash, type KdfConfig, KdfType } from '../crypto/kdf.js';
import type { SymmetricCryptoKey } from '../crypto/symmetricCryptoKey.js';
import {
  type CipherResponse,
  DeviceType,
  type PreloginResponse,
  type SyncResponse,
  type TokenErrorResponse,
  type TokenResponse,
  readField,
} from './models.js';

/** Échec d'un appel API, avec le contexte nécessaire au diagnostic. */
export class ApiError extends Error {
  override readonly name = 'ApiError';

  constructor(
    message: string,
    readonly status: number,
    readonly body: string,
  ) {
    super(message);
  }
}

/** Levée lorsque le serveur exige une seconde étape d'authentification. */
export class TwoFactorRequiredError extends Error {
  override readonly name = 'TwoFactorRequiredError';

  constructor(readonly providers: readonly string[]) {
    super(`Authentification à deux facteurs requise (fournisseurs : ${providers.join(', ') || '?'})`);
  }
}

/** Session authentifiée, telle que renvoyée par {@link ApiClient.login}. */
export interface LoginResult {
  readonly accessToken: string;
  readonly refreshToken: string | undefined;
  /** Instant d'expiration, en millisecondes epoch. */
  readonly expiresAt: number;
  /**
   * Clé du coffre, enveloppée par la clé maître étirée.
   * Toujours chiffrée : le déchiffrement relève de l'appelant.
   */
  readonly protectedUserKey: string | undefined;
  readonly protectedPrivateKey: string | undefined;
}

export interface ApiClientOptions {
  /** URL de base de l'instance, par exemple `https://vault.exemple.fr`. */
  readonly serverUrl: string;
  /** Nom d'appareil affiché dans les sessions actives côté serveur. */
  readonly deviceName?: string;
  /**
   * Identifiant stable de l'appareil (UUID). Doit être persisté : le
   * régénérer à chaque connexion crée une session de plus à chaque fois et
   * déclenche les alertes « nouvel appareil ».
   */
  readonly deviceIdentifier: string;
  /** Injection pour les tests. Par défaut, `fetch` global. */
  readonly fetchFn?: typeof fetch;
}

export class ApiClient {
  private readonly baseUrl: string;
  private readonly deviceName: string;
  private readonly deviceIdentifier: string;
  private readonly fetchFn: typeof fetch;

  constructor(options: ApiClientOptions) {
    // La normalisation du slash final évite les `//` dans les chemins, que
    // certains reverse-proxies traitent différemment du serveur applicatif.
    this.baseUrl = options.serverUrl.replace(/\/+$/, '');
    this.deviceName = options.deviceName ?? 'zwarden';
    this.deviceIdentifier = options.deviceIdentifier;
    this.fetchFn = options.fetchFn ?? globalThis.fetch.bind(globalThis);
  }

  /**
   * Récupère les paramètres KDF du compte.
   *
   * Appel **non authentifié** : n'importe qui connaissant l'e-mail peut
   * l'effectuer. Les valeurs renvoyées sont donc non fiables et doivent passer
   * par `assertKdfIsAcceptable` avant toute dérivation — ce que fait
   * `deriveMasterKey`.
   *
   * @param email E-mail du compte.
   * @returns Paramètres KDF normalisés.
   * @throws {ApiError} Si le serveur répond en erreur.
   */
  async prelogin(email: string): Promise<KdfConfig> {
    const response = await this.fetchFn(`${this.baseUrl}/identity/accounts/prelogin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email.trim().toLowerCase() }),
    });

    const body = await response.text();
    if (!response.ok) {
      throw new ApiError('Échec du prelogin', response.status, body);
    }

    const data = JSON.parse(body) as PreloginResponse;
    const kdf = readField<number>(data, 'kdf') ?? KdfType.PBKDF2_SHA256;
    const iterations = readField<number>(data, 'kdfIterations') ?? 0;

    if (kdf === KdfType.Argon2id) {
      return {
        type: KdfType.Argon2id,
        iterations,
        memoryMiB: readField<number>(data, 'kdfMemory') ?? 0,
        parallelism: readField<number>(data, 'kdfParallelism') ?? 0,
      };
    }

    return { type: KdfType.PBKDF2_SHA256, iterations };
  }

  /**
   * Authentifie le compte et ouvre une session.
   *
   * @param email E-mail du compte.
   * @param masterKey Clé maître dérivée localement.
   * @param password Mot de passe maître, utilisé uniquement comme sel pour
   *   produire le hash d'autorisation. Il n'est jamais transmis.
   * @returns Jetons et clé de coffre enveloppée.
   * @throws {TwoFactorRequiredError} Si une seconde étape est exigée.
   * @throws {ApiError} Pour tout autre échec.
   */
  async login(email: string, masterKey: SymmetricCryptoKey, password: string): Promise<LoginResult> {
    const passwordHash = await derivePasswordHash(
      masterKey,
      password,
      HashPurpose.ServerAuthorization,
    );

    const form = new URLSearchParams({
      grant_type: 'password',
      username: email.trim().toLowerCase(),
      password: passwordHash,
      scope: 'api offline_access',
      client_id: 'browser',
      deviceType: String(DeviceType.ChromeExtension),
      deviceIdentifier: this.deviceIdentifier,
      deviceName: this.deviceName,
    });

    const response = await this.fetchFn(`${this.baseUrl}/identity/connect/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        // Exigé par Vaultwarden pour les clients non-web depuis 2023.
        'Auth-Email': base64Url(email.trim().toLowerCase()),
      },
      body: form.toString(),
    });

    const body = await response.text();

    if (!response.ok) {
      const error = safeJsonParse<TokenErrorResponse>(body);
      const providers =
        readField<string[]>(error, 'TwoFactorProviders') ??
        Object.keys(readField<Record<string, unknown>>(error, 'TwoFactorProviders2') ?? {});

      if (providers.length > 0) {
        throw new TwoFactorRequiredError(providers);
      }

      throw new ApiError(
        error?.error_description ?? 'Échec de l’authentification',
        response.status,
        body,
      );
    }

    const data = JSON.parse(body) as TokenResponse;
    const expiresIn = readField<number>(data, 'expires_in') ?? 3600;

    return {
      accessToken: data.access_token,
      refreshToken: readField<string>(data, 'refresh_token'),
      expiresAt: Date.now() + expiresIn * 1000,
      protectedUserKey: readField<string>(data, 'Key'),
      protectedPrivateKey: readField<string>(data, 'PrivateKey'),
    };
  }

  /**
   * Récupère l'intégralité du coffre, sous forme chiffrée.
   *
   * @param accessToken Jeton d'accès issu de {@link ApiClient.login}.
   * @returns Réponse de synchronisation, tous champs sensibles encore chiffrés.
   * @throws {ApiError} Si le serveur répond en erreur.
   */
  async sync(accessToken: string): Promise<SyncResponse> {
    const response = await this.fetchFn(`${this.baseUrl}/api/sync?excludeDomains=true`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    const body = await response.text();
    if (!response.ok) {
      throw new ApiError('Échec de la synchronisation', response.status, body);
    }

    return JSON.parse(body) as SyncResponse;
  }
  /**
   * Crée un item dans le coffre.
   *
   * Le corps transmis doit être **déjà chiffré** par l'appelant : ce client ne
   * détient aucune clé. Passer du texte en clair ici l'enverrait tel quel au
   * serveur.
   *
   * @param accessToken Jeton d'accès.
   * @param cipher Item dont tous les champs sensibles sont des `EncString`
   *   sérialisées.
   * @returns Item créé, tel que renvoyé par le serveur, avec son `id`.
   * @throws {ApiError} Si le serveur refuse la création.
   */
  async createCipher(
    accessToken: string,
    cipher: Record<string, unknown>,
  ): Promise<CipherResponse> {
    const response = await this.fetchFn(`${this.baseUrl}/api/ciphers`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(cipher),
    });

    const body = await response.text();
    if (!response.ok) {
      throw new ApiError("Échec de la création de l'item", response.status, body);
    }

    return JSON.parse(body) as CipherResponse;
  }

  /**
   * Supprime définitivement un item.
   *
   * Utilise la suppression dure (`/delete`), qui contourne la corbeille. Cela
   * évite d'accumuler des résidus lors des tests d'interopérabilité.
   *
   * @param accessToken Jeton d'accès.
   * @param cipherId Identifiant de l'item.
   * @throws {ApiError} Si la suppression échoue.
   */
  async deleteCipher(accessToken: string, cipherId: string): Promise<void> {
    const response = await this.fetchFn(`${this.baseUrl}/api/ciphers/${cipherId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!response.ok && response.status !== 404) {
      throw new ApiError("Échec de la suppression de l'item", response.status, await response.text());
    }
  }
}
function base64Url(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Analyse un JSON sans jeter : les corps d'erreur ne sont pas toujours du JSON. */
function safeJsonParse<T>(body: string): T | undefined {
  try {
    return JSON.parse(body) as T;
  } catch {
    return undefined;
  }
}
