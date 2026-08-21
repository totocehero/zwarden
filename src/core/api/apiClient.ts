/**
 * @file Client HTTP pour l'API de coffre auto-hébergé.
 *
 * ## Responsabilité
 *
 * Transport et analyse de réponses, rien d'autre. Ce module ne déchiffre rien
 * et ne détient aucune clé — la cryptographie vit dans `core/crypto`. La
 * séparation permet d'auditer les deux indépendamment : une faille de
 * transport ne peut pas exposer de clé, puisqu'il n'y en a aucune ici.
 *
 * ## Le mot de passe ne quitte jamais le client
 *
 * {@link ApiClient.login} prend une clé maître **déjà dérivée**, jamais le mot
 * de passe. Le serveur ne reçoit que le hash d'autorisation. Cette signature
 * rend l'erreur difficile à commettre par inadvertance.
 *
 * ## Aucun serveur par défaut
 *
 * `serverUrl` est obligatoire et sans valeur de repli. Zwarden ne se connecte
 * qu'à l'instance que l'utilisateur désigne explicitement : aucun service tiers
 * n'est contacté, ni pour l'authentification, ni pour les icônes, ni pour de la
 * télémétrie.
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
    super(
      `Authentification à deux facteurs requise (fournisseurs : ${providers.join(', ') || 'non précisés'})`,
    );
  }
}

/**
 * Levée lorsque le serveur limite le débit (HTTP 429).
 *
 * Vaultwarden applique un limiteur sur l'authentification — 10 tentatives par
 * minute dans sa configuration par défaut. Distinguer ce cas d'un échec
 * d'identifiants est indispensable : réessayer immédiatement aggrave la
 * situation, et afficher « mot de passe incorrect » induirait l'utilisateur en
 * erreur.
 */
export class RateLimitedError extends Error {
  override readonly name = 'RateLimitedError';

  constructor(readonly retryAfterSeconds: number | undefined) {
    super(
      retryAfterSeconds === undefined
        ? 'Trop de tentatives : le serveur limite temporairement les connexions'
        : `Trop de tentatives : réessayer dans ${retryAfterSeconds} seconde(s)`,
    );
  }
}

/** Session authentifiée, telle que renvoyée par {@link ApiClient.login}. */
export interface LoginResult {
  readonly accessToken: string;
  readonly refreshToken: string | undefined;
  /** Instant d'expiration, en millisecondes epoch. */
  readonly expiresAt: number;
  /**
   * Clé du coffre, enveloppée par la clé maître étirée. Toujours chiffrée :
   * le déchiffrement relève de l'appelant.
   */
  readonly protectedUserKey: string | undefined;
  readonly protectedPrivateKey: string | undefined;
}

export interface ApiClientOptions {
  /**
   * URL de l'instance auto-hébergée, par exemple `https://coffre.exemple.fr`.
   * Obligatoire, sans valeur par défaut.
   */
  readonly serverUrl: string;
  /** Nom affiché dans la liste des sessions actives côté serveur. */
  readonly deviceName?: string;
  /**
   * Identifiant stable de l'appareil (UUID). Doit être persisté : le
   * régénérer à chaque connexion crée une session supplémentaire à chaque fois
   * et déclenche les alertes « nouvel appareil ».
   */
  readonly deviceIdentifier: string;
  /** Injection pour les tests. Par défaut, le `fetch` global. */
  readonly fetchFn?: typeof fetch;
}

/**
 * Identifiant de client transmis à l'authentification.
 *
 * Vérifié empiriquement : Vaultwarden n'impose aucune valeur particulière et
 * accepte `zwarden`. Zwarden s'annonce donc sous son propre nom plutôt que de
 * se faire passer pour un autre client. Cela rend aussi les sessions actives
 * lisibles côté serveur.
 */
const CLIENT_ID = 'zwarden';

/** Portée OAuth2 demandée. `offline_access` conditionne l'émission d'un jeton de rafraîchissement. */
const SCOPE = 'api offline_access';

export class ApiClient {
  private readonly baseUrl: string;
  private readonly deviceName: string;
  private readonly deviceIdentifier: string;
  private readonly fetchFn: typeof fetch;

  constructor(options: ApiClientOptions) {
    // Normaliser le slash final évite les `//` dans les chemins, que certains
    // reverse-proxies traitent différemment du serveur applicatif.
    this.baseUrl = options.serverUrl.replace(/\/+$/, '');
    this.deviceName = options.deviceName ?? 'Zwarden';
    this.deviceIdentifier = options.deviceIdentifier;
    this.fetchFn = options.fetchFn ?? globalThis.fetch.bind(globalThis);
  }

  /**
   * Récupère les paramètres de dérivation de clé du compte.
   *
   * Appel **non authentifié** : quiconque connaît l'e-mail peut l'effectuer.
   * Les valeurs renvoyées sont donc non fiables et doivent passer par
   * `assertKdfIsAcceptable` avant toute dérivation — ce que fait
   * `deriveMasterKey`.
   *
   * @param email E-mail du compte.
   * @returns Paramètres de dérivation normalisés.
   * @throws {ApiError} Si le serveur répond en erreur.
   */
  async prelogin(email: string): Promise<KdfConfig> {
    const body = await this.requestText('/identity/accounts/prelogin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: normalizeEmail(email) }),
    });

    return toKdfConfig(JSON.parse(body) as PreloginResponse);
  }

  /**
   * Authentifie le compte et ouvre une session.
   *
   * @param email E-mail du compte.
   * @param masterKey Clé maître dérivée localement.
   * @param password Mot de passe maître, utilisé uniquement comme sel pour
   *   produire le hash d'autorisation. Il n'est jamais transmis.
   * @returns Jetons de session et clé de coffre enveloppée.
   * @throws {TwoFactorRequiredError} Si une seconde étape est exigée.
   * @throws {RateLimitedError} Si le serveur limite le débit.
   * @throws {ApiError} Pour tout autre échec.
   */
  async login(email: string, masterKey: SymmetricCryptoKey, password: string): Promise<LoginResult> {
    const normalized = normalizeEmail(email);
    const passwordHash = await derivePasswordHash(
      masterKey,
      password,
      HashPurpose.ServerAuthorization,
    );

    const response = await this.fetchFn(`${this.baseUrl}/identity/connect/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Auth-Email': toBase64Url(normalized),
      },
      body: this.buildTokenForm(normalized, passwordHash).toString(),
    });

    const body = await response.text();
    if (!response.ok) {
      throw this.toLoginError(response, body);
    }

    return toLoginResult(JSON.parse(body) as TokenResponse);
  }

  /**
   * Récupère l'intégralité du coffre, sous forme chiffrée.
   *
   * @param accessToken Jeton d'accès issu de {@link ApiClient.login}.
   * @returns Réponse de synchronisation, tous champs sensibles encore chiffrés.
   * @throws {ApiError} Si le serveur répond en erreur.
   */
  async sync(accessToken: string): Promise<SyncResponse> {
    const body = await this.requestText('/api/sync?excludeDomains=true', {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    return JSON.parse(body) as SyncResponse;
  }

  /**
   * Crée un item dans le coffre.
   *
   * Le corps transmis doit être **déjà chiffré** par l'appelant : ce client ne
   * détient aucune clé. Y passer du texte en clair l'enverrait tel quel.
   *
   * @param accessToken Jeton d'accès.
   * @param cipher Item dont tous les champs sensibles sont des `EncString`
   *   sérialisées.
   * @returns Item créé, tel que renvoyé par le serveur, avec son identifiant.
   * @throws {ApiError} Si le serveur refuse la création.
   */
  async createCipher(accessToken: string, cipher: Record<string, unknown>): Promise<CipherResponse> {
    const body = await this.requestText('/api/ciphers', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(cipher),
    });

    return JSON.parse(body) as CipherResponse;
  }

  /**
   * Supprime définitivement un item, sans passer par la corbeille.
   *
   * Un 404 est traité comme un succès : l'item n'existe plus, l'intention est
   * satisfaite. Cela rend l'opération idempotente, utile au nettoyage après
   * échec partiel.
   *
   * @param accessToken Jeton d'accès.
   * @param cipherId Identifiant de l'item.
   * @throws {ApiError} Si la suppression échoue pour une autre raison.
   */
  async deleteCipher(accessToken: string, cipherId: string): Promise<void> {
    const response = await this.fetchFn(`${this.baseUrl}/api/ciphers/${cipherId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!response.ok && response.status !== 404) {
      throw new ApiError(
        "Échec de la suppression de l'item",
        response.status,
        await response.text(),
      );
    }
  }

  /** Construit le formulaire d'authentification OAuth2. */
  private buildTokenForm(email: string, passwordHash: string): URLSearchParams {
    return new URLSearchParams({
      grant_type: 'password',
      username: email,
      password: passwordHash,
      scope: SCOPE,
      client_id: CLIENT_ID,
      deviceType: String(DeviceType.ChromeExtension),
      deviceIdentifier: this.deviceIdentifier,
      deviceName: this.deviceName,
    });
  }

  /**
   * Traduit un échec d'authentification en erreur typée.
   *
   * L'ordre compte : le limiteur de débit répond avant toute vérification
   * d'identifiants, et une demande de second facteur n'est pas un échec.
   */
  private toLoginError(response: Response, body: string): Error {
    if (response.status === 429) {
      return new RateLimitedError(parseRetryAfter(response.headers.get('Retry-After')));
    }

    const error = parseJsonOrUndefined<TokenErrorResponse>(body);
    const providers = extractTwoFactorProviders(error);
    if (providers.length > 0) {
      return new TwoFactorRequiredError(providers);
    }

    return new ApiError(
      error?.error_description ?? "Échec de l'authentification",
      response.status,
      body,
    );
  }

  /** Exécute une requête et renvoie le corps, en traduisant les échecs. */
  private async requestText(path: string, init?: RequestInit): Promise<string> {
    const response = await this.fetchFn(`${this.baseUrl}${path}`, init);
    const body = await response.text();

    if (response.status === 429) {
      throw new RateLimitedError(parseRetryAfter(response.headers.get('Retry-After')));
    }
    if (!response.ok) {
      throw new ApiError(`Échec de la requête ${path}`, response.status, body);
    }

    return body;
  }
}

/** Normalise l'e-mail comme le fait la dérivation de clé, pour rester cohérent. */
function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

/** Convertit la réponse de prelogin en configuration de dérivation. */
function toKdfConfig(data: PreloginResponse): KdfConfig {
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

/** Convertit la réponse de jeton en session exploitable. */
function toLoginResult(data: TokenResponse): LoginResult {
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
 * Extrait la liste des fournisseurs de second facteur.
 *
 * Deux formes coexistent selon les versions : un tableau, ou un objet dont les
 * clés sont les identifiants de fournisseur.
 */
function extractTwoFactorProviders(error: TokenErrorResponse | undefined): readonly string[] {
  const liste = readField<string[]>(error, 'TwoFactorProviders');
  if (Array.isArray(liste)) {
    return liste;
  }

  const objet = readField<Record<string, unknown>>(error, 'TwoFactorProviders2');
  return objet ? Object.keys(objet) : [];
}

/** Lit l'en-tête `Retry-After`, en secondes. Ignore la forme date HTTP. */
function parseRetryAfter(value: string | null): number | undefined {
  if (value === null) {
    return undefined;
  }
  const seconds = Number(value);
  return Number.isFinite(seconds) && seconds >= 0 ? seconds : undefined;
}

/** Encode en base64url sans padding, format attendu par l'en-tête `Auth-Email`. */
function toBase64Url(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Analyse un JSON sans jeter : les corps d'erreur ne sont pas toujours du JSON. */
function parseJsonOrUndefined<T>(body: string): T | undefined {
  try {
    return JSON.parse(body) as T;
  } catch {
    return undefined;
  }
}
