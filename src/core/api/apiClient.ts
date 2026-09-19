/**
 * @file Client HTTP pour l'API de coffre auto-hébergé.
 *
 * ## Responsabilité
 *
 * Transport et analyse de réponses, rien d'autre. Ce module ne déchiffre rien,
 * ne détient aucune clé et **n'importe aucune primitive cryptographique** — la
 * cryptographie vit dans `core/crypto`, l'orchestration dans `core/vault`. La
 * séparation permet d'auditer les couches indépendamment : une faille de
 * transport ne peut pas exposer de clé, puisqu'il n'y en a aucune ici.
 *
 * ## Ni mot de passe, ni clé ne traversent ce module
 *
 * {@link ApiClient.login} prend le **hash d'autorisation déjà calculé**
 * (`derivePasswordHash`, usage `ServerAuthorization`) — jamais le mot de
 * passe, jamais la clé maître. Cette signature rend l'erreur impossible à
 * commettre par inadvertance : il n'existe aucun paramètre où placer un
 * secret.
 *
 * ## Aucun serveur par défaut
 *
 * `serverUrl` est obligatoire et sans valeur de repli. Zwarden ne se connecte
 * qu'à l'instance que l'utilisateur désigne explicitement : aucun service tiers
 * n'est contacté, ni pour l'authentification, ni pour les icônes, ni pour de la
 * télémétrie.
 */

import { type KdfConfig, KdfType } from '../crypto/kdf.js';
import { toBase64Url, toUtf8Bytes } from '../crypto/encoding.js';
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
  /** Identifiant stable pour l'interface : les messages servent aux journaux. */
  readonly code = 'api-error';

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
  /** Identifiant stable pour l'interface : les messages servent aux journaux. */
  readonly code = 'two-factor-required';

  constructor(readonly providers: readonly string[]) {
    super(
      `Authentification à deux facteurs requise (fournisseurs : ${providers.join(', ') || 'non précisés'})`,
    );
  }
}

/**
 * Levée lorsque le serveur exige la résolution d'un captcha.
 *
 * Vaultwarden peut l'imposer après des échecs répétés ou selon sa
 * configuration. Sans traitement dédié, l'utilisateur verrait un « échec
 * d'authentification » inexpliqué alors que son mot de passe est correct.
 */
export class CaptchaRequiredError extends Error {
  override readonly name = 'CaptchaRequiredError';
  /** Identifiant stable pour l'interface : les messages servent aux journaux. */
  readonly code = 'captcha-required';

  constructor(readonly siteKey: string) {
    super('Le serveur exige la résolution d’un captcha avant de poursuivre');
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
  /** Identifiant stable pour l'interface : les messages servent aux journaux. */
  readonly code = 'rate-limited';

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
  /**
   * Jeton de dispense de second facteur, présent si `remember` a été demandé
   * et accepté. À persister par appareil, puis rejouer comme fournisseur 5
   * (`Remember`) pour ne plus être sollicité sur cet appareil.
   */
  readonly twoFactorRememberToken: string | undefined;
}

/** Second facteur joint à une tentative d'authentification. */
export interface TwoFactorSubmission {
  /** Identifiant du fournisseur (voir `TwoFactorProvider` dans models.ts). */
  readonly provider: number;
  /** Code TOTP, code e-mail, OTP YubiKey, ou jeton de dispense (fournisseur 5). */
  readonly token: string;
  /** Demande un jeton de dispense pour cet appareil. */
  readonly remember?: boolean;
}

export interface ApiClientOptions {
  /**
   * URL de l'instance auto-hébergée, par exemple `https://coffre.exemple.fr`.
   * Obligatoire, sans valeur par défaut. HTTPS exigé — HTTP n'est toléré que
   * vers localhost, pour le développement.
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
  /**
   * Type d'appareil annoncé à l'authentification. À fixer selon la cible de
   * build (`ChromeExtension` par défaut, `FirefoxExtension` pour le paquet
   * Firefox) : Vaultwarden s'en sert pour l'affichage des sessions actives.
   */
  readonly deviceType?: DeviceType;
  /**
   * Délai maximal d'une requête, en millisecondes. Un dépassement rejette avec
   * une `DOMException` de nom `TimeoutError`. Une requête sans borne est
   * particulièrement coûteuse dans un service worker MV3, dont la durée de vie
   * est comptée.
   */
  readonly timeoutMs?: number;
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

/** Délai réseau par défaut, en millisecondes. */
const DEFAULT_TIMEOUT_MS = 30_000;

export class ApiClient {
  private readonly baseUrl: string;
  private readonly deviceName: string;
  private readonly deviceIdentifier: string;
  private readonly deviceType: DeviceType;
  private readonly timeoutMs: number;
  private readonly fetchFn: typeof fetch;

  /**
   * @throws {RangeError} Si `serverUrl` n'est pas une URL valide, ou n'est ni
   *   HTTPS ni du HTTP vers localhost.
   */
  constructor(options: ApiClientOptions) {
    this.baseUrl = validateServerUrl(options.serverUrl);
    this.deviceName = options.deviceName ?? 'Zwarden';
    this.deviceIdentifier = options.deviceIdentifier;
    this.deviceType = options.deviceType ?? DeviceType.ChromeExtension;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
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
    const data = await this.requestJson<PreloginResponse>('/identity/accounts/prelogin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: normalizeEmail(email) }),
    });

    return toKdfConfig(data);
  }

  /**
   * Authentifie le compte et ouvre une session.
   *
   * @param email E-mail du compte.
   * @param passwordHash Hash d'autorisation, produit par `derivePasswordHash`
   *   avec l'usage `ServerAuthorization`. Ni le mot de passe ni la clé maître
   *   ne doivent jamais atteindre ce module.
   * @param twoFactor Second facteur, lors d'une seconde tentative après
   *   {@link TwoFactorRequiredError} — ou jeton de dispense (fournisseur 5)
   *   dès la première.
   * @returns Jetons de session et clé de coffre enveloppée.
   * @throws {TwoFactorRequiredError} Si une seconde étape est exigée — y
   *   compris lorsque le second facteur fourni est invalide ou expiré.
   * @throws {CaptchaRequiredError} Si le serveur exige un captcha.
   * @throws {RateLimitedError} Si le serveur limite le débit.
   * @throws {ApiError} Pour tout autre échec.
   */
  async login(
    email: string,
    passwordHash: string,
    twoFactor?: TwoFactorSubmission,
  ): Promise<LoginResult> {
    const normalized = normalizeEmail(email);

    const form = this.buildTokenForm(normalized, passwordHash);
    if (twoFactor !== undefined) {
      form.set('twoFactorProvider', String(twoFactor.provider));
      form.set('twoFactorToken', twoFactor.token);
      form.set('twoFactorRemember', twoFactor.remember === true ? '1' : '0');
    }

    return this.requestToken(form, {
      'Auth-Email': toBase64Url(toUtf8Bytes(normalized)),
    });
  }

  /**
   * Renouvelle la session à partir du jeton de rafraîchissement.
   *
   * Indispensable au service worker MV3 : le jeton d'accès expire en une
   * heure environ, bien après la mort du worker. Rafraîchir évite de
   * redemander le mot de passe — et donc de refaire une dérivation KDF —
   * à chaque expiration.
   *
   * @param refreshToken Jeton émis par {@link ApiClient.login} (portée
   *   `offline_access`).
   * @returns Nouvelle session ; le serveur peut faire tourner le jeton de
   *   rafraîchissement, utiliser systématiquement celui du résultat.
   * @throws {RateLimitedError} Si le serveur limite le débit.
   * @throws {ApiError} Si le jeton est expiré ou révoqué.
   */
  async refreshToken(refreshToken: string): Promise<LoginResult> {
    return this.requestToken(
      new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: CLIENT_ID,
      }),
    );
  }

  /** Appelle `/identity/connect/token` et analyse la réponse de jeton. */
  private async requestToken(
    form: URLSearchParams,
    extraHeaders?: Record<string, string>,
  ): Promise<LoginResult> {
    const response = await this.fetchFn(`${this.baseUrl}/identity/connect/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        ...extraHeaders,
      },
      body: form.toString(),
      signal: AbortSignal.timeout(this.timeoutMs),
    });

    const body = await response.text();
    if (!response.ok) {
      throw this.toLoginError(response, body);
    }

    const data = parseJsonOrUndefined<TokenResponse>(body);
    if (data === undefined || typeof data.access_token !== 'string' || data.access_token === '') {
      // Un 200 sans jeton produirait une session silencieusement inutilisable :
      // mieux vaut échouer ici, avec le corps sous les yeux.
      throw new ApiError("Réponse d'authentification sans jeton d'accès", response.status, body);
    }

    return toLoginResult(data);
  }

  /**
   * Récupère l'intégralité du coffre, sous forme chiffrée.
   *
   * @param accessToken Jeton d'accès issu de {@link ApiClient.login}.
   * @returns Réponse de synchronisation, tous champs sensibles encore chiffrés.
   * @throws {ApiError} Si le serveur répond en erreur.
   */
  async sync(accessToken: string): Promise<SyncResponse> {
    return this.requestJson<SyncResponse>('/api/sync?excludeDomains=true', {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
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
    return this.requestJson<CipherResponse>('/api/ciphers', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(cipher),
    });
  }

  /**
   * Met à jour un item du coffre.
   *
   * Le corps transmis doit être **complet et déjà chiffré** : le serveur
   * remplace les données de l'item par ce qu'il reçoit, les champs omis sont
   * perdus. Voir `buildCipherUpdatePayload` dans la couche coffre, qui
   * reconstruit le corps à partir de l'item existant.
   *
   * @param accessToken Jeton d'accès.
   * @param cipherId Identifiant de l'item.
   * @param cipher Corps complet, champs sensibles en `EncString` sérialisées.
   * @returns Item mis à jour, tel que renvoyé par le serveur.
   * @throws {ApiError} Si le serveur refuse la mise à jour.
   */
  async updateCipher(
    accessToken: string,
    cipherId: string,
    cipher: Record<string, unknown>,
  ): Promise<CipherResponse> {
    return this.requestJson<CipherResponse>(`/api/ciphers/${encodeURIComponent(cipherId)}`, {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(cipher),
    });
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
    const url = `${this.baseUrl}/api/ciphers/${encodeURIComponent(cipherId)}`;
    const response = await this.fetchFn(url, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${accessToken}` },
      signal: AbortSignal.timeout(this.timeoutMs),
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
      deviceType: String(this.deviceType),
      deviceIdentifier: this.deviceIdentifier,
      deviceName: this.deviceName,
    });
  }

  /**
   * Traduit un échec d'authentification en erreur typée.
   *
   * L'ordre compte : le limiteur de débit répond avant toute vérification
   * d'identifiants, une demande de second facteur n'est pas un échec, et un
   * captcha exigé n'est pas un mauvais mot de passe.
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

    const captchaSiteKey = readField<string>(error, 'HCaptcha_SiteKey');
    if (typeof captchaSiteKey === 'string' && captchaSiteKey !== '') {
      return new CaptchaRequiredError(captchaSiteKey);
    }

    return new ApiError(
      error?.error_description ?? "Échec de l'authentification",
      response.status,
      body,
    );
  }

  /**
   * Exécute une requête attendue en JSON, en traduisant les échecs.
   *
   * Couvre aussi le cas du 200 non-JSON — page de garde d'un reverse-proxy,
   * portail captif — qui doit produire une `ApiError` exploitable, pas une
   * `SyntaxError` brute.
   */
  private async requestJson<T>(path: string, init?: RequestInit): Promise<T> {
    const response = await this.fetchFn(`${this.baseUrl}${path}`, {
      ...init,
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    const body = await response.text();

    if (response.status === 429) {
      throw new RateLimitedError(parseRetryAfter(response.headers.get('Retry-After')));
    }
    if (!response.ok) {
      throw new ApiError(`Échec de la requête ${path}`, response.status, body);
    }

    try {
      return JSON.parse(body) as T;
    } catch {
      throw new ApiError(`Réponse illisible (JSON attendu) pour ${path}`, response.status, body);
    }
  }
}

/**
 * Valide l'URL du serveur et la normalise.
 *
 * HTTPS est exigé : un coffre — même chiffré de bout en bout — ne transite pas
 * en clair, ne serait-ce que pour protéger les jetons de session. HTTP reste
 * toléré vers localhost, pour le développement.
 *
 * **La valeur renvoyée est reconstruite depuis l'URL analysée**, jamais la
 * chaîne d'entrée. Les renvoyer telle quelle laissait passer paramètres et
 * ancres, que la concaténation de chemin qui suit rend silencieusement
 * destructeurs : `https://coffre.fr/#x` + `/api/sync` donne
 * `https://coffre.fr/#x/api/sync`, où l'ancre avale le chemin. La requête
 * partait sur la racine, le serveur répondait du HTML, et l'utilisateur lisait
 * « Réponse illisible » sans pouvoir soupçonner son URL. Une saisie collée
 * depuis une barre d'adresse porte couramment l'un ou l'autre : mieux vaut les
 * refuser franchement.
 *
 * Le slash final est retiré pour éviter les `//` dans les chemins, que certains
 * reverse-proxies traitent différemment du serveur applicatif.
 *
 * @throws {RangeError} URL invalide, protocole refusé, ou URL porteuse d'un
 *   paramètre ou d'une ancre.
 */
function validateServerUrl(serverUrl: string): string {
  let url: URL;
  try {
    url = new URL(serverUrl);
  } catch {
    throw new RangeError(`URL de serveur invalide : « ${serverUrl} »`);
  }

  const isLoopback =
    url.hostname === 'localhost' ||
    url.hostname === '127.0.0.1' ||
    url.hostname === '[::1]' ||
    url.hostname === '::1' ||
    url.hostname.endsWith('.localhost');

  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopback)) {
    throw new RangeError(
      `Le serveur doit être joint en HTTPS (HTTP toléré pour localhost uniquement) : « ${serverUrl} »`,
    );
  }

  if (url.search !== '' || url.hash !== '') {
    throw new RangeError(
      `L'URL du serveur ne doit porter ni paramètre ni ancre : « ${serverUrl} »`,
    );
  }

  return `${url.origin}${url.pathname}`.replace(/\/+$/, '');
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
    twoFactorRememberToken: readField<string>(data, 'TwoFactorToken'),
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

/** Analyse un JSON sans jeter : les corps d'erreur ne sont pas toujours du JSON. */
function parseJsonOrUndefined<T>(body: string): T | undefined {
  try {
    return JSON.parse(body) as T;
  } catch {
    return undefined;
  }
}
