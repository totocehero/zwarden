/**
 * @file HTTP client for the self-hosted vault API.
 *
 * ## Responsibility
 *
 * Transport and response parsing, nothing else. This module decrypts nothing,
 * holds no key and **imports no cryptographic primitive** — cryptography lives
 * in `core/crypto`, orchestration in `core/vault`. The separation lets the
 * layers be audited independently: a transport flaw cannot expose a key, since
 * there is none here.
 *
 * ## Neither password nor key crosses this module
 *
 * {@link ApiClient.login} takes the **already-computed authorization hash**
 * (`derivePasswordHash`, `ServerAuthorization` purpose) — never the password,
 * never the master key. That signature makes the mistake impossible to commit
 * by accident: there is no parameter to put a secret in.
 *
 * ## No default server
 *
 * `serverUrl` is mandatory and has no fallback. Zwarden connects only to the
 * instance the user explicitly names: no third-party service is contacted, not
 * for authentication, not for icons, not for telemetry.
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

/** An API call failure, with the context needed to diagnose it. */
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

/** Thrown when the server requires a second authentication step. */
export class TwoFactorRequiredError extends Error {
  override readonly name = 'TwoFactorRequiredError';
  /** Identifiant stable pour l'interface : les messages servent aux journaux. */
  readonly code = 'two-factor-required';

  constructor(readonly providers: readonly string[]) {
    super(
      `Two-factor authentication required (providers: ${providers.join(', ') || 'unspecified'})`,
    );
  }
}

/**
 * Thrown when the server requires a captcha to be solved.
 *
 * Vaultwarden may impose one after repeated failures or by configuration.
 * Without dedicated handling, the user would see an unexplained "authentication
 * failed" while their password is perfectly correct.
 */
export class CaptchaRequiredError extends Error {
  override readonly name = 'CaptchaRequiredError';
  /** Identifiant stable pour l'interface : les messages servent aux journaux. */
  readonly code = 'captcha-required';

  constructor(readonly siteKey: string) {
    super('The server requires a captcha to be solved before continuing');
  }
}

/**
 * Thrown when the server rate-limits (HTTP 429).
 *
 * Vaultwarden applies a limiter on authentication — 10 attempts per minute in
 * its default configuration. Telling this apart from a credentials failure is
 * essential: retrying immediately makes things worse, and showing "wrong
 * password" would mislead the user.
 */
export class RateLimitedError extends Error {
  override readonly name = 'RateLimitedError';
  /** Identifiant stable pour l'interface : les messages servent aux journaux. */
  readonly code = 'rate-limited';

  constructor(readonly retryAfterSeconds: number | undefined) {
    super(
      retryAfterSeconds === undefined
        ? 'Too many attempts: the server is temporarily rate-limiting connections'
        : `Too many attempts: retry in ${retryAfterSeconds} second(s)`,
    );
  }
}

/** An authenticated session, as returned by {@link ApiClient.login}. */
export interface LoginResult {
  readonly accessToken: string;
  readonly refreshToken: string | undefined;
  /** Expiry instant, in epoch milliseconds. */
  readonly expiresAt: number;
  /**
   * Vault key, wrapped by the stretched master key. Always encrypted:
   * decryption is the caller's business.
   */
  readonly protectedUserKey: string | undefined;
  readonly protectedPrivateKey: string | undefined;
  /**
   * Two-factor remember token, present if `remember` was requested and granted.
   * To be persisted per device, then replayed as provider 5 (`Remember`) so the
   * device is no longer challenged.
   */
  readonly twoFactorRememberToken: string | undefined;
}

/** Second factor attached to an authentication attempt. */
export interface TwoFactorSubmission {
  /** Provider identifier (see `TwoFactorProvider` in models.ts). */
  readonly provider: number;
  /** TOTP code, email code, YubiKey OTP, or remember token (provider 5). */
  readonly token: string;
  /** Requests a remember token for this device. */
  readonly remember?: boolean;
}

export interface ApiClientOptions {
  /**
   * URL of the self-hosted instance, for example `https://vault.example.com`.
   * Mandatory, with no default. HTTPS required — HTTP is tolerated only towards
   * localhost, for development.
   */
  readonly serverUrl: string;
  /** Name shown in the server's list of active sessions. */
  readonly deviceName?: string;
  /**
   * Stable device identifier (UUID). Must be persisted: regenerating it on every
   * connection creates an extra session each time and triggers "new device"
   * alerts.
   */
  readonly deviceIdentifier: string;
  /**
   * Device type announced at authentication. To be set per build target
   * (`ChromeExtension` by default, `FirefoxExtension` for the Firefox package):
   * Vaultwarden uses it to display active sessions.
   */
  readonly deviceType?: DeviceType;
  /**
   * Maximum request duration, in milliseconds. Exceeding it rejects with a
   * `DOMException` named `TimeoutError`. An unbounded request is especially
   * costly inside an MV3 service worker, whose lifetime is counted.
   */
  readonly timeoutMs?: number;
  /** Injection point for tests. Defaults to the global `fetch`. */
  readonly fetchFn?: typeof fetch;
}

/**
 * Client identifier sent at authentication.
 *
 * Verified empirically: Vaultwarden imposes no particular value and accepts
 * `zwarden`. Zwarden therefore announces itself under its own name rather than
 * impersonating another client. It also makes active sessions legible
 * server-side.
 */
const CLIENT_ID = 'zwarden';

/** OAuth2 scope requested. `offline_access` is what makes a refresh token be issued. */
const SCOPE = 'api offline_access';

/** Default network timeout, in milliseconds. */
const DEFAULT_TIMEOUT_MS = 30_000;

export class ApiClient {
  private readonly baseUrl: string;
  private readonly deviceName: string;
  private readonly deviceIdentifier: string;
  private readonly deviceType: DeviceType;
  private readonly timeoutMs: number;
  private readonly fetchFn: typeof fetch;

  /**
   * @throws {RangeError} If `serverUrl` is not a valid URL, or is neither HTTPS
   *   nor HTTP towards localhost.
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
   * Fetches the account's key derivation parameters.
   *
   * An **unauthenticated** call: anyone who knows the email can make it. The
   * values returned are therefore untrusted and must pass through
   * `assertKdfIsAcceptable` before any derivation — which `deriveMasterKey`
   * does.
   *
   * @param email Account email.
   * @returns Normalised derivation parameters.
   * @throws {ApiError} If the server answers with an error.
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
   * Authenticates the account and opens a session.
   *
   * @param email Account email.
   * @param passwordHash Authorization hash, produced by `derivePasswordHash`
   *   with the `ServerAuthorization` purpose. Neither the password nor the
   *   master key must ever reach this module.
   * @param twoFactor Second factor, on a second attempt after
   *   {@link TwoFactorRequiredError} — or a remember token (provider 5) from the
   *   very first attempt.
   * @returns Session tokens and the wrapped vault key.
   * @throws {TwoFactorRequiredError} If a second step is demanded — including
   *   when the second factor supplied is invalid or expired.
   * @throws {CaptchaRequiredError} If the server demands a captcha.
   * @throws {RateLimitedError} If the server rate-limits.
   * @throws {ApiError} For any other failure.
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
   * Renews the session from the refresh token.
   *
   * Indispensable to the MV3 service worker: the access token expires in about
   * an hour, long after the worker has died. Refreshing avoids asking for the
   * password again — and therefore redoing a KDF derivation — on every expiry.
   *
   * @param refreshToken Token issued by {@link ApiClient.login} (`offline_access`
   *   scope).
   * @returns A new session; the server may rotate the refresh token, so always
   *   use the one from the result.
   * @throws {RateLimitedError} If the server rate-limits.
   * @throws {ApiError} If the token is expired or revoked.
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

  /** Calls `/identity/connect/token` and parses the token response. */
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
      // A 200 with no token would produce a silently unusable session: better to
      // fail here, with the body in plain sight.
      throw new ApiError('Authentication response without an access token', response.status, body);
    }

    return toLoginResult(data);
  }

  /**
   * Fetches the whole vault, in encrypted form.
   *
   * @param accessToken Access token from {@link ApiClient.login}.
   * @returns Sync response, every sensitive field still encrypted.
   * @throws {ApiError} If the server answers with an error.
   */
  async sync(accessToken: string): Promise<SyncResponse> {
    return this.requestJson<SyncResponse>('/api/sync?excludeDomains=true', {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
  }

  /**
   * Creates an item in the vault.
   *
   * The body passed must be **already encrypted** by the caller: this client
   * holds no key. Handing it plaintext would send it as-is.
   *
   * @param accessToken Access token.
   * @param cipher Item whose every sensitive field is a serialised `EncString`.
   * @returns The created item, as returned by the server, with its identifier.
   * @throws {ApiError} If the server refuses the creation.
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
   * Updates a vault item.
   *
   * The body passed must be **complete and already encrypted**: the server
   * replaces the item's data with what it receives, and omitted fields are lost.
   * See `buildCipherUpdatePayload` in the vault layer, which rebuilds the body
   * from the existing item.
   *
   * @param accessToken Access token.
   * @param cipherId Item identifier.
   * @param cipher Complete body, sensitive fields as serialised `EncString`s.
   * @returns The updated item, as returned by the server.
   * @throws {ApiError} If the server refuses the update.
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
   * Moves an item to the trash, where it can be recovered.
   *
   * Preferred over {@link ApiClient.deleteCipher} everywhere a person is
   * clicking: the official clients keep a trashed item for thirty days and can
   * restore it, so a misclick costs a trip to the web vault rather than a
   * password that no longer exists anywhere.
   *
   * A 404 is treated as success, as it is for the permanent deletion: the item
   * is not there, which is what was wanted.
   *
   * @param accessToken Access token.
   * @param cipherId Item identifier.
   * @throws {ApiError} If the server refuses for any other reason.
   */
  async trashCipher(accessToken: string, cipherId: string): Promise<void> {
    const url = `${this.baseUrl}/api/ciphers/${encodeURIComponent(cipherId)}/delete`;
    const response = await this.fetchFn(url, {
      method: 'PUT',
      headers: { Authorization: `Bearer ${accessToken}` },
      signal: AbortSignal.timeout(this.timeoutMs),
    });

    if (!response.ok && response.status !== 404) {
      throw new ApiError(
        'Failed to move the item to the trash',
        response.status,
        await response.text(),
      );
    }
  }

  /**
   * Permanently deletes an item, bypassing the trash.
   *
   * A 404 is treated as success: the item no longer exists, the intent is
   * satisfied. That makes the operation idempotent, which helps when cleaning up
   * after a partial failure.
   *
   * @param accessToken Access token.
   * @param cipherId Item identifier.
   * @throws {ApiError} If the deletion fails for any other reason.
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
        'Failed to delete the item',
        response.status,
        await response.text(),
      );
    }
  }

  /** Builds the OAuth2 authentication form. */
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
   * Translates an authentication failure into a typed error.
   *
   * Order matters: the rate limiter answers before any credentials check, a
   * second-factor demand is not a failure, and a required captcha is not a wrong
   * password.
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
      error?.error_description ?? 'Authentication failed',
      response.status,
      body,
    );
  }

  /**
   * Runs a request expected to return JSON, translating failures.
   *
   * Also covers the non-JSON 200 case — a reverse proxy's landing page, a
   * captive portal — which must produce a usable `ApiError`, not a raw
   * `SyntaxError`.
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
      throw new ApiError(`Request to ${path} failed`, response.status, body);
    }

    try {
      return JSON.parse(body) as T;
    } catch {
      throw new ApiError(`Unreadable response (JSON expected) for ${path}`, response.status, body);
    }
  }
}

/**
 * Validates the server URL and normalises it.
 *
 * HTTPS is required: a vault — end-to-end encrypted though it is — does not
 * travel in the clear, if only to protect the session tokens. HTTP stays
 * tolerated towards localhost, for development.
 *
 * **The value returned is rebuilt from the parsed URL**, never the input string.
 * Returning the input as-is let query strings and fragments through, which the
 * path concatenation that follows makes silently destructive:
 * `https://vault.example/#x` + `/api/sync` gives `https://vault.example/#x/api/sync`,
 * where the fragment swallows the path. The request went to the root, the server
 * answered HTML, and the user read "unreadable response" with no way to suspect
 * their URL. A value pasted from an address bar commonly carries one or the
 * other: better to refuse them outright.
 *
 * The trailing slash is dropped to avoid `//` in paths, which some reverse
 * proxies treat differently from the application server.
 *
 * @throws {RangeError} Invalid URL, refused protocol, or a URL carrying a query
 *   string or a fragment.
 */
function validateServerUrl(serverUrl: string): string {
  let url: URL;
  try {
    url = new URL(serverUrl);
  } catch {
    throw new RangeError(`Invalid server URL: "${serverUrl}"`);
  }

  const isLoopback =
    url.hostname === 'localhost' ||
    url.hostname === '127.0.0.1' ||
    url.hostname === '[::1]' ||
    url.hostname === '::1' ||
    url.hostname.endsWith('.localhost');

  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopback)) {
    throw new RangeError(
      `The server must be reached over HTTPS (HTTP tolerated for localhost only): "${serverUrl}"`,
    );
  }

  if (url.search !== '' || url.hash !== '') {
    throw new RangeError(
      `The server URL must carry neither a query string nor a fragment: "${serverUrl}"`,
    );
  }

  return `${url.origin}${url.pathname}`.replace(/\/+$/, '');
}

/** Normalises the email the way key derivation does, to stay consistent. */
function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

/** Converts the prelogin response into a derivation configuration. */
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

/** Converts the token response into a usable session. */
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
 * Extracts the list of second-factor providers.
 *
 * Two shapes coexist across versions: an array, or an object whose keys are the
 * provider identifiers.
 */
function extractTwoFactorProviders(error: TokenErrorResponse | undefined): readonly string[] {
  const liste = readField<string[]>(error, 'TwoFactorProviders');
  if (Array.isArray(liste)) {
    return liste;
  }

  const objet = readField<Record<string, unknown>>(error, 'TwoFactorProviders2');
  return objet ? Object.keys(objet) : [];
}

/** Reads the `Retry-After` header, in seconds. Ignores the HTTP-date form. */
function parseRetryAfter(value: string | null): number | undefined {
  if (value === null) {
    return undefined;
  }
  const seconds = Number(value);
  return Number.isFinite(seconds) && seconds >= 0 ? seconds : undefined;
}

/** Parses JSON without throwing: error bodies are not always JSON. */
function parseJsonOrUndefined<T>(body: string): T | undefined {
  try {
    return JSON.parse(body) as T;
  } catch {
    return undefined;
  }
}
