/**
 * @file Unit tests for the API client, with a stubbed `fetch`.
 *
 * The integration test (`tests/integration/`) validates interoperability against
 * a real Vaultwarden; here we validate the client's behaviour against the
 * degraded responses a real server will not produce on request: rate limiting,
 * non-JSON bodies, a missing token, a second factor.
 */

import { describe, expect, it } from 'vitest';

import {
  ApiClient,
  ApiError,
  CaptchaRequiredError,
  RateLimitedError,
  TwoFactorRequiredError,
} from '../src/core/api/apiClient.js';
import { DeviceType, readField } from '../src/core/api/models.js';
import { KdfType } from '../src/core/crypto/kdf.js';

/** A call captured by the stubbed `fetch`. */
interface Captured {
  url: string;
  init: RequestInit | undefined;
}

/** Builds a client wired to a stubbed `fetch`, capturing the calls. */
function clientWith(
  handler: (url: string, init?: RequestInit) => Response,
  captured?: Captured[],
  serverUrl = 'https://vault.example.com',
): ApiClient {
  const fetchFn: typeof fetch = async (input, init) => {
    const url = String(input);
    captured?.push({ url, init });
    return handler(url, init);
  };
  return new ApiClient({ serverUrl, deviceIdentifier: 'test-device', fetchFn });
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status });
}

/** A dummy authorization hash: derivation is covered by kdf.test.ts. */
const HASH = 'authorization-hash-b64';

describe('serverUrl validation', () => {
  it('accepts HTTPS', () => {
    expect(() => clientWith(() => new Response(''))).not.toThrow();
  });

  it.each(['http://localhost:8080', 'http://127.0.0.1', 'http://vault.localhost'])(
    'tolerates HTTP towards localhost: %s',
    (url) => {
      expect(() => clientWith(() => new Response(''), undefined, url)).not.toThrow();
    },
  );

  it('refuses HTTP towards a remote host', () => {
    expect(() => clientWith(() => new Response(''), undefined, 'http://vault.example.com')).toThrow(
      RangeError,
    );
  });

  it('refuses a string that is not a URL', () => {
    expect(() => clientWith(() => new Response(''), undefined, 'pas une url')).toThrow(RangeError);
  });

  it('strips trailing slashes', async () => {
    const captured: Captured[] = [];
    const client = clientWith(
      () => jsonResponse(200, { kdf: 0, kdfIterations: 600_000 }),
      captured,
      'https://vault.example.com///',
    );

    await client.prelogin('a@b.c');
    expect(captured[0]!.url).toBe('https://vault.example.com/identity/accounts/prelogin');
  });
});

describe('prelogin', () => {
  it('reads a camelCase response (Argon2id)', async () => {
    const client = clientWith(() =>
      jsonResponse(200, { kdf: 1, kdfIterations: 3, kdfMemory: 64, kdfParallelism: 4 }),
    );

    expect(await client.prelogin('a@b.c')).toEqual({
      type: KdfType.Argon2id,
      iterations: 3,
      memoryMiB: 64,
      parallelism: 4,
    });
  });

  it('reads a PascalCase response (PBKDF2)', async () => {
    const client = clientWith(() => jsonResponse(200, { Kdf: 0, KdfIterations: 600_000 }));

    expect(await client.prelogin('a@b.c')).toEqual({
      type: KdfType.PBKDF2_SHA256,
      iterations: 600_000,
    });
  });

  it('normalises the email it sends', async () => {
    const captured: Captured[] = [];
    const client = clientWith(() => jsonResponse(200, { kdf: 0, kdfIterations: 600_000 }), captured);

    await client.prelogin('  User@Example.COM ');
    expect(String(captured[0]!.init?.body)).toBe(JSON.stringify({ email: 'user@example.com' }));
  });

  it('translates a non-JSON 200 into an ApiError', async () => {
    // A real case: a reverse proxy's landing page, or a captive portal.
    const client = clientWith(() => new Response('<html>Maintenance</html>', { status: 200 }));

    await expect(client.prelogin('a@b.c')).rejects.toThrow(/JSON expected/);
  });

  it('translates an HTTP failure into an ApiError carrying the status', async () => {
    const client = clientWith(() => new Response('oups', { status: 500 }));

    const error = await client.prelogin('a@b.c').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(500);
    expect((error as ApiError).body).toBe('oups');
  });

  it('bounds every request with an AbortSignal', async () => {
    const captured: Captured[] = [];
    const client = clientWith(() => jsonResponse(200, { kdf: 0, kdfIterations: 600_000 }), captured);

    await client.prelogin('a@b.c');
    expect(captured[0]!.init?.signal).toBeInstanceOf(AbortSignal);
  });
});

describe('rate limiting (HTTP 429)', () => {
  it('reads Retry-After in seconds', async () => {
    const client = clientWith(() =>
      new Response('', { status: 429, headers: { 'Retry-After': '42' } }),
    );

    const error = await client.prelogin('a@b.c').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(RateLimitedError);
    expect((error as RateLimitedError).retryAfterSeconds).toBe(42);
  });

  it('tolerates a missing Retry-After', async () => {
    const client = clientWith(() => new Response('', { status: 429 }));

    const error = await client.prelogin('a@b.c').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(RateLimitedError);
    expect((error as RateLimitedError).retryAfterSeconds).toBeUndefined();
  });
});

describe('login', () => {
  const TOKEN_OK = {
    access_token: 'access-token',
    refresh_token: 'refresh-token',
    expires_in: 3600,
    token_type: 'Bearer',
    Key: '2.aaa|bbb|ccc',
    PrivateKey: '2.ddd|eee|fff',
  };

  it('returns the session and the wrapped vault key', async () => {
    const client = clientWith(() => jsonResponse(200, TOKEN_OK));
    const session = await client.login('a@b.c', HASH);

    expect(session.accessToken).toBe('access-token');
    expect(session.refreshToken).toBe('refresh-token');
    expect(session.protectedUserKey).toBe('2.aaa|bbb|ccc');
    expect(session.protectedPrivateKey).toBe('2.ddd|eee|fff');
    expect(session.expiresAt).toBeGreaterThan(Date.now());
  });

  it('sends the hash — and only the hash — as the password', async () => {
    const captured: Captured[] = [];
    const client = clientWith(() => jsonResponse(200, TOKEN_OK), captured);

    await client.login('a@b.c', HASH);

    const form = new URLSearchParams(String(captured[0]!.init?.body));
    expect(form.get('password')).toBe(HASH);
    expect(form.get('username')).toBe('a@b.c');
    expect(form.get('grant_type')).toBe('password');
    expect(form.get('client_id')).toBe('zwarden');
    expect(form.get('deviceType')).toBe(String(DeviceType.ChromeExtension));
  });

  it('announces the configured device type', async () => {
    const captured: Captured[] = [];
    const fetchFn: typeof fetch = async (input, init) => {
      captured.push({ url: String(input), init });
      return jsonResponse(200, TOKEN_OK);
    };
    const client = new ApiClient({
      serverUrl: 'https://vault.example.com',
      deviceIdentifier: 'test-device',
      deviceType: DeviceType.FirefoxExtension,
      fetchFn,
    });

    await client.login('a@b.c', HASH);
    const form = new URLSearchParams(String(captured[0]!.init?.body));
    expect(form.get('deviceType')).toBe(String(DeviceType.FirefoxExtension));
  });

  it('translates a second-factor demand (array shape)', async () => {
    const client = clientWith(() =>
      jsonResponse(400, { error: 'invalid_grant', TwoFactorProviders: ['0', '3'] }),
    );

    const error = await client.login('a@b.c', HASH).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(TwoFactorRequiredError);
    expect((error as TwoFactorRequiredError).providers).toEqual(['0', '3']);
    expect((error as TwoFactorRequiredError).code).toBe('two-factor-required');
  });

  it('translates a second-factor demand (object shape)', async () => {
    const client = clientWith(() =>
      jsonResponse(400, { error: 'invalid_grant', TwoFactorProviders2: { '1': null } }),
    );

    const error = await client.login('a@b.c', HASH).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(TwoFactorRequiredError);
    expect((error as TwoFactorRequiredError).providers).toEqual(['1']);
  });

  it('attaches the second factor to the form', async () => {
    const captured: Captured[] = [];
    const client = clientWith(() => jsonResponse(200, TOKEN_OK), captured);

    await client.login('a@b.c', HASH, { provider: 3, token: 'otp-yubikey', remember: true });

    const form = new URLSearchParams(String(captured[0]!.init?.body));
    expect(form.get('twoFactorProvider')).toBe('3');
    expect(form.get('twoFactorToken')).toBe('otp-yubikey');
    expect(form.get('twoFactorRemember')).toBe('1');
  });

  it('sends no second-factor field when there is no second factor', async () => {
    const captured: Captured[] = [];
    const client = clientWith(() => jsonResponse(200, TOKEN_OK), captured);

    await client.login('a@b.c', HASH);

    const form = new URLSearchParams(String(captured[0]!.init?.body));
    expect(form.get('twoFactorProvider')).toBeNull();
    expect(form.get('twoFactorToken')).toBeNull();
  });

  it('exposes the remember token the server returns', async () => {
    const client = clientWith(() =>
      jsonResponse(200, { ...TOKEN_OK, TwoFactorToken: 'two-factor-exemption-token' }),
    );

    const session = await client.login('a@b.c', HASH, {
      provider: 0,
      token: '123456',
      remember: true,
    });
    expect(session.twoFactorRememberToken).toBe('two-factor-exemption-token');
  });

  it('translates a captcha requirement', async () => {
    const client = clientWith(() =>
      jsonResponse(400, { error: 'invalid_grant', HCaptcha_SiteKey: 'hcaptcha-site-key' }),
    );

    const error = await client.login('a@b.c', HASH).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(CaptchaRequiredError);
    expect((error as CaptchaRequiredError).siteKey).toBe('hcaptcha-site-key');
    expect((error as CaptchaRequiredError).code).toBe('captcha-required');
  });

  it('rejects a 200 without an access token', async () => {
    const client = clientWith(() => jsonResponse(200, { token_type: 'Bearer' }));

    await expect(client.login('a@b.c', HASH)).rejects.toThrow(/without an access token/);
  });

  it('translates a non-JSON error body into an ApiError', async () => {
    const client = clientWith(() => new Response('Bad Gateway', { status: 502 }));

    const error = await client.login('a@b.c', HASH).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(502);
    expect((error as ApiError).code).toBe('api-error');
  });
});

describe('refreshToken', () => {
  it('returns a new session from the refresh token', async () => {
    const captured: Captured[] = [];
    const client = clientWith(
      () =>
        jsonResponse(200, {
          access_token: 'new-token',
          refresh_token: 'new-refresh',
          expires_in: 3600,
          token_type: 'Bearer',
          Key: '2.aaa|bbb|ccc',
        }),
      captured,
    );

    const session = await client.refreshToken('old-refresh');

    expect(session.accessToken).toBe('new-token');
    expect(session.refreshToken).toBe('new-refresh');
    expect(session.protectedUserKey).toBe('2.aaa|bbb|ccc');

    const form = new URLSearchParams(String(captured[0]!.init?.body));
    expect(form.get('grant_type')).toBe('refresh_token');
    expect(form.get('refresh_token')).toBe('old-refresh');
    expect(form.get('client_id')).toBe('zwarden');
  });

  it('translates an expired token into an ApiError', async () => {
    const client = clientWith(() => jsonResponse(400, { error: 'invalid_grant' }));

    const error = await client.refreshToken('expired').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(400);
  });
});

describe('updateCipher', () => {
  it('issues a complete PUT on the item', async () => {
    const captured: Captured[] = [];
    const client = clientWith(() => jsonResponse(200, { id: 'id-1', type: 1 }), captured);
    const body = { type: 1, name: '2.aaa|bbb|ccc' };

    const result = await client.updateCipher('token', 'id-1', body);

    expect(result.id).toBe('id-1');
    expect(captured[0]!.url).toBe('https://vault.example.com/api/ciphers/id-1');
    expect(captured[0]!.init?.method).toBe('PUT');
    expect(String(captured[0]!.init?.body)).toBe(JSON.stringify(body));
  });

  it('surfaces failures', async () => {
    const client = clientWith(() => new Response('forbidden', { status: 403 }));

    const error = await client.updateCipher('token', 'id-1', {}).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(403);
  });
});

describe('deleteCipher', () => {
  it('treats a 404 as success (idempotence)', async () => {
    const client = clientWith(() => new Response('', { status: 404 }));
    await expect(client.deleteCipher('token', 'unknown-id')).resolves.toBeUndefined();
  });

  it('surfaces other failures', async () => {
    const client = clientWith(() => new Response('forbidden', { status: 403 }));

    const error = await client.deleteCipher('token', 'id').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(403);
  });
});

describe('server URL normalisation', () => {
  const base = { deviceIdentifier: 'id-1', fetchFn: (async () => new Response('{}')) as typeof fetch };

  /**
   * Validation covered the parsed URL but returned the input string: query
   * strings and fragments survived, and the path concatenation that follows
   * makes them destructive. `https://vault.example/#x` + `/api/sync` gives
   * `https://vault.example/#x/api/sync`, where the fragment swallows the path.
   */
  it('refuses a URL carrying a query string or a fragment', () => {
    expect(() => new ApiClient({ ...base, serverUrl: 'https://coffre.fr/#x' })).toThrow(RangeError);
    expect(() => new ApiClient({ ...base, serverUrl: 'https://coffre.fr/?debug=1' })).toThrow(
      RangeError,
    );
  });

  it('preserves a subdirectory installation path', async () => {
    const appels: string[] = [];
    const client = new ApiClient({
      deviceIdentifier: 'id-1',
      serverUrl: 'https://coffre.fr/bitwarden/',
      fetchFn: (async (url: string) => {
        appels.push(url);
        return new Response('{"kdf":0,"kdfIterations":600000}');
      }) as unknown as typeof fetch,
    });
    await client.prelogin('a@b.fr');
    expect(appels[0]).toBe('https://coffre.fr/bitwarden/identity/accounts/prelogin');
  });

  it('requires HTTPS, except towards the loopback', () => {
    expect(() => new ApiClient({ ...base, serverUrl: 'http://coffre.fr' })).toThrow(RangeError);
    expect(() => new ApiClient({ ...base, serverUrl: 'http://localhost:8080' })).not.toThrow();
  });
});

describe('readField', () => {
  it('reads either casing indifferently', () => {
    expect(readField<string>({ accessToken: 'a' }, 'accessToken')).toBe('a');
    expect(readField<string>({ AccessToken: 'a' }, 'accessToken')).toBe('a');
    expect(readField<string>({ key: 'k' }, 'Key')).toBe('k');
  });

  /**
   * `name in record` walked the prototype chain: `constructor`, `toString` and
   * `valueOf` always answered present. No API field collided with them, so
   * nothing was exploitable — but the guarantee rested on a naming coincidence
   * rather than on the structure of the code.
   */
  it('never reads a property inherited from the prototype', () => {
    expect(readField<unknown>({}, 'constructor')).toBeUndefined();
    expect(readField<unknown>({}, 'toString')).toBeUndefined();
    expect(readField<unknown>({}, 'valueOf')).toBeUndefined();
    expect(readField<unknown>({}, 'hasOwnProperty')).toBeUndefined();
  });

  it('returns undefined for a non-object source', () => {
    expect(readField<unknown>(null, 'x')).toBeUndefined();
    expect(readField<unknown>('texte', 'x')).toBeUndefined();
  });
});
