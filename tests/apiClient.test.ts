/**
 * @file Tests unitaires du client API, avec un `fetch` simulé.
 *
 * Le test d'intégration (`tests/integration/`) valide l'interopérabilité
 * contre un vrai Vaultwarden ; ici on valide le comportement du client face
 * aux réponses dégradées qu'un vrai serveur ne renvoie pas sur demande :
 * limitation de débit, corps non-JSON, jeton absent, second facteur.
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

/** Appel capturé par le `fetch` simulé. */
interface Captured {
  url: string;
  init: RequestInit | undefined;
}

/** Construit un client branché sur un `fetch` simulé, en capturant les appels. */
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

/** Hash d'autorisation factice : la dérivation est couverte par kdf.test.ts. */
const HASH = 'hash-d-autorisation-b64';

describe('validation de serverUrl', () => {
  it('accepte HTTPS', () => {
    expect(() => clientWith(() => new Response(''))).not.toThrow();
  });

  it.each(['http://localhost:8080', 'http://127.0.0.1', 'http://vault.localhost'])(
    'tolère HTTP vers localhost : %s',
    (url) => {
      expect(() => clientWith(() => new Response(''), undefined, url)).not.toThrow();
    },
  );

  it('refuse HTTP vers un hôte distant', () => {
    expect(() => clientWith(() => new Response(''), undefined, 'http://vault.example.com')).toThrow(
      RangeError,
    );
  });

  it('refuse une chaîne qui n’est pas une URL', () => {
    expect(() => clientWith(() => new Response(''), undefined, 'pas une url')).toThrow(RangeError);
  });

  it('retire les slashs finaux', async () => {
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
  it('lit une réponse camelCase (Argon2id)', async () => {
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

  it('lit une réponse PascalCase (PBKDF2)', async () => {
    const client = clientWith(() => jsonResponse(200, { Kdf: 0, KdfIterations: 600_000 }));

    expect(await client.prelogin('a@b.c')).toEqual({
      type: KdfType.PBKDF2_SHA256,
      iterations: 600_000,
    });
  });

  it('normalise l’e-mail transmis', async () => {
    const captured: Captured[] = [];
    const client = clientWith(() => jsonResponse(200, { kdf: 0, kdfIterations: 600_000 }), captured);

    await client.prelogin('  User@Example.COM ');
    expect(String(captured[0]!.init?.body)).toBe(JSON.stringify({ email: 'user@example.com' }));
  });

  it('traduit un 200 non-JSON en ApiError', async () => {
    // Cas réel : page de garde d'un reverse-proxy ou portail captif.
    const client = clientWith(() => new Response('<html>Maintenance</html>', { status: 200 }));

    await expect(client.prelogin('a@b.c')).rejects.toThrow(/JSON attendu/);
  });

  it('traduit un échec HTTP en ApiError avec le statut', async () => {
    const client = clientWith(() => new Response('oups', { status: 500 }));

    const erreur = await client.prelogin('a@b.c').catch((e: unknown) => e);
    expect(erreur).toBeInstanceOf(ApiError);
    expect((erreur as ApiError).status).toBe(500);
    expect((erreur as ApiError).body).toBe('oups');
  });

  it('borne chaque requête par un AbortSignal', async () => {
    const captured: Captured[] = [];
    const client = clientWith(() => jsonResponse(200, { kdf: 0, kdfIterations: 600_000 }), captured);

    await client.prelogin('a@b.c');
    expect(captured[0]!.init?.signal).toBeInstanceOf(AbortSignal);
  });
});

describe('limitation de débit (HTTP 429)', () => {
  it('lit Retry-After en secondes', async () => {
    const client = clientWith(() =>
      new Response('', { status: 429, headers: { 'Retry-After': '42' } }),
    );

    const erreur = await client.prelogin('a@b.c').catch((e: unknown) => e);
    expect(erreur).toBeInstanceOf(RateLimitedError);
    expect((erreur as RateLimitedError).retryAfterSeconds).toBe(42);
  });

  it('tolère l’absence de Retry-After', async () => {
    const client = clientWith(() => new Response('', { status: 429 }));

    const erreur = await client.prelogin('a@b.c').catch((e: unknown) => e);
    expect(erreur).toBeInstanceOf(RateLimitedError);
    expect((erreur as RateLimitedError).retryAfterSeconds).toBeUndefined();
  });
});

describe('login', () => {
  const TOKEN_OK = {
    access_token: 'jeton-acces',
    refresh_token: 'jeton-rafraichissement',
    expires_in: 3600,
    token_type: 'Bearer',
    Key: '2.aaa|bbb|ccc',
    PrivateKey: '2.ddd|eee|fff',
  };

  it('renvoie la session et la clé de coffre enveloppée', async () => {
    const client = clientWith(() => jsonResponse(200, TOKEN_OK));
    const session = await client.login('a@b.c', HASH);

    expect(session.accessToken).toBe('jeton-acces');
    expect(session.refreshToken).toBe('jeton-rafraichissement');
    expect(session.protectedUserKey).toBe('2.aaa|bbb|ccc');
    expect(session.protectedPrivateKey).toBe('2.ddd|eee|fff');
    expect(session.expiresAt).toBeGreaterThan(Date.now());
  });

  it('transmet le hash — et uniquement le hash — comme mot de passe', async () => {
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

  it('annonce le type d’appareil configuré', async () => {
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

  it('traduit une demande de second facteur (forme tableau)', async () => {
    const client = clientWith(() =>
      jsonResponse(400, { error: 'invalid_grant', TwoFactorProviders: ['0', '3'] }),
    );

    const erreur = await client.login('a@b.c', HASH).catch((e: unknown) => e);
    expect(erreur).toBeInstanceOf(TwoFactorRequiredError);
    expect((erreur as TwoFactorRequiredError).providers).toEqual(['0', '3']);
    expect((erreur as TwoFactorRequiredError).code).toBe('two-factor-required');
  });

  it('traduit une demande de second facteur (forme objet)', async () => {
    const client = clientWith(() =>
      jsonResponse(400, { error: 'invalid_grant', TwoFactorProviders2: { '1': null } }),
    );

    const erreur = await client.login('a@b.c', HASH).catch((e: unknown) => e);
    expect(erreur).toBeInstanceOf(TwoFactorRequiredError);
    expect((erreur as TwoFactorRequiredError).providers).toEqual(['1']);
  });

  it('joint le second facteur au formulaire', async () => {
    const captured: Captured[] = [];
    const client = clientWith(() => jsonResponse(200, TOKEN_OK), captured);

    await client.login('a@b.c', HASH, { provider: 3, token: 'otp-yubikey', remember: true });

    const form = new URLSearchParams(String(captured[0]!.init?.body));
    expect(form.get('twoFactorProvider')).toBe('3');
    expect(form.get('twoFactorToken')).toBe('otp-yubikey');
    expect(form.get('twoFactorRemember')).toBe('1');
  });

  it('n’envoie aucun champ de second facteur sans second facteur', async () => {
    const captured: Captured[] = [];
    const client = clientWith(() => jsonResponse(200, TOKEN_OK), captured);

    await client.login('a@b.c', HASH);

    const form = new URLSearchParams(String(captured[0]!.init?.body));
    expect(form.get('twoFactorProvider')).toBeNull();
    expect(form.get('twoFactorToken')).toBeNull();
  });

  it('expose le jeton de dispense renvoyé par le serveur', async () => {
    const client = clientWith(() =>
      jsonResponse(200, { ...TOKEN_OK, TwoFactorToken: 'jeton-de-dispense' }),
    );

    const session = await client.login('a@b.c', HASH, {
      provider: 0,
      token: '123456',
      remember: true,
    });
    expect(session.twoFactorRememberToken).toBe('jeton-de-dispense');
  });

  it('traduit une exigence de captcha', async () => {
    const client = clientWith(() =>
      jsonResponse(400, { error: 'invalid_grant', HCaptcha_SiteKey: 'cle-site-hcaptcha' }),
    );

    const erreur = await client.login('a@b.c', HASH).catch((e: unknown) => e);
    expect(erreur).toBeInstanceOf(CaptchaRequiredError);
    expect((erreur as CaptchaRequiredError).siteKey).toBe('cle-site-hcaptcha');
    expect((erreur as CaptchaRequiredError).code).toBe('captcha-required');
  });

  it('rejette un 200 sans jeton d’accès', async () => {
    const client = clientWith(() => jsonResponse(200, { token_type: 'Bearer' }));

    await expect(client.login('a@b.c', HASH)).rejects.toThrow(/sans jeton d'accès/);
  });

  it('traduit un corps d’erreur non-JSON en ApiError', async () => {
    const client = clientWith(() => new Response('Bad Gateway', { status: 502 }));

    const erreur = await client.login('a@b.c', HASH).catch((e: unknown) => e);
    expect(erreur).toBeInstanceOf(ApiError);
    expect((erreur as ApiError).status).toBe(502);
    expect((erreur as ApiError).code).toBe('api-error');
  });
});

describe('refreshToken', () => {
  it('renvoie une nouvelle session à partir du jeton de rafraîchissement', async () => {
    const captured: Captured[] = [];
    const client = clientWith(
      () =>
        jsonResponse(200, {
          access_token: 'nouveau-jeton',
          refresh_token: 'nouveau-rafraichissement',
          expires_in: 3600,
          token_type: 'Bearer',
          Key: '2.aaa|bbb|ccc',
        }),
      captured,
    );

    const session = await client.refreshToken('ancien-rafraichissement');

    expect(session.accessToken).toBe('nouveau-jeton');
    expect(session.refreshToken).toBe('nouveau-rafraichissement');
    expect(session.protectedUserKey).toBe('2.aaa|bbb|ccc');

    const form = new URLSearchParams(String(captured[0]!.init?.body));
    expect(form.get('grant_type')).toBe('refresh_token');
    expect(form.get('refresh_token')).toBe('ancien-rafraichissement');
    expect(form.get('client_id')).toBe('zwarden');
  });

  it('traduit un jeton expiré en ApiError', async () => {
    const client = clientWith(() => jsonResponse(400, { error: 'invalid_grant' }));

    const erreur = await client.refreshToken('expire').catch((e: unknown) => e);
    expect(erreur).toBeInstanceOf(ApiError);
    expect((erreur as ApiError).status).toBe(400);
  });
});

describe('updateCipher', () => {
  it('émet un PUT complet sur l’item', async () => {
    const captured: Captured[] = [];
    const client = clientWith(() => jsonResponse(200, { id: 'id-1', type: 1 }), captured);
    const corps = { type: 1, name: '2.aaa|bbb|ccc' };

    const résultat = await client.updateCipher('jeton', 'id-1', corps);

    expect(résultat.id).toBe('id-1');
    expect(captured[0]!.url).toBe('https://vault.example.com/api/ciphers/id-1');
    expect(captured[0]!.init?.method).toBe('PUT');
    expect(String(captured[0]!.init?.body)).toBe(JSON.stringify(corps));
  });

  it('remonte les échecs', async () => {
    const client = clientWith(() => new Response('interdit', { status: 403 }));

    const erreur = await client.updateCipher('jeton', 'id-1', {}).catch((e: unknown) => e);
    expect(erreur).toBeInstanceOf(ApiError);
    expect((erreur as ApiError).status).toBe(403);
  });
});

describe('deleteCipher', () => {
  it('traite un 404 comme un succès (idempotence)', async () => {
    const client = clientWith(() => new Response('', { status: 404 }));
    await expect(client.deleteCipher('jeton', 'id-inconnu')).resolves.toBeUndefined();
  });

  it('remonte les autres échecs', async () => {
    const client = clientWith(() => new Response('interdit', { status: 403 }));

    const erreur = await client.deleteCipher('jeton', 'id').catch((e: unknown) => e);
    expect(erreur).toBeInstanceOf(ApiError);
    expect((erreur as ApiError).status).toBe(403);
  });
});

describe('normalisation de l’URL de serveur', () => {
  const base = { deviceIdentifier: 'id-1', fetchFn: (async () => new Response('{}')) as typeof fetch };

  /**
   * La validation portait sur l'URL analysée mais renvoyait la chaîne d'entrée :
   * paramètres et ancres survivaient, et la concaténation de chemin qui suit les
   * rend destructeurs. `https://coffre.fr/#x` + `/api/sync` donne
   * `https://coffre.fr/#x/api/sync`, où l'ancre avale le chemin.
   */
  it('refuse une URL porteuse d’un paramètre ou d’une ancre', () => {
    expect(() => new ApiClient({ ...base, serverUrl: 'https://coffre.fr/#x' })).toThrow(RangeError);
    expect(() => new ApiClient({ ...base, serverUrl: 'https://coffre.fr/?debug=1' })).toThrow(
      RangeError,
    );
  });

  it('conserve un chemin d’installation en sous-répertoire', async () => {
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

  it('exige HTTPS, sauf vers la boucle locale', () => {
    expect(() => new ApiClient({ ...base, serverUrl: 'http://coffre.fr' })).toThrow(RangeError);
    expect(() => new ApiClient({ ...base, serverUrl: 'http://localhost:8080' })).not.toThrow();
  });
});

describe('readField', () => {
  it('lit indifféremment les deux casses', () => {
    expect(readField<string>({ accessToken: 'a' }, 'accessToken')).toBe('a');
    expect(readField<string>({ AccessToken: 'a' }, 'accessToken')).toBe('a');
    expect(readField<string>({ key: 'k' }, 'Key')).toBe('k');
  });

  /**
   * `name in record` remontait la chaîne de prototypes : `constructor`,
   * `toString` et `valueOf` répondaient toujours présents. Aucun champ de l'API
   * n'entrait en collision, donc rien n'était exploitable — mais la garantie
   * tenait à une coïncidence de nommage plutôt qu'à la structure du code.
   */
  it('ne lit jamais une propriété héritée du prototype', () => {
    expect(readField<unknown>({}, 'constructor')).toBeUndefined();
    expect(readField<unknown>({}, 'toString')).toBeUndefined();
    expect(readField<unknown>({}, 'valueOf')).toBeUndefined();
    expect(readField<unknown>({}, 'hasOwnProperty')).toBeUndefined();
  });

  it('rend undefined sur une source non-objet', () => {
    expect(readField<unknown>(null, 'x')).toBeUndefined();
    expect(readField<unknown>('texte', 'x')).toBeUndefined();
  });
});
