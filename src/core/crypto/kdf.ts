/**
 * @file Dérivation de la clé maître à partir du mot de passe.
 *
 * ## Chaîne de clés
 *
 * ```
 *   mot de passe maître
 *          │  KDF (PBKDF2-SHA256 ou Argon2id), sel = e-mail
 *          ▼
 *      clé maître (32 o)  ─────────────┐
 *          │  HKDF-Expand              │  PBKDF2, 1 ou 2 itérations
 *          ▼                           ▼
 *   clé maître étirée (64 o)      hash du mot de passe
 *          │  déchiffre                 (authentification serveur /
 *          ▼                             validation hors ligne)
 *    clé du coffre (64 o)
 *          │  déchiffre
 *          ▼
 *   contenu des items
 * ```
 *
 * Point essentiel : **la clé maître ne chiffre jamais de données**. Elle sert
 * uniquement à déverrouiller la clé du coffre. C'est ce qui permet de changer
 * de mot de passe sans re-chiffrer l'intégralité du coffre — seule la clé du
 * coffre est ré-enveloppée.
 *
 * ## Coût du WASM
 *
 * PBKDF2-SHA256 passe par WebCrypto : natif, 0 octet de bundle. Argon2id n'a
 * aucun équivalent natif dans les navigateurs ; le module WASM (~45 Ko) est
 * chargé en import dynamique, donc uniquement au déverrouillage d'un compte
 * réellement configuré en Argon2id. Un compte PBKDF2 ne le télécharge jamais.
 * À comparer aux 7,4 Mo de SDK chargés inconditionnellement par le client
 * officiel.
 */

import { hkdfExpandSha256, pbkdf2Sha256, sha256 } from './primitives.js';
import { SymmetricCryptoKey } from './symmetricCryptoKey.js';
import { fromBase64, timingSafeEqual, toBase64, toUtf8Bytes, wipe } from './encoding.js';

/** Fonctions de dérivation supportées, valeurs telles qu'annoncées par l'API. */
export const KdfType = {
  PBKDF2_SHA256: 0,
  Argon2id: 1,
} as const;

export type KdfType = (typeof KdfType)[keyof typeof KdfType];

/**
 * Usage d'un hash de mot de passe.
 *
 * La valeur numérique **est** le nombre d'itérations PBKDF2 appliquées, ce qui
 * garantit que les deux hashs diffèrent. Conséquence : le hash conservé
 * localement pour valider le mot de passe hors ligne ne peut pas être rejoué
 * comme preuve d'authentification auprès du serveur, et inversement.
 */
export const HashPurpose = {
  /** Transmis au serveur lors de l'authentification. */
  ServerAuthorization: 1,
  /** Conservé localement pour valider le mot de passe sans réseau. */
  LocalAuthorization: 2,
} as const;

export type HashPurpose = (typeof HashPurpose)[keyof typeof HashPurpose];

/** Plancher OWASP 2023 pour PBKDF2-SHA256. */
export const PBKDF2_DEFAULT_ITERATIONS = 600_000;

/**
 * Seuil de refus pour PBKDF2.
 *
 * Volontairement plus bas que la valeur recommandée : de nombreux coffres
 * existants ont été créés avec 100 000 itérations (ancien défaut Bitwarden) et
 * doivent rester déverrouillables. En dessous, le coût d'une attaque hors
 * ligne devient dérisoire.
 */
export const PBKDF2_MIN_ITERATIONS = 100_000;

/**
 * Plafond de refus pour PBKDF2.
 *
 * Symétrique du plancher : les paramètres viennent du serveur avant
 * authentification, un serveur hostile peut donc annoncer une valeur absurde
 * (2³¹ itérations) pour geler le client au déverrouillage — un déni de service
 * qui pousse l'utilisateur vers un client moins regardant. L'interface du
 * client officiel plafonne à 2 000 000 ; 5 000 000 laisse une marge
 * confortable sans jamais refuser un coffre légitime.
 */
export const PBKDF2_MAX_ITERATIONS = 5_000_000;

/** Paramètres Argon2id par défaut, alignés sur ceux de Bitwarden. */
export const ARGON2_DEFAULTS = {
  iterations: 3,
  /** En mébioctets, comme dans l'API. */
  memoryMiB: 64,
  parallelism: 4,
} as const;

/** Seuils de refus pour Argon2id. */
const ARGON2_MINIMUMS = {
  iterations: 2,
  memoryMiB: 16,
  parallelism: 1,
} as const;

/**
 * Plafonds de refus pour Argon2id, alignés sur les maxima de l'interface du
 * client officiel : aucun coffre créé par Bitwarden ne peut les dépasser.
 *
 * Le plus critique est la mémoire : `memoryMiB` se traduit en allocation WASM
 * réelle. Sans plafond, un serveur hostile annonçant plusieurs gibioctets fait
 * échouer l'allocation ou tue l'onglet — déni de service au déverrouillage.
 */
const ARGON2_MAXIMUMS = {
  iterations: 10,
  memoryMiB: 1024,
  parallelism: 16,
} as const;

/** Paramètres de dérivation, tels qu'annoncés par le serveur. */
export type KdfConfig =
  | { readonly type: typeof KdfType.PBKDF2_SHA256; readonly iterations: number }
  | {
      readonly type: typeof KdfType.Argon2id;
      readonly iterations: number;
      readonly memoryMiB: number;
      readonly parallelism: number;
    };

/** Levée lorsque le serveur annonce des paramètres KDF dangereux ou malformés. */
export class WeakKdfError extends Error {
  override readonly name = 'WeakKdfError';
  /** Identifiant stable pour l'interface : les messages servent aux journaux. */
  readonly code = 'weak-kdf';
}

/**
 * Valide un paramètre KDF annoncé par le serveur : entier sûr, dans [min, max].
 *
 * @throws {WeakKdfError} Message adapté au cas rencontré.
 */
function assertParameterInRange(label: string, value: number, min: number, max: number): void {
  if (!Number.isSafeInteger(value)) {
    // Couvre NaN, ±Infinity, les flottants, et les valeurs non numériques
    // qu'un serveur hostile glisserait dans le JSON : rien de tout cela ne
    // doit atteindre le KDF.
    throw new WeakKdfError(
      `${label} : valeur non entière ou absente (${String(value)}). Connexion refusée.`,
    );
  }
  if (value < min) {
    throw new WeakKdfError(
      `${label} annoncé à ${value}, minimum accepté ${min}. ` +
        'Connexion refusée : ce paramètre rendrait le mot de passe maître attaquable hors ligne.',
    );
  }
  if (value > max) {
    throw new WeakKdfError(
      `${label} annoncé à ${value}, maximum accepté ${max}. ` +
        'Connexion refusée : une valeur aberrante gèlerait le client au déverrouillage.',
    );
  }
}

/**
 * Refuse les paramètres KDF trop faibles, aberrants ou malformés.
 *
 * ## Pourquoi cette vérification existe
 *
 * Les paramètres KDF sont fournis par le serveur via `/api/accounts/prelogin`,
 * **avant toute authentification**. Ils constituent donc une entrée non fiable.
 * Un serveur compromis — ou un attaquant en position de machine du milieu sur
 * une instance mal configurée — peut répondre `iterations: 1`. Le client
 * dérive alors une clé maître au coût d'un seul tour de PBKDF2 : le mot de
 * passe devient attaquable hors ligne en quelques secondes, et le hash
 * d'authentification transmis suffit à monter l'attaque.
 *
 * Le contrôle est borné dans les deux sens : trop faible, la clé devient
 * cassable hors ligne ; trop élevé (2³¹ itérations, mémoire Argon2 en
 * gibioctets), le client gèle ou l'onglet meurt — déni de service au
 * déverrouillage. Le client Bitwarden officiel n'effectue aucun de ces deux
 * contrôles. Zwarden préfère refuser de se connecter plutôt que d'affaiblir
 * silencieusement la clé ou de se laisser geler.
 *
 * @param config Paramètres annoncés par le serveur.
 * @throws {WeakKdfError} Si un paramètre est hors bornes ou non entier.
 */
export function assertKdfIsAcceptable(config: KdfConfig): void {
  if (config.type === KdfType.PBKDF2_SHA256) {
    assertParameterInRange(
      'PBKDF2 (itérations)',
      config.iterations,
      PBKDF2_MIN_ITERATIONS,
      PBKDF2_MAX_ITERATIONS,
    );
    return;
  }

  assertParameterInRange(
    'Argon2id (itérations)',
    config.iterations,
    ARGON2_MINIMUMS.iterations,
    ARGON2_MAXIMUMS.iterations,
  );
  assertParameterInRange(
    'Argon2id (mémoire MiB)',
    config.memoryMiB,
    ARGON2_MINIMUMS.memoryMiB,
    ARGON2_MAXIMUMS.memoryMiB,
  );
  assertParameterInRange(
    'Argon2id (parallélisme)',
    config.parallelism,
    ARGON2_MINIMUMS.parallelism,
    ARGON2_MAXIMUMS.parallelism,
  );
}

/**
 * Normalise l'e-mail servant de sel.
 *
 * Le sel doit être identique sur tous les clients, sinon la clé dérivée
 * diffère et le coffre devient illisible. Bitwarden applique `trim()` puis
 * `toLowerCase()` ; toute divergence ici casse l'interopérabilité.
 */
function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

/**
 * Normalise le mot de passe avant dérivation.
 *
 * NFKD aligne les représentations Unicode équivalentes : un « é » saisi comme
 * point de code unique et le même composé d'un « e » suivi d'un accent
 * combinant produisent alors la même clé, quel que soit le clavier ou l'OS.
 */
function normalizePassword(password: string): Uint8Array {
  return toUtf8Bytes(password.normalize('NFKD'));
}

/**
 * Dérive la clé maître depuis le mot de passe et l'e-mail.
 *
 * @param password Mot de passe maître, en clair.
 * @param email E-mail du compte, utilisé comme sel.
 * @param config Paramètres KDF annoncés par le serveur.
 * @returns Clé maître de 32 octets, non authentifiée (sans `macKey`).
 * @throws {WeakKdfError} Si les paramètres sont sous les seuils.
 */
export async function deriveMasterKey(
  password: string,
  email: string,
  config: KdfConfig,
): Promise<SymmetricCryptoKey> {
  assertKdfIsAcceptable(config);

  const passwordBytes = normalizePassword(password);
  try {
    if (config.type === KdfType.PBKDF2_SHA256) {
      // PBKDF2 prend l'e-mail normalisé directement comme sel.
      const salt = toUtf8Bytes(normalizeEmail(email));
      return new SymmetricCryptoKey(await pbkdf2Sha256(passwordBytes, salt, config.iterations, 32));
    }

    // Argon2id impose un sel de taille fixe : Bitwarden utilise le SHA-256 de
    // l'e-mail, et non l'e-mail brut. Divergence = coffres illisibles.
    const salt = await sha256(toUtf8Bytes(normalizeEmail(email)));

    // Build par algorithme (29 Ko) plutôt que l'ESM monolithique du paquet
    // (212 Ko une fois bundlé). Ce build UMD expose ses fonctions nommées ou
    // sous `default` selon l'interop CJS de l'environnement : on couvre les
    // deux. Voir `src/types/hash-wasm-argon2.d.ts`.
    const umd = await import('hash-wasm/dist/argon2.umd.min.js');
    const argon2id = umd.argon2id ?? umd.default?.argon2id;
    if (argon2id === undefined) {
      throw new Error('Module Argon2 illisible : aucun export argon2id');
    }

    const derived = await argon2id({
      password: passwordBytes,
      salt,
      parallelism: config.parallelism,
      iterations: config.iterations,
      memorySize: config.memoryMiB * 1024, // hash-wasm attend des KiB
      hashLength: 32,
      outputType: 'binary',
    });

    return new SymmetricCryptoKey(derived);
  } finally {
    // Le mot de passe encodé n'a plus d'usage une fois la clé dérivée.
    // Best-effort, comme tout effacement en JavaScript.
    wipe(passwordBytes);
  }
}

/**
 * Étire la clé maître en une clé authentifiée utilisable pour chiffrer.
 *
 * La clé maître fait 32 octets : de quoi chiffrer, pas d'authentifier. On la
 * développe en 64 octets (`encKey` ‖ `macKey`) par deux appels HKDF-Expand.
 *
 * L'étape Extract de HKDF est délibérément omise : la clé maître est déjà une
 * PRK uniformément aléatoire issue du KDF. C'est aussi ce que fait Bitwarden —
 * y ajouter Extract produirait une clé différente et rendrait les coffres
 * existants illisibles.
 *
 * @param masterKey Clé maître issue de {@link deriveMasterKey}.
 * @returns Clé de 64 octets, authentifiée.
 */
export async function stretchMasterKey(masterKey: SymmetricCryptoKey): Promise<SymmetricCryptoKey> {
  // Les deux dérivations sont indépendantes : lancées de front.
  const [encKey, macKey] = await Promise.all([
    hkdfExpandSha256(masterKey.key, 'enc', 32),
    hkdfExpandSha256(masterKey.key, 'mac', 32),
  ]);

  const stretched = new Uint8Array(64);
  stretched.set(encKey, 0);
  stretched.set(macKey, 32);
  wipe(encKey);
  wipe(macKey);
  return new SymmetricCryptoKey(stretched);
}

/**
 * Calcule un hash du mot de passe maître.
 *
 * PBKDF2 est appliqué « à l'envers » : la clé maître joue le rôle de mot de
 * passe et le mot de passe celui de sel. Le serveur reçoit donc une valeur
 * dont il ne peut retrouver ni le mot de passe, ni la clé maître.
 *
 * Le nombre d'itérations est l'usage lui-même ({@link HashPurpose}), ce qui
 * rend les deux hashs structurellement distincts.
 *
 * @param masterKey Clé maître.
 * @param password Mot de passe maître, en clair.
 * @param purpose Destination du hash.
 * @returns Hash de 32 octets encodé en base64.
 */
export async function derivePasswordHash(
  masterKey: SymmetricCryptoKey,
  password: string,
  purpose: HashPurpose,
): Promise<string> {
  const salt = normalizePassword(password);
  try {
    const hash = await pbkdf2Sha256(masterKey.key, salt, purpose, 32);
    return toBase64(hash);
  } finally {
    wipe(salt);
  }
}

/**
 * Valide un mot de passe contre le hash local, sans réseau.
 *
 * C'est le chemin de l'écran de verrouillage : le hash `LocalAuthorization`
 * est conservé au premier déverrouillage, puis chaque saisie est revalidée
 * contre lui. La comparaison porte sur les **octets décodés**, à temps
 * constant — jamais un `===` sur les chaînes base64, qui court-circuite au
 * premier caractère divergent.
 *
 * @param masterKey Clé maître dérivée de la saisie à valider.
 * @param password Mot de passe saisi, en clair.
 * @param expectedHashB64 Hash local conservé, en base64.
 * @returns `true` si la saisie correspond.
 */
export async function verifyLocalPasswordHash(
  masterKey: SymmetricCryptoKey,
  password: string,
  expectedHashB64: string,
): Promise<boolean> {
  const actual = await derivePasswordHash(masterKey, password, HashPurpose.LocalAuthorization);
  return timingSafeEqual(fromBase64(actual), fromBase64(expectedHashB64));
}
