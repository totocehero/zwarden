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
import { toBase64, toUtf8Bytes } from './encoding.js';

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

/** Paramètres de dérivation, tels qu'annoncés par le serveur. */
export type KdfConfig =
  | { readonly type: typeof KdfType.PBKDF2_SHA256; readonly iterations: number }
  | {
      readonly type: typeof KdfType.Argon2id;
      readonly iterations: number;
      readonly memoryMiB: number;
      readonly parallelism: number;
    };

/** Levée lorsque le serveur annonce des paramètres KDF dangereusement faibles. */
export class WeakKdfError extends Error {
  override readonly name = 'WeakKdfError';
}

/**
 * Refuse les paramètres KDF trop faibles.
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
 * Le client Bitwarden officiel n'effectue pas ce contrôle. Zwarden préfère
 * refuser de se connecter plutôt que d'affaiblir silencieusement la clé.
 *
 * @param config Paramètres annoncés par le serveur.
 * @throws {WeakKdfError} Si les paramètres sont sous les seuils.
 */
export function assertKdfIsAcceptable(config: KdfConfig): void {
  if (config.type === KdfType.PBKDF2_SHA256) {
    if (config.iterations < PBKDF2_MIN_ITERATIONS) {
      throw new WeakKdfError(
        `PBKDF2 annoncé à ${config.iterations} itérations, minimum accepté ${PBKDF2_MIN_ITERATIONS}. ` +
          'Connexion refusée : ce paramètre rendrait le mot de passe maître attaquable hors ligne.',
      );
    }
    return;
  }

  const faibles =
    config.iterations < ARGON2_MINIMUMS.iterations ||
    config.memoryMiB < ARGON2_MINIMUMS.memoryMiB ||
    config.parallelism < ARGON2_MINIMUMS.parallelism;

  if (faibles) {
    throw new WeakKdfError(
      `Argon2id annoncé à t=${config.iterations} m=${config.memoryMiB}MiB p=${config.parallelism}, ` +
        `minimum accepté t=${ARGON2_MINIMUMS.iterations} m=${ARGON2_MINIMUMS.memoryMiB}MiB ` +
        `p=${ARGON2_MINIMUMS.parallelism}. Connexion refusée.`,
    );
  }
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

  if (config.type === KdfType.PBKDF2_SHA256) {
    // PBKDF2 prend l'e-mail normalisé directement comme sel.
    const salt = toUtf8Bytes(normalizeEmail(email));
    return new SymmetricCryptoKey(await pbkdf2Sha256(passwordBytes, salt, config.iterations, 32));
  }

  // Argon2id impose un sel de taille fixe : Bitwarden utilise le SHA-256 de
  // l'e-mail, et non l'e-mail brut. Divergence = coffres illisibles.
  const salt = await sha256(toUtf8Bytes(normalizeEmail(email)));

  const { argon2id } = await import('hash-wasm');
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
  const stretched = new Uint8Array(64);
  stretched.set(await hkdfExpandSha256(masterKey.key, 'enc', 32), 0);
  stretched.set(await hkdfExpandSha256(masterKey.key, 'mac', 32), 32);
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
  const hash = await pbkdf2Sha256(masterKey.key, normalizePassword(password), purpose, 32);
  return toBase64(hash);
}
