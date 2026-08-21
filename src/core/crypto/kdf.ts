/**
 * Dérivation de la clé maître à partir du mot de passe.
 *
 * PBKDF2-SHA256 passe par WebCrypto (natif, 0 octet de bundle).
 * Argon2id n'a pas d'équivalent natif : le WASM est chargé en import dynamique,
 * donc uniquement au déverrouillage d'un compte configuré en Argon2id. C'est la
 * seule dépendance WASM du projet (~45 Ko contre 7,4 Mo pour le SDK Bitwarden).
 */

import { hkdfExpandSha256, pbkdf2Sha256, sha256 } from './primitives.js';
import { SymmetricCryptoKey } from './symmetricCryptoKey.js';
import { toBase64, toUtf8Bytes } from './encoding.js';

export const KdfType = {
  PBKDF2_SHA256: 0,
  Argon2id: 1,
} as const;

export type KdfType = (typeof KdfType)[keyof typeof KdfType];

/** Plancher recommandé par l'OWASP pour PBKDF2-SHA256. */
export const PBKDF2_MIN_ITERATIONS = 600_000;
export const PBKDF2_DEFAULT_ITERATIONS = 600_000;

export const ARGON2_DEFAULTS = {
  iterations: 3,
  /** En MiB, comme dans l'API Bitwarden. */
  memoryMiB: 64,
  parallelism: 4,
} as const;

export type KdfConfig =
  | { readonly type: typeof KdfType.PBKDF2_SHA256; readonly iterations: number }
  | {
      readonly type: typeof KdfType.Argon2id;
      readonly iterations: number;
      readonly memoryMiB: number;
      readonly parallelism: number;
    };

export class WeakKdfError extends Error {
  override readonly name = 'WeakKdfError';
}

/**
 * Rejette les paramètres KDF anormalement faibles.
 *
 * Un serveur hostile (ou compromis) peut annoncer `iterations: 1` pour rendre
 * la clé maître triviale à attaquer hors-ligne. Les paramètres KDF viennent du
 * serveur avant authentification : ils doivent être traités comme une entrée
 * non fiable. Bitwarden ne fait pas cette validation côté client.
 */
export function assertKdfIsAcceptable(config: KdfConfig): void {
  if (config.type === KdfType.PBKDF2_SHA256) {
    if (config.iterations < 100_000) {
      throw new WeakKdfError(
        `PBKDF2 avec ${config.iterations} itérations : trop faible, refusé (minimum 100 000)`,
      );
    }
    return;
  }

  if (config.iterations < 2 || config.memoryMiB < 16 || config.parallelism < 1) {
    throw new WeakKdfError(
      `Argon2id t=${config.iterations} m=${config.memoryMiB}MiB p=${config.parallelism} : trop faible, refusé`,
    );
  }
}

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

/**
 * Clé maître : 32 octets dérivés du mot de passe et de l'e-mail (le sel).
 * Elle ne chiffre jamais de données directement — elle protège la clé du coffre.
 */
export async function deriveMasterKey(
  password: string,
  email: string,
  config: KdfConfig,
): Promise<SymmetricCryptoKey> {
  assertKdfIsAcceptable(config);

  const passwordBytes = toUtf8Bytes(password.normalize('NFKD'));
  const emailBytes = toUtf8Bytes(normalizeEmail(email));

  if (config.type === KdfType.PBKDF2_SHA256) {
    return new SymmetricCryptoKey(
      await pbkdf2Sha256(passwordBytes, emailBytes, config.iterations, 32),
    );
  }

  // Argon2id : le sel est le SHA-256 de l'e-mail, pas l'e-mail brut.
  const salt = await sha256(emailBytes);
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
 * Étire la clé maître (32 o) en une clé authentifiée (64 o) via HKDF-Expand.
 * C'est cette clé qui déchiffre la clé du coffre.
 */
export async function stretchMasterKey(masterKey: SymmetricCryptoKey): Promise<SymmetricCryptoKey> {
  const encKey = await hkdfExpandSha256(masterKey.key, 'enc', 32);
  const macKey = await hkdfExpandSha256(masterKey.key, 'mac', 32);
  const stretched = new Uint8Array(64);
  stretched.set(encKey, 0);
  stretched.set(macKey, 32);
  return new SymmetricCryptoKey(stretched);
}

/**
 * Hash du mot de passe maître transmis au serveur pour l'authentification.
 *
 * PBKDF2 à 1 itération, clé maître en « mot de passe » et mot de passe en
 * « sel ». Le serveur ne voit donc jamais ni le mot de passe, ni la clé maître.
 */
export async function deriveMasterPasswordHash(
  masterKey: SymmetricCryptoKey,
  password: string,
): Promise<string> {
  const hash = await pbkdf2Sha256(masterKey.key, toUtf8Bytes(password.normalize('NFKD')), 1, 32);
  return toBase64(hash);
}

/**
 * Variante locale, utilisée pour valider le mot de passe hors ligne (2 itérations)
 * afin de ne jamais stocker le même hash que celui envoyé au serveur.
 */
export async function deriveLocalPasswordHash(
  masterKey: SymmetricCryptoKey,
  password: string,
): Promise<string> {
  const hash = await pbkdf2Sha256(masterKey.key, toUtf8Bytes(password.normalize('NFKD')), 2, 32);
  return toBase64(hash);
}
