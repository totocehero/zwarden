/**
 * @file Codes à usage unique (TOTP, RFC 6238).
 *
 * ## Ce que le coffre stocke, et ce qu'il faut en faire
 *
 * Le champ `totp` d'un item Bitwarden n'a pas une forme unique. Trois cas se
 * rencontrent dans la nature, et un gestionnaire qui n'en gère qu'un affiche
 * des codes faux :
 *
 * ```
 *   JBSWY3DPEHPK3PXP                    secret base32 nu
 *   otpauth://totp/GitHub:moi?secret=…  URI complète, avec ses paramètres
 *   steam://…                           variante Steam (hors périmètre)
 * ```
 *
 * L'URI porte éventuellement `digits`, `period` et `algorithm` : les ignorer
 * donnerait un code de six chiffres là où le site en attend huit, ou un code
 * SHA-1 là où il attend SHA-256. Ce sont des échecs silencieux — le code
 * s'affiche, il est simplement refusé — d'où l'analyse explicite ici.
 *
 * ## Séparation des responsabilités
 *
 * Ce module ne touche ni au coffre, ni au réseau, ni à l'horloge : `now` est
 * un paramètre. C'est ce qui rend les vecteurs de la RFC rejouables tels
 * quels.
 */

import { fromBase32 } from '../crypto/encoding.js';
import { type OtpAlgorithm, hmacForOtp } from '../crypto/primitives.js';

/** Paramètres d'un générateur TOTP, valeurs par défaut résolues. */
export interface TotpConfig {
  /** Secret partagé, décodé. */
  readonly secret: Uint8Array;
  /** Nombre de chiffres du code. */
  readonly digits: number;
  /** Durée de validité d'un code, en secondes. */
  readonly period: number;
  readonly algorithm: OtpAlgorithm;
}

/** Levée lorsque le champ `totp` de l'item est inexploitable. */
export class TotpError extends Error {
  override readonly name = 'TotpError';
  readonly code = 'totp-invalid';
}

/** Valeurs par défaut de RFC 6238, celles que suppose tout site qui se tait. */
const DEFAULTS = { digits: 6, period: 30, algorithm: 'SHA-1' as OtpAlgorithm };

/** Traduit le nom d'algorithme d'une URI vers celui de WebCrypto. */
function toWebCryptoAlgorithm(raw: string | null): OtpAlgorithm {
  switch (raw?.toUpperCase()) {
    case undefined:
    case 'SHA1':
    case 'SHA-1':
      return 'SHA-1';
    case 'SHA256':
    case 'SHA-256':
      return 'SHA-256';
    case 'SHA512':
    case 'SHA-512':
      return 'SHA-512';
    default:
      throw new TotpError(`Algorithme TOTP non pris en charge : ${raw}`);
  }
}

/** Lit un entier de paramètre d'URI, valeur par défaut si absent ou aberrant. */
function readInt(params: URLSearchParams, key: string, fallback: number, min: number, max: number): number {
  const raw = params.get(key);
  if (raw === null) {
    return fallback;
  }
  const value = Number.parseInt(raw, 10);
  // Un paramètre hors bornes est une erreur de saisie du site, pas une
  // instruction : mieux vaut le défaut de la RFC qu'un code impossible.
  return Number.isFinite(value) && value >= min && value <= max ? value : fallback;
}

/**
 * Analyse le champ `totp` d'un item.
 *
 * @param raw Contenu déchiffré du champ, secret nu ou URI `otpauth://`.
 * @returns Paramètres résolus, prêts pour {@link generateTotp}.
 * @throws {TotpError} Champ vide, schéma inconnu, secret absent ou illisible.
 */
export function parseTotp(raw: string): TotpConfig {
  const trimmed = raw.trim();
  if (trimmed === '') {
    throw new TotpError('Champ TOTP vide');
  }

  if (!trimmed.toLowerCase().startsWith('otpauth://')) {
    return { secret: decodeSecret(trimmed), ...DEFAULTS };
  }

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    throw new TotpError('URI otpauth:// illisible');
  }
  if (url.host.toLowerCase() !== 'totp') {
    // `otpauth://hotp/…` est un compteur, pas une horloge : afficher un code
    // TOTP pour un item HOTP donnerait un code faux à chaque fois.
    throw new TotpError(`Type de code non pris en charge : ${url.host}`);
  }

  const secret = url.searchParams.get('secret');
  if (secret === null || secret === '') {
    throw new TotpError('URI otpauth:// sans paramètre secret');
  }

  return {
    secret: decodeSecret(secret),
    digits: readInt(url.searchParams, 'digits', DEFAULTS.digits, 6, 10),
    period: readInt(url.searchParams, 'period', DEFAULTS.period, 1, 300),
    algorithm: toWebCryptoAlgorithm(url.searchParams.get('algorithm')),
  };
}

function decodeSecret(raw: string): Uint8Array {
  let secret: Uint8Array;
  try {
    secret = fromBase32(raw);
  } catch (error) {
    throw new TotpError(`Secret TOTP illisible : ${(error as Error).message}`);
  }
  if (secret.length === 0) {
    throw new TotpError('Secret TOTP vide');
  }
  return secret;
}

/**
 * Calcule le code courant.
 *
 * @param config Paramètres résolus par {@link parseTotp}.
 * @param now Instant, en millisecondes depuis l'époque.
 * @returns Code, complété de zéros à gauche à la longueur demandée.
 */
export async function generateTotp(config: TotpConfig, now: number = Date.now()): Promise<string> {
  const counter = Math.floor(now / 1000 / config.period);

  // Compteur sur 8 octets, gros-boutiste. `BigInt` plutôt qu'un décalage :
  // au-delà de 2^31 les opérateurs binaires de JavaScript repassent en 32
  // bits signés — le bogue attend l'an 2038 pour se manifester.
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(counter), false);

  const mac = await hmacForOtp(config.algorithm, config.secret, bytes);

  // Troncature dynamique, RFC 4226 §5.3.
  const offset = mac[mac.length - 1]! & 0x0f;
  const binary =
    ((mac[offset]! & 0x7f) << 24) |
    ((mac[offset + 1]! & 0xff) << 16) |
    ((mac[offset + 2]! & 0xff) << 8) |
    (mac[offset + 3]! & 0xff);

  return String(binary % 10 ** config.digits).padStart(config.digits, '0');
}

/**
 * Secondes restantes avant l'expiration du code courant.
 *
 * @param config Paramètres résolus.
 * @param now Instant, en millisecondes depuis l'époque.
 */
export function secondsRemaining(config: TotpConfig, now: number = Date.now()): number {
  return config.period - Math.floor(now / 1000) % config.period;
}

/** Insère une espace au milieu du code : `123456` → `123 456`. */
export function formatTotp(code: string): string {
  const half = Math.ceil(code.length / 2);
  return `${code.slice(0, half)} ${code.slice(half)}`;
}
