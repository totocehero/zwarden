/**
 * @file Trousseau de clés du coffre : clé personnelle + clés d'organisation.
 *
 * Un item personnel est chiffré avec la clé du coffre ; un item partagé, avec
 * la clé de **son organisation**. Ces clés d'organisation arrivent dans le
 * profil de synchronisation, chiffrées en RSA vers la clé publique du membre.
 * La chaîne de déballage :
 *
 * ```
 *   clé du coffre ──déchiffre──► clé privée RSA (profile.privateKey, type 2)
 *   clé privée RSA ──déchiffre──► clé d'organisation (organizations[].key, type 4)
 *   clé d'organisation ──déchiffre──► items de l'organisation
 * ```
 *
 * Le trousseau se reconstruit à chaque synchronisation : rien de tout cela
 * n'est persisté.
 */

import { type ProfileOrganizationResponse, type SyncResponse, readField } from '../api/models.js';
import { EncString } from '../crypto/encString.js';
import { decryptBytes, decryptRsaBytes } from '../crypto/cryptoService.js';
import { wipe } from '../crypto/encoding.js';
import { SymmetricCryptoKey } from '../crypto/symmetricCryptoKey.js';

/** Levée (via `onError`) quand un item d'organisation n'a pas de clé connue. */
export class MissingOrgKeyError extends Error {
  override readonly name = 'MissingOrgKeyError';
  /** Identifiant stable pour l'interface : les messages servent aux journaux. */
  readonly code = 'missing-org-key';

  constructor(readonly organizationId: string) {
    super(`Clé d'organisation indisponible : ${organizationId}`);
  }
}

/** Clés nécessaires au déchiffrement de l'ensemble du coffre. */
export interface VaultKeys {
  readonly userKey: SymmetricCryptoKey;
  /** Clés d'organisation déballées, indexées par identifiant d'organisation. */
  readonly orgKeys: ReadonlyMap<string, SymmetricCryptoKey>;
}

/**
 * Construit le trousseau à partir du profil de synchronisation.
 *
 * Robuste par construction : une organisation dont la clé ne se déballe pas
 * est signalée via `onError` et ignorée — ses items seront illisibles, le
 * reste du coffre non. Sans organisation, aucune cryptographie RSA n'est
 * touchée.
 *
 * @param profile Champ `profile` de la réponse de synchronisation.
 * @param userKey Clé du coffre.
 * @param onError Notification de chaque clé impossible à déballer.
 * @returns Trousseau, avec les clés d'organisation résolues.
 */
export async function buildVaultKeys(
  profile: SyncResponse['profile'],
  userKey: SymmetricCryptoKey,
  onError: (error: unknown) => void,
): Promise<VaultKeys> {
  const orgKeys = new Map<string, SymmetricCryptoKey>();
  const organizations =
    readField<readonly ProfileOrganizationResponse[]>(profile, 'organizations') ?? [];

  if (organizations.length === 0) {
    return { userKey, orgKeys };
  }

  const protectedPrivateKey = readField<string>(profile, 'privateKey');
  if (protectedPrivateKey == null || protectedPrivateKey === '') {
    onError(new Error('Profil sans clé privée : clés d’organisation indéchiffrables'));
    return { userKey, orgKeys };
  }

  let pkcs8: Uint8Array;
  try {
    pkcs8 = await decryptBytes(EncString.parse(protectedPrivateKey), userKey);
  } catch (error) {
    onError(error);
    return { userKey, orgKeys };
  }

  try {
    for (const organization of organizations) {
      const id = readField<string>(organization, 'id');
      const wrapped = readField<string>(organization, 'key');
      if (id == null || wrapped == null || wrapped === '') {
        continue;
      }
      try {
        const raw = await decryptRsaBytes(EncString.parse(wrapped), pkcs8);
        orgKeys.set(id, new SymmetricCryptoKey(raw));
      } catch (error) {
        onError(error);
      }
    }
  } finally {
    // La clé privée n'a plus d'usage une fois les clés d'organisation
    // déballées. Best-effort, comme tout effacement en JavaScript.
    wipe(pkcs8);
  }

  return { userKey, orgKeys };
}

/**
 * Clé de base d'un item : celle du coffre, ou celle de son organisation.
 *
 * @returns `null` si l'item appartient à une organisation dont la clé n'a pas
 *   pu être déballée.
 */
export function keyForCipher(cipher: unknown, keys: VaultKeys): SymmetricCryptoKey | null {
  const organizationId = readField<string | null>(cipher, 'organizationId') ?? null;
  if (organizationId === null) {
    return keys.userKey;
  }
  return keys.orgKeys.get(organizationId) ?? null;
}
