/**
 * @file Étiquettes du coffre : dossiers et collections, unifiés en « tags ».
 *
 * Deux mécanismes distincts du protocole, une seule notion en surface :
 *
 * - **dossier** (`#nom`) — rangement personnel, un seul par item, nom chiffré
 *   avec la clé du coffre ;
 * - **collection** (`@nom`) — unité de contrôle d'accès du partage, plusieurs
 *   par item, nom chiffré avec la clé de **son organisation**.
 *
 * Cette phase est en lecture : déchiffrer les noms pour l'affichage et le
 * filtrage. L'assignation et le partage par tag viendront ensuite.
 */

import {
  type CollectionResponse,
  type FolderResponse,
  type SyncResponse,
  readField,
} from '../api/models.js';
import { decryptStringOrNull } from '../crypto/cryptoService.js';
import { SymmetricCryptoKey } from '../crypto/symmetricCryptoKey.js';
import type { CipherKeys } from './cipherService.js';
import { MissingOrgKeyError } from './keyring.js';

/** Collection déchiffrée, avec ce que l'interface doit savoir. */
export interface CollectionLabel {
  readonly name: string;
  readonly organizationId: string | null;
  /**
   * `true` si le membre n'a que la lecture sur cette collection : l'interface
   * doit désactiver l'édition de ses items plutôt que promettre un
   * enregistrement qui échouera en 403.
   */
  readonly readOnly: boolean;
}

/** Étiquettes déchiffrées du coffre. */
export interface VaultLabels {
  /** Dossiers personnels : id → nom. */
  readonly folders: ReadonlyMap<string, string>;
  /** Collections : id → étiquette. */
  readonly collections: ReadonlyMap<string, CollectionLabel>;
  /** Organisations : id → nom (en clair dans le profil). */
  readonly organizations: ReadonlyMap<string, string>;
}

/** Étiquettes vides, pour les états intermédiaires de l'interface. */
export const EMPTY_LABELS: VaultLabels = {
  folders: new Map(),
  collections: new Map(),
  organizations: new Map(),
};

/**
 * Déchiffre les étiquettes d'une réponse de synchronisation.
 *
 * Robuste par construction : une étiquette illisible est signalée via
 * `onError` et ignorée — elle n'apparaît pas, le reste du coffre vit.
 *
 * @param sync Réponse de synchronisation complète.
 * @param keys Clé du coffre seule, ou trousseau complet (organisations).
 * @param onError Notification de chaque étiquette illisible.
 */
export async function decryptLabels(
  sync: SyncResponse,
  keys: CipherKeys,
  onError: (error: unknown) => void,
): Promise<VaultLabels> {
  const userKey = keys instanceof SymmetricCryptoKey ? keys : keys.userKey;
  const orgKeys =
    keys instanceof SymmetricCryptoKey ? new Map<string, SymmetricCryptoKey>() : keys.orgKeys;

  const [folders, collections] = await Promise.all([
    decryptFolders(sync, userKey, onError),
    decryptCollections(sync, userKey, orgKeys, onError),
  ]);

  return { folders, collections, organizations: readOrganizations(sync) };
}

/** Dossiers personnels : nom chiffré avec la clé du coffre. */
async function decryptFolders(
  sync: SyncResponse,
  userKey: SymmetricCryptoKey,
  onError: (error: unknown) => void,
): Promise<Map<string, string>> {
  const folders = new Map<string, string>();
  for (const folder of readField<readonly FolderResponse[]>(sync, 'folders') ?? []) {
    const id = readField<string>(folder, 'id');
    if (id == null) {
      continue;
    }
    const name = await decryptStringOrNull(readField<string>(folder, 'name'), userKey, onError);
    if (name !== null) {
      folders.set(id, name);
    }
  }
  return folders;
}

/**
 * Noms d'organisations. Seule famille d'étiquettes qui arrive **en clair** dans
 * le profil : d'où l'absence de déchiffrement, et de fonction asynchrone.
 */
function readOrganizations(sync: SyncResponse): Map<string, string> {
  const organizations = new Map<string, string>();
  const profile = readField<SyncResponse['profile']>(sync, 'profile');
  for (const org of readField<ReadonlyArray<Record<string, unknown>>>(profile, 'organizations') ??
    []) {
    const id = readField<string>(org, 'id');
    const name = readField<string>(org, 'name');
    if (id != null && name != null) {
      organizations.set(id, name);
    }
  }
  return organizations;
}

/**
 * Collections. Le nom est chiffré avec la clé de **son** organisation, pas
 * celle du coffre : une collection dont la clé d'organisation n'a pas été
 * déballée est signalée et sautée, sans faire échouer les autres.
 */
async function decryptCollections(
  sync: SyncResponse,
  userKey: SymmetricCryptoKey,
  orgKeys: ReadonlyMap<string, SymmetricCryptoKey>,
  onError: (error: unknown) => void,
): Promise<Map<string, CollectionLabel>> {
  const collections = new Map<string, CollectionLabel>();
  for (const collection of readField<readonly CollectionResponse[]>(sync, 'collections') ?? []) {
    const id = readField<string>(collection, 'id');
    if (id == null) {
      continue;
    }
    const organizationId = readField<string | null>(collection, 'organizationId') ?? null;

    const key = organizationId === null ? userKey : orgKeys.get(organizationId);
    if (key === undefined) {
      onError(new MissingOrgKeyError(organizationId ?? 'inconnue'));
      continue;
    }

    const name = await decryptStringOrNull(readField<string>(collection, 'name'), key, onError);
    if (name === null) {
      continue;
    }
    collections.set(id, {
      name,
      organizationId,
      readOnly: readField<boolean>(collection, 'readOnly') ?? false,
    });
  }
  return collections;
}
