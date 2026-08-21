/**
 * @file Déchiffrement des items du coffre vers des vues exploitables.
 *
 * ## Deux niveaux de vue, délibérément
 *
 * - {@link CipherOverview} — le strict nécessaire pour la liste et le filtrage
 *   par domaine : nom et URIs. C'est ce qui est déchiffré au déverrouillage.
 * - {@link CipherDetails} — identifiant, mot de passe, TOTP, notes :
 *   déchiffrés **à la demande**, quand l'utilisateur ouvre l'item.
 *
 * Ce découpage réduit la latence d'ouverture de la popup et, surtout, limite
 * la quantité de secrets en clair simultanément en mémoire.
 *
 * ## Clé par item
 *
 * Un item peut porter sa propre clé (`cipher.key`), elle-même enveloppée par
 * la clé du coffre. Le cas échéant, c'est elle qui déchiffre les champs. Cette
 * résolution est centralisée dans {@link resolveItemKey} — elle était
 * auparavant dupliquée chez chaque consommateur.
 *
 * ## Tolérance de casse
 *
 * Tous les accès aux champs passent par `readField` : l'API a migré de
 * PascalCase vers camelCase au fil des versions, et un accès direct recrée la
 * première cause de casse d'interopérabilité entre clients tiers.
 *
 * ## Robustesse
 *
 * Un champ illisible produit `null` et une notification `onError` — jamais un
 * rejet qui ferait échouer la liste entière. Voir `decryptStringOrNull`.
 */

import { EncString } from '../crypto/encString.js';
import { decryptBytes, decryptStringOrNull, encryptString } from '../crypto/cryptoService.js';
import { SymmetricCryptoKey } from '../crypto/symmetricCryptoKey.js';
import { type CipherResponse, readField } from '../api/models.js';
import { MissingOrgKeyError, type VaultKeys, keyForCipher } from './keyring.js';

/**
 * Clés acceptées par les fonctions de déchiffrement : la clé du coffre seule
 * (coffre sans organisation), ou le trousseau complet.
 */
export type CipherKeys = SymmetricCryptoKey | VaultKeys;

/**
 * Clé de base d'un item. Pour un item d'organisation sans clé déballée,
 * notifie `onError` et rend `null` — l'item sera présenté illisible, sans
 * faire échouer la liste.
 */
function baseKeyFor(
  cipher: CipherResponse,
  keys: CipherKeys,
  onError: (error: unknown) => void,
): SymmetricCryptoKey | null {
  if (keys instanceof SymmetricCryptoKey) {
    return keys;
  }
  const key = keyForCipher(cipher, keys);
  if (key === null) {
    onError(new MissingOrgKeyError(readField<string>(cipher, 'organizationId') ?? 'inconnue'));
  }
  return key;
}

/** Vue de liste : le nécessaire pour afficher, chercher et filtrer. */
export interface CipherOverview {
  readonly id: string;
  readonly type: number;
  /** Nom déchiffré, ou `null` si absent ou illisible. */
  readonly name: string | null;
  /**
   * Identifiant de connexion déchiffré. Nécessaire dès la liste : c'est lui
   * qui départage plusieurs comptes sur un même site.
   */
  readonly username: string | null;
  /** URIs déchiffrées, pour le filtrage par onglet actif. */
  readonly uris: readonly string[];
  readonly organizationId: string | null;
}

/** Vue détaillée : champs sensibles, déchiffrés à la demande. */
export interface CipherDetails {
  readonly username: string | null;
  readonly password: string | null;
  readonly totp: string | null;
  readonly notes: string | null;
}

/** Concurrence par défaut du déchiffrement de liste. */
const DEFAULT_CONCURRENCY = 8;

/** Forme brute d'une entrée d'URI, dans l'une ou l'autre casse. */
type RawUriEntry = Record<string, unknown>;

/**
 * Résout la clé qui déchiffre les champs d'un item.
 *
 * @param cipher Item brut, tel que renvoyé par la synchronisation.
 * @param userKey Clé de base de l'item : celle du coffre, ou celle de son
 *   organisation.
 * @returns La clé propre à l'item si `cipher.key` est présent, sinon la clé
 *   de base elle-même.
 * @throws {EncStringParseError | MacMismatchError} Si la clé enveloppée est
 *   malformée ou falsifiée — l'item entier est alors illisible.
 */
export async function resolveItemKey(
  cipher: CipherResponse,
  userKey: SymmetricCryptoKey,
): Promise<SymmetricCryptoKey> {
  const wrapped = readField<string>(cipher, 'key');
  if (wrapped == null || wrapped === '') {
    return userKey;
  }
  return new SymmetricCryptoKey(await decryptBytes(EncString.parse(wrapped), userKey));
}

/** Extrait le sous-objet `login` en tolérant les deux casses. */
function readLogin(cipher: CipherResponse): Record<string, unknown> | undefined {
  return readField<Record<string, unknown>>(cipher, 'login') ?? undefined;
}

/**
 * Déchiffre la vue de liste d'un item.
 *
 * Jamais de rejet : un item dont la clé propre est illisible produit une vue
 * aux champs `null`, et l'échec est notifié via `onError`.
 *
 * @param cipher Item brut.
 * @param keys Clé du coffre seule, ou trousseau complet (organisations).
 * @param onError Notification de chaque champ ou clé illisible.
 * @returns Vue de liste, champs illisibles à `null`.
 */
export async function decryptCipherOverview(
  cipher: CipherResponse,
  keys: CipherKeys,
  onError: (error: unknown) => void,
): Promise<CipherOverview> {
  const id = readField<string>(cipher, 'id') ?? '';
  const type = readField<number>(cipher, 'type') ?? 0;
  const organizationId = readField<string | null>(cipher, 'organizationId') ?? null;

  const baseKey = baseKeyFor(cipher, keys, onError);
  if (baseKey === null) {
    return { id, type, name: null, username: null, uris: [], organizationId };
  }

  let itemKey: SymmetricCryptoKey;
  try {
    itemKey = await resolveItemKey(cipher, baseKey);
  } catch (error) {
    onError(error);
    return { id, type, name: null, username: null, uris: [], organizationId };
  }

  const login = readLogin(cipher);
  const rawUris = readField<readonly RawUriEntry[]>(login, 'uris') ?? [];

  const [name, username, ...decryptedUris] = await Promise.all([
    decryptStringOrNull(readField<string>(cipher, 'name'), itemKey, onError),
    decryptStringOrNull(readField<string>(login, 'username'), itemKey, onError),
    ...rawUris.map((entry) =>
      decryptStringOrNull(readField<string>(entry, 'uri'), itemKey, onError),
    ),
  ]);
  const uris = decryptedUris.filter((uri): uri is string => uri !== null);

  return { id, type, name: name ?? null, username: username ?? null, uris, organizationId };
}

/**
 * Déchiffre les champs sensibles d'un item, à la demande.
 *
 * @param cipher Item brut.
 * @param keys Clé du coffre seule, ou trousseau complet (organisations).
 * @param onError Notification de chaque champ ou clé illisible.
 * @returns Champs sensibles, illisibles à `null`.
 */
export async function decryptCipherDetails(
  cipher: CipherResponse,
  keys: CipherKeys,
  onError: (error: unknown) => void,
): Promise<CipherDetails> {
  const baseKey = baseKeyFor(cipher, keys, onError);
  if (baseKey === null) {
    return { username: null, password: null, totp: null, notes: null };
  }

  let itemKey: SymmetricCryptoKey;
  try {
    itemKey = await resolveItemKey(cipher, baseKey);
  } catch (error) {
    onError(error);
    return { username: null, password: null, totp: null, notes: null };
  }

  const login = readLogin(cipher);
  const [username, password, totp, notes] = await Promise.all([
    decryptStringOrNull(readField<string>(login, 'username'), itemKey, onError),
    decryptStringOrNull(readField<string>(login, 'password'), itemKey, onError),
    decryptStringOrNull(readField<string>(login, 'totp'), itemKey, onError),
    decryptStringOrNull(readField<string>(cipher, 'notes'), itemKey, onError),
  ]);

  return { username, password, totp, notes };
}

/**
 * Déchiffre les vues de liste d'une collection d'items.
 *
 * Concurrence bornée : assez de déchiffrements en vol pour amortir les
 * allers-retours WebCrypto (le cache de `CryptoKey` fait le reste), pas au
 * point de saturer le thread au détriment de l'interface. L'ordre d'entrée
 * est préservé.
 *
 * @param ciphers Items bruts, typiquement `sync.ciphers`.
 * @param keys Clé du coffre seule, ou trousseau complet (organisations).
 * @param onError Notification de chaque champ ou clé illisible.
 * @param concurrency Déchiffrements simultanés.
 * @returns Vues de liste, dans l'ordre d'entrée.
 */
export async function decryptCipherList(
  ciphers: readonly CipherResponse[],
  keys: CipherKeys,
  onError: (error: unknown) => void,
  concurrency = DEFAULT_CONCURRENCY,
): Promise<CipherOverview[]> {
  const out = new Array<CipherOverview>(ciphers.length);
  let next = 0;

  // Pool de workers : chacun consomme le prochain index disponible. Pas de
  // section critique — `next++` est atomique en JavaScript mono-thread.
  const workers = Array.from({ length: Math.max(1, Math.min(concurrency, ciphers.length)) }, async () => {
    while (next < ciphers.length) {
      const index = next++;
      out[index] = await decryptCipherOverview(ciphers[index]!, keys, onError);
    }
  });

  await Promise.all(workers);
  return out;
}

/** Champs modifiables d'un item. Chaîne vide = champ effacé. */
export interface CipherEdit {
  readonly name: string;
  readonly username: string;
  readonly password: string;
  readonly totp: string;
  readonly notes: string;
  readonly uris: readonly string[];
}

/** Nombre d'entrées conservées dans l'historique de mots de passe. */
const PASSWORD_HISTORY_LIMIT = 5;

/**
 * Construit le corps complet d'une mise à jour d'item.
 *
 * Le serveur **remplace** les données de l'item par ce qu'il reçoit : le corps
 * est donc reconstruit à partir de l'item existant — les champs non édités
 * (dossier, favori, champs personnalisés, clé d'item…) sont repris tels
 * quels, déjà chiffrés — et seuls les champs édités sont rechiffrés.
 *
 * Le chiffrement utilise exactement le contexte du déchiffrement : clé
 * d'organisation pour un item partagé, puis clé propre à l'item si elle
 * existe (et elle est conservée dans le corps).
 *
 * Si le mot de passe change (`recordPasswordHistory`), l'ancien — encore
 * chiffré, jamais relu en clair ici — est ajouté en tête de l'historique,
 * plafonné à {@link PASSWORD_HISTORY_LIMIT} entrées.
 *
 * @param cipher Item brut existant, tel que renvoyé par la synchronisation.
 * @param edit Nouvelles valeurs en clair.
 * @param keys Clé du coffre seule, ou trousseau complet (organisations).
 * @param recordPasswordHistory Consigner l'ancien mot de passe.
 * @returns Corps prêt pour `ApiClient.updateCipher`.
 * @throws {MissingOrgKeyError} Item d'organisation sans clé déballée.
 */
export async function buildCipherUpdatePayload(
  cipher: CipherResponse,
  edit: CipherEdit,
  keys: CipherKeys,
  recordPasswordHistory: boolean,
): Promise<Record<string, unknown>> {
  let baseKey: SymmetricCryptoKey;
  if (keys instanceof SymmetricCryptoKey) {
    baseKey = keys;
  } else {
    const resolved = keyForCipher(cipher, keys);
    if (resolved === null) {
      throw new MissingOrgKeyError(readField<string>(cipher, 'organizationId') ?? 'inconnue');
    }
    baseKey = resolved;
  }
  const itemKey = await resolveItemKey(cipher, baseKey);

  const enc = async (text: string): Promise<string> =>
    (await encryptString(text, itemKey)).toString();
  const encOrNull = async (text: string): Promise<string | null> =>
    text === '' ? null : enc(text);

  const type = readField<number>(cipher, 'type') ?? 1;
  const login = readLogin(cipher);
  const wrappedItemKey = readField<string>(cipher, 'key');

  const payload: Record<string, unknown> = {
    type,
    organizationId: readField<string | null>(cipher, 'organizationId') ?? null,
    folderId: readField<string | null>(cipher, 'folderId') ?? null,
    favorite: readField<boolean>(cipher, 'favorite') ?? false,
    reprompt: readField<number>(cipher, 'reprompt') ?? 0,
    name: await enc(edit.name),
    notes: await encOrNull(edit.notes),
    // Champs personnalisés : repris tels quels, déjà chiffrés.
    fields: readField<unknown>(cipher, 'fields') ?? [],
  };

  if (wrappedItemKey != null && wrappedItemKey !== '') {
    payload['key'] = wrappedItemKey;
  }

  if (type === 1) {
    const uris = await Promise.all(
      edit.uris
        .map((uri) => uri.trim())
        .filter((uri) => uri !== '')
        .map(async (uri) => ({ uri: await enc(uri), match: null })),
    );
    payload['login'] = {
      username: await encOrNull(edit.username),
      password: await encOrNull(edit.password),
      totp: await encOrNull(edit.totp),
      uris,
    };

    const previousPassword = readField<string>(login, 'password');
    const history = readField<readonly unknown[]>(cipher, 'passwordHistory') ?? [];
    payload['passwordHistory'] =
      recordPasswordHistory && previousPassword != null && previousPassword !== ''
        ? [
            { password: previousPassword, lastUsedDate: new Date().toISOString() },
            ...history,
          ].slice(0, PASSWORD_HISTORY_LIMIT)
        : history;
  }

  return payload;
}
