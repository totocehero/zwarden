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
  /**
   * `true` si l'item embarque au moins une passkey (FIDO2). Détecté par la
   * simple présence des entrées — aucun déchiffrement requis pour la liste.
   */
  readonly hasPasskey: boolean;
  /**
   * `true` si l'item porte un secret TOTP. Comme `hasPasskey`, déduit de la
   * seule présence du champ chiffré : la liste sait donc afficher le bouton
   * sans déchiffrer un secret que l'utilisateur n'a pas demandé.
   */
  readonly hasTotp: boolean;
  /**
   * `true` si l'item exige une nouvelle saisie du mot de passe maître avant
   * de livrer un secret (`reprompt = 1` côté Bitwarden).
   *
   * C'est une protection choisie par l'utilisateur, item par item : elle est
   * portée par l'aperçu — donc disponible sans rien déchiffrer — parce que la
   * garde doit pouvoir se poser **avant** le déchiffrement, pas après.
   */
  readonly reprompt: boolean;
  readonly organizationId: string | null;
  /** Dossier personnel de l'item, ou `null`. Nom à résoudre via `labels.ts`. */
  readonly folderId: string | null;
  /** Collections de l'item. Noms à résoudre via `labels.ts`. */
  readonly collectionIds: readonly string[];
}

/**
 * Cherche l'item que des identifiants saisis mettraient à jour.
 *
 * Le critère est le couple (origine, identifiant de connexion) : c'est ce qui
 * distingue « j'ai changé mon mot de passe » de « j'ai un second compte sur
 * ce site ». Se tromper de sens écraserait un mot de passe encore valide,
 * d'où un rapprochement volontairement strict — l'origine exacte, jamais le
 * domaine (`uriMatch.ts`, et §4 de `docs/EXTENSION.md`).
 *
 * Un identifiant vide ne rapproche rien : le site ne l'annonçait pas, le
 * deviner reviendrait à écraser au hasard.
 *
 * @param items Items déchiffrés du coffre.
 * @param origin Origine de la page où la saisie a eu lieu.
 * @param username Identifiant saisi.
 * @param matchesOrigin Test de correspondance d'origine (`uriMatch.ts`),
 *   injecté pour garder ce module sans dépendance sur la couche URI.
 * @returns L'item à mettre à jour, ou `null` s'il s'agit d'un nouvel item.
 */
export function findSaveCandidate(
  items: readonly CipherOverview[],
  origin: string,
  username: string,
  matchesOrigin: (uris: readonly string[], origin: string) => boolean,
): CipherOverview | null {
  const needle = username.trim().toLowerCase();
  if (needle === '') {
    return null;
  }
  return (
    items.find(
      (item) =>
        item.type === 1 &&
        item.username !== null &&
        item.username.trim().toLowerCase() === needle &&
        matchesOrigin(item.uris, origin),
    ) ?? null
  );
}

/**
 * Construit le test de réutilisation à passer à {@link decryptCipherList}.
 *
 * ## Le problème
 *
 * Modifier un mot de passe déclenchait une resynchronisation, et donc le
 * redéchiffrement de **tous** les aperçus : deux mille items déchiffrés pour un
 * champ changé. Le coût est invisible sur un coffre de démonstration et
 * dominant sur un vrai.
 *
 * ## Pourquoi c'est sûr
 *
 * `revisionDate` est estampillée par le serveur à chaque écriture. À identifiant
 * et date de révision inchangés, le contenu chiffré est le même — donc le clair
 * aussi. On ne réutilise jamais sur la seule foi de l'identifiant : un item
 * modifié depuis un autre appareil porte une date différente et sera
 * redéchiffré.
 *
 * Une réponse d'écriture serait une source plus directe, mais tous les serveurs
 * ne renvoient pas l'item complet — un `collectionIds` absent effacerait
 * silencieusement ses collections de l'affichage. La synchronisation reste donc
 * la référence ; seul le déchiffrement est évité.
 *
 * @param previous Aperçus déjà déchiffrés.
 * @param previousRaw Items chiffrés correspondants, pour lire leur révision.
 */
export function reuseByRevision(
  previous: readonly CipherOverview[],
  previousRaw: ReadonlyMap<string, CipherResponse>,
): (cipher: CipherResponse) => CipherOverview | undefined {
  const parId = new Map(previous.map((item) => [item.id, item]));

  return (cipher) => {
    const id = readField<string>(cipher, 'id');
    if (id == null) {
      return undefined;
    }
    const revision = readField<string>(cipher, 'revisionDate');
    const ancien = previousRaw.get(id);
    if (revision == null || ancien === undefined) {
      return undefined;
    }
    return revision === readField<string>(ancien, 'revisionDate') ? parId.get(id) : undefined;
  };
}

/**
 * Issue d'une capture d'identifiants, une fois le coffre consulté.
 *
 * Trois cas, et le premier est le plus fréquent : une connexion ordinaire, où
 * le coffre sait déjà tout. Le taire est ce qui donne du sens à la pastille —
 * s'allumer à chaque connexion réussie la rendrait insignifiante.
 */
export type ProposalOutcome =
  | { readonly kind: 'aucune' }
  | { readonly kind: 'creation' }
  | { readonly kind: 'miseAJour'; readonly item: CipherOverview };

/**
 * Tranche ce qu'il faut proposer à l'utilisateur.
 *
 * Seule cette fonction porte la règle, et elle est pure : le déchiffrement du
 * mot de passe existant est fait par l'appelant, qui détient les clés. C'est ce
 * découpage qui rend la règle vérifiable — elle vivait auparavant au milieu
 * d'un composant, mêlée à des appels réseau et à de l'état d'interface.
 *
 * @param existing Item rapproché par {@link findSaveCandidate}, ou `null`.
 * @param capturedPassword Mot de passe que l'utilisateur vient de saisir.
 * @param existingPassword Mot de passe déchiffré de l'item rapproché. `null` si
 *   l'item est illisible — on propose alors la mise à jour plutôt que de se
 *   taire : ne rien dire sur la foi d'une comparaison impossible ferait perdre
 *   la saisie.
 */
export function decideProposal(
  existing: CipherOverview | null,
  capturedPassword: string,
  existingPassword: string | null,
): ProposalOutcome {
  if (existing === null) {
    return { kind: 'creation' };
  }
  if (existingPassword === capturedPassword) {
    return { kind: 'aucune' };
  }
  return { kind: 'miseAJour', item: existing };
}

/**
 * Classe les items les plus récemment utilisés en tête.
 *
 * Ce qu'on cherche à reproduire est un réflexe : le compte dont on vient de
 * se servir est celui dont on se resservira. Les items jamais utilisés
 * gardent leur ordre d'origine — remonter au hasard ceux qu'on n'a jamais
 * touchés brouillerait le repère plus qu'il ne l'aiderait.
 *
 * Tri stable et pur : c'est la même liste, réordonnée, sans effet de bord.
 *
 * @param items Items déchiffrés, dans l'ordre du serveur.
 * @param lastUsed Horodatages de dernier usage, par identifiant.
 */
export function sortByLastUsed(
  items: readonly CipherOverview[],
  lastUsed: Readonly<Record<string, number>>,
): readonly CipherOverview[] {
  const used: CipherOverview[] = [];
  const rest: CipherOverview[] = [];
  for (const item of items) {
    (lastUsed[item.id] === undefined ? rest : used).push(item);
  }
  if (used.length === 0) {
    return items;
  }
  used.sort((a, b) => (lastUsed[b.id] ?? 0) - (lastUsed[a.id] ?? 0));
  return [...used, ...rest];
}

/**
 * Passkey déchiffrée pour l'affichage. La clé privée (`keyValue`) n'est
 * volontairement **pas** exposée ici : elle ne sera déchiffrée qu'au moment
 * de signer une cérémonie WebAuthn.
 */
export interface PasskeyView {
  /** Domaine du site (RP ID), par exemple `npmjs.com`. */
  readonly rpId: string | null;
  /** Identifiant de compte associé chez le site. */
  readonly userName: string | null;
}

/** Vue détaillée : champs sensibles, déchiffrés à la demande. */
export interface CipherDetails {
  readonly username: string | null;
  readonly password: string | null;
  readonly totp: string | null;
  readonly notes: string | null;
  /** Passkeys de l'item, métadonnées déchiffrées. */
  readonly passkeys: readonly PasskeyView[];
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
  const login = readLogin(cipher);
  const meta = readCipherMetadata(cipher, login);
  const vide: CipherOverview = { ...meta, name: null, username: null, uris: [] };

  const baseKey = baseKeyFor(cipher, keys, onError);
  if (baseKey === null) {
    return vide;
  }

  let itemKey: SymmetricCryptoKey;
  try {
    itemKey = await resolveItemKey(cipher, baseKey);
  } catch (error) {
    onError(error);
    return vide;
  }

  const rawUris = readField<readonly RawUriEntry[]>(login, 'uris') ?? [];
  const [name, username, ...decryptedUris] = await Promise.all([
    decryptStringOrNull(readField<string>(cipher, 'name'), itemKey, onError),
    decryptStringOrNull(readField<string>(login, 'username'), itemKey, onError),
    ...rawUris.map((entry) =>
      decryptStringOrNull(readField<string>(entry, 'uri'), itemKey, onError),
    ),
  ]);

  return {
    ...meta,
    name: name ?? null,
    username: username ?? null,
    uris: decryptedUris.filter((uri): uri is string => uri !== null),
  };
}

/**
 * Lit tout ce qu'un item dit de lui-même **sans déchiffrement** : identité,
 * appartenance, et les trois indicateurs que la liste doit connaître avant de
 * déchiffrer quoi que ce soit.
 *
 * Extrait pour une raison de fond autant que de longueur : ces champs
 * apparaissaient deux fois dans l'appelant — une fois pour l'item illisible,
 * une fois pour l'item déchiffré — et deux copies d'une liste de onze champs
 * sont deux occasions d'en oublier un. L'ajout de `reprompt` a failli être
 * exactement cet oubli, et un `reprompt` omis dans la branche « illisible »
 * aurait retiré la garde d'un item précisément quand son déchiffrement échoue.
 */
function readCipherMetadata(
  cipher: CipherResponse,
  login: unknown,
): Omit<CipherOverview, 'name' | 'username' | 'uris'> {
  const totpField = readField<string>(login, 'totp');
  return {
    id: readField<string>(cipher, 'id') ?? '',
    type: readField<number>(cipher, 'type') ?? 0,
    hasPasskey: (readField<readonly unknown[]>(login, 'fido2Credentials') ?? []).length > 0,
    hasTotp: totpField != null && totpField !== '',
    // 0 = aucune garde, 1 = redemander le mot de passe maître. Toute autre
    // valeur est traitée comme une garde : se tromper dans ce sens fait
    // redemander un mot de passe, l'autre livre un secret sans garde.
    reprompt: (readField<number>(cipher, 'reprompt') ?? 0) !== 0,
    organizationId: readField<string | null>(cipher, 'organizationId') ?? null,
    folderId: readField<string | null>(cipher, 'folderId') ?? null,
    collectionIds: readField<readonly string[]>(cipher, 'collectionIds') ?? [],
  };
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
    return { username: null, password: null, totp: null, notes: null, passkeys: [] };
  }

  let itemKey: SymmetricCryptoKey;
  try {
    itemKey = await resolveItemKey(cipher, baseKey);
  } catch (error) {
    onError(error);
    return { username: null, password: null, totp: null, notes: null, passkeys: [] };
  }

  const login = readLogin(cipher);
  const rawPasskeys = readField<readonly Record<string, unknown>[]>(login, 'fido2Credentials') ?? [];

  const [username, password, totp, notes, ...passkeys] = await Promise.all([
    decryptStringOrNull(readField<string>(login, 'username'), itemKey, onError),
    decryptStringOrNull(readField<string>(login, 'password'), itemKey, onError),
    decryptStringOrNull(readField<string>(login, 'totp'), itemKey, onError),
    decryptStringOrNull(readField<string>(cipher, 'notes'), itemKey, onError),
    ...rawPasskeys.map(async (entry): Promise<PasskeyView> => {
      const [rpId, userName] = await Promise.all([
        decryptStringOrNull(readField<string>(entry, 'rpId'), itemKey, onError),
        decryptStringOrNull(readField<string>(entry, 'userName'), itemKey, onError),
      ]);
      return { rpId, userName };
    }),
  ]);

  return {
    username: username as string | null,
    password: password as string | null,
    totp: totp as string | null,
    notes: notes as string | null,
    passkeys: passkeys as PasskeyView[],
  };
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
  reuse: (cipher: CipherResponse) => CipherOverview | undefined = () => undefined,
): Promise<CipherOverview[]> {
  const out = new Array<CipherOverview>(ciphers.length);
  let next = 0;

  // Pool de workers : chacun consomme le prochain index disponible. Pas de
  // section critique — `next++` est atomique en JavaScript mono-thread.
  const workers = Array.from({ length: Math.max(1, Math.min(concurrency, ciphers.length)) }, async () => {
    while (next < ciphers.length) {
      const index = next++;
      const cipher = ciphers[index]!;
      out[index] = reuse(cipher) ?? (await decryptCipherOverview(cipher, keys, onError));
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

/**
 * Construit le corps d'une **création** d'item de connexion.
 *
 * Volontairement plus pauvre que la mise à jour : un item né d'une saisie
 * capturée n'a ni dossier, ni organisation, ni champs personnalisés, ni
 * historique. Il est chiffré directement avec la clé du coffre — sans clé
 * d'item propre — ce qui est la forme que l'aller-retour d'interopérabilité
 * valide contre un vrai Vaultwarden (`tests/integration`).
 *
 * @param edit Valeurs en clair. `totp` et `notes` sont acceptés vides.
 * @param userKey Clé du coffre.
 * @returns Corps prêt pour `ApiClient.createCipher`.
 */
export async function buildCipherCreatePayload(
  edit: CipherEdit,
  userKey: SymmetricCryptoKey,
): Promise<Record<string, unknown>> {
  const enc = async (text: string): Promise<string> =>
    (await encryptString(text, userKey)).toString();
  const encOrNull = async (text: string): Promise<string | null> =>
    text === '' ? null : enc(text);

  const uris = await Promise.all(
    edit.uris
      .map((uri) => uri.trim())
      .filter((uri) => uri !== '')
      .map(async (uri) => ({ uri: await enc(uri), match: null })),
  );

  return {
    type: 1,
    name: await enc(edit.name),
    notes: await encOrNull(edit.notes),
    login: {
      username: await encOrNull(edit.username),
      password: await encOrNull(edit.password),
      totp: await encOrNull(edit.totp),
      uris,
    },
    favorite: false,
    folderId: null,
    organizationId: null,
    reprompt: 0,
    fields: [],
    passwordHistory: [],
  };
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
/**
 * Clé de base sous laquelle réécrire un item : celle du coffre, ou celle de son
 * organisation.
 *
 * Contrairement à la lecture — où une clé manquante donne un item illisible et
 * un `onError` — l'écriture **lève**. Réécrire un item d'organisation avec la
 * clé du coffre produirait un item que plus personne, propriétaire compris, ne
 * saurait déchiffrer : mieux vaut refuser d'écrire.
 */
function requireBaseKey(cipher: CipherResponse, keys: CipherKeys): SymmetricCryptoKey {
  if (keys instanceof SymmetricCryptoKey) {
    return keys;
  }
  const resolved = keyForCipher(cipher, keys);
  if (resolved === null) {
    throw new MissingOrgKeyError(readField<string>(cipher, 'organizationId') ?? 'inconnue');
  }
  return resolved;
}

export async function buildCipherUpdatePayload(
  cipher: CipherResponse,
  edit: CipherEdit,
  keys: CipherKeys,
  recordPasswordHistory: boolean,
): Promise<Record<string, unknown>> {
  const itemKey = await resolveItemKey(cipher, requireBaseKey(cipher, keys));

  const enc = async (text: string): Promise<string> =>
    (await encryptString(text, itemKey)).toString();
  const encOrNull = async (text: string): Promise<string | null> =>
    text === '' ? null : enc(text);

  const type = readField<number>(cipher, 'type') ?? 1;
  const login = readLogin(cipher);
  const wrappedItemKey = readField<string>(cipher, 'key');

  // Champs repris de l'item existant, jamais recalculés : une mise à jour
  // remplace l'item entier côté serveur, et tout champ omis est perdu.
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
    payload['login'] = await buildLoginSection(edit, login, enc, encOrNull);
    payload['passwordHistory'] = buildPasswordHistory(cipher, login, recordPasswordHistory);
  }

  return payload;
}

/** Chiffreur de champ, tel que fourni par l'appelant qui détient la clé d'item. */
type FieldEncryptor = (text: string) => Promise<string>;

/** Section `login` d'une mise à jour : champs édités, passkeys préservées. */
async function buildLoginSection(
  edit: CipherEdit,
  login: unknown,
  enc: FieldEncryptor,
  encOrNull: (text: string) => Promise<string | null>,
): Promise<Record<string, unknown>> {
  const uris = await Promise.all(
    edit.uris
      .map((uri) => uri.trim())
      .filter((uri) => uri !== '')
      .map(async (uri) => ({ uri: await enc(uri), match: null })),
  );

  return {
    username: await encOrNull(edit.username),
    password: await encOrNull(edit.password),
    totp: await encOrNull(edit.totp),
    uris,
    // Les passkeys ne sont pas éditables ici : reprises telles quelles, déjà
    // chiffrées. Les omettre les effacerait du serveur.
    fido2Credentials: readField<unknown>(login, 'fido2Credentials') ?? null,
  };
}

/**
 * Historique de mots de passe, l'ancien en tête.
 *
 * L'ancien mot de passe est déjà chiffré — il est repris tel quel depuis l'item
 * existant, jamais rechiffré : le rechiffrer avec une autre clé d'item le
 * rendrait illisible, et c'est précisément l'historique qu'on consulte quand on
 * a perdu l'accès à un compte.
 */
function buildPasswordHistory(
  cipher: CipherResponse,
  login: unknown,
  record: boolean,
): readonly unknown[] {
  const history = readField<readonly unknown[]>(cipher, 'passwordHistory') ?? [];
  const previousPassword = readField<string>(login, 'password');
  if (!record || previousPassword == null || previousPassword === '') {
    return history;
  }
  return [
    { password: previousPassword, lastUsedDate: new Date().toISOString() },
    ...history,
  ].slice(0, PASSWORD_HISTORY_LIMIT);
}
