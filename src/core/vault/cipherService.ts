/**
 * @file Decrypting vault items into usable views.
 *
 * ## Two levels of view, deliberately
 *
 * - {@link CipherOverview} — the bare minimum for the list and for filtering by
 *   domain: name and URIs. That is what gets decrypted at unlock.
 * - {@link CipherDetails} — username, password, TOTP, notes: decrypted **on
 *   demand**, when the user opens the item.
 *
 * This split cuts the popup's opening latency and, above all, limits how many
 * cleartext secrets sit in memory at once.
 *
 * ## Per-item key
 *
 * An item may carry its own key (`cipher.key`), itself wrapped by the vault key.
 * Where it does, that is what decrypts the fields. This resolution is
 * centralised in {@link resolveItemKey} — it used to be duplicated in every
 * consumer.
 *
 * ## Case tolerance
 *
 * Every field access goes through `readField`: the API migrated from PascalCase
 * to camelCase over successive versions, and direct access recreates the leading
 * cause of interoperability breakage for third-party clients.
 *
 * ## Robustness
 *
 * An unreadable field yields `null` and an `onError` notification — never a
 * rejection that would fail the whole list. See `decryptStringOrNull`.
 */

import { EncString } from '../crypto/encString.js';
import { decryptBytes, decryptStringOrNull, encryptString } from '../crypto/cryptoService.js';
import { SymmetricCryptoKey } from '../crypto/symmetricCryptoKey.js';
import { type CipherResponse, readField } from '../api/models.js';
import {
  BRAND_LABELS,
  CARD_FIELDS,
  type CardEdit,
  type CardView,
  detectBrand,
  EMPTY_CARD,
  maskNumber,
} from './card.js';
import type { PasskeyCredential } from './passkey.js';
import {
  EMPTY_IDENTITY,
  fullName,
  type IdentityEdit,
  IDENTITY_FIELDS,
  type IdentityView,
} from './identity.js';
import { MissingOrgKeyError, type VaultKeys, keyForCipher } from './keyring.js';

/**
 * The keys the decryption functions accept: the vault key alone (a vault with no
 * organisation), or the full keyring.
 */
export type CipherKeys = SymmetricCryptoKey | VaultKeys;

/**
 * An item's base key. For an organisation item whose key was not unwrapped, it
 * notifies `onError` and returns `null` — the item is shown as unreadable
 * without failing the list.
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
    onError(new MissingOrgKeyError(readField<string>(cipher, 'organizationId') ?? 'unknown'));
  }
  return key;
}

/** List view: what it takes to display, search and filter. */
export interface CipherOverview {
  readonly id: string;
  readonly type: number;
  /** Decrypted name, or `null` if absent or unreadable. */
  readonly name: string | null;
  /**
   * Decrypted login username. Needed as early as the list: it is what tells
   * several accounts on the same site apart.
   */
  readonly username: string | null;
  /** Decrypted URIs, for filtering by active tab. */
  readonly uris: readonly string[];
  /**
   * What identifies the item in the list when a username does not: the masked
   * card, the full name of an identity.
   *
   * It exists because a vault holding three cards shows three identical rows
   * otherwise — Bitwarden's own list is unusable for exactly that reason. It is
   * also what the search matches on, so typing the last four digits finds the
   * card.
   *
   * **The full number never reaches here.** It is decrypted, reduced to its last
   * four digits, and dropped; what the list holds in memory for the whole
   * session is `•••• 4242`, not a number that could be charged.
   */
  readonly subtitle: string | null;
  /**
   * `true` if the item carries at least one passkey (FIDO2). Detected from the
   * mere presence of the entries — no decryption needed for the list.
   */
  readonly hasPasskey: boolean;
  /**
   * `true` if the item carries a TOTP secret. Like `hasPasskey`, inferred from
   * the mere presence of the encrypted field: the list can therefore show the
   * button without decrypting a secret nobody asked for.
   */
  readonly hasTotp: boolean;
  /**
   * `true` if the item demands the master password be entered again before any
   * secret is handed over (`reprompt = 1` on Bitwarden's side).
   *
   * This is a protection the user chooses, item by item: it is carried by the
   * overview — hence available without decrypting anything — because the guard
   * must be able to stand **before** decryption, not after.
   */
  readonly reprompt: boolean;
  readonly organizationId: string | null;
  /** The item's personal folder, or `null`. Name resolved through `labels.ts`. */
  readonly folderId: string | null;
  /** The item's collections. Names resolved through `labels.ts`. */
  readonly collectionIds: readonly string[];
}

/**
 * Finds the item that entered credentials would update.
 *
 * The criterion is the (origin, username) pair: that is what tells "I changed my
 * password" from "I have a second account on this site". Getting it wrong in the
 * second direction would overwrite a still-valid password, hence a deliberately
 * strict match — the exact origin, never the domain (`uriMatch.ts`, and §4 of
 * `docs/EXTENSION.md`).
 *
 * An empty username matches nothing: the site did not announce it, and guessing
 * would amount to overwriting at random.
 *
 * @param items Decrypted vault items.
 * @param origin Origin of the page where the entry happened.
 * @param username Username entered.
 * @param matchesOrigin Origin-matching test (`uriMatch.ts`), injected to keep
 *   this module free of any dependency on the URI layer.
 * @returns The item to update, or `null` if this is a new item.
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
 * Builds the reuse test to hand to {@link decryptCipherList}.
 *
 * ## The problem
 *
 * Changing one password triggered a resync, and therefore the re-decryption of
 * **every** overview: two thousand items decrypted for one changed field. The
 * cost is invisible on a demo vault and dominant on a real one.
 *
 * ## Why it is safe
 *
 * `revisionDate` is stamped by the server on every write. With the identifier
 * and the revision date unchanged, the encrypted content is the same — so the
 * plaintext is too. We never reuse on the identifier alone: an item edited from
 * another device carries a different date and gets re-decrypted.
 *
 * A write response would be a more direct source, but not every server returns
 * the complete item — a missing `collectionIds` would silently erase its
 * collections from the display. The sync therefore stays the reference; only the
 * decryption is skipped.
 *
 * @param previous Overviews already decrypted.
 * @param previousRaw The matching encrypted items, to read their revision.
 */
export function reuseByRevision(
  previous: readonly CipherOverview[],
  previousRaw: ReadonlyMap<string, CipherResponse>,
): (cipher: CipherResponse) => CipherOverview | undefined {
  const byId = new Map(previous.map((item) => [item.id, item]));

  return (cipher) => {
    const id = readField<string>(cipher, 'id');
    if (id == null) {
      return undefined;
    }
    const revision = readField<string>(cipher, 'revisionDate');
    const previousCipher = previousRaw.get(id);
    if (revision == null || previousCipher === undefined) {
      return undefined;
    }
    return revision === readField<string>(previousCipher, 'revisionDate') ? byId.get(id) : undefined;
  };
}

/**
 * The outcome of a credentials capture, once the vault has been consulted.
 *
 * Three cases, and the first is the most frequent: an ordinary sign-in, where
 * the vault already knows everything. Staying quiet about it is what gives the
 * badge meaning — lighting up on every successful sign-in would make it
 * meaningless.
 */
export type ProposalOutcome =
  | { readonly kind: 'none' }
  | { readonly kind: 'create' }
  | { readonly kind: 'update'; readonly item: CipherOverview };

/**
 * Decides what to offer the user.
 *
 * This function alone carries the rule, and it is pure: decrypting the existing
 * password is the caller's job, since the caller holds the keys. That split is
 * what makes the rule testable — it used to live in the middle of a component,
 * entangled with network calls and UI state.
 *
 * @param existing Item matched by {@link findSaveCandidate}, or `null`.
 * @param capturedPassword Password the user has just entered.
 * @param existingPassword Decrypted password of the matched item. `null` if the
 *   item is unreadable — we then offer the update rather than stay quiet: saying
 *   nothing on the strength of an impossible comparison would lose the entry.
 */
export function decideProposal(
  existing: CipherOverview | null,
  capturedPassword: string,
  existingPassword: string | null,
): ProposalOutcome {
  if (existing === null) {
    return { kind: 'create' };
  }
  if (existingPassword === capturedPassword) {
    return { kind: 'none' };
  }
  return { kind: 'update', item: existing };
}

/**
 * Sorts the most recently used items to the top.
 *
 * What this reproduces is a reflex: the account you have just used is the one
 * you will use again. Items never used keep their original order — floating up
 * ones you have never touched at random would blur the landmark more than help
 * it.
 *
 * Stable and pure: the same list, reordered, with no side effect.
 *
 * @param items Decrypted items, in the server's order.
 * @param lastUsed Last-use timestamps, by identifier.
 */
/**
 * The same order, applied to items **not yet decrypted**.
 *
 * The use log is keyed by identifier, and an identifier is not encrypted — so
 * the order the rows will appear in is known before a single field is read.
 * That is what lets the popup decrypt the first screenful first, instead of
 * decrypting everything and only then discovering which twenty were on top.
 *
 * @param ciphers Raw items, typically `sync.ciphers`.
 * @param lastUsed Use log, `{ [id]: timestamp }`.
 * @returns The same items, most recently used first.
 */
export function sortCiphersByLastUsed(
  ciphers: readonly CipherResponse[],
  lastUsed: Readonly<Record<string, number>>,
): readonly CipherResponse[] {
  return orderByLastUsed(ciphers, (cipher) => readField<string>(cipher, 'id') ?? '', lastUsed);
}

/**
 * The ordering rule itself, over anything that can name its own identifier.
 *
 * One rule, two callers: the decrypted list and the raw one must agree, and the
 * only way to guarantee that is for the comparison to exist once.
 */
function orderByLastUsed<T>(
  items: readonly T[],
  idOf: (item: T) => string,
  lastUsed: Readonly<Record<string, number>>,
): readonly T[] {
  const used: T[] = [];
  const rest: T[] = [];
  for (const item of items) {
    (lastUsed[idOf(item)] === undefined ? rest : used).push(item);
  }
  if (used.length === 0) {
    return items;
  }
  used.sort((a, b) => (lastUsed[idOf(b)] ?? 0) - (lastUsed[idOf(a)] ?? 0));
  return [...used, ...rest];
}

/**
 * A passkey decrypted for display. The private key (`keyValue`) is deliberately
 * **not** exposed here: it will only be decrypted at the moment of signing a
 * WebAuthn ceremony.
 */
export interface PasskeyView {
  /**
   * The credential's own identifier, base64url.
   *
   * Metadata, not a secret — the site names it in `allowCredentials`. Carried
   * here so a ceremony can be matched to an item **without** decrypting any
   * private key: only the credential actually chosen has its key read.
   */
  readonly credentialId: string | null;
  /** The site's domain (RP ID), for example `npmjs.com`. */
  readonly rpId: string | null;
  /** The associated account identifier at the site. */
  readonly userName: string | null;
}

/** Detailed view: sensitive fields, decrypted on demand. */
export interface CipherDetails {
  readonly username: string | null;
  readonly password: string | null;
  readonly totp: string | null;
  readonly notes: string | null;
  /** The item's passkeys, metadata decrypted. */
  readonly passkeys: readonly PasskeyView[];
  /** The card, for a type 3 item — `null` for every other type. */
  readonly card: CardView | null;
  /** The identity, for a type 4 item — `null` for every other type. */
  readonly identity: IdentityView | null;
}

/** An unreadable or type-less detail view. */
const EMPTY_DETAILS: CipherDetails = Object.freeze({
  username: null,
  password: null,
  totp: null,
  notes: null,
  passkeys: [],
  card: null,
  identity: null,
});

/** Default concurrency for list decryption. */
const DEFAULT_CONCURRENCY = 8;

/** Raw shape of a URI entry, in either casing. */
type RawUriEntry = Record<string, unknown>;

/**
 * Resolves the key that decrypts an item's fields.
 *
 * @param cipher Raw item, as returned by the sync.
 * @param userKey The item's base key: the vault's, or its organisation's.
 * @returns The item's own key if `cipher.key` is present, otherwise the base key
 *   itself.
 * @throws {EncStringParseError | MacMismatchError} If the wrapped key is
 *   malformed or forged — the whole item is then unreadable.
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

/**
 * Erases an item's own key once it has served.
 *
 * {@link resolveItemKey} allocates one per item per decryption when the item
 * carries a `key`; without this they accumulated, plaintext, until the
 * collector came round. The base key is the caller's and is left alone.
 */
function releaseItemKey(itemKey: SymmetricCryptoKey, baseKey: SymmetricCryptoKey): void {
  if (itemKey !== baseKey) {
    itemKey.destroy();
  }
}

/** Extracts the `login` sub-object, tolerating either casing. */
function readLogin(cipher: CipherResponse): Record<string, unknown> | undefined {
  return readField<Record<string, unknown>>(cipher, 'login') ?? undefined;
}

/**
 * Counts the items of each type, **without decrypting anything**.
 *
 * An item's `type` travels in clear — it has to, since the server routes on it —
 * so this answers "how many cards does this vault hold" the moment the cached
 * sync is read, tens of milliseconds before the first name is decrypted.
 *
 * That is what lets the type filter appear with real counts while the list is
 * still being decrypted, instead of arriving after it and shifting the layout
 * under a cursor already moving.
 *
 * @param ciphers Raw items, typically `sync.ciphers`.
 * @returns Item count per type. Types absent from the vault are absent here.
 */
export function countTypes(ciphers: readonly CipherResponse[]): ReadonlyMap<number, number> {
  const counts = new Map<number, number>();
  for (const cipher of ciphers) {
    const type = readField<number>(cipher, 'type') ?? 0;
    counts.set(type, (counts.get(type) ?? 0) + 1);
  }
  return counts;
}

/**
 * Decrypts an item's list view.
 *
 * Never rejects: an item whose own key is unreadable yields a view with `null`
 * fields, and the failure is reported through `onError`.
 *
 * @param cipher Raw item.
 * @param keys The vault key alone, or the full keyring (organisations).
 * @param onError Notification for each unreadable field or key.
 * @returns List view, unreadable fields set to `null`.
 */
export async function decryptCipherOverview(
  cipher: CipherResponse,
  keys: CipherKeys,
  onError: (error: unknown) => void,
): Promise<CipherOverview> {
  const login = readLogin(cipher);
  const meta = readCipherMetadata(cipher, login);
  const empty: CipherOverview = {
    ...meta,
    name: null,
    username: null,
    uris: [],
    subtitle: null,
  };

  const baseKey = baseKeyFor(cipher, keys, onError);
  if (baseKey === null) {
    return empty;
  }

  let itemKey: SymmetricCryptoKey;
  try {
    itemKey = await resolveItemKey(cipher, baseKey);
  } catch (error) {
    onError(error);
    return empty;
  }

  const rawUris = readField<readonly RawUriEntry[]>(login, 'uris') ?? [];
  let name: string | null, username: string | null, subtitle: string | null;
  let decryptedUris: (string | null)[];
  try {
    [name, username, subtitle, ...decryptedUris] = await Promise.all([
      decryptStringOrNull(readField<string>(cipher, 'name'), itemKey, onError),
      decryptStringOrNull(readField<string>(login, 'username'), itemKey, onError),
      decryptSubtitle(cipher, meta.type, itemKey, onError),
      ...rawUris.map((entry) =>
        decryptStringOrNull(readField<string>(entry, 'uri'), itemKey, onError),
      ),
    ]);
  } finally {
    releaseItemKey(itemKey, baseKey);
  }

  return {
    ...meta,
    name: name ?? null,
    username: username ?? null,
    subtitle: subtitle ?? null,
    uris: decryptedUris.filter((uri): uri is string => uri !== null),
  };
}

/**
 * Builds the list subtitle of a card or an identity.
 *
 * Two fields at most are decrypted, and for a card the number is reduced to its
 * last four digits **before returning** — the cleartext number exists for the
 * duration of this function and nowhere else. That is the whole point: the list
 * gains what it needs to tell three cards apart without the vault holding three
 * chargeable numbers in memory for as long as the popup is open.
 *
 * @returns The subtitle, or `null` for a type that has no use for one.
 */
async function decryptSubtitle(
  cipher: CipherResponse,
  type: number,
  itemKey: SymmetricCryptoKey,
  onError: (error: unknown) => void,
): Promise<string | null> {
  if (type === 3) {
    const card = readField<Record<string, unknown>>(cipher, 'card');
    const number = await decryptStringOrNull(readField<string>(card, 'number'), itemKey, onError);
    if (number === null || number === '') {
      return null;
    }
    const brand = detectBrand(number);
    const masked = maskNumber(number);
    return brand === null ? masked : `${BRAND_LABELS[brand]} ${masked}`;
  }
  if (type === 4) {
    const identity = readField<Record<string, unknown>>(cipher, 'identity');
    const [first, last] = await Promise.all([
      decryptStringOrNull(readField<string>(identity, 'firstName'), itemKey, onError),
      decryptStringOrNull(readField<string>(identity, 'lastName'), itemKey, onError),
    ]);
    const name = fullName({ ...EMPTY_IDENTITY, firstName: first, lastName: last });
    return name === '' ? null : name;
  }
  return null;
}

/**
 * Reads everything an item says about itself **without decryption**: identity,
 * membership, and the three flags the list must know before decrypting
 * anything.
 *
 * Extracted for a reason of substance as much as of length: these fields
 * appeared twice in the caller — once for the unreadable item, once for the
 * decrypted one — and two copies of an eleven-field list are two chances to
 * forget one. Adding `reprompt` came within a hair of being exactly that
 * oversight, and a `reprompt` missing from the "unreadable" branch would have
 * stripped an item's guard precisely when its decryption fails.
 */
function readCipherMetadata(
  cipher: CipherResponse,
  login: unknown,
): Omit<CipherOverview, 'name' | 'username' | 'uris' | 'subtitle'> {
  const totpField = readField<string>(login, 'totp');
  return {
    id: readField<string>(cipher, 'id') ?? '',
    type: readField<number>(cipher, 'type') ?? 0,
    hasPasskey: (readField<readonly unknown[]>(login, 'fido2Credentials') ?? []).length > 0,
    hasTotp: totpField != null && totpField !== '',
    // 0 = no guard, 1 = ask for the master password again. Any other value is
    // treated as a guard: erring this way asks for a password, erring the other
    // hands over a secret with no guard at all.
    reprompt: (readField<number>(cipher, 'reprompt') ?? 0) !== 0,
    organizationId: readField<string | null>(cipher, 'organizationId') ?? null,
    folderId: readField<string | null>(cipher, 'folderId') ?? null,
    collectionIds: readField<readonly string[]>(cipher, 'collectionIds') ?? [],
  };
}

/**
 * Decrypts an item's sensitive fields, on demand.
 *
 * @param cipher Raw item.
 * @param keys The vault key alone, or the full keyring (organisations).
 * @param onError Notification for each unreadable field or key.
 * @returns Sensitive fields, unreadable ones set to `null`.
 */
export async function decryptCipherDetails(
  cipher: CipherResponse,
  keys: CipherKeys,
  onError: (error: unknown) => void,
): Promise<CipherDetails> {
  const baseKey = baseKeyFor(cipher, keys, onError);
  if (baseKey === null) {
    return EMPTY_DETAILS;
  }

  let itemKey: SymmetricCryptoKey;
  try {
    itemKey = await resolveItemKey(cipher, baseKey);
  } catch (error) {
    onError(error);
    return EMPTY_DETAILS;
  }

  const type = readField<number>(cipher, 'type') ?? 1;
  const login = readLogin(cipher);
  const rawPasskeys = readField<readonly Record<string, unknown>[]>(login, 'fido2Credentials') ?? [];

  const [username, password, totp, notes, ...passkeys] = await Promise.all([
    decryptStringOrNull(readField<string>(login, 'username'), itemKey, onError),
    decryptStringOrNull(readField<string>(login, 'password'), itemKey, onError),
    decryptStringOrNull(readField<string>(login, 'totp'), itemKey, onError),
    decryptStringOrNull(readField<string>(cipher, 'notes'), itemKey, onError),
    ...rawPasskeys.map(async (entry): Promise<PasskeyView> => {
      const [credentialId, rpId, userName] = await Promise.all([
        decryptStringOrNull(readField<string>(entry, 'credentialId'), itemKey, onError),
        decryptStringOrNull(readField<string>(entry, 'rpId'), itemKey, onError),
        decryptStringOrNull(readField<string>(entry, 'userName'), itemKey, onError),
      ]);
      return { credentialId, rpId, userName };
    }),
  ]);

  let card: CardView | null, identity: IdentityView | null;
  try {
    [card, identity] = await Promise.all([
      type === 3 ? decryptSection(cipher, 'card', CARD_FIELDS, EMPTY_CARD, itemKey, onError) : null,
      type === 4
        ? decryptSection(cipher, 'identity', IDENTITY_FIELDS, EMPTY_IDENTITY, itemKey, onError)
        : null,
    ]);
  } finally {
    releaseItemKey(itemKey, baseKey);
  }

  return {
    username: username as string | null,
    password: password as string | null,
    totp: totp as string | null,
    notes: notes as string | null,
    passkeys: passkeys as PasskeyView[],
    card,
    identity,
  };
}

/**
 * Decrypts every field of a typed section in one pass.
 *
 * The field list is imported from the module that owns the type, not repeated
 * here: a field added to `CardView` and forgotten in the decryption would be a
 * field the user fills in, saves, and never sees again.
 *
 * @param section Name of the sub-object, `card` or `identity`.
 * @param fields The section's fields, from its own module.
 * @param empty The all-`null` value, returned when the section is absent.
 * @returns The section, unreadable fields set to `null`.
 */
async function decryptSection<F extends string, V>(
  cipher: CipherResponse,
  section: string,
  fields: readonly F[],
  empty: V,
  itemKey: SymmetricCryptoKey,
  onError: (error: unknown) => void,
): Promise<V> {
  const raw = readField<Record<string, unknown>>(cipher, section);
  if (raw == null) {
    return empty;
  }
  const values = await Promise.all(
    fields.map((field) => decryptStringOrNull(readField<string>(raw, field), itemKey, onError)),
  );
  return Object.fromEntries(fields.map((field, index) => [field, values[index] ?? null])) as V;
}

/**
 * Decrypts an item's passkeys **including their private keys**.
 *
 * Kept apart from {@link decryptCipherDetails} on purpose. That function is
 * called to show an item; this one is called to *sign* with it, and the
 * difference is a private key in memory. `PasskeyView` deliberately omits
 * `keyValue`, and this is the only place that does not.
 *
 * The caller is responsible for having satisfied the item's guard first: a
 * passkey on a `reprompt` item must not be usable without the master password,
 * and nothing in this layer can know whether that happened.
 *
 * @param cipher Raw item.
 * @param keys The vault key alone, or the full keyring.
 * @param onError Notification for each unreadable field.
 * @returns One entry per passkey; entries whose private key is unreadable are
 *   dropped, since a credential that cannot sign is not a credential.
 */
export async function decryptPasskeys(
  cipher: CipherResponse,
  keys: CipherKeys,
  onError: (error: unknown) => void,
): Promise<readonly PasskeyCredential[]> {
  const baseKey = baseKeyFor(cipher, keys, onError);
  if (baseKey === null) {
    return [];
  }

  let itemKey: SymmetricCryptoKey;
  try {
    itemKey = await resolveItemKey(cipher, baseKey);
  } catch (error) {
    onError(error);
    return [];
  }

  const login = readLogin(cipher);
  const raw = readField<readonly Record<string, unknown>[]>(login, 'fido2Credentials') ?? [];

  const decrypted = await Promise.all(
    raw.map(async (entry) => {
      const [credentialId, rpId, userHandle, keyValue, counter] = await Promise.all([
        decryptStringOrNull(readField<string>(entry, 'credentialId'), itemKey, onError),
        decryptStringOrNull(readField<string>(entry, 'rpId'), itemKey, onError),
        decryptStringOrNull(readField<string>(entry, 'userHandle'), itemKey, onError),
        decryptStringOrNull(readField<string>(entry, 'keyValue'), itemKey, onError),
        decryptStringOrNull(readField<string>(entry, 'counter'), itemKey, onError),
      ]);
      if (credentialId === null || rpId === null || keyValue === null) {
        return null;
      }
      return {
        credentialId,
        rpId,
        userHandle,
        keyValue,
        // Stored as an encrypted string; absent or unreadable means zero, which
        // is what a synced passkey reports anyway.
        counter: Number.parseInt(counter ?? '0', 10) || 0,
      } satisfies PasskeyCredential;
    }),
  );

  releaseItemKey(itemKey, baseKey);
  return decrypted.filter((entry): entry is PasskeyCredential => entry !== null);
}

/**
 * Decrypts the list views of a collection of items.
 *
 * Bounded concurrency: enough decryptions in flight to amortise the WebCrypto
 * round trips (the `CryptoKey` cache handles the rest), not so many as to
 * saturate the thread at the UI's expense. Input order is preserved.
 *
 * @param ciphers Raw items, typically `sync.ciphers`.
 * @param keys The vault key alone, or the full keyring (organisations).
 * @param onError Notification for each unreadable field or key.
 * @param concurrency Simultaneous decryptions.
 * @param reuse Optional test that returns an already-decrypted overview.
 * @returns List views, in input order.
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

  // A worker pool: each consumes the next available index. No critical section —
  // `next++` is atomic in single-threaded JavaScript.
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

/** An item's editable fields. Empty string = field cleared. */
export interface CipherEdit {
  readonly name: string;
  readonly username: string;
  readonly password: string;
  readonly totp: string;
  readonly notes: string;
  readonly uris: readonly string[];
  /**
   * The type to create. Only read on creation — an update never changes an
   * item's type, which would orphan the section it already carries.
   */
  readonly type?: number;
  /** The card's values, for a type 3 item. */
  readonly card?: CardEdit;
  /** The identity's values, for a type 4 item. */
  readonly identity?: IdentityEdit;
  /**
   * A passkey to append to this item's login section.
   *
   * Goes through the same write path as everything else rather than getting one
   * of its own: that path is where the carry-over of every field the editor does
   * not know about lives, and a second path would be a second chance to lose
   * them.
   */
  readonly addPasskey?: NewPasskey;
}

/** A passkey just created, in the clear, on its way into the vault. */
export interface NewPasskey {
  readonly credentialId: string;
  readonly rpId: string;
  readonly rpName: string;
  /** The account's opaque handle at the site, base64url. */
  readonly userHandle: string;
  readonly userName: string;
  readonly userDisplayName: string;
  /** The ECDSA P-256 private key, PKCS#8, base64url. */
  readonly keyValue: string;
}

/**
 * Encrypts a new passkey into the shape the API stores.
 *
 * Every field is an `EncString` except the creation date — including the
 * counter and the `discoverable` flag, which the server keeps encrypted like
 * the rest despite being neither secret nor interesting. Diverging would make
 * the credential unreadable by the official clients, which is the one thing a
 * passkey written here must not be.
 */
async function buildPasskeySection(
  passkey: NewPasskey,
  enc: FieldEncryptor,
): Promise<Record<string, unknown>> {
  const [
    credentialId,
    keyType,
    keyAlgorithm,
    keyCurve,
    keyValue,
    rpId,
    rpName,
    userHandle,
    userName,
    userDisplayName,
    counter,
    discoverable,
  ] = await Promise.all([
    enc(passkey.credentialId),
    enc('public-key'),
    enc('ECDSA'),
    enc('P-256'),
    enc(passkey.keyValue),
    enc(passkey.rpId),
    enc(passkey.rpName),
    enc(passkey.userHandle),
    enc(passkey.userName),
    enc(passkey.userDisplayName),
    enc('0'),
    enc('true'),
  ]);

  return {
    credentialId,
    keyType,
    keyAlgorithm,
    keyCurve,
    keyValue,
    rpId,
    rpName,
    userHandle,
    userName,
    userDisplayName,
    counter,
    discoverable,
    creationDate: new Date().toISOString(),
  };
}

/**
 * Everything the stored section holds that the editor does not know about.
 *
 * A section is rewritten whole, so a field this version has never heard of —
 * one a later Bitwarden adds, one an import brought in — vanishes the first time
 * the item is edited here. Carrying it over costs a spread and closes the
 * failure by construction rather than by vigilance.
 *
 * The carried-over values are already encrypted under this item's key: they pass
 * through untouched, exactly as passkeys and custom fields do.
 */
function unknownFieldsOf(stored: unknown, known: readonly string[]): Record<string, unknown> {
  if (stored == null || typeof stored !== 'object') {
    return {};
  }
  // Compared without regard to case: the API migrated from PascalCase, old
  // caches still hold it, and a `Number` carried over beside a `number` written
  // back would send the server the same field twice.
  const seen = new Set(known.map((field) => field.toLowerCase()));
  const rest: Record<string, unknown> = {};
  for (const [field, value] of Object.entries(stored as Record<string, unknown>)) {
    if (!seen.has(field.toLowerCase())) {
      rest[field] = value;
    }
  }
  return rest;
}

/** Encrypts a whole typed section, preserving what it does not know about. */
async function buildTypedSection<F extends string>(
  values: Readonly<Record<F, string>>,
  fields: readonly F[],
  stored: unknown,
  encOrNull: (text: string) => Promise<string | null>,
): Promise<Record<string, unknown>> {
  const encrypted = await Promise.all(fields.map((field) => encOrNull(values[field].trim())));
  return {
    ...unknownFieldsOf(stored, fields),
    ...Object.fromEntries(fields.map((field, index) => [field, encrypted[index] ?? null])),
  };
}

/**
 * The section an edit supplies for this type, encrypted — or `null` if the
 * editor has nothing to say about it.
 *
 * `null` is not an absence of data: it means "leave what is already there
 * alone", and the update path then carries the stored section over untouched.
 */
async function buildEditedSection(
  type: number,
  edit: CipherEdit,
  stored: CipherResponse | null,
  encOrNull: (text: string) => Promise<string | null>,
): Promise<readonly [string, Record<string, unknown>] | null> {
  if (type === 3 && edit.card !== undefined) {
    const previous = stored === null ? null : readField<unknown>(stored, 'card');
    return ['card', await buildTypedSection(edit.card, CARD_FIELDS, previous, encOrNull)];
  }
  if (type === 4 && edit.identity !== undefined) {
    const previous = stored === null ? null : readField<unknown>(stored, 'identity');
    return [
      'identity',
      await buildTypedSection(edit.identity, IDENTITY_FIELDS, previous, encOrNull),
    ];
  }
  return null;
}

/**
 * Builds the body of a login item **creation**.
 *
 * Deliberately poorer than an update: an item born of a captured entry has no
 * folder, no organisation, no custom fields and no history. It is encrypted
 * directly with the vault key — with no item key of its own — which is the shape
 * the interoperability round trip validates against a real Vaultwarden
 * (`tests/integration`).
 *
 * @param edit Cleartext values. `totp` and `notes` are accepted empty.
 * @param userKey The vault key.
 * @returns A body ready for `ApiClient.createCipher`.
 */
export async function buildCipherCreatePayload(
  edit: CipherEdit,
  userKey: SymmetricCryptoKey,
): Promise<Record<string, unknown>> {
  const enc = async (text: string): Promise<string> =>
    (await encryptString(text, userKey)).toString();
  const encOrNull = async (text: string): Promise<string | null> =>
    text === '' ? null : enc(text);

  const type = edit.type ?? 1;
  const payload: Record<string, unknown> = {
    type,
    name: await enc(edit.name),
    notes: await encOrNull(edit.notes),
    favorite: false,
    folderId: null,
    organizationId: null,
    reprompt: 0,
    fields: [],
  };

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
      fido2Credentials: await withNewPasskey(null, edit.addPasskey, enc),
    };
    payload['passwordHistory'] = [];
  } else if (type === 2) {
    // A secure note carries nothing but its notes; the sub-object exists only to
    // say which kind of note it is, and the API refuses the item without it.
    payload['secureNote'] = { type: 0 };
  } else {
    const section = await buildEditedSection(type, edit, null, encOrNull);
    if (section !== null) {
      payload[section[0]] = section[1];
    }
  }

  return payload;
}

/** How many entries the password history keeps. */
const PASSWORD_HISTORY_LIMIT = 5;

/**
 * The base key an item must be rewritten under: the vault's, or its
 * organisation's.
 *
 * Unlike reading — where a missing key yields an unreadable item and an
 * `onError` — writing **throws**. Rewriting an organisation item with the vault
 * key would produce an item nobody, the owner included, could decrypt: better to
 * refuse to write.
 */
function requireBaseKey(cipher: CipherResponse, keys: CipherKeys): SymmetricCryptoKey {
  if (keys instanceof SymmetricCryptoKey) {
    return keys;
  }
  const resolved = keyForCipher(cipher, keys);
  if (resolved === null) {
    throw new MissingOrgKeyError(readField<string>(cipher, 'organizationId') ?? 'unknown');
  }
  return resolved;
}

/**
 * Builds the complete body of an item update.
 *
 * The server **replaces** the item's data with what it receives: the body is
 * therefore rebuilt from the existing item — unedited fields (folder, favourite,
 * custom fields, item key…) are carried over as-is, already encrypted — and only
 * the edited fields are re-encrypted.
 *
 * Encryption uses exactly the decryption context: the organisation key for a
 * shared item, then the item's own key if it has one (and it is preserved in the
 * body).
 *
 * If the password changes (`recordPasswordHistory`), the old one — still
 * encrypted, never read back in the clear here — is added at the head of the
 * history, capped at {@link PASSWORD_HISTORY_LIMIT} entries.
 *
 * @param cipher The existing raw item, as returned by the sync.
 * @param edit New cleartext values.
 * @param keys The vault key alone, or the full keyring (organisations).
 * @param recordPasswordHistory Whether to record the old password.
 * @returns A body ready for `ApiClient.updateCipher`.
 * @throws {MissingOrgKeyError} Organisation item with no unwrapped key.
 */
export async function buildCipherUpdatePayload(
  cipher: CipherResponse,
  edit: CipherEdit,
  keys: CipherKeys,
  recordPasswordHistory: boolean,
): Promise<Record<string, unknown>> {
  const baseKey = requireBaseKey(cipher, keys);
  const itemKey = await resolveItemKey(cipher, baseKey);
  try {

    const enc = async (text: string): Promise<string> =>
      (await encryptString(text, itemKey)).toString();
    const encOrNull = async (text: string): Promise<string | null> =>
      text === '' ? null : enc(text);

    const type = readField<number>(cipher, 'type') ?? 1;
    const login = readLogin(cipher);
    const wrappedItemKey = readField<string>(cipher, 'key');

    // Fields carried over from the existing item, never recomputed: an update
    // replaces the whole item server-side, and any omitted field is lost.
    const payload: Record<string, unknown> = {
      type,
      organizationId: readField<string | null>(cipher, 'organizationId') ?? null,
      folderId: readField<string | null>(cipher, 'folderId') ?? null,
      favorite: readField<boolean>(cipher, 'favorite') ?? false,
      reprompt: readField<number>(cipher, 'reprompt') ?? 0,
      name: await enc(edit.name),
      notes: await encOrNull(edit.notes),
      // Custom fields: carried over as-is, already encrypted.
      fields: readField<unknown>(cipher, 'fields') ?? [],
    };

    if (wrappedItemKey != null && wrappedItemKey !== '') {
      payload['key'] = wrappedItemKey;
    }

    if (type === 1) {
      payload['login'] = await buildLoginSection(edit, login, enc, encOrNull);
      payload['passwordHistory'] = buildPasswordHistory(cipher, login, recordPasswordHistory);
    } else {
      const edited = await buildEditedSection(type, edit, cipher, encOrNull);
      if (edited !== null) {
        payload[edited[0]] = edited[1];
      } else {
        carryTypeSection(cipher, type, payload);
      }
    }

    return payload;
  } finally {
    releaseItemKey(itemKey, baseKey);
  }
}

/**
 * The sub-object each item type carries its own data in.
 *
 * An update replaces the whole item server-side, so a type whose section is not
 * in the payload loses it. The editor only knows how to rebuild `login`; every
 * other section is carried over as-is, still encrypted.
 *
 * This is the same trap the passkeys fell into, one level up: there a field was
 * missing from a section, here a whole section is missing from the item. Both
 * are silent, irreversible, and triggered by the most innocuous edit there is —
 * a rename.
 */
const TYPE_SECTIONS: Readonly<Record<number, string>> = {
  2: 'secureNote',
  3: 'card',
  4: 'identity',
  5: 'sshKey',
};

/** Copies the type's own section into the payload, untouched. */
function carryTypeSection(
  cipher: CipherResponse,
  type: number,
  payload: Record<string, unknown>,
): void {
  const section = TYPE_SECTIONS[type];
  if (section === undefined) {
    return;
  }
  const content = readField<unknown>(cipher, section);
  if (content != null) {
    payload[section] = content;
  }
}

/** Field encryptor, as supplied by the caller that holds the item key. */
type FieldEncryptor = (text: string) => Promise<string>;

/** The item's passkeys, with a new one appended if there is one. */
async function withNewPasskey(
  existing: readonly unknown[] | null,
  passkey: NewPasskey | undefined,
  enc: FieldEncryptor,
): Promise<readonly unknown[] | null> {
  if (passkey === undefined) {
    return existing;
  }
  return [...(existing ?? []), await buildPasskeySection(passkey, enc)];
}

/** An update's `login` section: edited fields, passkeys preserved. */
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
    // Everything the form does not touch — `passwordRevisionDate`,
    // `autofillOnPageLoad`, anything a later version adds — carried over rather
    // than dropped. A setting the user chose in another client must not be
    // undone by a rename here.
    ...unknownFieldsOf(login, ['username', 'password', 'totp', 'uris', 'fido2Credentials']),
    username: await encOrNull(edit.username),
    password: await encOrNull(edit.password),
    totp: await encOrNull(edit.totp),
    uris,
    // Passkeys are not editable here: carried over as-is, already encrypted.
    // Omitting them would erase them from the server. A newly created one is
    // appended to that list, never substituted for it.
    fido2Credentials: await withNewPasskey(
      readField<readonly unknown[]>(login, 'fido2Credentials') ?? null,
      edit.addPasskey,
      enc,
    ),
  };
}

/**
 * Password history, the old one at the head.
 *
 * The old password is already encrypted — it is carried over as-is from the
 * existing item, never re-encrypted: re-encrypting it under a different item key
 * would make it unreadable, and the history is precisely what one consults after
 * losing access to an account.
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
