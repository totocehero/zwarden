/**
 * @file The vault's health report, and throwing things out from it.
 *
 * Lifted out of `App`. What lives here is the sequence — decrypt every
 * password that is not guarded, optionally ask the breach corpus, build the
 * report, and move an item to the trash when the user decides to — while the
 * rules stay in `core/vault/health.ts`, pure and tested.
 *
 * The one property worth restating where the work happens: a `reprompt` item
 * is never decrypted here, not even to be counted. `buildHealthReport` skips
 * it and says how many it skipped, and this must not quietly undo that by
 * fetching the details first.
 */

import { useState } from 'preact/hooks';

import { t } from '@shared/i18n.js';
import { readField, type CipherResponse } from '@core/api/models.js';
import type { SymmetricCryptoKey } from '@core/crypto/symmetricCryptoKey.js';
import {
  type CipherKeys,
  type CipherOverview,
  decryptCipherDetails,
} from '@core/vault/cipherService.js';
import { buildHealthReport, type HealthReport } from '@core/vault/health.js';
import { checkPasswords } from '@core/vault/breachCheck.js';
import type { AppSettings } from '@shared/storage.js';

/** What the report needs of an open vault. */
export interface HealthVault {
  readonly userKey: SymmetricCryptoKey;
  readonly keys: CipherKeys;
  readonly items: readonly CipherOverview[];
  readonly raw: ReadonlyMap<string, CipherResponse>;
}

/**
 * The little a session must offer for this to use it.
 *
 * Structural and generic rather than a copy of `App`'s own type: this hook
 * trashes one item and hands the session straight back for the resync, so
 * naming the whole shape here would be asserting knowledge it does not need
 * and would drift from the real one.
 */
export interface TrashingSession {
  readonly client: { readonly trashCipher: (token: string, id: string) => Promise<void> };
  readonly accessToken: string;
}

export interface VaultHealth {
  readonly report: HealthReport | null;
  readonly check: () => Promise<void>;
  readonly trash: (cipherId: string) => Promise<void>;
  readonly close: () => void;
}

export function useVaultHealth<Session extends TrashingSession>({
  vault,
  settings,
  authorize,
  afterWrite,
  setBusy,
  setError,
  messageFor,
}: {
  vault: HealthVault | null;
  settings: AppSettings;
  authorize: () => Promise<Session>;
  /** Resyncs and redisplays, as `App` does after any write. */
  afterWrite: (auth: Session, userKey: SymmetricCryptoKey) => Promise<void>;
  setBusy: (value: string | null) => void;
  setError: (value: string | null) => void;
  messageFor: (error: unknown) => string;
}): VaultHealth {
  const [health, setHealth] = useState<HealthReport | null>(null);
  const open = vault;

/**
 * Examines the vault and opens the report.
 *
 * Every password has to be decrypted for this, which is why it happens on an
 * explicit gesture and not on opening: it is exactly the work the list was
 * just taught to avoid. Items guarded by `reprompt` are handed over
 * untouched — `buildHealthReport` skips them, and says how many.
 */
async function onCheckHealth(): Promise<void> {
  if (open === null) {
    return;
  }
  setError(null);
  setBusy(t('healthChecking'));
  try {
        const inputs = await Promise.all(
      open.items.map(async (item) => {
        const cipher = open.raw.get(item.id);
        // A guarded item is never decrypted, not even to be counted.
        const details =
          item.reprompt || cipher === undefined
            ? null
            : await decryptCipherDetails(cipher, open.keys, () => undefined);
        const login = cipher === undefined ? undefined : readField<unknown>(cipher, 'login');
        return {
          id: item.id,
          name: item.name,
          username: item.username,
          uris: item.uris,
          type: item.type,
          reprompt: item.reprompt,
          password: details?.password ?? null,
          // Neither is encrypted, so reading them costs nothing and asks
          // nothing of the guard.
          //
          // The fallback is the point: Bitwarden sets `passwordRevisionDate`
          // only when a password is **changed after creation**, so an item
          // made years ago and never edited has none at all. Skipping those
          // would hide exactly the oldest passwords, which is the opposite of
          // what this list is for. If the password was never revised, it is
          // as old as the item.
          passwordUpdatedAt:
            readField<string>(login, 'passwordRevisionDate') ??
            readField<string>(cipher, 'creationDate') ??
            null,
          card: details?.card ?? null,
        };
      }),
    );
    // The corpus is consulted only if the user asked for it to be, and only
    // as part of a report they explicitly requested. Never on opening, never
    // in the background.
    let breached: ReadonlyMap<string, number> | undefined;
    if (settings.breachCheckEnabled) {
      const passwords = inputs
        .map((input) => input.password)
        .filter((password): password is string => password !== null && password !== '');
      setBusy(t('healthBreachChecking', String(new Set(passwords).size)));
      breached = await checkPasswords(passwords);
    }
    setHealth(buildHealthReport(inputs, new Date(), breached === undefined ? {} : { breached }));
  } catch (err) {
    setError(messageFor(err));
  } finally {
    setBusy(null);
  }
}

/**
 * Moves an item to the trash, from the health report.
 *
 * The trash and not the permanent deletion: the official clients keep a
 * trashed item for thirty days, so a misclick on a list one is skimming costs
 * a trip to the web vault rather than a password that exists nowhere any
 * more.
 *
 * Not queued when the server is unreachable, unlike an edit. A held deletion
 * would have to decide what to do about an item changed in the meantime, and
 * "delete it anyway" is the wrong answer often enough that the honest
 * behaviour is to fail visibly and let the user try again.
 */
async function onTrashItem(cipherId: string): Promise<void> {
  if (open === null) {
    return;
  }
  const name = open.items.find((i) => i.id === cipherId)?.name ?? cipherId;
  setError(null);
  setBusy(t('statusSaving'));
  try {
    const auth = await authorize();
    await auth.client.trashCipher(auth.accessToken, cipherId);
    await afterWrite(auth, open.userKey);
    // The report described a vault that no longer holds this item: the row
    // goes, rather than staying until the panel is reopened.
    setHealth((current) =>
      current === null
        ? null
        : { ...current, stale: current.stale.filter((f) => f.id !== cipherId) },
    );
    setError(t('healthDeleted', name));
  } catch (err) {
    setError(messageFor(err));
  } finally {
    setBusy(null);
  }
}

  return {
    report: health,
    check: onCheckHealth,
    trash: onTrashItem,
    close: () => setHealth(null),
  };
}
