/**
 * @file The encrypted export, as a screen with three secrets.
 *
 * Lifted out of `App`, which had grown to thirteen hundred lines of logic by
 * absorbing one feature after another. The repository already had the shape
 * for this — `useReprompt`, `useGenerator` — and it was not applied to the
 * features added since.
 *
 * What lives here is everything the export needs and nothing else: the three
 * fields, the offline verification of the master password, the decryption of
 * the whole vault, and handing the file to the browser. `App` keeps the vault
 * and the screen; it no longer keeps the export.
 */

import { useState } from 'preact/hooks';

import { t } from '@shared/i18n.js';
import { deriveMasterKey, verifyLocalPasswordHash } from '@core/crypto/kdf.js';
import { type CipherKeys, decryptCipherDetails } from '@core/vault/cipherService.js';
import { type CipherResponse, readField } from '@core/api/models.js';
import type { SymmetricCryptoKey } from '@core/crypto/symmetricCryptoKey.js';
import type { CipherOverview } from '@core/vault/cipherService.js';
import type { VaultLabels } from '@core/vault/labels.js';
import {
  type ExportedItem,
  type ExportPayload,
  sealExport,
} from '@core/vault/exportFile.js';
import { loadStoredSession } from '@shared/storage.js';

/** What the export needs of an open vault. */
export interface ExportableVault {
  readonly userKey: SymmetricCryptoKey;
  readonly keys: CipherKeys;
  readonly items: readonly CipherOverview[];
  readonly raw: ReadonlyMap<string, CipherResponse>;
  readonly labels: VaultLabels;
}

/** The export screen's state and its one action. */
export interface VaultExport {
  readonly active: boolean;
  readonly masterPassword: string;
  readonly passphrase: string;
  readonly confirmation: string;
  readonly open: () => void;
  readonly close: () => void;
  readonly setMasterPassword: (value: string) => void;
  readonly setPassphrase: (value: string) => void;
  readonly setConfirmation: (value: string) => void;
  readonly run: (event: Event) => Promise<void>;
}

export function useVaultExport({
  vault,
  setBusy,
  setError,
  messageFor,
}: {
  vault: ExportableVault | null;
  setBusy: (value: string | null) => void;
  setError: (value: string | null) => void;
  messageFor: (error: unknown) => string;
}): VaultExport {
  const [active, setActive] = useState(false);
  const [masterPassword, setMasterPassword] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const open = vault;

/** How short a passphrase may not be. Long beats complicated. */
const MIN_PASSPHRASE = 12;

/** Leaves the export screen, taking its three secrets with it. */
function close(): void {
  setActive(false);
  setMasterPassword('');
  setPassphrase('');
  setConfirmation('');
  setError(null);
}

/**
 * Builds the encrypted export and hands it to the browser to save.
 *
 * The master password is asked for once and verified **offline**, against the
 * witness kept at unlock — the same check a per-item guard makes. That single
 * answer covers every `reprompt` item at once, which is what lets the backup
 * be complete: one missing exactly the items the user was most careful about
 * would be worse than none, because it would be trusted.
 */
async function run(event: Event): Promise<void> {
  event.preventDefault();
  if (open === null) {
    return;
  }
  if (passphrase !== confirmation) {
    setError(t('exportMismatch'));
    return;
  }
  if (passphrase.length < MIN_PASSPHRASE) {
    setError(t('exportTooShort'));
    return;
  }

  setError(null);
  setBusy(t('exportWorking'));
  try {
    const stored = await loadStoredSession();
    if (stored === null) {
      throw new Error(t('errorSessionExpired'));
    }
    const masterKey = await deriveMasterKey(masterPassword, stored.email, stored.kdfConfig);
    let verified: boolean;
    try {
      verified = await verifyLocalPasswordHash(
        masterKey,
        masterPassword,
        stored.localPasswordHash,
      );
    } finally {
      masterKey.destroy();
    }
    if (!verified) {
      setError(t('exportWrongMaster'));
      return;
    }

    const payload = await buildExportPayload(open);
    const file = await sealExport(payload, passphrase);
    downloadFile(file, `zwarden-${new Date().toISOString().slice(0, 10)}.json`);

    close();
    setError(t('exportDone', String(payload.items.length)));
  } catch (err) {
    setError(messageFor(err));
  } finally {
    setBusy(null);
  }
}

/**
 * Decrypts the whole vault into the shape the file carries.
 *
 * Every field, or no file. A field whose MAC fails is not written as `null`
 * into a backup the user will believe complete — that is the "worse than
 * none" the file format's own header warns about. The count is thrown so the
 * user hears how much is unreadable and can look at the vault's own report.
 */
async function buildExportPayload(open: ExportableVault): Promise<ExportPayload> {
  const unreadable: unknown[] = [];
  const items = await Promise.all(
    open.items.map(async (item: CipherOverview): Promise<ExportedItem> => {
      const cipher = open.raw.get(item.id);
      const details =
        cipher === undefined
          ? null
          : await decryptCipherDetails(cipher, open.keys, (error) => unreadable.push(error));
      const base = {
        id: item.id,
        type: item.type,
        name: item.name ?? '',
        notes: details?.notes ?? null,
        favorite: cipher === undefined ? false : (readField<boolean>(cipher, 'favorite') ?? false),
        folderId: item.folderId,
      };
      if (item.type === 1) {
        return {
          ...base,
          login: {
            username: details?.username ?? null,
            password: details?.password ?? null,
            totp: details?.totp ?? null,
            uris: item.uris.map((uri: string) => ({ uri })),
          },
        };
      }
      if (item.type === 3 && details?.card != null) {
        return { ...base, card: { ...details.card } };
      }
      if (item.type === 4 && details?.identity != null) {
        return { ...base, identity: { ...details.identity } };
      }
      return base;
    }),
  );

  if (unreadable.length > 0) {
    throw new Error(t('exportUnreadable', String(unreadable.length)));
  }

  return {
    encrypted: false,
    folders: [...open.labels.folders].map(([id, name]) => ({ id, name })),
    items,
  };
}

/**
 * Hands a file to the browser.
 *
 * A blob URL and an anchor rather than `chrome.downloads`: the API would need
 * a permission in the manifest, and a password manager asking for one more
 * than it needs is a password manager asking to be distrusted. The URL is
 * revoked straight after — it names the whole vault, encrypted or not.
 */
function downloadFile(text: string, filename: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

  return {
    active,
    masterPassword,
    passphrase,
    confirmation,
    open: () => setActive(true),
    close,
    setMasterPassword,
    setPassphrase,
    setConfirmation,
    run,
  };
}
