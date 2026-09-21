/**
 * @file A page waiting on a passkey, from badge to signature.
 *
 * The whole ceremony, lifted out of `App`: picking up what the service worker
 * left, deciding whether this vault can answer at all, offering the choice,
 * signing, creating, and telling the page either way.
 *
 * It is the largest thing `App` was carrying and the one with the most steps,
 * which is exactly why it belongs on its own. Every fault found while getting
 * it to work — a setting read from a stale closure, an identifier compared as
 * text, a silent decline — was a fault in this sequence, and none of them was
 * easy to see inside thirteen hundred lines of something else.
 *
 * The private key of exactly one credential is ever decrypted, and only after
 * the user has said yes. Everything before that is matched on metadata.
 */

import { useState } from 'preact/hooks';

import { t } from '@shared/i18n.js';
import { deriveMasterKey, verifyLocalPasswordHash } from '@core/crypto/kdf.js';
import type { CipherResponse } from '@core/api/models.js';
import { toBase64Url } from '@core/crypto/encoding.js';
import type { SymmetricCryptoKey } from '@core/crypto/symmetricCryptoKey.js';
import type { ApiClient } from '@core/api/apiClient.js';
import {
  buildCipherCreatePayload,
  buildCipherUpdatePayload,
  type CipherKeys,
  type CipherOverview,
  decryptCipherDetails,
  decryptPasskeys,
} from '@core/vault/cipherService.js';
import { createCredential, selectCredentials, signAssertion } from '@core/vault/passkey.js';
import {
  type AssertionAsk,
  type CreationAsk,
  validateAssertionAsk,
  validateCreationAsk,
  WebAuthnRefusal,
} from '@core/vault/webauthnRequest.js';
import {
  clearPendingAssertion,
  loadPendingAssertion,
  loadPendingSave,
  loadSettings,
  loadStoredSession,
  savePasskeyParties,
} from '@shared/storage.js';

import type { AssertionChoice } from '../components/AssertionScreen.js';

/** What the ceremony needs of an open vault. */
export interface CeremonyVault {
  readonly userKey: SymmetricCryptoKey;
  readonly keys: CipherKeys;
  readonly items: readonly CipherOverview[];
  readonly raw: ReadonlyMap<string, CipherResponse>;
}

/** A writable session, as `App` obtains one. */
export interface AuthorizedSession {
  readonly client: ApiClient;
  readonly accessToken: string;
}

/** The ceremony in progress, and what can be done about it. */
export interface PasskeyCeremony {
  readonly pending:
    | { readonly kind: 'get'; readonly id: string; readonly ask: AssertionAsk; readonly choices: readonly AssertionChoice[] }
    | { readonly kind: 'create'; readonly id: string; readonly ask: CreationAsk; readonly choices: readonly AssertionChoice[] }
    | null;
  readonly choice: string | null;
  readonly masterPassword: string;
  readonly setChoice: (value: string) => void;
  readonly setMasterPassword: (value: string) => void;
  /** Called once the vault is open: publishes what it holds, and picks up. */
  readonly pickUp: (open: CeremonyVault) => Promise<void>;
  readonly confirm: (event: Event) => Promise<void>;
  readonly decline: () => Promise<void>;
  /** Forgets everything on screen, for locking. */
  readonly reset: () => void;
}

export function usePasskeyCeremony({
  vault,
  authorize,
  noteUsage,
  setBusy,
  setError,
  messageFor,
}: {
  vault: CeremonyVault | null;
  authorize: () => Promise<AuthorizedSession>;
  noteUsage: (item: CipherOverview) => Promise<void>;
  setBusy: (value: string | null) => void;
  setError: (value: string | null) => void;
  messageFor: (error: unknown) => string;
}): PasskeyCeremony {
  const [assertion, setAssertion] = useState<
    | { readonly kind: 'get'; readonly id: string; readonly ask: AssertionAsk; readonly choices: readonly AssertionChoice[] }
    | { readonly kind: 'create'; readonly id: string; readonly ask: CreationAsk; readonly choices: readonly AssertionChoice[] }
    | null
  >(null);
  const [assertionChoice, setAssertionChoice] = useState<string | null>(null);
  const [assertionPassword, setAssertionPassword] = useState('');
  const open = vault;

/**
 * Picks up a page waiting on a passkey, if there is one.
 *
 * Runs once the vault is open, because answering needs keys — a locked vault
 * simply leaves the page waiting until the user unlocks, which is the same
 * position they would be in with any other authenticator.
 *
 * The request is validated **before anything is shown**: whether this page
 * may ask for this relying party is not a question to put to the user, who
 * would be looking at the name of a site they trust and clicking yes.
 */
async function pickUpAssertion(open: CeremonyVault): Promise<void> {
  // Read from storage, not from `settings`. This runs inside the very turn
  // that loads the settings, before the state update has been applied, so
  // the closure would still hold the defaults — and `passkeySignIn` defaults
  // to false, which silently disabled the whole feature.
  const { passkeySignIn } = await loadSettings();
  if (!passkeySignIn) {
    return;
  }

  // Computed on every opening, before anything else, and left where the
  // service worker can read it. That worker has no keys and cannot work out
  // whether this vault can answer for a site; without this list it must hold
  // every ceremony open until somebody opens this window to find out there
  // was nothing to offer — which is most ceremonies, since most sign-ins use
  // a hardware key, and it makes Zwarden a ninety-second delay on all of
  // them.
  const views = await passkeyViews(open);
  await savePasskeyParties(views.map((view) => view.rpId));
  console.debug('[zwarden] passkeys this vault can answer for', views.map((v) => v.rpId));

  const pending = await loadPendingAssertion();
  console.debug('[zwarden] ceremony waiting?', pending === null ? 'none' : pending.ceremony);
  if (pending === null) {
    // The badge may still be up from a ceremony that has since gone. Better
    // to say so than to leave the user looking for something to click.
    if (await hadBadgeWithoutCeremony()) {
      setError(t('assertionGone'));
    }
    return;
  }
  if (pending.ceremony === 'create') {
    try {
      const ask = validateCreationAsk(
        pending.options,
        pending.origin,
        views.map((view) => view.credentialId),
      );
      setAssertion({
        kind: 'create',
        id: pending.id,
        ask,
        // Where to put it: any item, or a new one — the empty value.
        choices: [
          { itemId: '', credentialId: '', label: t('registrationNewItem') },
          ...open.items.map((item: CipherOverview) => ({
            itemId: item.id,
            credentialId: item.id,
            label: item.name ?? item.id,
          })),
        ],
      });
      setAssertionChoice('');
      setAssertionPassword('');
    } catch (error) {
      await answerAssertion(pending.id, null);
      setError(error instanceof WebAuthnRefusal ? t('assertionRefused') : messageFor(error));
    }
    return;
  }

  let ask: AssertionAsk;
  try {
    ask = validateAssertionAsk(pending.options, pending.origin);
  } catch (error) {
    // Refused outright, and the page is told nothing beyond "we have
    // nothing" — it falls back to the browser.
    await answerAssertion(pending.id, null);
    setError(error instanceof WebAuthnRefusal ? t('assertionRefused') : messageFor(error));
    return;
  }

  const choices = selectCredentials(views, ask.rpId, ask.allowCredentials);
  console.debug('[zwarden] matching for', ask.rpId, {
    asked: ask.allowCredentials,
    held: views.map((v) => ({ rpId: v.rpId, credentialId: v.credentialId })),
    matched: choices.length,
  });
  if (choices.length === 0) {
    // Answered **at once**, so the page falls back to the browser now rather
    // than after the ninety-second timeout.
    await answerAssertion(pending.id, null);
    // And said out loud. This window was opened because a badge asked for it;
    // showing nothing in return is the worst possible answer, and it was what
    // happened. The message names the relying party, which is also the one
    // thing needed to tell "no passkey here" from "the wrong name matched".
    setError(t('assertionNoneFor', ask.rpId, String(views.length)));
    return;
  }
  setAssertion({ kind: 'get', id: pending.id, ask, choices });
  setAssertionChoice(choices[0]?.credentialId ?? null);
  setAssertionPassword('');
}

/**
 * Every passkey the vault holds, as metadata.
 *
 * No private key is decrypted here. Signing opens exactly the one the user
 * chose, afterwards; registering never opens any.
 */
async function passkeyViews(
  open: CeremonyVault,
): Promise<readonly (AssertionChoice & { readonly rpId: string })[]> {
  const perItem = await Promise.all(
    open.items
      .filter((item: CipherOverview) => item.hasPasskey)
      .map(async (item: CipherOverview) => {
        const cipher = open.raw.get(item.id);
        if (cipher === undefined) {
          return [];
        }
        const details = await decryptCipherDetails(cipher, open.keys, () => undefined);
        return details.passkeys
          .filter((view) => view.credentialId !== null && view.rpId !== null)
          .map((view) => ({
            itemId: item.id,
            credentialId: view.credentialId!,
            rpId: view.rpId!,
            label:
              view.userName === null
                ? (item.name ?? item.id)
                : `${item.name ?? item.id} — ${view.userName}`,
          }));
      }),
  );
  return perItem.flat();
}

/**
 * Whether the icon is carrying a badge with nothing behind it.
 *
 * The badge itself is read, not inferred. Inferring it from "no capture and
 * no proposal" was the first attempt and it was wrong in the ordinary case:
 * every normal opening satisfies that, and the window would have announced a
 * vanished sign-in to someone who had simply clicked the icon.
 *
 * The badge is shared with the save proposal, so it only means a lost
 * ceremony when no capture is waiting either.
 */
async function hadBadgeWithoutCeremony(): Promise<boolean> {
  if (typeof chrome === 'undefined' || typeof chrome.action?.getBadgeText !== 'function') {
    return false;
  }
  const badge = await chrome.action.getBadgeText({});
  return badge !== '' && (await loadPendingSave()) === null;
}

/** Hands the verdict to the service worker, which carries it to the page. */
async function answerAssertion(id: string, payload: unknown): Promise<void> {
  // Told first, cleared second. The worker owns the entry it wrote — it is the
  // one that knows whether any other ceremony is still waiting on the badge —
  // and clearing it here beforehand simply hid this one from it.
  await chrome.runtime.sendMessage({ type: 'assertion-answer', id, assertion: payload });
  // Belt and braces, for the case where the worker died between the two.
  await clearPendingAssertion();
}

/**
 * Verifies the master password, when the ceremony asked for it.
 *
 * The same offline check a per-item guard makes: re-derive and compare
 * against the witness kept at unlock. Having the server confirm it would
 * hand whoever controls the network the power to wave a passkey through.
 */
async function verifyMaster(candidate: string): Promise<boolean> {
  const stored = await loadStoredSession();
  if (stored === null) {
    throw new Error(t('errorSessionExpired'));
  }
  const masterKey = await deriveMasterKey(candidate, stored.email, stored.kdfConfig);
  try {
    return await verifyLocalPasswordHash(masterKey, candidate, stored.localPasswordHash);
  } finally {
    masterKey.destroy();
  }
}

/** Creates a passkey and puts it in the vault. */
async function onCreatePasskey(): Promise<void> {
  if (open === null || assertion === null || assertion.kind !== 'create') {
    return;
  }
  const ask = assertion.ask;
  setError(null);
  setBusy(t('assertionWorking'));
  try {
    let verified = false;
    if (ask.requiresVerification) {
      verified = await verifyMaster(assertionPassword);
      if (!verified) {
        setError(t('exportWrongMaster'));
        return;
      }
    }

    const created = await createCredential({
      rpId: ask.rpId,
      origin: ask.origin,
      challenge: ask.challenge,
      userId: ask.userId,
      userName: ask.userName,
      userDisplayName: ask.userDisplayName,
      userVerified: verified,
    });

    const addPasskey = {
      // The vault records the UUID spelling; the site was given the bytes.
      credentialId: created.storedCredentialId,
      rpId: ask.rpId,
      rpName: ask.rpName,
      userHandle: toBase64Url(ask.userId),
      userName: ask.userName,
      userDisplayName: ask.userDisplayName,
      keyValue: created.privateKey,
    };

    // Attached to an item the user chose, or to one made for it. Either way
    // through the write path every other edit uses.
    const target = assertionChoice === '' ? undefined : open.raw.get(assertionChoice ?? '');
    const edit = {
      name: target === undefined ? ask.rpName : (open.items.find((i) => i.id === assertionChoice)?.name ?? ask.rpName),
      username: ask.userName,
      password: '',
      totp: '',
      notes: '',
      uris: [ask.origin],
      addPasskey,
    };

    const auth = await authorize();
    if (target === undefined) {
      await auth.client.createCipher(
        auth.accessToken,
        await buildCipherCreatePayload(edit, open.userKey),
      );
    } else {
      await auth.client.updateCipher(
        auth.accessToken,
        assertionChoice!,
        await buildCipherUpdatePayload(target, edit, open.keys, false),
      );
    }

    // The site only hears about it once the vault has it: a passkey a site
    // believes in and the vault has lost is an account locked shut.
    await answerAssertion(assertion.id, {
      credentialId: created.credentialId,
      clientDataJSON: toBase64Url(new TextEncoder().encode(created.clientDataJSON)),
      attestationObject: toBase64Url(created.attestationObject),
      authenticatorData: toBase64Url(created.attestationObject),
    });
    setAssertion(null);
    window.close();
  } catch (err) {
    setError(messageFor(err));
  } finally {
    setBusy(null);
  }
}

/** Signs, and lets the page in. */
async function onConfirmAssertion(event: Event): Promise<void> {
  event.preventDefault();
  if (open === null || assertion === null || assertionChoice === null) {
    return;
  }
  if (assertion.kind === 'create') {
    await onCreatePasskey();
    return;
  }
  const choice = assertion.choices.find((c) => c.credentialId === assertionChoice);
  const cipher = choice === undefined ? undefined : open.raw.get(choice.itemId);
  if (choice === undefined || cipher === undefined) {
    return;
  }

  setError(null);
  setBusy(t('assertionWorking'));
  try {
    let verified = false;
    if (assertion.ask.requiresVerification) {
      verified = await verifyMaster(assertionPassword);
      if (!verified) {
        setError(t('exportWrongMaster'));
        return;
      }
    }

    // The one call that decrypts a private key, on the one credential the
    // user has just chosen.
    const credentials = await decryptPasskeys(cipher, open.keys, () => undefined);
    const credential = credentials.find((c) => c.credentialId === choice.credentialId);
    if (credential === undefined) {
      throw new Error(t('errorItemNotFound'));
    }

    const signed = await signAssertion(credential, { ...assertion.ask, userVerified: verified });
    await answerAssertion(assertion.id, {
      credentialId: signed.credentialId,
      clientDataJSON: toBase64Url(new TextEncoder().encode(signed.clientDataJSON)),
      authenticatorData: toBase64Url(signed.authenticatorData),
      signature: toBase64Url(signed.signature),
      userHandle: signed.userHandle,
    });
    void noteUsage(open.items.find((i) => i.id === choice.itemId)!);
    setAssertion(null);
    window.close();
  } catch (err) {
    setError(messageFor(err));
  } finally {
    setBusy(null);
  }
}

/** Declines, and lets the browser take over. */
async function onDeclineAssertion(): Promise<void> {
  if (assertion !== null) {
    await answerAssertion(assertion.id, null);
  }
  setAssertion(null);
  setAssertionPassword('');
}

  return {
    pending: assertion,
    choice: assertionChoice,
    masterPassword: assertionPassword,
    setChoice: setAssertionChoice,
    setMasterPassword: setAssertionPassword,
    pickUp: pickUpAssertion,
    confirm: onConfirmAssertion,
    decline: onDeclineAssertion,
    reset: () => {
      setAssertion(null);
      setAssertionPassword('');
    },
  };
}
