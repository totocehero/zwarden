/**
 * @file Popup — version de preuve de vie.
 *
 * Chaîne complète dans le vrai contexte d'extension : `unlock()` → second
 * facteur éventuel → `sync` → `decryptCipherList` → liste filtrable → copie
 * ou révélation d'un mot de passe déchiffré à la demande.
 *
 * ## Filtre par onglet actif
 *
 * À l'ouverture du coffre, si le domaine de l'onglet actif correspond à au
 * moins un item, le filtre est prérempli avec ce domaine — l'esquisse de la
 * « vue Zwarden » de `docs/EXTENSION.md`. Effacer le champ montre tout.
 *
 * ## Second facteur
 *
 * Fournisseurs saisissables : TOTP (0), code e-mail (1), YubiKey OTP (3).
 * WebAuthn (7) exige une page de rebond servie par le serveur (l'origine
 * d'une extension ne peut pas répondre au RP ID du coffre) : hors périmètre
 * de cette version — une YubiKey s'utilise en mode OTP. « Se souvenir de cet
 * appareil » conserve le jeton de dispense (fournisseur 5), rejoué
 * automatiquement ; s'il expire, l'écran de saisie revient.
 *
 * ## Persistance de session et verrouillage
 *
 * Le coffre déverrouillé survit à la fermeture de la popup : clé et jetons
 * dans `chrome.storage.session` (mémoire pure, purgée à la fermeture du
 * navigateur). Le verrouillage automatique est porté par `chrome.alarms` —
 * l'échéance repart à chaque ouverture de popup — et exécuté par le service
 * worker. Le mot de passe n'est jamais persisté.
 *
 * Limite assumée restante (`docs/EXTENSION.md`) : la dérivation tourne ici,
 * pas encore dans le service worker.
 */

import { render } from 'preact';
import { useEffect, useRef, useState } from 'preact/hooks';

import {
  ApiClient,
  ApiError,
  TwoFactorRequiredError,
  type TwoFactorSubmission,
} from '@core/api/apiClient.js';
import { TwoFactorProvider, type CipherResponse, type SyncResponse } from '@core/api/models.js';
import { SymmetricCryptoKey } from '@core/crypto/symmetricCryptoKey.js';
import {
  type CipherDetails,
  type CipherKeys,
  type CipherOverview,
  type PasskeyView,
  buildCipherUpdatePayload,
  decryptCipherDetails,
  decryptCipherList,
} from '@core/vault/cipherService.js';
import { buildVaultKeys } from '@core/vault/keyring.js';
import { type VaultLabels, decryptLabels } from '@core/vault/labels.js';
import { matchesOrigin } from '@core/vault/uriMatch.js';
import { unlock } from '@core/vault/session.js';
import {
  type AppSettings,
  DEFAULT_SETTINGS,
  cancelAutoLock,
  clearRememberToken,
  clearStoredSession,
  getDeviceId,
  loadRememberToken,
  loadSettings,
  loadStoredSession,
  saveRememberToken,
  saveSettings,
  saveStoredSession,
  scheduleAutoLock,
} from '@shared/storage.js';

/** État d'un coffre déverrouillé, vivant uniquement tant que la popup l'est. */
interface OpenVault {
  readonly userKey: SymmetricCryptoKey;
  /** Trousseau complet : clé du coffre + clés d'organisation déballées. */
  readonly keys: CipherKeys;
  readonly items: readonly CipherOverview[];
  readonly raw: ReadonlyMap<string, CipherResponse>;
  /** Dossiers, collections et organisations, noms déchiffrés. */
  readonly labels: VaultLabels;
  /** Échecs de déchiffrement rencontrés, pour le diagnostic à l'écran. */
  readonly errors: readonly unknown[];
}

/** Tag affichable sur un item : dossier ou collection. */
interface Chip {
  readonly kind: 'dossier' | 'collection';
  readonly name: string;
  readonly title: string;
}

/** Tags d'un item, noms résolus via les étiquettes du coffre. */
function chipsFor(item: CipherOverview, labels: VaultLabels): Chip[] {
  const chips: Chip[] = [];
  if (item.folderId !== null) {
    const name = labels.folders.get(item.folderId);
    if (name !== undefined) {
      chips.push({ kind: 'dossier', name, title: `Dossier : ${name}` });
    }
  }
  for (const collectionId of item.collectionIds) {
    const collection = labels.collections.get(collectionId);
    if (collection !== undefined) {
      const org =
        collection.organizationId !== null
          ? labels.organizations.get(collection.organizationId)
          : undefined;
      chips.push({
        kind: 'collection',
        name: collection.name,
        title: `${org ?? 'Organisation'} — collection${collection.readOnly ? ' (lecture seule)' : ''}`,
      });
    }
  }
  return chips;
}

/** Regroupe les erreurs par nom, pour un diagnostic lisible. */
function groupErrors(errors: readonly unknown[]): ReadonlyArray<readonly [string, number]> {
  const grouped = new Map<string, number>();
  for (const error of errors) {
    const name = error instanceof Error ? error.name : 'Erreur inconnue';
    grouped.set(name, (grouped.get(name) ?? 0) + 1);
  }
  return [...grouped.entries()].sort((a, b) => b[1] - a[1]);
}

/** Fournisseurs dont la popup sait recueillir le code. */
const PROVIDER_LABELS: Readonly<Record<string, string>> = {
  [String(TwoFactorProvider.Authenticator)]: 'Application d’authentification (TOTP)',
  [String(TwoFactorProvider.Email)]: 'Code reçu par e-mail',
  [String(TwoFactorProvider.YubiKey)]: 'YubiKey (mode OTP — toucher la clé)',
};

/** Onglet actif, s'il pointe une page web. */
async function activeWebTab(): Promise<{ tabId: number; url: URL } | null> {
  if (typeof chrome === 'undefined' || typeof chrome.tabs?.query === 'undefined') {
    return null;
  }
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.id === undefined || tab.url === undefined) {
      return null;
    }
    const url = new URL(tab.url);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return null;
    }
    return { tabId: tab.id, url };
  } catch {
    return null;
  }
}

/**
 * Remplit le premier formulaire d'identification visible de la page.
 *
 * Cette fonction est **sérialisée** puis exécutée dans la page via
 * `chrome.scripting` : elle ne doit référencer aucune variable extérieure.
 * Uniquement le cadre principal, jamais de soumission automatique.
 */
function fillCredentials(username: string, password: string): void {
  const visible = (el: HTMLElement): boolean => el.getClientRects().length > 0;
  const setValue = (input: HTMLInputElement, value: string): void => {
    // Passer par le setter natif du prototype, pour que les frameworks qui
    // interceptent `value` (React, etc.) voient bien le changement.
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
    setter?.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
  };

  const passwordInput = Array.from(
    document.querySelectorAll<HTMLInputElement>('input[type="password"]'),
  ).find(visible);
  if (passwordInput !== undefined && password !== '') {
    setValue(passwordInput, password);
  }

  if (username !== '') {
    const scope = passwordInput?.form ?? document;
    const usernameInput = Array.from(
      scope.querySelectorAll<HTMLInputElement>(
        'input[type="email"], input[autocomplete="username"], input[type="text"], input:not([type])',
      ),
    ).find(visible);
    if (usernameInput !== undefined) {
      setValue(usernameInput, username);
    }
  }
}

function openOptions(): void {
  if (typeof chrome !== 'undefined' && typeof chrome.runtime?.openOptionsPage === 'function') {
    void chrome.runtime.openOptionsPage();
  }
}

/** Formulaire d'édition d'un item. Chaîne vide = champ effacé. */
interface EditForm {
  name: string;
  username: string;
  password: string;
  totp: string;
  notes: string;
  /** Une URI par ligne. */
  uris: string;
}

const EMPTY_EDIT: EditForm = { name: '', username: '', password: '', totp: '', notes: '', uris: '' };

/** Durée d'affichage d'un mot de passe révélé avant masquage automatique. */
const REVEAL_HIDE_MS = 20_000;

/** Icône crayon, pour l'édition. */
function IconCrayon() {
  return (
    <svg
      width="15"
      height="15"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="2"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      <path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z" />
    </svg>
  );
}

/** Icône copie (coche quand la copie vient d'aboutir). */
function IconCopie({ fait }: { fait: boolean }) {
  return (
    <svg
      width="15"
      height="15"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="2"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      {fait ? (
        <polyline points="20 6 9 17 4 12" />
      ) : (
        <>
          <rect x="9" y="9" width="13" height="13" rx="2" />
          <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
        </>
      )}
    </svg>
  );
}

/** Icône œil (barré quand le secret est visible, pour proposer de le cacher). */
function IconOeil({ barre }: { barre: boolean }) {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="2"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      <path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z" />
      <circle cx="12" cy="12" r="3" />
      {barre && <line x1="4" y1="3" x2="20" y2="21" />}
    </svg>
  );
}

/** Message d'erreur à afficher. Les codes stables priment sur les messages. */
function messageFor(err: unknown): string {
  if (err instanceof DOMException && err.name === 'TimeoutError') {
    return 'Serveur injoignable : délai dépassé.';
  }
  if (err instanceof Error) {
    return err.message;
  }
  return String(err);
}

function App() {
  const [settings, setSettings] = useState<AppSettings>(DEFAULT_SETTINGS);
  /** Vrai tant que la tentative de restauration initiale n'a pas conclu. */
  const [initializing, setInitializing] = useState(true);
  const [serverUrl, setServerUrl] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [vault, setVault] = useState<OpenVault | null>(null);
  const [tabOrigin, setTabOrigin] = useState<string | null>(null);
  const [filter, setFilter] = useState('');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [copiedUserId, setCopiedUserId] = useState<string | null>(null);
  const [revealed, setRevealed] = useState<{ id: string; password: string } | null>(null);
  const [showPassword, setShowPassword] = useState(false);

  // Édition : item en cours, valeurs du formulaire, mot de passe d'origine
  // (pour l'historique), visibilité du champ.
  const [editing, setEditing] = useState<CipherOverview | null>(null);
  const [editForm, setEditForm] = useState<EditForm>(EMPTY_EDIT);
  const [editOriginalPassword, setEditOriginalPassword] = useState('');
  const [editShowPassword, setEditShowPassword] = useState(false);
  const [editPasskeys, setEditPasskeys] = useState<readonly PasskeyView[]>([]);

  // Second facteur : fournisseurs annoncés par le serveur, choix et code.
  const [twoFaProviders, setTwoFaProviders] = useState<readonly string[] | null>(null);
  const [twoFaChoice, setTwoFaChoice] = useState('');
  const [twoFaCode, setTwoFaCode] = useState('');
  const [rememberDevice, setRememberDevice] = useState(true);

  useEffect(() => {
    void (async () => {
      const loaded = await loadSettings();
      setSettings(loaded);
      setServerUrl(loaded.serverUrl);
      setEmail(loaded.email);
      await restoreSession(loaded);
    })();
  }, []);

  function makeClient(s: AppSettings, url: string, deviceId: string): ApiClient {
    return new ApiClient({
      serverUrl: url,
      deviceIdentifier: deviceId,
      deviceName: s.deviceName,
      timeoutMs: s.timeoutSeconds * 1000,
    });
  }

  /**
   * Restaure une session encore vivante dans `chrome.storage.session`.
   *
   * Deux temps, pour ne jamais montrer la mire inutilement :
   *
   * 1. **Affichage immédiat** depuis la dernière synchronisation en cache —
   *    aucun réseau, la liste apparaît en quelques dizaines de millisecondes.
   * 2. **Rafraîchissement réseau** en arrière-plan, qui met la liste à jour.
   *
   * Un échec réseau conserve le cache affiché — être hors ligne ne verrouille
   * pas le coffre. Seul un refus d'authentification (jeton révoqué) verrouille.
   */
  async function restoreSession(s: AppSettings): Promise<void> {
    const stored = await loadStoredSession();
    if (stored === null) {
      setInitializing(false);
      return;
    }

    setServerUrl(stored.serverUrl);
    setEmail(stored.email);
    const userKey = SymmetricCryptoKey.fromBase64(stored.userKeyB64);
    scheduleAutoLock(s.autoLockMinutes);

    let displayed = false;
    if (stored.cachedSync !== null) {
      try {
        await showVault(stored.cachedSync, userKey, false);
        displayed = true;
        setInitializing(false);
      } catch {
        // Cache inexploitable : le chemin réseau ci-dessous tranchera.
      }
    }

    try {
      const client = makeClient(s, stored.serverUrl, await getDeviceId());

      let accessToken = stored.accessToken;
      let refreshToken = stored.refreshToken;
      let expiresAt = stored.expiresAt;
      if (Date.now() > expiresAt - 60_000) {
        if (refreshToken === null) {
          throw new ApiError('Session expirée sans jeton de rafraîchissement', 401, '');
        }
        const renewed = await client.refreshToken(refreshToken);
        accessToken = renewed.accessToken;
        refreshToken = renewed.refreshToken ?? refreshToken;
        expiresAt = renewed.expiresAt;
      }

      if (!displayed) {
        setBusy('Ouverture du coffre…');
      }
      const sync = await client.sync(accessToken);
      await saveStoredSession({
        userKeyB64: stored.userKeyB64,
        accessToken,
        refreshToken,
        expiresAt,
        serverUrl: stored.serverUrl,
        email: stored.email,
        cachedSync: sync,
      });
      await showVault(sync, userKey, !displayed);
    } catch (err) {
      // Jeton refusé : la session est morte côté serveur, verrouillage net.
      const authFailure = err instanceof ApiError && (err.status === 400 || err.status === 401);
      if (authFailure) {
        await clearStoredSession();
        cancelAutoLock();
        userKey.destroy();
        setVault(null);
      } else if (!displayed) {
        // Panne réseau sans cache : la session est conservée pour un essai
        // ultérieur, mais il n'y a rien à montrer.
        setError('Serveur injoignable — réessayer, ou déverrouiller à nouveau.');
      }
      // Panne réseau avec cache affiché : on reste simplement sur le cache.
    } finally {
      setBusy(null);
      setInitializing(false);
    }
  }

  /** Déchiffre une réponse de synchronisation et affiche le coffre. */
  async function showVault(
    sync: SyncResponse,
    userKey: SymmetricCryptoKey,
    announce: boolean,
  ): Promise<void> {
    const ciphers = sync.ciphers ?? [];

    // Les échecs sont journalisés dans la console DE LA POPUP (clic droit sur
    // la popup → Inspecter) ET résumés à l'écran — la console de la page ne
    // les voit jamais.
    const errors: unknown[] = [];
    const onDecryptError = (error: unknown): void => {
      errors.push(error);
      console.warn('[zwarden] champ illisible :', error);
    };

    if (announce) {
      setBusy(`Déchiffrement de ${ciphers.length} item(s)…`);
    }
    const keys = await buildVaultKeys(sync.profile, userKey, onDecryptError);
    const [items, labels] = await Promise.all([
      decryptCipherList(ciphers, keys, onDecryptError),
      decryptLabels(sync, keys, onDecryptError),
    ]);

    const raw = new Map<string, CipherResponse>();
    for (const cipher of ciphers) {
      raw.set(cipher.id, cipher);
    }

    setVault({ userKey, keys, items, raw, labels, errors });

    // Onglet actif : origine stricte pour « Remplir », domaine pour le filtre
    // prérempli — sans écraser une recherche déjà saisie, et seulement s'il
    // correspond à quelque chose, une liste vide serait déroutante.
    const tab = await activeWebTab();
    setTabOrigin(tab === null ? null : tab.url.origin);
    const host = tab?.url.hostname.replace(/^www\./, '');
    if (host !== undefined && items.some((item) => matchesNeedle(item, host, labels))) {
      setFilter((current) => (current === '' ? host : current));
    }
  }

  /**
   * Tentative de déverrouillage complète. Sans `twoFactor`, rejoue d'abord un
   * éventuel jeton de dispense conservé pour cet appareil.
   */
  async function attemptUnlock(twoFactor?: TwoFactorSubmission): Promise<void> {
    setError(null);
    setBusy('Dérivation de la clé…');

    // Persistés dès la tentative, pas seulement au succès : un échec de mot
    // de passe ou de second facteur ne doit pas faire retaper le serveur et
    // l'e-mail à la prochaine ouverture. Jamais le mot de passe.
    await saveSettings({ serverUrl, email });

    let submission = twoFactor;
    if (submission === undefined) {
      const remembered = await loadRememberToken(serverUrl, email);
      if (remembered !== null) {
        submission = { provider: TwoFactorProvider.Remember, token: remembered };
      }
    }

    try {
      const client = makeClient(settings, serverUrl, await getDeviceId());
      const result = await unlock(client, email, password, submission);
      setPassword('');
      setShowPassword(false);
      setTwoFaProviders(null);
      setTwoFaCode('');

      if (result.twoFactorRememberToken !== undefined) {
        await saveRememberToken(serverUrl, email, result.twoFactorRememberToken);
      }

      setBusy('Synchronisation…');
      const sync = await client.sync(result.session.accessToken);

      // La session survit à la fermeture de la popup, jusqu'à la fermeture du
      // navigateur, l'échéance d'inactivité ou le verrouillage manuel. La
      // synchronisation est mise en cache pour un affichage immédiat à la
      // prochaine ouverture.
      await saveStoredSession({
        userKeyB64: result.userKey.toBase64(),
        accessToken: result.session.accessToken,
        refreshToken: result.session.refreshToken ?? null,
        expiresAt: result.session.expiresAt,
        serverUrl,
        email,
        cachedSync: sync,
      });
      scheduleAutoLock(settings.autoLockMinutes);

      await showVault(sync, result.userKey, true);
    } catch (err) {
      if (err instanceof TwoFactorRequiredError) {
        // Un jeton de dispense refusé est expiré : on l'oublie et on repasse
        // par la saisie.
        if (submission?.provider === TwoFactorProvider.Remember) {
          await clearRememberToken(serverUrl, email);
        }
        const saisissables = err.providers.filter((p) => p in PROVIDER_LABELS);
        setTwoFaProviders(err.providers);
        setTwoFaChoice(saisissables[0] ?? '');
        if (twoFactor !== undefined) {
          setError('Second facteur refusé — réessayer.');
        }
      } else {
        setError(messageFor(err));
      }
    } finally {
      setBusy(null);
    }
  }

  function onLock(): void {
    vault?.userKey.destroy();
    void clearStoredSession();
    cancelAutoLock();
    clearRevealTimer();
    setVault(null);
    setFilter('');
    setRevealed(null);
  }

  async function detailsOf(item: CipherOverview): Promise<CipherDetails | null> {
    if (vault === null) {
      return null;
    }
    const cipher = vault.raw.get(item.id);
    if (cipher === undefined) {
      return null;
    }
    return decryptCipherDetails(cipher, vault.keys, (err) => {
      setError(messageFor(err));
    });
  }

  async function onCopyPassword(item: CipherOverview): Promise<void> {
    const motDePasse = (await detailsOf(item))?.password ?? null;
    if (motDePasse !== null) {
      await navigator.clipboard.writeText(motDePasse);
      setCopiedId(item.id);
      setTimeout(() => setCopiedId(null), 1500);

      // Best-effort tant que la popup est ouverte ; l'effacement fiable après
      // fermeture passera par un document offscreen (docs/EXTENSION.md).
      if (settings.clipboardClearSeconds > 0) {
        setTimeout(() => {
          void navigator.clipboard.writeText('');
        }, settings.clipboardClearSeconds * 1000);
      }
    }
  }

  async function onCopyUsername(item: CipherOverview): Promise<void> {
    if (item.username !== null) {
      await navigator.clipboard.writeText(item.username);
      setCopiedUserId(item.id);
      setTimeout(() => setCopiedUserId(null), 1500);
    }
  }

  /** Minuteur d'auto-masquage du mot de passe révélé. */
  const revealTimer = useRef<number | undefined>(undefined);

  function clearRevealTimer(): void {
    if (revealTimer.current !== undefined) {
      clearTimeout(revealTimer.current);
      revealTimer.current = undefined;
    }
  }

  async function onToggleReveal(item: CipherOverview): Promise<void> {
    clearRevealTimer();
    if (revealed?.id === item.id) {
      setRevealed(null);
      return;
    }
    const motDePasse = (await detailsOf(item))?.password ?? null;
    if (motDePasse !== null) {
      setRevealed({ id: item.id, password: motDePasse });
      // Auto-masquage : un mot de passe affiché ne doit pas rester à l'écran
      // par oubli.
      revealTimer.current = window.setTimeout(() => setRevealed(null), REVEAL_HIDE_MS);
    }
  }

  /**
   * Remplit le formulaire de l'onglet actif avec les identifiants de l'item.
   *
   * Uniquement sur geste explicite, et uniquement si le bouton était visible —
   * c'est-à-dire si l'origine de l'item correspond à celle de l'onglet
   * (`docs/EXTENSION.md`, règles d'autofill). Revérifiée ici : l'onglet a pu
   * changer depuis le rendu.
   */
  async function onFill(item: CipherOverview): Promise<void> {
    const tab = await activeWebTab();
    if (tab === null || !matchesOrigin(item.uris, tab.url.origin)) {
      setError('L’onglet actif ne correspond plus à cet item.');
      return;
    }

    const details = await detailsOf(item);
    if (details === null || (details.username === null && details.password === null)) {
      return;
    }

    await chrome.scripting.executeScript({
      target: { tabId: tab.tabId },
      func: fillCredentials,
      args: [details.username ?? '', details.password ?? ''],
    });
    window.close();
  }

  /** Ouvre l'écran d'édition, prérempli avec les valeurs déchiffrées. */
  async function onEdit(item: CipherOverview): Promise<void> {
    const details = await detailsOf(item);
    if (details === null) {
      return;
    }
    setEditForm({
      name: item.name ?? '',
      username: details.username ?? '',
      password: details.password ?? '',
      totp: details.totp ?? '',
      notes: details.notes ?? '',
      uris: item.uris.join('\n'),
    });
    setEditOriginalPassword(details.password ?? '');
    setEditPasskeys(details.passkeys);
    setEditShowPassword(false);
    setEditing(item);
    setError(null);
  }

  /** Chiffre, envoie la mise à jour, resynchronise et revient à la liste. */
  async function onSaveEdit(event: Event): Promise<void> {
    event.preventDefault();
    if (vault === null || editing === null) {
      return;
    }
    const raw = vault.raw.get(editing.id);
    if (raw === undefined) {
      return;
    }

    setError(null);
    setBusy('Chiffrement…');
    try {
      const stored = await loadStoredSession();
      if (stored === null) {
        throw new Error('Session expirée — verrouiller puis déverrouiller.');
      }
      const client = makeClient(settings, stored.serverUrl, await getDeviceId());

      let accessToken = stored.accessToken;
      let refreshToken = stored.refreshToken;
      let expiresAt = stored.expiresAt;
      if (Date.now() > expiresAt - 60_000 && refreshToken !== null) {
        const renewed = await client.refreshToken(refreshToken);
        accessToken = renewed.accessToken;
        refreshToken = renewed.refreshToken ?? refreshToken;
        expiresAt = renewed.expiresAt;
      }

      const payload = await buildCipherUpdatePayload(
        raw,
        {
          name: editForm.name.trim(),
          username: editForm.username,
          password: editForm.password,
          totp: editForm.totp,
          notes: editForm.notes,
          uris: editForm.uris.split('\n'),
        },
        vault.keys,
        editForm.password !== editOriginalPassword,
      );

      setBusy('Enregistrement…');
      await client.updateCipher(accessToken, editing.id, payload);

      setBusy('Synchronisation…');
      const sync = await client.sync(accessToken);
      await saveStoredSession({
        userKeyB64: stored.userKeyB64,
        accessToken,
        refreshToken,
        expiresAt,
        serverUrl: stored.serverUrl,
        email: stored.email,
        cachedSync: sync,
      });
      await showVault(sync, vault.userKey, false);

      setEditing(null);
      setEditForm(EMPTY_EDIT);
      setEditOriginalPassword('');
      setRevealed(null);
    } catch (err) {
      setError(messageFor(err));
    } finally {
      setBusy(null);
    }
  }

  function onCancelEdit(): void {
    setEditing(null);
    setEditForm(EMPTY_EDIT);
    setEditOriginalPassword('');
    setError(null);
  }

  function matchesNeedle(item: CipherOverview, needle: string, labels: VaultLabels): boolean {
    return (
      (item.name ?? '').toLowerCase().includes(needle) ||
      (item.username ?? '').toLowerCase().includes(needle) ||
      item.uris.some((uri) => uri.toLowerCase().includes(needle)) ||
      chipsFor(item, labels).some((chip) => chip.name.toLowerCase().includes(needle))
    );
  }

  // --- Initialisation : ni mire ni liste tant qu'on ne sait pas -------------
  if (vault === null && initializing) {
    return (
      <div>
        <header>
          <h1>Zwarden</h1>
        </header>
        <main>
          <p class="statut">{busy ?? 'Ouverture…'}</p>
        </main>
      </div>
    );
  }

  // --- Écran second facteur -------------------------------------------------
  if (vault === null && twoFaProviders !== null) {
    const saisissables = twoFaProviders.filter((p) => p in PROVIDER_LABELS);
    const seulementWebAuthn = saisissables.length === 0;

    return (
      <div>
        <header>
          <h1>Zwarden</h1>
          <button class="discret" onClick={openOptions}>
            Paramètres
          </button>
        </header>
        <main>
          <p class="statut">Authentification à deux facteurs requise.</p>
          {seulementWebAuthn ? (
            <p class="erreur">
              Seul WebAuthn est proposé par ce compte, et il n’est pas encore pris en charge.
              Activer le mode OTP de la YubiKey ou le TOTP sur le serveur.
            </p>
          ) : (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void attemptUnlock({
                  provider: Number(twoFaChoice),
                  token: twoFaCode.trim(),
                  remember: rememberDevice,
                });
              }}
            >
              <label>
                Méthode
                <select
                  value={twoFaChoice}
                  onInput={(e) => setTwoFaChoice(e.currentTarget.value)}
                >
                  {saisissables.map((p) => (
                    <option key={p} value={p}>
                      {PROVIDER_LABELS[p]}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Code
                <input
                  type="text"
                  autocomplete="one-time-code"
                  autofocus
                  value={twoFaCode}
                  onInput={(e) => setTwoFaCode(e.currentTarget.value)}
                  required
                />
              </label>
              <label class="ligne">
                <input
                  type="checkbox"
                  checked={rememberDevice}
                  onInput={(e) => setRememberDevice(e.currentTarget.checked)}
                />
                Se souvenir de cet appareil
              </label>
              <button type="submit" disabled={busy !== null || twoFaCode.trim() === ''}>
                Valider
              </button>
            </form>
          )}
          <button
            class="discret"
            onClick={() => {
              setTwoFaProviders(null);
              setTwoFaCode('');
              setError(null);
            }}
          >
            ← Retour
          </button>
          {busy !== null && <p class="statut">{busy}</p>}
          {error !== null && <p class="erreur">{error}</p>}
        </main>
      </div>
    );
  }

  // --- Écran de déverrouillage ----------------------------------------------
  if (vault === null) {
    return (
      <div>
        <header>
          <h1>Zwarden</h1>
          <button class="discret" onClick={openOptions}>
            Paramètres
          </button>
        </header>
        <main>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void attemptUnlock();
            }}
          >
            <label>
              Serveur
              <input
                type="url"
                placeholder="https://coffre.exemple.fr"
                value={serverUrl}
                onInput={(e) => setServerUrl(e.currentTarget.value)}
                required
              />
            </label>
            <label>
              E-mail
              <input
                type="email"
                value={email}
                onInput={(e) => setEmail(e.currentTarget.value)}
                required
              />
            </label>
            <label>
              Mot de passe maître
              <div class="champ-mdp">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onInput={(e) => setPassword(e.currentTarget.value)}
                  required
                />
                <button
                  type="button"
                  class="oeil"
                  title={showPassword ? 'Masquer le mot de passe' : 'Afficher le mot de passe'}
                  onClick={() => setShowPassword(!showPassword)}
                >
                  <IconOeil barre={showPassword} />
                </button>
              </div>
            </label>
            <button type="submit" disabled={busy !== null}>
              Déverrouiller
            </button>
          </form>
          {busy !== null && <p class="statut">{busy}</p>}
          {error !== null && <p class="erreur">{error}</p>}
        </main>
      </div>
    );
  }

  // --- Écran d'édition ------------------------------------------------------
  if (editing !== null) {
    const estLogin = editing.type === 1;
    return (
      <div>
        <header>
          <h1>Zwarden</h1>
          <button class="discret" onClick={onCancelEdit}>
            ← Annuler
          </button>
        </header>
        <main>
          <form onSubmit={(e) => void onSaveEdit(e)}>
            <label>
              Nom
              <input
                type="text"
                value={editForm.name}
                onInput={(e) => setEditForm({ ...editForm, name: e.currentTarget.value })}
                required
              />
            </label>
            {estLogin && (
              <label>
                Identifiant
                <input
                  type="text"
                  value={editForm.username}
                  onInput={(e) => setEditForm({ ...editForm, username: e.currentTarget.value })}
                />
              </label>
            )}
            {estLogin && (
              <label>
                Mot de passe
                <div class="champ-mdp">
                  <input
                    type={editShowPassword ? 'text' : 'password'}
                    value={editForm.password}
                    onInput={(e) => setEditForm({ ...editForm, password: e.currentTarget.value })}
                  />
                  <button
                    type="button"
                    class="oeil"
                    title={editShowPassword ? 'Masquer' : 'Afficher'}
                    onClick={() => setEditShowPassword(!editShowPassword)}
                  >
                    <IconOeil barre={editShowPassword} />
                  </button>
                </div>
              </label>
            )}
            {estLogin && (
              <label>
                TOTP (clé ou otpauth://)
                <input
                  type="text"
                  value={editForm.totp}
                  onInput={(e) => setEditForm({ ...editForm, totp: e.currentTarget.value })}
                />
              </label>
            )}
            {estLogin && (
              <label>
                URIs (une par ligne)
                <textarea
                  rows={2}
                  value={editForm.uris}
                  onInput={(e) => setEditForm({ ...editForm, uris: e.currentTarget.value })}
                />
              </label>
            )}
            <label>
              Notes
              <textarea
                rows={3}
                value={editForm.notes}
                onInput={(e) => setEditForm({ ...editForm, notes: e.currentTarget.value })}
              />
            </label>
            {editPasskeys.length > 0 && (
              <div class="passkeys-info">
                {editPasskeys.map((pk, i) => (
                  <p key={i}>
                    <span class="badge">passkey</span> {pk.rpId ?? 'site inconnu'}
                    {pk.userName !== null ? ` — ${pk.userName}` : ''}
                  </p>
                ))}
                <p class="aide-diag">
                  Passkey conservée telle quelle — la signature WebAuthn arrivera dans une
                  prochaine version.
                </p>
              </div>
            )}
            <button type="submit" disabled={busy !== null}>
              Enregistrer
            </button>
          </form>
          {busy !== null && <p class="statut">{busy}</p>}
          {error !== null && <p class="erreur">{error}</p>}
        </main>
      </div>
    );
  }

  // --- Liste du coffre ------------------------------------------------------
  const needle = filter.trim().toLowerCase();
  const visible =
    needle === ''
      ? vault.items
      : vault.items.filter((i) => matchesNeedle(i, needle, vault.labels));

  return (
    <div>
      <header>
        <h1>Zwarden</h1>
        <div>
          <button class="discret" onClick={openOptions}>
            Paramètres
          </button>
          <button class="discret" onClick={onLock}>
            Verrouiller
          </button>
        </div>
      </header>
      <main>
        <input
          class="recherche"
          type="search"
          placeholder={`Rechercher parmi ${vault.items.length} item(s)…`}
          value={filter}
          onInput={(e) => setFilter(e.currentTarget.value)}
        />
        {vault.errors.length > 0 && (
          <details class="diagnostic">
            <summary class="erreur">{vault.errors.length} champ(s) illisible(s) — détails</summary>
            <ul>
              {groupErrors(vault.errors).map(([name, count]) => (
                <li key={name}>
                  {name} × {count}
                </li>
              ))}
            </ul>
            <p class="aide-diag">
              Journal complet : clic droit sur la popup → « Inspecter » → Console.
            </p>
          </details>
        )}
        {error !== null && <p class="erreur">{error}</p>}
        {visible.length === 0 ? (
          <p class="vide">Aucun item.</p>
        ) : (
          <ul class="items">
            {visible.map((item) => (
              <li key={item.id}>
                <div class="item-ligne">
                  <div class="item-texte">
                    <div class="item-nom" title={item.name ?? ''}>
                      {item.name ?? '(sans nom)'}
                      {item.hasPasskey && <span class="badge">passkey</span>}
                    </div>
                    {item.username !== null && (
                      <div
                        class="item-user"
                        title={`Copier : ${item.username}`}
                        onClick={() => void onCopyUsername(item)}
                      >
                        {item.username}
                        {copiedUserId === item.id ? ' — copié !' : ''}
                      </div>
                    )}
                    {item.uris[0] !== undefined && <div class="item-uri">{item.uris[0]}</div>}
                    {chipsFor(item, vault.labels).length > 0 && (
                      <div class="chips">
                        {chipsFor(item, vault.labels).map((chip) => (
                          <button
                            key={`${chip.kind}:${chip.name}`}
                            class={`chip chip-${chip.kind}`}
                            title={`${chip.title} — cliquer pour filtrer`}
                            onClick={() => setFilter(chip.name)}
                          >
                            {chip.kind === 'dossier' ? `#${chip.name}` : `@${chip.name}`}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                  <button
                    class="discret oeil-item"
                    title={
                      revealed?.id === item.id
                        ? 'Masquer le mot de passe'
                        : 'Voir le mot de passe'
                    }
                    onClick={() => void onToggleReveal(item)}
                  >
                    <IconOeil barre={revealed?.id === item.id} />
                  </button>
                  <button
                    class="discret oeil-item"
                    title="Modifier l’item"
                    onClick={() => void onEdit(item)}
                  >
                    <IconCrayon />
                  </button>
                  <button
                    class={`icone${copiedId === item.id ? ' copie-ok' : ''}`}
                    title={copiedId === item.id ? 'Mot de passe copié !' : 'Copier le mot de passe'}
                    onClick={() => void onCopyPassword(item)}
                  >
                    <IconCopie fait={copiedId === item.id} />
                  </button>
                  {tabOrigin !== null && matchesOrigin(item.uris, tabOrigin) && (
                    <button
                      class="remplir"
                      title="Remplir le formulaire de l’onglet actif"
                      onClick={() => void onFill(item)}
                    >
                      Remplir
                    </button>
                  )}
                </div>
                {revealed?.id === item.id && <div class="secret">{revealed.password}</div>}
              </li>
            ))}
          </ul>
        )}
      </main>
    </div>
  );
}

render(<App />, document.getElementById('app')!);
