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
 * navigateur). Par défaut, il ne se verrouille qu'à cette fermeture. Si un
 * délai d'inactivité est configuré, c'est le service worker qui le tient : la
 * popup se contente de signaler son activité (`recordActivity`), au même
 * titre qu'un changement d'onglet. Le mot de passe n'est jamais persisté.
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
  buildCipherCreatePayload,
  buildCipherUpdatePayload,
  decryptCipherDetails,
  decryptCipherList,
  findSaveCandidate,
  sortByLastUsed,
} from '@core/vault/cipherService.js';
import { deriveMasterKey, verifyLocalPasswordHash } from '@core/crypto/kdf.js';
import { buildVaultKeys } from '@core/vault/keyring.js';
import { type VaultLabels, decryptLabels } from '@core/vault/labels.js';
import { matchesOrigin } from '@core/vault/uriMatch.js';
import {
  type TotpConfig,
  formatTotp,
  generateTotp,
  parseTotp,
  secondsRemaining,
} from '@core/vault/totp.js';
import {
  type PasswordOptions,
  MAX_LENGTH,
  MIN_LENGTH,
  generatePassword,
} from '@core/generator/password.js';
import { unlock } from '@core/vault/session.js';
import {
  type AppSettings,
  type PendingSave,
  type StoredSession,
  DEFAULT_SETTINGS,
  addNeverSaveHost,
  clearPendingSave,
  clearRememberToken,
  getDeviceId,
  loadGeneratorOptions,
  loadLastUsed,
  loadPendingSave,
  loadRememberToken,
  loadSettings,
  loadStoredSession,
  lockVault,
  markUsed,
  recordActivity,
  setSaveBadge,
  saveGeneratorOptions,
  saveRememberToken,
  saveSettings,
  saveStoredSession,
  startAutoLockWatch,
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

/**
 * Code à usage unique affiché sur une ligne de la liste.
 *
 * Le `config` est conservé — pas seulement le code — parce que le
 * rafraîchissement à la seconde doit pouvoir recalculer sans redéchiffrer le
 * secret à chaque battement.
 */
interface OtpView {
  readonly id: string;
  readonly config: TotpConfig;
  readonly code: string;
  readonly remaining: number;
}

/** Panneau du générateur : ses options, sa production, et sa destination. */
interface GeneratorState {
  readonly options: PasswordOptions;
  readonly password: string;
  /** `'edit'` : un bouton « Utiliser » réinjecte dans le formulaire ouvert. */
  readonly target: 'edit' | 'standalone';
}

/** Session prête à écrire : client API et jetons valides. */
interface AuthorizedSession {
  readonly client: ApiClient;
  readonly stored: StoredSession;
  readonly accessToken: string;
  readonly refreshToken: string | null;
  readonly expiresAt: number;
}

/**
 * Proposition d'enregistrement en attente : ce que l'utilisateur a saisi, et
 * l'item que cela mettrait à jour — `null` s'il s'agit d'un nouvel item.
 */
interface SaveProposal {
  readonly capture: PendingSave;
  readonly existing: CipherOverview | null;
}

/**
 * Action suspendue en attente d'une nouvelle saisie du mot de passe maître.
 *
 * L'action est portée telle quelle (`run`) plutôt que reconstruite après
 * vérification : la garde n'a ainsi rien à savoir de ce qu'elle protège, et
 * ajouter une action protégée ne demande pas de la modifier.
 */
interface RepromptState {
  readonly item: CipherOverview;
  readonly run: () => void | Promise<void>;
  readonly password: string;
  readonly error: string | null;
  /** Vrai pendant la dérivation, qui dure — le KDF est lent par construction. */
  readonly busy: boolean;
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

/**
 * Période du battement d'activité émis tant que la popup est ouverte sur un
 * coffre déverrouillé. Sous le seuil d'écriture de `recordActivity` (20 s)
 * il n'y aurait pas d'écriture supplémentaire ; au-dessus, l'horodatage
 * pourrait vieillir inutilement.
 */
const ACTIVITY_PING_MS = 30_000;

/**
 * Délai avant d'enregistrer les options du générateur. Assez court pour que
 * la préférence survive à la fermeture de la popup dans un usage normal,
 * assez long pour qu'un glissement de curseur ne compte que pour une écriture.
 */
const GENERATOR_SAVE_DELAY_MS = 400;

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

/** Icône « code à usage unique » : une horloge. */
function IconOtp() {
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
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5l3 2" />
    </svg>
  );
}

/**
 * Anneau de décompte du code à usage unique.
 *
 * Un nombre de secondes se lit ; une jauge se voit. Comme le code est
 * recopié sous contrainte de temps, l'information « il me reste de quoi » doit
 * être saisie du coin de l'œil, sans lire. L'anneau se vide, et le chiffre
 * reste au centre pour qui veut la valeur exacte.
 *
 * @param remaining Secondes restantes.
 * @param period Durée totale de la fenêtre, pour l'échelle.
 */
function AnneauOtp({ remaining, period }: { remaining: number; period: number }) {
  const rayon = 8;
  const circonference = 2 * Math.PI * rayon;
  const part = Math.max(0, Math.min(1, remaining / period));
  const urgent = remaining <= 5;

  return (
    <svg
      class={`anneau${urgent ? ' anneau-urgent' : ''}`}
      width="22"
      height="22"
      viewBox="0 0 22 22"
      aria-hidden="true"
    >
      {/* Piste : l'anneau vide reste visible, sinon la jauge semble disparaître. */}
      <circle cx="11" cy="11" r={rayon} fill="none" stroke="currentColor" stroke-width="2" opacity="0.22" />
      <circle
        cx="11"
        cy="11"
        r={rayon}
        fill="none"
        stroke="currentColor"
        stroke-width="2"
        stroke-linecap="round"
        stroke-dasharray={circonference}
        stroke-dashoffset={circonference * (1 - part)}
        // Départ à midi, sens horaire : le sens de lecture d'une horloge.
        transform="rotate(-90 11 11)"
      />
      <text x="11" y="11" class="anneau-texte" text-anchor="middle" dominant-baseline="central">
        {remaining}
      </text>
    </svg>
  );
}

/** Icône du générateur : un dé. */
function IconDe() {
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
      <rect x="3" y="3" width="18" height="18" rx="3" />
      <circle cx="8.5" cy="8.5" r="1.2" fill="currentColor" />
      <circle cx="15.5" cy="15.5" r="1.2" fill="currentColor" />
      <circle cx="15.5" cy="8.5" r="1.2" fill="currentColor" />
      <circle cx="8.5" cy="15.5" r="1.2" fill="currentColor" />
    </svg>
  );
}

/**
 * Panneau du générateur de mots de passe.
 *
 * Composant à part, rendu aussi bien au-dessus de la liste qu'au-dessus du
 * formulaire d'édition : c'est le même outil, appelé depuis deux endroits.
 * Il ne connaît ni le coffre ni le réseau — il reçoit son état et rend ses
 * gestes, ce qui le laisse hors de la logique de coffre (§3).
 */
function PanneauGenerateur({
  state,
  onPatch,
  onRegenerate,
  onCopy,
  onUse,
  onClose,
  copie,
}: {
  state: GeneratorState;
  onPatch: (patch: Partial<PasswordOptions>) => void;
  onRegenerate: () => void;
  onCopy: () => void;
  onUse: () => void;
  onClose: () => void;
  copie: boolean;
}) {
  const { options, password } = state;
  const classes: ReadonlyArray<readonly [keyof PasswordOptions, string]> = [
    ['lowercase', 'a-z'],
    ['uppercase', 'A-Z'],
    ['digits', '0-9'],
    ['symbols', '!@#$%^&*'],
  ];

  return (
    <section class="generateur">
      <div class="generateur-sortie" title="Cliquer pour copier" onClick={onCopy}>
        {password === '' ? '—' : password}
      </div>
      <div class="generateur-actions">
        <button type="button" onClick={onRegenerate} disabled={password === ''}>
          Régénérer
        </button>
        <button type="button" class="secondaire" onClick={onCopy} disabled={password === ''}>
          {copie ? 'Copié !' : 'Copier'}
        </button>
        {state.target === 'edit' && (
          <button type="button" class="secondaire" onClick={onUse} disabled={password === ''}>
            Utiliser
          </button>
        )}
        <button type="button" class="discret" onClick={onClose}>
          Fermer
        </button>
      </div>
      <label class="generateur-longueur">
        Longueur : {options.length}
        <input
          type="range"
          min={MIN_LENGTH}
          max={MAX_LENGTH}
          value={options.length}
          onInput={(e) => onPatch({ length: e.currentTarget.valueAsNumber })}
        />
      </label>
      <div class="generateur-classes">
        {classes.map(([cle, libelle]) => (
          <label key={cle} class="ligne">
            <input
              type="checkbox"
              checked={options[cle] as boolean}
              onInput={(e) => onPatch({ [cle]: e.currentTarget.checked })}
            />
            {libelle}
          </label>
        ))}
        <label class="ligne">
          <input
            type="checkbox"
            checked={options.avoidAmbiguous}
            onInput={(e) => onPatch({ avoidAmbiguous: e.currentTarget.checked })}
          />
          Éviter l’ambigu (l 1 I O 0 o)
        </label>
      </div>
    </section>
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
  const [proposal, setProposal] = useState<SaveProposal | null>(null);
  const [reprompt, setReprompt] = useState<RepromptState | null>(null);

  // Code à usage unique affiché, et générateur de mots de passe. `generator`
  // à `null` = panneau fermé ; sa cible dit où repartira le mot de passe
  // engendré : dans le formulaire d'édition, ou nulle part (copie seule).
  const [otp, setOtp] = useState<OtpView | null>(null);
  const [copiedOtp, setCopiedOtp] = useState(false);
  const [generator, setGenerator] = useState<GeneratorState | null>(null);
  const [copiedGenerated, setCopiedGenerated] = useState(false);

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

  /**
   * Battement d'activité tant que la popup est ouverte sur un coffre
   * déverrouillé. Sans lui, une popup laissée ouverte le temps de composer un
   * mot de passe pourrait se faire verrouiller sous le nez par le service
   * worker : lire l'écran est une activité, elle n'émet simplement aucun
   * événement de navigateur.
   */
  useEffect(() => {
    if (vault === null) {
      return;
    }
    void recordActivity();
    const timer = setInterval(() => void recordActivity(), ACTIVITY_PING_MS);
    return () => clearInterval(timer);
  }, [vault]);

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
    void startAutoLockWatch(s.autoLockMinutes);

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
        localPasswordHash: stored.localPasswordHash,
        kdfConfig: stored.kdfConfig,
      });
      await showVault(sync, userKey, !displayed);
    } catch (err) {
      // Jeton refusé : la session est morte côté serveur, verrouillage net.
      const authFailure = err instanceof ApiError && (err.status === 400 || err.status === 401);
      if (authFailure) {
        await lockVault();
        userKey.destroy();
        resetVaultState();
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

    // Le classement est figé à l'ouverture, jamais réappliqué pendant que la
    // popup est ouverte : un item qui remonterait sous le curseur au moment
    // où on le copie ferait cliquer à côté la fois suivante.
    const ordered = sortByLastUsed(items, await loadLastUsed());

    setVault({ userKey, keys, items: ordered, raw, labels, errors });
    await evaluatePending(ordered, raw, keys, onDecryptError);

    // Onglet actif : origine stricte pour « Remplir », domaine pour le filtre
    // prérempli — sans écraser une recherche déjà saisie, et seulement s'il
    // correspond à quelque chose, une liste vide serait déroutante.
    const tab = await activeWebTab();
    setTabOrigin(tab === null ? null : tab.url.origin);
    const host = tab?.url.hostname.replace(/^www\./, '');
    if (host !== undefined && ordered.some((item) => matchesNeedle(item, host, labels))) {
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
        // Conservés pour vérifier le mot de passe maître sans réseau quand un
        // item exige de le redemander.
        localPasswordHash: result.localPasswordHash,
        kdfConfig: result.kdfConfig,
      });
      await startAutoLockWatch(settings.autoLockMinutes);

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

  /**
   * Purge tout ce que l'état déverrouillé a laissé dans la popup.
   *
   * `lockVault()` porte la liste côté stockage ; celle-ci porte la liste côté
   * mémoire, et les deux doivent être appelées ensemble — sans quoi la règle
   * « verrouiller, c'est tout purger » (`docs/EXTENSION.md` §2) ne vaut que
   * pour la moitié qu'on a pensé à écrire.
   *
   * Y figurent des secrets déchiffrés qu'on n'attend pas au premier coup
   * d'œil : `otp` porte le secret TOTP **et** un minuteur qui recalcule un
   * code chaque seconde, `generator` un mot de passe engendré, et le
   * formulaire d'édition le mot de passe de l'item ouvert. Aucun n'est visible
   * après verrouillage — ils survivaient pourtant en mémoire.
   */
  function resetVaultState(): void {
    clearRevealTimer();
    setVault(null);
    setFilter('');
    setRevealed(null);
    setProposal(null);
    setOtp(null);
    setGenerator(null);
    setEditing(null);
    setEditForm(EMPTY_EDIT);
    setEditOriginalPassword('');
    setEditShowPassword(false);
    setEditPasskeys([]);
    setReprompt(null);
  }

  function onLock(): void {
    vault?.userKey.destroy();
    void lockVault();
    resetVaultState();
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

  /**
   * Décide s'il y a quelque chose à proposer, une fois le coffre affiché.
   *
   * Le service worker capture sans savoir ce que le coffre contient — il n'a
   * pas la clé. C'est donc ici, et seulement ici, que la question se tranche :
   *
   * - identifiant déjà connu sur cette origine, **même** mot de passe → rien à
   *   proposer, la capture est jetée sans rien afficher. C'est le cas le plus
   *   fréquent, celui d'une connexion ordinaire : ne pas le taire rendrait la
   *   pastille insignifiante à force de s'allumer pour rien ;
   * - identifiant connu, mot de passe différent → mise à jour ;
   * - sinon → nouvel item.
   */
  async function evaluatePending(
    items: readonly CipherOverview[],
    raw: Map<string, CipherResponse>,
    keys: CipherKeys,
    onDecryptError: (error: unknown) => void,
  ): Promise<void> {
    const capture = await loadPendingSave();
    if (capture === null) {
      setProposal(null);
      return;
    }

    const existing = findSaveCandidate(items, capture.origin, capture.username, matchesOrigin);
    if (existing !== null) {
      const cipher = raw.get(existing.id);
      if (cipher !== undefined) {
        const details = await decryptCipherDetails(cipher, keys, onDecryptError);
        if (details.password === capture.password) {
          await dismissProposal();
          return;
        }
      }
    }
    setProposal({ capture, existing });
  }

  /** Oublie la proposition en cours : capture purgée, pastille éteinte. */
  async function dismissProposal(): Promise<void> {
    setProposal(null);
    await clearPendingSave();
    await setSaveBadge(false);
  }

  /** « Ne plus proposer pour ce site » — l'hôte rejoint la liste d'exclusion. */
  async function onNeverForHost(): Promise<void> {
    if (proposal !== null) {
      await addNeverSaveHost(proposal.capture.host);
    }
    await dismissProposal();
  }

  /**
   * Enregistre la capture : création d'un item, ou mise à jour du mot de passe
   * de l'item rapproché.
   *
   * La mise à jour reprend l'item existant tel quel et n'en change que le mot
   * de passe — nom, dossier, notes et champs personnalisés survivent — et
   * consigne l'ancien dans l'historique : un enregistrement automatique ne
   * doit jamais faire perdre ce qui était là avant.
   */
  async function onSaveProposal(): Promise<void> {
    if (vault === null || proposal === null) {
      return;
    }
    const { capture, existing } = proposal;

    setError(null);
    setBusy('Chiffrement…');
    try {
      const auth = await authorize();

      if (existing === null) {
        const payload = await buildCipherCreatePayload(
          {
            name: capture.host,
            username: capture.username,
            password: capture.password,
            totp: '',
            notes: '',
            uris: [capture.origin],
          },
          vault.userKey,
        );
        setBusy('Enregistrement…');
        await auth.client.createCipher(auth.accessToken, payload);
      } else {
        const cipher = vault.raw.get(existing.id);
        if (cipher === undefined) {
          throw new Error('Item introuvable — resynchroniser puis réessayer.');
        }
        const details = await decryptCipherDetails(cipher, vault.keys, (err) => {
          throw err;
        });
        const payload = await buildCipherUpdatePayload(
          cipher,
          {
            name: existing.name ?? capture.host,
            username: details.username ?? capture.username,
            password: capture.password,
            totp: details.totp ?? '',
            notes: details.notes ?? '',
            uris: existing.uris.length > 0 ? existing.uris : [capture.origin],
          },
          vault.keys,
          true,
        );
        setBusy('Enregistrement…');
        await auth.client.updateCipher(auth.accessToken, existing.id, payload);
      }

      await dismissProposal();
      await refreshAfterWrite(auth, vault.userKey);
    } catch (err) {
      setError(messageFor(err));
    } finally {
      setBusy(null);
    }
  }

  /**
   * Vérifie une saisie du mot de passe maître, **sans réseau**.
   *
   * Le hash local conservé au déverrouillage sert de témoin : on redérive la
   * clé maître depuis la saisie et on compare en temps constant
   * (`verifyLocalPasswordHash`). Rien ne part vers le serveur — un `reprompt`
   * doit fonctionner hors ligne, et le faire valider à distance offrirait à
   * qui contrôle le réseau le pouvoir de le désarmer.
   *
   * La clé maître redérivée est détruite aussitôt : elle ne sert qu'à comparer.
   */
  async function verifyMasterPassword(candidate: string): Promise<boolean> {
    const stored = await loadStoredSession();
    if (stored === null) {
      throw new Error('Session expirée — verrouiller puis déverrouiller.');
    }
    const masterKey = await deriveMasterKey(candidate, stored.email, stored.kdfConfig);
    try {
      return await verifyLocalPasswordHash(masterKey, candidate, stored.localPasswordHash);
    } finally {
      masterKey.destroy();
    }
  }

  /**
   * Exécute une action qui sort un secret du coffre, derrière la garde de
   * l'item.
   *
   * Item sans garde : l'action part immédiatement, rien ne change. Item marqué
   * `reprompt` : elle est suspendue jusqu'à vérification. Le point important
   * est que la garde se pose **avant** `detailsOf` — donc avant tout
   * déchiffrement : un secret protégé n'est pas déchiffré puis caché, il n'est
   * pas déchiffré du tout.
   */
  function guarded(item: CipherOverview, run: () => void | Promise<void>): void {
    if (!item.reprompt) {
      void run();
      return;
    }
    setReprompt({ item, run, password: '', error: null, busy: false });
  }

  /** Valide la saisie et relance l'action suspendue. */
  async function onConfirmReprompt(event: Event): Promise<void> {
    event.preventDefault();
    const en_cours = reprompt;
    if (en_cours === null || en_cours.busy) {
      return;
    }
    // La dérivation dure : sans cet état, un second envoi lancerait un
    // deuxième KDF pendant que le premier tourne.
    setReprompt({ ...en_cours, busy: true, error: null });
    try {
      if (!(await verifyMasterPassword(en_cours.password))) {
        setReprompt({
          ...en_cours,
          busy: false,
          password: '',
          error: 'Mot de passe incorrect.',
        });
        return;
      }
      setReprompt(null);
      await en_cours.run();
    } catch (err) {
      setReprompt({ ...en_cours, busy: false, password: '', error: messageFor(err) });
    }
  }

  /**
   * Affiche — et copie — le code à usage unique d'un item.
   *
   * Le secret TOTP est déchiffré à la demande, comme le mot de passe : la
   * règle du déchiffrement partiel (`docs/EXTENSION.md` §3) vaut pour lui.
   * Un second clic referme.
   *
   * La copie est immédiate parce qu'un code à six chiffres n'est jamais
   * consulté pour le plaisir : on le veut dans le presse-papiers, et il aura
   * expiré avant qu'on ait fini de le recopier à la main.
   */
  function onToggleOtp(item: CipherOverview): void {
    // Refermer n'expose rien : la garde ne porte que sur l'ouverture.
    if (otp?.id === item.id) {
      setOtp(null);
      return;
    }
    guarded(item, () => doShowOtp(item));
  }

  async function doShowOtp(item: CipherOverview): Promise<void> {
    const secret = (await detailsOf(item))?.totp ?? null;
    if (secret === null) {
      return;
    }
    try {
      const config = parseTotp(secret);
      const code = await generateTotp(config);
      setOtp({ id: item.id, config, code, remaining: secondsRemaining(config) });
      void noteUsage(item);
      await copyOtp(code);
    } catch (err) {
      setError(messageFor(err));
    }
  }

  /**
   * Programme l'effacement du presse-papiers après le délai configuré.
   *
   * Best-effort, et c'est assumé : le minuteur meurt avec la popup.
   * L'effacement fiable après fermeture passera par un document offscreen
   * (`docs/EXTENSION.md`). Factorisé parce que les trois copies — mot de
   * passe, code à usage unique, mot de passe engendré — doivent suivre la même
   * règle, et qu'en dupliquer la condition était déjà la raison pour laquelle
   * le code à usage unique y échappait.
   */
  function scheduleClipboardClear(): void {
    if (settings.clipboardClearSeconds > 0) {
      setTimeout(() => {
        void navigator.clipboard.writeText('');
      }, settings.clipboardClearSeconds * 1000);
    }
  }

  async function copyOtp(code: string): Promise<void> {
    await navigator.clipboard.writeText(code);
    setCopiedOtp(true);
    setTimeout(() => setCopiedOtp(false), 1500);
    scheduleClipboardClear();
  }

  /**
   * Rafraîchit le code affiché à la seconde.
   *
   * Recalculé plutôt que décompté : un minuteur JavaScript dérive, et la
   * popup peut être gelée par le navigateur. Se caler sur l'horloge à chaque
   * battement garantit qu'un code affiché est bien celui de la fenêtre en
   * cours — afficher un code périmé serait pire que ne rien afficher.
   */
  useEffect(() => {
    if (otp === null) {
      return;
    }
    const timer = setInterval(() => {
      void (async () => {
        const code = await generateTotp(otp.config);
        setOtp((current) =>
          current === null || current.id !== otp.id
            ? current
            : { ...current, code, remaining: secondsRemaining(current.config) },
        );
      })();
    }, 1000);
    return () => clearInterval(timer);
  }, [otp?.id, otp?.config]);

  /**
   * Enregistre les options du générateur, une fois la main relevée.
   *
   * Le curseur de longueur émet un événement par cran : glisser de 8 à 128
   * déclencherait cent vingt écritures de stockage pour une seule intention.
   * Le tirage, lui, reste immédiat — c'est le retour visuel.
   */
  function persistGeneratorOptions(options: PasswordOptions): void {
    if (generatorSaveTimer.current !== undefined) {
      clearTimeout(generatorSaveTimer.current);
    }
    generatorSaveTimer.current = window.setTimeout(() => {
      generatorSaveTimer.current = undefined;
      void saveGeneratorOptions(options);
    }, GENERATOR_SAVE_DELAY_MS);
  }

  /** Ouvre le générateur, options persistées rechargées, premier tirage fait. */
  async function openGenerator(target: 'edit' | 'standalone'): Promise<void> {
    const options = await loadGeneratorOptions();
    setError(null);
    try {
      setGenerator({ options, password: generatePassword(options), target });
    } catch (err) {
      setError(messageFor(err));
    }
  }

  /**
   * Applique un changement d'options : nouveau tirage immédiat, réglages
   * persistés. Régénérer à chaque coche évite l'état incohérent où l'écran
   * montre un mot de passe qui ne correspond plus aux cases affichées.
   */
  function patchGenerator(patch: Partial<PasswordOptions>): void {
    if (generator === null) {
      return;
    }
    const options = { ...generator.options, ...patch };
    persistGeneratorOptions(options);
    try {
      setGenerator({ ...generator, options, password: generatePassword(options) });
      setError(null);
    } catch (err) {
      // Toutes les cases décochées : on garde les options (l'utilisateur est
      // en train d'en recocher une) mais on ne prétend pas avoir engendré.
      setGenerator({ ...generator, options, password: '' });
      setError(messageFor(err));
    }
  }

  async function onCopyGenerated(): Promise<void> {
    if (generator === null || generator.password === '') {
      return;
    }
    await navigator.clipboard.writeText(generator.password);
    setCopiedGenerated(true);
    setTimeout(() => setCopiedGenerated(false), 1500);
    scheduleClipboardClear();
  }

  /** Réinjecte le mot de passe engendré dans le formulaire d'édition ouvert. */
  function onUseGenerated(): void {
    if (generator === null || generator.password === '') {
      return;
    }
    setEditForm({ ...editForm, password: generator.password });
    // Affiché : on vient de le fabriquer, le masquer n'a plus de sens et
    // laisserait un doute sur ce qui sera enregistré.
    setEditShowPassword(true);
    setGenerator(null);
  }

  /** Rend le panneau du générateur, ou rien. Même outil dans les deux vues. */
  function renderGenerator() {
    if (generator === null) {
      return null;
    }
    return (
      <PanneauGenerateur
        state={generator}
        copie={copiedGenerated}
        onPatch={patchGenerator}
        onRegenerate={() => patchGenerator({})}
        onCopy={() => void onCopyGenerated()}
        onUse={onUseGenerated}
        onClose={() => setGenerator(null)}
      />
    );
  }

  /**
   * Note l'usage d'un item : il remontera en tête à la prochaine ouverture.
   *
   * Appelé sur toute action qui sort réellement un secret du coffre — copie,
   * remplissage, révélation. Ouvrir l'édition n'en est pas une : on y va pour
   * corriger une faute de frappe aussi souvent que pour s'en servir.
   */
  async function noteUsage(item: CipherOverview): Promise<void> {
    await markUsed(item.id);
  }

  function onCopyPassword(item: CipherOverview): void {
    guarded(item, () => doCopyPassword(item));
  }

  async function doCopyPassword(item: CipherOverview): Promise<void> {
    const motDePasse = (await detailsOf(item))?.password ?? null;
    if (motDePasse !== null) {
      await navigator.clipboard.writeText(motDePasse);
      void noteUsage(item);
      setCopiedId(item.id);
      setTimeout(() => setCopiedId(null), 1500);
      scheduleClipboardClear();
    }
  }

  async function onCopyUsername(item: CipherOverview): Promise<void> {
    if (item.username !== null) {
      await navigator.clipboard.writeText(item.username);
      void noteUsage(item);
      setCopiedUserId(item.id);
      setTimeout(() => setCopiedUserId(null), 1500);
    }
  }

  /** Minuteur d'auto-masquage du mot de passe révélé. */
  const revealTimer = useRef<number | undefined>(undefined);
  const generatorSaveTimer = useRef<number | undefined>(undefined);

  function clearRevealTimer(): void {
    if (revealTimer.current !== undefined) {
      clearTimeout(revealTimer.current);
      revealTimer.current = undefined;
    }
  }

  function onToggleReveal(item: CipherOverview): void {
    clearRevealTimer();
    // Masquer n'expose rien : seule la révélation est gardée.
    if (revealed?.id === item.id) {
      setRevealed(null);
      return;
    }
    guarded(item, () => doReveal(item));
  }

  async function doReveal(item: CipherOverview): Promise<void> {
    const motDePasse = (await detailsOf(item))?.password ?? null;
    if (motDePasse !== null) {
      void noteUsage(item);
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
    // L'origine d'abord, la garde ensuite : demander un mot de passe pour
    // ensuite refuser le remplissage serait le pire des deux ordres.
    guarded(item, () => doFill(item, tab));
  }

  async function doFill(item: CipherOverview, tab: { tabId: number }): Promise<void> {
    const details = await detailsOf(item);
    if (details === null || (details.username === null && details.password === null)) {
      return;
    }

    await chrome.scripting.executeScript({
      target: { tabId: tab.tabId },
      func: fillCredentials,
      args: [details.username ?? '', details.password ?? ''],
    });
    // Attendu, pas lancé en fond : `window.close()` tue la popup avant que
    // l'écriture ne parte, et l'usage le plus fréquent serait le seul à ne
    // jamais être compté.
    await noteUsage(item);
    window.close();
  }

  /** Ouvre l'écran d'édition, prérempli avec les valeurs déchiffrées. */
  function onEdit(item: CipherOverview): void {
    // Le formulaire affiche le mot de passe en clair dans son champ : c'est
    // une sortie de secret comme une autre.
    guarded(item, () => doEdit(item));
  }

  async function doEdit(item: CipherOverview): Promise<void> {
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

  /**
   * Session écrivable : client API et jetons rafraîchis si besoin.
   *
   * Toute écriture (édition, enregistrement d'une capture) commence par là.
   * Le jeton d'accès expire en ~1 h ; le renouveler au moment d'écrire évite
   * un 401 sur un geste que l'utilisateur croit abouti.
   *
   * @throws {Error} Session absente — le coffre a été verrouillé entre-temps.
   */
  async function authorize(): Promise<AuthorizedSession> {
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
      // Persistés **avant** l'écriture qu'ils autorisent. Un serveur qui fait
      // tourner les jetons de rafraîchissement a déjà invalidé l'ancien : si
      // l'appel suivant échoue et qu'on n'a rien enregistré, la session est
      // morte et il faut tout redéverrouiller pour un simple échec réseau.
      await saveStoredSession({ ...stored, accessToken, refreshToken, expiresAt });
    }
    return { client, stored, accessToken, refreshToken, expiresAt };
  }

  /**
   * Resynchronise après une écriture, met le cache à jour et réaffiche la
   * liste. Sans cela, la popup montrerait encore l'état d'avant l'écriture.
   */
  async function refreshAfterWrite(auth: AuthorizedSession, userKey: SymmetricCryptoKey): Promise<void> {
    setBusy('Synchronisation…');
    const sync = await auth.client.sync(auth.accessToken);
    await saveStoredSession({
      userKeyB64: auth.stored.userKeyB64,
      accessToken: auth.accessToken,
      refreshToken: auth.refreshToken,
      expiresAt: auth.expiresAt,
      serverUrl: auth.stored.serverUrl,
      email: auth.stored.email,
      cachedSync: sync,
      localPasswordHash: auth.stored.localPasswordHash,
      kdfConfig: auth.stored.kdfConfig,
    });
    await showVault(sync, userKey, false);
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
      const auth = await authorize();

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
      await auth.client.updateCipher(auth.accessToken, editing.id, payload);
      await refreshAfterWrite(auth, vault.userKey);

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
                  <button
                    type="button"
                    class="oeil de"
                    title="Générer un mot de passe"
                    onClick={() => void openGenerator('edit')}
                  >
                    <IconDe />
                  </button>
                </div>
              </label>
            )}
            {/* Hors du `<label>` : imbriquer des champs dans le libellé d'un
                autre ferait basculer la case cochée dans le panneau sur le
                champ mot de passe. */}
            {renderGenerator()}
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
          <button
            class="discret"
            title="Générer un mot de passe"
            onClick={() => void openGenerator('standalone')}
          >
            Générer
          </button>
          <button class="discret" onClick={openOptions}>
            Paramètres
          </button>
          <button class="discret" onClick={onLock}>
            Verrouiller
          </button>
        </div>
      </header>
      <main>
        {reprompt !== null && (
          /* Superposition, pas un bandeau : une demande de mot de passe maître
             doit être sans ambiguïté sur ce qu'elle protège et sur ce qui
             attend derrière. */
          <div class="voile">
            <form class="reprompt" onSubmit={(e) => void onConfirmReprompt(e)}>
              <p class="reprompt-titre">Mot de passe maître requis</p>
              <p class="reprompt-detail">
                « {reprompt.item.name ?? 'Cet item'} » est protégé par une nouvelle saisie.
              </p>
              <input
                type="password"
                autofocus
                autocomplete="off"
                value={reprompt.password}
                disabled={reprompt.busy}
                placeholder="Mot de passe maître"
                onInput={(e) => setReprompt({ ...reprompt, password: e.currentTarget.value })}
              />
              {reprompt.error !== null && <p class="reprompt-erreur">{reprompt.error}</p>}
              <div class="reprompt-actions">
                <button type="submit" disabled={reprompt.busy || reprompt.password === ''}>
                  {reprompt.busy ? 'Vérification…' : 'Déverrouiller'}
                </button>
                <button
                  type="button"
                  class="discret"
                  disabled={reprompt.busy}
                  onClick={() => setReprompt(null)}
                >
                  Annuler
                </button>
              </div>
            </form>
          </div>
        )}
        {renderGenerator()}
        {proposal !== null && (
          <section class="proposition">
            <p class="proposition-titre">
              {proposal.existing === null
                ? `Enregistrer les identifiants pour ${proposal.capture.host} ?`
                : `Mettre à jour le mot de passe de « ${proposal.existing.name ?? proposal.capture.host} » ?`}
            </p>
            <p class="proposition-detail">
              {proposal.capture.username === ''
                ? '(identifiant non détecté — à compléter après enregistrement)'
                : proposal.capture.username}
              {' — '}
              {/* Longueur plafonnée : elle n'apprend rien à l'utilisateur et
                  en dit trop à qui regarde par-dessus son épaule. */}
              {'•'.repeat(Math.min(proposal.capture.password.length, 12))}
            </p>
            <div class="proposition-actions">
              <button disabled={busy !== null} onClick={() => void onSaveProposal()}>
                Enregistrer
              </button>
              <button class="discret" onClick={() => void dismissProposal()}>
                Ignorer
              </button>
              <button
                class="discret"
                title={`Ne plus rien proposer pour ${proposal.capture.host}`}
                onClick={() => void onNeverForHost()}
              >
                Ne plus proposer ici
              </button>
            </div>
          </section>
        )}
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
                  {item.hasTotp && (
                    <button
                      class="discret oeil-item"
                      title={
                        otp?.id === item.id
                          ? 'Masquer le code'
                          : 'Code à usage unique — l’affiche et le copie'
                      }
                      onClick={() => void onToggleOtp(item)}
                    >
                      <IconOtp />
                    </button>
                  )}
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
                {otp?.id === item.id && (
                  <div class="otp" title="Copier le code" onClick={() => void copyOtp(otp.code)}>
                    <span class="otp-code">{formatTotp(otp.code)}</span>
                    <span class="otp-fin">
                      {copiedOtp && <span class="otp-copie">copié !</span>}
                      <AnneauOtp remaining={otp.remaining} period={otp.config.period} />
                    </span>
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </main>
    </div>
  );
}

render(<App />, document.getElementById('app')!);
