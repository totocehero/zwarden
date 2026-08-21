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
import { useEffect, useState } from 'preact/hooks';

import {
  ApiClient,
  TwoFactorRequiredError,
  type TwoFactorSubmission,
} from '@core/api/apiClient.js';
import { TwoFactorProvider, type CipherResponse } from '@core/api/models.js';
import { SymmetricCryptoKey } from '@core/crypto/symmetricCryptoKey.js';
import {
  type CipherOverview,
  decryptCipherDetails,
  decryptCipherList,
} from '@core/vault/cipherService.js';
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
  readonly items: readonly CipherOverview[];
  readonly raw: ReadonlyMap<string, CipherResponse>;
  readonly fieldErrors: number;
}

/** Fournisseurs dont la popup sait recueillir le code. */
const PROVIDER_LABELS: Readonly<Record<string, string>> = {
  [String(TwoFactorProvider.Authenticator)]: 'Application d’authentification (TOTP)',
  [String(TwoFactorProvider.Email)]: 'Code reçu par e-mail',
  [String(TwoFactorProvider.YubiKey)]: 'YubiKey (mode OTP — toucher la clé)',
};

/** Domaine de l'onglet actif, ou `null` hors contexte pertinent. */
async function activeTabHost(): Promise<string | null> {
  if (typeof chrome === 'undefined' || typeof chrome.tabs?.query === 'undefined') {
    return null;
  }
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.url === undefined) {
      return null;
    }
    const url = new URL(tab.url);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return null;
    }
    return url.hostname.replace(/^www\./, '');
  } catch {
    return null;
  }
}

function openOptions(): void {
  if (typeof chrome !== 'undefined' && typeof chrome.runtime?.openOptionsPage === 'function') {
    void chrome.runtime.openOptionsPage();
  }
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
  const [serverUrl, setServerUrl] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [vault, setVault] = useState<OpenVault | null>(null);
  const [filter, setFilter] = useState('');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [copiedUserId, setCopiedUserId] = useState<string | null>(null);
  const [revealed, setRevealed] = useState<{ id: string; password: string } | null>(null);
  const [showPassword, setShowPassword] = useState(false);

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
   * Rafraîchit le jeton d'accès s'il approche de l'expiration. Tout échec
   * (session périmée, jeton révoqué, serveur injoignable) retombe simplement
   * sur l'écran de déverrouillage — c'est un cas normal, pas une erreur à
   * afficher.
   */
  async function restoreSession(s: AppSettings): Promise<void> {
    const stored = await loadStoredSession();
    if (stored === null) {
      return;
    }

    setBusy('Restauration de la session…');
    try {
      const client = makeClient(s, stored.serverUrl, await getDeviceId());

      let accessToken = stored.accessToken;
      if (Date.now() > stored.expiresAt - 60_000) {
        if (stored.refreshToken === null) {
          throw new Error('session expirée sans jeton de rafraîchissement');
        }
        const renewed = await client.refreshToken(stored.refreshToken);
        accessToken = renewed.accessToken;
        await saveStoredSession({
          ...stored,
          accessToken,
          refreshToken: renewed.refreshToken ?? stored.refreshToken,
          expiresAt: renewed.expiresAt,
        });
      }

      setServerUrl(stored.serverUrl);
      setEmail(stored.email);
      await openVaultFrom(client, SymmetricCryptoKey.fromBase64(stored.userKeyB64), accessToken);
      scheduleAutoLock(s.autoLockMinutes);
    } catch {
      await clearStoredSession();
    } finally {
      setBusy(null);
    }
  }

  /** Synchronise, déchiffre les vues de liste et affiche le coffre. */
  async function openVaultFrom(
    client: ApiClient,
    userKey: SymmetricCryptoKey,
    accessToken: string,
  ): Promise<void> {
    setBusy('Synchronisation…');
    const sync = await client.sync(accessToken);
    const ciphers = sync.ciphers ?? [];

    setBusy(`Déchiffrement de ${ciphers.length} item(s)…`);
    let fieldErrors = 0;
    const items = await decryptCipherList(ciphers, userKey, () => {
      fieldErrors++;
    });

    const raw = new Map<string, CipherResponse>();
    for (const cipher of ciphers) {
      raw.set(cipher.id, cipher);
    }

    setVault({ userKey, items, raw, fieldErrors });

    // Filtre prérempli avec le domaine de l'onglet actif — seulement s'il
    // correspond à quelque chose, une liste vide serait déroutante.
    const host = await activeTabHost();
    if (host !== null && items.some((item) => matchesNeedle(item, host))) {
      setFilter(host);
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

      // La session survit à la fermeture de la popup, jusqu'à la fermeture du
      // navigateur, l'échéance d'inactivité ou le verrouillage manuel.
      await saveStoredSession({
        userKeyB64: result.userKey.toBase64(),
        accessToken: result.session.accessToken,
        refreshToken: result.session.refreshToken ?? null,
        expiresAt: result.session.expiresAt,
        serverUrl,
        email,
      });
      scheduleAutoLock(settings.autoLockMinutes);

      await openVaultFrom(client, result.userKey, result.session.accessToken);
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
    setVault(null);
    setFilter('');
    setRevealed(null);
  }

  async function detailsOf(item: CipherOverview): Promise<string | null> {
    if (vault === null) {
      return null;
    }
    const cipher = vault.raw.get(item.id);
    if (cipher === undefined) {
      return null;
    }
    const details = await decryptCipherDetails(cipher, vault.userKey, (err) => {
      setError(messageFor(err));
    });
    return details.password;
  }

  async function onCopyPassword(item: CipherOverview): Promise<void> {
    const motDePasse = await detailsOf(item);
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

  async function onToggleReveal(item: CipherOverview): Promise<void> {
    if (revealed?.id === item.id) {
      setRevealed(null);
      return;
    }
    const motDePasse = await detailsOf(item);
    if (motDePasse !== null) {
      setRevealed({ id: item.id, password: motDePasse });
    }
  }

  function matchesNeedle(item: CipherOverview, needle: string): boolean {
    return (
      (item.name ?? '').toLowerCase().includes(needle) ||
      (item.username ?? '').toLowerCase().includes(needle) ||
      item.uris.some((uri) => uri.toLowerCase().includes(needle))
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

  // --- Liste du coffre ------------------------------------------------------
  const needle = filter.trim().toLowerCase();
  const visible = needle === '' ? vault.items : vault.items.filter((i) => matchesNeedle(i, needle));

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
        {vault.fieldErrors > 0 && (
          <p class="erreur">{vault.fieldErrors} champ(s) illisible(s) — voir la console.</p>
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
                    <div class="item-nom">{item.name ?? '(sans nom)'}</div>
                    {item.username !== null && (
                      <div
                        class="item-user"
                        title="Copier l’identifiant"
                        onClick={() => void onCopyUsername(item)}
                      >
                        {item.username}
                        {copiedUserId === item.id ? ' — copié !' : ''}
                      </div>
                    )}
                    {item.uris[0] !== undefined && <div class="item-uri">{item.uris[0]}</div>}
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
                  <button onClick={() => void onCopyPassword(item)}>
                    {copiedId === item.id ? 'Copié !' : 'Copier'}
                  </button>
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
