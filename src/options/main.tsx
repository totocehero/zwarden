/**
 * @file Page de paramètres.
 *
 * Édite les préférences durables (`chrome.storage.local`) et offre les
 * actions d'hygiène : verrouiller, oublier les dispenses 2FA, régénérer
 * l'identifiant d'appareil. Aucune clé ni mot de passe ne transite par cette
 * page.
 */

import { render } from 'preact';
import { useEffect, useState } from 'preact/hooks';

import {
  type AppSettings,
  DEFAULT_SETTINGS,
  cancelAutoLock,
  clearAllRememberTokens,
  clearStoredSession,
  getDeviceId,
  loadSettings,
  regenerateDeviceId,
  saveSettings,
} from '@shared/storage.js';

/** Valeurs proposées pour le verrouillage automatique, en minutes. */
const AUTOLOCK_CHOICES: ReadonlyArray<readonly [number, string]> = [
  [1, '1 minute'],
  [5, '5 minutes'],
  [15, '15 minutes'],
  [30, '30 minutes'],
  [60, '1 heure'],
  [0, 'Jamais (fermeture du navigateur)'],
];

/** Valeurs proposées pour l'effacement du presse-papiers, en secondes. */
const CLIPBOARD_CHOICES: ReadonlyArray<readonly [number, string]> = [
  [10, '10 secondes'],
  [30, '30 secondes'],
  [60, '1 minute'],
  [0, 'Jamais'],
];

function appVersion(): string {
  if (typeof chrome !== 'undefined' && typeof chrome.runtime?.getManifest === 'function') {
    return chrome.runtime.getManifest().version;
  }
  return 'dev';
}

function App() {
  const [settings, setSettings] = useState<AppSettings>(DEFAULT_SETTINGS);
  const [deviceId, setDeviceId] = useState('');
  const [statut, setStatut] = useState('');

  useEffect(() => {
    void (async () => {
      setSettings(await loadSettings());
      setDeviceId(await getDeviceId());
    })();
  }, []);

  function flash(message: string): void {
    setStatut(message);
    setTimeout(() => setStatut(''), 2500);
  }

  function patch(champ: Partial<AppSettings>): void {
    setSettings({ ...settings, ...champ });
  }

  async function onSave(event: Event): Promise<void> {
    event.preventDefault();
    const timeoutSeconds = Math.min(120, Math.max(5, Math.round(settings.timeoutSeconds)));
    const propre = { ...settings, timeoutSeconds };
    setSettings(propre);
    await saveSettings(propre);
    flash('Paramètres enregistrés.');
  }

  async function onLockNow(): Promise<void> {
    await clearStoredSession();
    cancelAutoLock();
    flash('Coffre verrouillé.');
  }

  async function onForgetTwoFa(): Promise<void> {
    const n = await clearAllRememberTokens();
    flash(
      n === 0
        ? 'Aucune dispense 2FA à oublier.'
        : `${n} dispense(s) 2FA oubliée(s) — le second facteur sera redemandé.`,
    );
  }

  async function onRegenerateDevice(): Promise<void> {
    const ok = confirm(
      'Régénérer l’identifiant d’appareil ?\n\n' +
        'Le serveur verra un nouvel appareil : une session supplémentaire apparaîtra ' +
        'dans la liste, une alerte « nouvel appareil » peut être envoyée, et les ' +
        'dispenses 2FA de cet appareil deviendront invalides.',
    );
    if (!ok) {
      return;
    }
    setDeviceId(await regenerateDeviceId());
    await clearAllRememberTokens();
    flash('Identifiant régénéré.');
  }

  return (
    <div class="page">
      <h1>Zwarden — Paramètres</h1>
      <p class="version">Version {appVersion()}</p>

      <form onSubmit={(e) => void onSave(e)}>
        <section>
          <h2>Serveur</h2>
          <div class="champs">
            <label>
              URL de l’instance
              <input
                type="url"
                placeholder="https://coffre.exemple.fr"
                value={settings.serverUrl}
                onInput={(e) => patch({ serverUrl: e.currentTarget.value })}
              />
            </label>
            <label>
              E-mail du compte
              <input
                type="email"
                value={settings.email}
                onInput={(e) => patch({ email: e.currentTarget.value })}
              />
            </label>
            <label>
              Nom de l’appareil (affiché dans les sessions actives du serveur)
              <input
                type="text"
                value={settings.deviceName}
                onInput={(e) => patch({ deviceName: e.currentTarget.value })}
              />
            </label>
            <label>
              Délai réseau (secondes, 5–120)
              <input
                type="number"
                min="5"
                max="120"
                value={settings.timeoutSeconds}
                onInput={(e) => {
                  const n = e.currentTarget.valueAsNumber;
                  patch({ timeoutSeconds: Number.isFinite(n) ? n : DEFAULT_SETTINGS.timeoutSeconds });
                }}
              />
            </label>
          </div>
        </section>

        <section>
          <h2>Sécurité</h2>
          <div class="champs">
            <label>
              Verrouillage automatique après inactivité
              <select
                value={String(settings.autoLockMinutes)}
                onInput={(e) => patch({ autoLockMinutes: Number(e.currentTarget.value) })}
              >
                {AUTOLOCK_CHOICES.map(([minutes, libelle]) => (
                  <option key={minutes} value={String(minutes)}>
                    {libelle}
                  </option>
                ))}
              </select>
            </label>
            <p class="aide">
              « Inactivité » : popup non rouverte. À la fermeture du navigateur, le coffre est
              toujours verrouillé, quel que soit ce réglage.
            </p>
            <label>
              Effacement du presse-papiers après une copie
              <select
                value={String(settings.clipboardClearSeconds)}
                onInput={(e) => patch({ clipboardClearSeconds: Number(e.currentTarget.value) })}
              >
                {CLIPBOARD_CHOICES.map(([secondes, libelle]) => (
                  <option key={secondes} value={String(secondes)}>
                    {libelle}
                  </option>
                ))}
              </select>
            </label>
            <p class="aide">
              Effacement garanti tant que la popup est ouverte ; l’effacement après fermeture
              viendra avec le document offscreen.
            </p>
          </div>
        </section>

        <button type="submit">Enregistrer</button>
        <p class="statut">{statut}</p>
      </form>

      <section>
        <h2>Actions</h2>
        <div class="actions">
          <button class="secondaire" onClick={() => void onLockNow()}>
            Verrouiller le coffre maintenant
          </button>
          <button class="secondaire" onClick={() => void onForgetTwoFa()}>
            Oublier les dispenses 2FA
          </button>
        </div>
      </section>

      <section>
        <h2>Appareil</h2>
        <div class="champs">
          <div>
            <p class="aide">Identifiant transmis au serveur :</p>
            <p class="device-id">{deviceId}</p>
          </div>
          <button class="danger" onClick={() => void onRegenerateDevice()}>
            Régénérer l’identifiant d’appareil
          </button>
        </div>
      </section>
    </div>
  );
}

render(<App />, document.getElementById('app')!);
