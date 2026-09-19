/**
 * @file Page de paramètres.
 *
 * Édite les préférences durables (`chrome.storage.local`) et offre les actions
 * d'hygiène : verrouiller, oublier les dispenses 2FA ou le classement d'usage,
 * régénérer l'identifiant d'appareil. Aucune clé ni mot de passe ne transite par
 * cette page.
 *
 * Ce fichier ne fait qu'assembler : l'état et les actions vivent dans
 * `useParametres`, le rendu dans `components/`.
 */

import { render } from 'preact';

import { SectionActions, SectionAppareil } from './components/SectionsActions.js';
import {
  SectionEnregistrement,
  SectionSecurite,
  SectionServeur,
} from './components/SectionsParametres.js';
import { useParametres } from './hooks/useParametres.js';

/** Version affichée. `dev` hors contexte d'extension (aperçu Vite). */
function appVersion(): string {
  if (typeof chrome !== 'undefined' && typeof chrome.runtime?.getManifest === 'function') {
    return chrome.runtime.getManifest().version;
  }
  return 'dev';
}

function App() {
  const p = useParametres();

  return (
    <div class="page">
      <h1>Zwarden — Paramètres</h1>
      <p class="version">Version {appVersion()}</p>

      <form onSubmit={(e) => void p.save(e)}>
        <SectionServeur settings={p.settings} patch={p.patch} />
        <SectionSecurite settings={p.settings} patch={p.patch} />
        <SectionEnregistrement settings={p.settings} patch={p.patch} />

        <button type="submit">Enregistrer</button>
        <p class="statut">{p.statut}</p>
      </form>

      <SectionActions
        onLockNow={() => void p.lockNow()}
        onForgetTwoFa={() => void p.forgetTwoFa()}
        onForgetNeverSave={() => void p.forgetNeverSave()}
        onForgetLastUsed={() => void p.forgetLastUsed()}
      />

      <SectionAppareil deviceId={p.deviceId} onRegenerate={() => void p.regenerateDevice()} />
    </div>
  );
}

render(<App />, document.getElementById('app')!);
