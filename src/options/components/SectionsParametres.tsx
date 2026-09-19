/**
 * @file Sections du formulaire de paramètres.
 *
 * Découpées par sujet, comme elles le sont à l'écran. Chacune reçoit les
 * paramètres courants et remonte une modification partielle : aucune ne lit ni
 * n'écrit le stockage, ce qui laisse `App` seul responsable de l'enregistrement
 * et de son message de confirmation.
 */

import { type AppSettings, DEFAULT_SETTINGS } from '@shared/storage.js';

/** Une modification partielle des paramètres, remontée à `App`. */
export type PatchSettings = (patch: Partial<AppSettings>) => void;

/** Valeurs proposées pour le verrouillage automatique, en minutes. */
const AUTOLOCK_CHOICES: ReadonlyArray<readonly [number, string]> = [
  [0, 'À la fermeture du navigateur'],
  [1, '1 minute'],
  [5, '5 minutes'],
  [15, '15 minutes'],
  [30, '30 minutes'],
  [60, '1 heure'],
  [240, '4 heures'],
];

/** Valeurs proposées pour l'effacement du presse-papiers, en secondes. */
const CLIPBOARD_CHOICES: ReadonlyArray<readonly [number, string]> = [
  [10, '10 secondes'],
  [30, '30 secondes'],
  [60, '1 minute'],
  [0, 'Jamais'],
];

/** Instance, compte, nom d'appareil et délai réseau. */
export function SectionServeur({ settings, patch }: { settings: AppSettings; patch: PatchSettings }) {
  return (
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

  );
}

/** Verrouillage automatique et effacement du presse-papiers. */
export function SectionSecurite({ settings, patch }: { settings: AppSettings; patch: PatchSettings }) {
  return (
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
          « Inactivité » : aucun changement d’onglet, de fenêtre ni de page, et popup fermée.
          Naviguer suffit donc à garder le coffre ouvert. Le verrouillage peut tarder d’une
          minute sur le délai choisi. À la fermeture du navigateur, le coffre est de toute
          façon verrouillé : la clé ne vit qu’en mémoire.
        </p>
        <label class="ligne">
          <input
            type="checkbox"
            checked={settings.lockOnSystemLock}
            onInput={(e) => patch({ lockOnSystemLock: e.currentTarget.checked })}
          />
          Verrouiller aussi quand la session de l’ordinateur se verrouille
        </label>
        <p class="aide">
          Écran de verrouillage, veille, « Win+L » : le coffre se verrouille immédiatement,
          quel que soit le délai ci-dessus. S’éloigner de sa machine est plus fréquent que
          fermer son navigateur.
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

  );
}

/** Proposition d'enregistrer un identifiant saisi. */
export function SectionEnregistrement({ settings, patch }: { settings: AppSettings; patch: PatchSettings }) {
  return (
    <section>
      <h2>Enregistrement des identifiants</h2>
      <div class="champs">
        <label class="ligne">
          <input
            type="checkbox"
            checked={settings.offerToSave}
            onInput={(e) => patch({ offerToSave: e.currentTarget.checked })}
          />
          Proposer d’enregistrer un identifiant saisi sur un site inconnu
        </label>
        <p class="aide">
          Un détecteur observe les formulaires de connexion et signale une saisie par une
          pastille sur l’icône ; la proposition s’affiche à l’ouverture de la popup. Rien
          n’est ajouté au coffre sans un clic, rien n’est injecté dans la page, et rien
          n’est envoyé ailleurs qu’à l’extension. Décoché, le détecteur n’est pas injecté du
          tout — pas un script silencieux, aucun script.
        </p>
      </div>
    </section>

  );
}

