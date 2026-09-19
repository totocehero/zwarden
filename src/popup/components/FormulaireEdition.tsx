/**
 * @file Formulaire d'édition d'un item.
 *
 * Purement présentationnel : il reçoit des valeurs en clair déjà déchiffrées
 * par `App`, et remonte chaque frappe. Il ne chiffre rien, n'appelle pas le
 * réseau et ne sait pas ce qu'est une clé — ce qui le met hors de la logique de
 * coffre (`docs/EXTENSION.md` §3).
 *
 * Les champs propres à une connexion (identifiant, mot de passe, TOTP, URIs)
 * n'apparaissent que pour le type 1 : les afficher vides sur une note sécurisée
 * laisserait croire qu'ils y sont enregistrables.
 */

import type { JSX } from 'preact';

import type { PasskeyView } from '@core/vault/cipherService.js';

import { IconDe, IconOeil } from './Icons.js';

/** Valeurs en clair du formulaire. */
export interface EditForm {
  name: string;
  username: string;
  password: string;
  totp: string;
  notes: string;
  /** Une URI par ligne. */
  uris: string;
}

export const EMPTY_EDIT: EditForm = {
  name: '',
  username: '',
  password: '',
  totp: '',
  notes: '',
  uris: '',
};

export function FormulaireEdition({
  form,
  estLogin,
  showPassword,
  passkeys,
  busy,
  error,
  generateur,
  onPatch,
  onToggleShowPassword,
  onOpenGenerator,
  onSubmit,
  onCancel,
}: {
  form: EditForm;
  estLogin: boolean;
  showPassword: boolean;
  passkeys: readonly PasskeyView[];
  busy: string | null;
  error: string | null;
  /** Panneau du générateur, rendu par l'appelant — ou rien s'il est fermé. */
  generateur: JSX.Element | null;
  onPatch: (patch: Partial<EditForm>) => void;
  onToggleShowPassword: () => void;
  onOpenGenerator: () => void;
  onSubmit: (event: Event) => void;
  onCancel: () => void;
}) {
  return (
    <div>
      <header>
        <h1>Zwarden</h1>
        <button class="discret" onClick={onCancel}>
          ← Annuler
        </button>
      </header>
      <main>
        <form onSubmit={onSubmit}>
          <label>
            Nom
            <input
              type="text"
              value={form.name}
              onInput={(e) => onPatch({ name: e.currentTarget.value })}
              required
            />
          </label>
          {estLogin && (
            <label>
              Identifiant
              <input
                type="text"
                value={form.username}
                onInput={(e) => onPatch({ username: e.currentTarget.value })}
              />
            </label>
          )}
          {estLogin && (
            <label>
              Mot de passe
              <div class="champ-mdp">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={form.password}
                  onInput={(e) => onPatch({ password: e.currentTarget.value })}
                />
                <button
                  type="button"
                  class="oeil"
                  title={showPassword ? 'Masquer' : 'Afficher'}
                  onClick={onToggleShowPassword}
                >
                  <IconOeil barre={showPassword} />
                </button>
                <button
                  type="button"
                  class="oeil de"
                  title="Générer un mot de passe"
                  onClick={onOpenGenerator}
                >
                  <IconDe />
                </button>
              </div>
            </label>
          )}
          {/* Hors du `<label>` : imbriquer des champs dans le libellé d'un autre
              ferait basculer la case cochée dans le panneau sur le champ mot de
              passe. */}
          {generateur}
          {estLogin && (
            <label>
              TOTP (clé ou otpauth://)
              <input
                type="text"
                value={form.totp}
                onInput={(e) => onPatch({ totp: e.currentTarget.value })}
              />
            </label>
          )}
          {estLogin && (
            <label>
              URIs (une par ligne)
              <textarea
                rows={2}
                value={form.uris}
                onInput={(e) => onPatch({ uris: e.currentTarget.value })}
              />
            </label>
          )}
          <label>
            Notes
            <textarea
              rows={3}
              value={form.notes}
              onInput={(e) => onPatch({ notes: e.currentTarget.value })}
            />
          </label>
          {passkeys.length > 0 && (
            <div class="passkeys-info">
              {passkeys.map((pk, i) => (
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
