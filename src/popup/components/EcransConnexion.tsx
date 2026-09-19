/**
 * @file Les deux écrans d'avant-coffre : déverrouillage et second facteur.
 *
 * Réunis dans un fichier parce qu'ils forment une seule séquence — le second
 * facteur n'apparaît qu'après une première tentative — et partagent l'en-tête
 * et la restitution d'erreur.
 *
 * Aucun des deux ne détient de secret au-delà de la frappe en cours : ils
 * remontent la saisie, et c'est `App` qui appelle `unlock()`.
 */

import { IconOeil } from './Icons.js';

/** En-tête commun : le nom, et l'accès aux paramètres. */
function EnTete({ onOptions }: { onOptions: () => void }) {
  return (
    <header>
      <h1>Zwarden</h1>
      <button class="discret" onClick={onOptions}>
        Paramètres
      </button>
    </header>
  );
}

/** Messages d'état et d'erreur, dans cet ordre, sous le formulaire. */
function Statut({ busy, error }: { busy: string | null; error: string | null }) {
  return (
    <>
      {busy !== null && <p class="statut">{busy}</p>}
      {error !== null && <p class="erreur">{error}</p>}
    </>
  );
}

export function EcranDeverrouillage({
  serverUrl,
  email,
  password,
  showPassword,
  busy,
  error,
  onServerUrl,
  onEmail,
  onPassword,
  onToggleShowPassword,
  onSubmit,
  onOptions,
}: {
  serverUrl: string;
  email: string;
  password: string;
  showPassword: boolean;
  busy: string | null;
  error: string | null;
  onServerUrl: (value: string) => void;
  onEmail: (value: string) => void;
  onPassword: (value: string) => void;
  onToggleShowPassword: () => void;
  onSubmit: () => void;
  onOptions: () => void;
}) {
  return (
    <div>
      <EnTete onOptions={onOptions} />
      <main>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            onSubmit();
          }}
        >
          <label>
            Serveur
            <input
              type="url"
              placeholder="https://coffre.exemple.fr"
              value={serverUrl}
              onInput={(e) => onServerUrl(e.currentTarget.value)}
              required
            />
          </label>
          <label>
            E-mail
            <input
              type="email"
              value={email}
              onInput={(e) => onEmail(e.currentTarget.value)}
              required
            />
          </label>
          <label>
            Mot de passe maître
            <div class="champ-mdp">
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onInput={(e) => onPassword(e.currentTarget.value)}
                required
              />
              <button
                type="button"
                class="oeil"
                title={showPassword ? 'Masquer le mot de passe' : 'Afficher le mot de passe'}
                onClick={onToggleShowPassword}
              >
                <IconOeil barre={showPassword} />
              </button>
            </div>
          </label>
          <button type="submit" disabled={busy !== null}>
            Déverrouiller
          </button>
        </form>
        <Statut busy={busy} error={error} />
      </main>
    </div>
  );
}

export function EcranSecondFacteur({
  saisissables,
  libelles,
  choice,
  code,
  remember,
  busy,
  error,
  onChoice,
  onCode,
  onRemember,
  onSubmit,
  onBack,
  onOptions,
}: {
  /** Fournisseurs dont la popup sait recueillir le code. */
  saisissables: readonly string[];
  libelles: Readonly<Record<string, string>>;
  choice: string;
  code: string;
  remember: boolean;
  busy: string | null;
  error: string | null;
  onChoice: (value: string) => void;
  onCode: (value: string) => void;
  onRemember: (value: boolean) => void;
  onSubmit: () => void;
  onBack: () => void;
  onOptions: () => void;
}) {
  return (
    <div>
      <EnTete onOptions={onOptions} />
      <main>
        <p class="statut">Authentification à deux facteurs requise.</p>
        {saisissables.length === 0 ? (
          <p class="erreur">
            Seul WebAuthn est proposé par ce compte, et il n’est pas encore pris en charge.
            Activer le mode OTP de la YubiKey ou le TOTP sur le serveur.
          </p>
        ) : (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              onSubmit();
            }}
          >
            <label>
              Méthode
              <select value={choice} onInput={(e) => onChoice(e.currentTarget.value)}>
                {saisissables.map((p) => (
                  <option key={p} value={p}>
                    {libelles[p]}
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
                value={code}
                onInput={(e) => onCode(e.currentTarget.value)}
                required
              />
            </label>
            <label class="ligne">
              <input
                type="checkbox"
                checked={remember}
                onInput={(e) => onRemember(e.currentTarget.checked)}
              />
              Se souvenir de cet appareil
            </label>
            <button type="submit" disabled={busy !== null || code.trim() === ''}>
              Valider
            </button>
          </form>
        )}
        <button class="discret" onClick={onBack}>
          ← Retour
        </button>
        <Statut busy={busy} error={error} />
      </main>
    </div>
  );
}
