/**
 * @file Code à usage unique : l'anneau de décompte, et le battement.
 *
 * ## Pourquoi le battement vit ici et non dans `App`
 *
 * Le code se recalcule chaque seconde. Tant que cet état vivait dans `App`,
 * chaque battement réaffichait la popup entière — filtrage de tout le coffre et
 * comparaison de l'arbre complet, une fois par seconde. En le confinant au
 * composant qui l'affiche, le battement ne réaffiche plus que lui.
 *
 * ## Recalculé, jamais décompté
 *
 * Un minuteur JavaScript dérive, et la popup peut être gelée par le navigateur.
 * Se caler sur l'horloge à chaque battement garantit qu'un code affiché est bien
 * celui de la fenêtre en cours — afficher un code périmé serait pire que ne rien
 * afficher.
 */

import { useEffect, useState } from 'preact/hooks';

import { type TotpConfig, formatTotp, generateTotp, secondsRemaining } from '@core/vault/totp.js';

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
export function AnneauOtp({ remaining, period }: { remaining: number; period: number }) {
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


/**
 * Code à usage unique d'un item, avec son décompte.
 *
 * @param config Paramètres résolus, déjà déchiffrés par l'appelant : ce
 *   composant ne touche jamais au coffre.
 * @param onCopy Recopie le code — l'appelant y ajoute son propre retour visuel.
 * @param copie Vrai brièvement après une copie.
 */
export function CodeOtp({
  config,
  onCopy,
  copie,
}: {
  config: TotpConfig;
  onCopy: (code: string) => void;
  copie: boolean;
}) {
  const [code, setCode] = useState('');
  const [remaining, setRemaining] = useState(() => secondsRemaining(config));

  useEffect(() => {
    let vivant = true;
    const battre = async (): Promise<void> => {
      const calcule = await generateTotp(config);
      if (vivant) {
        setCode(calcule);
        setRemaining(secondsRemaining(config));
      }
    };
    void battre();
    const timer = setInterval(() => void battre(), 1000);
    return () => {
      vivant = false;
      clearInterval(timer);
    };
  }, [config]);

  if (code === '') {
    return null;
  }

  return (
    <div class="otp" title="Copier le code" onClick={() => onCopy(code)}>
      <span class="otp-code">{formatTotp(code)}</span>
      <span class="otp-fin">
        {copie && <span class="otp-copie">copié !</span>}
        <AnneauOtp remaining={remaining} period={config.period} />
      </span>
    </div>
  );
}
