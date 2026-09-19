/**
 * @file Détecteur d'identifiants saisis — script de contenu.
 *
 * ## Ce qu'il fait, et rien d'autre
 *
 * Il observe les soumissions de formulaires de la page, et lorsqu'un mot de
 * passe non vide vient d'être saisi, il l'envoie **au service worker de
 * l'extension** — jamais ailleurs. Il n'injecte aucune interface, ne lit
 * jamais le coffre, ne remplit rien : la décision « enregistrer ou non »
 * appartient à la popup, qui seule sait ce que le coffre contient déjà.
 *
 * ## Pourquoi il ne remplit pas
 *
 * Les deux règles d'autofill de `docs/EXTENSION.md` §4 restent entières :
 * aucun remplissage sans geste explicite. Ce script n'écrit rien dans la
 * page, il ne fait que lire ce que l'utilisateur vient lui-même de taper.
 *
 * ## Ce qui reste imparfait, et assumé
 *
 * Les connexions sans `<form>` (applications monopages qui appellent `fetch`
 * sur un clic) ne déclenchent pas d'événement `submit`. Le repli sur le clic
 * couvre les plus courantes ; il ne prétend pas être exhaustif. Un
 * identifiant non capturé se rattrape par « Ajouter » dans la popup — un
 * identifiant capturé à tort ne coûte qu'un « Ignorer ».
 */

/** Type du message, partagé avec le service worker. */
const MESSAGE_TYPE = 'zwarden-credentials';

/** Fenêtre de déduplication entre un `submit` et le clic qui l'a provoqué. */
const DEDUPE_MS = 1000;

let lastSentAt = 0;

/** Champs mot de passe visibles et remplis, dans l'ordre du document. */
function filledPasswords(root: ParentNode): HTMLInputElement[] {
  return [...root.querySelectorAll<HTMLInputElement>('input[type="password"]')].filter(
    (input) => input.value !== '' && input.offsetParent !== null,
  );
}

/**
 * Devine l'identifiant associé à un champ mot de passe.
 *
 * Par ordre de fiabilité : l'annotation explicite du site
 * (`autocomplete="username"`), puis un champ e-mail, puis le dernier champ
 * texte rempli **avant** le mot de passe — l'ordre visuel est le seul indice
 * quand le site n'annote rien. Faute de mieux : chaîne vide, l'utilisateur
 * complétera dans la popup.
 */
function guessUsername(scope: ParentNode, password: HTMLInputElement): string {
  const annotated = scope.querySelector<HTMLInputElement>(
    'input[autocomplete="username"], input[autocomplete="email"]',
  );
  if (annotated?.value !== undefined && annotated.value !== '') {
    return annotated.value;
  }

  const candidates = [
    ...scope.querySelectorAll<HTMLInputElement>('input[type="email"], input[type="text"]'),
  ].filter((input) => input.value !== '' && input.offsetParent !== null);

  let best = '';
  for (const candidate of candidates) {
    // `compareDocumentPosition` plutôt qu'un index : le champ mot de passe
    // n'est pas forcément dans la même sous-arborescence que le champ texte.
    const avant = password.compareDocumentPosition(candidate) & Node.DOCUMENT_POSITION_PRECEDING;
    if (avant !== 0) {
      best = candidate.value;
    }
  }
  return best === '' ? (candidates[0]?.value ?? '') : best;
}

/**
 * Reconnaît un bouton « afficher le mot de passe ».
 *
 * C'est le faux positif structurel du repli sur le clic : l'œil de révélation
 * est un bouton, il est à côté d'un champ mot de passe rempli, et il est
 * cliqué au moment exact où une capture semblerait justifiée. Deux marques le
 * distinguent d'une soumission, et aucune ne repose sur son libellé — un
 * libellé est traduit, une structure ne l'est pas :
 *
 * - `aria-pressed` désigne un bouton à deux états ; une soumission n'en a pas ;
 * - un `type="button"` explicite logé dans le bloc du champ lui-même, qui est
 *   l'emplacement de l'œil dans la quasi-totalité des formulaires.
 */
function estBasculeAffichage(control: Element, password: HTMLInputElement): boolean {
  if (control.hasAttribute('aria-pressed')) {
    return true;
  }
  return (
    control.getAttribute('type') === 'button' &&
    password.parentElement !== null &&
    password.parentElement.contains(control)
  );
}

/**
 * Envoie la capture au service worker. Silencieux en cas d'échec.
 *
 * @param scope Sous-arbre où chercher les champs.
 * @param control Contrôle cliqué, quand la capture vient du repli sur le clic.
 *   Il est alors examiné : tout ce qui ressemble à une bascule d'affichage est
 *   écarté.
 */
function report(scope: ParentNode, control: Element | null = null): void {
  const now = Date.now();
  if (now - lastSentAt < DEDUPE_MS) {
    return;
  }
  const passwords = filledPasswords(scope);
  const password = passwords[0];
  if (password === undefined) {
    return;
  }
  if (control !== null && estBasculeAffichage(control, password)) {
    return;
  }
  // Deux champs mot de passe remplis et différents : c'est une création de
  // compte ou un changement de mot de passe avec confirmation. On garde le
  // premier ; s'ils diffèrent, la saisie n'est pas encore valide et le site
  // la refusera — inutile de proposer quoi que ce soit.
  if (passwords.length > 1 && passwords.some((p) => p.value !== password.value)) {
    return;
  }

  lastSentAt = now;
  // Ni l'origine ni l'hôte ne sont transmis : le worker les lit sur
  // l'émetteur, que le navigateur renseigne. Les annoncer ici donnerait à
  // croire qu'ils comptent, et inviterait un jour à leur faire confiance.
  const message = {
    type: MESSAGE_TYPE,
    username: guessUsername(scope, password),
    password: password.value,
  };
  // La popup ou le worker peuvent être absents : l'erreur est sans
  // conséquence et ne doit pas polluer la console du site.
  void chrome.runtime.sendMessage(message).catch(() => undefined);
}

document.addEventListener(
  'submit',
  (event) => {
    const form = event.target;
    report(form instanceof HTMLFormElement ? form : document);
  },
  true,
);

// Repli pour les connexions sans soumission de formulaire. Restreint aux
// éléments qui se présentent comme un bouton : un clic n'importe où dans la
// page ne doit pas déclencher de capture.
document.addEventListener(
  'click',
  (event) => {
    const target = event.target;
    if (!(target instanceof Element)) {
      return;
    }
    const bouton = target.closest('button, input[type="submit"], [role="button"]');
    if (bouton === null) {
      return;
    }
    // Le contrôle est transmis pour être examiné : c'est là que les bascules
    // d'affichage sont écartées. Hors formulaire, la recherche porte sur le
    // document entier — c'est la raison d'être de ce repli (connexions sans
    // `<form>`), et sa part d'imprécision assumée.
    report(bouton.closest('form') ?? document, bouton);
  },
  true,
);
