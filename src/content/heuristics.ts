/**
 * @file Heuristiques de détection d'identifiants — la décision, sans le DOM global.
 *
 * ## Pourquoi ce fichier existe séparément du détecteur
 *
 * `detector.ts` est un script de contenu : il s'accroche à `document`, lit
 * `location`, parle au service worker. Rien de tout cela n'est testable, et
 * c'est précisément pour cette raison que les décisions ne doivent pas y vivre.
 *
 * Ici, aucune API d'extension, aucun événement, aucun état global : des
 * fonctions qui reçoivent un sous-arbre DOM et rendent un verdict. C'est ce qui
 * permet de rejouer sur des fragments HTML les cas qui, autrement, ne se
 * vérifieraient qu'à la main sur un vrai site — le bouton « afficher le mot de
 * passe », le formulaire de création de compte, la page sans `<form>`.
 *
 * Le détecteur n'en garde que ce qui exige le vrai navigateur : le câblage des
 * événements, la déduplication temporelle, et l'envoi du message.
 */

/**
 * Test de visibilité d'un champ, injectable.
 *
 * Le test réel est `offsetParent !== null` : il couvre `display:none` et les
 * champs détachés, qui sont les cas rencontrés. Mais il repose sur la mise en
 * page, que jsdom n'implémente pas — `offsetParent` y vaut toujours `null`.
 * Sans cette couture, aucune des décisions de ce fichier ne serait vérifiable
 * autrement qu'à la main sur un vrai site. C'est le même procédé que la source
 * aléatoire injectable du générateur, pour la même raison.
 */
export type VisibilityTest = (element: HTMLElement) => boolean;

/** Test de visibilité réel, celui du navigateur. */
export const estAffiche: VisibilityTest = (element) => element.offsetParent !== null;

/** Identifiants repérés dans une page, prêts à être transmis au worker. */
export interface CaptureCandidate {
  readonly username: string;
  readonly password: string;
}

/**
 * Champs mot de passe visibles et remplis, dans l'ordre du document.
 *
 * `offsetParent === null` sert de test de visibilité : il couvre `display:none`
 * et les champs détachés, qui sont les cas réels — un champ que l'utilisateur
 * n'a pas pu remplir n'a pas à être capturé.
 */
export function filledPasswords(
  root: ParentNode,
  visible: VisibilityTest = estAffiche,
): HTMLInputElement[] {
  return [...root.querySelectorAll<HTMLInputElement>('input[type="password"]')].filter(
    (input) => input.value !== '' && visible(input),
  );
}

/**
 * Reconnaît un bouton « afficher le mot de passe ».
 *
 * C'est le faux positif structurel du repli sur le clic : l'œil de révélation
 * est un bouton, il est à côté d'un champ mot de passe rempli, et il est cliqué
 * au moment exact où une capture semblerait justifiée. Deux marques le
 * distinguent d'une soumission, et aucune ne repose sur son libellé — un
 * libellé est traduit, une structure ne l'est pas :
 *
 * - `aria-pressed` désigne un bouton à deux états ; une soumission n'en a pas ;
 * - un `type="button"` explicite logé dans le bloc du champ lui-même, qui est
 *   l'emplacement de l'œil dans la quasi-totalité des formulaires.
 */
export function estBasculeAffichage(control: Element, password: HTMLInputElement): boolean {
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
 * Devine l'identifiant associé à un champ mot de passe.
 *
 * Par ordre de fiabilité : l'annotation explicite du site
 * (`autocomplete="username"`), puis un champ e-mail, puis le dernier champ
 * texte rempli **avant** le mot de passe — l'ordre visuel est le seul indice
 * quand le site n'annote rien. Faute de mieux : chaîne vide, l'utilisateur
 * complétera dans la popup.
 */
export function guessUsername(
  scope: ParentNode,
  password: HTMLInputElement,
  visible: VisibilityTest = estAffiche,
): string {
  const annotated = scope.querySelector<HTMLInputElement>(
    'input[autocomplete="username"], input[autocomplete="email"]',
  );
  if (annotated !== null && annotated.value !== '') {
    return annotated.value;
  }

  const candidates = [
    ...scope.querySelectorAll<HTMLInputElement>('input[type="email"], input[type="text"]'),
  ].filter((input) => input.value !== '' && visible(input));

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
 * Verdict complet : y a-t-il quelque chose à capturer dans ce sous-arbre ?
 *
 * @param scope Formulaire soumis, ou le document quand il n'y a pas de `<form>`.
 * @param control Contrôle cliqué, si la capture vient du repli sur le clic. Il
 *   est alors examiné : tout ce qui ressemble à une bascule d'affichage est
 *   écarté.
 * @param visible Test de visibilité — voir {@link VisibilityTest}.
 * @returns Les identifiants à transmettre, ou `null` s'il n'y a rien à proposer.
 */
export function findCapture(
  scope: ParentNode,
  control: Element | null = null,
  visible: VisibilityTest = estAffiche,
): CaptureCandidate | null {
  const passwords = filledPasswords(scope, visible);
  const password = passwords[0];
  if (password === undefined) {
    return null;
  }
  if (control !== null && estBasculeAffichage(control, password)) {
    return null;
  }
  // Deux champs mot de passe remplis et différents : c'est une création de
  // compte ou un changement de mot de passe avec confirmation. On garde le
  // premier ; s'ils diffèrent, la saisie n'est pas encore valide et le site la
  // refusera — inutile de proposer quoi que ce soit.
  if (passwords.length > 1 && passwords.some((p) => p.value !== password.value)) {
    return null;
  }

  return { username: guessUsername(scope, password, visible), password: password.value };
}
