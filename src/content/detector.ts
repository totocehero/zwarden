/**
 * @file Détecteur d'identifiants saisis — script de contenu.
 *
 * ## Ce qu'il fait, et rien d'autre
 *
 * Il observe les soumissions de formulaires de la page, et lorsqu'un mot de
 * passe non vide vient d'être saisi, il l'envoie **au service worker de
 * l'extension** — jamais ailleurs. Il n'injecte aucune interface, ne lit jamais
 * le coffre, ne remplit rien : la décision « enregistrer ou non » appartient à
 * la popup, qui seule sait ce que le coffre contient déjà.
 *
 * ## Ce fichier ne décide rien
 *
 * Tout le discernement — quel champ, quel identifiant, est-ce un bouton
 * « afficher » — vit dans `heuristics.ts`, sans API d'extension ni état global,
 * donc sous tests. Ici ne reste que ce qui exige le vrai navigateur : le
 * câblage des événements, la déduplication temporelle, l'envoi du message.
 *
 * ## Pourquoi il ne remplit pas
 *
 * Les deux règles d'autofill de `docs/EXTENSION.md` §4 restent entières :
 * aucun remplissage sans geste explicite. Ce script n'écrit rien dans la page,
 * il ne fait que lire ce que l'utilisateur vient lui-même de taper.
 *
 * ## Ce qui reste imparfait, et assumé
 *
 * Les connexions sans `<form>` (applications monopages qui appellent `fetch`
 * sur un clic) ne déclenchent pas d'événement `submit`. Le repli sur le clic
 * couvre les plus courantes ; il ne prétend pas être exhaustif. Un identifiant
 * non capturé se rattrape par « Ajouter » dans la popup — un identifiant
 * capturé à tort ne coûte qu'un « Ignorer ».
 *
 * L'identifiant, lui, est **deviné** : aucun site n'est obligé de l'annoncer. Le
 * deviner faux est possible ; le deviner *égal au mot de passe* ne l'est plus
 * (`heuristics.ts`), parce que c'était le seul cas où une erreur de devinette
 * écrivait un secret dans un champ qui n'est pas fait pour lui.
 */

import { findCapture } from './heuristics.js';

/** Type du message, partagé avec le service worker. */
const MESSAGE_TYPE = 'zwarden-credentials';

/** Fenêtre de déduplication entre un `submit` et le clic qui l'a provoqué. */
const DEDUPE_MS = 1000;

let lastSentAt = 0;

/** Transmet la capture au service worker, si le verdict est positif. */
function report(scope: ParentNode, control: Element | null = null): void {
  const now = Date.now();
  if (now - lastSentAt < DEDUPE_MS) {
    return;
  }
  const capture = findCapture(scope, control);
  if (capture === null) {
    return;
  }

  lastSentAt = now;
  // Ni l'origine ni l'hôte ne sont transmis : le worker les lit sur l'émetteur,
  // que le navigateur renseigne. Les annoncer ici donnerait à croire qu'ils
  // comptent, et inviterait un jour à leur faire confiance.
  //
  // La popup ou le worker peuvent être absents : l'erreur est sans conséquence
  // et ne doit pas polluer la console du site.
  void chrome.runtime
    .sendMessage({ type: MESSAGE_TYPE, username: capture.username, password: capture.password })
    .catch(() => undefined);
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
