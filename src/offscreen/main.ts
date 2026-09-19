/**
 * @file Document hors écran : l'accès au presse-papiers du service worker.
 *
 * ## Pourquoi ce document existe
 *
 * Un service worker MV3 n'a pas de DOM, et le presse-papiers en exige un. Sans
 * lui, l'effacement différé du presse-papiers ne pouvait être porté que par un
 * `setTimeout` dans la popup — donc mourait avec elle. Un mot de passe copié
 * puis la popup refermée restait dans le presse-papiers indéfiniment, alors que
 * le réglage promettait le contraire.
 *
 * ## Pourquoi `execCommand`, qui est obsolète
 *
 * `navigator.clipboard.writeText` exige un document au premier plan. Un document
 * hors écran ne l'est jamais, par définition. `document.execCommand('copy')` sur
 * une sélection de `<textarea>` reste la méthode documentée par Chrome pour ce
 * cas précis. La Clipboard API est tout de même essayée d'abord : le jour où
 * elle fonctionnera ici, le repli deviendra mort sans qu'on ait à y revenir.
 *
 * ## Écrasé, pas vidé
 *
 * `execCommand('copy')` ne fait rien d'une sélection vide. L'effacement écrit
 * donc une seule espace. L'effet utile est le même — le secret n'est plus dans
 * le presse-papiers — mais le mot juste est « écrasé ».
 */

/** Type des messages acceptés, partagé avec le service worker. */
const MESSAGE_TYPE = 'zwarden-clipboard';

interface ClipboardMessage {
  readonly type: string;
  /** Texte à placer dans le presse-papiers. Vide = effacement. */
  readonly text: unknown;
}

/** Place `text` dans le presse-papiers. Une espace si `text` est vide. */
async function write(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    return;
  } catch {
    // Attendu hors premier plan : on passe au repli.
  }

  const zone = document.getElementById('tampon');
  if (!(zone instanceof HTMLTextAreaElement)) {
    return;
  }
  zone.value = text === '' ? ' ' : text;
  zone.select();
  document.execCommand('copy');
  // Le tampon ne garde pas le secret une fois la copie faite.
  zone.value = '';
}

chrome.runtime.onMessage.addListener((message: unknown, _sender, respond) => {
  if (
    typeof message !== 'object' ||
    message === null ||
    (message as { type?: unknown }).type !== MESSAGE_TYPE
  ) {
    return false;
  }
  const { text } = message as ClipboardMessage;
  void write(typeof text === 'string' ? text : '').then(() => respond(true));
  // Réponse asynchrone : le worker attend la confirmation avant de fermer ce
  // document, sans quoi il le fermerait pendant l'écriture.
  return true;
});

export {};
