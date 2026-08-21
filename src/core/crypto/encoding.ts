/**
 * @file Conversions d'encodage et comparaisons sûres.
 *
 * Convention du projet : toute donnée binaire circule en `Uint8Array`. On ne
 * laisse jamais fuiter de « binary string » (chaîne dont chaque code unit
 * représente un octet) hors de ce module — c'est une source classique de
 * corruption silencieuse dès qu'un octet dépasse 0x7f et qu'un `TextEncoder`
 * repasse dessus.
 *
 * Ces fonctions manipulent du matériel de clé et des ciphertexts : toute
 * modification ici doit être accompagnée d'un aller-retour sur les 256 valeurs
 * d'octet (voir `tests/encoding.test.ts`).
 */

/**
 * Découpage utilisé pour `String.fromCharCode(...)`.
 *
 * L'opérateur spread se traduit par un appel avec autant d'arguments que
 * d'éléments ; au-delà de quelques dizaines de milliers, on déborde la pile.
 * 8192 reste très en dessous de la limite tout en amortissant le coût d'appel.
 */
const FROM_CHAR_CODE_CHUNK = 8192;

/**
 * Encode des octets en base64 standard (RFC 4648 §4), avec padding.
 *
 * S'appuie sur `btoa`, disponible dans tous les contextes d'extension
 * (fenêtre, service worker, content script). Une implémentation manuelle a été
 * mesurée : elle est plus lente que la primitive de la plateforme à l'encodage
 * comme au décodage (voir `scripts/bench-base64.mjs`). Le code natif gagne sur
 * les deux tableaux, il n'y a donc aucune raison de le réimplémenter.
 *
 * @param bytes Octets à encoder.
 * @returns Chaîne base64 avec padding `=`.
 */
export function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += FROM_CHAR_CODE_CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + FROM_CHAR_CODE_CHUNK));
  }
  return btoa(binary);
}

/**
 * Décode une chaîne base64 vers des octets.
 *
 * Tolérant en entrée, volontairement : les espaces et retours ligne sont
 * ignorés et l'alphabet URL-safe (`-` et `_`) est accepté. Les payloads
 * transitent par plusieurs implémentations serveur et clients tiers ; refuser
 * un coffre déchiffrable pour un `\n` parasite serait une régression
 * fonctionnelle sans bénéfice de sécurité.
 *
 * Le padding manquant est reconstitué : `atob` le refuse, mais un base64
 * non paddé reste décodable sans ambiguïté.
 *
 * @param input Chaîne base64, standard ou URL-safe.
 * @returns Octets décodés.
 * @throws {DOMException} Si l'entrée contient des caractères hors alphabet
 *   après normalisation.
 */
export function fromBase64(input: string): Uint8Array {
  const normalized = input.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), '=');

  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

const UTF8_ENCODER = /* @__PURE__ */ new TextEncoder();
const UTF8_DECODER = /* @__PURE__ */ new TextDecoder('utf-8', { fatal: false });

/**
 * Encode du texte en UTF-8.
 *
 * @param text Texte source.
 * @returns Octets UTF-8.
 */
export function toUtf8Bytes(text: string): Uint8Array {
  return UTF8_ENCODER.encode(text);
}

/**
 * Décode des octets UTF-8 en texte.
 *
 * Le décodeur est non strict (`fatal: false`) : une séquence invalide produit
 * U+FFFD plutôt qu'une exception. C'est délibéré — un champ de coffre corrompu
 * doit rester affichable et signalable, pas faire échouer la synchronisation.
 *
 * @param bytes Octets UTF-8.
 * @returns Texte décodé, caractères invalides remplacés par U+FFFD.
 */
export function fromUtf8Bytes(bytes: Uint8Array): string {
  return UTF8_DECODER.decode(bytes);
}

/**
 * Concatène plusieurs tampons en un seul.
 *
 * @param parts Tampons à concaténer, dans l'ordre.
 * @returns Nouveau tampon contenant la concaténation.
 */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const part of parts) {
    total += part.length;
  }

  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/**
 * Compare deux tampons en temps constant.
 *
 * Indispensable pour la vérification de MAC. Une comparaison naïve s'arrête au
 * premier octet divergent : le temps de réponse révèle alors combien d'octets
 * de tête sont corrects, ce qui permet de forger un MAC valide octet par octet
 * en 256 × 32 requêtes au lieu de 2^256.
 *
 * La durée dépend uniquement de la longueur des entrées, jamais de leur
 * contenu. Ici les MAC font toujours 32 octets, donc la longueur n'est pas un
 * secret ; on évite malgré tout tout retour anticipé.
 *
 * @param a Premier tampon.
 * @param b Second tampon.
 * @returns `true` si les tampons sont identiques.
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  let diff = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

/**
 * Écrase un tampon sensible en place.
 *
 * Best-effort assumé. Un moteur JS à GC générationnel a pu recopier le tampon
 * lors d'une promotion mémoire, et rien en JavaScript ne permet de garantir
 * l'effacement de ces copies. Cela réduit la fenêtre d'exposition (dumps
 * mémoire, hibernation) sans l'éliminer.
 *
 * @param bytes Tampon à effacer.
 */
export function wipe(bytes: Uint8Array): void {
  bytes.fill(0);
}
