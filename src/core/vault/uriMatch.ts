/**
 * @file Correspondance entre les URIs d'un item et la page active.
 *
 * Règle non négociable de `docs/EXTENSION.md` : correspondance par **origine
 * stricte** — schéma + hôte + port — jamais par sous-chaîne. Un matching
 * laxiste livre les identifiants de `banque.fr` à `banque.fr.attaquant.com`.
 * Le matching par domaine de base exigerait la Public Suffix List
 * (inacceptable pour le budget de poids) ; l'origine stricte est sûre sans
 * elle.
 */

/**
 * Origine d'une URI de coffre.
 *
 * Les coffres réels contiennent des URIs sans schéma (`exemple.fr`) : elles
 * sont interprétées en HTTPS — jamais en HTTP, qui élargirait la
 * correspondance vers du trafic en clair.
 *
 * **Le repli en HTTPS n'est tenté que sur une URI sans schéma**, et c'est une
 * subtilité qui mérite d'être dite, parce que la version évidente du code est
 * dangereuse. `new URL('localhost:8080')` réussit — protocole `localhost:` —
 * donc s'arrêter au premier candidat qui s'analyse faisait échouer toute URI
 * de la forme `hôte:port`, la forme courante d'un service auto-hébergé.
 * Enchaîner naïvement sur `https://${uri}` corrige ce cas et en ouvre un pire :
 * `https://mailto:alice@banque.fr` s'analyse en `https://banque.fr`, et un item
 * dont l'unique URI est une adresse e-mail proposerait alors le remplissage sur
 * la banque. Un échec muet devenait une correspondance fausse — l'échange n'est
 * pas acceptable. D'où {@link porteUnSchema}, qui départage `hôte:port` d'un
 * vrai schéma opaque.
 *
 * @returns L'origine normalisée, ou `null` si l'URI est inexploitable.
 */
export function uriOrigin(uri: string): string | null {
  const trimmed = uri.trim();
  if (trimmed === '') {
    return null;
  }
  const candidates = porteUnSchema(trimmed) ? [trimmed] : [trimmed, `https://${trimmed}`];
  for (const candidate of candidates) {
    try {
      const url = new URL(candidate);
      if (url.protocol === 'http:' || url.protocol === 'https:') {
        return url.origin;
      }
    } catch {
      // Candidat suivant.
    }
  }
  return null;
}

/**
 * `true` si l'URI porte déjà un schéma, auquel cas il ne faut pas lui en
 * ajouter un.
 *
 * Deux marques : `://`, ou un préfixe `mot:` suivi d'autre chose qu'un numéro
 * de port. C'est cette seconde clause qui distingue `mailto:alice@banque.fr`
 * (schéma opaque, à laisser tel quel) de `exemple.fr:8080` (hôte et port, à
 * préfixer).
 */
function porteUnSchema(uri: string): boolean {
  if (uri.includes('://')) {
    return true;
  }
  const schema = /^[a-zA-Z][a-zA-Z0-9+.-]*:(.*)$/.exec(uri);
  return schema !== null && !/^\d+([/?#]|$)/.test(schema[1]!);
}

/**
 * `true` si l'une des URIs de l'item correspond exactement à l'origine
 * donnée.
 *
 * @param uris URIs déchiffrées de l'item.
 * @param origin Origine de la page active (`https://exemple.fr` ou avec
 *   port explicite).
 */
export function matchesOrigin(uris: readonly string[], origin: string): boolean {
  return uris.some((uri) => uriOrigin(uri) === origin);
}
