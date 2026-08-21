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
 * @returns L'origine normalisée, ou `null` si l'URI est inexploitable.
 */
export function uriOrigin(uri: string): string | null {
  const trimmed = uri.trim();
  if (trimmed === '') {
    return null;
  }
  for (const candidate of [trimmed, `https://${trimmed}`]) {
    try {
      const url = new URL(candidate);
      if (url.protocol === 'http:' || url.protocol === 'https:') {
        return url.origin;
      }
      return null;
    } catch {
      // Essayer le candidat suivant.
    }
  }
  return null;
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
