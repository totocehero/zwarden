/**
 * @file Matching an item's URIs against the active page.
 *
 * Non-negotiable rule from `docs/EXTENSION.md`: match by **strict origin** —
 * scheme + host + port — never by substring. Loose matching hands
 * `bank.example`'s credentials to `bank.example.attacker.com`. Base-domain
 * matching would require the Public Suffix List (unacceptable for the size
 * budget); strict origin is safe without it.
 */

/**
 * The origin of a vault URI.
 *
 * Real vaults contain URIs without a scheme (`example.com`): those are read as
 * HTTPS — never HTTP, which would widen matching towards cleartext traffic.
 *
 * **The HTTPS fallback is only attempted on a URI without a scheme**, and that
 * subtlety deserves stating, because the obvious version of this code is
 * dangerous. `new URL('localhost:8080')` succeeds — protocol `localhost:` — so
 * stopping at the first candidate that parses made every `host:port` URI fail,
 * the common shape for a self-hosted service. Naively chaining on to
 * `https://${uri}` fixes that case and opens a worse one:
 * `https://mailto:alice@bank.example` parses as `https://bank.example`, and an
 * item whose only URI is an email address would then offer autofill on the bank.
 * A silent failure became a false match — not an acceptable trade. Hence
 * {@link hasScheme}, which tells `host:port` apart from a genuine opaque scheme.
 *
 * @returns The normalised origin, or `null` if the URI is unusable.
 */
export function uriOrigin(uri: string): string | null {
  const trimmed = uri.trim();
  if (trimmed === '') {
    return null;
  }
  const candidates = hasScheme(trimmed) ? [trimmed] : [trimmed, `https://${trimmed}`];
  for (const candidate of candidates) {
    try {
      const url = new URL(candidate);
      if (url.protocol === 'http:' || url.protocol === 'https:') {
        return url.origin;
      }
    } catch {
      // Next candidate.
    }
  }
  return null;
}

/**
 * `true` if the URI already carries a scheme, in which case one must not be
 * added.
 *
 * Two marks: `://`, or a `word:` prefix followed by something other than a port
 * number. It is that second clause which tells `mailto:alice@bank.example` (an
 * opaque scheme, to be left alone) from `example.com:8080` (host and port, to be
 * prefixed).
 */
function hasScheme(uri: string): boolean {
  if (uri.includes('://')) {
    return true;
  }
  const scheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:(.*)$/.exec(uri);
  return scheme !== null && !/^\d+([/?#]|$)/.test(scheme[1]!);
}

/**
 * `true` if one of the item's URIs matches the given origin exactly.
 *
 * @param uris The item's decrypted URIs.
 * @param origin Origin of the active page (`https://example.com`, or with an
 *   explicit port).
 */
export function matchesOrigin(uris: readonly string[], origin: string): boolean {
  return uris.some((uri) => uriOrigin(uri) === origin);
}
