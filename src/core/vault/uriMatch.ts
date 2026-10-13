/**
 * @file Matching an item's URIs against the active page.
 *
 * Non-negotiable rule from `docs/EXTENSION.md`: by default, match by **strict
 * origin** — scheme + host + port — never by substring. Loose matching hands
 * `bank.example`'s credentials to `bank.example.attacker.com`. Base-domain
 * matching would require the Public Suffix List (unacceptable for the size
 * budget); strict origin is safe without it.
 *
 * ## The rule the user wrote on the URI
 *
 * The Bitwarden format lets each URI carry its own rule — base domain, host,
 * starts-with, exact, regular expression, never — chosen in a client and
 * synchronised with the item. For a long time this extension read the URI and
 * ignored the rule, which is why an item that Bitwarden offered on a
 * single-sign-on page (`sso.example.org`, for an app saved as
 * `app.example.org`) was not offered here.
 *
 * {@link matchesPage} honours that rule when the user set one, and keeps strict
 * origin when they did not. The dangerous one, the regular expression, is not
 * evaluated: a pattern written for another engine, run against a URL an
 * attacker controls, is not a rule this code can vouch for. Base domain is
 * approximated — see {@link sameBaseDomain} for exactly how far.
 */

/** A login URI and the rule its owner attached to it, decrypted. */
export interface LoginUri {
  readonly uri: string;
  /** One of {@link UriMatchType}, or `null` for the client's default: strict origin. */
  readonly match: number | null;
}

/** The rule values of the Bitwarden format, as stored in `login.uris[].match`. */
export const UriMatchType = {
  Domain: 0,
  Host: 1,
  StartsWith: 2,
  Exact: 3,
  RegularExpression: 4,
  Never: 5,
} as const;

/**
 * Second-level labels that are themselves public registries under a
 * two-letter country code: `co.uk`, `com.au`, `gouv.fr`. Under one of these,
 * sharing two labels (`co.uk`) is sharing nothing, and three are required.
 *
 * A short list, not the Public Suffix List: it covers the shapes that are both
 * common and dangerous, and the comment at {@link sameBaseDomain} says what it
 * does not cover.
 */
const REGISTRY_SECOND_LABELS = new Set([
  'ac',
  'asso',
  'biz',
  'co',
  'com',
  'edu',
  'gob',
  'gouv',
  'gov',
  'go',
  'info',
  'mil',
  'ne',
  'net',
  'nom',
  'or',
  'org',
]);

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

/** A vault URI as a URL, with the bare-host form read as HTTPS; `null` if unusable. */
function uriUrl(uri: string): URL | null {
  const origin = uriOrigin(uri);
  if (origin === null) {
    return null;
  }
  const trimmed = uri.trim();
  try {
    return new URL(hasScheme(trimmed) ? trimmed : `https://${trimmed}`);
  } catch {
    return null;
  }
}

/**
 * Whether a page may receive credentials saved for a URI, as far as the scheme
 * goes: an HTTPS page always may; an HTTP page only when the URI itself says
 * HTTP. Filling a cleartext page from an HTTPS entry would be a downgrade no
 * matching rule should buy.
 */
function schemeAllows(saved: URL, page: URL): boolean {
  return page.protocol === 'https:' || saved.protocol === 'http:';
}

/**
 * Whether two hosts belong to the same registrable domain — approximately.
 *
 * The real answer needs the Public Suffix List. The approximation: the hosts
 * share their last two labels, or their last three when the second one is a
 * known registry label under a country code (`bank.co.uk` and `shop.co.uk`
 * share `co.uk` and are **not** related). IP addresses are never related to
 * anything: a range is not a domain.
 *
 * What slips through: a multi-label public suffix this list does not name —
 * `github.io`, `herokuapp.com`, a hosting provider's wildcard. A user who
 * chose base-domain matching for an item hosted under one of those has chosen
 * to be offered that item on their neighbours' pages, which is what Bitwarden
 * does with the full list in hand as well, since those suffixes are the
 * private section of it. The default rule, strict origin, has none of this.
 */
export function sameBaseDomain(a: string, b: string): boolean {
  const ours = a.toLowerCase();
  const theirs = b.toLowerCase();
  if (ours === theirs) {
    return true;
  }
  if (
    /^[\d.]+$/.test(ours) ||
    /^[\d.]+$/.test(theirs) ||
    ours.includes(':') ||
    theirs.includes(':')
  ) {
    return false;
  }
  const mine = ours.split('.');
  const yours = theirs.split('.');
  const tld = mine[mine.length - 1];
  const second = mine[mine.length - 2];
  if (tld === undefined || second === undefined || tld === '' || second === '') {
    return false;
  }
  const needed = tld.length === 2 && REGISTRY_SECOND_LABELS.has(second) ? 3 : 2;
  if (mine.length < needed || yours.length < needed) {
    return false;
  }
  return mine.slice(-needed).join('.') === yours.slice(-needed).join('.');
}

/** Whether one saved URI, under its own rule, matches the page. */
function uriMatchesPage(saved: LoginUri, page: URL): boolean {
  const rule = saved.match ?? null;
  if (rule === UriMatchType.Never || rule === UriMatchType.RegularExpression) {
    return false;
  }
  if (rule === null) {
    return uriOrigin(saved.uri) === page.origin;
  }
  const url = uriUrl(saved.uri);
  if (url === null || !schemeAllows(url, page)) {
    return false;
  }
  switch (rule) {
    case UriMatchType.Domain:
      return sameBaseDomain(url.hostname, page.hostname);
    case UriMatchType.Host:
      return url.host === page.host;
    case UriMatchType.StartsWith:
      return page.href.toLowerCase().startsWith(url.href.toLowerCase());
    case UriMatchType.Exact:
      return page.href === url.href;
    default:
      // A rule this version does not know: the safe reading, not a guess.
      return uriOrigin(saved.uri) === page.origin;
  }
}

/**
 * `true` if one of the item's URIs, each under its own rule, matches the page.
 *
 * @param uris The item's decrypted URIs with the rule each carries.
 * @param page The active page's URL.
 */
export function matchesPage(uris: readonly LoginUri[], page: URL): boolean {
  return uris.some((saved) => uriMatchesPage(saved, page));
}

/**
 * The items that match the page, then the rest, each in their original order.
 *
 * The popup lists the whole vault and puts the matches first under their own
 * heading, rather than hiding everything else: a vault is also opened to copy
 * a password for another site, and a list that showed only this page's items
 * would have to be undone before that. No page — a browser page, a new tab —
 * means no split: everything is "the rest".
 */
export function splitForPage<T extends { readonly uris: readonly LoginUri[] }>(
  items: readonly T[],
  page: URL | null,
): { readonly forPage: readonly T[]; readonly others: readonly T[] } {
  if (page === null) {
    return { forPage: [], others: items };
  }
  const forPage: T[] = [];
  const others: T[] = [];
  for (const item of items) {
    (matchesPage(item.uris, page) ? forPage : others).push(item);
  }
  return { forPage, others };
}
