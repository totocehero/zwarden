/**
 * @file Asking the repository whether a newer release exists.
 *
 * The extension is installed unpacked, from a zip attached to a release, so no
 * store will ever tell the user it is out of date. This is the replacement: one
 * request to GitHub's release endpoint, a version comparison, and a link to the
 * release page. Nothing installs itself — the user downloads and reloads, as
 * the README describes — so "proposing" an update means saying one exists and
 * where it is.
 *
 * ## What leaves
 *
 * The request carries what every HTTPS request carries: the user's address and
 * the browser's identity. No account, no vault data, not even the current
 * version — the comparison happens here, after the answer comes back. Still,
 * it is a request to a third party on a schedule, so the automatic form is off
 * by default and the settings page says so; the manual button works either way,
 * because a click is consent.
 *
 * ## Pure
 *
 * No `chrome.*`, no storage: the fetcher is injected, the answer is parsed and
 * compared, and the result is handed back. The worker and the settings page
 * both call this; the tests call it with canned answers.
 */

const OWNER = 'totocehero';
const REPOSITORY = 'zwarden';

/** The release endpoint. `latest` excludes drafts and pre-releases on its own. */
export const RELEASES_API_URL = `https://api.github.com/repos/${OWNER}/${REPOSITORY}/releases/latest`;

/** Where to send someone who wants to read or download, when the API said nothing usable. */
export const RELEASES_PAGE_URL = `https://github.com/${OWNER}/${REPOSITORY}/releases`;

/** A release the repository publishes. */
export interface Release {
  /** Plain version, `0.2.0`, with the tag's `v` removed. */
  readonly version: string;
  /** The release page, where the zips and the notes are. */
  readonly url: string;
}

/** What one check established, kept so the popup and the settings page can show it. */
export interface UpdateStatus {
  /** When the check ran, in milliseconds since the epoch. */
  readonly checkedAt: number;
  /** The newest release the repository knows, or `null` if the check failed. */
  readonly latest: Release | null;
}

export type JsonFetcher = (url: string) => Promise<unknown>;

/**
 * Splits a version into its numeric parts: `v1.2.3` → `[1, 2, 3]`.
 *
 * `null` for anything that is not dot-separated integers, so a tag like
 * `nightly` compares as "not a version" rather than as zero.
 */
export function parseVersion(text: string): readonly number[] | null {
  const trimmed = text.trim().replace(/^v/i, '');
  if (!/^\d+(\.\d+)*$/.test(trimmed)) {
    return null;
  }
  return trimmed.split('.').map((part) => Number.parseInt(part, 10));
}

/**
 * Whether `candidate` is strictly newer than `current`.
 *
 * Missing trailing parts count as zero, so `0.2` and `0.2.0` are the same
 * version — which is how the manifest and a tag may spell one release.
 * Anything unparseable is not newer: an update prompt resting on a tag we
 * could not read would be a prompt for nothing.
 */
export function isNewer(current: string, candidate: string): boolean {
  const ours = parseVersion(current);
  const theirs = parseVersion(candidate);
  if (ours === null || theirs === null) {
    return false;
  }
  const length = Math.max(ours.length, theirs.length);
  for (let i = 0; i < length; i += 1) {
    const a = ours[i] ?? 0;
    const b = theirs[i] ?? 0;
    if (a !== b) {
      return b > a;
    }
  }
  return false;
}

/**
 * Reads the release out of GitHub's answer.
 *
 * `null` for anything that is not a published release with a version-shaped
 * tag: a draft, a pre-release, an error body, or a tag named after something
 * other than a version. The release page is taken from the answer when it has
 * one and falls back to the releases listing otherwise, so a usable version
 * never comes without somewhere to go.
 */
export function parseLatestRelease(body: unknown): Release | null {
  if (typeof body !== 'object' || body === null) {
    return null;
  }
  const record = body as Record<string, unknown>;
  if (record['draft'] === true || record['prerelease'] === true) {
    return null;
  }
  const tag = record['tag_name'];
  if (typeof tag !== 'string' || parseVersion(tag) === null) {
    return null;
  }
  const url = record['html_url'];
  return {
    version: tag.trim().replace(/^v/i, ''),
    url: typeof url === 'string' && url.startsWith('https://') ? url : RELEASES_PAGE_URL,
  };
}

/**
 * Asks the repository for its latest release.
 *
 * Never throws: a network that is down, a rate limit, or an answer we cannot
 * read all become `latest: null` with the time of the attempt, so a caller can
 * say "could not check" rather than nothing, and nobody's sign-in waits on it.
 */
export async function checkForUpdate(
  fetchJson: JsonFetcher,
  now: () => number = Date.now,
): Promise<UpdateStatus> {
  try {
    return { checkedAt: now(), latest: parseLatestRelease(await fetchJson(RELEASES_API_URL)) };
  } catch {
    return { checkedAt: now(), latest: null };
  }
}

/** The fetcher used outside tests: GitHub's JSON, and nothing identifying beyond the request itself. */
export async function fetchGitHubJson(url: string): Promise<unknown> {
  const response = await fetch(url, {
    headers: { Accept: 'application/vnd.github+json' },
    // No cookies: GitHub would happily attach the user's session, and a version
    // check has no business carrying one.
    credentials: 'omit',
    cache: 'no-store',
  });
  if (!response.ok) {
    throw new Error(`GitHub answered ${response.status}`);
  }
  return response.json();
}
