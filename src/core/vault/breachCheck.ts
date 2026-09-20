/**
 * @file Asking whether a password has appeared in a public breach.
 *
 * The one thing in Zwarden that talks to somebody other than the user's own
 * server, which is why it is off unless switched on and why this file explains
 * itself at length.
 *
 * ## What it can tell you that no local check can
 *
 * `health.ts` judges a password's **shape** — short, reused, a run on the
 * keyboard. This judges its **history**. A password can be structurally
 * excellent and have been in a dump since 2019, and nothing computable on this
 * machine will ever know that.
 *
 * ## The protocol, and why it is acceptable
 *
 * Have I Been Pwned's range API never receives the password, nor its full
 * hash. The exchange is:
 *
 * 1. SHA-1 the password, here;
 * 2. send the **first five hex characters** of that hash — nothing else;
 * 3. the server answers with every suffix it knows beginning with that prefix,
 *    around eight hundred of them;
 * 4. look for ours **in that answer**, here.
 *
 * The server sees `21BD1`. It cannot tell which of the eight hundred passwords
 * in that bucket was being asked about, or whether any of them was.
 *
 * ## What it leaks anyway, stated rather than glossed
 *
 * - the user's **IP address**, along with the fact that they run a password
 *   manager and the moment they checked;
 * - roughly **how many passwords** the vault holds, if it is all checked at
 *   once;
 * - a prefix is still a prefix: it narrows the candidates from hundreds of
 *   millions to about eight hundred. Enormous, and not zero.
 *
 * Hence `Add-Padding`, which the API honours: the response is padded with
 * decoy entries so that its **size** says nothing either. Without it, an
 * observer who cannot read the body still learns something from how long it is.
 *
 * SHA-1 is used because that is what the corpus is indexed by. It is not
 * relied on for anything — no secret is protected by it here.
 */

/** How many hex characters of the hash are sent. The rest never leaves. */
const PREFIX_LENGTH = 5;

/** Where the corpus lives. */
const RANGE_URL = 'https://api.pwnedpasswords.com/range/';

/** Fetches the suffixes for one prefix. Injected, so this module can be tested. */
export type RangeFetcher = (prefix: string) => Promise<string>;

/** The SHA-1 of a password, uppercase hex — the form the corpus is indexed by. */
export async function sha1Hex(password: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(password));
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

/** The part that is sent, and the part that never is. */
export function splitHash(hash: string): { readonly prefix: string; readonly suffix: string } {
  return { prefix: hash.slice(0, PREFIX_LENGTH), suffix: hash.slice(PREFIX_LENGTH) };
}

/**
 * How many times this suffix appears in the corpus, per the server's answer.
 *
 * A count of zero means **not breached**, and that covers the padding too: the
 * decoy entries `Add-Padding` inserts are all zero, so they need no special
 * handling and cannot be told from a real absence — which is the point of them.
 *
 * @param body The server's response, one `SUFFIX:COUNT` per line.
 * @param suffix The suffix looked for, uppercase hex.
 * @returns The count, or `0` if it is not there.
 */
export function countInRange(body: string, suffix: string): number {
  const wanted = suffix.toUpperCase();
  for (const line of body.split('\n')) {
    const separator = line.indexOf(':');
    if (separator < 0) {
      continue;
    }
    // `trimEnd` for the carriage returns the API sends.
    if (line.slice(0, separator).trimEnd().toUpperCase() !== wanted) {
      continue;
    }
    const count = Number.parseInt(line.slice(separator + 1).trim(), 10);
    return Number.isFinite(count) && count > 0 ? count : 0;
  }
  return 0;
}

/** The default fetcher, padded, used outside tests. */
export const fetchRange: RangeFetcher = async (prefix) => {
  const response = await fetch(`${RANGE_URL}${prefix}`, {
    // Without padding, the size of the answer says something even to an
    // observer who cannot read it.
    headers: { 'Add-Padding': 'true' },
  });
  if (!response.ok) {
    throw new Error(`Breach lookup failed: ${response.status}`);
  }
  return response.text();
};

/** How many lookups run at once. Polite, and enough to finish in seconds. */
const DEFAULT_CONCURRENCY = 4;

/**
 * Checks a set of passwords against the corpus.
 *
 * **One lookup per distinct password**, not per item: a password reused across
 * six items is one question, asked once. That is fewer requests, less exposure
 * and a faster answer, all from the same line of code.
 *
 * A lookup that fails is treated as "not known to be breached" rather than
 * aborting the run. A network hiccup part-way through should leave the user
 * with the answers it did get, not with nothing.
 *
 * @param passwords The passwords to ask about. Duplicates are collapsed.
 * @param fetcher How to reach the corpus. Injected for tests.
 * @param concurrency How many lookups to have in flight.
 * @returns Password → number of appearances. Absent means not found.
 */
export async function checkPasswords(
  passwords: readonly string[],
  fetcher: RangeFetcher = fetchRange,
  concurrency: number = DEFAULT_CONCURRENCY,
): Promise<ReadonlyMap<string, number>> {
  const distinct = [...new Set(passwords.filter((password) => password !== ''))];
  const found = new Map<string, number>();
  let next = 0;

  async function worker(): Promise<void> {
    for (let index = next++; index < distinct.length; index = next++) {
      const password = distinct[index]!;
      try {
        const { prefix, suffix } = splitHash(await sha1Hex(password));
        const count = countInRange(await fetcher(prefix), suffix);
        if (count > 0) {
          found.set(password, count);
        }
      } catch {
        // One unanswered question must not throw away the answers already had.
      }
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(concurrency, distinct.length) }, () => worker()),
  );
  return found;
}
