/**
 * @file Matching an entered credential against the vault.
 *
 * `findSaveCandidate` decides between "create an item" and "update this one". An
 * error of direction is not a display defect: it overwrites a still-valid
 * password, or silently creates a duplicate. Hence the insistence on strict
 * origin, taken from rule 2 of §4 in `docs/EXTENSION.md`.
 */

import { describe, expect, it } from 'vitest';

import type { CipherOverview } from '../src/core/vault/cipherService.js';
import { decideProposal, findSaveCandidate } from '../src/core/vault/cipherService.js';
import { matchesOrigin } from '../src/core/vault/uriMatch.js';

function item(id: string, username: string, uris: string[]): CipherOverview {
  return {
    id,
    type: 1,
    name: id,
    username,
    uris,
    hasPasskey: false,
    hasTotp: false,
    reprompt: false,
    organizationId: null,
    folderId: null,
    collectionIds: [],
  };
}

describe('findSaveCandidate', () => {
  const personal = item('personal', 'me@example.com', ['https://github.com']);
  const work = item('work', 'me@company.com', ['https://github.com']);
  const elsewhere = item('elsewhere', 'me@example.com', ['https://gitlab.com']);
  const vault = [personal, work, elsewhere];

  const find = (origin: string, username: string) =>
    findSaveCandidate(vault, origin, username, matchesOrigin);

  it('matches the item with the same origin and the same username', () => {
    expect(find('https://github.com', 'me@example.com')).toBe(personal);
  });

  it('tells two accounts on the same site apart', () => {
    expect(find('https://github.com', 'me@company.com')).toBe(work);
  });

  it('ignores the username case and surrounding spaces', () => {
    expect(find('https://github.com', '  ME@Example.COM ')).toBe(personal);
  });

  it('matches nothing for a username unknown on this site', () => {
    // A second account: it must be created, and above all not overwritten.
    expect(find('https://github.com', 'other@example.com')).toBeNull();
  });

  it('matches nothing on a different origin', () => {
    expect(find('https://bitbucket.org', 'me@example.com')).toBeNull();
  });

  it('does not accept a neighbouring origin', () => {
    // The §4 rule: strict origin. `github.com.attacker.com` must match no item,
    // on pain of overwriting a password there.
    expect(find('https://github.com.attacker.com', 'me@example.com')).toBeNull();
    expect(find('http://github.com', 'me@example.com')).toBeNull();
  });

  it('matches nothing when no username was detected', () => {
    expect(find('https://github.com', '')).toBeNull();
    expect(find('https://github.com', '   ')).toBeNull();
  });
});

describe('decideProposal', () => {
  const captured = 'new-secret';

  it('offers creation when nothing matches', () => {
    expect(decideProposal(null, captured, null)).toEqual({ kind: 'create' });
  });

  /**
   * The most frequent case: an ordinary sign-in. Staying quiet about it is what
   * gives the badge meaning — lighting up on every successful sign-in would make
   * it meaningless.
   */
  it('stays quiet when the vault already holds this password', () => {
    const existing = item('i1', 'alice', ['https://example.com']);
    expect(decideProposal(existing, captured, captured)).toEqual({ kind: 'none' });
  });

  it('offers an update when the password has changed', () => {
    const existing = item('i1', 'alice', ['https://example.com']);
    expect(decideProposal(existing, captured, 'old')).toEqual({
      kind: 'update',
      item: existing,
    });
  });

  /**
   * An unreadable item: staying quiet on the strength of an impossible
   * comparison would lose the entry. We offer, and the user decides.
   */
  it('offers an update when the existing item is unreadable', () => {
    const existing = item('i1', 'alice', ['https://example.com']);
    expect(decideProposal(existing, captured, null)).toEqual({
      kind: 'update',
      item: existing,
    });
  });
});
