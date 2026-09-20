/**
 * @file Asking whether a password has been in a breach.
 *
 * The property that makes this acceptable in a password manager is that the
 * password never leaves, nor does its full hash — only five hex characters.
 * That is what these tests are mostly about, and they check it by watching
 * what the injected fetcher is actually handed.
 *
 * The SHA-1 vector is the published one for `password`, so a broken hash shows
 * up here rather than as a corpus that never matches anything.
 */

import { describe, expect, it, vi } from 'vitest';

import {
  checkPasswords,
  countInRange,
  sha1Hex,
  splitHash,
} from '../src/core/vault/breachCheck.js';

/** SHA-1("password"), as every corpus indexes it. */
const PASSWORD_SHA1 = '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8';

describe('sha1Hex', () => {
  it('matches the published vector', async () => {
    expect(await sha1Hex('password')).toBe(PASSWORD_SHA1);
  });

  it('answers in uppercase, as the corpus is indexed', async () => {
    expect(await sha1Hex('hello')).toBe((await sha1Hex('hello')).toUpperCase());
  });
});

describe('splitHash', () => {
  it('sends five characters and keeps the other thirty-five', () => {
    const { prefix, suffix } = splitHash(PASSWORD_SHA1);
    expect(prefix).toBe('5BAA6');
    expect(suffix).toBe('1E4C9B93F3F0682250B6CF8331B7EE68FD8');
    expect(prefix + suffix).toBe(PASSWORD_SHA1);
  });
});

describe('countInRange', () => {
  const body = ['0018A45C4D1DEF81644B54AB7F969B88D65:1', '1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365'].join(
    '\r\n',
  );

  it('finds a suffix and reports its count', () => {
    expect(countInRange(body, '1E4C9B93F3F0682250B6CF8331B7EE68FD8')).toBe(9_659_365);
  });

  it('reports nothing for a suffix that is absent', () => {
    expect(countInRange(body, 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')).toBe(0);
  });

  it('treats the padding as absence, which is what it is for', () => {
    // `Add-Padding` inserts decoys with a count of zero so the size of the
    // answer says nothing. They must not be told apart from a real absence.
    expect(countInRange('AAAA:0\r\nBBBB:0', 'AAAA')).toBe(0);
  });

  it('ignores the carriage returns and the case the API sends', () => {
    expect(countInRange('abcd:12\r\n', 'ABCD')).toBe(12);
  });

  it('survives a line that is not one', () => {
    expect(countInRange('garbage\r\nABCD:3', 'ABCD')).toBe(3);
  });
});

describe('checkPasswords', () => {
  it('never hands the fetcher more than the prefix', async () => {
    const seen: string[] = [];
    await checkPasswords(['password'], async (prefix) => {
      seen.push(prefix);
      return '';
    });

    // The whole privacy argument, asserted: five characters, and nothing that
    // could be the password or its full hash.
    expect(seen).toEqual(['5BAA6']);
    expect(seen[0]).toHaveLength(5);
  });

  it('reports a password the corpus knows', async () => {
    const found = await checkPasswords(
      ['password'],
      async () => '1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365',
    );
    expect(found.get('password')).toBe(9_659_365);
  });

  it('says nothing about one the corpus does not know', async () => {
    const found = await checkPasswords(['K7#mQv2$Lz9!Rt4W'], async () => 'AAAA:1');
    expect(found.size).toBe(0);
  });

  it('asks once for a password used many times', async () => {
    const fetcher = vi.fn(async () => '');
    await checkPasswords(['same', 'same', 'same'], fetcher);

    // Fewer requests, less exposure and a faster answer, from one line.
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it('asks nothing about an empty password', async () => {
    const fetcher = vi.fn(async () => '');
    await checkPasswords(['', ''], fetcher);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('keeps the answers it got when one lookup fails', async () => {
    let call = 0;
    const found = await checkPasswords(['password', 'other'], async () => {
      call += 1;
      if (call === 1) {
        throw new Error('network');
      }
      return `${splitHash(await sha1Hex('other')).suffix}:42`;
    }, 1);

    // A hiccup part-way through must not throw away what was already learnt.
    expect(found.get('other')).toBe(42);
    expect(found.has('password')).toBe(false);
  });

  it('does nothing at all when there is nothing to ask', async () => {
    const fetcher = vi.fn(async () => '');
    expect((await checkPasswords([], fetcher)).size).toBe(0);
    expect(fetcher).not.toHaveBeenCalled();
  });
});
