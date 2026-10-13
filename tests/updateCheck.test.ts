/**
 * @file Asking the repository for a newer release.
 *
 * Two things matter and both are checked: the comparison must not announce an
 * update for a version that is not newer (or for a tag that is not a version),
 * and a check that fails must say so quietly rather than throw into a worker
 * that has other things to do.
 */

import { describe, expect, it, vi } from 'vitest';

import {
  RELEASES_API_URL,
  RELEASES_PAGE_URL,
  checkForUpdate,
  isNewer,
  parseLatestRelease,
  parseVersion,
} from '../src/core/update/updateCheck.js';

describe('parseVersion', () => {
  it('reads the manifest spelling and the tag spelling alike', () => {
    expect(parseVersion('0.1.1')).toEqual([0, 1, 1]);
    expect(parseVersion('v0.1.1')).toEqual([0, 1, 1]);
    expect(parseVersion(' V2.0 ')).toEqual([2, 0]);
  });

  it('refuses what is not a version', () => {
    expect(parseVersion('nightly')).toBeNull();
    expect(parseVersion('1.2.x')).toBeNull();
    expect(parseVersion('')).toBeNull();
    expect(parseVersion('1..2')).toBeNull();
  });
});

describe('isNewer', () => {
  it('compares numerically, not as text', () => {
    expect(isNewer('0.9.0', '0.10.0')).toBe(true);
    expect(isNewer('0.10.0', '0.9.0')).toBe(false);
  });

  it('treats a missing trailing part as zero', () => {
    expect(isNewer('0.2.0', '0.2')).toBe(false);
    expect(isNewer('0.2', '0.2.0')).toBe(false);
    expect(isNewer('0.2', '0.2.1')).toBe(true);
  });

  it('says nothing is newer than itself', () => {
    expect(isNewer('0.1.1', 'v0.1.1')).toBe(false);
  });

  it('never calls an unreadable tag newer', () => {
    expect(isNewer('0.1.1', 'nightly')).toBe(false);
    expect(isNewer('dev', '0.1.1')).toBe(false);
  });
});

describe('parseLatestRelease', () => {
  it('takes the version from the tag and the page from the answer', () => {
    expect(
      parseLatestRelease({
        tag_name: 'v0.2.0',
        html_url: 'https://github.com/totocehero/zwarden/releases/tag/v0.2.0',
        draft: false,
        prerelease: false,
      }),
    ).toEqual({
      version: '0.2.0',
      url: 'https://github.com/totocehero/zwarden/releases/tag/v0.2.0',
    });
  });

  it('falls back to the releases listing when the page is missing or odd', () => {
    expect(parseLatestRelease({ tag_name: 'v0.2.0' })?.url).toBe(RELEASES_PAGE_URL);
    expect(parseLatestRelease({ tag_name: 'v0.2.0', html_url: 'javascript:alert(1)' })?.url).toBe(
      RELEASES_PAGE_URL,
    );
  });

  it('ignores drafts, pre-releases, and tags that are not versions', () => {
    expect(parseLatestRelease({ tag_name: 'v0.2.0', draft: true })).toBeNull();
    expect(parseLatestRelease({ tag_name: 'v0.2.0', prerelease: true })).toBeNull();
    expect(parseLatestRelease({ tag_name: 'nightly' })).toBeNull();
  });

  it('ignores an error body', () => {
    expect(parseLatestRelease({ message: 'Not Found' })).toBeNull();
    expect(parseLatestRelease(null)).toBeNull();
    expect(parseLatestRelease('v0.2.0')).toBeNull();
  });
});

describe('checkForUpdate', () => {
  it('asks the latest-release endpoint and only that', async () => {
    const fetchJson = vi.fn().mockResolvedValue({ tag_name: 'v0.3.0' });
    const status = await checkForUpdate(fetchJson, () => 1_000);
    expect(fetchJson).toHaveBeenCalledTimes(1);
    expect(fetchJson).toHaveBeenCalledWith(RELEASES_API_URL);
    expect(status).toEqual({
      checkedAt: 1_000,
      latest: { version: '0.3.0', url: RELEASES_PAGE_URL },
    });
  });

  it('turns a failed request into a dated "nothing", and does not throw', async () => {
    const fetchJson = vi.fn().mockRejectedValue(new Error('offline'));
    await expect(checkForUpdate(fetchJson, () => 42)).resolves.toEqual({
      checkedAt: 42,
      latest: null,
    });
  });
});
