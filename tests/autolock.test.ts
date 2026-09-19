/**
 * @file The auto-lock rule.
 *
 * The rest of the mechanism (the periodic alarm, the browser events) only exists
 * inside a browser; the decision, though, is a pure function — and it is the one
 * that decides whether to ask for the master password again. It is therefore the
 * only part worth pinning down here.
 */

import { describe, expect, it } from 'vitest';

import { DEFAULT_SETTINGS, shouldAutoLock } from '../src/shared/storage.js';

const MINUTE = 60_000;

describe('shouldAutoLock', () => {
  it('never locks when the delay is zero', () => {
    // The default: only closing the browser locks.
    expect(DEFAULT_SETTINGS.autoLockMinutes).toBe(0);
    expect(shouldAutoLock(0, 0, 10 * 365 * 24 * 60 * MINUTE)).toBe(false);
  });

  it('does not lock before the deadline', () => {
    expect(shouldAutoLock(1_000_000, 15, 1_000_000 + 14 * MINUTE)).toBe(false);
  });

  it('locks at the deadline and beyond', () => {
    expect(shouldAutoLock(1_000_000, 15, 1_000_000 + 15 * MINUTE)).toBe(true);
    expect(shouldAutoLock(1_000_000, 15, 1_000_000 + 60 * MINUTE)).toBe(true);
  });

  it('does not lock on a missing timestamp', () => {
    // A lost timestamp is no proof of inactivity: the service worker resets it
    // rather than lock.
    expect(shouldAutoLock(null, 15, Date.now())).toBe(false);
  });
});
