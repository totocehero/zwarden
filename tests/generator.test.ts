/**
 * @file Password generator.
 *
 * A generator never "crashes": it produces weaker passwords than advertised,
 * and says nothing. The tests therefore target what cannot be seen — the
 * uniformity of the draw, the composition guarantee, the shuffle — by injecting
 * a deterministic random source.
 */

import { describe, expect, it } from 'vitest';

import {
  DEFAULT_PASSWORD_OPTIONS,
  GeneratorError,
  MAX_LENGTH,
  MIN_LENGTH,
  type PasswordOptions,
  type RandomSource,
  generatePassword,
} from '../src/core/generator/password.js';

/** Deterministic source: replays the given byte sequence, looping. */
function sequence(bytes: readonly number[]): RandomSource {
  let i = 0;
  return () => new Uint8Array([bytes[i++ % bytes.length]!]);
}

const options = (patch: Partial<PasswordOptions>): PasswordOptions => ({
  ...DEFAULT_PASSWORD_OPTIONS,
  ...patch,
});

describe('generatePassword', () => {
  it('honours the requested length', () => {
    for (const length of [8, 12, 20, 64, 128]) {
      expect(generatePassword(options({ length }))).toHaveLength(length);
    }
  });

  it('brings an out-of-range length back into the interval', () => {
    expect(generatePassword(options({ length: 1 }))).toHaveLength(MIN_LENGTH);
    expect(generatePassword(options({ length: 9999 }))).toHaveLength(MAX_LENGTH);
  });

  it('guarantees at least one character from every requested class', () => {
    // Repeated: the guarantee must hold on every draw, not on average.
    for (let i = 0; i < 200; i++) {
      const password = generatePassword(options({ length: 8 }));
      expect(password).toMatch(/[a-z]/);
      expect(password).toMatch(/[A-Z]/);
      expect(password).toMatch(/[0-9]/);
      expect(password).toMatch(/[!@#$%^&*]/);
    }
  });

  it('uses only the ticked classes', () => {
    const password = generatePassword(
      options({ length: 40, uppercase: false, symbols: false, avoidAmbiguous: false }),
    );
    expect(password).toMatch(/^[a-z0-9]+$/);
  });

  it('excludes ambiguous characters on request', () => {
    const password = generatePassword(options({ length: 128, avoidAmbiguous: true }));
    for (const ambiguous of 'l1IO0o') {
      expect(password).not.toContain(ambiguous);
    }
  });

  it('allows them again when the option is lifted', () => {
    // Across 4,000 characters, meeting none would mean a filter left switched on.
    const sample = Array.from({ length: 40 }, () =>
      generatePassword(options({ length: 100, avoidAmbiguous: false })),
    ).join('');
    expect([...'l1IO0o'].some((c) => sample.includes(c))).toBe(true);
  });

  it('refuses to compose with no class at all', () => {
    expect(() =>
      generatePassword(
        options({ lowercase: false, uppercase: false, digits: false, symbols: false }),
      ),
    ).toThrow(GeneratorError);
  });

  it('rejects the incomplete slice rather than folding it back', () => {
    // A 10-digit alphabet: the limit is 250, so 250..255 must be rejected. A
    // modulo implementation would fold 250 onto "0".
    const source = sequence([250, 255, 7]);
    const password = generatePassword(
      options({
        length: 8,
        lowercase: false,
        uppercase: false,
        symbols: false,
        avoidAmbiguous: false,
      }),
      source,
    );
    expect(password).toBe('77777777');
  });

  it('shuffles: the guaranteed classes do not stay at the head', () => {
    // Without a shuffle, the first character would always be a lowercase letter
    // and the fourth always a symbol, whatever the draw.
    const firsts = new Set(
      Array.from({ length: 300 }, () => generatePassword(options({ length: 8 }))[0]!),
    );
    expect([...firsts].some((c) => /[0-9]/.test(c))).toBe(true);
    expect([...firsts].some((c) => /[!@#$%^&*]/.test(c))).toBe(true);
  });

  it('never draws the same password twice', () => {
    const draws = new Set(Array.from({ length: 500 }, () => generatePassword()));
    expect(draws.size).toBe(500);
  });
});
