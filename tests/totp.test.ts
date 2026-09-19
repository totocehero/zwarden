/**
 * @file One-time codes.
 *
 * RFC 6238's vectors (appendix B) are the only proof worth having: a TOTP
 * generator that gets it wrong does not crash, it shows a code the site refuses
 * — and the user blames the site. We therefore replay them as they stand, for
 * all three algorithms.
 */

import { describe, expect, it } from 'vitest';

import { fromBase32 } from '../src/core/crypto/encoding.js';
import {
  TotpError,
  formatTotp,
  generateTotp,
  parseTotp,
  secondsRemaining,
} from '../src/core/vault/totp.js';

/**
 * The RFC's secrets: `12345678901234567890` repeated up to the algorithm's block
 * length, then base32-encoded.
 */
function secretBase32(bytes: number): string {
  const seed = '12345678901234567890';
  const extended = seed.repeat(Math.ceil(bytes / seed.length)).slice(0, bytes);
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let buffer = 0;
  let bits = 0;
  let out = '';
  for (const char of extended) {
    buffer = (buffer << 8) | char.charCodeAt(0);
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += alphabet[(buffer >> bits) & 31];
    }
  }
  if (bits > 0) {
    out += alphabet[(buffer << (5 - bits)) & 31];
  }
  return out;
}

const SHA1 = secretBase32(20);
const SHA256 = secretBase32(32);
const SHA512 = secretBase32(64);

describe('RFC 6238 vectors', () => {
  // Appendix B: instant (seconds), expected 8-digit code.
  const cases: ReadonlyArray<readonly [number, string, string, string]> = [
    [59, SHA1, 'SHA1', '94287082'],
    [59, SHA256, 'SHA256', '46119246'],
    [59, SHA512, 'SHA512', '90693936'],
    [1111111109, SHA1, 'SHA1', '07081804'],
    [1111111111, SHA1, 'SHA1', '14050471'],
    [1234567890, SHA1, 'SHA1', '89005924'],
    [2000000000, SHA1, 'SHA1', '69279037'],
    [20000000000, SHA1, 'SHA1', '65353130'],
    [1111111109, SHA256, 'SHA256', '68084774'],
    [1234567890, SHA512, 'SHA512', '93441116'],
  ];

  for (const [seconds, secret, algo, expected] of cases) {
    it(`${algo} at T=${seconds} gives ${expected}`, async () => {
      const config = parseTotp(
        `otpauth://totp/Test?secret=${secret}&digits=8&algorithm=${algo}&period=30`,
      );
      expect(await generateTotp(config, seconds * 1000)).toBe(expected);
    });
  }

  it('stays correct beyond 2^31 seconds', async () => {
    // There the counter exceeds the range of JavaScript's 32-bit bitwise
    // operators: this is the case that breaks a naive implementation.
    const config = parseTotp(`otpauth://totp/Test?secret=${SHA1}&digits=8`);
    expect(await generateTotp(config, 20000000000 * 1000)).toBe('65353130');
  });
});

describe('parseTotp', () => {
  it('accepts a bare base32 secret, with the RFC defaults', () => {
    const config = parseTotp('JBSWY3DPEHPK3PXP');
    expect(config.digits).toBe(6);
    expect(config.period).toBe(30);
    expect(config.algorithm).toBe('SHA-1');
    expect(config.secret).toEqual(fromBase32('JBSWY3DPEHPK3PXP'));
  });

  it('tolerates spaces, dashes and lowercase in the secret', () => {
    // These secrets get copied by hand from a web page.
    expect(parseTotp('jbsw y3dp-ehpk 3pxp').secret).toEqual(parseTotp('JBSWY3DPEHPK3PXP').secret);
  });

  it('reads digits, period and algorithm from the URI', () => {
    const config = parseTotp(
      'otpauth://totp/Site:moi?secret=JBSWY3DPEHPK3PXP&digits=8&period=60&algorithm=SHA256',
    );
    expect(config.digits).toBe(8);
    expect(config.period).toBe(60);
    expect(config.algorithm).toBe('SHA-256');
  });

  it('falls back to the defaults for an absurd parameter', () => {
    const config = parseTotp('otpauth://totp/Site?secret=JBSWY3DPEHPK3PXP&digits=99&period=0');
    expect(config.digits).toBe(6);
    expect(config.period).toBe(30);
  });

  it('refuses what it cannot compute', () => {
    expect(() => parseTotp('')).toThrow(TotpError);
    expect(() => parseTotp('   ')).toThrow(TotpError);
    // HOTP is a counter, not a clock: a TOTP code there would be wrong.
    expect(() => parseTotp('otpauth://hotp/Site?secret=JBSWY3DPEHPK3PXP')).toThrow(TotpError);
    expect(() => parseTotp('otpauth://totp/Site?digits=6')).toThrow(TotpError);
    expect(() => parseTotp('otpauth://totp/Site?secret=JBSW&algorithm=MD5')).toThrow(TotpError);
    expect(() => parseTotp('not!base32!')).toThrow(TotpError);
  });
});

describe('secondsRemaining', () => {
  const config = parseTotp('JBSWY3DPEHPK3PXP');

  it('counts down to the end of the window', () => {
    expect(secondsRemaining(config, 0)).toBe(30);
    expect(secondsRemaining(config, 1_000)).toBe(29);
    expect(secondsRemaining(config, 29_000)).toBe(1);
    expect(secondsRemaining(config, 30_000)).toBe(30);
  });

  it('never returns zero — a displayed code is valid for at least 1 s', () => {
    for (let s = 0; s < 120; s++) {
      const remaining = secondsRemaining(config, s * 1000);
      expect(remaining).toBeGreaterThan(0);
      expect(remaining).toBeLessThanOrEqual(30);
    }
  });
});

/**
 * The reason {@link OtpCode} receives its first code rather than computing it.
 *
 * The popup copies the code the moment the panel opens; the component would
 * compute its own a few milliseconds later. Those few milliseconds astride a
 * window boundary are enough for the two to fall in different windows — the user
 * reads one code and pastes another, silently, and blames the site.
 *
 * The invariant is now structural (one computation, handed to both), and this
 * test pins the property that made it necessary.
 */
describe('window boundary', () => {
  const config = parseTotp('JBSWY3DPEHPK3PXP');

  it('two computations 4 ms apart can fall in different windows', async () => {
    const justBefore = 30_000 - 2;
    const justAfter = justBefore + 4;

    expect(await generateTotp(config, justBefore)).not.toBe(
      await generateTotp(config, justAfter),
    );
  });

  it('two computations inside the same window agree', async () => {
    expect(await generateTotp(config, 1_000)).toBe(await generateTotp(config, 29_000));
  });
});

describe('formatTotp', () => {
  it('splits the code into two readable halves', () => {
    expect(formatTotp('123456')).toBe('123 456');
    expect(formatTotp('12345678')).toBe('1234 5678');
  });
});
