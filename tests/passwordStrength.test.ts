/**
 * @file Judging a password's weakness.
 *
 * The contract being tested is asymmetric, and that asymmetry is the point: a
 * **weak** verdict must be reliable, a **strong** one is not a certificate.
 * What is pinned here is the first half — everything obviously bad is caught —
 * and the absence of false alarms on passwords a generator would produce.
 */

import { describe, expect, it } from 'vitest';

import { echoesItsOwner, passwordStrength } from '../src/core/vault/passwordStrength.js';

const verdict = (password: string) => passwordStrength(password).strength;
const reason = (password: string) => passwordStrength(password).reason;

describe('passwordStrength', () => {
  it.each([
    ['', 'short'],
    ['abc', 'short'],
    ['Tr0ub4!', 'short'],
  ])('calls %j weak for being too short', (password, why) => {
    expect(verdict(password)).toBe('weak');
    expect(reason(password)).toBe(why);
  });

  it.each([
    'password',
    'Password1',
    'P@ssw0rd!',
    'P4ssw0rd',
    'Az3rty!',
    '123azerty',
    'motdepasse',
    'iloveyou',
    'admin',
  ])(
    'catches %j, which an entropy count gets wrong',
    (password) => {
      // `Password1` scores 53 bits and is cracked instantly. This is the gap a
      // list exists to fill.
      expect(verdict(password)).toBe('weak');
      expect(reason(password)).toBe('notorious');
    },
  );

  it.each(['aaaaaaaa', '11111111', 'ZZZZZZZZZZ'])('catches the repetition in %j', (password) => {
    expect(verdict(password)).toBe('weak');
    expect(reason(password)).toBe('repeated');
  });

  it.each(['abcdefgh', '12345678', 'qwertyui', '87654321', 'asdfghjk'])(
    'catches the run in %j',
    (password) => {
      expect(verdict(password)).toBe('weak');
      expect(reason(password)).toBe('sequence');
    },
  );

  it('catches a long word that draws on one class only', () => {
    expect(verdict('cheeseburger')).toBe('weak');
    expect(reason('cheeseburger')).toBe('single-class');
  });

  it('lets a long single-class passphrase through', () => {
    // Length is the one thing that redeems a single class, and a passphrase is
    // the reason not to punish it outright.
    expect(verdict('correcthorsebatterystaple')).not.toBe('weak');
  });

  it('accepts what the generator produces', () => {
    // A false alarm on a freshly generated password would teach the user to
    // ignore the report, which is the only way this feature truly fails.
    expect(verdict('K7#mQv2$Lz9!Rt4W')).toBe('strong');
    expect(verdict('x9Kq-2Fm-7Bz')).not.toBe('weak');
  });

  it('places fair between the two', () => {
    const fair = passwordStrength('Hv3xQr9m');
    expect(fair.strength).toBe('fair');
    expect(fair.bits).toBeGreaterThan(40);
  });

  it('reports bits that grow with length', () => {
    expect(passwordStrength('Hv3xQr9mPl').bits).toBeGreaterThan(
      passwordStrength('Hv3xQr9m').bits,
    );
  });
});

describe('echoesItsOwner', () => {
  it('catches a password that is the site name', () => {
    expect(echoesItsOwner('github', ['GitHub', 'ada@example.org'])).toBe(true);
    expect(echoesItsOwner('GitHub2024!', ['GitHub'])).toBe(true);
  });

  it('catches a password that is the username', () => {
    expect(echoesItsOwner('ada', ['GitHub', 'ada'])).toBe(true);
  });

  it('leaves an unrelated password alone', () => {
    expect(echoesItsOwner('K7#mQv2$Lz9!', ['GitHub', 'ada@example.org'])).toBe(false);
  });

  it('ignores hints too short to mean anything', () => {
    // A two-letter name would match half the vault.
    expect(echoesItsOwner('K7#mQv2$Lz9!', ['ab', null, ''])).toBe(false);
  });
});
