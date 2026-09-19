/**
 * @file Codes à usage unique.
 *
 * Les vecteurs de la RFC 6238 (annexe B) sont la seule preuve qui vaille :
 * un générateur TOTP qui se trompe ne plante pas, il affiche un code refusé
 * par le site — et l'utilisateur accuse le site. On les rejoue donc tels
 * quels, pour les trois algorithmes.
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
 * Secrets de la RFC : `12345678901234567890` répété jusqu'à la longueur du
 * bloc de l'algorithme, puis encodé en base32.
 */
function secretBase32(bytes: number): string {
  const graine = '12345678901234567890';
  const étendu = graine.repeat(Math.ceil(bytes / graine.length)).slice(0, bytes);
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let buffer = 0;
  let bits = 0;
  let out = '';
  for (const char of étendu) {
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

describe('vecteurs RFC 6238', () => {
  // Annexe B : instant (secondes), code attendu sur 8 chiffres.
  const cas: ReadonlyArray<readonly [number, string, string, string]> = [
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

  for (const [secondes, secret, algo, attendu] of cas) {
    it(`${algo} à T=${secondes} donne ${attendu}`, async () => {
      const config = parseTotp(
        `otpauth://totp/Test?secret=${secret}&digits=8&algorithm=${algo}&period=30`,
      );
      expect(await generateTotp(config, secondes * 1000)).toBe(attendu);
    });
  }

  it('reste juste au-delà de 2^31 secondes', async () => {
    // Le compteur y dépasse la plage des opérateurs binaires 32 bits de
    // JavaScript : c'est le cas qui casse une implémentation naïve.
    const config = parseTotp(`otpauth://totp/Test?secret=${SHA1}&digits=8`);
    expect(await generateTotp(config, 20000000000 * 1000)).toBe('65353130');
  });
});

describe('parseTotp', () => {
  it('accepte un secret base32 nu, avec les défauts de la RFC', () => {
    const config = parseTotp('JBSWY3DPEHPK3PXP');
    expect(config.digits).toBe(6);
    expect(config.period).toBe(30);
    expect(config.algorithm).toBe('SHA-1');
    expect(config.secret).toEqual(fromBase32('JBSWY3DPEHPK3PXP'));
  });

  it('tolère espaces, tirets et minuscules dans le secret', () => {
    // Ces secrets sont recopiés à la main depuis une page web.
    expect(parseTotp('jbsw y3dp-ehpk 3pxp').secret).toEqual(parseTotp('JBSWY3DPEHPK3PXP').secret);
  });

  it('lit digits, period et algorithm depuis l’URI', () => {
    const config = parseTotp(
      'otpauth://totp/Site:moi?secret=JBSWY3DPEHPK3PXP&digits=8&period=60&algorithm=SHA256',
    );
    expect(config.digits).toBe(8);
    expect(config.period).toBe(60);
    expect(config.algorithm).toBe('SHA-256');
  });

  it('retombe sur les défauts pour un paramètre aberrant', () => {
    const config = parseTotp('otpauth://totp/Site?secret=JBSWY3DPEHPK3PXP&digits=99&period=0');
    expect(config.digits).toBe(6);
    expect(config.period).toBe(30);
  });

  it('refuse ce qu’il ne sait pas calculer', () => {
    expect(() => parseTotp('')).toThrow(TotpError);
    expect(() => parseTotp('   ')).toThrow(TotpError);
    // HOTP est un compteur, pas une horloge : un code TOTP y serait faux.
    expect(() => parseTotp('otpauth://hotp/Site?secret=JBSWY3DPEHPK3PXP')).toThrow(TotpError);
    expect(() => parseTotp('otpauth://totp/Site?digits=6')).toThrow(TotpError);
    expect(() => parseTotp('otpauth://totp/Site?secret=JBSW&algorithm=MD5')).toThrow(TotpError);
    expect(() => parseTotp('pas!du!base32')).toThrow(TotpError);
  });
});

describe('secondsRemaining', () => {
  const config = parseTotp('JBSWY3DPEHPK3PXP');

  it('décompte jusqu’à la fin de la fenêtre', () => {
    expect(secondsRemaining(config, 0)).toBe(30);
    expect(secondsRemaining(config, 1_000)).toBe(29);
    expect(secondsRemaining(config, 29_000)).toBe(1);
    expect(secondsRemaining(config, 30_000)).toBe(30);
  });

  it('ne renvoie jamais zéro — un code affiché est valide au moins 1 s', () => {
    for (let s = 0; s < 120; s++) {
      const restant = secondsRemaining(config, s * 1000);
      expect(restant).toBeGreaterThan(0);
      expect(restant).toBeLessThanOrEqual(30);
    }
  });
});

describe('formatTotp', () => {
  it('coupe le code en deux moitiés lisibles', () => {
    expect(formatTotp('123456')).toBe('123 456');
    expect(formatTotp('12345678')).toBe('1234 5678');
  });
});
