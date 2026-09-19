/**
 * @file Générateur de mots de passe.
 *
 * Un générateur ne « plante » jamais : il produit des mots de passe plus
 * faibles qu'annoncé, sans rien dire. Les tests portent donc sur ce qui ne se
 * voit pas — l'uniformité du tirage, la garantie de composition, le mélange —
 * en injectant une source d'aléa déterministe.
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

/** Source déterministe : rejoue la suite d'octets fournie, en boucle. */
function suite(octets: readonly number[]): RandomSource {
  let i = 0;
  return () => new Uint8Array([octets[i++ % octets.length]!]);
}

const options = (patch: Partial<PasswordOptions>): PasswordOptions => ({
  ...DEFAULT_PASSWORD_OPTIONS,
  ...patch,
});

describe('generatePassword', () => {
  it('respecte la longueur demandée', () => {
    for (const length of [8, 12, 20, 64, 128]) {
      expect(generatePassword(options({ length }))).toHaveLength(length);
    }
  });

  it('ramène une longueur hors bornes dans l’intervalle', () => {
    expect(generatePassword(options({ length: 1 }))).toHaveLength(MIN_LENGTH);
    expect(generatePassword(options({ length: 9999 }))).toHaveLength(MAX_LENGTH);
  });

  it('garantit au moins un caractère de chaque classe demandée', () => {
    // Répété : la garantie doit tenir à chaque tirage, pas en moyenne.
    for (let i = 0; i < 200; i++) {
      const mdp = generatePassword(options({ length: 8 }));
      expect(mdp).toMatch(/[a-z]/);
      expect(mdp).toMatch(/[A-Z]/);
      expect(mdp).toMatch(/[0-9]/);
      expect(mdp).toMatch(/[!@#$%^&*]/);
    }
  });

  it('n’utilise que les classes cochées', () => {
    const mdp = generatePassword(
      options({ length: 40, uppercase: false, symbols: false, avoidAmbiguous: false }),
    );
    expect(mdp).toMatch(/^[a-z0-9]+$/);
  });

  it('exclut les caractères ambigus sur demande', () => {
    const mdp = generatePassword(options({ length: 128, avoidAmbiguous: true }));
    for (const ambigu of 'l1IO0o') {
      expect(mdp).not.toContain(ambigu);
    }
  });

  it('les autorise quand l’option est levée', () => {
    // Sur 4 000 caractères, en croiser zéro signifierait un filtre resté actif.
    const échantillon = Array.from({ length: 40 }, () =>
      generatePassword(options({ length: 100, avoidAmbiguous: false })),
    ).join('');
    expect([...'l1IO0o'].some((c) => échantillon.includes(c))).toBe(true);
  });

  it('refuse de composer sans aucune classe', () => {
    expect(() =>
      generatePassword(
        options({ lowercase: false, uppercase: false, digits: false, symbols: false }),
      ),
    ).toThrow(GeneratorError);
  });

  it('rejette les octets de la tranche incomplète au lieu de les replier', () => {
    // Alphabet de 10 chiffres : la limite est 250, donc 250..255 doivent être
    // rejetés. Une implémentation à modulo replierait 250 sur « 0 ».
    const source = suite([250, 255, 7]);
    const mdp = generatePassword(
      options({
        length: 8,
        lowercase: false,
        uppercase: false,
        symbols: false,
        avoidAmbiguous: false,
      }),
      source,
    );
    expect(mdp).toBe('77777777');
  });

  it('mélange : les classes garanties ne restent pas en tête', () => {
    // Sans mélange, le premier caractère serait toujours une minuscule et le
    // quatrième toujours un symbole, quel que soit le tirage.
    const premiers = new Set(
      Array.from({ length: 300 }, () => generatePassword(options({ length: 8 }))[0]!),
    );
    expect([...premiers].some((c) => /[0-9]/.test(c))).toBe(true);
    expect([...premiers].some((c) => /[!@#$%^&*]/.test(c))).toBe(true);
  });

  it('ne répète pas deux fois le même mot de passe', () => {
    const tirages = new Set(Array.from({ length: 500 }, () => generatePassword()));
    expect(tirages.size).toBe(500);
  });
});
