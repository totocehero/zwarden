import { describe, expect, it } from 'vitest';

import {
  concatBytes,
  fromBase64,
  fromBase64Js,
  fromUtf8Bytes,
  timingSafeEqual,
  toBase64,
  toBase64Js,
  toBase64Url,
  toUtf8Bytes,
} from '../src/core/crypto/encoding.js';

// La suite tourne sur les deux chemins — méthodes natives de la plateforme
// quand elles existent, et repli btoa/atob — pour que la couverture ne dépende
// pas de la version du moteur qui exécute les tests.
describe.each([
  ['implémentation publique', toBase64, fromBase64],
  ['repli btoa/atob', toBase64Js, fromBase64Js],
])('base64 (%s)', (_label, encode, decode) => {
  // Vecteurs RFC 4648 §10.
  const vectors: ReadonlyArray<readonly [string, string]> = [
    ['', ''],
    ['f', 'Zg=='],
    ['fo', 'Zm8='],
    ['foo', 'Zm9v'],
    ['foob', 'Zm9vYg=='],
    ['fooba', 'Zm9vYmE='],
    ['foobar', 'Zm9vYmFy'],
  ];

  it.each(vectors)('encode %j en %j', (plain, encoded) => {
    expect(encode(toUtf8Bytes(plain))).toBe(encoded);
  });

  it.each(vectors)('décode %j depuis %j', (plain, encoded) => {
    expect(fromUtf8Bytes(decode(encoded))).toBe(plain);
  });

  it('gère les 256 valeurs d’octet sans perte', () => {
    const all = new Uint8Array(256);
    for (let i = 0; i < 256; i++) all[i] = i;
    expect(decode(encode(all))).toEqual(all);
  });

  it('fait un aller-retour sur des longueurs aléatoires', () => {
    for (let len = 0; len < 200; len++) {
      const bytes = crypto.getRandomValues(new Uint8Array(len));
      expect(decode(encode(bytes))).toEqual(bytes);
    }
  });

  it('préserve l’UTF-8 multi-octets', () => {
    const text = 'mot de passe — 日本語 🔐 àéîõü';
    expect(fromUtf8Bytes(decode(encode(toUtf8Bytes(text))))).toBe(text);
  });
});

describe('tolérance d’entrée de fromBase64', () => {
  // La normalisation (espaces, URL-safe, padding) est faite par la fonction
  // publique avant de déléguer au décodeur : elle n'est testée que sur elle.
  it('accepte l’alphabet URL-safe en entrée', () => {
    const bytes = Uint8Array.of(0xfb, 0xff, 0xbf);
    expect(fromBase64(toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_'))).toEqual(bytes);
  });

  it('ignore les espaces parasites', () => {
    expect(fromUtf8Bytes(fromBase64('Zm9v YmFy\n'))).toBe('foobar');
  });
});

describe('toBase64Url', () => {
  it('utilise l’alphabet URL-safe et retire le padding', () => {
    // 0xfb 0xff 0xbf encode en `+/+/` : les deux caractères à remplacer.
    expect(toBase64Url(Uint8Array.of(0xfb, 0xff, 0xbf))).toBe('-_-_');
    expect(toBase64Url(toUtf8Bytes('f'))).toBe('Zg');
    expect(toBase64Url(toUtf8Bytes('fo'))).toBe('Zm8');
    expect(toBase64Url(new Uint8Array(0))).toBe('');
  });
});

describe('timingSafeEqual', () => {
  it('reconnaît deux tampons identiques', () => {
    expect(timingSafeEqual(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2, 3))).toBe(true);
  });

  it('rejette une divergence sur le dernier octet', () => {
    expect(timingSafeEqual(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2, 4))).toBe(false);
  });

  it('rejette une divergence sur le premier octet', () => {
    expect(timingSafeEqual(Uint8Array.of(9, 2, 3), Uint8Array.of(1, 2, 3))).toBe(false);
  });

  it('rejette des longueurs différentes', () => {
    expect(timingSafeEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 2, 3))).toBe(false);
  });

  it('reconnaît deux tampons vides', () => {
    expect(timingSafeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
  });
});

describe('concatBytes', () => {
  it('concatène dans l’ordre', () => {
    expect(concatBytes(Uint8Array.of(1), Uint8Array.of(2, 3), new Uint8Array(0))).toEqual(
      Uint8Array.of(1, 2, 3),
    );
  });
});
