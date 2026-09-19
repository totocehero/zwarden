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

// The suite runs on both paths — the platform's native methods where they
// exist, and the btoa/atob fallback — so that coverage does not depend on the
// engine version running the tests.
describe.each([
  ['public implementation', toBase64, fromBase64],
  ['btoa/atob fallback', toBase64Js, fromBase64Js],
])('base64 (%s)', (_label, encode, decode) => {
  // RFC 4648 §10 vectors.
  const vectors: ReadonlyArray<readonly [string, string]> = [
    ['', ''],
    ['f', 'Zg=='],
    ['fo', 'Zm8='],
    ['foo', 'Zm9v'],
    ['foob', 'Zm9vYg=='],
    ['fooba', 'Zm9vYmE='],
    ['foobar', 'Zm9vYmFy'],
  ];

  it.each(vectors)('encodes %j as %j', (plain, encoded) => {
    expect(encode(toUtf8Bytes(plain))).toBe(encoded);
  });

  it.each(vectors)('decodes %j from %j', (plain, encoded) => {
    expect(fromUtf8Bytes(decode(encoded))).toBe(plain);
  });

  it('handles all 256 byte values without loss', () => {
    const all = new Uint8Array(256);
    for (let i = 0; i < 256; i++) all[i] = i;
    expect(decode(encode(all))).toEqual(all);
  });

  it('round-trips across random lengths', () => {
    for (let len = 0; len < 200; len++) {
      const bytes = crypto.getRandomValues(new Uint8Array(len));
      expect(decode(encode(bytes))).toEqual(bytes);
    }
  });

  it('preserves multi-byte UTF-8', () => {
    const text = 'password — 日本語 🔐 àéîõü';
    expect(fromUtf8Bytes(decode(encode(toUtf8Bytes(text))))).toBe(text);
  });
});

describe('fromBase64 input tolerance', () => {
  // Normalisation (whitespace, URL-safe, padding) is done by the public
  // function before it delegates to the decoder: it is tested on that alone.
  it('accepts the URL-safe alphabet as input', () => {
    const bytes = Uint8Array.of(0xfb, 0xff, 0xbf);
    expect(fromBase64(toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_'))).toEqual(bytes);
  });

  it('ignores stray whitespace', () => {
    expect(fromUtf8Bytes(fromBase64('Zm9v YmFy\n'))).toBe('foobar');
  });
});

describe('toBase64Url', () => {
  it('uses the URL-safe alphabet and strips the padding', () => {
    // 0xfb 0xff 0xbf encodes as `+/+/`: both characters that need replacing.
    expect(toBase64Url(Uint8Array.of(0xfb, 0xff, 0xbf))).toBe('-_-_');
    expect(toBase64Url(toUtf8Bytes('f'))).toBe('Zg');
    expect(toBase64Url(toUtf8Bytes('fo'))).toBe('Zm8');
    expect(toBase64Url(new Uint8Array(0))).toBe('');
  });
});

describe('timingSafeEqual', () => {
  it('recognises two identical buffers', () => {
    expect(timingSafeEqual(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2, 3))).toBe(true);
  });

  it('rejects a difference in the last byte', () => {
    expect(timingSafeEqual(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2, 4))).toBe(false);
  });

  it('rejects a difference in the first byte', () => {
    expect(timingSafeEqual(Uint8Array.of(9, 2, 3), Uint8Array.of(1, 2, 3))).toBe(false);
  });

  it('rejects differing lengths', () => {
    expect(timingSafeEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 2, 3))).toBe(false);
  });

  it('recognises two empty buffers', () => {
    expect(timingSafeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
  });
});

describe('concatBytes', () => {
  it('concatenates in order', () => {
    expect(concatBytes(Uint8Array.of(1), Uint8Array.of(2, 3), new Uint8Array(0))).toEqual(
      Uint8Array.of(1, 2, 3),
    );
  });
});
