/**
 * @file The slice of CBOR a passkey registration needs.
 *
 * Checked against the vectors in RFC 8949 rather than against itself: an
 * encoder tested only by its own decoder agrees with itself and with nobody
 * else, and the party reading these bytes is a relying party's library.
 */

import { describe, expect, it } from 'vitest';

import { encodeCbor } from '../src/core/crypto/cbor.js';

const hex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');

describe('encodeCbor', () => {
  it.each([
    [0, '00'],
    [1, '01'],
    [10, '0a'],
    [23, '17'],
    [24, '1818'],
    [100, '1864'],
    [1000, '1903e8'],
    [1000000, '1a000f4240'],
  ])('encodes the unsigned integer %i as in RFC 8949', (value, expected) => {
    expect(hex(encodeCbor(value))).toBe(expected);
  });

  it.each([
    [-1, '20'],
    [-7, '26'],
    [-10, '29'],
    [-100, '3863'],
    [-1000, '3903e7'],
  ])('encodes the negative integer %i as in RFC 8949', (value, expected) => {
    // COSE labels the algorithm-specific parameters with negative integers, so
    // this is not an edge case here — it is every key of the map.
    expect(hex(encodeCbor(value))).toBe(expected);
  });

  it.each([
    ['', '60'],
    ['a', '6161'],
    ['IETF', '6449455446'],
  ])('encodes the text string %j as in RFC 8949', (value, expected) => {
    expect(hex(encodeCbor(value))).toBe(expected);
  });

  it('encodes byte strings with their length', () => {
    expect(hex(encodeCbor(new Uint8Array([1, 2, 3, 4])))).toBe('4401020304');
    expect(hex(encodeCbor(new Uint8Array(0)))).toBe('40');
  });

  it('encodes an array as in RFC 8949', () => {
    expect(hex(encodeCbor([1, 2, 3]))).toBe('83010203');
  });

  it('encodes a map as in RFC 8949', () => {
    expect(hex(encodeCbor(new Map([[1, 2], [3, 4]])))).toBe('a201020304');
  });

  it('encodes an empty map, which is the whole of a `none` attestation', () => {
    expect(hex(encodeCbor(new Map()))).toBe('a0');
  });

  it('keeps the order it was given', () => {
    // CTAP2's canonical form wants sorted keys; the callers supply them sorted,
    // and this is what makes that promise observable.
    expect(hex(encodeCbor(new Map([[3, 1], [1, 2]])))).toBe('a203010102');
  });

  it('uses the shortest head that fits, at every boundary', () => {
    // A longer encoding is still valid CBOR and still wrong for CTAP2.
    expect(hex(encodeCbor(23))).toHaveLength(2);
    expect(hex(encodeCbor(24))).toHaveLength(4);
    expect(hex(encodeCbor(255))).toHaveLength(4);
    expect(hex(encodeCbor(256))).toHaveLength(6);
    expect(hex(encodeCbor(65535))).toHaveLength(6);
    expect(hex(encodeCbor(65536))).toHaveLength(10);
  });

  it('refuses what it does not encode, rather than encoding it wrongly', () => {
    expect(() => encodeCbor(1.5)).toThrow(TypeError);
  });
});
