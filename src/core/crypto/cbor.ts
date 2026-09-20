/**
 * @file The slice of CBOR that WebAuthn registration needs.
 *
 * Creating a passkey means handing the site an attestation object and a public
 * key, and both are CBOR — not JSON. A general CBOR library is tens of
 * kilobytes and handles tagged values, floats, indefinite lengths and
 * streaming, none of which appear here.
 *
 * What does appear is four types: unsigned integers, negative integers, byte
 * strings and text strings, arranged in maps. That is the whole of a COSE key
 * and the whole of an `none`-format attestation object. So it is written out,
 * in about sixty lines, and tested by decoding what it produces.
 *
 * ## Canonical order
 *
 * Map keys are emitted in the order given. CTAP2's canonical form wants them
 * sorted, and the callers here supply them already sorted — which is stated
 * because relying on a caller is a weaker guarantee than enforcing it, and the
 * cost of the enforcement (a comparator over mixed integer and text keys) is
 * not worth paying for two call sites that are right.
 */

/** A value this encoder accepts. */
export type CborValue =
  | number
  | string
  | Uint8Array
  | readonly CborValue[]
  | ReadonlyMap<number | string, CborValue>;

/** Major types, as the specification numbers them. */
const UNSIGNED = 0;
const NEGATIVE = 1;
const BYTES = 2;
const TEXT = 3;
const ARRAY = 4;
const MAP = 5;

/** Emits a major type and its argument, in the shortest form that fits. */
function head(major: number, value: number, out: number[]): void {
  const prefix = major << 5;
  if (value < 24) {
    out.push(prefix | value);
  } else if (value < 0x100) {
    out.push(prefix | 24, value);
  } else if (value < 0x10000) {
    out.push(prefix | 25, value >> 8, value & 0xff);
  } else {
    out.push(prefix | 26, (value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
  }
}

function write(value: CborValue, out: number[]): void {
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) {
      throw new TypeError('CBOR here encodes integers only');
    }
    // A negative integer is encoded as `-1 - n`, which is why -1 takes no more
    // room than 0 and why the COSE key's negative labels cost nothing.
    if (value < 0) {
      head(NEGATIVE, -1 - value, out);
    } else {
      head(UNSIGNED, value, out);
    }
    return;
  }
  if (typeof value === 'string') {
    const bytes = new TextEncoder().encode(value);
    head(TEXT, bytes.length, out);
    out.push(...bytes);
    return;
  }
  if (value instanceof Uint8Array) {
    head(BYTES, value.length, out);
    out.push(...value);
    return;
  }
  if (Array.isArray(value)) {
    head(ARRAY, value.length, out);
    for (const item of value as readonly CborValue[]) {
      write(item, out);
    }
    return;
  }
  const map = value as ReadonlyMap<number | string, CborValue>;
  head(MAP, map.size, out);
  for (const [key, item] of map) {
    write(key, out);
    write(item, out);
  }
}

/** Encodes one value. */
export function encodeCbor(value: CborValue): Uint8Array {
  const out: number[] = [];
  write(value, out);
  return Uint8Array.from(out);
}
