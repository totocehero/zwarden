/**
 * Compares three base64 implementations to settle a simplification.
 * Usage: node scripts/bench-base64.mjs
 */

const LOOKUP = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const REVERSE = (() => {
  const t = new Uint8Array(256).fill(255);
  for (let i = 0; i < LOOKUP.length; i++) t[LOOKUP.charCodeAt(i)] = i;
  t['-'.charCodeAt(0)] = 62;
  t['_'.charCodeAt(0)] = 63;
  return t;
})();

function handToBase64(bytes) {
  let out = '';
  const len = bytes.length;
  const rem = len % 3;
  const limit = len - rem;
  for (let i = 0; i < limit; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += LOOKUP[(n >>> 18) & 63] + LOOKUP[(n >>> 12) & 63] + LOOKUP[(n >>> 6) & 63] + LOOKUP[n & 63];
  }
  if (rem === 1) {
    const n = bytes[limit];
    out += LOOKUP[n >>> 2] + LOOKUP[(n << 4) & 63] + '==';
  } else if (rem === 2) {
    const n = (bytes[limit] << 8) | bytes[limit + 1];
    out += LOOKUP[n >>> 10] + LOOKUP[(n >>> 4) & 63] + LOOKUP[(n << 2) & 63] + '=';
  }
  return out;
}

function handFromBase64(input) {
  let clean = 0;
  const codes = new Uint8Array(input.length);
  for (let i = 0; i < input.length; i++) {
    const v = REVERSE[input.charCodeAt(i)];
    if (v !== 255) codes[clean++] = v;
  }
  const out = new Uint8Array((clean * 3) >>> 2);
  let o = 0, i = 0;
  for (; i + 4 <= clean; i += 4) {
    const n = (codes[i] << 18) | (codes[i + 1] << 12) | (codes[i + 2] << 6) | codes[i + 3];
    out[o++] = (n >>> 16) & 255;
    out[o++] = (n >>> 8) & 255;
    out[o++] = n & 255;
  }
  const tail = clean - i;
  if (tail === 3) {
    const n = (codes[i] << 18) | (codes[i + 1] << 12) | (codes[i + 2] << 6);
    out[o++] = (n >>> 16) & 255;
    out[o++] = (n >>> 8) & 255;
  } else if (tail === 2) {
    out[o++] = ((codes[i] << 18) | (codes[i + 1] << 12)) >>> 16 & 255;
  }
  return o === out.length ? out : out.subarray(0, o);
}

function atobToBase64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function atobFromBase64(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const hasNative = typeof Uint8Array.prototype.toBase64 === 'function';

function bench(label, fn, iterations) {
  fn(); // warm-up
  const t0 = performance.now();
  for (let i = 0; i < iterations; i++) fn();
  return { label, ms: +(performance.now() - t0).toFixed(1) };
}

// A realistic profile: a 1000-item vault, ~6 EncStrings per item,
// chacune ~120 octets (IV 16 + ciphertext ~64 + MAC 32).
const SAMPLES = Array.from({ length: 6000 }, () =>
  crypto.getRandomValues(new Uint8Array(120)),
);
const ENCODED = SAMPLES.map(handToBase64);

console.log(`Node ${process.version} — native toBase64/fromBase64: ${hasNative ? 'yes' : 'no'}`);
console.log('\nProfile: 6000 EncStrings of 120 bytes (a ~1000-item vault), 20 passes\n');

const results = [
  bench('encode  hand-made', () => SAMPLES.forEach(handToBase64), 20),
  bench('encode  btoa     ', () => SAMPLES.forEach(atobToBase64), 20),
  bench('decode  hand-made', () => ENCODED.forEach(handFromBase64), 20),
  bench('decode  atob     ', () => ENCODED.forEach(atobFromBase64), 20),
];

if (hasNative) {
  results.push(
    bench('encode  native   ', () => SAMPLES.forEach((b) => b.toBase64()), 20),
    bench('decode  native   ', () => ENCODED.forEach((s) => Uint8Array.fromBase64(s)), 20),
  );
}

for (const r of results) console.log(`  ${r.label}  ${String(r.ms).padStart(7)} ms`);

// Consistency check across implementations.
const probe = crypto.getRandomValues(new Uint8Array(257));
const ok =
  handToBase64(probe) === atobToBase64(probe) &&
  Buffer.compare(Buffer.from(handFromBase64(ENCODED[0])), Buffer.from(atobFromBase64(ENCODED[0]))) === 0 &&
  (!hasNative || handToBase64(probe) === probe.toBase64());
console.log(`\nConsistency across implementations: ${ok ? 'OK' : 'DIVERGENCE'}`);
