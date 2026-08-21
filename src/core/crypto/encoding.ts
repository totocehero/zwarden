/**
 * Primitives d'encodage sans dépendance.
 *
 * Tout est exprimé en Uint8Array. On n'expose jamais de `string` binaire
 * (« binary string ») en dehors de ce module : c'est une source classique de
 * corruption silencieuse sur les octets >= 0x80.
 */

const B64_LOOKUP = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/** Table inverse construite une fois, indexée par code ASCII. */
const B64_REVERSE = /* @__PURE__ */ (() => {
  const table = new Uint8Array(256).fill(255);
  for (let i = 0; i < B64_LOOKUP.length; i++) {
    table[B64_LOOKUP.charCodeAt(i)] = i;
  }
  // Alphabet URL-safe accepté en entrée, par tolérance.
  table['-'.charCodeAt(0)] = 62;
  table['_'.charCodeAt(0)] = 63;
  return table;
})();

export function toBase64(bytes: Uint8Array): string {
  let out = '';
  const len = bytes.length;
  const remainder = len % 3;
  const limit = len - remainder;

  for (let i = 0; i < limit; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out +=
      B64_LOOKUP[(n >>> 18) & 63]! +
      B64_LOOKUP[(n >>> 12) & 63]! +
      B64_LOOKUP[(n >>> 6) & 63]! +
      B64_LOOKUP[n & 63]!;
  }

  if (remainder === 1) {
    const n = bytes[limit]!;
    out += B64_LOOKUP[n >>> 2]! + B64_LOOKUP[(n << 4) & 63]! + '==';
  } else if (remainder === 2) {
    const n = (bytes[limit]! << 8) | bytes[limit + 1]!;
    out += B64_LOOKUP[n >>> 10]! + B64_LOOKUP[(n >>> 4) & 63]! + B64_LOOKUP[(n << 2) & 63]! + '=';
  }

  return out;
}

export function fromBase64(input: string): Uint8Array {
  // On ignore le padding et tout caractère hors alphabet plutôt que de jeter :
  // les payloads serveur contiennent parfois des espaces parasites.
  let clean = 0;
  const codes = new Uint8Array(input.length);
  for (let i = 0; i < input.length; i++) {
    const v = B64_REVERSE[input.charCodeAt(i)]!;
    if (v !== 255) {
      codes[clean++] = v;
    }
  }

  const out = new Uint8Array((clean * 3) >>> 2);
  let o = 0;
  let i = 0;
  for (; i + 4 <= clean; i += 4) {
    const n = (codes[i]! << 18) | (codes[i + 1]! << 12) | (codes[i + 2]! << 6) | codes[i + 3]!;
    out[o++] = (n >>> 16) & 255;
    out[o++] = (n >>> 8) & 255;
    out[o++] = n & 255;
  }
  const tail = clean - i;
  if (tail === 3) {
    const n = (codes[i]! << 18) | (codes[i + 1]! << 12) | (codes[i + 2]! << 6);
    out[o++] = (n >>> 16) & 255;
    out[o++] = (n >>> 8) & 255;
  } else if (tail === 2) {
    const n = (codes[i]! << 18) | (codes[i + 1]! << 12);
    out[o++] = (n >>> 16) & 255;
  }

  return o === out.length ? out : out.subarray(0, o);
}

const UTF8_ENCODER = /* @__PURE__ */ new TextEncoder();
const UTF8_DECODER = /* @__PURE__ */ new TextDecoder('utf-8', { fatal: false });

export function toUtf8Bytes(text: string): Uint8Array {
  return UTF8_ENCODER.encode(text);
}

export function fromUtf8Bytes(bytes: Uint8Array): string {
  return UTF8_DECODER.decode(bytes);
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/**
 * Comparaison à temps constant.
 *
 * Indispensable pour la vérification de MAC : une comparaison naïve avec
 * court-circuit laisse fuiter la position du premier octet divergent, ce qui
 * suffit à forger un MAC octet par octet.
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  // La longueur n'est pas un secret ici (toujours 32 octets pour HMAC-SHA256),
  // mais on évite malgré tout un retour anticipé exploitable.
  let diff = a.length ^ b.length;
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

/** Écrase un tampon sensible. Best-effort : le GC peut avoir déjà copié. */
export function wipe(bytes: Uint8Array): void {
  bytes.fill(0);
}
