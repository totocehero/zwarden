import { describe, expect, it } from 'vitest';

import {
  hkdfExpandSha256,
  hmacSha256,
  hmacSha256Verify,
  importHmacSha256Key,
  pbkdf2Sha256,
} from '../src/core/crypto/primitives.js';
import { fromBase64, toBase64, toUtf8Bytes } from '../src/core/crypto/encoding.js';

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

describe('HMAC-SHA256 (RFC 4231 vectors)', () => {
  it('case 1', async () => {
    const mac = await hmacSha256(hexToBytes('0b'.repeat(20)), toUtf8Bytes('Hi There'));
    expect(bytesToHex(mac)).toBe(
      'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
    );
  });

  it('case 2', async () => {
    const mac = await hmacSha256(toUtf8Bytes('Jefe'), toUtf8Bytes('what do ya want for nothing?'));
    expect(bytesToHex(mac)).toBe(
      '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
    );
  });

  it('produces the same MAC through an imported, reused CryptoKey', async () => {
    const raw = hexToBytes('0b'.repeat(20));
    const imported = await importHmacSha256Key(raw);
    const data = toUtf8Bytes('Hi There');

    const viaRaw = await hmacSha256(raw, data);
    const viaKey = await hmacSha256(imported, data);
    const viaKeyAgain = await hmacSha256(imported, data);

    expect(bytesToHex(viaKey)).toBe(bytesToHex(viaRaw));
    expect(bytesToHex(viaKeyAgain)).toBe(bytesToHex(viaRaw));
  });
});

describe('hmacSha256Verify', () => {
  const key = toUtf8Bytes('test key');
  const data = toUtf8Bytes('authenticated data');

  it('accepts the correct MAC', async () => {
    const mac = await hmacSha256(key, data);
    expect(await hmacSha256Verify(key, mac, data)).toBe(true);
  });

  it('rejects a MAC altered by a single bit', async () => {
    const mac = await hmacSha256(key, data);
    mac[0]! ^= 0x01;
    expect(await hmacSha256Verify(key, mac, data)).toBe(false);
  });

  it('rejects a MAC made with another key', async () => {
    const mac = await hmacSha256(toUtf8Bytes('other key'), data);
    expect(await hmacSha256Verify(key, mac, data)).toBe(false);
  });
});

describe('PBKDF2-SHA256 (RFC 7914 §11 vectors)', () => {
  it('c=1', async () => {
    const out = await pbkdf2Sha256(toUtf8Bytes('passwd'), toUtf8Bytes('salt'), 1, 64);
    expect(bytesToHex(out)).toBe(
      '55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc' +
        '49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783',
    );
  });

  it('c=80000', async () => {
    const out = await pbkdf2Sha256(toUtf8Bytes('Password'), toUtf8Bytes('NaCl'), 80000, 64);
    expect(bytesToHex(out)).toBe(
      '4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56' +
        'a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d',
    );
  });
});

describe('HKDF-Expand SHA-256 (RFC 5869 vectors)', () => {
  // Case A.1: we start straight from the PRK, the Extract step being out of scope.
  it('case A.1, L=42', async () => {
    const prk = hexToBytes('077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5');
    const info = hexToBytes('f0f1f2f3f4f5f6f7f8f9');
    expect(bytesToHex(await hkdfExpandSha256(prk, info, 42))).toBe(
      '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
    );
  });

  it('case A.3, empty info, L=42', async () => {
    const prk = hexToBytes('19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04');
    expect(bytesToHex(await hkdfExpandSha256(prk, new Uint8Array(0), 42))).toBe(
      '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8',
    );
  });

  it('produces exactly the requested length across several blocks', async () => {
    const prk = new Uint8Array(32).fill(7);
    for (const len of [1, 31, 32, 33, 64, 100]) {
      expect((await hkdfExpandSha256(prk, 'enc', len)).length).toBe(len);
    }
  });

  it('the "enc" and "mac" info values give distinct outputs', async () => {
    const prk = new Uint8Array(32).fill(42);
    const enc = await hkdfExpandSha256(prk, 'enc', 32);
    const mac = await hkdfExpandSha256(prk, 'mac', 32);
    expect(toBase64(enc)).not.toBe(toBase64(mac));
  });
});

describe('fromBase64 on adversarial input', () => {
  // Decoding leans on `atob`, which rejects invalid input. That is the intended
  // behaviour: on cryptographic material, silently ignoring unreadable bytes
  // would mask vault corruption or a tampered server response.
  // `EncString.parse` then translates those failures into
  // `EncStringParseError`.
  it.each(['Z', '!!!!', 'a=b=c'])('rejects the invalid input %j', (input) => {
    expect(() => fromBase64(input)).toThrow();
  });

  it('accepts unpadded base64', () => {
    expect(fromBase64('Zm9vYmE')).toEqual(toUtf8Bytes('fooba'));
    expect(fromBase64('Zg')).toEqual(toUtf8Bytes('f'));
  });
});
