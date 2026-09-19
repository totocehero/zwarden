import { describe, expect, it } from 'vitest';

import { EncString, EncStringParseError, EncryptionType } from '../src/core/crypto/encString.js';
import { SymmetricCryptoKey } from '../src/core/crypto/symmetricCryptoKey.js';
import {
  MacMismatchError,
  UnsupportedEncryptionError,
  decryptString,
  decryptStringOrNull,
  encryptString,
} from '../src/core/crypto/cryptoService.js';
import { toBase64 } from '../src/core/crypto/encoding.js';

/** Deterministic test key: encKey = 0x00..0x1f, macKey = 0x20..0x3f. */
function testKey(): SymmetricCryptoKey {
  const raw = new Uint8Array(64);
  for (let i = 0; i < 64; i++) raw[i] = i;
  return new SymmetricCryptoKey(raw);
}

describe('EncString — parsing', () => {
  it('parses a complete type 2', () => {
    const iv = toBase64(new Uint8Array(16).fill(1));
    const ct = toBase64(new Uint8Array(32).fill(2));
    const mac = toBase64(new Uint8Array(32).fill(3));
    const enc = EncString.parse(`2.${iv}|${ct}|${mac}`);

    expect(enc.encryptionType).toBe(EncryptionType.AesCbc256_HmacSha256_B64);
    expect(enc.iv).toHaveLength(16);
    expect(enc.mac).toHaveLength(32);
    expect(enc.hasMac).toBe(true);
    expect(enc.isSymmetric).toBe(true);
  });

  it('round-trips serialisation exactly', () => {
    const iv = toBase64(new Uint8Array(16).fill(1));
    const ct = toBase64(new Uint8Array(48).fill(2));
    const mac = toBase64(new Uint8Array(32).fill(3));
    const raw = `2.${iv}|${ct}|${mac}`;
    expect(EncString.parse(raw).toString()).toBe(raw);
  });

  it('parses a type 0 without a MAC', () => {
    const raw = `0.${toBase64(new Uint8Array(16))}|${toBase64(new Uint8Array(16))}`;
    const enc = EncString.parse(raw);
    expect(enc.hasMac).toBe(false);
    expect(enc.toString()).toBe(raw);
  });

  it('parses a type 3 (RSA)', () => {
    const enc = EncString.parse(`3.${toBase64(new Uint8Array(256).fill(9))}`);
    expect(enc.isSymmetric).toBe(false);
    expect(enc.iv).toBeUndefined();
  });

  const invalid: ReadonlyArray<readonly [string, string]> = [
    ['no dot', 'abcdef'],
    ['non-numeric type', 'x.aaaa|bbbb|cccc'],
    ['unknown type', '99.aaaa'],
    ['missing segments', `2.${toBase64(new Uint8Array(16))}|AAAA`],
    ['extra segments', `2.${toBase64(new Uint8Array(16))}|AAAA|BBBB|CCCC`],
    ['empty string', ''],
    ['leading dot', '.aaaa'],
  ];

  it.each(invalid)('rejects: %s', (_label, raw) => {
    expect(() => EncString.parse(raw)).toThrow(EncStringParseError);
  });

  it('rejects an IV of the wrong size', () => {
    const raw = `2.${toBase64(new Uint8Array(8))}|AAAA|${toBase64(new Uint8Array(32))}`;
    expect(() => EncString.parse(raw)).toThrow(/"iv": 8 bytes, 16 expected/);
  });

  it('rejects a MAC of the wrong size', () => {
    const raw = `2.${toBase64(new Uint8Array(16))}|${toBase64(new Uint8Array(16))}|${toBase64(
      new Uint8Array(16),
    )}`;
    expect(() => EncString.parse(raw)).toThrow(/"mac": 16 bytes, 32 expected/);
  });

  it('rejects an empty ciphertext on a symmetric type', () => {
    const raw = `2.${toBase64(new Uint8Array(16))}||${toBase64(new Uint8Array(32))}`;
    expect(() => EncString.parse(raw)).toThrow(/"ciphertext": 0 bytes/);
  });

  it('rejects a ciphertext not aligned on AES blocks', () => {
    const raw = `2.${toBase64(new Uint8Array(16))}|${toBase64(new Uint8Array(15))}|${toBase64(
      new Uint8Array(32),
    )}`;
    expect(() => EncString.parse(raw)).toThrow(EncStringParseError);
  });

  it('does not impose block alignment on RSA types', () => {
    // The AES block constraint concerns the symmetric types alone.
    expect(() => EncString.parse(`3.${toBase64(new Uint8Array(11))}`)).not.toThrow();
  });

  it('parseOrNull returns null instead of throwing, reporting malformations', () => {
    const erreurs: unknown[] = [];
    const surErreur = (e: unknown) => erreurs.push(e);

    expect(EncString.parseOrNull('n’importe quoi', surErreur)).toBeNull();
    expect(erreurs).toHaveLength(1);
    expect(erreurs[0]).toBeInstanceOf(EncStringParseError);

    // Legitimate absence: null returned with no notification.
    expect(EncString.parseOrNull(null, surErreur)).toBeNull();
    expect(EncString.parseOrNull('', surErreur)).toBeNull();
    expect(erreurs).toHaveLength(1);
  });
});

describe('SymmetricCryptoKey', () => {
  it('splits a 64-byte key into encKey / macKey', () => {
    const key = testKey();
    expect(key.encKey).toHaveLength(32);
    expect(key.macKey).toHaveLength(32);
    expect(key.encKey[0]).toBe(0);
    expect(key.macKey![0]).toBe(32);
    expect(key.isAuthenticated).toBe(true);
    expect(key.encryptionType).toBe(EncryptionType.AesCbc256_HmacSha256_B64);
  });

  it('treats a 32-byte key as unauthenticated', () => {
    const key = new SymmetricCryptoKey(new Uint8Array(32));
    expect(key.macKey).toBeUndefined();
    expect(key.isAuthenticated).toBe(false);
  });

  it.each([0, 16, 31, 33, 63, 65])('rejects a key of %i bytes', (len) => {
    expect(() => new SymmetricCryptoKey(new Uint8Array(len))).toThrow(RangeError);
  });

  it('erases the key material', () => {
    const key = testKey();
    key.destroy();
    expect(key.key.every((b) => b === 0)).toBe(true);
  });
});

describe('encryption / decryption', () => {
  it('round-trips a string', async () => {
    const key = testKey();
    const enc = await encryptString('a very secret password', key);
    expect(await decryptString(enc, key)).toBe('a very secret password');
  });

  it('always produces type 2', async () => {
    const enc = await encryptString('x', testKey());
    expect(enc.encryptionType).toBe(EncryptionType.AesCbc256_HmacSha256_B64);
    expect(enc.toString().startsWith('2.')).toBe(true);
  });

  it('uses a different IV on every encryption', async () => {
    const key = testKey();
    const a = await encryptString('same content', key);
    const b = await encryptString('same content', key);
    expect(toBase64(a.iv!)).not.toBe(toBase64(b.iv!));
    expect(a.toString()).not.toBe(b.toString());
  });

  it.each(['', 'a', 'a'.repeat(15), 'a'.repeat(16), 'a'.repeat(17), 'a'.repeat(10_000)])(
    'handles a text of %i characters',
    async (text) => {
      const key = testKey();
      expect(await decryptString(await encryptString(text, key), key)).toBe(text);
    },
  );

  it('preserves multi-byte UTF-8', async () => {
    const key = testKey();
    const text = 'p@ssw0rd — 日本語 🔐 àéîõü ñ';
    expect(await decryptString(await encryptString(text, key), key)).toBe(text);
  });

  it('survives a round trip through the serialised form', async () => {
    const key = testKey();
    const serialised = (await encryptString('over the wire', key)).toString();
    expect(await decryptString(EncString.parse(serialised), key)).toBe('over the wire');
  });
});

/** Returns a copy of the buffer with one byte flipped. */
function flipByte(bytes: Uint8Array, index: number): Uint8Array {
  const copy = new Uint8Array(bytes);
  copy.set([(copy.at(index) ?? 0) ^ 0xff], index);
  return copy;
}

describe('tamper resistance', () => {
  it('rejects a modified ciphertext', async () => {
    const key = testKey();
    const enc = await encryptString('balance: 100', key);
    const ct = flipByte(enc.ciphertext, 0);
    const falsifie = EncString.fromParts(enc.encryptionType, enc.iv, ct, enc.mac);

    await expect(decryptString(falsifie, key)).rejects.toThrow(MacMismatchError);
  });

  it('rejects a modified IV', async () => {
    const key = testKey();
    const enc = await encryptString('balance: 100', key);
    const iv = flipByte(enc.iv!, 0);
    const falsifie = EncString.fromParts(enc.encryptionType, iv, enc.ciphertext, enc.mac);

    await expect(decryptString(falsifie, key)).rejects.toThrow(MacMismatchError);
  });

  it('rejects a modified MAC', async () => {
    const key = testKey();
    const enc = await encryptString('balance: 100', key);
    const mac = flipByte(enc.mac!, 31);
    const falsifie = EncString.fromParts(enc.encryptionType, enc.iv, enc.ciphertext, mac);

    await expect(decryptString(falsifie, key)).rejects.toThrow(MacMismatchError);
  });

  it('rejects a missing MAC on type 2', async () => {
    const key = testKey();
    const enc = await encryptString('balance: 100', key);
    const sansMac = EncString.fromParts(enc.encryptionType, enc.iv, enc.ciphertext, undefined);

    await expect(decryptString(sansMac, key)).rejects.toThrow(MacMismatchError);
  });

  it('rejects a different key', async () => {
    const enc = await encryptString('balance: 100', testKey());
    const autre = new SymmetricCryptoKey(new Uint8Array(64).fill(9));

    await expect(decryptString(enc, autre)).rejects.toThrow(MacMismatchError);
  });

  it('rejects a downgrade to type 0 (downgrade attack)', async () => {
    const key = testKey();
    const enc = await encryptString('balance: 100', key);
    const downgraded = EncString.fromParts(
      EncryptionType.AesCbc256_B64,
      enc.iv,
      enc.ciphertext,
      undefined,
    );

    await expect(decryptString(downgraded, key)).rejects.toThrow(UnsupportedEncryptionError);
  });

  it('refuses to encrypt with a key that has no MAC', async () => {
    const weak = new SymmetricCryptoKey(new Uint8Array(32));
    await expect(encryptString('secret', weak)).rejects.toThrow(UnsupportedEncryptionError);
  });

  it('refuses to decrypt type 1 (obsolete AES-128)', async () => {
    const key = testKey();
    const raw = `1.${toBase64(new Uint8Array(16))}|${toBase64(new Uint8Array(16))}|${toBase64(
      new Uint8Array(32),
    )}`;
    await expect(decryptString(EncString.parse(raw), key)).rejects.toThrow(
      UnsupportedEncryptionError,
    );
  });

  it('refuses symmetric decryption of an RSA EncString', async () => {
    const key = testKey();
    const raw = `3.${toBase64(new Uint8Array(256))}`;
    await expect(decryptString(EncString.parse(raw), key)).rejects.toThrow(
      UnsupportedEncryptionError,
    );
  });
});

describe('decryptStringOrNull', () => {
  it('decrypts a valid value without invoking onError', async () => {
    const key = testKey();
    const enc = (await encryptString('visible', key)).toString();
    const erreurs: unknown[] = [];

    expect(await decryptStringOrNull(enc, key, (e) => erreurs.push(e))).toBe('visible');
    expect(erreurs).toHaveLength(0);
  });

  it('returns null without an error for a missing field', async () => {
    const key = testKey();
    const jamais = () => {
      throw new Error('onError must not be called for a missing field');
    };

    expect(await decryptStringOrNull(null, key, jamais)).toBeNull();
    expect(await decryptStringOrNull(undefined, key, jamais)).toBeNull();
    expect(await decryptStringOrNull('', key, jamais)).toBeNull();
  });

  it('returns null and reports on unreadable data', async () => {
    const key = testKey();
    const erreurs: unknown[] = [];

    expect(await decryptStringOrNull('pas une EncString', key, (e) => erreurs.push(e))).toBeNull();
    expect(erreurs).toHaveLength(1);
  });

  it('returns null and reports on an invalid MAC', async () => {
    const key = testKey();
    const autre = new SymmetricCryptoKey(new Uint8Array(64).fill(7));
    const enc = (await encryptString('secret', key)).toString();
    const erreurs: unknown[] = [];

    expect(await decryptStringOrNull(enc, autre, (e) => erreurs.push(e))).toBeNull();
    expect(erreurs).toHaveLength(1);
    expect(erreurs[0]).toBeInstanceOf(MacMismatchError);
  });
});

describe('frozen vector (format regression detection)', () => {
  // Encrypted with the test key and a fixed IV. If this test breaks, the wire
  // format has changed and existing vaults become unreadable.
  const IV_FIXE = new Uint8Array(16).fill(0xa5);

  it('stays stable over time', async () => {
    const key = testKey();
    const { aesCbcEncrypt, hmacSha256 } = await import('../src/core/crypto/primitives.js');
    const { concatBytes, toUtf8Bytes } = await import('../src/core/crypto/encoding.js');

    const ct = await aesCbcEncrypt(key.encKey, IV_FIXE, toUtf8Bytes('zwarden'));
    const mac = await hmacSha256(key.macKey!, concatBytes(IV_FIXE, ct));
    const enc = EncString.fromParts(EncryptionType.AesCbc256_HmacSha256_B64, IV_FIXE, ct, mac);

    expect(enc.toString()).toBe(
      '2.paWlpaWlpaWlpaWlpaWlpQ==' +
        '|zcMvGS9B2UbJTTRy/fUbZA==' +
        '|dafCZJOaO0kn9JgId9yUPywdV0Hhs1p97HA2Rj9ltuk=',
    );
    expect(await decryptString(enc, key)).toBe('zwarden');
  });
});
