import { describe, expect, it } from 'vitest';

import { EncString, EncStringParseError, EncryptionType } from '../src/core/crypto/encString.js';
import { SymmetricCryptoKey } from '../src/core/crypto/symmetricCryptoKey.js';
import {
  MacMismatchError,
  UnsupportedEncryptionError,
  decryptString,
  encryptString,
} from '../src/core/crypto/cryptoService.js';
import { toBase64 } from '../src/core/crypto/encoding.js';

/** Clé de test déterministe : encKey = 0x00..0x1f, macKey = 0x20..0x3f. */
function testKey(): SymmetricCryptoKey {
  const raw = new Uint8Array(64);
  for (let i = 0; i < 64; i++) raw[i] = i;
  return new SymmetricCryptoKey(raw);
}

describe('EncString — analyse', () => {
  it('analyse un type 2 complet', () => {
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

  it('fait un aller-retour exact sur la sérialisation', () => {
    const iv = toBase64(new Uint8Array(16).fill(1));
    const ct = toBase64(new Uint8Array(48).fill(2));
    const mac = toBase64(new Uint8Array(32).fill(3));
    const raw = `2.${iv}|${ct}|${mac}`;
    expect(EncString.parse(raw).toString()).toBe(raw);
  });

  it('analyse un type 0 sans MAC', () => {
    const raw = `0.${toBase64(new Uint8Array(16))}|${toBase64(new Uint8Array(16))}`;
    const enc = EncString.parse(raw);
    expect(enc.hasMac).toBe(false);
    expect(enc.toString()).toBe(raw);
  });

  it('analyse un type 3 (RSA)', () => {
    const enc = EncString.parse(`3.${toBase64(new Uint8Array(256).fill(9))}`);
    expect(enc.isSymmetric).toBe(false);
    expect(enc.iv).toBeUndefined();
  });

  const invalides: ReadonlyArray<readonly [string, string]> = [
    ['sans point', 'abcdef'],
    ['type non numérique', 'x.aaaa|bbbb|cccc'],
    ['type inconnu', '99.aaaa'],
    ['segments manquants', `2.${toBase64(new Uint8Array(16))}|AAAA`],
    ['segments en trop', `2.${toBase64(new Uint8Array(16))}|AAAA|BBBB|CCCC`],
    ['chaîne vide', ''],
    ['point en tête', '.aaaa'],
  ];

  it.each(invalides)('rejette : %s', (_label, raw) => {
    expect(() => EncString.parse(raw)).toThrow(EncStringParseError);
  });

  it('rejette un IV de mauvaise taille', () => {
    const raw = `2.${toBase64(new Uint8Array(8))}|AAAA|${toBase64(new Uint8Array(32))}`;
    expect(() => EncString.parse(raw)).toThrow(/« iv » : 8 octets, 16 attendus/);
  });

  it('rejette un MAC de mauvaise taille', () => {
    const raw = `2.${toBase64(new Uint8Array(16))}|AAAA|${toBase64(new Uint8Array(16))}`;
    expect(() => EncString.parse(raw)).toThrow(/« mac » : 16 octets, 32 attendus/);
  });

  it('parseOrNull renvoie null au lieu de jeter', () => {
    expect(EncString.parseOrNull('n’importe quoi')).toBeNull();
    expect(EncString.parseOrNull(null)).toBeNull();
    expect(EncString.parseOrNull('')).toBeNull();
  });
});

describe('SymmetricCryptoKey', () => {
  it('scinde une clé de 64 octets en encKey / macKey', () => {
    const key = testKey();
    expect(key.encKey).toHaveLength(32);
    expect(key.macKey).toHaveLength(32);
    expect(key.encKey[0]).toBe(0);
    expect(key.macKey![0]).toBe(32);
    expect(key.isAuthenticated).toBe(true);
    expect(key.encryptionType).toBe(EncryptionType.AesCbc256_HmacSha256_B64);
  });

  it('traite une clé de 32 octets comme non authentifiée', () => {
    const key = new SymmetricCryptoKey(new Uint8Array(32));
    expect(key.macKey).toBeUndefined();
    expect(key.isAuthenticated).toBe(false);
  });

  it.each([0, 16, 31, 33, 63, 65])('rejette une clé de %i octets', (len) => {
    expect(() => new SymmetricCryptoKey(new Uint8Array(len))).toThrow(RangeError);
  });

  it('efface le matériel de clé', () => {
    const key = testKey();
    key.destroy();
    expect(key.key.every((b) => b === 0)).toBe(true);
  });
});

describe('chiffrement / déchiffrement', () => {
  it('fait un aller-retour sur une chaîne', async () => {
    const key = testKey();
    const enc = await encryptString('mot de passe très secret', key);
    expect(await decryptString(enc, key)).toBe('mot de passe très secret');
  });

  it('produit toujours du type 2', async () => {
    const enc = await encryptString('x', testKey());
    expect(enc.encryptionType).toBe(EncryptionType.AesCbc256_HmacSha256_B64);
    expect(enc.toString().startsWith('2.')).toBe(true);
  });

  it('utilise un IV différent à chaque chiffrement', async () => {
    const key = testKey();
    const a = await encryptString('même contenu', key);
    const b = await encryptString('même contenu', key);
    expect(toBase64(a.iv!)).not.toBe(toBase64(b.iv!));
    expect(a.toString()).not.toBe(b.toString());
  });

  it.each(['', 'a', 'a'.repeat(15), 'a'.repeat(16), 'a'.repeat(17), 'a'.repeat(10_000)])(
    'gère un texte de %i caractères',
    async (text) => {
      const key = testKey();
      expect(await decryptString(await encryptString(text, key), key)).toBe(text);
    },
  );

  it('préserve l’UTF-8 multi-octets', async () => {
    const key = testKey();
    const text = 'p@ssw0rd — 日本語 🔐 àéîõü ñ';
    expect(await decryptString(await encryptString(text, key), key)).toBe(text);
  });

  it('survit à un aller-retour par la forme sérialisée', async () => {
    const key = testKey();
    const serialise = (await encryptString('via le réseau', key)).toString();
    expect(await decryptString(EncString.parse(serialise), key)).toBe('via le réseau');
  });
});

/** Retourne une copie du tampon avec un octet inversé. */
function flipByte(bytes: Uint8Array, index: number): Uint8Array {
  const copy = new Uint8Array(bytes);
  copy.set([(copy.at(index) ?? 0) ^ 0xff], index);
  return copy;
}

describe('résistance à l’altération', () => {
  it('rejette un ciphertext modifié', async () => {
    const key = testKey();
    const enc = await encryptString('solde: 100', key);
    const ct = flipByte(enc.ciphertext, 0);
    const falsifie = EncString.fromParts(enc.encryptionType, enc.iv, ct, enc.mac);

    await expect(decryptString(falsifie, key)).rejects.toThrow(MacMismatchError);
  });

  it('rejette un IV modifié', async () => {
    const key = testKey();
    const enc = await encryptString('solde: 100', key);
    const iv = flipByte(enc.iv!, 0);
    const falsifie = EncString.fromParts(enc.encryptionType, iv, enc.ciphertext, enc.mac);

    await expect(decryptString(falsifie, key)).rejects.toThrow(MacMismatchError);
  });

  it('rejette un MAC modifié', async () => {
    const key = testKey();
    const enc = await encryptString('solde: 100', key);
    const mac = flipByte(enc.mac!, 31);
    const falsifie = EncString.fromParts(enc.encryptionType, enc.iv, enc.ciphertext, mac);

    await expect(decryptString(falsifie, key)).rejects.toThrow(MacMismatchError);
  });

  it('rejette un MAC absent sur du type 2', async () => {
    const key = testKey();
    const enc = await encryptString('solde: 100', key);
    const sansMac = EncString.fromParts(enc.encryptionType, enc.iv, enc.ciphertext, undefined);

    await expect(decryptString(sansMac, key)).rejects.toThrow(MacMismatchError);
  });

  it('rejette une clé différente', async () => {
    const enc = await encryptString('solde: 100', testKey());
    const autre = new SymmetricCryptoKey(new Uint8Array(64).fill(9));

    await expect(decryptString(enc, autre)).rejects.toThrow(MacMismatchError);
  });

  it('rejette une rétrogradation vers le type 0 (attaque par downgrade)', async () => {
    const key = testKey();
    const enc = await encryptString('solde: 100', key);
    const retrograde = EncString.fromParts(
      EncryptionType.AesCbc256_B64,
      enc.iv,
      enc.ciphertext,
      undefined,
    );

    await expect(decryptString(retrograde, key)).rejects.toThrow(UnsupportedEncryptionError);
  });

  it('refuse de chiffrer avec une clé sans MAC', async () => {
    const faible = new SymmetricCryptoKey(new Uint8Array(32));
    await expect(encryptString('secret', faible)).rejects.toThrow(UnsupportedEncryptionError);
  });

  it('refuse le déchiffrement du type 1 (AES-128 obsolète)', async () => {
    const key = testKey();
    const raw = `1.${toBase64(new Uint8Array(16))}|${toBase64(new Uint8Array(16))}|${toBase64(
      new Uint8Array(32),
    )}`;
    await expect(decryptString(EncString.parse(raw), key)).rejects.toThrow(
      UnsupportedEncryptionError,
    );
  });

  it('refuse le déchiffrement symétrique d’une EncString RSA', async () => {
    const key = testKey();
    const raw = `3.${toBase64(new Uint8Array(256))}`;
    await expect(decryptString(EncString.parse(raw), key)).rejects.toThrow(
      UnsupportedEncryptionError,
    );
  });
});

describe('vecteur figé (détection de régression de format)', () => {
  // Chiffré avec la clé de test et un IV fixe. Si ce test casse, le format
  // sur le fil a changé et les coffres existants deviennent illisibles.
  const IV_FIXE = new Uint8Array(16).fill(0xa5);

  it('reste stable dans le temps', async () => {
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
