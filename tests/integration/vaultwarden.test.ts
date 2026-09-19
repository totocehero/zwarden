/**
 * @file Interoperability validation against a real Vaultwarden instance.
 *
 * ## Why this test exists
 *
 * The unit tests prove RFC conformance and internal coherence. They do **not**
 * prove that a real vault opens: the complete chain (the server's KDF parameters
 * → master key → stretched key → vault key → item fields) can only be validated
 * end to end. This is the only test able to detect a divergence in
 * normalisation, in salt, or in derivation order.
 *
 * ## Running it
 *
 * Skipped by default. Requires a **throwaway** account, never a real one:
 *
 * ```bash
 * export ZWARDEN_TEST_SERVER=https://vault.example.com
 * export ZWARDEN_TEST_EMAIL=account+test@example.com
 * export ZWARDEN_TEST_PASSWORD='...'
 * npx vitest run tests/integration
 * ```
 *
 * ## Discipline about secrets
 *
 * No secret is written to disk nor logged. The assertions are on structural
 * properties (lengths, type prefixes, item counts) and never on decrypted
 * values. The report printed is deliberately redacted.
 */

import { beforeAll, describe, expect, it } from 'vitest';

import { ApiClient, type LoginResult } from '../../src/core/api/apiClient.js';
import { EncString } from '../../src/core/crypto/encString.js';
import { SymmetricCryptoKey } from '../../src/core/crypto/symmetricCryptoKey.js';
import { decryptBytes, encryptString } from '../../src/core/crypto/cryptoService.js';
import {
  HashPurpose,
  KdfType,
  type KdfConfig,
  deriveMasterKey,
  derivePasswordHash,
  stretchMasterKey,
} from '../../src/core/crypto/kdf.js';
import {
  buildCipherUpdatePayload,
  decryptCipherDetails,
  decryptCipherList,
  decryptCipherOverview,
} from '../../src/core/vault/cipherService.js';
import { unlock } from '../../src/core/vault/session.js';

const SERVER = process.env['ZWARDEN_TEST_SERVER'];
const EMAIL = process.env['ZWARDEN_TEST_EMAIL'];
const PASSWORD = process.env['ZWARDEN_TEST_PASSWORD'];

const configured = Boolean(SERVER && EMAIL && PASSWORD);

/** Describes a KDF without revealing anything sensitive. */
function describeKdf(config: KdfConfig): string {
  return config.type === KdfType.PBKDF2_SHA256
    ? `PBKDF2-SHA256, ${config.iterations.toLocaleString('en-GB')} iterations`
    : `Argon2id, t=${config.iterations} m=${config.memoryMiB}MiB p=${config.parallelism}`;
}

describe.skipIf(!configured)('Vaultwarden interoperability', () => {
  let client: ApiClient;
  let kdfConfig: KdfConfig;
  let masterKey: SymmetricCryptoKey;
  let session: LoginResult;
  let userKey: SymmetricCryptoKey;

  beforeAll(() => {
    client = new ApiClient({
      serverUrl: SERVER!,
      deviceIdentifier: '00000000-0000-4000-8000-00000000dead',
      deviceName: 'zwarden-interop-test',
    });
  });

  it('fetches the KDF parameters through prelogin', async () => {
    kdfConfig = await client.prelogin(EMAIL!);

    expect(kdfConfig.iterations).toBeGreaterThan(0);
    console.log(`  KDF announced: ${describeKdf(kdfConfig)}`);
  });

  it('derives a 32-byte master key', async () => {
    masterKey = await deriveMasterKey(PASSWORD!, EMAIL!, kdfConfig);

    expect(masterKey.key).toHaveLength(32);
    expect(masterKey.isAuthenticated).toBe(false);
  });

  it('authenticates and receives the wrapped vault key', async () => {
    const serverHash = await derivePasswordHash(
      masterKey,
      PASSWORD!,
      HashPurpose.ServerAuthorization,
    );
    session = await client.login(EMAIL!, serverHash);

    expect(session.accessToken.length).toBeGreaterThan(0);
    expect(session.protectedUserKey).toBeDefined();

    // The server validated our hash: the master key derivation is therefore
    // identical to the official client's. That is the first proof of
    // interoperability.
    console.log('  Authentication accepted by the server');
  });

  it('decrypts the vault key with the stretched master key', async () => {
    const stretched = await stretchMasterKey(masterKey);
    expect(stretched.key).toHaveLength(64);

    const wrapped = EncString.parse(session.protectedUserKey!);
    console.log(`  Vault key wrapped as type ${wrapped.encryptionType}`);

    // The decisive proof: if HKDF-Expand, the enc/mac order or the format
    // diverged, MAC verification would fail right here.
    const raw = await decryptBytes(wrapped, stretched);
    userKey = new SymmetricCryptoKey(raw);

    expect(userKey.key).toHaveLength(64);
    expect(userKey.isAuthenticated).toBe(true);
    console.log('  Vault key decrypted: 64 bytes, authenticated');
  });

  it('the unlock() orchestrator reproduces the manual path', async () => {
    // The step-by-step path above validates every link; this one validates the
    // packaged sequence the extension will actually use.
    const result = await unlock(client, EMAIL!, PASSWORD!);

    expect(result.userKey.toBase64()).toBe(userKey.toBase64());
    expect(result.session.accessToken.length).toBeGreaterThan(0);
    expect(result.localPasswordHash.length).toBeGreaterThan(0);

    result.userKey.destroy();
    console.log('  unlock(): vault key identical to the manual path');
  });

  it('performs a complete write-then-read round trip', async () => {
    // The strongest proof of interoperability: we encrypt locally, push to the
    // server, resync, and decrypt again. If the format diverged on a single
    // point, one of the two ends would fail.
    //
    // The values are randomly generated to avoid any collision with real
    // content, and the item is deleted at the end of the test.
    const marker = `zwarden-interop-${crypto.randomUUID()}`;
    const password = crypto.randomUUID();

    const body = {
      type: 1,
      name: (await encryptString(marker, userKey)).toString(),
      notes: (await encryptString('Zwarden test item, deleted automatically.', userKey))
        .toString(),
      login: {
        username: (await encryptString('user@test.local', userKey)).toString(),
        password: (await encryptString(password, userKey)).toString(),
        uris: [{ uri: (await encryptString('https://test.local', userKey)).toString(), match: null }],
      },
      favorite: false,
      folderId: null,
      organizationId: null,
      reprompt: 0,
      fields: [],
      passwordHistory: [],
    };

    const created = await client.createCipher(session.accessToken, body);
    expect(created.id).toBeTruthy();
    console.log(`  Item created server-side: ${created.id}`);

    try {
      // Read back through a full sync, not from the creation response: we want
      // to validate the real round trip.
      const sync = await client.sync(session.accessToken);
      const reread = (sync.ciphers ?? []).find((c) => c.id === created.id);
      expect(reread).toBeDefined();

      const errors: unknown[] = [];
      const onError = (e: unknown) => errors.push(e);
      const view = await decryptCipherOverview(reread!, userKey, onError);
      const details = await decryptCipherDetails(reread!, userKey, onError);

      expect(errors).toHaveLength(0);
      expect(view.name).toBe(marker);
      expect(details.username).toBe('user@test.local');
      expect(details.password).toBe(password);

      console.log('  Round trip validated: name, username and password identical');

      // Update: a new name and a new password, pushed and then read back through
      // a full sync — the exact path an edit takes in the popup.
      const modifiedMarker = `${marker}-modified`;
      const newPassword = crypto.randomUUID();
      const payload = await buildCipherUpdatePayload(
        reread!,
        {
          name: modifiedMarker,
          username: 'user@test.local',
          password: newPassword,
          totp: '',
          notes: 'Zwarden test item, deleted automatically.',
          uris: ['https://test.local'],
        },
        userKey,
        true,
      );
      await client.updateCipher(session.accessToken, created.id, payload);

      const sync2 = await client.sync(session.accessToken);
      const reread2 = (sync2.ciphers ?? []).find((c) => c.id === created.id);
      expect(reread2).toBeDefined();

      const vue2 = await decryptCipherOverview(reread2!, userKey, onError);
      const details2 = await decryptCipherDetails(reread2!, userKey, onError);
      expect(errors).toHaveLength(0);
      expect(vue2.name).toBe(modifiedMarker);
      expect(details2.password).toBe(newPassword);

      console.log('  Update pushed, read back and revalidated');
    } finally {
      // Systematic cleanup, including when an assertion has failed.
      await client.deleteCipher(session.accessToken, created.id);
      console.log('  Test item deleted');
    }
  });

  it('decrypts the vault existing items', async () => {
    const sync = await client.sync(session.accessToken);
    const ciphers = sync.ciphers ?? [];

    console.log(`  ${ciphers.length} pre-existing item(s)`);

    // An empty vault is an environment condition, not a code defect. The round
    // trip above already covers the complete path.
    if (ciphers.length === 0) {
      console.log('  Empty vault: nothing to decrypt, inconclusive but not blocking');
      return;
    }

    // The vault layer's service handles the per-item key and the case
    // tolerance; that is the path the extension will actually use.
    let failures = 0;
    const vues = await decryptCipherList(ciphers, userKey, () => {
      failures++;
    });

    for (const view of vues) {
      if (view.name !== null) {
        // Only the length is logged: the content stays secret.
        console.log(
          `    type ${view.type} item — name decrypted, ${view.name.length} character(s)`,
        );
      }
    }

    const decryptedCount = vues.filter((v) => v.name !== null).length;
    console.log(`  ${decryptedCount} decrypted, ${failures} failure(s)`);
    expect(failures).toBe(0);
    expect(decryptedCount).toBe(ciphers.length);
  });
});

describe.skipIf(configured)('Vaultwarden interoperability', () => {
  it('is skipped for want of configuration', () => {
    console.log(
      '  Interoperability test skipped. Set ZWARDEN_TEST_SERVER, ' +
        'ZWARDEN_TEST_EMAIL and ZWARDEN_TEST_PASSWORD to enable it.',
    );
    expect(configured).toBe(false);
  });
});
