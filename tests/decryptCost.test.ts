/**
 * @file What decrypting a vault actually costs.
 *
 * **Skipped by default**: it measures rather than asserts, it takes seconds,
 * and a timing threshold in a test suite is a flake waiting for a slow machine.
 * It is kept because the numbers settled a design decision and someone will
 * want to take them again — change `describe.skip` to `describe` and run
 * `npx vitest run tests/decryptCost.test.ts --reporter=verbose`.
 *
 * What it established, on one developer machine under Node, cold:
 *
 * | items | vault key | key per item |
 * |------:|----------:|-------------:|
 * |    50 |     76 ms |       102 ms |
 * |   200 |    133 ms |       222 ms |
 * |   500 |    335 ms |       649 ms |
 * |  1000 |    744 ms |      1296 ms |
 *
 * Two conclusions, both acted on:
 *
 * 1. A key per item — what a modern Bitwarden vault has — roughly **doubles**
 *    the cost, because each item then needs its own key unwrapped and imported.
 *    That is the case to design for, not the flattering one.
 * 2. Raising `decryptCipherList`'s concurrency from 8 changes nothing: the
 *    curve from 1 to 128 is flat inside the noise. The work is CPU in one
 *    thread, not round trips waiting to be overlapped.
 *
 * Hence `FIRST_SLICE` in the popup: the cost is real and it is in the
 * decryption, so that is what is split — the server offers no help, `/api/sync`
 * returning the vault whole with no page parameter.
 */

import { describe, expect, it } from 'vitest';

import type { CipherResponse } from '../src/core/api/models.js';
import { encryptBytes, encryptString } from '../src/core/crypto/cryptoService.js';
import { SymmetricCryptoKey } from '../src/core/crypto/symmetricCryptoKey.js';
import { decryptCipherList } from '../src/core/vault/cipherService.js';

describe.skip('decryption cost', () => {
  const key = SymmetricCryptoKey.generate();

  /** A vault of `n` plausible login items, with or without a key of their own. */
  async function vault(n: number, perItemKey: boolean): Promise<CipherResponse[]> {
    const out: CipherResponse[] = [];
    for (let i = 0; i < n; i += 1) {
      const itemKey = perItemKey ? SymmetricCryptoKey.generate() : key;
      const e = async (text: string): Promise<string> =>
        (await encryptString(text, itemKey)).toString();
      const cipher: Record<string, unknown> = {
        id: `i${i}`,
        type: 1,
        name: await e(`Account number ${i}`),
        login: {
          username: await e(`user${i}@example.org`),
          password: await e('x'),
          uris: [{ uri: await e(`https://site${i}.example.org`) }],
        },
        organizationId: null,
      };
      if (perItemKey) {
        cipher['key'] = (await encryptBytes(itemKey.key, key)).toString();
      }
      out.push(cipher as unknown as CipherResponse);
    }
    return out;
  }

  it('measures the cost per item, with and without a key of its own', async () => {
    for (const perItemKey of [false, true]) {
      for (const n of [50, 200, 500, 1000]) {
        const ciphers = await vault(n, perItemKey);
        const started = performance.now();
        const items = await decryptCipherList(ciphers, key, () => undefined);
        const ms = performance.now() - started;
        expect(items).toHaveLength(n);
        console.log(
          `  ${perItemKey ? 'key per item' : 'vault key   '} ${String(n).padStart(4)} items` +
            ` -> ${ms.toFixed(0)} ms (${(ms / n).toFixed(2)} ms/item)`,
        );
      }
    }
  });

  it('shows that concurrency is not the lever', async () => {
    const ciphers = await vault(500, true);
    // Warm-up: the first pass pays for the JIT and for WebCrypto's own set-up.
    await decryptCipherList(ciphers, key, () => undefined);

    for (const concurrency of [1, 4, 8, 16, 32, 64, 128]) {
      const runs: number[] = [];
      for (let run = 0; run < 3; run += 1) {
        const started = performance.now();
        await decryptCipherList(ciphers, key, () => undefined, concurrency);
        runs.push(performance.now() - started);
      }
      console.log(`  concurrency ${String(concurrency).padStart(3)} -> ${Math.min(...runs).toFixed(0)} ms`);
    }
  });
});
