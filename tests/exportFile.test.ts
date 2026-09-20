/**
 * @file The encrypted export file.
 *
 * What is pinned here is what a backup has to be worth: it opens with the right
 * passphrase and with nothing else, it cannot be weakened by editing the
 * parameters it carries in clear, no two copies are alike, and none of it ever
 * exists unencrypted on disk.
 */

import { describe, expect, it } from 'vitest';

import {
  ExportError,
  type ExportPayload,
  openExport,
  sealExport,
} from '../src/core/vault/exportFile.js';

const PASSPHRASE = 'a passphrase nobody will guess, honestly';

const PAYLOAD: ExportPayload = {
  encrypted: false,
  folders: [{ id: 'f1', name: 'Work' }],
  items: [
    {
      id: 'i1',
      type: 1,
      name: 'My bank',
      notes: 'the account with the overdraft',
      favorite: true,
      folderId: 'f1',
      login: {
        username: 'ada@example.org',
        password: 'K7#mQv2$Lz9!Rt4W',
        totp: 'otpauth://totp/x',
        uris: [{ uri: 'https://bank.example.org' }],
      },
    },
  ],
};

/** Parses a sealed file back into its envelope. */
const envelopeOf = (text: string) => JSON.parse(text) as Record<string, unknown>;

describe('sealing and opening', () => {
  it('gives back exactly what it was given', async () => {
    const sealed = await sealExport(PAYLOAD, PASSPHRASE);
    expect(await openExport(sealed, PASSPHRASE)).toEqual(PAYLOAD);
  });

  it('refuses the wrong passphrase', async () => {
    const sealed = await sealExport(PAYLOAD, PASSPHRASE);

    const error = await openExport(sealed, 'not it').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ExportError);
    expect((error as ExportError).code).toBe('wrong-passphrase');
  });

  it('puts nothing in clear in the file', async () => {
    const sealed = await sealExport(PAYLOAD, PASSPHRASE);

    // The whole reason there is no plaintext export: this file ends up in a
    // downloads folder, in every backup, and on the drive when it is resold.
    expect(sealed).not.toContain('K7#mQv2$Lz9!Rt4W');
    expect(sealed).not.toContain('ada@example.org');
    expect(sealed).not.toContain('My bank');
    expect(sealed).not.toContain('overdraft');
  });

  it('seals the same vault differently every time', async () => {
    const first = envelopeOf(await sealExport(PAYLOAD, PASSPHRASE));
    const second = envelopeOf(await sealExport(PAYLOAD, PASSPHRASE));

    // Identical files would tell anyone holding both that nothing had changed
    // between them.
    expect(first['salt']).not.toBe(second['salt']);
    expect(first['nonce']).not.toBe(second['nonce']);
    expect(first['data']).not.toBe(second['data']);
  });

  it('announces its parameters in clear, so it can be opened later', async () => {
    const envelope = envelopeOf(await sealExport(PAYLOAD, PASSPHRASE));

    expect(envelope['format']).toBe('zwarden-export');
    expect(envelope['kdf']).toMatchObject({ type: 'argon2id' });
  });
});

describe('what cannot be tampered with', () => {
  it('refuses a file whose work factor was lowered', async () => {
    const envelope = envelopeOf(await sealExport(PAYLOAD, PASSPHRASE));
    (envelope['kdf'] as Record<string, unknown>)['iterations'] = 2;

    // The attack the authenticated header exists for: hand back a file asking
    // for less work, hoping it is re-sealed under something cheaper to crack.
    const error = await openExport(JSON.stringify(envelope), PASSPHRASE).catch(
      (e: unknown) => e,
    );
    expect((error as ExportError).code).toBe('wrong-passphrase');
  });

  it('refuses a file whose salt was swapped', async () => {
    const envelope = envelopeOf(await sealExport(PAYLOAD, PASSPHRASE));
    const other = envelopeOf(await sealExport(PAYLOAD, PASSPHRASE));
    envelope['salt'] = other['salt'];

    const error = await openExport(JSON.stringify(envelope), PASSPHRASE).catch(
      (e: unknown) => e,
    );
    expect((error as ExportError).code).toBe('wrong-passphrase');
  });

  it('refuses a file whose ciphertext was edited', async () => {
    const sealed = await sealExport(PAYLOAD, PASSPHRASE);
    const envelope = envelopeOf(sealed);
    const data = envelope['data'] as string;
    envelope['data'] = `${data.slice(0, -2)}${data.endsWith('A=') ? 'B=' : 'A='}`;

    const error = await openExport(JSON.stringify(envelope), PASSPHRASE).catch(
      (e: unknown) => e,
    );
    expect((error as ExportError).code).toBe('wrong-passphrase');
  });

  it('refuses parameters outside what the KDF accepts, before doing the work', async () => {
    const envelope = envelopeOf(await sealExport(PAYLOAD, PASSPHRASE));
    // A gibibyte of memory would be a denial of service at open time, not a
    // stronger file.
    (envelope['kdf'] as Record<string, unknown>)['memoryMiB'] = 65_536;

    const error = await openExport(JSON.stringify(envelope), PASSPHRASE).catch(
      (e: unknown) => e,
    );
    expect((error as ExportError).code).toBe('wrong-passphrase');
  });
});

describe('what it refuses to call an export', () => {
  it('rejects something that is not JSON', async () => {
    const error = await openExport('not json at all', PASSPHRASE).catch((e: unknown) => e);
    expect((error as ExportError).code).toBe('not-an-export');
  });

  it('rejects JSON that is not one of ours', async () => {
    const error = await openExport('{"hello":true}', PASSPHRASE).catch((e: unknown) => e);
    expect((error as ExportError).code).toBe('not-an-export');
  });

  it('rejects one missing the pieces it needs', async () => {
    const envelope = envelopeOf(await sealExport(PAYLOAD, PASSPHRASE));
    delete envelope['nonce'];

    const error = await openExport(JSON.stringify(envelope), PASSPHRASE).catch(
      (e: unknown) => e,
    );
    expect((error as ExportError).code).toBe('not-an-export');
  });

  it('says so plainly when the file is from a later version', async () => {
    const envelope = envelopeOf(await sealExport(PAYLOAD, PASSPHRASE));
    envelope['version'] = 99;

    // No passphrase can fix this, so blaming the passphrase would send the user
    // to try every one they have.
    const error = await openExport(JSON.stringify(envelope), PASSPHRASE).catch(
      (e: unknown) => e,
    );
    expect((error as ExportError).code).toBe('unsupported-version');
  });
});

describe('what is inside', () => {
  it('is the shape Bitwarden imports', async () => {
    const payload = await openExport(await sealExport(PAYLOAD, PASSPHRASE), PASSPHRASE);

    // Leaving is a feature: a vault one cannot take elsewhere is one to be
    // locked into.
    expect(payload.encrypted).toBe(false);
    expect(payload.items[0]!.login!.uris[0]!.uri).toBe('https://bank.example.org');
    expect(payload.folders[0]!.name).toBe('Work');
  });

  it('carries an empty vault without complaint', async () => {
    const empty: ExportPayload = { encrypted: false, folders: [], items: [] };
    expect(await openExport(await sealExport(empty, PASSPHRASE), PASSPHRASE)).toEqual(empty);
  });
});
