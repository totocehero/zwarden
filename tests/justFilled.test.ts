/**
 * @file Not offering back what Zwarden itself just filled.
 *
 * Filling a form from the vault and then being asked whether to save what was
 * filled is a question with no useful answer: the item exists, with that exact
 * password. The badge went up regardless, because the service worker captures
 * without keys and cannot tell one submission from another.
 *
 * The line these tests defend is the one that keeps it useful: a password
 * **changed** after the fill is still captured. That is a rotation, and it is
 * exactly what the offer is for.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';

import { fakeChromeStorage } from './support/fakes.js';

describe('what we just filled', () => {
  let store: { data: Record<string, unknown> };

  beforeEach(() => {
    vi.resetModules();
    store = fakeChromeStorage();
  });

  async function load() {
    return import('../src/shared/storage.js');
  }

  it('recognises the submission that follows a fill', async () => {
    const { noteFilled, wasJustFilled } = await load();
    await noteFilled('https://bank.example', 'ada', 'K7#mQv2$Lz9!');

    expect(await wasJustFilled('https://bank.example', 'ada', 'K7#mQv2$Lz9!')).toBe(true);
  });

  it('still captures a password changed since the fill', async () => {
    const { noteFilled, wasJustFilled } = await load();
    await noteFilled('https://bank.example', 'ada', 'the-old-one');

    // A rotation. Suppressing this would be suppressing the feature.
    expect(await wasJustFilled('https://bank.example', 'ada', 'the-new-one')).toBe(false);
  });

  it('does not confuse two accounts on one site', async () => {
    const { noteFilled, wasJustFilled } = await load();
    await noteFilled('https://bank.example', 'ada', 'K7#mQv2$Lz9!');

    expect(await wasJustFilled('https://bank.example', 'grace', 'K7#mQv2$Lz9!')).toBe(false);
  });

  it('does not carry across sites', async () => {
    const { noteFilled, wasJustFilled } = await load();
    await noteFilled('https://bank.example', 'ada', 'K7#mQv2$Lz9!');

    expect(await wasJustFilled('https://shop.example', 'ada', 'K7#mQv2$Lz9!')).toBe(false);
  });

  it('never writes the password itself', async () => {
    const { noteFilled } = await load();
    await noteFilled('https://bank.example', 'ada', 'K7#mQv2$Lz9!');

    // A second cleartext copy of a password, kept for ten minutes to spare one
    // badge, would be a poor trade. A digest answers the only question asked.
    const written = JSON.stringify(store.data);
    expect(written).not.toContain('K7#mQv2$Lz9!');
    expect(written).toMatch(/[0-9a-f]{64}/);
  });

  it('forgets a fill that is no longer recent', async () => {
    const { noteFilled, wasJustFilled } = await load();
    await noteFilled('https://bank.example', 'ada', 'K7#mQv2$Lz9!');

    // Eleven minutes later: a submission now is a new intention, not the echo
    // of an old fill.
    (store.data['justFilled'] as { at: number }).at = Date.now() - 11 * 60_000;

    expect(await wasJustFilled('https://bank.example', 'ada', 'K7#mQv2$Lz9!')).toBe(false);
  });

  it('says no when nothing was filled at all', async () => {
    const { wasJustFilled } = await load();
    expect(await wasJustFilled('https://bank.example', 'ada', 'x')).toBe(false);
  });

  it('records nothing for an empty password', async () => {
    const { noteFilled } = await load();
    await noteFilled('https://bank.example', 'ada', '');
    expect(store.data['justFilled']).toBeUndefined();
  });
});
