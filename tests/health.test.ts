/**
 * @file What the vault says about itself.
 *
 * Two properties matter more than any individual finding, and both are
 * promises the feature would be dishonest without:
 *
 * - an item guarded by `reprompt` is **not examined**, because reporting that
 *   two items share a password says something about both;
 * - **no password ever appears in the result**, which would be a second
 *   cleartext copy living as long as the panel is open.
 */

import { describe, expect, it } from 'vitest';

import { EMPTY_CARD } from '../src/core/vault/card.js';
import { buildHealthReport, findingCount, type HealthItem } from '../src/core/vault/health.js';

const NOW = new Date(Date.UTC(2026, 8, 20));

function item(patch: Partial<HealthItem> = {}): HealthItem {
  return {
    id: 'i1',
    name: 'My bank',
    username: 'ada@example.org',
    uris: ['https://bank.example.org/login'],
    type: 1,
    reprompt: false,
    password: 'K7#mQv2$Lz9!Rt4W',
    passwordUpdatedAt: null,
    card: null,
    ...patch,
  };
}

describe('guarded items', () => {
  it('does not examine an item that demands the master password again', () => {
    const report = buildHealthReport([item({ reprompt: true, password: 'password' })], NOW);

    // Honouring the guard for a copy but not for an aggregate would be
    // honouring it for show.
    expect(report.weak).toEqual([]);
    expect(report.checked).toBe(0);
    expect(report.guarded).toBe(1);
  });

  it('says how many it left alone, rather than claiming full coverage', () => {
    const report = buildHealthReport(
      [item({ id: 'a' }), item({ id: 'b', reprompt: true }), item({ id: 'c', reprompt: true })],
      NOW,
    );
    expect(report.checked).toBe(1);
    expect(report.guarded).toBe(2);
  });
});

describe('reuse', () => {
  it('groups the items sharing a password', () => {
    const report = buildHealthReport(
      [
        item({ id: 'a', name: 'Bank', password: 'K7#mQv2$Lz9!Rt4W' }),
        item({ id: 'b', name: 'Shop', password: 'K7#mQv2$Lz9!Rt4W' }),
        item({ id: 'c', name: 'Mail', password: 'Xr4%Nb8@Kp1^Qw6E' }),
      ],
      NOW,
    );

    expect(report.reused).toHaveLength(1);
    expect(report.reused[0]!.items.map((i) => i.name)).toEqual(['Bank', 'Shop']);
  });

  it('does not call a password used once reuse', () => {
    expect(buildHealthReport([item()], NOW).reused).toEqual([]);
  });

  it('never lets a password into the report', () => {
    const report = buildHealthReport(
      [
        item({ id: 'a', password: 'K7#mQv2$Lz9!Rt4W' }),
        item({ id: 'b', password: 'K7#mQv2$Lz9!Rt4W' }),
      ],
      NOW,
    );

    // The grouping happens in memory and the passwords are dropped there.
    expect(JSON.stringify(report)).not.toContain('K7#mQv2$Lz9!Rt4W');
  });

  it('ignores items with no password at all', () => {
    const report = buildHealthReport(
      [item({ id: 'a', password: null }), item({ id: 'b', password: '' })],
      NOW,
    );
    expect(report.reused).toEqual([]);
    expect(report.weak).toEqual([]);
  });
});

describe('weak passwords', () => {
  it('names the item and why', () => {
    const report = buildHealthReport([item({ password: 'azerty' })], NOW);

    expect(report.weak).toHaveLength(1);
    expect(report.weak[0]!.name).toBe('My bank');
    expect(report.weak[0]!.reason).toBe('notorious');
  });

  it('falls back to the identifier when an item has no name', () => {
    const report = buildHealthReport([item({ name: null, password: 'azerty' })], NOW);
    expect(report.weak[0]!.name).toBe('i1');
  });
});

describe('passwords that echo their own item', () => {
  it('catches a password built from the site host', () => {
    const report = buildHealthReport([item({ password: 'Bank.example2024' })], NOW);
    expect(report.echoing.map((i) => i.id)).toEqual(['i1']);
  });

  it('does not say it twice when the password is already weak', () => {
    // Two findings for one password is one finding too many.
    const report = buildHealthReport([item({ name: 'admin', password: 'admin' })], NOW);
    expect(report.weak).toHaveLength(1);
    expect(report.echoing).toEqual([]);
  });

  it('leaves an unrelated strong password alone', () => {
    const report = buildHealthReport([item()], NOW);
    expect(report.echoing).toEqual([]);
    expect(report.weak).toEqual([]);
  });
});

describe('stale passwords', () => {
  it('reports one older than the threshold, with its age', () => {
    const report = buildHealthReport(
      [item({ passwordUpdatedAt: '2024-01-01T00:00:00Z' })],
      NOW,
    );
    expect(report.stale).toHaveLength(1);
    expect(report.stale[0]!.days).toBeGreaterThan(600);
  });

  it('leaves a recent one alone', () => {
    const report = buildHealthReport(
      [item({ passwordUpdatedAt: '2026-09-01T00:00:00Z' })],
      NOW,
    );
    expect(report.stale).toEqual([]);
  });

  it('treats a date it cannot read as unknown, not as old', () => {
    // A missing date is the caller's business — it resolves the creation date
    // when a password was never revised. What reaches here and cannot be read
    // is not evidence of age.
    expect(buildHealthReport([item({ passwordUpdatedAt: null })], NOW).stale).toEqual([]);
    expect(buildHealthReport([item({ passwordUpdatedAt: 'not a date' })], NOW).stale).toEqual([]);
  });

  it('honours a threshold given to it', () => {
    const report = buildHealthReport(
      [item({ passwordUpdatedAt: '2026-06-01T00:00:00Z' })],
      NOW,
      30,
    );
    expect(report.stale).toHaveLength(1);
  });
});

describe('cards', () => {
  const card = (expMonth: string, expYear: string) =>
    item({ type: 3, password: null, card: { ...EMPTY_CARD, expMonth, expYear } });

  it('reports an expired card', () => {
    const report = buildHealthReport([card('1', '2025')], NOW);
    expect(report.expiring).toHaveLength(1);
    expect(report.expiring[0]!.expired).toBe(true);
  });

  it('reports one about to expire, without calling it expired', () => {
    const report = buildHealthReport([card('10', '2026')], NOW);
    expect(report.expiring[0]!.expired).toBe(false);
  });

  it('leaves a card with years to run alone', () => {
    expect(buildHealthReport([card('12', '2030')], NOW).expiring).toEqual([]);
  });
});

describe('findingCount', () => {
  it('counts every kind of finding', () => {
    const report = buildHealthReport(
      [
        item({ id: 'a', password: 'azerty' }),
        item({ id: 'b', password: 'K7#mQv2$Lz9!Rt4W' }),
        item({ id: 'c', password: 'K7#mQv2$Lz9!Rt4W' }),
      ],
      NOW,
    );
    // One weak, one reuse group.
    expect(findingCount(report)).toBe(2);
  });

  it('is zero on a healthy vault', () => {
    expect(findingCount(buildHealthReport([item()], NOW))).toBe(0);
  });
});

describe('the order findings come back in', () => {
  it('puts the oldest password at the top of the stale list', () => {
    // This list is read to decide what to throw away, and the likeliest
    // candidate is the one untouched the longest.
    const report = buildHealthReport(
      [
        item({ id: 'recent', passwordUpdatedAt: '2025-06-01T00:00:00Z' }),
        item({ id: 'ancient', passwordUpdatedAt: '2019-01-01T00:00:00Z' }),
        item({ id: 'middling', passwordUpdatedAt: '2022-01-01T00:00:00Z' }),
      ],
      NOW,
    );
    expect(report.stale.map((f) => f.id)).toEqual(['ancient', 'middling', 'recent']);
  });
});
