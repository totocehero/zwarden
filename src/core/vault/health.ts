/**
 * @file The vault's own weaknesses, found without leaving the machine.
 *
 * No network, no third party, no telemetry: everything here is computed from
 * what the popup has already decrypted to show the list. That is the whole
 * appeal — it is the most useful thing a password manager can tell you that
 * costs nothing in exposure.
 *
 * ## What is deliberately left out
 *
 * **Items guarded by `reprompt` are not examined.** Reporting that two items
 * share a password says something about both, and one of them is marked "ask
 * for the master password again". Honouring that guard for a copy but not for
 * an aggregate would be honouring it for show. They are counted and named as
 * skipped, so the report never quietly claims a coverage it does not have.
 *
 * **No password appears in the result.** Reuse is found by grouping on the
 * password and reporting only the items — what comes back out is names and
 * identifiers. A report structure that carried passwords would be a second
 * cleartext copy, living as long as the panel is open, for no benefit.
 */

import { type CardView, expiryStatus } from './card.js';
import { echoesItsOwner, passwordStrength, type StrengthReason } from './passwordStrength.js';

/** One item, decrypted, as the report needs it. */
export interface HealthItem {
  readonly id: string;
  readonly name: string | null;
  readonly username: string | null;
  readonly uris: readonly string[];
  readonly type: number;
  /** `true` if the item demands the master password again: it is not examined. */
  readonly reprompt: boolean;
  readonly password: string | null;
  /** When the password last changed, ISO-8601, if the server said. */
  readonly passwordUpdatedAt: string | null;
  readonly card: CardView | null;
}

/** An item named in a finding. */
export interface HealthSubject {
  readonly id: string;
  readonly name: string;
}

/** Several items sharing one password. */
export interface ReuseGroup {
  readonly items: readonly HealthSubject[];
}

/** A password judged weak, and why. */
export interface WeakFinding extends HealthSubject {
  readonly reason: StrengthReason;
  readonly bits: number;
}

/** A password unchanged for longer than the threshold. */
export interface StaleFinding extends HealthSubject {
  readonly days: number;
}

/** A card at or near its expiry date. */
export interface ExpiryFinding extends HealthSubject {
  readonly expired: boolean;
}

export interface HealthReport {
  /** How many items were actually examined. */
  readonly checked: number;
  /** How many were left alone because they demand the master password again. */
  readonly guarded: number;
  readonly reused: readonly ReuseGroup[];
  readonly weak: readonly WeakFinding[];
  /** Passwords that merely repeat the site name or the username. */
  readonly echoing: readonly HealthSubject[];
  readonly stale: readonly StaleFinding[];
  readonly expiring: readonly ExpiryFinding[];
}

/** After how long a password is worth revisiting, by default. */
export const STALE_AFTER_DAYS = 365;

const DAY_MS = 86_400_000;

/** A displayable name for an item that may not have one. */
function subject(item: HealthItem): HealthSubject {
  return { id: item.id, name: item.name ?? item.id };
}

/** The host of the first URI, which is what a password most often echoes. */
function hostOf(uris: readonly string[]): string | null {
  const first = uris[0];
  if (first === undefined) {
    return null;
  }
  try {
    return new URL(first.includes('://') ? first : `https://${first}`).hostname.replace(
      /^www\./,
      '',
    );
  } catch {
    return null;
  }
}

/** Days since an ISO-8601 instant, or `null` if it cannot be read. */
function daysSince(iso: string | null, now: Date): number | null {
  if (iso === null || iso === '') {
    return null;
  }
  const then = Date.parse(iso);
  return Number.isNaN(then) ? null : Math.floor((now.getTime() - then) / DAY_MS);
}

/**
 * Examines the vault.
 *
 * @param items Every item, decrypted. Guarded ones are counted, not examined.
 * @param now The instant to measure ages against — injected, so the boundaries
 *   can be tested rather than depending on the day the suite runs.
 * @param staleAfterDays How old a password may be before it is worth revisiting.
 */
export function buildHealthReport(
  items: readonly HealthItem[],
  now: Date,
  staleAfterDays: number = STALE_AFTER_DAYS,
): HealthReport {
  const byPassword = new Map<string, HealthSubject[]>();
  const weak: WeakFinding[] = [];
  const echoing: HealthSubject[] = [];
  const stale: StaleFinding[] = [];
  const expiring: ExpiryFinding[] = [];
  let checked = 0;
  let guarded = 0;

  for (const item of items) {
    if (item.reprompt) {
      guarded += 1;
      continue;
    }
    checked += 1;

    if (item.type === 3 && item.card !== null) {
      const status = expiryStatus(item.card.expMonth ?? '', item.card.expYear ?? '', now);
      if (status === 'expired' || status === 'soon') {
        expiring.push({ ...subject(item), expired: status === 'expired' });
      }
    }

    const password = item.password;
    if (password === null || password === '') {
      continue;
    }

    const group = byPassword.get(password);
    if (group === undefined) {
      byPassword.set(password, [subject(item)]);
    } else {
      group.push(subject(item));
    }

    const verdict = passwordStrength(password);
    if (verdict.strength === 'weak') {
      weak.push({ ...subject(item), reason: verdict.reason, bits: verdict.bits });
    } else if (echoesItsOwner(password, [item.name, item.username, hostOf(item.uris)])) {
      // Only worth saying when the password was not already flagged as weak —
      // two findings for one password is one finding too many.
      echoing.push(subject(item));
    }

    const age = daysSince(item.passwordUpdatedAt, now);
    if (age !== null && age >= staleAfterDays) {
      stale.push({ ...subject(item), days: age });
    }
  }

  return {
    checked,
    guarded,
    // Only the groups: a password used once is not reuse. The passwords
    // themselves are dropped here and never leave this function.
    reused: [...byPassword.values()].filter((g) => g.length > 1).map((items) => ({ items })),
    weak,
    echoing,
    stale,
    expiring,
  };
}

/** How many findings a report holds — what the banner counts. */
export function findingCount(report: HealthReport): number {
  return (
    report.reused.length +
    report.weak.length +
    report.echoing.length +
    report.stale.length +
    report.expiring.length
  );
}
