/**
 * @file The vault's health, as a screen.
 *
 * Purely presentational: it receives a report already built by `core/vault`
 * and renders it. It decrypts nothing and judges nothing — the rules are in
 * `health.ts` and `passwordStrength.ts`, where they are tested.
 *
 * Two things it is careful to say out loud. That items guarded by `reprompt`
 * were **not examined**, so the report never implies a coverage it does not
 * have. And that a "weak" verdict is reliable while its absence is not a
 * certificate — an estimate computed here, with no dictionary and no network,
 * finds the obviously bad and does not certify the rest.
 */

import { useState } from 'preact/hooks';

import { t, type MessageKey } from '@shared/i18n.js';
import type { HealthReport, HealthSubject } from '@core/vault/health.js';
import { findingCount } from '@core/vault/health.js';
import type { StrengthReason } from '@core/vault/passwordStrength.js';

/** Why a password was judged weak, in words. */
const REASONS: Readonly<Record<StrengthReason, MessageKey>> = {
  short: 'healthReasonShort',
  notorious: 'healthReasonNotorious',
  repeated: 'healthReasonRepeated',
  sequence: 'healthReasonSequence',
  'single-class': 'healthReasonSingleClass',
  entropy: 'healthReasonEntropy',
  ok: 'healthReasonEntropy',
};

/** One row of a finding group. */
interface FindingRow {
  readonly key: string;
  readonly name: string;
  readonly detail?: string;
  /** The item to discard, when the row offers it. */
  readonly deletable?: string;
}

/**
 * The discard button, which asks twice.
 *
 * Two clicks rather than a dialog: the popup is four hundred and twenty pixels
 * wide and an overlay to confirm one row would cover the list it came from. The
 * second click is the confirmation, and moving away from the row cancels it —
 * so a misclick costs nothing and does not need undoing.
 */
function DiscardButton({ onDelete }: { onDelete: () => void }) {
  const [armed, setArmed] = useState(false);

  return (
    <button
      class={`chip health-discard${armed ? ' chip-on' : ''}`}
      title={t('healthDelete')}
      onMouseLeave={() => setArmed(false)}
      onBlur={() => setArmed(false)}
      onClick={() => {
        if (armed) {
          onDelete();
        }
        setArmed(!armed);
      }}
    >
      {armed ? t('healthDeleteConfirm') : t('healthDelete')}
    </button>
  );
}

/**
 * One group of findings, folded, or nothing when there are none.
 *
 * `<details>` rather than a hand-rolled toggle: it opens on click, on Enter and
 * on Space, it is announced correctly, and browser find-in-page can open it.
 * None of that comes free from a `useState` and a chevron.
 *
 * **Folded by default, with the count in the heading.** A report of five
 * categories opened flat is a wall one scrolls past; folded, it is a summary
 * one reads in a second and then opens where it matters. That is the whole
 * reason to have categories at all.
 */
function Finding({
  title,
  rows,
  onDelete,
}: {
  title: string;
  rows: readonly FindingRow[];
  onDelete?: (id: string) => void;
}) {
  if (rows.length === 0) {
    return null;
  }
  return (
    <details class="detail-group health-group">
      <summary>
        <span class="health-group-title">{title}</span>
        <span class="health-group-count">{rows.length}</span>
      </summary>
      {rows.map((row) => (
        <div key={row.key} class="health-row">
          <span class="health-name">{row.name}</span>
          {row.detail !== undefined && <span class="health-detail">{row.detail}</span>}
          {row.deletable !== undefined && onDelete !== undefined && (
            <DiscardButton onDelete={() => onDelete(row.deletable!)} />
          )}
        </div>
      ))}
    </details>
  );
}

/** The names in a reuse group, on one line. */
const joined = (items: readonly HealthSubject[]): string => items.map((i) => i.name).join(' · ');

export function HealthPanel({
  report,
  onBack,
  onDelete,
}: {
  report: HealthReport;
  onBack: () => void;
  /** Moves an item to the trash. Offered on the stale list, which is the one
   *  read to decide what is no longer worth keeping. */
  onDelete: (id: string) => void;
}) {
  const total = findingCount(report);

  return (
    <div>
      <header>
        <h1>{t('healthTitle')}</h1>
        <button class="quiet" onClick={onBack}>
          {t('actionBack')}
        </button>
      </header>
      <main>
        {total === 0 && <p class="empty">{t('healthAllGood', String(report.checked))}</p>}

        <Finding
          title={t('healthReused')}
          rows={report.reused.map((group, index) => ({
            key: `reuse-${index}`,
            name: joined(group.items),
            detail: t('healthReusedDetail', String(group.items.length)),
          }))}
        />
        <Finding
          title={t('healthWeak')}
          rows={report.weak.map((finding) => ({
            key: finding.id,
            name: finding.name,
            detail: t(REASONS[finding.reason]),
          }))}
        />
        <Finding
          title={t('healthEchoing')}
          rows={report.echoing.map((finding) => ({ key: finding.id, name: finding.name }))}
        />
        <Finding
          title={t('healthStale')}
          rows={report.stale.map((finding) => ({
            key: finding.id,
            name: finding.name,
            detail: t('healthStaleDetail', String(finding.days)),
            deletable: finding.id,
          }))}
          onDelete={onDelete}
        />
        {report.stale.length > 0 && <p class="hint-diag">{t('healthDeleteHint')}</p>}
        <Finding
          title={t('healthExpiring')}
          rows={report.expiring.map((finding) => ({
            key: finding.id,
            name: finding.name,
            detail: finding.expired ? t('cardExpired') : t('cardExpiresSoon'),
          }))}
        />

        {report.guarded > 0 && (
          <p class="hint-diag">{t('healthGuarded', String(report.guarded))}</p>
        )}
        <p class="hint-diag">{t('healthDisclaimer')}</p>
      </main>
    </div>
  );
}
