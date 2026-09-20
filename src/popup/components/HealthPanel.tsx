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

import { useEffect, useRef, useState } from 'preact/hooks';

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
  /** The item's site, when there is one worth offering to open. */
  readonly uri?: string | null;
}

/** How long an armed discard waits before giving up on being confirmed. */
const ARMED_MS = 4_000;

/**
 * The discard button, which asks twice.
 *
 * Two clicks rather than a dialog: the popup is four hundred and twenty pixels
 * wide, and an overlay to confirm one row would cover the list it came from.
 *
 * ## The bug this shape exists to avoid
 *
 * The first version cancelled on `mouseleave`, which read well and did not
 * work: "Confirm" is half the width of "Move to the trash", so arming shrank
 * the button out from under the pointer, `mouseleave` fired, and it disarmed
 * before anyone could click it again. An element that resizes cannot use the
 * pointer leaving it as a signal.
 *
 * So it disarms on a timer instead, and the button reserves the width of its
 * longer label in CSS so neither state moves the row.
 */
function DiscardButton({ onDelete }: { onDelete: () => void }) {
  const [armed, setArmed] = useState(false);
  const timer = useRef<number | undefined>(undefined);

  // An armed button left alone goes back to safety rather than waiting all
  // session for a click that is not coming.
  useEffect(() => {
    if (!armed) {
      return;
    }
    timer.current = window.setTimeout(() => setArmed(false), ARMED_MS);
    return () => clearTimeout(timer.current);
  }, [armed]);

  return (
    <button
      class={`chip health-discard${armed ? ' chip-on' : ''}`}
      title={t('healthDelete')}
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
  onOpen,
}: {
  title: string;
  rows: readonly FindingRow[];
  onDelete?: (id: string) => void;
  onOpen?: (uri: string) => void;
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
          {row.uri != null && onOpen !== undefined ? (
            <button
              class="health-name health-link"
              title={row.uri}
              onClick={() => onOpen(row.uri!)}
            >
              {row.name}
            </button>
          ) : (
            <span class="health-name">{row.name}</span>
          )}
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
  onOpen,
}: {
  report: HealthReport;
  onBack: () => void;
  /** Moves an item to the trash. Offered on the stale list, which is the one
   *  read to decide what is no longer worth keeping. */
  onDelete: (id: string) => void;
  /**
   * Opens an item's site in a tab.
   *
   * Only ever called with an `http`/`https` URL: `openableUri` refuses
   * everything else before it reaches a row, because a vault URI is arbitrary
   * text and `javascript:` rendered as a link would run inside the extension's
   * own page.
   */
  onOpen: (uri: string) => void;
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
            uri: finding.uri,
          }))}
          onOpen={onOpen}
        />
        <Finding
          title={t('healthEchoing')}
          rows={report.echoing.map((finding) => ({
            key: finding.id,
            name: finding.name,
            uri: finding.uri,
          }))}
          onOpen={onOpen}
        />
        <Finding
          title={t('healthStale')}
          rows={report.stale.map((finding) => ({
            key: finding.id,
            name: finding.name,
            detail: t('healthStaleDetail', String(finding.days)),
            deletable: finding.id,
            uri: finding.uri,
          }))}
          onDelete={onDelete}
          onOpen={onOpen}
        />
        {report.stale.length > 0 && <p class="hint-diag">{t('healthDeleteHint')}</p>}
        <Finding
          title={t('healthExpiring')}
          rows={report.expiring.map((finding) => ({
            key: finding.id,
            name: finding.name,
            detail: finding.expired ? t('cardExpired') : t('cardExpiresSoon'),
            uri: finding.uri,
          }))}
          onOpen={onOpen}
        />

        {report.guarded > 0 && (
          <p class="hint-diag">{t('healthGuarded', String(report.guarded))}</p>
        )}
        <p class="hint-diag">{t('healthDisclaimer')}</p>
      </main>
    </div>
  );
}
