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

/** One group of findings, or nothing when there are none. */
function Finding({
  title,
  rows,
}: {
  title: string;
  rows: readonly { readonly key: string; readonly name: string; readonly detail?: string }[];
}) {
  if (rows.length === 0) {
    return null;
  }
  return (
    <section class="detail-group">
      <h2>{title}</h2>
      {rows.map((row) => (
        <div key={row.key} class="health-row">
          <span class="health-name">{row.name}</span>
          {row.detail !== undefined && <span class="health-detail">{row.detail}</span>}
        </div>
      ))}
    </section>
  );
}

/** The names in a reuse group, on one line. */
const joined = (items: readonly HealthSubject[]): string => items.map((i) => i.name).join(' · ');

export function HealthPanel({
  report,
  onBack,
}: {
  report: HealthReport;
  onBack: () => void;
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
          }))}
        />
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
