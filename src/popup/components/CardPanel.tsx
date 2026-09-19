/**
 * @file The detail panel of a bank card.
 *
 * ## What it does that a list of fields does not
 *
 * - The **network is derived from the number**, not read from what was stored.
 *   A vault imported from elsewhere routinely carries a brand that contradicts
 *   its number; the number is the one that pays.
 * - The **expiry date is compared to today**, and says so. A card that expired
 *   last month looks exactly like a valid one in a plain list of fields, and one
 *   finds out at the till.
 * - The number is **grouped as it is embossed**, so it can be checked against
 *   the plastic without counting digits.
 * - Copying the number yields **digits alone**. Payment forms reject the spaces,
 *   and a value one has to clean up after pasting is a value one retypes.
 * - The number and the security code are **concealed by default**, the number
 *   behind its own last four digits — enough to tell two cards apart, not enough
 *   to charge either.
 */

import { t } from '@shared/i18n.js';
import {
  BRAND_LABELS,
  type CardView,
  cvvLength,
  detectBrand,
  digitsOf,
  expiryStatus,
  formatExpiry,
  groupNumber,
  isLuhnValid,
  maskNumber,
} from '@core/vault/card.js';

import { DetailField } from './DetailField.js';

/** The badge shown next to the expiry date, or nothing while it is fine. */
function ExpiryBadge({ status }: { status: ReturnType<typeof expiryStatus> }) {
  if (status === 'expired') {
    return <span class="badge badge-alert">{t('cardExpired')}</span>;
  }
  if (status === 'soon') {
    return <span class="badge badge-warn">{t('cardExpiresSoon')}</span>;
  }
  return null;
}

export function CardPanel({
  card,
  copiedField,
  onCopy,
  now = new Date(),
}: {
  card: CardView;
  /** Label of the field copied a moment ago, or `null`. */
  copiedField: string | null;
  /** Copies one field. The value is already in the form to be pasted. */
  onCopy: (label: string, value: string) => void;
  /** Injected so the expiry boundaries can be tested. */
  now?: Date;
}) {
  const number = card.number ?? '';
  const brand = detectBrand(number);
  const status = expiryStatus(card.expMonth ?? '', card.expYear ?? '', now);
  const expiry = formatExpiry(card.expMonth ?? '', card.expYear ?? '');
  // A number that fails its check digit is worth saying; one that passes is not.
  const mistyped = number !== '' && !isLuhnValid(number);

  const numberLabel = t('cardNumber');
  const codeLabel = t('cardCode');

  return (
    <div class="detail-panel">
      <div class="detail-head">
        <span class="brand">{brand === null ? t('cardSection') : BRAND_LABELS[brand]}</span>
        {expiry !== '' && (
          <span class="detail-expiry">
            {t('cardExpiry')} {expiry} <ExpiryBadge status={status} />
          </span>
        )}
      </div>
      <DetailField
        label={numberLabel}
        value={number === '' ? null : groupNumber(number, brand)}
        sensitive
        mono
        masked={maskNumber(number)}
        copied={copiedField === numberLabel}
        // Digits alone: what a payment form accepts.
        onCopy={() => onCopy(numberLabel, digitsOf(number))}
      />
      {mistyped && <p class="hint-alert">{t('cardCheckDigitFailed')}</p>}
      <DetailField
        label={t('cardholderName')}
        value={card.cardholderName}
        copied={copiedField === t('cardholderName')}
        onCopy={() => onCopy(t('cardholderName'), card.cardholderName ?? '')}
      />
      <DetailField
        label={`${codeLabel} (${t('cardCodeHint', String(cvvLength(brand)))})`}
        value={card.code}
        sensitive
        mono
        copied={copiedField === codeLabel}
        onCopy={() => onCopy(codeLabel, card.code ?? '')}
      />
    </div>
  );
}
