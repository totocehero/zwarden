/**
 * @file The card section of the edit form.
 *
 * Three things distinguish it from a row of text inputs:
 *
 * 1. **The network is not asked for.** It is read off the number as it is typed.
 *    Asking a user to pick "Visa" from a dropdown, right under a number that
 *    starts with a 4, is asking them to restate what they have already said —
 *    and to get it wrong.
 * 2. **The number is checked.** Its check digit catches a wrong digit and two
 *    swapped ones, which is what people actually mistype. It is said at once,
 *    not at the till.
 * 3. **The number is grouped on leaving the field**, as it is embossed. Grouping
 *    it while typing would mean moving the caret under the user's fingers, which
 *    is worse than no grouping at all.
 */

import { t } from '@shared/i18n.js';
import {
  BRAND_LABELS,
  type CardEdit,
  cvvLength,
  detectBrand,
  digitsOf,
  groupNumber,
  isLuhnValid,
} from '@core/vault/card.js';

/** The twelve months, as they are printed on a card. */
const MONTHS = Array.from({ length: 12 }, (_, index) => String(index + 1).padStart(2, '0'));

export function CardFields({
  card,
  onPatch,
}: {
  card: CardEdit;
  onPatch: (patch: Partial<CardEdit>) => void;
}) {
  const digits = digitsOf(card.number);
  const brand = detectBrand(digits);
  // Silent while the number is too short to judge: telling someone their card is
  // invalid on the fourth digit is noise, not feedback.
  const judgeable = digits.length >= 12;
  const mistyped = judgeable && !isLuhnValid(digits);

  return (
    <>
      <label>
        {t('cardholderName')}
        <input
          type="text"
          autocomplete="off"
          value={card.cardholderName}
          onInput={(e) => onPatch({ cardholderName: e.currentTarget.value })}
        />
      </label>
      <label>
        {t('cardNumber')}
        <input
          type="text"
          class="mono"
          inputMode="numeric"
          autocomplete="off"
          placeholder={t('cardNumberPlaceholder')}
          value={card.number}
          onInput={(e) => onPatch({ number: e.currentTarget.value })}
          onBlur={(e) => onPatch({ number: groupNumber(e.currentTarget.value, brand) })}
        />
      </label>
      {brand !== null && (
        <p class="hint-diag">
          {t('cardBrandAuto')} — {BRAND_LABELS[brand]}
        </p>
      )}
      {mistyped && <p class="hint-alert">{t('cardCheckDigitFailed')}</p>}
      <div class="field-row">
        <label>
          {t('cardExpMonth')}
          <select
            value={card.expMonth}
            onChange={(e) => onPatch({ expMonth: e.currentTarget.value })}
          >
            <option value=""></option>
            {MONTHS.map((month) => (
              <option key={month} value={month}>
                {month}
              </option>
            ))}
          </select>
        </label>
        <label>
          {t('cardExpYear')}
          <input
            type="text"
            inputMode="numeric"
            autocomplete="off"
            maxLength={4}
            value={card.expYear}
            onInput={(e) => onPatch({ expYear: e.currentTarget.value })}
          />
        </label>
        <label>
          {`${t('cardCode')} (${t('cardCodeHint', String(cvvLength(brand)))})`}
          {/* `password` rather than `text`: the code is the half of a card that
              cannot be read off the front of it. */}
          <input
            type="password"
            class="mono"
            inputMode="numeric"
            autocomplete="off"
            maxLength={4}
            value={card.code}
            onInput={(e) => onPatch({ code: e.currentTarget.value })}
          />
        </label>
      </div>
    </>
  );
}
