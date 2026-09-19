/**
 * @file The detail panel of an identity.
 *
 * ## What it does that a list of eighteen fields does not
 *
 * - It **composes**: the full name and the postal address each become one value,
 *   copied in one gesture. That is what one actually needs — no form asks for a
 *   street and a postcode in two separate pastes.
 * - It **groups**: name, contact, address, papers. Eighteen fields in one flat
 *   column is a wall one reads three times to find an email address.
 * - It **hides what is empty**. A real identity fills in six fields; the other
 *   twelve are noise.
 * - It **conceals the papers** — social-security, passport, licence. Unlike a
 *   password, those cannot be rotated after being read over a shoulder.
 */

import { t } from '@shared/i18n.js';
import {
  addressLines,
  fullAddress,
  fullName,
  IDENTITY_GROUPS,
  isSensitive,
  type IdentityGroup,
  type IdentityView,
} from '@core/vault/identity.js';

import { DetailBlock, DetailField } from './DetailField.js';
import { IDENTITY_FIELD_LABELS, IDENTITY_GROUP_LABELS } from './itemLabels.js';

export function IdentityPanel({
  identity,
  copiedField,
  onCopy,
}: {
  identity: IdentityView;
  /** Label of the field copied a moment ago, or `null`. */
  copiedField: string | null;
  onCopy: (label: string, value: string) => void;
}) {
  const name = fullName(identity);
  const lines = addressLines(identity);

  /** One group of fields, or nothing if every field in it is empty. */
  function group(key: IdentityGroup) {
    const fields = IDENTITY_GROUPS[key].filter((field) => (identity[field] ?? '').trim() !== '');
    if (fields.length === 0) {
      return null;
    }
    return (
      <section class="detail-group">
        <h2>{t(IDENTITY_GROUP_LABELS[key])}</h2>
        {fields.map((field) => {
          const label = t(IDENTITY_FIELD_LABELS[field]);
          return (
            <DetailField
              key={field}
              label={label}
              value={identity[field]}
              sensitive={isSensitive(field)}
              copied={copiedField === label}
              onCopy={() => onCopy(label, identity[field] ?? '')}
            />
          );
        })}
      </section>
    );
  }

  return (
    <div class="detail-panel">
      {/* The two composed values first: they are what one came for. */}
      <DetailField
        label={t('identityFullName')}
        value={name === '' ? null : name}
        copied={copiedField === t('identityFullName')}
        onCopy={() => onCopy(t('identityFullName'), name)}
      />
      <DetailBlock
        label={t('identityFullAddress')}
        lines={lines}
        copied={copiedField === t('identityFullAddress')}
        onCopy={() => onCopy(t('identityFullAddress'), fullAddress(identity))}
      />
      {group('name')}
      {group('contact')}
      {group('address')}
      {group('documents')}
    </div>
  );
}
