/**
 * @file The identity section of the edit form.
 *
 * Eighteen fields, laid out in the four groups a person thinks in — name,
 * contact, address, papers — rather than in the one column the API stores them
 * in. The grouping comes from `identity.ts`, which is also what the detail panel
 * reads: the two views cannot drift apart, and a field added to the model
 * appears in both or in neither.
 */

import { t } from '@shared/i18n.js';
import {
  IDENTITY_GROUPS,
  isSensitive,
  type IdentityEdit,
  type IdentityGroup,
} from '@core/vault/identity.js';

import { IDENTITY_FIELD_LABELS, IDENTITY_GROUP_LABELS } from './itemLabels.js';

/** The groups, in the order the form lays them out. */
const GROUP_ORDER: readonly IdentityGroup[] = ['name', 'contact', 'address', 'documents'];

export function IdentityFields({
  identity,
  onPatch,
}: {
  identity: IdentityEdit;
  onPatch: (patch: Partial<IdentityEdit>) => void;
}) {
  return (
    <>
      {GROUP_ORDER.map((group) => (
        <fieldset key={group} class="field-group">
          <legend>{t(IDENTITY_GROUP_LABELS[group])}</legend>
          {IDENTITY_GROUPS[group].map((field) => (
            <label key={field}>
              {t(IDENTITY_FIELD_LABELS[field])}
              <input
                // The papers are typed masked, like a password: a shoulder in an
                // open-plan office reads a passport number as easily as a
                // password, and unlike a password it cannot be changed after.
                type={isSensitive(field) ? 'password' : 'text'}
                autocomplete="off"
                value={identity[field]}
                onInput={(e) => onPatch({ [field]: e.currentTarget.value })}
              />
            </label>
          ))}
        </fieldset>
      ))}
    </>
  );
}
