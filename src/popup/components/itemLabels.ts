/**
 * @file Field labels of the typed items.
 *
 * A data table, not a component: the detail panel and the edit form must name
 * the same field the same way, and the only way to guarantee that is for the
 * name to exist once.
 *
 * Written out rather than derived from the field names — the message keys are
 * typed, and a table the compiler checks is worth more than a concatenation it
 * cannot.
 */

import type { MessageKey } from '@shared/i18n.js';
import type { CardField } from '@core/vault/card.js';
import type { IdentityField, IdentityGroup } from '@core/vault/identity.js';

/** The label of each card field. */
export const CARD_FIELD_LABELS: Readonly<Record<CardField, MessageKey>> = {
  cardholderName: 'cardholderName',
  brand: 'cardBrand',
  number: 'cardNumber',
  expMonth: 'cardExpMonth',
  expYear: 'cardExpYear',
  code: 'cardCode',
};

/** The label of each identity field. */
export const IDENTITY_FIELD_LABELS: Readonly<Record<IdentityField, MessageKey>> = {
  title: 'identityTitle',
  firstName: 'identityFirstName',
  middleName: 'identityMiddleName',
  lastName: 'identityLastName',
  company: 'identityCompany',
  email: 'identityEmail',
  phone: 'identityPhone',
  username: 'identityUsername',
  address1: 'identityAddress1',
  address2: 'identityAddress2',
  address3: 'identityAddress3',
  city: 'identityCity',
  state: 'identityState',
  postalCode: 'identityPostalCode',
  country: 'identityCountry',
  ssn: 'identitySsn',
  passportNumber: 'identityPassportNumber',
  licenseNumber: 'identityLicenseNumber',
};

/** The heading of each identity group. */
export const IDENTITY_GROUP_LABELS: Readonly<Record<IdentityGroup, MessageKey>> = {
  name: 'identityGroupName',
  contact: 'identityGroupContact',
  address: 'identityGroupAddress',
  documents: 'identityGroupDocuments',
};

/** The label of each item type. */
export const TYPE_LABELS: Readonly<Record<number, MessageKey>> = {
  1: 'typeLogin',
  2: 'typeNote',
  3: 'typeCard',
  4: 'typeIdentity',
  5: 'typeSshKey',
};
