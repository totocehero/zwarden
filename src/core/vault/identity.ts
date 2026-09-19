/**
 * @file Identity logic: composition and grouping of civil fields.
 *
 * Pure, like `card.ts`. An identity is eighteen loose fields on Bitwarden's
 * side, presented as one flat column; what makes it usable is not storing them
 * but *composing* them — the full name as one runs of it, the postal address as
 * a form expects it, the fields ordered by what the user is looking for.
 *
 * Composition lives here rather than in the view because it is exactly what
 * needs pinning down: "is the middle name included?", "does an empty line
 * collapse?" are questions with one right answer, and a test is the only place
 * to keep it.
 */

/** An identity, decrypted. Every field is optional in practice. */
export interface IdentityView {
  readonly title: string | null;
  readonly firstName: string | null;
  readonly middleName: string | null;
  readonly lastName: string | null;
  readonly company: string | null;
  readonly email: string | null;
  readonly phone: string | null;
  readonly username: string | null;
  readonly address1: string | null;
  readonly address2: string | null;
  readonly address3: string | null;
  readonly city: string | null;
  readonly state: string | null;
  readonly postalCode: string | null;
  readonly country: string | null;
  readonly ssn: string | null;
  readonly passportNumber: string | null;
  readonly licenseNumber: string | null;
}

/** The field names, in storage order — the single source of truth for both
 *  decryption and the edit form. */
export const IDENTITY_FIELDS = [
  'title',
  'firstName',
  'middleName',
  'lastName',
  'company',
  'email',
  'phone',
  'username',
  'address1',
  'address2',
  'address3',
  'city',
  'state',
  'postalCode',
  'country',
  'ssn',
  'passportNumber',
  'licenseNumber',
] as const;

/** Name of one identity field. */
export type IdentityField = (typeof IDENTITY_FIELDS)[number];

/** An identity's cleartext values, one string per field. */
export type IdentityEdit = Readonly<Record<IdentityField, string>>;

/** An identity edit with every field blank. */
export const EMPTY_IDENTITY_EDIT: IdentityEdit = Object.freeze(
  Object.fromEntries(IDENTITY_FIELDS.map((field) => [field, ''])) as unknown as IdentityEdit,
);

/** An identity with no field set. */
export const EMPTY_IDENTITY: IdentityView = Object.freeze(
  Object.fromEntries(IDENTITY_FIELDS.map((field) => [field, null])) as unknown as IdentityView,
);

/** Joins the parts that are actually there, separated by a single space. */
function join(parts: readonly (string | null)[], separator = ' '): string {
  return parts
    .map((part) => part?.trim() ?? '')
    .filter((part) => part !== '')
    .join(separator);
}

/**
 * The full name, in reading order.
 *
 * The honorific is included because it is what forms ask for, and the middle
 * name because an identity that drops it silently is worse than useless on the
 * documents that require it.
 *
 * @returns An empty string if no name part is set.
 */
export function fullName(identity: IdentityView): string {
  return join([identity.title, identity.firstName, identity.middleName, identity.lastName]);
}

/**
 * The address, one line per line of an envelope.
 *
 * City, region and postcode share a line, as every postal service prints them.
 * Empty parts collapse rather than leaving a blank line — an address with no
 * second street line should not be two lines taller than it needs to be.
 *
 * @returns The lines, in order. Empty if nothing is set.
 */
export function addressLines(identity: IdentityView): readonly string[] {
  const locality = join([identity.city, identity.state, identity.postalCode]);
  return [identity.address1, identity.address2, identity.address3, locality, identity.country]
    .map((line) => line?.trim() ?? '')
    .filter((line) => line !== '');
}

/** The address as one block of text, ready to be copied into a form. */
export function fullAddress(identity: IdentityView): string {
  return addressLines(identity).join('\n');
}

/** The groups the edit form and the detail panel lay the fields out in. */
export type IdentityGroup = 'name' | 'contact' | 'address' | 'documents';

/** Which group each field belongs to. */
export const IDENTITY_GROUPS: Readonly<Record<IdentityGroup, readonly IdentityField[]>> = {
  name: ['title', 'firstName', 'middleName', 'lastName'],
  contact: ['company', 'email', 'phone', 'username'],
  address: ['address1', 'address2', 'address3', 'city', 'state', 'postalCode', 'country'],
  documents: ['ssn', 'passportNumber', 'licenseNumber'],
};

/**
 * The fields that are masked until the user asks for them.
 *
 * These three are the ones that cost something when read over a shoulder: they
 * identify a person to an administration, and unlike a password they cannot be
 * rotated afterwards.
 */
export const SENSITIVE_IDENTITY_FIELDS: readonly IdentityField[] = [
  'ssn',
  'passportNumber',
  'licenseNumber',
];

/** True if the field is one of the masked ones. */
export function isSensitive(field: IdentityField): boolean {
  return SENSITIVE_IDENTITY_FIELDS.includes(field);
}

/** True if the identity carries nothing at all. */
export function isEmptyIdentity(identity: IdentityView): boolean {
  return IDENTITY_FIELDS.every((field) => (identity[field] ?? '') === '');
}
