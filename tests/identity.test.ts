/**
 * @file Composition of the civil fields of an identity.
 *
 * What is pinned here is the composition, not the storage: which parts enter the
 * full name, and how an address collapses when half of it is missing.
 */

import { describe, expect, it } from 'vitest';

import {
  addressLines,
  EMPTY_IDENTITY,
  fullAddress,
  fullName,
  IDENTITY_FIELDS,
  IDENTITY_GROUPS,
  isEmptyIdentity,
  isSensitive,
  type IdentityView,
} from '../src/core/vault/identity.js';

function identity(patch: Partial<IdentityView>): IdentityView {
  return { ...EMPTY_IDENTITY, ...patch };
}

describe('fullName', () => {
  it('reads in order, honorific included', () => {
    expect(
      fullName(identity({ title: 'Dr', firstName: 'Ada', middleName: 'King', lastName: 'Lovelace' })),
    ).toBe('Dr Ada King Lovelace');
  });

  it('collapses the parts that are absent instead of leaving gaps', () => {
    expect(fullName(identity({ firstName: 'Ada', lastName: 'Lovelace' }))).toBe('Ada Lovelace');
    expect(fullName(identity({ lastName: 'Lovelace' }))).toBe('Lovelace');
  });

  it('treats a field of spaces as absent', () => {
    expect(fullName(identity({ firstName: '  ', lastName: 'Lovelace' }))).toBe('Lovelace');
  });

  it('gives an empty string when there is no name', () => {
    expect(fullName(EMPTY_IDENTITY)).toBe('');
  });
});

describe('addressLines', () => {
  it('puts city, region and postcode on one line, as an envelope does', () => {
    expect(
      addressLines(
        identity({
          address1: '12 rue de la Paix',
          city: 'Paris',
          postalCode: '75002',
          country: 'France',
        }),
      ),
    ).toEqual(['12 rue de la Paix', 'Paris 75002', 'France']);
  });

  it('keeps the second and third street lines when they are there', () => {
    expect(
      addressLines(identity({ address1: 'Acme Corp', address2: 'Building C', address3: 'Desk 4' })),
    ).toEqual(['Acme Corp', 'Building C', 'Desk 4']);
  });

  it('does not leave a blank line where a part is missing', () => {
    expect(addressLines(identity({ address1: '12 rue de la Paix', country: 'France' }))).toEqual([
      '12 rue de la Paix',
      'France',
    ]);
  });

  it('gives nothing for an empty address', () => {
    expect(addressLines(EMPTY_IDENTITY)).toEqual([]);
    expect(fullAddress(EMPTY_IDENTITY)).toBe('');
  });

  it('joins the block with newlines, ready to paste', () => {
    expect(fullAddress(identity({ address1: 'A', city: 'B', country: 'C' }))).toBe('A\nB\nC');
  });
});

describe('field layout', () => {
  it('lays every stored field out in exactly one group', () => {
    const grouped = Object.values(IDENTITY_GROUPS).flat();
    expect([...grouped].sort()).toEqual([...IDENTITY_FIELDS].sort());
    expect(new Set(grouped).size).toBe(grouped.length);
  });

  it('masks the three that cannot be rotated once read', () => {
    expect(isSensitive('ssn')).toBe(true);
    expect(isSensitive('passportNumber')).toBe(true);
    expect(isSensitive('licenseNumber')).toBe(true);
    expect(isSensitive('email')).toBe(false);
    expect(isSensitive('firstName')).toBe(false);
  });
});

describe('isEmptyIdentity', () => {
  it('is true only when nothing at all is set', () => {
    expect(isEmptyIdentity(EMPTY_IDENTITY)).toBe(true);
    expect(isEmptyIdentity(identity({ email: 'ada@example.org' }))).toBe(false);
  });
});
