/**
 * @file Bank-card rules.
 *
 * These are the assertions a user checks against the plastic in their hand, so
 * they are written against real published issuer ranges and real test numbers —
 * not against the implementation.
 */

import { describe, expect, it } from 'vitest';

import {
  CARD_FIELDS,
  cvvLength,
  detectBrand,
  digitsOf,
  EMPTY_CARD,
  expiryStatus,
  formatExpiry,
  groupNumber,
  isEmptyCard,
  isLuhnValid,
  maskNumber,
  SENSITIVE_CARD_FIELDS,
} from '../src/core/vault/card.js';

describe('detectBrand', () => {
  it.each([
    ['4242424242424242', 'visa'],
    ['4000056655665556', 'visa'],
    ['5555555555554444', 'mastercard'],
    ['2223003122003222', 'mastercard'],
    ['378282246310005', 'amex'],
    ['371449635398431', 'amex'],
    ['6011111111111117', 'discover'],
    ['6511111111111119', 'discover'],
    ['30569309025904', 'diners'],
    ['36227206271667', 'diners'],
    ['3530111333300000', 'jcb'],
    ['6200000000000005', 'unionpay'],
    ['8171999927660000', 'unionpay'],
    ['6759649826438453', 'maestro'],
    ['2200000000000004', 'mir'],
  ])('recognises %s as %s', (number, brand) => {
    expect(detectBrand(number)).toBe(brand);
  });

  it('accepts the separators people paste', () => {
    expect(detectBrand('4242 4242 4242 4242')).toBe('visa');
    expect(detectBrand('4242-4242-4242-4242')).toBe('visa');
  });

  it('returns null rather than guessing on an unallocated prefix', () => {
    expect(detectBrand('9999999999999999')).toBeNull();
    expect(detectBrand('')).toBeNull();
  });

  it('gives the narrow range priority over the one containing it', () => {
    // 622126-622925 is Discover, carved out of UnionPay's 62.
    expect(detectBrand('6221260000000000')).toBe('discover');
    expect(detectBrand('6229250000000000')).toBe('discover');
    // Either side of the carve-out, UnionPay takes it back.
    expect(detectBrand('6221250000000000')).toBe('unionpay');
    expect(detectBrand('6229260000000000')).toBe('unionpay');
  });

  it('gives Maestro priority over the ranges around its prefixes', () => {
    expect(detectBrand('6759000000000000')).toBe('maestro');
    expect(detectBrand('5018000000000000')).toBe('maestro');
  });
});

describe('isLuhnValid', () => {
  it.each([
    '4242424242424242',
    '5555555555554444',
    '378282246310005',
    '6011111111111117',
    '30569309025904',
  ])('accepts the published test number %s', (number) => {
    expect(isLuhnValid(number)).toBe(true);
  });

  it('catches a single wrong digit', () => {
    expect(isLuhnValid('4242424242424243')).toBe(false);
  });

  it('catches two swapped digits', () => {
    // 4242...4242 with the last two transposed reads 24, which breaks the key.
    expect(isLuhnValid('4242424242424224')).toBe(false);
  });

  it('refuses what cannot carry a check digit', () => {
    expect(isLuhnValid('')).toBe(false);
    expect(isLuhnValid('4')).toBe(false);
  });
});

describe('groupNumber', () => {
  it('groups in fours by default', () => {
    expect(groupNumber('4242424242424242', 'visa')).toBe('4242 4242 4242 4242');
  });

  it('follows the embossing on American Express, which is not in fours', () => {
    expect(groupNumber('378282246310005', 'amex')).toBe('3782 822463 10005');
  });

  it('follows the embossing on Diners Club', () => {
    expect(groupNumber('30569309025904', 'diners')).toBe('3056 930902 5904');
  });

  it('groups an unknown brand in fours', () => {
    expect(groupNumber('9999999999999999')).toBe('9999 9999 9999 9999');
  });

  it('keeps the tail of a 19-digit number rather than dropping it', () => {
    expect(groupNumber('4242424242424242424', 'visa')).toBe('4242 4242 4242 4242 424');
  });

  it('groups as the user types, without padding', () => {
    expect(groupNumber('424242', 'visa')).toBe('4242 42');
  });
});

describe('maskNumber', () => {
  it('keeps only the last four', () => {
    expect(maskNumber('4242424242424242')).toBe('•••• 4242');
  });

  it('shows a number too short to mask as it is', () => {
    expect(maskNumber('424')).toBe('424');
  });

  it('shows nothing for nothing', () => {
    expect(maskNumber('')).toBe('');
  });
});

describe('cvvLength', () => {
  it('is four on American Express and three everywhere else', () => {
    expect(cvvLength('amex')).toBe(4);
    expect(cvvLength('visa')).toBe(3);
    expect(cvvLength(null)).toBe(3);
  });
});

describe('expiryStatus', () => {
  const march2026 = new Date(Date.UTC(2026, 2, 15));

  it('keeps a card valid through the last day of its month', () => {
    // A card stamped 03/26 works on 31 March 2026 and not on 1 April.
    expect(expiryStatus('3', '26', new Date(Date.UTC(2026, 2, 31, 23, 59)))).toBe('soon');
    expect(expiryStatus('3', '26', new Date(Date.UTC(2026, 3, 1)))).toBe('expired');
  });

  it('flags a card expiring within two months', () => {
    expect(expiryStatus('4', '2026', march2026)).toBe('soon');
  });

  it('leaves a distant card alone', () => {
    expect(expiryStatus('12', '2030', march2026)).toBe('valid');
  });

  it('reads both two- and four-digit years', () => {
    expect(expiryStatus('12', '30', march2026)).toBe('valid');
    expect(expiryStatus('12', '2030', march2026)).toBe('valid');
  });

  it('says it does not know rather than guessing', () => {
    expect(expiryStatus('', '', march2026)).toBe('unknown');
    expect(expiryStatus('13', '2030', march2026)).toBe('unknown');
    expect(expiryStatus('0', '2030', march2026)).toBe('unknown');
    expect(expiryStatus('12', 'trente', march2026)).toBe('unknown');
  });
});

describe('formatExpiry', () => {
  it('pads to the form printed on the card', () => {
    expect(formatExpiry('3', '2026')).toBe('03/26');
    expect(formatExpiry('12', '30')).toBe('12/30');
  });

  it('shows nothing rather than a broken date', () => {
    expect(formatExpiry('', '')).toBe('');
    expect(formatExpiry('13', '2026')).toBe('');
  });
});

describe('digitsOf', () => {
  it('keeps only the digits', () => {
    expect(digitsOf(' 4242-4242 4242.4242 ')).toBe('4242424242424242');
  });
});

describe('card shape', () => {
  it('lists exactly the fields the view carries', () => {
    expect([...CARD_FIELDS].sort()).toEqual(Object.keys(EMPTY_CARD).sort());
  });

  it('masks the number and the code, which authorise a payment on their own', () => {
    expect([...SENSITIVE_CARD_FIELDS].sort()).toEqual(['code', 'number']);
  });

  it('is empty only when nothing at all is set', () => {
    expect(isEmptyCard(EMPTY_CARD)).toBe(true);
    expect(isEmptyCard({ ...EMPTY_CARD, number: '4242424242424242' })).toBe(false);
  });
});
