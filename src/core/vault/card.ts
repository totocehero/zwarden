/**
 * @file Bank-card logic: brand, validity, expiry, presentation.
 *
 * Everything here is pure — no crypto, no DOM, no clock of its own. A card
 * number is a string of digits, and every question one can ask of it (which
 * network issued it? is it well-formed? how is it grouped for reading?) is
 * answered without leaving this module. That is what makes it testable field by
 * field, which matters: these are the rules a user checks against the plastic in
 * their hand, and a wrong answer is immediately visible.
 *
 * ## What this adds over simply storing the number
 *
 * Bitwarden asks the user to pick the brand from a dropdown and never checks
 * anything. Here the brand is *derived* from the number, the number is checked
 * against its Luhn key, and the expiry date is compared to today. The three
 * together turn a mistyped digit into immediate feedback instead of a payment
 * refused at the till.
 */

/** The field names of a card, in storage order. */
export const CARD_FIELDS = [
  'cardholderName',
  'brand',
  'number',
  'expMonth',
  'expYear',
  'code',
] as const;

/** Name of one card field. */
export type CardField = (typeof CARD_FIELDS)[number];

/** A card, decrypted. Every field is optional in practice. */
export interface CardView {
  readonly cardholderName: string | null;
  /** The brand **as stored**, which may disagree with the number: see
   *  {@link detectBrand}, which the view prefers. */
  readonly brand: string | null;
  readonly number: string | null;
  readonly expMonth: string | null;
  readonly expYear: string | null;
  /** The security code — CVV, CVC, CID depending on the network. */
  readonly code: string | null;
}

/**
 * A card's cleartext values, one string per field — empty means absent.
 *
 * Defined here rather than beside the write path: it mirrors {@link CARD_FIELDS}
 * exactly, and a shape that mirrors a list belongs next to the list.
 */
export type CardEdit = Readonly<Record<CardField, string>>;

/** A card edit with every field blank. */
export const EMPTY_CARD_EDIT: CardEdit = Object.freeze(
  Object.fromEntries(CARD_FIELDS.map((field) => [field, ''])) as unknown as CardEdit,
);

/** A card with no field set. */
export const EMPTY_CARD: CardView = Object.freeze({
  cardholderName: null,
  brand: null,
  number: null,
  expMonth: null,
  expYear: null,
  code: null,
});

/**
 * The fields masked until the user asks for them.
 *
 * The number and the security code are the pair that authorises a payment on
 * their own; the rest is printed on receipts anyway.
 */
export const SENSITIVE_CARD_FIELDS: readonly CardField[] = ['number', 'code'];

/** True if the card carries nothing at all. */
export function isEmptyCard(card: CardView): boolean {
  return CARD_FIELDS.every((field) => (card[field] ?? '') === '');
}

/** The card networks recognised from the issuer prefix. */
export type CardBrand =
  | 'visa'
  | 'mastercard'
  | 'amex'
  | 'discover'
  | 'diners'
  | 'jcb'
  | 'unionpay'
  | 'maestro'
  | 'mir';

/** Display names, as the networks themselves write them. */
export const BRAND_LABELS: Readonly<Record<CardBrand, string>> = {
  visa: 'Visa',
  mastercard: 'Mastercard',
  amex: 'American Express',
  discover: 'Discover',
  diners: 'Diners Club',
  jcb: 'JCB',
  unionpay: 'UnionPay',
  maestro: 'Maestro',
  mir: 'Mir',
};

/** Keeps only the digits: users paste numbers with spaces and dashes. */
export function digitsOf(input: string): string {
  return input.replace(/\D/g, '');
}

/** True if `digits` starts with any of the given prefixes. */
function startsWithAny(digits: string, prefixes: readonly string[]): boolean {
  return prefixes.some((prefix) => digits.startsWith(prefix));
}

/**
 * True if the first `length` digits, read as a number, fall in `[low, high]`.
 *
 * Ranges are the only honest way to express IIN allocations: Mastercard's second
 * series is 222100-272099, which no prefix list can describe.
 */
function inRange(digits: string, length: number, low: number, high: number): boolean {
  if (digits.length < length) {
    return false;
  }
  const head = Number(digits.slice(0, length));
  return head >= low && head <= high;
}

/**
 * The issuer prefix rules, **in order of decreasing specificity**.
 *
 * Order is load-bearing, because the allocations genuinely overlap: 622126-622925
 * is Discover carved out of UnionPay's 62, and 6759 is Maestro carved out of
 * Discover's 65-adjacent space. Testing the narrow rule first is what keeps a
 * real co-branded card from being labelled by its neighbour.
 */
const BRAND_RULES: readonly (readonly [CardBrand, (digits: string) => boolean])[] = [
  ['amex', (d) => startsWithAny(d, ['34', '37'])],
  ['jcb', (d) => inRange(d, 4, 3528, 3589)],
  ['diners', (d) => inRange(d, 3, 300, 305) || startsWithAny(d, ['3095', '36', '38', '39'])],
  ['visa', (d) => d.startsWith('4')],
  [
    'maestro',
    (d) =>
      startsWithAny(d, ['5018', '5020', '5038', '5893', '6304', '6759', '6761', '6762', '6763']),
  ],
  ['mir', (d) => inRange(d, 4, 2200, 2204)],
  ['mastercard', (d) => inRange(d, 2, 51, 55) || inRange(d, 4, 2221, 2720)],
  [
    'discover',
    (d) => d.startsWith('6011') || inRange(d, 6, 622126, 622925) || inRange(d, 3, 644, 649) || d.startsWith('65'),
  ],
  ['unionpay', (d) => startsWithAny(d, ['62', '81'])],
];

/**
 * Identifies the network from the issuer prefix.
 *
 * @param input Card number, with or without separators.
 * @returns The brand, or `null` if no rule matches — an unknown prefix is not an
 *   error, only an absence: prefixes are reallocated over time, and refusing to
 *   store a number we cannot label would be the wrong trade.
 */
export function detectBrand(input: string): CardBrand | null {
  const digits = digitsOf(input);
  for (const [brand, matches] of BRAND_RULES) {
    if (matches(digits)) {
      return brand;
    }
  }
  return null;
}

/**
 * Verifies the number against its Luhn check digit.
 *
 * Every network but one uses it, and it catches the two mistakes people actually
 * make: a wrong digit, and two digits swapped. It proves nothing about the card
 * existing — only that what was typed is not a typo.
 *
 * @param input Card number, with or without separators.
 * @returns `false` for anything shorter than two digits, including empty.
 */
export function isLuhnValid(input: string): boolean {
  const digits = digitsOf(input);
  if (digits.length < 2) {
    return false;
  }
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let value = digits.charCodeAt(i) - 48;
    if (double) {
      value *= 2;
      if (value > 9) {
        value -= 9;
      }
    }
    sum += value;
    double = !double;
  }
  return sum % 10 === 0;
}

/** How each brand groups its digits when printed on the card. */
const GROUPINGS: Readonly<Record<CardBrand, readonly number[]>> = {
  visa: [4, 4, 4, 4],
  mastercard: [4, 4, 4, 4],
  amex: [4, 6, 5],
  discover: [4, 4, 4, 4],
  diners: [4, 6, 4],
  jcb: [4, 4, 4, 4],
  unionpay: [4, 4, 4, 4],
  maestro: [4, 4, 4, 4],
  mir: [4, 4, 4, 4],
};

/**
 * Groups the digits the way they are embossed on the card.
 *
 * Reading a sixteen-digit run to check it against the plastic is exactly the
 * task the eye is worst at; the grouping is not decoration.
 *
 * @param input Card number, with or without separators.
 * @param brand Network, if known — American Express and Diners Club do not
 *   group in fours.
 * @returns The grouped number. Digits beyond the pattern are appended in fours.
 */
export function groupNumber(input: string, brand: CardBrand | null = null): string {
  const digits = digitsOf(input);
  const pattern = brand === null ? [4, 4, 4, 4] : GROUPINGS[brand];
  const groups: string[] = [];
  let index = 0;
  for (const size of pattern) {
    if (index >= digits.length) {
      break;
    }
    groups.push(digits.slice(index, index + size));
    index += size;
  }
  while (index < digits.length) {
    groups.push(digits.slice(index, index + 4));
    index += 4;
  }
  return groups.join(' ');
}

/**
 * The last four digits behind a mask.
 *
 * This is the form the list shows, and it is deliberately the **only** form the
 * list ever holds: the full number is decrypted, reduced to this, and dropped.
 *
 * @param input Card number, with or without separators.
 * @returns For example `•••• 4242`, or an empty string if there is nothing to
 *   show.
 */
export function maskNumber(input: string): string {
  const digits = digitsOf(input);
  if (digits.length === 0) {
    return '';
  }
  return digits.length <= 4 ? digits : `•••• ${digits.slice(-4)}`;
}

/** How many digits the security code has — American Express prints four. */
export function cvvLength(brand: CardBrand | null): number {
  return brand === 'amex' ? 4 : 3;
}

/** Where a card stands relative to its expiry date. */
export type ExpiryStatus = 'unknown' | 'valid' | 'soon' | 'expired';

/** A card is flagged as expiring this many days ahead. */
const SOON_DAYS = 60;

/**
 * Normalises a stored year.
 *
 * Bitwarden stores whatever the user typed, so both `29` and `2029` occur in
 * real vaults.
 */
function fullYear(raw: string): number | null {
  const trimmed = raw.trim();
  if (!/^\d{2}$|^\d{4}$/.test(trimmed)) {
    return null;
  }
  const value = Number(trimmed);
  return trimmed.length === 2 ? 2000 + value : value;
}

/**
 * Compares a card's expiry date to a given instant.
 *
 * A card stays valid through the **last day of its stated month** — that is the
 * rule the networks apply, and stopping a day early would flag a perfectly
 * usable card.
 *
 * @param month Stored month, `1`-`12`, as a string (`'3'` and `'03'` both work).
 * @param year Stored year, two or four digits.
 * @param now The instant to compare against. Injected rather than read from the
 *   clock, so the boundaries can be tested.
 * @returns `'unknown'` if either part is missing or unparseable.
 */
export function expiryStatus(month: string, year: string, now: Date): ExpiryStatus {
  const monthValue = Number(month.trim());
  const yearValue = fullYear(year);
  if (yearValue === null || !Number.isInteger(monthValue) || monthValue < 1 || monthValue > 12) {
    return 'unknown';
  }
  // The first instant of the following month: the card dies as it strikes.
  const expiresAt = Date.UTC(yearValue, monthValue, 1);
  const current = now.getTime();
  if (current >= expiresAt) {
    return 'expired';
  }
  return expiresAt - current <= SOON_DAYS * 86_400_000 ? 'soon' : 'valid';
}

/** The expiry date as printed on the card, or an empty string. */
export function formatExpiry(month: string, year: string): string {
  const monthValue = Number(month.trim());
  const yearValue = fullYear(year);
  if (yearValue === null || !Number.isInteger(monthValue) || monthValue < 1 || monthValue > 12) {
    return '';
  }
  return `${String(monthValue).padStart(2, '0')}/${String(yearValue).slice(-2)}`;
}
