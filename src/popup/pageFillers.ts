/**
 * @file The functions injected into a page to fill it, and to ask what it has.
 *
 * Every function here is handed to `chrome.scripting.executeScript` as `func`,
 * which **serialises it to text** and runs it in the page. That is why each
 * one is self-contained: no import, no module constant, no helper shared
 * between two of them — a closure over anything outside the function body
 * would be `undefined` on the other side. The duplication of the small
 * visibility test and the field patterns is the price of that, and it is paid
 * knowingly.
 *
 * The rules they honour are in `docs/EXTENSION.md` §4: a user gesture first,
 * only visible fields, and a form that actually is what it is being filled as
 * — a password field for a login, a card-number field for a card. Without the
 * anchoring field nothing is written, because a username alone lands in a
 * search box and a card number alone lands wherever a hostile page put a
 * text field.
 */

/** Fills the page's login form: the password field first, the username beside it. */
export function fillCredentials(username: string, password: string): void {
  // Visible means painted and not made transparent: `getClientRects()` alone
  // let through `opacity: 0` and `visibility: hidden`, the two ways a field is
  // hidden without leaving the layout. `checkVisibility` is Chrome 105+, and
  // the manifest asks for 120.
  const visible = (el: HTMLElement): boolean =>
    el.getClientRects().length > 0 &&
    (typeof el.checkVisibility !== 'function' ||
      el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true }));
  const setValue = (input: HTMLInputElement, value: string): void => {
    // Go through the prototype's native setter, so that frameworks intercepting
    // `value` (React and friends) actually see the change.
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
    setter?.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
  };

  const passwordInput = Array.from(
    document.querySelectorAll<HTMLInputElement>('input[type="password"]'),
  ).find(visible);
  if (passwordInput === undefined) {
    // No password field, no fill. A username alone would land in whatever
    // text field comes first — a search box, as often as not — and a search
    // box posts what it is given.
    return;
  }
  if (password !== '') {
    setValue(passwordInput, password);
  }
  if (username === '') {
    return;
  }

  // The field the page announces first; the generic text field only as a
  // fallback, and only within the same form.
  const scope = passwordInput.form ?? document;
  const announced = scope.querySelectorAll<HTMLInputElement>(
    'input[autocomplete="username"], input[autocomplete="email"], input[type="email"]',
  );
  const generic = scope.querySelectorAll<HTMLInputElement>(
    'input[type="text"], input:not([type])',
  );
  const usernameInput =
    Array.from(announced).find(visible) ??
    Array.from(generic).find((el) => visible(el) && el !== passwordInput);
  if (usernameInput !== undefined) {
    setValue(usernameInput, username);
  }
}

/**
 * Whether the page shows a card-number field.
 *
 * Asked when the popup opens on a vault that holds cards, so that cards can be
 * offered under "For this page" the way logins are offered by origin — a card
 * has no URI, and a payment form is the only thing that says a card belongs
 * here. The `autocomplete` token is the page's own word; the name patterns are
 * for the many pages that never set it.
 */
export function probePaymentForm(): boolean {
  const visible = (el: HTMLElement): boolean =>
    el.getClientRects().length > 0 &&
    (typeof el.checkVisibility !== 'function' ||
      el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true }));
  const NUMBER = /card.?n(um|o)|cardnumber|cc.?num|ccnumber|\bpan\b|num.{0,8}carte|credit.?card/i;
  const describe = (el: HTMLInputElement): string =>
    `${el.name} ${el.id} ${el.placeholder} ${el.getAttribute('aria-label') ?? ''} ${el.autocomplete}`;
  return Array.from(
    document.querySelectorAll<HTMLInputElement>(
      'input[autocomplete="cc-number"], input[type="text"], input[type="tel"], input:not([type])',
    ),
  ).some((el) => visible(el) && (el.autocomplete === 'cc-number' || NUMBER.test(describe(el))));
}

/** A card, in the clear, on its way into a payment form. */
export interface CardToFill {
  readonly number: string;
  readonly name: string;
  /** `1`–`12`, as the vault spells it. */
  readonly month: string;
  /** Two or four digits. */
  readonly year: string;
  readonly code: string;
}

/**
 * Fills the page's payment form. `false` if no card-number field was found,
 * in which case nothing at all was written.
 *
 * Fields are found by their `autocomplete` token first, then by what they call
 * themselves. The expiry is the awkward one: one field (`MM/YY`), or two, each
 * of which may be a text input or a `<select>` whose options spell the month
 * as `7`, `07` or `July` and the year as `27` or `2027`. Each shape is handled
 * by matching what the page offers rather than by guessing a format.
 */
export function fillPaymentCard(card: CardToFill): boolean {
  const visible = (el: HTMLElement): boolean =>
    el.getClientRects().length > 0 &&
    (typeof el.checkVisibility !== 'function' ||
      el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true }));
  const setValue = (input: HTMLInputElement, value: string): void => {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
    setter?.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
  };
  const setSelect = (select: HTMLSelectElement, candidates: readonly string[]): boolean => {
    const options = Array.from(select.options);
    const wanted = candidates.map((c) => c.toLowerCase());
    const option =
      options.find((o) => wanted.includes(o.value.trim().toLowerCase())) ??
      options.find((o) => wanted.includes(o.text.trim().toLowerCase())) ??
      options.find((o) => wanted.some((w) => w.length > 2 && o.text.trim().toLowerCase().startsWith(w)));
    if (option === undefined) {
      return false;
    }
    const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value')?.set;
    setter?.call(select, option.value);
    select.dispatchEvent(new Event('input', { bubbles: true }));
    select.dispatchEvent(new Event('change', { bubbles: true }));
    return true;
  };

  type Field = HTMLInputElement | HTMLSelectElement;
  const describe = (el: Field): string =>
    `${el.name} ${el.id} ${el.getAttribute('placeholder') ?? ''} ${el.getAttribute('aria-label') ?? ''} ${el.autocomplete}`;
  const NUMBER = /card.?n(um|o)|cardnumber|cc.?num|ccnumber|\bpan\b|num.{0,8}carte|credit.?card/i;
  const NAME = /card.?holder|cc.?name|name.?on.?card|titulaire|nom.{0,8}carte|holder.?name/i;
  const MONTH = /month|mois|cc.?exp.?mm|exp.?mm|\bmm\b/i;
  const YEAR = /year|ann[ée]e|cc.?exp.?yy|exp.?yy|\byy(yy)?\b/i;
  const EXPIRY = /exp|valid|mm.{0,3}[/-].{0,3}yy|échéance|echeance/i;
  // `MM/YY` in a name or a placeholder is one field for both, never a month.
  const COMBINED = /mm.{0,3}[/.-].{0,3}yy/i;
  const CODE = /cvv|cvc|csc|cvn|\bcid\b|security.?code|cryptogram|verification.?(code|value)/i;

  const inputs = Array.from(
    document.querySelectorAll<HTMLInputElement>(
      'input[type="text"], input[type="tel"], input[type="number"], input[type="password"], input:not([type])',
    ),
  ).filter(visible);
  const numberInput =
    inputs.find((el) => el.autocomplete === 'cc-number') ??
    inputs.find((el) => NUMBER.test(describe(el)));
  if (numberInput === undefined) {
    return false;
  }

  // The same form as the number, or the whole page when the number is loose.
  const scope: ParentNode = numberInput.form ?? document;
  const fields = Array.from(scope.querySelectorAll<Field>('input, select')).filter(
    (el) => el !== numberInput && visible(el) && !(el instanceof HTMLInputElement && el.type === 'hidden'),
  );
  const byToken = (token: string): Field | undefined =>
    fields.find((el) => el.autocomplete === token);
  const byPattern = (
    pattern: RegExp,
    taken: readonly (Field | undefined)[],
    unless: RegExp | null = null,
  ): Field | undefined =>
    fields.find(
      (el) =>
        !taken.includes(el) &&
        pattern.test(describe(el)) &&
        (unless === null || !unless.test(describe(el))),
    );

  const digits = card.number.replace(/\D/g, '');
  setValue(numberInput, digits === '' ? card.number : digits);

  const nameField = byToken('cc-name') ?? byPattern(NAME, []);
  if (nameField instanceof HTMLInputElement && card.name !== '') {
    setValue(nameField, card.name);
  }

  const codeField = byToken('cc-csc') ?? byPattern(CODE, [nameField]);
  if (codeField instanceof HTMLInputElement && card.code !== '') {
    setValue(codeField, card.code);
  }

  const month = card.month.trim().replace(/^0+(?=\d)/, '');
  const yearDigits = card.year.trim().replace(/\D/g, '');
  const fullYear = yearDigits.length === 2 ? `20${yearDigits}` : yearDigits;
  const shortYear = fullYear.slice(-2);
  if (month === '' && fullYear === '') {
    return true;
  }
  const monthPadded = month.padStart(2, '0');
  const taken = [nameField, codeField];

  const monthField = byToken('cc-exp-month') ?? byPattern(MONTH, taken, COMBINED);
  const yearField = byToken('cc-exp-year') ?? byPattern(YEAR, [...taken, monthField], COMBINED);
  if (monthField !== undefined || yearField !== undefined) {
    if (monthField instanceof HTMLSelectElement) {
      setSelect(monthField, [month, monthPadded]);
    } else if (monthField !== undefined && month !== '') {
      setValue(monthField, monthPadded);
    }
    if (yearField instanceof HTMLSelectElement) {
      setSelect(yearField, [fullYear, shortYear]);
    } else if (yearField !== undefined && fullYear !== '') {
      // Two digits when the field says it takes two, four otherwise.
      setValue(yearField, yearField.maxLength === 2 ? shortYear : fullYear);
    }
    return true;
  }

  // One field for both: `MM/YY`, or `MM/YYYY` when it leaves room for it.
  const expiryField = byToken('cc-exp') ?? byPattern(EXPIRY, taken);
  if (expiryField instanceof HTMLInputElement && month !== '' && fullYear !== '') {
    const longForm =
      expiryField.maxLength >= 7 || /yyyy/i.test(expiryField.getAttribute('placeholder') ?? '');
    setValue(expiryField, `${monthPadded}/${longForm ? fullYear : shortYear}`);
  }
  return true;
}
