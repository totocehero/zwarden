// @vitest-environment jsdom

/**
 * @file What the injected fillers do to a page.
 *
 * jsdom lays nothing out, so every element reports no client rects and would
 * count as hidden; the tests give the prototype a rect and hide elements the
 * way pages do, by removing the rect again. What is checked is the rules: no
 * anchoring field, nothing written; fields found by their `autocomplete` token
 * before their name; the expiry in each of the shapes forms give it.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { fillCredentials, fillPaymentCard, probePaymentForm } from '../src/popup/pageFillers.js';

const RECT = [{ width: 10, height: 10 }] as unknown as DOMRectList;

beforeEach(() => {
  HTMLElement.prototype.getClientRects = function (this: HTMLElement) {
    return this.hasAttribute('data-hidden') ? ([] as unknown as DOMRectList) : RECT;
  };
});

afterEach(() => {
  document.body.innerHTML = '';
});

function page(html: string): void {
  document.body.innerHTML = html;
}

function value(selector: string): string {
  return document.querySelector<HTMLInputElement | HTMLSelectElement>(selector)!.value;
}

const CARD = { number: '4242 4242 4242 4242', name: 'Ada Lovelace', month: '7', year: '2027', code: '123' };

describe('probePaymentForm', () => {
  it('sees a card-number field by its token or by its name', () => {
    page('<form><input autocomplete="cc-number"></form>');
    expect(probePaymentForm()).toBe(true);
    page('<form><input type="tel" name="numero_carte"></form>');
    expect(probePaymentForm()).toBe(true);
    page('<form><input type="text" id="creditCardNumber"></form>');
    expect(probePaymentForm()).toBe(true);
  });

  it('is not fooled by a hidden field or an unrelated form', () => {
    page('<form><input autocomplete="cc-number" data-hidden></form>');
    expect(probePaymentForm()).toBe(false);
    page('<form><input type="text" name="q"><input type="password" name="p"></form>');
    expect(probePaymentForm()).toBe(false);
  });
});

describe('fillPaymentCard', () => {
  it('writes nothing at all without a card-number field', () => {
    page('<form><input name="cvv"><input name="cardholder"></form>');
    expect(fillPaymentCard(CARD)).toBe(false);
    expect(value('[name=cvv]')).toBe('');
    expect(value('[name=cardholder]')).toBe('');
  });

  it('fills a form that announces its fields', () => {
    page(`<form>
      <input autocomplete="cc-number"><input autocomplete="cc-name">
      <input autocomplete="cc-exp-month"><input autocomplete="cc-exp-year" maxlength="2">
      <input autocomplete="cc-csc">
    </form>`);
    expect(fillPaymentCard(CARD)).toBe(true);
    expect(value('[autocomplete=cc-number]')).toBe('4242424242424242');
    expect(value('[autocomplete=cc-name]')).toBe('Ada Lovelace');
    expect(value('[autocomplete=cc-exp-month]')).toBe('07');
    expect(value('[autocomplete=cc-exp-year]')).toBe('27');
    expect(value('[autocomplete=cc-csc]')).toBe('123');
  });

  it('fills a form that only names its fields, in French too', () => {
    page(`<form>
      <input type="tel" name="numero_carte"><input name="titulaire">
      <input name="mois"><input name="annee"><input name="cryptogramme" type="password">
    </form>`);
    expect(fillPaymentCard(CARD)).toBe(true);
    expect(value('[name=numero_carte]')).toBe('4242424242424242');
    expect(value('[name=titulaire]')).toBe('Ada Lovelace');
    expect(value('[name=mois]')).toBe('07');
    expect(value('[name=annee]')).toBe('2027');
    expect(value('[name=cryptogramme]')).toBe('123');
  });

  it('picks the matching option of a month or year select, however it is spelt', () => {
    page(`<form>
      <input autocomplete="cc-number">
      <select name="expMonth"><option value=""></option><option value="6">June</option><option value="7">July</option></select>
      <select name="expYear"><option value="26">2026</option><option value="27">2027</option></select>
    </form>`);
    expect(fillPaymentCard(CARD)).toBe(true);
    expect(value('[name=expMonth]')).toBe('7');
    expect(value('[name=expYear]')).toBe('27');

    page(`<form>
      <input autocomplete="cc-number">
      <select name="month"><option value="07">07</option><option value="08">08</option></select>
      <select name="year"><option value="2027">27</option></select>
    </form>`);
    expect(fillPaymentCard(CARD)).toBe(true);
    expect(value('[name=month]')).toBe('07');
    expect(value('[name=year]')).toBe('2027');
  });

  it('writes MM/YY into a single expiry field, MM/YYYY when it has room', () => {
    page('<form><input autocomplete="cc-number"><input autocomplete="cc-exp" maxlength="5"></form>');
    expect(fillPaymentCard(CARD)).toBe(true);
    expect(value('[autocomplete=cc-exp]')).toBe('07/27');

    page('<form><input name="cardnumber"><input name="expiry" placeholder="MM/YYYY"></form>');
    expect(fillPaymentCard(CARD)).toBe(true);
    expect(value('[name=expiry]')).toBe('07/2027');
  });

  it('stays inside the number’s form and skips hidden fields', () => {
    page(`<form id="pay"><input autocomplete="cc-number"><input name="cvv" data-hidden><input name="cvc"></form>
      <form id="other"><input name="cardholder"></form>`);
    expect(fillPaymentCard(CARD)).toBe(true);
    expect(value('#pay [name=cvv]')).toBe('');
    expect(value('#pay [name=cvc]')).toBe('123');
    expect(value('#other [name=cardholder]')).toBe('');
  });

  it('accepts a month the vault spelt with a zero and a two-digit year', () => {
    page('<form><input autocomplete="cc-number"><input autocomplete="cc-exp"></form>');
    expect(fillPaymentCard({ ...CARD, month: '07', year: '27' })).toBe(true);
    expect(value('[autocomplete=cc-exp]')).toBe('07/27');
  });
});

describe('fillCredentials', () => {
  it('still fills a login form as before, and nothing without a password field', () => {
    page('<form><input autocomplete="username"><input type="password"></form>');
    fillCredentials('ada', 's3cret');
    expect(value('[autocomplete=username]')).toBe('ada');
    expect(value('[type=password]')).toBe('s3cret');

    page('<form><input type="text" name="q"></form>');
    fillCredentials('ada', 's3cret');
    expect(value('[name=q]')).toBe('');
  });
});
