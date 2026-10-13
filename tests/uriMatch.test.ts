/**
 * @file The rule each URI carries, and what it lets a page receive.
 *
 * The default is strict origin and stays so. What these tests guard is the
 * other five rules: that each does what its owner asked and no more, that the
 * two unsafe ones (regular expression, never) give nothing, and that the
 * base-domain approximation refuses the shapes it was written to refuse —
 * `co.uk`, IP addresses, a look-alike host.
 */

import { describe, expect, it } from 'vitest';

import {
  type LoginUri,
  UriMatchType,
  matchesPage,
  sameBaseDomain,
  splitForPage,
} from '../src/core/vault/uriMatch.js';

function saved(uri: string, match: number | null = null): LoginUri {
  return { uri, match };
}

const page = (href: string): URL => new URL(href);

describe('matchesPage with no rule', () => {
  it('is strict origin, as before', () => {
    expect(matchesPage([saved('https://app.example.org')], page('https://app.example.org/x'))).toBe(
      true,
    );
    expect(matchesPage([saved('https://app.example.org')], page('https://sso.example.org/'))).toBe(
      false,
    );
    expect(matchesPage([saved('https://app.example.org')], page('https://app.example.org:8443/'))).toBe(
      false,
    );
  });
});

describe('matchesPage with the Domain rule', () => {
  it('offers an app item on its single-sign-on host', () => {
    const uris = [saved('https://app.example.org', UriMatchType.Domain)];
    expect(matchesPage(uris, page('https://sso.example.org/realms/x/protocol/openid-connect/auth'))).toBe(true);
    expect(matchesPage(uris, page('https://example.org/'))).toBe(true);
    expect(matchesPage(uris, page('https://sso.example.org:8443/'))).toBe(true);
  });

  it('does not reach a look-alike or a neighbour', () => {
    const uris = [saved('https://bank.example', UriMatchType.Domain)];
    expect(matchesPage(uris, page('https://bank.example.attacker.com/'))).toBe(false);
    expect(matchesPage(uris, page('https://bank-example.com/'))).toBe(false);
  });

  it('never fills a cleartext page from an HTTPS entry', () => {
    const uris = [saved('https://app.example.org', UriMatchType.Domain)];
    expect(matchesPage(uris, page('http://sso.example.org/'))).toBe(false);
    expect(matchesPage([saved('http://intranet.example.org', UriMatchType.Domain)], page('http://sso.example.org/'))).toBe(true);
  });
});

describe('sameBaseDomain', () => {
  it('relates hosts under one registrable domain', () => {
    expect(sameBaseDomain('app.example.org', 'sso.example.org')).toBe(true);
    expect(sameBaseDomain('example.org', 'sso.example.org')).toBe(true);
    expect(sameBaseDomain('A.Example.ORG', 'example.org')).toBe(true);
  });

  it('knows that co.uk and its kind are registries, not domains', () => {
    expect(sameBaseDomain('bank.co.uk', 'shop.co.uk')).toBe(false);
    expect(sameBaseDomain('impots.gouv.fr', 'ants.gouv.fr')).toBe(false);
    expect(sameBaseDomain('login.bank.co.uk', 'www.bank.co.uk')).toBe(true);
    expect(sameBaseDomain('bank.co.uk', 'co.uk')).toBe(false);
  });

  it('relates no IP address to anything but itself', () => {
    expect(sameBaseDomain('10.0.0.1', '10.0.0.2')).toBe(false);
    expect(sameBaseDomain('10.0.0.1', '10.0.0.1')).toBe(true);
    expect(sameBaseDomain('[::1]', '[::2]')).toBe(false);
  });

  it('needs two labels to call anything a domain', () => {
    expect(sameBaseDomain('localhost', 'localhost')).toBe(true);
    expect(sameBaseDomain('localhost', 'intranet')).toBe(false);
    expect(sameBaseDomain('a.org', 'org')).toBe(false);
  });
});

describe('matchesPage with the Host rule', () => {
  it('compares host and port, ignores the path', () => {
    const uris = [saved('https://sso.example.org:8443/realms/x', UriMatchType.Host)];
    expect(matchesPage(uris, page('https://sso.example.org:8443/other'))).toBe(true);
    expect(matchesPage(uris, page('https://sso.example.org/other'))).toBe(false);
    expect(matchesPage(uris, page('https://app.example.org:8443/'))).toBe(false);
  });
});

describe('matchesPage with StartsWith and Exact', () => {
  it('starts-with compares the whole URL prefix, case-insensitively', () => {
    const uris = [saved('https://sso.example.org/realms/Tenant', UriMatchType.StartsWith)];
    expect(matchesPage(uris, page('https://sso.example.org/realms/tenant/protocol/x'))).toBe(true);
    expect(matchesPage(uris, page('https://sso.example.org/realms/other'))).toBe(false);
  });

  it('exact compares the whole URL', () => {
    const uris = [saved('https://sso.example.org/login', UriMatchType.Exact)];
    expect(matchesPage(uris, page('https://sso.example.org/login'))).toBe(true);
    expect(matchesPage(uris, page('https://sso.example.org/login?next=1'))).toBe(false);
  });
});

describe('matchesPage with the rules it will not run', () => {
  it('evaluates no regular expression and honours never', () => {
    expect(
      matchesPage([saved('^https://sso\\.example\\.org/.*', UriMatchType.RegularExpression)], page('https://sso.example.org/')),
    ).toBe(false);
    expect(matchesPage([saved('https://sso.example.org', UriMatchType.Never)], page('https://sso.example.org/'))).toBe(false);
  });

  it('reads an unknown rule as the default', () => {
    expect(matchesPage([saved('https://sso.example.org', 42)], page('https://sso.example.org/'))).toBe(true);
    expect(matchesPage([saved('https://app.example.org', 42)], page('https://sso.example.org/'))).toBe(false);
  });

  it('is unmoved by a URI that is not one', () => {
    expect(matchesPage([saved('not a url', UriMatchType.Domain)], page('https://sso.example.org/'))).toBe(false);
    expect(matchesPage([saved('', UriMatchType.Host)], page('https://sso.example.org/'))).toBe(false);
  });
});

describe('splitForPage', () => {
  const app = { id: 'app', uris: [saved('https://app.example.org', UriMatchType.Domain)] };
  const bank = { id: 'bank', uris: [saved('https://bank.example')] };
  const note = { id: 'note', uris: [] };

  it('puts the page’s items first and keeps every order', () => {
    const { forPage, others } = splitForPage([bank, app, note], page('https://sso.example.org/'));
    expect(forPage.map((i) => i.id)).toEqual(['app']);
    expect(others.map((i) => i.id)).toEqual(['bank', 'note']);
  });

  it('splits nothing without a page', () => {
    const { forPage, others } = splitForPage([bank, app], null);
    expect(forPage).toEqual([]);
    expect(others.map((i) => i.id)).toEqual(['bank', 'app']);
  });
});
