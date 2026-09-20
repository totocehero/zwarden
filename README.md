# Zwarden

*[Français](README.fr.md)*

An open-source browser password manager, compatible with
[Vaultwarden](https://github.com/dani-garcia/vaultwarden) and the Bitwarden API.

The goal: the same compatibility, an order of magnitude less weight.

## Where this code comes from

**This repository contains no line written by a human.** Code, tests and
documentation were produced entirely by a language model (Claude), under human
direction: scope, trade-offs and validation. The commits' `Co-Authored-By`
trailers keep the record.

What that implies, said plainly: the cryptographic choices are verified against
official vectors (RFC 4231 / 5869 / 6238 / 7914) and an interoperability round
trip against a real Vaultwarden, but **no independent human security audit has
been conducted**. For a password manager, that is a fact you are entitled to
before trusting it with a vault.

## Why

The official Bitwarden extension (2026.7.0), measured on disk — **46.4 MB**
uncompressed, excluding source maps:

| Item | Size | Consequence |
|---|---|---|
| `background.js` | 3.3 MB | an MV3 service worker killed after 30 s idle → 3.3 MB reparsed on every wake-up |
| WASM module (Rust SDK) | 7.4 MB **× 2** | loaded at start-up — and the package holds two **byte-for-byte identical** copies |
| autofill bundles (`bootstrap-autofill-overlay*.js` × 3) | 4.9 MB | candidates for injection into visited pages; the "detector" at `document_start` is in fact a 164-byte unconditional trigger, with no form detection |
| Angular popup (JS + CSS) | 6.7 MB | several hundred ms before the first render |
| translations (63 locales) | 15 MB | shipped in full, whatever the language |

Zwarden aims for **under 300 KB** in total.

The levers, in order of impact:

1. **Native WebCrypto** rather than a Rust SDK compiled to WASM. AES-256-CBC,
   HMAC-SHA256, PBKDF2-SHA256 and SHA-2 are already in the browser: native,
   constant-time, audited, and 0 bytes of bundle. Argon2id alone needs WASM
   (~45 KB), loaded through a dynamic import and only when unlocking an account
   configured that way.
2. **Two-stage autofill**: a light form detector at `document_start`, the
   autofill engine injected only once a relevant field is detected.
3. **Preact** (~10 KB of runtime) instead of Angular.
4. **A thin service worker**: heavy logic in dynamic modules, volatile state in
   `chrome.storage.session`.

## Status

The cryptographic core is implemented and tested. The rest is in progress.

- [x] Encoding (base64, UTF-8, constant-time comparison)
- [x] `EncString` — parsing and serialising Bitwarden's 7 types
- [x] `SymmetricCryptoKey` — 32/64-byte keys
- [x] AES-256-CBC + HMAC-SHA256, encrypt-then-MAC
- [x] Key derivation: PBKDF2-SHA256 and Argon2id
- [x] 689 tests, including the RFC 4231 / 5869 / 6238 / 7914 vectors
- [x] **Interoperability validated against Vaultwarden 2026.6.0** —
      authentication, vault key decryption, and a complete write/read round trip
- [x] API client: prelogin, authentication, session refresh, sync, item creation
      and deletion — without ever seeing a key or a password
- [x] Vault layer: the unlock orchestrator (`unlock()`, memory hygiene included)
      and item decryption (per-item key, partial views, case tolerance)
- [x] Service worker and the locking life cycle — inactivity, system session
      lock, browser close
- [x] Popup: unlock, list, search, copy
- [ ] Two switchable popup views: "Bitwarden-like" (the classic layout, nothing
      to relearn for people migrating) and "Zwarden" (filtered on the active
      tab, keyboard-driven). One view today, the second still to come
- [x] Organisation vaults: RSA private key and organisation keys unwrapped,
      shared items readable
- [x] Tags: folders and collections decrypted, filtering chips (phase 1 of 3 —
      assignment then sharing by tag to come)
- [x] Filling from the popup — an explicit gesture, strict origin matching
- [x] Editing items from the popup — fields preserved, item key and organisation
      keys respected, password history
- [x] Recently used items at the top of the list
- [x] Offering to save a credential entered on an unknown site — a badge on the
      icon, the decision in the popup, nothing injected into the page
- [x] TOTP codes on the vault's rows — RFC 6238 vectors replayed
      (SHA-1/256/512), `otpauth://` parsed, countdown and copy
- [x] Password generator — unbiased draw, guaranteed composition
- [x] Per-item guard (`reprompt`) — an item marked "ask for the master password
      again" hands over no secret without a fresh entry, verified offline
- [x] Keyboard shortcuts — open, generate and copy, lock
- [x] Clipboard overwrite that survives the popup closing (offscreen document +
      alarm)
- [x] Creating items from the popup — login, card, identity or secure note
- [x] Cards and identities, taken further than Bitwarden's: the network read off
      the number rather than picked from a list, the check digit verified as it
      is typed, the expiry compared to today, the number copied as bare digits,
      the full name and the postal address composed and copied in one gesture,
      the papers masked, and the list showing `Visa •••• 4242` without ever
      holding a chargeable number
- [x] The browser's language and theme followed — `chrome.i18n` and a toolbar
      icon that inverts against a light background
- [x] A language the user can choose, against the grain of an API that offers
      no way to: `chrome.i18n` reads the browser's language and nothing can
      change it, so the chosen catalogue is loaded by hand. Adding a language is
      one folder (`node scripts/new-locale.mjs <code>`), checked automatically
      by the test suite, and loaded only for the users who read it — which is
      the whole argument against shipping 63 translations to everyone
- [x] Filtering the list by item type, several types at once
- [x] Optional breach checking against Have I Been Pwned, **off by default**
      and the only thing here that talks to anyone but your own server. The
      password never leaves and neither does its full hash: five hex characters
      of its SHA-1 go out, some eight hundred suffixes come back, and the
      comparison happens locally. What it does leak is written out in the
      settings rather than summarised into reassurance
- [x] An encrypted export — Argon2id then AES-256-GCM, with the parameters
      authenticated alongside the ciphertext so lowering them makes the file
      refuse to open rather than open weaker. **There is no cleartext export**:
      such a file ends up in a downloads folder, in every backup, and on the
      drive when it is resold. Inside is Bitwarden's own import shape, because
      a vault one cannot take elsewhere is one to be locked into
- [x] A health report, computed entirely on the machine — reused passwords,
      weak ones, ones that merely repeat the site or the account, ones
      unchanged for a year, cards at their expiry date. No dictionary, no
      network, no third party. Items guarded by `reprompt` are **not examined**
      and the report says how many, since an aggregate about a password tells
      as much as a copy of it
- [x] Editing offline: a write the server never received is held — already
      encrypted, never the cleartext edit — and sent when it can be reached. A
      held write is **never replayed over an item that changed since**: the
      user is told rather than having a rotated password silently put back
- [x] The first screenful decrypted first — the ordering is computed from the
      identifiers, which are not encrypted, so the twenty rows the popup shows
      are the twenty decrypted before it draws. A vault of 500 items with a key
      of its own per item costs ~650 ms to decrypt whole; the list no longer
      waits for it
- [x] Passkeys: **creating and using** them from the vault. The relying party a page
      may claim is enforced here, because intercepting
      `navigator.credentials.get()` takes that enforcement away from the
      browser. Off by default — it is the one feature that puts code in every
      page, and even then only a replacement for one function: nothing is
      drawn, and the confirmation happens in the popup. When Zwarden has
      nothing to offer, the browser takes over and a hardware key still works
- [ ] Key derivation in the service worker (a popup with no key) — and, with it,
      the autofill shortcut
- [ ] Automatic autofill (form detection, in-page suggestion)

## Security model

The server is treated as **untrusted**. It never sees the master password, the
master key, or any cleartext content.

Notable decisions, some of them stricter than Bitwarden's:

- **The MAC is verified before any decryption.** A ciphertext never touches AES
  if the HMAC does not match — that is what closes padding oracles on CBC. The
  comparison is constant-time.
- **Downgrades are refused.** Type 2 (authenticated) data presented as type 0
  (unauthenticated) is rejected. Without that, a hostile server can strip the
  MAC and recover a padding oracle.
- **Writes are always authenticated.** Encrypting with a key that has no
  `macKey` raises an error. Type 0 stays readable, to migrate old vaults.
- **KDF parameters validated, in both directions.** `iterations` and `memory`
  come from the server *before* authentication: a compromised server can
  announce 1 iteration to make the master key trivial to crack offline — or
  absurd values (2³¹ iterations, Argon2 memory in gibibytes) to freeze the
  client at unlock. Zwarden rejects configurations below the OWASP floor, above
  the official client's maxima, and non-integer values. Bitwarden performs
  neither check.
- **AES-128 (type 1) refused** for decryption: re-encryption required.

## Compatibility

The encryption format is identical to Bitwarden's, so vaults are interoperable
in both directions:

```
2.<iv b64>|<ciphertext b64>|<mac b64>
```

- master key: `PBKDF2-SHA256(pw, normalised email, n)` or `Argon2id(pw, SHA-256(email))`
- stretched key: `HKDF-Expand(master key, "enc"|"mac")` — Expand alone, no Extract
- server hash: `PBKDF2-SHA256(master key, pw, 1 iteration)`

## Development

```bash
npm install
npm test          # 689 tests
npm run typecheck # strict TypeScript
npm run lint      # ESLint: lost promises, loose comparisons
npm run build
npm run size      # size budget for dist/
```

## Documentation

- [`docs/CRYPTO.md`](docs/CRYPTO.md) — threat model, key hierarchy, encryption
  scheme, hardening measures and the reasoning behind them.
- [`docs/EXTENSION.md`](docs/EXTENSION.md) — the extension's usability and
  security decisions: unlocking, the locking cycle, the two popup views, the
  autofill rules.
- [`docs/STORAGE.md`](docs/STORAGE.md) — what is stored where, and what an
  attacker reaching each store actually gets. Written backwards, from the
  attacker's capabilities rather than from the feature list.

## Licence

AGPL-3.0-only — see [`LICENSE`](LICENSE).
