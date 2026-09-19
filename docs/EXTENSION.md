# The extension's usability and security decisions

This document fixes the extension's design decisions **before** the interface
code exists, with the same seriousness that `CRYPTO.md` fixes the cryptographic
scheme. Each section states a rule and its reason; departing from one will take
an argument, not an oversight.

---

## 1. Unlocking

**Target: derivation runs in the service worker, never in the popup.**
⏳ *Not implemented yet — today `unlock()` runs in the popup, which therefore
holds the key.* Closing the popup must not cancel an unlock in progress, and key
material has no business in a UI context. The popup will send the password to
the worker, display progress, and receive a success signal — not a key.

This move is not a setting but a redesign: "a popup with no key" implies that
**every** decryption becomes a round trip to the worker, hence a message layer
across the whole data path. That is why it waits on a test suite for the
interface rather than being attempted blind — and it is also what blocks the
autofill shortcut (§4 ter).

**There is one unlock path: `core/vault/unlock()`.** The sequence prelogin →
derivation → hashes → login → stretching → unwrapping, with the intermediate
keys erased, is written and audited once. No other code recomposes that
choreography.

**Offline unlocking.** The first successful unlock keeps locally: the
`LocalAuthorization` hash, the wrapped vault key and the validated KDF
parameters. Server unreachable ⇒ validation through `verifyLocalPasswordHash`
(a constant-time comparison on the bytes, never `===` on the base64) then the
vault opens on the last synced state. A password manager that is inaccessible
during a server outage is a non-starter.

**Distinct errors on screen.** Wrong password, rate limiting (with the delay),
second factor required, captcha required, server unreachable, KDF refused: each
case has its own message. Routing is on the errors' `code` field, never on the
messages (which are for logs).

## 2. The locking cycle

- The unlocked state lives in `chrome.storage.session` (memory only): closing
  the browser ⇒ locking, for free. **That is the default** —
  `autoLockMinutes = 0` — and it is the behaviour anyone coming from the
  official extension expects.
- An optional inactivity delay layers on top of that guarantee. "Inactivity"
  means the *browser* is inactive, not that the *popup* is closed: a user
  switching tabs and browsing is active. Counting time since the popup was last
  opened asked for the password mid-work — the recurring complaint about the
  previous version.
- The service worker is its sole owner (`background/main.ts`): it listens to
  `tabs.onActivated`, `windows.onFocusChanged` and `tabs.onUpdated` (on the
  foreground tab only, so a background page refreshing itself does not hold the
  vault open), and records a timestamp in `chrome.storage.session`. An open
  popup adds its own heartbeat.
- The `chrome.alarms` alarm — the only timer that survives the death of an MV3
  service worker — is a **one-minute heartbeat**, not a deadline: recreating it
  on every activity event would run into the rate limit. Acknowledged
  trade-off: locking can be up to a minute late. The decision rule is
  `shouldAutoLock()`, pure and tested.
- Locking the system session (`chrome.idle`, state `locked`: lock screen,
  sleep) locks immediately, whatever the delay — it is that net which makes the
  "browser close" default tenable, since one walks away from a machine far more
  often than one closes the browser. Setting `lockOnSystemLock`, on by default.
  The `idle` state (no input for a few minutes) does **not** lock: it says
  nothing about the user's presence, who may well be reading their screen.
- To lock = `userKey.destroy()` **and** purging `chrome.storage.session` **and**
  purging the popup's state. All three, systematically, in a single gesture:
  `lockVault()` carries the storage list, `resetVaultState()` the memory one.
  The second is not cosmetic — a displayed one-time code holds the decrypted
  TOTP secret *and* a timer recomputing it every second, the generator holds its
  output, and the edit form the open item's password. None of that is visible
  after locking: which is precisely what makes it easy to forget.
- Limit of the "system session locked" net: it depends on `chrome.idle`
  reporting the `locked` state, which not every desktop environment emits
  (depending on the session manager under Linux in particular). Where the event
  does not come, the `autoLockMinutes = 0` default leaves the vault open for as
  long as the browser lives — an explicit inactivity delay is then the only
  recourse.
- The expiring access token (~1 h) is renewed through `refreshToken()` — never
  by asking for the password again. Renewed tokens are saved **before** the
  write they authorise: a server that rotates refresh tokens has already
  invalidated the old one, and saving nothing would make a network failure cost
  a full unlock.

## 3. The popup — two switchable views

| | "Bitwarden-like" view | "Zwarden" view |
|---|---|---|
| Audience | People migrating from the official extension | Daily keyboard use |
| On opening | The full list, classic tabs | Filtered on the active tab's domain |
| Navigation | Mouse first | Focused search, arrows + Enter |

The two views are two Preact renderings of the **same view model**
(`core/vault/cipherService`); the choice is a persisted preference. No vault
logic in the components.

Common rules:

- **Partial decryption**: at unlock, only names and URIs are decrypted
  (`CipherOverview`). Password, TOTP and notes are decrypted when the item is
  opened (`CipherDetails`). Minimal opening latency, fewer cleartext secrets at
  once.
- **The clipboard is overwritten after ~30 s** following a secret being copied,
  through **two** deliberately redundant mechanisms: a timer in the popup, which
  honours the exact delay while it lives, and a `chrome.alarms` alarm that
  survives its closing and triggers an offscreen document (`src/offscreen/`).
  The popup alone was not enough — its timer died with it, which is precisely
  when the wipe matters. Two caveats, said plainly: Chrome raises any alarm to
  thirty seconds minimum, so the "10 seconds" setting is honoured by the popup
  alone; and since `execCommand('copy')` ignores an empty selection, the
  clipboard is **overwritten with a space**, not emptied. The useful effect is
  the same, but "wiped" is not quite the word. Locking triggers the overwrite
  immediately.
- Passwords hidden by default; revealed on an explicit gesture.
- **Per-item guard (`reprompt`).** An item marked "ask for the master password
  again" on Bitwarden's side hands over nothing — copy, reveal, one-time code,
  fill, edit — without a fresh entry. Three design points:
  - the guard stands **before** `detailsOf`, hence before any decryption: a
    protected secret is not decrypted and then hidden, it is not decrypted;
  - `reprompt` is carried by `CipherOverview`, precisely so the guard is
    readable without decrypting anything;
  - verification is **offline**: the master key is re-derived from the entry and
    compared against the local hash kept at unlock (`verifyLocalPasswordHash`, a
    constant-time comparison). Having the server validate a `reprompt` would
    hand whoever controls the network the power to disarm it.

  Closing a code or hiding a password is not guarded: only a secret leaving the
  vault is.
- **The one-time code on the row.** Items carrying a TOTP secret show a clock
  button; one click decrypts the secret, displays the code with its countdown
  and copies it. The code is **recomputed** every second from the clock, never
  counted down: a JavaScript timer drifts, and the popup can be frozen —
  displaying a stale code would be worse than displaying none. `hasTotp` is
  inferred from the presence of the encrypted field, so the list knows where to
  put the button without decrypting a secret nobody asked for.
- **A password generator** (`core/generator`), opened from the header or from
  the edit form's password field — one panel, two entry points. A draw with no
  modulo bias (the incomplete slice is rejected), one character guaranteed per
  ticked class, then a shuffle. The options are persisted apart from the
  application settings: the popup and the options page do not write into the
  same object.
- **Recently used items float to the top.** Copying, revealing or filling
  records the use (`markUsed`); the order is applied at opening
  (`sortByLastUsed`), never while the popup is open — an item floating up under
  the cursor would make the next click land on the wrong row. Items never used
  keep the server's order. The log is capped at 100 entries and can be cleared
  from the settings.

## 4. Autofill — non-negotiable rules

The extension-side counterpart of "MAC before decryption". Two rules, both known
to have failed in other managers:

1. **Never fill without a user gesture.** Silent automatic filling is the classic
   vector for exfiltration through an invisible form: a compromised page places
   a hidden field, the manager fills it, the script exfiltrates it. Filling
   requires a click on the suggestion or a keyboard shortcut.
2. **URI matching by origin** (scheme + host + port), never by substring. Loose
   matching hands `bank.example`'s credentials to `bank.example.attacker.com`.
   Base-domain matching would require the Public Suffix List (unacceptable for
   the size budget); strict origin is safe without it.

A two-stage architecture (see the README): a light detector at
`document_start`, the engine injected only if a relevant field exists, and only
into `http(s)` pages.

**Status: v1 is in place.** The popup's "Fill" button injects on demand
(`chrome.scripting`, main frame only) a filler that honours both rules: an
explicit gesture required, the button visible only when the item's origin
matches the tab's (`uriMatch.ts`), and rechecked at click time. Still to come in
v2: the in-page detector, the inline suggestion, and iframes.

## 4 bis. Offering to save an entered credential

Three actors, with deliberately disjoint roles — it is the split that keeps the
promise, not anyone's good intentions:

| Actor | Sees | Decides |
|---|---|---|
| `content/detector.ts` | What the user types in the page | Nothing — it passes it on |
| Service worker | The setting, the vault's state, the exclusion list | Whether to *keep* the capture |
| Popup | The decrypted vault | Whether to *offer*, and what |

The detector has no key and does not know the vault; neither does the worker.
Only the popup can say "that password is already in there" — which is why it
settles, when it opens, between three outcomes: nothing to offer (same username,
same password on this origin — the ordinary sign-in, passed over in silence,
without which the badge would light up on every sign-in and mean nothing any
more), an update, or a creation.

- **One signal only: a badge on the icon.** Nothing is injected into the page —
  no bar, no CSS to isolate, no interface a hostile site could read, cover or
  imitate. Acknowledged trade-off: the popup must be opened to see the offer.
- **The detector is registered dynamically** (`chrome.scripting`), not declared
  in the manifest: with the setting unticked, there is no script in pages at all
  — not a script keeping quiet. The difference between a promise and a
  guarantee.
- **Nothing leaves without a click.** The capture waits; "Dismiss" throws it
  away, "Never for this site" adds the host to a local exclusion list.
- **Vault locked: the capture is refused**, not queued. Keeping a cleartext
  password in memory while everything else is purged would contradict §2.
- **Non-destructive updates.** Only the password changes; name, folder, notes,
  TOTP and custom fields are carried over, and the old password joins the
  history.
- **Matching by strict origin** (`findSaveCandidate`), never by domain: a loose
  match would not show a wrong row, it would overwrite a valid password from a
  neighbouring site.
- **The username is guessed, never guaranteed.** No site is obliged to announce
  it (`autocomplete="username"`). The fallback rule — the last text field filled
  before the password — gets contorted layouts wrong, and the user then corrects
  it in the popup. One wrong guess was unacceptable: taking the password itself.
  The two-field "show password" pattern (a `password` and a `text` mirror whose
  visibility the site toggles) placed a filled, visible text field just before
  the password field — the perfect candidate for the proximity rule. The item
  created then carried the password in the clear in its username field. A
  candidate whose value is exactly the password is now ruled out, as is a field
  the site announces as a password.

Known limits: main frame only, and sign-ins with neither a `<form>` nor an
identifiable button escape the detector. A missed credential is recovered by
hand; a credential captured in error costs only a "Dismiss".

## 4 ter. Keyboard shortcuts — parity with the official extension

The shortcuts follow the official extension's (read from its 2026.7.0 manifest).
Only those that **can succeed without the vault key** are declared, since the
service worker does not hold it: declaring a shortcut that does nothing would be
worse than not declaring it.

| Command | Shortcut | Status |
|---|---|---|
| Open the popup | `Ctrl+Shift+Y` (`Ctrl+Shift+U` on Linux) | ✅ `_execute_action` |
| Generate a password and copy it | `Ctrl+Shift+9` | ✅ generating needs no key |
| Lock the vault | no default, configurable | ✅ a purge, no key required |
| Autofill credentials | `Ctrl+Shift+L` | ⏳ needs the key in the worker (§1) |

## 4 quater. Manifest — notes taken from the official extension

- **CSP**: running WASM under MV3 requires
  `script-src 'self' 'wasm-unsafe-eval'`. The Argon2id module (hash-wasm) needs
  it — without that directive, Argon2id unlocking will fail in production while
  passing in Node tests.
- **Permissions**: the official one asks for 16 permissions including
  `webRequest`, `tabs`, `unlimitedStorage` and `http(s)://*/*`. Zwarden aims for
  the minimum: `storage`, `alarms`, `idle`, `offscreen`, `activeTab`,
  `scripting`, `clipboardWrite`, plus the hosts strictly needed for autofill —
  and the `optional_permissions` model for the rest. `idle` grants only the
  session's active / idle / locked transitions: it serves the lock-on-lock-screen
  behaviour and nothing else. Tracking browsing activity makes do with the `tabs`
  and `windows` events available without permission — hence the absence of
  `tabs`, whose only contribution would be reading URLs.
- **Clipboard**: the deferred wipe goes through an offscreen document
  (`offscreen`), since an MV3 service worker has no DOM access. Implemented —
  see §3.

## 5. First run

- The server field is validated immediately (`new URL`, HTTPS required — HTTP
  tolerated for localhost) with an explicit message.
- A "test the connection" button = a plain `prelogin`.
- The stance is stated: self-hosted, no third-party service contacted, no
  telemetry, no remote icons.
- `deviceIdentifier`: a UUID generated once and persisted in
  `chrome.storage.local` — regenerating it creates one server session per
  connection.
- `deviceType`: fixed by the build target (Chrome / Firefox).

## 6. Chosen differentiators

- Badge: the number of matches for the active tab.
- Automatic TOTP copy after filling (a paid feature at Bitwarden).
- Size budget: popup under 50 KB, total under 300 KB (see the README) — every
  interface addition is measured with `npm run size`.
