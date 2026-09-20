# What is stored where, and what an attacker gets

This document exists because "it is in `chrome.storage`" says nothing useful.
The two stores Zwarden uses have opposite properties, and the difference is the
whole of the local threat model.

It is written **backwards**: not "here is what we store and it is fine", but
"here is what someone who reaches each store can actually do". The decisions at
the end follow from that, including where the offline write queue may live.

---

## 1. The two stores, physically

### `chrome.storage.session` — memory

Held in the browser process's memory and, per Chrome's documentation, **not
written to disk**. Cleared when the browser closes. Not readable by content
scripts: the access level defaults to trusted contexts and Zwarden never calls
`setAccessLevel` to widen it (grep for it — there is no call).

This is what makes the default lock policy work: closing the browser destroys
the key because there is nowhere for it to survive.

**Two honest caveats**, because "memory" is not a security boundary the way one
wishes it were:

- the operating system may page that memory to swap, and a hibernation image is
  a copy of RAM. "Not deliberately persisted by the browser" is not "never
  touches a disk". Full-disk encryption is what actually closes this;
- the vault key sits there as a base64 **string**. `SymmetricCryptoKey.destroy()`
  zeroes the byte arrays it owns, but a JavaScript string is immutable and
  cannot be wiped — `lockVault()` removes the entry, and the bytes linger until
  the garbage collector gets to them. This is inherent to the platform, not a
  bug we have declined to fix, and it is why the key is never written anywhere
  that survives.

### `chrome.storage.local` — disk, in the clear

A LevelDB database inside the browser profile
(`Local Extension Settings/<extension id>/`). **Chrome does not encrypt it.**
Chrome encrypts the passwords of its *own* password manager through the OS
keychain or DPAPI; extension storage gets none of that.

The rule that follows, and the one this whole document exists to state:

> **Anything in `chrome.storage.local` must be assumed readable by any process
> running as the user, and by anyone holding the disk.**

It does not follow the profile to other machines — that is `storage.sync`,
which Zwarden does not use.

---

## 2. Complete inventory

### In memory (`session`) — never deliberately written to disk

| Entry | Contents | Why it may live there |
|---|---|---|
| `zwardenSession` | vault key (base64), access and refresh tokens, **the whole cached sync**, the local master-password hash, KDF parameters | The key is the most sensitive object in the extension; everything of comparable value is kept beside it rather than given a second, weaker home |
| `zwardenPendingSave` | a credential captured on a page — **username and password in clear** | The only cleartext password the extension ever stores. It lives for the few seconds between a form submission and the user's answer, and is dropped on either answer |
| `zwardenActivity` | a timestamp | Drives the inactivity lock |

### On disk (`local`) — assume it is read

| Entry | Contents | What it gives an attacker |
|---|---|---|
| settings | server URL, account email, device name, timeouts, chosen language | **Identifies the account and names the server to attack.** Unavoidable: the unlock form has to be able to prefill |
| `deviceId` | a random UUID | Identifies this installation to the server. Regenerable from the settings |
| `2faRemember:<email>@<server>` | the token that exempts this device from the second factor | **The sharpest item here** — see §3 |
| `neverSaveHosts` | hosts the user told Zwarden to stop asking about | Reveals sites the user has an account on. Hardened — see §4 |
| `generatorOptions` | length, character classes | Nothing |
| `lastUsed` | `{ item id: timestamp }` | How many distinct items are used and when. The identifiers are server-side UUIDs and mean nothing without the vault, which is not on disk |

**The vault ciphertext is not on disk today.** The cached sync lives in memory
with the key. That is a stronger position than most password managers take, and
§5 is about not giving it up carelessly.

---

## 3. Working backwards: what each attacker actually achieves

### A. A local process running as the user

Malware, a hostile `postinstall` script, any application the user was persuaded
to run.

- **Gets**: everything in §2's second table. The account email, the server, the
  usage metadata, and the 2FA exemption token.
- **Does not get from storage**: the vault key, the cached vault, the master
  password hash. They are in memory, in another process.
- **But** such a process can attach a debugger to the browser, read its memory,
  add an extension, or replace Zwarden's own files if it was loaded unpacked
  from a writable directory. Once arbitrary code runs as the user, storage
  hygiene reduces the *passive harvest*, not the *active attacker*.

Stated plainly so nobody mistakes the scope: **this threat model does not claim
to defeat local code execution.** No browser extension can.

### B. The disk, without live execution

A stolen laptop, a backup, a forensic image, a resold drive.

- `session` is gone: memory did not survive the power cut.
- `local` yields the whole second table.
- The vault itself is **not** there, and neither is the key or the password
  hash. An attacker at this level cannot mount an offline attack on the master
  password from Zwarden's own files — they would need the wrapped key, which
  only the server hands out, and only against a correct authorization hash.

This is the scenario the split is designed for, and it is the one it wins.

### C. Another extension

Extensions cannot read each other's storage. Not a vector.

### D. A web page or a content script

`chrome.storage` is not exposed to pages. Session storage additionally defaults
to trusted contexts only, and Zwarden does not widen it.

### E. Profile sync

`storage.local` does not sync. Nothing here rides to another machine.

---

## 4. The decisions this produced

### The 2FA exemption token stays on disk, and it is the weakest thing there

Its entire purpose is to survive a browser restart — a token in memory would be
forgotten on every launch and the feature would not exist. So it must be on
disk, where §3.B reaches it.

What limits the damage:

- it is useless without the master password. It removes a factor, it does not
  replace one;
- it is scoped to one `(server, account)` pair and revocable server-side;
- the settings page has a one-click **"forget the exemptions"** that removes
  every one of them.

The official Bitwarden extension makes the same trade. We state it rather than
inherit it quietly.

### Never-save hosts are stored hashed, not in clear

A list of hostnames in cleartext on disk is a list of sites the user has an
account on — handed over by §3.B for free, with no vault needed.

They are therefore stored as `SHA-256(salt ‖ host)`, with a random per-install
salt in the same store. The salt buys nothing against someone who has the file
— they hold it too — and that is not what it is for. What changes is the *kind*
of question the attacker can ask:

- before: **enumerate** the list and read off the sites;
- after: **confirm** a host they already guessed.

Turning a disclosure into an oracle is a real reduction, and the lookup is an
exact match, so hashing costs nothing in function. It is not a defence against a
determined attacker with a host list; it is the removal of a free gift.

### The usage log stays as it is

`{ item id: timestamp }` where the identifiers are server-side UUIDs. Without
the vault — which is not on disk — they identify nothing. The residual leak is
"this user opened twelve distinct items, at these times", and paying for it with
a broken "recently used" ordering across restarts is not a trade worth making.

### The offline write queue holds ciphertext, and nothing else

The queue introduced for offline edits is the **first vault ciphertext Zwarden
writes to disk**, so the reasoning is recorded here rather than in a commit
message.

- What is queued is the output of `buildCipherUpdatePayload`: every sensitive
  field is already an `EncString` under the item's key. **The cleartext edit is
  never stored** — it is encrypted first, then queued. Storing the edit and
  encrypting at replay would put a cleartext password on disk, which is the one
  thing this document exists to prevent.
- Without the vault key, that ciphertext is opaque, and the key is not on disk.
  An attacker at §3.B holds an AES-256-CBC ciphertext with a valid HMAC and no
  path to either key.
- What it does add is **metadata**: the identifiers and revision dates of the
  items edited while offline. A handful of UUIDs, of the same nature as the
  usage log, and only for items actually edited offline.

That is the cost, and it is stated so the trade can be disagreed with.
