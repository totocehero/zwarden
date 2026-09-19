# Zwarden's cryptography

This document describes the cryptographic scheme implemented in
`src/core/crypto/`. It is aimed at two audiences: anyone auditing the code, and
anyone who will have to change it in six months.

Zwarden is **compatible with the Bitwarden / Vaultwarden format**. Deliberate
divergences are flagged with ⚠ and concern hardening alone, never the wire
format.

---

## 1. Threat model

### What Zwarden protects against

| Adversary | Assumed capability | Protection |
|---|---|---|
| A malicious or compromised server | Reads and modifies everything it stores, controls its responses | End-to-end encryption; every field authenticated; KDF parameters validated |
| The network (MITM) | Reads and modifies traffic | TLS, plus end-to-end encryption as defence in depth |
| Theft of the server database | Offline reading of all storage | The server holds no key; only a dictionary attack on the master password remains possible, slowed by the KDF |
| Theft of the browser profile, vault locked | Reading persistent local storage | No key in the clear on disk |

### What Zwarden does not protect against

These limits are structural and common to every browser-extension password
manager. Stating them avoids false expectations.

- **A compromised machine with the vault unlocked.** The vault key is in memory.
  Malware with access to the process retrieves it. `wipe()` narrows the exposure
  window, no more.
- **A weak master password.** The KDF raises the cost of an offline attack; it
  does not make up for a guessable password.
- **A malicious browser extension** holding the same permissions.
- **Metadata.** The server knows the number of items, their modification dates
  and their approximate size. That information is not encrypted in the Bitwarden
  format.
- **The clipboard.** A copied secret sits there until the deferred overwrite
  (30 s by default). Any program on the machine can read it meanwhile, and the
  operating system's clipboard history, if active, may keep a trace the
  extension cannot reach.
- **Local traces of use.** The "most recently used" ordering persists item
  identifiers (opaque UUIDs) and timestamps to disk — never a name, a URL, a
  username or a secret. Whoever reads the browser profile learns that an item was
  used at a given time, not which one. The list of sites excluded from the save
  proposal, however, is in the clear: they are hostnames the user named
  themselves.
- **A captured credential, in memory.** Between an entry and the user's
  decision, a cleartext password waits in `chrome.storage.session`: the same
  storage as the vault key, the same purge — locking, closing the browser — plus
  a 10-minute expiry. It never reaches disk.
- **The local master-password hash, in memory.** The unlocked session keeps
  `localPasswordHash` so a fresh entry can be verified offline (the `reprompt`
  guard, §7). It cannot be replayed against the server — its iteration count
  differs from the authorization hash's — and it lives in the same memory
  storage as the vault key, which is strictly more sensitive: keeping it opens
  no new surface.

---

## 2. Key hierarchy

```
                       master password
                              │
              ┌───────────────┴───────────────┐
              │ KDF                           │
              │ salt = normalised email       │
              ▼                               │
        master key (32 B)                     │
              │                               │
      ┌───────┴────────┐                      │
      │ HKDF-Expand    │ PBKDF2               │
      │ "enc" / "mac"  │ 1 or 2 iterations    │
      ▼                ▼                      │
  stretched         password hash ────────────┘
  master key        (sent to the server)
  (64 B)
      │
      │ decrypts the profile's `Key` field
      ▼
   vault key (64 B)  ← random, independent of the password
      │
      ├── decrypts each item's fields
      └── decrypts the RSA private key (organisation sharing)
```

### Why this indirection

The master key **never encrypts data**. It serves only to wrap the vault key.

The direct consequence: changing the master password requires only re-wrapping
64 bytes. Without that indirection, the entire vault would have to be
re-encrypted and retransmitted on every change — expensive, and above all
fragile if the operation is interrupted halfway.

---

## 3. Master key derivation

### PBKDF2-SHA256

```
master key = PBKDF2-SHA256(
    password = NFKD(password),
    salt     = lowercase(trim(email)),
    c        = iterations announced by the server,
    dkLen    = 32
)
```

### Argon2id

```
master key = Argon2id(
    password    = NFKD(password),
    salt        = SHA-256(lowercase(trim(email))),
    t           = iterations,
    m           = memory in MiB × 1024,
    p           = parallelism,
    hashLength  = 32
)
```

The salt is the email's **digest**, not the raw email: Argon2 requires a
fixed-size salt.

### Details that break interoperability if they diverge

| Point | Rule | Consequence of a deviation |
|---|---|---|
| Password normalisation | `NFKD` | Composed accents produce a different key depending on the OS |
| Email normalisation | `trim()` then `toLowerCase()` | Different salt, unreadable vault |
| Argon2id salt | `SHA-256(email)` | Unreadable vault |
| HKDF | Expand **alone**, no Extract | Different stretched key, unreadable vault |

⚠ **KDF parameter validation.** The parameters arrive from
`/api/accounts/prelogin`, hence **before authentication**: untrusted input. A
hostile server answering `iterations: 1` obtains a master key derived in a
single round, and the authentication hash then sent is enough to crack the
password offline within seconds.

The check is bounded **in both directions**:

- **Floors** — below them, the key becomes crackable offline. Refused below
  100,000 PBKDF2 iterations (Bitwarden's old default, kept so existing vaults are
  not blocked) and below `t=2, m=16 MiB, p=1` for Argon2id.
- **Ceilings** — above them, it is a denial of service: `iterations: 2³¹` freezes
  the client, an Argon2 memory of several gibibytes kills the tab with an OOM at
  unlock. Refused above 5,000,000 PBKDF2 iterations and above
  `t=10, m=1024 MiB, p=16` for Argon2id — the maxima in the official client's
  interface, so no legitimate vault can exceed them.
- **Non-integer values** — `NaN`, floats and strings dressed up as numbers are
  rejected before reaching the KDF (`Number.isSafeInteger`).

**The official Bitwarden client performs none of these checks.**

---

## 4. Stretching: 32 → 64 bytes

The master key is 32 bytes: enough to encrypt, not to authenticate.

```
encKey = HKDF-Expand-SHA256(prk = master key, info = "enc", L = 32)
macKey = HKDF-Expand-SHA256(prk = master key, info = "mac", L = 32)

stretched master key = encKey ‖ macKey
```

HKDF's Extract step is omitted: the master key is already a uniformly random PRK
out of the KDF, and Extract would add no entropy. This is Bitwarden's choice;
departing from it would make vaults unreadable.

The `enc` and `mac` labels guarantee the two halves are independent. Reusing one
key for both AES and HMAC is a classic fault: the composition loses every proven
guarantee.

---

## 5. Master password hash

```
hash = base64( PBKDF2-SHA256(password = master key, salt = NFKD(password), c = purpose, dkLen = 32) )
```

PBKDF2 is applied "backwards": the master key is the password, the password is
the salt. The server receives a value from which it can recover neither.

| Purpose | `c` | Destination |
|---|---|---|
| `ServerAuthorization` | 1 | Sent to `/identity/connect/token` |
| `LocalAuthorization` | 2 | Kept locally to validate the password offline |

The iteration count **is** the enum's value. The two hashes are therefore
structurally distinct: the one stored locally cannot be replayed as proof of
authentication, and vice versa.

Offline validation goes through `verifyLocalPasswordHash`, which compares the
**decoded bytes** in constant time — never a `===` on the base64 strings, which
short-circuits at the first differing character.

---

## 6. Data encryption

### Construction

```
iv  ← 16 random bytes
ct  ← AES-256-CBC-PKCS7(encKey, iv, plaintext)
mac ← HMAC-SHA256(macKey, iv ‖ ct)
```

Serialisation: `2.<base64(iv)>|<base64(ct)>|<base64(mac)>`

### Decryption

```
1. verify    HMAC-SHA256(macKey, iv ‖ ct) == mac    (subtle.verify, native constant time)
2. on failure → reject, without touching AES
3. otherwise  → AES-256-CBC-decrypt
```

**The order of these steps is the module's most important security property.**
AES-CBC throws on invalid PKCS#7 padding. Decrypting before verifying turns that
exception into a *padding oracle*: an attacker able to submit ciphertexts and
observe the failure reconstructs the plaintext block by block, without ever
learning the key.

The MAC covers the IV **and** the ciphertext. A forged IV would allow arbitrary
bits of the first plaintext block to be flipped; it is therefore authenticated.

### Supported types

| Type | Algorithm | Read | Write |
|---|---|---|---|
| 0 | AES-256-CBC, no MAC | legacy ⚠ | refused |
| 1 | AES-128-CBC + HMAC | refused | refused |
| 2 | AES-256-CBC + HMAC-SHA256 | yes | **yes** |
| 3–4 | RSA-2048 OAEP | organisation keys only | refused |
| 5–6 | RSA-2048 OAEP + HMAC | refused (a legacy that never took hold) | refused |

RSA serves only to unwrap **organisation keys** (`keyring.ts`): the account's
private key, itself wrapped by the vault key, decrypts each organisation's key,
which then decrypts its items with AES type 2.

---

## 7. Hardening beyond the official client

### ⚠ Downgrade refusal

Type 2 data served back as type 0 is rejected.

Without that check the attack is immediate: the server strips the MAC segment,
changes the `2.` prefix to `0.`, and the client decrypts without verification.
The padding oracle neutralised in §6 is fully reopened.

Implementation: decrypting a type 0 with an authenticated key (64 B) raises
`UnsupportedEncryptionError`. A genuine legacy vault uses a 32-byte key, so the
distinction is clean.

### ⚠ Writes are always authenticated

`encryptBytes` throws if the key has no `macKey`. Zwarden cannot produce
unauthenticated data, whatever the vault's configuration.

### ⚠ KDF parameter validation

See §3.

### ⚠ AES-128 (type 1) refused for reading

An obsolete format. The vault must be re-encrypted. No known active vault still
uses it.

### SHA-1: one door, and it does not open onto the vault

`hmacForOtp` is the only place in the code where SHA-1 appears, and it serves
one-time codes alone (RFC 6238). This is not a concession: TOTP is specified on
HMAC-SHA1, the vast majority of sites offer nothing else, and refusing it would
make the second factor unusable without securing anything. SHA-1's weakness is
collisions; HMAC does not depend on them.

No encrypted data passes through this function: "encrypt-then-MAC" remains
carried by `hmacSha256`, and it alone. The separation is in the names as much as
in the calls — a vault HMAC computed with `hmacForOtp` would stand out on
reading.

### Verifying the master password without a network

`unlock()` produces two independent hashes: one authorises against the server,
the other stays local. The second is used to revalidate an entry when an item
demands the master password again (`reprompt`, `docs/EXTENSION.md` §3): we
re-derive the master key from the entry, recompute the local hash, and compare
with `timingSafeEqual`. The re-derived master key is destroyed immediately.

Two reasons not to go through the server. First, a `reprompt` must work offline,
like the rest of the cached vault. Second, having the guard validated remotely
would hand whoever controls the network the power to disarm it — a "password
correct" response would suffice. The guard is local because what it protects is
local.

---

## 8. Implementation choices

### WebCrypto rather than a compiled SDK

| Operation | Implementation | Bundle |
|---|---|---|
| AES-256-CBC | native WebCrypto | 0 B |
| HMAC-SHA256 | native WebCrypto | 0 B |
| SHA-256 | native WebCrypto | 0 B |
| PBKDF2-SHA256 | native WebCrypto | 0 B |
| HKDF-Expand | a loop of native HMACs | ~15 lines |
| Argon2id | WASM, dynamic import | ~45 KB, loaded on demand |

The official client loads 7.4 MB of Rust SDK at start-up, unconditionally. The
browser's native code is written in constant-time C++, continuously audited, and
already in memory.

An account configured for PBKDF2 **never** downloads the Argon2id module.

### base64 delegated to the platform

The main path uses `Uint8Array.prototype.toBase64` / `Uint8Array.fromBase64`
(the TC39 arraybuffer-base64 proposal), detected at module load; failing that,
it falls back to `btoa`/`atob`. A hand-written implementation was written and
then removed: `scripts/bench-base64.mjs` measures it **slower** than
`atob`/`btoa` (2.2× on decoding), which are themselves beaten by the dedicated
native methods. Forty lines of sensitive code deleted for a performance gain.

The platform's decoders **reject** invalid input, where the hand-written one
ignored it. That is the right behaviour: on cryptographic material, ignoring
unreadable bytes would mask corruption or a tampered response. `EncString.parse`
translates those failures into `EncStringParseError`.

### Reusing imported keys

`subtle.importKey` costs an async round trip to the crypto module.
`SymmetricCryptoKey` therefore imports each key half **once** (non-extractable
handles, cached lazily): syncing an N-item vault saves 2 N imports. `destroy()`
drops the handles at the same time as it erases the raw material.

### Constant-time comparison

MAC verification is delegated to `subtle.verify`: native code, with constant time
guaranteed by the platform. A "constant-time" JavaScript loop remains at the
mercy of the JIT, which promises nothing about the timing profile of the code it
optimises.

`timingSafeEqual` remains for comparisons outside WebCrypto (the local hash,
tests). It always walks the full length and accumulates differences with a
bitwise OR: a short-circuiting comparison reveals, through its response time, how
many leading bytes are correct, which brings forging a MAC down from 2²⁵⁶ to
about 256 × 32 attempts.

### Memory erasure

`wipe()` and `SymmetricCryptoKey.destroy()` are **best-effort**. A JS engine with
a generational GC copies objects during memory promotions, and those copies are
out of JavaScript's reach. This narrows the exposure window to memory dumps and
hibernation without closing it. Do not overestimate this guarantee.

---

## 9. Test coverage

`npm test` — 301 tests.

| File | Scope |
|---|---|
| `encoding.test.ts` | RFC 4648 vectors, on the native path **and** the fallback; round trip over all 256 byte values; multi-byte UTF-8; base64url; constant time |
| `primitives.test.ts` | RFC 4231 (HMAC), RFC 7914 (PBKDF2), RFC 5869 (HKDF) vectors; `subtle.verify`; equivalence of a raw key and an imported `CryptoKey` |
| `cryptoService.test.ts` | Round trips; IV uniqueness; **tampering with IV / ciphertext / MAC**; downgrade; wrong key; structural ciphertext validation; a frozen non-regression vector |
| `kdf.test.ts` | Determinism; email and password normalisation; salt separation; refusal of weak, absurd and non-integer KDFs; hash separation; constant-time local validation |
| `apiClient.test.ts` | Stubbed `fetch`: URL validation, field casing, 429 / Retry-After, second factor, captcha, session refresh, non-JSON 200, missing token, deletion idempotence; only the authorization hash travels |
| `vault.test.ts` | A stubbed server that **verifies the hash**: `unlock()` end to end, weak-KDF refusal before anything is sent, a missing or forged wrapped key; items with their own key, PascalCase casing, corrupted fields isolated, a list with bounded concurrency |
| `detector.test.ts` | Under jsdom: the "show password" click, account creation with a diverging confirmation, a hidden field, and the mirror field that once handed the password over as the username |
| `totp.test.ts` | RFC 6238 vectors on SHA-1/256/512; `otpauth://` parsing; the counter beyond 2^31 |
| `generator.test.ts` | Composition guarantee; rejection of the incomplete slice; shuffle; ambiguous characters |

The tampering tests are the most important: they check that every possible
forgery does produce a `MacMismatchError`.

---

## 10. Interoperability: validated

Interoperability is no longer a deduction from the specification, it is an
observed fact. Validation carried out against **Vaultwarden 2026.6.0**, on an
account using PBKDF2-SHA256 at 600,000 iterations.

| Step | Result | What it proves |
|---|---|---|
| `prelogin` | PBKDF2, 600,000 iterations | The KDF parameters are read correctly |
| Master key derivation | 32 bytes | — |
| `connect/token` | **Accepted** | The authorization hash is identical to the official client's, so the master key derivation is too (NFKD, email normalisation, salt, iterations) |
| Vault key decryption | 64 B, MAC verified | HKDF-Expand without Extract, the `enc`/`mac` labels, the concatenation order, the type 2 `EncString` format, AES-256-CBC and HMAC-SHA256: all correct |
| Write then read back | Identical values | The encryption path produces data the server accepts and that we decrypt again after a complete round trip |

The write test is the most conclusive: an item is encrypted locally, pushed
through `POST /api/ciphers`, read back by a full sync, then decrypted again.
Name, username and password are compared against the original. The item is
deleted at the end of the test, including when an assertion fails.

### Replaying the validation

```bash
export ZWARDEN_TEST_SERVER=https://vault.example.com
export ZWARDEN_TEST_EMAIL=account+test@example.com
export ZWARDEN_TEST_PASSWORD='...'
npx vitest run tests/integration
```

Without those variables the test is skipped: the suite stays runnable offline.

**Use a throwaway account.** The test creates and deletes an item. No secret is
written to disk nor logged — the report shows only lengths and item identifiers.

### Not covered yet

- Argon2id against a real server (unit-tested, not interoperability-tested)
- Items with their own key (`cipher.key`) — the code handles them, no real
  sample encountered
- Organisation vaults against a real server — the full RSA chain is validated by
  unit tests (a simulated RSA pair, a reconstructed profile), not yet in
  interoperability
- Attachments
