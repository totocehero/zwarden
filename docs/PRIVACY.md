# Privacy policy

*Zwarden — browser extension. Last updated 2026-10-17.*

Zwarden is a password manager that talks to a server **you** choose: your own
Vaultwarden, or a Bitwarden-compatible server. There is no Zwarden service,
no account with us, no telemetry, no analytics, no advertising, and no remote
code. This page says exactly what the extension stores, what leaves your
browser, and to whom.

## What the extension does

It unlocks your vault with your master password, decrypts it **in your
browser**, and lets you search, copy, fill, edit and export its items. It can
offer to save a credential you just typed into a page, answer a passkey
sign-in with a passkey from the vault, check whether a password appears in a
known breach, and tell you when a newer release of the extension exists. The
last three are **off by default** and switched on, one by one, in the
settings.

## What leaves your browser, and to whom

| Destination | When | What |
|---|---|---|
| **The server you configured** | On unlock, sync, and every edit | Your account email, a hash derived from your master password (never the password itself), your device name and a random device identifier, and your vault items **encrypted with keys the server does not have**. This is the Bitwarden protocol; the server is yours or one you chose. |
| **api.pwnedpasswords.com** (Have I Been Pwned) | Only if you enabled breach checking, and only when you run a health check | The first five characters of the SHA-1 hash of a password. Neither the password nor its full hash leaves; the comparison happens locally. Documented in the settings. |
| **api.github.com** | Only if you enabled the update check (once a day), or when you press "Check now" | A request for this repository's latest release. It carries what every request carries — your IP address and your browser's identity — and nothing else: not even the version you have installed. |

Nothing else. No request is made to any other host, and no data is sent to
the author of this extension.

## What is stored in your browser

Everything below lives in the extension's own storage, readable by no web
page and no other extension. The full inventory, with what each entry would
give an attacker, is in [`STORAGE.md`](STORAGE.md).

**In memory, erased when the vault locks or the browser closes:** the vault
key (sealed), the session tokens, the cached encrypted vault, the credential
you just typed into a page while the extension asks whether to save it, and a
pending passkey request.

**On disk, until you remove the extension or clear them in the settings:**
the server address, your account email, the device name and identifier, your
settings, the token that exempts this device from a second factor (if you
chose "remember me"), the hosts you asked the extension to stop offering to
save for (stored hashed), the order in which you last used items, and edits
made while offline (already encrypted).

**Never stored on disk:** your master password, your vault key, any decrypted
vault item, any password in clear.

## Passkeys

With the passkey setting on, the extension replaces one browser function
(`navigator.credentials.get` / `.create`) in HTTPS pages so that a site's
passkey request can be answered from the vault. Nothing is drawn in the page,
nothing is read from it beyond that request, and every request is checked
against the page's own origin before the vault is consulted. With the setting
off — the default — no code of this extension runs in any page.

## Saving credentials

With the "offer to save" setting on, a small script watches login forms in
the pages you visit, and only when you submit one does it pass the username
and password to the extension, which asks you in the popup whether to save
them. The script sends nothing anywhere else. With the setting off, no code
of this extension runs in any page.

## Permissions, and why

| Permission | Why |
|---|---|
| `storage` | The settings and the session described above. |
| `clipboardWrite` | Copying a username, password or one-time code, and wiping it after a delay you set. |
| `alarms` | The inactivity lock, the clipboard wipe, and the optional daily update check. |
| `idle` | Locking the vault when the computer locks. |
| `offscreen` | Wiping the clipboard after the popup has closed (Chrome only). |
| `activeTab`, `scripting` | Filling a login form on the page you are on, when you click "Fill"; installing the two optional page scripts above, only while their settings are on. |
| Host access to `https://*/*` | Reaching **your** server at whatever address it has, filling forms on any site you have a login for, and the two optional scripts. The extension contacts only the hosts listed in the table above. |

## Your choices

Every optional network feature is off by default and has its own switch in
the settings, next to a plain statement of what it sends. You can clear the
remembered second factor, the never-save list and the usage order from the
settings at any time. Removing the extension removes everything it stored.

## Changes

This page lives in the repository and changes with it. The commit history is
the record of what changed and when.

## Contact

Questions and concerns: open an issue at
<https://github.com/totocehero/zwarden/issues>.
