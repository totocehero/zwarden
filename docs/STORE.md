# Publishing on the Chrome Web Store

Everything the Developer Dashboard asks for, in the order it asks, with the
text to paste. The dashboard is at <https://chrome.google.com/webstore/devconsole>.

## 0. Before the first upload

- **A developer account**: a Google account, a one-time 5 USD fee, and the
  identity verification Google now requires of publishers. Allow a day.
- **The package**: the Chrome zip attached to the GitHub release
  (`zwarden-<version>-chrome.zip`). Its root holds `manifest.json`, which is
  what the store expects. Do not re-zip `dist/` by hand: the release's zip is
  the one whose SHA-256 and attestation are published.
- **Know what changes for users**: the store gives the extension an identifier
  of its own, different from the one an unpacked load had. The first install
  from the store starts empty — server address, email and session have to be
  entered again. Say so in the release notes of the first store version.
- **Screenshots**: at least one, 1280×800 or 640×400, PNG or JPEG, no alpha.
  Take them with a test vault, in both themes if you like, and check that no
  real site or username is readable. Suggested set: the unlocked list on a page
  with a match (the "For this page" heading), the settings page, the passkey
  confirmation.

## 1. Store listing

**Title**: taken from the manifest (`Zwarden`).

**Summary**: taken from the manifest's `description`, 132 characters at most.
Current: *Open-source password manager, compatible with Vaultwarden / the
Bitwarden API. Built to stay light.* (99 characters.)

**Detailed description** — English:

> Zwarden is a password manager for your own server. It speaks the Bitwarden
> protocol, so it works with Vaultwarden and with any Bitwarden-compatible
> server, and it does so in about 270 KB.
>
> What it does: unlock your vault with your master password and decrypt it in
> your browser; search, copy, fill, edit and export items; one-time codes;
> cards and identities; organisation vaults; create and use passkeys from the
> vault; offer to save a credential you just typed; check passwords against
> known breaches; tell you when a new release is out.
>
> What it does not do: contact anyone you did not ask it to. There is no
> Zwarden service and no account with us. The extension talks to the server
> you configured, and — only if you switch them on — to Have I Been Pwned
> (five characters of a hash, never the password) and to GitHub (to ask
> whether a newer release exists). No telemetry, no analytics, no remote code.
>
> Security choices you can read about: the vault key never touches the disk;
> every encrypted field is authenticated before it is used; the server cannot
> lower the key-derivation parameters or substitute an organisation key
> without the extension refusing; filling requires a click and matches by
> strict origin unless you set a rule on the URI yourself.
>
> Open source, MIT. The code, the tests and the documentation are on GitHub,
> including a page on exactly what is stored where and what each piece would
> give an attacker. Built for one person first; no independent security audit
> has been conducted yet, and the README says so.

**Detailed description** — French (add `fr` as a listing language):

> Zwarden est un gestionnaire de mots de passe pour votre propre serveur. Il
> parle le protocole Bitwarden, fonctionne donc avec Vaultwarden et tout
> serveur compatible, et tient en 270 Ko environ.
>
> Ce qu'il fait : déverrouiller votre coffre avec votre mot de passe maître et
> le déchiffrer dans votre navigateur ; rechercher, copier, remplir, modifier
> et exporter des éléments ; codes à usage unique ; cartes et identités ;
> coffres d'organisation ; créer et utiliser des passkeys depuis le coffre ;
> proposer d'enregistrer un identifiant que vous venez de saisir ; vérifier
> les mots de passe contre les fuites connues ; vous dire quand une nouvelle
> version est publiée.
>
> Ce qu'il ne fait pas : contacter qui que ce soit sans que vous l'ayez
> demandé. Il n'y a pas de service Zwarden ni de compte chez nous.
> L'extension parle au serveur que vous avez configuré, et — seulement si vous
> les activez — à Have I Been Pwned (cinq caractères d'une empreinte, jamais
> le mot de passe) et à GitHub (pour savoir si une version plus récente
> existe). Pas de télémétrie, pas d'analytique, pas de code distant.
>
> Des choix de sécurité documentés : la clé du coffre ne touche jamais le
> disque ; chaque champ chiffré est authentifié avant usage ; le serveur ne
> peut pas abaisser les paramètres de dérivation ni substituer une clé
> d'organisation sans que l'extension refuse ; le remplissage demande un clic
> et correspond par origine stricte, sauf règle posée par vous sur l'URI.
>
> Open source, MIT. Le code, les tests et la documentation sont sur GitHub, y
> compris une page sur ce qui est stocké où et ce que chaque élément
> donnerait à un attaquant. Construit pour une personne d'abord ; aucun audit
> de sécurité indépendant n'a encore été mené, et le README le dit.

**Category**: Productivity → Tools (or "Workflow & Planning"; there is no
"security" category).

**Language**: English, with French added under "Add language".

**Icon**: `public/images/icon128.png` — 128×128, already in the package.

**Links**: homepage and support both to
<https://github.com/totocehero/zwarden>.

## 2. Privacy practices

This tab is where a password manager with `https://*/*` gets read closely.
Every answer below is true of the code as it is; if a later version changes
one, change it here before uploading.

**Single purpose** (one sentence):

> Store, fill and manage the user's own passwords, passkeys and related
> secrets in a vault held on a server the user chooses.

**Permission justifications** (one box per permission):

- `storage` — *Keeps the user's settings (server address, account email,
  timeouts) and the unlocked session's state. No vault key and no decrypted
  item is ever written to disk.*
- `clipboardWrite` — *Copying a username, password or one-time code on the
  user's click, and clearing the clipboard after the delay the user set.*
- `alarms` — *The inactivity lock, the delayed clipboard wipe, and an optional
  daily check for a newer release.*
- `idle` — *Locking the vault when the operating system session locks.*
- `offscreen` — *Clearing the clipboard after the popup has closed, which only
  an offscreen document can do.*
- `activeTab` — *Filling the login form of the page the user is on, when they
  click "Fill" in the popup.*
- `scripting` — *Injecting the form filler into the current tab on the user's
  click, and registering two optional content scripts (credential-save
  detector, passkey hook) only while the user has switched those settings on.
  With both settings off — the default — no content script is registered.*
- **Host permissions** `https://*/*`, `http://localhost/*`,
  `http://127.0.0.1/*` — *The user's vault server can be at any address, so
  the extension cannot name it in advance; logins exist for any site, so the
  filler must reach any page the user is on. The extension itself contacts
  only: the server the user configured; api.pwnedpasswords.com and
  api.github.com, each only when the user has enabled that feature. The
  localhost entries exist for a self-hosted server on the same machine.*
- **Remote code**: *No, I am not using remote code.* (Everything ships in the
  package; the only external requests are data, never scripts.)

**Data usage** — tick these, because they are true:

- [x] Personally identifiable information — *the account email, kept locally
  to prefill the unlock form and sent to the user's own server to sign in.*
- [x] Authentication information — *passwords, passkeys, one-time-code seeds:
  the vault's contents, encrypted; the master password, used in memory only.*
- [x] Financial and payment information — *the vault can hold payment cards,
  encrypted like everything else.*
- [x] Website content — *with "offer to save" on, the username and password
  typed into a login form, held for seconds while the user decides.*
- [ ] Health information
- [ ] Personal communications
- [ ] Location
- [ ] Web history — *the extension sees the active tab's URL to match items,
  and keeps none of it; the never-save list is stored hashed.*
- [ ] User activity

**Certifications** — all three are true:

- [x] I do not sell or transfer user data to third parties, outside of the
  approved use cases
- [x] I do not use or transfer user data for purposes unrelated to my item's
  single purpose
- [x] I do not use or transfer user data to determine creditworthiness or for
  lending purposes

**Privacy policy URL**:
<https://github.com/totocehero/zwarden/blob/master/docs/PRIVACY.md>

## 3. Distribution

- **Visibility**: *Public*, or *Unlisted* for a first round where only people
  with the link install it. Unlisted still goes through review and still gets
  a stable identifier, so it is the right first step.
- **Regions**: all.
- **Pricing**: free.

## 4. Submit, and what to expect

Press *Submit for review*. Because of the broad host permission and
`scripting`, expect the longer review path: a few days rather than hours, and
possibly a question about why `https://*/*` is needed — the host-permission
justification above is the answer. Leave *Publish automatically after review*
on, or off if you want to time the first release.

A rejection names a policy section. The ones that could plausibly come up:

- **"Use of permissions"** — they want a narrower host list. The honest reply
  is the one above: the server address is the user's choice. If they insist,
  the alternative is `optional_host_permissions` requested at first run, which
  is a code change, not a listing change.
- **"User data privacy"** — a missing or vague policy. `PRIVACY.md` is
  deliberately specific; point at the tables.

## 5. Every release after the first

1. Tag and push as usual; the GitHub workflow builds and attaches the zip.
2. Dashboard → the item → *Package* → *Upload new package* → the release's
   `zwarden-<version>-chrome.zip`. The version must be higher than the one
   in the store; the manifest test keeps `package.json` and the manifest in
   step.
3. *Submit for review*. Updates with no new permission are usually quick.

When this becomes routine, the upload can move into `release.yml` with the
Chrome Web Store API (a Google Cloud OAuth client and a refresh token kept as
repository secrets). Not before: the first few reviews are worth reading by
hand.

## 6. Afterwards, in the code

- The in-extension update check is redundant for store installs, which Chrome
  updates itself. `chrome.runtime.getManifest().update_url` is set on a store
  install and absent on an unpacked one; hiding the section when it is set is a
  small change, worth making once the store listing is live.
- The README's install section should gain the store link and keep the zip
  path for people who prefer to verify the attestation.
