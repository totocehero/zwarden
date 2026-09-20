/**
 * @file Interface strings, in the browser's language.
 *
 * ## Why `chrome.i18n` rather than a bundled catalogue
 *
 * The browser already knows the user's language, and `chrome.i18n` already
 * picks the matching `_locales/` folder — no detection code, no preference to
 * store, no locale to ship in the JavaScript bundle. Chrome loads the active
 * locale alone at runtime: adding a language costs one folder, and costs nothing
 * to the users of the others.
 *
 * That last point is why the README can hold Bitwarden's 15 MB of translations
 * against it and not repeat the mistake: the 63 locales are not the problem, the
 * problem is shipping all of them to everyone.
 *
 * ## Typed keys
 *
 * {@link MESSAGE_KEYS} is the list, and `MessageKey` derives from it — so a typo
 * is a compile error rather than an empty string in the interface.
 * `tests/i18n.test.ts` closes the loop in the other direction: every key must
 * exist in every locale, with matching placeholders, and no locale may hold a
 * key the code never asks for.
 *
 * ## Letting the user choose, against the grain of the API
 *
 * `chrome.i18n.getMessage` reads the **browser's** language and there is no way
 * to tell it otherwise: no argument, no setting, nothing at runtime. A user
 * whose browser is in English cannot have the extension in French without
 * changing their whole browser — which is not a trade anyone should have to
 * make for a password manager.
 *
 * So the override is loaded by hand: {@link applyLocale} fetches the packaged
 * `_locales/<code>/messages.json` and {@link t} resolves from it. This is
 * affordable for exactly one reason — every string in the interface already
 * goes through `t()`, so there is one place to change and no call site to
 * revisit. Without that chokepoint the same feature would be a rewrite.
 *
 * `chrome.i18n` stays underneath as the fallback, and stays the **only**
 * mechanism for the strings Chrome itself reads — the extension's name, its
 * description, the keyboard-shortcut labels in `chrome://extensions`. Those are
 * resolved by the browser before any of our code runs, and no amount of fetching
 * changes them.
 *
 * ## Outside an extension
 *
 * `chrome.i18n` does not exist in a Vite preview or in tests. {@link t} then
 * returns the key itself, which is visible enough to notice and harmless enough
 * not to break anything. The real run is `dist/` loaded in the browser.
 */

/**
 * Every message key the interface uses.
 *
 * Grouped by the screen that reads them, which is also the order the locale
 * files follow — a diff between the two stays readable.
 */
export const MESSAGE_KEYS = [
  // Application
  'appName',
  'appDescription',
  'appSettingsTitle',
  'cmdOpen',
  'cmdGenerate',
  'cmdLock',

  // Shared actions
  'actionSettings',
  'actionLock',
  'actionGenerate',
  'actionSave',
  'actionCancel',
  'actionBack',
  'actionClose',
  'actionUse',
  'actionCopy',
  'actionCopied',
  'actionMenu',

  // Unlock screen
  'unlockServer',
  'unlockServerPlaceholder',
  'unlockEmail',
  'unlockMasterPassword',
  'unlockSubmit',
  'unlockShowPassword',
  'unlockHidePassword',

  // Second factor
  'twoFaRequired',
  'twoFaWebAuthnOnly',
  'twoFaMethod',
  'twoFaCode',
  'twoFaRemember',
  'twoFaSubmit',
  'twoFaProviderAuthenticator',
  'twoFaProviderEmail',
  'twoFaProviderYubiKey',
  'twoFaRefused',

  // Vault list
  'listSearch',
  'listSearchUnknown',
  'listStillOpening',
  'listEmpty',
  'listUnreadableFields',
  'listFullLog',
  'listOpening',

  // An item's row
  'itemNoName',
  'itemPasskeyBadge',
  'itemCopyUsername',
  'itemUsernameCopied',
  'itemCopyPassword',
  'itemPasswordCopied',
  'itemShowPassword',
  'itemHidePassword',
  'itemShowOtp',
  'itemHideOtp',
  'itemEdit',
  'itemFill',
  'itemFillTitle',
  'itemChipFolder',
  'itemChipCollection',
  'itemChipReadOnly',
  'itemChipFilter',
  'itemOrganisation',

  // One-time code
  'otpCopy',
  'otpCopied',

  // Edit form
  'editName',
  'editUsername',
  'editPassword',
  'editTotp',
  'editUris',
  'editNotes',
  'editGeneratePassword',
  'editShow',
  'editHide',
  'editPasskeyNote',

  // List filters
  'filterAll',
  'filterShowType',
  'filterHideType',
  'filterShowAll',
  'filterCount',

  // Item types and creation
  'newItem',
  'newItemTitle',
  'newItemType',
  'typeLogin',
  'typeCard',
  'typeIdentity',
  'typeNote',
  'typeSshKey',

  // Item details, shared
  'itemShowDetails',
  'itemHideDetails',
  'itemCopyField',
  'itemFieldCopied',
  'itemNotes',
  'itemReveal',
  'itemConceal',

  // Cards
  'cardSection',
  'cardNumber',
  'cardNumberPlaceholder',
  'cardholderName',
  'cardBrand',
  'cardBrandAuto',
  'cardExpiry',
  'cardExpMonth',
  'cardExpYear',
  'cardCode',
  'cardCodeHint',
  'cardExpired',
  'cardExpiresSoon',
  'cardCheckDigitFailed',
  'cardCheckDigitOk',

  // Identities
  'identitySection',
  'identityGroupName',
  'identityGroupContact',
  'identityGroupAddress',
  'identityGroupDocuments',
  'identityFullName',
  'identityFullAddress',
  'identityTitle',
  'identityFirstName',
  'identityMiddleName',
  'identityLastName',
  'identityCompany',
  'identityEmail',
  'identityPhone',
  'identityUsername',
  'identityAddress1',
  'identityAddress2',
  'identityAddress3',
  'identityCity',
  'identityState',
  'identityPostalCode',
  'identityCountry',
  'identitySsn',
  'identityPassportNumber',
  'identityLicenseNumber',

  // Generator
  'genOutputTitle',
  'genRegenerate',
  'genLength',
  'genAvoidAmbiguous',

  // Master-password guard
  'repromptTitle',
  'repromptDetail',
  'repromptThisItem',
  'repromptPlaceholder',
  'repromptUnlock',
  'repromptVerifying',
  'repromptWrongPassword',

  // Passkey sign-in
  'settingsPasskeySection',
  'settingsPasskeyEnable',
  'settingsPasskeyHint',
  'assertionTitle',
  'assertionAsks',
  'assertionChoose',
  'assertionNone',
  'assertionVerify',
  'assertionVerifyHint',
  'assertionConfirm',
  'assertionDecline',
  'assertionRefused',
  'assertionNoneFor',
  'assertionGone',
  'assertionWorking',
  'registrationTitle',
  'registrationAsks',
  'registrationAttach',
  'registrationNewItem',
  'registrationConfirm',
  'registrationDone',
  'registrationVerifyHint',

  // Breach checking
  'settingsBreachSection',
  'settingsBreachEnable',
  'settingsBreachHint',
  'healthBreached',
  'healthBreachedDetail',
  'healthBreachOff',
  'healthBreachChecking',

  // Encrypted export
  'actionExport',
  'exportTitle',
  'exportIntro',
  'exportMaster',
  'exportMasterHint',
  'exportPassphrase',
  'exportPassphraseAgain',
  'exportPassphraseHint',
  'exportMismatch',
  'exportTooShort',
  'exportWrongMaster',
  'exportRun',
  'exportWorking',
  'exportDone',
  'exportAlgorithm',

  // Vault health
  'actionHealth',
  'healthTitle',
  'healthChecking',
  'healthAllGood',
  'healthGuarded',
  'healthReused',
  'healthReusedDetail',
  'healthWeak',
  'healthEchoing',
  'healthStale',
  'healthStaleDetail',
  'healthExpiring',
  'healthDisclaimer',
  'healthDelete',
  'healthDeleteConfirm',
  'healthDeleteHint',
  'healthDeleted',
  'healthReasonShort',
  'healthReasonNotorious',
  'healthReasonRepeated',
  'healthReasonSequence',
  'healthReasonSingleClass',
  'healthReasonEntropy',

  // Offline write queue
  'queueSavedOffline',
  'queuePending',
  'queueHeld',
  'queueHeldDetail',
  'queueDiscard',
  'queueDiscarded',
  'queueSent',

  // Save proposal
  'proposalCreateTitle',
  'proposalUpdateTitle',
  'proposalNoUsername',
  'proposalSave',
  'proposalDismiss',
  'proposalNever',
  'proposalNeverTitle',

  // Progress and errors
  'statusDeriving',
  'statusSyncing',
  'statusEncrypting',
  'statusSaving',
  'statusOpeningVault',
  'statusDecrypting',
  'errorUnknown',
  'errorTimeout',
  'errorServerUnreachable',
  'errorSessionExpired',
  'errorSessionNoRefresh',
  'errorItemNotFound',
  'errorTabMismatch',

  // Settings — server
  'settingsServerSection',
  'settingsInstanceUrl',
  'settingsAccountEmail',
  'settingsDeviceName',
  'settingsNetworkTimeout',

  // Settings — interface
  'settingsInterfaceSection',
  'settingsLanguage',
  'settingsLanguageFollow',
  'settingsLanguageHint',

  // Settings — security
  'settingsSecuritySection',
  'settingsAutoLock',
  'settingsAutoLockHint',
  'settingsLockOnSystemLock',
  'settingsLockOnSystemLockHint',
  'settingsClipboard',
  'settingsClipboardHint',
  'settingsAutoLockOnClose',
  'settingsMinutes1',
  'settingsMinutes5',
  'settingsMinutes15',
  'settingsMinutes30',
  'settingsHours1',
  'settingsHours4',
  'settingsSeconds10',
  'settingsSeconds30',
  'settingsMinute1',
  'settingsNever',

  // Settings — saving credentials
  'settingsSaveSection',
  'settingsOfferToSave',
  'settingsOfferToSaveHint',

  // Settings — actions
  'settingsActionsSection',
  'settingsLockNow',
  'settingsForgetTwoFa',
  'settingsRestoreExcluded',
  'settingsForgetOrdering',
  'settingsDeviceSection',
  'settingsDeviceIdLabel',
  'settingsRegenerateDevice',
  'settingsRegenerateConfirm',
  'settingsVersion',

  // Settings — confirmations
  'settingsSaved',
  'settingsVaultLocked',
  'settingsNoTwoFa',
  'settingsTwoFaForgotten',
  'settingsNoExcluded',
  'settingsExcludedRestored',
  'settingsOrderingForgotten',
  'settingsDeviceRegenerated',
] as const;

export type MessageKey = (typeof MESSAGE_KEYS)[number];

/**
 * The languages shipped, with the name each calls itself.
 *
 * Endonyms, never translated: someone looking for their own language scans this
 * list for the word they know, and "German" is of no help to a reader who only
 * reads Deutsch.
 *
 * `tests/i18n.test.ts` holds this list against the `_locales/` folders on disk,
 * in both directions — a language shipped but unlisted is unreachable, and a
 * language listed but unshipped is a dead entry in the settings.
 */
export const AVAILABLE_LOCALES: ReadonlyArray<readonly [string, string]> = [
  ['en', 'English'],
  ['fr', 'Français'],
];

/** Follow the browser: the value of the setting when nothing is chosen. */
export const FOLLOW_BROWSER = '';

const hasI18n = typeof chrome !== 'undefined' && typeof chrome.i18n?.getMessage === 'function';

/** The chosen catalogue, or `null` while the browser's language is followed. */
let chosen: ReadonlyMap<string, string> | null = null;

/** The raw shape of a `messages.json` entry. */
interface RawMessage {
  readonly message?: unknown;
}

/**
 * Loads the catalogue for `locale`, or goes back to following the browser.
 *
 * Call it **before the first render**: `t` is synchronous, so a catalogue that
 * arrives late would show one language and then flip to another under the
 * reader's eyes.
 *
 * Never throws. A locale that fails to load — a folder removed, a file
 * truncated — leaves the browser's language in place, which is a worse language
 * for that user but a working interface.
 *
 * @param locale A code from {@link AVAILABLE_LOCALES}, or
 *   {@link FOLLOW_BROWSER} to use the browser's own.
 */
export async function applyLocale(locale: string): Promise<void> {
  if (locale === FOLLOW_BROWSER || typeof chrome === 'undefined' || chrome.runtime == null) {
    chosen = null;
    return;
  }
  if (!AVAILABLE_LOCALES.some(([code]) => code === locale)) {
    chosen = null;
    return;
  }
  try {
    const url = chrome.runtime.getURL(`_locales/${locale}/messages.json`);
    const catalogue = (await (await fetch(url)).json()) as Record<string, RawMessage>;
    const messages = new Map<string, string>();
    for (const [key, entry] of Object.entries(catalogue)) {
      if (typeof entry?.message === 'string') {
        messages.set(key, entry.message);
      }
    }
    chosen = messages;
  } catch {
    chosen = null;
  }
}

/**
 * Substitutes `$1`…`$9`, as `chrome.i18n` does.
 *
 * Reimplemented because the chosen catalogue is read directly, outside the API
 * that would normally do it. `$$` is Chrome's escape for a literal `$`; no
 * message uses it, and `tests/i18n.test.ts` keeps it that way rather than have
 * this function grow a case it never exercises.
 */
function substitute(message: string, substitutions: readonly string[]): string {
  return message.replace(/\$([1-9])/g, (whole, digit: string) => {
    const value = substitutions[Number(digit) - 1];
    return value ?? whole;
  });
}

/**
 * The message for `key`, in the chosen language or the browser's.
 *
 * The chain is deliberate: the chosen catalogue, then `chrome.i18n` — which
 * applies Chrome's own fallback to `default_locale` — then the key itself. A
 * partially translated language therefore degrades to English rather than
 * showing raw keys, and the key only ever surfaces outside an extension.
 *
 * @param key A key from {@link MESSAGE_KEYS}.
 * @param substitutions Values for the `$1`…`$9` placeholders, in order.
 * @returns The translated message, or the key outside an extension context.
 */
export function t(key: MessageKey, ...substitutions: string[]): string {
  const override = chosen?.get(key);
  if (override !== undefined && override !== '') {
    return substitute(override, substitutions);
  }
  if (!hasI18n) {
    return key;
  }
  // An empty return means the key is missing from the active locale. Showing the
  // key beats showing nothing: an empty label is a bug one does not see.
  return chrome.i18n.getMessage(key, substitutions) || key;
}
