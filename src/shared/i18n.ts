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

const hasI18n = typeof chrome !== 'undefined' && typeof chrome.i18n?.getMessage === 'function';

/**
 * The message for `key`, in the browser's language.
 *
 * @param key A key from {@link MESSAGE_KEYS}.
 * @param substitutions Values for the `$1`…`$9` placeholders, in order.
 * @returns The translated message, or the key outside an extension context.
 */
export function t(key: MessageKey, ...substitutions: string[]): string {
  if (!hasI18n) {
    return key;
  }
  // An empty return means the key is missing from the active locale. Showing the
  // key beats showing nothing: an empty label is a bug one does not see.
  return chrome.i18n.getMessage(key, substitutions) || key;
}
