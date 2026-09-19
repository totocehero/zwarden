/**
 * @file One row of the vault.
 *
 * Purely presentational: the row receives an already-decrypted item and boolean
 * flags, and raises gestures. It knows how to neither decrypt, nor copy, nor
 * what a `reprompt` guard is — `App` decides whether a gesture goes through.
 *
 * It is also what lets the one-time code beat once a second without re-rendering
 * the whole popup: {@link OtpCode} owns its own state, and the row passes it only
 * stable parameters.
 */

import { t } from '@shared/i18n.js';
import type { CipherOverview } from '@core/vault/cipherService.js';
import type { VaultLabels } from '@core/vault/labels.js';
import type { TotpConfig } from '@core/vault/totp.js';

import { OtpCode } from './OtpCode.js';
import { IconCopy, IconEye, IconOtp, IconPencil } from './Icons.js';

/** A tag displayable on an item: a folder or a collection. */
export interface Chip {
  readonly kind: 'folder' | 'collection';
  readonly name: string;
  readonly title: string;
}

/** An item's tags, names resolved through the vault's labels. */
export function chipsFor(item: CipherOverview, labels: VaultLabels): Chip[] {
  const chips: Chip[] = [];
  if (item.folderId !== null) {
    const name = labels.folders.get(item.folderId);
    if (name !== undefined) {
      chips.push({ kind: 'folder', name, title: t('itemChipFolder', name) });
    }
  }
  for (const collectionId of item.collectionIds) {
    const collection = labels.collections.get(collectionId);
    if (collection !== undefined) {
      const org =
        collection.organizationId !== null
          ? labels.organizations.get(collection.organizationId)
          : undefined;
      chips.push({
        kind: 'collection',
        name: collection.name,
        title: t(
          'itemChipCollection',
          org ?? t('itemOrganisation'),
          collection.readOnly ? t('itemChipReadOnly') : '',
        ),
      });
    }
  }
  return chips;
}

export function ItemRow({
  item,
  labels,
  passwordCopied,
  usernameCopied,
  revealed,
  otp,
  otpCopied,
  fillable,
  onCopyUsername,
  onCopyPassword,
  onToggleReveal,
  onToggleOtp,
  onEdit,
  onFill,
  onCopyOtp,
  onFilter,
}: {
  item: CipherOverview;
  labels: VaultLabels;
  passwordCopied: boolean;
  usernameCopied: boolean;
  /** The revealed password, or `null` while it is hidden. */
  revealed: string | null;
  /**
   * The open one-time code — its parameters and the code already copied — or
   * `null` while it is closed.
   */
  otp: { readonly config: TotpConfig; readonly code: string } | null;
  otpCopied: boolean;
  /** True if the active tab's origin matches: gates the "Fill" button. */
  fillable: boolean;
  onCopyUsername: () => void;
  onCopyPassword: () => void;
  onToggleReveal: () => void;
  onToggleOtp: () => void;
  onEdit: () => void;
  onFill: () => void;
  onCopyOtp: (code: string) => void;
  onFilter: (needle: string) => void;
}) {
  // Computed once: the call used to be made twice per row per render, once to
  // test for presence and once to render.
  const chips = chipsFor(item, labels);

  return (
    <li>
      <div class="item-row">
        <div class="item-text">
          <div class="item-name" title={item.name ?? ''}>
            {item.name ?? t('itemNoName')}
            {item.hasPasskey && <span class="badge">{t('itemPasskeyBadge')}</span>}
          </div>
          {item.username !== null && (
            <div class="item-user" title={t('itemCopyUsername', item.username)} onClick={onCopyUsername}>
              {item.username}
              {usernameCopied ? t('itemUsernameCopied') : ''}
            </div>
          )}
          {item.uris[0] !== undefined && <div class="item-uri">{item.uris[0]}</div>}
          {chips.length > 0 && (
            <div class="chips">
              {chips.map((chip) => (
                <button
                  key={`${chip.kind}:${chip.name}`}
                  class={`chip chip-${chip.kind}`}
                  title={t('itemChipFilter', chip.title)}
                  onClick={() => onFilter(chip.name)}
                >
                  {chip.kind === 'folder' ? `#${chip.name}` : `@${chip.name}`}
                </button>
              ))}
            </div>
          )}
        </div>
        {item.hasTotp && (
          <button
            class="quiet eye-item"
            title={otp !== null ? t('itemHideOtp') : t('itemShowOtp')}
            onClick={onToggleOtp}
          >
            <IconOtp />
          </button>
        )}
        <button
          class="quiet eye-item"
          title={revealed !== null ? t('itemHidePassword') : t('itemShowPassword')}
          onClick={onToggleReveal}
        >
          <IconEye struck={revealed !== null} />
        </button>
        <button class="quiet eye-item" title={t('itemEdit')} onClick={onEdit}>
          <IconPencil />
        </button>
        <button
          class={`icon${passwordCopied ? ' copie-ok' : ''}`}
          title={passwordCopied ? t('itemPasswordCopied') : t('itemCopyPassword')}
          onClick={onCopyPassword}
        >
          <IconCopy done={passwordCopied} />
        </button>
        {fillable && (
          <button class="fill" title={t('itemFillTitle')} onClick={onFill}>
            {t('itemFill')}
          </button>
        )}
      </div>
      {revealed !== null && <div class="secret">{revealed}</div>}
      {otp !== null && (
        <OtpCode
          config={otp.config}
          initialCode={otp.code}
          copied={otpCopied}
          onCopy={onCopyOtp}
        />
      )}
    </li>
  );
}
