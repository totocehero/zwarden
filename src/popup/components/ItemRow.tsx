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

import { t, type MessageKey } from '@shared/i18n.js';
import type { CardView } from '@core/vault/card.js';
import type { CipherOverview } from '@core/vault/cipherService.js';
import type { IdentityView } from '@core/vault/identity.js';
import type { VaultLabels } from '@core/vault/labels.js';
import type { TotpConfig } from '@core/vault/totp.js';

import { CardPanel } from './CardPanel.js';
import { IdentityPanel } from './IdentityPanel.js';
import { OtpCode } from './OtpCode.js';
import { IconCopy, IconEye, IconOtp, IconPencil } from './Icons.js';
import { TYPE_LABELS } from './itemLabels.js';

/**
 * What the eye reveals, which depends on the type.
 *
 * A login reveals a password, a card its panel, an identity its fields. Making
 * it one union rather than four booleans is what keeps a single auto-hide timer
 * and a single `reprompt` guard covering all of them: a secret shown is a secret
 * shown, whatever its shape.
 */
export type RevealedContent =
  | { readonly kind: 'password'; readonly password: string }
  | { readonly kind: 'card'; readonly card: CardView }
  | { readonly kind: 'identity'; readonly identity: IdentityView }
  | { readonly kind: 'note'; readonly notes: string };

/**
 * What the row's copy button takes, per type.
 *
 * A card's is its number, an identity's its full name — the value one opened the
 * vault for. `null` for a type with no obvious single value.
 */
const PRIMARY_LABELS: Readonly<Record<number, MessageKey>> = {
  2: 'itemNotes',
  3: 'cardNumber',
  4: 'identityFullName',
};

/** Types that have something to reveal behind the eye. */
const REVEALABLE = new Set([1, 2, 3, 4]);

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
  copiedField,
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
  onCopyField,
  onFilter,
}: {
  item: CipherOverview;
  labels: VaultLabels;
  passwordCopied: boolean;
  usernameCopied: boolean;
  /** What is revealed under the row, or `null` while nothing is. */
  revealed: RevealedContent | null;
  /** Label of the detail field copied a moment ago, or `null`. */
  copiedField: string | null;
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
  /** Copies one field of a detail panel. */
  onCopyField: (label: string, value: string) => void;
  onFilter: (needle: string) => void;
}) {
  // Computed once: the call used to be made twice per row per render, once to
  // test for presence and once to render.
  const chips = chipsFor(item, labels);
  const typeLabel = item.type === 1 ? null : (TYPE_LABELS[item.type] ?? null);
  const primaryKey = PRIMARY_LABELS[item.type];
  const primaryLabel = primaryKey === undefined ? null : t(primaryKey);

  return (
    <li>
      <div class="item-row">
        <div class="item-text">
          <div class="item-name" title={item.name ?? ''}>
            {item.name ?? t('itemNoName')}
            {item.hasPasskey && <span class="badge">{t('itemPasskeyBadge')}</span>}
            {typeLabel !== null && <span class="badge badge-type">{t(typeLabel)}</span>}
          </div>
          {/* What tells two cards or two identities apart — a masked card, a
              full name. Not clickable: copying `•••• 4242` helps nobody. */}
          {item.subtitle !== null && <div class="item-sub">{item.subtitle}</div>}
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
        {REVEALABLE.has(item.type) && (
          <button
            class="quiet eye-item"
            title={
              revealed !== null
                ? item.type === 1
                  ? t('itemHidePassword')
                  : t('itemHideDetails')
                : item.type === 1
                  ? t('itemShowPassword')
                  : t('itemShowDetails')
            }
            onClick={onToggleReveal}
          >
            <IconEye struck={revealed !== null} />
          </button>
        )}
        <button class="quiet eye-item" title={t('itemEdit')} onClick={onEdit}>
          <IconPencil />
        </button>
        {(item.type === 1 || primaryLabel !== null) && (
          <button
            class={`icon${passwordCopied ? ' copied-ok' : ''}`}
            title={
              primaryLabel === null
                ? passwordCopied
                  ? t('itemPasswordCopied')
                  : t('itemCopyPassword')
                : passwordCopied
                  ? t('itemFieldCopied', primaryLabel)
                  : t('itemCopyField', primaryLabel)
            }
            onClick={onCopyPassword}
          >
            <IconCopy done={passwordCopied} />
          </button>
        )}
        {fillable && (
          <button class="fill" title={t('itemFillTitle')} onClick={onFill}>
            {t('itemFill')}
          </button>
        )}
      </div>
      {revealed !== null && revealed.kind === 'password' && (
        <div class="secret">{revealed.password}</div>
      )}
      {revealed !== null && revealed.kind === 'note' && (
        <div class="secret secret-note">{revealed.notes}</div>
      )}
      {revealed !== null && revealed.kind === 'card' && (
        <CardPanel card={revealed.card} copiedField={copiedField} onCopy={onCopyField} />
      )}
      {revealed !== null && revealed.kind === 'identity' && (
        <IdentityPanel
          identity={revealed.identity}
          copiedField={copiedField}
          onCopy={onCopyField}
        />
      )}
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
