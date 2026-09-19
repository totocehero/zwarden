/**
 * @file One line of a detail panel: a label, a value, and what can be done to it.
 *
 * The primitive both the card and the identity panels are built from. It owns
 * one piece of state and one only — whether a masked value is currently
 * revealed — because that is a purely visual decision, local to the line, and
 * made after the `reprompt` guard has already let the user through. Copying, by
 * contrast, touches the clipboard and its timers: it is raised to `App`.
 *
 * A field with no value renders nothing at all. An identity has eighteen fields
 * and a real one fills in six; showing the other twelve as empty rows is
 * precisely what makes Bitwarden's panel unreadable.
 */

import { useState } from 'preact/hooks';

import { t } from '@shared/i18n.js';

import { IconCopy, IconEye } from './Icons.js';

/** How many bullets stand in for a concealed value, at most. */
const MASK_WIDTH = 12;

/** The default concealed form: bullets, never the real length beyond a point. */
function bullets(value: string): string {
  return '•'.repeat(Math.min(value.length, MASK_WIDTH));
}

export function DetailField({
  label,
  value,
  sensitive = false,
  mono = false,
  masked,
  copied,
  onCopy,
}: {
  label: string;
  /** The value. An empty or absent value renders nothing. */
  value: string | null;
  /** Conceal the value until the user asks for it. */
  sensitive?: boolean;
  /** Render in a monospaced face — for numbers read digit by digit. */
  mono?: boolean;
  /**
   * What to show while concealed. A card shows its last four digits, which is
   * what tells two cards apart without revealing either.
   */
  masked?: string;
  /** True just after this field was copied. */
  copied: boolean;
  /** Copies the **whole** value, revealed or not. */
  onCopy: () => void;
}) {
  const [revealed, setRevealed] = useState(false);

  if (value === null || value.trim() === '') {
    return null;
  }

  const shown = !sensitive || revealed ? value : (masked ?? bullets(value));

  return (
    <div class="detail-field">
      <div class="detail-label">{label}</div>
      <div class={`detail-value${mono ? ' mono' : ''}`}>{shown}</div>
      {sensitive && (
        <button
          class="quiet eye-item"
          type="button"
          title={revealed ? t('itemConceal') : t('itemReveal')}
          onClick={() => setRevealed(!revealed)}
        >
          <IconEye struck={revealed} />
        </button>
      )}
      <button
        class={`icon${copied ? ' copied-ok' : ''}`}
        type="button"
        title={copied ? t('itemFieldCopied', label) : t('itemCopyField', label)}
        onClick={onCopy}
      >
        <IconCopy done={copied} />
      </button>
    </div>
  );
}

/**
 * A multi-line block — a postal address — with a single copy action.
 *
 * Copying an address line by line is the kind of small friction that makes a
 * feature go unused; the block is copied whole, newlines included, which is what
 * a delivery form expects.
 */
export function DetailBlock({
  label,
  lines,
  copied,
  onCopy,
}: {
  label: string;
  lines: readonly string[];
  copied: boolean;
  onCopy: () => void;
}) {
  if (lines.length === 0) {
    return null;
  }
  return (
    <div class="detail-field">
      <div class="detail-label">{label}</div>
      <div class="detail-value">
        {lines.map((line, index) => (
          <div key={index}>{line}</div>
        ))}
      </div>
      <button
        class={`icon${copied ? ' copied-ok' : ''}`}
        type="button"
        title={copied ? t('itemFieldCopied', label) : t('itemCopyField', label)}
        onClick={onCopy}
      >
        <IconCopy done={copied} />
      </button>
    </div>
  );
}
