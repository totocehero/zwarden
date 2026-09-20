/**
 * @file Filter chips by item type, above the search box.
 *
 * Search answers "where is the item I am thinking of"; these chips answer "show
 * me my cards" — a different question, and one a text box answers badly, since
 * nothing in a card's name says it is a card.
 *
 * The selection is **several types at once**: a vault is not consulted one
 * category at a time, and "logins and cards, not my notes" is a reasonable thing
 * to want. An empty selection means everything — which is also what the last
 * chip being switched off falls back to, rather than an empty list.
 *
 * Two deliberate restraints:
 *
 * - **only the types actually held are offered.** A vault with no identity gains
 *   nothing from a chip that filters to nothing, and every chip shown for a type
 *   that is absent is one more thing to read past;
 * - **the bar disappears below two types.** A vault of logins alone would get a
 *   row of controls whose every state shows the same list.
 */

import { t } from '@shared/i18n.js';

import { TYPE_LABELS } from './itemLabels.js';

/**
 * The order the chips are laid out in — the order the types are used, not the
 * order the API numbers them.
 */
const FILTER_ORDER: readonly number[] = [1, 3, 4, 2, 5];

/**
 * Which chips the bar shows, given what the vault holds.
 *
 * Separated from the rendering because it is the only rule here worth being
 * sure of, and a rule pinned by a test is worth more than one read off a JSX
 * expression.
 *
 * @param counts How many items of each type the vault holds.
 * @returns The types to offer, in display order — **empty** below two, where a
 *   filter bar would be a row of controls that all show the same list.
 */
export function chipsToShow(counts: ReadonlyMap<number, number>): readonly number[] {
  const present = FILTER_ORDER.filter((type) => (counts.get(type) ?? 0) > 0);
  return present.length < 2 ? [] : present;
}

/**
 * Switches one type in or out of the selection.
 *
 * Switching the last one off empties the selection, which shows everything
 * again — never nothing. An interface whose only escape from an empty list is
 * to guess which chip to press again would be a trap.
 *
 * @param selected The types currently shown; empty means all of them.
 * @param type The type whose chip was clicked.
 * @returns The new selection.
 */
export function toggleType(selected: ReadonlySet<number>, type: number): ReadonlySet<number> {
  const next = new Set(selected);
  if (!next.delete(type)) {
    next.add(type);
  }
  return next;
}

export function TypeFilter({
  counts,
  selected,
  onSelect,
}: {
  /** How many items of each type the vault holds. Absent types are not listed. */
  counts: ReadonlyMap<number, number>;
  /** The types shown. Empty means every type. */
  selected: ReadonlySet<number>;
  onSelect: (types: ReadonlySet<number>) => void;
}) {
  const present = chipsToShow(counts);
  if (present.length === 0) {
    return null;
  }

  return (
    <div class="type-filter">
      <button
        class={`chip chip-type-filter${selected.size === 0 ? ' chip-on' : ''}`}
        title={t('filterShowAll')}
        onClick={() => onSelect(new Set())}
      >
        {t('filterAll')}
      </button>
      {present.map((type) => {
        const label = t(TYPE_LABELS[type] ?? 'typeLogin');
        const on = selected.has(type);
        return (
          <button
            key={type}
            class={`chip chip-type-filter${on ? ' chip-on' : ''}`}
            title={on ? t('filterHideType', label) : t('filterShowType', label)}
            // The same gesture undoes itself: no hunting for the "All" chip to
            // get back to where one was.
            onClick={() => onSelect(toggleType(selected, type))}
          >
            {t('filterCount', label, String(counts.get(type) ?? 0))}
          </button>
        );
      })}
    </div>
  );
}
