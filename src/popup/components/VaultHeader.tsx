/**
 * @file The vault's header bar.
 *
 * Extracted for one reason: it is drawn twice — once while the vault is still
 * being decrypted, once over the list — and two copies of a header are two
 * chances for them to differ by a few pixels. They did: `button.quiet` stands
 * five pixels taller than the title alone, so a header that gained its buttons
 * on arrival pushed the search box down just as the user reached for it.
 *
 * ## Why only two actions are out in the open
 *
 * Four hundred and twenty pixels hold two labelled buttons and a title, and
 * that is all. Creating and generating are the two one reaches for without
 * thinking; the rest — the health report, the export, the settings, locking —
 * are deliberate acts, and a deliberate act can afford one more click.
 *
 * The alternative tried first was letting five buttons wrap onto a second row.
 * It worked and it looked like a mistake.
 */

import { useEffect, useRef, useState } from 'preact/hooks';

import { t, type MessageKey } from '@shared/i18n.js';

import { IconMenu } from './Icons.js';

/** One entry of the menu. A `null` action renders it disabled. */
export interface MenuAction {
  readonly key: string;
  readonly label: MessageKey;
  readonly run: (() => void) | undefined;
}

export function VaultHeader({
  canCreate,
  onNew,
  onGenerate,
  actions,
}: {
  /** False while the vault is still opening: there is nothing to save into yet. */
  canCreate: boolean;
  onNew: () => void;
  onGenerate: () => void;
  /** What the menu holds, in order. */
  actions: readonly MenuAction[];
}) {
  const [open, setOpen] = useState(false);
  const menu = useRef<HTMLDivElement | null>(null);

  /**
   * Closes on a click anywhere else, and on Escape.
   *
   * Registered only while the menu is open: a popup that listens to every click
   * in order to do nothing is a popup that pays for a feature nobody is using.
   */
  useEffect(() => {
    if (!open) {
      return;
    }
    const onPointer = (event: MouseEvent): void => {
      if (menu.current !== null && !menu.current.contains(event.target as Node)) {
        setOpen(false);
      }
    };
    const onKey = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', onPointer);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onPointer);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  return (
    <header>
      <h1>Zwarden</h1>
      <div class="header-actions">
        <button class="quiet" title={t('newItemTitle')} disabled={!canCreate} onClick={onNew}>
          {t('newItem')}
        </button>
        <button class="quiet" title={t('editGeneratePassword')} onClick={onGenerate}>
          {t('actionGenerate')}
        </button>
        <div class="menu" ref={menu}>
          <button
            class="quiet menu-button"
            title={t('actionMenu')}
            aria-haspopup="menu"
            aria-expanded={open}
            onClick={() => setOpen(!open)}
          >
            <IconMenu />
          </button>
          {open && (
            <div class="menu-items" role="menu">
              {actions.map((action) => (
                <button
                  key={action.key}
                  role="menuitem"
                  disabled={action.run === undefined}
                  onClick={() => {
                    setOpen(false);
                    action.run?.();
                  }}
                >
                  {t(action.label)}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
