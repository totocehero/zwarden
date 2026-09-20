// @vitest-environment jsdom
/**
 * @file The health report's screen.
 *
 * Written because a user asked "are you sure the test passes?" about a button
 * that had stopped working, and the honest answer was that five hundred tests
 * said nothing about it: not one of them rendered a component. A rule that
 * only lives in a component is still a rule.
 *
 * Outside an extension `t()` returns the message key, so the assertions here
 * are on keys rather than on French or English — which is also what keeps them
 * from breaking every time a wording is improved.
 *
 * Every click goes through `act`, awaited: Preact defers a state update to a
 * microtask, so reading the DOM straight after a click reads the frame before
 * it. Without it these tests fail for a reason that has nothing to do with the
 * code — and `act` returns a thenable, so dropping it would be the same bug
 * one level up.
 */

import { render } from 'preact';
import { act } from 'preact/test-utils';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { HealthReport } from '../src/core/vault/health.js';
import { HealthPanel } from '../src/popup/components/HealthPanel.js';

function report(patch: Partial<HealthReport> = {}): HealthReport {
  return {
    checked: 3,
    guarded: 0,
    reused: [],
    weak: [],
    echoing: [],
    stale: [],
    expiring: [],
    ...patch,
  };
}

const STALE = {
  id: 'i1',
  name: 'Old forum',
  uri: 'https://forum.example.org/',
  days: 2190,
};

let container: HTMLDivElement | undefined;

afterEach(() => {
  if (container !== undefined) {
    render(null, container);
    container.remove();
    container = undefined;
  }
});

/** Mounts the panel and hands back its root. */
function mount(props: Partial<Parameters<typeof HealthPanel>[0]> = {}): HTMLDivElement {
  container = document.createElement('div');
  document.body.append(container);
  render(
    <HealthPanel
      report={report()}
      onBack={() => undefined}
      onDelete={() => undefined}
      onOpen={() => undefined}
      {...props}
    />,
    container,
  );
  return container;
}

/** The button whose label is exactly `label`. */
function button(root: HTMLElement, label: string): HTMLButtonElement | undefined {
  return [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === label);
}

describe('the discard button', () => {
  it('is there on a stale row', () => {
    const root = mount({ report: report({ stale: [STALE] }) });
    expect(button(root, 'healthDelete')).toBeDefined();
  });

  it('asks before acting', async () => {
    const onDelete = vi.fn();
    const root = mount({ report: report({ stale: [STALE] }), onDelete });

    await act(() => button(root, 'healthDelete')!.click());

    // The first click arms and must not delete anything.
    expect(onDelete).not.toHaveBeenCalled();
    expect(button(root, 'healthDeleteConfirm')).toBeDefined();
  });

  it('acts on the second click', async () => {
    const onDelete = vi.fn();
    const root = mount({ report: report({ stale: [STALE] }), onDelete });

    await act(() => button(root, 'healthDelete')!.click());
    await act(() => button(root, 'healthDeleteConfirm')!.click());

    expect(onDelete).toHaveBeenCalledWith('i1');
  });

  /**
   * The regression that prompted this whole file.
   *
   * The first version disarmed on `mouseleave`. "Confirm" is half the width of
   * "Move to the trash", so arming shrank the button out from under the
   * pointer, the event fired, and it disarmed before it could be clicked. An
   * element that resizes cannot use the pointer leaving it as a signal.
   */
  it('stays armed when the pointer leaves it', async () => {
    const root = mount({ report: report({ stale: [STALE] }) });

    const armed = button(root, 'healthDelete')!;
    await act(() => armed.click());
    await act(() => {
      armed.dispatchEvent(new MouseEvent('mouseleave', { bubbles: true }));
    });

    expect(button(root, 'healthDeleteConfirm')).toBeDefined();
  });
});

describe('opening the site', () => {
  it('offers a link when the item has one', async () => {
    const onOpen = vi.fn();
    const root = mount({ report: report({ stale: [STALE] }), onOpen });

    await act(() => button(root, 'Old forum')!.click());

    expect(onOpen).toHaveBeenCalledWith('https://forum.example.org/');
  });

  it('shows plain text when there is nothing safe to open', () => {
    // `openableUri` has already refused `javascript:` and the rest upstream; a
    // row with no URI must not become a link to nowhere.
    const root = mount({ report: report({ stale: [{ ...STALE, uri: null }] }) });

    expect(button(root, 'Old forum')).toBeUndefined();
    expect(root.textContent).toContain('Old forum');
  });
});

describe('the groups', () => {
  it('start folded, with their count on show', () => {
    const root = mount({
      report: report({ stale: [STALE, { ...STALE, id: 'i2', name: 'Old shop' }] }),
    });

    const group = root.querySelector('details.health-group');
    expect(group).not.toBeNull();
    // Folded: five categories opened flat is a wall one scrolls past.
    expect((group as HTMLDetailsElement).open).toBe(false);
    expect(group!.querySelector('.health-group-count')!.textContent).toBe('2');
  });

  it('shows nothing for a category with no findings', () => {
    const root = mount({ report: report({ stale: [STALE] }) });
    expect(root.querySelectorAll('details.health-group')).toHaveLength(1);
  });

  it('says so when there is nothing at all to report', () => {
    const root = mount();
    expect(root.querySelector('.empty')).not.toBeNull();
  });

  it('never claims coverage it does not have', () => {
    const root = mount({ report: report({ guarded: 4 }) });
    expect(root.textContent).toContain('healthGuarded');
  });
});
