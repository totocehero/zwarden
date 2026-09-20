/**
 * @file The two halves of the passkey hook agree on what to say to each other.
 *
 * The hook runs in the page's world, the bridge in the isolated one, and they
 * reach each other only by matching a message name. They cannot share a module
 * to define it: a content script is not an ES module, and a bundler asked to
 * share code between two entries emits exactly the `import` that would fail at
 * load. So the strings are written out twice, and this is what stops them
 * drifting.
 *
 * A rename on one side alone fails **silently**: the page waits, times out,
 * falls back to the browser, and looks for all the world like a user who has
 * no passkey for that site. Nothing throws, nothing is logged, and the feature
 * is simply gone.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const read = (name: string): string =>
  readFileSync(fileURLToPath(new URL(`../src/content/${name}`, import.meta.url)), 'utf8');

const hook = read('webauthnHook.ts');
const bridge = read('webauthnBridge.ts');

/** The value a file gives a `const`, or `undefined`. */
function literal(source: string, name: string): string | undefined {
  return new RegExp(`const ${name} = '([^']*)'`).exec(source)?.[1];
}

describe('the hook and the bridge', () => {
  it.each(['TO_EXTENSION', 'FROM_EXTENSION'])('agree on %s', (name) => {
    const inHook = literal(hook, name);
    expect(inHook).toBeDefined();
    expect(literal(bridge, name)).toBe(inHook);
  });

  it('name the port the same way the bridge opens it', () => {
    // Only the bridge holds it: the hook never opens a port.
    expect(literal(bridge, 'PORT_NAME')).toBe('zwarden-webauthn');
  });

  it('both refuse a message from another frame', () => {
    // A frame answering for its parent, or asking on its behalf, is the one
    // thing `postMessage` makes easy and must not be allowed.
    expect(hook).toContain('event.source !== window');
    expect(bridge).toContain('event.source !== window');
  });

  it('both address their replies to the page origin, never to a wildcard', () => {
    // `postMessage(..., '*')` would put an assertion on any listener's doorstep.
    expect(hook).toContain('window.location.origin');
    expect(bridge).toContain('window.location.origin');
    expect(hook).not.toMatch(/postMessage\([^)]*,\s*'\*'/);
    expect(bridge).not.toMatch(/postMessage\([^)]*,\s*'\*'/);
  });

  it('the hook keeps the browser as its fallback', () => {
    // Swallowing the cases it cannot serve would make every passkey sign-in on
    // the machine depend on this extension being right.
    expect(hook).toContain('return original(options)');
  });
});
