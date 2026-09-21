/**
 * @file Makes `chrome.*` mean the same thing in Firefox as in Chrome.
 *
 * Imported for its effect, before anything else, in every entry point.
 *
 * ## The one difference that matters
 *
 * Firefox ships two namespaces. `browser.*` returns promises, as the
 * WebExtensions standard says; `chrome.*` is the Chrome-compatible alias and
 * takes callbacks. This codebase has sixty-seven `await chrome.…` calls, and
 * every one of them would await a value that is not a promise — resolving
 * immediately to `undefined`, silently, with no error anywhere.
 *
 * That failure is the worst kind: a vault that reads as empty, a session that
 * reads as absent, settings that read as defaults. Nothing throws, so nothing
 * points at the cause.
 *
 * So in Firefox, `chrome` is made to *be* `browser`. One assignment, at the
 * top of each entry, and the rest of the code stays written once.
 *
 * ## Why not write `browser.*` everywhere instead
 *
 * Because Chrome has no `browser`, and a codebase that reaches for whichever
 * exists at each call site is a codebase that has the problem in sixty-seven
 * places rather than one.
 */

interface WithNamespaces {
  chrome?: unknown;
  browser?: unknown;
}

const globals = globalThis as WithNamespaces;

// Only when `browser` is genuinely there and is not already what `chrome` is:
// Chrome defines neither, and some environments alias them already.
if (globals.browser !== undefined && globals.browser !== globals.chrome) {
  globals.chrome = globals.browser;
}

export {};
