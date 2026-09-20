/**
 * Holds the injected bundles to the two rules a content script must obey.
 *
 * 1. **It declares nothing.** A content script is injected as a classic script,
 *    not a module, so a top-level `const` lands in a shared global scope — the
 *    one every isolated-world script of this extension shares, or, for a
 *    main-world script, the page's own. Minified bundles name their constants
 *    `a` and `l`, so a collision is not a risk but a certainty. It surfaces as
 *    a parse error: the script never runs, logs nothing, and is indistinguishable
 *    from one that was never injected.
 * 2. **It imports nothing.** There is no module loader on the other side; an
 *    `import` is a runtime failure, and a bundler asked to share code between
 *    two entries emits exactly that.
 *
 * Both have already gone wrong once. Run by `npm run size` in CI.
 */

import { readFileSync } from 'node:fs';

const SCRIPTS = ['content.js', 'webauthnHook.js', 'webauthnBridge.js'];
const DIST = new URL('../dist/', import.meta.url);

let failed = false;

for (const name of SCRIPTS) {
  let code;
  try {
    code = readFileSync(new URL(name, DIST), 'utf8');
  } catch {
    console.error(`✗ ${name}: missing from dist/`);
    failed = true;
    continue;
  }

  if (!code.startsWith('(()=>{') && !code.startsWith('(function')) {
    console.error(`✗ ${name}: not wrapped — its declarations reach a shared global scope`);
    failed = true;
  }
  if (/^\s*import[\s{*'"]/m.test(code)) {
    console.error(`✗ ${name}: contains an import, which cannot be resolved where it runs`);
    failed = true;
  }
  if (!failed) {
    console.log(`✓ ${name}: self-contained, declares nothing`);
  }
}

process.exit(failed ? 1 : 0);
