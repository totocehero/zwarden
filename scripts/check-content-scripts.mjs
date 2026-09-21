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
  // Anywhere, not at the start of a line.
  //
  // This check was first written as `/^\s*import/m` and passed a bundle whose
  // very first statement was an `import` — because the wrapper added in the
  // same commit put the whole file on one line, and the anchor never matched
  // again. The guard meant to prevent exactly this failure reported success
  // while shipping it.
  const importer = /(^|[;{\s])import\s*[{*'"(]|(^|[;{\s])import\s+[A-Za-z_$]/.exec(code);
  if (importer !== null) {
    console.error(
      `✗ ${name}: imports (\`${code.slice(importer.index, importer.index + 40).trim()}…\`),` +
        ' which cannot be resolved where it runs',
    );
    failed = true;
  }
  if (!failed) {
    console.log(`✓ ${name}: self-contained, declares nothing`);
  }
}

process.exit(failed ? 1 : 0);
