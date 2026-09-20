/**
 * @file The extension's build.
 *
 * Five entry points: the two HTML pages (popup, options), the service worker
 * (an ES module, named `background.js` at the root of `dist/` to match the
 * manifest), the credential detector (`content.js`, injected on demand by the
 * worker) and the offscreen document (`offscreen.js`, which gives the worker
 * access to the clipboard). `public/` — manifest and `offscreen.html`
 * included — is copied as-is to the root of `dist/`.
 *
 * The detector must **import nobody**: a content script is not an ES module, and
 * an `import` in the emitted file would break it silently in production.
 *
 * Loading it in Chrome: `chrome://extensions` → developer mode → "Load unpacked"
 * → select `dist/`.
 */

import { fileURLToPath } from 'node:url';
import { defineConfig, type PluginOption } from 'vite';

/** The bundles injected into pages, which must declare nothing globally. */
const CONTENT_SCRIPTS = new Set(['content.js', 'webauthnHook.js', 'webauthnBridge.js']);

/**
 * Wraps each content script in a function, so it declares nothing at all.
 *
 * A content script is injected as a classic script, not as a module, so its
 * top-level `const` lands in a global scope it shares with others. Two of them
 * share it in two different directions, and both went wrong:
 *
 * - every isolated-world script of an extension shares **one** scope, so the
 *   detector and the passkey bridge — minified to `const a` and `const a` —
 *   collided with each other;
 * - a main-world script shares the **page's** scope, so the passkey hook
 *   collided with the page itself and with every other extension injecting
 *   there.
 *
 * The failure is a parse error: the script never runs, nothing it would have
 * logged is logged, and it looks exactly like a script that was never injected.
 * That cost several rounds of looking for the fault somewhere else.
 *
 * Rollup cannot emit one format for some entries and another for the rest, and
 * a second build for three small files is more machinery than the problem
 * deserves. These files import nothing — `scripts/check-content-scripts.mjs`
 * holds them to it — so wrapping them is safe.
 */
function wrapContentScripts(): PluginOption {
  return {
    name: 'zwarden-wrap-content-scripts',
    generateBundle(_options, bundle) {
      for (const [name, chunk] of Object.entries(bundle)) {
        if (CONTENT_SCRIPTS.has(name) && chunk.type === 'chunk') {
          chunk.code = `(()=>{${chunk.code}})();`;
        }
      }
    },
  };
}

export default defineConfig({
  plugins: [wrapContentScripts()],
  resolve: {
    alias: {
      '@core': fileURLToPath(new URL('./src/core', import.meta.url)),
      '@shared': fileURLToPath(new URL('./src/shared', import.meta.url)),
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'es2022',
    // No preload polyfill: extension pages load locally, so preloading brings
    // nothing and weighs something.
    modulePreload: false,
    rollupOptions: {
      input: {
        popup: 'src/popup/index.html',
        options: 'src/options/index.html',
        background: 'src/background/main.ts',
        content: 'src/content/detector.ts',
        // Two entries, because they run in two different JavaScript worlds:
        // the hook replaces a function in the page's own context, the bridge
        // is the only one that can reach `chrome.runtime`.
        webauthnHook: 'src/content/webauthnHook.ts',
        webauthnBridge: 'src/content/webauthnBridge.ts',
        offscreen: 'src/offscreen/main.ts',
      },
      output: {
        entryFileNames: (chunk) => {
          if (chunk.name === 'background') {
            return 'background.js';
          }
          if (chunk.name === 'content') {
            return 'content.js';
          }
          if (chunk.name.startsWith('webauthn')) {
            // At the root and unhashed: the worker registers them by path.
            return `${chunk.name}.js`;
          }
          // Named at the root: `offscreen.html`, copied from `public/`,
          // references it by a relative path.
          return chunk.name === 'offscreen' ? 'offscreen.js' : 'assets/[name]-[hash].js';
        },
      },
    },
  },
});
