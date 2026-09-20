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
import { defineConfig } from 'vite';

export default defineConfig({
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
