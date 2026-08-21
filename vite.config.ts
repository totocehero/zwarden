/**
 * @file Build de l'extension.
 *
 * Deux entrées : la popup (page HTML) et le service worker (module ES, nommé
 * `background.js` à la racine de `dist/` pour correspondre au manifest).
 * `public/` — manifest inclus — est copié tel quel à la racine de `dist/`.
 *
 * Charger dans Chrome : `chrome://extensions` → mode développeur → « Charger
 * l'extension non empaquetée » → sélectionner `dist/`.
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
    // Pas de polyfill de préchargement : les pages d'extension chargent en
    // local, le préchargement n'apporte rien et pèse.
    modulePreload: false,
    rollupOptions: {
      input: {
        popup: 'src/popup/index.html',
        options: 'src/options/index.html',
        background: 'src/background/main.ts',
      },
      output: {
        entryFileNames: (chunk) =>
          chunk.name === 'background' ? 'background.js' : 'assets/[name]-[hash].js',
      },
    },
  },
});
