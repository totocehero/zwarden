/**
 * @file Build de l'extension.
 *
 * Cinq entrées : les deux pages HTML (popup, options), le service worker
 * (module ES, nommé `background.js` à la racine de `dist/` pour correspondre
 * au manifest) et le détecteur d'identifiants (`content.js`, injecté à la
 * demande par le worker) et le document hors écran (`offscreen.js`, qui donne
 * au worker l'accès au presse-papiers). `public/` — manifest et
 * `offscreen.html` inclus — est copié tel quel à la racine de `dist/`.
 *
 * Le détecteur ne doit **importer personne** : un script de contenu n'est pas
 * un module ES, un `import` dans le fichier émis le casserait silencieusement
 * en production.
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
        content: 'src/content/detector.ts',
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
          // Nommé à la racine : `offscreen.html`, copié depuis `public/`, le
          // référence par un chemin relatif.
          return chunk.name === 'offscreen' ? 'offscreen.js' : 'assets/[name]-[hash].js';
        },
      },
    },
  },
});
