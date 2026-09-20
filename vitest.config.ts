import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

export default defineConfig({
  // The same aliases the build uses. Without them a test can reach the core
  // modules (which import by relative path) but not a component, which imports
  // by alias — and a rule worth testing is not always in the core.
  resolve: {
    alias: {
      '@core': fileURLToPath(new URL('./src/core', import.meta.url)),
      '@shared': fileURLToPath(new URL('./src/shared', import.meta.url)),
    },
  },
  test: {
    globals: true,
    // WebCrypto is available natively in Node >= 20 through globalThis.crypto,
    // so the crypto core needs no jsdom.
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    // Tests that need a DOM ask for one file by file, through
    // `// @vitest-environment jsdom`: forcing jsdom everywhere would slow down
    // the forty KDF tests, which need nothing but WebCrypto.
    //
    // Transform cache: TypeScript compilation dominated the run time (58 %) and
    // was redone on every launch.
    fsModuleCache: true,
    // The interoperability test's network calls exceed the 5 s default, and
    // PBKDF2 derivation at 600,000 iterations costs about 1 s on its own.
    testTimeout: 60_000,
    hookTimeout: 60_000,
  },
});
