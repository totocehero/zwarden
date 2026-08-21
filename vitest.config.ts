import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    // WebCrypto est disponible nativement dans Node >= 20 via globalThis.crypto,
    // donc pas besoin de jsdom pour le noyau crypto.
    environment: 'node',
    include: ['tests/**/*.test.ts'],
  },
});
