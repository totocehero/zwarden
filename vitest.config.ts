import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    // WebCrypto est disponible nativement dans Node >= 20 via globalThis.crypto,
    // donc pas besoin de jsdom pour le noyau crypto.
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    // Les tests qui ont besoin d'un DOM le demandent fichier par fichier, par
    // `// @vitest-environment jsdom` : imposer jsdom partout ralentirait les
    // quarante tests de KDF, qui n'ont besoin que de WebCrypto.
    //
    // Cache de transformation : la compilation TypeScript dominait le temps
    // d'exécution (58 %) et était refaite à chaque lancement.
    fsModuleCache: true,
    // Les appels réseau du test d'interopérabilité dépassent le défaut de 5 s,
    // et la dérivation PBKDF2 à 600 000 itérations coûte à elle seule ~1 s.
    testTimeout: 60_000,
    hookTimeout: 60_000,
  },
});
