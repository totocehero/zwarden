/**
 * Déclaration du build par algorithme de hash-wasm.
 *
 * Le paquet n'expose en ESM que `index.esm.js`, monolithique (212 Ko après
 * bundling : tous les algorithmes). Le build `argon2.umd.min.js` (29 Ko) ne
 * contient qu'Argon2 et ses dépendances — c'est lui que Zwarden importe.
 * Selon l'environnement (interop CJS), les exports arrivent nommés ou sous
 * `default` ; `kdf.ts` gère les deux.
 */
declare module 'hash-wasm/dist/argon2.umd.min.js' {
  import type { argon2id } from 'hash-wasm';

  const umd: {
    readonly argon2id?: typeof argon2id;
    readonly default?: { readonly argon2id: typeof argon2id };
  };
  export = umd;
}
