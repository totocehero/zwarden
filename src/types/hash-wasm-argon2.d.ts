/**
 * Declaration for hash-wasm's per-algorithm build.
 *
 * In ESM the package only exposes `index.esm.js`, which is monolithic (212 KB
 * once bundled: every algorithm). The `argon2.umd.min.js` build (29 KB) contains
 * Argon2 and its dependencies alone — that is the one Zwarden imports. Depending
 * on the environment (CJS interop), the exports arrive either named or under
 * `default`; `kdf.ts` handles both.
 */
declare module 'hash-wasm/dist/argon2.umd.min.js' {
  import type { argon2id } from 'hash-wasm';

  const umd: {
    readonly argon2id?: typeof argon2id;
    readonly default?: { readonly argon2id: typeof argon2id };
  };
  export = umd;
}
