/**
 * @file ESLint configuration ("flat" format, ESLint 9).
 *
 * ## What the linter has to do here, and what it does not
 *
 * `tsconfig.json` is already severe — `strict`, `noUncheckedIndexedAccess`,
 * `exactOptionalPropertyTypes`, `noUnusedLocals`. Typing is therefore covered,
 * and asking the linter again for what the compiler already refuses would only
 * double the messages.
 *
 * That leaves two families `tsc` does not see and which, in a password manager,
 * cost dearly:
 *
 * 1. **Lost promises.** A storage write or a session purge forgotten without
 *    `await` fails in silence — the vault believes itself locked without being
 *    so. `no-floating-promises` forbids it, and the code already marks
 *    deliberately unawaited calls with an explicit `void`.
 * 2. **Loose comparisons.** A `==` between two coerced values is a source of
 *    silent errors. One exception, explicitly tolerated: `== null`, which the
 *    code uses throughout to mean "absent, `null` or `undefined`" — splitting it
 *    into two tests would say nothing more and would weigh down thirteen
 *    already-dense field reads.
 *
 * The type-aware rules require the project's `tsconfig`: hence `projectService`,
 * which resolves it on its own for each file.
 */

import tseslint from '@typescript-eslint/eslint-plugin';
import tsparser from '@typescript-eslint/parser';

export default [
  {
    ignores: ['dist/', 'dist-firefox/', 'node_modules/', 'coverage/'],
  },
  {
    files: ['**/*.ts', '**/*.tsx'],
    languageOptions: {
      parser: tsparser,
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: { '@typescript-eslint': tseslint },
    rules: {
      ...tseslint.configs['eslint-recommended'].overrides[0].rules,
      ...tseslint.configs.recommended.rules,

      // Promises: the whole family, because it is what protects the session
      // purges.
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-misused-promises': 'error',
      '@typescript-eslint/await-thenable': 'error',

      // Strict comparisons, except the `== null` idiom (see the header).
      eqeqeq: ['error', 'always', { null: 'ignore' }],

      // An unused parameter is prefixed with `_` — `tsc`'s own convention.
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
    },
  },
  {
    // The tooling and probe scripts run under Node, outside the vault: they have
    // no business being held to the extension code's rules of rigour.
    files: ['scripts/**/*.mjs'],
    rules: {},
  },
];
