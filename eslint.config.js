/**
 * @file Configuration ESLint (format « flat », ESLint 9).
 *
 * ## Ce que le linter a à faire ici, et ce qu'il n'a pas à faire
 *
 * `tsconfig.json` est déjà sévère — `strict`, `noUncheckedIndexedAccess`,
 * `exactOptionalPropertyTypes`, `noUnusedLocals`. Le typage est donc couvert,
 * et redemander au linter ce que le compilateur refuse déjà ne ferait que
 * doubler les messages.
 *
 * Restent deux familles que `tsc` ne voit pas et qui, dans un gestionnaire de
 * mots de passe, coûtent cher :
 *
 * 1. **Les promesses perdues.** Une écriture de stockage ou une purge de
 *    session oubliée sans `await` échoue en silence — le coffre se croit
 *    verrouillé sans l'être. `no-floating-promises` l'interdit, et le code
 *    marque déjà d'un `void` explicite les appels délibérément non attendus.
 * 2. **Les comparaisons laxistes.** Un `==` entre deux valeurs converties est
 *    une source d'erreurs silencieuses. Seule exception, explicitement
 *    tolérée : `== null`, que le code emploie partout pour dire « absent,
 *    `null` ou `undefined` » — le distinguer en deux tests ne dirait rien de
 *    plus et alourdirait treize lectures de champs déjà denses.
 *
 * Les règles à information de types exigent le `tsconfig` du projet : d'où
 * `projectService`, qui le résout seul pour chaque fichier.
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

      // Promesses : la famille complète, parce que c'est elle qui protège les
      // purges de session.
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-misused-promises': 'error',
      '@typescript-eslint/await-thenable': 'error',

      // Comparaisons strictes, sauf l'idiome `== null` (voir l'en-tête).
      eqeqeq: ['error', 'always', { null: 'ignore' }],

      // Un paramètre inutilisé se préfixe d'un `_` — la convention de `tsc`.
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
    },
  },
  {
    // Les scripts d'outillage et de sonde tournent sous Node, hors du coffre :
    // ils n'ont pas à subir les règles de rigueur du code d'extension.
    files: ['scripts/**/*.mjs'],
    rules: {},
  },
];
