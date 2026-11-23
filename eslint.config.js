import js from '@eslint/js';
import globals from 'globals';

export default [
  // Sample projects are deliberately broken test data, not this package's code.
  { ignores: ['test/fixtures/**', 'coverage/**', 'readiness/**'] },
  js.configs.recommended,
  {
    languageOptions: { ecmaVersion: 2024, sourceType: 'module', globals: { ...globals.node } },
    rules: {
      'no-unused-vars': ['error', { argsIgnorePattern: '^_', caughtErrors: 'none' }],
      'no-empty': ['error', { allowEmptyCatch: false }],
      eqeqeq: ['error', 'always'],
      'prefer-const': 'error',
    },
  },
];
