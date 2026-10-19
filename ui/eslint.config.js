import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'
import jsxA11y from 'eslint-plugin-jsx-a11y'
import { defineConfig, globalIgnores } from 'eslint/config'

export default defineConfig([
  globalIgnores(['dist']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommended,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
    },
  },
  {
    files: ['**/*.{ts,tsx}'],
    ignores: ['**/*.test.{ts,tsx}', 'src/mocks/**'],
    extends: [jsxA11y.flatConfigs.recommended],
    rules: {
      // Depth 3 lets a wrapping <label> find text nested in two spans (radio option cards).
      'jsx-a11y/label-has-associated-control': ['error', { depth: 3 }],
    },
    settings: {
      'jsx-a11y': {
        components: { Button: 'button', Input: 'input', Select: 'select', Textarea: 'textarea' },
      },
    },
  },
])
