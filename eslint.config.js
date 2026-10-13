import js from '@eslint/js'
import tseslint from 'typescript-eslint'
import prettier from 'eslint-config-prettier'
import globals from 'globals'

export default tseslint.config(
  { ignores: ['dist/', '.build/', 'node_modules/', '.cache/'] },
  js.configs.recommended,
  ...tseslint.configs.strict,
  prettier,
  {
    files: ['scripts/**', 'cli/**', 'test/e2e/*.ts', 'test/e2e/support/**', 'test/unit/**', '*.config.*'],
    languageOptions: { globals: globals.node }
  },
  {
    // Code that runs inside Frida.
    files: ['src/**', 'examples/**', 'test/e2e/agents/**'],
    rules: {
      'no-restricted-syntax': [
        'error',
        {
          selector: "BinaryExpression[operator='**'] > Literal[bigint]",
          message: "BigInt exponentiation crashes Frida's QuickJS on Windows under Wine; write the value as a literal."
        }
      ]
    }
  }
)
