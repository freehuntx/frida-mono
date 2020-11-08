module.exports = {
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 2020,
    sourceType: 'module'
  },
  extends: ['plugin:@typescript-eslint/recommended', 'prettier/@typescript-eslint', 'plugin:prettier/recommended'],
  ignorePatterns: ['.cache', 'lib/', 'node_modules/', 'src2/'],
  rules: {
    '@typescript-eslint/no-var-requires': 'off',

    'prettier/prettier': [
      'error',
      {
        semi: false,
        trailingComma: 'none',
        singleQuote: true,
        tabWidth: 2,
        printWidth: 180
      }
    ]
  }
}
