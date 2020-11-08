import typescript from '@rollup/plugin-typescript'
import eslint from '@rbnlffl/rollup-plugin-eslint'

export default {
  input: 'src/index.ts',
  output: {
    file: 'lib/frida-mono.js',
    format: 'umd',
    name: 'FridaMono'
  },
  plugins: [
    eslint({
      throwOnError: true
    }),
    typescript({
      target: 'es5'
    })
  ]
}
