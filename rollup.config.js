import typescript from '@rollup/plugin-typescript'

export default {
  input: 'src/index.ts',
  output: {
    file: 'lib/frida-mono.js',
    format: 'umd',
    name: 'FridaMono'
  },
  plugins: [typescript({
    target: 'es5'
  })]
}
