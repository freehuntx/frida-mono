import { defineConfig } from 'vite'

// Library build: one ESM file, no runtime deps. Frida agents bundle it again (see test/e2e/support/agent.ts).
export default defineConfig({
  build: {
    target: 'es2022',
    minify: false,
    sourcemap: true,
    lib: {
      entry: 'src/index.ts',
      formats: ['es'],
      fileName: 'index'
    }
  }
})
