#!/usr/bin/env node
// Bundles src/cli/agent.ts into dist/cli-agent.js, the script `frida-mono dump` injects.
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { build } from 'vite'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')

await build({
  configFile: false,
  logLevel: 'warn',
  build: {
    outDir: resolve(root, 'dist'),
    emptyOutDir: false,
    target: 'es2022',
    minify: false,
    lib: { entry: resolve(root, 'src/cli/agent.ts'), formats: ['iife'], name: 'agent', fileName: () => 'cli-agent.js' }
  }
})
