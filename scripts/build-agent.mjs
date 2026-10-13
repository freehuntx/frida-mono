#!/usr/bin/env node
// Bundles a Frida agent (TypeScript, may import the library from src/) into one script file.
//
//   npm run build:agent examples/game-smoke.ts            # → .build/game-smoke.js
//   npm run build:agent examples/game-smoke.ts --watch    # rebuild on change; `frida -l` reloads it automatically

import { basename, extname, resolve } from 'node:path'
import { build } from 'vite'

const args = process.argv.slice(2)
const watch = args.includes('--watch')
const entry = args.find((a) => !a.startsWith('--'))
if (entry === undefined) {
  console.error('Usage: npm run build:agent <entry.ts> [--watch]')
  process.exit(2)
}

const name = basename(entry, extname(entry))

await build({
  configFile: false,
  logLevel: 'info',
  build: {
    outDir: '.build',
    emptyOutDir: false,
    target: 'es2022',
    minify: false,
    sourcemap: 'inline',
    watch: watch ? {} : null,
    lib: { entry: resolve(entry), formats: ['iife'], name: 'agent', fileName: () => `${name}.js` }
  }
})

console.log(`\nfrida -l ${resolve('.build', `${name}.js`)}`)
