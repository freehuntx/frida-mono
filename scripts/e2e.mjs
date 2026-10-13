#!/usr/bin/env node
// Runs the e2e suite once per Mono runtime.
//
// For each runtime a "target" container (the Mono image) compiles test/fixtures and runs Host.exe.
// A "runner" container (modern Node + Frida) shares the target's PID namespace, so Frida can attach
// even to runtimes whose distro is far too old for Node. Usage:
//
//   npm run test:e2e                 # all runtimes
//   npm run test:e2e mono-6.12       # only the named runtimes
//   npm run test:e2e -- -- -t smoke     # extra args after `--` go to vitest

import { execFileSync, spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const runtimes = JSON.parse(readFileSync(resolve(root, 'test/e2e/runtimes.json'), 'utf8'))

const RUNNER_IMAGE = 'node:24-bookworm-slim'
const READY_TIMEOUT_MS = 120_000

const args = process.argv.slice(2)
const separator = args.indexOf('--')
const names = separator === -1 ? args : args.slice(0, separator)
const vitestArgs = separator === -1 ? [] : args.slice(separator + 1)

const selected = names.length === 0 ? runtimes : runtimes.filter((r) => names.includes(r.name))
const unknown = names.filter((n) => !runtimes.some((r) => r.name === n))
if (unknown.length > 0) {
  console.error(`Unknown runtime(s): ${unknown.join(', ')}. Known: ${runtimes.map((r) => r.name).join(', ')}`)
  process.exit(2)
}

function docker(...dockerArgs) {
  return execFileSync('docker', dockerArgs, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim()
}

function removeContainer(name) {
  spawnSync('docker', ['rm', '-f', name], { stdio: 'ignore' })
}

async function waitForReady(container) {
  const deadline = Date.now() + READY_TIMEOUT_MS
  while (Date.now() < deadline) {
    const logs = spawnSync('docker', ['logs', container], { encoding: 'utf8' })
    const output = `${logs.stdout}${logs.stderr}`
    if (output.includes('READY')) return
    const running = docker('inspect', '-f', '{{.State.Running}}', container)
    if (running !== 'true') throw new Error(`Target container exited before READY:\n${output}`)
    await new Promise((r) => setTimeout(r, 500))
  }
  throw new Error(`Target container not READY after ${READY_TIMEOUT_MS / 1000}s`)
}

/** Compiles the fixtures with the runtime's own compiler and runs Host.exe (by default with the `mono` CLI). */
function targetCommand(runtime) {
  const mcs = runtime.compiler ?? 'mcs'
  return [
    'set -e',
    'mkdir -p /tmp/fixtures && cd /tmp/fixtures',
    `${mcs} -nologo -target:library -out:TestLib.dll /fixtures/TestLib.cs`,
    `${mcs} -nologo -out:Host.exe -r:TestLib.dll /fixtures/Host.cs`,
    `${mcs} -nologo -target:library -out:LazyA.dll /fixtures/Lazy.cs`,
    `${mcs} -nologo -target:library -out:LazyB.dll /fixtures/Lazy.cs`,
    // A second host that only loads Mono once /tmp/go exists (test/e2e/wait.e2e.ts).
    ...(runtime.delayed === undefined ? [] : [`${runtime.delayed} > /tmp/delayed.log 2>&1 &`]),
    `exec ${runtime.run ?? 'mono Host.exe'}`
  ].join('\n')
}

const runnerCommand = ['set -e', 'npm ci --no-audit --no-fund', `npx vitest run --project e2e ${vitestArgs.map((a) => `'${a}'`).join(' ')}`].join('\n')

const failed = []
for (const runtime of selected) {
  const target = `frida-mono-e2e-${runtime.name}`
  console.log(`\n=== ${runtime.name} (${runtime.image}) ===`)
  removeContainer(target)

  try {
    docker('run', '-d', '--name', target, '-v', `${resolve(root, 'test/fixtures')}:/fixtures:ro`, runtime.image, 'sh', '-c', targetCommand(runtime))
    await waitForReady(target)

    const result = spawnSync(
      'docker',
      [
        'run',
        '--rm',
        `--pid=container:${target}`,
        '--cap-add=SYS_PTRACE',
        '--security-opt',
        'seccomp=unconfined',
        '-v',
        `${root}:/w`,
        // Linux node_modules live in volumes so they never clash with the host's install.
        '-v',
        'frida-mono-e2e-node-modules:/w/node_modules',
        '-v',
        'frida-mono-e2e-npm-cache:/root/.npm',
        '-e',
        `FRIDA_MONO_RUNTIME=${runtime.name}`,
        '-w',
        '/w',
        RUNNER_IMAGE,
        'sh',
        '-c',
        runnerCommand
      ],
      { stdio: 'inherit' }
    )
    if (result.status !== 0) {
      failed.push(runtime.name)
      const logs = spawnSync('docker', ['logs', '--tail', '60', target], { encoding: 'utf8' })
      console.error(`\n--- ${runtime.name} target output (last 60 lines) ---\n${logs.stdout}${logs.stderr}`)
    }
  } catch (error) {
    console.error(error instanceof Error ? error.message : error)
    failed.push(runtime.name)
  } finally {
    removeContainer(target)
  }
}

console.log(failed.length === 0 ? `\nAll ${selected.length} runtime(s) passed.` : `\nFailed: ${failed.join(', ')}`)
process.exit(failed.length === 0 ? 0 : 1)
