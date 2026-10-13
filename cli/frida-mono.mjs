#!/usr/bin/env node
// frida-mono command line.
//
//   frida-mono dump -n Game -o types/Game.d.ts                 typings for the bridge
//   frida-mono dump -p 1234 -a Assembly-CSharp --format cs     C#-like listing to stdout
//   frida-mono dump -H 127.0.0.1 -n Game.exe --wait Assembly-CSharp -o Game.d.ts

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseArgs } from 'node:util'

const USAGE = `Usage: frida-mono dump (-n NAME | -p PID) [options]

Target:
  -n, --name NAME         attach to the process with this name
  -p, --pid PID           attach to this process id
  -H, --host HOST         remote frida-server (host[:port])
  -U, --usb               USB device

Output:
  -a, --assembly NAME     assembly to dump (repeatable; default: all non-framework assemblies)
      --format FORMAT     dts (default), cs or json
      --wait NAME         wait until this assembly is loaded (repeatable)
  -o, --out FILE          write to FILE instead of stdout
`

function fail(message) {
  console.error(`frida-mono: ${message}\n\n${USAGE}`)
  process.exit(2)
}

const [command, ...rest] = process.argv.slice(2)
if (command !== 'dump') fail(command === undefined ? 'missing command' : `unknown command ${command}`)

const { values } = parseArgs({
  args: rest,
  options: {
    name: { type: 'string', short: 'n' },
    pid: { type: 'string', short: 'p' },
    host: { type: 'string', short: 'H' },
    usb: { type: 'boolean', short: 'U' },
    assembly: { type: 'string', short: 'a', multiple: true },
    format: { type: 'string', default: 'dts' },
    wait: { type: 'string', multiple: true },
    out: { type: 'string', short: 'o' }
  }
})

if ((values.name === undefined) === (values.pid === undefined)) fail('give exactly one of --name or --pid')
if (!['dts', 'cs', 'json'].includes(values.format)) fail(`unknown format ${values.format}`)

const agentPath = resolve(dirname(fileURLToPath(import.meta.url)), '../dist/cli-agent.js')
if (!existsSync(agentPath)) fail(`${agentPath} is missing; run \`npm run build\` first`)

let frida
try {
  frida = (await import('frida')).default
} catch {
  fail('the `frida` npm package is required: npm install frida')
}

const device = values.usb ? await frida.getUsbDevice() : values.host !== undefined ? await frida.getDeviceManager().addRemoteDevice(values.host) : await frida.getLocalDevice()
const target = values.pid !== undefined ? Number(values.pid) : values.name
const session = await device.attach(target)
try {
  const script = await session.createScript(readFileSync(agentPath, 'utf8'))
  script.logHandler = (level, text) => console.error(`[agent] ${text}`)
  await script.load()
  const result = await script.exports.dump({ assemblies: values.assembly ?? null, format: values.format, waitFor: values.wait ?? null })
  const text = typeof result === 'string' ? result : JSON.stringify(result, null, 2)
  if (values.out === undefined) process.stdout.write(text)
  else {
    mkdirSync(dirname(resolve(values.out)), { recursive: true })
    writeFileSync(values.out, text)
    console.error(`frida-mono: wrote ${values.out} (${text.length} chars)`)
  }
  await script.unload()
} finally {
  await session.detach()
}
