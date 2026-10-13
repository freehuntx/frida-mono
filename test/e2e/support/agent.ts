import { resolve } from 'node:path'
import frida from 'frida'
import { build, type Rolldown } from 'vite'
import { currentRuntime } from './runtime'

/** Bundles an agent entry (TypeScript, may import src/) into a single Frida script. */
export async function bundleAgent(entry: string): Promise<string> {
  const result = await build({
    configFile: false,
    logLevel: 'warn',
    build: {
      write: false,
      target: 'es2022',
      minify: false,
      lib: { entry: resolve(entry), formats: ['iife'], name: 'agent' }
    }
  })
  const outputs = (Array.isArray(result) ? result : [result]) as Rolldown.RolldownOutput[]
  const chunk = outputs[0]?.output[0]
  if (chunk?.type !== 'chunk') throw new Error(`No chunk produced for ${entry}`)
  return chunk.code
}

export interface LoadedAgent<T> {
  exports: T
  unload(): Promise<void>
}

const sessions = new Map<string, Promise<frida.Session>>()

/**
 * One session per target process for the whole run, never detached: when the last session detaches,
 * Frida unloads its agent from the target, and on old glibc (Debian 7, the Mono 4.8 image) that
 * segfaults the process, Mono or not. Sharing it needs the e2e project's `isolate: false` (vitest.config.ts).
 */
function getSession(processName: string): Promise<frida.Session> {
  let session = sessions.get(processName)
  if (session === undefined) {
    session = (async () => {
      const device = await frida.getLocalDevice()
      const processes = await device.enumerateProcesses()
      // Exact match first: `unity-host` is a prefix of `unity-host-delayed`.
      const target = processes.find((p) => p.name === processName) ?? processes.find((p) => p.name.startsWith(processName))
      if (target === undefined) throw new Error(`No ${processName} process visible. Is the target container sharing its PID namespace?`)
      return device.attach(target.pid)
    })()
    sessions.set(processName, session)
  }
  return session
}

/** Loads the agent into the Mono target process; `exports` proxies its `rpc.exports`. */
export async function loadAgent<T>(entry: string, processName = currentRuntime().process ?? 'mono'): Promise<LoadedAgent<T>> {
  const session = await getSession(processName)
  const script = await session.createScript(await bundleAgent(entry))
  script.logHandler = (level, text) => console[level === 'error' ? 'error' : 'log'](`[agent] ${text}`)
  await script.load()

  return {
    exports: script.exports as T,
    async unload() {
      await script.unload()
    }
  }
}
