import runtimes from '../runtimes.json' with { type: 'json' }

export interface Runtime {
  name: string
  image: string
  /** Prefix of `mono_get_runtime_build_info()` for this runtime; `null` for runtimes without it (legacy). */
  version: string | null
  /** C# compiler in the target image (default `mcs`). */
  compiler?: string
  /** Command that runs Host.exe (default `mono Host.exe`). */
  run?: string
  /** Name prefix of the target process (default `mono`). */
  process?: string
  /** Frida detaching from the process crashes it (old glibc: Debian 7 and 6 images), so tests that detach are skipped. */
  detachCrashes?: boolean
  /** A second host command that waits for /tmp/go before loading Mono (process `unity-host-delayed`). */
  delayed?: string
}

/** The runtime the current e2e run targets (set by scripts/e2e.mjs). */
export function currentRuntime(): Runtime {
  const name = process.env.FRIDA_MONO_RUNTIME
  const runtime = (runtimes as Runtime[]).find((r) => r.name === name)
  if (runtime === undefined) throw new Error(`Unknown FRIDA_MONO_RUNTIME '${name}'. Run e2e tests through 'npm run test:e2e'.`)
  return runtime
}
