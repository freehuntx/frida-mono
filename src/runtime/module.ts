import { MonoNotFoundError } from '../errors'
import { isKnownMonoModuleName } from './names'

/** Every Mono version exports this, so it identifies the module that hosts the runtime. */
const PROBE_EXPORT = 'mono_thread_attach'

let cached: Module | null = null

/** True if `module` hosts a Mono runtime (known file name and the probe export). */
export function isMonoModule(module: Module): boolean {
  return isKnownMonoModuleName(module.name) && module.findExportByName(PROBE_EXPORT) !== null
}

/** Finds the module hosting the Mono runtime, or `null` if Mono is not loaded (yet). */
export function findMonoModule(): Module | null {
  if (cached !== null) return cached

  for (const module of Process.enumerateModules()) {
    if (isMonoModule(module)) return (cached = module)
  }

  // Statically linked runtimes (e.g. the `mono` CLI, some Unity players) export it from the executable.
  const address = Module.findGlobalExportByName(PROBE_EXPORT)
  if (address !== null) return (cached = Process.getModuleByAddress(address))

  return null
}

/** Like {@link findMonoModule}, but throws if Mono is not loaded. */
export function getMonoModule(): Module {
  const module = findMonoModule()
  if (module === null) throw new MonoNotFoundError(`Mono runtime not found: no loaded module exports ${PROBE_EXPORT}`)
  return module
}
