const KNOWN_RUNTIMES = ['mono.dll', 'libmonosgen-2.0.so']
const KNOWN_EXPORTS = ['mono_thread_attach']
const KNOWN_STRINGS = ["'%s' in MONO_PATH doesn't exist or has wrong permissions"]

/**
 * To work with mono we need the mono module thats loaded in the current process.
 * This function tries to find it using 3 methods.
 * - Find by module name
 * - Find by export function names
 * - Find by strings in memory
 */
function findMonoModule(): Module {
  for (const runtime of KNOWN_RUNTIMES) {
    const module = Process.findModuleByName(runtime)
    if (module) return module
  }

  for (const exportName of KNOWN_EXPORTS) {
    const exportFunction = Module.findExportByName(null, exportName)
    if (exportFunction) return Process.findModuleByAddress(exportFunction)
  }

  const allModules = Process.enumerateModules()
  for (const module of allModules) {
    for (const string of KNOWN_STRINGS) {
      const pattern = string
        .split('')
        .map((e) => ('0' + e.charCodeAt(0).toString(16)).slice(-2))
        .join(' ')
      const matches = Memory.scanSync(module.base, module.size, pattern)
      if (matches.length > 0) {
        return Process.findModuleByAddress(matches[0].address)
      }
    }
  }

  throw new Error('Failed finding the mono module!')
}

export const module = findMonoModule()
