import { getMonoModule } from './module'

let table: Map<string, NativePointer> | null = null

/**
 * All function exports of the Mono module, enumerated once.
 *
 * Deliberately not `Module.findExportByName`: Frida returns `null` from it for runtimes linked into a PIE
 * executable (e.g. `/usr/bin/mono-sgen`), although `enumerateExports()` lists them. The table doubles as
 * the source for capability detection.
 */
export function monoExports(): ReadonlyMap<string, NativePointer> {
  if (table === null) {
    table = new Map()
    for (const e of getMonoModule().enumerateExports()) {
      if (e.type === 'function') table.set(e.name, e.address)
    }
  }
  return table
}

export function findMonoExport(name: string): NativePointer | null {
  return monoExports().get(name) ?? null
}

export function getMonoExport(name: string): NativePointer {
  const address = findMonoExport(name)
  if (address === null) throw new Error(`Mono export not found: ${name} (in ${getMonoModule().name})`)
  return address
}
