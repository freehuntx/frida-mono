import { persistentCallback } from '../memory/persistent'
import { keepAlive } from '../memory/keep-alive'
import { readUtf8 } from '../memory/strings'
import type { MonoAssemblyPtr } from '../native/api.generated'
import { api } from '../native/api'

type Listener = (assembly: MonoAssemblyPtr, name: string) => void

const listeners = new Set<Listener>()
let hookInstalled = false

/** The simple name of an assembly (`Assembly-CSharp`), read via its image so it works on every runtime. */
export function assemblyName(assembly: MonoAssemblyPtr): string {
  return readUtf8(api.mono_image_get_name(api.mono_assembly_get_image(assembly))) ?? ''
}

/** Every assembly loaded in the current domain. */
export function loadedAssemblies(): MonoAssemblyPtr[] {
  const found: MonoAssemblyPtr[] = []
  // Only called during mono_assembly_foreach, so a plain NativeCallback is safe here.
  const collect = new NativeCallback((assembly) => void found.push(assembly as MonoAssemblyPtr), 'void', ['pointer', 'pointer'])
  api.mono_assembly_foreach(collect, NULL)
  return found
}

/** The loaded assembly named `name` (case-insensitive, without `.dll`), or `null`. */
export function findLoadedAssembly(name: string): MonoAssemblyPtr | null {
  const wanted = normalize(name)
  return loadedAssemblies().find((a) => normalize(assemblyName(a)) === wanted) ?? null
}

/**
 * Calls `listener` for every assembly loaded from now on, on the loading thread.
 * Returns a function that removes the listener.
 */
export function onAssemblyLoad(listener: Listener): () => void {
  if (!hookInstalled) {
    hookInstalled = true
    // Load hooks can't be uninstalled, so this must survive the script (see persistentCallback).
    const hook = persistentCallback(
      (assembly: NativePointer) => {
        const name = assemblyName(assembly as MonoAssemblyPtr)
        for (const l of [...listeners]) l(assembly as MonoAssemblyPtr, name)
      },
      'void',
      ['pointer', 'pointer']
    )
    api.mono_install_assembly_load_hook(keepAlive(hook), NULL)
  }
  listeners.add(listener)
  return () => listeners.delete(listener)
}

/** Calls `callback` once the named assembly is loaded: right away if it already is. */
export function whenAssemblyLoaded(name: string, callback: (assembly: MonoAssemblyPtr) => void): void {
  const loaded = findLoadedAssembly(name)
  if (loaded !== null) return callback(loaded)

  const wanted = normalize(name)
  const remove = onAssemblyLoad((assembly, loadedName) => {
    if (normalize(loadedName) !== wanted) return
    remove()
    callback(assembly)
  })
}

function normalize(name: string): string {
  return name.replace(/\.(dll|exe)$/i, '').toLowerCase()
}
