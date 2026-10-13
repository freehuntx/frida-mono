import { MonoError } from '../errors'
import { scoped } from '../memory/scope'
import { api } from '../native/api'
import { findLoadedAssembly, loadedAssemblies } from '../runtime/assembly-load'
import { ensureThreadAttached } from '../runtime/thread'
import { Assembly } from './assembly'
import type { Class } from './class'
import type { Image } from './image'
import { Method } from './method'

/** Every loaded assembly. */
export function assemblies(): Assembly[] {
  ensureThreadAttached()
  return loadedAssemblies().map((a) => Assembly.from(a))
}

/** The loaded assembly with this simple name (case-insensitive, `.dll` optional), or `null`. */
export function findAssembly(name: string): Assembly | null {
  ensureThreadAttached()
  const assembly = findLoadedAssembly(name)
  return assembly === null ? null : Assembly.from(assembly)
}

/** Like {@link findAssembly}, but throws if it isn't loaded. */
export function getAssembly(name: string): Assembly {
  const assembly = findAssembly(name)
  if (assembly === null) throw new MonoError(`Assembly ${name} is not loaded. Loaded: ${assemblies().map(String).join(', ')}`)
  return assembly
}

function images(): Image[] {
  return assemblies().map((a) => a.image)
}

/**
 * Every class matching `name` in any loaded assembly. `name` is either a full name (`Ns.Name`,
 * `Ns.Outer+Inner`), which is looked up directly, or a simple name (`Name`), which searches every
 * type of every assembly (slow the first time per assembly, cached after that).
 */
export function findClasses(name: string): Class[] {
  if (/[.+/]/.test(name)) return images().flatMap((image) => image.class(name) ?? [])
  return images().flatMap((image) => image.classesNamed(name))
}

/** The first class matching `name` (see {@link findClasses}), or `null`. */
export function findClass(name: string): Class | null {
  if (/[.+/]/.test(name)) {
    for (const image of images()) {
      const klass = image.class(name)
      if (klass !== null) return klass
    }
    return null
  }
  return findClasses(name)[0] ?? null
}

/** Like {@link findClass}, but throws if nothing matches. */
export function getClass(name: string): Class {
  const klass = findClass(name)
  if (klass === null) throw new MonoError(`Class ${name} not found in any loaded assembly`)
  return klass
}

/**
 * Finds a method by Mono's description syntax: `Ns.Class:Method`, `Ns.Class:Method(int,string)`,
 * `:Method(System.String)`. Searches every loaded assembly.
 */
export function findMethodByDesc(description: string): Method | null {
  ensureThreadAttached()
  return scoped((scope) => {
    const desc = api.mono_method_desc_new(scope.utf8(description), 1)
    if (desc.isNull()) throw new MonoError(`Invalid method description: ${description}`)
    try {
      for (const image of images()) {
        const method = api.mono_method_desc_search_in_image(desc, image.handle)
        if (!method.isNull()) return Method.from(method)
      }
      return null
    } finally {
      api.mono_method_desc_free(desc)
    }
  })
}
