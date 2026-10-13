/* eslint-disable @typescript-eslint/no-explicit-any -- the namespace tree is only known at runtime */
import { MonoError } from '../errors'
import { scoped } from '../memory/scope'
import { Class } from '../meta/class'
import type { Image } from '../meta/image'
import { assemblies, findClass, getAssembly } from '../meta/lookup'
import { api } from '../native/api'
import { onAssemblyLoad } from '../runtime/assembly-load'
import { ensureThreadAttached } from '../runtime/thread'
import { C_SHARP_ALIASES } from './aliases'
import type { MonoNamespaces, MonoTypes } from './types'
import { classWrapper, type MonoClassWrapper } from './bridge'

const MAX_GENERIC_ARITY = 8

let imageList: Image[] | null = null
const found = new Map<string, Class | null>()
let watching = false

function images(): Image[] {
  if (!watching) {
    watching = true
    // New assemblies can make missing names resolvable and add images.
    onAssemblyLoad(() => {
      imageList = null
      for (const [key, value] of found) if (value === null) found.delete(key)
    })
  }
  return (imageList ??= assemblies().map((a) => a.image))
}

/** Looks up `namespace.name` in every loaded image, also as a generic definition (`name\`1` …). */
function classIn(namespace: string, name: string): Class | null {
  const key = `${namespace}\u0000${name}`
  let klass = found.get(key)
  if (klass !== undefined) return klass
  klass = scoped((scope) => {
    const ns = scope.utf8(namespace)
    const names = [name, ...Array.from({ length: MAX_GENERIC_ARITY }, (_, i) => `${name}\`${i + 1}`)].map((n) => scope.utf8(n))
    for (const image of images()) {
      for (const n of names) {
        const c = api.mono_class_from_name(image.handle, ns, n)
        if (!c.isNull()) return Class.from(c)
      }
    }
    return null
  })
  found.set(key, klass)
  return klass
}

const namespaceProxies = new Map<string, unknown>()

function namespaceProxy(path: string): any {
  let proxy = namespaceProxies.get(path)
  if (proxy === undefined) {
    proxy = new Proxy(Object.create(null), {
      get(_target, key) {
        if (typeof key === 'symbol') return key === Symbol.toPrimitive ? () => (path === '' ? 'namespaces' : `namespace ${path}`) : undefined
        if (key === 'then') return undefined // not a thenable
        ensureThreadAttached()
        const klass = classIn(path, key)
        return klass !== null ? classWrapper(klass) : namespaceProxy(path === '' ? key : `${path}.${key}`)
      },
      set() {
        throw new TypeError('Mono.namespaces is read-only')
      }
    })
    namespaceProxies.set(path, proxy)
  }
  return proxy
}

/**
 * The namespace tree across all loaded assemblies: `Mono.namespaces.System.Collections.Generic.List`.
 * Segments resolve lazily; a name that is neither a class nor (yet) loaded yields a namespace node.
 */
export const namespaces: MonoNamespaces & Record<string, any> = namespaceProxy('')

interface ParsedTypeName {
  name: string
  args: ParsedTypeName[]
}

/** Parses `Ns.Dictionary<System.String, System.Collections.Generic.List<int>>`. */
export function parseTypeName(text: string): ParsedTypeName {
  let i = 0
  const parse = (): ParsedTypeName => {
    let name = ''
    while (i < text.length && !'<>,'.includes(text[i] as string)) name += text[i++]
    const node: ParsedTypeName = { name: name.trim(), args: [] }
    if (text[i] === '<') {
      i++
      for (;;) {
        node.args.push(parse())
        if (text[i] === ',') i++
        else if (text[i] === '>') {
          i++
          break
        } else throw new MonoError(`Invalid type name: ${text}`)
      }
    }
    return node
  }
  const result = parse()
  if (i !== text.length) throw new MonoError(`Invalid type name: ${text}`)
  return result
}

function resolveParsed(node: ParsedTypeName, image: Image | null): Class {
  const name = C_SHARP_ALIASES[node.name] ?? node.name
  const lookup = (n: string): Class | null => (image !== null ? image.class(n) : findClass(n))
  if (node.args.length === 0) {
    const klass = lookup(name)
    if (klass === null) throw new MonoError(`Class ${name} not found${image !== null ? ` in ${image.name}` : ''}`)
    return klass
  }
  const definition = lookup(`${name}\`${node.args.length}`) ?? lookup(name)
  if (definition === null) throw new MonoError(`Generic class ${name}\`${node.args.length} not found`)
  return definition.makeGeneric(...node.args.map((a) => resolveParsed(a, null)))
}

/**
 * The JS class for a managed class: `Mono.use('Game.Player')`, `Mono.use('Assembly-CSharp', 'Game.Player')`,
 * `Mono.use('System.Collections.Generic.List<System.String>')`, `Mono.use('int')`.
 */
export function use<K extends keyof MonoTypes>(name: K): MonoTypes[K]
export function use<K extends keyof MonoTypes>(assembly: string, name: K): MonoTypes[K]
export function use(assemblyOrName: string, name?: string): MonoClassWrapper
export function use(assemblyOrName: string, name?: string): MonoClassWrapper {
  ensureThreadAttached()
  const image = name === undefined ? null : getAssembly(assemblyOrName).image
  return classWrapper(resolveParsed(parseTypeName(name ?? assemblyOrName), image))
}
