import type { Class } from '../meta/class'
import type { ManagedObject } from '../object/object'
import type { StructView } from '../object/struct'

/** Own property of bridge instances: the underlying object or struct. Symbols can't clash with C# names. */
export const INTERNAL = Symbol('frida-mono.internal')
/** Own property of class wrappers' targets: the `Class`. */
export const CLASS = Symbol('frida-mono.class')

export function internalOf(value: unknown): ManagedObject | StructView | undefined {
  if ((typeof value === 'object' || typeof value === 'function') && value !== null && Object.prototype.hasOwnProperty.call(value, INTERNAL)) {
    return (value as Record<symbol, ManagedObject | StructView>)[INTERNAL]
  }
  return undefined
}

export function classOfWrapper(value: unknown): Class | undefined {
  return typeof value === 'function' ? ((value as unknown as Record<symbol, Class | undefined>)[CLASS] ?? undefined) : undefined
}
