import { Class } from '../meta/class'
import type { MonoClassPtr } from '../native/api.generated'
import { api } from '../native/api'
import { EnumValue } from '../object/enum'
import { marshallerFor } from './marshaller'
import { scoped } from '../memory/scope'

/**
 * Boxes a JS primitive for a reference-typed parameter (`object`, `ValueType`, `IComparable`, …).
 * The managed type is the best guess: integers in Int32 range → `Int32`, other numbers → `Double`,
 * booleans → `Boolean`, bigints → `Int64`, enum values → their enum. Use `Mono.box(klass, value)`
 * to choose the type yourself.
 */
export function boxValue(value: unknown, target: Class): NativePointer {
  if (value instanceof EnumValue) return box(value.class, value)
  switch (typeof value) {
    case 'number':
      return Number.isInteger(value) && value >= -0x80000000 && value <= 0x7fffffff ? boxAs(api.mono_get_int32_class(), value) : boxAs(api.mono_get_double_class(), value)
    case 'boolean':
      return boxAs(api.mono_get_boolean_class(), value)
    case 'bigint':
      return boxAs(api.mono_get_int64_class(), value)
    default:
      throw new TypeError(`Cannot convert ${typeof value} to ${target.fullName}`)
  }
}

/** Boxes `value` as an instance of the value type `klass`. */
export function box(klass: Class, value: unknown): NativePointer {
  return boxAs(klass.handle, value)
}

function boxAs(klass: MonoClassPtr, value: unknown): NativePointer {
  return scoped((scope) => {
    const m = marshallerFor(Class.from(klass).type)
    return api.mono_value_box(api.mono_domain_get(), klass, m.toStorage(value, scope))
  })
}
