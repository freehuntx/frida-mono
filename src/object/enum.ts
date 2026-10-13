import type { Class } from '../meta/class'
import { api } from '../native/api'
import { marshallerFor } from '../marshal/marshaller'

const namesByClass = new Map<string, Map<string, number | bigint>>()

/** The named constants of an enum class, in declaration order. */
export function enumMembers(klass: Class): ReadonlyMap<string, number | bigint> {
  const key = klass.handle.toString()
  let members = namesByClass.get(key)
  if (members === undefined) {
    members = new Map()
    const underlying = marshallerFor(klass.enumBaseType ?? klass.type)
    const vtable = api.mono_class_vtable(api.mono_domain_get(), klass.handle)
    const slot = Memory.alloc(8)
    for (const field of klass.fields) {
      if (!field.isLiteral) continue
      api.mono_field_static_get_value(vtable, field.handle, slot)
      members.set(field.name, underlying.read(slot) as number | bigint)
    }
    namesByClass.set(key, members)
  }
  return members
}

/** A value of a managed enum: number-like (`valueOf`), with its constant name(s). */
export class EnumValue {
  readonly class: Class
  readonly value: number | bigint

  constructor(klass: Class, value: number | bigint) {
    this.class = klass
    this.value = value
  }

  /** The constant's name; for `[Flags]` combinations `"Read, Write"`; the number if nothing matches. */
  get name(): string {
    const members = enumMembers(this.class)
    for (const [name, v] of members) if (v === this.value) return name
    const bits = BigInt(this.value)
    if (bits === 0n) return String(this.value)
    const parts: string[] = []
    let rest = bits
    for (const [name, v] of members) {
      const b = BigInt(v)
      if (b !== 0n && (bits & b) === b) {
        parts.push(name)
        rest &= ~b
      }
    }
    return rest === 0n && parts.length > 0 ? parts.join(', ') : String(this.value)
  }

  /** True if all bits of `flag` are set. */
  has(flag: EnumValue | number | bigint | string): boolean {
    const b = BigInt(EnumValue.parse(this.class, flag).value)
    return (BigInt(this.value) & b) === b
  }

  valueOf(): number | bigint {
    return this.value
  }

  toString(): string {
    return this.name
  }

  toJSON(): string {
    return this.name
  }

  /** Accepts an `EnumValue` of the same enum, a number/bigint, or constant name(s) (`'Read'`, `'Read, Write'`). */
  static parse(klass: Class, value: unknown): EnumValue {
    if (value instanceof EnumValue) {
      if (value.class !== klass) throw new TypeError(`Expected ${klass.fullName}, got ${value.class.fullName}`)
      return value
    }
    if (typeof value === 'number' || typeof value === 'bigint') return new EnumValue(klass, value)
    if (typeof value === 'string') {
      const members = enumMembers(klass)
      let bits = 0n
      for (const part of value.split(',').map((p) => p.trim())) {
        const v = members.get(part)
        if (v === undefined) throw new TypeError(`${klass.fullName} has no constant ${part}. Constants: ${[...members.keys()].join(', ')}`)
        bits |= BigInt(v)
      }
      const sample = members.values().next().value
      return new EnumValue(klass, typeof sample === 'bigint' ? bits : Number(bits))
    }
    throw new TypeError(`Expected a ${klass.fullName} value, got ${typeof value}`)
  }
}
