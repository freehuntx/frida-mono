import { MonoError } from '../errors'
import type { Scope } from '../memory/scope'
import { Class } from '../meta/class'
import { TypeEnum, typeEnumName } from '../meta/constants'
import type { Type } from '../meta/type'
import type { MonoObjectPtr } from '../native/api.generated'
import { api } from '../native/api'
import { MArray } from '../object/array'
import { EnumValue } from '../object/enum'
import { pinFor } from '../object/handles'
import { ManagedObject } from '../object/object'
import { newMonoString, readMonoString } from '../object/string'
import { StructView } from '../object/struct'
import { box, boxValue } from './box'
import { hooks } from './hooks'
import { createDelegate } from '../delegate/delegate'

/**
 * Converts between JS values and one managed type. Built once per `MonoType` and
 * cached, so calls only run the precomputed readers and writers.
 *
 * A *slot* is memory holding a value of the type the way the runtime stores it: the bytes of a
 * value type, or a `MonoObject*` for reference types (fields, array elements, out-parameters).
 */
export interface Marshaller {
  readonly type: Type
  /** Size of a slot in bytes. */
  readonly size: number
  /** The slot holds a `MonoObject*`. */
  readonly isReference: boolean
  /** Reads the value in `slot`. */
  read(slot: NativePointer): unknown
  /** Writes `value` into unmanaged scratch memory (no GC write barriers: never use it on managed memory). */
  write(slot: NativePointer, value: unknown, scope: Scope): void
  /**
   * The pointer `mono_field_set_value`, `mono_value_box` and friends expect: the (pinned) object for
   * reference types, a pointer to the bytes for value types.
   */
  toStorage(value: unknown, scope: Scope): NativePointer
  /** The pointer `mono_runtime_invoke` expects in `params`. Same as {@link toStorage} except for `Nullable<T>`. */
  toArgument(value: unknown, scope: Scope): NativePointer
  /** Reads a value returned by `mono_runtime_invoke` (boxed for value types). */
  fromReturn(object: NativePointer): unknown
}

const HEADER_SIZE = 2 * Process.pointerSize // MonoObject: vtable + synchronisation

/** Offset of an instance field inside the unboxed value of a struct. */
export function unboxedOffset(fieldOffset: number): number {
  return fieldOffset - HEADER_SIZE
}

const cache = new Map<string, Marshaller>()

export function marshallerFor(type: Type): Marshaller {
  const key = type.handle.toString()
  let m = cache.get(key)
  if (m === undefined) {
    m = create(type)
    cache.set(key, m)
  }
  return m
}

// ---------------------------------------------------------------------------------------------------
// Value types

abstract class ValueMarshaller implements Marshaller {
  readonly isReference = false
  abstract readonly size: number

  constructor(readonly type: Type) {}

  abstract read(slot: NativePointer): unknown
  abstract write(slot: NativePointer, value: unknown, scope: Scope): void

  toStorage(value: unknown, scope: Scope): NativePointer {
    const slot = scope.alloc(this.size)
    this.write(slot, value, scope)
    return slot
  }

  toArgument(value: unknown, scope: Scope): NativePointer {
    return this.toStorage(value, scope)
  }

  fromReturn(object: NativePointer): unknown {
    return this.read(api.mono_object_unbox(object as MonoObjectPtr))
  }
}

type Primitive = { size: number; read(slot: NativePointer): unknown; write(slot: NativePointer, value: unknown): void }

function toNumber(value: unknown, what: string): number {
  if (typeof value === 'number') return value
  if (typeof value === 'bigint') return Number(value)
  if (typeof value === 'boolean') return value ? 1 : 0
  if (value instanceof EnumValue) return Number(value.value)
  throw new TypeError(`Expected a number for ${what}, got ${describe(value)}`)
}

function toBigIntString(value: unknown, what: string): string {
  if (typeof value === 'bigint' || typeof value === 'number') return value.toString()
  if (value instanceof Int64 || value instanceof UInt64) return value.toString()
  if (value instanceof EnumValue) return value.value.toString()
  throw new TypeError(`Expected a number, bigint or Int64 for ${what}, got ${describe(value)}`)
}

function toPointer(value: unknown, what: string): NativePointer {
  if (value instanceof NativePointer) return value
  if (typeof value === 'number' || typeof value === 'bigint') return ptr(value.toString())
  if (value === null || value === undefined) return NULL
  throw new TypeError(`Expected a NativePointer or number for ${what}, got ${describe(value)}`)
}

const PRIMITIVES: Partial<Record<number, Primitive>> = {
  [TypeEnum.BOOLEAN]: {
    size: 1,
    read: (s) => s.readU8() !== 0,
    write: (s, v) => s.writeU8(v ? 1 : 0)
  },
  [TypeEnum.CHAR]: {
    size: 2,
    read: (s) => String.fromCharCode(s.readU16()),
    write: (s, v) => s.writeU16(typeof v === 'string' ? v.charCodeAt(0) : toNumber(v, 'char'))
  },
  [TypeEnum.I1]: { size: 1, read: (s) => s.readS8(), write: (s, v) => s.writeS8(toNumber(v, 'sbyte')) },
  [TypeEnum.U1]: { size: 1, read: (s) => s.readU8(), write: (s, v) => s.writeU8(toNumber(v, 'byte')) },
  [TypeEnum.I2]: { size: 2, read: (s) => s.readS16(), write: (s, v) => s.writeS16(toNumber(v, 'short')) },
  [TypeEnum.U2]: { size: 2, read: (s) => s.readU16(), write: (s, v) => s.writeU16(toNumber(v, 'ushort')) },
  [TypeEnum.I4]: { size: 4, read: (s) => s.readS32(), write: (s, v) => s.writeS32(toNumber(v, 'int')) },
  [TypeEnum.U4]: { size: 4, read: (s) => s.readU32(), write: (s, v) => s.writeU32(toNumber(v, 'uint')) },
  [TypeEnum.I8]: {
    size: 8,
    read: (s) => BigInt(s.readS64().toString()),
    write: (s, v) => s.writeS64(int64(toBigIntString(v, 'long')))
  },
  [TypeEnum.U8]: {
    size: 8,
    read: (s) => BigInt(s.readU64().toString()),
    write: (s, v) => s.writeU64(uint64(toBigIntString(v, 'ulong')))
  },
  [TypeEnum.R4]: { size: 4, read: (s) => s.readFloat(), write: (s, v) => s.writeFloat(toNumber(v, 'float')) },
  [TypeEnum.R8]: { size: 8, read: (s) => s.readDouble(), write: (s, v) => s.writeDouble(toNumber(v, 'double')) },
  [TypeEnum.I]: { size: Process.pointerSize, read: (s) => s.readPointer(), write: (s, v) => s.writePointer(toPointer(v, 'IntPtr')) },
  [TypeEnum.U]: { size: Process.pointerSize, read: (s) => s.readPointer(), write: (s, v) => s.writePointer(toPointer(v, 'UIntPtr')) },
  [TypeEnum.PTR]: { size: Process.pointerSize, read: (s) => s.readPointer(), write: (s, v) => s.writePointer(toPointer(v, 'pointer')) },
  [TypeEnum.FNPTR]: { size: Process.pointerSize, read: (s) => s.readPointer(), write: (s, v) => s.writePointer(toPointer(v, 'function pointer')) }
}

class PrimitiveMarshaller extends ValueMarshaller {
  readonly size: number

  constructor(
    type: Type,
    private readonly primitive: Primitive
  ) {
    super(type)
    this.size = primitive.size
  }

  read(slot: NativePointer): unknown {
    return this.primitive.read(slot)
  }

  write(slot: NativePointer, value: unknown): void {
    this.primitive.write(slot, value)
  }
}

class EnumMarshaller extends ValueMarshaller {
  readonly size: number
  readonly #underlying: Marshaller
  readonly #class: Class

  constructor(type: Type) {
    super(type)
    this.#class = type.class
    this.#underlying = marshallerFor(type.underlying)
    this.size = this.#underlying.size
  }

  read(slot: NativePointer): EnumValue {
    return new EnumValue(this.#class, this.#underlying.read(slot) as number | bigint)
  }

  write(slot: NativePointer, value: unknown, scope: Scope): void {
    this.#underlying.write(slot, EnumValue.parse(this.#class, value).value, scope)
  }
}

class StructMarshaller extends ValueMarshaller {
  readonly size: number
  readonly #class: Class

  constructor(type: Type) {
    super(type)
    this.#class = type.class
    this.size = this.#class.valueSize
  }

  /** Copies the value into a new box, so the view owns it (value semantics, like C#). */
  read(slot: NativePointer): unknown {
    return hooks.wrapStruct(StructView.copyOf(this.#class, slot))
  }

  write(slot: NativePointer, value: unknown, scope: Scope): void {
    value = hooks.unwrap(value) ?? value
    if (value instanceof StructView) {
      if (value.class !== this.#class) throw new TypeError(`Expected ${this.#class.fullName}, got ${value.class.fullName}`)
      // Pin the source box while its bytes are copied out.
      pinFor(value.box.pointer, scope)
      Memory.copy(slot, value.address, this.size)
      return
    }
    if (value === undefined || value === null) return // default(T): the slot is already zeroed
    if (typeof value !== 'object') throw new TypeError(`Expected ${this.#class.fullName} (a struct view or plain object), got ${describe(value)}`)
    const fields = value as Record<string, unknown>
    for (const field of this.#class.fields) {
      if (field.isStatic || !(field.name in fields)) continue
      marshallerFor(field.type).write(slot.add(unboxedOffset(field.offset)), fields[field.name], scope)
    }
  }
}

/**
 * `Nullable<T>` ⇄ `T | null`. The struct is `{ T value; bool hasValue }` (field names and order differ
 * between corlib versions, so fields are found by type), and the runtime boxes it as `T` or null.
 */
class NullableMarshaller extends ValueMarshaller {
  readonly size: number
  readonly #value: Marshaller
  readonly #valueClass: Class
  readonly #valueOffset: number
  readonly #hasValueOffset: number

  constructor(type: Type) {
    super(type)
    const klass = type.class
    const fields = klass.fields.filter((f) => !f.isStatic)
    const hasValue = fields.find((f) => f.type.typeEnum === TypeEnum.BOOLEAN && /has_?value/i.test(f.name))
    const value = fields.find((f) => f !== hasValue)
    if (hasValue === undefined || value === undefined) throw new MonoError(`Unexpected layout of ${klass.fullName}: ${fields.map(String).join(', ')}`)
    this.size = klass.valueSize
    this.#value = marshallerFor(value.type)
    this.#valueClass = value.type.class
    this.#valueOffset = unboxedOffset(value.offset)
    this.#hasValueOffset = unboxedOffset(hasValue.offset)
  }

  read(slot: NativePointer): unknown {
    return slot.add(this.#hasValueOffset).readU8() === 0 ? null : this.#value.read(slot.add(this.#valueOffset))
  }

  write(slot: NativePointer, value: unknown, scope: Scope): void {
    if (value === null || value === undefined) return // zeroed: hasValue = false
    this.#value.write(slot.add(this.#valueOffset), value, scope)
    slot.add(this.#hasValueOffset).writeU8(1)
  }

  /** The runtime-invoke wrapper takes nullables boxed (as `T` or null) and unpacks them itself. */
  override toArgument(value: unknown, scope: Scope): NativePointer {
    if (value === null || value === undefined) return NULL
    return pinFor(box(this.#valueClass, value), scope)
  }

  override fromReturn(object: NativePointer): unknown {
    return fromObject(object)
  }
}

// ---------------------------------------------------------------------------------------------------
// Reference types

class ReferenceMarshaller implements Marshaller {
  readonly isReference = true
  readonly size = Process.pointerSize
  readonly #class: Class

  constructor(readonly type: Type) {
    this.#class = type.class
  }

  read(slot: NativePointer): unknown {
    return fromObject(slot.readPointer())
  }

  write(slot: NativePointer, value: unknown, scope: Scope): void {
    slot.writePointer(this.toArgument(value, scope))
  }

  toStorage(value: unknown, scope: Scope): NativePointer {
    return pinFor(toObject(value, this.#class), scope)
  }

  toArgument(value: unknown, scope: Scope): NativePointer {
    return this.toStorage(value, scope)
  }

  fromReturn(object: NativePointer): unknown {
    return fromObject(object)
  }
}

/** Wraps a `MonoObject*` as the most useful JS value for its runtime class. */
export function fromObject(pointer: NativePointer): unknown {
  if (pointer.isNull()) return null
  const object = pointer as MonoObjectPtr
  const klass = Class.from(api.mono_object_get_class(object))
  if (klass.handle.equals(api.mono_get_string_class())) return readMonoString(object)
  if (klass.rank > 0) return new MArray(object)
  // Boxed primitives, enums and structs come back as their JS value.
  if (klass.isValueType) return marshallerFor(klass.type).read(api.mono_object_unbox(object))
  return hooks.wrapObject(new ManagedObject(object))
}

/** Converts a JS value to a `MonoObject*` assignable to `target` (unpinned: pin it before the next allocation). */
export function toObject(value: unknown, target: Class): NativePointer {
  if (value === null || value === undefined) return NULL
  if (value instanceof NativePointer) return value // raw MonoObject*, trusted
  value = hooks.unwrap(value) ?? value
  let object: NativePointer
  if (value instanceof ManagedObject) object = value.pointer
  else if (value instanceof StructView) object = value.box.pointer
  else if (typeof value === 'string') object = newMonoString(value)
  else if (typeof value === 'function' && target.isDelegate) object = createDelegate(target, value as (...args: unknown[]) => unknown).pointer
  else if (Array.isArray(value)) {
    if (target.rank === 0) throw new TypeError(`Cannot pass a JS array as ${target.fullName}`)
    object = MArray.from(target.elementClass, value).pointer
  } else object = boxValue(value, target)

  if (api.mono_object_isinst(object as MonoObjectPtr, target.handle).isNull()) {
    const actual = Class.from(api.mono_object_get_class(object as MonoObjectPtr))
    throw new TypeError(`Expected ${target.fullName}, got ${actual.fullName}`)
  }
  return object
}

// ---------------------------------------------------------------------------------------------------

class UnsupportedMarshaller implements Marshaller {
  readonly isReference = false
  readonly size = 0

  constructor(
    readonly type: Type,
    private readonly reason: string
  ) {}

  read(): never {
    throw this.error()
  }
  write(): never {
    throw this.error()
  }
  toStorage(): never {
    throw this.error()
  }
  toArgument(): never {
    throw this.error()
  }
  fromReturn(): never {
    throw this.error()
  }

  private error(): MonoError {
    return new MonoError(`Cannot marshal ${this.type.name}: ${this.reason}`)
  }
}

class VoidMarshaller implements Marshaller {
  readonly isReference = false
  readonly size = 0

  constructor(readonly type: Type) {}

  read(): undefined {
    return undefined
  }
  write(): void {}
  toStorage(): NativePointer {
    return NULL
  }
  toArgument(): NativePointer {
    return NULL
  }
  fromReturn(): undefined {
    return undefined
  }
}

function create(type: Type): Marshaller {
  const t = type.typeEnum
  if (t === TypeEnum.VOID) return new VoidMarshaller(type)
  const primitive = PRIMITIVES[t]
  if (primitive !== undefined) return new PrimitiveMarshaller(type, primitive)
  if (t === TypeEnum.VAR || t === TypeEnum.MVAR) return new UnsupportedMarshaller(type, 'open generic parameter; use a closed generic type')
  if (t === TypeEnum.TYPEDBYREF) return new UnsupportedMarshaller(type, 'TypedReference is not supported')

  const klass = type.class
  if (klass.isEnum) return new EnumMarshaller(type)
  if (t === TypeEnum.GENERICINST && klass.isValueType && klass.namespace === 'System' && klass.name === 'Nullable`1') return new NullableMarshaller(type)
  if (klass.isValueType) return new StructMarshaller(type)
  if (t === TypeEnum.STRING || t === TypeEnum.CLASS || t === TypeEnum.OBJECT || t === TypeEnum.SZARRAY || t === TypeEnum.ARRAY || t === TypeEnum.GENERICINST) {
    return new ReferenceMarshaller(type)
  }
  return new UnsupportedMarshaller(type, `type ${typeEnumName(t)} is not supported`)
}

export function describe(value: unknown): string {
  if (value === null) return 'null'
  if (typeof value === 'object') return (value as object).constructor?.name ?? 'object'
  return `${typeof value} ${String(value)}`
}
