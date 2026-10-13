import { Class } from '../meta/class'
import { TypeEnum } from '../meta/constants'
import type { Type } from '../meta/type'
import { api } from '../native/api'
import { EnumValue } from '../object/enum'
import { ManagedObject } from '../object/object'
import { Ref } from '../object/ref'
import { StructView } from '../object/struct'
import type { ArgumentInspector, IntegerName, ParamKind } from './overload'
import { classOfWrapper, internalOf } from './symbols'

const INTEGERS: Partial<Record<number, IntegerName>> = {
  [TypeEnum.I1]: 'sbyte',
  [TypeEnum.U1]: 'byte',
  [TypeEnum.I2]: 'short',
  [TypeEnum.U2]: 'ushort',
  [TypeEnum.I4]: 'int',
  [TypeEnum.U4]: 'uint',
  [TypeEnum.I8]: 'long',
  [TypeEnum.U8]: 'ulong'
}

/** Classifies a parameter type for overload scoring. */
export function paramKindOf(type: Type): ParamKind {
  if (type.isByRef) return { kind: 'byref', inner: paramKindOf(type.class.type) }
  const t = type.typeEnum
  const integer = INTEGERS[t]
  if (integer !== undefined) return { kind: 'integer', name: integer }
  switch (t) {
    case TypeEnum.BOOLEAN:
      return { kind: 'bool' }
    case TypeEnum.CHAR:
      return { kind: 'char' }
    case TypeEnum.R4:
      return { kind: 'float' }
    case TypeEnum.R8:
      return { kind: 'double' }
    case TypeEnum.I:
    case TypeEnum.U:
    case TypeEnum.PTR:
    case TypeEnum.FNPTR:
      return { kind: 'pointer' }
    case TypeEnum.STRING:
      return { kind: 'string' }
    case TypeEnum.VAR:
    case TypeEnum.MVAR:
      return { kind: 'generic' }
    case TypeEnum.SZARRAY:
    case TypeEnum.ARRAY:
      return { kind: 'array', class: type.class }
  }
  const klass = type.class
  if (klass.isEnum) return { kind: 'enum', class: klass }
  if (klass.isValueType) {
    if (klass.namespace === 'System' && klass.name === 'Nullable`1') {
      const value = klass.fields.find((f) => !f.isStatic && f.type.typeEnum !== TypeEnum.BOOLEAN)
      return { kind: 'nullable', inner: value === undefined ? { kind: 'unsupported' } : paramKindOf(value.type) }
    }
    return { kind: 'struct', class: klass }
  }
  if (t === TypeEnum.CLASS || t === TypeEnum.OBJECT || t === TypeEnum.GENERICINST) return { kind: 'reference', class: klass }
  return { kind: 'unsupported' }
}

let corlibClasses: { type: Class; string: Class; int32: Class; double: Class; boolean: Class; int64: Class } | null = null

function corlib(): NonNullable<typeof corlibClasses> {
  return (corlibClasses ??= {
    type: Class.from(api.mono_class_from_name(api.mono_get_corlib(), Memory.allocUtf8String('System'), Memory.allocUtf8String('Type'))),
    string: Class.from(api.mono_get_string_class()),
    int32: Class.from(api.mono_get_int32_class()),
    double: Class.from(api.mono_get_double_class()),
    boolean: Class.from(api.mono_get_boolean_class()),
    int64: Class.from(api.mono_get_int64_class())
  })
}

/** The managed class behind a JS value (bridge instance, raw wrapper, enum value), if any. */
export function managedClassOf(value: unknown): Class | undefined {
  const internal = internalOf(value) ?? value
  if (internal instanceof ManagedObject || internal instanceof StructView) return internal.class
  if (internal instanceof EnumValue) return internal.class
  return undefined
}

export const inspector: ArgumentInspector = {
  classOf: managedClassOf,
  isClassWrapper: (value) => classOfWrapper(value) !== undefined,
  isRef: (value): value is Ref => value instanceof Ref,
  isEnumValue: (value) => value instanceof EnumValue,
  distance(from, to) {
    const source = from as Class
    const target = to as Class
    if (source === target) return 0
    const index = source.hierarchy.indexOf(target)
    if (index >= 0) return index
    return target.isAssignableFrom(source) ? 5 : -1
  },
  acceptsType: (klass) => (klass as Class).isAssignableFrom(corlib().type),
  isDelegate: (klass) => (klass as Class).isDelegate,
  acceptsBoxed(klass, boxed) {
    const c = corlib()
    const target = klass as Class
    switch (boxed) {
      case 'string':
        return target.isAssignableFrom(c.string)
      case 'number':
        return target.isAssignableFrom(c.int32) || target.isAssignableFrom(c.double)
      case 'boolean':
        return target.isAssignableFrom(c.boolean)
      case 'bigint':
        return target.isAssignableFrom(c.int64)
    }
  }
}

/** Groups JS arguments by the properties overload scoring looks at, to cache resolutions. */
export function shapeOf(value: unknown): string {
  if (value === null || value === undefined) return 'n'
  switch (typeof value) {
    case 'number':
      if (!Number.isInteger(value)) return 'f'
      if (value >= -128 && value <= 127) return value < 0 ? 'i8' : 'u7'
      if (value >= 0 && value <= 255) return 'u8'
      if (value >= -32768 && value <= 32767) return 'i16'
      if (value >= 0 && value <= 65535) return 'u16'
      if (value >= -2147483648 && value <= 2147483647) return 'i32'
      if (value >= 0 && value <= 4294967295) return 'u32'
      return value < 0 ? 'i53' : 'u53'
    case 'bigint':
      return `b${value < 0n ? '-' : '+'}${value >= -2147483648n && value <= 2147483647n ? 's' : 'l'}`
    case 'string':
      return value.length === 1 ? 'c' : 's'
    case 'boolean':
      return 'z'
    case 'function':
      return classOfWrapper(value) !== undefined ? 't' : 'F'
  }
  if (value instanceof Ref) return `r${value.value === undefined ? '' : shapeOf(value.value)}`
  if (value instanceof NativePointer) return 'p'
  if (Array.isArray(value)) return 'a'
  const klass = managedClassOf(value)
  if (klass !== undefined) return `${value instanceof EnumValue ? 'e' : 'w'}${klass.handle}`
  return 'o'
}
