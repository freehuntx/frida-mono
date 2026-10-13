// Values from ECMA-335 and Mono's metadata/blob.h, metadata/tabledefs.h.

/** `MonoTypeEnum`: the element type of a `MonoType`. */
export const TypeEnum = {
  END: 0x00,
  VOID: 0x01,
  BOOLEAN: 0x02,
  CHAR: 0x03,
  I1: 0x04,
  U1: 0x05,
  I2: 0x06,
  U2: 0x07,
  I4: 0x08,
  U4: 0x09,
  I8: 0x0a,
  U8: 0x0b,
  R4: 0x0c,
  R8: 0x0d,
  STRING: 0x0e,
  PTR: 0x0f,
  BYREF: 0x10,
  VALUETYPE: 0x11,
  CLASS: 0x12,
  VAR: 0x13,
  ARRAY: 0x14,
  GENERICINST: 0x15,
  TYPEDBYREF: 0x16,
  I: 0x18,
  U: 0x19,
  FNPTR: 0x1b,
  OBJECT: 0x1c,
  SZARRAY: 0x1d,
  MVAR: 0x1e,
  CMOD_REQD: 0x1f,
  CMOD_OPT: 0x20,
  INTERNAL: 0x21,
  MODIFIER: 0x40,
  SENTINEL: 0x41,
  PINNED: 0x45,
  ENUM: 0x55
} as const

export type TypeEnum = (typeof TypeEnum)[keyof typeof TypeEnum]

const TYPE_ENUM_NAMES = new Map<number, string>(Object.entries(TypeEnum).map(([name, value]) => [value, name]))

export function typeEnumName(value: number): string {
  return TYPE_ENUM_NAMES.get(value) ?? `0x${value.toString(16)}`
}

/** Metadata table ids (`MONO_TABLE_*`). */
export const Table = {
  TYPEDEF: 2
} as const

/** Token type prefixes (`MONO_TOKEN_*`). */
export const Token = {
  TYPE_DEF: 0x02000000
} as const

/** Member access, shared by fields and methods (`FIELD_ATTRIBUTE_FIELD_ACCESS_MASK` / `METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK`). */
export const MemberAccess = {
  MASK: 0x0007,
  COMPILER_CONTROLLED: 0x0000,
  PRIVATE: 0x0001,
  FAMILY_AND_ASSEMBLY: 0x0002,
  ASSEMBLY: 0x0003,
  FAMILY: 0x0004,
  FAMILY_OR_ASSEMBLY: 0x0005,
  PUBLIC: 0x0006
} as const

export type Access = 'private' | 'private protected' | 'internal' | 'protected' | 'protected internal' | 'public' | 'compiler-controlled'

export function accessOf(flags: number): Access {
  switch (flags & MemberAccess.MASK) {
    case MemberAccess.PRIVATE:
      return 'private'
    case MemberAccess.FAMILY_AND_ASSEMBLY:
      return 'private protected'
    case MemberAccess.ASSEMBLY:
      return 'internal'
    case MemberAccess.FAMILY:
      return 'protected'
    case MemberAccess.FAMILY_OR_ASSEMBLY:
      return 'protected internal'
    case MemberAccess.PUBLIC:
      return 'public'
    default:
      return 'compiler-controlled'
  }
}

export const FieldAttributes = {
  STATIC: 0x0010,
  INIT_ONLY: 0x0020,
  LITERAL: 0x0040,
  SPECIAL_NAME: 0x0200
} as const

export const MethodAttributes = {
  STATIC: 0x0010,
  FINAL: 0x0020,
  VIRTUAL: 0x0040,
  ABSTRACT: 0x0400,
  SPECIAL_NAME: 0x0800,
  PINVOKE_IMPL: 0x2000
} as const

export const MethodImplAttributes = {
  INTERNAL_CALL: 0x1000
} as const

export const TypeAttributes = {
  VISIBILITY_MASK: 0x0007,
  NOT_PUBLIC: 0x0000,
  PUBLIC: 0x0001,
  NESTED_PUBLIC: 0x0002,
  INTERFACE: 0x0020,
  ABSTRACT: 0x0080,
  SEALED: 0x0100
} as const
