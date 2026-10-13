/**
 * The JSON model `Mono.dump()` produces (`format: 'json'`) and the emitters consume. Plain data, no
 * Frida types, so typings can also be generated on the Node side (CLI).
 */

/** A type as it appears in a signature. */
export type TypeRef =
  | { kind: 'void' }
  | { kind: 'primitive'; name: PrimitiveName }
  | { kind: 'generic'; name: string }
  | { kind: 'byref'; type: TypeRef }
  | { kind: 'array'; element: TypeRef; rank: number }
  | { kind: 'pointer' }
  | { kind: 'nullable'; type: TypeRef }
  | { kind: 'type'; key: string; args: TypeRef[]; shape: 'class' | 'interface' | 'struct' | 'enum' | 'delegate' }

export type PrimitiveName =
  'bool' | 'char' | 'sbyte' | 'byte' | 'short' | 'ushort' | 'int' | 'uint' | 'long' | 'ulong' | 'float' | 'double' | 'nint' | 'nuint' | 'string' | 'object' | 'type'

export interface ParamModel {
  name: string
  type: TypeRef
  out: boolean
}

export interface MethodModel {
  name: string
  static: boolean
  access: string
  virtual: boolean
  abstract: boolean
  genericParams: string[]
  params: ParamModel[]
  returns: TypeRef
}

export interface FieldModel {
  name: string
  static: boolean
  access: string
  readonly: boolean
  literal: boolean
  type: TypeRef
}

export interface PropertyModel {
  name: string
  static: boolean
  type: TypeRef
  get: boolean
  set: boolean
  index: TypeRef[]
}

export interface EventModel {
  name: string
  static: boolean
  type: TypeRef | null
}

export interface TypeModel {
  /** Reflection-style key: `Ns.Outer+Inner`, generic definitions with arity (`Ns.Box\`1`). */
  key: string
  namespace: string
  /** Simple name without arity (`Box`). */
  name: string
  /** Key of the enclosing type, for nested types. */
  declaringType: string | null
  kind: 'class' | 'interface' | 'struct' | 'enum' | 'delegate'
  access: 'public' | 'internal' | 'nested'
  abstract: boolean
  sealed: boolean
  genericParams: string[]
  parent: TypeRef | null
  interfaces: TypeRef[]
  enumValues: { name: string; value: string }[]
  fields: FieldModel[]
  properties: PropertyModel[]
  methods: MethodModel[]
  constructors: MethodModel[]
  events: EventModel[]
}

export interface DumpModel {
  runtime: string | null
  assemblies: string[]
  types: TypeModel[]
}
