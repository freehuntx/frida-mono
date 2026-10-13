import type { Assembly } from '../meta/assembly'
import type { Class } from '../meta/class'
import { MethodAttributes, TypeEnum } from '../meta/constants'
import { assemblies as loadedAssemblies, getAssembly } from '../meta/lookup'
import type { Method } from '../meta/method'
import type { Type } from '../meta/type'
import { enumMembers } from '../object/enum'
import { getRuntimeBuildInfo } from '../runtime/version'
import { ensureThreadAttached } from '../runtime/thread'
import type { DumpModel, MethodModel, PrimitiveName, TypeModel, TypeRef } from './model'

const PRIMITIVES: Partial<Record<number, PrimitiveName>> = {
  [TypeEnum.BOOLEAN]: 'bool',
  [TypeEnum.CHAR]: 'char',
  [TypeEnum.I1]: 'sbyte',
  [TypeEnum.U1]: 'byte',
  [TypeEnum.I2]: 'short',
  [TypeEnum.U2]: 'ushort',
  [TypeEnum.I4]: 'int',
  [TypeEnum.U4]: 'uint',
  [TypeEnum.I8]: 'long',
  [TypeEnum.U8]: 'ulong',
  [TypeEnum.R4]: 'float',
  [TypeEnum.R8]: 'double',
  [TypeEnum.I]: 'nint',
  [TypeEnum.U]: 'nuint',
  [TypeEnum.STRING]: 'string',
  [TypeEnum.OBJECT]: 'object'
}

/** Reflection-style key of a class: `Ns.Outer+Inner`, keeping the arity of generics (`Box\`1`). */
export function classKey(klass: Class): string {
  const declaring = klass.declaringClass
  if (declaring !== null) return `${classKey(declaring)}+${klass.name}`
  return klass.namespace === '' ? klass.name : `${klass.namespace}.${klass.name}`
}

function shapeOf(klass: Class): 'class' | 'interface' | 'struct' | 'enum' | 'delegate' {
  if (klass.isInterface) return 'interface'
  if (klass.isEnum) return 'enum'
  if (klass.isValueType) return 'struct'
  if (klass.isDelegate) return 'delegate'
  return 'class'
}

function typeRef(type: Type): TypeRef {
  if (type.isByRef) return { kind: 'byref', type: typeRef(type.class.type) }
  const t = type.typeEnum
  if (t === TypeEnum.VOID) return { kind: 'void' }
  const primitive = PRIMITIVES[t]
  if (primitive !== undefined) return { kind: 'primitive', name: primitive }
  if (t === TypeEnum.VAR || t === TypeEnum.MVAR) return { kind: 'generic', name: type.name }
  if (t === TypeEnum.PTR || t === TypeEnum.FNPTR) return { kind: 'pointer' }
  const klass = type.class
  if (t === TypeEnum.SZARRAY || t === TypeEnum.ARRAY) return { kind: 'array', element: typeRef(klass.elementClass.type), rank: klass.rank }
  return classRef(klass)
}

function classRef(klass: Class): TypeRef {
  const key = classKey(klass)
  if (key === 'System.Type') return { kind: 'primitive', name: 'type' }
  if (klass.isGenericInstance) {
    const args = klass.genericArguments.map((c) => typeRef(c.type))
    if (key === 'System.Nullable`1' && args[0] !== undefined) return { kind: 'nullable', type: args[0] }
    return { kind: 'type', key, args, shape: shapeOf(klass) }
  }
  return { kind: 'type', key, args: [], shape: shapeOf(klass) }
}

/** Names that compilers generate (`<>c`, `<Age>k__BackingField`, `<PrivateImplementationDetails>`). */
function isCompilerGenerated(name: string): boolean {
  return name.includes('<') || name.includes('>') || name.includes('$')
}

function methodModel(method: Method): MethodModel {
  return {
    name: method.name,
    static: method.isStatic,
    access: method.access,
    virtual: method.isVirtual,
    abstract: method.isAbstract,
    genericParams: method.genericArity > 0 ? [...method.genericArgumentNames] : [],
    params: method.parameters.map((p) => ({ name: p.name, type: typeRef(p.type), out: p.out })),
    returns: typeRef(method.returnType)
  }
}

function typeModel(klass: Class): TypeModel {
  const accessorNames = new Set<string>()
  for (const p of klass.properties) {
    if (p.getter !== null) accessorNames.add(p.getter.name)
    if (p.setter !== null) accessorNames.add(p.setter.name)
  }
  for (const e of klass.events) for (const m of [e.add, e.remove, e.raise]) if (m !== null) accessorNames.add(m.name)

  const methods = klass.methods.filter((m) => !accessorNames.has(m.name) && !(m.flags & MethodAttributes.SPECIAL_NAME && !m.name.startsWith('op_')) && !isCompilerGenerated(m.name))
  const visibility = klass.flags & 0x7
  return {
    key: classKey(klass),
    namespace: klass.namespace,
    name: klass.name.replace(/`\d+$/, ''),
    declaringType: klass.declaringClass === null ? null : classKey(klass.declaringClass),
    kind: shapeOf(klass),
    access: visibility === 1 ? 'public' : visibility === 0 ? 'internal' : 'nested',
    abstract: klass.isAbstract,
    sealed: klass.isSealed,
    genericParams: klass.isGenericDefinition ? klass.genericArguments.map((c) => c.name) : [],
    parent: klass.parent === null || klass.isEnum || klass.isValueType ? null : classRef(klass.parent),
    interfaces: klass.interfaces.map(classRef),
    enumValues: klass.isEnum ? [...enumMembers(klass)].map(([name, value]) => ({ name, value: value.toString() })) : [],
    fields: klass.isEnum
      ? []
      : klass.fields
          .filter((f) => !isCompilerGenerated(f.name))
          .map((f) => ({ name: f.name, static: f.isStatic, access: f.access, readonly: f.isInitOnly, literal: f.isLiteral, type: typeRef(f.type) })),
    properties: klass.properties
      .filter((p) => (p.getter ?? p.setter) !== null && !isCompilerGenerated(p.name))
      .map((p) => ({ name: p.name, static: p.isStatic, type: typeRef(p.type), get: p.getter !== null, set: p.setter !== null, index: p.indexParameters.map(typeRef) })),
    methods: methods.filter((m) => !m.isConstructor).map(methodModel),
    // Constructors carry the special-name flag, so they come from the unfiltered list.
    constructors: klass.methods.filter((m) => m.name === '.ctor').map(methodModel),
    events: klass.events.filter((e) => !isCompilerGenerated(e.name)).map((e) => ({ name: e.name, static: e.isStatic, type: e.type === null ? null : typeRef(e.type) }))
  }
}

export interface DumpOptions {
  /** Assembly names to dump. Default: every loaded assembly except the framework (corlib, `System*`, `Mono*`). */
  assemblies?: readonly string[]
}

function isFramework(name: string): boolean {
  return name === 'mscorlib' || name === 'netstandard' || /^(System|Mono|Microsoft)(\.|$)/.test(name)
}

/** Collects the dump model of the given assemblies. Types that fail to load are skipped. */
export function collect(options: DumpOptions = {}): DumpModel {
  ensureThreadAttached()
  const selected: Assembly[] = options.assemblies === undefined ? loadedAssemblies().filter((a) => !isFramework(a.name)) : options.assemblies.map((name) => getAssembly(name))
  const types: TypeModel[] = []
  for (const assembly of selected) {
    for (const klass of assembly.image.classes) {
      if (isCompilerGenerated(klass.name)) continue
      try {
        types.push(typeModel(klass))
      } catch (error) {
        console.warn(`frida-mono: dump skipped ${klass.fullName}: ${error instanceof Error ? error.message : String(error)}`)
      }
    }
  }
  return { runtime: getRuntimeBuildInfo(), assemblies: selected.map((a) => a.name), types }
}
