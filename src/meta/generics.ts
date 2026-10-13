import { MonoError } from '../errors'
import { invoke } from '../invoke/invoke'
import type { MonoMethodPtr, MonoReflectionTypePtr } from '../native/api.generated'
import { api } from '../native/api'
import { asManagedObject } from '../marshal/hooks'
import { MArray } from '../object/array'
import { ManagedObject } from '../object/object'
import { Class } from './class'
import type { Method } from './method'

// mono_class_bind_generic_parameters isn't public API, so generic instantiation goes through managed
// reflection (Type.MakeGenericType / MethodInfo.MakeGenericMethod), which every runtime has.

const typeObjects = new Map<string, ManagedObject>()

/** The `System.Type` object of `klass` (cached; reflection objects are unique per type). */
export function typeObject(klass: Class): ManagedObject {
  const key = klass.handle.toString()
  let object = typeObjects.get(key)
  if (object === undefined) {
    object = new ManagedObject(api.mono_type_get_object(api.mono_domain_get(), klass.type.handle))
    typeObjects.set(key, object)
  }
  return object
}

function systemClass(name: string): Class {
  const klass = Class.from.orNull(api.mono_class_from_name(api.mono_get_corlib(), Memory.allocUtf8String('System'), Memory.allocUtf8String(name)))
  if (klass === null) throw new MonoError(`System.${name} not found in corlib`)
  return klass
}

function typeArray(args: readonly Class[]): MArray {
  return MArray.from(systemClass('Type'), args.map(typeObject))
}

function requireArity(what: string, expected: number, got: number): void {
  if (expected !== got) throw new MonoError(`${what} takes ${expected} type argument(s), got ${got}`)
}

const genericArguments = new Map<string, readonly Class[]>()

/**
 * Type arguments of a generic instance (`List<String>` → `[String]`), or the type parameters of a
 * definition (`List<T>` → `[T]`, generic-parameter classes). Empty for non-generic classes.
 */
export function classGenericArguments(klass: Class): readonly Class[] {
  const key = klass.handle.toString()
  let args = genericArguments.get(key)
  if (args === undefined) {
    args = []
    if (klass.isGenericInstance || klass.isGenericDefinition) {
      const type = typeObject(klass)
      const get = type.class.method('GetGenericArguments', 0)
      if (get !== null) {
        args = (invoke(get, type, []) as MArray)
          .toArray()
          .map((t) => Class.from(api.mono_class_from_mono_type(api.mono_reflection_type_get_type(asManagedObject(t).pointer as unknown as MonoReflectionTypePtr))))
      }
    }
    genericArguments.set(key, args)
  }
  return args
}

const closedClasses = new Map<string, Class>()

/** `List<T>` + `[String]` → `List<String>`. */
export function makeGenericClass(definition: Class, args: readonly Class[]): Class {
  if (!definition.isGenericDefinition) throw new MonoError(`${definition.fullName} is not a generic type definition`)
  const arity = Number(/`(\d+)/.exec(definition.name)?.[1] ?? args.length)
  requireArity(definition.fullName, arity, args.length)
  const key = [definition, ...args].map((c) => c.handle.toString()).join(',')
  let closed = closedClasses.get(key)
  if (closed === undefined) {
    const make = systemClass('Type').method('MakeGenericType', 1)
    if (make === null) throw new MonoError('System.Type.MakeGenericType not found')
    const result = asManagedObject(invoke(make, typeObject(definition), [typeArray(args)]))
    closed = Class.from(api.mono_class_from_mono_type(api.mono_reflection_type_get_type(result.pointer as unknown as MonoReflectionTypePtr)))
    closedClasses.set(key, closed)
  }
  return closed
}

const methodObjects = new Map<string, ManagedObject>()

/** The `MethodInfo` object of `method`. */
export function methodObject(method: Method): ManagedObject {
  const key = method.handle.toString()
  let object = methodObjects.get(key)
  if (object === undefined) {
    object = new ManagedObject(api.mono_method_get_object(api.mono_domain_get(), method.handle, method.class.handle))
    methodObjects.set(key, object)
  }
  return object
}

const genericDefinitions = new Map<string, number>()

/** Number of generic parameters of a generic method definition (`Map<U>` → 1), 0 for other methods. */
export function genericMethodArity(method: Method): number {
  const key = method.handle.toString()
  let arity = genericDefinitions.get(key)
  if (arity !== undefined) return arity
  // mono_method_full_name writes generic method definitions as `Ns.Class:Name<T> (…)`.
  if (!method.fullName.includes(`:${method.name}<`)) {
    genericDefinitions.set(key, 0)
    return 0
  }
  // Provisional value: the reflection calls below invoke methods, which ask for their own arity.
  genericDefinitions.set(key, 0)
  const info = methodObject(method)
  const isDefinition = info.class.property('IsGenericMethodDefinition')?.getter ?? null
  const getArgs = info.class.method('GetGenericArguments', 0)
  arity = isDefinition !== null && getArgs !== null && invoke(isDefinition, info, []) === true ? (invoke(getArgs, info, []) as MArray).length : 0
  genericDefinitions.set(key, arity)
  return arity
}

const argumentNames = new Map<string, readonly string[]>()

/** Names of a generic method definition's type parameters (`Map<U>` → `['U']`). */
export function genericMethodArgumentNames(method: Method): readonly string[] {
  const key = method.handle.toString()
  let names = argumentNames.get(key)
  if (names === undefined) {
    names = []
    if (genericMethodArity(method) > 0) {
      const info = methodObject(method)
      const getArgs = info.class.method('GetGenericArguments', 0)
      if (getArgs !== null) {
        // Each element is a System.Type of a generic parameter, whose ToString() is its name.
        names = (invoke(getArgs, info, []) as MArray).toArray().map(String)
      }
    }
    argumentNames.set(key, names)
  }
  return names
}

const closedMethods = new Map<string, Method>()

/** `Enumerable.Count<T>` + `[String]` → `Count<String>`. */
export function makeGenericMethod(definition: Method, args: readonly Class[], from: (handle: MonoMethodPtr) => Method): Method {
  requireArity(definition.fullName, genericMethodArity(definition), args.length)
  const key = [definition.handle, ...args.map((c) => c.handle)].map(String).join(',')
  let closed = closedMethods.get(key)
  if (closed === undefined) {
    const info = methodObject(definition)
    const make = info.class.method('MakeGenericMethod', 1)
    if (make === null) throw new MonoError('MethodInfo.MakeGenericMethod not found')
    const result = asManagedObject(invoke(make, info, [typeArray(args)]))
    // MonoReflectionMethod: { MonoObject object; MonoMethod *method; … }
    closed = from(result.pointer.add(2 * Process.pointerSize).readPointer() as MonoMethodPtr)
    closedMethods.set(key, closed)
  }
  return closed
}
