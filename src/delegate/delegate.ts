/* eslint-disable @typescript-eslint/no-explicit-any -- driven through the dynamic bridge */
import { MonoError } from '../errors'
import { Class } from '../meta/class'
import { scoped } from '../memory/scope'
import { persistentCallback } from '../memory/persistent'
import type { MonoObjectPtr } from '../native/api.generated'
import { api } from '../native/api'
import { box } from '../marshal/box'
import { asManagedObject } from '../marshal/hooks'
import { toObject } from '../marshal/marshaller'
import { MArray } from '../object/array'
import { freeHandle, newHandle } from '../object/handles'
import { ManagedObject } from '../object/object'
import { ensureThreadAttached } from '../runtime/thread'
import { classWrapper } from '../bridge/bridge'
import { namespaces as typedNamespaces } from '../bridge/namespaces'

// Untyped on purpose: generated typings (e.g. for corlib) augment `Mono.namespaces`, and library
// internals must not be typechecked against whatever a user generated.
const namespaces: any = typedNamespaces

/**
 * JS functions as managed delegates:
 *
 * 1. Once: a dynamic type with `[InternalCall] static object Invoke(int id, object[] args)`,
 *    bound with `mono_add_internal_call` to a persistent native callback that dispatches to JS.
 * 2. Per delegate: a `DynamicMethod` with the delegate's exact signature that boxes its arguments
 *    into `object[]`, calls `Invoke(id, args)` and unboxes/casts the result; `CreateDelegate` makes
 *    the delegate. Needs Reflection.Emit, which aggressive Unity code stripping can remove.
 */

type JsFunction = (...args: any[]) => unknown

interface Entry {
  fn: JsFunction
  returns: Class | null
}

const entries = new Map<number, Entry>()
let nextId = 1
let invokeInfo: any = null

function typeOf(klass: Class): any {
  return classWrapper(klass)
}

function bridgeInvoke(id: number, argsPointer: NativePointer): NativePointer {
  ensureThreadAttached()
  const entry = entries.get(id)
  if (entry === undefined) return NULL
  try {
    const args = argsPointer.isNull() ? [] : new MArray(argsPointer).toArray()
    const result = entry.fn(...args)
    if (entry.returns === null) return NULL
    const returns = entry.returns
    const object = returns.isValueType ? box(returns, result) : toObject(result, returns)
    // Keep the result alive until the managed caller holds it.
    if (!object.isNull()) {
      const handle = newHandle(object as MonoObjectPtr)
      setTimeout(() => freeHandle(handle), 0)
    }
    return object
  } catch (error) {
    console.error(`frida-mono: delegate callback threw; returning the default value.\n${error instanceof Error ? (error.stack ?? error.message) : String(error)}`)
    // default(T): a zeroed box for value types (unbox.any on null would throw in the caller).
    const returns = entry.returns
    return returns !== null && returns.isValueType ? api.mono_value_box(api.mono_domain_get(), returns.handle, Memory.alloc(Math.max(returns.valueSize, 8))) : NULL
  }
}

function ensureInvoke(): any {
  if (invokeInfo !== null) return invokeInfo
  const System = namespaces.System
  const Emit = System.Reflection.Emit
  // A fresh name per script load: earlier loads' types stay registered (with no-op callbacks).
  const suffix = `${Date.now().toString(36)}${Math.floor(Math.random() * 1e6).toString(36)}`
  const ns = 'FridaMono.Dynamic'
  const typeName = `Callbacks_${suffix}`

  const callback = persistentCallback(bridgeInvoke, 'pointer', ['int', 'pointer'])
  scoped((scope) => api.mono_add_internal_call(scope.utf8(`${ns}.${typeName}::Invoke`), callback))

  const name = new System.Reflection.AssemblyName(`${ns}.${suffix}`)
  const assembly = System.AppDomain.CurrentDomain.DefineDynamicAssembly(name, Emit.AssemblyBuilderAccess.Run)
  const module = assembly.DefineDynamicModule(`${ns}.${suffix}`)
  const TypeAttributes = System.Reflection.TypeAttributes
  const type = module.DefineType(`${ns}.${typeName}`, TypeAttributes.Public.value | TypeAttributes.Sealed.value | TypeAttributes.Abstract.value)
  const MethodAttributes = System.Reflection.MethodAttributes
  const objectArray = Class.from(api.mono_array_class_get(api.mono_get_object_class(), 1))
  const method = type.DefineMethod('Invoke', MethodAttributes.Public.value | MethodAttributes.Static.value, System.Object, [System.Int32, typeOf(objectArray)])
  method.SetImplementationFlags(System.Reflection.MethodImplAttributes.InternalCall)
  const created = type.CreateType()
  invokeInfo = created.GetMethod('Invoke')
  return invokeInfo
}

const cache = new WeakMap<JsFunction, Map<string, ManagedObject>>()

/**
 * A managed delegate of `delegateClass` (e.g. `System.Action`, `UnityEngine.Events.UnityAction`)
 * that calls `fn`. The same function and delegate type always give the same delegate, so passing
 * `fn` again to an event's `remove` works.
 */
export function createDelegate(delegateClass: Class, fn: JsFunction): ManagedObject {
  const key = delegateClass.handle.toString()
  let perFunction = cache.get(fn)
  const cached = perFunction?.get(key)
  if (cached !== undefined) return cached

  ensureThreadAttached()
  if (!delegateClass.isDelegate) throw new MonoError(`${delegateClass.fullName} is not a delegate type`)
  const invokeMethod = delegateClass.method('Invoke')
  if (invokeMethod === null) throw new MonoError(`${delegateClass.fullName} has no Invoke method`)
  const params = invokeMethod.parameters
  if (params.some((p) => p.byRef)) throw new MonoError(`${delegateClass.fullName}: delegates with ref/out parameters are not supported`)

  const System = namespaces.System
  const OpCodes = System.Reflection.Emit.OpCodes
  const invoke = ensureInvoke()
  const returnType = invokeMethod.returnType
  const returns = returnType.isVoid ? null : returnType.class
  const id = nextId++
  entries.set(id, { fn, returns })

  const dynamicMethod = new System.Reflection.Emit.DynamicMethod(
    `FridaMonoDelegate${id}`,
    typeOf(returnType.class),
    params.map((p) => typeOf(p.type.class)),
    invoke.DeclaringType
  )
  const il = dynamicMethod.GetILGenerator()
  const emitByte = il.Emit.$overload('System.Reflection.Emit.OpCode', 'System.Byte')
  il.Emit(OpCodes.Ldc_I4, id)
  il.Emit(OpCodes.Ldc_I4, params.length)
  il.Emit(OpCodes.Newarr, System.Object)
  params.forEach((p, i) => {
    il.Emit(OpCodes.Dup)
    il.Emit(OpCodes.Ldc_I4, i)
    if (i < 4) il.Emit([OpCodes.Ldarg_0, OpCodes.Ldarg_1, OpCodes.Ldarg_2, OpCodes.Ldarg_3][i])
    else emitByte(OpCodes.Ldarg_S, i)
    if (p.type.class.isValueType || p.type.isGenericParameter) il.Emit(OpCodes.Box, typeOf(p.type.class))
    il.Emit(OpCodes.Stelem_Ref)
  })
  il.Emit(OpCodes.Call, invoke)
  if (returns === null) il.Emit(OpCodes.Pop)
  else if (returns.isValueType) il.Emit(OpCodes.Unbox_Any, typeOf(returns))
  else il.Emit(OpCodes.Castclass, typeOf(returns))
  il.Emit(OpCodes.Ret)

  const delegate = asManagedObject(dynamicMethod.CreateDelegate(typeOf(delegateClass)))
  if (perFunction === undefined) {
    perFunction = new Map()
    cache.set(fn, perFunction)
  }
  perFunction.set(key, delegate)
  return delegate
}
