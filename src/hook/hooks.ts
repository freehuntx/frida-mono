import { MonoError } from '../errors'
import { invoke } from '../invoke/invoke'
import type { Method } from '../meta/method'
import { api } from '../native/api'
import { ManagedError } from '../object/managed-error'
import type { ManagedObject } from '../object/object'
import { StructView } from '../object/struct'
import { handleKey } from '../object/handles'
import { onUnload } from '../runtime/cleanup'
import { ensureThreadAttached } from '../runtime/thread'
import { hooks as wrapHooks } from '../marshal/hooks'
import { nativeSignature, type NativeSignature } from './native'

/**
 * A hook implementation: gets the (wrapped) `this` — `null` for static methods — and the arguments.
 *
 * If it throws (a JS error, or a managed exception from the original that it didn't catch), the
 * error is logged and the caller gets the default value (0/null). Exceptions can't be rethrown into
 * the managed caller: `mono_raise_exception` can't unwind through the hook's native frame (it
 * crashes the process, verified in e2e), so catch `Mono.ManagedError` in the hook where it matters.
 */
export type HookFunction = (self: unknown, args: unknown[]) => unknown

interface Entry {
  method: Method
  code: NativePointer
  signature: NativeSignature
  callback: NativeCallback<NativeCallbackReturnType, NativeCallbackArgumentType[]>
  /** Applies to every call. */
  global: HookFunction | null
  /** Applies to calls on one object only (keyed by GC handle). */
  instances: Map<string, { object: ManagedObject; fn: HookFunction }>
}

const entries = new Map<string, Entry>()

function report(method: Method, error: unknown): void {
  const text = error instanceof ManagedError ? error.managedStack : error instanceof Error ? (error.stack ?? error.message) : String(error)
  console.error(`frida-mono: hook on ${method.fullName} threw; returning the default value.\n${text}`)
}

function install(method: Method): Entry {
  const key = method.handle.toString()
  const existing = entries.get(key)
  if (existing !== undefined) return existing

  ensureThreadAttached()
  const signature = nativeSignature(method)
  const code = api.mono_compile_method(method.handle)
  if (code.isNull()) throw new MonoError(`mono_compile_method returned NULL for ${method.fullName}`)

  const entry = { method, code, signature, global: null, instances: new Map() } as unknown as Entry
  const replacement = (...raw: unknown[]): unknown => {
    ensureThreadAttached()
    let fn = entry.global
    if (entry.instances.size > 0 && !method.isStatic) {
      const self = raw[0] as NativePointer
      for (const { object, fn: instanceFn } of entry.instances.values()) {
        if (object.pointer.equals(self)) {
          fn = instanceFn
          break
        }
      }
    }
    let call
    try {
      call = signature.decode(raw)
    } catch (error) {
      report(method, error)
      return signature.defaultReturn
    }
    try {
      // No hook for this instance: run the original through the runtime, like any other call.
      const result = fn !== null ? fn(call.self, call.args) : callOriginal(method, call.self, call.args)
      call.writeBack()
      return call.encodeReturn(result)
    } catch (error) {
      report(method, error)
      return call.defaultReturn()
    }
  }
  entry.callback = new NativeCallback(replacement as NativeCallbackImplementation<NativeCallbackReturnValue, NativeCallbackArgumentValue[]>, signature.ret, signature.args)
  Interceptor.replace(code, entry.callback)
  entries.set(key, entry)
  if (entries.size === 1) onUnload(revertAll)
  return entry
}

/**
 * Calls the original implementation. Inside a hook, Frida's interceptor routes calls from the
 * hooking thread to the replaced function back to the original, so this runs the real method.
 */
export function callOriginal(method: Method, self: unknown, args: readonly unknown[]): unknown {
  const instance = self === null || self === undefined ? null : (wrapHooks.unwrap(self) ?? (self as ManagedObject | StructView))
  return invoke(method, instance, args, { virtual: false })
}

/** Replaces `method` for all calls, or only for calls on `instance`. Returns a function that removes it. */
export function override(method: Method, fn: HookFunction, instance: ManagedObject | StructView | null = null): () => void {
  if (instance instanceof StructView) throw new MonoError('Per-instance hooks need a reference-type instance (structs are copied on every call)')
  const entry = install(method)
  if (instance === null) {
    entry.global = fn
    return () => revert(method)
  }
  entry.instances.set(handleKey(instance.gcHandle), { object: instance, fn })
  return () => revert(method, instance)
}

/** Removes the hook of `method` (all calls, or one instance's). The native hook goes once nothing is left. */
export function revert(method: Method, instance: ManagedObject | null = null): void {
  const key = method.handle.toString()
  const entry = entries.get(key)
  if (entry === undefined) return
  if (instance === null) entry.global = null
  else entry.instances.delete(handleKey(instance.gcHandle))
  if (entry.global === null && entry.instances.size === 0) {
    Interceptor.revert(entry.code)
    Interceptor.flush()
    entries.delete(key)
  }
}

export function revertAll(): void {
  for (const entry of entries.values()) Interceptor.revert(entry.code)
  Interceptor.flush()
  entries.clear()
}

/** Methods currently hooked. */
export function hookedMethods(): Method[] {
  return [...entries.values()].map((e) => e.method)
}
