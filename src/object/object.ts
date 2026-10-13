import { MonoError } from '../errors'
import type { MonoObjectPtr } from '../native/api.generated'
import { api } from '../native/api'
import { Class } from '../meta/class'
import { freeHandle, handleTarget, newHandle, type GcHandle } from './handles'
import { readMonoString } from './string'

/**
 * A reference to a managed object. Holds a GC handle, not a raw pointer, so it stays valid when SGen
 * moves the object; {@link pointer} resolves the current address on every access. The handle is
 * freed when the wrapper is garbage-collected, on script unload, or by {@link dispose}.
 */
export class ManagedObject {
  readonly gcHandle: GcHandle
  #weakRef: number | null
  #state: { freed: boolean }
  #class?: Class

  constructor(pointer: NativePointer, options: { weak?: boolean } = {}) {
    if (pointer.isNull()) throw new TypeError('Cannot wrap a NULL object')
    const handle = newHandle(pointer as MonoObjectPtr, options.weak)
    const state = { freed: false }
    this.gcHandle = handle
    this.#state = state
    // The callback must not capture `this`, or the wrapper could never be collected.
    this.#weakRef = Script.bindWeak(this, () => {
      if (state.freed) return
      state.freed = true
      freeHandle(handle)
    })
  }

  /** The object's current address. `NULL` once a weak handle's target was collected. */
  get pointer(): MonoObjectPtr {
    if (this.#weakRef === null) throw new MonoError('Object wrapper was disposed')
    return handleTarget(this.gcHandle)
  }

  /** The runtime (most-derived) class. */
  get class(): Class {
    return (this.#class ??= Class.from(api.mono_object_get_class(this.pointer)))
  }

  /** True if the object is an instance of `klass` (inheritance and interfaces). */
  isInstanceOf(klass: Class): boolean {
    return !api.mono_object_isinst(this.pointer, klass.handle).isNull()
  }

  /** True if both wrappers refer to the same managed object. */
  equals(other: ManagedObject): boolean {
    return this.pointer.equals(other.pointer)
  }

  /** Frees the GC handle now instead of when the wrapper is collected. */
  dispose(): void {
    if (this.#weakRef === null) return
    Script.unbindWeak(this.#weakRef)
    this.#weakRef = null
    if (!this.#state.freed) {
      this.#state.freed = true
      freeHandle(this.gcHandle)
    }
  }

  /** Managed `ToString()`. */
  toString(): string {
    return objectToString(this.pointer) ?? `${this.class.fullName}@${this.pointer}`
  }
}

/** Calls managed `ToString()` on an object; `null` if it throws. */
export function objectToString(object: MonoObjectPtr): string | null {
  const exc = Memory.alloc(Process.pointerSize)
  const result = api.mono_object_to_string(object, exc)
  return exc.readPointer().isNull() ? readMonoString(result) : null
}
