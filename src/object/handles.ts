import type { MonoObjectPtr } from '../native/api.generated'
import { api } from '../native/api'
import type { Scope } from '../memory/scope'

/**
 * A GC handle: a 32-bit number with the classic API, or a pointer with the `_v2` API.
 *
 * Unity's MonoBleedingEdge made handles pointers internally and kept the `uint32_t` API as a
 * truncating wrapper (`(uint32_t)(size_t)handle`), which corrupts every handle above 4 GB on 64-bit.
 * So the `_v2` functions are used whenever the runtime exports them.
 */
export type GcHandle = number | NativePointer

interface HandleApi {
  create(object: NativePointer, pinned: boolean): GcHandle
  createWeak(object: NativePointer): GcHandle
  target(handle: GcHandle): MonoObjectPtr
  free(handle: GcHandle): void
}

let handleApi: HandleApi | null = null

function handles(): HandleApi {
  if (handleApi !== null) return handleApi
  if (api.has('mono_gchandle_new_v2')) {
    const create = api.bind('mono_gchandle_new_v2', 'pointer', ['pointer', 'int'])
    const createWeak = api.bind('mono_gchandle_new_weakref_v2', 'pointer', ['pointer', 'int'])
    const target = api.bind('mono_gchandle_get_target_v2', 'pointer', ['pointer'])
    const free = api.bind('mono_gchandle_free_v2', 'void', ['pointer'])
    handleApi = {
      create: (object, pinned) => create(object, pinned ? 1 : 0),
      createWeak: (object) => createWeak(object, 0),
      target: (handle) => target(handle as NativePointer) as MonoObjectPtr,
      free: (handle) => free(handle as NativePointer)
    }
  } else {
    handleApi = {
      create: (object, pinned) => api.mono_gchandle_new(object as MonoObjectPtr, pinned ? 1 : 0),
      createWeak: (object) => api.mono_gchandle_new_weakref(object as MonoObjectPtr, 0),
      target: (handle) => api.mono_gchandle_get_target(handle as number),
      free: (handle) => api.mono_gchandle_free(handle as number)
    }
  }
  return handleApi
}

let live = 0

/** Debug counters (`Mono.stats`). */
export const stats = {
  /** GC handles currently held by JS wrappers. */
  get handles(): number {
    return live
  }
}

/** A strong (or weak) GC handle: keeps the object alive and finds it again after SGen moves it. */
export function newHandle(object: MonoObjectPtr, weak = false): GcHandle {
  live++
  return weak ? handles().createWeak(object) : handles().create(object, false)
}

export function freeHandle(handle: GcHandle): void {
  live--
  handles().free(handle)
}

export function handleTarget(handle: GcHandle): MonoObjectPtr {
  return handles().target(handle)
}

/** A key for maps keyed by handle (numbers and pointers alike). */
export function handleKey(handle: GcHandle): string {
  return handle.toString()
}

/**
 * Pins `object` until `scope` ends, so neither a GC nor a moving collection can invalidate the raw
 * pointer while it sits in an argument buffer that the GC doesn't scan. Returns the pointer.
 */
export function pinFor<P extends NativePointer>(object: P, scope: Scope): P {
  if (object.isNull()) return object
  const handle = handles().create(object, true)
  scope.defer(() => handles().free(handle))
  return object
}
