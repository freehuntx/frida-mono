import type { MonoApi } from './api'

/**
 * Stand-ins for public API functions some runtimes don't export (Unity's legacy Mono 2.6 lacks the
 * ones below; see docs/exports.md). `Mono.api.<name>` uses them when the export is missing, so
 * callers don't need to care. `Mono.api.has(name)` still reports whether the real export exists.
 *
 * Struct reads rely on layouts unchanged since Mono 2.x: MonoObject is two pointers (vtable, sync), followed by
 * - MonoString: `int32 length; uint16 chars[]`
 * - MonoArray: `MonoArrayBounds *bounds; size max_length` (read as 32-bit, which every array fits)
 * - MonoReflectionType: `MonoType *type`
 * and MonoType is `{ void *data; uint attrs:16; … }`.
 */

const HEADER = 2 * Process.pointerSize
const PARAM_ATTRIBUTE_OUT = 0x0002

type Fallback = (api: MonoApi) => (...args: never[]) => unknown

export const FALLBACKS: Readonly<Record<string, Fallback>> = {
  mono_string_length: () => (s: NativePointer) => s.add(HEADER).readS32(),
  mono_string_chars: () => (s: NativePointer) => s.add(HEADER + 4),
  mono_array_length: () => (a: NativePointer) => a.add(HEADER + Process.pointerSize).readU32(),
  mono_reflection_type_get_type: () => (t: NativePointer) => t.add(HEADER).readPointer(),

  mono_signature_param_is_out: (api) => (signature: NativePointer, index: number) => {
    const iter = Memory.alloc(Process.pointerSize)
    let type: NativePointer = NULL
    for (let i = 0; i <= index; i++) type = api.mono_signature_get_params(signature as never, iter)
    return !type.isNull() && (type.add(Process.pointerSize).readU16() & PARAM_ATTRIBUTE_OUT) !== 0 ? 1 : 0
  },

  mono_class_is_delegate: (api) => (klass: NativePointer) => {
    for (let c = api.mono_class_get_parent(klass as never); !c.isNull(); c = api.mono_class_get_parent(c)) {
      if (api.mono_class_get_name(c).readUtf8String() === 'MulticastDelegate' && api.mono_class_get_namespace(c).readUtf8String() === 'System') return 1
    }
    return 0
  },

  /**
   * Older Unity `mono.dll` builds (e.g. Unity 5 on Windows) predate `mono_free`. The strings it frees
   * come from eglib's `g_malloc`, so `g_free` is the matching deallocator. Without either, leak:
   * `free()` from another C runtime would corrupt the heap.
   */
  mono_free: (api) => {
    const gFree = api.address('g_free')
    if (gFree === null) return () => undefined
    const free = new NativeFunction(gFree, 'void', ['pointer'], { exceptions: 'propagate' })
    return (pointer: NativePointer) => free(pointer)
  },

  /** Without the name struct accessor there's nothing to stringify; `Assembly.fullName` falls back to the simple name. */
  mono_assembly_get_name: () => () => NULL,
  mono_stringify_assembly_name: () => () => NULL,
  mono_domain_get_friendly_name: () => () => NULL,

  /** `object.ToString()` through a virtual call. */
  mono_object_to_string: (api) => (object: NativePointer, exc: NativePointer) => {
    const objectClass = api.mono_get_object_class()
    const toString = api.mono_class_get_method_from_name(objectClass, Memory.allocUtf8String('ToString'), 0)
    const method = api.mono_object_get_virtual_method(object as never, toString)
    const self = api.mono_class_is_valuetype(api.mono_method_get_class(method)) !== 0 ? api.mono_object_unbox(object as never) : object
    return api.mono_runtime_invoke(method, self, NULL, exc.isNull() ? Memory.alloc(Process.pointerSize) : exc)
  }
}
