import type { MonoStringPtr } from '../native/api.generated'
import { api } from '../native/api'

/** `MonoString*` → JS string, read as UTF-16 so surrogate pairs survive. `NULL` → `null`. */
export function readMonoString(pointer: NativePointer): string | null {
  if (pointer.isNull()) return null
  const s = pointer as MonoStringPtr
  const length = api.mono_string_length(s)
  return length === 0 ? '' : api.mono_string_chars(s).readUtf16String(length)
}

/** JS string → new `MonoString*` in the current domain. Unrooted: pin it or hand it to managed code right away. */
export function newMonoString(text: string): MonoStringPtr {
  return api.mono_string_new_utf16(api.mono_domain_get(), Memory.allocUtf16String(text), text.length)
}
