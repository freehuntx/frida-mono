import { api } from '../native/api'

/** Reads a UTF-8 string the runtime allocated for the caller and frees it with `mono_free`. */
export function takeUtf8(pointer: NativePointer): string | null {
  if (pointer.isNull()) return null
  try {
    return pointer.readUtf8String()
  } finally {
    api.mono_free(pointer)
  }
}

/** Reads a UTF-8 string owned by the runtime (metadata names etc.), without freeing it. */
export function readUtf8(pointer: NativePointer): string | null {
  return pointer.isNull() ? null : pointer.readUtf8String()
}
