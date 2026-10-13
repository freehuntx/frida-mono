/**
 * One wrapper per handle and kind: keyed by the full pointer string, so 64-bit
 * addresses never collide, and one map per kind, so a class and an image at the same address
 * can't be confused. Metadata lives as long as its domain, so entries are never evicted.
 */
export interface Interner<P extends NativePointer, T> {
  (handle: P): T
  /** Like calling the interner, but maps a NULL handle to `null`. */
  orNull(handle: P): T | null
}

export function interner<P extends NativePointer, T>(create: (handle: P) => T): Interner<P, T> {
  const cache = new Map<string, T>()
  const get = (handle: P): T => {
    if (handle.isNull()) throw new TypeError('NULL handle')
    const key = handle.toString()
    let value = cache.get(key)
    if (value === undefined) {
      value = create(handle)
      cache.set(key, value)
    }
    return value
  }
  return Object.assign(get, { orNull: (handle: P): T | null => (handle.isNull() ? null : get(handle)) })
}

/** Collects a Mono `void* iter` style enumeration (`mono_class_get_methods(klass, &iter)` etc.). */
export function iterate<P extends NativePointer>(next: (iter: NativePointer) => P): P[] {
  const iter = Memory.alloc(Process.pointerSize)
  const out: P[] = []
  for (let item = next(iter); !item.isNull(); item = next(iter)) out.push(item)
  return out
}
