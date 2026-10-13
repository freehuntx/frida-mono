/**
 * Short-lived native allocations for one call: everything allocated through a scope stays alive
 * until {@link Scope.dispose} (or the end of {@link scoped}), then becomes collectable.
 */
export class Scope {
  #held: NativePointer[] = []
  #deferred: (() => void)[] = []

  /** `size` zeroed bytes. */
  alloc(size: number): NativePointer {
    return this.hold(Memory.alloc(Math.max(size, 1)))
  }

  /** NUL-terminated UTF-8 copy of `text`. */
  utf8(text: string): NativePointer {
    return this.hold(Memory.allocUtf8String(text))
  }

  /** NUL-terminated UTF-16 copy of `text`. */
  utf16(text: string): NativePointer {
    return this.hold(Memory.allocUtf16String(text))
  }

  /** A `void*[]` holding `values`. */
  pointers(values: readonly NativePointerValue[]): NativePointer {
    const array = this.alloc(values.length * Process.pointerSize)
    values.forEach((value, i) => array.add(i * Process.pointerSize).writePointer(value as NativePointer))
    return array
  }

  /** A zeroed pointer-sized out-parameter (`void*`, `MonoObject**`, iterator state, …). */
  out(): NativePointer {
    return this.alloc(Process.pointerSize)
  }

  /** Keeps `pointer`'s backing memory alive for the scope's lifetime. */
  hold<T extends NativePointer>(pointer: T): T {
    this.#held.push(pointer)
    return pointer
  }

  /** Runs `fn` when the scope is disposed (in reverse order), e.g. to free a temporary GC handle. */
  defer(fn: () => void): void {
    this.#deferred.push(fn)
  }

  dispose(): void {
    for (let fn = this.#deferred.pop(); fn !== undefined; fn = this.#deferred.pop()) fn()
    this.#held.length = 0
  }
}

/** Runs `fn` with a fresh {@link Scope} that is disposed afterwards, even if `fn` throws. */
export function scoped<T>(fn: (scope: Scope) => T): T {
  const scope = new Scope()
  try {
    return fn(scope)
  } finally {
    scope.dispose()
  }
}
