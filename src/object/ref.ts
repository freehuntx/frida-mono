/** A `ref`/`out` argument: pass it in place of the value, read `.value` after the call. */
export class Ref<T = unknown> {
  constructor(public value: T) {}

  toString(): string {
    return `ref ${String(this.value)}`
  }
}

/** `Mono.ref()` for `out` parameters, `Mono.ref(initial)` for `ref` parameters. */
export function ref<T = unknown>(initial?: T): Ref<T> {
  return new Ref(initial as T)
}
