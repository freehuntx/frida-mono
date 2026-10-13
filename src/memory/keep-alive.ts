const alive = new Set<unknown>()

/** Keeps `value` (e.g. a `NativeCallback` handed to Mono) from being garbage-collected until the script unloads. */
export function keepAlive<T>(value: T): T {
  alive.add(value)
  return value
}

/** Releases a value kept by {@link keepAlive}. */
export function release(value: unknown): void {
  alive.delete(value)
}
