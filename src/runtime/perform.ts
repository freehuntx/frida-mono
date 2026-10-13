import { whenAssemblyLoaded } from './assembly-load'
import { MonoNotFoundError } from '../errors'
import { isRuntimeReady, whenRuntimeReady } from './ready'
import { ensureThreadAttached } from './thread'

export interface PerformOptions {
  /** Assembly names (e.g. `'Assembly-CSharp'`) that must be loaded before `fn` runs. */
  waitFor?: string | readonly string[]
}

/**
 * Runs `fn` once Mono is ready: waits for the runtime module, its initialization and any assemblies
 * in `options.waitFor`, then attaches the calling thread and runs `fn`.
 *
 * When something has to be waited for, `fn` runs synchronously on the thread that completed it (the
 * one initializing Mono or loading the assembly), before managed code gets to use it. That's the
 * moment to install hooks.
 */
export function perform<T>(fn: () => T, options: PerformOptions = {}): Promise<Awaited<T>> {
  const assemblies = typeof options.waitFor === 'string' ? [options.waitFor] : [...(options.waitFor ?? [])]

  return new Promise((resolve, reject) => {
    const run = (): void => {
      try {
        ensureThreadAttached()
        Promise.resolve(fn()).then(resolve, reject)
      } catch (error) {
        reject(error)
      }
    }
    const next = (): void => {
      const name = assemblies.shift()
      if (name === undefined) return run()
      try {
        ensureThreadAttached()
        whenAssemblyLoaded(name, next)
      } catch (error) {
        reject(error)
      }
    }
    whenRuntimeReady(next)
  })
}

/** Runs `fn` right away on an attached thread. Throws {@link MonoNotFoundError} if Mono isn't ready. */
export function performNow<T>(fn: () => T): T {
  if (!isRuntimeReady()) throw new MonoNotFoundError('Mono is not loaded or not initialized yet. Use Mono.perform() to wait for it.')
  ensureThreadAttached()
  return fn()
}
