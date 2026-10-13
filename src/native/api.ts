import { MonoApiMissingError } from '../errors'
import { findMonoExport, monoExports } from '../runtime/exports'
import { getMonoModule } from '../runtime/module'
import { getRuntimeBuildInfo } from '../runtime/version'
import { MONO_API_TABLE, MONO_RUNTIMES_SCANNED, type MonoApiFunctions, type MonoApiName } from './api.generated'
import type { ApiEntry } from './entry'
import { FALLBACKS } from './fallbacks'

export interface MonoApi extends MonoApiFunctions {
  /**
   * True if the loaded runtime exports `name` (also for functions outside the generated table, e.g.
   * `mono_unity_*`). A few missing functions still work through fallbacks (src/native/fallbacks.ts).
   */
  has(name: string): boolean
  /** Address of an export, or `null`. */
  address(name: string): NativePointer | null
  /**
   * Binds an export that isn't in the generated table, e.g. Unity's `mono_unity_*` additions.
   * Throws {@link MonoApiMissingError} if it isn't exported.
   */
  bind<R extends NativeFunctionReturnType, A extends NativeFunctionArgumentType[] | []>(
    name: string,
    ret: R,
    args: A
  ): NativeFunction<GetNativeFunctionReturnValue<R>, ResolveVariadic<Extract<GetNativeFunctionArgumentValue<A>, unknown[]>>>
}

const TABLE: Readonly<Record<string, ApiEntry>> = MONO_API_TABLE

function missingMessage(name: string): string {
  const entry = TABLE[name]
  const declared =
    entry === undefined
      ? 'It is not part of the public headers frida-mono was generated from.'
      : entry.runtimes === undefined
        ? `Every scanned runtime declares it (${MONO_RUNTIMES_SCANNED.join(', ')}), so this runtime may be stripped or a fork.`
        : `Only these runtimes declare it: ${entry.runtimes.join(', ')}.`
  let runtime: string
  try {
    runtime = `${getMonoModule().name} (${getRuntimeBuildInfo() ?? 'legacy runtime without build info'})`
  } catch {
    runtime = 'the Mono runtime'
  }
  return `${name} is not exported by ${runtime}. ${declared} Check with Mono.api.has('${name}') first.`
}

function bindExport(name: string, ret: NativeFunctionReturnType, args: readonly (NativeFunctionArgumentType | '...')[]): (...a: unknown[]) => unknown {
  const address = findMonoExport(name)
  const fallback = FALLBACKS[name]
  if (address === null && fallback !== undefined) return fallback(api) as (...a: unknown[]) => unknown
  if (address === null) {
    const message = missingMessage(name)
    // Fails on call, not on access, so `const { a, b } = Mono.api` works on runtimes lacking `b`.
    return () => {
      throw new MonoApiMissingError(name, message)
    }
  }
  // 'propagate': Mono turns SIGSEGV/SIGFPE inside managed code into NullReference/DivideByZero
  // exceptions with its own signal handlers. Frida's default ('steal') would catch them first.
  return new NativeFunction(address, ret, args as NativeFunctionArgumentType[], { exceptions: 'propagate' }) as unknown as (...a: unknown[]) => unknown
}

function createApi(): MonoApi {
  const bound = new Map<string, unknown>()
  const helpers = {
    has: (name: string) => monoExports().has(name),
    address: (name: string) => findMonoExport(name),
    bind(name: string, ret: NativeFunctionReturnType, args: NativeFunctionArgumentType[]) {
      if (findMonoExport(name) === null) throw new MonoApiMissingError(name, missingMessage(name))
      return bindExport(name, ret, args)
    }
  }

  // Functions are created on first access, so nothing touches the process until a function is used.
  return new Proxy(helpers, {
    get(target, key, receiver) {
      if (typeof key !== 'string' || !(key in TABLE)) return Reflect.get(target, key, receiver)
      let fn = bound.get(key)
      if (fn === undefined) {
        const entry = TABLE[key as MonoApiName] as ApiEntry
        fn = bindExport(key, entry.ret, entry.args)
        bound.set(key, fn)
      }
      return fn
    },
    has: (target, key) => (typeof key === 'string' && key in TABLE) || key in target
  }) as unknown as MonoApi
}

/** The typed Mono C API. Functions bind lazily; a function the runtime doesn't export throws {@link MonoApiMissingError} when called. */
export const api: MonoApi = createApi()
