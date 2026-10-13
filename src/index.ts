import { MonoApiMissingError, MonoError, MonoNotFoundError } from './errors'
import { OverloadError } from './bridge/bridge'
import { hookedMethods, revertAll } from './hook/hooks'
import { findMethods, symbolicate, trace } from './hook/trace'
import { dump } from './tools/dump'
import { createDelegate } from './delegate/delegate'
import { classOfWrapper } from './bridge/symbols'
import { wrapInstance } from './bridge/bridge'
import type { MonoClassLike, MonoObject } from './bridge/types'
import { namespaces, use } from './bridge/namespaces'
import { api } from './native/api'
import { assemblies, Domain, findAssembly, findClass, findClasses, findMethodByDesc, getAssembly, getClass } from './meta'
import { onAssemblyLoad } from './runtime/assembly-load'
import { box } from './marshal/box'
import { hooks } from './marshal/hooks'
import { ManagedError } from './object/managed-error'
import { ManagedObject } from './object/object'
import { ref } from './object/ref'
import { newMonoString } from './object/string'
import { stats } from './object/handles'
import type { Class } from './meta'
import { getCapabilities } from './runtime/capabilities'
import { getMonoModule } from './runtime/module'
import { perform, performNow } from './runtime/perform'
import { isRuntimeReady } from './runtime/ready'
import { ensureThreadAttached } from './runtime/thread'
import { getRuntimeBuildInfo } from './runtime/version'

/** The `Mono` facade. Library-owned, so no `$` prefix. */
const Mono = {
  /** The JS class for a managed class: `Mono.use('Game.Player')`, `Mono.use('Assembly-CSharp', 'Game.Player')`, `Mono.use('List<System.String>')`. */
  use,
  /** Lazy namespace tree across all assemblies: `const { UnityEngine, System } = Mono.namespaces`. */
  namespaces,
  perform,
  performNow,
  /** The typed Mono C API (lazily bound). */
  api,
  /** Attaches the calling thread if needed. `perform` does this for you. */
  attachThread: ensureThreadAttached,
  get module(): Module {
    return getMonoModule()
  },
  /** `mono_get_runtime_build_info()`, or `null` on legacy runtimes. */
  get version(): string | null {
    return getRuntimeBuildInfo()
  },
  get capabilities() {
    return getCapabilities()
  },
  get ready(): boolean {
    return isRuntimeReady()
  },
  /** The root application domain. */
  get domain(): Domain {
    return Domain.root
  },
  /** Every loaded assembly. */
  get assemblies() {
    return assemblies()
  },
  /** Loaded assembly by simple name (`'Assembly-CSharp'`); throws if it isn't loaded. */
  assembly: getAssembly,
  findAssembly,
  /** Class by full name (`'Ns.Outer+Inner'`) or simple name, across all assemblies; throws if not found. */
  class: getClass,
  findClass,
  findClasses,
  /** Method by Mono's description syntax: `'Ns.Class:Method(int,string)'`. */
  findMethod: findMethodByDesc,
  /** Calls `listener(assembly, name)` for every assembly loaded from now on. Returns a remover. */
  onAssemblyLoad,
  /** A `ref`/`out` argument: `Mono.ref()` for `out`, `Mono.ref(value)` for `ref`; read `.value` after the call. */
  ref,
  /** Boxes `value` as the value type `klass` (e.g. to pass a `float` where `object` is expected). */
  box(klass: Class, value: unknown): ManagedObject {
    return new ManagedObject(box(klass, value))
  },
  /** A new managed `System.String` (strings are converted automatically; this is for when you need the object). */
  string(text: string): ManagedObject {
    return new ManagedObject(newMonoString(text))
  },
  /** The raw `ManagedObject` / `StructView` behind a bridge instance (for the low-level API), or `undefined`. */
  unwrap(value: unknown) {
    return hooks.unwrap(value)
  },
  /** Hook management: `Mono.hooks.revertAll()`, `Mono.hooks.list()`. */
  hooks: { revertAll, list: hookedMethods },
  /** Logs calls of methods matching `'Class:Method'` globs, e.g. `Mono.trace('Game.*Player*:Take*')`. Returns a stop function. */
  trace,
  /** Methods matching `'Class:Method'` globs. */
  findMethods,
  /** Managed method at a native address (for backtraces): `Thread.backtrace(ctx).map(Mono.symbolicate)`. */
  symbolicate,
  /**
   * A managed delegate that calls `fn`: `Mono.delegate(UnityEngine.Events.UnityAction, () => …)`.
   * Usually unnecessary: JS functions convert automatically where a delegate is expected.
   */
  delegate(type: MonoClassLike | Class, fn: (...args: never[]) => unknown): MonoObject {
    const klass = classOfWrapper(type) ?? (type as Class)
    return wrapInstance(createDelegate(klass, fn as (...args: unknown[]) => unknown)) as MonoObject
  },
  /** Dumps loaded assemblies as TypeScript typings (default), a C#-like listing or JSON. */
  dump,
  /** Debug counters, e.g. `Mono.stats.handles` (GC handles held by wrappers). */
  stats,
  MonoError,
  MonoNotFoundError,
  MonoApiMissingError,
  ManagedError,
  OverloadError
}

export default Mono

export { MonoApiMissingError, MonoError, MonoNotFoundError } from './errors'
export { api, type MonoApi } from './native/api'
export type * from './native/api.generated'
export { MONO_API_TABLE } from './native/api.generated'
export { Scope, scoped } from './memory/scope'
export { keepAlive, release } from './memory/keep-alive'
export { persistentCallback } from './memory/persistent'
export { takeUtf8, readUtf8 } from './memory/strings'
export { onUnload } from './runtime/cleanup'
export * from './meta'
export { callOriginal, hookedMethods, override, revert, revertAll, type HookFunction } from './hook/hooks'
export { nativeSignature, unsupportedReason } from './hook/native'
export { findMethods, symbolicate, trace } from './hook/trace'
export { dump, type DumpFormatOptions } from './tools/dump'
export { createDelegate } from './delegate/delegate'
export { collect, type DumpOptions } from './tools/collect'
export { emitCs } from './tools/emit-cs'
export { emitDts } from './tools/emit-dts'
export type * from './tools/model'
export { classWrapper, OverloadError, wrapInstance, type MonoClassWrapper, type MonoInstance } from './bridge/bridge'
export { namespaces, parseTypeName, use } from './bridge/namespaces'
export { MonoObject, type MonoClassLike, type MonoEvent, type MonoMethod, type MonoMethodHelpers, type MonoNamespaces, type MonoTypes } from './bridge/types'
export { construct, getField, invoke, setField, type Instance } from './invoke/invoke'
export { box, boxValue } from './marshal/box'
export { asManagedObject } from './marshal/hooks'
export { fromObject, marshallerFor, toObject, type Marshaller } from './marshal/marshaller'
export { MArray } from './object/array'
export { EnumValue, enumMembers } from './object/enum'
export { stats, type GcHandle } from './object/handles'
export { ManagedError } from './object/managed-error'
export { ManagedObject } from './object/object'
export { Ref, ref } from './object/ref'
export { newMonoString, readMonoString } from './object/string'
export { StructView } from './object/struct'
export { assemblyName, findLoadedAssembly, loadedAssemblies, onAssemblyLoad, whenAssemblyLoaded } from './runtime/assembly-load'
export { getCapabilities, type Capabilities } from './runtime/capabilities'
export { findMonoExport, getMonoExport, monoExports } from './runtime/exports'
export { findMonoModule, getMonoModule, isMonoModule } from './runtime/module'
export { KNOWN_MONO_MODULE_NAMES, isKnownMonoModuleName } from './runtime/names'
export { perform, performNow, type PerformOptions } from './runtime/perform'
export { isRuntimeReady, whenRuntimeReady } from './runtime/ready'
export { ensureThreadAttached, isThreadAttached } from './runtime/thread'
export { getRuntimeBuildInfo } from './runtime/version'
