import Mono, { MONO_API_TABLE, MonoApiMissingError, api, assemblyName, isThreadAttached, readUtf8, scoped } from '../../../src'

const FIXTURES = '/tmp/fixtures'

let lazyResult: { thread: number; assembly: string } | null = null

function load(name: string): string {
  return Mono.performNow(() =>
    scoped((scope) => {
      const assembly = api.mono_domain_assembly_open(api.mono_get_root_domain(), scope.utf8(`${FIXTURES}/${name}.dll`))
      if (assembly.isNull()) throw new Error(`could not load ${name}`)
      return assemblyName(assembly)
    })
  )
}

function errorOf(fn: () => unknown): { name: string; message: string; missing: boolean } | null {
  try {
    fn()
    return null
  } catch (error) {
    const missing = error instanceof MonoApiMissingError
    return error instanceof Error ? { name: error.name, message: error.message, missing } : { name: 'unknown', message: String(error), missing }
  }
}

rpc.exports = {
  info() {
    return { ready: Mono.ready, version: Mono.version, module: Mono.module.name, capabilities: Mono.capabilities }
  },

  async perform() {
    const before = isThreadAttached()
    const corlib = await Mono.perform(() => readUtf8(api.mono_image_get_name(api.mono_get_corlib())))
    return { before, after: isThreadAttached(), corlib }
  },

  classOfString() {
    return Mono.performNow(() =>
      scoped((scope) => {
        const klass = api.mono_class_from_name(api.mono_get_corlib(), scope.utf8('System'), scope.utf8('String'))
        return `${readUtf8(api.mono_class_get_namespace(klass))}.${readUtf8(api.mono_class_get_name(klass))}`
      })
    )
  },

  assemblies() {
    return Mono.performNow(() => Mono.assemblies.map((a) => a.name))
  },

  missing() {
    const absent = Object.keys(MONO_API_TABLE).find((name) => !api.has(name)) as keyof typeof MONO_API_TABLE
    const fn = api[absent] as unknown as () => unknown // accessing never throws, calling does
    const call = errorOf(() => fn())
    const bind = errorOf(() => api.bind('mono_definitely_not_there', 'void', []))
    return { absent, call, bind }
  },

  waitForLazy() {
    void Mono.perform(() => ({ thread: Process.getCurrentThreadId(), assembly: 'LazyA' }), { waitFor: 'LazyA' }).then((r) => (lazyResult = r))
    return lazyResult
  },

  loadLazy() {
    return { name: load('LazyA'), jsThread: Process.getCurrentThreadId() }
  },

  lazyResult() {
    return lazyResult
  },

  installLoadListener() {
    Mono.performNow(() => Mono.onAssemblyLoad(() => undefined))
  },

  loadLazyB() {
    return load('LazyB')
  }
}
