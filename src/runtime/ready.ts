import { api } from '../native/api'
import { onUnload } from './cleanup'
import { findMonoModule, isMonoModule } from './module'

/** Embedding entry points that return once the runtime is initialized. */
const INIT_FUNCTIONS = ['mono_jit_init', 'mono_jit_init_version', 'mono_jit_init_version_for_test_only']
const POLL_INTERVAL_MS = 10

const waiters: (() => void)[] = []
let watching = false

/** True once Mono is loaded and its root domain and corlib exist. */
export function isRuntimeReady(): boolean {
  if (findMonoModule() === null) return false
  return !api.mono_get_root_domain().isNull() && !api.mono_get_corlib().isNull()
}

/**
 * Calls `callback` as soon as the runtime is ready: right away if it already is, otherwise
 * synchronously on the thread that finishes initialization, so it runs before managed code does.
 */
export function whenRuntimeReady(callback: () => void): void {
  if (isRuntimeReady()) return callback()
  waiters.push(callback)
  if (!watching) {
    watching = true
    watchForModule()
  }
}

function notifyReady(): void {
  if (!watching || !isRuntimeReady()) return
  watching = false
  for (const callback of waiters.splice(0)) callback()
}

function watchForModule(): void {
  if (findMonoModule() !== null) return watchForInit()

  const observer = Process.attachModuleObserver({
    onAdded(module) {
      if (!watching || !isMonoModule(module) || findMonoModule() === null) return
      // Hooks go in before the loader returns, so the embedder's init call can't be missed.
      watchForInit()
      Script.nextTick(() => observer.detach())
    }
  })
  onUnload(() => observer.detach())
}

function watchForInit(): void {
  const listeners: InvocationListener[] = []
  for (const name of INIT_FUNCTIONS) {
    const address = api.address(name)
    if (address !== null) listeners.push(Interceptor.attach(address, { onLeave: notifyReady }))
  }
  // The `mono` CLI and some embedders initialize without these entry points (mini_init directly).
  const timer = setInterval(notifyReady, POLL_INTERVAL_MS)

  const stop = (): void => {
    clearInterval(timer)
    for (const l of listeners) l.detach()
  }
  waiters.push(() => Script.nextTick(stop))
  notifyReady()
}
