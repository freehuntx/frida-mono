import { MonoNotFoundError } from '../errors'
import type { MonoThreadPtr } from '../native/api.generated'
import { api } from '../native/api'
import { onUnload } from './cleanup'

/** Threads known to be attached, whether by us or by the runtime. */
const attachedThreads = new Set<ThreadId>()
/** Threads we attached ourselves, which we detach again on unload. */
const ownThreads = new Map<ThreadId, MonoThreadPtr>()

/**
 * Attaches the calling thread to the root domain unless it already is (once per thread).
 *
 * Calling into Mono from a thread it doesn't know (Frida's JS thread, `setTimeout`, `recv`, native
 * threads) crashes or corrupts the GC. Threads the runtime already manages are left alone.
 */
export function ensureThreadAttached(): void {
  const id = Process.getCurrentThreadId()
  if (attachedThreads.has(id)) return

  if (!knownToRuntime()) {
    const domain = api.mono_get_root_domain()
    if (domain.isNull()) throw new MonoNotFoundError('Mono is loaded but not initialized yet (no root domain). Use Mono.perform() to wait for it.')
    if (ownThreads.size === 0) onUnload(detachOwnThreads)
    ownThreads.set(id, api.mono_thread_attach(domain))
  }
  attachedThreads.add(id)
}

/**
 * True if the runtime knows the calling thread. Unknown threads read NULL from the current-domain
 * TLS slot. That alone isn't enough: Mono 2.6's `mono_thread_detach` clears the thread object but
 * leaves the domain set, so a re-used thread (Frida's JS thread after a script reload) would look
 * attached. Hence also `mono_thread_current()`, which is only safe to call once the domain is set
 * (modern runtimes assert on unattached threads).
 */
function knownToRuntime(): boolean {
  return !api.mono_domain_get().isNull() && !api.mono_thread_current().isNull()
}

/** True if the calling thread is attached (by us or the runtime). */
export function isThreadAttached(): boolean {
  return attachedThreads.has(Process.getCurrentThreadId()) || knownToRuntime()
}

function detachOwnThreads(): void {
  // mono_thread_detach must run on the thread itself. Unload runs on the JS thread, which is the one
  // we normally attach; others are left attached rather than detached from the wrong thread.
  const id = Process.getCurrentThreadId()
  const thread = ownThreads.get(id)
  if (thread !== undefined) api.mono_thread_detach(thread)
  ownThreads.clear()
  attachedThreads.clear()
}
