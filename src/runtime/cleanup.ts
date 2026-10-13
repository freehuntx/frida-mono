const handlers: (() => void)[] = []
let sentinel: object | null = null

/**
 * Runs `fn` when the script unloads, in reverse registration order (like destructors).
 *
 * Uses `Script.bindWeak` on a sentinel that stays referenced, so the callback only fires on unload.
 */
export function onUnload(fn: () => void): void {
  if (sentinel === null) {
    sentinel = {}
    Script.bindWeak(sentinel, runUnloadHandlers)
  }
  handlers.push(fn)
}

function runUnloadHandlers(): void {
  for (let fn = handlers.pop(); fn !== undefined; fn = handlers.pop()) {
    try {
      fn()
    } catch (error) {
      console.error(`frida-mono: cleanup failed: ${error instanceof Error ? (error.stack ?? error.message) : String(error)}`)
    }
  }
}
