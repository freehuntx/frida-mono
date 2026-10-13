import Mono from '../../../src'

// Loaded into a host that hasn't loaded Mono yet (UNITY_HOST_WAIT_FILE); see test/e2e/wait.e2e.ts.
let outcome: { result?: unknown; error?: string } | null = null

rpc.exports = {
  start() {
    const before = { ready: Mono.ready, jsThread: Process.getCurrentThreadId() }
    Mono.perform(
      () => ({
        thread: Process.getCurrentThreadId(),
        assemblies: Mono.assemblies.map((a) => a.name),
        answer: Mono.use('FridaMono.Tests.Smoke').Answer()
      }),
      { waitFor: 'TestLib' }
    ).then(
      (result) => (outcome = { result }),
      (error: unknown) => (outcome = { error: String(error) })
    )
    return before
  },

  go() {
    new File('/tmp/go', 'w').close()
  },

  outcome() {
    return outcome
  }
}
