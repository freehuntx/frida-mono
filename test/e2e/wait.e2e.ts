import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { loadAgent, type LoadedAgent } from './support/agent'
import { currentRuntime } from './support/runtime'

interface WaitAgent {
  start(): Promise<{ ready: boolean; jsThread: number }>
  go(): Promise<void>
  outcome(): Promise<{ result?: { thread: number; assemblies: string[]; answer: number }; error?: string } | null>
}

// Needs a host that can delay loading Mono (the Unity images); the stock `mono` CLI starts with it.
describe.skipIf(currentRuntime().delayed === undefined)('perform before Mono is loaded', () => {
  let agent: LoadedAgent<WaitAgent>

  beforeAll(async () => {
    agent = await loadAgent<WaitAgent>('test/e2e/agents/wait.ts', 'unity-host-delayed')
  })

  afterAll(async () => {
    await agent?.unload()
  })

  it('waits for the module, runtime init and the assembly, then runs on the loading thread', async () => {
    const before = await agent.exports.start()
    expect(before.ready).toBe(false)

    await agent.exports.go()
    let outcome = await agent.exports.outcome()
    for (let i = 0; i < 100 && outcome === null; i++) {
      await new Promise((resolve) => setTimeout(resolve, 100))
      outcome = await agent.exports.outcome()
    }

    expect(outcome?.error).toBeUndefined()
    expect(outcome?.result?.answer).toBe(42)
    expect(outcome?.result?.assemblies).toContain('TestLib')
    // The callback ran synchronously on the thread that loaded TestLib, not on Frida's JS thread.
    expect(outcome?.result?.thread).not.toBe(before.jsThread)
  })
})
